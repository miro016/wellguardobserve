package orchestration

import (
	"sort"
	"sync"
)

// terminalSeedState owns what the terminal stages will act on: the GoScans
// substage's approved hosts, virtual-host candidates, and observed ports.
//
// All fields are guarded by mu, and every method takes it itself. Snapshot methods
// copy under the lock and sort after releasing it, so a stage never plans from a
// reference into live state and the same passive input always yields the same plan.
//
// Nothing here is filled unless its stage is enabled - the orchestrator's wrappers
// check the configuration before recording - and the seeds accumulate from this
// run's own stream, so equivalent histories produce the same union whatever order
// they arrive in.
type terminalSeedState struct {
	mu sync.Mutex

	// goscansTargets maps an approved address to the EventID of the discovery that
	// introduced it. An address lands here once it has passed every gate the host
	// scheduler applies, so the substage inherits those decisions and spends no
	// second host-budget unit.
	goscansTargets map[string]string

	// goscansHostNames maps an approved address to the passive names that resolve to
	// it, the virtual-host candidates the substage hands its TLS and web modules. It
	// is built from ordinary domain and address observations only: no other active
	// tool's output may seed it, which is what keeps the two tools independent enough
	// to corroborate each other.
	goscansHostNames map[string]map[string]bool

	// goscansPorts maps an approved address to the TCP ports the port scanner found
	// open on it. A key is present only for a host the scanner definitively swept, so
	// an absent key means "not swept" rather than "swept and nothing open", and the
	// substage sweeps that host itself instead of assuming an empty result.
	goscansPorts map[string][]int
}

// newTerminalSeedState returns an empty terminalSeedState.
func newTerminalSeedState() *terminalSeedState {
	return &terminalSeedState{
		goscansTargets:   make(map[string]string),
		goscansHostNames: make(map[string]map[string]bool),
		goscansPorts:     make(map[string][]int),
	}
}

// captureGoScansTarget records an approved host for the terminal substage, keeping
// the first causation seen for it.
func (s *terminalSeedState) captureGoScansTarget(ip, causationID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.goscansTargets[ip]; !exists {
		s.goscansTargets[ip] = causationID
	}
}

// goscansTargetIPs returns a copy of the approved host addresses. The caller sorts
// them into the canonical address order the plan and its budget cap use.
func (s *terminalSeedState) goscansTargetIPs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.goscansTargets))
	for ip := range s.goscansTargets {
		out = append(out, ip)
	}
	return out
}

// goscansCausation returns a copy of the per-address causation ids, so an
// observation about a host threads back to the discovery that introduced it.
func (s *terminalSeedState) goscansCausation() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.goscansTargets))
	for ip, id := range s.goscansTargets {
		out[ip] = id
	}
	return out
}

// recordGoScansHostName records that name resolves to ip, building the virtual-host
// candidates the substage passes to its TLS and web modules.
func (s *terminalSeedState) recordGoScansHostName(ip, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := s.goscansHostNames[ip]
	if names == nil {
		names = make(map[string]bool)
		s.goscansHostNames[ip] = names
	}
	names[name] = true
}

// goscansHostNamesFor returns a copy of the names recorded against ip. The scope
// policy is applied by the caller rather than at collection time, because a name can
// be recorded against an address before its crawl depth is known.
func (s *terminalSeedState) goscansHostNamesFor(ip string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.goscansHostNames[ip]))
	for name := range s.goscansHostNames[ip] {
		out = append(out, name)
	}
	return out
}

// recordGoScansPorts records the ports the port scanner definitively found open on
// ip. A host that errored, or that answered no probe at all, must never reach here:
// recording an empty set for it would turn a coverage gap into a confident claim
// that nothing is open.
func (s *terminalSeedState) recordGoScansPorts(ip string, ports []int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.goscansPorts[ip] = ports
}

// goscansPortsFor returns a sorted copy of the ports recorded for ip, or nil when
// the port scanner did not definitively sweep it. Nil is what makes the substage
// fall back to its own full sweep, so an unswept host is never assessed as though it
// had been. The sort is applied here, not only in the actor, because the sweep
// reports ports in whatever order its concurrent probes answered and the target
// snapshot must be identical for the same passive input.
func (s *terminalSeedState) goscansPortsFor(ip string) []int {
	s.mu.Lock()
	ports, ok := s.goscansPorts[ip]
	out := append([]int(nil), ports...)
	s.mu.Unlock()

	if !ok || len(out) == 0 {
		return nil
	}
	sort.Ints(out)
	return out
}
