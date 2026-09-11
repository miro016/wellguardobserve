package orchestration

import (
	"sort"
	"sync"

	"github.com/velgard-sk/vanguard/internal/collection/events"
)

// workKind names one first-wins claim set inside [targetState]. Every kind answers
// the same question - "has this unit of work already been claimed for this key?" -
// so they share one implementation instead of a map per tool. The kinds are
// deliberately independent of each other: a name claimed for the DNS lookup is not
// thereby claimed for whois, and an address claimed for the host scan is not thereby
// registered as discovered.
//
// None of these claims is authorization. They answer "was this already scheduled",
// never "may this receive traffic"; that question belongs to gate's approval
// registries alone.
type workKind int

const (
	// workDNS dedups the per-domain DNS lookup. A name enters it exactly when the run
	// decided to do per-domain work for it.
	workDNS workKind = iota
	// workWhois dedups the registration lookup. Its key is the registrable apex, not
	// the discovered name, so one estate costs one whois call.
	workWhois
	// workMailsec, workBreach, workCensys, workVirustotal, workShodan and workNetlas
	// dedup their per-domain passive lookups. Censys keys on the estate root because
	// its query already covers every subdomain.
	workMailsec
	workBreach
	workCensys
	workVirustotal
	workShodan
	workNetlas
	// workZoneTransfer dedups the active AXFR check.
	workZoneTransfer
	// workHostScan dedups the active host scan per address. It is deliberately
	// separate from IP registration: a provider result that registers an address
	// first must not suppress the DNS-confirmed scan of the same address.
	workHostScan
	// workCoverageIssue dedups the per-target "unreachable, not probed" coverage
	// issue so the audit stream carries one line per skipped target.
	workCoverageIssue
	workKindCount
)

// domainSignals is the copied per-domain reachability summary the active schedulers
// gate on. It is returned by value, never as a reference into [targetState].
type domainSignals struct {
	// hasIPv4 and hasIPv6 record which address families the passive DNS lookup
	// resolved the name to, so the active sweep can tell an IPv6-only name from a
	// dual-stack one and skip a host the scanner cannot reach.
	hasIPv4 bool
	hasIPv6 bool
	// hasMX records whether at least one MX record was resolved, so the SMTP probe
	// can skip a name that handles no mail instead of dialling STARTTLS in vain.
	hasMX bool
}

// targetState owns what the run has discovered and what it has already scheduled:
// the per-tool claim sets, each domain's first-discovery identity and depth, the
// per-domain reachability signals, and the registered addresses with their causation
// event ids.
//
// All fields are guarded by mu. Every method takes mu itself; no caller holds it,
// and no method calls a tool, publishes an event, or touches another state owner
// while it is held. Snapshots (discoveredDomains, signalsFor) copy under the lock and
// sort after releasing it, so a caller never receives a reference into the state.
//
// Everything here is accumulated by this run: a name enters through
// recordDomainDiscovery when it is first discovered and an address through
// registerIPs when it is first resolved, both first-wins, so causation always threads
// back to the observation that introduced the target.
type targetState struct {
	mu sync.Mutex

	// claims holds one first-wins key set per workKind, indexed by the kind.
	claims [workKindCount]map[string]bool

	// domainEventIDs maps a discovered domain to the EventID of the first
	// DnsDomainNameDiscovered for it, so per-domain work can set CausationID back to
	// the discovery event. domainDepth carries that same first sighting's crawl
	// depth, which the scope depth cap is applied against.
	domainEventIDs map[string]string
	domainDepth    map[string]int

	// signals records the per-domain address-family and mail-route facts observed
	// during the passive phase.
	signals map[string]domainSignals

	// seenIPs is the registration set for discovered addresses (the emit and ASN
	// dedup) and ipEventIDs the EventID of the IPAddressDiscovered that introduced
	// each one. Registration is not permission to scan: that is workHostScan's claim
	// plus the gate's approval.
	seenIPs    map[string]bool
	ipEventIDs map[string]string
}

// newTargetState returns an empty targetState with every claim set allocated.
func newTargetState() *targetState {
	s := &targetState{
		domainEventIDs: make(map[string]string),
		domainDepth:    make(map[string]int),
		signals:        make(map[string]domainSignals),
		seenIPs:        make(map[string]bool),
		ipEventIDs:     make(map[string]string),
	}
	for i := range s.claims {
		s.claims[i] = make(map[string]bool)
	}
	return s
}

// claim reserves key for kind and reports whether this call is the first to do so.
// A false result means the work is already scheduled or done and the caller must
// skip it.
func (s *targetState) claim(kind workKind, key string) (first bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.claims[kind][key] {
		return false
	}
	s.claims[kind][key] = true
	return true
}

// recordDomainDiscovery remembers the first discovery of domain: its EventID (the
// causation anchor for every later per-domain event) and its crawl depth. Later
// sightings of the same name are ignored, so causation always threads back to the
// first one.
func (s *targetState) recordDomainDiscovery(domain, eventID string, depth int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.domainEventIDs[domain]; exists {
		return
	}
	s.domainEventIDs[domain] = eventID
	s.domainDepth[domain] = depth
}

// depth returns the recorded crawl depth of domain. The bool distinguishes a name
// discovered at depth zero from a name never discovered at all, which the request
// authorizer must not conflate.
func (s *targetState) depth(domain string) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	depth, known := s.domainDepth[domain]
	return depth, known
}

// domainEventID returns the EventID of the first discovery of domain, or "" when
// the name was never discovered.
func (s *targetState) domainEventID(domain string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.domainEventIDs[domain]
}

// discoveredDomains returns a copy of every distinct name discovered so far, sorted.
// It is the input to the end-of-discovery collapse backstop.
func (s *targetState) discoveredDomains() []string {
	s.mu.Lock()
	out := make([]string, 0, len(s.domainEventIDs))
	for d := range s.domainEventIDs {
		out = append(out, d)
	}
	s.mu.Unlock()
	sort.Strings(out)
	return out
}

// recordAddressFamilies notes that domain resolved to an IPv4 and/or IPv6 address.
// The flags only ever turn on: a later answer that omits a family does not retract
// an earlier sighting of it.
func (s *targetState) recordAddressFamilies(domain string, hasIPv4, hasIPv6 bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sig := s.signals[domain]
	sig.hasIPv4 = sig.hasIPv4 || hasIPv4
	sig.hasIPv6 = sig.hasIPv6 || hasIPv6
	s.signals[domain] = sig
}

// recordMailRoute notes that domain publishes at least one MX record.
func (s *targetState) recordMailRoute(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sig := s.signals[domain]
	sig.hasMX = true
	s.signals[domain] = sig
}

// signalsFor returns a copy of the reachability signals recorded for domain. A name
// with nothing recorded reads as all-false, which the callers treat as "no signal"
// rather than as a negative answer.
func (s *targetState) signalsFor(domain string) domainSignals {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.signals[domain]
}

// registerIPs registers the addresses in ipEvents and returns the genuinely new
// ones, in argument order, so the caller runs the ASN lookup exactly once per
// address. Registration records the first sighting's EventID as the address's
// causation anchor; it grants no permission to scan.
func (s *targetState) registerIPs(ipEvents []events.IPAddressDiscovered) []events.IPAddressDiscovered {
	var newIPs []events.IPAddressDiscovered
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range ipEvents {
		if s.seenIPs[e.IP] {
			continue
		}
		s.seenIPs[e.IP] = true
		s.ipEventIDs[e.IP] = e.EventID
		newIPs = append(newIPs, e)
	}
	return newIPs
}

// ipEventID returns the EventID of the discovery that introduced ip, or "" when the
// address was never registered.
func (s *targetState) ipEventID(ip string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ipEventIDs[ip]
}
