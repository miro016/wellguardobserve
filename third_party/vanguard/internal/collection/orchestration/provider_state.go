package orchestration

import (
	"sort"
	"sync"
)

// providerState owns the evidence the provider-host policy decides on: which
// addresses customer DNS resolved directly, which routed prefix each address belongs
// to, which prefixes contain a DNS-confirmed address, the provider-only candidates
// waiting for a verdict, and the independently collected PTR and certificate names.
//
// All fields are guarded by mu, and every method takes it itself. No method sends a
// request, publishes an event, or calls the gate while the lock is held: the
// decision inputs are copied out (evidenceFor, drainCandidates) and judged by the
// orchestrator afterwards, so a verdict never depends on which goroutine arrived
// first.
//
// Direct DNS evidence is the strongest signal and is never downgraded: an address
// ever seen in an A/AAAA answer stays confirmed regardless of a later provider
// sighting, and confirming an address promotes its already-known prefix.
type providerState struct {
	mu sync.Mutex

	// dnsConfirmed records the addresses observed in A/AAAA answers. It is separate
	// from the discovery registry so corroboration can distinguish direct customer
	// DNS evidence regardless of arrival order.
	dnsConfirmed map[string]bool

	// netblocks maps an address to its routed prefix, and confirmedNetblocks holds
	// the prefixes that contain at least one DNS-confirmed address. A provider-only
	// address is corroborated when its prefix appears in the latter.
	netblocks          map[string]string
	confirmedNetblocks map[string]bool

	// candidates holds the provider-only addresses waiting for a verdict, and
	// collectorStarted marks the ones an evidence collector was already launched
	// for, so at most one collector runs per address.
	candidates       map[string]providerHostCandidate
	collectorStarted map[string]bool

	// evidence accumulates the independently collected ownership evidence per
	// address: reverse-DNS names and leaf certificate DNS SANs.
	evidence map[string]providerHostEvidence
}

// newProviderState returns an empty providerState.
func newProviderState() *providerState {
	return &providerState{
		dnsConfirmed:       make(map[string]bool),
		netblocks:          make(map[string]string),
		confirmedNetblocks: make(map[string]bool),
		candidates:         make(map[string]providerHostCandidate),
		collectorStarted:   make(map[string]bool),
		evidence:           make(map[string]providerHostEvidence),
	}
}

// confirmDNS records direct A/AAAA evidence for ip and promotes its known prefix to
// a customer-confirmed one.
func (s *providerState) confirmDNS(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dnsConfirmed[ip] = true
	if prefix := s.netblocks[ip]; prefix != "" {
		s.confirmedNetblocks[prefix] = true
	}
}

// isDNSConfirmed reports whether direct A/AAAA evidence has arrived for ip.
func (s *providerState) isDNSConfirmed(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dnsConfirmed[ip]
}

// recordNetblock records one ASN result for ip and marks its prefix confirmed when
// the caller says so or when the address already carries direct DNS evidence.
func (s *providerState) recordNetblock(ip string, confirmed bool, prefix string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.netblocks[ip] = prefix
	if confirmed || s.dnsConfirmed[ip] {
		s.confirmedNetblocks[prefix] = true
	}
}

// hasNetblock reports whether a routed prefix is already known for ip from an ASN
// lookup in this run. The provider-host path uses it to decide whether a host needs
// its ASN call, which is what keeps one address to one paid lookup however many
// providers attribute it.
func (s *providerState) hasNetblock(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.netblocks[ip] != ""
}

// addPTRNames stores reverse-DNS evidence for the final policy decision.
func (s *providerState) addPTRNames(ip string, names []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.evidence[ip]
	e.ptrNames = append(e.ptrNames, names...)
	s.evidence[ip] = e
}

// addCertificateNames stores leaf DNS SAN evidence from the bounded certificate
// preflight.
func (s *providerState) addCertificateNames(ip string, names []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.evidence[ip]
	e.certNames = append(e.certNames, names...)
	s.evidence[ip] = e
}

// enqueue records candidate for a later verdict. alreadyConfirmed is true when the
// address already carries direct DNS evidence, in which case the caller schedules
// the ordinary host scan and no corroboration is needed. startCollector is true only
// for the first caller, so exactly one evidence collector runs per address.
func (s *providerState) enqueue(candidate providerHostCandidate) (alreadyConfirmed, startCollector bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dnsConfirmed[candidate.ip] {
		return true, false
	}
	if _, exists := s.candidates[candidate.ip]; !exists {
		s.candidates[candidate.ip] = candidate
	}
	if s.collectorStarted[candidate.ip] {
		return false, false
	}
	s.collectorStarted[candidate.ip] = true
	return false, true
}

// drainCandidates removes and returns every queued candidate, sorted by address, so
// the verdicts are made in a deterministic order rather than in the order the
// collectors happened to finish. The copy is taken under the lock and sorted after
// releasing it.
func (s *providerState) drainCandidates() []providerHostCandidate {
	s.mu.Lock()
	out := make([]providerHostCandidate, 0, len(s.candidates))
	for _, candidate := range s.candidates {
		out = append(out, candidate)
	}
	s.candidates = make(map[string]providerHostCandidate)
	s.mu.Unlock()

	sort.Slice(out, func(i, j int) bool { return out[i].ip < out[j].ip })
	return out
}

// evidenceFor returns copies of the ownership evidence collected for ip: the
// reverse-DNS names, the certificate SANs, the routed prefix, and whether that
// prefix also contains a DNS-confirmed address. The scope test that turns this into
// a verdict is applied by the caller, after the lock is released.
func (s *providerState) evidenceFor(ip string) (ptrNames, certNames []string, prefix string, sharedNetblock bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.evidence[ip]
	prefix = s.netblocks[ip]
	return append([]string(nil), e.ptrNames...),
		append([]string(nil), e.certNames...),
		prefix,
		prefix != "" && s.confirmedNetblocks[prefix]
}
