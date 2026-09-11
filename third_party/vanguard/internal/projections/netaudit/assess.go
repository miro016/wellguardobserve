package netaudit

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// ExclusionIssue is one domain exclusion IssueObserved row: the event-side record
// that the control plane denied a target under an exclusion rule.
// The adapter fills these from the canonical event log so the analyzer never
// depends on the event package.
type ExclusionIssue struct {
	// Target is the normalized denied target (a domain name or an IP literal).
	Target string
	// At is the capture time of the issue.
	At time.Time
}

// ToolSpan is one active or exploit tool invocation, or a typed tool rejection,
// pulled from the collection's tool-event log. It correlates packet traffic to
// a deliberate active attempt and supplies tool-side attribution.
type ToolSpan struct {
	Tool string
	// Target is the host/IP/URL the invocation concerned, normalized when possible.
	// For a rejection it is the correlation target of the whole call (normally the
	// root domain), which is rarely the denied destination: use Destinations for
	// rule matching.
	Target string
	// Phase is the recon phase (active or exploit spans are the target-facing ones).
	Phase string
	At    time.Time
	// Rejected marks a typed exclusion rejection span rather than an ordinary
	// invocation.
	Rejected bool
	// Destinations are the denied destinations a rejection actually concerned,
	// derived from the event's own attributes (a resolved address, a nameserver, an
	// MX host, a redirect host, a probed target). One rejection can deny more than
	// one destination, so all of them are preserved. Empty for an ordinary
	// invocation, and empty for a rejection whose event carried no destination, in
	// which case matching falls back to Target.
	Destinations []string
	// Reason is the policy reason the tool recorded for a rejection, so an
	// unmatched rejection can be reported with its own words. Empty otherwise.
	Reason string
}

// UnmatchedRejection is a typed tool rejection whose denied destination matched no
// configured exclusion rule. It is reported explicitly rather
// than silently dropped: a rejection nobody can attribute is either a rule the
// snapshot does not describe or an attribution gap, and both matter to an audit.
type UnmatchedRejection struct {
	Tool string `json:"tool"`
	// Destination is the denied destination(s) derived from the rejection event.
	Destination string `json:"destination"`
	// Reason is the tool's own policy reason, when it recorded one.
	Reason string    `json:"reason,omitempty"`
	At     time.Time `json:"at"`
}

// CaptureSource is the discovered, hashed capture plus the facts that bind it to
// the collection. It is nil when the collection holds no capture file (absent).
type CaptureSource struct {
	RelPath  string
	SHA256   string
	ByteSize int64
	Start    time.Time
	Stop     time.Time
	// Readable is false when the file exists but could not be opened or read.
	Readable bool
	// TimeOverlap is false when the capture bracket does not intersect the
	// collection's own; UniqueConfig is false when the collection named no engagement
	// snapshot to assess the capture against. Either one blocks a packet-level
	// verdict.
	TimeOverlap  bool
	UniqueConfig bool
	// Extract is the streamed packet result. Zero value when unreadable.
	Extract ExtractResult
}

// CaptureInput is everything the pure assessment needs. The adapter assembles it
// from the manifest, the config snapshot, the event log, the tool log, and the
// capture file; the assessment itself reads no clock and touches no filesystem.
type CaptureInput struct {
	// DomainRules and CIDRRules are the normalized exclusion rules, in config order,
	// so every configured rule gets a row even when no evidence touches it.
	DomainRules []string
	CIDRRules   []netip.Prefix
	// Started and Completed bracket the collection.
	Started   time.Time
	Completed time.Time
	// ActiveRan reports whether target-facing active work ran, so a loopback-only
	// capture is judged partial rather than complete.
	ActiveRan bool

	ExclusionIssues []ExclusionIssue
	ToolSpans       []ToolSpan
	Capture         *CaptureSource
}

// AssessCapture builds the immutable capture audit: the capture-health status, one
// verdict per configured rule, and the compact violation list. It is a pure,
// deterministic function of its input.
func AssessCapture(in CaptureInput) CaptureAudit {
	health := assessHealth(in)
	flows := buildFlows(in.Capture)
	dnsExcluded := dnsAnswerIndex(in.Capture, in.DomainRules)

	audit := CaptureAudit{Health: health, Limitations: health.Limitations}
	audit.Traffic = summarizeTraffic(in.Capture, flows)

	for _, rule := range in.DomainRules {
		ra, viols := assessDomainRule(rule, in, flows, dnsExcluded, health)
		audit.Rules = append(audit.Rules, ra)
		audit.Violations = append(audit.Violations, viols...)
	}
	for _, rule := range in.CIDRRules {
		ra, viols := assessCIDRRule(rule, in, flows, health)
		audit.Rules = append(audit.Rules, ra)
		audit.Violations = append(audit.Violations, viols...)
	}
	audit.UnmatchedRejections = unmatchedRejections(in)
	sortViolations(audit.Violations)
	return audit
}

// unmatchedRejections returns the typed rejections whose derived destinations
// matched none of the configured rules, in log order. Attributing a
// rejection to no rule is a reconciliation gap, so it is surfaced rather than
// dropped.
func unmatchedRejections(in CaptureInput) []UnmatchedRejection {
	var out []UnmatchedRejection
	for _, s := range in.ToolSpans {
		if !s.Rejected {
			continue
		}
		dests := rejectionTargets(s)
		if matchesAnyRule(dests, in.DomainRules, in.CIDRRules) {
			continue
		}
		out = append(out, UnmatchedRejection{
			Tool:        s.Tool,
			Destination: strings.Join(dests, ", "),
			Reason:      s.Reason,
			At:          s.At,
		})
	}
	return out
}

// matchesAnyRule reports whether any denied destination is covered by a configured
// domain or CIDR rule.
func matchesAnyRule(dests, domainRules []string, cidrRules []netip.Prefix) bool {
	for _, d := range dests {
		if _, ok := matchDomain(d, domainRules); ok {
			return true
		}
		for _, p := range cidrRules {
			if addrInPrefix(d, p) {
				return true
			}
		}
	}
	return false
}

// assessHealth derives the capture-health status and its limitations from the
// discovered capture and its extraction result.
func assessHealth(in CaptureInput) CaptureHealth {
	c := in.Capture
	if c == nil {
		return CaptureHealth{Status: StatusAbsent, Backend: BackendUnknown,
			Limitations: []string{"the collection holds no capture file"}}
	}
	h := CaptureHealth{
		Backend:  c.Extract.Backend,
		RelPath:  c.RelPath,
		SHA256:   c.SHA256,
		ByteSize: c.ByteSize,
		Start:    c.Start,
		Stop:     c.Stop,
	}
	if h.Backend == "" {
		h.Backend = BackendUnknown
	}
	if !c.Readable {
		h.Status = StatusUnreadable
		h.Limitations = []string{"capture file exists but could not be opened or read"}
		return h
	}
	e := c.Extract
	h.PacketCount = e.PacketCount
	h.RemotePackets = e.RemotePackets
	h.LoopbackPackets = e.LoopbackPackets
	h.DroppedPackets = e.DroppedPackets
	h.DecodedLinkTypes = e.DecodedLinkTypes
	h.SkippedLinkTypes = e.SkippedLinkTypes
	h.ProcessAttribution = e.ProcessAttribution
	h.ParseError = e.ParseError
	h.ParseOffset = e.ParseOffset

	if e.ParseError != "" && e.PacketCount == 0 {
		h.Status = StatusParseFailed
		h.Limitations = []string{fmt.Sprintf("capture parsing failed at packet %d: %s", e.ParseOffset, e.ParseError)}
		return h
	}
	if !c.TimeOverlap || !c.UniqueConfig {
		h.Status = StatusCollectionMismatch
		if !c.TimeOverlap {
			h.Limitations = append(h.Limitations, "capture times do not overlap the collection")
		}
		if !c.UniqueConfig {
			h.Limitations = append(h.Limitations, "the collection named no config snapshot to assess the capture against")
		}
		return h
	}

	var lim []string
	if e.ParseError != "" {
		lim = append(lim, fmt.Sprintf("capture is truncated at packet %d: %s", e.ParseOffset, e.ParseError))
	}
	if e.Truncated && e.ParseError == "" {
		lim = append(lim, "capture is truncated or hit the decode cap")
	}
	if e.DroppedPackets > 0 {
		lim = append(lim, fmt.Sprintf("%d packets were dropped during capture", e.DroppedPackets))
	}
	if len(e.SkippedLinkTypes) > 0 {
		lim = append(lim, "unsupported link types were skipped: "+strings.Join(e.SkippedLinkTypes, ", "))
	}
	if in.ActiveRan && e.RemotePackets == 0 {
		lim = append(lim, "active work ran but the capture holds only loopback traffic")
	}
	h.Limitations = lim
	if len(lim) > 0 {
		h.Status = StatusPartial
	} else {
		h.Status = StatusComplete
	}
	return h
}

// flow is one deduplicated conversation between two endpoints: both directions and
// every retransmission collapse into it, retaining first/last time and packet count.
type flow struct {
	a, b         netip.Addr
	portA, portB int
	protocol     string
	packets      int
	first, last  time.Time
	sni          string
	httpHost     string
	process      string
	syn          bool
	// opened is the travel direction of the conversation's first packet, so a reader
	// can tell a contact this host initiated from one it received. Unknown when the
	// capture format carries no per-packet direction.
	opened Direction
}

// buildFlows folds packet observations into deduplicated conversations. Frames
// duplicated across interfaces (identical fingerprint) are counted once.
func buildFlows(c *CaptureSource) []flow {
	if c == nil || !c.Readable {
		return nil
	}
	seen := make(map[[32]byte]bool)
	byKey := make(map[string]*flow)
	var order []*flow
	for i := range c.Extract.Observations {
		o := c.Extract.Observations[i]
		if !o.SrcIP.IsValid() || !o.DstIP.IsValid() {
			continue
		}
		if seen[o.Fingerprint] {
			continue
		}
		seen[o.Fingerprint] = true

		a, portA, b, portB := canonicalEndpoints(o)
		key := fmt.Sprintf("%s/%d|%s/%d|%s", a, portA, b, portB, o.Protocol)
		f := byKey[key]
		if f == nil {
			f = &flow{a: a, b: b, portA: portA, portB: portB, protocol: o.Protocol,
				first: o.Time, last: o.Time, opened: o.Direction}
			byKey[key] = f
			order = append(order, f)
		}
		f.packets++
		if o.Time.Before(f.first) {
			f.first = o.Time
		}
		if o.Time.After(f.last) {
			f.last = o.Time
		}
		if o.SNI != "" {
			f.sni = o.SNI
		}
		if o.HTTPHost != "" {
			f.httpHost = o.HTTPHost
		}
		if o.Process != "" {
			f.process = o.Process
		}
		if o.TCPFlags.SYN && !o.TCPFlags.ACK {
			f.syn = true
		}
	}
	out := make([]flow, 0, len(order))
	for _, f := range order {
		out = append(out, *f)
	}
	return out
}

// canonicalEndpoints orders a packet's two endpoints so both directions of one
// conversation map to a single flow key.
func canonicalEndpoints(o Observation) (a netip.Addr, portA int, b netip.Addr, portB int) {
	if compareEndpoint(o.SrcIP, o.SrcPort, o.DstIP, o.DstPort) <= 0 {
		return o.SrcIP, o.SrcPort, o.DstIP, o.DstPort
	}
	return o.DstIP, o.DstPort, o.SrcIP, o.SrcPort
}

func compareEndpoint(ip1 netip.Addr, p1 int, ip2 netip.Addr, p2 int) int {
	if c := ip1.Compare(ip2); c != 0 {
		return c
	}
	return p1 - p2
}

// dnsAnswerIndex maps a resolved address to the set of excluded names that
// resolved to it, so an active conversation to a shared address can be correlated
// to an excluded domain even without SNI/Host proof.
func dnsAnswerIndex(c *CaptureSource, domainRules []string) map[netip.Addr][]string {
	if c == nil || !c.Readable {
		return nil
	}
	idx := make(map[netip.Addr][]string)
	for i := range c.Extract.Observations {
		for _, ans := range c.Extract.Observations[i].DNSAnswers {
			if !ans.Addr.IsValid() {
				continue
			}
			name := strings.ToLower(strings.TrimSuffix(ans.Name, "."))
			if rule, ok := matchDomain(name, domainRules); ok {
				idx[ans.Addr] = appendUnique(idx[ans.Addr], rule)
			}
		}
	}
	return idx
}

// assessDomainRule reconciles one domain exclusion against the four evidence
// sources. A direct SNI/Host match to the excluded name is a confirmed violation;
// a shared DNS-answer address correlated to an active span is a possible violation;
// otherwise the verdict follows exercise state and capture completeness.
func assessDomainRule(rule string, in CaptureInput, flows []flow, dnsExcluded map[netip.Addr][]string, health CaptureHealth) (RuleAssessment, []Violation) {
	ra := RuleAssessment{Kind: RuleDomain, Rule: rule}
	ra.ExclusionIssues = countIssues(in.ExclusionIssues, func(t string) bool { _, ok := matchDomain(t, []string{rule}); return ok })
	ra.ToolRejections = countRejections(in.ToolSpans, func(t string) bool { _, ok := matchDomain(t, []string{rule}); return ok })

	var confirmed, possible []Violation
	for i := range flows {
		f := flows[i]
		host := f.sni
		if host == "" {
			host = f.httpHost
		}
		if host != "" {
			if _, ok := matchDomain(host, []string{rule}); ok {
				confirmed = append(confirmed, domainViolation(rule, f, host, VerdictViolationConfirmed, in.ToolSpans))
				continue
			}
		}
		// Possible: the conversation reached an address that resolved from the
		// excluded name, but no SNI/Host proves the hostname, and an active tool span
		// correlates the attempt.
		if names := sharedExcludedNames(f, dnsExcluded, rule); len(names) > 0 && correlatedActive(f, in.ToolSpans) {
			possible = append(possible, domainViolation(rule, f, rule, VerdictViolationPossible, in.ToolSpans))
		}
	}

	ra.PacketConversations = len(confirmed)
	viols := make([]Violation, 0, len(confirmed)+len(possible))
	viols = append(viols, confirmed...)
	viols = append(viols, possible...)
	ra.Verdict = domainVerdict(len(confirmed) > 0, len(possible) > 0, exercisedRule(ra), health)
	ra.Detail = ruleDetail(ra, health)
	return ra, viols
}

// assessCIDRRule reconciles one IP/CIDR exclusion. Any conversation whose endpoint
// falls in the excluded prefix is direct IP contact and a confirmed violation;
// capture incompleteness does not weaken it.
func assessCIDRRule(rule netip.Prefix, in CaptureInput, flows []flow, health CaptureHealth) (RuleAssessment, []Violation) {
	ra := RuleAssessment{Kind: RuleCIDR, Rule: rule.String()}
	ra.ExclusionIssues = countIssues(in.ExclusionIssues, func(t string) bool { return addrInPrefix(t, rule) })
	ra.ToolRejections = countRejections(in.ToolSpans, func(t string) bool { return addrInPrefix(t, rule) })

	var confirmed []Violation
	for i := range flows {
		f := flows[i]
		if peer, ok := excludedEndpoint(f, rule); ok {
			confirmed = append(confirmed, cidrViolation(rule, f, peer, in.ToolSpans))
		}
	}
	ra.PacketConversations = len(confirmed)
	ra.Verdict = cidrVerdict(len(confirmed) > 0, exercisedRule(ra), health)
	ra.Detail = ruleDetail(ra, health)
	return ra, confirmed
}

// domainVerdict applies the conservative verdict table for a domain rule.
func domainVerdict(confirmed, possible, ruleExercised bool, health CaptureHealth) Verdict {
	switch {
	case confirmed:
		return VerdictViolationConfirmed
	case possible:
		return VerdictViolationPossible
	case !ruleExercised:
		return VerdictNotExercised
	case health.Status.SupportsZeroContact():
		return VerdictZeroContactCorroborated
	default:
		return VerdictInconclusive
	}
}

// cidrVerdict applies the conservative verdict table for a CIDR rule.
func cidrVerdict(confirmed, ruleExercised bool, health CaptureHealth) Verdict {
	switch {
	case confirmed:
		return VerdictViolationConfirmed
	case !ruleExercised:
		return VerdictNotExercised
	case health.Status.SupportsZeroContact():
		return VerdictZeroContactCorroborated
	default:
		return VerdictInconclusive
	}
}

// exercisedRule reports whether this specific rule was exercised: a rejection or
// exclusion issue naming a target the rule matches.
func exercisedRule(ra RuleAssessment) bool {
	return ra.ExclusionIssues > 0 || ra.ToolRejections > 0
}

func ruleDetail(ra RuleAssessment, health CaptureHealth) string {
	switch ra.Verdict {
	case VerdictViolationConfirmed:
		return fmt.Sprintf("%d outbound conversation(s) reached the excluded target", ra.PacketConversations)
	case VerdictViolationPossible:
		return "traffic correlates to an excluded DNS answer and an active tool span; hostname proof is missing"
	case VerdictZeroContactCorroborated:
		return fmt.Sprintf("%d rejection/issue(s) recorded; a complete capture shows no matching outbound conversation", ra.ExclusionIssues+ra.ToolRejections)
	case VerdictNotExercised:
		return "configured but not exercised by this run; not enforcement confirmation"
	default:
		return "capture " + string(health.Status) + "; packet-level verdict is inconclusive, event-only evidence shown"
	}
}
