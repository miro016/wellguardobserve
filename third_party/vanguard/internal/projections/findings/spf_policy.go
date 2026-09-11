package findings

import "strings"

// spfPolicy is the terminal result an SPF record reaches for a sender that matches
// none of its listed hosts. It is deliberately not a general SPF evaluator: it
// answers only "what does this record do with everyone else", which is the question
// the policy-quality findings ask. No sender IP is evaluated, no include: is
// followed, and no DNS is performed.
type spfPolicy int

const (
	// spfUnknown is an empty, non-SPF, or malformed record. Nothing is concluded from
	// it: an uncertain policy must raise no finding rather than a guessed one.
	spfUnknown spfPolicy = iota
	// spfPassAll is a bare "all" or "+all": every sender passes.
	spfPassAll
	// spfFailAll is "-all": an unlisted sender fails.
	spfFailAll
	// spfSoftFailAll is "~all": an unlisted sender soft-fails.
	spfSoftFailAll
	// spfNeutralAll is an explicit "?all": the record reaches Neutral by choice.
	spfNeutralAll
	// spfImplicitNeutral is a valid record with no "all" and no redirect: evaluation
	// falls off the end and returns Neutral without ever saying so.
	spfImplicitNeutral
	// spfRedirected is a record with no "all" that delegates its result to a
	// redirect= target. The terminal policy is that target's, which this classifier
	// does not resolve.
	spfRedirected
)

// spfMechanisms are the mechanism names an SPF record may use (RFC 7208 section 5).
// A term naming anything else is not a mechanism this classifier understands, and an
// unrecognized term makes the whole record unknown rather than implicitly neutral.
var spfMechanisms = map[string]struct{}{
	"all": {}, "include": {}, "a": {}, "mx": {}, "ptr": {}, "ip4": {}, "ip6": {}, "exists": {},
}

// spfArgRequired are the mechanisms that are meaningless without a value. "a" and
// "mx" default to the current domain, and "ptr" to the sender's, so those are valid
// bare; "include", "ip4", "ip6", and "exists" are not.
var spfArgRequired = map[string]struct{}{
	"include": {}, "ip4": {}, "ip6": {}, "exists": {},
}

// classifySPFPolicy reads the effective terminal policy of one raw SPF record.
//
// SPF evaluates its terms left to right, and "all" always matches, so the first
// exact "all" mechanism decides the result and nothing after it can be reached. A
// missing qualifier means "+", so a bare "all" is pass-all. A record that ends
// without matching returns Neutral unless a redirect= modifier hands the decision to
// another domain.
//
// The framing of every term is checked before any of that is concluded. A record
// carrying a term this parser does not recognize is reported unknown, because
// calling an invalid record "neutral" would raise a finding about a policy nobody
// actually published. Matching is on exact tokens: "include:all.example" and
// "all.example" are not the "all" mechanism, and "+-all" is malformed rather than a
// qualifier this code should pick from.
func classifySPFPolicy(record string) spfPolicy {
	terms := strings.Fields(record)
	if len(terms) == 0 || !strings.EqualFold(terms[0], "v=spf1") {
		return spfUnknown
	}

	redirected := false
	terminal := spfUnknown
	for _, term := range terms[1:] {
		name, value, isModifier := splitSPFModifier(term)
		if isModifier {
			if !validSPFModifier(name, value) {
				return spfUnknown
			}
			if strings.EqualFold(name, "redirect") {
				redirected = true
			}
			continue
		}

		qualifier, mechanism, ok := splitSPFMechanism(term)
		if !ok {
			return spfUnknown
		}
		// The first exact "all" is terminal; later terms are unreachable, but they
		// are still validated so a malformed record is never read as a policy.
		if terminal == spfUnknown && strings.EqualFold(mechanism, "all") {
			terminal = spfTerminalFor(qualifier)
		}
	}

	switch {
	case terminal != spfUnknown:
		return terminal
	case redirected:
		return spfRedirected
	default:
		return spfImplicitNeutral
	}
}

// splitSPFModifier splits a "name=value" modifier term. A term with no "=" is a
// mechanism, which the caller handles instead.
func splitSPFModifier(term string) (name, value string, isModifier bool) {
	name, value, isModifier = strings.Cut(term, "=")
	return name, value, isModifier
}

// validSPFModifier checks a modifier's framing. redirect= and exp= must name a
// target; an unknown modifier is accepted with no policy meaning, because SPF
// receivers ignore modifiers they do not recognize, but its name still has to look
// like a name.
func validSPFModifier(name, value string) bool {
	switch {
	case name == "":
		return false
	case strings.EqualFold(name, "redirect"), strings.EqualFold(name, "exp"):
		return value != ""
	default:
		return true
	}
}

// splitSPFMechanism strips at most one leading qualifier and validates the mechanism
// framing. Exactly one qualifier is removed: a second one ("+-all") is malformed, not
// a policy, and stripping qualifiers repeatedly would read it as one.
func splitSPFMechanism(term string) (qualifier byte, mechanism string, ok bool) {
	qualifier = '+'
	if term == "" {
		return 0, "", false
	}
	switch term[0] {
	case '+', '-', '~', '?':
		qualifier = term[0]
		term = term[1:]
	}
	if term == "" {
		return 0, "", false
	}
	// A mechanism carries its argument after ":" and an ip4/ip6 prefix length after
	// "/". Both belong to the argument, not to the name.
	name, arg, hasArg := strings.Cut(term, ":")
	name, cidr, hasCIDR := strings.Cut(name, "/")
	name = strings.ToLower(name)
	if _, known := spfMechanisms[name]; !known {
		return 0, "", false
	}
	if _, needs := spfArgRequired[name]; needs && !hasArg {
		return 0, "", false
	}
	if hasArg && arg == "" {
		return 0, "", false
	}
	if hasCIDR && cidr == "" {
		return 0, "", false
	}
	// "all" takes neither an argument nor a prefix length, so a term like
	// "all:example" or "all/24" is not this mechanism.
	if name == "all" && (hasArg || hasCIDR) {
		return 0, "", false
	}
	return qualifier, name, true
}

// spfTerminalFor maps the qualifier on the terminal "all" to its result.
func spfTerminalFor(qualifier byte) spfPolicy {
	switch qualifier {
	case '-':
		return spfFailAll
	case '~':
		return spfSoftFailAll
	case '?':
		return spfNeutralAll
	default:
		return spfPassAll
	}
}
