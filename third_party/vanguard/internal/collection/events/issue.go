package events

import (
	"fmt"
	"time"
)

var _ DomainEvent = IssueObserved{}

// IssueObserved signals that a failure or error occurred during domain operations.
type IssueObserved struct {
	EventMeta
	// Query or domain being processed when the issue occurred.
	Query string
	// Error message or description of the issue.
	Error string
	// Payload holds the raw JSON payload of the triggering system event.
	Payload string
	// Class names what kind of issue this is, in the producer's own words, so a
	// reader is not left inferring it from the source. "coverage" and "timeout"
	// mean a target went unmeasured and the result is short, not clean; everything
	// else means a tool broke and the target is unaffected.
	//
	// It exists because the source is too coarse for a tool that produces both. A
	// scanner that reports an unreachable host and a missing dependency under one
	// name cannot be bucketed by name alone, and calling the unreachable host a
	// "tool error" tells the reader the opposite of what happened. An empty value
	// means the producer did not classify, and the reader falls back to the source.
	//
	// Control-plane decisions (scope and budget gates) set one of the IssueClass*
	// constants below so scope accounting can count each decision kind from the
	// canonical stream without parsing free-text messages.
	Class string
}

// Control-plane issue classes. A scope/budget gate stamps one of these on the
// IssueObserved it emits so a reader (and the report's scope accounting) can
// distinguish the decision kinds that all share Source "scope" or "budget",
// without inferring intent from the message text.
const (
	// IssueClassScopeSchedule is a name skipped at scheduling scope: the passive
	// fan-out or active probe was withheld because the name is out of engagement
	// scope. Emitted once per name.
	IssueClassScopeSchedule = "scope-schedule"
	// IssueClassScopeRedirect is a redirect destination rejected before contact.
	// Emitted once per normalized (source host, destination host) pair.
	IssueClassScopeRedirect = "scope-redirect"
	// IssueClassBudget is an active or paid target refused because a budget cap was
	// reached. Emitted once per capped tool or stage.
	IssueClassBudget = "budget"
	// IssueClassProviderApproved is a provider-only host admitted to active probing
	// by ownership policy. Emitted once per host.
	IssueClassProviderApproved = "provider-approved"
	// IssueClassProviderSkipped is a provider-only host withheld from active probing
	// by ownership policy. Emitted once per host.
	IssueClassProviderSkipped = "provider-skipped"
	// IssueClassExclusion is an active target denied by a hard engagement exclusion
	// (scope.domains.exclude or scope.ip_ranges.exclude). It is a boundary the deny
	// wins over root/include membership, prior approval, provider corroboration, and
	// budget. Emitted once per (target kind, normalized target, matched rule); it is
	// never a network failure or an unreachability result.
	IssueClassExclusion = "exclusion"
)

// At returns the capture time recorded in the event envelope.
func (e IssueObserved) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e IssueObserved) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e IssueObserved) String() string {
	return fmt.Sprintf("issue observed (%s) for %q: %s (triggering event: %s)",
		e.Meta().Severity, e.Query, e.Error, e.Meta().CausationID)
}

func (IssueObserved) isDomainEvent() {}
