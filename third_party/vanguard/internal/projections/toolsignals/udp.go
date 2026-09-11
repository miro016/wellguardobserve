package toolsignals

import (
	"fmt"
	"sort"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

// The UDP pass is the one portscan call whose honest result can look like a broken
// one. It reports a verdict for every port it probed, and on a healthy host none of
// those verdicts is "open": a zero-service UDP pass is a clean pass, not a failed
// call. The live rollup already knows that. What it cannot know, because it watches
// a bounded window while the scan runs, is whether the pass's own accounting adds
// up across the whole capture - and that is what these diagnostics are for.
//
// Everything here reads the immutable tool-event log offline. A signal raised here
// says the recorded evidence about a pass is internally inconsistent; it never says
// the target behaved one way or another.

// UDP portscan event names, as the portscan tool emits them. They are matched as
// strings because the analyzer reads a log written by an earlier build and must not
// depend on the tool package's current types.
const (
	udpStartedName    = "portscan: udp scan started"
	udpCompletedName  = "portscan: udp scan completed"
	udpCancelledName  = "portscan: udp scan cancelled"
	udpErrorName      = "portscan: udp scan error"
	udpPermDeniedName = "portscan: udp permission denied"
)

// UDP diagnostic evidence keys, named once so the JSON evidence shape stays
// consistent across the detectors.
const (
	evUDPAccounted  = "accounted"
	evUDPTotalPorts = "totalPorts"
)

// UDP completion attribute keys.
const (
	udpAttrProtocol     = "protocol"
	udpAttrPorts        = "ports"
	udpAttrTotalPorts   = "total_ports"
	udpAttrOpen         = "open"
	udpAttrOpenFiltered = "open_filtered"
	udpAttrClosed       = "closed"
	udpAttrFiltered     = "filtered"
	udpAttrAccounted    = "accounted"
	udpAttrPartial      = "partial"
)

// UDPPass is one correlated UDP portscan pass folded from the log: whether it
// started, which terminal events it reached, and what its completion accounted for.
// One pass per CorrID; the orchestrator gives the UDP pass its own correlation id,
// separate from the TCP pass on the same host.
type UDPPass struct {
	// CorrID is the correlation id joining the pass's events.
	CorrID string `json:"corrID"`
	// Target is the host the pass probed, as the log attributed it.
	Target string `json:"target"`
	// Started is true when the pass emitted its started event. A pass with a
	// completion but no start is a torn sequence, not a healthy call.
	Started bool `json:"started"`
	// StartedPorts is the port count the started event announced, -1 when absent.
	StartedPorts int64 `json:"startedPorts"`
	// Completions, Cancellations, Errors and PermissionDenials count the pass's
	// terminal events by kind. A healthy pass settles once - it completed, or it was
	// cancelled - and fails at most once. The one shape that carries both is a
	// partial result: a completion that kept the evidence it had, beside the error
	// event naming what it lost.
	Completions       int `json:"completions"`
	Cancellations     int `json:"cancellations"`
	Errors            int `json:"errors"`
	PermissionDenials int `json:"permissionDenials"`
	// The fields below come from the completion event and are -1 when it carried no
	// such attribute or when there was no completion at all.
	TotalPorts   int64 `json:"totalPorts"`
	Open         int64 `json:"open"`
	OpenFiltered int64 `json:"openFiltered"`
	Closed       int64 `json:"closed"`
	Filtered     int64 `json:"filtered"`
	Accounted    int64 `json:"accounted"`
	// Partial is the completion's own claim that it kept evidence from a pass that
	// then failed.
	Partial bool `json:"partial"`
}

// settlements is how many times the pass reported its own outcome: it completed, or
// it was cancelled. Exactly one is healthy.
func (p *UDPPass) settlements() int { return p.Completions + p.Cancellations }

// failures is how many local scanner failures the pass recorded. A cancellation is
// not one: an interrupted run is the capture manifest's to describe.
func (p *UDPPass) failures() int { return p.Errors + p.PermissionDenials }

// failed reports whether the pass recorded a local scanner failure.
func (p *UDPPass) failed() bool { return p.failures() > 0 }

// unterminated reports whether the pass never said how it ended, in either form.
func (p *UDPPass) unterminated() bool { return p.settlements() == 0 && p.failures() == 0 }

// duplicateTerminal reports whether the log claims the pass ended more than once.
// A partial completion beside one failure event is NOT that: it is the documented
// shape of a pass that kept the evidence it had and then lost the rest, and the two
// events describe the two halves of one outcome. Two completions, or two failures,
// are a genuine duplicate.
func (p *UDPPass) duplicateTerminal() bool { return p.settlements() > 1 || p.failures() > 1 }

// stateSum is the number of ports the completion assigned a state to. It is the
// figure that must reconcile with the accounted count.
func (p *UDPPass) stateSum() int64 {
	return p.Open + p.OpenFiltered + p.Closed + p.Filtered
}

// isUDPPassEvent reports whether an envelope belongs to a UDP portscan pass. The
// protocol attribute is the primary test, because every UDP event carries it; the
// name check catches an event whose attrs were dropped.
func isUDPPassEvent(env *tooleventlog.ToolEventEnvelope) bool {
	if proto, ok := env.Attrs[udpAttrProtocol].(string); ok && proto == "udp" {
		return true
	}
	switch env.Name {
	case udpStartedName, udpCompletedName, udpCancelledName, udpErrorName, udpPermDeniedName:
		return true
	default:
		return false
	}
}

// foldUDPPass folds one envelope into its pass. An uncorrelated UDP event
// contributes nothing: without a correlation id there is no pass to attribute it
// to, and the missing-corr signal already reports that class of defect.
func foldUDPPass(passes map[string]*UDPPass, env *tooleventlog.ToolEventEnvelope) {
	if env.CorrID == "" || !isUDPPassEvent(env) {
		return
	}
	p := passes[env.CorrID]
	if p == nil {
		p = &UDPPass{
			CorrID: env.CorrID, Target: env.Target, StartedPorts: -1,
			TotalPorts: -1, Open: -1, OpenFiltered: -1, Closed: -1, Filtered: -1, Accounted: -1,
		}
		passes[env.CorrID] = p
	}
	if p.Target == "" {
		p.Target = env.Target
	}
	switch env.Name {
	case udpStartedName:
		p.Started = true
		p.StartedPorts = udpAttrInt(env, udpAttrPorts)
	case udpCompletedName:
		p.Completions++
		p.TotalPorts = udpAttrInt(env, udpAttrTotalPorts)
		p.Open = udpAttrInt(env, udpAttrOpen)
		p.OpenFiltered = udpAttrInt(env, udpAttrOpenFiltered)
		p.Closed = udpAttrInt(env, udpAttrClosed)
		p.Filtered = udpAttrInt(env, udpAttrFiltered)
		p.Accounted = udpAttrInt(env, udpAttrAccounted)
		if partial, ok := env.Attrs[udpAttrPartial].(bool); ok {
			p.Partial = partial
		}
	case udpCancelledName:
		p.Cancellations++
	case udpErrorName:
		p.Errors++
	case udpPermDeniedName:
		p.PermissionDenials++
	}
}

// udpAttrInt reads a numeric attribute, returning -1 when it is absent or not a
// number. JSON decoding yields float64 while a freshly built envelope yields int64,
// so both are accepted.
func udpAttrInt(env *tooleventlog.ToolEventEnvelope, key string) int64 {
	switch n := env.Attrs[key].(type) {
	case int64:
		return n
	case float64:
		return int64(n)
	case int:
		return int64(n)
	default:
		return -1
	}
}

// sortedUDPPasses orders the folded passes by (target, corrID) so the analyzer's
// output does not depend on log order.
func sortedUDPPasses(passes map[string]*UDPPass) []UDPPass {
	out := make([]UDPPass, 0, len(passes))
	for _, p := range passes {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		return out[i].CorrID < out[j].CorrID
	})
	return out
}

// udpFinding builds one UDP diagnostic, keyed on the portscan tool and the pass's
// target so it groups across scans the way every other signal does.
func udpFinding(id string, sev Severity, p UDPPass, summary string, evidence map[string]any) Finding {
	evidence["corrID"] = p.CorrID
	return Finding{ID: id, Severity: sev, Tool: udpTool, Target: p.Target, Summary: summary, Evidence: evidence}
}

// udpTool is the tool every UDP diagnostic is filed under. The UDP pass is part of
// the port scanner, so its signals group with the rest of that tool's.
const udpTool = "portscan"

// detectUDPPassTerminal fires when a pass's start and terminal events do not pair
// up: a started pass with no terminal at all, or one the log says finished more than
// once. Either way the pass's own record of itself is broken, so no count derived
// from it can be trusted. High severity: this is a scanner or log defect, never a
// property of the target.
func detectUDPPassTerminal(sd ScanData, _ Config) []Finding {
	var out []Finding
	for _, p := range sd.UDPPasses {
		switch {
		case p.unterminated():
			out = append(out, udpFinding(SigUDPPassTerminalMissing, SeverityHigh, p,
				fmt.Sprintf("udp pass on %s started and never reached a terminal event", p.Target),
				map[string]any{"startedPorts": p.StartedPorts}))
		case p.duplicateTerminal():
			out = append(out, udpFinding(SigUDPPassTerminalDuplicate, SeverityHigh, p,
				fmt.Sprintf("udp pass on %s reported its outcome more than once (%d settlement(s), %d failure(s))",
					p.Target, p.settlements(), p.failures()),
				map[string]any{
					"completions": p.Completions, "cancellations": p.Cancellations,
					"errors": p.Errors, "permissionDenials": p.PermissionDenials,
				}))
		case !p.Started:
			out = append(out, udpFinding(SigUDPPassTerminalMissing, SeverityHigh, p,
				fmt.Sprintf("udp pass on %s reached a terminal event with no start", p.Target),
				map[string]any{"completions": p.Completions}))
		}
	}
	return out
}

// detectUDPPortAccounting fires when a completion's numbers do not add up: the
// per-state counts must sum to the accounted count, and a pass that claims to be
// complete must have accounted for every port it was asked about. A pass that lost
// work says so with Partial, and that case is checked against its error event by
// detectUDPPartialEvidence rather than counted as a mismatch here.
func detectUDPPortAccounting(sd ScanData, _ Config) []Finding {
	var out []Finding
	for _, p := range sd.UDPPasses {
		if p.Completions != 1 || p.Accounted < 0 || p.TotalPorts < 0 {
			// No single completion, or a completion that carried no counts: the
			// terminal detector already reports the first and there is nothing to
			// reconcile in the second.
			continue
		}
		if sum := p.stateSum(); sum != p.Accounted {
			out = append(out, udpFinding(SigUDPPortAccountingMismatch, SeverityMedium, p,
				fmt.Sprintf("udp pass on %s assigned %d port state(s) but accounted for %d", p.Target, sum, p.Accounted),
				map[string]any{
					"open": p.Open, "openFiltered": p.OpenFiltered, "closed": p.Closed,
					"filtered": p.Filtered, evUDPAccounted: p.Accounted,
				}))
			continue
		}
		if !p.Partial && p.Accounted != p.TotalPorts {
			out = append(out, udpFinding(SigUDPPortAccountingMismatch, SeverityMedium, p,
				fmt.Sprintf("udp pass on %s claims a complete result but accounted for %d of %d requested port(s)",
					p.Target, p.Accounted, p.TotalPorts),
				map[string]any{evUDPAccounted: p.Accounted, evUDPTotalPorts: p.TotalPorts, "partial": p.Partial}))
		}
	}
	return out
}

// detectUDPPartialEvidence fires on the two ways a pass can disagree with itself
// about whether it lost work: a partial completion with no error event to say what
// was lost, and an error event on a pass whose completion claims it covered
// everything. Both leave a reader unable to tell how much of the requested coverage
// actually happened, which is the one thing a partial result exists to communicate.
func detectUDPPartialEvidence(sd ScanData, _ Config) []Finding {
	var out []Finding
	for _, p := range sd.UDPPasses {
		if p.Completions != 1 {
			continue
		}
		switch {
		case p.Partial && !p.failed():
			out = append(out, udpFinding(SigUDPPartialWithoutError, SeverityHigh, p,
				fmt.Sprintf("udp pass on %s reported a partial result with no error event naming the loss", p.Target),
				map[string]any{evUDPAccounted: p.Accounted, evUDPTotalPorts: p.TotalPorts}))
		case p.failed() && !p.Partial && p.Accounted >= 0 && p.Accounted == p.TotalPorts:
			out = append(out, udpFinding(SigUDPErrorWithCompleteSuccess, SeverityHigh, p,
				fmt.Sprintf("udp pass on %s emitted an error event yet its completion claims full coverage of %d port(s)",
					p.Target, p.TotalPorts),
				map[string]any{
					"errors": p.Errors, "permissionDenials": p.PermissionDenials,
					evUDPAccounted: p.Accounted, evUDPTotalPorts: p.TotalPorts,
				}))
		}
	}
	return out
}
