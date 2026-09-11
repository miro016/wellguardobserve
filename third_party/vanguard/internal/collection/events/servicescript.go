package events

import (
	"fmt"
	"time"
)

var _ DomainEvent = ServiceScriptObserved{}

// ScriptParseStatus states what a producer managed to make of a script's output.
// It exists so an unparsed script is visibly unparsed: without it, a consumer
// reading empty structured values cannot tell "the script found nothing" from "no
// one has written a parser for this script".
type ScriptParseStatus string

const (
	// ScriptParseNone means no reviewed parser exists for this script, so the
	// output is evidence only. It is the default: an unknown script is retained as
	// text and never guessed at.
	ScriptParseNone ScriptParseStatus = "none"
	// ScriptParseOK means a reviewed parser handled the output.
	ScriptParseOK ScriptParseStatus = "ok"
	// ScriptParseFailed means a reviewed parser exists but could not read this
	// output. That is a defect worth seeing, not a quiet fallback to raw text.
	ScriptParseFailed ScriptParseStatus = "failed"
)

// ServiceScriptObserved carries one host or service script result, such as an nmap
// NSE script. It is deliberately evidence rather than a verdict: a script result is
// text a scanner collected, and turning any particular script into a finding is a
// separate, reviewed decision. An unrecognised script is still recorded, because
// evidence nobody parses yet is worth more than evidence nobody kept.
//
// The output is bounded by the producer, which also reports the original size and a
// digest, so two scans can be compared for change without either storing the full
// text or pretending the stored excerpt is complete.
type ServiceScriptObserved struct {
	EventMeta
	// IP is the host the script ran against.
	IP string
	// Port is the service port, 0 for a host-scope script. Protocol is the
	// transport for a port-scope script, empty for a host-scope one. Scope states
	// which of the two this is, so a consumer never has to infer it from a zero
	// port.
	Port     int
	Protocol string
	Scope    string
	// Script is the script identifier, for example "ssl-enum-ciphers".
	Script string
	// Values are structured key/value pairs a reviewed parser extracted, sorted by
	// key. Empty unless ParseStatus is "ok".
	Values []ScriptValue
	// Output is the redacted, bounded script output.
	Output string
	// RawBytes is the output size before bounding, and Digest a hash of the full
	// raw output. Truncated marks output that did not fit.
	RawBytes  int
	Digest    string
	Truncated bool
	// ParseStatus states whether a reviewed parser handled the output.
	ParseStatus ScriptParseStatus
}

// ScriptValue is one structured value a reviewed script parser extracted.
type ScriptValue struct {
	// Key names the extracted value within the script's own vocabulary.
	Key string
	// Value is the extracted value, already bounded and redacted by the producer.
	Value string
}

// At returns the capture time recorded in the event envelope.
func (e ServiceScriptObserved) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e ServiceScriptObserved) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e ServiceScriptObserved) String() string {
	if e.Port == 0 {
		return fmt.Sprintf("script %s on %s", e.Script, e.IP)
	}
	return fmt.Sprintf("script %s on %s:%d", e.Script, e.IP, e.Port)
}

func (ServiceScriptObserved) isDomainEvent() {}
