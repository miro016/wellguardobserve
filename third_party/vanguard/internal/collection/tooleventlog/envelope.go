package tooleventlog

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
)

// SchemaVersion is the version stamped on every persisted tool-event envelope.
// It mirrors events.SchemaVersion for domain events: bump it when the envelope
// shape changes so readers can migrate older tooling.jsonl logs.
const SchemaVersion = 1

// ToolEventEnvelope is the structured, correlated, persisted wrapper written for
// every tool event in the canonical tooling.jsonl log. It is the tool-event
// analogue of the domain-event envelope: it carries enough correlation (ScanID,
// tool, phase, target, sequence, time) to reconstruct what a provider did, when,
// and on whose behalf, fully offline from the persisted stream alone.
type ToolEventEnvelope struct {
	// Version is the envelope schema version (SchemaVersion at write time).
	Version int `json:"version"`
	// Seq is a monotonic per-scan sequence for ordering and gap detection.
	Seq int64 `json:"seq"`
	// ScanID correlates the event back to the domain-event stream.
	ScanID string `json:"scanID,omitempty"`
	// Tool is the emitting tool's identifier (e.EventName's tool, e.ToolName()).
	Tool string `json:"tool"`
	// Name is the human-readable event label (e.EventName()).
	Name string `json:"name"`
	// Level is the rendered severity (debug/info/warn/error).
	Level string `json:"level"`
	// Phase is the recon phase that produced the event (passive | active).
	Phase string `json:"phase,omitempty"`
	// Target is the domain / host / IP / URL the event concerns, when known.
	Target string `json:"target,omitempty"`
	// At is the emit time.
	At time.Time `json:"at"`
	// Attrs is the flattened EventAttrs(), including any raw payloads.
	Attrs map[string]any `json:"attrs,omitempty"`
	// CorrID ties every tool event of a single tool invocation together. The
	// orchestrator stamps the same id onto the domain events it derives from the
	// call's result (events.EventMeta.ToolCorrID), so an audit can join a finding
	// in events.jsonl back to the exact provider response in tooling.jsonl. Empty
	// for events emitted outside a correlated tool call.
	CorrID string `json:"corrID,omitempty"`
}

// buildEnvelope assembles a ToolEventEnvelope from a tool event, the monotonic
// sequence, and the correlation carried on the call (scanID, phase, target,
// corrID). The target is taken from the correlation when set, otherwise lifted
// from the event attributes by the well-known key convention.
func buildEnvelope(seq int64, corr correlation, at time.Time, e Event) ToolEventEnvelope {
	attrs := flattenAttrs(e.EventAttrs())
	target := corr.target
	if target == "" {
		target = targetFromAttrs(attrs)
	}
	return ToolEventEnvelope{
		Version: SchemaVersion,
		Seq:     seq,
		ScanID:  corr.scanID,
		Tool:    e.ToolName(),
		Name:    e.EventName(),
		Level:   levelString(e.EventLevel()),
		Phase:   corr.phase,
		Target:  target,
		At:      at,
		Attrs:   attrs,
		CorrID:  corr.corrID,
	}
}

// EncodeEnvelope marshals a tool-event envelope to a single JSON line, intended
// to be written as one line of the canonical tooling.jsonl log.
func EncodeEnvelope(env *ToolEventEnvelope) ([]byte, error) {
	b, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal tool event envelope: %w", err)
	}
	return b, nil
}

// DecodeEnvelope reverses EncodeEnvelope. The envelope is self-describing (Attrs
// is a generic map), so no type registry is needed.
func DecodeEnvelope(line []byte) (ToolEventEnvelope, error) {
	var env ToolEventEnvelope
	if err := json.Unmarshal(line, &env); err != nil {
		return ToolEventEnvelope{}, fmt.Errorf("unmarshal tool event envelope: %w", err)
	}
	return env, nil
}

// targetKeys are the attribute keys, in priority order, that name the target a
// tool event concerns. The first present key wins.
var targetKeys = []string{"domain", "host", "url", "ip"}

// targetFromAttrs lifts the target from the flattened attributes by the
// well-known key convention, returning "" if none is present.
func targetFromAttrs(attrs map[string]any) string {
	for _, k := range targetKeys {
		if v, ok := attrs[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// flattenAttrs walks a tool event's []slog.Attr into a JSON-friendly map,
// resolving each value to a concrete Go type. Groups are flattened into nested
// maps so the structure is preserved.
func flattenAttrs(attrs []slog.Attr) map[string]any {
	if len(attrs) == 0 {
		return nil
	}
	out := make(map[string]any, len(attrs))
	for _, a := range attrs {
		out[a.Key] = attrValue(a.Value)
	}
	return out
}

// attrValue resolves a slog.Value into a concrete Go value suitable for JSON.
func attrValue(v slog.Value) any {
	v = v.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return v.String()
	case slog.KindInt64:
		return v.Int64()
	case slog.KindUint64:
		return v.Uint64()
	case slog.KindFloat64:
		return v.Float64()
	case slog.KindBool:
		return v.Bool()
	case slog.KindDuration:
		return v.Duration().String()
	case slog.KindTime:
		return v.Time()
	case slog.KindGroup:
		group := v.Group()
		m := make(map[string]any, len(group))
		for _, a := range group {
			m[a.Key] = attrValue(a.Value)
		}
		return m
	default:
		// A string list stays a list so the log keeps a machine-readable array (the
		// excluded addresses behind one rejection, for example) rather than a Go-
		// formatted "[a b]" that a reader would have to parse back.
		if list, ok := v.Any().([]string); ok {
			return list
		}
		// KindAny and anything else: render via the slog representation so errors
		// and arbitrary payloads (the raw-response convention) are captured.
		return v.String()
	}
}

// Level tokens as rendered into and read back from the envelope.
const (
	levelDebug = "debug"
	levelInfo  = "info"
	levelWarn  = "warn"
	levelError = "error"
)

// levelString renders a slog.Level as the lowercase token used in the envelope.
func levelString(l slog.Level) string {
	switch {
	case l < slog.LevelInfo:
		return levelDebug
	case l < slog.LevelWarn:
		return levelInfo
	case l < slog.LevelError:
		return levelWarn
	default:
		return levelError
	}
}
