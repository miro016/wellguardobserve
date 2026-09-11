package tooleventlog

import (
	"context"
	"log/slog"
)

// Event is implemented by every tool event struct.
// Typed events replace direct slog calls in tool actors.
type Event interface {
	// ToolName returns the tool identifier (e.g., "crtsh").
	ToolName() string
	// EventName returns a short human-readable label (e.g., "crtsh: network error").
	EventName() string
	// EventLevel returns the log severity.
	EventLevel() slog.Level
	// EventAttrs returns the structured key-value pairs for logging and display.
	EventAttrs() []slog.Attr
}

// HealthProblem describes collection work that a tool attempted but could not
// complete. Code is a stable machine-readable identifier owned by the producer.
// Component optionally identifies a bounded provider or module. Target and
// SafeDetail are live-display fields and must not contain credentials, response
// bodies, or arbitrary error text.
type HealthProblem struct {
	// Code is the stable lower-case dotted identity owned by the producer.
	Code string
	// Component optionally identifies a bounded provider or module.
	Component string
	// Target identifies the affected domain, address, or URL for live display.
	Target string
	// SafeDetail is optional producer-written context safe for live display.
	SafeDetail string
}

// HealthEvent is implemented only by events with an explicit collection-health
// meaning. CollectionHealth returns false for a health-aware terminal event whose
// concrete outcome was healthy.
type HealthEvent interface {
	Event
	CollectionHealth() (HealthProblem, bool)
}

// EventSink receives events emitted by a tool actor.
// A nil EventSink is safe: Emit is a no-op.
type EventSink interface {
	Emit(ctx context.Context, e Event)
}
