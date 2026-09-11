package tooleventlog

import "context"

// correlation is the per-call correlation context carried on a ctx passed to a
// tool. The orchestrator sets it around each tool invocation; PersistSink reads
// it when stamping an envelope. All fields are optional and additive: an event
// emitted without any correlation still persists with just its tool, name, and
// level.
type correlation struct {
	// scanID correlates the event back to the domain-event stream.
	scanID string
	// phase is the recon phase the tool runs in (passive | active).
	phase string
	// target is the domain / host / IP / URL the call concerns.
	target string
	// corrID ties every tool event of a single tool invocation together, and to
	// the domain events the orchestrator derives from that call's result.
	corrID string
}

type scanKey struct{}
type phaseKey struct{}
type targetKey struct{}
type corrIDKey struct{}

// WithScan returns a child context tagging the scan and the recon phase a tool
// runs in. The orchestrator sets it once the ScanID is known; PersistSink reads
// it to correlate every tool event back to the scan.
func WithScan(ctx context.Context, scanID, phase string) context.Context {
	ctx = context.WithValue(ctx, scanKey{}, scanID)
	return context.WithValue(ctx, phaseKey{}, phase)
}

// WithTarget returns a child context tagging the target a tool call concerns
// (domain, host, or IP). It lets PersistSink stamp Target even when the event
// attributes do not carry it.
func WithTarget(ctx context.Context, target string) context.Context {
	return context.WithValue(ctx, targetKey{}, target)
}

// WithCorrID returns a child context tagging the per-invocation correlation id.
// The orchestrator sets it around a single tool call so PersistSink stamps the id
// on every tool event the call emits, and stamps the same id onto the domain
// events it derives from the call's result (events.EventMeta.ToolCorrID).
func WithCorrID(ctx context.Context, corrID string) context.Context {
	return context.WithValue(ctx, corrIDKey{}, corrID)
}

// CorrIDFrom reads the per-invocation correlation id stamped on ctx, or "" when
// none is set. The orchestrator uses it to stamp ToolCorrID on derived events.
func CorrIDFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(corrIDKey{}).(string); ok {
		return v
	}
	return ""
}

// TargetFrom reads the target stamped on ctx by WithTarget, or "" when none is set.
// It mirrors CorrIDFrom so a caller (or a test) can read back the target a tool call
// was tagged with.
func TargetFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(targetKey{}).(string); ok {
		return v
	}
	return ""
}

// correlationFrom reads the correlation fields stamped on ctx. Missing fields
// come back empty.
func correlationFrom(ctx context.Context) correlation {
	var c correlation
	if ctx == nil {
		return c
	}
	if v, ok := ctx.Value(scanKey{}).(string); ok {
		c.scanID = v
	}
	if v, ok := ctx.Value(phaseKey{}).(string); ok {
		c.phase = v
	}
	c.target = TargetFrom(ctx)
	c.corrID = CorrIDFrom(ctx)
	return c
}
