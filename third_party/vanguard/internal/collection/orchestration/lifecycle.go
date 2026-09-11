package orchestration

import (
	"context"
	"fmt"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
)

// runLifecycle is the execution shell around one run's scanning work. It performs
// the fail-fast initialization check, selects the scan identity, validates the root,
// emits the ScanStarted and immediate ScanEnvironmentRecorded markers, runs the
// stages, and closes the bracket with ScanCompleted carrying the elapsed duration -
// whatever the stages returned. The stage error is returned unwrapped, never
// swallowed: a failed run is still a closed bracket, but it still reports the
// failure to the caller.
//
// scanID and the lifecycle markers are written before any goroutine the stages
// start, so the identity every later event carries is fixed here once.
func (o *Orchestrator) runLifecycle(ctx context.Context, root string) error {
	if o.initErr != nil {
		return o.initErr
	}
	// The app injects the identity it also records in the capture manifest, so the
	// two provenance records of one collection cannot disagree; a run given none
	// generates its own.
	o.scanID = o.cfg.ScanID
	if o.scanID == "" {
		o.scanID = newScanID()
	}
	startedAt := time.Now()

	if root == "" {
		return fmt.Errorf("failed to create scan: root target must not be empty")
	}

	o.emitLifecycle(ctx, func(at time.Time) events.DomainEvent {
		e := events.ScanStarted{EventMeta: o.newLifecycleMeta(at), RootTarget: root}
		e.EventID = events.NewEventID(at, e)
		return e
	})
	o.emitEnvironment(ctx)

	stageErr := o.runStages(ctx, root)

	o.emitLifecycle(ctx, func(at time.Time) events.DomainEvent {
		e := events.ScanCompleted{
			EventMeta:  o.newLifecycleMeta(at),
			RootTarget: root,
			Duration:   elapsedDuration(startedAt, at),
		}
		e.EventID = events.NewEventID(at, e)
		return e
	})

	return stageErr
}

// checkIPv6Once records the scanner's own IPv6 capability before an execution adds
// any active work. An IPv6-only target is unreachable from an IPv4-only host, and a
// probe against it records an empty result indistinguishable from a clean one, so
// the active schedulers skip such targets with an explicit coverage Issue. It is
// called once per execution, at the point active work is about to be scheduled.
func (o *Orchestrator) checkIPv6Once() {
	o.ipv6Usable = hasIPv6Connectivity()
}

// runTerminalStages runs the terminal stages after the active workers drain, so the
// GoScans substage's own nmap invocation cannot race the port scanner. Each stage is
// individually gated on its own configuration, so a disabled one is a no-op here.
func (o *Orchestrator) runTerminalStages(ctx context.Context) {
	o.goscansPhase(ctx)
}
