package persistence

import (
	"context"
	"fmt"
	"time"

	"github.com/velgard-sk/vanguard/internal/buildid"
	"github.com/velgard-sk/vanguard/internal/projections/surfacereport"
)

// Build reads the collection at collectionDir and writes its complete set of
// artifacts into destination. It is the one entry point for a projection: everything
// below it is a fold or a render, and everything above it is a caller choosing two
// directories.
//
// The two roots are independent parameters and are kept that way. Reading and writing
// are never the same tree, so a failed build cannot damage the collection, and a
// half-written destination cannot be mistaken for the evidence it was folded from.
// [PrepareDestination] refuses a destination that is the collection, sits inside it,
// or contains it, and refuses a non-empty one without touching it.
//
// It is a host-side operation. A collection run never calls it, which is what keeps a
// scan VM free of derived output. It contacts nothing and is deterministic: the same
// collection bytes reproduce the same artifacts, with the sole exception of the
// manifest's own timestamp.
//
// The manifest is written last. Its presence is the claim that everything before it
// succeeded, so a build that fails or is cancelled leaves a destination without one,
// and the fix for that is to empty the destination and build again.
//
// ctx is checked between artifact families rather than inside them. The folds are
// pure functions of the collection, and between families is where stopping is cheap
// and where the record of what was written is still coherent.
func Build(ctx context.Context, collectionDir, destination string, projector buildid.Identity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	manifest, err := ValidateCollection(collectionDir)
	if err != nil {
		return err
	}
	// The manifest's collection verdict is mapped once here and handed to every
	// writer, so the report, the surface artifacts, and the projection manifest state
	// one outcome instead of three derivations of it.
	health, err := SourceHealth(manifest)
	if err != nil {
		return fmt.Errorf("collection %s: %w", collectionDir, err)
	}

	dst, err := PrepareDestination(collectionDir, destination)
	if err != nil {
		return err
	}

	// Entity snapshots, the operator report and its ledgers, and the decoded
	// network-audit view all come from one fold of the event stream plus the packet
	// evidence.
	if err := RebuildDerived(collectionDir, dst, health); err != nil {
		return fmt.Errorf("collection %s: %w", collectionDir, err)
	}
	if err := WriteReadme(dst); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := writeQualityArtifacts(collectionDir, dst); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// One fold, both graph views: the surface is contracted from this graph in
	// memory, never from the facts.json written beside it, so the two artifacts can
	// never come from two different folds of one collection.
	graph, err := BuildFacts(collectionDir)
	if err != nil {
		return err
	}
	if err := WriteFacts(dst, graph); err != nil {
		return err
	}
	surface, err := surfacereport.Contract(graph, health)
	if err != nil {
		return err
	}
	if err := WriteSurface(dst, surface); err != nil {
		return err
	}

	// The manifest is the claim that everything above it is complete, so a cancelled
	// build must not write it: a destination without one is an unfinished build,
	// which is exactly what a cancelled caller is left with.
	if err := ctx.Err(); err != nil {
		return err
	}
	return WriteProjectionManifest(dst, NewProjectionManifest(manifest, projector, time.Now(), health))
}

// writeQualityArtifacts builds the data-quality report and, when a tool-event log
// exists, the tool-health signals. A missing optional log yields content-only
// quality output; a present broken log is an error shared by both consumers.
func writeQualityArtifacts(collectionDir, dst string) error {
	quality, err := BuildDataQuality(collectionDir)
	if err != nil {
		return fmt.Errorf("data-quality report: %w", err)
	}
	if err := WriteDataQuality(dst, &quality); err != nil {
		return fmt.Errorf("data-quality report: %w", err)
	}

	// A collection whose tools wrote nothing has no signals to analyze. That is a
	// quiet run rather than a failure, so no report is written and none is claimed.
	hasSignals, err := hasToolingLog(collectionDir)
	if err != nil {
		return fmt.Errorf("tool-health signals: %w", err)
	}
	if !hasSignals {
		return nil
	}
	signals, err := BuildSignals(SignalsInputs{Scans: []string{collectionDir}})
	if err != nil {
		return fmt.Errorf("tool-health signals: %w", err)
	}
	if err := WriteSignals(dst, &signals); err != nil {
		return fmt.Errorf("tool-health signals: %w", err)
	}
	return nil
}
