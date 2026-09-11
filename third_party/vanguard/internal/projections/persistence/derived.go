package persistence

import (
	"fmt"

	collection "github.com/velgard-sk/vanguard/internal/collection/persistence"
	"github.com/velgard-sk/vanguard/internal/projections"
	"github.com/velgard-sk/vanguard/internal/projections/collectionhealth"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
	"github.com/velgard-sk/vanguard/internal/projections/report"
)

// entitySnapshotKinds are the folded read models written to entities/ below the
// projection destination, in a stable order. Every kind is written on every rebuild, even when empty: a
// missing file would leave a reader unable to tell "none found" from "not
// produced".
var entitySnapshotKinds = []struct {
	kind string
	of   func(*projections.Projection) any
}{
	{"DnsDomainName", func(p *projections.Projection) any { return p.Inventory.SortedDomains() }},
	{"Certificate", func(p *projections.Projection) any { return p.Inventory.SortedCertificates() }},
	{"Issue", func(p *projections.Projection) any { return p.Issues }},
	{"Finding", func(p *projections.Projection) any { return p.Findings.Sorted() }},
	{"IPAddress", func(p *projections.Projection) any { return p.Inventory.SortedIPs() }},
	{"Netblock", func(p *projections.Projection) any { return p.Inventory.SortedNetblocks() }},
	{"Service", func(p *projections.Projection) any { return p.Inventory.SortedServices() }},
	{"Endpoint", func(p *projections.Projection) any { return p.Inventory.SortedEndpoints() }},
}

// WriteEntitySnapshots writes the folded read models into the destination's
// entities/ bucket as indented JSON in stable sort order. The canonical event log stays the
// source of truth; these are a browsable snapshot of one fold of it, so they are
// rewritten whole rather than patched.
//
// dst is the exact projection root the caller asked the build to write.
func WriteEntitySnapshots(dst string, proj *projections.Projection) error {
	for _, e := range entitySnapshotKinds {
		if err := writeJSON(dst, entitiesBucket, "entity_"+e.kind+".json", e.of(proj)); err != nil {
			return err
		}
	}
	return nil
}

// RebuildDerived rebuilds the derived artifacts a collection's own streams determine:
// the entity snapshots, the operator report and its issue, temporal-anomaly, and
// threat-scenario companions, and the decoded network-audit projection. It reads
// only from the collection root - the canonical event log, collection manifest,
// config snapshots, tool-event log, and packet captures - and writes only into the
// explicit projection destination, so it runs offline, contacts nothing, and is
// deterministic: the same collection bytes reproduce the same files.
//
// The two roots are separate parameters. Reading and writing are never the same
// tree, so a half-finished
// projection cannot be mistaken for a complete one and a failed one cannot damage
// the capture.
//
// It is a host-side operation. A collection run never calls it, which is what keeps
// a scan VM free of projection output.
//
// health is the collection outcome, mapped once from the validated collection
// manifest by the caller through [SourceHealth] and passed in because this function
// must not derive a second opinion about it from the streams it folds. It is nil only
// for a caller with no manifest, and the report then states nothing about source
// completeness.
//
// A capture-ingestion problem yields a failed or inconclusive network-audit section
// rather than an abandoned report; only an inability to write a file is returned as
// an error.
func RebuildDerived(capture, projected string, health *collectionhealth.Summary) error {
	evts, err := collection.LoadEvents(capture)
	if err != nil {
		return err
	}
	proj := projections.NewProjection()
	var scan entities.Scan
	for _, evt := range evts {
		proj.ApplyDomain(evt)
		captureScan(&scan, evt)
	}
	if scan.ID == "" {
		return fmt.Errorf("no ScanStarted event in %s: cannot rebuild the derived artifacts", collection.EventsLogPath(capture))
	}
	a, err := AnalysisContext(evts)
	if err != nil {
		return err
	}
	if err := WriteEntitySnapshots(projected, &proj); err != nil {
		return err
	}
	model, raw := buildNetAudit(capture, evts)
	a.NetAudit = model
	// The collection verdict is mapped once by the caller from the validated capture
	// manifest and carried in, so the report states the manifest's outcome rather than
	// a weaker one reconstructed from the streams folded above.
	a.SourceCollection = health
	if err := writeReportArtifacts(projected, &proj, scan, a); err != nil {
		return err
	}
	return writeNetAuditProjection(projected, raw)
}

// writeReportArtifacts writes report.md/report.json plus the complete
// issues.md/json, temporal-anomalies.md/json, and threat-scenarios.md/json
// artifacts beside it, given a folded projection,
// the scan identity, and the analysis context (including the network-audit model).
func writeReportArtifacts(dst string, proj *projections.Projection, scan entities.Scan, a report.Analysis) error {
	rpt := report.BuildReport(proj, scan, a)
	if err := writeFile(dst, reportsBucket, reportMD, []byte(rpt.Markdown())); err != nil {
		return err
	}
	if err := writeJSON(dst, reportsBucket, reportJSON, rpt); err != nil {
		return err
	}

	// Every ledger is written whole, always, even when empty. The compact operator
	// report links to each of them - to the issue ledger whenever it omits
	// lower-priority rows, and to the threat ledger unconditionally - so a missing
	// file would leave a reader unable to tell "nothing to report" from "not
	// produced", or leave a link broken rather than empty.
	issues := rpt.IssueLedger()
	if err := writeFile(dst, reportsBucket, issuesMD, []byte(issues.Markdown())); err != nil {
		return err
	}
	if err := writeJSON(dst, reportsBucket, issuesJSON, issues); err != nil {
		return err
	}

	anomalies := rpt.TemporalAnomalies()
	if err := writeFile(dst, reportsBucket, anomaliesMD, []byte(anomalies.Markdown())); err != nil {
		return err
	}
	if err := writeJSON(dst, reportsBucket, anomaliesJSON, anomalies); err != nil {
		return err
	}

	scenarios := rpt.ThreatLedger()
	if err := writeFile(dst, reportsBucket, threatsMD, []byte(scenarios.Markdown())); err != nil {
		return err
	}
	return writeJSON(dst, reportsBucket, threatsJSON, scenarios)
}
