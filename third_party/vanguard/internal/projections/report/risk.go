package report

import (
	"sort"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// topRiskAssetsCap bounds how many assets the risk view details.
const topRiskAssetsCap = 10

// severityWeight maps a finding severity to its numeric risk contribution. It is a
// transparent, deliberately coarse scale (printed in the report) so the score is
// explainable, not a black box. The jumps widen with severity so a single critical
// outranks several lows.
var severityWeight = map[int]int{
	int(events.SeverityInfo):     0,
	int(events.SeverityLow):      1,
	int(events.SeverityMedium):   3,
	int(events.SeverityHigh):     7,
	int(events.SeverityCritical): 15,
}

// RiskBand is the overall risk posture label for the customer.
type RiskBand string

// Risk bands, from least to most severe overall posture.
const (
	RiskLow      RiskBand = "low"
	RiskMedium   RiskBand = "medium"
	RiskHigh     RiskBand = "high"
	RiskCritical RiskBand = "critical"
)

// AssetFinding is a finding's contribution to an asset's risk score.
type AssetFinding struct {
	Rule           string `json:"rule"`
	Title          string `json:"title"`
	Severity       int    `json:"severity"`
	Weight         int    `json:"weight"`         // effective weight, after the confidence and known-exploited factors
	Confidence     string `json:"confidence"`     // "confirmed" or "inferred"
	KnownExploited bool   `json:"knownExploited"` // CVE is in the known-exploited snapshot
	// TemporalStatus and TemporalReason state whether the evidence behind this
	// contribution is current, historical, mixed, or unknown, and why. They stay
	// separate from Confidence on purpose: the two can disagree.
	TemporalStatus string `json:"temporalStatus"`
	TemporalReason string `json:"temporalReason,omitempty"`
}

// historicalPercent and unknownPercent are the temporal-relevance adjustments, expressed
// as percentages so a coarse integer weight can be scaled without floats.
//
// Temporal relevance is a third, independent input beside severity and confidence,
// because it answers a question neither does. Confidence asks how much to trust the
// source; temporal relevance asks whether the evidence still describes the estate. A
// high-confidence finding resting on a year-old provider banner is trustworthy and
// possibly no longer true.
//
// Historical-only evidence is heavily discounted but never zeroed: the finding stays in
// the ledger and keeps contributing, because having seen something once is a real lead.
// Unknown currentness is discounted only lightly, because the conservative reading is
// that we have no idea; treating unknown like historical would quietly clear findings
// nobody has re-observed.
const (
	historicalPercent = 25
	unknownPercent    = 75
)

// temporalWeight scales a weight by the finding's temporal status. Current and mixed
// evidence keeps full weight: mixed means something current does support the finding, and
// the historical half of it is reported separately rather than discounted away.
func temporalWeight(base int, status entities.TemporalStatus) int {
	switch status {
	case entities.TemporalStatusHistorical:
		return scalePercent(base, historicalPercent)
	case entities.TemporalStatusUnknown:
		return scalePercent(base, unknownPercent)
	case entities.TemporalStatusCurrent, entities.TemporalStatusMixed:
		return base
	}
	return base
}

// scalePercent scales a coarse integer weight, rounding up so a low-severity finding
// never silently reaches zero and drops out of the score.
func scalePercent(base, percent int) int {
	if base <= 0 {
		return base
	}
	if w := (base*percent + 99) / 100; w > 0 {
		return w
	}
	return 1
}

// inferredWeight scales an inferred finding's severity weight down so it does not
// outrank a confirmed finding of the same severity. It is a deliberately simple,
// printed halving (rounded up so a low still counts), consistent with the
// transparent severity-weight table.
func inferredWeight(base int) int {
	return (base + 1) / 2
}

// effectiveWeight is a finding's risk weight after applying the confidence factor
// (a confirmed finding keeps its full severity weight, an inferred one is
// down-weighted), the known-exploited factor (a CVE exploited in the wild is
// doubled so it outranks an equal-severity finding with no known exploit), and the
// temporal-relevance factor. All adjustments are simple, printed multipliers so the
// score stays explainable.
func effectiveWeight(severity int, c entities.Confidence, knownExploited bool,
	temporal entities.TemporalStatus) int {
	w := severityWeight[severity]
	if c == entities.ConfidenceInferred {
		w = inferredWeight(w)
	}
	if knownExploited {
		w *= 2
	}
	return temporalWeight(w, temporal)
}

// AssetRisk is one asset's aggregated risk: the criticality-weighted sum of the
// findings against it, with the contributing findings and the reasons criticality
// was raised, so the number is fully explainable.
type AssetRisk struct {
	Kind        string         `json:"kind"`
	ID          string         `json:"id"`
	Score       int            `json:"score"`       // BaseScore * Criticality
	BaseScore   int            `json:"baseScore"`   // sum of finding weights
	Criticality int            `json:"criticality"` // 1..N multiplier from cheap signals
	Reasons     []string       `json:"reasons"`     // why criticality was raised
	Findings    []AssetFinding `json:"findings"`    // contributing findings, worst first
}

// RiskModel is the per-customer risk posture rolled up from the findings and the
// asset facets. It is a pure function of the event stream (built from the folded
// Findings and Inventory read models), so it is deterministic and survives replay.
type RiskModel struct {
	// Band is the overall posture, driven by the worst finding severity present.
	Band RiskBand `json:"band"`
	// TotalScore is the sum of every asset's weighted score.
	TotalScore int `json:"totalScore"`
	// BySeverity counts findings per severity (mirrors the findings rollup).
	BySeverity map[int]int `json:"bySeverity"`
	// TopAssets are the riskiest assets, worst first, capped for the report.
	TopAssets []AssetRisk `json:"topAssets"`
	// Weights is the severity-weight table, printed so the score is explainable.
	Weights map[int]int `json:"weights"`
	// HistoricalPercent and UnknownPercent are the temporal-relevance adjustments,
	// printed with the rest so the temporal discount is as visible as the others.
	HistoricalPercent int `json:"historicalPercent"`
	UnknownPercent    int `json:"unknownPercent"`
	// Views splits the complete ledger by temporal status, so current posture is
	// readable without any finding being hidden to achieve it.
	Views TemporalViews `json:"views"`
}

// TemporalViews splits every finding in the ledger by temporal status. The four
// views are reconciled by construction: Current + Mixed + Historical + Unknown
// always equals Ledger, so no finding can be quietly dropped from the posture.
type TemporalViews struct {
	// Ledger is the complete finding count, unchanged and auditable.
	Ledger int `json:"ledger"`
	// Current holds findings supported as current at the as-of time.
	Current int `json:"current"`
	// Mixed holds findings combining current and historical evidence.
	Mixed int `json:"mixed"`
	// Historical holds findings whose evidence is historical-only.
	Historical int `json:"historical"`
	// Unknown holds findings that need re-observation before any current claim.
	Unknown int `json:"unknown"`
}

// Reconciles reports whether the four views account for exactly the ledger. A false
// result is a bug in the split rather than a property of the data.
func (v TemporalViews) Reconciles() bool {
	return v.Current+v.Mixed+v.Historical+v.Unknown == v.Ledger
}

// BuildRiskModel rolls the findings up into per-asset and per-customer risk. Each
// asset's base score is the sum of its findings' severity weights; criticality
// scales it from cheap signals already in the stream (apex, auth surface, mail
// infrastructure). The band is the worst severity present, kept simple and visible.
func BuildRiskModel(p *projections.Projection) RiskModel {
	rm := RiskModel{
		BySeverity:        make(map[int]int, len(p.Findings.BySeverity)),
		Weights:           severityWeight,
		HistoricalPercent: historicalPercent,
		UnknownPercent:    unknownPercent,
	}
	rm.Views = temporalViews(p)
	for sev, n := range p.Findings.BySeverity {
		rm.BySeverity[sev] = n
	}

	// Build the unified host view once so IP-asset criticality can consult one
	// merged host model (live, confirmed services vs provider-only claims) rather
	// than re-reading the separate provider facets.
	hosts := p.Inventory.HostView()
	for key, ids := range p.Findings.ByAsset {
		ar := assetRisk(p, key, ids, hosts)
		if ar.Score == 0 {
			continue
		}
		rm.TopAssets = append(rm.TopAssets, ar)
		rm.TotalScore += ar.Score
	}

	sort.Slice(rm.TopAssets, func(i, j int) bool {
		if rm.TopAssets[i].Score != rm.TopAssets[j].Score {
			return rm.TopAssets[i].Score > rm.TopAssets[j].Score
		}
		return rm.TopAssets[i].ID < rm.TopAssets[j].ID
	})
	if len(rm.TopAssets) > topRiskAssetsCap {
		rm.TopAssets = rm.TopAssets[:topRiskAssetsCap]
	}

	rm.Band = bandFor(p.Findings.Highest())
	return rm
}

// temporalViews splits the complete finding ledger by temporal status. Every finding
// lands in exactly one view and none is dropped, so the four counts reconcile to the
// ledger total by construction.
func temporalViews(p *projections.Projection) TemporalViews {
	v := TemporalViews{Ledger: len(p.Findings.All)}
	for _, f := range p.Findings.All {
		switch f.TemporalStatus {
		case entities.TemporalStatusCurrent:
			v.Current++
		case entities.TemporalStatusMixed:
			v.Mixed++
		case entities.TemporalStatusHistorical:
			v.Historical++
		case entities.TemporalStatusUnknown:
			v.Unknown++
		default:
			// An unclassified finding is not silently current: the report has to be
			// able to say it carries no temporal reading at all.
			v.Unknown++
		}
	}
	return v
}

// assetRisk builds one asset's risk record from its findings and criticality.
func assetRisk(p *projections.Projection, key string, findingIDs []string, hosts projections.HostView) AssetRisk {
	kind, id := splitAssetKey(key)
	ar := AssetRisk{Kind: kind, ID: id, Criticality: 1}

	for _, fid := range findingIDs {
		f, ok := p.Findings.All[fid]
		if !ok {
			continue
		}
		w := effectiveWeight(f.Severity, f.Confidence, f.KnownExploited, f.TemporalStatus)
		ar.BaseScore += w
		ar.Findings = append(ar.Findings, AssetFinding{
			Rule:           f.Rule,
			Title:          f.Title,
			Severity:       f.Severity,
			Weight:         w,
			Confidence:     string(f.Confidence),
			KnownExploited: f.KnownExploited,
			TemporalStatus: string(f.TemporalStatus),
			TemporalReason: f.TemporalReason,
		})
	}
	sort.Slice(ar.Findings, func(i, j int) bool {
		if ar.Findings[i].Weight != ar.Findings[j].Weight {
			return ar.Findings[i].Weight > ar.Findings[j].Weight
		}
		return ar.Findings[i].Rule < ar.Findings[j].Rule
	})

	ar.Criticality, ar.Reasons = criticality(p, kind, id, hosts)
	ar.Score = ar.BaseScore * ar.Criticality
	return ar
}

// criticality returns a small multiplier (>=1) and the reasons it was raised, from
// cheap signals already in the stream. Domain assets carry the discovery signals;
// IP assets carry a host signal from the unified host view. The table is
// intentionally small and printed.
func criticality(p *projections.Projection, kind, id string, hosts projections.HostView) (factor int, reasons []string) {
	factor = 1
	switch kind {
	case "domain":
		node, ok := p.Inventory.Domains[id]
		if !ok {
			return factor, reasons
		}
		if node.Depth == 0 {
			factor++
			reasons = append(reasons, "apex domain")
		}
		if node.HasAuthSurface() {
			factor++
			reasons = append(reasons, "auth/admin surface")
		}
		if node.HasMailInfra() {
			factor++
			reasons = append(reasons, "mail infrastructure")
		}
	case "ip":
		// A host with a port the active scan actually observed open is a live,
		// reachable target - more critical than one only a provider claimed. This
		// makes a confirmed vulnerable host outrank a provider-only-claimed one.
		if h, ok := hosts.Hosts[id]; ok && h.HasConfirmedPort() {
			factor++
			reasons = append(reasons, "live services (confirmed open)")
		}
	}
	return factor, reasons
}

// bandFor maps the worst finding severity present to the overall risk band.
func bandFor(highestSeverity int) RiskBand {
	switch {
	case highestSeverity >= int(events.SeverityCritical):
		return RiskCritical
	case highestSeverity >= int(events.SeverityHigh):
		return RiskHigh
	case highestSeverity >= int(events.SeverityMedium):
		return RiskMedium
	default:
		return RiskLow
	}
}

// splitAssetKey reverses assetKey ("kind:id"), tolerating ids that contain ':'
// (for example "ip:port" service ids) by splitting on the first separator only.
func splitAssetKey(key string) (kind, id string) {
	for i := 0; i < len(key); i++ {
		if key[i] == ':' {
			return key[:i], key[i+1:]
		}
	}
	return key, ""
}
