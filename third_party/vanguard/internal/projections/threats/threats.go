package threats

import (
	"sort"

	"github.com/velgard-sk/vanguard/internal/projections/assetgraph"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// ThreatScenario is a named, evidenced attack path inferred from a combination of
// findings and facets across related assets. Unlike a detector finding (one event,
// one weakness), a scenario chains independent signals into a plausible attacker
// story. It is a report artifact, not a persisted event: it is recomputed
// deterministically from the folded projection on every build (and replay).
type ThreatScenario struct {
	// Name is the scenario label.
	Name string `json:"name"`
	// Severity ranks the scenario (events.Severity as int).
	Severity int `json:"severity"`
	// Narrative is the plain-language attack path for the report, naming the
	// assets it fired on.
	Narrative string `json:"narrative"`
	// Summary is the same attack path with the assets left out: what this class of
	// scenario means, stated once for every instance of it. A scenario that fires
	// on thirteen assets has thirteen narratives and one summary, so a report can
	// explain the path once and then list what it fired on.
	//
	// It carries the same temporal qualification as Narrative, so two instances of
	// one scenario whose chains differ in currentness do not share a summary that
	// is true of only one of them.
	Summary string `json:"summary"`
	// Assets are the assets involved in the scenario.
	Assets []entities.AssetRef `json:"assets"`
	// Evidence lists the contributing findings/facets that fired the scenario.
	Evidence []string `json:"evidence"`
	// References are CWE / MITRE ATT&CK identifiers for the attack pattern.
	References []string `json:"references"`
	// TemporalStatus states whether the chain this scenario describes is current,
	// historical, mixed, or unknown. It is independent of Severity: a
	// scenario can be severe, validated, and resting on evidence a year old.
	//
	// A scenario is never dropped for being historical or mixed. An attack path that
	// was real six months ago is a hypothesis worth checking, not noise; it is
	// labelled and grouped instead of discarded.
	TemporalStatus entities.TemporalStatus `json:"temporalStatus"`
}

// withChain records what a scenario's contributing findings say about its chain:
// whether their evidence is current, historical, mixed, or unknown. The narrative is
// qualified here, at the point each scenario builds it, rather than rewritten
// afterwards, so a scenario file always states its own temporal claim.
func (s ThreatScenario) withChain(findings ...*entities.Finding) ThreatScenario {
	s.TemporalStatus = chainStatus(findings...)
	s.Narrative = qualifyNarrative(s.TemporalStatus, s.Narrative)
	s.Summary = qualifyNarrative(s.TemporalStatus, s.Summary)
	return s
}

// chainStatus combines the temporal status of every required step into the status of the
// chain as a whole.
//
// Unknown wins outright: one step whose currentness cannot be read means the chain cannot
// be asserted as current, whatever the other steps say. Mixed comes next, including the
// case where separate steps are individually current and historical, because a chain
// whose links never coexisted in time is exactly what an unqualified present-tense
// narrative would misrepresent.
func chainStatus(findings ...*entities.Finding) entities.TemporalStatus {
	var current, historical, mixed, unknown bool
	steps := 0
	for _, f := range findings {
		if f == nil {
			continue
		}
		steps++
		switch f.TemporalStatus {
		case entities.TemporalStatusCurrent:
			current = true
		case entities.TemporalStatusHistorical:
			historical = true
		case entities.TemporalStatusMixed:
			mixed = true
		case entities.TemporalStatusUnknown:
			unknown = true
		default:
			unknown = true
		}
	}
	switch {
	case steps == 0 || unknown:
		return entities.TemporalStatusUnknown
	case mixed || (current && historical):
		return entities.TemporalStatusMixed
	case historical:
		return entities.TemporalStatusHistorical
	default:
		return entities.TemporalStatusCurrent
	}
}

// qualifyNarrative prefixes a scenario narrative with its temporal claim unless the chain
// is current. Only a current chain earns unqualified present tense; everything else says
// up front what it is before it describes what an attacker could do.
func qualifyNarrative(status entities.TemporalStatus, narrative string) string {
	switch status {
	case entities.TemporalStatusCurrent:
		return narrative
	case entities.TemporalStatusMixed:
		return "current and historical evidence combined, so the steps may never have coexisted: " + narrative
	case entities.TemporalStatusHistorical:
		return "historical, not observed as current at the as-of time: " + narrative
	case entities.TemporalStatusUnknown:
		return "currentness unknown, re-observation needed before acting: " + narrative
	}
	return narrative
}

// scenario is one curated scenario rule. Each lives in its own file, mirroring the
// one-rule-per-file layout of the findings package. A scenario is a pure function
// of the read-only asset graph.
type scenario func(assetgraph.Graph) []ThreatScenario

// scenarios is the curated set, run in registration order then sorted by Build.
var scenarios = []scenario{
	CredentialStuffing,
	TransportDowngrade,
	DowngradeToExposedApp,
	ExposedDatabase,
	OpenDataExposure,
	InfraMapping,
	ExpiredLiveCert,
	RemoteAccessExposure,
	IISWebExposure,
}

// Build runs every curated scenario over the asset graph and returns those that fire,
// grouped by temporal status and then ordered by severity (then name, then asset)
// for a stable report. The set is deliberately small and high-signal: each
// scenario chains signals that already exist as findings or facets.
//
// Every scenario that fires is returned. Historical and mixed chains are labelled and
// sorted after the current ones, never dropped: a path that was real last quarter is a
// hypothesis to check, and deleting it would be the same completeness failure the whole
// temporal model exists to prevent.
func Build(g assetgraph.Graph) []ThreatScenario {
	var out []ThreatScenario
	for _, s := range scenarios {
		out = append(out, s(g)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		// Temporal status groups before severity does: an analyst reads the current
		// chains first, then the mixed, then the historical, and no scenario is
		// dropped to achieve that ordering.
		if ri, rj := temporalRank(out[i].TemporalStatus), temporalRank(out[j].TemporalStatus); ri != rj {
			return ri < rj
		}
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return firstAssetID(&out[i]) < firstAssetID(&out[j])
	})
	return out
}

// temporalRank orders the temporal statuses for grouping: current chains first, then
// mixed, then historical, then unknown. It is an ordering, never a filter.
func temporalRank(s entities.TemporalStatus) int {
	switch s {
	case entities.TemporalStatusCurrent:
		return 0
	case entities.TemporalStatusMixed:
		return 1
	case entities.TemporalStatusHistorical:
		return 2
	case entities.TemporalStatusUnknown:
		return 3
	}
	return 4
}

// Reference ids reused across several scenarios, defined once so the catalogue stays
// consistent (and the goconst linter is satisfied).
const (
	// cweInfoExposure is CWE-200: Exposure of Sensitive Information.
	cweInfoExposure = "CWE-200"
	// attckAiTM is MITRE ATT&CK T1557: Adversary-in-the-Middle (downgrade/intercept).
	attckAiTM = "MITRE ATT&CK T1557"
)

// assetRef builds an asset reference by kind and id.
func assetRef(kind, id string) entities.AssetRef { return entities.AssetRef{Kind: kind, ID: id} }

// firstOf returns the finding for the first of rules present on the asset.
func firstOf(m map[string]*entities.Finding, rules ...string) *entities.Finding {
	for _, r := range rules {
		if f, ok := m[r]; ok {
			return f
		}
	}
	return nil
}

// evidence renders a finding as a short evidence line.
func evidence(f *entities.Finding) string {
	if f.Evidence == "" {
		return f.Title
	}
	return f.Title + ": " + f.Evidence
}

// firstAssetID returns a scenario's first asset id for stable ordering.
func firstAssetID(s *ThreatScenario) string {
	if len(s.Assets) == 0 {
		return ""
	}
	return s.Assets[0].ID
}
