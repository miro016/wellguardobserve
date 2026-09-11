package orchestration

import (
	"context"
	"fmt"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/collection/orchestration/certs"
)

// crossCheckCTCoverage compares crt.sh's certificate-transparency subdomain
// coverage against the certspotter second CT source and raises a coverage
// IssueObserved for either of two gaps: crt.sh materially short of certspotter (a
// likely-truncated crt.sh response), or certspotter inert (it returned nothing while
// crt.sh found names, so the corroboration did no work). Both Issues are sourced
// "coverage" so the report files them under Coverage gaps (not a tool error).
//
// The two conditions are mutually exclusive on the certspotter count (> 0 for a
// shortfall, 0 for inert), so at most one Issue is raised. The pure decisions and the
// per-source name tracking live in the certs subpackage (certs.CrtshCoverageShortfall,
// certs.CertspotterInert, certs.Coverage); this method reads the two counts and emits,
// keeping the certificate seam a thin orchestrator method.
func (o *Orchestrator) crossCheckCTCoverage(ctx context.Context, root string) {
	crtshCount := o.certCoverage.Count(sourceCrtsh)
	certspotterCount := o.certCoverage.Count(sourceCertspotter)
	minRatio := o.cfg.CertspotterCrossCheckMinRatio

	// crt.sh materially below the corroborator: a likely-truncated crt.sh response.
	if certs.CrtshCoverageShortfall(crtshCount, certspotterCount, minRatio) {
		msg := fmt.Sprintf(
			"crt.sh returned %d subdomain(s) for %s but the certspotter CT cross-check found %d; "+
				"crt.sh likely truncated its response (a 200 with a short body), so its certificate/subdomain "+
				"coverage may be incomplete",
			crtshCount, root, certspotterCount)
		o.emitPassiveCoverageIssue(ctx, root, msg, events.SeverityMedium)
		return
	}

	// certspotter contributed nothing while crt.sh found names: the second CT source
	// is present but the cross-check did no work, so the inert state is made visible
	// rather than reading as a clean corroboration.
	if certs.CertspotterInert(crtshCount, certspotterCount, minRatio) {
		msg := fmt.Sprintf(
			"the certspotter CT cross-check returned 0 names for %s while crt.sh returned %d; "+
				"the second CT source is present but contributed nothing (keyless recent-window limit, "+
				"rate limiting, or a failed query), so crt.sh coverage could not be corroborated",
			root, crtshCount)
		o.emitPassiveCoverageIssue(ctx, root, msg, events.SeverityMedium)
	}
}
