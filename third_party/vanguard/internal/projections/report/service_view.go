package report

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/projections"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// ServiceIdentity is one socket in the operator report: what is exposed there, how
// it was identified, how certain the observation is, who reported it, and how old
// the evidence is. It is a compact identity index over the provider-inclusive host
// view, not a second copy of the evidence: the raw banner, the NSE script output,
// the CPEs, and the TLS/SSH detail stay in the service entity snapshots, and the
// TLS/SSH posture stays in [ServiceAssessment].
type ServiceIdentity struct {
	// ID is the canonical service asset id ("host/port/proto"), the same identity
	// the inventory and the findings key a service by.
	ID string
	// IP is the address the service answers on, as the host view normalized it.
	IP string
	// Port is the port number.
	Port int
	// Protocol is the transport: "tcp", "udp", or "unknown" when the reporting
	// provider named none. It is never inferred from the port or the service name.
	Protocol string
	// Confidence is confirmed when the active phase observed the socket open, and
	// inferred when only a passive provider claimed it.
	Confidence string
	// Name, Product and Version are the best available identification across the
	// contributing sources. Any of them may be empty: an open socket nobody could
	// fingerprint is still a service, and a guessed name would be worse than none.
	Name    string
	Product string
	Version string
	// BannerPresent states whether a banner was captured for this service. The
	// banner itself is deliberately absent: it is attacker-controlled target output,
	// so the report says it exists and the entity snapshot holds it.
	BannerPresent bool
	// Sources are the tools and providers that reported this service, sorted.
	Sources []string
	// SourceObservedAt is the newest real-world observation time across those
	// sources. Zero means none of them dated its claim, which reads as unknown age
	// rather than as fresh.
	SourceObservedAt time.Time
}

// buildServiceIdentities projects the already-merged host view into the report's
// service index. It rebuilds nothing: the provider merge, the transport keying, the
// confidence precedence, and the ordering are the host view's, so the Services
// section and the Hosts section can never describe two different surfaces.
func buildServiceIdentities(hv projections.HostView) []ServiceIdentity {
	var out []ServiceIdentity
	for _, h := range hv.SortedHosts() {
		for i := range h.Ports {
			p := &h.Ports[i]
			out = append(out, ServiceIdentity{
				ID:            serviceID(h.IP, p.Port, p.Protocol),
				IP:            h.IP,
				Port:          p.Port,
				Protocol:      p.Protocol,
				Confidence:    string(p.Confidence),
				Name:          p.Service,
				Product:       p.Product,
				Version:       p.Version,
				BannerPresent: p.Banner != "",
				// Copied, never aliased: the report must not hand a consumer a slice
				// the projection still owns.
				Sources:          slices.Clone(p.Sources),
				SourceObservedAt: p.SourceObservedAt,
			})
		}
	}
	return out
}

// serviceID renders the canonical service asset id. Every service identity the
// report prints goes through it, so the Services index and the Service Assessments
// index cannot drift into two spellings of the same socket.
func serviceID(host string, port int, protocol string) string {
	return entities.NewServiceID(host, port, protocol).String()
}

// writeServices renders the service identity index: one row per socket in the
// unified host view, including the provider-only ones the active phase never
// confirmed. It is the socket-level view between the per-host summary above and the
// per-service posture detail below.
func (r Report) writeServices(sb *strings.Builder) {
	fmt.Fprintf(sb, "## Services (%d)\n\n", len(r.Services))
	if len(r.Services) == 0 {
		sb.WriteString("No service identities were observed by active scanning or passive providers.\n\n")
		return
	}
	sb.WriteString("One row per socket from the same merged host view as the table above. ")
	sb.WriteString("Confirmed means the active phase observed the socket open; inferred means only a passive provider claimed it. ")
	sb.WriteString("Banner reports whether service output was captured, not what it said: the banner text, the script output, and the CPEs stay in the service snapshots. ")
	sb.WriteString("Evidence age is unknown when no contributing source dated its claim.\n\n")
	sb.WriteString("| Service | Protocol | Confidence | Name | Product | Version | Banner | Sources | Evidence age |\n")
	sb.WriteString("|---------|----------|------------|------|---------|---------|--------|---------|--------------|\n")
	for _, s := range r.Services {
		fmt.Fprintf(sb, "| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			s.ID, cell(s.Protocol), cell(s.Confidence), cell(s.Name), cell(s.Product), cell(s.Version),
			yesNo(s.BannerPresent), cell(strings.Join(s.Sources, ", ")),
			evidenceAge(r.AnalysisAsOf, s.SourceObservedAt))
	}
	sb.WriteString("\n")
}

// cell renders free-form target and provider metadata inside a Markdown table cell.
// A service name, product, or version is whatever the target said it was, so it can
// carry a newline or a pipe that would silently reshape the table; both are
// neutralized rather than dropped, because an odd value is evidence and hiding it
// would be the worse failure. An empty result reads as a dash, never as a blank a
// reader would take for missing data.
func cell(s string) string {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer("\r\n", " ", "\r", " ", "\n", " ").Replace(s)
	s = strings.ReplaceAll(s, "|", "\\|")
	if s == "" {
		return "-"
	}
	return s
}

// yesNo renders a presence flag for a table cell.
func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
