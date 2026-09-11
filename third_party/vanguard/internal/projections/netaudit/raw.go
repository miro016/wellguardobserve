package netaudit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// topDestinationCap bounds how many busy destinations the compact traffic overview
// lists. The full set lives in the raw netaudit projection.
const topDestinationCap = 8

// summarizeTraffic folds a capture's observations and deduplicated flows into a
// compact, deterministic traffic overview. A nil or unreadable capture yields a
// zero summary.
func summarizeTraffic(c *CaptureSource, flows []flow) TrafficSummary {
	var t TrafficSummary
	if c == nil || !c.Readable {
		return t
	}
	t.Conversations = len(flows)
	peers := map[netip.Addr]int{}
	for i := range flows {
		f := flows[i]
		for _, e := range []netip.Addr{f.a.Unmap(), f.b.Unmap()} {
			if e.IsValid() && !e.IsLoopback() && !e.IsUnspecified() {
				peers[e] += f.packets
			}
		}
		if f.sni != "" {
			t.TLSHandshakes++
		}
		if f.httpHost != "" {
			t.HTTPRequests++
		}
	}
	t.RemotePeers = len(peers)
	for i := range c.Extract.Observations {
		o := c.Extract.Observations[i]
		t.DNSQueries += len(o.DNSQueries)
		t.DNSAnswers += len(o.DNSAnswers)
	}
	t.TopDestinations = topDestinations(peers)
	return t
}

// topDestinations returns the busiest peers by packet count, most first, bounded to
// topDestinationCap and broken ties by address for stable output.
func topDestinations(peers map[netip.Addr]int) []DestCount {
	out := make([]DestCount, 0, len(peers))
	for addr, pkts := range peers {
		out = append(out, DestCount{Addr: addr.String(), Packets: pkts})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Packets != out[j].Packets {
			return out[i].Packets > out[j].Packets
		}
		return out[i].Addr < out[j].Addr
	})
	if len(out) > topDestinationCap {
		out = out[:topDestinationCap]
	}
	return out
}

// RawCapture is the decoded, bounded network-audit detail for the collection's
// capture: the deduplicated conversations, the DNS answers, and the app-layer
// observations. It is the source for the projection's netaudit/ investigation files
// and never carries packet payloads.
type RawCapture struct {
	Status        Status            `json:"status"`
	Backend       Backend           `json:"backend"`
	RelPath       string            `json:"relPath,omitempty"`
	SHA256        string            `json:"sha256,omitempty"`
	Packets       int               `json:"packets"`
	Conversations []RawConversation `json:"conversations,omitempty"`
	DNS           []RawDNS          `json:"dns,omitempty"`
	Notes         []string          `json:"notes,omitempty"`
}

// RawConversation is one deduplicated flow rendered for investigation: both
// endpoints, the transport, the packet count and time span, and any decoded
// application identity.
type RawConversation struct {
	EndpointA string    `json:"a"`
	EndpointB string    `json:"b"`
	Protocol  string    `json:"protocol"`
	Port      int       `json:"port,omitempty"`
	Packets   int       `json:"packets"`
	First     time.Time `json:"first"`
	Last      time.Time `json:"last"`
	SNI       string    `json:"sni,omitempty"`
	HTTPHost  string    `json:"httpHost,omitempty"`
	// Opened is the travel direction of the conversation's first packet: "outbound"
	// means this host reached out. Empty when the capture carries no direction.
	Opened Direction `json:"opened,omitempty"`
	// Process is the ptcpdump-attributed owner of the conversation, empty when the
	// backend carried no attribution. It is what separates the scanner's own traffic
	// from another process sharing the host.
	Process string `json:"process,omitempty"`
}

// RawDNS is one deduplicated resolved (name -> address) answer.
type RawDNS struct {
	Name string `json:"name"`
	Addr string `json:"addr"`
}

// BuildRaw folds a capture into its RawCapture investigation view. It is pure and
// deterministic; the adapter supplies the discovered capture and the assessed
// health status so the raw view and the report agree on what the capture was.
func BuildRaw(status Status, c *CaptureSource) RawCapture {
	raw := RawCapture{Status: status, Backend: BackendUnknown}
	if c == nil {
		raw.Notes = []string{"the collection holds no capture file"}
		return raw
	}
	raw.Backend = c.Extract.Backend
	if raw.Backend == "" {
		raw.Backend = BackendUnknown
	}
	raw.RelPath = c.RelPath
	raw.SHA256 = c.SHA256
	if !c.Readable {
		raw.Notes = []string{"capture file exists but could not be opened or read"}
		return raw
	}
	raw.Packets = c.Extract.PacketCount

	for _, f := range buildFlows(c) {
		raw.Conversations = append(raw.Conversations, RawConversation{
			EndpointA: f.a.String(),
			EndpointB: f.b.String(),
			Protocol:  f.protocol,
			Port:      remotePort(f),
			Packets:   f.packets,
			First:     f.first,
			Last:      f.last,
			SNI:       f.sni,
			HTTPHost:  f.httpHost,
			Opened:    f.opened,
			Process:   f.process,
		})
	}
	sortRawConversations(raw.Conversations)
	raw.DNS = rawDNS(c)
	return raw
}

func sortRawConversations(cs []RawConversation) {
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].Packets != cs[j].Packets {
			return cs[i].Packets > cs[j].Packets
		}
		if cs[i].EndpointA != cs[j].EndpointA {
			return cs[i].EndpointA < cs[j].EndpointA
		}
		return cs[i].EndpointB < cs[j].EndpointB
	})
}

// rawDNS collects the deduplicated resolved answers from a capture, sorted for
// stable output.
func rawDNS(c *CaptureSource) []RawDNS {
	seen := map[string]bool{}
	var out []RawDNS
	for i := range c.Extract.Observations {
		for _, a := range c.Extract.Observations[i].DNSAnswers {
			if !a.Addr.IsValid() {
				continue
			}
			name := strings.ToLower(strings.TrimSuffix(a.Name, "."))
			key := name + "|" + a.Addr.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, RawDNS{Name: name, Addr: a.Addr.String()})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Addr < out[j].Addr
	})
	return out
}

// SummaryMarkdown renders the decoded network-audit summary for the collection:
// capture health plus an aggregated endpoint table. Conversations are grouped by
// endpoints, protocol, port, and decoded SNI/Host, with the conversation count and
// total packets summed per group, so an operator sees who the capture talked to at a
// glance. The full per-conversation and per-answer detail lives in the raw.jsonl log
// beside it.
func SummaryMarkdown(raw RawCapture) string {
	var sb strings.Builder
	sb.WriteString("# Network Audit - decoded traffic summary\n\n")
	sb.WriteString("Decoded, bounded audit metadata rebuilt from the immutable captures under " +
		"`netaudit/`. No packet payloads are included. Conversations are grouped by endpoints, " +
		"protocol, port, and decoded SNI/Host; per-conversation and DNS detail is in `raw.jsonl`. " +
		"This is investigation context behind the report's Network Audit & Exclusion Verification " +
		"section; verdicts live there.\n\n")
	writeSummaryCapture(&sb, raw)
	return sb.String()
}

func writeSummaryCapture(sb *strings.Builder, raw RawCapture) {
	fmt.Fprintf(sb, "## Capture (%s)\n\n", raw.Status)
	fmt.Fprintf(sb, "- Backend: %s\n", raw.Backend)
	if raw.RelPath != "" {
		fmt.Fprintf(sb, "- Capture: %s\n", raw.RelPath)
	}
	if raw.SHA256 != "" {
		fmt.Fprintf(sb, "- SHA-256: %s\n", raw.SHA256)
	}
	fmt.Fprintf(sb, "- Packets: %d, conversations: %d, unique DNS answers: %d\n\n", raw.Packets, len(raw.Conversations), len(raw.DNS))
	for _, n := range raw.Notes {
		fmt.Fprintf(sb, "- %s\n", n)
	}
	if len(raw.Notes) > 0 {
		sb.WriteString("\n")
	}

	groups := groupConversations(raw.Conversations)
	if len(groups) > 0 {
		sb.WriteString("### Endpoints\n\n")
		sb.WriteString("| Endpoint A | Endpoint B | Proto | Port | SNI / HTTP Host | Process | Conversations | Packets |\n")
		sb.WriteString("|---|---|---|---:|---|---|---:|---:|\n")
		for _, g := range groups {
			port := ""
			if g.Port > 0 {
				port = fmt.Sprintf("%d", g.Port)
			}
			fmt.Fprintf(sb, "| %s | %s | %s | %s | %s | %s | %d | %d |\n",
				g.EndpointA, g.EndpointB, g.Protocol, port, g.App, g.Process, g.Conversations, g.Packets)
		}
		sb.WriteString("\n")
	}

	if len(raw.DNS) > 0 {
		sb.WriteString("### DNS answers\n\n")
		sb.WriteString("| Name | Address |\n|---|---|\n")
		for _, d := range raw.DNS {
			fmt.Fprintf(sb, "| %s | %s |\n", d.Name, d.Addr)
		}
		sb.WriteString("\n")
	}
}

// endpointGroup is one aggregated row of the summary table: all conversations that
// share the same endpoints, protocol, port, and decoded app identity, with the
// conversation count and total packets summed.
type endpointGroup struct {
	EndpointA     string
	EndpointB     string
	Protocol      string
	Port          int
	App           string
	Process       string
	Conversations int
	Packets       int
}

// groupConversations aggregates conversations by (endpoints, protocol, port, app),
// summing packets and counting conversations, sorted by total packets descending
// then by endpoints for stable output.
func groupConversations(cs []RawConversation) []endpointGroup {
	type key struct {
		a, b, proto, app, process string
		port                      int
	}
	index := map[key]*endpointGroup{}
	var order []*endpointGroup
	for i := range cs {
		c := cs[i]
		app := c.SNI
		if app == "" {
			app = c.HTTPHost
		}
		k := key{a: c.EndpointA, b: c.EndpointB, proto: c.Protocol, app: app, process: c.Process, port: c.Port}
		g := index[k]
		if g == nil {
			g = &endpointGroup{EndpointA: c.EndpointA, EndpointB: c.EndpointB, Protocol: c.Protocol,
				Port: c.Port, App: app, Process: c.Process}
			index[k] = g
			order = append(order, g)
		}
		g.Conversations++
		g.Packets += c.Packets
	}
	out := make([]endpointGroup, 0, len(order))
	for _, g := range order {
		out = append(out, *g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Packets != out[j].Packets {
			return out[i].Packets > out[j].Packets
		}
		if out[i].EndpointA != out[j].EndpointA {
			return out[i].EndpointA < out[j].EndpointA
		}
		if out[i].EndpointB != out[j].EndpointB {
			return out[i].EndpointB < out[j].EndpointB
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// rawRecord is one line of the raw.jsonl investigation log. Kind discriminates
// the record so an investigator can filter with grep/jq/duckdb: "capture" is the
// header, "conversation" is one deduplicated flow, and "dns" is one resolved answer.
type rawRecord struct {
	Kind         string           `json:"kind"`
	Status       Status           `json:"status,omitempty"`
	Backend      Backend          `json:"backend,omitempty"`
	RelPath      string           `json:"relPath,omitempty"`
	SHA256       string           `json:"sha256,omitempty"`
	Packets      int              `json:"packets,omitempty"`
	Note         string           `json:"note,omitempty"`
	Conversation *RawConversation `json:"conversation,omitempty"`
	DNS          *RawDNS          `json:"dns,omitempty"`
}

// RawJSONL renders the decoded network-audit detail as a newline-delimited JSON
// log: the capture header, then one line per conversation and per DNS answer. It is
// deterministic, so a later replay of the same capture reproduces it byte for byte.
func RawJSONL(raw RawCapture) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(rawRecord{
		Kind: "capture", Status: raw.Status, Backend: raw.Backend,
		RelPath: raw.RelPath, SHA256: raw.SHA256, Packets: raw.Packets,
	}); err != nil {
		return nil, err
	}
	for _, n := range raw.Notes {
		if err := enc.Encode(rawRecord{Kind: "note", Note: n}); err != nil {
			return nil, err
		}
	}
	for j := range raw.Conversations {
		if err := enc.Encode(rawRecord{Kind: "conversation", Conversation: &raw.Conversations[j]}); err != nil {
			return nil, err
		}
	}
	for j := range raw.DNS {
		if err := enc.Encode(rawRecord{Kind: "dns", DNS: &raw.DNS[j]}); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}
