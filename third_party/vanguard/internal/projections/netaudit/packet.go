package netaudit

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// maxPackets bounds how many packets a single capture contributes to the model,
// so a hostile or runaway capture cannot exhaust memory during offline analysis.
// A capture that hits the cap is reported truncated (partial) rather than silently
// clipped.
const maxPackets = 2_000_000

// Direction is the observed travel direction of a packet, when the capture format
// carries it. Most capture formats and the tcpdump fallback do not, so Unknown is
// the common case and no conclusion is drawn from its absence.
type Direction string

// Direction values. Unknown is the common case: most capture formats and the
// tcpdump fallback carry no per-packet direction.
const (
	DirectionUnknown  Direction = ""
	DirectionInbound  Direction = "inbound"
	DirectionOutbound Direction = "outbound"
)

// Observation is the bounded audit metadata extracted from one decoded packet.
// It never carries payload bodies, credentials, cookies, request paths, banners,
// or raw packet bytes: the retained pcap remains the detailed evidence.
type Observation struct {
	Time      time.Time
	Interface string
	Direction Direction
	CapLen    int
	OrigLen   int
	// Fingerprint deduplicates a frame seen on several interfaces without collapsing
	// distinct retransmissions or datagrams: it hashes the capture time, length, and
	// packet bytes, all of which differ across genuinely distinct packets.
	Fingerprint [32]byte

	SrcIP    netip.Addr
	DstIP    netip.Addr
	Protocol string
	SrcPort  int
	DstPort  int
	TCPFlags tcpFlags

	// DNSQueries are the query names in a DNS packet. DNSAnswers maps each answered
	// name (or CNAME target) to a resolved address, so a later active conversation
	// to a shared address can be correlated to an excluded name.
	DNSQueries []string
	DNSAnswers []DNSAnswer

	// SNI is the TLS ClientHello server name; HTTPHost is a plaintext HTTP Host
	// header. Either directly proves the application-level target of a connection.
	SNI      string
	HTTPHost string

	// Process is the ptcpdump-attributed process identity, empty when the backend
	// carries no attribution or the metadata could not be decoded.
	Process string
}

// DNSAnswer is one resolved (name -> address) mapping decoded from a DNS answer.
type DNSAnswer struct {
	Name string
	Addr netip.Addr
}

// tcpFlags is the minimal set of TCP flags an audit needs to tell an initiating
// SYN from an established or reply segment.
type tcpFlags struct {
	SYN bool
	ACK bool
	FIN bool
	RST bool
}

// ExtractResult is the output of streaming a single capture: the bounded packet
// observations plus the capture-health counters the assessment needs to decide
// whether packet absence is evidence.
type ExtractResult struct {
	Backend            Backend
	Observations       []Observation
	PacketCount        int
	RemotePackets      int
	LoopbackPackets    int
	DroppedPackets     int
	DecodedLinkTypes   []string
	SkippedLinkTypes   []string
	SkippedPackets     int
	ProcessAttribution bool
	// Truncated is set when the capture ended mid-record or hit the packet cap, so
	// the caller reports partial rather than complete. An unsupported link type does
	// not set it: that incompleteness is reported through SkippedLinkTypes instead,
	// so the limitation names its real cause.
	Truncated   bool
	ParseError  string
	ParseOffset int64
}

// Extract streams a pcapng or classic pcap capture from r and returns the bounded
// observations and capture-health counters. The input may be gzipped: collected
// packet evidence is compressed on the VM the moment the capture stops, so the
// normal case is a .gz, and an uncompressed capture made by hand or by a backend run
// outside the wrapper reads identically. Both forms decode to the same model, since
// compression is a storage concern and nothing about the capture itself.
//
// It picks the reader from the file magic, decodes mixed link layers, records rather
// than discards unsupported link types, and never holds the whole file in memory
// beyond the bounded observation slice - gzip included, which is decompressed as a
// stream rather than into a buffer. A decode failure part-way through is not fatal:
// the observations gathered so far are returned with ParseError set, so the report
// can render a partial or parse_failed status instead of losing the whole audit.
//
// A gzip header that cannot be opened at all is a different matter and is returned
// as an error: nothing was decoded, so there is no partial audit to report, and the
// caller renders the capture unreadable.
func Extract(r io.Reader) (ExtractResult, error) {
	br := bufio.NewReaderSize(r, 64*1024)
	if head, err := br.Peek(2); err == nil && head[0] == 0x1f && head[1] == 0x8b {
		zr, gzErr := gzip.NewReader(br)
		if gzErr != nil {
			return ExtractResult{}, fmt.Errorf("open gzip capture: %w", gzErr)
		}
		defer func() { _ = zr.Close() }()
		br = bufio.NewReaderSize(zr, 64*1024)
	}
	magic, err := br.Peek(4)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("read capture magic: %w", err)
	}
	if binary.BigEndian.Uint32(magic) == 0x0A0D0D0A {
		return extractPcapng(br)
	}
	return extractPcap(br)
}

// extractPcap streams a classic (single link type, no process metadata) pcap.
func extractPcap(br *bufio.Reader) (ExtractResult, error) {
	// Peek the file header before the reader consumes it: pcapgo truncates the
	// 32-bit link type field to a uint8, which loses Linux cooked v2 entirely.
	hdr, _ := br.Peek(pcapHeaderLen)
	reader, err := pcapgo.NewReader(br)
	if err != nil {
		return ExtractResult{Backend: BackendTcpdump, ParseError: safeErr(err)}, nil
	}
	res := ExtractResult{Backend: BackendTcpdump}
	link := linkType(reader.LinkType())
	if wide, ok := pcapHeaderLinkType(hdr); ok {
		link = wide
	}
	seenLink := map[string]bool{}
	for {
		data, ci, err := reader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			res.Truncated = true
			res.ParseError = safeErr(err)
			res.ParseOffset = int64(res.PacketCount)
			break
		}
		if res.PacketCount >= maxPackets {
			res.Truncated = true
			break
		}
		decodePacket(&res, link, "", data, ci, seenLink, ngPacketMeta{})
	}
	return res, nil
}

// linkType is a pcap link type as the capture formats store it: 32 bits in a
// classic pcap file header, 16 in a pcapng interface description. gopacket's
// layers.LinkType is a uint8 and silently truncates anything above 255, which turns
// Linux cooked v2 (276) into an unrelated low-numbered type, so the extractor keeps
// the untruncated value and converts only where a decoder needs it.
type linkType uint32

// pcapHeaderLen is the fixed size of a classic pcap file header.
const pcapHeaderLen = 24

// pcapHeaderLinkType reads the untruncated 32-bit link type from a classic pcap
// file header, picking the byte order from the magic. It returns ok=false for a
// header it does not recognize, leaving the caller on the reader's own value.
func pcapHeaderLinkType(hdr []byte) (linkType, bool) {
	if len(hdr) < pcapHeaderLen {
		return 0, false
	}
	var order binary.ByteOrder
	switch binary.BigEndian.Uint32(hdr[:4]) {
	case 0xA1B2C3D4, 0xA1B23C4D: // microsecond and nanosecond, big-endian
		order = binary.BigEndian
	case 0xD4C3B2A1, 0x4D3CB2A1: // the same two, little-endian
		order = binary.LittleEndian
	default:
		return 0, false
	}
	return linkType(order.Uint32(hdr[20:24])), true
}

// baseLayer maps a pcap link type to the gopacket base decoder for its frames.
// An unsupported link type returns ok=false so the caller records it as skipped
// rather than mis-decoding or discarding it silently.
func baseLayer(link linkType) (gopacket.LayerType, bool) {
	switch link {
	case linkType(layers.LinkTypeEthernet):
		return layers.LayerTypeEthernet, true
	case linkType(layers.LinkTypeLinuxSLL):
		return layers.LayerTypeLinuxSLL, true
	case linkTypeLinuxSLL2:
		return layerTypeLinuxSLL2, true
	case linkType(layers.LinkTypeRaw), linkType(layers.LinkTypeIPv4), linkType(layers.LinkTypeIPv6):
		return layers.LayerTypeIPv4, true // Raw/IPv4/IPv6 all start at the IP header; IPv4 decoder version-sniffs
	case linkType(layers.LinkTypeNull), linkType(layers.LinkTypeLoop):
		return layers.LayerTypeLoopback, true
	default:
		return 0, false
	}
}

// linkName renders a link type for the health counters. gopacket names only the
// types that fit its uint8, so cooked v2 and any other high-numbered type are named
// here rather than reported as "UnknownLinkType".
func linkName(link linkType) string {
	if link == linkTypeLinuxSLL2 {
		return "Linux SLL2"
	}
	if link > 255 {
		return fmt.Sprintf("LinkType(%d)", uint32(link))
	}
	return layers.LinkType(link).String()
}

// decodePacket decodes one frame into an Observation, updating the health
// counters. Unsupported link types are counted and skipped, not mis-decoded.
func decodePacket(res *ExtractResult, link linkType, ifaceName string, data []byte, ci gopacket.CaptureInfo, seenLink map[string]bool, meta ngPacketMeta) {
	base, ok := baseLayer(link)
	if !ok {
		name := linkName(link)
		if !seenLink[name] {
			seenLink[name] = true
			res.SkippedLinkTypes = append(res.SkippedLinkTypes, name)
		}
		res.SkippedPackets++
		// A skipped link type means the audit did not see every frame, but it is not
		// truncation: it is reported as its own limitation so the cause is accurate.
		return
	}
	if name := linkName(link); !seenLink[name] {
		seenLink[name] = true
		res.DecodedLinkTypes = append(res.DecodedLinkTypes, name)
	}

	pkt := gopacket.NewPacket(data, base, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	obs, ok := observe(pkt, ci, ifaceName, data)
	if !ok {
		return
	}
	obs.Direction = meta.direction
	obs.Process = meta.process
	if obs.Process != "" {
		res.ProcessAttribution = true
	}
	res.PacketCount++
	if obs.SrcIP.IsLoopback() || obs.DstIP.IsLoopback() {
		res.LoopbackPackets++
	} else {
		res.RemotePackets++
	}
	res.Observations = append(res.Observations, obs)
}

// observe extracts the bounded audit metadata from a decoded packet. It returns
// ok=false for a frame with no IP layer (for example ARP), which carries no
// exclusion-relevant destination.
func observe(pkt gopacket.Packet, ci gopacket.CaptureInfo, ifaceName string, raw []byte) (Observation, bool) {
	obs := Observation{
		Time:        ci.Timestamp,
		Interface:   ifaceName,
		CapLen:      ci.CaptureLength,
		OrigLen:     ci.Length,
		Fingerprint: fingerprint(ci, raw),
	}

	switch ip := pkt.Layer(layers.LayerTypeIPv4).(type) {
	case *layers.IPv4:
		obs.SrcIP, _ = netip.AddrFromSlice(ip.SrcIP)
		obs.DstIP, _ = netip.AddrFromSlice(ip.DstIP)
	default:
		if ip6, ok := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
			obs.SrcIP, _ = netip.AddrFromSlice(ip6.SrcIP)
			obs.DstIP, _ = netip.AddrFromSlice(ip6.DstIP)
		} else {
			return Observation{}, false
		}
	}
	obs.SrcIP = obs.SrcIP.Unmap()
	obs.DstIP = obs.DstIP.Unmap()

	if tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		obs.Protocol = "tcp"
		obs.SrcPort = int(tcp.SrcPort)
		obs.DstPort = int(tcp.DstPort)
		obs.TCPFlags = tcpFlags{SYN: tcp.SYN, ACK: tcp.ACK, FIN: tcp.FIN, RST: tcp.RST}
		obs.SNI = clientHelloSNI(tcp.Payload)
		obs.HTTPHost = httpHost(tcp.Payload)
	} else if udp, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
		obs.Protocol = "udp"
		obs.SrcPort = int(udp.SrcPort)
		obs.DstPort = int(udp.DstPort)
		if dns, ok := pkt.Layer(layers.LayerTypeDNS).(*layers.DNS); ok {
			obs.DNSQueries, obs.DNSAnswers = decodeDNS(dns)
		}
	} else if t := pkt.TransportLayer(); t != nil {
		obs.Protocol = t.LayerType().String()
	} else if n := pkt.NetworkLayer(); n != nil {
		// No transport layer decoded (ICMP, ESP, an unhandled IP protocol): keep the
		// IP-layer contact visible so an excluded-CIDR datagram is still audited.
		obs.Protocol = "ip"
	}
	return obs, true
}

// fingerprint hashes the identity of a captured frame: its time, length, and
// bytes. Distinct retransmissions and datagrams differ in at least one, so they
// never collapse; a single frame duplicated across interfaces matches exactly.
func fingerprint(ci gopacket.CaptureInfo, raw []byte) [32]byte {
	h := sha256.New()
	var b [16]byte
	binary.LittleEndian.PutUint64(b[0:8], uint64(ci.Timestamp.UnixNano()))
	binary.LittleEndian.PutUint64(b[8:16], uint64(ci.CaptureLength))
	_, _ = h.Write(b[:])
	_, _ = h.Write(raw)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// decodeDNS returns the query names and the resolved (name -> address) answers of
// a DNS packet, so passive lookups of excluded names stay visible and a shared
// answer address can correlate a later active conversation.
func decodeDNS(dns *layers.DNS) ([]string, []DNSAnswer) {
	var queries []string
	for _, q := range dns.Questions {
		if len(q.Name) > 0 {
			queries = append(queries, string(q.Name))
		}
	}
	var answers []DNSAnswer
	for _, a := range dns.Answers {
		name := string(a.Name)
		if a.Type == layers.DNSTypeCNAME && len(a.CNAME) > 0 {
			answers = append(answers, DNSAnswer{Name: name, Addr: netip.Addr{}})
			continue
		}
		if addr, ok := netip.AddrFromSlice(a.IP); ok {
			answers = append(answers, DNSAnswer{Name: name, Addr: addr.Unmap()})
		}
	}
	return queries, answers
}

// safeErr renders an error as a bounded, single-line summary safe to embed in the
// report: it never carries packet bytes, only the decoder's own message.
func safeErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	const maxLen = 200
	if len(s) > maxLen {
		s = s[:maxLen] + "..."
	}
	return s
}
