package netaudit

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// The netaudit pcapng reader is deliberately its own block walker rather than
// gopacket's pcapgo.NgReader. That reader discards every per-packet option
// ("handle options somehow - this would be expensive"), and those options are
// exactly the evidence this audit needs: the enhanced packet block carries the
// travel direction in opt_epb_flags, and ptcpdump records the owning process in
// opt_comment. Reading them through gopacket would mean patching the vendored
// tree, which is read-only. Frame decoding still belongs to gopacket; only block
// framing is ours.

// pcapng block types this reader recognizes. Any other block is skipped, as the
// format requires of a reader that does not understand it.
const (
	ngBlockSectionHeader      uint32 = 0x0A0D0D0A
	ngBlockInterfaceDesc      uint32 = 0x00000001
	ngBlockPacketObsolete     uint32 = 0x00000002
	ngBlockSimplePacket       uint32 = 0x00000003
	ngBlockInterfaceStatistic uint32 = 0x00000005
	ngBlockEnhancedPacket     uint32 = 0x00000006
)

// pcapng option codes this reader reads. Codes are per-block namespaces, so the
// same number means different things in an interface block and a statistics block.
const (
	ngOptEnd uint16 = 0

	ngOptComment uint16 = 1 // any block: free text; ptcpdump's process metadata

	ngOptIfaceName    uint16 = 2  // interface block: interface name
	ngOptIfaceTSResol uint16 = 9  // interface block: timestamp resolution
	ngOptIfaceTSOff   uint16 = 14 // interface block: timestamp offset in seconds

	ngOptEPBFlags uint16 = 2 // enhanced packet block: direction and reception type

	ngOptStatsIfDrop uint16 = 5 // statistics block: packets dropped by the interface
)

// ngByteOrderMagic identifies a section's byte order when read as little-endian.
const ngByteOrderMagic uint32 = 0x1A2B3C4D

// ngMaxBlockBytes caps one block so a corrupt or hostile length field cannot make
// an offline analysis allocate unbounded memory. It is far above any real capture
// block: a jumbo frame at ptcpdump's 256 KiB snap length plus options fits easily.
const ngMaxBlockBytes = 32 << 20

// ngDefaultTSUnits is the per-second timestamp resolution assumed when an interface
// block omits if_tsresol, as the format specifies: microseconds.
const ngDefaultTSUnits uint64 = 1_000_000

// ngIface is the decoded interface description a packet block refers to by index.
type ngIface struct {
	link linkType
	name string
	// tsUnits is the timestamp resolution in units per second, and tsOffset is the
	// whole-second offset added to every packet time on this interface.
	tsUnits  uint64
	tsOffset int64
}

// ngPacketMeta is the per-packet evidence carried in block options rather than in
// the frame itself. Both fields are zero when the capture does not record them.
type ngPacketMeta struct {
	direction Direction
	process   string
}

// ngReader walks pcapng blocks from a buffered stream, tracking the current
// section's byte order and interface table.
type ngReader struct {
	br    *bufio.Reader
	order binary.ByteOrder
	// ifaces is the current section's interface table, indexed as packet blocks
	// index it. A new section header resets it.
	ifaces []ngIface
}

// errNGShortBlock reports a block whose declared length cannot hold its own header,
// which means the stream is no longer aligned on block boundaries.
var errNGShortBlock = errors.New("pcapng: block length too small")

// extractPcapng streams a pcapng, honoring mixed link types and per-packet
// interfaces, and surfacing interface drop statistics, per-packet direction, and
// ptcpdump process attribution when the file records them.
func extractPcapng(br *bufio.Reader) (ExtractResult, error) {
	res := ExtractResult{Backend: BackendPtcpdump}
	r := &ngReader{br: br}
	seenLink := map[string]bool{}
	for {
		typ, body, err := r.readBlock()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// A block that cannot be read is where the audit stops seeing traffic: keep
			// everything decoded so far and report the capture partial.
			res.Truncated = true
			res.ParseError = safeErr(err)
			res.ParseOffset = int64(res.PacketCount)
			break
		}
		if res.PacketCount >= maxPackets {
			res.Truncated = true
			break
		}
		switch typ {
		case ngBlockSectionHeader:
			r.ifaces = nil
		case ngBlockInterfaceDesc:
			r.readInterfaceDesc(body)
		case ngBlockEnhancedPacket:
			r.readEnhancedPacket(&res, body, seenLink)
		case ngBlockSimplePacket:
			r.readSimplePacket(&res, body, seenLink)
		case ngBlockPacketObsolete:
			r.readObsoletePacket(&res, body, seenLink)
		case ngBlockInterfaceStatistic:
			r.readStatistics(&res, body)
		default:
			// The format requires an unknown block to be skipped, not to fail the read.
		}
	}
	return res, nil
}

// readBlock returns the next block's type and its body: everything between the
// leading type/length pair and the trailing length. A section header block also
// establishes the byte order for every block after it.
func (r *ngReader) readBlock() (typ uint32, body []byte, err error) {
	var head [8]byte
	if _, err := io.ReadFull(r.br, head[:4]); err != nil {
		return 0, nil, ngEOF(err)
	}
	// The section header's type reads the same in both byte orders, which is what
	// lets a reader find the order before it can interpret any length field.
	if binary.BigEndian.Uint32(head[:4]) == ngBlockSectionHeader {
		return r.readSectionHeader()
	}
	if r.order == nil {
		return 0, nil, errors.New("pcapng: block before any section header")
	}
	if _, err := io.ReadFull(r.br, head[4:]); err != nil {
		return 0, nil, ngEOF(err)
	}
	typ = r.order.Uint32(head[:4])
	body, err = r.readBody(r.order.Uint32(head[4:]), nil)
	return typ, body, err
}

// readSectionHeader reads the byte-order magic, adopts the section's byte order,
// and returns the section header body. The magic is part of the body, so the
// caller sees a complete block either way.
func (r *ngReader) readSectionHeader() (typ uint32, body []byte, err error) {
	var head [8]byte // declared length, then byte-order magic
	if _, err := io.ReadFull(r.br, head[:]); err != nil {
		return 0, nil, ngEOF(err)
	}
	switch {
	case binary.LittleEndian.Uint32(head[4:]) == ngByteOrderMagic:
		r.order = binary.LittleEndian
	case binary.BigEndian.Uint32(head[4:]) == ngByteOrderMagic:
		r.order = binary.BigEndian
	default:
		return 0, nil, fmt.Errorf("pcapng: unknown byte-order magic %#x", binary.LittleEndian.Uint32(head[4:]))
	}
	body, err = r.readBody(r.order.Uint32(head[:4]), head[4:])
	return ngBlockSectionHeader, body, err
}

// readBody reads the remainder of a block of the given total length, returning the
// already-consumed prefix followed by the bytes still on the wire, and consumes the
// trailing length field.
func (r *ngReader) readBody(total uint32, prefix []byte) ([]byte, error) {
	const framing = 12 // leading type, leading length, trailing length
	if total < framing+uint32(len(prefix)) {
		return nil, fmt.Errorf("%w: %d", errNGShortBlock, total)
	}
	if total > ngMaxBlockBytes {
		return nil, fmt.Errorf("pcapng: block of %d bytes exceeds the %d byte cap", total, ngMaxBlockBytes)
	}
	body := make([]byte, total-framing)
	copy(body, prefix)
	if _, err := io.ReadFull(r.br, body[len(prefix):]); err != nil {
		return nil, ngEOF(err)
	}
	var tail [4]byte
	if _, err := io.ReadFull(r.br, tail[:]); err != nil {
		return nil, ngEOF(err)
	}
	if r.order.Uint32(tail[:]) != total {
		return nil, fmt.Errorf("pcapng: trailing block length %d does not match %d",
			r.order.Uint32(tail[:]), total)
	}
	return body, nil
}

// readInterfaceDesc appends one interface to the current section's table. A
// malformed block still appends a placeholder so later packet blocks keep indexing
// the table correctly.
func (r *ngReader) readInterfaceDesc(body []byte) {
	iface := ngIface{tsUnits: ngDefaultTSUnits}
	if len(body) >= 8 {
		iface.link = linkType(r.order.Uint16(body[:2]))
		r.eachOption(body[8:], func(code uint16, value []byte) {
			switch code {
			case ngOptIfaceName:
				iface.name = string(value)
			case ngOptIfaceTSResol:
				if len(value) >= 1 {
					iface.tsUnits = ngTimestampUnits(value[0])
				}
			case ngOptIfaceTSOff:
				if len(value) >= 8 {
					iface.tsOffset = int64(r.order.Uint64(value[:8]))
				}
			}
		})
	}
	r.ifaces = append(r.ifaces, iface)
}

// readEnhancedPacket decodes the block that carries everything this audit wants: a
// frame, its interface, and the options naming its direction and owning process.
func (r *ngReader) readEnhancedPacket(res *ExtractResult, body []byte, seenLink map[string]bool) {
	const header = 20
	if len(body) < header {
		res.Truncated = true
		return
	}
	iface := r.iface(int(r.order.Uint32(body[:4])))
	ts := uint64(r.order.Uint32(body[4:8]))<<32 | uint64(r.order.Uint32(body[8:12]))
	capLen := int(r.order.Uint32(body[12:16]))
	origLen := int(r.order.Uint32(body[16:20]))
	data, rest, ok := ngPacketData(body[header:], capLen)
	if !ok {
		res.Truncated = true
		return
	}

	var meta ngPacketMeta
	r.eachOption(rest, func(code uint16, value []byte) {
		switch code {
		case ngOptEPBFlags:
			if len(value) >= 4 {
				meta.direction = ngDirection(r.order.Uint32(value[:4]))
			}
		case ngOptComment:
			if meta.process == "" {
				meta.process = ngProcessIdentity(string(value))
			}
		}
	})
	decodePacket(res, iface.link, iface.name, data, ngCaptureInfo(iface, ts, capLen, origLen), seenLink, meta)
}

// readSimplePacket decodes the minimal packet block: no timestamp, no interface
// index, no options. It exists so a capture written with it is still audited.
func (r *ngReader) readSimplePacket(res *ExtractResult, body []byte, seenLink map[string]bool) {
	if len(body) < 4 {
		res.Truncated = true
		return
	}
	iface := r.iface(0)
	origLen := int(r.order.Uint32(body[:4]))
	data := body[4:]
	if len(data) < origLen {
		origLen = len(data)
	}
	decodePacket(res, iface.link, iface.name, data[:origLen],
		ngCaptureInfo(iface, 0, origLen, origLen), seenLink, ngPacketMeta{})
}

// readObsoletePacket decodes the superseded packet block, kept so an older capture
// still yields evidence. Its header carries the interface as a 16-bit id and a
// per-packet drop count before the timestamp.
func (r *ngReader) readObsoletePacket(res *ExtractResult, body []byte, seenLink map[string]bool) {
	const header = 20
	if len(body) < header {
		res.Truncated = true
		return
	}
	iface := r.iface(int(r.order.Uint16(body[:2])))
	ts := uint64(r.order.Uint32(body[4:8]))<<32 | uint64(r.order.Uint32(body[8:12]))
	capLen := int(r.order.Uint32(body[12:16]))
	origLen := int(r.order.Uint32(body[16:20]))
	data, _, ok := ngPacketData(body[header:], capLen)
	if !ok {
		res.Truncated = true
		return
	}
	decodePacket(res, iface.link, iface.name, data, ngCaptureInfo(iface, ts, capLen, origLen), seenLink, ngPacketMeta{})
}

// readStatistics adds the interface's reported drop count. A non-zero total is what
// keeps a capture from being judged complete, so it is read from every statistics
// block rather than only the last.
func (r *ngReader) readStatistics(res *ExtractResult, body []byte) {
	if len(body) < 12 {
		return
	}
	r.eachOption(body[12:], func(code uint16, value []byte) {
		if code == ngOptStatsIfDrop && len(value) >= 8 {
			dropped := r.order.Uint64(value[:8])
			if dropped > math.MaxInt32 {
				dropped = math.MaxInt32
			}
			res.DroppedPackets += int(dropped)
		}
	})
}

// iface returns the interface at index, or a default when the block references one
// the section never described. A bad index costs the frame its link type and name,
// never the whole capture.
func (r *ngReader) iface(index int) ngIface {
	if index < 0 || index >= len(r.ifaces) {
		return ngIface{link: linkType(layers.LinkTypeEthernet), tsUnits: ngDefaultTSUnits}
	}
	return r.ifaces[index]
}

// eachOption walks a block's option list, calling fn for every option before the
// end marker. Options are 16-bit code, 16-bit length, value, padded to 4 bytes.
func (r *ngReader) eachOption(opts []byte, fn func(code uint16, value []byte)) {
	for len(opts) >= 4 {
		code := r.order.Uint16(opts[:2])
		length := int(r.order.Uint16(opts[2:4]))
		if code == ngOptEnd {
			return
		}
		padded := (length + 3) &^ 3
		if 4+padded > len(opts) {
			return
		}
		fn(code, opts[4:4+length])
		opts = opts[4+padded:]
	}
}

// ngPacketData splits a packet block's frame from the options that follow it,
// honoring the 4-byte padding between them.
func ngPacketData(rest []byte, capLen int) (data, opts []byte, ok bool) {
	if capLen < 0 || capLen > len(rest) {
		return nil, nil, false
	}
	padded := (capLen + 3) &^ 3
	if padded > len(rest) {
		padded = len(rest)
	}
	return rest[:capLen], rest[padded:], true
}

// ngCaptureInfo converts a block's raw timestamp and lengths into the capture info
// the frame decoder expects, applying the interface's resolution and offset.
func ngCaptureInfo(iface ngIface, ts uint64, capLen, origLen int) gopacket.CaptureInfo {
	units := iface.tsUnits
	if units == 0 {
		units = ngDefaultTSUnits
	}
	secs := int64(ts/units) + iface.tsOffset
	nanos := int64(float64(ts%units) * (float64(time.Second) / float64(units)))
	return gopacket.CaptureInfo{
		Timestamp:     time.Unix(secs, nanos).UTC(),
		CaptureLength: capLen,
		Length:        origLen,
	}
}

// ngTimestampUnits decodes an if_tsresol byte into timestamp units per second: the
// low bits are an exponent, base 10 normally and base 2 when the high bit is set.
func ngTimestampUnits(resol byte) uint64 {
	exp := uint(resol & 0x7f)
	if resol&0x80 != 0 {
		if exp >= 64 {
			return ngDefaultTSUnits
		}
		return uint64(1) << exp
	}
	units := uint64(1)
	for range exp {
		if units > math.MaxUint64/10 {
			return ngDefaultTSUnits
		}
		units *= 10
	}
	return units
}

// ngDirection reads the travel direction from the two low bits of opt_epb_flags.
// Any other value means the writer recorded no direction.
func ngDirection(flags uint32) Direction {
	switch flags & 0x3 {
	case 1:
		return DirectionInbound
	case 2:
		return DirectionOutbound
	default:
		return DirectionUnknown
	}
}

// ngProcessIdentity extracts a compact owning-process identity from a ptcpdump
// comment option, which is a "Key: value" block naming the process, its parent, and
// the full argument vector. Only the command's base name and pid are kept: they
// identify who opened the connection, while the full paths and argument vectors
// would put command lines into the report for no audit gain.
func ngProcessIdentity(comment string) string {
	var name, pid string
	for line := range strings.SplitSeq(comment, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "Cmd":
			name = path.Base(value)
		case "PID":
			if _, err := strconv.Atoi(value); err == nil {
				pid = value
			}
		}
	}
	switch {
	case name != "" && pid != "":
		return name + "[" + pid + "]"
	case name != "":
		return name
	default:
		return ""
	}
}

// ngEOF maps an unexpected end of stream onto io.EOF at a block boundary and keeps
// it distinct mid-block, where it means the capture was cut short.
func ngEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.EOF
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("pcapng: capture ends mid-block: %w", err)
	}
	return err
}
