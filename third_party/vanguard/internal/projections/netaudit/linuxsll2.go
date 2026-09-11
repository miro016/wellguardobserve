package netaudit

import (
	"encoding/binary"
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// linkTypeLinuxSLL2 is pcap link type 276, the Linux cooked v2 header tcpdump
// writes when it captures on the `any` pseudo-interface. The wrapper captures all
// interfaces, so it is the normal link type of collected evidence, and gopacket
// carries no decoder for it.
const linkTypeLinuxSLL2 linkType = 276

// sll2HeaderLen is the fixed Linux cooked v2 header size: protocol type (2),
// reserved (2), interface index (4), ARPHRD type (2), packet type (1), address
// length (1), address (8).
const sll2HeaderLen = 20

// layerTypeLinuxSLL2 registers the cooked v2 decoder in gopacket's global layer
// registry. The number sits above every type gopacket itself registers and below
// its 2000 ceiling, so it cannot collide with a library layer.
var layerTypeLinuxSLL2 = gopacket.RegisterLayerType(1276, gopacket.LayerTypeMetadata{
	Name:    "Linux SLL2",
	Decoder: gopacket.DecodeFunc(decodeLinuxSLL2),
})

// linuxSLL2 is a decoded Linux cooked v2 header. Only the fields the audit needs
// are retained: the protocol that selects the next decoder, the packet type that
// carries the kernel's own view of travel direction, and the interface index that
// names the capturing interface.
type linuxSLL2 struct {
	layers.BaseLayer
	// Protocol is the ethertype of the encapsulated frame. It is zero on interfaces
	// whose frames have no link-layer protocol field, where the payload starts at
	// the IP header.
	Protocol layers.EthernetType
	// InterfaceIndex is the kernel ifindex of the interface the frame crossed.
	InterfaceIndex uint32
	// ARPHRDType is the interface's ARPHRD_ hardware type.
	ARPHRDType uint16
	// PacketType is the kernel packet type (host, broadcast, outgoing, ...), shared
	// with cooked v1.
	PacketType layers.LinuxSLLPacketType
}

// LayerType returns layerTypeLinuxSLL2.
func (sll *linuxSLL2) LayerType() gopacket.LayerType { return layerTypeLinuxSLL2 }

// CanDecode reports the single layer this decoder produces.
func (sll *linuxSLL2) CanDecode() gopacket.LayerClass { return layerTypeLinuxSLL2 }

// NextLayerType selects the decoder for the encapsulated frame. A zero protocol
// carries no ethertype, so the payload's IP version is sniffed instead; the IPv4
// decoder handles both versions the same way the raw link types do.
func (sll *linuxSLL2) NextLayerType() gopacket.LayerType {
	if sll.Protocol == 0 {
		return layers.LayerTypeIPv4
	}
	return sll.Protocol.LayerType()
}

// DecodeFromBytes parses the fixed 20-byte cooked v2 header.
func (sll *linuxSLL2) DecodeFromBytes(data []byte, _ gopacket.DecodeFeedback) error {
	if len(data) < sll2HeaderLen {
		return errors.New("linux SLL2 packet too small")
	}
	sll.Protocol = layers.EthernetType(binary.BigEndian.Uint16(data[0:2]))
	sll.InterfaceIndex = binary.BigEndian.Uint32(data[4:8])
	sll.ARPHRDType = binary.BigEndian.Uint16(data[8:10])
	sll.PacketType = layers.LinuxSLLPacketType(data[10])
	sll.BaseLayer = layers.BaseLayer{Contents: data[:sll2HeaderLen], Payload: data[sll2HeaderLen:]}
	return nil
}

// decodeLinuxSLL2 is the gopacket decoder entry point for cooked v2 frames.
func decodeLinuxSLL2(data []byte, p gopacket.PacketBuilder) error {
	sll := &linuxSLL2{}
	if err := sll.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(sll)
	return p.NextDecoder(sll.NextLayerType())
}
