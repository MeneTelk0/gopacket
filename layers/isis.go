package layers

import (
	"github.com/google/gopacket"
)

type ISIS struct {
	BaseLayer
	// Describe packet fields
	// Use OSPF (v2 or v3) as reference
}

func (isis *ISIS) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {

	// Use (ospf *OSPFv2) DecodeFromBytes as reference

	return nil
}

// LayerType returns LayerTypeISIS
func (isis *ISIS) LayerType() gopacket.LayerType {
	return LayerTypeISIS
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (isis *ISIS) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (isis *ISIS) CanDecode() gopacket.LayerClass {
	return LayerTypeISIS
}

func decodeISIS(data []byte, p gopacket.PacketBuilder) error {

	// Check if packet is of correct type
	// Use OSPF decodeOSPF as reference
	isis := &ISIS{}
	return decodingLayerDecoder(isis, data, p)
}
