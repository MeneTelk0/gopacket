package layers

import (
	"github.com/google/gopacket"
)

// For reference use Wireshark OSI dissector
// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-osi.c
// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-osi.h

type OSI struct {
	BaseLayer

	// This type is defined in layers/enums.go
	// All the methods for this type are auto-generated
	// (see layers/enums_generated.go and layers/gen2.go for more details)
	OSIType OSIType

	// TODO Describe other header fields
}

func (osi *OSI) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {

	// Use SNAP layer type decoder from layers/llc.go as reference
	// TODO don't forget to assign value to osi.OSIType
	return nil
}

// LayerType returns LayerTypeISIS
func (osi *OSI) LayerType() gopacket.LayerType {
	return LayerTypeOSI
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (osi *OSI) NextLayerType() gopacket.LayerType {
	return osi.OSIType.LayerType()
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (osi *OSI) CanDecode() gopacket.LayerClass {
	return LayerTypeOSI
}

func decodeOSI(data []byte, p gopacket.PacketBuilder) error {

	// Check if packet is of correct type
	osi := &OSI{}
	return decodingLayerDecoder(osi, data, p)
}
