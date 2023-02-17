package layers

import (
	"fmt"

	"github.com/google/gopacket"
)

// For reference use Wireshark OSI dissector
// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-osi.c
// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-osi.h

type OSI struct {
	BaseLayer

	Protocol OSIType
}

func (osi *OSI) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {

	osi.Protocol = OSIType(data[0])

	osi.Contents = data[:1]
	osi.Payload = data[1:]

	return nil
}

// LayerType returns LayerTypeISIS
func (osi *OSI) LayerType() gopacket.LayerType {
	return LayerTypeOSI

}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (osi *OSI) NextLayerType() gopacket.LayerType {
	return osi.Protocol.LayerType()
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (osi *OSI) CanDecode() gopacket.LayerClass {
	return LayerTypeOSI
}

func decodeOSI(data []byte, p gopacket.PacketBuilder) error {

	osi := &OSI{}

	if len(data) < 1 {
		return fmt.Errorf("osi header too small")
	}
	return decodingLayerDecoder(osi, data, p)
}
