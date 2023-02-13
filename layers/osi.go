package layers

import (
	"errors"
	"fmt"

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

	Protocol byte
	// TODO Describe other header fields
}

func (osi *OSI) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {

	if len(data) < 1 {
		return errors.New("OSI header too small")
	}

	osi.Protocol = data[0]

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

	switch osi.Protocol {
	case 0x83:
		return LayerTypeISIS
	case 0x82:
		return LayerTypeESIS
	}

	return gopacket.LayerTypeZero // Not implemented

	// return osi.OSIType.LayerType()
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (osi *OSI) CanDecode() gopacket.LayerClass {
	return LayerTypeOSI
}

func decodeOSI(data []byte, p gopacket.PacketBuilder) error {

	osi := &OSI{}

	if len(data) < 1 {
		return fmt.Errorf("OSI HEADER TOO SMALL")
	}

	return decodingLayerDecoder(osi, data, p)
}
