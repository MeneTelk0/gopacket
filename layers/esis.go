package layers

import (
	"github.com/google/gopacket"
)

type ESISType byte

type ESIS struct {
	BaseLayer

	Type ESISType
}

func (esis *ESIS) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {

	return nil
}

// LayerType returns LayerTypeESIS
func (esis *ESIS) LayerType() gopacket.LayerType {
	return LayerTypeESIS
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (esis *ESIS) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (esis *ESIS) CanDecode() gopacket.LayerClass {
	return LayerTypeESIS
}

func decodeESIS(data []byte, p gopacket.PacketBuilder) error {

	esis := &ESIS{}
	return decodingLayerDecoder(esis, data, p)
}
