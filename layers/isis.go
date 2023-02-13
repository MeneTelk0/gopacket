package layers

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/gopacket"
)

type ISISType byte

const (
	ISISHello                     ISISType = 1
	ISISCompleteSequenceNumberPDU ISISType = 2
	ISISPartialSequenceNumberPDU  ISISType = 3
	ISISLinkStatePDU              ISISType = 4
)

type PDUCommonHeader struct {
	LengthIndicator            byte
	VersionProtocolIdExtension byte
	IdLength                   byte
	PDUType                    SpecificHeaderType
	Version                    byte
	Reserved                   byte
	MaximumAreaAddresses       byte
}

type SpecificHeaderType byte

const (
	IIHL1  SpecificHeaderType = 15
	IIHL2  SpecificHeaderType = 16
	IIHP2P SpecificHeaderType = 17
	L1LSP  SpecificHeaderType = 18
	L2LSP  SpecificHeaderType = 20
	L1CSNP SpecificHeaderType = 24
	L2CSNP SpecificHeaderType = 25
	L1PSNP SpecificHeaderType = 26
	L2PSNP SpecificHeaderType = 27
)

// ///////////////////////////////////////////CLV TYPES
type CLVCode byte

const (
	AreaAddresses               CLVCode = 1
	ISNeighbors                 CLVCode = 2
	ESNeighbors                 CLVCode = 3
	PartitionDesignatedLevel2IS CLVCode = 4
	ISNeighborsMac              CLVCode = 6
	ISNeighborsSNPA             CLVCode = 7
	Padding                     CLVCode = 8
	LspEntries                  CLVCode = 9
	AuthenticationInfo          CLVCode = 10
	ProtocolsSupported          CLVCode = 129
	IpInterfaceAddress          CLVCode = 132
	Hostname                    CLVCode = 137
	RestartSignaling            CLVCode = 211
)

type CLV struct {
	Code   CLVCode
	Length byte
	Value  interface{}
}

// ///////////////////////////////////////////////
type ISIS struct {
	BaseLayer
	Type                 ISISType
	CH                   PDUCommonHeader
	SpecificHeader       interface{}
	VariableLengthFields []CLV
}

// ///////////////////////////////////////////////HELLO PKG TYPES FOR SPECIFIC HEADER
type ISISHelloPkg struct {
	CircuitType    byte
	SenderSystemId uint64
	HoldingTimer   uint16
	PDULength      uint16
}

type IIHvL1_L2Lan struct {
	Base     ISISHelloPkg
	Priority byte

	DesignatedSystemId struct {
		SystemId     uint64
		PseudonodeId byte
	}
}

type IIHvP2P struct {
	Base         ISISHelloPkg
	LocalCircuit byte
}

// ///////////////////////////////////////////////LSP PACKETS SPECIFIC HEADER

type LspEntry struct {
	LspSeqNumber      uint32
	RemainingLifetime uint16
	Checksum          uint16
	Id                LspId
}

type LspId struct {
	SystemId     uint64
	PseudonodeId byte
	FragmentNum  byte
}

type ISISLsp struct {
	PDULength         uint16
	RemainingLifetime uint16

	Id LspId

	SequenceNumber uint32
	Checksum       uint16

	PartitionRepair byte
	Attachment      byte
	LSDBOverload    byte
	IsType          byte
}

type ISISPsnp struct {
	PDULength uint16
	SourceId  struct {
		Id        uint64
		CircuitId byte
	}
}

type ISISCsnp struct {
	ISISPsnp

	StartLspId LspId

	EndLspId LspId
}

// ///////////////////////////////////////////////ISIS METHODS
// String conversions for ISISType
func (i ISISType) String() string {
	switch i {
	case ISISHello:
		return "Hello"
	case ISISCompleteSequenceNumberPDU:
		return "ISISCompleteSequenceNumberPDU"
	case ISISPartialSequenceNumberPDU:
		return "ISISPartialSequenceNumberPDU"
	case ISISLinkStatePDU:
		return "ISISLinkStatePDU"
	default:
		return "No Such ISIS Type"
	}
}

func (isis *ISIS) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	var index int = 0
	index += isis.decodeCommonHeader(data[0:])

	switch isis.CH.PDUType {
	case IIHL1, IIHL2, IIHP2P: //IIH
		isis.Type = ISISHello
		add, err := isis.decodeHelloPDU(data[index:])
		if err != nil {
			return err
		}
		index += add

	case L1LSP, L2LSP:
		isis.Type = ISISLinkStatePDU
		add := isis.decodeLspPDU(data[index:])
		index += add

	case L1PSNP, L2PSNP:
		isis.Type = ISISPartialSequenceNumberPDU
		add := isis.decodePsnpPDU(data[index:])
		index += add

	case L1CSNP, L2CSNP:
		isis.Type = ISISCompleteSequenceNumberPDU
		add := isis.decodeCsnpPDU(data[index:])
		index += add

	default:
		fmt.Printf("Specific HEADER PARSE ERROR\n")
		return errors.New("unknown PDU TYPE")
	}

	add, err := isis.decodeCLV(data[index:])
	if err != nil {
		return err
	}
	index += add

	isis.Contents = data[:index]
	if len(data[index:]) == 0 {
		isis.Payload = nil
	} else {
		isis.Payload = data[index:]
	}
	return nil
}

func (isis *ISIS) decodeCommonHeader(data []byte) int {
	index := 0

	isis.CH.LengthIndicator = data[index] //index == 0
	index++

	isis.CH.VersionProtocolIdExtension = data[index] //index == 1
	index++

	isis.CH.IdLength = data[index] //index == 2
	index++

	isis.CH.PDUType = SpecificHeaderType(data[index] & 0x1f) //index == 3
	index++

	isis.CH.Version = data[index] //index == 4
	index++

	isis.CH.Reserved = data[index] //index == 5
	index++

	isis.CH.MaximumAreaAddresses = data[index] //index == 6
	index++

	return index
}

func (isis *ISIS) decodeHelloPDU(data []byte) (int, error) {
	index := 0

	helloPkg := ISISHelloPkg{}

	helloPkg.CircuitType = data[index] & 0x3 //index == 0
	index++

	systemid := binary.BigEndian.Uint64(data[index : index+8])
	helloPkg.SenderSystemId = systemid & 0xffffffffffff0000 >> 16
	index += 6

	helloPkg.HoldingTimer = uint16(binary.BigEndian.Uint16(data[index : index+2]))
	index += 2

	helloPkg.PDULength = binary.BigEndian.Uint16(data[index : index+2])
	index += 2

	switch isis.CH.PDUType {

	case IIHL1, IIHL2: //L1/L2 IIH

		answerPkg := IIHvL1_L2Lan{
			Base: helloPkg,
		}
		answerPkg.Priority = data[index] & 0x7f
		index++

		systemid := binary.BigEndian.Uint64(data[index : index+8])
		answerPkg.DesignatedSystemId.SystemId = systemid & 0xffffffffffff0000 >> 16
		answerPkg.DesignatedSystemId.PseudonodeId = byte(systemid & 0xff00 >> 8)

		index += 7

		isis.SpecificHeader = answerPkg

	case IIHP2P: //P2P IIH
		answerPkg := IIHvP2P{
			Base: helloPkg,
		}
		answerPkg.LocalCircuit = data[index]
		index++

		isis.SpecificHeader = answerPkg

	default:
		fmt.Printf("UNKNOWN TYPE HELLO PDU\n")
		return 0, errors.New("internal error Parsing IIH")
	}

	return index, nil
}

func (isis *ISIS) decodeLspPDU(data []byte) int {
	index := 0

	lsp := ISISLsp{}

	lsp.PDULength = binary.BigEndian.Uint16(data[index : index+2])
	index += 2

	lsp.RemainingLifetime = binary.BigEndian.Uint16(data[index : index+2])
	index += 2

	lspid := binary.BigEndian.Uint64(data[index : index+8])
	lsp.Id.SystemId = (lspid & 0xffffffffffff0000) >> 16
	lsp.Id.PseudonodeId = data[index+6]
	lsp.Id.FragmentNum = data[index+7]
	index += 8

	lsp.SequenceNumber = binary.BigEndian.Uint32(data[index : index+4])
	index += 4

	lsp.Checksum = binary.BigEndian.Uint16(data[index : index+2])
	index += 2

	tmp := data[index]
	index++
	lsp.PartitionRepair = tmp & 0x80
	lsp.Attachment = tmp & 0x78
	lsp.LSDBOverload = tmp & 0x4
	lsp.IsType = tmp & 0x3

	isis.SpecificHeader = lsp
	return index
}

func (isis *ISIS) decodeCsnpPDU(data []byte) int {
	index := 0

	snp := ISISCsnp{}

	snp.PDULength = binary.BigEndian.Uint16(data[index : index+2])
	index += 2

	sourceid := binary.BigEndian.Uint64(data[index : index+8])
	snp.SourceId.Id = sourceid & 0xffffffffffff0000 >> 16
	snp.SourceId.CircuitId = data[index+6]
	index += 7

	startid := binary.BigEndian.Uint64(data[index : index+8])
	snp.StartLspId.SystemId = startid & 0xffffffffffff0000 >> 16
	snp.StartLspId.PseudonodeId = data[index+6]
	snp.StartLspId.FragmentNum = data[index+7]
	index += 8

	endid := binary.BigEndian.Uint64(data[index : index+8])
	snp.EndLspId.SystemId = endid & 0xffffffffffff0000 >> 16
	snp.EndLspId.PseudonodeId = data[index+6]
	snp.EndLspId.FragmentNum = data[index+7]
	index += 8

	isis.SpecificHeader = snp
	return index
}

func (isis *ISIS) decodePsnpPDU(data []byte) int {
	index := 0

	snp := ISISPsnp{}

	snp.PDULength = binary.BigEndian.Uint16(data[index : index+2])
	index += 2

	sourceid := binary.BigEndian.Uint64(data[index : index+8])
	snp.SourceId.Id = sourceid & 0xffffffffffff0000 >> 16
	snp.SourceId.CircuitId = data[index+6]
	index += 7

	isis.SpecificHeader = snp
	return index
}

func (isis *ISIS) decodeCLV(data []byte) (int, error) {
	index := 0

	for len(data) > index {
		isis.VariableLengthFields = append(isis.VariableLengthFields, CLV{
			Code:   CLVCode(data[index]),
			Length: data[index+1],
		})
		index += 2

		cur := &isis.VariableLengthFields[len(isis.VariableLengthFields)-1]
		switch cur.Code {

		case AreaAddresses:
			cur.Value = string(data[index : index+int(cur.Length)])

		case RestartSignaling:
			cur.Value = string(data[index : index+int(cur.Length)])

		case ISNeighborsMac:
			cur.Value = string(data[index : index+int(cur.Length)])

		case Hostname:
			cur.Value = string(data[index : index+int(cur.Length)])

		case ISNeighbors:
			cur.Value = string(data[index : index+int(cur.Length)])

		case ESNeighbors:
			cur.Value = string(data[index : index+int(cur.Length)])

		case LspEntries:
			var arr []LspEntry

			var lspEntryLen byte = 16
			entryCnt := cur.Length / lspEntryLen

			ind := index
			for counter := 0; counter < int(entryCnt); counter++ {

				var tmp LspEntry
				tmp.RemainingLifetime = binary.BigEndian.Uint16(data[ind : ind+2])
				ind += 2

				id := binary.BigEndian.Uint64(data[ind : ind+8])
				tmp.Id.SystemId = id & 0xffffffffffff0000 >> 16
				tmp.Id.PseudonodeId = data[ind+6]
				tmp.Id.FragmentNum = data[ind+7]
				ind += 8

				tmp.LspSeqNumber = binary.BigEndian.Uint32(data[ind : ind+4])
				ind += 4

				tmp.Checksum = binary.BigEndian.Uint16(data[ind : ind+2])
				ind += 2

				arr = append(arr, tmp)

			}
			cur.Value = arr

		case Padding:

		default:
			fmt.Printf("%v\t UNKNOWN CLV CODE\n", cur.Code)
			return index, errors.New("unknown CLV Code")
		}

		index += int(cur.Length)
	}
	return index, nil
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

	if len(data) < 27 {
		return fmt.Errorf("packet too smal for ISIS")
	}

	isis := &ISIS{}
	return decodingLayerDecoder(isis, data, p)
}
