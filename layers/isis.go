package layers

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/gopacket"
)

type ISISType uint8

const (
	ISISHello                     ISISType = 1
	ISISCompleteSequenceNumberPDU ISISType = 2
	ISISPartialSequenceNumberPDU  ISISType = 3
	ISISLinkStatePDU              ISISType = 4
)

type PDUCommonHeader struct {
	LengthIndicator            uint8
	VersionProtocolIdExtension uint8
	IdLength                   uint8
	PDUType                    SpecificHeaderType
	Version                    uint8
	Reserved                   uint8
	MaximumAreaAddresses       uint8
}

type SpecificHeaderType uint8

const (
	IIHL1  SpecificHeaderType = 15 //Level-1 IS-IS Hello
	IIHL2  SpecificHeaderType = 16 //Level-1 IS-IS Hello
	IIHP2P SpecificHeaderType = 17 //P2P IS-IS Hello
	L1LSP  SpecificHeaderType = 18 //Level-1 Link State PDU
	L2LSP  SpecificHeaderType = 20 //Level-2 Link State PDU
	L1CSNP SpecificHeaderType = 24 //Level-1 Complete Sequence Numbers PDU
	L2CSNP SpecificHeaderType = 25 //Level-2 Complete Sequence Numbers PDU
	L1PSNP SpecificHeaderType = 26 //Level-1 Partial Sequence Numbers PDU
	L2PSNP SpecificHeaderType = 27 //Level-2 Partial Sequence Numbers PDU
)

// ///////////////////////////////////////////CLV TYPES
type CLVCode uint8

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
	Length uint8
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
	CircuitType    uint8
	SenderSystemId uint64
	HoldingTimer   uint16
	PDULength      uint16
}

// IS-IS Hello L1 L2 LAN
type IIHvL1L2Lan struct {
	Base     ISISHelloPkg
	Priority uint8

	DesignatedSystemId struct {
		SystemId     uint64
		PseudonodeId uint8
	}
}

type IIHvP2P struct {
	Base         ISISHelloPkg
	LocalCircuit uint8
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
	PseudonodeId uint8
	FragmentNum  uint8
}

type ISISLsp struct {
	PDULength         uint16
	RemainingLifetime uint16

	Id LspId

	SequenceNumber uint32
	Checksum       uint16

	PartitionRepair uint8
	Attachment      uint8
	LSDBOverload    uint8
	IsType          uint8
}

type ISISPsnp struct {
	PDULength uint16
	SourceId  struct {
		Id        uint64
		CircuitId uint8
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
		return "ISIS Hello"
	case ISISCompleteSequenceNumberPDU:
		return "ISIS CompleteSequenceNumberPDU"
	case ISISPartialSequenceNumberPDU:
		return "ISIS PartialSequenceNumberPDU"
	case ISISLinkStatePDU:
		return "ISIS LinkStatePDU"
	default:
		return fmt.Sprintf("no such ISIS type: %d", i)
	}
}

func (isis *ISIS) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	index := isis.decodeCommonHeader(data[0:])

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
		return fmt.Errorf("unknown PDU type: %d", isis.CH.PDUType)
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

		answerPkg := IIHvL1L2Lan{
			Base: helloPkg,
		}
		answerPkg.Priority = data[index] & 0x7f
		index++

		systemid := binary.BigEndian.Uint64(data[index : index+8])
		answerPkg.DesignatedSystemId.SystemId = systemid & 0xffffffffffff0000 >> 16
		answerPkg.DesignatedSystemId.PseudonodeId = uint8(systemid & 0xff00 >> 8)

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
		return 0, fmt.Errorf("no such ISIS Hello type: %d", isis.CH.PDUType)
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
			cur.Value = (data[index : index+int(cur.Length)])

		case ISNeighbors:
			cur.Value = (data[index : index+int(cur.Length)])

		case ESNeighbors:
			cur.Value = (data[index : index+int(cur.Length)])

		case ISNeighborsMac:
			cur.Value = net.HardwareAddr(data[index:index])
			var arr []net.HardwareAddr

			var MacAddrLen uint8 = 6
			entryCnt := cur.Length / MacAddrLen

			ind := index
			for counter := 0; counter < int(entryCnt); counter++ {

				tmp := net.HardwareAddr(data[index : index+6])

				ind += 6
				arr = append(arr, tmp)

			}
			cur.Value = arr

		case Padding:

		case LspEntries:
			var arr []LspEntry

			var lspEntryLen uint8 = 16
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

		case ProtocolsSupported:

		case IpInterfaceAddress:
			cur.Value = net.IP(data[index : index+int(cur.Length)])

		case Hostname:
			cur.Value = string(data[index : index+int(cur.Length)])

		case RestartSignaling:
			cur.Value = (data[index : index+int(cur.Length)])

		default:
			// fmt.Printf("unknown CLV code: %d\n", cur.Code)
			// panic("PANICCC\n")
			return index, fmt.Errorf("unknown CLV code: %d", cur.Code)
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
		return fmt.Errorf("packet too smal for ISIS: %d", len(data))
	}

	isis := &ISIS{}
	return decodingLayerDecoder(isis, data, p)
}
