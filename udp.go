package p25

// UDPData is the parsed 8-byte UDP datagram header and the payload that
// follows. Reference: RFC 768; sdrtrunk UDPHeader.java.
type UDPData struct {
	SrcPort uint16
	DstPort uint16
	Length  uint16 // total UDP length (header + payload), in bytes
	Payload []byte
}

func parseUDP(buf []byte) *UDPData {
	if len(buf) < 8 {
		return nil
	}
	length := uint16(buf[4])<<8 | uint16(buf[5])
	if length < 8 || int(length) > len(buf) {
		return nil
	}
	return &UDPData{
		SrcPort: uint16(buf[0])<<8 | uint16(buf[1]),
		DstPort: uint16(buf[2])<<8 | uint16(buf[3]),
		Length:  length,
		Payload: buf[8:length],
	}
}
