package p25

import "fmt"

// ARS PDU types - the low nibble of the PDU header byte. Values from sdrtrunk
// module/decode/ip/mototrbo/ars/ARSPDUType.java.
const (
	ARSDeviceRegistration   uint8 = 0x0
	ARSDeviceDeregistration uint8 = 0x1
	ARSQuery                uint8 = 0x4
	ARSUserRegistration     uint8 = 0x5
	ARSUserDeregistration   uint8 = 0x6
	ARSUserRegistrationAck  uint8 = 0x7
	ARSRegistrationAck      uint8 = 0xF
)

// ARSData is the result of running parseARS over a UDP/4005 datagram - Motorola
// ARS (Automatic Registration Service), the presence/registration protocol used
// by MOTOTRBO and P25 integrated-data systems. Reference: sdrtrunk
// module/decode/ip/mototrbo/ars/ (ARSHeader.java, ARSPDUType.java).
//
// Wire layout: a 2-byte big-endian PDU length (count of bytes following the
// length field) then a PDU header byte that is a bitfield (MSB-first):
//
//	bit 0x80 HEADER_EXTENSION_FLAG
//	bit 0x40 ACKNOWLEDGEMENT_FLAG
//	bit 0x20 PRIORITY_FLAG
//	bit 0x10 CONTROL_USER_FLAG
//	bits 0x0F PDU type (see constants above)
//
// On the captured P25 system the only on-air ARS we see is the server->radio
// REGISTRATION_ACKNOWLEDGEMENT (type 0xF). Its dominant variant carries a
// TLV-style 32-bit Unix-epoch timestamp (header 0xBF, body `08 04 <ts32>`);
// corpus decode proved the field tracks wall-clock to +-2s over 14h. A shorter
// variant (header 0xFF, body `00`) carries no timestamp. See
// bench_results/sndcp_corpus_sweep_2026-06-15.md "UPDATE 2".
type ARSData struct {
	PDULength    uint16 // value of the 2-byte length field (bytes after it)
	HasExtension bool
	Acknowledge  bool
	Priority     bool
	Control      bool
	PDUType      uint8 // low nibble of the header byte

	// RawPayload is the bytes after the PDU header byte (i.e. the extension
	// byte + body), length = PDULength-1. Caller owns the buffer.
	RawPayload []byte

	// Timestamp is the 32-bit Unix-epoch seconds carried by the observed
	// reg-ack variant; HasTimestamp is false when the message has no such
	// field (e.g. the short `ff 00` ack).
	HasTimestamp bool
	Timestamp    uint32
}

// parseARS returns nil only if the 2-byte length + PDU header byte cannot be
// read or the declared length runs past the buffer. A successful decode always
// returns a non-nil result; the timestamp fields stay zero/false when the body
// does not match the observed `<ext> 04 <ts32>` TLV shape.
func parseARS(buf []byte) *ARSData {
	if len(buf) < 3 {
		return nil // need 2-byte length + at least the PDU header byte
	}
	pduLen := int(buf[0])<<8 | int(buf[1])
	if pduLen < 1 || 2+pduLen > len(buf) {
		return nil
	}
	hdr := buf[2]
	a := &ARSData{
		PDULength:    uint16(pduLen),
		HasExtension: hdr&0x80 != 0,
		Acknowledge:  hdr&0x40 != 0,
		Priority:     hdr&0x20 != 0,
		Control:      hdr&0x10 != 0,
		PDUType:      hdr & 0x0f,
	}
	a.RawPayload = append([]byte(nil), buf[3:2+pduLen]...)

	// Observed P25 reg-ack: extension flag set, then `<ext-byte> 04 <ts32>`.
	// RawPayload[0] is the extension byte, [1]=TLV length (4), [2:6]=timestamp.
	if a.HasExtension && len(a.RawPayload) >= 6 && a.RawPayload[1] == 0x04 {
		v := a.RawPayload[2:6]
		a.Timestamp = uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
		a.HasTimestamp = true
	}
	return a
}

// PDUTypeName returns the sdrtrunk mnemonic for the PDU type nibble.
func (a *ARSData) PDUTypeName() string {
	if a == nil {
		return ""
	}
	switch a.PDUType {
	case ARSDeviceRegistration:
		return "DEVICE_REGISTRATION"
	case ARSDeviceDeregistration:
		return "DEVICE_DEREGISTRATION"
	case ARSQuery:
		return "QUERY"
	case ARSUserRegistration:
		return "USER_REGISTRATION"
	case ARSUserDeregistration:
		return "USER_DEREGISTRATION"
	case ARSUserRegistrationAck:
		return "USER_REGISTRATION_ACK"
	case ARSRegistrationAck:
		return "REGISTRATION_ACK"
	default:
		return fmt.Sprintf("UNKNOWN_0x%X", a.PDUType)
	}
}
