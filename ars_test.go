package p25

import (
	"bytes"
	"testing"
)

// Real, CRC-32-validated reg-ack from a live SNDCP corpus (file
// 20260614T... NAC 0x176, llid 0x018001): UDP/4005 payload
// `00 07 bf 08 04 6a 2f 56 66`. ts32 = 0x6a2f5666 = 1781487206
// (2026-06-15T01:33:26Z). The corpus chose these bytes, not the test, so this
// is a non-circular ground-truth vector.
func TestParseARS_RegistrationAckTimestamp(t *testing.T) {
	ars := parseARS([]byte{0x00, 0x07, 0xbf, 0x08, 0x04, 0x6a, 0x2f, 0x56, 0x66})
	if ars == nil {
		t.Fatal("parseARS returned nil for a valid reg-ack")
	}
	if ars.PDULength != 7 {
		t.Errorf("PDULength = %d, want 7", ars.PDULength)
	}
	if ars.PDUType != ARSRegistrationAck {
		t.Errorf("PDUType = 0x%X, want 0xF (REGISTRATION_ACK)", ars.PDUType)
	}
	if !ars.HasExtension || ars.Acknowledge || !ars.Priority || !ars.Control {
		t.Errorf("flags ext=%v ack=%v prio=%v ctrl=%v, want ext=1 ack=0 prio=1 ctrl=1",
			ars.HasExtension, ars.Acknowledge, ars.Priority, ars.Control)
	}
	if !ars.HasTimestamp || ars.Timestamp != 1781487206 {
		t.Errorf("HasTimestamp=%v Timestamp=%d, want true / 1781487206",
			ars.HasTimestamp, ars.Timestamp)
	}
	if name := ars.PDUTypeName(); name != "REGISTRATION_ACK" {
		t.Errorf("PDUTypeName = %q, want REGISTRATION_ACK", name)
	}
}

// Real, CRC-32-validated short ack from the corpus (NAC 0x176, llid 0x0182da,
// dst 10.71.193.3): `00 02 ff 00`. Header 0xff sets the ACK flag and carries no
// timestamp.
func TestParseARS_ShortAckNoTimestamp(t *testing.T) {
	ars := parseARS([]byte{0x00, 0x02, 0xff, 0x00})
	if ars == nil {
		t.Fatal("parseARS returned nil for a valid short ack")
	}
	if ars.PDULength != 2 {
		t.Errorf("PDULength = %d, want 2", ars.PDULength)
	}
	if ars.PDUType != ARSRegistrationAck {
		t.Errorf("PDUType = 0x%X, want 0xF", ars.PDUType)
	}
	if !ars.Acknowledge {
		t.Error("Acknowledge = false, want true (0xff has the ack bit set)")
	}
	if ars.HasTimestamp {
		t.Errorf("HasTimestamp = true, want false for the short ack")
	}
	if !bytes.Equal(ars.RawPayload, []byte{0x00}) {
		t.Errorf("RawPayload = % x, want 00", ars.RawPayload)
	}
}

func TestParseARS_RejectsTruncated(t *testing.T) {
	if parseARS(nil) != nil {
		t.Error("nil should return nil")
	}
	if parseARS([]byte{0x00, 0x07}) != nil {
		t.Error("2-byte (no header byte) should return nil")
	}
	if parseARS([]byte{0x00, 0x07, 0xbf}) != nil {
		t.Error("declared length 7 but only 1 byte after length should return nil")
	}
	if parseARS([]byte{0x00, 0x00, 0xbf}) != nil {
		t.Error("zero declared length should return nil")
	}
}

// A body that is not the `<ext> 04 <ts32>` TLV shape must not synthesize a
// bogus timestamp.
func TestParseARS_NoFalseTimestamp(t *testing.T) {
	// extension flag set but the TLV length byte is not 0x04.
	ars := parseARS([]byte{0x00, 0x07, 0xbf, 0x08, 0x05, 0x6a, 0x2f, 0x56, 0x66})
	if ars == nil {
		t.Fatal("parseARS returned nil")
	}
	if ars.HasTimestamp {
		t.Errorf("HasTimestamp = true for non-04 TLV length, want false")
	}
}

// End-to-end: a synthesized packet-data PDU carrying IPv4/UDP:4005/ARS must
// surface as ControlFrame.ARS with the timestamp decoded, alongside PDU+SNDCP.
// Mirrors TestProcessFrame_LRRP_PointEmitted.
func TestProcessFrame_ARS_RegAckEmitted(t *testing.T) {
	ars := []byte{0x00, 0x07, 0xbf, 0x08, 0x04, 0x6a, 0x2f, 0x56, 0x66}

	udpLen := uint16(8 + len(ars))
	udp := []byte{
		0xc1, 0x6c, // src 49516
		0x0f, 0xa5, // dst 4005
		byte(udpLen >> 8), byte(udpLen & 0xff),
		0x00, 0x00, // checksum (not verified)
	}
	udp = append(udp, ars...)

	totalLen := uint16(20 + len(udp))
	ip := []byte{
		0x45,
		0x00,
		byte(totalLen >> 8), byte(totalLen & 0xff),
		0x12, 0x34,
		0x40, 0x00,
		0x40,
		0x11, // proto UDP
		0x00, 0x00, // checksum (not verified)
		10, 51, 1, 116, // src 10.51.1.116
		10, 72, 193, 241, // dst 10.72.193.241
	}
	ip = append(ip, udp...)

	const blocksNeeded = 4
	blockBytes := blocksNeeded * 12
	user := make([]byte, blockBytes-6) // SN-DATA(2) + CRC(4) trailer
	copy(user, ip)
	pad := byte(len(user) - len(ip))

	header := [12]byte{
		0x36, // fmt=0x16 (22), confirmed=0, outbound=1
		0x04, // SAP=4
		0x90, // MFID
		0x01, 0x80, 0x01, // LLID
		blocksNeeded,
		pad & 0x1f,
		0x00,
		0x02, // DataHeaderOffset=2
		0x00, 0x00,
	}
	data := make([][12]byte, blocksNeeded)
	dataBytes := append([]byte{0x45, 0x00}, user...) // SN-DATA: PDUType=4, NSAPI=5
	dataBytes = append(dataBytes, 0x00, 0x00, 0x00, 0x00)
	for i := 0; i < blocksNeeded; i++ {
		copy(data[i][:], dataBytes[i*12:(i+1)*12])
	}
	payload := synthPDUPayload(header, data)

	d := NewP25Decoder(25000)
	f := Frame{NID: NID{NAC: 0x171, DUID: 0xC}, Payload: payload}
	_, cfs := d.processFrame(f)

	var got *ControlFrame
	for i := range cfs {
		if cfs[i].ARS != nil {
			got = &cfs[i]
		}
	}
	if got == nil {
		t.Fatal("no ControlFrame had ARS populated")
	}
	if got.PDU == nil || got.SNDCP == nil {
		t.Errorf("PDU/SNDCP must still be populated alongside ARS: pdu=%v sndcp=%v",
			got.PDU != nil, got.SNDCP != nil)
	}
	if got.ARS.PDUType != ARSRegistrationAck {
		t.Errorf("ARS.PDUType = 0x%X, want 0xF", got.ARS.PDUType)
	}
	if !got.ARS.HasTimestamp || got.ARS.Timestamp != 1781487206 {
		t.Errorf("ARS timestamp = %v/%d, want true/1781487206",
			got.ARS.HasTimestamp, got.ARS.Timestamp)
	}
}
