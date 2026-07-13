package p25

import (
	"bytes"
	"testing"
)

func TestParseSNDCP_Outbound_TypicalPacket(t *testing.T) {
	// Outbound (FNE->SU) RF UNCONFIRMED DATA, NSAPI=5, no IP/UDP compression.
	//   byte 0: PDUType=4 (OUTBOUND_RF_UNCONFIRMED_DATA), NSAPI=5
	//           top nibble = 4, bottom nibble = 5 -> 0x45
	//   byte 1: IPComp=0, UDPComp=0 -> 0x00
	snHeader := []byte{0x45, 0x00}
	user := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	pad := byte(2)

	// Build the equivalent of pdu.Payload: [snHeader][user][pad bytes][CRC-32 slot].
	// Caller is expected to pass a payload-shaped byte slice; CRC bytes are
	// zeroed because parseSNDCP does not look at them.
	payload := []byte{}
	payload = append(payload, snHeader...)
	payload = append(payload, user...)
	payload = append(payload, make([]byte, pad)...)
	payload = append(payload, 0x00, 0x00, 0x00, 0x00) // CRC-32 trailer

	pdu := &PDUData{
		Format:           0x16, // PACKET_DATA
		Outbound:         true,
		Confirmed:        false,
		BlocksToFollow:   uint8(len(payload) / 12),
		DataHeaderOffset: 2,
		PadOctets:        pad,
		Payload:          payload,
	}
	sn := parseSNDCP(pdu)
	if sn == nil {
		t.Fatal("parseSNDCP returned nil for a valid format-22 PDU")
	}
	if sn.PDUType != 4 {
		t.Errorf("PDUType = %d, want 4 (OUTBOUND_RF_UNCONFIRMED_DATA)", sn.PDUType)
	}
	if sn.NSAPI != 5 {
		t.Errorf("NSAPI = %d, want 5", sn.NSAPI)
	}
	if sn.IPHeaderCompression != 0 {
		t.Errorf("IPHeaderCompression = %d, want 0", sn.IPHeaderCompression)
	}
	if sn.UDPHeaderCompression != 0 {
		t.Errorf("UDPHeaderCompression = %d, want 0", sn.UDPHeaderCompression)
	}
	if !bytes.Equal(sn.UserPayload, user) {
		t.Errorf("UserPayload = % x, want % x", sn.UserPayload, user)
	}
}

func TestParseSNDCP_Inbound_RegistrationFlavor(t *testing.T) {
	// Inbound (SU->FNE) ACTIVATE_TDS_CONTEXT_REQUEST, NSAPI=0.
	//   byte 0: PDUType=0, NSAPI=0 -> 0x00
	//   byte 1: 0x00
	snHeader := []byte{0x00, 0x00}
	user := []byte{0xde, 0xad}
	payload := append(append([]byte{}, snHeader...), user...)
	payload = append(payload, 0x00, 0x00, 0x00, 0x00) // CRC

	pdu := &PDUData{
		Format:           0x16,
		Outbound:         false,
		BlocksToFollow:   1,
		DataHeaderOffset: 2,
		PadOctets:        0,
		Payload:          payload,
	}
	sn := parseSNDCP(pdu)
	if sn == nil {
		t.Fatal("parseSNDCP returned nil")
	}
	if sn.PDUType != 0 {
		t.Errorf("PDUType = %d, want 0", sn.PDUType)
	}
	if sn.NSAPI != 0 {
		t.Errorf("NSAPI = %d, want 0", sn.NSAPI)
	}
	if !bytes.Equal(sn.UserPayload, user) {
		t.Errorf("UserPayload = % x, want % x", sn.UserPayload, user)
	}
}

// MBT formats (21, 23) are not packet data - parseSNDCP must skip them.
// Use a payload that would otherwise pass every other guard (off=2, no pad,
// adequate length) so this test fails only if the Format gate is removed.
func TestParseSNDCP_SkipsMBTFormats(t *testing.T) {
	for _, fmt := range []uint8{0x15, 0x17} {
		pdu := &PDUData{
			Format:           fmt,
			BlocksToFollow:   1,
			DataHeaderOffset: 2,
			Payload:          make([]byte, 16),
		}
		if sn := parseSNDCP(pdu); sn != nil {
			t.Errorf("parseSNDCP(fmt=0x%02x) = %+v, want nil", fmt, sn)
		}
	}
}

// Confirmed packet PDUs are now decoded: parsePDU reassembles the 16-octet
// per-block payloads (3/4-rate trellis + per-block CRC-9), and parseSNDCP reads
// the SN-DATA header from that payload exactly as for unconfirmed packets. The
// confirmed block decode itself is exercised by TestParsePDU_ConfirmedPacketData.
func TestParseSNDCP_ConfirmedPacketParsed(t *testing.T) {
	// 16-octet payload: SN-DATA header (PDUType=4, NSAPI=5 => 0x45), then user
	// bytes and a 4-byte CRC-32 slot (not validated here).
	payload := make([]byte, 16)
	payload[0] = 0x45
	pdu := &PDUData{
		Format:           0x16,
		Confirmed:        true,
		BlocksToFollow:   1,
		DataHeaderOffset: 2,
		Payload:          payload,
	}
	sn := parseSNDCP(pdu)
	if sn == nil {
		t.Fatal("parseSNDCP(confirmed=true) = nil, want parsed SN-DATA")
	}
	if sn.PDUType != 4 || sn.NSAPI != 5 {
		t.Errorf("PDUType=%d NSAPI=%d, want 4/5", sn.PDUType, sn.NSAPI)
	}
}

func TestParseSNDCP_TruncatesBeforePadAndCRC(t *testing.T) {
	// 1 block (12 B), DataHeaderOffset=2, PadOctets=3 -> user is only 12-2-4-3 = 3 bytes.
	user := []byte{0xaa, 0xbb, 0xcc}
	payload := []byte{0x45, 0x00} // SN-DATA header
	payload = append(payload, user...)
	payload = append(payload, 0xff, 0xff, 0xff)       // 3 pad bytes
	payload = append(payload, 0x00, 0x00, 0x00, 0x00) // CRC-32

	pdu := &PDUData{
		Format:           0x16,
		Outbound:         true,
		BlocksToFollow:   1,
		DataHeaderOffset: 2,
		PadOctets:        3,
		Payload:          payload,
	}
	sn := parseSNDCP(pdu)
	if sn == nil {
		t.Fatal("parseSNDCP returned nil")
	}
	if !bytes.Equal(sn.UserPayload, user) {
		t.Errorf("UserPayload = % x, want % x", sn.UserPayload, user)
	}
}

// Pathological: DataHeaderOffset > Payload length. Must not panic and must
// return nil.
func TestParseSNDCP_RejectsImpossibleOffsets(t *testing.T) {
	pdu := &PDUData{
		Format:           0x16,
		BlocksToFollow:   1,
		DataHeaderOffset: 200,
		PadOctets:        0,
		Payload:          make([]byte, 16),
	}
	if sn := parseSNDCP(pdu); sn != nil {
		t.Errorf("expected nil for impossible DataHeaderOffset, got %+v", sn)
	}
	// Pad larger than remaining payload after offset+CRC: also nil.
	pdu = &PDUData{
		Format:           0x16,
		BlocksToFollow:   1,
		DataHeaderOffset: 2,
		PadOctets:        100,
		Payload:          make([]byte, 16),
	}
	if sn := parseSNDCP(pdu); sn != nil {
		t.Errorf("expected nil for over-large PadOctets, got %+v", sn)
	}
}

// DataHeaderOffset != 2 means sdrtrunk treats SN-DATA as absent (hasData()=
// false) and parses IPv4 directly from Payload[off:]. We must surface
// HasHeader=false, leave the type/comp fields zeroed so the frame.go gate
// doesn't read uninitialized SN-DATA bytes, and still return UserPayload so
// the caller can attempt IPv4 from the right offset.
func TestParseSNDCP_NoHeaderWhenOffsetNotTwo(t *testing.T) {
	for _, off := range []uint8{0, 1, 4, 8} {
		// Build a payload large enough to satisfy off + CRC.
		const crcBytes, padOctets = 4, 0
		size := int(off) + 4 + crcBytes + padOctets
		payload := make([]byte, size)
		// Drop a non-zero IP-shaped sentinel into the data window so we can
		// confirm UserPayload starts at off, not 0.
		for i := int(off); i < size-crcBytes; i++ {
			payload[i] = 0xab
		}
		// And put a non-zero pattern in the SN-DATA bytes we're meant to NOT
		// interpret (would otherwise be PDUType=0xa, IPComp=0xb).
		if size > 2 {
			payload[0] = 0xab
			payload[1] = 0xcd
		}
		pdu := &PDUData{
			Format:           0x16,
			BlocksToFollow:   1,
			DataHeaderOffset: off,
			Payload:          payload,
		}
		sn := parseSNDCP(pdu)
		if sn == nil {
			t.Fatalf("off=%d: parseSNDCP returned nil, want non-nil with HasHeader=false", off)
		}
		if sn.HasHeader {
			t.Errorf("off=%d: HasHeader = true, want false", off)
		}
		if sn.PDUType != 0 || sn.NSAPI != 0 || sn.IPHeaderCompression != 0 || sn.UDPHeaderCompression != 0 {
			t.Errorf("off=%d: SN-DATA fields not zeroed, got %+v", off, sn)
		}
		// UserPayload starts at byte off (not 0).
		want := payload[off : len(payload)-crcBytes]
		if !bytes.Equal(sn.UserPayload, want) {
			t.Errorf("off=%d: UserPayload = % x, want % x", off, sn.UserPayload, want)
		}
	}
}

// off==2 is the canonical case: HasHeader=true and SN-DATA fields populated.
func TestParseSNDCP_HasHeaderWhenOffsetIsTwo(t *testing.T) {
	pdu := &PDUData{
		Format:           0x16,
		BlocksToFollow:   1,
		DataHeaderOffset: 2,
		Payload:          []byte{0x45, 0x00, 0xde, 0xad, 0x00, 0x00, 0x00, 0x00},
	}
	sn := parseSNDCP(pdu)
	if sn == nil || !sn.HasHeader {
		t.Fatalf("HasHeader = false, want true")
	}
	if sn.PDUType != 4 || sn.NSAPI != 5 {
		t.Errorf("SN-DATA fields = %+v, want PDUType=4 NSAPI=5", sn)
	}
}

func TestProcessFrame_SNDCP_PacketDataEmitsBoth(t *testing.T) {
	// Build a real on-the-wire-shaped PDU: 1-block format-22 packet with the
	// SN-DATA header at byte 0, DataHeaderOffset=2, no pad. (Plenty of space
	// in the 12-byte block: SN-DATA(2) + user(6) + CRC(4) = 12.)
	header := [12]byte{
		// fmt=0x16 (22), confirmed=0, outbound=1
		// byte 0: 0_0_1_10110 = 0x36
		0x36,
		// SAP=4 (USER DATA / PACKET_DATA)
		// byte 1: 00_000100 = 0x04
		0x04,
		0x90,             // MFID
		0x01, 0x79, 0xa6, // LLID
		// blks=1
		// byte 6: 0_0000001 = 0x01
		0x01,
		// pad=0
		0x00,
		// sync=0
		0x00,
		// DataHeaderOffset=2
		0x02,
		0x00, 0x00,
	}
	// 12-byte data block: SN-DATA[2] + user[6] + CRC[4]
	user := [6]byte{0xde, 0xad, 0xbe, 0xef, 0x12, 0x34}
	data := [][12]byte{
		{
			0x45, 0x00, // PDUType=4, NSAPI=5, both comps=0
			user[0], user[1], user[2], user[3], user[4], user[5],
			0x00, 0x00, 0x00, 0x00, // CRC-32 (overwritten by synthPDUPayload)
		},
	}
	payload := synthPDUPayload(header, data)

	d := NewP25Decoder(25000)
	f := Frame{NID: NID{NAC: 0x171, DUID: 0xC}, Payload: payload}
	_, cfs := d.processFrame(f)

	var got *ControlFrame
	for i := range cfs {
		if cfs[i].PDU != nil && cfs[i].SNDCP != nil {
			got = &cfs[i]
		}
	}
	if got == nil {
		t.Fatal("no ControlFrame had both PDU and SNDCP populated")
	}
	if !got.PDU.HeaderCRCOK || !got.PDU.PayloadCRCOK {
		t.Errorf("CRCs failed on synthesized frame: hdr=%v pay=%v", got.PDU.HeaderCRCOK, got.PDU.PayloadCRCOK)
	}
	if got.SNDCP.PDUType != 4 || got.SNDCP.NSAPI != 5 {
		t.Errorf("SN-DATA hdr = type=%d nsapi=%d, want 4/5", got.SNDCP.PDUType, got.SNDCP.NSAPI)
	}
	if !bytes.Equal(got.SNDCP.UserPayload, user[:]) {
		t.Errorf("UserPayload = % x, want % x", got.SNDCP.UserPayload, user)
	}
}

// MBT (Format=0x15/0x17) PDUs must round-trip with PDU set but SNDCP nil.
func TestProcessFrame_SNDCP_MBTHasNilSNDCP(t *testing.T) {
	header := [12]byte{
		0x35,             // fmt=0x15, conf=0, out=1, bit0=0
		0x3d,             // SAP=61 (UNENCRYPTED_TRUNKING_CONTROL)
		0x90,
		0x01, 0x79, 0xa6,
		0x01,             // blks=1
		0x00, 0x00, 0x00,
		0x00, 0x00,
	}
	data := [][12]byte{{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}}
	payload := synthPDUPayload(header, data)

	d := NewP25Decoder(25000)
	f := Frame{NID: NID{NAC: 0x171, DUID: 0xC}, Payload: payload}
	_, cfs := d.processFrame(f)

	for _, cf := range cfs {
		if cf.PDU == nil {
			continue
		}
		if cf.SNDCP != nil {
			t.Errorf("MBT frame got SNDCP=%+v, want nil", cf.SNDCP)
		}
	}
}
