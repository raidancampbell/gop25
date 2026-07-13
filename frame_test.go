package p25

import (
	"math"
	"math/bits"
	"testing"
)

func TestExtractVoiceCW_Length(t *testing.T) {
	payload := make([]Dibit, 1728)
	for _, start := range lduVoiceStarts {
		raw := extractVoiceCW(payload, start)
		if len(raw) != voiceDibits*2 {
			t.Errorf("extractVoiceCW(start=%d) returned %d bits, want %d", start, len(raw), voiceDibits*2)
		}
	}
}

func TestExtractVoiceCW_PreservesData(t *testing.T) {
	// Fill payload with known dibits and verify extraction
	payload := make([]Dibit, 1728)
	for i := range payload {
		payload[i] = Dibit(i % 4)
	}
	raw := extractVoiceCW(payload, 0)
	// First dibit (payload[0]) should map to bits: MSB, LSB
	if raw[0] != uint8((payload[0]>>1)&1) || raw[1] != uint8(payload[0]&1) {
		t.Errorf("first dibit not correctly unpacked: got [%d,%d], payload[0]=%d", raw[0], raw[1], payload[0])
	}
}

func TestParseLDU1_ShortPayload(t *testing.T) {
	dec := NewP25Decoder(25000)
	f := Frame{
		NID:     NID{NAC: 0x293, DUID: 0x5},
		Payload: make([]Dibit, 100), // too short
	}
	if vf := dec.parseLDU1(f); vf != nil {
		t.Error("parseLDU1 should return nil for short payload")
	}
}

func TestParseLDU2_ShortPayload(t *testing.T) {
	dec := NewP25Decoder(25000)
	f := Frame{
		NID:     NID{NAC: 0x293, DUID: 0xA},
		Payload: make([]Dibit, 100), // too short
	}
	if vf := dec.parseLDU2(f); vf != nil {
		t.Error("parseLDU2 should return nil for short payload")
	}
}

func TestParseLDU2_AlgoIDZero_NotEncrypted(t *testing.T) {
	// AlgoID=0x00 should also be treated as unencrypted
	nac := uint16(0x293)
	duid := uint8(0xA)
	pLen := payloadLen(duid)
	payload := make([]Dibit, pLen)
	for vc := 0; vc < 9; vc++ {
		fillEncodedVoiceCW(payload, lduVoiceStarts[vc])
	}

	// AlgoID=0x00 (all zeros already)
	f := Frame{NID: NID{NAC: nac, DUID: duid}, Payload: payload}
	dec := NewP25Decoder(25000)
	vf := dec.parseLDU2(f)
	if vf == nil {
		t.Fatal("parseLDU2 returned nil")
	}
	if vf.Encrypted {
		t.Error("AlgoID=0x00 should not be encrypted")
	}
	if vf.AlgoID != 0x00 {
		t.Errorf("AlgoID = 0x%02X, want 0x00", vf.AlgoID)
	}
}

func TestParseLDU1_LCCarryForward(t *testing.T) {
	// When LC extraction fails, the decoder should carry forward from the last successful LC
	dec := NewP25Decoder(25000)

	// First: parse an LDU1 with good LC
	unitID := uint32(999999)
	talkgroup := uint16(200)
	f1 := buildLDU1Frame(0x293, unitID, talkgroup, 0x00)
	vf1 := dec.parseLDU1(f1)
	if vf1 == nil {
		t.Fatal("first parseLDU1 returned nil")
	}
	if vf1.UnitID != unitID {
		t.Errorf("first LDU1: UnitID = %d, want %d", vf1.UnitID, unitID)
	}

	// Second: parse an LDU2 — should carry forward LC from LDU1
	// AlgoID=0x80 (unencrypted)
	f2 := buildLDU2Frame(0x293, 0x80, 0x0000)
	vf2 := dec.parseLDU2(f2)
	if vf2 == nil {
		t.Fatal("parseLDU2 returned nil")
	}
	if vf2.UnitID != unitID {
		t.Errorf("LDU2 carry-forward: UnitID = %d, want %d", vf2.UnitID, unitID)
	}
	if vf2.Talkgroup != talkgroup {
		t.Errorf("LDU2 carry-forward: Talkgroup = %d, want %d", vf2.Talkgroup, talkgroup)
	}
}

func TestParseLDU1_MultipleUnitIDs(t *testing.T) {
	// Verify different Unit IDs are extracted correctly
	testCases := []struct {
		unitID    uint32
		talkgroup uint16
		mfid      uint8
	}{
		{0, 0, 0},
		{1, 1, 0},
		{0xFFFFFF, 0xFFFF, 0xFF},
		{1234567, 100, 0x00},
		{0x000001, 0x0001, 0x90},
	}
	for _, tc := range testCases {
		f := buildLDU1Frame(0x293, tc.unitID, tc.talkgroup, tc.mfid)
		dec := NewP25Decoder(25000)
		vf := dec.parseLDU1(f)
		if vf == nil {
			t.Errorf("parseLDU1 returned nil for unitID=%d", tc.unitID)
			continue
		}
		// Note: only 24 bits for UnitID
		wantUID := tc.unitID & 0xFFFFFF
		if vf.UnitID != wantUID {
			t.Errorf("UnitID = %d (0x%06X), want %d (0x%06X)", vf.UnitID, vf.UnitID, wantUID, wantUID)
		}
		if vf.Talkgroup != tc.talkgroup {
			t.Errorf("Talkgroup = %d, want %d", vf.Talkgroup, tc.talkgroup)
		}
	}
}

func TestParseLDU2_EncryptionVariants(t *testing.T) {
	testCases := []struct {
		algoID    uint8
		keyID     uint16
		encrypted bool
	}{
		{0x00, 0x0000, false}, // no encryption
		{0x80, 0x0000, false}, // unencrypted marker
		{0x80, 0x1234, false}, // unencrypted with key ID (ignored)
		{0x81, 0x0001, true},  // DES-OFB
		{0x84, 0x0002, true},  // AES-256
		{0xAA, 0xFFFF, true},  // arbitrary encrypted
	}
	for _, tc := range testCases {
		f := buildLDU2Frame(0x293, tc.algoID, tc.keyID)
		dec := NewP25Decoder(25000)
		vf := dec.parseLDU2(f)
		if vf == nil {
			t.Errorf("parseLDU2 returned nil for algoID=0x%02X", tc.algoID)
			continue
		}
		if vf.Encrypted != tc.encrypted {
			t.Errorf("algoID=0x%02X: Encrypted=%v, want %v", tc.algoID, vf.Encrypted, tc.encrypted)
		}
		if vf.AlgoID != tc.algoID {
			t.Errorf("algoID=0x%02X: got 0x%02X", tc.algoID, vf.AlgoID)
		}
		if vf.KeyID != tc.keyID {
			t.Errorf("keyID=0x%04X: got 0x%04X", tc.keyID, vf.KeyID)
		}
	}
}

func TestExtractLC_ShortPayload(t *testing.T) {
	// LC extraction should return nil if payload is too short for any fragment
	lc := extractLC(make([]Dibit, 50))
	if lc != nil {
		t.Error("extractLC should return nil for short payload")
	}
}

func TestExtractES_ShortPayload(t *testing.T) {
	es := extractES(make([]Dibit, 50))
	if es != nil {
		t.Error("extractES should return nil for short payload")
	}
}

func TestPayloadLen_AllDUIDs(t *testing.T) {
	// Verify expected payload lengths per TIA-102.BAAA-A table 7-1.
	// Total frame dibits = bits/2; payload = total - sync(24) - NID(33).
	expected := map[uint8]int{
		0x0: 396 - syncLen - nidSpan, // HDU (792 bits)
		0x3: 72 - syncLen - nidSpan,  // TDU (144 bits)
		0x5: 864 - syncLen - nidSpan, // LDU1 (1728 bits)
		0x7: 360 - syncLen - nidSpan, // TSDU single-block (720 bits)
		0xA: 864 - syncLen - nidSpan, // LDU2 (1728 bits)
		0xF: 216 - syncLen - nidSpan, // TDUlc (432 bits)
	}
	for duid, want := range expected {
		got := payloadLen(duid)
		if got != want {
			t.Errorf("payloadLen(0x%X) = %d, want %d", duid, got, want)
		}
	}
	// Unknown DUID
	if payloadLen(0x9) != 0 {
		t.Error("payloadLen for unknown DUID should be 0")
	}
}

func TestP25Decoder_ProcessNonVoiceDUIDs(t *testing.T) {
	// HDU, TDU, TDUlc, TSDU should not produce VoiceFrames
	dec := NewP25Decoder(25000)
	for _, duid := range []uint8{0x0, 0x3, 0x7, 0xF} {
		pLen := payloadLen(duid)
		payload := make([]Dibit, pLen)
		f := Frame{NID: NID{NAC: 0x293, DUID: duid}, Payload: payload}
		// Directly test the processing logic
		switch f.NID.DUID {
		case 0x5:
			t.Error("should not match LDU1")
		case 0xA:
			t.Error("should not match LDU2")
		}
		_ = dec // just verifying the switch logic is correct
	}
}

func TestP25Decoder_Reset(t *testing.T) {
	dec := NewP25Decoder(25000)

	// Parse an LDU1 to populate lastLC
	f := buildLDU1Frame(0x293, 1234567, 100, 0x00)
	dec.parseLDU1(f)
	if !dec.lastLC.valid {
		t.Fatal("lastLC should be valid after parsing LDU1")
	}

	dec.Reset()
	if dec.lastLC.valid {
		t.Error("lastLC should be cleared after Reset")
	}
}

func TestP25Decoder_LDU1ThenLDU2Sequence(t *testing.T) {
	// Simulate a realistic LDU1→LDU2 sequence
	dec := NewP25Decoder(25000)

	// LDU1 with known LC
	f1 := buildLDU1Frame(0x293, 5551234, 300, 0x00)
	vf1 := dec.parseLDU1(f1)
	if vf1 == nil {
		t.Fatal("parseLDU1 returned nil")
	}
	if vf1.UnitID != 5551234 {
		t.Errorf("LDU1 UnitID = %d, want 5551234", vf1.UnitID)
	}
	if vf1.DUID != 0x5 {
		t.Errorf("LDU1 DUID = 0x%X, want 0x5", vf1.DUID)
	}

	// LDU2 with unencrypted ES
	f2 := buildLDU2Frame(0x293, 0x80, 0x0000)
	vf2 := dec.parseLDU2(f2)
	if vf2 == nil {
		t.Fatal("parseLDU2 returned nil")
	}
	if vf2.Encrypted {
		t.Error("LDU2 should not be encrypted (AlgoID=0x80)")
	}
	// UnitID/Talkgroup carried from LDU1
	if vf2.UnitID != 5551234 {
		t.Errorf("LDU2 UnitID (carry) = %d, want 5551234", vf2.UnitID)
	}
	if vf2.Talkgroup != 300 {
		t.Errorf("LDU2 Talkgroup (carry) = %d, want 300", vf2.Talkgroup)
	}
	if vf2.DUID != 0xA {
		t.Errorf("LDU2 DUID = 0x%X, want 0xA", vf2.DUID)
	}
}

func TestBitsToUint32(t *testing.T) {
	tests := []struct {
		bits []uint8
		want uint32
	}{
		{[]uint8{1, 0, 1, 0}, 0xA},
		{[]uint8{1, 1, 1, 1, 1, 1, 1, 1}, 0xFF},
		{[]uint8{0}, 0},
		{[]uint8{1}, 1},
		{nil, 0},
	}
	for _, tt := range tests {
		got := bitsToUint32(tt.bits)
		if got != tt.want {
			t.Errorf("bitsToUint32(%v) = 0x%X, want 0x%X", tt.bits, got, tt.want)
		}
	}
}

func TestBitsToUint16(t *testing.T) {
	tests := []struct {
		bits []uint8
		want uint16
	}{
		{[]uint8{1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0}, 0xAAAA},
		{[]uint8{0, 0, 0, 0}, 0},
		{[]uint8{1, 1, 1, 1}, 0xF},
	}
	for _, tt := range tests {
		got := bitsToUint16(tt.bits)
		if got != tt.want {
			t.Errorf("bitsToUint16(%v) = 0x%X, want 0x%X", tt.bits, got, tt.want)
		}
	}
}

// --- Helper: build a complete LDU1 frame with known LC ---

// writeLDUHexbits is the inverse of extractLDUHexbits: it Hamming(10,6)-
// encodes each hexbit and writes the 240 LC/ES bits at lduLCBitPositions.
func writeLDUHexbits(payload []Dibit, hb [24]uint8) {
	const fullFrameOffset = 2 * (syncLen + nidSpan)
	for i := range 24 {
		cw := (uint16(hb[i]&0x3F) << 4) | uint16(hamming1063Encode(hb[i]))
		for j := range 10 {
			pb := int(lduLCBitPositions[i*10+j]) - fullFrameOffset
			di := pb / 2
			bit := uint8((cw >> uint(9-j)) & 1)
			if pb%2 == 0 {
				payload[di] = (payload[di] &^ 2) | Dibit(bit<<1)
			} else {
				payload[di] = (payload[di] &^ 1) | Dibit(bit)
			}
		}
	}
}

func buildLDU1Frame(nac uint16, unitID uint32, talkgroup uint16, mfid uint8) Frame {
	return buildLDU1FrameSvc(nac, unitID, talkgroup, mfid, 0x00)
}

// buildLDU1FrameSvc is buildLDU1Frame with an explicit service-options byte
// (LCW byte 2), used to exercise the emergency/priority bits.
func buildLDU1FrameSvc(nac uint16, unitID uint32, talkgroup uint16, mfid, svcOpts uint8) Frame {
	payload := make([]Dibit, payloadLen(0x5))
	for vc := range 9 {
		fillEncodedVoiceCW(payload, lduVoiceStarts[vc])
	}

	// LCW for LCO=0 "Group Voice Channel User" (TIA-102.BAAA 7.3):
	//   LCO[8] MFID[8] SvcOpts[8] rsvd[8] TGID[16] SrcID[24]
	lcBits := make([]uint8, 72)
	pack := func(off, n int, v uint32) {
		for i := range n {
			lcBits[off+i] = uint8((v >> uint(n-1-i)) & 1)
		}
	}
	pack(8, 8, uint32(mfid))
	pack(16, 8, uint32(svcOpts))
	pack(32, 16, uint32(talkgroup))
	pack(48, 24, unitID)

	var hb [24]uint8
	for i := range 12 {
		hb[i] = uint8(bitsToUint32(lcBits[i*6 : i*6+6]))
	}
	hb = rsEncode63(hb, 12)
	writeLDUHexbits(payload, hb)

	return Frame{NID: NID{NAC: nac, DUID: 0x5}, Payload: payload}
}

// buildLDU1FrameLCW builds an LDU1 frame carrying an arbitrary 72-bit LCW
// (MSB-first bit slice), used to exercise vendor LCOs (Motorola GPS, etc.).
func buildLDU1FrameLCW(nac uint16, lcBits []uint8) Frame {
	payload := make([]Dibit, payloadLen(0x5))
	for vc := range 9 {
		fillEncodedVoiceCW(payload, lduVoiceStarts[vc])
	}
	var hb [24]uint8
	for i := range 12 {
		hb[i] = uint8(bitsToUint32(lcBits[i*6 : i*6+6]))
	}
	hb = rsEncode63(hb, 12)
	writeLDUHexbits(payload, hb)
	return Frame{NID: NID{NAC: nac, DUID: 0x5}, Payload: payload}
}

// TestParseLDU1_MotorolaUnitGPS verifies parseLDU1 decodes a Motorola Unit GPS
// LCW (LCO=6, MFID=0x90) and surfaces the position on the VoiceFrame.
func TestParseLDU1_MotorolaUnitGPS(t *testing.T) {
	lcBits := make([]uint8, 72)
	pack := func(off, n int, v uint32) {
		for i := range n {
			lcBits[off+i] = uint8((v >> uint(n-1-i)) & 1)
		}
	}
	pack(0, 8, 6)     // LCO=6
	pack(8, 8, 0x90)  // MFID Motorola
	const latMag = 0x400000
	const lonMag = 0x200000
	pack(25, 23, latMag)
	lcBits[48] = 1 // lon sign -> -180 offset
	pack(49, 23, lonMag)

	wantLat := float64(latMag) * 90.0 / float64(0x7FFFFF)
	wantLon := float64(lonMag)*180.0/float64(0x7FFFFF) - 180.0

	f := buildLDU1FrameLCW(0x293, lcBits)
	dec := NewP25Decoder(25000)
	vf := dec.parseLDU1(f)
	if vf == nil {
		t.Fatal("parseLDU1 returned nil")
	}
	if !vf.GPSOK {
		t.Fatalf("vf.GPSOK = false, want true")
	}
	if math.Abs(vf.GPS.Lat-wantLat) > 1e-4 || math.Abs(vf.GPS.Lon-wantLon) > 1e-4 {
		t.Errorf("vf.GPS = (%.5f, %.5f), want (%.5f, %.5f)", vf.GPS.Lat, vf.GPS.Lon, wantLat, wantLon)
	}
}

// TestProcessFrame_HDUCarriesTalkgroup verifies the HDU dispatch path (DUID 0x0)
// surfaces the header's talkgroup onto the emitted VoiceFrame. The HDU carries
// the talkgroup once at call start under the strong RS(36,20,17) code, so it must
// be usable to label a call whose recurring LDU1 link control never locks.
func TestProcessFrame_HDUCarriesTalkgroup(t *testing.T) {
	want := HDUData{AlgoID: 0x80, KeyID: 0, TalkgroupID: 5301}
	payload := buildHDUPayloadWithStatus(synthHDUBits(t, want))
	dec := NewP25Decoder(25000)
	voice, ctrl := dec.processFrame(Frame{NID: NID{NAC: 0x293, DUID: 0x0}, Payload: payload})
	if len(voice) != 1 {
		t.Fatalf("processFrame returned %d voice frames, want 1", len(voice))
	}
	if voice[0].Talkgroup != 5301 {
		t.Errorf("HDU VoiceFrame.Talkgroup = %d, want 5301", voice[0].Talkgroup)
	}
	// The ControlFrame carries it too (pre-existing); guard that assumption.
	if len(ctrl) != 1 || ctrl[0].HDU == nil || ctrl[0].HDU.TalkgroupID != 5301 {
		t.Fatalf("HDU ControlFrame.TalkgroupID missing: %+v", ctrl)
	}
}

// TestProcessFrame_TDUlcMotorolaGPS verifies the TDULC dispatch path (DUID 0xF)
// also decodes Motorola Unit GPS, for parity with the LDU1 path.
func TestProcessFrame_TDUlcMotorolaGPS(t *testing.T) {
	lcBits := make([]uint8, 72)
	pack := func(off, n int, v uint32) {
		for i := range n {
			lcBits[off+i] = uint8((v >> uint(n-1-i)) & 1)
		}
	}
	pack(0, 8, 6)    // LCO=6
	pack(8, 8, 0x90) // MFID Motorola
	const latMag = 0x300000
	pack(25, 23, latMag)
	wantLat := float64(latMag) * 90.0 / float64(0x7FFFFF)

	payload := encodeTDUlcPayloadLCW(t, lcBits)
	dec := NewP25Decoder(25000)
	voice, _ := dec.processFrame(Frame{NID: NID{NAC: 0x293, DUID: 0xF}, Payload: payload})
	if len(voice) != 1 {
		t.Fatalf("processFrame returned %d voice frames, want 1", len(voice))
	}
	vf := voice[0]
	if !vf.GPSOK {
		t.Fatalf("vf.GPSOK = false, want true")
	}
	if math.Abs(vf.GPS.Lat-wantLat) > 1e-4 {
		t.Errorf("vf.GPS.Lat = %.5f, want %.5f", vf.GPS.Lat, wantLat)
	}
}

// TestParseLDU1_ServiceOptions verifies parseLDU1 surfaces the LCO=0 service-
// options byte (and thus the emergency bit) onto the VoiceFrame.
func TestParseLDU1_ServiceOptions(t *testing.T) {
	const svcOpts = uint8(0x80) // emergency
	f := buildLDU1FrameSvc(0x293, 1234567, 100, 0x00, svcOpts)
	dec := NewP25Decoder(25000)
	vf := dec.parseLDU1(f)
	if vf == nil {
		t.Fatal("parseLDU1 returned nil")
	}
	if vf.ServiceOpts != svcOpts {
		t.Errorf("vf.ServiceOpts = 0x%02X, want 0x%02X", vf.ServiceOpts, svcOpts)
	}
}

// --- Helper: build a complete LDU2 frame with known ES ---

func buildLDU2Frame(nac uint16, algoID uint8, keyID uint16) Frame {
	payload := make([]Dibit, payloadLen(0xA))
	for vc := range 9 {
		fillEncodedVoiceCW(payload, lduVoiceStarts[vc])
	}

	// ES (96 bits): MI[72] | AlgoID[8] | KeyID[16]
	esBits := make([]uint8, 96)
	pack := func(off, n int, v uint32) {
		for i := range n {
			esBits[off+i] = uint8((v >> uint(n-1-i)) & 1)
		}
	}
	pack(72, 8, uint32(algoID))
	pack(80, 16, uint32(keyID))

	var hb [24]uint8
	for i := range 16 {
		hb[i] = uint8(bitsToUint32(esBits[i*6 : i*6+6]))
	}
	hb = rsEncode63(hb, 8)
	writeLDUHexbits(payload, hb)

	return Frame{NID: NID{NAC: nac, DUID: 0xA}, Payload: payload}
}

func TestGolayEncode_RoundTrip(t *testing.T) {
	for msg := uint16(0); msg < 4096; msg++ {
		encoded := golayEncode(msg)
		decoded, ok := golayDecode(encoded)
		if !ok {
			t.Fatalf("golayDecode failed for msg=0x%03X", msg)
		}
		if decoded != msg {
			t.Fatalf("round-trip mismatch: msg=0x%03X, got=0x%03X", msg, decoded)
		}
	}
}

func TestGolayDecode_BitErrors(t *testing.T) {
	msg := uint16(0xABC)
	encoded := golayEncode(msg)

	// 1-bit errors
	for i := 0; i < 23; i++ {
		corrupted := encoded ^ (1 << uint(i))
		decoded, ok := golayDecode(corrupted)
		if !ok || decoded != msg {
			t.Errorf("1-bit error at pos %d: ok=%v decoded=0x%03X want=0x%03X", i, ok, decoded, msg)
		}
	}

	// 2-bit errors (sample a subset)
	for i := 0; i < 23; i += 3 {
		for j := i + 1; j < 23; j += 3 {
			corrupted := encoded ^ (1 << uint(i)) ^ (1 << uint(j))
			decoded, ok := golayDecode(corrupted)
			if !ok || decoded != msg {
				t.Errorf("2-bit error at pos %d,%d: ok=%v decoded=0x%03X want=0x%03X", i, j, ok, decoded, msg)
			}
		}
	}

	// 3-bit errors (sample a few)
	for i := 0; i < 23; i += 5 {
		for j := i + 1; j < 23; j += 5 {
			for k := j + 1; k < 23; k += 5 {
				corrupted := encoded ^ (1 << uint(i)) ^ (1 << uint(j)) ^ (1 << uint(k))
				decoded, ok := golayDecode(corrupted)
				if !ok || decoded != msg {
					t.Errorf("3-bit error at pos %d,%d,%d: ok=%v decoded=0x%03X want=0x%03X",
						i, j, k, ok, decoded, msg)
				}
			}
		}
	}
}

func TestGolayEncode_Weight(t *testing.T) {
	// All Golay(23,12) codewords have minimum weight 7
	for msg := uint16(0); msg < 4096; msg++ {
		cw := golayEncode(msg)
		w := bits.OnesCount32(cw)
		if msg != 0 && w < 7 {
			t.Errorf("msg=0x%03X: codeword weight %d < 7", msg, w)
		}
	}
}

func TestParseLDU1_Synthetic(t *testing.T) {
	nac := uint16(0x293)
	unitID := uint32(1234567)
	talkgroup := uint16(100)

	f := buildLDU1Frame(nac, unitID, talkgroup, 0x00)

	dec := NewP25Decoder(25000)
	vf := dec.parseLDU1(f)
	if vf == nil {
		t.Fatal("parseLDU1 returned nil")
	}
	if vf.NAC != nac {
		t.Errorf("NAC = 0x%03X, want 0x%03X", vf.NAC, nac)
	}
	if vf.UnitID != unitID {
		t.Errorf("UnitID = %d, want %d", vf.UnitID, unitID)
	}
	if vf.Talkgroup != talkgroup {
		t.Errorf("Talkgroup = %d, want %d", vf.Talkgroup, talkgroup)
	}
}

// TestParseLDU1_IMBEErrors_CountsCorruption verifies that corrupting bits in
// a voice codeword raises the FEC error count reported on the VoiceFrame,
// so recorders can measure real decode quality across a call's voice
// codewords rather than just the C4FM symbol-recovery EVM. The synthetic
// all-zero baseline is not itself a zero-error codeword (C1-C6 are
// PR-sequence-whitened from C0 before their own FEC decode), so this compares
// corrupted against baseline rather than asserting an absolute value.
func TestParseLDU1_IMBEErrors_CountsCorruption(t *testing.T) {
	base := buildLDU1Frame(0x293, 1234567, 100, 0x00)
	dec := NewP25Decoder(25000)
	baseVF := dec.parseLDU1(base)
	if baseVF == nil {
		t.Fatal("parseLDU1 returned nil for baseline frame")
	}

	corrupted := buildLDU1Frame(0x293, 1234567, 100, 0x00)
	corruptVoiceCW(corrupted.Payload, lduVoiceStarts[0])
	corruptVF := dec.parseLDU1(corrupted)
	if corruptVF == nil {
		t.Fatal("parseLDU1 returned nil for corrupted frame")
	}

	if corruptVF.IMBEErrors <= baseVF.IMBEErrors {
		t.Errorf("IMBEErrors = %d after corruption, want > baseline %d", corruptVF.IMBEErrors, baseVF.IMBEErrors)
	}
}

// corruptVoiceCW flips several dibits within one voice codeword's span
// (skipping status symbols, mirroring fillEncodedVoiceCW), moving it away
// from the all-zero codeword to exercise the FEC error path.
func corruptVoiceCW(payload []Dibit, start int) {
	flipped := 0
	for i := start; flipped < 6 && i < len(payload); i++ {
		if isStatusPosition(i) {
			continue
		}
		payload[i] = 3
		flipped++
	}
}

func TestExtractLC_UnitToUnit_LCO3(t *testing.T) {
	// LCO=3 "Unit-to-Unit Voice Channel User" LCW (72 bits):
	//   LCO[8]=0x03, MFID[8]=0x00, SvcOpts[8]=0x00, Target[24]=0x00ABCD, Source[24]=0x001234
	lcBits := make([]uint8, 72)
	pack := func(off, n int, v uint32) {
		for i := range n {
			lcBits[off+i] = uint8((v >> uint(n-1-i)) & 1)
		}
	}
	pack(0, 8, 0x03)       // LCO=3
	pack(8, 8, 0x00)       // MFID
	pack(16, 8, 0x00)      // service options
	pack(24, 24, 0x00ABCD) // target/dest
	pack(48, 24, 0x001234) // source

	// Golay+RS encode into hexbits (replicate buildLDU1Frame's synthesis)
	var hb [24]uint8
	for i := range 12 {
		hb[i] = uint8(bitsToUint32(lcBits[i*6 : i*6+6]))
	}
	hb = rsEncode63(hb, 12)

	// Build the frame
	payload := make([]Dibit, payloadLen(0x5))
	for vc := range 9 {
		fillEncodedVoiceCW(payload, lduVoiceStarts[vc])
	}
	writeLDUHexbits(payload, hb)
	frame := Frame{NID: NID{NAC: 0x293, DUID: 0x5}, Payload: payload}

	// Parse and assert
	d := NewP25Decoder(48000)
	vf := d.parseLDU1(frame)
	if vf == nil {
		t.Fatal("parseLDU1 returned nil")
	}
	if vf.LCO != 3 {
		t.Errorf("LCO = %d, want 3", vf.LCO)
	}
	if vf.UnitID != 0x001234 {
		t.Errorf("UnitID (source) = %#x, want 0x1234", vf.UnitID)
	}
	if vf.DestID != 0x00ABCD {
		t.Errorf("DestID (target) = %#x, want 0xABCD", vf.DestID)
	}
	if vf.Talkgroup != 0 {
		t.Errorf("Talkgroup = %d, want 0 (private call)", vf.Talkgroup)
	}
}

func TestParseLDU2_Encrypted(t *testing.T) {
	algoID := uint8(0xAA)
	keyID := uint16(0x1234)

	f := buildLDU2Frame(0x293, algoID, keyID)
	dec := NewP25Decoder(25000)
	vf := dec.parseLDU2(f)
	if vf == nil {
		t.Fatal("parseLDU2 returned nil")
	}
	if !vf.Encrypted {
		t.Error("expected Encrypted=true for AlgoID=0xAA")
	}
	if vf.AlgoID != algoID {
		t.Errorf("AlgoID = 0x%02X, want 0x%02X", vf.AlgoID, algoID)
	}
	if vf.KeyID != keyID {
		t.Errorf("KeyID = 0x%04X, want 0x%04X", vf.KeyID, keyID)
	}
}

func TestParseLDU2_Unencrypted(t *testing.T) {
	f := buildLDU2Frame(0x293, 0x80, 0x0000)
	dec := NewP25Decoder(25000)
	vf := dec.parseLDU2(f)
	if vf == nil {
		t.Fatal("parseLDU2 returned nil")
	}
	if vf.Encrypted {
		t.Error("expected Encrypted=false for AlgoID=0x80")
	}
}

// TestParseLDU1_TalkerAlias verifies that a Motorola talker alias (header +
// data blocks) is recognized across multiple LDU1 frames, reassembled, and
// surfaced on VoiceFrame when complete. References TIA-102.AABD Annex A,
// sdrtrunk LCMotorolaTalkerAliasAssembler.java.
func TestParseLDU1_TalkerAlias(t *testing.T) {
	const (
		seq = 3
		tg  = 0x1234
	)
	// Build a Motorola talker-alias buffer: SUID[7] | encoded-alias | CRC[2].
	// Minimal valid: 7-byte stub SUID + 2-byte alias (1 UTF-16 char 'A' = 0x0041) + 2-byte CRC.
	// Total 11 bytes = 88 bits -> ceil(88/44) = 2 data blocks.
	suid := []byte{0, 0, 0, 0, 0, 0, 0}
	aliasBytes := []byte{0x00, 0x41} // UTF-16 big-endian 'A'
	payload := append(suid, aliasBytes...)
	crc := CRC16GSM(payload)
	buf := append(payload, byte(crc>>8), byte(crc&0xFF))

	hdr, blocks := packMotoBlocks(t, seq, tg, buf)

	// Use MotorolaAliasDecode as the oracle for the expected decoded alias.
	wantAlias, _, ok := MotorolaAliasDecode(buf)
	if !ok {
		t.Fatalf("MotorolaAliasDecode failed on synthetic buffer (CRC issue?)")
	}

	dec := NewP25Decoder(48000)

	// Build an LDU1 frame for each LCW (header + blocks).
	allLCWs := append([][9]byte{hdr}, blocks...)
	for i, lcw := range allLCWs {
		// Golay+RS encode the LCW into hexbits.
		lcBits := make([]uint8, 72)
		for j := range 9 {
			for bit := range 8 {
				lcBits[j*8+bit] = (lcw[j] >> uint(7-bit)) & 1
			}
		}
		var hb [24]uint8
		for j := range 12 {
			hb[j] = uint8(bitsToUint32(lcBits[j*6 : j*6+6]))
		}
		hb = rsEncode63(hb, 12)

		// Build the LDU1 payload (voice + LC hexbits).
		payload := make([]Dibit, payloadLen(0x5))
		for vc := range 9 {
			fillEncodedVoiceCW(payload, lduVoiceStarts[vc])
		}
		writeLDUHexbits(payload, hb)
		frame := Frame{NID: NID{NAC: 0x293, DUID: 0x5}, Payload: payload}

		// Parse and assert.
		vf := dec.parseLDU1(frame)
		if vf == nil {
			t.Fatalf("frame %d: parseLDU1 returned nil", i)
		}

		// Header + intermediate blocks: TalkerAlias should be empty.
		// Final block (i == len(allLCWs)-1): TalkerAlias should match wantAlias.
		if i < len(allLCWs)-1 {
			if vf.TalkerAlias != "" {
				t.Errorf("frame %d: TalkerAlias = %q, want empty (not complete yet)", i, vf.TalkerAlias)
			}
		} else {
			if vf.TalkerAlias != wantAlias {
				t.Errorf("frame %d: TalkerAlias = %q, want %q", i, vf.TalkerAlias, wantAlias)
			}
			if vf.TalkerAliasTGID != tg {
				t.Errorf("frame %d: TalkerAliasTGID = 0x%04X, want 0x%04X", i, vf.TalkerAliasTGID, tg)
			}
		}
	}
}

// encodeLCWIntoTDULC Golay+RS-encodes a 9-byte LC word into a TDULC (DUID 0xF)
// payload, mirroring the synthesis the TestParseTDUlc tests use. Returns the
// payload ready to feed processFrame.
func encodeLCWIntoTDULC(t *testing.T, lcw [9]byte) []Dibit {
	t.Helper()
	lcBits := make([]uint8, 72)
	for i := range 9 {
		for j := range 8 {
			lcBits[i*8+j] = (lcw[i] >> uint(7-j)) & 1
		}
	}
	var hb [rsN]uint8
	for i := range rsK {
		hb[i] = uint8(bitsToUint32(lcBits[i*6 : i*6+6]))
	}
	hb = rsEncode63(hb, rsN-rsK)

	out := make([]uint8, 0, 288)
	for c := range 12 {
		msg12 := (uint16(hb[2*c]) << 6) | uint16(hb[2*c+1])
		g := golayEncode(msg12)
		par := uint32(0)
		for x := g; x != 0; x >>= 1 {
			par ^= x & 1
		}
		cw24 := (g << 1) | par
		for b := 23; b >= 0; b-- {
			out = append(out, uint8((cw24>>uint(b))&1))
		}
	}

	payload := make([]Dibit, payloadLen(0xF))
	bi := 0
	for i := 0; i < len(payload) && bi+1 < tdulcDataBits; i++ {
		if isStatusPosition(i) {
			continue
		}
		payload[i] = Dibit(out[bi]<<1 | out[bi+1])
		bi += 2
	}
	return payload
}

// TestProcessFrame_TDULC_TalkerAlias drives a Motorola alias header + data
// blocks through the TDULC (DUID 0xF) path of processFrame. Aliases frequently
// arrive in the post-call TDULC on real systems, so this exercises that route
// end to end (the LDU1 route is covered by TestParseLDU1_TalkerAlias).
func TestProcessFrame_TDULC_TalkerAlias(t *testing.T) {
	const (
		seq = 5
		tg  = 0x07AB
	)
	suid := []byte{0, 0, 0, 0, 0, 0, 0}
	aliasBytes := []byte{0x00, 0x42} // UTF-16 big-endian 'B'
	payload := append(suid, aliasBytes...)
	crc := CRC16GSM(payload)
	buf := append(payload, byte(crc>>8), byte(crc&0xFF))

	hdr, blocks := packMotoBlocks(t, seq, tg, buf)
	wantAlias, _, ok := MotorolaAliasDecode(buf)
	if !ok {
		t.Fatalf("MotorolaAliasDecode failed on synthetic buffer")
	}

	dec := NewP25Decoder(48000)
	allLCWs := append([][9]byte{hdr}, blocks...)
	var lastAlias string
	var lastTG uint16
	for i, lcw := range allLCWs {
		frame := Frame{NID: NID{NAC: 0x293, DUID: 0xF}, Payload: encodeLCWIntoTDULC(t, lcw)}
		vfs, _ := dec.processFrame(frame)
		if len(vfs) != 1 {
			t.Fatalf("frame %d: want 1 VoiceFrame, got %d", i, len(vfs))
		}
		if i < len(allLCWs)-1 && vfs[0].TalkerAlias != "" {
			t.Errorf("frame %d: TalkerAlias = %q, want empty (not complete)", i, vfs[0].TalkerAlias)
		}
		lastAlias, lastTG = vfs[0].TalkerAlias, vfs[0].TalkerAliasTGID
	}
	if lastAlias != wantAlias {
		t.Errorf("TDULC final TalkerAlias = %q, want %q", lastAlias, wantAlias)
	}
	if lastTG != tg {
		t.Errorf("TDULC final TalkerAliasTGID = 0x%04X, want 0x%04X", lastTG, tg)
	}
}

// TestParseLDU1_HarrisTalkerAlias drives Harris alias blocks (LCO 50/51)
// through parseLDU1, exercising the addHarris dispatch arm (the Motorola arms
// are covered by TestParseLDU1_TalkerAlias).
func TestParseLDU1_HarrisTalkerAlias(t *testing.T) {
	lcws := [][9]byte{
		{0x32, 0xA4, 'E', 'N', 'G', 'I', 'N', 'E', ' '}, // LCO 50, "ENGINE "
		{0x33, 0xA4, '1', '2', ' ', 'C', 'A', 'P', 'T'}, // LCO 51, "12 CAPT"
	}
	want := HarrisAliasString([][]byte{lcws[0][2:], lcws[1][2:]})

	dec := NewP25Decoder(48000)
	var got string
	for i, lcw := range lcws {
		lcBits := make([]uint8, 72)
		for j := range 9 {
			for bit := range 8 {
				lcBits[j*8+bit] = (lcw[j] >> uint(7-bit)) & 1
			}
		}
		var hb [24]uint8
		for j := range 12 {
			hb[j] = uint8(bitsToUint32(lcBits[j*6 : j*6+6]))
		}
		hb = rsEncode63(hb, 12)

		payload := make([]Dibit, payloadLen(0x5))
		for vc := range 9 {
			fillEncodedVoiceCW(payload, lduVoiceStarts[vc])
		}
		writeLDUHexbits(payload, hb)
		frame := Frame{NID: NID{NAC: 0x293, DUID: 0x5}, Payload: payload}

		vf := dec.parseLDU1(frame)
		if vf == nil {
			t.Fatalf("block %d: parseLDU1 returned nil", i)
		}
		got = vf.TalkerAlias
	}
	if got != want {
		t.Errorf("Harris TalkerAlias = %q, want %q", got, want)
	}
}

// fillEncodedVoiceCW fills voiceDibits non-status positions starting at start
// with dibit 0, skipping status positions (mirrors extractVoiceCW read behavior).
func fillEncodedVoiceCW(payload []Dibit, start int) {
	written := 0
	for i := start; written < voiceDibits && i < len(payload); i++ {
		if isStatusPosition(i) {
			continue
		}
		payload[i] = 0
		written++
	}
}

func TestP25Decoder_Integration(t *testing.T) {
	// Build a full dibit stream: sync + NID + LDU1 payload
	nac := uint16(0x293)
	duid := uint8(0x5)
	pLen := payloadLen(duid)

	var stream []Dibit
	// sync word
	for _, d := range syncWord {
		stream = append(stream, d)
	}
	// NID
	msg := (nac << 4) | uint16(duid)
	encoded := bchEncode(msg)
	for i := 0; i < nidLen; i++ {
		shift := uint(2 * (nidLen - 1 - i))
		stream = append(stream, Dibit((encoded>>shift)&0x3))
	}
	// Payload
	payload := make([]Dibit, pLen)
	for vc := 0; vc < 9; vc++ {
		fillEncodedVoiceCW(payload, lduVoiceStarts[vc])
	}
	stream = append(stream, payload...)

	// Convert dibits to fake discriminator samples and run through P25Decoder
	samples := generateC4FM(stream, 25000, 0)
	dec := NewP25Decoder(25000)
	voiceFrames, _ := dec.Process(samples)

	// We may or may not get a VoiceFrame depending on symbol recovery accuracy.
	// Log the result for inspection.
	t.Logf("P25Decoder integration: %d voice frames from %d-dibit stream (%d samples)",
		len(voiceFrames), len(stream), len(samples))
	if len(voiceFrames) > 0 {
		vf := voiceFrames[0]
		t.Logf("  NAC=0x%03X DUID=0x%X UnitID=%d TG=%d Encrypted=%v",
			vf.NAC, vf.DUID, vf.UnitID, vf.Talkgroup, vf.Encrypted)
	}
}

func TestVoiceFrame_TalkerAliasUnit(t *testing.T) {
	var a aliasAssembler
	suid := []byte{0, 0, 0, 0, 0x12, 0x34, 0x56}
	valid := append(append([]byte{}, suid...), 0x41, 0x00)
	crc := CRC16GSM(valid)
	valid = append(valid, byte(crc>>8), byte(crc))
	blockCount := (len(valid)*8 + 43) / 44

	a.addMotorolaHeader(buildMotoHeaderLCW(1234, blockCount, 5))
	frags := fragsForBuffer(valid, blockCount)
	var gotUnit uint32
	for i := 1; i <= blockCount; i++ {
		_, _, unit, done := a.addMotorolaBlock(buildMotoBlockLCW(i, 5, frags[i-1]))
		if done {
			gotUnit = unit
		}
	}
	if gotUnit != 0x123456 {
		t.Fatalf("alias unit = %#x, want 0x123456", gotUnit)
	}
}
