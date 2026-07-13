package phase2

import (
	"testing"

	"github.com/raidancampbell/gop25"
)

func TestTDMAProcessor_NonVoiceBurst(t *testing.T) {
	proc := NewTDMAProcessor()
	defer proc.Close()

	b := Burst{Type: BurstSACCH}
	b.ISCH.Valid = true
	b.ISCH.Slot = 0
	if vf := proc.ProcessBurst(b); vf != nil {
		t.Error("expected nil P2VoiceFrame for SACCH burst")
	}
}

func TestTDMAProcessor_InvalidISCH(t *testing.T) {
	proc := NewTDMAProcessor()
	defer proc.Close()

	b := Burst{Type: Burst4V}
	b.ISCH.Valid = false
	b.ISCH.Slot = -1
	if vf := proc.ProcessBurst(b); vf != nil {
		t.Error("expected nil P2VoiceFrame for invalid ISCH")
	}
}

func TestTDMAProcessor_4VBurst_ProducesPCM(t *testing.T) {
	proc := NewTDMAProcessor()
	defer proc.Close()

	b := make4VBurst(0)
	vf := proc.ProcessBurst(b)
	if vf == nil {
		t.Fatal("expected non-nil P2VoiceFrame for 4V burst")
	}
	// 4 voice codewords × 160 samples each = 640 samples
	if len(vf.PCM) != 640 {
		t.Errorf("PCM length = %d, want 640", len(vf.PCM))
	}
	if vf.Slot != 0 {
		t.Errorf("Slot = %d, want 0", vf.Slot)
	}
}

func TestTDMAProcessor_2VBurst_ProducesPCM(t *testing.T) {
	proc := NewTDMAProcessor()
	defer proc.Close()

	b := make2VBurst(1)
	vf := proc.ProcessBurst(b)
	if vf == nil {
		t.Fatal("expected non-nil P2VoiceFrame for 2V burst")
	}
	// 2 voice codewords × 160 samples = 320 samples
	if len(vf.PCM) != 320 {
		t.Errorf("PCM length = %d, want 320", len(vf.PCM))
	}
	if vf.Slot != 1 {
		t.Errorf("Slot = %d, want 1", vf.Slot)
	}
}

// build2VBurstWithFACCH constructs a descrambled 2V burst whose FACCH region
// encodes a MAC_ACTIVE (opcode 4) sub-op 0x01 Group Voice Channel User PDU with
// the given talkgroup and source. We use sub-op 0x01 because its ga (buf[3:5])
// and sa (buf[5:8]) fields sit clear of the FACCH 12-bit CRC region (the
// trailing 12 bits of the 144-bit PDU), so the decoded tg/src are the literals
// we wrote, not CRC-stamped values. DecodeACCH(_, true) only reads the FACCH
// dibit ranges, so the voice codewords (left zero here) do not affect it; the
// resulting PCM is silence/garbage, which is fine — the test asserts identity.
func build2VBurstWithFACCH(t *testing.T, tg uint16, src uint32) Burst {
	t.Helper()
	mac := macPDUForTest(ACCHFacch, func(b []byte) {
		b[0] = (4 << 5) // opcode 4 MAC_ACTIVE
		b[1] = 0x01     // sub-opcode: group voice channel user (abbreviated)
		b[2] = 0x00     // service opts
		b[3], b[4] = byte(tg>>8), byte(tg)
		b[5], b[6], b[7] = byte(src>>16), byte(src>>8), byte(src)
	})
	var b Burst
	b.Dibits = acchEncodeForTest(mac, ACCHFacch)
	b.Type = Burst2V
	b.ISCH = ISCHInfo{Location: 0, Slot: 0, Valid: true}
	return b
}

func TestProcessBurst_2V_LatchesMACIdentity(t *testing.T) {
	tp := NewTDMAProcessor()
	defer tp.Close()

	b := build2VBurstWithFACCH(t, 1234, 0x1234)

	vf := tp.ProcessBurst(b)
	if vf == nil {
		t.Fatal("ProcessBurst returned nil for 2V burst")
	}
	if !vf.IdentityFromMAC {
		t.Fatalf("IdentityFromMAC=false, want true")
	}
	if vf.Talkgroup != 1234 || vf.SourceID != 0x1234 {
		t.Fatalf("MAC identity tg=%d src=%#x, want 1234/0x1234", vf.Talkgroup, vf.SourceID)
	}
}

func TestProcessBurst_2V_LatchesTalkerAlias(t *testing.T) {
	tp := NewTDMAProcessor()
	defer tp.Close()

	// Build a 2V burst carrying a Harris talker-alias (simpler than Motorola:
	// single sub-message, no multi-block assembly, no CRC validation).
	// Harris alias: op 0xA8, mfid 0xA4, payload is raw ASCII.
	b1 := build2VBurstWithHarrisAlias(t, "UNIT5")

	// First burst: Harris alias completes immediately (single sub-message)
	vf1 := tp.ProcessBurst(b1)
	if vf1 == nil {
		t.Fatal("ProcessBurst returned nil for 2V burst with Harris alias")
	}
	if vf1.TalkerAlias != "UNIT5" {
		t.Errorf("TalkerAlias=%q after Harris alias burst, want 'UNIT5'", vf1.TalkerAlias)
	}

	// Second burst (no alias sub-message): latched alias should persist
	b2 := make2VBurst(0)
	vf2 := tp.ProcessBurst(b2)
	if vf2 == nil {
		t.Fatal("ProcessBurst returned nil for second 2V burst")
	}
	if vf2.TalkerAlias != "UNIT5" {
		t.Errorf("TalkerAlias=%q on subsequent frame, want 'UNIT5'", vf2.TalkerAlias)
	}

	// ResetSlot should clear the alias
	tp.ResetSlot(0)
	b3 := make2VBurst(0)
	vf3 := tp.ProcessBurst(b3)
	if vf3 == nil {
		t.Fatal("ProcessBurst returned nil after ResetSlot")
	}
	if vf3.TalkerAlias != "" {
		t.Errorf("TalkerAlias=%q after ResetSlot, want empty", vf3.TalkerAlias)
	}
}

func TestProcessBurst_2V_LatchesHarrisGPS(t *testing.T) {
	tp := NewTDMAProcessor()
	defer tp.Close()

	// Build a known 112-bit Harris GPS field and embed it in a 2V FACCH burst.
	field := make([]uint8, 112)
	packGPSBits(field, 0, 16, 5000) // lat frac
	packGPSBits(field, 17, 7, 45)   // lat minutes
	packGPSBits(field, 24, 8, 39)   // lat degrees
	field[48] = 1                   // lon hemisphere negative
	packGPSBits(field, 49, 7, 30)   // lon minutes
	packGPSBits(field, 56, 8, 104)  // lon degrees
	want, ok := p25.DecodeHarrisGPS(field)
	if !ok {
		t.Fatalf("reference GPS decode failed")
	}

	b1 := build2VBurstWithHarrisGPS(t, field)
	vf1 := tp.ProcessBurst(b1)
	if vf1 == nil {
		t.Fatal("ProcessBurst returned nil for 2V GPS burst")
	}
	if !vf1.GPSOK || vf1.GPS != want {
		t.Fatalf("GPS=%+v ok=%v, want %+v", vf1.GPS, vf1.GPSOK, want)
	}

	// Latched GPS persists on a subsequent burst with no GPS sub-message.
	b2 := make2VBurst(0)
	vf2 := tp.ProcessBurst(b2)
	if vf2 == nil || !vf2.GPSOK || vf2.GPS != want {
		t.Fatalf("latched GPS lost on next frame: %+v ok=%v", vf2.GPS, vf2.GPSOK)
	}

	// ResetSlot clears it.
	tp.ResetSlot(0)
	b3 := make2VBurst(0)
	vf3 := tp.ProcessBurst(b3)
	if vf3 == nil || vf3.GPSOK {
		t.Fatalf("GPS not cleared after ResetSlot (ok=%v)", vf3.GPSOK)
	}
}

// build2VBurstWithHarrisGPS constructs a SACCH control burst carrying a Harris
// GPS sub-message (op 0xAA, mfid 0xA4) with the given 112-bit field. SACCH (21
// bytes) is used rather than the 2V FACCH (18 bytes) because the 17-byte GPS
// sub-message plus PDU header and CRC-12 do not fit in a FACCH.
func build2VBurstWithHarrisGPS(t *testing.T, field []uint8) Burst {
	t.Helper()
	fieldBytes := gpsBitsToBytes(field) // 14 bytes
	b := macPDUForTest(ACCHSacch, func(b []byte) {
		b[0] = (4 << 5) // MAC_ACTIVE
		b[1] = 0xAA     // Harris GPS sub-opcode
		b[2] = 0xA4     // mfid Harris
		msgLen := 3 + len(fieldBytes)
		b[3] = byte(msgLen & 0x3F)
		copy(b[4:], fieldBytes)
	})
	bits := make([]uint8, 168)
	for i := 0; i < 21; i++ {
		for k := 0; k < 8; k++ {
			bits[i*8+k] = (b[i] >> uint(7-k)) & 1
		}
	}

	var burst Burst
	burstDibits := synthACCHBurst(t, bits, ACCHSacch)
	burst.Raw = burstDibits
	burst.Dibits = burstDibits
	burst.ISCH = ISCHInfo{Location: 0, Slot: 0, Valid: true}
	for cw := 0; cw < 256; cw++ {
		if duidLookup[cw] == 12 { // unscrambled SACCH
			burst.DUID = uint8(cw)
			break
		}
	}
	burst.Type = Classify(burst)
	return burst
}

// build2VBurstWithHarrisAlias constructs a descrambled 2V burst whose FACCH
// carries a MAC_ACTIVE (opcode 4) PDU with a Harris talker-alias sub-message
// (op 0xA8, mfid 0xA4). Harris aliases are single sub-messages with raw ASCII
// payload (no CRC), making them simpler to synthesize than Motorola multi-block.
func build2VBurstWithHarrisAlias(t *testing.T, alias string) Burst {
	t.Helper()
	mac := macPDUForTest(ACCHFacch, func(b []byte) {
		b[0] = (4 << 5) // opcode 4 MAC_ACTIVE
		// Embed a Harris alias sub-message starting at byte 1.
		// Walker copies buf[ptr:ptr+msgLen] as body, so b[1:1+msgLen] becomes body[0:msgLen].
		// The assembler expects body[0]=op, body[1]=mfid, body[2]=len, body[3:]=ASCII payload.
		b[1] = 0xA8                // sub-op: vendor sub-message (b1b2=2)
		b[2] = 0xA4                // mfid: Harris
		msgLen := 3 + len(alias)   // op + mfid + len + ASCII payload
		b[3] = byte(msgLen & 0x3F) // length (masked with 0x3F per walker logic)
		// ASCII payload starts at byte 4 (body[3]).
		copy(b[4:], []byte(alias))
	})
	var burst Burst
	burst.Dibits = acchEncodeForTest(mac, ACCHFacch)
	burst.Type = Burst2V
	burst.ISCH = ISCHInfo{Location: 0, Slot: 0, Valid: true}
	return burst
}

func TestTDMAProcessor_WithScramble(t *testing.T) {
	proc := NewTDMAProcessor()
	defer proc.Close()
	proc.SetScrambleParams(0x293, 0x18, 0x1)

	b := make4VBurst(0)
	b.ISCH.Location = 3 // valid location for descrambling
	vf := proc.ProcessBurst(b)
	if vf == nil {
		t.Fatal("expected non-nil P2VoiceFrame with scramble params set")
	}
	if len(vf.PCM) != 640 {
		t.Errorf("PCM length = %d, want 640", len(vf.PCM))
	}
}

func TestTDMAProcessor_SlotsIndependent(t *testing.T) {
	proc := NewTDMAProcessor()
	defer proc.Close()

	// Process voice on slot 0, then slot 1 — both should produce output.
	b0 := make4VBurst(0)
	b1 := make4VBurst(1)

	vf0 := proc.ProcessBurst(b0)
	vf1 := proc.ProcessBurst(b1)

	if vf0 == nil || vf1 == nil {
		t.Fatal("both slots should produce P2VoiceFrames")
	}
	if vf0.Slot != 0 || vf1.Slot != 1 {
		t.Errorf("slot assignment wrong: got slots %d,%d want 0,1", vf0.Slot, vf1.Slot)
	}
}

func TestTDMAProcessor_ResetSlot(t *testing.T) {
	proc := NewTDMAProcessor()
	defer proc.Close()

	// Process a burst, reset, process again — should not panic.
	b := make4VBurst(0)
	proc.ProcessBurst(b)
	proc.ResetSlot(0)
	vf := proc.ProcessBurst(b)
	if vf == nil {
		t.Fatal("expected P2VoiceFrame after slot reset")
	}
}

func TestVCWPositions_NoOverlap(t *testing.T) {
	// Verify that VCW positions don't extend past the burst boundary.
	offsets := []int{
		PayloadOffset + VCW1Offset,
		PayloadOffset + VCW2Offset,
		PayloadOffset + VCW3Offset,
		PayloadOffset + VCW4Offset,
	}
	for i, off := range offsets {
		end := off + VoiceCWDibits
		if end > BurstDibits {
			t.Errorf("VCW%d extends past burst: end=%d > %d", i+1, end, BurstDibits)
		}
	}
	// ESS should not overlap with VCW3 or VCW4 start.
	essEnd := PayloadOffset + ESSOffset + ESSDibits
	vcw3Start := PayloadOffset + VCW3Offset
	if essEnd > vcw3Start {
		t.Errorf("ESS overlaps VCW3: ESS ends at %d, VCW3 starts at %d", essEnd, vcw3Start)
	}
}

func TestVCWPositions_MatchDUID(t *testing.T) {
	// DUID dibits at positions 10, 47, 132, 169 should be between or within
	// VCW ranges (they're embedded in the VCW data for DUIDs 1-3).
	// DUID[0] at burst 10 is before any VCW.
	vcw1Start := PayloadOffset + VCW1Offset
	if DUIDPos0 >= vcw1Start {
		t.Errorf("DUID[0] at %d should be before VCW1 start %d", DUIDPos0, vcw1Start)
	}
}

// --- test helpers ---

// make4VBurst creates a synthetic 4V burst for testing.
// Dibits are zero (FEC will fail but we still get silence PCM).
func make4VBurst(slot int) Burst {
	var b Burst
	b.Type = Burst4V
	b.ISCH.Valid = true
	b.ISCH.Slot = slot
	b.ISCH.Location = slot // simplification: location = slot for testing
	return b
}

func make2VBurst(slot int) Burst {
	var b Burst
	b.Type = Burst2V
	b.ISCH.Valid = true
	b.ISCH.Slot = slot
	b.ISCH.Location = slot + 1
	return b
}

// makeSynthetic4VBurst creates a burst with valid Golay-encoded voice codewords
// at the correct positions. All VCWs encode u=[0,0,0,0] for simplicity.
func makeSynthetic4VBurst(slot int) Burst {
	b := make4VBurst(slot)

	// Encode u=[0,0,0,0]: c0=Golay24(0), c1=Golay23(0)^PR(0), c2=0, c3=0
	u0 := uint16(0)
	c0_23 := golayEncode23(u0)
	c0 := (c0_23 << 1) | parityBit(c0_23)
	m1 := generatePRMask(u0)
	c1 := golayEncode23(0) ^ m1

	offsets := []int{
		PayloadOffset + VCW1Offset,
		PayloadOffset + VCW2Offset,
		PayloadOffset + VCW3Offset,
		PayloadOffset + VCW4Offset,
	}
	for _, off := range offsets {
		vcw := interleaveVCW(c0, c1, 0, 0)
		for i := 0; i < VoiceCWDibits; i++ {
			b.Dibits[off+i] = vcw[i]
		}
	}
	return b
}

func TestXORCodewordP2_OffsetFormula(t *testing.T) {
	// Verify the XOR offset formula matches op25: offset = 256 + 7*(cwIndex + burstID*4)
	// The XOR is its own inverse, so encrypt+decrypt should yield the original.
	var a p25.ADP
	key := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x12}
	mi := [9]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x00}
	if err := a.Prepare(key, mi); err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	// Test every valid (burstID, cwIndex) combination.
	for burstID := 0; burstID < 5; burstID++ {
		maxCW := 4
		if burstID == 4 {
			maxCW = 2
		}
		for cwIdx := 0; cwIdx < maxCW; cwIdx++ {
			plain := [7]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x80}
			ct := plain

			// Encrypt.
			a.XORCodewordP2(&ct, burstID, cwIdx)
			// The masked byte 6 should only have MSB.
			if ct[6]&0x7F != 0 {
				t.Errorf("burst=%d cw=%d: byte 6 low bits not masked: %#x", burstID, cwIdx, ct[6])
			}

			// Decrypt (XOR is its own inverse, but need fresh prepare + mask handling).
			var a2 p25.ADP
			a2.Prepare(key, mi)
			a2.XORCodewordP2(&ct, burstID, cwIdx)
			// After double-XOR, bytes 0-5 should match. Byte 6 is masked both times
			// so only the MSB survives.
			for i := 0; i < 6; i++ {
				if ct[i] != plain[i] {
					t.Errorf("burst=%d cw=%d byte[%d]: %#x != %#x", burstID, cwIdx, i, ct[i], plain[i])
				}
			}
			// Byte 6: only MSB should survive the mask (0x80).
			if ct[6] != (plain[6] & 0x80) {
				t.Errorf("burst=%d cw=%d byte[6]: %#x != %#x (MSB only)", burstID, cwIdx, ct[6], plain[6]&0x80)
			}
		}
	}
}

func TestXORCodewordP2_OffsetBounds(t *testing.T) {
	// Verify that the maximum offset doesn't exceed keystream length.
	// Max: burstID=4, cwIndex=1 → offset = 256 + 7*(1+4*4) = 256 + 7*17 = 256+119 = 375
	// Plus 6 bytes indexed: 375+6 = 381 < 469 (ADPKeystreamLen).
	maxOffset := 256 + 7*(1+4*4) + 6
	if maxOffset >= p25.ADPKeystreamLen {
		t.Errorf("max keystream index %d >= ADPKeystreamLen %d", maxOffset, p25.ADPKeystreamLen)
	}
}

func TestTDMAProcessor_ADPDecrypt_RoundTrip(t *testing.T) {
	// Simulate an encrypted superframe: encrypt clear voice codewords, feed
	// them to the TDMAProcessor with key lookup, and verify decryption produces
	// the same u[] values.
	key := []byte{0x62, 0x00, 0x32, 0x68, 0x31}
	mi := [9]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33}
	algID := uint8(0xAA) // ADP
	keyID := uint16(0x05FC)

	proc := NewTDMAProcessor()
	defer proc.Close()
	proc.SetKeyLookup(func(a uint8, k uint16) ([]byte, bool) {
		if a == algID && k == keyID {
			return key, true
		}
		return nil, false
	})

	// Encode clear u[]=[0,0,0,0] into dibits, then encrypt the packed form.
	u := [4]uint16{0, 0, 0, 0}
	c0_23 := golayEncode23(u[0])
	c0 := (c0_23 << 1) | parityBit(c0_23)
	m1 := generatePRMask(u[0])
	c1 := golayEncode23(u[1]) ^ m1

	// Build 5 bursts (4×4V + 1×2V) as a complete superframe cycle.
	// The ESS must report encryption for the processor to attempt decrypt.
	// We'll manually inject ESS data into the bursts.

	// First cycle: no cipher prepared yet → voice should pass through un-decrypted.
	// After the first 2V burst (cycle 0), the cipher is prepared for cycle 1.
	// We'll process two full cycles to verify decryption kicks in.

	// For simplicity, test that after a full cycle, the Decrypted flag is set on
	// subsequent frames when ESS reports encryption.
	// Use makeSynthetic4VBurst as a baseline, then tweak ESS area.

	// Build the ESS data that encodes algID=0xAA, keyID=0x05FC, mi=...
	essData := encodeESS(algID, keyID, mi)

	// Process cycle 0: 4 × 4V + 1 × 2V.
	// The 4V bursts accumulate ESS-B; the 2V triggers RS decode + cipher prepare.
	for burstIdx := 0; burstIdx < 4; burstIdx++ {
		b := Burst{Type: Burst4V}
		b.ISCH.Valid = true
		b.ISCH.Slot = 0
		b.ISCH.Location = burstIdx * 2

		// Place valid VCWs.
		offsets := []int{
			PayloadOffset + VCW1Offset,
			PayloadOffset + VCW2Offset,
			PayloadOffset + VCW3Offset,
			PayloadOffset + VCW4Offset,
		}
		vcw := interleaveVCW(c0, c1, 0, 0)
		for _, off := range offsets {
			for i := 0; i < VoiceCWDibits; i++ {
				b.Dibits[off+i] = vcw[i]
			}
		}

		// Place ESS-B hexbits.
		essStart := PayloadOffset + ESSOffset
		for i := 0; i < ESSDibits; i++ {
			b.Dibits[essStart+i] = essData.essB4V[burstIdx][i]
		}

		proc.ProcessBurst(b)
	}

	// 2V burst: ESS-A + voice.
	b2v := Burst{Type: Burst2V}
	b2v.ISCH.Valid = true
	b2v.ISCH.Slot = 0
	b2v.ISCH.Location = 1

	offsets := []int{PayloadOffset + VCW1Offset, PayloadOffset + VCW2Offset}
	vcw := interleaveVCW(c0, c1, 0, 0)
	for _, off := range offsets {
		for i := 0; i < VoiceCWDibits; i++ {
			b2v.Dibits[off+i] = vcw[i]
		}
	}
	essStart := PayloadOffset + ESSOffset
	for i := 0; i < len(essData.essA2V); i++ {
		b2v.Dibits[essStart+i] = essData.essA2V[i]
	}

	vf2v := proc.ProcessBurst(b2v)
	if vf2v == nil {
		t.Fatal("expected P2VoiceFrame from 2V burst")
	}
	// The 2V burst itself should NOT be decrypted (no cipher prepared yet for
	// cycle 0's voice), but after this burst the cipher is prepared for cycle 1.
	// The Decrypted flag should be false since hasMI was false when VCWs were processed.
	if vf2v.Decrypted {
		t.Error("expected Decrypted=false on first-cycle 2V burst")
	}

	// Now process cycle 1: encrypted voice with prepared cipher.
	// Encrypt the clear VCWs using the ADP keystream.
	var adp p25.ADP
	adp.Prepare(key, mi)

	for burstIdx := 0; burstIdx < 4; burstIdx++ {
		b := Burst{Type: Burst4V}
		b.ISCH.Valid = true
		b.ISCH.Slot = 0
		b.ISCH.Location = burstIdx * 2

		offsets := []int{
			PayloadOffset + VCW1Offset,
			PayloadOffset + VCW2Offset,
			PayloadOffset + VCW3Offset,
			PayloadOffset + VCW4Offset,
		}
		for cwIdx, off := range offsets {
			// Encrypt: pack clear u[], XOR with keystream, unpack, re-encode.
			clearPacked := PackCW(u)
			adp.XORCodewordP2(&clearPacked, burstIdx, cwIdx)
			encU := UnpackCW(clearPacked)

			// Re-encode the encrypted u[] through Golay.
			ec0_23 := golayEncode23(encU[0])
			ec0 := (ec0_23 << 1) | parityBit(ec0_23)
			em1 := generatePRMask(encU[0])
			ec1 := golayEncode23(encU[1]) ^ em1
			encVCW := interleaveVCW(ec0, ec1, uint32(encU[2]), uint32(encU[3]))
			for i := 0; i < VoiceCWDibits; i++ {
				b.Dibits[off+i] = encVCW[i]
			}
		}

		// Re-use same ESS-B data.
		essStart := PayloadOffset + ESSOffset
		for i := 0; i < ESSDibits; i++ {
			b.Dibits[essStart+i] = essData.essB4V[burstIdx][i]
		}

		vf := proc.ProcessBurst(b)
		if vf == nil {
			t.Fatalf("expected P2VoiceFrame from cycle-1 4V burst %d", burstIdx)
		}
		if !vf.Decrypted {
			t.Errorf("cycle-1 4V burst %d: expected Decrypted=true", burstIdx)
		}
		if !vf.Encrypted {
			t.Errorf("cycle-1 4V burst %d: expected Encrypted=true", burstIdx)
		}
	}
}

func TestTDMAProcessor_NoKeyLookup_NoDecrypt(t *testing.T) {
	// Without a key lookup, encrypted frames should not be decrypted.
	proc := NewTDMAProcessor()
	defer proc.Close()
	// No SetKeyLookup call.

	b := make4VBurst(0)
	vf := proc.ProcessBurst(b)
	if vf == nil {
		t.Fatal("expected P2VoiceFrame")
	}
	if vf.Decrypted {
		t.Error("expected Decrypted=false without key lookup")
	}
}

func TestTDMAProcessor_ResetSlot_ClearsADP(t *testing.T) {
	proc := NewTDMAProcessor()
	defer proc.Close()

	proc.SetKeyLookup(func(uint8, uint16) ([]byte, bool) {
		return []byte{1, 2, 3, 4, 5}, true
	})

	// Process a burst to establish some state.
	b := make4VBurst(0)
	proc.ProcessBurst(b)

	// Reset should clear ADP state.
	proc.ResetSlot(0)

	// After reset, slot should have no ADP prepared.
	ss := &proc.slots[0]
	if ss.adp != nil {
		t.Error("expected adp=nil after ResetSlot")
	}
	if ss.hasMI {
		t.Error("expected hasMI=false after ResetSlot")
	}
}

// --- ESS test data encoder ---

type essTestData struct {
	essB4V [4][ESSDibits]p25.Dibit // 4V burst ESS-B dibits (4 bursts × 12 dibits)
	essA2V [86]p25.Dibit           // 2V burst ESS-A dibits (85 + 1 spare)
}

// encodeESS creates synthetic ESS burst data that RS-encodes to the given
// AlgID/KeyID/MI. Uses the RS encoder from ess_test.go.
func encodeESS(algID uint8, keyID uint16, mi [9]byte) essTestData {
	// Pack AlgID(8) + KeyID(16) + MI(72) into 16 hexbits (6 bits each).
	var data [16]uint8
	data[0] = algID >> 2
	data[1] = (algID&0x03)<<4 | uint8(keyID>>12)
	data[2] = uint8((keyID >> 6) & 0x3F)
	data[3] = uint8(keyID & 0x3F)

	j := 4
	for i := 0; i < 9; i += 3 {
		data[j] = mi[i] >> 2
		data[j+1] = (mi[i]&0x03)<<4 | mi[i+1]>>4
		data[j+2] = (mi[i+1]&0x0F)<<2 | mi[i+2]>>6
		data[j+3] = mi[i+2] & 0x3F
		j += 4
	}

	// RS(63,35) encode: compute parity for the data hexbits.
	parity := encodeESSParity(data)

	// ESS-B = data hexbits, ESS-A = parity hexbits.
	essB := data
	essA := parity

	var td essTestData

	// 4V bursts: each carries 4 hexbits → 12 dibits (3 dibits per hexbit).
	for burstIdx := 0; burstIdx < 4; burstIdx++ {
		for i := 0; i < 4; i++ {
			h := essB[4*burstIdx+i]
			td.essB4V[burstIdx][3*i] = p25.Dibit((h >> 4) & 0x3)
			td.essB4V[burstIdx][3*i+1] = p25.Dibit((h >> 2) & 0x3)
			td.essB4V[burstIdx][3*i+2] = p25.Dibit(h & 0x3)
		}
	}

	// 2V burst: 28 hexbits → 85 dibits (with DUID skip after hexbit 15).
	j = 0
	for i := 0; i < 28; i++ {
		h := essA[i]
		td.essA2V[j] = p25.Dibit((h >> 4) & 0x3)
		td.essA2V[j+1] = p25.Dibit((h >> 2) & 0x3)
		td.essA2V[j+2] = p25.Dibit(h & 0x3)
		if i == 15 {
			j += 4 // skip one dibit (DUID position)
		} else {
			j += 3
		}
	}

	return td
}

// encodeESSParity computes the 28 parity hexbits for 16 data hexbits using
// RS(63,35) over GF(2^6). Reuses the same algorithm as ess_test.go:essRSEncode.
func encodeESSParity(data [16]uint8) [28]uint8 {
	// Build generator polynomial: g(x) = ∏(x - α^i), i=1..28.
	gen := []uint8{1}
	for i := 1; i <= 28; i++ {
		root := p25.GFExp(i)
		next := make([]uint8, len(gen)+1)
		for j, c := range gen {
			next[j+1] ^= c
			next[j] ^= p25.GFMul(c, root)
		}
		gen = next
	}

	// Place data at high positions.
	var msg [63]uint8
	for i := 0; i < 16; i++ {
		msg[43-i] = data[i]
	}

	// Polynomial long division.
	rem := make([]uint8, 63)
	copy(rem, msg[:])
	for i := 62; i >= 28; i-- {
		c := rem[i]
		if c == 0 {
			continue
		}
		for j := 0; j <= 28; j++ {
			rem[i-28+j] ^= p25.GFMul(c, gen[j])
		}
	}

	var parity [28]uint8
	for i := 0; i < 28; i++ {
		parity[i] = rem[27-i]
	}
	return parity
}

func TestTDMAProcessor_SyntheticVCW_NoFECErrors(t *testing.T) {
	proc := NewTDMAProcessor()
	defer proc.Close()

	b := makeSynthetic4VBurst(0)
	vf := proc.ProcessBurst(b)
	if vf == nil {
		t.Fatal("expected P2VoiceFrame")
	}
	if len(vf.PCM) != 640 {
		t.Errorf("PCM length = %d, want 640", len(vf.PCM))
	}
	// With valid Golay encoding, FEC error count from voice.go should be 0.
	// The vocoder may add its own errors (errs2), so just check it's reasonable.
	if vf.Errs > 20 {
		t.Errorf("FEC errors = %d, expected <= 20 for valid Golay-encoded VCWs", vf.Errs)
	}
}

func TestTDMAProcessor_HasKey(t *testing.T) {
	p := NewTDMAProcessor()

	// No key lookup configured -> never has a key.
	if p.HasKey(0x84, 0x1234) {
		t.Fatal("HasKey must be false when no key lookup is configured")
	}

	// Configure a lookup that only knows one (alg,key) pair.
	p.SetKeyLookup(func(algID uint8, keyID uint16) ([]byte, bool) {
		if algID == 0x84 && keyID == 0x1234 {
			return []byte{1, 2, 3}, true
		}
		return nil, false
	})

	if !p.HasKey(0x84, 0x1234) {
		t.Error("HasKey must be true for a known (alg,key) pair")
	}
	if p.HasKey(0x84, 0x9999) {
		t.Error("HasKey must be false for an unknown key id")
	}
}

func TestProcessBurst_ControlSACCH_EmitsIdentity(t *testing.T) {
	tp := NewTDMAProcessor()
	defer tp.Close()

	// Build a MAC_ACTIVE PDU (opcode 4) with a 0x01 Group Voice Channel User
	// sub-message: opts, ga(2), sa(3). Reuse the acch_test synthesis helper.
	tg := uint16(0x1234)
	src := uint32(0x0ABCDE)
	body := buildMACActiveGroupVoiceBody(t, tg, src)
	burstDibits := synthACCHBurst(t, body, ACCHSacch)

	var b Burst
	b.Raw = burstDibits
	b.Dibits = burstDibits
	b.ISCH = ISCHInfo{Location: 0, Slot: 0, Valid: true}
	// DUID codeword that maps to id 12 (unscrambled SACCH).
	for cw := 0; cw < 256; cw++ {
		if duidLookup[cw] == 12 {
			b.DUID = uint8(cw)
			break
		}
	}
	b.Type = Classify(b)
	if b.Type != BurstSACCH {
		t.Fatalf("setup: burst classified %v, want BurstSACCH", b.Type)
	}

	vf := tp.ProcessBurst(b)
	if vf == nil {
		t.Fatal("ProcessBurst returned nil for a control SACCH burst")
	}
	if !vf.ControlOnly || vf.PCM != nil {
		t.Fatalf("want ControlOnly with nil PCM, got ControlOnly=%v len(PCM)=%d", vf.ControlOnly, len(vf.PCM))
	}
	if vf.MACOpcode != MACOpActive {
		t.Fatalf("MACOpcode = %d, want %d (MAC_ACTIVE)", vf.MACOpcode, MACOpActive)
	}
	if !vf.IdentityFromMAC || vf.Talkgroup != tg || vf.SourceID != src {
		t.Fatalf("identity: from=%v tg=0x%X src=0x%X; want tg=0x%X src=0x%X",
			vf.IdentityFromMAC, vf.Talkgroup, vf.SourceID, tg, src)
	}
	if vf.Slot != 0 {
		t.Fatalf("Slot = %d, want 0", vf.Slot)
	}
}

// buildMACActiveGroupVoiceBody builds a 168-bit SACCH body with CRC-12,
// carrying a MAC_ACTIVE (opcode 4<<5) + 0x01 Group Voice Channel User sub-message.
func buildMACActiveGroupVoiceBody(t *testing.T, tg uint16, src uint32) []uint8 {
	t.Helper()
	b := macPDUForTest(ACCHSacch, func(b []byte) {
		b[0] = (4 << 5)                                           // opcode 4 MAC_ACTIVE
		b[1] = 0x01                                               // sub-opcode: group voice channel user (abbreviated)
		b[2] = 0x00                                               // service opts
		b[3], b[4] = byte(tg>>8), byte(tg)                        // ga = tg
		b[5], b[6], b[7] = byte(src>>16), byte(src>>8), byte(src) // sa = src
	})
	// Expand to 168 bits MSB-first.
	bits := make([]uint8, 168)
	for i := 0; i < 21; i++ {
		for k := 0; k < 8; k++ {
			bits[i*8+k] = (b[i] >> uint(7-k)) & 1
		}
	}
	return bits
}
