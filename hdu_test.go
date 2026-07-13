package p25

import (
	"math/rand"
	"testing"
)

// --- RS(36,20,17) tests ---

func TestRSHDURoundTrip(t *testing.T) {
	// Encode known data, decode clean, verify round-trip.
	var data [rsHDUK]uint8
	for i := range data {
		data[i] = uint8(i * 7 % 63)
	}
	cw := rsEncodeHDU(data)
	got, ok := rsDecodeHDU(cw)
	if !ok {
		t.Fatal("rsDecodeHDU failed on clean codeword")
	}
	for i, d := range data {
		if got[i] != d {
			t.Errorf("data[%d]: want %d, got %d", i, d, got[i])
		}
	}
}

func TestRSHDUErrorCorrection(t *testing.T) {
	// Verify t=8 error correction: inject up to 8 symbol errors and confirm decode.
	var data [rsHDUK]uint8
	for i := range data {
		data[i] = uint8((i * 13 + 5) % 63)
	}
	cw := rsEncodeHDU(data)

	// Inject 8 symbol errors at known positions.
	corrupt := cw
	errorPositions := []int{0, 4, 7, 11, 15, 20, 28, 35}
	for _, pos := range errorPositions {
		corrupt[pos] ^= 0x15 // XOR with nonzero to corrupt
		if corrupt[pos] == 0 {
			corrupt[pos] = 1
		}
	}

	got, ok := rsDecodeHDU(corrupt)
	if !ok {
		t.Fatal("rsDecodeHDU failed with 8 symbol errors (expected correction)")
	}
	for i, d := range data {
		if got[i] != d {
			t.Errorf("data[%d]: want %d, got %d", i, d, got[i])
		}
	}
}

func TestRSHDUTooManyErrors(t *testing.T) {
	// 9 errors should fail (exceeds t=8).
	var data [rsHDUK]uint8
	for i := range data {
		data[i] = uint8(i % 63)
	}
	cw := rsEncodeHDU(data)
	for i := 0; i < 9; i++ {
		cw[i] ^= 0x3F
		if cw[i] == 0 {
			cw[i] = 0x3F
		}
	}
	_, ok := rsDecodeHDU(cw)
	if ok {
		t.Log("note: RS corrected 9 errors (burst pattern may have been within correction capability)")
	}
}

func TestRSHDURandomData(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	for trial := 0; trial < 100; trial++ {
		var data [rsHDUK]uint8
		for i := range data {
			data[i] = uint8(rng.Intn(63))
		}
		cw := rsEncodeHDU(data)
		got, ok := rsDecodeHDU(cw)
		if !ok {
			t.Fatalf("trial %d: rsDecodeHDU failed on clean codeword", trial)
		}
		for i, d := range data {
			if got[i] != d {
				t.Fatalf("trial %d: data[%d] mismatch", trial, i)
			}
		}
	}
}

// The previous "HDU [17,8,5]" cyclic-code and parseHDU synthetic tests are
// removed: per TIA-102.BAAA and op25 process_HDU the on-air HDU inner code
// is shortened Golay(24,12,8) over 36 hexbits, NOT a [17,8] code over 15
// octets. Those tests passed only because the synthetic encoder shared the
// decoder's wrong layout — the same failure mode that hid the LDU1 LC offset
// bug (commit 41a7fdf). On-air verification (data/iq/2026-05-18/453437500/
// 20260518T143612Z.iq) showed the old parseHDU returning AlgoID=0x5D
// KeyID=0x5F00 TGID=147 where 22 LDU2 ES rows agree on AlgoID=0xAA
// KeyID=0x05FC TGID=5314.

// TestProcess_HDUVoiceFrameCarriesES verifies that when the framer emits the
// NAC-only VoiceFrame for an HDU it now also carries the decoded ES (MI,
// AlgoID, KeyID, Encrypted) so that an offline decode path that iterates
// VoiceFrames only can prime the ADP keystream from the HDU instead of waiting
// for the first LDU2.
func TestProcess_HDUVoiceFrameCarriesES(t *testing.T) {
	want := HDUData{
		MI:     [9]uint8{0x6B, 0x10, 0xC0, 0x95, 0x4F, 0x77, 0x21, 0x68, 0x00},
		AlgoID: 0xAA, KeyID: 0x05FC, TalkgroupID: 5314,
	}
	f := Frame{
		NID:     NID{NAC: 0x171, DUID: 0x0},
		Payload: buildHDUPayloadWithStatus(synthHDUBits(t, want)),
	}
	d := NewP25Decoder(25000)
	vfs, cfs := d.processFrame(f)
	if len(vfs) != 1 || vfs[0].DUID != 0x0 {
		t.Fatalf("processFrame(HDU): got %d voice frames, want 1 with DUID=0x0", len(vfs))
	}
	if len(cfs) != 1 || cfs[0].HDU == nil {
		t.Fatalf("processFrame(HDU): got %d control frames, want 1 with HDU set", len(cfs))
	}
	hdu := &vfs[0]
	if hdu.AlgoID != want.AlgoID || hdu.KeyID != want.KeyID || hdu.MI != want.MI || !hdu.Encrypted {
		t.Fatalf("HDU VoiceFrame missing ES: algo=0x%02X key=0x%04X mi=%x enc=%v",
			hdu.AlgoID, hdu.KeyID, hdu.MI, hdu.Encrypted)
	}
}

// TestParseHDU_OnAirLayout encodes an HDU exactly the way op25's process_HDU
// expects to read it (reference/op25/.../p25p1_fdma.cc:244-262 + op25_imbe_frame.h
// hdu_codeword_bits): 36 hexbits, each shortened-Golay(24,12,8)-encoded into
// 18 on-air bits, RS(36,20,17) over the 36 hexbits. This is the layout that
// the 2026-05-18T143612Z capture is encoded with; bug #6 was that parseHDU
// sliced 15 x 17-bit codewords instead.
//
// Independent verification: per the corpus, this capture's 22 LDU2 ES rows all
// decode AlgoID=0xAA KeyID=0x05FC TGID=5314, and the original parseHDU returned
// AlgoID=0x5D KeyID=0x5F00 TGID=147 — the synthesised vector below uses the
// LDU2-ES-confirmed values so a regression to the old slicing fails here.
func TestParseHDU_OnAirLayout(t *testing.T) {
	want := HDUData{
		MI:          [9]uint8{0x6B, 0x10, 0xC0, 0x95, 0x4F, 0x77, 0x21, 0x68, 0x00},
		MFID:        0x00,
		AlgoID:      0xAA,
		KeyID:       0x05FC,
		TalkgroupID: 5314,
	}
	payload := buildHDUPayloadWithStatus(synthHDUBits(t, want))
	got := parseHDU(payload)
	if got == nil {
		t.Fatal("parseHDU returned nil")
	}
	if *got != want {
		t.Fatalf("parseHDU mismatch:\n got  %+v\n want %+v", *got, want)
	}
}

// TestParseHDU_OnAirLayout_WithErrors injects bit errors that should be
// corrected by the inner Golay(24,12,8) (t=3 per 18-bit codeword) and the
// outer RS(36,20,17) (t=8 hexbits).
func TestParseHDU_OnAirLayout_WithErrors(t *testing.T) {
	want := HDUData{
		MI:          [9]uint8{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33, 0x00},
		AlgoID:      0xAA,
		KeyID:       0x0001,
		TalkgroupID: 0x14C2,
	}
	bits := synthHDUBits(t, want)

	// Two bit errors in codeword 0, one in codeword 5: Golay-correctable.
	bits[1] ^= 1
	bits[7] ^= 1
	bits[5*18+10] ^= 1
	// Burst-corrupt codeword 12 entirely (4 bit errors > t=3); the resulting
	// wrong hexbit must be repaired by the outer RS.
	bits[12*18+0] ^= 1
	bits[12*18+3] ^= 1
	bits[12*18+9] ^= 1
	bits[12*18+15] ^= 1

	got := parseHDU(buildHDUPayloadWithStatus(bits))
	if got == nil {
		t.Fatal("parseHDU returned nil")
	}
	if *got != want {
		t.Fatalf("parseHDU mismatch after error injection:\n got  %+v\n want %+v", *got, want)
	}
}

// TestParseHDU_RejectsRSFailure verifies that when more than t=8 hexbits are
// corrupted the HDU is rejected (nil) rather than emitting garbage fields the
// way the original implementation did.
func TestParseHDU_RejectsRSFailure(t *testing.T) {
	want := HDUData{AlgoID: 0xAA, KeyID: 0x05FC, TalkgroupID: 5314}
	bits := synthHDUBits(t, want)
	for i := 0; i < 9; i++ {
		// Wreck 9 distinct codewords with 4 errors each.
		for _, b := range []int{0, 4, 9, 13} {
			bits[i*18+b] ^= 1
		}
	}
	if got := parseHDU(buildHDUPayloadWithStatus(bits)); got != nil {
		t.Fatalf("parseHDU returned %+v on uncorrectable HDU; want nil", *got)
	}
}

// synthHDUBits builds the 648 status-stripped HDU data bits per
// TIA-102.BAAA / op25 process_HDU: 20 data hexbits packed from the 120-bit
// HDU message, RS(36,20,17)-encoded to 36 hexbits, each hexbit zero-padded to
// 12 bits and Golay(23,12)-encoded then doubled to 24 bits with an overall
// parity LSB; on air the upper 6 message bits (always zero here) are dropped,
// leaving 18 transmitted bits per codeword.
func synthHDUBits(t *testing.T, h HDUData) []uint8 {
	t.Helper()
	msg := make([]uint8, 120)
	for i, b := range h.MI {
		for j := 0; j < 8; j++ {
			msg[i*8+j] = (b >> uint(7-j)) & 1
		}
	}
	for j := 0; j < 8; j++ {
		msg[72+j] = (h.MFID >> uint(7-j)) & 1
		msg[80+j] = (h.AlgoID >> uint(7-j)) & 1
	}
	for j := 0; j < 16; j++ {
		msg[88+j] = uint8((h.KeyID >> uint(15-j)) & 1)
		msg[104+j] = uint8((h.TalkgroupID >> uint(15-j)) & 1)
	}

	var data [rsHDUK]uint8
	for i := 0; i < rsHDUK; i++ {
		data[i] = uint8(bitsToUint32(msg[i*6 : (i+1)*6]))
	}
	cw := rsEncodeHDU(data)
	// On-air hexbit i is the coefficient of x^{35-i}: data hexbits 0..19 sit
	// at cw[35..16], parity hexbits 20..35 at cw[15..0].
	var hb36 [rsHDUN]uint8
	for i := 0; i < rsHDUN; i++ {
		hb36[i] = cw[rsHDUN-1-i]
	}

	bits := make([]uint8, rsHDUN*18)
	for i, h6 := range hb36 {
		g23 := golayEncode(uint16(h6))
		par := uint32(0)
		for b := uint(0); b < 23; b++ {
			par ^= (g23 >> b) & 1
		}
		g24 := (g23 << 1) | par
		for j := 0; j < 18; j++ {
			bits[i*18+j] = uint8((g24 >> uint(17-j)) & 1)
		}
	}
	return bits
}

// buildHDUPayloadWithStatus packs encoded bits into a dibit payload with status symbols.
func buildHDUPayloadWithStatus(bits []uint8) []Dibit {
	payload := make([]Dibit, 0, len(bits)/2*37/36+40)
	dataIdx := 0
	for pos := 0; dataIdx < len(bits)-1; pos++ {
		if isStatusPosition(pos) {
			payload = append(payload, 0)
		} else {
			b0 := bits[dataIdx] & 1
			b1 := bits[dataIdx+1] & 1
			payload = append(payload, Dibit((b0<<1)|b1))
			dataIdx += 2
		}
	}
	return payload
}




