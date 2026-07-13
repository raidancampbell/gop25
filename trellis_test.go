package p25

import (
	"math/rand"
	"testing"
)

func TestTSBKDeinterleave_RoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 50; i++ {
		var in [196]uint8
		for j := range in {
			in[j] = uint8(rng.Intn(2))
		}
		if got := tsbkDeinterleave(tsbkInterleave(in)); got != in {
			t.Fatalf("iter %d: deinterleave(interleave(x)) != x", i)
		}
		if got := tsbkInterleave(tsbkDeinterleave(in)); got != in {
			t.Fatalf("iter %d: interleave(deinterleave(x)) != x", i)
		}
	}
}

func TestTrellisDibit_RoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for i := 0; i < 50; i++ {
		var data [96]uint8
		for j := 0; j < 80; j++ {
			data[j] = uint8(rng.Intn(2))
		}
		appendTSBKCRC(data[:])
		got, ok := trellisDibitDecode(trellisDibitEncode(data))
		if !ok {
			t.Fatalf("iter %d: decode rejected clean input", i)
		}
		if got != data {
			t.Fatalf("iter %d: round-trip mismatch", i)
		}
	}
}

func TestTrellisDibit_SingleSymbolError(t *testing.T) {
	data := makeTSBKBits(t, 0x3D, 0x00, [8]byte{0x10, 0x64, 0x00, 0x80, 0x05, 0x5D, 0x4A, 0x80})
	var d96 [96]uint8
	copy(d96[:], data)
	enc := trellisDibitEncode(d96)
	for pos := 0; pos < trellisOut; pos++ {
		bad := enc
		bad[pos] ^= 1
		got, ok := trellisDibitDecode(bad)
		if !ok || got != d96 {
			t.Fatalf("single-bit error at %d not corrected (ok=%v)", pos, ok)
		}
	}
}

// onAirTSBKs are 12-byte trellis-decoded TSBK blocks captured from the
// NAC 0x171 control channel at 460.4125 MHz on 2026-05-15. Each must pass
// the P25 TSBK CRC (TIA-102.BAAC: poly 0x1021, init 0, final XOR 0xFFFF).
// See cmd/diagnose31 for the capture/decode path.
var onAirTSBKs = [][12]byte{
	{0x3a, 0x00, 0x00, 0x31, 0x70, 0x02, 0x29, 0x36, 0x82, 0x70, 0x96, 0x07}, // RFSS_STS
	{0xbb, 0x00, 0x00, 0xbe, 0xe0, 0x01, 0x70, 0x36, 0x82, 0x70, 0x9a, 0x5c}, // NET_STS
	{0xb4, 0x00, 0x35, 0x8c, 0x80, 0x32, 0x05, 0x5d, 0x4a, 0x80, 0xa3, 0x8d}, // IDEN_UP_VU
	{0x02, 0x00, 0x54, 0xc9, 0x23, 0x3b, 0x54, 0xc9, 0x23, 0x3b, 0x70, 0x7d}, // GRP_V_CH_GRANT_UPDT
}

// TestViterbiDecode_OnAirTSBK feeds real captured TSBK blocks (re-encoded
// with our trellis encoder, which round-trip tests prove correct) through
// viterbiDecode and verifies the CRC accepts them. This pins crcCCITT16 to
// the on-air spec rather than to an internally-consistent-but-wrong variant.
func TestViterbiDecode_OnAirTSBK(t *testing.T) {
	for i, blk := range onAirTSBKs {
		var bits [96]uint8
		for j := 0; j < 96; j++ {
			bits[j] = (blk[j>>3] >> uint(7-(j&7))) & 1
		}
		enc := tsbkInterleave(trellisDibitEncode(bits))
		got, ok := viterbiDecode(enc[:])
		if !ok {
			t.Errorf("on-air TSBK[%d] (%x): viterbiDecode rejected (CRC fail)", i, blk)
			continue
		}
		for j := 0; j < 96; j++ {
			if got[j] != bits[j] {
				t.Errorf("on-air TSBK[%d]: bit %d mismatch", i, j)
				break
			}
		}
	}
}

// End-to-end through trellisEncode/viterbiDecode wrappers (interleave+trellis).
func TestTrellisOnAir_RoundTrip(t *testing.T) {
	data := makeTSBKBits(t, 0x00, 0x00, [8]byte{0x00, 0x10, 0x0A, 0x00, 0x64, 0x00, 0x30, 0x39})
	enc := trellisEncode(data)
	if len(enc) != trellisOut {
		t.Fatalf("trellisEncode: want %d bits, got %d", trellisOut, len(enc))
	}
	got, ok := viterbiDecode(enc)
	if !ok {
		t.Fatal("viterbiDecode failed on clean input")
	}
	for i := range data {
		if got[i] != data[i] {
			t.Fatalf("bit %d mismatch", i)
		}
	}
}

func TestParseTSBKs_StatusStripAndDecode(t *testing.T) {
	tsbk0 := makeTSBKBitsNoLast(t, uint8(OpcodeNetworkStatusBcast), 0x00,
		[8]byte{0x00, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00})
	tsbk1 := makeTSBKBits(t, uint8(OpcodeSystemServiceBcast), 0x00, [8]byte{})
	var enc []uint8
	for _, tb := range [][]uint8{tsbk0, tsbk1} {
		enc = append(enc, trellisEncode(tb)...)
	}
	payload := buildPayloadWithStatus(enc)
	got := parseTSBKs(payload)
	if len(got) != 2 {
		t.Fatalf("expected 2 TSBKs, got %d", len(got))
	}
	if got[0].Opcode != OpcodeNetworkStatusBcast || got[1].Opcode != OpcodeSystemServiceBcast {
		t.Fatalf("opcodes wrong: %02x %02x", got[0].Opcode, got[1].Opcode)
	}
}

// --- helpers (kept from previous test file) ---

func buildPayloadWithStatus(encodedBits []uint8) []Dibit {
	payload := make([]Dibit, 0, len(encodedBits)/2*37/36+40)
	di := 0
	for pos := 0; di+1 < len(encodedBits); pos++ {
		if isStatusPosition(pos) {
			payload = append(payload, 0)
		} else {
			payload = append(payload, Dibit((encodedBits[di]&1)<<1|(encodedBits[di+1]&1)))
			di += 2
		}
	}
	return payload
}

func makeTSBKBits(t *testing.T, opcode, mfid uint8, args [8]byte) []uint8 {
	t.Helper()
	bits := make([]uint8, 96)
	bits[0] = 1
	for i := 0; i < 6; i++ {
		bits[2+i] = (opcode >> uint(5-i)) & 1
	}
	for i := 0; i < 8; i++ {
		bits[8+i] = (mfid >> uint(7-i)) & 1
	}
	for i, b := range args {
		for j := 0; j < 8; j++ {
			bits[16+i*8+j] = (b >> uint(7-j)) & 1
		}
	}
	appendTSBKCRC(bits)
	return bits
}

func makeTSBKBitsNoLast(t *testing.T, opcode, mfid uint8, args [8]byte) []uint8 {
	t.Helper()
	bits := makeTSBKBits(t, opcode, mfid, args)
	bits[0] = 0
	appendTSBKCRC(bits)
	return bits
}

// appendTSBKCRC overwrites bits[80:96] with the on-air TSBK CRC such that
// crcCCITT16 over the resulting 12 bytes is 0.
func appendTSBKCRC(bits []uint8) {
	for j := 80; j < 96; j++ {
		bits[j] = 0
	}
	crc := crcCCITT16(bitsToBytes(bits[:96]))
	for j := 0; j < 16; j++ {
		bits[80+j] = uint8(crc>>uint(15-j)) & 1
	}
}

// TestViterbiSoft_CleanMatchesHard runs random 96-bit data (with a valid TSBK
// CRC appended over bits[80:96]) through trellisEncode + soft demap +
// viterbiSoftDecodeRaw, asserting bit-exact recovery and CRC pass on a
// noiseless signal -- the soft analogue of TestTrellisDibit_RoundTrip.
func TestViterbiSoft_CleanMatchesHard(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	for trial := 0; trial < 50; trial++ {
		data := make([]uint8, 96)
		for i := 0; i < 80; i++ {
			data[i] = uint8(rng.Intn(2))
		}
		appendTSBKCRC(data) // bits[80:96] = CRC over bits[0:96] s.t. crcCCITT16==0
		onair := trellisEncode(data) // 196 interleaved bits
		soft := softBlockFromSymbols(symbolsFromBits(onair)) // helper from trellis34_test.go
		got, ok := viterbiSoftDecodeRaw(soft)
		if !ok {
			t.Fatalf("trial %d: soft decode reported CRC fail on clean signal", trial)
		}
		for i := range data {
			if got[i] != data[i] {
				t.Fatalf("trial %d bit %d: soft 1/2-rate decode of clean signal wrong", trial, i)
			}
		}
	}
}
