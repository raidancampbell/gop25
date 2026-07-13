package p25

import (
	"math"
	"math/rand"
	"testing"
)

// randomBits144 generates a deterministic pseudo-random 144-bit vector so the
// 3/4-rate trellis round-trip tests are reproducible.
func randomBits144(seed uint32) [144]uint8 {
	var data [144]uint8
	s := seed
	for i := range data {
		s = s*1664525 + 1013904223
		data[i] = uint8(s>>31) & 1
	}
	return data
}

// TestTrellis34_RoundTrip encodes 144 data bits through the (non-interleaved)
// 3/4-rate trellis encoder and decodes them back, expecting an exact match.
// This proves the encoder and the 8-state Viterbi decoder are mutually
// consistent over the P25 3/4-rate transition matrix.
func TestTrellis34_RoundTrip(t *testing.T) {
	data := randomBits144(0x12345)
	enc := trellis34DibitEncode(data)
	got := trellis34DibitDecode(enc)
	if got != data {
		t.Fatalf("round-trip mismatch\n got=%v\nwant=%v", got, data)
	}
}

// TestTrellis34_RoundTripInterleaved runs the full on-air path: encode 144 bits,
// block-interleave, then deinterleave + decode. Exercises viterbi34DecodeRaw,
// the production entry point used by parsePDU for confirmed data blocks.
func TestTrellis34_RoundTripInterleaved(t *testing.T) {
	data := randomBits144(0xabcde)
	onair := trellis34Encode(data[:]) // 196 interleaved bits
	if len(onair) != 196 {
		t.Fatalf("trellis34Encode len = %d, want 196", len(onair))
	}
	got := viterbi34DecodeRaw(onair) // 144 data bits
	if len(got) != 144 {
		t.Fatalf("viterbi34DecodeRaw len = %d, want 144", len(got))
	}
	for i := range data {
		if got[i] != data[i] {
			t.Fatalf("bit %d mismatch: got %d want %d", i, got[i], data[i])
		}
	}
}

// TestTrellis34_CorrectsBitErrors flips a small number of on-air bits and
// confirms the Viterbi decoder still recovers the exact message — proving it
// performs real maximum-likelihood error correction, not a lookup.
func TestTrellis34_CorrectsBitErrors(t *testing.T) {
	data := randomBits144(0x5555)
	onair := trellis34Encode(data[:])
	// Flip two well-separated bits in different symbols.
	onair[12] ^= 1
	onair[120] ^= 1
	got := viterbi34DecodeRaw(onair)
	for i := range data {
		if got[i] != data[i] {
			t.Fatalf("bit %d not corrected: got %d want %d", i, got[i], data[i])
		}
	}
}

// symbolsFromBits maps a 196-bit on-air block to its 98 normalized C4FM symbol
// values (ideal levels +/-1, +/-3): each consecutive bit pair (b1,b0) is the
// dibit (b1<<1)|b0 -> c4fmLevels[dibit].
func symbolsFromBits(bits []uint8) []float64 {
	out := make([]float64, len(bits)/2)
	for k := range out {
		d := bits[2*k]<<1 | bits[2*k+1]
		out[k] = c4fmLevels[d]
	}
	return out
}

// softBlockFromSymbols demaps 98 symbol values to 196 SoftBits in on-air bit
// order (the same order viterbi34SoftDecodeRaw expects: pre-deinterleave).
func softBlockFromSymbols(sym []float64) []SoftBit {
	out := make([]SoftBit, len(sym)*2)
	for k, x := range sym {
		hi, lo := softDemapSymbol(x)
		out[2*k] = hi
		out[2*k+1] = lo
	}
	return out
}

// nearestDibit slices a normalized value to the dibit whose level is closest
// (the hard-decision reference for the comparison test).
func nearestDibit(x float64) uint8 {
	best, bestD := uint8(0), math.Inf(1)
	for d := uint8(0); d < 4; d++ {
		if dd := math.Abs(x - c4fmLevels[d]); dd < bestD {
			bestD, best = dd, d
		}
	}
	return best
}

func equalBits(a []uint8, b []uint8) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestViterbi34Soft_CleanMatchesHard(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for trial := 0; trial < 50; trial++ {
		data := make([]uint8, trellis34DataLen)
		for i := range data {
			data[i] = uint8(rng.Intn(2))
		}
		onair := trellis34Encode(data) // 196 interleaved bits
		soft := softBlockFromSymbols(symbolsFromBits(onair))
		got := viterbi34SoftDecodeRaw(soft)
		for i := range data {
			if got[i] != data[i] {
				t.Fatalf("trial %d bit %d: soft decode of clean signal wrong", trial, i)
			}
		}
	}
}

func TestViterbi34Soft_BeatsHardUnderNoise(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	const trials = 400
	// Noise sigma in normalized level units (ideal levels are +/-1, +/-3 with
	// spacing 2). At sigma=0.5 the noise tail crosses every other slicer
	// boundary often enough to break ~25% of blocks on the hard path while soft
	// recovers nearly all of them: empirically hardOK=294/400 vs softOK=394/400
	// under this seed, a strict soft > hard with comfortable margin.
	const sigma = 0.5
	hardOK, softOK := 0, 0
	for trial := 0; trial < trials; trial++ {
		data := make([]uint8, trellis34DataLen)
		for i := range data {
			data[i] = uint8(rng.Intn(2))
		}
		onair := trellis34Encode(data)
		sym := symbolsFromBits(onair)
		noisy := make([]float64, len(sym))
		for k := range sym {
			noisy[k] = sym[k] + rng.NormFloat64()*sigma
		}
		// Hard path: slice each noisy symbol to the nearest level -> bits.
		hard := make([]uint8, len(onair))
		for k, x := range noisy {
			d := nearestDibit(x)
			hard[2*k] = (d >> 1) & 1
			hard[2*k+1] = d & 1
		}
		hd := viterbi34DecodeRaw(hard)
		sd := viterbi34SoftDecodeRaw(softBlockFromSymbols(noisy))
		if equalBits(hd, data) {
			hardOK++
		}
		if equalBits(sd, data) {
			softOK++
		}
	}
	if softOK <= hardOK {
		t.Fatalf("soft did not beat hard: softOK=%d hardOK=%d (want soft > hard)", softOK, hardOK)
	}
	t.Logf("sigma=%.2f: hardOK=%d/%d softOK=%d/%d", sigma, hardOK, trials, softOK, trials)
}
