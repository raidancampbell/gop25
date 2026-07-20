package mbe

import (
	"testing"
)

// Independently-derived AMBE+2 3600x2450 ECC reference vectors. Each row is a
// clean 4x24-bit AMBE frame and the 49-bit information vector a conformant
// decoder recovers with zero errors. Derived via a self-inverse encoder that
// round-trips self-chosen 49-bit frames through the AMBE+2 FEC pipeline. NO
// third-party data — vectors are encoder-generated from our own test frames.
//
// The AMBE+2 3600x2450 (DMR voice codec) pipeline is structurally simpler than
// IMBE 7200x4400:
//   - C0: Golay(23,12) FEC on ambe_fr[0][1..23]
//   - Demodulate: PRBS from ambe_fr[0][12..23], XOR-descramble ambe_fr[1][22..0]
//   - C1: Golay(23,12) on ambe_fr[1][0..22] -> bits 22..11 (12 bits)
//   - C2: copy ambe_fr[2][10..0] (11 bits)
//   - C3: copy ambe_fr[3][13..0] (14 bits)
//
// Total information: 12+12+11+14 = 49 bits. Encoder strategy mirrors Task 5's
// IMBE approach (build frame from 49-bit info, apply PRBS, no interleave step).
var ambeECCVectors = []struct {
	frame [4][24]uint8
	ambeD [49]uint8
}{
	// Round-trip vector 0: all-zero information frame
	{
		frame: [4][24]uint8{
			{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			{1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0},
			{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		ambeD: [49]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	},
	// Round-trip vector 1: alternating bits (exercises bit-position sensitivity)
	{
		frame: [4][24]uint8{
			{0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0},
			{0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0},
			{0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			{0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		ambeD: [49]uint8{0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0},
	},
	// Round-trip vector 2: structured pattern (first 24 bits = 1, rest = 0)
	{
		frame: [4][24]uint8{
			{0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			{1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0},
			{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		ambeD: [49]uint8{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	},
}

func TestAMBEECCDecodeCleanVectors(t *testing.T) {
	if len(ambeECCVectors) == 0 {
		t.Skip("AMBE ECC vectors not derived; PCM self-snapshot (vocoder_compare_test) covers regression")
	}
	for i, v := range ambeECCVectors {
		// Note: these functions mutate the frame, so test against the already-scrambled
		// encoded frame (v.frame), not the information bits (v.ambeD).
		// The generator output shows these frames decode with 0 errors.
		fr := v.frame
		var d [49]uint8
		errs0 := eccAmbe3600x2450C0(&fr)
		demodulateAmbe3600x2450Data(&fr)
		errs := eccAmbe3600x2450Data(&fr, &d)

		// Assert zero total errors (C0 + C1)
		totalErrs := errs0 + errs
		if totalErrs != 0 {
			t.Errorf("vector %d: decoded with %d total errors (C0=%d, C1=%d), want 0", i, totalErrs, errs0, errs)
		}
		if d != v.ambeD {
			t.Errorf("vector %d: ambeD mismatch\ngot:  %v\nwant: %v", i, d, v.ambeD)
		}
	}
}

// encodeAMBE3600x2450 encodes a 49-bit AMBE+2 3600x2450 information frame into
// the on-air 4x24-bit frame format. This is the self-inverse encoder used to
// generate the test vectors above. It mirrors the decode pipeline exactly:
//   1. Build 4x24 frame from 49-bit info (C0/C1 via Golay, C2/C3 raw copy)
//   2. Apply PRBS scrambling (same seed/recurrence as demodulate, self-inverse)
//   3. No interleave step (AMBE frame is already in on-air order)
func encodeAMBE3600x2450(info [49]uint8) [4][24]uint8 {
	var fr [4][24]uint8

	// Extract C0 (12 bits), C1 (12 bits), C2 (11 bits), C3 (14 bits)
	pos := 0
	var c0, c1 [12]uint8
	for i := 0; i < 12; i++ {
		c0[i] = info[pos] & 1
		pos++
	}
	for i := 0; i < 12; i++ {
		c1[i] = info[pos] & 1
		pos++
	}

	// Encode C0 and C1 via Golay(23,12)
	c0enc := encodeGolay2312(c0)
	c1enc := encodeGolay2312(c1)

	// Place C0 into fr[0][1..23] (bit 0 is unused in AMBE C0)
	for j := 0; j < 23; j++ {
		fr[0][j+1] = c0enc[j]
	}

	// Place C1 into fr[1][0..22]
	for j := 0; j < 23; j++ {
		fr[1][j] = c1enc[j]
	}

	// Copy C2 (11 bits) into fr[2][10..0]
	for j := 10; j >= 0; j-- {
		fr[2][j] = info[pos] & 1
		pos++
	}

	// Copy C3 (14 bits) into fr[3][13..0]
	for j := 13; j >= 0; j-- {
		fr[3][j] = info[pos] & 1
		pos++
	}

	// Apply PRBS scrambling (self-inverse operation, same as demodulate)
	// Build PR sequence from C0 MSBs (fr[0][12..23])
	var pr [115]uint16
	var foo uint16
	for i := 23; i >= 12; i-- {
		foo <<= 1
		foo |= uint16(fr[0][i])
	}
	pr[0] = uint16(16 * uint32(foo))
	for i := 1; i < 24; i++ {
		pr[i] = uint16((173 * int(pr[i-1])) + 13849)
	}
	for i := 1; i < 24; i++ {
		pr[i] = pr[i] / 32768
	}

	// XOR-scramble fr[1][22..0] with pr[1..23]
	k := 1
	for j := 22; j >= 0; j-- {
		fr[1][j] = fr[1][j] ^ uint8(pr[k])
		k++
	}

	return fr
}

// encodeGolay2312 is reused from imbe_refvec_test.go (same package, visible here)

// TestAMBEEncoderRoundTrip verifies the encoder derives correct vectors by
// encoding self-chosen 49-bit frames, decoding them, and asserting exact
// round-trip with zero errors.
func TestAMBEEncoderRoundTrip(t *testing.T) {
	for i, v := range ambeECCVectors {
		// Encode the known ambeD
		fr := encodeAMBE3600x2450(v.ambeD)

		// Verify it matches the expected frame
		if fr != v.frame {
			t.Errorf("vector %d: encoder produced wrong frame", i)
		}

		// Decode it back
		errs0 := eccAmbe3600x2450C0(&fr)
		demodulateAmbe3600x2450Data(&fr)
		var d [49]uint8
		errs := eccAmbe3600x2450Data(&fr, &d)

		// Assert zero errors and exact match
		if errs0 != 0 || errs != 0 {
			t.Errorf("vector %d: round-trip decode errors: C0=%d, C1=%d", i, errs0, errs)
		}
		if d != v.ambeD {
			t.Errorf("vector %d: round-trip ambeD mismatch", i)
		}
	}
}
