package mbe

import (
	"testing"
)

// DSD's P25 Phase1 IMBE interleave schedule (from vocoder.go, mirroring p25p1_const.h)
var imbeIW = [72]int{
	0, 2, 4, 1, 3, 5,
	0, 2, 4, 1, 3, 6,
	0, 2, 4, 1, 3, 6,
	0, 2, 4, 1, 3, 6,
	0, 2, 4, 1, 3, 6,
	0, 2, 4, 1, 3, 6,
	0, 2, 5, 1, 3, 6,
	0, 2, 5, 1, 3, 6,
	0, 2, 5, 1, 3, 7,
	0, 2, 5, 1, 3, 7,
	0, 2, 5, 1, 4, 7,
	0, 3, 5, 2, 4, 7,
}

var imbeIX = [72]int{
	22, 20, 10, 20, 18, 0,
	20, 18, 8, 18, 16, 13,
	18, 16, 6, 16, 14, 11,
	16, 14, 4, 14, 12, 9,
	14, 12, 2, 12, 10, 7,
	12, 10, 0, 10, 8, 5,
	10, 8, 13, 8, 6, 3,
	8, 6, 11, 6, 4, 1,
	6, 4, 9, 4, 2, 6,
	4, 2, 7, 2, 0, 4,
	2, 0, 5, 0, 13, 2,
	0, 21, 3, 21, 11, 0,
}

var imbeIY = [72]int{
	1, 3, 5, 0, 2, 4,
	1, 3, 6, 0, 2, 4,
	1, 3, 6, 0, 2, 4,
	1, 3, 6, 0, 2, 4,
	1, 3, 6, 0, 2, 4,
	1, 3, 6, 0, 2, 5,
	1, 3, 6, 0, 2, 5,
	1, 3, 6, 0, 2, 5,
	1, 3, 6, 0, 2, 5,
	1, 3, 7, 0, 2, 5,
	1, 4, 7, 0, 3, 5,
	2, 4, 7, 1, 3, 5,
}

var imbeIZ = [72]int{
	21, 19, 1, 21, 19, 9,
	19, 17, 14, 19, 17, 7,
	17, 15, 12, 17, 15, 5,
	15, 13, 10, 15, 13, 3,
	13, 11, 8, 13, 11, 1,
	11, 9, 6, 11, 9, 14,
	9, 7, 4, 9, 7, 12,
	7, 5, 2, 7, 5, 10,
	5, 3, 0, 5, 3, 8,
	3, 1, 5, 3, 1, 6,
	1, 14, 3, 1, 22, 4,
	22, 12, 1, 22, 20, 2,
}

// encodeGolay2312 computes systematic Golay(23,12) encoding.
// Input: 12-bit message. Output: 23-bit codeword with message in bits 22..11, parity in 10..0.
func encodeGolay2312(msg [12]uint8) [23]uint8 {
	var out [23]uint8

	// Place message in bits 22..11 of the array
	for i := 0; i < 12; i++ {
		out[22-i] = msg[i] & 1
	}

	// Build the block as int64 the same way Golay2312 does (bits 22..0 -> MSB..LSB of int64)
	// to compute the parity the same way checkGolayBlock does
	block := int64(0)
	for i := 22; i >= 0; i-- {
		block <<= 1
		block += int64(out[i] & 1) // only message bits are set so far, parity bits are 0
	}

	// Compute expected parity using the same method as checkGolayBlock
	eccexpected := 0
	mask := int64(0x400000) // bit 22 of the int64
	for i := 0; i < 12; i++ {
		if (block & mask) != 0 {
			eccexpected ^= golayGenerator[i]
		}
		mask = mask >> 1
	}

	// Place parity in bits 10..0
	for i := 0; i < 11; i++ {
		out[i] = uint8((eccexpected >> i) & 1)
	}

	return out
}

// encodeHamming1511 computes systematic Hamming(15,11) encoding.
// Input: 11-bit message in bits 14..4. Output: 15-bit codeword with parity in bits 3..0.
func encodeHamming1511(msg [11]uint8) [15]uint8 {
	var out [15]uint8

	// Place message in bits 14..4
	for i := 0; i < 11; i++ {
		out[14-i] = msg[i] & 1
	}

	// Build block as integer from all 15 bits (parity bits 3..0 are currently 0)
	block := 0
	for i := 14; i >= 0; i-- {
		block = (block << 1) | int(out[i]&1)
	}

	// Compute syndrome contribution from data bits, then set parity bits to cancel it
	// The syndrome is built MSB-first (i=0 produces MSB of 4-bit syndrome)
	syndrome := 0
	for i := 0; i < 4; i++ {
		syndrome <<= 1
		stmp := block & hammingGenerator[i]
		stmp2 := stmp % 2
		for j := 0; j < 14; j++ {
			stmp >>= 1
			stmp2 ^= stmp % 2
		}
		syndrome |= stmp2
	}

	// The syndrome tells us what to XOR into the block to make syndrome=0
	// But we can only modify the parity bits (3..0)
	// For systematic Hamming(15,11), the syndrome directly gives us the parity bits
	for i := 0; i < 4; i++ {
		out[i] = uint8((syndrome >> i) & 1)
	}

	return out
}

// imbeFECEncode inverts the IMBEFECDecode pipeline to produce a 144-bit on-air codeword
// from an 88-bit information frame.
func imbeFECEncode(imbeD [88]uint8) [144]uint8 {
	// Build the 8x23 frame from the 88-bit information
	var imbeFr [8][23]uint8

	idx := 0

	// Rows 0..3: each takes 12 bits (22..11)
	for i := 0; i < 4; i++ {
		var msg [12]uint8
		for j := 0; j < 12; j++ {
			msg[j] = imbeD[idx]
			idx++
		}
		// Encode with Golay(23,12)
		codeword := encodeGolay2312(msg)
		for j := 0; j < 23; j++ {
			imbeFr[i][j] = codeword[j]
		}
	}

	// Rows 4..6: each takes 11 bits (14..4)
	for i := 4; i < 7; i++ {
		var msg [11]uint8
		for j := 0; j < 11; j++ {
			msg[j] = imbeD[idx]
			idx++
		}
		// Encode with Hamming(15,11)
		codeword := encodeHamming1511(msg)
		for j := 0; j < 15; j++ {
			imbeFr[i][j] = codeword[j]
		}
		// Bits 15..22 remain zero (unused in Hamming)
		for j := 15; j < 23; j++ {
			imbeFr[i][j] = 0
		}
	}

	// Row 7: 7 bits (6..0), no FEC
	for j := 0; j < 7; j++ {
		imbeFr[7][j] = imbeD[idx]
		idx++
	}
	// Bits 7..22 remain zero
	for j := 7; j < 23; j++ {
		imbeFr[7][j] = 0
	}

	// Apply PRBS scrambling (same as demodulate, since XOR is self-inverse)
	// Build modulator seed from row0 bits 22..11 (12 bits) as a binary integer
	foo := uint16(0)
	for i := 22; i >= 11; i-- {
		foo = (foo << 1) | uint16(imbeFr[0][i]&1)
	}

	// Generate PR sequence
	var pr [115]uint16
	pr[0] = 16 * foo
	for i := 1; i < 115; i++ {
		pr[i] = (173*pr[i-1] + 13849) & 0xFFFF
	}
	// Convert to 0/1 bits
	for i := 1; i < 115; i++ {
		pr[i] = pr[i] / 32768
	}

	// XOR-scramble (same order as descramble)
	k := 1
	for i := 1; i < 4; i++ {
		for j := 22; j >= 0; j-- {
			imbeFr[i][j] ^= uint8(pr[k] & 1)
			k++
		}
	}
	for i := 4; i < 7; i++ {
		for j := 14; j >= 0; j-- {
			imbeFr[i][j] ^= uint8(pr[k] & 1)
			k++
		}
	}

	// Interleave into 144 bits (inverse of deinterleave)
	var rawBits [144]uint8
	for j := 0; j < 72; j++ {
		rawBits[j*2] = imbeFr[imbeIW[j]][imbeIX[j]]       // MSB of dibit
		rawBits[j*2+1] = imbeFr[imbeIY[j]][imbeIZ[j]]     // LSB of dibit
	}

	return rawBits
}

// TestGolayEncoder verifies the Golay encoder produces valid codewords.
func TestGolayEncoder(t *testing.T) {
	testCases := []struct {
		name string
		msg  [12]uint8
	}{
		{"all-zero", [12]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"all-one", [12]uint8{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}},
		{"alternating", [12]uint8{1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			codeword := encodeGolay2312(tc.msg)
			decoded, errs := Golay2312(codeword)
			if errs != 0 {
				t.Errorf("encoded codeword had %d errors when decoded", errs)
			}
			// Verify message bits match
			for i := 0; i < 12; i++ {
				if decoded[22-i] != tc.msg[i] {
					t.Errorf("bit %d mismatch: expected %d, got %d", i, tc.msg[i], decoded[22-i])
				}
			}
		})
	}
}

// TestHammingEncoder verifies the Hamming encoder produces valid codewords.
func TestHammingEncoder(t *testing.T) {
	testCases := []struct {
		name string
		msg  [11]uint8
	}{
		{"all-zero", [11]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"all-one", [11]uint8{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}},
		{"alternating", [11]uint8{1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			codeword := encodeHamming1511(tc.msg)
			decoded, errs := Hamming1511(codeword)
			if errs != 0 {
				t.Errorf("encoded codeword had %d errors when decoded", errs)
			}
			// Verify message bits match
			for i := 0; i < 11; i++ {
				if decoded[14-i] != tc.msg[i] {
					t.Errorf("bit %d mismatch: expected %d, got %d", i, tc.msg[i], decoded[14-i])
				}
			}
		})
	}
}

// TestIMBEFECRegressionVectors verifies IMBE FEC decode via round-trip encoding.
// Vectors are generated by encoding self-chosen information frames through an in-test
// encoder that inverts the decoder, NOT copied from third-party sources.
func TestIMBEFECRegressionVectors(t *testing.T) {
	vectors := []struct {
		name  string
		imbeD [88]uint8
	}{
		{
			name:  "all-zero",
			imbeD: [88]uint8{}, // all zeros
		},
		{
			name: "alternating",
			imbeD: func() [88]uint8 {
				var arr [88]uint8
				for i := 0; i < 88; i++ {
					arr[i] = uint8(i % 2)
				}
				return arr
			}(),
		},
		{
			name: "pitch-like",
			imbeD: func() [88]uint8 {
				var arr [88]uint8
				// Simulate a pitch pattern with some structure
				for i := 0; i < 88; i++ {
					if i < 44 {
						arr[i] = 1
					} else {
						arr[i] = 0
					}
				}
				return arr
			}(),
		},
	}

	for _, vec := range vectors {
		t.Run(vec.name, func(t *testing.T) {
			// Encode the information frame
			encoded := imbeFECEncode(vec.imbeD)

			// Decode it back
			_, decoded, errs := IMBEFECDecode(encoded, imbeIW, imbeIX, imbeIY, imbeIZ)

			// Assert zero FEC errors
			if errs != 0 {
				t.Errorf("expected 0 FEC errors, got %d", errs)
			}

			// Assert exact round-trip
			if decoded != vec.imbeD {
				t.Errorf("round-trip failed: decoded != original")
				for i := 0; i < 88; i++ {
					if decoded[i] != vec.imbeD[i] {
						t.Logf("  bit %d: expected %d, got %d", i, vec.imbeD[i], decoded[i])
					}
				}
			}
		})
	}
}
