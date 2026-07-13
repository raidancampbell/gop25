package p25

import "testing"

// TestRSEncode63x35_RoundTrip verifies the exported RS(63,35) encoder produces
// a codeword that RSDecodeN accepts with zero corrections, and that the data
// symbols survive the round trip unchanged.
func TestRSEncode63x35_RoundTrip(t *testing.T) {
	var cw [63]uint8
	// Place 28 data symbols somewhere in the data span (positions 28..62 are
	// the high-order data coefficients in the RSDecodeN convention).
	for i := 5; i <= 32; i++ {
		cw[i] = uint8((i*5)%63) & 0x3f
	}
	enc := RSEncode63x35(cw)
	dec, nerr, ok := RSDecodeN(63, 35, 14, enc[:])
	if !ok || nerr != 0 {
		t.Fatalf("decode of clean RSEncode63x35 codeword: ok=%v nerr=%d", ok, nerr)
	}
	for i := range enc {
		if dec[i] != enc[i] {
			t.Fatalf("symbol %d changed: %d -> %d", i, enc[i], dec[i])
		}
	}
}
