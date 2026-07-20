package mbe

import "testing"

func TestGolay2312CorrectsKnownWord(t *testing.T) {
	var in [23]uint8
	for i := 11; i < 23; i += 2 {
		in[i] = 1
	}
	out, errs := Golay2312(in)
	if errs < 0 || errs > 3 {
		t.Fatalf("errs = %d, want 0..3", errs)
	}
	for i := 0; i < 11; i++ {
		if out[i] != in[i] {
			t.Fatalf("parity bit %d changed: got %d want %d", i, out[i], in[i])
		}
	}
}

func TestHamming1511NoError(t *testing.T) {
	var in [15]uint8
	for i := 0; i < 15; i += 2 {
		in[i] = 1
	}
	out, errs := Hamming1511(in)
	if errs != 0 {
		t.Fatalf("errs = %d, want 0", errs)
	}
	if out != in {
		t.Fatalf("out = %v, want %v", out, in)
	}
}

// TestHamming1511SingleBit verifies that every single-bit error in the 15-bit
// codeword is corrected back to the clean codeword. Regression guard for the
// hammingMatrix syndrome->error-mask table: an identity table (1<<(s-1)) leaves
// positions 2..7 miscorrected (the error stays AND a second bit flips), silently
// corrupting the u4/u5/u6 spectral-amplitude bits decoded from rows 4..6.
func TestHamming1511SingleBit(t *testing.T) {
	// Exercise a few valid codewords (encoded from real 11-bit messages) plus the
	// all-zero codeword, injecting each of the 15 single-bit errors into each.
	msgs := [][11]uint8{
		{}, // all-zero -> all-zero codeword
		{1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1},
		{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		{0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0},
	}
	for mi, msg := range msgs {
		cw := encodeHamming1511(msg)
		// sanity: clean codeword decodes with no error
		if out, errs := Hamming1511(cw); errs != 0 || out != cw {
			t.Fatalf("msg %d: clean codeword: errs=%d out=%v", mi, errs, out)
		}
		for p := 0; p < 15; p++ {
			corrupt := cw
			corrupt[p] ^= 1
			out, errs := Hamming1511(corrupt)
			if errs != 1 {
				t.Errorf("msg %d pos %d: errs=%d, want 1", mi, p, errs)
			}
			if out != cw {
				t.Errorf("msg %d pos %d: single-bit error NOT corrected\n got=%v\nwant=%v", mi, p, out, cw)
			}
		}
	}
}
