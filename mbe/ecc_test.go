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
