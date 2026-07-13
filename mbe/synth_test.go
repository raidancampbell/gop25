package mbe

import "testing"

func TestSynthesizeSilence(t *testing.T) {
	var out [160]float32
	for i := range out {
		out[i] = 123
	}
	SynthesizeSilence(&out)
	for i, s := range out {
		if s != 0 {
			t.Fatalf("out[%d] = %v, want 0", i, s)
		}
	}
}
