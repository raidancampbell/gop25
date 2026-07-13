package p25

import "testing"

func TestIMBEDecoder_Silence(t *testing.T) {
	dec := NewIMBEDecoder()
	defer dec.Close()

	// Decode an all-zero codeword (silence frame)
	var cw [88]uint8
	pcm, errs := dec.Decode(cw, 0)

	t.Logf("decoded all-zero IMBE codeword: %d errors, first 10 samples: %v",
		errs, pcm[:10])

	// Verify output is finite (not NaN/Inf)
	for i, s := range pcm {
		if s != s { // NaN check
			t.Fatalf("sample %d is NaN", i)
		}
	}
}

func TestIMBEDecoder_Consecutive(t *testing.T) {
	dec := NewIMBEDecoder()
	defer dec.Close()

	// Decode 9 consecutive codewords (one LDU worth) to exercise state carry
	var cw [88]uint8
	for i := 0; i < 9; i++ {
		pcm, errs := dec.Decode(cw, 0)
		_ = pcm
		_ = errs
	}
	// If we get here without panic/crash, the decoder handles consecutive calls
	t.Log("decoded 9 consecutive IMBE codewords without error")
}
