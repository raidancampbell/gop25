package p25

import (
	"testing"
)

func TestRSDebug(t *testing.T) {
	// Encode a simple non-zero data symbol set and check syndromes are zero
	var data [rsK]uint8
	data[0] = 32 // 0x80 >> 1 → AlgoID high bits
	cw := rsEncode(data)
	t.Logf("data: %v", data[:])
	t.Logf("cw:   %v", cw[:])

	// Now decode the same codeword
	result, ok := rsDecode(cw)
	if !ok {
		t.Error("rsDecode failed on error-free codeword from rsEncode")
	} else {
		t.Logf("decoded: %v", result[:])
		if result != data {
			t.Errorf("round-trip mismatch: got %v, want %v", result[:], data[:])
		}
	}
}
