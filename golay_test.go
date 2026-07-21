package p25

import (
	"math/bits"
	"testing"
)

// make24 builds a valid 24-bit extended Golay(24,12,8) codeword from a 12-bit
// message: systematic (23,12) codeword in the high bits, overall even-parity
// bit as the LSB. Mirrors the phase2 test helpers' c0 = (c0_23<<1)|parityBit.
func make24(msg uint16) uint32 {
	c23 := golayEncode(msg)
	return (c23 << 1) | uint32(bits.OnesCount32(c23&0x7FFFFF)&1)
}

func TestGolay24DetectUncorrectable_Clean(t *testing.T) {
	for m := uint32(0); m < 4096; m++ {
		if Golay24DetectUncorrectable(make24(uint16(m))) {
			t.Fatalf("clean codeword msg=%#x wrongly flagged uncorrectable", m)
		}
	}
}

func TestGolay24DetectUncorrectable_CorrectableNotFlagged(t *testing.T) {
	base := make24(0x555)
	for w := 1; w <= 3; w++ {
		enumErrors(24, w, 0, 0, func(pat uint32) {
			if Golay24DetectUncorrectable(base ^ pat) {
				t.Fatalf("weight-%d error %#x wrongly flagged (must be correctable)", w, pat)
			}
		})
	}
}

func TestGolay24DetectUncorrectable_Weight4Detected(t *testing.T) {
	base := make24(0x555)
	miss := 0
	enumErrors(24, 4, 0, 0, func(pat uint32) {
		if !Golay24DetectUncorrectable(base ^ pat) {
			miss++
		}
	})
	if miss != 0 {
		t.Fatalf("%d weight-4 patterns went undetected (must all be detected)", miss)
	}
}
