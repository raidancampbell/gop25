package p25

import "testing"

func TestCycleMI_ZeroIsFixedPoint(t *testing.T) {
	var z [9]uint8
	if got := CycleMI(z); got != z {
		t.Fatalf("CycleMI(zeros) = %x, want zeros", got)
	}
}

func TestCycleMI_ClearsByte8(t *testing.T) {
	in := [9]uint8{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAA}
	if got := CycleMI(in); got[8] != 0 {
		t.Fatalf("CycleMI(...)[8] = 0x%02X, want 0", got[8])
	}
}

// TestCycleMI_MatchesOp25LFSR pins CycleMI to op25's step_p25_lfsr / cycle_p25_mi
// (reference/op25/.../op25_crypt_algs.cc:120-144). The reference is reproduced inline
// so a divergence in the production port is caught here rather than on-air.
// On-air verification: any two consecutive LDU2 ES MIs from the same speaker
// must satisfy CycleMI(MI_n) == MI_{n+1}.
func TestCycleMI_MatchesOp25LFSR(t *testing.T) {
	step := func(l uint64) uint64 {
		fb := ((l >> 63) ^ (l >> 61) ^ (l >> 45) ^ (l >> 37) ^ (l >> 26) ^ (l >> 14)) & 1
		return (l << 1) | fb
	}
	for _, tc := range [][9]uint8{
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
		{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00},
		{0x6B, 0x10, 0xC0, 0x95, 0x4F, 0x77, 0x21, 0x68, 0x00},
	} {
		var l uint64
		for i := 0; i < 8; i++ {
			l = (l << 8) | uint64(tc[i])
		}
		for i := 0; i < 64; i++ {
			l = step(l)
		}
		var want [9]uint8
		for i := 7; i >= 0; i-- {
			want[i] = uint8(l)
			l >>= 8
		}
		if got := CycleMI(tc); got != want {
			t.Errorf("CycleMI(%x) = %x, want %x", tc, got, want)
		}
	}
}
