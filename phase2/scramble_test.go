package phase2

import (
	"testing"

	"github.com/raidancampbell/gop25"
)

func TestLFSRCycle_SubRegisters(t *testing.T) {
	// Verify the sub-register widths: after cycling, bits stay within their
	// respective registers (no overflow).
	reg := uint64(0xFFF_FFFFF_FFFFF) // all 44 bits set
	next := lfsrCycle(reg)
	// The 44-bit register should still fit in 44 bits.
	if next>>44 != 0 {
		t.Errorf("LFSR overflow: %#x has bits above 43", next)
	}
}

func TestLFSRCycle_Zero(t *testing.T) {
	// A zero register should stay zero (no feedback adds new bits).
	reg := uint64(0)
	if next := lfsrCycle(reg); next != 0 {
		t.Errorf("LFSR cycle of zero = %#x, want 0", next)
	}
}

func TestGF2MatVecMul_Identity(t *testing.T) {
	// Zero input should produce zero output.
	if result := gf2MatVecMul(0); result != 0 {
		t.Errorf("gf2MatVecMul(0) = %#x, want 0", result)
	}
}

func TestGF2MatVecMul_Row0(t *testing.T) {
	// Input with only bit 43 set should return lfsrM[0].
	input := uint64(1) << 43
	result := gf2MatVecMul(input)
	if result != lfsrM[0] {
		t.Errorf("gf2MatVecMul(1<<43) = %#x, want %#x", result, lfsrM[0])
	}
}

func TestGenerateXORMask_KnownVector(t *testing.T) {
	// Test against op25's lfsr.py __main__ test case:
	// NAC=0x293, SYSID=0x18, WACN=0x1
	// Expected first 40 dibits from Python:
	// [0,0,0,0,0,0,0,0,0,1,0,0,0,1,2,0,0,2,2,1,0,3,1,2,0,2,3,1,0,3,3,1,1,3,2,2,1,3,3,0]
	expected := []p25.Dibit{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 2, 0, 0, 2, 2, 1,
		0, 3, 1, 2, 0, 2, 3, 1, 0, 3, 3, 1, 1, 3, 2, 2, 1, 3, 3, 0,
	}
	// Expected last 10 dibits:
	expectedTail := []p25.Dibit{2, 3, 2, 3, 3, 1, 1, 3, 0, 3}

	mask := GenerateXORMask(0x293, 0x18, 0x1)

	for i, want := range expected {
		if mask[i] != want {
			t.Errorf("mask[%d] = %d, want %d", i, mask[i], want)
		}
	}
	for i, want := range expectedTail {
		idx := SuperframeDibits - 10 + i
		if mask[idx] != want {
			t.Errorf("mask[%d] = %d, want %d", idx, mask[idx], want)
		}
	}
}

func TestGenerateXORMask_DifferentParams(t *testing.T) {
	// NAC=0x171 first 20 dibits from Python:
	// [0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,1,0,1,1,3]
	expected := []p25.Dibit{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 3,
	}
	mask := GenerateXORMask(0x171, 0x1, 0x1)
	for i, want := range expected {
		if mask[i] != want {
			t.Errorf("mask[%d] = %d, want %d", i, mask[i], want)
		}
	}
}

func TestGenerateXORMask_DibitRange(t *testing.T) {
	mask := GenerateXORMask(0x293, 0x18, 0x1)
	for i, d := range mask {
		if d > 3 {
			t.Errorf("mask[%d] = %d, exceeds dibit range [0,3]", i, d)
		}
	}
}

func TestDescramble_PreservesISCH(t *testing.T) {
	// The first 10 dibits (ISCH) should not be modified by Descramble.
	var b Burst
	for i := range b.Dibits {
		b.Dibits[i] = p25.Dibit(i % 4)
	}
	b.ISCH.Location = 0
	b.ISCH.Valid = true

	mask := GenerateXORMask(0x293, 0x18, 0x1)
	out := Descramble(b, mask)

	for i := 0; i < 10; i++ {
		if out.Dibits[i] != b.Dibits[i] {
			t.Errorf("Descramble modified ISCH dibit %d: got %d, want %d",
				i, out.Dibits[i], b.Dibits[i])
		}
	}
}

func TestDescramble_ModifiesPayload(t *testing.T) {
	// With a non-zero mask, the payload dibits should be different.
	var b Burst
	b.ISCH.Location = 5
	b.ISCH.Valid = true
	// Set all payload dibits to 0 — after XOR with non-zero mask, at least
	// some should change.
	mask := GenerateXORMask(0x293, 0x18, 0x1)
	out := Descramble(b, mask)
	changed := 0
	for i := 10; i < BurstDibits; i++ {
		if out.Dibits[i] != b.Dibits[i] {
			changed++
		}
	}
	if changed == 0 {
		t.Error("Descramble did not modify any payload dibits")
	}
}

func TestDescramble_InvalidLocation(t *testing.T) {
	// Invalid ISCH location should return the burst unchanged.
	var b Burst
	b.ISCH.Location = -1
	mask := GenerateXORMask(0x293, 0x18, 0x1)
	out := Descramble(b, mask)
	if out.Dibits != b.Dibits {
		t.Error("Descramble modified burst with invalid ISCH location")
	}
}
