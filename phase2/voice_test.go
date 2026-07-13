package phase2

import (
	"testing"

	"github.com/raidancampbell/gop25"
)

func TestExtractVCW_Deinterleave(t *testing.T) {
	// Build a 36-dibit voice codeword where we know the codeword values.
	// Set all c0 bits to 1 (24-bit = 0xFFFFFF), all others to 0.
	var dibits [VoiceCWDibits]p25.Dibit
	for i := 0; i < 72; i++ {
		e := vcwDeinterleave[i]
		if e[0] == 0 { // c0
			// Set this bit to 1 in the dibits
			dibitIdx := i / 2
			if i%2 == 0 { // MSB
				dibits[dibitIdx] |= p25.Dibit(1 << 1)
			} else { // LSB
				dibits[dibitIdx] |= p25.Dibit(1)
			}
		}
	}
	c0, c1, c2, c3 := extractVCW(dibits[:])
	if c0 != 0xFFFFFF {
		t.Errorf("c0 = %#x, want 0xFFFFFF", c0)
	}
	if c1 != 0 {
		t.Errorf("c1 = %#x, want 0", c1)
	}
	if c2 != 0 {
		t.Errorf("c2 = %#x, want 0", c2)
	}
	if c3 != 0 {
		t.Errorf("c3 = %#x, want 0", c3)
	}
}

func TestExtractVCW_AllOnes(t *testing.T) {
	// All dibits = 3 (both bits set) → all codewords should be all-1s.
	var dibits [VoiceCWDibits]p25.Dibit
	for i := range dibits {
		dibits[i] = 3
	}
	c0, c1, c2, c3 := extractVCW(dibits[:])
	if c0 != (1<<24)-1 {
		t.Errorf("c0 = %#x, want %#x", c0, (1<<24)-1)
	}
	if c1 != (1<<23)-1 {
		t.Errorf("c1 = %#x, want %#x", c1, (1<<23)-1)
	}
	if c2 != (1<<11)-1 {
		t.Errorf("c2 = %#x, want %#x", c2, (1<<11)-1)
	}
	if c3 != (1<<14)-1 {
		t.Errorf("c3 = %#x, want %#x", c3, (1<<14)-1)
	}
}

func TestExtractVCW_BitCount(t *testing.T) {
	// Verify that the deinterleave table maps exactly 24+23+11+14 = 72 bits.
	cwBits := [4]int{24, 23, 11, 14}
	counts := [4]int{}
	for _, e := range vcwDeinterleave {
		counts[e[0]]++
	}
	for i, want := range cwBits {
		if counts[i] != want {
			t.Errorf("codeword %d: %d bit mappings, want %d", i, counts[i], want)
		}
	}
}

func TestGeneratePRMask_KnownValue(t *testing.T) {
	// For u0=0, seed = 0*16 = 0.
	// pr[1] = (173*0 + 13849) mod 65536 = 13849, MSB = 0
	// pr[2] = (173*13849 + 13849) mod 65536 = (2395877 + 13849) % 65536
	//       = 2409726 % 65536 = 2409726 - 36*65536 = 2409726 - 2359296 = 50430
	//       MSB of 50430: 50430 >= 32768 → 1
	m1 := generatePRMask(0)
	if m1 == 0 {
		t.Error("PR mask for u0=0 should not be all zeros")
	}
	// Verify it's 23 bits (bit 22 is the MSB).
	if m1 >= (1 << 23) {
		t.Errorf("PR mask exceeds 23 bits: %#x", m1)
	}
}

func TestDecodeVoiceCW_Synthetic(t *testing.T) {
	// Encode known u[] values through Golay, interleave, and verify round-trip.
	// Use u0=0 (simplest case: all-zero message).
	u0 := uint16(0)
	u1 := uint16(0)
	u2 := uint16(0)
	u3 := uint16(0)

	// Encode c0: Golay(24,12,8)
	c0_23 := golayEncode23(u0)
	c0 := (c0_23 << 1) | parityBit(c0_23) // append overall parity as LSB

	// Encode c1: Golay(23,12) with PR mask
	m1 := generatePRMask(u0)
	c1 := golayEncode23(u1) ^ m1

	c2 := uint32(u2)
	c3 := uint32(u3)

	// Interleave into 36 dibits
	dibits := interleaveVCW(c0, c1, c2, c3)

	result := DecodeVoiceCW(dibits[:])
	if !result.OK {
		t.Fatalf("DecodeVoiceCW failed for all-zero input, errs=%d", result.Errs)
	}
	if result.U[0] != u0 || result.U[1] != u1 || result.U[2] != u2 || result.U[3] != u3 {
		t.Errorf("got u=%v, want [%d %d %d %d]", result.U, u0, u1, u2, u3)
	}
	if result.Errs != 0 {
		t.Errorf("got %d errors, want 0", result.Errs)
	}
}

func TestDecodeVoiceCW_NonZero(t *testing.T) {
	// Encode non-zero u[] values and verify round-trip.
	u0 := uint16(0xABC)  // 12 bits
	u1 := uint16(0x123)  // 12 bits
	u2 := uint16(0x456)  // 11 bits → mask to 11 bits
	u3 := uint16(0x1234) // 14 bits → mask to 14 bits
	u2 &= 0x7FF
	u3 &= 0x3FFF

	c0_23 := golayEncode23(u0)
	c0 := (c0_23 << 1) | parityBit(c0_23)
	m1 := generatePRMask(u0)
	c1 := golayEncode23(u1) ^ m1
	c2 := uint32(u2)
	c3 := uint32(u3)

	dibits := interleaveVCW(c0, c1, c2, c3)
	result := DecodeVoiceCW(dibits[:])
	if !result.OK {
		t.Fatalf("DecodeVoiceCW failed, errs=%d", result.Errs)
	}
	if result.U[0] != u0 {
		t.Errorf("u[0] = %#x, want %#x", result.U[0], u0)
	}
	if result.U[1] != u1 {
		t.Errorf("u[1] = %#x, want %#x", result.U[1], u1)
	}
	if result.U[2] != u2 {
		t.Errorf("u[2] = %#x, want %#x", result.U[2], u2)
	}
	if result.U[3] != u3 {
		t.Errorf("u[3] = %#x, want %#x", result.U[3], u3)
	}
}

func TestPackAMBE_BitCount(t *testing.T) {
	// Verify that PackAMBE produces exactly 49 bits.
	u := [4]uint16{0xFFF, 0xFFF, 0x7FF, 0x3FFF}
	d := PackAMBE(u)
	ones := 0
	for _, b := range d {
		if b != 0 && b != 1 {
			t.Fatalf("PackAMBE produced non-binary value %d", b)
		}
		ones += int(b)
	}
	if ones != 12+12+11+14 {
		t.Errorf("all-ones input: %d ones, want %d", ones, 12+12+11+14)
	}
}

func TestPackAMBE_RoundTrip(t *testing.T) {
	u := [4]uint16{0xABC, 0x123, 0x456 & 0x7FF, 0x1234 & 0x3FFF}
	d := PackAMBE(u)

	// Unpack: reverse the packing
	var got [4]uint16
	pos := 0
	for i := 11; i >= 0; i-- {
		got[0] |= uint16(d[pos]) << uint(i)
		pos++
	}
	for i := 11; i >= 0; i-- {
		got[1] |= uint16(d[pos]) << uint(i)
		pos++
	}
	for i := 10; i >= 0; i-- {
		got[2] |= uint16(d[pos]) << uint(i)
		pos++
	}
	for i := 13; i >= 0; i-- {
		got[3] |= uint16(d[pos]) << uint(i)
		pos++
	}
	if got != u {
		t.Errorf("round-trip failed: got %v, want %v", got, u)
	}
}

func TestPackCW_UnpackCW_RoundTrip(t *testing.T) {
	tests := [][4]uint16{
		{0, 0, 0, 0},
		{0xFFF, 0xFFF, 0x7FF, 0x3FFF}, // max values (12, 12, 11, 14 bits)
		{0xABC, 0x123, 0x456, 0x1234},
		{1, 2, 3, 4},
		{0x800, 0x001, 0x400, 0x2000},
	}
	for _, u := range tests {
		packed := PackCW(u)
		got := UnpackCW(packed)
		if got != u {
			t.Errorf("PackCW/UnpackCW round-trip failed: input=%v, packed=%x, got=%v", u, packed, got)
		}
	}
}

func TestPackCW_KnownValues(t *testing.T) {
	// Verify packing matches op25 p25p2_vf::pack_cw bit layout.
	u := [4]uint16{0xABC, 0x123, 0x456, 0x1234}
	cw := PackCW(u)

	// u[0]=0xABC (12 bits): cw[0] = 0xABC >> 4 = 0xAB
	if cw[0] != 0xAB {
		t.Errorf("cw[0] = %#x, want 0xAB", cw[0])
	}
	// cw[1] = ((0xABC & 0xf) << 4) | (0x123 >> 8) = (0xC<<4) | 0x1 = 0xC1
	if cw[1] != 0xC1 {
		t.Errorf("cw[1] = %#x, want 0xC1", cw[1])
	}
	// cw[2] = u[1] & 0xff = 0x23
	if cw[2] != 0x23 {
		t.Errorf("cw[2] = %#x, want 0x23", cw[2])
	}
}

func TestPackCW_49thBit(t *testing.T) {
	// u[3] has 14 bits. The LSB of u[3] becomes the MSB of cw[6].
	// Only the MSB of cw[6] is meaningful (the 49th bit).
	u := [4]uint16{0, 0, 0, 1} // u[3] = 1, LSB set
	cw := PackCW(u)
	if cw[6] != 0x80 {
		t.Errorf("u[3]=1: cw[6] = %#x, want 0x80", cw[6])
	}

	u2 := [4]uint16{0, 0, 0, 0} // u[3] = 0
	cw2 := PackCW(u2)
	if cw2[6] != 0x00 {
		t.Errorf("u[3]=0: cw[6] = %#x, want 0x00", cw2[6])
	}
}

// --- test helpers ---

// golayEncode23 is a simple Golay(23,12) encoder for test use.
// Mirrors the encoding in internal/p25/golay.go (unexported golayEncode).
func golayEncode23(msg uint16) uint32 {
	const poly = 0xC75
	shifted := uint32(msg) << 11
	rem := shifted
	for i := 22; i >= 11; i-- {
		if rem&(1<<uint(i)) != 0 {
			rem ^= poly << uint(i-11)
		}
	}
	return shifted | (rem & 0x7FF)
}

// parityBit returns the overall parity (XOR of all bits) of a 23-bit word.
func parityBit(cw uint32) uint32 {
	p := uint32(0)
	for i := 0; i < 23; i++ {
		p ^= (cw >> uint(i)) & 1
	}
	return p
}

// interleaveVCW is the inverse of extractVCW: packs c0/c1/c2/c3 into 36 dibits.
func interleaveVCW(c0, c1, c2, c3 uint32) [VoiceCWDibits]p25.Dibit {
	cw := [4]uint32{c0, c1, c2, c3}
	var dibits [VoiceCWDibits]p25.Dibit
	for i := 0; i < 72; i++ {
		e := vcwDeinterleave[i]
		bit := uint8((cw[e[0]] >> uint(e[1])) & 1)
		dibitIdx := i / 2
		if i%2 == 0 { // MSB of dibit
			dibits[dibitIdx] |= p25.Dibit(bit << 1)
		} else { // LSB of dibit
			dibits[dibitIdx] |= p25.Dibit(bit)
		}
	}
	return dibits
}
