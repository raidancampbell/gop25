package phase2

import (
	"github.com/raidancampbell/gop25"
)

// VoiceCWDibits is the number of dibits per voice codeword.
const VoiceCWDibits = 36

// VoiceCWResult holds the decoded AMBE+2 parameters from one voice codeword.
type VoiceCWResult struct {
	U               [4]uint16 // u[0..3]: 12+12+11+14 = 49 bits of AMBE+2 parameters
	Errs            int       // total FEC errors (c0 + c1)
	OK              bool      // true if both Golay decodes succeeded
	C0Uncorrectable bool      // c0 extended-Golay detected a weight->=4 (uncorrectable) error
}

// vcwDeinterleave maps each of the 72 bit positions (from 36 dibits expanded
// MSB-first) to a (codeword_index, bit_position) pair.
// Codeword 0 (c0): 24 bits — Golay(24,12,8)
// Codeword 1 (c1): 23 bits — Golay(23,12,7) with PR mask
// Codeword 2 (c2): 11 bits — uncoded
// Codeword 3 (c3): 14 bits — uncoded
// Source: op25 p25p2_vf.cc:extract_vcw (lines 747-818)
var vcwDeinterleave = [72][2]int{
	// vf[0..3]
	{0, 23}, {0, 5}, {1, 10}, {2, 3},
	// vf[4..7]
	{0, 22}, {0, 4}, {1, 9}, {2, 2},
	// vf[8..11]
	{0, 21}, {0, 3}, {1, 8}, {2, 1},
	// vf[12..15]
	{0, 20}, {0, 2}, {1, 7}, {2, 0},
	// vf[16..19]
	{0, 19}, {0, 1}, {1, 6}, {3, 13},
	// vf[20..23]
	{0, 18}, {0, 0}, {1, 5}, {3, 12},
	// vf[24..27]
	{0, 17}, {1, 22}, {1, 4}, {3, 11},
	// vf[28..31]
	{0, 16}, {1, 21}, {1, 3}, {3, 10},
	// vf[32..35]
	{0, 15}, {1, 20}, {1, 2}, {3, 9},
	// vf[36..39]
	{0, 14}, {1, 19}, {1, 1}, {3, 8},
	// vf[40..43]
	{0, 13}, {1, 18}, {1, 0}, {3, 7},
	// vf[44..47]
	{0, 12}, {1, 17}, {2, 10}, {3, 6},
	// vf[48..51]
	{0, 11}, {1, 16}, {2, 9}, {3, 5},
	// vf[52..55]
	{0, 10}, {1, 15}, {2, 8}, {3, 4},
	// vf[56..59]
	{0, 9}, {1, 14}, {2, 7}, {3, 3},
	// vf[60..63]
	{0, 8}, {1, 13}, {2, 6}, {3, 2},
	// vf[64..67]
	{0, 7}, {1, 12}, {2, 5}, {3, 1},
	// vf[68..71]
	{0, 6}, {1, 11}, {2, 4}, {3, 0},
}

// extractVCW deinterleaves 36 dibits (72 bits) into four codewords.
// Returns c0 (24-bit), c1 (23-bit), c2 (11-bit), c3 (14-bit) as uint32.
// The bit ordering follows op25: c[N] → bit N of the integer (MSB = highest index).
func extractVCW(dibits []p25.Dibit) (c0, c1, c2, c3 uint32) {
	var cw [4]uint32
	for i := 0; i < VoiceCWDibits; i++ {
		msb := uint32((dibits[i] >> 1) & 1)
		lsb := uint32(dibits[i] & 1)
		e0 := vcwDeinterleave[2*i]
		e1 := vcwDeinterleave[2*i+1]
		cw[e0[0]] |= msb << uint(e0[1])
		cw[e1[0]] |= lsb << uint(e1[1])
	}
	return cw[0], cw[1], cw[2], cw[3]
}

// generatePRMask generates the 23-bit pseudo-random mask from u0 (12-bit
// decoded c0 message). The mask is XOR'd with c1 before Golay(23,12) decode.
// Uses LCG: pr[n] = (173*pr[n-1] + 13849) mod 65536, output = MSB of pr[n].
// Source: op25 p25p2_vf.cc:process_vcw (lines 578-588)
func generatePRMask(u0 uint16) uint32 {
	pr := int(u0) * 16
	var m1 uint32
	for n := 1; n < 24; n++ {
		pr = (173*pr + 13849) % 65536
		bit := uint32((pr >> 15) & 1)
		m1 = (m1 << 1) | bit
	}
	return m1
}

// DecodeVoiceCW decodes one Phase 2 voice codeword from 36 dibits.
// Returns the four AMBE+2 parameter words (49 bits total), FEC error count,
// and whether decoding succeeded.
func DecodeVoiceCW(dibits []p25.Dibit) VoiceCWResult {
	if len(dibits) < VoiceCWDibits {
		return VoiceCWResult{}
	}

	c0, c1, c2, c3 := extractVCW(dibits)
	c0Uncorr := p25.Golay24DetectUncorrectable(c0)

	// c0: Golay(24,12,8) — strip parity bit (LSB), decode as Golay(23,12).
	u0, errs0, ok0 := p25.Golay24Decode(c0)
	if !ok0 {
		return VoiceCWResult{Errs: errs0, C0Uncorrectable: c0Uncorr}
	}

	// Generate PR mask from u0 and XOR with c1 before Golay(23,12) decode.
	m1 := generatePRMask(u0)
	u1, errs1, ok1 := p25.GolayDecode(c1 ^ m1)
	if !ok1 {
		return VoiceCWResult{U: [4]uint16{u0}, Errs: errs0 + errs1, C0Uncorrectable: c0Uncorr}
	}

	// c2 and c3 are uncoded — pass through directly.
	u2 := uint16(c2) // 11 bits
	u3 := uint16(c3) // 14 bits

	return VoiceCWResult{
		U:               [4]uint16{u0, u1, u2, u3},
		Errs:            errs0 + errs1,
		OK:              true,
		C0Uncorrectable: c0Uncorr,
	}
}

// PackCW packs the four AMBE+2 parameter words into a 7-byte packed codeword.
// This is the format used for ADP decryption (XOR keystream is applied to
// the packed form). Matches op25 p25p2_vf::pack_cw.
func PackCW(u [4]uint16) [7]byte {
	var cw [7]byte
	cw[0] = byte(u[0] >> 4)
	cw[1] = byte(((u[0] & 0xf) << 4) | (u[1] >> 8))
	cw[2] = byte(u[1] & 0xff)
	cw[3] = byte(u[2] >> 3)
	cw[4] = byte(((u[2] & 0x7) << 5) | (u[3] >> 9))
	cw[5] = byte((u[3] >> 1) & 0xff)
	cw[6] = byte((u[3] & 0x1) << 7)
	return cw
}

// UnpackCW unpacks a 7-byte packed codeword into four AMBE+2 parameter words.
// Inverse of PackCW. Matches op25 p25p2_vf::unpack_cw.
func UnpackCW(cw [7]byte) [4]uint16 {
	var u [4]uint16
	u[0] = uint16(cw[0])<<4 | uint16(cw[1]&0xf0)>>4
	u[1] = uint16(cw[1]&0x0f)<<8 | uint16(cw[2])
	u[2] = uint16(cw[3])<<3 | uint16(cw[4]&0xe0)>>5
	u[3] = uint16(cw[4]&0x1f)<<9 | uint16(cw[5])<<1 | uint16(cw[6]&0x80)>>7
	return u
}

// PackAMBE packs the four u[] words into a 49-element bit vector (1 bit per
// byte, MSB-first within each word) suitable for mbelib's ambe_d[49] input.
// Layout: u[0] bits 11..0 → d[0..11], u[1] bits 11..0 → d[12..23],
// u[2] bits 10..0 → d[24..34], u[3] bits 13..0 → d[35..48].
func PackAMBE(u [4]uint16) [49]uint8 {
	var d [49]uint8
	pos := 0
	for i := 11; i >= 0; i-- {
		d[pos] = uint8((u[0] >> uint(i)) & 1)
		pos++
	}
	for i := 11; i >= 0; i-- {
		d[pos] = uint8((u[1] >> uint(i)) & 1)
		pos++
	}
	for i := 10; i >= 0; i-- {
		d[pos] = uint8((u[2] >> uint(i)) & 1)
		pos++
	}
	for i := 13; i >= 0; i-- {
		d[pos] = uint8((u[3] >> uint(i)) & 1)
		pos++
	}
	return d
}
