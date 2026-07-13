package phase2

import "github.com/raidancampbell/gop25"

// SuperframeDibits is the total number of dibits in one superframe XOR mask.
const SuperframeDibits = SuperframeBursts * BurstDibits // 2160

// lfsrM is the 44×44 GF(2) transformation matrix used to condition the LFSR
// initial state from (WACN<<24 | SYSID<<12 | NAC). Each row is stored as a
// uint64 bitmask; column j of row i is bit (43-j) of lfsrM[i].
// Source: op25 lfsr.py matrix M (generated via script extraction).
var lfsrM = [44]uint64{
	0x88410800200, // row 0
	0x44208400100, // row 1
	0x22104200080, // row 2
	0x11082100040, // row 3
	0x08841080020, // row 4
	0x04420840010, // row 5
	0x02210420008, // row 6
	0x01108210004, // row 7
	0x00884108002, // row 8
	0x00442084001, // row 9
	0x00221042000, // row 10
	0x00110821000, // row 11
	0x00088410800, // row 12
	0x00044208400, // row 13
	0x00022104200, // row 14
	0x00011082100, // row 15
	0x00008841080, // row 16
	0x00004420840, // row 17
	0x00002210420, // row 18
	0x00001108210, // row 19
	0x00000884108, // row 20
	0x00000442084, // row 21
	0x00000221042, // row 22
	0x00000110821, // row 23
	0x00000088410, // row 24
	0x00000044208, // row 25
	0x00000022104, // row 26
	0x00000011082, // row 27
	0x00000008841, // row 28
	0x00000004420, // row 29
	0x00000002210, // row 30
	0x00000001108, // row 31
	0x00000000884, // row 32
	0x00000000442, // row 33
	0x00000000221, // row 34
	0x00000000110, // row 35
	0x00000000088, // row 36
	0x00000000044, // row 37
	0x00000000022, // row 38
	0x00000000011, // row 39
	0x00000000008, // row 40
	0x00000000004, // row 41
	0x00000000002, // row 42
	0x00000000001, // row 43
}

// gf2MatVecMul multiplies a 44-bit row vector by the 44×44 matrix M over GF(2).
// The input vector v has bit k representing element k; the result is computed as
// result[i] = XOR of (v[j] AND M[j][i]) for all j.
func gf2MatVecMul(v uint64) uint64 {
	var result uint64
	for bit := 0; bit < 44; bit++ {
		if (v>>uint(43-bit))&1 == 0 {
			continue
		}
		result ^= lfsrM[bit]
	}
	return result
}

// lfsrCycle advances the 44-bit LFSR by one clock. The register is decomposed
// into six sub-registers: S1(4), S2(5), S3(6), S4(5), S5(14), S6(10).
// Source: op25 lfsr.py:cyc_reg
func lfsrCycle(reg uint64) uint64 {
	s1 := (reg >> 40) & 0xF
	s2 := (reg >> 35) & 0x1F
	s3 := (reg >> 29) & 0x3F
	s4 := (reg >> 24) & 0x1F
	s5 := (reg >> 10) & 0x3FFF
	s6 := reg & 0x3FF

	cy1 := (s1 >> 3) & 1
	cy2 := (s2 >> 4) & 1
	cy3 := (s3 >> 5) & 1
	cy4 := (s4 >> 4) & 1
	cy5 := (s5 >> 13) & 1
	cy6 := (s6 >> 9) & 1

	x1 := cy1 ^ cy2
	x2 := cy1 ^ cy3
	x3 := cy1 ^ cy4
	x4 := cy1 ^ cy5
	x5 := cy1 ^ cy6

	s1 = ((s1 << 1) & 0xF) | (x1 & 1)
	s2 = ((s2 << 1) & 0x1F) | (x2 & 1)
	s3 = ((s3 << 1) & 0x3F) | (x3 & 1)
	s4 = ((s4 << 1) & 0x1F) | (x4 & 1)
	s5 = ((s5 << 1) & 0x3FFF) | (x5 & 1)
	s6 = ((s6 << 1) & 0x3FF) | (cy1 & 1)

	return (s1 << 40) | (s2 << 35) | (s3 << 29) | (s4 << 24) | (s5 << 10) | s6
}

// GenerateXORMask computes the 2160-dibit XOR descrambling mask for one
// superframe, given the system identity parameters. The LFSR produces 4320
// bits (2160 dibits = 12 × 180). Indexed at stride 180 (BurstDibits):
// mask[burstPosition*180 + i] where i=0..169. The first 10 entries per
// burst slot (ISCH area) exist in the array but are not applied.
// Source: op25 lfsr.py:mk_xor_bits + p25p2_tdma.cc:set_xormask
func GenerateXORMask(nac uint16, sysid uint16, wacn uint32) [SuperframeDibits]p25.Dibit {
	// Build initial 44-bit LFSR seed.
	seed := uint64(wacn)<<24 | uint64(sysid)<<12 | uint64(nac)

	// Convert to bit vector (MSB-first, bit 43 = MSB) and multiply by M.
	reg := gf2MatVecMul(seed)

	// Generate 4320 bits (output is MSB of register before each cycle).
	var bits [4320]uint8
	for i := 0; i < 4320; i++ {
		bits[i] = uint8((reg >> 43) & 1)
		reg = lfsrCycle(reg)
	}

	// Pack pairs of bits into dibits.
	var mask [SuperframeDibits]p25.Dibit
	for i := 0; i < SuperframeDibits; i++ {
		mask[i] = p25.Dibit((bits[2*i] << 1) | bits[2*i+1])
	}
	return mask
}

// PayloadDibitsPerBurst is the number of payload dibits per burst (positions
// 10..179 = 170 dibits). Used for burst-level payload size calculations.
const PayloadDibitsPerBurst = BurstDibits - 10 // 170

// Descramble applies the XOR mask to a burst at the given superframe position.
// Only the 170 payload dibits (burst[10:180]) are XOR'd; the first 10 dibits
// (ISCH/sync) are preserved. Returns a new burst with descrambled payload.
//
// The mask stride is BurstDibits (180), NOT PayloadDibitsPerBurst (170).
// Each superframe position occupies a 180-dibit block in the mask array;
// the first 10 entries of each block (corresponding to ISCH) are skipped.
// Source: op25 p25p2_tdma.cc handle_packet:
//
//	tdma_xormask[sync.tdma_slotid() * BURST_SIZE + i]  (BURST_SIZE=180, i=0..169)
func Descramble(b Burst, mask [SuperframeDibits]p25.Dibit) Burst {
	out := b
	if b.ISCH.Location < 0 || b.ISCH.Location >= SuperframeBursts {
		return out // cannot descramble without valid ISCH location
	}
	base := b.ISCH.Location * BurstDibits // stride 180, matching op25
	for i := 10; i < BurstDibits; i++ {
		out.Dibits[i] = b.Dibits[i] ^ mask[base+i-10]
	}
	return out
}
