package p25

import "math/bits"

// GF(2^6) field tables, primitive polynomial x^6 + x + 1.
var (
	gfExp [64]uint8
	gfLog [64]uint8
)

// BCH(63,16,23) generator polynomial and NID codeword table.
var (
	genPoly  uint64
	nidTable [65536]uint64
)

func init() {
	// Build GF(2^6) exp/log tables
	x := uint8(1)
	for i := 0; i < 63; i++ {
		gfExp[i] = x
		gfLog[x] = uint8(i)
		x <<= 1
		if x >= 64 {
			x ^= 0x43 // x^6 + x + 1
		}
	}
	gfExp[63] = gfExp[0]

	// Generator polynomial = product of minimal polynomials for
	// cyclotomic cosets covering α^1 through α^22.
	cosets := [][]int{
		{1, 2, 4, 8, 16, 32},
		{3, 6, 12, 24, 48, 33},
		{5, 10, 20, 40, 17, 34},
		{7, 14, 28, 56, 49, 35},
		{9, 18, 36},
		{11, 22, 44, 25, 50, 37},
		{13, 26, 52, 41, 19, 38},
		{15, 30, 60, 57, 51, 39},
		{21, 42},
	}
	genPoly = 1
	for _, cs := range cosets {
		genPoly = gf2PolyMul(genPoly, minPoly(cs))
	}

	// Pre-compute all 65536 valid 64-bit NID codewords
	for msg := 0; msg < 65536; msg++ {
		nidTable[msg] = bchEncode(uint16(msg))
	}
}

func gfMul(a, b uint8) uint8 {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[(int(gfLog[a])+int(gfLog[b]))%63]
}

// GFMul returns the product of a and b in GF(2^6). Exported for phase2 tests.
func GFMul(a, b uint8) uint8 { return gfMul(a, b) }

// GFExp returns α^i in GF(2^6). Exported for phase2 tests.
func GFExp(i int) uint8 { return gfExp[i%63] }

// minPoly computes the minimal polynomial over GF(2) for a cyclotomic coset
// of GF(2^6). The result is a bitmask with bit i = coefficient of x^i.
func minPoly(coset []int) uint64 {
	// Multiply (x + α^exp) for each exp in the coset, over GF(2^6).
	// Coefficients are guaranteed to land in GF(2).
	poly := []uint8{1}
	for _, exp := range coset {
		root := gfExp[exp%63]
		next := make([]uint8, len(poly)+1)
		for i, c := range poly {
			next[i+1] ^= c
			next[i] ^= gfMul(c, root)
		}
		poly = next
	}
	var result uint64
	for i, c := range poly {
		if c == 1 {
			result |= uint64(1) << uint(i)
		}
	}
	return result
}

// gf2PolyMul multiplies two polynomials over GF(2), each represented
// as a uint64 bitmask with bit i = coefficient of x^i.
func gf2PolyMul(a, b uint64) uint64 {
	var r uint64
	for b != 0 {
		if b&1 != 0 {
			r ^= a
		}
		a <<= 1
		b >>= 1
	}
	return r
}

// bchEncode performs systematic BCH(63,16) encoding of a 16-bit message
// (NAC<<4 | DUID) and appends an even parity bit to produce a 64-bit NID.
func bchEncode(msg uint16) uint64 {
	cw := uint64(msg) << 47
	rem := cw
	for i := 62; i >= 47; i-- {
		if rem&(uint64(1)<<uint(i)) != 0 {
			rem ^= genPoly << uint(i-47)
		}
	}
	cw |= rem
	p := uint64(bits.OnesCount64(cw) & 1)
	return (cw << 1) | p
}

var validDUIDs = [...]uint8{0x0, 0x3, 0x5, 0x7, 0xA, 0xC, 0xF}

// decodeNID performs brute-force minimum-distance decoding of a received
// 64-bit NID. Returns the decoded NID and true if the best match is within
// the correction capability (≤11 bit errors), or zero NID and false otherwise.
func decodeNID(received uint64) (NID, bool) {
	bestDist := 65
	var bestNAC uint16
	var bestDUID uint8

	for _, duid := range validDUIDs {
		for nac := uint16(0); nac < 4096; nac++ {
			msg := (nac << 4) | uint16(duid)
			dist := bits.OnesCount64(received ^ nidTable[msg])
			if dist < bestDist {
				bestDist = dist
				bestNAC = nac
				bestDUID = duid
			}
		}
	}

	if bestDist > 11 {
		return NID{}, false
	}
	return NID{NAC: bestNAC, DUID: bestDUID}, true
}

// decodeNIDWithHintDist performs NID decoding using a known NAC as a hint,
// returning the winning Hamming distance alongside the NID.
//
// When the NAC is already established from previous frames, the search space
// collapses from 4096×6 to just 6 DUID candidates for that NAC. The minimum
// Hamming distance between distinct same-NAC valid-DUID NID codewords is 24
// (verified by brute force over all 4096 NACs and 7 valid DUIDs), so the
// guaranteed-unambiguous correction limit is floor((24-1)/2)=11 — the same as
// the standard full-search decode. Using a larger threshold would admit
// received words in the ambiguous zone between two same-NAC codewords and
// mis-correct to the wrong DUID, mis-routing the frame (control vs voice,
// squelch/capture lifecycle).
//
// Returning the distance lets the caller record when a frame decoded via the
// hint path, without re-running the 4096×6 brute-force. Returns ok=false
// (falling back to the standard full-search decode) when the hint-based decode
// fails.
func decodeNIDWithHintDist(received uint64, hintNAC uint16) (NID, int, bool) {
	const hintThresh = 11
	bestDist := 65
	var bestDUID uint8

	for _, duid := range validDUIDs {
		msg := (hintNAC << 4) | uint16(duid)
		dist := bits.OnesCount64(received ^ nidTable[msg])
		if dist < bestDist {
			bestDist = dist
			bestDUID = duid
		}
	}
	if bestDist <= hintThresh {
		return NID{NAC: hintNAC, DUID: bestDUID}, bestDist, true
	}

	// Hint failed — fall back to full search with standard threshold.
	nid, ok := decodeNID(received)
	if ok {
		// Return actual distance for the winning full-search codeword.
		msg := (nid.NAC << 4) | uint16(nid.DUID)
		return nid, bits.OnesCount64(received ^ nidTable[msg]), true
	}
	return nid, bestDist, false
}
