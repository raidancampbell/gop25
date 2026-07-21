package p25

import "math/bits"

// golayPoly is the generator polynomial for the Golay(23,12) code:
// g(x) = x^11 + x^10 + x^6 + x^5 + x^4 + x^2 + 1.
const golayPoly = 0xC75

// golayTable maps each 11-bit syndrome to a 23-bit error pattern.
// Built in init().
var golayTable [2048]uint32

func init() {
	// Build Golay(23,12) syndrome lookup table.
	for w := 0; w <= 3; w++ {
		enumErrors(23, w, 0, 0, func(pat uint32) {
			s := golaySyndrome(pat)
			if golayTable[s] == 0 || bits.OnesCount32(pat) < bits.OnesCount32(golayTable[s]) {
				golayTable[s] = pat
			}
		})
	}

}

func enumErrors(n, w, start int, pat uint32, fn func(uint32)) {
	if w == 0 {
		fn(pat)
		return
	}
	for i := start; i < n; i++ {
		enumErrors(n, w-1, i+1, pat|(1<<uint(i)), fn)
	}
}

// golayEncode performs systematic encoding of a 12-bit message into a 23-bit
// Golay codeword via polynomial division by the generator polynomial.
func golayEncode(msg uint16) uint32 {
	shifted := uint32(msg) << 11
	rem := shifted
	for i := 22; i >= 11; i-- {
		if rem&(1<<uint(i)) != 0 {
			rem ^= golayPoly << uint(i-11)
		}
	}
	return shifted | (rem & 0x7FF)
}

// golaySyndrome computes the 11-bit syndrome by dividing the received 23-bit
// word by the generator polynomial.
func golaySyndrome(received uint32) uint16 {
	rem := received
	for i := 22; i >= 11; i-- {
		if rem&(1<<uint(i)) != 0 {
			rem ^= golayPoly << uint(i-11)
		}
	}
	return uint16(rem & 0x7FF)
}

// golayDecode decodes a 23-bit received word, correcting up to 3 bit errors.
// Returns the 12-bit message and true, or 0 and false if uncorrectable.
func golayDecode(received uint32) (uint16, bool) {
	s := golaySyndrome(received)
	if s == 0 {
		return uint16(received >> 11), true
	}
	errPat := golayTable[s]
	if errPat == 0 {
		return 0, false
	}
	corrected := received ^ errPat
	return uint16(corrected >> 11), true
}

// GolayDecode decodes a 23-bit received word, correcting up to 3 bit errors.
// Returns the 12-bit message, the number of corrected bit errors, and ok=true
// if the codeword was correctable. Exported for use by Phase 2 voice FEC.
func GolayDecode(received uint32) (uint16, int, bool) {
	s := golaySyndrome(received)
	if s == 0 {
		return uint16(received >> 11), 0, true
	}
	errPat := golayTable[s]
	if errPat == 0 {
		return 0, 0, false
	}
	corrected := received ^ errPat
	return uint16(corrected >> 11), bits.OnesCount32(errPat), true
}

// Golay24Decode decodes a 24-bit Golay(24,12,8) received word, correcting up
// to 3 bit errors. The LSB is the overall parity bit, which is stripped before
// delegating to the Golay(23,12) decoder.
func Golay24Decode(received uint32) (uint16, int, bool) {
	return GolayDecode(received >> 1)
}

// Golay24DetectUncorrectable reports whether a 24-bit extended Golay(24,12,8)
// received word carries a DETECTED but uncorrectable error (Hamming weight >= 4).
//
// The (24,12,8) code corrects up to 3 errors and detects 4. Golay24Decode
// discards the overall-parity bit (received >> 1) and delegates to the perfect
// (23,12) decoder, which ALWAYS "succeeds" — so it silently miscorrects >=4-error
// words. This function recovers the discarded signal: it decodes the (23,12) part
// (always correctable), re-encodes the clean codeword, and measures the total
// Hamming distance including the overall-parity bit. Distance >= 4 means the word
// was beyond the correction radius. Layout matches the c0 convention used by the
// phase2 voice path: bit 0 (LSB) is the overall even-parity bit; bits 1..23 are
// the 23-bit systematic Golay codeword.
//
// Verified over the full space: 0 false positives on all 4096 clean codewords and
// all weight-1..3 error patterns; 100% detection on all 10,626 weight-4 patterns.
func Golay24DetectUncorrectable(received uint32) bool {
	rx23 := received >> 1
	rxParity := received & 1
	corr12, _, _ := GolayDecode(rx23) // (23,12) is perfect: always corrects to some codeword
	clean23 := golayEncode(corr12)
	dist := bits.OnesCount32(rx23 ^ clean23) // errors in the 23-bit part
	if uint32(bits.OnesCount32(clean23&0x7FFFFF)&1) != rxParity {
		dist++ // overall-parity bit also in error
	}
	return dist >= 4
}

