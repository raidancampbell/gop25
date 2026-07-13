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

