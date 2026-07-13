package p25

// ADP (Motorola Advanced Digital Privacy) keystream generator and per-codeword
// XOR. Direct port of reference/op25/op25/gr-op25_repeater/lib/op25_crypt_adp.cc.
//
// ADP wraps RC4 with a P25-specific schedule:
//   - The 13-byte effective key is 5 bytes of secret || 8 bytes of MI.
//     Short secret keys are left-padded with zeros to 5 bytes.
//   - RC4 KSA permutes S[0..255] using K[i] = effective_key[i % 13].
//   - The PRGA emits 469 bytes of keystream up front; everything afterwards
//     indexes into that buffer. Standard RC4 "discard N" is folded into the
//     per-codeword offset (the +267 below), not a separate prologue.
//
// One Prepare() call covers exactly one LDU1+LDU2 pair: 9 voice codewords
// per LDU x 11 keystream bytes per codeword = 99 bytes per LDU, x 2 LDUs =
// 198 bytes consumed, plus the +267 base discard and a 2-byte gap between LDUs
// = 469 bytes generated. Re-Prepare with the next MI before processing the
// next pair (the next MI arrives in each LDU2's ES).

import (
	"errors"
)

// ADPKeystreamLen is the count of pre-generated keystream bytes per (key, MI)
// pair. Mirrors op25_crypt_adp.cc:89 (loop bound 469).
const ADPKeystreamLen = 469

// ADP carries the prepared RC4 keystream + per-frame position.
type ADP struct {
	Keystream [ADPKeystreamLen]byte
	Position  int // 0..8, cycles per voice codeword within an LDU
}

// Prepare initialises the keystream from a 5-byte (or shorter) key and a
// 9-byte MI. Only MI[0:8] is actually used (op25_crypt_adp.cc:70-72 reads
// d_mi[0..7]); MI[8] is ignored. Resets the per-LDU position counter.
//
// key must be <= 5 bytes (longer keys are silently truncated by op25's loop
// at line 65-67; we mirror that for compatibility but it's worth verifying
// against an actual ADP key before trusting).
func (a *ADP) Prepare(key []byte, mi [9]byte) error {
	if len(key) > 5 {
		// op25 truncates silently; we surface the case rather than hide it.
		return errors.New("adp: key length > 5 bytes is non-standard")
	}

	// Build 13-byte effective key: leading zero-padding, then key, then MI[0:8].
	var effective [13]byte
	pad := 5 - len(key)
	for i := 0; i < len(key); i++ {
		effective[pad+i] = key[i]
	}
	for i := 0; i < 8; i++ {
		effective[5+i] = mi[i]
	}

	// Expand to K[0..255] = effective[i % 13].
	var K [256]byte
	for i := 0; i < 256; i++ {
		K[i] = effective[i%13]
	}

	// RC4 KSA (key scheduling algorithm).
	var S [256]byte
	for i := 0; i < 256; i++ {
		S[i] = byte(i)
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(S[i]) + int(K[i])) & 0xFF
		S[i], S[j] = S[j], S[i]
	}

	// RC4 PRGA generating 469 bytes into a.Keystream.
	i := 0
	j = 0
	for k := 0; k < ADPKeystreamLen; k++ {
		i = (i + 1) & 0xFF
		j = (j + int(S[i])) & 0xFF
		S[i], S[j] = S[j], S[i]
		a.Keystream[k] = S[(int(S[i])+int(S[j]))&0xFF]
	}

	a.Position = 0
	return nil
}

// XORCodeword applies the ADP keystream to one 11-byte packed IMBE codeword
// in-place. The keystream offset is determined by:
//   - which LDU within the pair (LDU1 -> base 0, LDU2 -> base 101)
//   - the voice-codeword position within that LDU (0..8, auto-advancing)
//   - a fixed +267 discard, plus +2 padding after position 7
//
// This is the Phase 1 (FDMA) path.
//
// Call this exactly 9 times per LDU. After the 9th call position wraps to 0,
// so the same ADP can process LDU2 immediately after LDU1.
func (a *ADP) XORCodeword(packed *[11]byte, isLDU2 bool) {
	var base int
	if isLDU2 {
		base = 101
	}
	offset := base + a.Position*11 + 267
	if a.Position >= 8 {
		offset += 2
	}
	for i := 0; i < 11; i++ {
		packed[i] ^= a.Keystream[offset+i]
	}
	a.Position = (a.Position + 1) % 9
}

// CycleMI advances a 9-byte P25 Message Indicator one superframe via the
// 64-bit LFSR with primitive polynomial x^64+x^62+x^46+x^38+x^27+x^15+1
// (TIA-102.AAAD; matches op25_crypt_algs::cycle_p25_mi). Only MI[0..7] are
// stepped; MI[8] is always written as zero. Used as a fallback when an
// LDU2's ES fails RS decode and the next-superframe MI must be inferred.
func CycleMI(mi [9]uint8) [9]uint8 {
	var l uint64
	for i := 0; i < 8; i++ {
		l = (l << 8) | uint64(mi[i])
	}
	for i := 0; i < 64; i++ {
		fb := ((l >> 63) ^ (l >> 61) ^ (l >> 45) ^ (l >> 37) ^ (l >> 26) ^ (l >> 14)) & 1
		l = (l << 1) | fb
	}
	var out [9]uint8
	for i := 7; i >= 0; i-- {
		out[i] = uint8(l)
		l >>= 8
	}
	return out
}

// XORCodewordP2 applies the ADP keystream to one 7-byte packed AMBE+2
// codeword in-place for Phase 2 (TDMA). After XOR, byte 6 is masked to
// preserve only the MSB (the 49th parameter bit).
//
// The keystream offset is determined by the burst's position within the
// superframe voice cycle (burstID) and the codeword index within the burst
// (cwIndex):
//
//	burstID 0-3 → four consecutive 4V bursts (4 codewords each)
//	burstID 4   → the 2V burst (2 codewords)
//	cwIndex 0-3 → codeword position within the burst
//
// Offset formula: 256 + 7 * (cwIndex + burstID * 4)
//
// Source: op25_crypt_adp.cc lines 106-146 (FT_4V_0..3, FT_2V cases).
func (a *ADP) XORCodewordP2(packed *[7]byte, burstID int, cwIndex int) {
	offset := 256 + 7*(cwIndex+burstID*4)
	for i := 0; i < 7; i++ {
		packed[i] ^= a.Keystream[offset+i]
	}
	packed[6] &= 0x80
}
