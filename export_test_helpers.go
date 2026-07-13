package p25

// This file exports a handful of low-level P25 FEC primitives that are
// otherwise unexported, for use by cross-package tests and the diagnostic
// command-line tools. They are stable, side-effect-free helpers.

// DecodeNID decodes a 64-bit P25 NID codeword, returning the NID and whether
// the BCH check passed.
func DecodeNID(received uint64) (NID, bool) { return decodeNID(received) }

// BCHEncode returns the P25 NID BCH(63,16) codeword for the given NAC and DUID.
func BCHEncode(nac uint16, duid uint8) uint64 {
	return bchEncode((nac << 4) | uint16(duid))
}

// BCHGenPoly returns the generator polynomial used by the P25 NID BCH code.
func BCHGenPoly() uint64 { return genPoly }

// ViterbiDecodeTSBK runs the on-air TSBK Viterbi decode: 196 received bits to
// 96 data bits, returning the data and whether the CRC passed.
func ViterbiDecodeTSBK(received []uint8) ([]uint8, bool) { return viterbiDecode(received) }

// CRCCheck16 computes the CRC-CCITT-16 residue over the first 96 bits and the
// stored CRC from bits 80..96, for TSBK CRC verification.
func CRCCheck16(bits []uint8) (residue, stored uint16) {
	residue = crcCCITT16(bitsToBytes(bits[:96]))
	stored = uint16(bitsToUint32(bits[80:88]))<<8 | uint16(bitsToUint32(bits[88:96]))
	return
}
