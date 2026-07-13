package p25

// Diagnostic-only exports for external decode-inspection tooling. Not
// test-gated because those diagnostic binaries link against the package, not
// the test scope.

// DiagViterbiDecodeTSBK is the on-air TSBK decoder: 196 received bits ->
// deinterleave -> dibit Viterbi -> 96 data bits + CRC pass/fail.
func DiagViterbiDecodeTSBK(received []uint8) ([]uint8, bool) {
	return viterbiDecode(received)
}

// DiagTrellisDibitDecode runs Viterbi only (no deinterleave) and returns
// the 96 data bits, the path metric of the chosen end state, and CRC ok.
func DiagTrellisDibitDecode(received []uint8) (data []uint8, pathMetric int, crcOK bool) {
	if len(received) < trellisOut {
		return nil, 0, false
	}
	var r [196]uint8
	copy(r[:], received[:trellisOut])
	d, ok := trellisDibitDecode(r)
	out := make([]uint8, 96)
	copy(out, d[:])
	// Re-encode to compute path metric (Hamming distance from received).
	enc := trellisDibitEncode(d)
	pm := 0
	for i := range enc {
		if (enc[i] ^ r[i]) & 1 == 1 {
			pm++
		}
	}
	return out, pm, ok
}

// DiagTSBKDeinterleave undoes the on-air block interleave.
func DiagTSBKDeinterleave(in []uint8) []uint8 {
	if len(in) < trellisOut {
		return nil
	}
	var r [196]uint8
	copy(r[:], in[:trellisOut])
	out := tsbkDeinterleave(r)
	res := make([]uint8, 196)
	copy(res, out[:])
	return res
}

// DiagCRCCCITT16 computes the TSBK CRC over packed bytes.
func DiagCRCCCITT16(b []byte) uint16 { return crcCCITT16(b) }
