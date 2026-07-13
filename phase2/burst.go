package phase2

import "github.com/raidancampbell/gop25"

// extractDUID packs the four DUID dibits at absolute burst positions
// (20/57/142/179) into an 8-bit codeword. Pass the RAW (pre-descramble)
// burst: op25 extracts the DUID before applying the XOR mask.
// Source: op25 p25p2_duid.cc::extract_duid.
//
// NOTE: the DUID is unreliable for VOICE classification (see ClassifyByFEC);
// it is only consulted as a fallback for non-voice (control) bursts.
func extractDUID(b Burst) uint8 {
	d0 := uint8(b.Dibits[DUIDPos0] & 0x3)
	d1 := uint8(b.Dibits[DUIDPos1] & 0x3)
	d2 := uint8(b.Dibits[DUIDPos2] & 0x3)
	d3 := uint8(b.Dibits[DUIDPos3] & 0x3)
	return (d0 << 6) | (d1 << 4) | (d2 << 2) | d3
}

// Classify determines a burst's type. Voice detection is FEC-based and
// authoritative (ClassifyByFEC); the DUID is consulted ONLY when FEC rejects
// the burst as non-voice, to label it as a control burst. b.DUID must already
// be set from the RAW burst (see Decoder.processBurst).
func Classify(b Burst) BurstType {
	if t := ClassifyByFEC(b.Dibits); t != BurstUnknown {
		return t
	}
	return classifyDUID(b.DUID)
}

// classifyDUID maps a raw 8-bit DUID codeword to a control BurstType via the
// op25 duid_lookup minimum-distance table. Voice ids (0=4V, 6=2V) and invalid
// codewords return BurstUnknown (voice is handled by ClassifyByFEC).
// Source: op25 p25p2_tdma.cc:754-770 handle_packet dispatch.
//
//	id 3  -> scrambled SACCH    id 12 -> unscrambled SACCH
//	id 9  -> scrambled FACCH    id 15 -> unscrambled FACCH
//	id 13 -> unscrambled LCCH (CRC-16)
func classifyDUID(duid uint8) BurstType {
	switch duidLookup[duid] {
	case 3, 12:
		return BurstSACCH
	case 9, 15:
		return BurstFACCH
	case 13:
		return BurstLCCH
	default:
		return BurstUnknown
	}
}

// ClassifyByFEC classifies a burst by checking Golay FEC quality at the
// voice codeword positions. This is far more reliable than DUID-based
// classification for voice bursts.
//
// Detection uses the SUM of c0 Golay errors across all 4 VCW positions.
// For voice, each VCW typically has c0=0, so sum ≈ 0-4. For random data,
// each c0 averages ~2.5 errors (Golay(23,12) is perfect, always ≤3), so
// sum ≈ 10. The false-positive rate at sum ≤ 4 is negligible (< 10^-6).
//
// 4V vs 2V: compare the c0-error sum of VCW1+2 vs VCW3+4. If VCW3+4
// contribute ≤ 2 errors, it's 4V (4 voice codewords). Otherwise 2V
// (2 voice codewords + control data in VCW3+4 positions).
func ClassifyByFEC(dibits [BurstDibits]p25.Dibit) BurstType {
	vcwOffsets := [4]int{
		PayloadOffset + VCW1Offset,
		PayloadOffset + VCW2Offset,
		PayloadOffset + VCW3Offset,
		PayloadOffset + VCW4Offset,
	}
	var errsPerVCW [4]int
	for i, off := range vcwOffsets {
		if off+VoiceCWDibits > BurstDibits {
			errsPerVCW[i] = 99
			continue
		}
		c0, _, _, _ := extractVCW(dibits[off : off+VoiceCWDibits])
		_, errs, _ := p25.Golay24Decode(c0)
		errsPerVCW[i] = errs
	}

	// Sum of c0 errors across VCW1+VCW2.
	sum12 := errsPerVCW[0] + errsPerVCW[1]
	// Sum of c0 errors across VCW3+VCW4.
	sum34 := errsPerVCW[2] + errsPerVCW[3]
	sumAll := sum12 + sum34

	// Voice detection: total c0 errors across all 4 VCWs must be low.
	if sumAll <= 4 {
		return Burst4V
	}
	// 2V: VCW1+VCW2 carry voice, VCW3+VCW4 carry control data.
	if sum12 <= 2 {
		return Burst2V
	}
	return BurstUnknown
}
