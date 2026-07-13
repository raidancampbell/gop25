package phase2

import (
	"math/bits"

	"github.com/raidancampbell/gop25"
)

// DecodeISCH decodes a 20-dibit (40-bit) ISCH codeword to ISCHInfo.
// First tries an exact lookup; on miss, finds the nearest codeword by
// Hamming distance and accepts if ≤7 bits (the code's correction limit).
func DecodeISCH(dibits [SyncDibits]p25.Dibit) ISCHInfo {
	var cw uint64
	for _, d := range dibits {
		cw = (cw << 2) | uint64(d&3)
	}
	cw &= SyncMask

	// Exact match?
	if v, ok := ischCodewords[cw]; ok {
		return makeInfo(v)
	}

	// Nearest-neighbour search.
	bestDist := 8 // strict: must be ≤7
	var bestVal int16 = -1
	for valid, v := range ischCodewords {
		d := bits.OnesCount64(cw ^ valid)
		if d < bestDist {
			bestDist = d
			bestVal = v
		}
	}
	if bestDist >= 8 {
		return ISCHInfo{Location: -1, Slot: -1}
	}
	return makeInfo(bestVal)
}

func makeInfo(v int16) ISCHInfo {
	if v == -2 {
		return ISCHInfo{Location: -1, Slot: -1, IsSISCH: true, Valid: true}
	}
	// Normal I-ISCH: the 7-bit message field decomposes into sub-fields
	// (op25 p25p2_sync.cc::check_confidence):
	//   cnt = v & 3      (bits 0-1)
	//   fr  = (v>>2) & 1 (bit 2)
	//   loc = (v>>3) & 3 (bits 3-4)
	//   chn = (v>>5) & 3 (bits 5-6)
	// and the burst position within the superframe is loc*4 + chn. This is
	// NOT v % SuperframeBursts — that formula disagrees for 120 of the 128
	// possible messages and breaks the decoder.go confirmation gate.
	//
	// Per op25's expected_sync table {0,1,-2,-2,4,5,-2,-2,8,9,-2,-2}, valid
	// I-ISCH positions are only {0,1,4,5,8,9}; the -2 slots carry S-ISCH.
	// A position of 2,3,6,7 or >=SuperframeBursts therefore cannot come from
	// a real I-ISCH and is treated as a decode failure.
	loc := (int(v) >> 3) & 3
	chn := (int(v) >> 5) & 3
	pos := loc*4 + chn
	if pos >= SuperframeBursts {
		return ISCHInfo{Location: -1, Slot: -1}
	}
	return ISCHInfo{
		Location: pos,
		Slot:     WhichSlot[pos],
		Valid:    true,
	}
}
