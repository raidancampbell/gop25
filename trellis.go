package p25

import "math/bits"

// P25 Phase-1 1/2-rate dibit trellis (TIA-102.BAAA-A). 96 data bits are
// taken as 48 dibits + 1 zero flush dibit. Each step emits a 4-bit
// constellation point next_words[curState][nextState]; the decoded dibit
// IS the next state. 49 dibits in -> 49*4 = 196 encoded bits.
// The 196 bits are then block-interleaved before transmission.
//
// Tables are taken verbatim from op25
// (reference/op25/op25/gr-op25_repeater/lib/p25p1_fdma.cc:124-180).

const (
	trellisDibits = 49  // 48 data + 1 flush
	trellisOut    = 196 // 49 * 4
)

// next_words[curState][nextState] = 4-bit constellation point.
var trellisNext = [4][4]uint8{
	{0x2, 0xC, 0x1, 0xF},
	{0xE, 0x0, 0xD, 0x3},
	{0x9, 0x7, 0xA, 0x4},
	{0x5, 0xB, 0x6, 0x8},
}

// op25 deinterleave_tb. tsbkDeinterleaveTab[i] is the *interleaved* bit
// position whose value belongs at *deinterleaved* position i.
var tsbkDeinterleaveTab = [196]uint8{
	0, 1, 2, 3, 52, 53, 54, 55, 100, 101, 102, 103, 148, 149, 150, 151,
	4, 5, 6, 7, 56, 57, 58, 59, 104, 105, 106, 107, 152, 153, 154, 155,
	8, 9, 10, 11, 60, 61, 62, 63, 108, 109, 110, 111, 156, 157, 158, 159,
	12, 13, 14, 15, 64, 65, 66, 67, 112, 113, 114, 115, 160, 161, 162, 163,
	16, 17, 18, 19, 68, 69, 70, 71, 116, 117, 118, 119, 164, 165, 166, 167,
	20, 21, 22, 23, 72, 73, 74, 75, 120, 121, 122, 123, 168, 169, 170, 171,
	24, 25, 26, 27, 76, 77, 78, 79, 124, 125, 126, 127, 172, 173, 174, 175,
	28, 29, 30, 31, 80, 81, 82, 83, 128, 129, 130, 131, 176, 177, 178, 179,
	32, 33, 34, 35, 84, 85, 86, 87, 132, 133, 134, 135, 180, 181, 182, 183,
	36, 37, 38, 39, 88, 89, 90, 91, 136, 137, 138, 139, 184, 185, 186, 187,
	40, 41, 42, 43, 92, 93, 94, 95, 140, 141, 142, 143, 188, 189, 190, 191,
	44, 45, 46, 47, 96, 97, 98, 99, 144, 145, 146, 147, 192, 193, 194, 195,
	48, 49, 50, 51,
}

func tsbkDeinterleave(in [196]uint8) (out [196]uint8) {
	for i := range out {
		out[i] = in[tsbkDeinterleaveTab[i]] & 1
	}
	return out
}

func tsbkInterleave(in [196]uint8) (out [196]uint8) {
	for i := range in {
		out[tsbkDeinterleaveTab[i]] = in[i] & 1
	}
	return out
}

// trellisDibitEncode encodes 96 data bits to 196 trellis bits (not interleaved).
func trellisDibitEncode(data [96]uint8) (out [196]uint8) {
	state := uint8(0)
	for d := 0; d < trellisDibits; d++ {
		var ns uint8
		if d < 48 {
			ns = (data[d*2]&1)<<1 | (data[d*2+1] & 1)
		}
		cw := trellisNext[state][ns]
		out[d*4+0] = (cw >> 3) & 1
		out[d*4+1] = (cw >> 2) & 1
		out[d*4+2] = (cw >> 1) & 1
		out[d*4+3] = cw & 1
		state = ns
	}
	return out
}

// trellisDibitDecode runs hard-decision Viterbi over 196 trellis bits and
// returns 96 data bits + CRC-CCITT-16 pass/fail. The terminal state is
// constrained to 0 to match the encoder's appended zero flush dibit (matching
// sdrtrunk's ViterbiDecoder_1_2_P25 createFlushingNode); admitting any other
// terminal state would follow a path the encoder could not have produced and
// measurably reduces correction headroom on real signals.
func trellisDibitDecode(in [196]uint8) (data [96]uint8, ok bool) {
	const inf = 1 << 20
	pm := [4]int{0, inf, inf, inf}
	var path [trellisDibits][4]uint8 // path[t][ns] = prev state

	for t := 0; t < trellisDibits; t++ {
		rx := (in[t*4]&1)<<3 | (in[t*4+1]&1)<<2 | (in[t*4+2]&1)<<1 | (in[t*4+3] & 1)
		npm := [4]int{inf, inf, inf, inf}
		for s := 0; s < 4; s++ {
			if pm[s] == inf {
				continue
			}
			for ns := uint8(0); ns < 4; ns++ {
				bm := bits.OnesCount8(rx ^ trellisNext[s][ns])
				c := pm[s] + bm
				if c < npm[ns] {
					npm[ns] = c
					path[t][ns] = uint8(s)
				}
			}
		}
		pm = npm
	}

	// Terminal state is forced to 0 (zero flush dibit). pm[0]==inf only when
	// every path through the trellis was pruned, which can't happen given the
	// initial (state 0, pm=0) and full 4-way fan-out at every stage.
	dibits := [trellisDibits]uint8{}
	s := 0
	for t := trellisDibits - 1; t >= 0; t-- {
		dibits[t] = uint8(s)
		s = int(path[t][s])
	}
	for d := 0; d < 48; d++ {
		data[d*2] = (dibits[d] >> 1) & 1
		data[d*2+1] = dibits[d] & 1
	}

	return data, crcCCITT16(bitsToBytes(data[:])) == 0
}

// trellisEncode is the on-air encoder used by tests / parseTSBKs round-trips:
// 96 data bits -> dibit-trellis -> interleave -> 196 bits.
func trellisEncode(data []uint8) []uint8 {
	if len(data) < 96 {
		return nil
	}
	var d96 [96]uint8
	copy(d96[:], data[:96])
	il := tsbkInterleave(trellisDibitEncode(d96))
	out := make([]uint8, trellisOut)
	copy(out, il[:])
	return out
}

// viterbiDecode is the on-air decoder used by parseTSBKs:
// 196 received bits -> deinterleave -> dibit Viterbi -> 96 bits + CRC.
// It discards the bits on CRC failure; callers that need the bits regardless
// (PDU blocks) should use viterbiDecodeRaw.
func viterbiDecode(received []uint8) ([]uint8, bool) {
	data, ok := viterbiDecodeRaw(received)
	if !ok {
		return nil, false
	}
	return data, true
}

// viterbiDecodeRaw decodes one 196-bit trellis block to 96 data bits and
// reports whether the embedded CRC-CCITT-16 passes, returning the decoded bits
// regardless of the CRC outcome. Used for PDU data blocks, where the caller
// needs the bits even though they carry no per-block CRC, and for the PDU
// header block, whose CRC-16 the caller checks explicitly.
func viterbiDecodeRaw(received []uint8) (data []uint8, crcOK bool) {
	if len(received) < trellisOut {
		return nil, false
	}
	var r [196]uint8
	copy(r[:], received[:trellisOut])
	d, ok := trellisDibitDecode(tsbkDeinterleave(r))
	out := make([]uint8, 96)
	copy(out, d[:])
	return out, ok
}

// _ enforces that the 1/2- and 3/4-rate blocks share the 196-bit interleaver
// size, so deinterleaveSoft (defined in trellis34.go on a [trellis34Out]SoftBit
// array) is usable from the 1/2-rate path.
const _ = trellisOut - trellis34Out // must be 0

// branchCost is the 1/2-rate analogue of branchCost34: summed per-bit cost of
// the 4-bit expected codeword cw against soft[base:base+4] (deinterleaved order,
// MSB first).
func branchCost(soft *[trellisOut]SoftBit, base int, cw uint8) float32 {
	var c float32
	for j := 0; j < 4; j++ {
		sb := soft[base+j]
		if (cw>>(3-j))&1 == 0 {
			c += sb.Cost0
		} else {
			c += sb.Cost1
		}
	}
	return c
}

// trellisSoftDecode runs the 4-state 1/2-rate Viterbi with soft per-bit costs.
// Terminal state forced to 0 (zero flush dibit), matching trellisDibitDecode.
func trellisSoftDecode(in [trellisOut]SoftBit) (data [96]uint8, ok bool) {
	const inf = float32(1e18)
	pm := [4]float32{0, inf, inf, inf}
	var path [trellisDibits][4]uint8

	for t := 0; t < trellisDibits; t++ {
		npm := [4]float32{inf, inf, inf, inf}
		for s := 0; s < 4; s++ {
			if pm[s] >= inf {
				continue
			}
			for ns := uint8(0); ns < 4; ns++ {
				bm := branchCost(&in, t*4, trellisNext[s][ns])
				if c := pm[s] + bm; c < npm[ns] {
					npm[ns] = c
					path[t][ns] = uint8(s)
				}
			}
		}
		pm = npm
	}

	// Terminal state forced to 0 (zero flush dibit).
	dibits := [trellisDibits]uint8{}
	s := 0
	for t := trellisDibits - 1; t >= 0; t-- {
		dibits[t] = uint8(s)
		s = int(path[t][s])
	}
	for d := 0; d < 48; d++ {
		data[d*2] = (dibits[d] >> 1) & 1
		data[d*2+1] = dibits[d] & 1
	}
	return data, crcCCITT16(bitsToBytes(data[:])) == 0
}

// viterbiSoftDecodeRaw is the soft analogue of viterbiDecodeRaw: 196 on-air
// (pre-deinterleave) SoftBits -> deinterleave -> soft 1/2-rate Viterbi -> 96
// data bits + CRC pass/fail flag. deinterleaveSoft is shared from trellis34.go
// (the cross-file size assertion above guarantees the array length matches).
func viterbiSoftDecodeRaw(soft []SoftBit) (data []uint8, crcOK bool) {
	if len(soft) < trellisOut {
		return nil, false
	}
	var r [trellisOut]SoftBit
	copy(r[:], soft[:trellisOut])
	d, ok := trellisSoftDecode(deinterleaveSoft(r))
	out := make([]uint8, 96)
	copy(out, d[:])
	return out, ok
}
