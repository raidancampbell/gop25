package p25

import "math/bits"

// P25 Phase-1 3/4-rate trellis-coded modulation (TIA-102.BAAA), used by
// Confirmed Packet Data blocks. Unlike the 1/2-rate dibit trellis (trellis.go),
// the 3/4-rate code takes tribits (3 bits) as input and has 8 states (the state
// IS the previous input tribit). 48 data tribits + 1 zero flush tribit produce
// 49 four-bit constellation symbols = 196 encoded bits. The 196 bits are then
// block-interleaved (the same rate-independent interleaver as the 1/2-rate
// path, tsbkInterleave/tsbkDeinterleave) before transmission.
//
// The transition matrix is taken verbatim from sdrtrunk's P25_3_4_Node
// (io.github.dsheirer.edac.trellis.P25_3_4_Node.TRANSITION_MATRIX), which the
// sdrtrunk author notes is "converted from the ICD state transition table where
// the table symbol is converted to the transmitted bit value" -- i.e. it is
// already in transmitted-symbol form, so received 4-bit symbols compare to it
// directly via Hamming distance.

const (
	trellis34Tribits = 49  // 48 data + 1 flush
	trellis34States  = 8   // tribit input/state values 0..7
	trellis34Out     = 196 // 49 * 4
	trellis34DataLen = 144 // 48 tribits * 3
)

// trellis34Transition[prevInput][curInput] = expected 4-bit transmitted symbol.
var trellis34Transition = [trellis34States][trellis34States]uint8{
	{2, 13, 14, 1, 7, 8, 11, 4},
	{14, 1, 7, 8, 11, 4, 2, 13},
	{10, 5, 6, 9, 15, 0, 3, 12},
	{6, 9, 15, 0, 3, 12, 10, 5},
	{15, 0, 3, 12, 10, 5, 6, 9},
	{3, 12, 10, 5, 6, 9, 15, 0},
	{7, 8, 11, 4, 2, 13, 14, 1},
	{11, 4, 2, 13, 14, 1, 7, 8},
}

// trellis34DibitEncode encodes 144 data bits (48 tribits, MSB-first within each
// tribit) to 196 trellis bits (not interleaved). The encoder starts in state 0
// and appends a zero flush tribit as the final (49th) symbol.
func trellis34DibitEncode(data [trellis34DataLen]uint8) (out [trellis34Out]uint8) {
	prev := uint8(0)
	for t := 0; t < trellis34Tribits; t++ {
		var cur uint8
		if t < 48 {
			cur = data[t*3]<<2 | data[t*3+1]<<1 | data[t*3+2]
		} // else flush: cur = 0
		cw := trellis34Transition[prev][cur]
		out[t*4+0] = (cw >> 3) & 1
		out[t*4+1] = (cw >> 2) & 1
		out[t*4+2] = (cw >> 1) & 1
		out[t*4+3] = cw & 1
		prev = cur
	}
	return out
}

// trellis34DibitDecode runs an 8-state hard-decision Viterbi over 196
// (deinterleaved) trellis bits and returns the 144 decoded data bits. The path
// is constrained to start in state 0 and to flush to state 0 on the final
// (49th) symbol, matching sdrtrunk's ViterbiDecoder start/flush nodes.
func trellis34DibitDecode(in [trellis34Out]uint8) (data [trellis34DataLen]uint8) {
	const inf = 1 << 20
	var pm [trellis34States]int
	for s := 1; s < trellis34States; s++ {
		pm[s] = inf
	}
	// back[t][ns] = predecessor state for arriving at state ns after data
	// transition t (t = 0..47).
	var back [48][trellis34States]uint8

	for t := 0; t < 48; t++ {
		rx := in[t*4]<<3 | in[t*4+1]<<2 | in[t*4+2]<<1 | in[t*4+3]
		var npm [trellis34States]int
		for i := range npm {
			npm[i] = inf
		}
		for s := 0; s < trellis34States; s++ {
			if pm[s] == inf {
				continue
			}
			for ns := 0; ns < trellis34States; ns++ {
				bm := bits.OnesCount8(rx ^ trellis34Transition[s][ns])
				if c := pm[s] + bm; c < npm[ns] {
					npm[ns] = c
					back[t][ns] = uint8(s)
				}
			}
		}
		pm = npm
	}

	// Flush transition (symbol 48): the final input is forced to 0, so select
	// the surviving stage-48 state with the least total error after the flush.
	rxf := in[48*4]<<3 | in[48*4+1]<<2 | in[48*4+2]<<1 | in[48*4+3]
	best, bestCost := 0, inf
	for s := 0; s < trellis34States; s++ {
		if pm[s] == inf {
			continue
		}
		c := pm[s] + bits.OnesCount8(rxf^trellis34Transition[s][0])
		if c < bestCost {
			bestCost = c
			best = s
		}
	}

	// Backtrack: state at stage t+1 is data tribit t.
	s := best
	for t := 47; t >= 0; t-- {
		data[t*3+0] = (uint8(s) >> 2) & 1
		data[t*3+1] = (uint8(s) >> 1) & 1
		data[t*3+2] = uint8(s) & 1
		s = int(back[t][s])
	}
	return data
}

// trellis34Encode encodes 144 data bits, then block-interleaves to 196 on-air
// bits. Used by synthesis tests (the inverse of viterbi34DecodeRaw).
func trellis34Encode(data []uint8) []uint8 {
	if len(data) < trellis34DataLen {
		return nil
	}
	var d [trellis34DataLen]uint8
	copy(d[:], data[:trellis34DataLen])
	il := tsbkInterleave(trellis34DibitEncode(d))
	out := make([]uint8, trellis34Out)
	copy(out, il[:])
	return out
}

// viterbi34DecodeRaw decodes one 196-bit on-air confirmed-data block:
// deinterleave (same interleaver as the 1/2-rate path) then 3/4-rate Viterbi,
// returning the 144 decoded data bits (DBSN + CRC-9 + 16-octet payload).
func viterbi34DecodeRaw(received []uint8) []uint8 {
	if len(received) < trellis34Out {
		return nil
	}
	var r [trellis34Out]uint8
	copy(r[:], received[:trellis34Out])
	d := trellis34DibitDecode(tsbkDeinterleave(r))
	out := make([]uint8, trellis34DataLen)
	copy(out, d[:])
	return out
}

// deinterleaveSoft applies the bit-level block interleaver to a 196-element
// soft array, mirroring tsbkDeinterleave for hard bits: out[i] is the SoftBit
// from interleaved position tsbkDeinterleaveTab[i].
func deinterleaveSoft(in [trellis34Out]SoftBit) (out [trellis34Out]SoftBit) {
	for i := range out {
		out[i] = in[tsbkDeinterleaveTab[i]]
	}
	return out
}

// branchCost34 returns the summed per-bit cost of the 4-bit expected codeword
// cw against the four SoftBits at soft[base:base+4] (deinterleaved order, MSB
// first). This is the soft analogue of bits.OnesCount8(rx ^ cw).
func branchCost34(soft *[trellis34Out]SoftBit, base int, cw uint8) float32 {
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

// trellis34SoftDecode runs the 8-state 3/4-rate Viterbi using soft per-bit
// costs instead of Hamming distance. Same start-in-0 / flush-to-0 constraints
// as the hard trellis34DibitDecode. Input is 196 deinterleaved SoftBits.
func trellis34SoftDecode(in [trellis34Out]SoftBit) (data [trellis34DataLen]uint8) {
	const inf = float32(1e18)
	var pm [trellis34States]float32
	for s := 1; s < trellis34States; s++ {
		pm[s] = inf
	}
	var back [48][trellis34States]uint8

	for t := 0; t < 48; t++ {
		var npm [trellis34States]float32
		for i := range npm {
			npm[i] = inf
		}
		for s := 0; s < trellis34States; s++ {
			if pm[s] >= inf {
				continue
			}
			for ns := 0; ns < trellis34States; ns++ {
				bm := branchCost34(&in, t*4, trellis34Transition[s][ns])
				if c := pm[s] + bm; c < npm[ns] {
					npm[ns] = c
					back[t][ns] = uint8(s)
				}
			}
		}
		pm = npm
	}

	// Flush transition (symbol 48): final input forced to 0.
	best, bestCost := 0, inf
	for s := 0; s < trellis34States; s++ {
		if pm[s] >= inf {
			continue
		}
		if c := pm[s] + branchCost34(&in, 48*4, trellis34Transition[s][0]); c < bestCost {
			bestCost, best = c, s
		}
	}

	s := best
	for t := 47; t >= 0; t-- {
		data[t*3+0] = (uint8(s) >> 2) & 1
		data[t*3+1] = (uint8(s) >> 1) & 1
		data[t*3+2] = uint8(s) & 1
		s = int(back[t][s])
	}
	return data
}

// viterbi34SoftDecodeRaw is the soft analogue of viterbi34DecodeRaw: it takes
// 196 on-air (pre-deinterleave) SoftBits, deinterleaves them, and runs the soft
// 3/4-rate Viterbi, returning the 144 decoded data bits.
func viterbi34SoftDecodeRaw(soft []SoftBit) []uint8 {
	if len(soft) < trellis34Out {
		return nil
	}
	var r [trellis34Out]SoftBit
	copy(r[:], soft[:trellis34Out])
	d := trellis34SoftDecode(deinterleaveSoft(r))
	out := make([]uint8, trellis34DataLen)
	copy(out, d[:])
	return out
}
