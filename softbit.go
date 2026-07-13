package p25

// SoftBit holds the two max-log costs for one received code bit, in normalized
// squared-distance units (C4FM ideal levels +/-1, +/-3): Cost0 is the squared
// distance from the received symbol to the nearest level whose label has this
// bit = 0; Cost1 likewise for bit = 1. Lower cost = more likely. This is the
// soft analogue of a hard 0/1 bit: a clean bit has one cost ~ 0 and the other
// large; a noisy bit has both costs close.
type SoftBit struct {
	Cost0, Cost1 float32
}

// hardBit returns the maximum-likelihood bit (the cheaper cost). Ties resolve
// to 0 -- used only in tests.
func (s SoftBit) hardBit() uint8 {
	if s.Cost1 < s.Cost0 {
		return 1
	}
	return 0
}

// c4fmLevels are the four normalized C4FM symbol levels, indexed so that the
// dibit value (b1<<1)|b0 selects its level: dibit0->+1, dibit1->+3, dibit2->-1,
// dibit3->-3 (mirrors dibitIdealLevel / sliceDibitScaled in symbol.go).
var c4fmLevels = [4]float64{+1, +3, -1, -3}

// softDemapSymbol converts a normalized symbol value x (ideal levels +/-1, +/-3)
// into per-bit costs for the symbol's two label bits b1 (MSB/sign) and b0
// (LSB/outer). Labeling (dibit = (b1<<1)|b0): +3->01, +1->00, -1->10, -3->11.
//   b1=0 <=> level in {+1,+3};  b1=1 <=> {-1,-3}
//   b0=0 <=> level in {+1,-1};  b0=1 <=> {+3,-3}
// Each cost is the min squared distance over the levels matching that bit value
// (max-log approximation), which is exactly what a bit-interleaved Viterbi
// branch metric consumes.
func softDemapSymbol(x float64) (b1, b0 SoftBit) {
	sq := func(v float64) float32 { d := x - v; return float32(d * d) }
	min2 := func(a, b float32) float32 {
		if a < b {
			return a
		}
		return b
	}
	// b1 (sign): 0 -> {+1,+3}, 1 -> {-1,-3}
	b1.Cost0 = min2(sq(+1), sq(+3))
	b1.Cost1 = min2(sq(-1), sq(-3))
	// b0 (outer): 0 -> {+1,-1}, 1 -> {+3,-3}
	b0.Cost0 = min2(sq(+1), sq(-1))
	b0.Cost1 = min2(sq(+3), sq(-3))
	return b1, b0
}
