package mbe

import "math"

type Parms struct {
	W0 float32
	L  int
	K  int
	Vl [57]int
	Ml [57]float32
	// Log2Ml has one extra slot (index 57): the parameter-decode interpolation
	// reads Log2Ml[intkl[l]+1], which reaches index 57 when prev.L==cur.L==56.
	// In mbelib's C struct log2Ml[57] is immediately followed by PHIl[0] (always
	// 0 after init), so that read silently yields 0; Go would bounds-panic on a
	// [57] array. The extra always-zero slot reproduces the C value exactly.
	Log2Ml [58]float32
	PHIl   [57]float32
	PSIl   [57]float32
	Gamma  float32
	Un     int
	Repeat int
}

func MoveParms(cur, prev *Parms) {
	prev.W0 = cur.W0
	prev.L = cur.L
	prev.K = cur.K
	prev.Ml[0] = 0
	prev.Gamma = cur.Gamma
	prev.Repeat = cur.Repeat
	for l := 1; l <= 56; l++ {
		prev.Ml[l] = cur.Ml[l]
		prev.Vl[l] = cur.Vl[l]
		prev.Log2Ml[l] = cur.Log2Ml[l]
		prev.PHIl[l] = cur.PHIl[l]
		prev.PSIl[l] = cur.PSIl[l]
	}
}

func UseLastParms(cur, prev *Parms) {
	MoveParms(prev, cur)
}

func InitParms(cur, prev, enhanced *Parms) {
	*prev = Parms{}
	prev.W0 = 0.09378
	prev.L = 30
	prev.K = 10
	for l := 1; l <= 56; l++ {
		prev.PSIl[l] = float32(math.Pi / 2)
	}
	MoveParms(prev, cur)
	MoveParms(prev, enhanced)
}

func (p *Parms) PitchPeriod() int {
	w0 := float64(p.W0)
	if w0 <= 0 || w0 > math.Pi {
		return 0
	}
	return int(math.Round(2 * math.Pi / w0))
}

func (p *Parms) IsVoiced() bool {
	if p.L <= 0 {
		return false
	}
	voiced := 0
	for l := 1; l <= p.L; l++ {
		if p.Vl[l] == 1 {
			voiced++
		}
	}
	return voiced > p.L/2
}
