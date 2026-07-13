package mbe

import "testing"

func TestInitParmsMatchesMbelibDefaults(t *testing.T) {
	var cur, prev, enh Parms
	InitParms(&cur, &prev, &enh)

	if prev.W0 != 0.09378 {
		t.Fatalf("prev.W0 = %v, want 0.09378", prev.W0)
	}
	if prev.L != 30 || prev.K != 10 {
		t.Fatalf("prev L/K = %d/%d, want 30/10", prev.L, prev.K)
	}
	if prev.PSIl[1] == 0 {
		t.Fatal("prev.PSIl[1] = 0, want pi/2 initialization")
	}
	if cur != prev {
		t.Fatal("cur does not match prev after InitParms")
	}
	if enh != prev {
		t.Fatal("enhanced prev does not match prev after InitParms")
	}
}

// TestLog2MlHasInterpolationGuardSlot pins the one-past-end slot that the
// parameter-decode interpolation (Log2Ml[intkl[l]+1]) reaches when
// prev.L==cur.L==56 -> index 57. mbelib's C struct lets that read fall into the
// zeroed PHIl[0]; Go must carry an explicit always-zero slot instead, or it
// bounds-panics on live max-pitch frames. If anyone narrows Log2Ml back to
// [57], this fails loudly.
func TestLog2MlHasInterpolationGuardSlot(t *testing.T) {
	var p Parms
	if n := len(p.Log2Ml); n < 58 {
		t.Fatalf("len(Log2Ml) = %d, want >= 58 (index 57 is read when prev.L==cur.L==56)", n)
	}
	if p.Log2Ml[57] != 0 {
		t.Fatalf("Log2Ml[57] = %v, want 0 (guard slot must stay zero to match mbelib)", p.Log2Ml[57])
	}
}

func TestPitchAndVoicedHelpers(t *testing.T) {
	p := Parms{W0: 0.1, L: 5}
	p.Vl[1], p.Vl[2], p.Vl[3] = 1, 1, 1
	if !p.IsVoiced() {
		t.Fatal("IsVoiced() = false, want true")
	}
	if got := p.PitchPeriod(); got <= 0 {
		t.Fatalf("PitchPeriod() = %d, want positive", got)
	}
}
