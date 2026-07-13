package p25

import "testing"

func TestSoftDemapSymbol_HardConsistency(t *testing.T) {
	// At the exact ideal levels the cheaper cost must select the same bits the
	// hard slicer would: +3->dibit1(01), +1->dibit0(00), -1->dibit2(10), -3->dibit3(11).
	cases := []struct {
		x      float64
		b1, b0 uint8 // expected hard bits (sign, outer)
	}{
		{+3, 0, 1},
		{+1, 0, 0},
		{-1, 1, 0},
		{-3, 1, 1},
	}
	for _, c := range cases {
		hi, lo := softDemapSymbol(c.x)
		if got := hi.hardBit(); got != c.b1 {
			t.Errorf("x=%v b1: got %d want %d", c.x, got, c.b1)
		}
		if got := lo.hardBit(); got != c.b0 {
			t.Errorf("x=%v b0: got %d want %d", c.x, got, c.b0)
		}
	}
}

func TestSoftDemapSymbol_CostsNonNegativeAndOrdered(t *testing.T) {
	// A value pulled toward +3 must make b0=1 (outer) cheaper than b0=0.
	_, lo := softDemapSymbol(2.7)
	if lo.Cost1 >= lo.Cost0 {
		t.Errorf("x=2.7 outer bit: Cost1=%v should be < Cost0=%v", lo.Cost1, lo.Cost0)
	}
	hi, _ := softDemapSymbol(2.7)
	if hi.Cost0 >= hi.Cost1 {
		t.Errorf("x=2.7 sign bit: Cost0=%v should be < Cost1=%v", hi.Cost0, hi.Cost1)
	}
}
