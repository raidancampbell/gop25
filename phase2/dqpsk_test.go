package phase2

import (
	"math"
	"math/cmplx"
	"testing"

	"github.com/raidancampbell/gop25"
)

func TestDifferentialDecode_Exact(t *testing.T) {
	cases := []struct {
		advance float64
		want    p25.Dibit
	}{
		{+math.Pi / 4, 0},     // 00
		{+3 * math.Pi / 4, 1}, // 01
		{-math.Pi / 4, 2},     // 10
		{-3 * math.Pi / 4, 3}, // 11
	}
	prev := complex64(complex(1, 0))
	for _, c := range cases {
		cur := complex64(cmplx.Rect(1, float64(cmplx.Phase(complex128(prev)))+c.advance))
		got := differentialDecode(cur, prev)
		if got != c.want {
			t.Errorf("advance %v: got %d want %d", c.advance, got, c.want)
		}
	}
}

func TestDifferentialDecode_NoisyButCorrect(t *testing.T) {
	// Each ideal phase advance perturbed by ±π/16; decision should still be right.
	for _, eps := range []float64{-math.Pi / 16, math.Pi / 16} {
		for _, c := range []struct {
			advance float64
			want    p25.Dibit
		}{
			{+math.Pi / 4, 0},
			{+3 * math.Pi / 4, 1},
			{-math.Pi / 4, 2},
			{-3 * math.Pi / 4, 3},
		} {
			prev := complex64(complex(1, 0))
			cur := complex64(cmplx.Rect(1, c.advance+eps))
			if got := differentialDecode(cur, prev); got != c.want {
				t.Errorf("advance %v + %v: got %d want %d", c.advance, eps, got, c.want)
			}
		}
	}
}

func TestHDQPSKDemod_RecoversSynthetic(t *testing.T) {
	// 500 random dibits → synthesize → demod → must recover with ≥99% accuracy.
	src := make([]p25.Dibit, 500)
	for i := range src {
		src[i] = p25.Dibit(i*7+3) % 4 // deterministic spread
	}
	iq := synthDQPSK(25000, src)
	d := NewHDQPSKDemod(25000)
	got := d.Process(iq)
	// Allow up to a couple symbol-period worth of skew at start.
	if len(got) < len(src)-5 || len(got) > len(src)+5 {
		t.Fatalf("got %d dibits, expected ~%d", len(got), len(src))
	}
	// Align by best lag in [-3, 3]; count mismatches.
	bestErr := len(got)
	for lag := -3; lag <= 3; lag++ {
		errs := 0
		for i := 0; i < len(got); i++ {
			j := i + lag
			if j < 0 || j >= len(src) {
				continue
			}
			if got[i] != src[j] {
				errs++
			}
		}
		if errs < bestErr {
			bestErr = errs
		}
	}
	// Allow 5 errors (1%) for startup transient.
	if bestErr > 5 {
		t.Errorf("recovered %d errors out of %d dibits (>1%%)", bestErr, len(got))
	}
}

func TestHDQPSKDemod_RecoversWithCarrierOffset(t *testing.T) {
	// Same as above but with +200 Hz carrier offset added.
	src := make([]p25.Dibit, 1000)
	for i := range src {
		src[i] = p25.Dibit((i*13 + 5) % 4)
	}
	iq := synthDQPSK(25000, src)
	// Rotate by 2π·200·t / 25000 per sample.
	rot := 2 * math.Pi * 200 / 25000
	for i := range iq {
		iq[i] = complex64(complex128(iq[i]) * cmplx.Rect(1, rot*float64(i)))
	}
	d := NewHDQPSKDemod(25000)
	got := d.Process(iq)
	bestErr := len(got)
	for lag := -3; lag <= 3; lag++ {
		errs := 0
		for i := 0; i < len(got); i++ {
			j := i + lag
			if j < 0 || j >= len(src) {
				continue
			}
			if got[i] != src[j] {
				errs++
			}
		}
		if errs < bestErr {
			bestErr = errs
		}
	}
	// 200 Hz at 6 ksps is ≈12° per symbol — well within the loop's pull-in.
	// Allow 3% errors during convergence.
	if bestErr > 30 {
		t.Errorf("with 200 Hz offset: %d errors out of %d (>3%%)", bestErr, len(got))
	}
}
