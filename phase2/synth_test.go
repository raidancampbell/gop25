package phase2

import (
	"math"
	"math/cmplx"
	"testing"

	"github.com/raidancampbell/gop25"
)

// synthDQPSK generates complex IQ samples at sampleRate Hz containing the
// given dibits modulated as π/4 DQPSK at SymbolRate symbols/sec.
//
// Each dibit maps to a phase advance from the previous symbol:
//
//	00 →  +π/4
//	01 → +3π/4
//	11 → -3π/4
//	10 →  -π/4
//
// (Gray-coded so a single phase error costs at most one bit.)
//
// The output is constant-envelope (|sample|=1) with a square pulse shape —
// good enough for unit testing the demod; not bandwidth-limited like real
// P25P2 RRC-filtered transmissions.
func synthDQPSK(sampleRate float64, dibits []p25.Dibit) []complex64 {
	sampPerSym := sampleRate / SymbolRate
	out := make([]complex64, 0, int(float64(len(dibits))*sampPerSym)+1)
	var phase float64
	advance := [4]float64{
		math.Pi / 4,      // 00
		3 * math.Pi / 4,  // 01
		-math.Pi / 4,     // 10
		-3 * math.Pi / 4, // 11
	}
	var carry float64
	for _, d := range dibits {
		phase += advance[d]
		s := complex64(cmplx.Rect(1, phase))
		// Emit floor(sampPerSym + carry) samples; track fractional carry
		// so the long-run average matches sampPerSym exactly.
		carry += sampPerSym
		n := int(carry)
		carry -= float64(n)
		for i := 0; i < n; i++ {
			out = append(out, s)
		}
	}
	return out
}

func TestSynthDQPSK_SampleCount(t *testing.T) {
	dibits := make([]p25.Dibit, 1000)
	iq := synthDQPSK(25000, dibits)
	// 1000 symbols at 25000/6000 ≈ 4.1667 samp/sym ≈ 4167 samples
	if len(iq) < 4160 || len(iq) > 4170 {
		t.Fatalf("expected ~4167 samples, got %d", len(iq))
	}
}

func TestSynthDQPSK_PhaseAdvances(t *testing.T) {
	// Each dibit advances phase by ±π/4 or ±3π/4. Verify by inspecting
	// the differential phase at symbol boundaries.
	iq := synthDQPSK(60000, []p25.Dibit{0, 1, 3, 2}) // sampPerSym=10
	if len(iq) < 40 {
		t.Fatalf("too few samples: %d", len(iq))
	}
	// Symbol-boundary samples are at indices 0, 10, 20, 30.
	// Phase advances for dibits [0, 1, 3, 2] are [π/4, 3π/4, -3π/4, -π/4]
	want := []float64{math.Pi / 4, 3 * math.Pi / 4, -3 * math.Pi / 4, -math.Pi / 4}
	prev := complex128(1)
	for i, target := range want {
		s := complex128(iq[i*10])
		diff := cmplx.Phase(s / prev)
		// Wrap into [-π, π]
		for diff > math.Pi {
			diff -= 2 * math.Pi
		}
		for diff < -math.Pi {
			diff += 2 * math.Pi
		}
		if math.Abs(diff-target) > 1e-3 && math.Abs(math.Abs(diff)-math.Abs(target)) > 1e-3 {
			t.Errorf("dibit %d: phase diff %v want %v", i, diff, target)
		}
		prev = s
	}
}
