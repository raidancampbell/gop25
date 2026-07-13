package p25

import (
	"math"
	"testing"
)

// designC4FMRxNaive is the pre-optimization reference for designC4FMRx: a direct
// per-tap inverse DFT that recomputes the transfer function inside every tap and
// calls math.Cos for every (tap, frequency) pair — O(numTaps·symbolRate). The
// shipped designC4FMRx precomputes the transfer function, exploits even symmetry,
// and steps a unit phasor instead of calling math.Cos, which is ~22× faster while
// producing bit-identical float32 taps (guarded below).
func designC4FMRxNaive(symbolRate, sampleRate float64, numTaps int) []float32 {
	if numTaps%2 == 0 {
		numTaps++
	}
	half := (numTaps - 1) / 2
	fsym := int(symbolRate)
	taps := make([]float32, numTaps)
	var sum float64
	for i := 0; i < numTaps; i++ {
		n := float64(i - half)
		acc := 1.0
		for f := 1; f < fsym; f++ {
			t := math.Pi * float64(f) / symbolRate
			d := math.Sin(t) / t
			acc += 2.0 * d * math.Cos(2.0*math.Pi*float64(f)*n/sampleRate)
		}
		taps[i] = float32(acc)
		sum += acc
	}
	g := float32(1.0 / sum)
	for i := range taps {
		taps[i] *= g
	}
	return taps
}

// TestDesignC4FMRx_MatchesNaive pins the optimized phasor/symmetry design to the
// naive inverse-DFT reference: the result must be bit-identical, so the speedup
// carries no decoder-EVM risk. Covers the production tap count (81) and the
// neighbours called out as good in frame.go's c4fmRxTaps note.
func TestDesignC4FMRx_MatchesNaive(t *testing.T) {
	for _, numTaps := range []int{61, 81, 101} {
		got := designC4FMRx(4800, 25000, numTaps)
		want := designC4FMRxNaive(4800, 25000, numTaps)
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("taps=%d tap[%d]=%v, naive=%v (must be bit-identical)",
					numTaps, i, got[i], want[i])
			}
		}
	}
}

func BenchmarkDesignC4FMRx(b *testing.B) {
	for i := 0; i < b.N; i++ {
		designC4FMRx(4800, 25000, 81)
	}
}
