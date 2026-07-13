package p25

import "math"

// designC4FMRx generates the P25 C4FM receive (de-emphasis) matched filter,
// ported from op25 (op25_c4fm_mod.transfer_function_rx + c4fm_taps.generate).
//   - symbolRate: symbol rate in symbols/second (4800 for P25 C4FM)
//   - sampleRate: sample rate of the FM-discriminator signal in Hz
//   - numTaps: number of taps (forced odd for a symmetric type-I FIR)
//
// The receive transfer function is D(f) = sinc(pi·f/symbolRate) for
// 0 ≤ f < symbolRate and 0 above. Cascaded with the C4FM transmit shaping
// (a raised-cosine H(f) times the sample-and-hold 1/sinc pre-emphasis P(f))
// it forms a Nyquist, zero-ISI overall response — i.e. this is the filter
// matched to the C4FM symbol pulse in the discriminator domain, unlike a
// generic brick-wall low-pass. The impulse response is the inverse transform
// of D(f) sampled on a 1 Hz grid (matching op25's irfft), truncated to numTaps
// around the (central) peak and normalized to unit DC gain.
func designC4FMRx(symbolRate, sampleRate float64, numTaps int) []float32 {
	if numTaps%2 == 0 {
		numTaps++
	}
	half := (numTaps - 1) / 2
	fsym := int(symbolRate)
	taps := make([]float32, numTaps)

	// D(f) = sinc(π f / symbolRate) depends only on f, not the tap index, so
	// evaluate the band-limited transfer function once (fsym sines) rather than
	// recomputing it inside every tap's inverse-DFT sum.
	d := make([]float64, fsym)
	for f := 1; f < fsym; f++ {
		t := math.Pi * float64(f) / symbolRate
		d[f] = math.Sin(t) / t
	}

	// h[n] = D(0) + 2·Σ_{f=1}^{fsym-1} D(f)·cos(2π f n / Fs), the real even
	// inverse DFT of the transfer function (D(0)=1). h[n] is even in n, so only
	// the n≥0 half is computed and mirrored. For a fixed n the cos(2π f n/Fs)
	// run over f is the real part of a unit phasor stepped by e^{iθ} (θ=2π n/Fs):
	// one complex multiply per term replaces a math.Cos call, collapsing the
	// inner loop's transcendental cost to a single sin/cos seed per tap.
	var sum float64
	for n := 0; n <= half; n++ {
		acc := 1.0
		if n == 0 {
			for f := 1; f < fsym; f++ {
				acc += 2.0 * d[f]
			}
		} else {
			theta := 2.0 * math.Pi * float64(n) / sampleRate
			wr, wi := math.Cos(theta), math.Sin(theta)
			cr, ci := wr, wi // phasor at f=1
			for f := 1; f < fsym; f++ {
				acc += 2.0 * d[f] * cr
				cr, ci = cr*wr-ci*wi, cr*wi+ci*wr
			}
		}
		v := float32(acc)
		taps[half+n] = v
		taps[half-n] = v
		if n == 0 {
			sum += acc
		} else {
			sum += 2.0 * acc // acc lands in both taps[half±n]
		}
	}

	// Normalize to unit DC gain (op25: gain = filter_gain / sum(coeffs)).
	g := float32(1.0 / sum)
	for i := range taps {
		taps[i] *= g
	}
	return taps
}
