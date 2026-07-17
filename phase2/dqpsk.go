package phase2

import (
	"math"
	"math/cmplx"

	"github.com/raidancampbell/gop25"
)

// HDQPSKDemod converts complex64 IQ at sampleRate Hz into Phase 2 dibits at
// SymbolRate sym/s using:
//   - linear-interpolated symbol-rate strobe
//   - Gardner timing error detector with PI loop filter (complex-sample form)
//   - decision-directed phase rotator (first-order PLL on the differential phase)
//   - Gray-coded pi/4 DQPSK slicer (differentialDecode)
//
// Sample rate must be ≥ 2·SymbolRate. At 25 kSPS the loop runs at 4.167
// samp/sym, which Gardner handles cleanly.
type HDQPSKDemod struct {
	sampleRate float64
	sampPerSym float64

	pos     float64     // fractional sample index of next "on" strobe
	prevOn  complex64   // previous on-symbol sample, post-rotation
	prevMid complex64   // previous mid-symbol sample, post-rotation
	tail    []complex64 // leftover samples carried into next Process call

	// concatBuf and dibitsBuf are reusable scratch for Process, reset to len 0
	// each call and parked (possibly grown) for the next. concatBuf holds
	// tail||in when there is leftover tail; dibitsBuf collects the recovered
	// dibits and is returned to the caller by reslicing. This mirrors the Phase 1
	// symbol.go buffer-reuse pattern, avoiding the per-block heap churn that a
	// fresh make() on every call would reintroduce on the hot TDMA demod path.
	concatBuf []complex64
	dibitsBuf []p25.Dibit

	// PI loop filter (Gardner)
	propGain float64
	intGain  float64
	integ    float64

	// First-order carrier-phase tracker (decision-directed).
	carrierPhase float64
	carrierGain  float64

	// EVM accumulator: tracks RMS phase error from ideal constellation.
	// Normalized by π/4 (the nominal phase advance), so a perfect signal
	// has EVM ≈ 0 and a noisy one approaches 1.0+.
	evmSumSq float64
	evmCount int64
}

// NewHDQPSKDemod returns a demod configured for the given input sample rate.
// Loop gains are tuned for 4–10 samp/sym; the defaults work at 25 kSPS.
func NewHDQPSKDemod(sampleRate float64) *HDQPSKDemod {
	return &HDQPSKDemod{
		sampleRate:  sampleRate,
		sampPerSym:  sampleRate / SymbolRate,
		propGain:    0.05,
		intGain:     0.002,
		carrierGain: 0.02,
	}
}

// Process consumes complex IQ and returns recovered dibits. State carries
// across calls — feed contiguous samples from the upstream source.
//
// The returned slice is backed by an internal buffer reused on the next Process
// call; callers must consume it before calling Process again (framer.Feed does
// so synchronously within Decoder.Process).
func (d *HDQPSKDemod) Process(in []complex64) []p25.Dibit {
	var buf []complex64
	if len(d.tail) > 0 {
		need := len(d.tail) + len(in)
		if cap(d.concatBuf) < need {
			d.concatBuf = make([]complex64, need)
		}
		buf = d.concatBuf[:need]
		copy(buf, d.tail)
		copy(buf[len(d.tail):], in)
	} else {
		buf = in
	}
	n := len(buf)
	out := d.dibitsBuf[:0]

	for {
		onIdx := d.pos + d.sampPerSym
		if int(onIdx)+1 >= n {
			break
		}
		midIdx := d.pos + d.sampPerSym/2

		onSample := lerpC(buf, onIdx)
		midSample := lerpC(buf, midIdx)

		// Apply current carrier phase rotation.
		rot := complex64(cmplx.Rect(1, -d.carrierPhase))
		on := onSample * rot
		mid := midSample * rot

		// Gardner timing error (complex form):
		//   e = Re{ mid * conj(prevOn - on) }
		// Sign convention: prevOn−on (not on−prevOn) so that a late strobe
		// produces negative error → negative correction → earlier next strobe.
		// This matches the real-valued Gardner in symbol.go (midSample*(prevOn−on)).
		diff := d.prevOn - on
		ePhase := real(complex128(mid) * cmplx.Conj(complex128(diff)))
		// Normalize by mean power to keep loop gain stable across SNR.
		mag := real(complex128(on)*cmplx.Conj(complex128(on))) + 1e-6
		err := ePhase / mag

		d.integ += d.intGain * err
		corr := d.propGain*err + d.integ
		limit := d.sampPerSym / 4
		if corr > limit {
			corr = limit
		} else if corr < -limit {
			corr = -limit
		}

		// Differential decode and carrier update (skip the very first symbol —
		// no prevOn to differentiate against yet).
		var dibit p25.Dibit
		if d.prevOn != 0 {
			dibit = differentialDecode(on, d.prevOn)
			out = append(out, dibit)

			// Decision-directed carrier-phase update:
			// expected phase advance for this dibit is one of ±π/4, ±3π/4.
			diffPhase := cmplx.Phase(complex128(on) * cmplx.Conj(complex128(d.prevOn)))
			ideal := idealAdvance(dibit)
			phaseErr := diffPhase - ideal
			// Wrap into [-π, π].
			for phaseErr > math.Pi {
				phaseErr -= 2 * math.Pi
			}
			for phaseErr < -math.Pi {
				phaseErr += 2 * math.Pi
			}
			d.carrierPhase += d.carrierGain * phaseErr

			// EVM: phase error normalized by nominal advance (π/4).
			norm := phaseErr / (math.Pi / 4)
			d.evmSumSq += norm * norm
			d.evmCount++
		}

		d.prevOn = on
		d.prevMid = mid
		d.pos = onIdx + corr
	}

	// Carry any unconsumed tail into the next call.
	tailStart := int(d.pos)
	if tailStart < 0 {
		tailStart = 0
	}
	if tailStart < n {
		d.tail = append(d.tail[:0], buf[tailStart:]...)
		d.pos -= float64(tailStart)
	} else {
		d.tail = d.tail[:0]
		d.pos -= float64(n)
	}
	// Park the (possibly grown) backing storage for the next call.
	d.dibitsBuf = out
	return out
}

// CarrierPhase returns the current accumulated carrier-phase estimate (radians).
// Diagnostic only.
func (d *HDQPSKDemod) CarrierPhase() float64 { return d.carrierPhase }

// EVM returns the RMS Error Vector Magnitude (phase-domain), normalized by
// the nominal π/4 phase advance. A perfect signal returns 0; typical values
// for good P25 Phase 2 signals are 0.05–0.15.
func (d *HDQPSKDemod) EVM() float64 {
	if d.evmCount == 0 {
		return 0
	}
	return math.Sqrt(d.evmSumSq / float64(d.evmCount))
}

// ResetStats clears the EVM accumulator without affecting timing or carrier state.
func (d *HDQPSKDemod) ResetStats() {
	d.evmSumSq = 0
	d.evmCount = 0
}

func idealAdvance(d p25.Dibit) float64 {
	switch d {
	case 0:
		return math.Pi / 4
	case 1:
		return 3 * math.Pi / 4
	case 2:
		return -math.Pi / 4
	default: // 3
		return -3 * math.Pi / 4
	}
}

func lerpC(buf []complex64, pos float64) complex64 {
	i := int(pos)
	f := complex64(complex(pos-float64(i), 0))
	return buf[i]*(1-f) + buf[i+1]*f
}

// differentialDecode maps the phase advance from prev to cur to a Gray-coded
// dibit:
//
//	 +π/4 → 00 (0)
//	+3π/4 → 01 (1)
//	 -π/4 → 10 (2)
//	-3π/4 → 11 (3)
//
// Implemented via complex multiplication by conjugate (cur * conj(prev)) to
// extract the differential phase, then quadrant assignment.
func differentialDecode(cur, prev complex64) p25.Dibit {
	d := complex128(cur) * cmplx.Conj(complex128(prev))
	phi := cmplx.Phase(d) // (-π, π]
	switch {
	case phi >= 0 && phi < math.Pi/2:
		return 0 // +π/4
	case phi >= math.Pi/2:
		return 1 // +3π/4
	case phi < 0 && phi >= -math.Pi/2:
		return 2 // -π/4
	default:
		return 3 // -3π/4
	}
}
