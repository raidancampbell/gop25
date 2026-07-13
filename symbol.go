package p25

import "math"

// Dibit represents a two-bit symbol (values 0–3).
type Dibit uint8

const (
	symbolRate       = 4800.0 // P25 C4FM symbol rate
	nominalDeviation = 1800.0 // outer deviation level in Hz

	// dfeTapMax bounds the single-tap DFE coefficient. The tap models
	// 1st-postcursor ISI leakage, which physically cannot exceed the symbol
	// energy itself; 0.5 is a generous ceiling that still prevents a noise
	// burst from driving the LMS update into a regime where the feedback
	// term dominates (and inverts) the decision sample.
	dfeTapMax = 0.5
)

// SymbolRecovery recovers P25 C4FM dibits from FM discriminator output
// using a Gardner timing error detector with a PI loop filter.
type SymbolRecovery struct {
	sampleRate   float64
	sampPerSym   float64
	pos          float64
	prevOnSample float32
	propGain     float64
	intGain      float64
	integrator   float64
	carrierEst   float64
	carrierAlpha float64
	tail         []float32
	timingSum    float64
	symbolCount  int64

	// devScale tracks the transmitter's actual deviation relative to the
	// nominal 1800 Hz outer level. P25 permits ±10% and field equipment
	// often runs hot (the NAC 0x171 CC at 460.4125 sits at 2006 Hz ≈ 1.115).
	// The slicer thresholds and EVM "ideal" levels are scaled by this so
	// the EVM metric reflects symbol quality rather than tx calibration,
	// and the ±1/±3 decision boundary stays centred between the actual
	// constellation points. Updated decision-directed from the outer (±3)
	// symbols only, where |corrected|/1800 directly observes the scale.
	devScale float64
	devAlpha float64

	// dfeTap is a single-tap decision-feedback equaliser estimating the
	// 1st-postcursor ISI coefficient: corrected_n ≈ ideal_n + dfeTap·ideal_{n-1}.
	// The C4FM tx pulse (raised-cosine α=0.2 + inverse-sinc) leaves a small
	// negative postcursor after the rx LPF; subtracting dfeTap·prevIdeal
	// from the decision sample removes that data-dependent bias.
	// LMS-updated from the residual (corrected − ideal)·prevIdeal.
	dfeTap    float64
	dfeAlpha  float64
	prevIdeal float64

	// EVM (Error Vector Magnitude) accumulator.
	// RMS distance between the sliced ideal symbol level and the actual
	// carrier-corrected sample value at the decision instant. Normalized
	// by the nominal outer deviation (1800 Hz), so a perfect signal has
	// EVM ≈ 0 and a noisy one approaches 1.0+.
	evmSumSq float64 // sum of squared errors
	evmCount int64

	// concatBuf and dibitsBuf are reusable scratch for Process. concatBuf
	// holds tail||raw when there is leftover tail from the previous call;
	// dibitsBuf collects the recovered dibits. Both are returned to the
	// caller via slice reslicing (len reset to 0 each call), avoiding the
	// per-block allocations that were the second-largest source of heap
	// churn in the captured profile (~2.83 GB / 30 s).
	concatBuf []float32
	dibitsBuf []Dibit
	// softBuf holds the normalized decision-instant value (ideal levels +/-1,
	// +/-3) for each dibit in dibitsBuf, 1:1 aligned. Reused across Process
	// calls with the same lifetime contract as dibitsBuf. Feeds the
	// soft-decision Viterbi.
	softBuf []float32
}

func NewSymbolRecovery(sampleRate float64) *SymbolRecovery {
	return &SymbolRecovery{
		sampleRate:   sampleRate,
		sampPerSym:   sampleRate / symbolRate,
		propGain:     0.04,
		intGain:      0.001,
		carrierAlpha: 0.001,
		devScale:     1.0,
		devAlpha:     0.002,
		dfeAlpha:     0.002,
	}
}

// Process takes FM discriminator output (Hz) and returns recovered dibits.
// The returned slice is backed by an internal buffer that is reused on the
// next Process call; callers (FrameSync.Feed today) must consume it before
// the next Process. ProcessRaw on P25Decoder is the same single producer.
func (sr *SymbolRecovery) Process(raw []float32) []Dibit {
	var buf []float32
	if len(sr.tail) > 0 {
		need := len(sr.tail) + len(raw)
		if cap(sr.concatBuf) < need {
			sr.concatBuf = make([]float32, need)
		}
		buf = sr.concatBuf[:need]
		copy(buf, sr.tail)
		copy(buf[len(sr.tail):], raw)
	} else {
		buf = raw
	}

	dibits := sr.dibitsBuf[:0]
	soft := sr.softBuf[:0]
	n := len(buf)

	for {
		onIdx := sr.pos + sr.sampPerSym
		if int(onIdx)+1 >= n {
			break
		}

		midIdx := sr.pos + sr.sampPerSym/2

		onSample := lerp(buf, onIdx)
		midSample := lerp(buf, midIdx)

		// Gardner timing error detector, normalized by deviation²
		err := float64(midSample) * (float64(sr.prevOnSample) - float64(onSample))
		err /= nominalDeviation * nominalDeviation

		// PI loop filter
		sr.integrator += sr.intGain * err
		correction := sr.propGain*err + sr.integrator

		limit := sr.sampPerSym / 4
		if correction > limit {
			correction = limit
		} else if correction < -limit {
			correction = -limit
		}

		// Slice after carrier correction and 1-tap DFE.
		corrected := float64(onSample) - sr.carrierEst - sr.dfeTap*sr.prevIdeal
		dibit := sliceDibitScaled(corrected, sr.devScale)
		dibits = append(dibits, dibit)
		// Soft value in normalized level units (ideal +/-1, +/-3) for the soft
		// Viterbi: corrected/(600*devScale) puts the four levels at exactly
		// +/-1 and +/-3 regardless of the transmitter's deviation calibration
		// (devScale tracks +/-3 / 1800).
		soft = append(soft, float32(corrected/(600*sr.devScale)))
		ideal := dibitIdealLevel(dibit) * sr.devScale
		residual := corrected - ideal

		// Decision-directed carrier offset tracking: update from the residual
		// so the estimate isolates true LO offset from data-dependent levels.
		sr.carrierEst += sr.carrierAlpha * residual

		// Decision-directed deviation tracking: update from outer (±3) symbols
		// only, where |corrected|/1800 directly observes the deviation scale.
		// Clamped to keep a bad startup transient from collapsing the slicer.
		if dibit == 1 || dibit == 3 {
			sr.devScale += sr.devAlpha * (math.Abs(corrected)/nominalDeviation - sr.devScale)
			if sr.devScale < 0.7 {
				sr.devScale = 0.7
			} else if sr.devScale > 1.4 {
				sr.devScale = 1.4
			}
		}

		// 1-tap DFE LMS update: drive E[residual·prevIdeal] -> 0.
		if sr.prevIdeal != 0 {
			sr.dfeTap += sr.dfeAlpha * residual * sr.prevIdeal / (nominalDeviation * nominalDeviation)
			if sr.dfeTap < -dfeTapMax {
				sr.dfeTap = -dfeTapMax
			} else if sr.dfeTap > dfeTapMax {
				sr.dfeTap = dfeTapMax
			}
		}

		// EVM: distance from ideal symbol level, normalized by outer deviation
		sr.evmSumSq += (residual / nominalDeviation) * (residual / nominalDeviation)
		sr.evmCount++

		sr.prevIdeal = ideal
		sr.prevOnSample = onSample
		sr.timingSum += correction
		sr.symbolCount++
		sr.pos = onIdx + correction
	}

	// Save unprocessed samples for next call
	tailStart := int(sr.pos)
	if tailStart < 0 {
		tailStart = 0
	}
	if tailStart < n {
		sr.tail = append(sr.tail[:0], buf[tailStart:]...)
		sr.pos -= float64(tailStart)
	} else {
		sr.tail = sr.tail[:0]
		sr.pos -= float64(n)
	}

	// Park the (possibly grown) backing storage for the next call.
	sr.dibitsBuf = dibits
	sr.softBuf = soft
	return dibits
}

func (sr *SymbolRecovery) CarrierOffset() float64 {
	return sr.carrierEst
}

func (sr *SymbolRecovery) TimingOffset() float64 {
	if sr.symbolCount == 0 {
		return 0
	}
	return sr.timingSum / float64(sr.symbolCount)
}

// DeviationScale returns the current deviation-tracking estimate
// (1.0 = nominal 1800 Hz outer level).
func (sr *SymbolRecovery) DeviationScale() float64 { return sr.devScale }

// LastSoft returns the normalized soft symbol values (ideal levels +/-1, +/-3)
// for the dibits returned by the most recent Process call, 1:1 aligned. Backed
// by an internal buffer reused on the next Process; consume before calling
// Process again -- same lifetime contract as the returned dibit slice.
func (sr *SymbolRecovery) LastSoft() []float32 { return sr.softBuf }

// EVM returns the RMS Error Vector Magnitude, normalized by nominal deviation.
// A perfect signal returns 0; typical values for good P25 signals are 0.05–0.15.
func (sr *SymbolRecovery) EVM() float64 {
	if sr.evmCount == 0 {
		return 0
	}
	return math.Sqrt(sr.evmSumSq / float64(sr.evmCount))
}

func (sr *SymbolRecovery) Reset() {
	sr.pos = 0
	sr.prevOnSample = 0
	sr.integrator = 0
	// carrierEst and devScale are intentionally NOT reset here. Both are
	// slowly-varying properties of the channel/hardware (SDR tuning error,
	// LO drift, transmitter deviation calibration) that persist across
	// transmissions on the same frequency. Preserving the converged
	// estimates lets each new transmission start with corrected symbols
	// from the first dibit, avoiding the ~2-LDU convergence gap that
	// manifests as heavy IMBE errors in early frames. devScale is also
	// hard-clamped to [0.7, 1.4], so a stale value cannot mis-slice.
	//
	// dfeTap and prevIdeal ARE reset: they are per-signal adaptation state
	// learned from the symbol stream itself. A noisy squelch tail at the
	// end of one call can drive dfeTap large, and the stale
	// dfeTap*prevIdeal subtraction then corrupts the next call's HDU until
	// LMS re-converges.
	sr.dfeTap = 0
	sr.prevIdeal = 0
	sr.tail = sr.tail[:0]
	sr.timingSum = 0
	sr.symbolCount = 0
	sr.evmSumSq = 0
	sr.evmCount = 0
}

// ResetFull resets all state including the carrier estimate.
// Use this only when starting a completely new channel (e.g., retuning).
func (sr *SymbolRecovery) ResetFull() {
	sr.carrierEst = 0
	sr.devScale = 1.0
	sr.dfeTap = 0
	sr.prevIdeal = 0
	sr.Reset()
}

// ResetStats clears carrier/timing/EVM accumulators without resetting the
// timing loop or sample position. This preserves symbol lock across squelch transitions.
func (sr *SymbolRecovery) ResetStats() {
	sr.timingSum = 0
	sr.symbolCount = 0
	sr.evmSumSq = 0
	sr.evmCount = 0
}

func lerp(buf []float32, pos float64) float32 {
	idx := int(pos)
	frac := float32(pos - float64(idx))
	return buf[idx]*(1-frac) + buf[idx+1]*frac
}

// sliceDibit maps a carrier-corrected discriminator value (Hz) to a dibit.
//
//	+1800 Hz → dibit 01 (1)   +3 symbol
//	 +600 Hz → dibit 00 (0)   +1 symbol
//	 −600 Hz → dibit 10 (2)   −1 symbol
//	−1800 Hz → dibit 11 (3)   −3 symbol
func sliceDibit(val float64) Dibit { return sliceDibitScaled(val, 1.0) }

func sliceDibitScaled(val, scale float64) Dibit {
	t := 1200 * scale
	if val > t {
		return 1
	}
	if val > 0 {
		return 0
	}
	if val > -t {
		return 2
	}
	return 3
}

// dibitIdealLevel returns the nominal discriminator output (Hz) for a dibit.
func dibitIdealLevel(d Dibit) float64 {
	switch d {
	case 1:
		return 1800 // +3
	case 0:
		return 600 // +1
	case 2:
		return -600 // −1
	case 3:
		return -1800 // −3
	default:
		return 0
	}
}

