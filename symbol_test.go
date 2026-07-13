package p25

import (
	"math"
	"testing"
)

// generateC4FM builds a staircase C4FM discriminator signal from a dibit sequence.
func generateC4FM(dibits []Dibit, sampleRate, carrierOffset float64) []float32 {
	return generateC4FMScaled(dibits, sampleRate, carrierOffset, 1.0)
}

// generateC4FMScaled is generateC4FM with an explicit deviation scale (1.0 = nominal).
func generateC4FMScaled(dibits []Dibit, sampleRate, carrierOffset, devScale float64) []float32 {
	levels := [4]float64{600 * devScale, 1800 * devScale, -600 * devScale, -1800 * devScale}
	sampPerSym := sampleRate / symbolRate
	totalSamples := int(float64(len(dibits))*sampPerSym) + 1
	samples := make([]float32, totalSamples)

	for i := range samples {
		symIdx := int(float64(i) / sampPerSym)
		if symIdx >= len(dibits) {
			symIdx = len(dibits) - 1
		}
		samples[i] = float32(levels[dibits[symIdx]] + carrierOffset)
	}
	return samples
}

// bestErrorRate tries all phase rotations of a repeating 4-dibit pattern
// and returns the lowest error rate over the checked range.
func bestErrorRate(recovered []Dibit, pattern []Dibit, lockIn, count int) float64 {
	minErrors := count
	for shift := 0; shift < len(pattern); shift++ {
		errors := 0
		for i := 0; i < count; i++ {
			expected := pattern[(lockIn+i+shift)%len(pattern)]
			if recovered[lockIn+i] != expected {
				errors++
			}
		}
		if errors < minErrors {
			minErrors = errors
		}
	}
	return float64(minErrors) / float64(count)
}

func TestSymbolRecovery_Basic(t *testing.T) {
	pattern := []Dibit{0, 1, 2, 3}
	dibits := make([]Dibit, 1000)
	for i := range dibits {
		dibits[i] = pattern[i%4]
	}

	samples := generateC4FM(dibits, 25000, 0)
	sr := NewSymbolRecovery(25000)
	recovered := sr.Process(samples)

	lockIn := 50
	count := len(recovered) - lockIn
	if count < 100 {
		t.Fatalf("only recovered %d symbols total, need at least %d", len(recovered), lockIn+100)
	}
	if count > len(dibits)-lockIn {
		count = len(dibits) - lockIn
	}

	errRate := bestErrorRate(recovered, pattern, lockIn, count)
	if errRate > 0.05 {
		t.Errorf("error rate %.2f%% exceeds 5%% threshold", errRate*100)
	}
	t.Logf("recovered %d symbols, error rate %.2f%% after %d-symbol lock-in", len(recovered), errRate*100, lockIn)
}

func TestSymbolRecovery_CarrierOffset(t *testing.T) {
	pattern := []Dibit{0, 1, 2, 3}
	dibits := make([]Dibit, 3000)
	for i := range dibits {
		dibits[i] = pattern[i%4]
	}

	offset := 200.0
	samples := generateC4FM(dibits, 25000, offset)
	sr := NewSymbolRecovery(25000)
	recovered := sr.Process(samples)

	// Carrier estimate should converge near the true offset
	est := sr.CarrierOffset()
	if math.Abs(est-offset) > 100 {
		t.Errorf("carrier offset estimate %.1f Hz, expected near %.1f Hz", est, offset)
	}

	lockIn := 100
	count := len(recovered) - lockIn
	if count < 100 {
		t.Fatalf("only recovered %d symbols", len(recovered))
	}
	if count > len(dibits)-lockIn {
		count = len(dibits) - lockIn
	}

	errRate := bestErrorRate(recovered, pattern, lockIn, count)
	if errRate > 0.05 {
		t.Errorf("error rate %.2f%% with +%.0f Hz carrier offset", errRate*100, offset)
	}
	t.Logf("carrier est: %.1f Hz (actual: %.0f Hz), error rate %.2f%%", est, offset, errRate*100)
}

func TestSymbolRecovery_Chunked(t *testing.T) {
	pattern := []Dibit{0, 1, 2, 3}
	dibits := make([]Dibit, 1000)
	for i := range dibits {
		dibits[i] = pattern[i%4]
	}

	samples := generateC4FM(dibits, 25000, 0)
	sr := NewSymbolRecovery(25000)

	// Feed in small chunks to exercise tail buffer handling
	var recovered []Dibit
	chunkSize := 50
	for i := 0; i < len(samples); i += chunkSize {
		end := i + chunkSize
		if end > len(samples) {
			end = len(samples)
		}
		recovered = append(recovered, sr.Process(samples[i:end])...)
	}

	lockIn := 50
	count := len(recovered) - lockIn
	if count < 100 {
		t.Fatalf("only recovered %d symbols total", len(recovered))
	}
	if count > len(dibits)-lockIn {
		count = len(dibits) - lockIn
	}

	errRate := bestErrorRate(recovered, pattern, lockIn, count)
	if errRate > 0.05 {
		t.Errorf("chunked: error rate %.2f%% exceeds 5%%", errRate*100)
	}
	t.Logf("chunked: %d symbols, error rate %.2f%%", len(recovered), errRate*100)
}

func TestSymbolRecovery_NegativeCarrierOffset(t *testing.T) {
	pattern := []Dibit{0, 1, 2, 3}
	dibits := make([]Dibit, 3000)
	for i := range dibits {
		dibits[i] = pattern[i%4]
	}

	offset := -150.0
	samples := generateC4FM(dibits, 25000, offset)
	sr := NewSymbolRecovery(25000)
	recovered := sr.Process(samples)

	est := sr.CarrierOffset()
	if est-offset > 100 || est-offset < -100 {
		t.Errorf("carrier offset estimate %.1f Hz, expected near %.1f Hz", est, offset)
	}

	lockIn := 100
	count := len(recovered) - lockIn
	if count < 100 {
		t.Fatalf("only recovered %d symbols", len(recovered))
	}
	if count > len(dibits)-lockIn {
		count = len(dibits) - lockIn
	}
	errRate := bestErrorRate(recovered, pattern, lockIn, count)
	if errRate > 0.05 {
		t.Errorf("error rate %.2f%% with %.0f Hz carrier offset", errRate*100, offset)
	}
}

func TestSymbolRecovery_Reset(t *testing.T) {
	sr := NewSymbolRecovery(25000)
	pattern := []Dibit{0, 1, 2, 3}
	dibits := make([]Dibit, 500)
	for i := range dibits {
		dibits[i] = pattern[i%4]
	}
	samples := generateC4FM(dibits, 25000, 100)
	sr.Process(samples)

	if sr.CarrierOffset() == 0 {
		t.Error("carrier offset should be non-zero before reset")
	}

	sr.Reset()
	if sr.CarrierOffset() == 0 {
		t.Error("carrier offset should be preserved after Reset() (hardware offset is stable)")
	}
	if sr.TimingOffset() != 0 {
		t.Error("timing offset should be 0 after reset")
	}

	// ResetFull should clear carrier estimate
	sr.ResetFull()
	if sr.CarrierOffset() != 0 {
		t.Error("carrier offset should be 0 after ResetFull()")
	}
}

func TestSymbolRecovery_AllSameSymbol(t *testing.T) {
	// All same symbol — no timing info from Gardner TED, but should still produce dibits
	dibits := make([]Dibit, 500)
	// all dibit 1 (+1800 Hz)
	for i := range dibits {
		dibits[i] = 1
	}
	samples := generateC4FM(dibits, 25000, 0)
	sr := NewSymbolRecovery(25000)
	recovered := sr.Process(samples)
	if len(recovered) < 100 {
		t.Fatalf("expected at least 100 recovered symbols, got %d", len(recovered))
	}
	// Most should be dibit 1
	correct := 0
	for i := 50; i < len(recovered); i++ {
		if recovered[i] == 1 {
			correct++
		}
	}
	total := len(recovered) - 50
	if float64(correct)/float64(total) < 0.75 {
		t.Errorf("only %.0f%% correct for constant symbol", float64(correct)/float64(total)*100)
	}
}

func TestSymbolRecovery_RandomPattern(t *testing.T) {
	// A longer pseudo-random pattern to stress test
	dibits := make([]Dibit, 5000)
	for i := range dibits {
		dibits[i] = Dibit((i*7 + 3) % 4)
	}
	samples := generateC4FM(dibits, 25000, 0)
	sr := NewSymbolRecovery(25000)
	recovered := sr.Process(samples)

	lockIn := 100
	if len(recovered) < lockIn+100 {
		t.Fatalf("only recovered %d symbols", len(recovered))
	}

	// Check error rate against the known pattern
	errors := 0
	checked := 0
	for i := lockIn; i < len(recovered) && i < len(dibits); i++ {
		if recovered[i] != dibits[i] {
			errors++
		}
		checked++
	}
	errRate := float64(errors) / float64(checked)
	if errRate > 0.05 {
		t.Errorf("random pattern: error rate %.2f%% (%d/%d)", errRate*100, errors, checked)
	}
	t.Logf("random pattern: %d symbols, error rate %.2f%%", len(recovered), errRate*100)
}

func TestSymbolRecovery_EVM_PerfectSignal(t *testing.T) {
	// A perfect C4FM signal should have very low EVM
	pattern := []Dibit{0, 1, 2, 3}
	dibits := make([]Dibit, 3000)
	for i := range dibits {
		dibits[i] = pattern[i%4]
	}
	samples := generateC4FM(dibits, 25000, 0)
	sr := NewSymbolRecovery(25000)
	sr.Process(samples)

	evm := sr.EVM()
	if evm > 0.15 {
		t.Errorf("EVM = %.4f, expected < 0.15 for perfect signal", evm)
	}
	t.Logf("perfect signal EVM: %.4f", evm)
}

func TestSymbolRecovery_EVM_NoisySignal(t *testing.T) {
	// Add noise to the signal — EVM should be higher
	pattern := []Dibit{0, 1, 2, 3}
	dibits := make([]Dibit, 3000)
	for i := range dibits {
		dibits[i] = pattern[i%4]
	}
	samples := generateC4FM(dibits, 25000, 0)

	// Add deterministic "noise" (±200 Hz perturbation)
	for i := range samples {
		noise := float32(200.0 * (float64(i%7)/3.0 - 1.0))
		samples[i] += noise
	}

	sr := NewSymbolRecovery(25000)
	sr.Process(samples)

	evm := sr.EVM()
	// Noisy signal should have higher EVM than perfect
	if evm < 0.01 {
		t.Errorf("EVM = %.4f, expected > 0.01 for noisy signal", evm)
	}
	t.Logf("noisy signal EVM: %.4f", evm)
}

func TestSymbolRecovery_EVM_Reset(t *testing.T) {
	sr := NewSymbolRecovery(25000)
	pattern := []Dibit{0, 1, 2, 3}
	dibits := make([]Dibit, 500)
	for i := range dibits {
		dibits[i] = pattern[i%4]
	}
	samples := generateC4FM(dibits, 25000, 0)
	sr.Process(samples)

	if sr.EVM() == 0 {
		t.Error("EVM should be non-zero before reset")
	}

	sr.Reset()
	if sr.EVM() != 0 {
		t.Error("EVM should be 0 after reset")
	}
}

func TestSymbolRecovery_EVM_WithCarrierOffset(t *testing.T) {
	// EVM should still be low after carrier tracking converges
	pattern := []Dibit{0, 1, 2, 3}
	dibits := make([]Dibit, 5000)
	for i := range dibits {
		dibits[i] = pattern[i%4]
	}
	samples := generateC4FM(dibits, 25000, 200.0) // +200 Hz offset
	sr := NewSymbolRecovery(25000)
	sr.Process(samples)

	evm := sr.EVM()
	// After carrier tracking converges, EVM should be reasonable
	if evm > 0.25 {
		t.Errorf("EVM = %.4f with carrier offset, expected < 0.25 after tracking", evm)
	}
	t.Logf("EVM with +200Hz carrier offset: %.4f, carrier est: %.1f Hz", evm, sr.CarrierOffset())
}

// TestSymbolRecovery_DeviationTracking verifies that the deviation-tracking
// loop converges on a transmitter whose outer level is 2000 Hz instead of the
// nominal 1800 Hz (an 11% over-deviation, well within the P25 spec tolerance
// and matching the on-air NAC 0x171 CC). Without tracking, the bias alone
// contributes ~0.083 to EVM; with tracking it should be near-eliminated.
func TestSymbolRecovery_DeviationTracking(t *testing.T) {
	dibits := make([]Dibit, 8000)
	for i := range dibits {
		dibits[i] = Dibit((i*7 + 3) % 4)
	}
	samples := generateC4FMScaled(dibits, 25000, 0, 2000.0/1800.0)

	sr := NewSymbolRecovery(25000)
	// Burn-in: let the dev/DFE loops converge before measuring.
	burn := len(samples) / 2
	sr.Process(samples[:burn])
	sr.ResetStats()
	sr.Process(samples[burn:])

	if got := sr.EVM(); got > 0.05 {
		t.Errorf("EVM with 11%% over-deviation = %.4f after tracking; want <= 0.05 (devScale=%.4f)",
			got, sr.DeviationScale())
	}
	if ds := sr.DeviationScale(); ds < 1.06 || ds > 1.16 {
		t.Errorf("DeviationScale converged to %.4f; want approx 1.111", ds)
	}
}

// TestSymbolRecovery_Reset_ClearsDFEState verifies that Reset() clears the
// per-signal DFE adaptation state (dfeTap, prevIdeal). These are learned from
// the symbol stream of a particular transmission and must not bleed into the
// next call -- a noisy squelch tail can drive dfeTap large, and the stale
// dfeTap*prevIdeal term then mis-slices the next call's HDU. carrierEst is a
// hardware property and must remain preserved.
func TestSymbolRecovery_Reset_ClearsDFEState(t *testing.T) {
	sr := NewSymbolRecovery(25000)

	const carrierSentinel = 137.0
	sr.carrierEst = carrierSentinel
	sr.dfeTap = 3.7
	sr.prevIdeal = 1800

	sr.Reset()

	if sr.dfeTap != 0 {
		t.Errorf("dfeTap = %v after Reset(), want 0", sr.dfeTap)
	}
	if sr.prevIdeal != 0 {
		t.Errorf("prevIdeal = %v after Reset(), want 0", sr.prevIdeal)
	}
	if sr.carrierEst != carrierSentinel {
		t.Errorf("carrierEst = %v after Reset(), want %v (must be preserved)",
			sr.carrierEst, carrierSentinel)
	}
}

// TestSymbolRecovery_DFETap_Clamped verifies that the LMS-updated DFE tap is
// bounded to |dfeTap| <= dfeTapMax so a burst of garbage cannot drive the
// equaliser into a regime where it dominates the decision sample.
func TestSymbolRecovery_DFETap_Clamped(t *testing.T) {
	// One symbol period at 25 kS/s is ~5.2 samples; 7 samples yields exactly
	// one decision in Process() so the LMS update + clamp path runs once.
	oneSymbol := make([]float32, 7)

	for _, tc := range []struct {
		name    string
		tap     float64
		wantMin float64
		wantMax float64
	}{
		{"positive", 100.0, -0.5, 0.5},
		{"negative", -100.0, -0.5, 0.5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sr := NewSymbolRecovery(25000)
			sr.dfeTap = tc.tap
			sr.prevIdeal = nominalDeviation // ensure the LMS branch is taken

			sr.Process(oneSymbol)

			if sr.dfeTap < tc.wantMin || sr.dfeTap > tc.wantMax {
				t.Errorf("dfeTap = %v after LMS update, want within [%v, %v]",
					sr.dfeTap, tc.wantMin, tc.wantMax)
			}
		})
	}
}

// TestSymbolRecovery_ProcessZeroAllocSteadyState confirms the dibits +
// concat buffers are reused. The previous Process path made a fresh
// len(tail)+len(raw) []float32 plus an unsized append to []Dibit on every
// call (~2.83 GB / 30 s in the captured profile).
func TestSymbolRecovery_ProcessZeroAllocSteadyState(t *testing.T) {
	pattern := []Dibit{0, 1, 2, 3, 1, 0, 3, 2}
	dibits := make([]Dibit, 1024)
	for i := range dibits {
		dibits[i] = pattern[i%len(pattern)]
	}
	samples := generateC4FM(dibits, 25000, 0)
	sr := NewSymbolRecovery(25000)

	// Feed in 250-sample blocks (matches the production block size) to
	// build up tail state, then measure steady-state allocs.
	const block = 250
	for i := 0; i+block <= len(samples); i += block {
		sr.Process(samples[i : i+block])
	}

	// Pick a fresh stretch of samples and reuse it across allocs runs so
	// AllocsPerRun's repeats don't drift in tail length.
	chunk := samples[:block]
	allocs := testing.AllocsPerRun(50, func() {
		sr.Process(chunk)
	})
	if allocs > 0 {
		t.Fatalf("Process allocs/op = %.2f, want 0", allocs)
	}
}

func TestDigitIdealLevel(t *testing.T) {
	tests := []struct {
		d    Dibit
		want float64
	}{
		{0, 600},
		{1, 1800},
		{2, -600},
		{3, -1800},
	}
	for _, tt := range tests {
		got := dibitIdealLevel(tt.d)
		if got != tt.want {
			t.Errorf("dibitIdealLevel(%d) = %f, want %f", tt.d, got, tt.want)
		}
	}
}

// TestSymbolRecovery_SoftAlignsWithDibits feeds the four ideal C4FM levels and
// asserts LastSoft() returns one normalized value per emitted dibit, with the
// same sign as the dibit's ideal level (a clean signal must demap to the
// matching quadrant). Length and sign are the contract the soft Viterbi path
// relies on.
func TestSymbolRecovery_SoftAlignsWithDibits(t *testing.T) {
	pattern := []Dibit{1, 0, 2, 3} // levels +3, +1, -1, -3 (one of each)
	dibits := make([]Dibit, 1000)
	for i := range dibits {
		dibits[i] = pattern[i%4]
	}
	samples := generateC4FM(dibits, 25000, 0)

	sr := NewSymbolRecovery(25000)
	recovered := sr.Process(samples)
	soft := sr.LastSoft()

	if len(soft) != len(recovered) {
		t.Fatalf("soft len %d != dibit len %d", len(soft), len(recovered))
	}
	// Skip the lock-in window where the slicer hasn't converged yet.
	const lockIn = 50
	if len(recovered) < lockIn+100 {
		t.Fatalf("only recovered %d symbols, need >= %d", len(recovered), lockIn+100)
	}
	for i := lockIn; i < len(recovered); i++ {
		want := c4fmLevels[recovered[i]]
		// Normalized soft value must share sign with the sliced dibit's level
		// (sign correctness is the soft-Viterbi-relevant invariant; magnitude
		// has already been exercised by softbit_test.go).
		if (want > 0) != (float64(soft[i]) > 0) {
			t.Errorf("symbol %d: dibit %d (level %v) but soft %v has wrong sign",
				i, recovered[i], want, soft[i])
		}
	}
}

