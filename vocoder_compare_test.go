package p25

import (
	"math"
	"testing"
)

type pcmMetrics struct {
	RMSDelta float64
	MaxDelta float64
	SNRDB    float64
	Corr     float64
}

func comparePCM(a, b [160]float32) pcmMetrics {
	var sumA, sumB, sumAB, sumErr, maxErr float64
	for i := range a {
		af := float64(a[i])
		bf := float64(b[i])
		err := af - bf
		sumA += af * af
		sumB += bf * bf
		sumAB += af * bf
		sumErr += err * err
		if math.Abs(err) > maxErr {
			maxErr = math.Abs(err)
		}
	}
	rmsErr := math.Sqrt(sumErr / float64(len(a)))
	snr := 120.0
	if sumErr > 0 {
		snr = 10 * math.Log10(sumA/sumErr)
	}
	corr := 1.0
	if sumA > 0 && sumB > 0 {
		corr = sumAB / math.Sqrt(sumA*sumB)
	}
	return pcmMetrics{RMSDelta: rmsErr, MaxDelta: maxErr, SNRDB: snr, Corr: corr}
}

func requirePCMClose(t *testing.T, got, want [160]float32) {
	t.Helper()
	m := comparePCM(got, want)
	if m.Corr < 0.995 || m.SNRDB < 35 || m.RMSDelta > 350 || m.MaxDelta > 3000 {
		t.Fatalf("PCM mismatch: corr=%.6f snr=%.2f rms_delta=%.2f max_delta=%.2f",
			m.Corr, m.SNRDB, m.RMSDelta, m.MaxDelta)
	}
}

func TestComparePCMIdentical(t *testing.T) {
	var pcm [160]float32
	for i := range pcm {
		pcm[i] = float32(i - 80)
	}
	requirePCMClose(t, pcm, pcm)
}

func TestComparePCMRejectsInverted(t *testing.T) {
	var a, b [160]float32
	for i := range a {
		a[i] = float32(i - 80)
		b[i] = -a[i]
	}
	m := comparePCM(a, b)
	if m.Corr >= 0.995 {
		t.Fatalf("corr = %.6f, want rejected", m.Corr)
	}
}
