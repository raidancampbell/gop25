package mbe

import "math"

// Rand is a deterministic, decoder-local pseudo-random number generator.
// Replicates libc rand() (Park-Miller MINSTD) for audio-match with C oracle.
type Rand struct {
	state uint32
}

// Seed initializes the PRNG. If seed is 0, state is forced to 1 (libc behavior).
func (r *Rand) Seed(seed uint32) {
	if seed == 0 {
		r.state = 1
	} else {
		r.state = seed
	}
}

// Float32 returns a pseudo-random float32 in [0.0, 1.0].
// Matches mbe_rand() = (float)rand() / (float)RAND_MAX.
func (r *Rand) Float32() float32 {
	// Park-Miller MINSTD: state = (16807 * state) % 2147483647
	r.state = uint32((uint64(16807) * uint64(r.state)) % 2147483647)
	return float32(r.state) / float32(2147483647)
}

// phase returns a pseudo-random phase in [-pi, +pi], mirroring mbe_rand_phase().
func (r *Rand) phase() float32 {
	return r.Float32()*float32(2*math.Pi) - float32(math.Pi)
}

// SynthesizeSilence sets all 160 samples to 0.
// Mirrors mbe_synthesizeSilencef.
func SynthesizeSilence(out *[160]float32) {
	for i := range out {
		out[i] = 0
	}
}

// Helper functions to match C float precision (cosf, sqrtf, powf, logf).
func cosf(x float32) float32    { return float32(math.Cos(float64(x))) }
func sqrtf(x float32) float32   { return float32(math.Sqrt(float64(x))) }
func powf(x, y float32) float32 { return float32(math.Pow(float64(x), float64(y))) }
func logf(x float32) float32    { return float32(math.Log(float64(x))) }

// SpectralAmpEnhance performs spectral amplitude enhancement on cur.
// Mirrors mbe_spectralAmpEnhance (mbelib.c lines 117-185).
func SpectralAmpEnhance(cur *Parms) {
	var Rm0, Rm1, R2m0, R2m1 float32
	var Wl [57]float32

	// Compute Rm0 and Rm1
	Rm0 = 0
	Rm1 = 0
	for l := 1; l <= cur.L; l++ {
		Rm0 = Rm0 + (cur.Ml[l] * cur.Ml[l])
		Rm1 = Rm1 + ((cur.Ml[l] * cur.Ml[l]) * cosf(cur.W0*float32(l)))
	}

	R2m0 = Rm0 * Rm0
	R2m1 = Rm1 * Rm1

	// Compute Wl and apply selective enhancement
	for l := 1; l <= cur.L; l++ {
		if cur.Ml[l] != 0 {
			Wl[l] = sqrtf(cur.Ml[l]) * powf((float32(0.96)*float32(math.Pi)*((R2m0+R2m1)-(float32(2)*Rm0*Rm1*cosf(cur.W0*float32(l)))))/(cur.W0*Rm0*(R2m0-R2m1)), float32(0.25))

			if (8 * l) <= cur.L {
				// Do nothing
			} else if Wl[l] > 1.2 {
				cur.Ml[l] = 1.2 * cur.Ml[l]
			} else if Wl[l] < 0.5 {
				cur.Ml[l] = 0.5 * cur.Ml[l]
			} else {
				cur.Ml[l] = Wl[l] * cur.Ml[l]
			}
		}
	}

	// Generate scaling factor
	sum := float32(0)
	for l := 1; l <= cur.L; l++ {
		M := cur.Ml[l]
		if M < 0 {
			M = -M
		}
		sum += M * M
	}
	var gamma float32
	if sum == 0 {
		gamma = float32(1.0)
	} else {
		gamma = sqrtf(Rm0 / sum)
	}

	// Apply scaling factor
	for l := 1; l <= cur.L; l++ {
		cur.Ml[l] = gamma * cur.Ml[l]
	}
}

// SynthesizeSpeech synthesizes speech from MBE parameters.
// Mirrors mbe_synthesizeSpeechf (mbelib.c lines 218-457).
func SynthesizeSpeech(out *[160]float32, cur, prev *Parms, uvquality int, rng *Rand) {
	const N = 160

	uvthresholdf := float32(2700)
	uvthreshold := (uvthresholdf * float32(math.Pi)) / float32(4000)

	// voiced/unvoiced/gain settings
	uvsine := float32(1.3591409) * float32(math.E)
	uvrand := float32(2.0)

	if (uvquality < 1) || (uvquality > 64) {
		// C prints error; we just clamp
		uvquality = 3
	}

	// calculate loguvquality
	var loguvquality float32
	if uvquality == 1 {
		loguvquality = float32(1) / float32(math.E)
	} else {
		loguvquality = logf(float32(uvquality)) / float32(uvquality)
	}

	// calculate unvoiced step and offset values
	uvstep := float32(1.0) / float32(uvquality)
	qfactor := loguvquality
	uvoffset := (uvstep * float32(uvquality-1)) / float32(2)

	// count number of unvoiced bands
	numUv := 0
	for l := 1; l <= cur.L; l++ {
		if cur.Vl[l] == 0 {
			numUv++
		}
	}

	cw0 := cur.W0
	pw0 := prev.W0

	// init aout_buf
	for n := 0; n < N; n++ {
		out[n] = float32(0)
	}

	// eq 128 and 129
	var maxl int
	if cur.L > prev.L {
		maxl = cur.L
		for l := prev.L + 1; l <= maxl; l++ {
			prev.Ml[l] = float32(0)
			prev.Vl[l] = 1
		}
	} else {
		maxl = prev.L
		for l := cur.L + 1; l <= maxl; l++ {
			cur.Ml[l] = float32(0)
			cur.Vl[l] = 1
		}
	}

	// update phil from eq 139,140
	for l := 1; l <= 56; l++ {
		cur.PSIl[l] = prev.PSIl[l] + ((pw0 + cw0) * (float32(l*N) / float32(2)))
		if l <= (cur.L / 4) {
			cur.PHIl[l] = cur.PSIl[l]
		} else {
			cur.PHIl[l] = cur.PSIl[l] + ((float32(numUv) * rng.phase()) / float32(cur.L))
		}
	}

	var rphase [64]float32
	var rphase2 [64]float32

	for l := 1; l <= maxl; l++ {
		cw0l := cw0 * float32(l)
		pw0l := pw0 * float32(l)

		if (cur.Vl[l] == 0) && (prev.Vl[l] == 1) {
			// Case (a): eq 131 + unvoiced mix
			// init random phase
			for i := 0; i < uvquality; i++ {
				rphase[i] = rng.phase()
			}
			for n := 0; n < N; n++ {
				C1 := float32(0)
				// eq 131
				C1 = ws[n+N] * prev.Ml[l] * cosf((pw0l*float32(n))+prev.PHIl[l])
				C3 := float32(0)
				// unvoiced multisine mix
				for i := 0; i < uvquality; i++ {
					C3 = C3 + cosf((cw0*float32(n)*(float32(l)+(float32(i)*uvstep)-uvoffset))+rphase[i])
					if cw0l > uvthreshold {
						C3 = C3 + ((cw0l - uvthreshold) * uvrand * rng.Float32())
					}
				}
				C3 = C3 * uvsine * ws[n] * cur.Ml[l] * qfactor
				out[n] = out[n] + C1 + C3
			}
		} else if (cur.Vl[l] == 1) && (prev.Vl[l] == 0) {
			// Case (b): eq 132 + unvoiced mix
			// init random phase
			for i := 0; i < uvquality; i++ {
				rphase[i] = rng.phase()
			}
			for n := 0; n < N; n++ {
				C1 := float32(0)
				// eq 132
				C1 = ws[n] * cur.Ml[l] * cosf((cw0l*float32(n-N))+cur.PHIl[l])
				C3 := float32(0)
				// unvoiced multisine mix
				for i := 0; i < uvquality; i++ {
					C3 = C3 + cosf((pw0*float32(n)*(float32(l)+(float32(i)*uvstep)-uvoffset))+rphase[i])
					if pw0l > uvthreshold {
						C3 = C3 + ((pw0l - uvthreshold) * uvrand * rng.Float32())
					}
				}
				C3 = C3 * uvsine * ws[n+N] * prev.Ml[l] * qfactor
				out[n] = out[n] + C1 + C3
			}
		} else if (cur.Vl[l] == 1) || (prev.Vl[l] == 1) {
			// Case (c): eq 133-1 + eq 133-2 (purely-voiced overlap-add)
			for n := 0; n < N; n++ {
				C1 := float32(0)
				// eq 133-1
				C1 = ws[n+N] * prev.Ml[l] * cosf((pw0l*float32(n))+prev.PHIl[l])
				C2 := float32(0)
				// eq 133-2
				C2 = ws[n] * cur.Ml[l] * cosf((cw0l*float32(n-N))+cur.PHIl[l])
				out[n] = out[n] + C1 + C2
			}
		} else {
			// Case (d): both unvoiced
			// init random phase
			for i := 0; i < uvquality; i++ {
				rphase[i] = rng.phase()
			}
			// init random phase
			for i := 0; i < uvquality; i++ {
				rphase2[i] = rng.phase()
			}
			for n := 0; n < N; n++ {
				C3 := float32(0)
				// unvoiced multisine mix
				for i := 0; i < uvquality; i++ {
					C3 = C3 + cosf((pw0*float32(n)*(float32(l)+(float32(i)*uvstep)-uvoffset))+rphase[i])
					if pw0l > uvthreshold {
						C3 = C3 + ((pw0l - uvthreshold) * uvrand * rng.Float32())
					}
				}
				C3 = C3 * uvsine * ws[n+N] * prev.Ml[l] * qfactor
				C4 := float32(0)
				// unvoiced multisine mix
				for i := 0; i < uvquality; i++ {
					C4 = C4 + cosf((cw0*float32(n)*(float32(l)+(float32(i)*uvstep)-uvoffset))+rphase2[i])
					if cw0l > uvthreshold {
						C4 = C4 + ((cw0l - uvthreshold) * uvrand * rng.Float32())
					}
				}
				C4 = C4 * uvsine * ws[n] * cur.Ml[l] * qfactor
				out[n] = out[n] + C3 + C4
			}
		}
	}
}
