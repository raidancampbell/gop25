package mbe

import "math"

// DecodeAMBE2450Parms decodes AMBE+2 (P25 Phase 2 / TDMA) voice parameters from a 49-bit codeword.
// Returns bad: 0=ok, 2=erasure, 3=tone.
// Faithful translation of mbe_decodeAmbe2450Parms (internal/p25/mbelib/ambe3600x2450.c lines 143-555).
func DecodeAMBE2450Parms(ambeD [49]uint8, cur, prev *Parms) (bad int) {
	var ji, i, j, k, l, L, m, am, ak int
	var intkl [57]int
	var b0, b1, b2, b3, b4, b5, b6, b7, b8 int
	var f0, deltaGamma, BigGamma float32
	var Cik [5][18]float32
	var flokl, deltal, Tl [57]float32
	var Gm, Ri [9]float32
	var sum, c1, c2, Sum42, Sum43 float32
	var silence int
	var Ji [5]int
	var jl int
	var unvc, rconst float32

	silence = 0

	// copy repeat from prev
	cur.Repeat = prev.Repeat

	// decode fundamental frequency w0 from b0
	b0 = 0
	b0 |= int(ambeD[0]) << 6
	b0 |= int(ambeD[1]) << 5
	b0 |= int(ambeD[2]) << 4
	b0 |= int(ambeD[3]) << 3
	b0 |= int(ambeD[37]) << 2
	b0 |= int(ambeD[38]) << 1
	b0 |= int(ambeD[39])

	if b0 >= 120 && b0 <= 123 {
		// erasure frame
		return 2
	} else if b0 == 124 || b0 == 125 {
		// silence frame
		silence = 1
		cur.W0 = (float32(2) * float32(math.Pi)) / float32(32)
		f0 = float32(1) / float32(32)
		L = 14
		cur.L = 14
		for l = 1; l <= L; l++ {
			cur.Vl[l] = 0
		}
	} else if b0 == 126 || b0 == 127 {
		// tone frame
		return 3
	}

	if silence == 0 {
		f0 = ambeW0Table[b0]
		cur.W0 = f0 * float32(2) * float32(math.Pi)
	}

	unvc = float32(0.2046) / sqrtf(cur.W0)

	// decode L
	if silence == 0 {
		L = int(ambeLtable[b0])
		cur.L = L
	}

	// decode V/UV parameters
	b1 = 0
	b1 |= int(ambeD[4]) << 4
	b1 |= int(ambeD[5]) << 3
	b1 |= int(ambeD[6]) << 2
	b1 |= int(ambeD[7]) << 1
	b1 |= int(ambeD[35])

	for l = 1; l <= L; l++ {
		jl = int(float32(l) * float32(16.0) * f0)
		if silence == 0 {
			cur.Vl[l] = ambeVuv[b1][jl]
		}
	}

	// decode gain vector
	b2 = 0
	b2 |= int(ambeD[8]) << 4
	b2 |= int(ambeD[9]) << 3
	b2 |= int(ambeD[10]) << 2
	b2 |= int(ambeD[11]) << 1
	b2 |= int(ambeD[36])

	deltaGamma = ambeDg[b2]
	cur.Gamma = deltaGamma + (float32(0.5) * prev.Gamma)

	// decode PRBA vectors
	Gm[1] = 0

	// load b3 from ambeD (9 bits)
	b3 = 0
	b3 |= int(ambeD[12]) << 8
	b3 |= int(ambeD[13]) << 7
	b3 |= int(ambeD[14]) << 6
	b3 |= int(ambeD[15]) << 5
	b3 |= int(ambeD[16]) << 4
	b3 |= int(ambeD[17]) << 3
	b3 |= int(ambeD[18]) << 2
	b3 |= int(ambeD[19]) << 1
	b3 |= int(ambeD[40])
	Gm[2] = ambePRBA24[b3][0]
	Gm[3] = ambePRBA24[b3][1]
	Gm[4] = ambePRBA24[b3][2]

	// load b4 from ambeD (7 bits)
	b4 = 0
	b4 |= int(ambeD[20]) << 6
	b4 |= int(ambeD[21]) << 5
	b4 |= int(ambeD[22]) << 4
	b4 |= int(ambeD[23]) << 3
	b4 |= int(ambeD[41]) << 2
	b4 |= int(ambeD[42]) << 1
	b4 |= int(ambeD[43])
	Gm[5] = ambePRBA58[b4][0]
	Gm[6] = ambePRBA58[b4][1]
	Gm[7] = ambePRBA58[b4][2]
	Gm[8] = ambePRBA58[b4][3]

	// compute Ri
	for i = 1; i <= 8; i++ {
		sum = 0
		for m = 1; m <= 8; m++ {
			if m == 1 {
				am = 1
			} else {
				am = 2
			}
			sum = sum + (float32(am) * Gm[m] * cosf((float32(math.Pi)*float32(m-1)*(float32(i)-float32(0.5)))/float32(8)))
		}
		Ri[i] = sum
	}

	// generate first two elements of each Ci,k block from PRBA vector
	rconst = (float32(1) / (float32(2) * float32(math.Sqrt2)))
	Cik[1][1] = float32(0.5) * (Ri[1] + Ri[2])
	Cik[1][2] = rconst * (Ri[1] - Ri[2])
	Cik[2][1] = float32(0.5) * (Ri[3] + Ri[4])
	Cik[2][2] = rconst * (Ri[3] - Ri[4])
	Cik[3][1] = float32(0.5) * (Ri[5] + Ri[6])
	Cik[3][2] = rconst * (Ri[5] - Ri[6])
	Cik[4][1] = float32(0.5) * (Ri[7] + Ri[8])
	Cik[4][2] = rconst * (Ri[7] - Ri[8])

	// decode HOC
	b5 = 0
	b5 |= int(ambeD[24]) << 4
	b5 |= int(ambeD[25]) << 3
	b5 |= int(ambeD[26]) << 2
	b5 |= int(ambeD[27]) << 1
	b5 |= int(ambeD[44])

	b6 = 0
	b6 |= int(ambeD[28]) << 3
	b6 |= int(ambeD[29]) << 2
	b6 |= int(ambeD[30]) << 1
	b6 |= int(ambeD[45])

	b7 = 0
	b7 |= int(ambeD[31]) << 3
	b7 |= int(ambeD[32]) << 2
	b7 |= int(ambeD[33]) << 1
	b7 |= int(ambeD[46])

	b8 = 0
	b8 |= int(ambeD[34]) << 2
	b8 |= int(ambeD[47]) << 1
	b8 |= int(ambeD[48])

	// lookup Ji - NOTE: index by L, not L9
	Ji[1] = ambeLmprbl[L][0]
	Ji[2] = ambeLmprbl[L][1]
	Ji[3] = ambeLmprbl[L][2]
	Ji[4] = ambeLmprbl[L][3]

	// Load Ci,k with the values from the HOC tables
	for k = 3; k <= Ji[1]; k++ {
		if k > 6 {
			Cik[1][k] = 0
		} else {
			Cik[1][k] = ambeHOCb5[b5][k-3]
		}
	}
	for k = 3; k <= Ji[2]; k++ {
		if k > 6 {
			Cik[2][k] = 0
		} else {
			Cik[2][k] = ambeHOCb6[b6][k-3]
		}
	}
	for k = 3; k <= Ji[3]; k++ {
		if k > 6 {
			Cik[3][k] = 0
		} else {
			Cik[3][k] = ambeHOCb7[b7][k-3]
		}
	}
	for k = 3; k <= Ji[4]; k++ {
		if k > 6 {
			Cik[4][k] = 0
		} else {
			Cik[4][k] = ambeHOCb8[b8][k-3]
		}
	}

	// inverse DCT each Ci,k to give ci,j (Tl)
	l = 1
	for i = 1; i <= 4; i++ {
		ji = Ji[i]
		for j = 1; j <= ji; j++ {
			sum = 0
			for k = 1; k <= ji; k++ {
				if k == 1 {
					ak = 1
				} else {
					ak = 2
				}
				sum = sum + (float32(ak) * Cik[i][k] * cosf((float32(math.Pi)*float32(k-1)*(float32(j)-float32(0.5)))/float32(ji)))
			}
			Tl[l] = sum
			l++
		}
	}

	// determine log2Ml by applying ci,j to previous log2Ml

	// fix for when L > L(-1)
	if cur.L > prev.L {
		for l = (prev.L) + 1; l <= cur.L; l++ {
			prev.Ml[l] = prev.Ml[prev.L]
			prev.Log2Ml[l] = prev.Log2Ml[prev.L]
		}
	}
	prev.Log2Ml[0] = prev.Log2Ml[1]
	prev.Ml[0] = prev.Ml[1]

	// Part 1
	Sum43 = 0
	for l = 1; l <= cur.L; l++ {
		flokl[l] = (float32(prev.L) / float32(cur.L)) * float32(l)
		intkl[l] = int(flokl[l])
		deltal[l] = flokl[l] - float32(intkl[l])
		Sum43 = Sum43 + (((float32(1) - deltal[l]) * prev.Log2Ml[intkl[l]]) + (deltal[l] * prev.Log2Ml[intkl[l]+1]))
	}
	Sum43 = ((float32(0.65) / float32(cur.L)) * Sum43)

	// Part 2
	Sum42 = 0
	for l = 1; l <= cur.L; l++ {
		Sum42 += Tl[l]
	}
	Sum42 = Sum42 / float32(cur.L)
	// NOTE: C uses double-precision exp/log here
	BigGamma = cur.Gamma - (float32(0.5) * float32(math.Log(float64(cur.L))/math.Log(2))) - Sum42

	// Part 3
	for l = 1; l <= cur.L; l++ {
		c1 = (float32(0.65) * (float32(1) - deltal[l]) * prev.Log2Ml[intkl[l]])
		c2 = (float32(0.65) * deltal[l] * prev.Log2Ml[intkl[l]+1])
		cur.Log2Ml[l] = Tl[l] + c1 + c2 - Sum43 + BigGamma
		// inverse log to generate spectral amplitudes
		// NOTE: C uses double-precision exp here
		if cur.Vl[l] == 1 {
			cur.Ml[l] = float32(math.Exp(float64(0.693) * float64(cur.Log2Ml[l])))
		} else {
			cur.Ml[l] = unvc * float32(math.Exp(float64(0.693)*float64(cur.Log2Ml[l])))
		}
	}

	return 0
}

// ProcessAMBE2450Data decodes an AMBE+2 voice frame and synthesizes 160 PCM samples.
// Returns errs (== errs2 on entry).
// Faithful translation of mbe_processAmbe2450Dataf (internal/p25/mbelib/ambe3600x2450.c lines 588-651).
func ProcessAMBE2450Data(out *[160]float32, ambeD [49]uint8, errs2 int, cur, prev, enhanced *Parms, rng *Rand) (errs int) {
	bad := DecodeAMBE2450Parms(ambeD, cur, prev)
	if bad == 2 {
		// Erasure frame
		cur.Repeat = 0
	} else if bad == 3 {
		// Tone frame
		cur.Repeat = 0
	} else if errs2 > 3 {
		UseLastParms(cur, prev)
		cur.Repeat++
	} else {
		cur.Repeat = 0
	}

	if bad == 0 {
		if cur.Repeat <= 3 {
			MoveParms(cur, prev)
			SpectralAmpEnhance(cur)
			SynthesizeSpeech(out, cur, enhanced, 3, rng)
			MoveParms(cur, enhanced)
		} else {
			SynthesizeSilence(out)
			InitParms(cur, prev, enhanced)
		}
	} else {
		// erasure (2) AND tone (3) both -> silence+init
		SynthesizeSilence(out)
		InitParms(cur, prev, enhanced)
	}
	return errs2
}
