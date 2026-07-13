package mbe

// IMBEFECDecode applies IMBE forward-error-correction to a raw 144-bit on-air
// codeword and returns the 88-bit packed u-vector plus the FEC error count.
// This is the layer ADP and AES encryption operate on (encryption XORs the
// post-FEC u-vector, not the FEC-protected on-air bits).
//
// The 88-bit output is packed MSB-first into 11 bytes. Returns (packed, imbeD, totalErrs)
// where imbeD is the unpacked 88-bit array and totalErrs sums the C0 Golay errors
// and the C1..C6 FEC errors.
//
// Pipeline: deinterleave 144 raw bits into imbe_fr[8][23] via the iW/iX/iY/iZ
// schedule; run Golay-23 on C0, derive the PR sequence and XOR-demodulate,
// then run Golay-23 on C1..C3 and Hamming-15 on C4..C6, writing 88 bits to imbeD.
func IMBEFECDecode(rawBits [144]uint8, iw, ix, iy, iz [72]int) (packed [11]byte, imbeD [88]uint8, errs int) {
	// Deinterleave 144 transmitted bits into imbe_fr[8][23]
	var imbeFr [8][23]uint8
	for j := 0; j < 72; j++ {
		imbeFr[iw[j]][ix[j]] = rawBits[j*2]   // MSB of dibit
		imbeFr[iy[j]][iz[j]] = rawBits[j*2+1] // LSB of dibit
	}

	// Step 1: mbe_eccImbe7200x4400C0 - Golay-2312 on row 0
	errs += eccImbe7200x4400C0(&imbeFr)

	// Step 2: mbe_demodulateImbe7200x4400Data - build PR sequence and XOR-descramble
	demodulateImbe7200x4400Data(&imbeFr)

	// Step 3: mbe_eccImbe7200x4400Data - FEC decode and extract 88 bits
	errs += eccImbe7200x4400Data(&imbeFr, &imbeD)

	// Pack 88 bits MSB-first into 11 bytes
	for i := 0; i < 88; i++ {
		packed[i/8] |= (imbeD[i] & 1) << uint(7-i%8)
	}

	return packed, imbeD, errs
}

// eccImbe7200x4400C0 applies Golay-2312 FEC to row 0 of the IMBE frame.
// Translates mbe_eccImbe7200x4400C0 from mbelib/imbe7200x4400.c.
func eccImbe7200x4400C0(imbeFr *[8][23]uint8) int {
	var in, out [23]uint8
	for j := 0; j < 23; j++ {
		in[j] = imbeFr[0][j]
	}
	out, errs := Golay2312(in)
	for j := 0; j < 23; j++ {
		imbeFr[0][j] = out[j]
	}
	return errs
}

// demodulateImbe7200x4400Data builds the pseudo-random modulator sequence
// from row 0 and XOR-descrambles rows 1..6.
// Translates mbe_demodulateImbe7200x4400Data from mbelib/imbe7200x4400.c.
func demodulateImbe7200x4400Data(imbeFr *[8][23]uint8) {
	// Build modulator seed from row0 bits 22..11 (12 bits) as a binary integer
	foo := uint16(0)
	for i := 22; i >= 11; i-- {
		foo = (foo << 1) | uint16(imbeFr[0][i]&1)
	}

	// Generate PR sequence
	var pr [115]uint16
	pr[0] = 16 * foo
	for i := 1; i < 115; i++ {
		// (173*pr[i-1] + 13849) mod 65536 using uint16 wraparound
		pr[i] = (173*pr[i-1] + 13849) & 0xFFFF
	}
	// Convert to 0/1 bits
	for i := 1; i < 115; i++ {
		pr[i] = pr[i] / 32768 // 0 if < 32768, 1 if >= 32768
	}

	// XOR-descramble
	k := 1
	for i := 1; i < 4; i++ {
		for j := 22; j >= 0; j-- {
			imbeFr[i][j] ^= uint8(pr[k] & 1)
			k++
		}
	}
	for i := 4; i < 7; i++ {
		for j := 14; j >= 0; j-- {
			imbeFr[i][j] ^= uint8(pr[k] & 1)
			k++
		}
	}
}

// eccImbe7200x4400Data applies FEC (Golay + Hamming) and extracts the 88-bit imbeD.
// Translates mbe_eccImbe7200x4400Data from mbelib/imbe7200x4400.c.
func eccImbe7200x4400Data(imbeFr *[8][23]uint8, imbeD *[88]uint8) int {
	errs := 0
	idx := 0

	// Rows 0..3: each produces 12 bits (bits 22..11)
	for i := 0; i < 4; i++ {
		if i > 0 {
			// Rows 1..3: apply Golay-2312
			var gin, gout [23]uint8
			for j := 0; j < 23; j++ {
				gin[j] = imbeFr[i][j]
			}
			gout, e := Golay2312(gin)
			errs += e
			// Extract bits 22..11 (12 bits)
			for j := 22; j > 10; j-- {
				imbeD[idx] = gout[j]
				idx++
			}
		} else {
			// Row 0: already corrected, just copy bits 22..11
			for j := 22; j > 10; j-- {
				imbeD[idx] = imbeFr[0][j]
				idx++
			}
		}
	}

	// Rows 4..6: each produces 11 bits (bits 14..4)
	for i := 4; i < 7; i++ {
		var hin, hout [15]uint8
		for j := 0; j < 15; j++ {
			hin[j] = imbeFr[i][j]
		}
		hout, e := Hamming1511(hin)
		errs += e
		// Extract bits 14..4 (11 bits)
		for j := 14; j >= 4; j-- {
			imbeD[idx] = hout[j]
			idx++
		}
	}

	// Row 7: 7 bits (bits 6..0)
	for j := 6; j >= 0; j-- {
		imbeD[idx] = imbeFr[7][j]
		idx++
	}

	// Total: 4*12 + 3*11 + 7 = 48 + 33 + 7 = 88 bits
	return errs
}

// bitsToInt converts a slice of 0/1 bits to an integer (MSB-first).
func bitsToInt(bits []uint8) int {
	val := 0
	for _, b := range bits {
		val = (val << 1) | int(b&1)
	}
	return val
}

// DecodeIMBE4400Parms decodes IMBE 4400 parameters from an 88-bit codeword.
// Translates mbe_decodeImbe4400Parms from mbelib/imbe7200x4400.c lines 166-462.
// Returns true (bad) if fundamental frequency or L are invalid.
func DecodeIMBE4400Parms(imbeD [88]uint8, cur, prev *Parms) bool {
	const pi = 3.141592653589793

	// Copy repeat from prev
	cur.Repeat = prev.Repeat

	// Decode b0 from bits [0..5] + [85,86] (8 bits MSB-first)
	b0 := bitsToInt([]uint8{imbeD[0], imbeD[1], imbeD[2], imbeD[3], imbeD[4], imbeD[5], imbeD[85], imbeD[86]})
	if b0 > 207 {
		return true // silence or invalid
	}
	cur.W0 = (4 * pi) / (float32(b0) + 39.5)

	// Decode L from w0 - note: C truncates inner expression to int before multiplying
	L := int(0.9254 * float64(int(pi/float64(cur.W0)+0.25)))
	if L > 56 || L < 9 {
		return true
	}
	cur.L = L
	L9 := L - 9

	// Decode K from L
	if L < 37 {
		cur.K = (L + 2) / 3
	} else {
		cur.K = 12
	}
	K := cur.K

	// Read bits from imbeD[6..84] into bb[58][12] using bo[L9] schedule
	var bb [58][12]uint8
	for i := 6; i < 85; i++ {
		row := bo[L9][i-6][0]
		col := bo[L9][i-6][1]
		bb[row][col] = imbeD[i]
	}

	// Decode Vl[1..L] from bb[1][k]
	j := 1
	k := K - 1
	for l := 1; l <= L; l++ {
		cur.Vl[l] = int(bb[1][k])
		if j == 3 {
			j = 1
			if k > 0 {
				k--
			}
		} else {
			j++
		}
	}

	// Decode G1 from bb[2][5..0] (reversed)
	b2idx := bitsToInt([]uint8{bb[2][5], bb[2][4], bb[2][3], bb[2][2], bb[2][1], bb[2][0]})
	var Gm [7]float32
	Gm[1] = b2[b2idx]

	// Decode G2..G6 from bb[3..7] using ba[L9] schedule
	for i := 2; i < 7; i++ {
		length := int(ba[L9][i-2][0])
		scale := ba[L9][i-2][1]
		var bmBits []uint8
		for j := length - 1; j >= 0; j-- {
			bmBits = append(bmBits, bb[i+1][j])
		}
		bm := bitsToInt(bmBits)
		Gm[i] = scale * (float32(bm) - powf(2, float32(length-1)) + 0.5)
	}

	// Inverse DCT: Gm[1..6] -> Ri[1..6]
	var Ri [7]float32
	for i := 1; i <= 6; i++ {
		sum := float32(0)
		for m := 1; m <= 6; m++ {
			am := 1
			if m != 1 {
				am = 2
			}
			sum += float32(am) * Gm[m] * cosf((pi*float32(m-1)*(float32(i)-0.5))/6)
		}
		Ri[i] = sum
	}

	// Load b8..bL+1 into Cik[i][k] using imbeJi, hoba, quantstep, standdev
	var Cik [7][11]float32
	m := 8
	for i := 1; i <= 6; i++ {
		Cik[i][1] = Ri[i]
		ji := imbeJi[L9][i-1]
		for k := 2; k <= ji; k++ {
			Bm := hoba[L9][m-8]
			if Bm == 0 {
				Cik[i][k] = 0
			} else {
				var bmBits []uint8
				for b := 0; b < Bm; b++ {
					bmBits = append(bmBits, bb[m][(Bm-b)-1])
				}
				bm := bitsToInt(bmBits)
				Cik[i][k] = (quantstep[Bm-1] * standdev[k-2]) * (float32(bm) - powf(2, float32(Bm-1)) + 0.5)
			}
			m++
		}
	}

	// Inverse DCT: Cik[i][k] -> Tl[l]
	var Tl [57]float32
	l := 1
	for i := 1; i <= 6; i++ {
		ji := imbeJi[L9][i-1]
		for jj := 1; jj <= ji; jj++ {
			sum := float32(0)
			for k := 1; k <= ji; k++ {
				ak := 1
				if k != 1 {
					ak = 2
				}
				sum += float32(ak) * Cik[i][k] * cosf((pi*float32(k-1)*(float32(jj)-0.5))/float32(ji))
			}
			Tl[l] = sum
			l++
		}
	}

	// Determine rho
	var rho float32
	if cur.L <= 15 {
		rho = 0.4
	} else if cur.L <= 24 {
		rho = 0.03*float32(cur.L) - 0.05
	} else {
		rho = 0.7
	}

	// Fix for L > prev.L
	if cur.L > prev.L {
		for ll := prev.L + 1; ll <= cur.L; ll++ {
			prev.Ml[ll] = prev.Ml[prev.L]
			prev.Log2Ml[ll] = prev.Log2Ml[prev.L]
		}
	}

	// Part 1: Sum77 (eq 75-77)
	var flokl [57]float32
	var intkl [57]int
	var deltal [57]float32
	Sum77 := float32(0)
	for ll := 1; ll <= cur.L; ll++ {
		flokl[ll] = (float32(prev.L) / float32(cur.L)) * float32(ll)
		intkl[ll] = int(flokl[ll])
		deltal[ll] = flokl[ll] - float32(intkl[ll])
		Sum77 += ((1 - deltal[ll]) * prev.Log2Ml[intkl[ll]]) + (deltal[ll] * prev.Log2Ml[intkl[ll]+1])
	}
	Sum77 = (rho / float32(cur.L)) * Sum77

	// Part 2: log2Ml and Ml
	for ll := 1; ll <= cur.L; ll++ {
		c1 := rho * (1 - deltal[ll]) * prev.Log2Ml[intkl[ll]]
		c2 := rho * deltal[ll] * prev.Log2Ml[intkl[ll]+1]
		cur.Log2Ml[ll] = Tl[ll] + c1 + c2 - Sum77
		cur.Ml[ll] = powf(2, cur.Log2Ml[ll])
	}

	return false
}

// ProcessIMBE4400Data processes an 88-bit IMBE 4400 codeword and synthesizes 160 PCM samples.
// Translates mbe_processImbe4400Dataf from mbelib/imbe7200x4400.c lines 514-552.
func ProcessIMBE4400Data(out *[160]float32, imbeD [88]uint8, errs2 int, cur, prev, enhanced *Parms, rng *Rand) int {
	bad := DecodeIMBE4400Parms(imbeD, cur, prev)
	if bad || errs2 > 5 {
		UseLastParms(cur, prev)
		cur.Repeat++
	} else {
		cur.Repeat = 0
	}

	if cur.Repeat <= 3 {
		MoveParms(cur, prev)
		SpectralAmpEnhance(cur)
		SynthesizeSpeech(out, cur, enhanced, 3, rng)
		MoveParms(cur, enhanced)
	} else {
		SynthesizeSilence(out)
		InitParms(cur, prev, enhanced)
	}

	return errs2
}

// ProcessIMBE7200x4400Frame processes a full 144-bit on-air IMBE frame (FEC + decode + synth).
// Translates mbe_processImbe7200x4400Framef from mbelib/imbe7200x4400.c lines 564-575.
func ProcessIMBE7200x4400Frame(out *[160]float32, raw [144]uint8, iw, ix, iy, iz [72]int, cur, prev, enhanced *Parms, rng *Rand) int {
	_, imbeD, errs := IMBEFECDecode(raw, iw, ix, iy, iz)
	return ProcessIMBE4400Data(out, imbeD, errs, cur, prev, enhanced, rng)
}
