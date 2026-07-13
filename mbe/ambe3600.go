package mbe

// AMBE+2 3600x2450 frame front-end (FEC + descramble + ambe_d assembly).
//
// This file ports the FRONT half of the AMBE+2 3600x2450 pipeline from the
// libmbe C reference (ambe3600x2450.c): converting a received AMBE frame
// ambe_fr[4][24] into the 49-bit ambe_d[49] that DecodeAMBE2450Parms /
// ProcessAMBE2450Data (the BACK half, in ambe2450.go) consumes. The DMR voice
// codec is the SAME codec libmbe calls "Ambe3600x2450".
//
// Faithful translation: index ranges, integer widths, and call order match the
// C exactly. Bit-exactness vs libmbe was originally proven by a cgo differential
// oracle (since removed to keep the codebase cgo-free).
//
// NOTE: this file is PURE GO with NO build tags and NO cgo.

// eccAmbe3600x2450C0 — faithful port of mbe_eccAmbe3600x2450C0
// (ambe3600x2450.c lines 77-98). Runs Golay(23,12) on row 0 (C0): copies
// ambe_fr[0][1..23] into a 23-element buffer, error-corrects via Golay2312,
// writes the corrected bits back to ambe_fr[0][1..23], and returns the error
// count. Reuses mbe.Golay2312 (ecc.go); C's mbe_golay2312(in,out) takes 23-char
// arrays, and the index mapping C in[j] = ambe_fr[0][j+1] is preserved exactly.
func eccAmbe3600x2450C0(ambeFr *[4][24]uint8) int {
	// C lines 84-87: for (j=0;j<23;j++) in[j] = ambe_fr[0][j+1];
	var in [23]uint8
	for j := 0; j < 23; j++ {
		in[j] = ambeFr[0][j+1]
	}
	// C line 88: errs = mbe_golay2312(in, out);
	out, errs := Golay2312(in)
	// C lines 91-94: for (j=0;j<23;j++) ambe_fr[0][j+1] = out[j];
	for j := 0; j < 23; j++ {
		ambeFr[0][j+1] = out[j]
	}
	return errs
}

// demodulateAmbe3600x2450Data — faithful port of mbe_demodulateAmbe3600x2450Data
// (ambe3600x2450.c lines 556-587). Builds a 24-entry pseudo-random sequence pr[]
// from the C0 MSBs (ambe_fr[0][12..23]) and XOR-descrambles ambe_fr[1][22..0]
// with pr[1..23].
//
// Integer-width fidelity: C declares `unsigned short pr[115]` and
// `unsigned short foo`. The LCG core 173*pr[i-1]+13849 is computed in C `int`
// (integer promotion) before the explicit mod-65536, and the result is stored
// back into the `unsigned short` pr[i] (16-bit truncation). We replicate by
// computing the LCG step in int and storing into a uint16, which reproduces the
// implicit mod-65536 wraparound exactly. foo is uint16 to match the C
// `unsigned short` shift accumulation.
func demodulateAmbe3600x2450Data(ambeFr *[4][24]uint8) {
	var pr [115]uint16
	var foo uint16

	// C lines 564-568: create pseudo-random modulator from ambe_fr[0][12..23].
	// for (i=23;i>=12;i--){ foo<<=1; foo |= ambe_fr[0][i]; }
	for i := 23; i >= 12; i-- {
		foo <<= 1
		foo |= uint16(ambeFr[0][i])
	}
	// C line 569: pr[0] = (16 * foo);  (16*foo truncated into unsigned short)
	pr[0] = uint16(16 * uint32(foo))
	// C lines 570-573: LCG. The explicit form is
	//   pr[i] = (173*pr[i-1])+13849 - (65536 * (((173*pr[i-1])+13849)/65536));
	// i.e. (173*pr[i-1]+13849) mod 65536 — reproduced by uint16 truncation.
	for i := 1; i < 24; i++ {
		pr[i] = uint16((173 * int(pr[i-1])) + 13849)
	}
	// C lines 574-577: pr[i] = pr[i] / 32768;  (now pr[i] is 0 or 1)
	for i := 1; i < 24; i++ {
		pr[i] = pr[i] / 32768
	}

	// C lines 580-585: demodulate ambe_fr[1] with pr.
	// k=1; for (j=22;j>=0;j--){ ambe_fr[1][j] ^= pr[k]; k++; }
	k := 1
	for j := 22; j >= 0; j-- {
		ambeFr[1][j] = ambeFr[1][j] ^ uint8(pr[k])
		k++
	}
}

// eccAmbe3600x2450Data — faithful port of mbe_eccAmbe3600x2450Data
// (ambe3600x2450.c lines 99-141). Fills ambeD[49] from the (already
// C0-corrected, row-1-descrambled) frame:
//   - C0: copy ambe_fr[0][23..12]            (j=23;j>11;j--   => 12 bits)
//   - C1: Golay(23,12) on ambe_fr[1][0..22], then copy gout[22..11]
//     (j=22;j>10;j--   => 12 bits)
//   - C2: copy ambe_fr[2][10..0]             (j=10;j>=0;j--   => 11 bits)
//   - C3: copy ambe_fr[3][13..0]             (j=13;j>=0;j--   => 14 bits)
//
// Total = 12+12+11+14 = 49. Returns the C1 Golay error count.
func eccAmbe3600x2450Data(ambeFr *[4][24]uint8, ambeD *[49]uint8) int {
	pos := 0

	// C lines 107-112: just copy C0. for (j=23;j>11;j--) *ambe++ = ambe_fr[0][j];
	for j := 23; j > 11; j-- {
		ambeD[pos] = ambeFr[0][j]
		pos++
	}

	// C lines 114-124: ecc and copy C1.
	// for (j=0;j<23;j++) gin[j]=ambe_fr[1][j]; errs=golay2312(gin,gout);
	var gin [23]uint8
	for j := 0; j < 23; j++ {
		gin[j] = ambeFr[1][j]
	}
	gout, errs := Golay2312(gin)
	// for (j=22;j>10;j--) *ambe++ = gout[j];
	for j := 22; j > 10; j-- {
		ambeD[pos] = gout[j]
		pos++
	}

	// C lines 126-131: just copy C2. for (j=10;j>=0;j--) *ambe++ = ambe_fr[2][j];
	for j := 10; j >= 0; j-- {
		ambeD[pos] = ambeFr[2][j]
		pos++
	}

	// C lines 133-138: just copy C3. for (j=13;j>=0;j--) *ambe++ = ambe_fr[3][j];
	for j := 13; j >= 0; j-- {
		ambeD[pos] = ambeFr[3][j]
		pos++
	}

	return errs
}

// ProcessAMBE3600x2450Frame — faithful port of mbe_processAmbe3600x2450Framef
// (ambe3600x2450.c lines 661-673). Runs the full AMBE+2 3600x2450 frame
// pipeline: C0 Golay FEC -> row-1 PR descramble -> C1 Golay FEC + ambe_d
// assembly -> ProcessAMBE2450Data synthesis. Returns 160 PCM samples (written to
// out) plus errs (C0 Golay errors) and errs2 (errs + C1 Golay errors).
//
// Mirrors the C driver exactly:
//
//	*errs  = mbe_eccAmbe3600x2450C0(ambe_fr);
//	mbe_demodulateAmbe3600x2450Data(ambe_fr);
//	*errs2 = *errs;
//	*errs2 += mbe_eccAmbe3600x2450Data(ambe_fr, ambe_d);
//	mbe_processAmbe2450Dataf(aout, errs, errs2, ..., ambe_d, ..., uvquality=3);
//
// Critically, mbe_processAmbe2450Dataf reads *errs2 but does NOT modify *errs,
// so the returned errs stays the C0 Golay count (it is NOT overwritten by the
// synthesis step). ProcessAMBE2450Data's own return value (== errs2 on entry)
// is therefore discarded here, exactly matching C.
//
// Note ambeFr is passed by value into this function but eccC0/demod mutate a
// local copy; that matches the C semantics where the caller's frame buffer is
// scratch and only ambe_d / the PCM output are consumed downstream.
func ProcessAMBE3600x2450Frame(out *[160]float32, ambeFr [4][24]uint8, cur, prev, enhanced *Parms, rng *Rand) (errs, errs2 int) {
	errs = eccAmbe3600x2450C0(&ambeFr)
	demodulateAmbe3600x2450Data(&ambeFr)
	errs2 = errs
	var ambeD [49]uint8
	errs2 += eccAmbe3600x2450Data(&ambeFr, &ambeD)
	// C: mbe_processAmbe2450Dataf(aout, &errs, &errs2, ...) with uvquality=3.
	// It uses errs2 to decide the repeat path; it leaves errs unchanged.
	ProcessAMBE2450Data(out, ambeD, errs2, cur, prev, enhanced, rng)
	return errs, errs2
}
