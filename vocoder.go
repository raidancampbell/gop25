package p25

import "github.com/raidancampbell/gop25/mbe"

// SeedRand sets the package-level default seed for new decoders' PRNG.
// Exposed for deterministic comparison testing; production callers don't need it.
// New decoders seed their own PRNG from this value at creation time.
var defaultRandSeed uint32 = 1

func SeedRand(seed uint32) {
	defaultRandSeed = seed
}

// IMBEDecoder decodes IMBE voice codewords to 8 kHz float32 PCM via pure Go.
type IMBEDecoder struct {
	cur, prev, prevEnhanced mbe.Parms
	rng                     mbe.Rand
}

// NewIMBEDecoder creates an initialized IMBE decoder.
func NewIMBEDecoder() *IMBEDecoder {
	d := &IMBEDecoder{}
	mbe.InitParms(&d.cur, &d.prev, &d.prevEnhanced)
	d.rng.Seed(defaultRandSeed)
	return d
}

// Decode synthesises 160 float32 PCM samples (20 ms at 8 kHz) from one IMBE
// codeword (88 bits, 1 bit per byte). fecErrs is the FEC error count for
// this codeword (as returned by FECDecode); the vocoder reads it to decide
// whether to trust the decode or repeat the previous frame's parameters
// (the threshold is errs2 > 5). Pass 0 if the codeword's FEC step was skipped
// or the count isn't known.
func (d *IMBEDecoder) Decode(codeword [88]uint8, fecErrs int) (pcm [160]float32, errs int) {
	errs = mbe.ProcessIMBE4400Data(&pcm, codeword, fecErrs, &d.cur, &d.prev, &d.prevEnhanced, &d.rng)
	return
}

// DecodeRaw decodes one IMBE voice codeword from 144 raw transmitted bits
// (in transmission order, before deinterleaving/FEC). Handles deinterleaving
// and FEC internally via IMBEFECDecode. The 144 bits are packed into imbe_fr[8][23]
// using DSD's iW/iX/iY/iZ tables.
func (d *IMBEDecoder) DecodeRaw(rawBits [144]uint8) (pcm [160]float32, errs int) {
	// Some Motorola P25 subscribers transmit a fixed non-Golay-encoded
	// 144-bit DTX comfort-noise frame between speech bursts (observed on
	// uid=11864573, May 14 captures: 277 bit-identical instances). After
	// deinterleave, c0=0x3E4628 is 4 bits from its data's valid Golay
	// codeword but only 3 bits from a different one; the vocoder miscorrects
	// c0, derails the PR sequence, fails all c1-c6 (errs2=11), and
	// frame-repeats the previous syllable -- producing a 30 Hz stutter
	// when interleaved with real speech.
	//
	// Recognize the pattern and return clean silence, advancing prev_mp
	// to silence so the next real codeword starts from a clean baseline.
	if rawBits == imbeDTXFrame {
		mbe.SynthesizeSilence(&pcm)
		mbe.InitParms(&d.cur, &d.prev, &d.prevEnhanced)
		return pcm, 0
	}

	errs = mbe.ProcessIMBE7200x4400Frame(&pcm, rawBits, imbeIW, imbeIX, imbeIY, imbeIZ, &d.cur, &d.prev, &d.prevEnhanced, &d.rng)
	return
}

// IsDTXFrame reports whether a raw 144-bit IMBE codeword matches the
// Motorola P25 DTX comfort-noise pattern (see imbeDTXFrame below).
// Callers that bypass DecodeRaw (e.g., decryption flows that call
// FECDecode+Decode) should check this and emit silence + Reset() instead.
func IsDTXFrame(rawBits [144]uint8) bool {
	return rawBits == imbeDTXFrame
}

// imbeDTXFrame is the on-air Motorola P25 DTX comfort-noise IMBE codeword
// (raw 144 bits, transmission order, before deinterleave). Built at init
// from the packed hex pattern observed in May 14 captures.
var imbeDTXFrame [144]uint8

func init() {
	for i, b := range [18]byte{
		0x6f, 0xce, 0x96, 0xbb, 0x15, 0x22, 0xe0, 0x13, 0x04,
		0x9f, 0xa5, 0x4a, 0x31, 0x80, 0x90, 0x70, 0x41, 0x14,
	} {
		for j := range 8 {
			imbeDTXFrame[i*8+j] = (b >> uint(7-j)) & 1
		}
	}
}

// DSD's P25 Phase1 IMBE interleave schedule (from p25p1_const.h)
var imbeIW = [72]int{
	0, 2, 4, 1, 3, 5,
	0, 2, 4, 1, 3, 6,
	0, 2, 4, 1, 3, 6,
	0, 2, 4, 1, 3, 6,
	0, 2, 4, 1, 3, 6,
	0, 2, 4, 1, 3, 6,
	0, 2, 5, 1, 3, 6,
	0, 2, 5, 1, 3, 6,
	0, 2, 5, 1, 3, 7,
	0, 2, 5, 1, 3, 7,
	0, 2, 5, 1, 4, 7,
	0, 3, 5, 2, 4, 7,
}

var imbeIX = [72]int{
	22, 20, 10, 20, 18, 0,
	20, 18, 8, 18, 16, 13,
	18, 16, 6, 16, 14, 11,
	16, 14, 4, 14, 12, 9,
	14, 12, 2, 12, 10, 7,
	12, 10, 0, 10, 8, 5,
	10, 8, 13, 8, 6, 3,
	8, 6, 11, 6, 4, 1,
	6, 4, 9, 4, 2, 6,
	4, 2, 7, 2, 0, 4,
	2, 0, 5, 0, 13, 2,
	0, 21, 3, 21, 11, 0,
}

var imbeIY = [72]int{
	1, 3, 5, 0, 2, 4,
	1, 3, 6, 0, 2, 4,
	1, 3, 6, 0, 2, 4,
	1, 3, 6, 0, 2, 4,
	1, 3, 6, 0, 2, 4,
	1, 3, 6, 0, 2, 5,
	1, 3, 6, 0, 2, 5,
	1, 3, 6, 0, 2, 5,
	1, 3, 6, 0, 2, 5,
	1, 3, 7, 0, 2, 5,
	1, 4, 7, 0, 3, 5,
	2, 4, 7, 1, 3, 5,
}

var imbeIZ = [72]int{
	21, 19, 1, 21, 19, 9,
	19, 17, 14, 19, 17, 7,
	17, 15, 12, 17, 15, 5,
	15, 13, 10, 15, 13, 3,
	13, 11, 8, 13, 11, 1,
	11, 9, 6, 11, 9, 14,
	9, 7, 4, 9, 7, 12,
	7, 5, 2, 7, 5, 10,
	5, 3, 0, 5, 3, 8,
	3, 1, 5, 3, 1, 6,
	1, 14, 3, 1, 22, 4,
	22, 12, 1, 22, 20, 2,
}

// FECDecode applies IMBE forward-error-correction to a raw 144-bit on-air
// codeword and returns the 88-bit packed u-vector plus the FEC error count.
// This is the layer ADP and AES encryption operate on (encryption XORs the
// post-FEC u-vector, not the FEC-protected on-air bits).
//
// The 88-bit output is packed MSB-first into 11 bytes ready to be fed to
// IMBEDecoder.Decode after any decryption step. Returns (packed, totalErrs)
// where totalErrs sums the C0 Golay errors and the C1..C6 FEC errors.
//
// Pipeline: pack 144 raw bits into imbe_fr[8][23] via the iW/iX/iY/iZ
// deinterleave schedule (same as DecodeRaw); run Golay-23 on C0,
// derive the PR sequence and XOR-demodulate, then run Golay-23 on
// C1..C3 and Hamming-15 on C4..C6, writing 88 bits to imbe_d.
func (d *IMBEDecoder) FECDecode(rawBits [144]uint8) (packed [11]byte, errs int) {
	packed, _, errs = mbe.IMBEFECDecode(rawBits, imbeIW, imbeIX, imbeIY, imbeIZ)
	return
}

// Reset reinitializes the IMBE decoder state, discarding any accumulated pitch
// and spectral information. Call this at P25 call boundaries (TDU/HDU) to
// prevent the vocoder state from one call from contaminating the next.
// NOTE: Reset does NOT re-seed this decoder's PRNG, so the unvoiced-phase
// stream continues uninterrupted across calls. Unlike the old CGO path (which
// shared one global libc rand() across all decoders), each decoder now owns an
// independent deterministic MINSTD stream seeded at construction (see SeedRand).
func (d *IMBEDecoder) Reset() {
	mbe.InitParms(&d.cur, &d.prev, &d.prevEnhanced)
}

// Close releases decoder resources. The decoder should not be used after Close.
func (d *IMBEDecoder) Close() {
	// Pure Go: nothing to free.
}

// PitchPeriod returns the pitch period T in samples at 8 kHz for the most
// recently decoded frame. Returns 0 for unvoiced/silence.
func (d *IMBEDecoder) PitchPeriod() int {
	return d.cur.PitchPeriod()
}

// IsVoiced returns true if more than half the harmonics are voiced.
func (d *IMBEDecoder) IsVoiced() bool {
	return d.cur.IsVoiced()
}

// AMBE2Decoder decodes AMBE+2 voice codewords (P25 Phase 2 / TDMA) to 8 kHz
// float32 PCM via pure Go. Each codeword is 49 decoded parameter bits.
type AMBE2Decoder struct {
	cur, prev, prevEnhanced mbe.Parms
	rng                     mbe.Rand
}

// NewAMBE2Decoder creates an initialized AMBE+2 decoder.
func NewAMBE2Decoder() *AMBE2Decoder {
	d := &AMBE2Decoder{}
	mbe.InitParms(&d.cur, &d.prev, &d.prevEnhanced)
	d.rng.Seed(defaultRandSeed)
	return d
}

// Decode synthesises 160 float32 PCM samples (20 ms at 8 kHz) from one
// AMBE+2 voice codeword (49 decoded parameter bits, 1 bit per byte).
// fecErrs is the FEC error count from the voice codeword's Golay decode.
func (d *AMBE2Decoder) Decode(ambeD [49]uint8, fecErrs int) (pcm [160]float32, errs int) {
	errs = mbe.ProcessAMBE2450Data(&pcm, ambeD, fecErrs, &d.cur, &d.prev, &d.prevEnhanced, &d.rng)
	return
}

// Reset reinitializes the AMBE+2 decoder state.
func (d *AMBE2Decoder) Reset() {
	mbe.InitParms(&d.cur, &d.prev, &d.prevEnhanced)
}

// Close releases decoder resources.
func (d *AMBE2Decoder) Close() {}

// PitchPeriod returns the pitch period T in samples at 8 kHz for the most
// recently decoded frame. Returns 0 for unvoiced/silence.
func (d *AMBE2Decoder) PitchPeriod() int {
	return d.cur.PitchPeriod()
}

// IsVoiced returns true if more than half the harmonics are voiced.
func (d *AMBE2Decoder) IsVoiced() bool {
	return d.cur.IsVoiced()
}
