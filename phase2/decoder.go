package phase2

import "github.com/raidancampbell/gop25"

// syncBurstCount is the number of bursts buffered during the offset-detection
// phase. Two full superframes (24 bursts = 720 ms) gives robust statistics.
const syncBurstCount = 24

// Decoder is the Phase 2 receive chain: complex IQ -> classified bursts
// and decoded voice frames.
// State persists across Process() calls; feed contiguous IQ samples.
type Decoder struct {
	demod  *HDQPSKDemod
	framer *Framer
	tdma   *TDMAProcessor

	// Superframe position counter (0..11). Advances by 1 for each burst.
	// -1 = not yet synced.
	superframePos int

	// syncBuf holds bursts during the offset-detection phase (superframePos == -1).
	// Once syncBurstCount bursts are collected, all 12 offsets are tried and the
	// one producing the best voice codeword FEC is selected.
	syncBuf []Burst

	// Counters (diagnostic only).
	BurstsTotal int
	BurstsValid int // ISCH decoded successfully
	VoiceFrames int // voice frames produced
}

// NewDecoder builds a decoder for the given input sample rate (e.g. 25000).
func NewDecoder(sampleRate float64) *Decoder {
	return &Decoder{
		demod:         NewHDQPSKDemod(sampleRate),
		framer:        NewFramer(),
		tdma:          NewTDMAProcessor(),
		superframePos: -1,
	}
}

// SetScrambleParams configures the TDMA descrambling mask. Must be called
// before voice bursts can be decoded. Parameters come from the control channel.
func (d *Decoder) SetScrambleParams(nac uint16, sysid uint16, wacn uint32) {
	d.tdma.SetScrambleParams(nac, sysid, wacn)
}

// SetKeyLookup configures the key-resolution function used for ADP decryption
// of encrypted Phase 2 voice. Thread-safe.
func (d *Decoder) SetKeyLookup(fn KeyLookupFunc) {
	d.tdma.SetKeyLookup(fn)
}

// HasKey reports whether a usable decryption key exists for (algID, keyID).
// Passthrough to the TDMA processor; see TDMAProcessor.HasKey.
func (d *Decoder) HasKey(algID uint8, keyID uint16) bool {
	return d.tdma.HasKey(algID, keyID)
}

// Process consumes IQ and returns classified bursts and decoded voice frames.
// Voice frames are only produced for 4V/2V bursts when scramble params are set.
//
// The processing pipeline for each burst is:
//  1. Assign superframe position from the running counter (or buffer for
//     FEC-guided sync detection if counter not yet initialized).
//  2. Descramble payload (positions 10-179) using the XOR mask at the
//     burst's superframe location.
//  3. Extract DUID and classify from the descrambled burst.
//  4. Feed voice-bearing bursts to the TDMA processor for voice decode.
//
// Superframe offset detection: the ISCH second half (positions 10-19) is in
// the scrambled region, making the (40,9,16) Hamming decode unreliable for
// I-ISCH location extraction. Instead, we buffer the first 24 bursts and
// brute-force all 12 offsets, selecting the one with the most perfect Golay
// c0 decodes in the voice codeword positions.
func (d *Decoder) Process(iq []complex64) ([]Burst, []P2VoiceFrame) {
	dibits := d.demod.Process(iq)
	raw := d.framer.Feed(dibits)
	bursts := make([]Burst, 0, len(raw))
	var voice []P2VoiceFrame

	// Snapshot the XOR mask once per call.
	d.tdma.mu.Lock()
	hasMask := d.tdma.hasMask
	var mask [SuperframeDibits]p25.Dibit
	if hasMask {
		mask = d.tdma.xorMask
	}
	d.tdma.mu.Unlock()

	for _, b := range raw {
		d.BurstsTotal++

		// Phase 1: offset detection — buffer bursts until we have enough
		// to determine the superframe offset via FEC brute-force.
		if d.superframePos < 0 && hasMask {
			d.syncBuf = append(d.syncBuf, b)
			if len(d.syncBuf) >= syncBurstCount {
				d.superframePos = detectOffset(d.syncBuf, mask)
				// Reprocess buffered bursts now that we know the offset.
				for _, sb := range d.syncBuf {
					bs, vfs := d.processBurst(sb, hasMask, mask)
					bursts = append(bursts, bs)
					voice = append(voice, vfs...)
				}
				d.syncBuf = nil
			}
			continue
		}

		// Phase 2: normal processing with known superframe position.
		bs, vfs := d.processBurst(b, hasMask, mask)
		bursts = append(bursts, bs)
		voice = append(voice, vfs...)
	}
	return bursts, voice
}

// processBurst handles a single burst with known superframe position.
func (d *Decoder) processBurst(b Burst, hasMask bool, mask [SuperframeDibits]p25.Dibit) (Burst, []P2VoiceFrame) {
	// Snapshot the raw (pre-descramble) dibits: op25 extracts the DUID and
	// decodes UNSCRAMBLED control ACCH from the raw burst.
	b.Raw = b.Dibits

	// Assign superframe position and advance counter.
	expectedLocation := -1
	if d.superframePos >= 0 {
		expectedLocation = d.superframePos
		b.ISCH.Location = expectedLocation
		b.ISCH.Slot = WhichSlot[expectedLocation]
		d.superframePos = (d.superframePos + 1) % SuperframeBursts
	}

	// Descramble payload if mask is available and location is known.
	if hasMask && b.ISCH.Location >= 0 {
		// Decode the ISCH from the RAW burst, before descrambling. Descramble
		// XORs dibits 10..179, which overlaps ISCH dibits 10..19, so reading
		// the ISCH afterwards decodes a half-corrupted codeword. The ISCH is
		// not scrambled on the air: it has to be readable to establish slot
		// and location before the payload can be descrambled at all.
		decoded := DecodeISCH(ischDibits(b.Raw))
		b = Descramble(b, mask)
		if decoded.Valid && !decoded.IsSISCH && decoded.Location == expectedLocation {
			b.ISCH = decoded
			d.BurstsValid++
		} else if decoded.IsSISCH {
			// S-ISCH does not carry a location. Retain the position and slot
			// established by the running superframe counter so the burst remains
			// eligible for descrambling and TDMA voice/control processing.
			b.ISCH = ISCHInfo{
				Location: expectedLocation,
				Slot:     WhichSlot[expectedLocation],
				IsSISCH:  true,
				Valid:    true,
			}
			d.BurstsValid++
		} else {
			b.ISCH = ISCHInfo{Location: -1, Slot: -1}
		}
	} else if expectedLocation >= 0 {
		b.ISCH.Valid = true
		d.BurstsValid++
	}

	// Extract DUID from the RAW burst and classify (FEC-first, DUID-fallback).
	b.DUID = extractDUID(Burst{Dibits: b.Raw})
	b.Type = Classify(b)

	// Feed to TDMA processor for voice OR control decode.
	var voice []P2VoiceFrame
	if vf := d.tdma.ProcessBurst(b); vf != nil {
		d.VoiceFrames++
		voice = append(voice, *vf)
	}
	return b, voice
}

func ischDibits(dibits [BurstDibits]p25.Dibit) [SyncDibits]p25.Dibit {
	var out [SyncDibits]p25.Dibit
	copy(out[:], dibits[:SyncDibits])
	return out
}

// detectOffset brute-forces all 12 superframe offsets on the buffered bursts
// and returns the offset (0..11) that produces the most perfect Golay c0
// decodes in voice codeword positions. This is extremely reliable: with the
// correct offset, ~33% of CWs have perfect c0; with wrong offsets, ~0.05%.
func detectOffset(bursts []Burst, mask [SuperframeDibits]p25.Dibit) int {
	bestOffset := 0
	bestScore := -1
	for offset := 0; offset < SuperframeBursts; offset++ {
		score := 0
		for idx, b := range bursts {
			pos := (idx + offset) % SuperframeBursts
			trial := b
			trial.ISCH.Location = pos
			trial = Descramble(trial, mask)
			for _, vcwOff := range []int{
				PayloadOffset + VCW1Offset,
				PayloadOffset + VCW2Offset,
				PayloadOffset + VCW3Offset,
				PayloadOffset + VCW4Offset,
			} {
				if vcwOff+VoiceCWDibits > BurstDibits {
					continue
				}
				vcw := trial.Dibits[vcwOff : vcwOff+VoiceCWDibits]
				c0, _, _, _ := extractVCW(vcw)
				_, errs0, ok0 := p25.Golay24Decode(c0)
				if ok0 && errs0 == 0 {
					score++
				}
			}
		}
		if score > bestScore {
			bestScore = score
			bestOffset = offset
		}
	}
	// The counter should start at (offset + len(bursts)) % 12 because
	// we'll reprocess the buffered bursts starting from offset.
	// But we return just the offset; the caller sets superframePos to
	// offset (and advances during reprocessing).
	return bestOffset
}

// EVM returns the demodulator's RMS Error Vector Magnitude.
func (d *Decoder) EVM() float64 { return d.demod.EVM() }

// ResetStats clears EVM accumulators without affecting demod state.
func (d *Decoder) ResetStats() { d.demod.ResetStats() }

// Reset reinitializes the decoder's demod, framer, and per-slot state so that
// stale inter-block state does not contaminate a new TDMA session. The scramble
// mask is preserved (it depends on system identity, not call state).
// Call when switching from FDMA to TDMA mode or vice versa.
func (d *Decoder) Reset() {
	d.demod = NewHDQPSKDemod(d.demod.sampleRate)
	d.framer = NewFramer()
	d.tdma.ResetSlot(0)
	d.tdma.ResetSlot(1)
	d.BurstsTotal = 0
	d.BurstsValid = 0
	d.VoiceFrames = 0
	d.superframePos = -1
	d.syncBuf = nil
}

// Close releases decoder resources.
func (d *Decoder) Close() {
	d.tdma.Close()
}
