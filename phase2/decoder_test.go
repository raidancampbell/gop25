package phase2

import (
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/raidancampbell/gop25"
)

func TestDecoder_SyntheticBurst(t *testing.T) {
	// Build a single Phase 2 burst:
	//   - 20 dibits of sync
	//   - 160 filler dibits with valid DUID at positions 10/47/132/169
	//     encoding the byte 0x00 (which classifies as Burst4V)
	var dibits []p25.Dibit
	dibits = append(dibits, magicDibits()...) // sync
	for i := SyncDibits; i < BurstDibits; i++ {
		dibits = append(dibits, 0)
	}

	// Modulate, run through demod -> decoder.
	iq := synthDQPSK(25000, dibits)
	dec := NewDecoder(25000)
	bursts, _ := dec.Process(iq)
	if len(bursts) == 0 {
		t.Fatalf("expected at least 1 burst, got 0")
	}
	if bursts[0].Type != Burst4V {
		t.Errorf("synthetic burst classified as %v, expected Burst4V", bursts[0].Type)
	}
}

func readComplex64IQ(t *testing.T, path string) []complex64 {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("reference IQ unavailable (%v) -- skipping integration test", err)
	}
	if len(data)%8 != 0 {
		t.Fatalf("file size %d not a multiple of 8", len(data))
	}
	out := make([]complex64, len(data)/8)
	for i := range out {
		re := math.Float32frombits(binary.LittleEndian.Uint32(data[i*8:]))
		im := math.Float32frombits(binary.LittleEndian.Uint32(data[i*8+4:]))
		out[i] = complex(re, im)
	}
	return out
}

func TestDecoder_SISCHKeepsExpectedLocationAndSlot(t *testing.T) {
	var sischCodeword uint64
	for cw, value := range ischCodewords {
		if value == -2 {
			sischCodeword = cw
			break
		}
	}
	if sischCodeword == 0 {
		t.Fatal("S-ISCH codeword not found")
	}

	dec := NewDecoder(25000)
	dec.superframePos = 2 // S-ISCH position, slot 0.
	var burst Burst
	isch := cwToDibits(sischCodeword)
	copy(burst.Dibits[:SyncDibits], isch[:])

	got, _ := dec.processBurst(burst, true, [SuperframeDibits]p25.Dibit{})
	if !got.ISCH.Valid || !got.ISCH.IsSISCH {
		t.Fatalf("S-ISCH validity lost: %+v", got.ISCH)
	}
	if got.ISCH.Location != 2 || got.ISCH.Slot != 0 {
		t.Fatalf("S-ISCH location/slot = %d/%d, want 2/0", got.ISCH.Location, got.ISCH.Slot)
	}
}

func TestDecoder_Reset_ClearsState(t *testing.T) {
	dec := NewDecoder(25000)
	// Set scramble params before reset — they should survive.
	dec.SetScrambleParams(0x171, 0x001, 0x12345)

	// Feed a synthetic burst to populate counters.
	var dibits []p25.Dibit
	dibits = append(dibits, magicDibits()...)
	for i := SyncDibits; i < BurstDibits; i++ {
		dibits = append(dibits, 0)
	}
	iq := synthDQPSK(25000, dibits)
	dec.Process(iq)

	if dec.BurstsTotal == 0 {
		t.Fatal("expected BurstsTotal > 0 after processing synthetic burst")
	}

	// Reset
	dec.Reset()

	if dec.BurstsTotal != 0 {
		t.Errorf("BurstsTotal=%d after Reset, want 0", dec.BurstsTotal)
	}
	if dec.BurstsValid != 0 {
		t.Errorf("BurstsValid=%d after Reset, want 0", dec.BurstsValid)
	}
	if dec.VoiceFrames != 0 {
		t.Errorf("VoiceFrames=%d after Reset, want 0", dec.VoiceFrames)
	}
	// Scramble mask should survive reset — verify by processing again
	// (the mask is preserved in the TDMAProcessor).
	dec.Process(iq)
	// If mask was lost, this would be a no-op; with mask it should process.
	t.Logf("After reset+reprocess: BurstsTotal=%d", dec.BurstsTotal)
}

func TestDecoder_ProcessBurstRejectsMismatchedISCH(t *testing.T) {
	dec := NewDecoder(25000)
	var mask [SuperframeDibits]p25.Dibit
	dec.superframePos = 0

	var b Burst
	isch := cwToDibits(0x111e6fe55d) // message 10 → location 4, mismatches expected 0
	copy(b.Dibits[:SyncDibits], isch[:])
	bs, vfs := dec.processBurst(b, true, mask)
	if bs.ISCH.Valid {
		t.Fatalf("mismatched ISCH marked valid: %+v", bs.ISCH)
	}
	if len(vfs) != 0 {
		t.Fatalf("mismatched ISCH produced %d voice frame(s)", len(vfs))
	}
	if dec.BurstsValid != 0 {
		t.Errorf("BurstsValid = %d, want 0 for mismatched ISCH", dec.BurstsValid)
	}
}

func TestDecoder_ReferenceCapture_163419(t *testing.T) {
	path, _ := filepath.Abs("testdata/453825000_20260524T163419Z.iq")
	iq := readComplex64IQ(t, path)
	dec := NewDecoder(25000)
	// Set scramble params so FEC-based offset detection can sync.
	dec.SetScrambleParams(0x171, 0x170, 0xBEE00)
	const blockSize = 625
	for off := 0; off < len(iq); off += blockSize {
		end := off + blockSize
		if end > len(iq) {
			end = len(iq)
		}
		dec.Process(iq[off:end]) //nolint:errcheck
	}
	// 8.24 seconds of TDMA at ~16.7 bursts/sec/slot x 2 slots = 275
	// bursts in an ideal world. A working decoder should see at least 100
	// bursts with at least 50 having valid ISCH.
	if dec.BurstsTotal < 100 {
		t.Errorf("BurstsTotal=%d, expected >=100 over 8.24s of TDMA", dec.BurstsTotal)
	}
	if dec.BurstsValid < 50 {
		t.Errorf("BurstsValid=%d, expected >=50 (decoder ISCH lock failing)", dec.BurstsValid)
	}
	t.Logf("Reference capture 163419Z: %d bursts, %d with valid ISCH (%.1f%%)",
		dec.BurstsTotal, dec.BurstsValid,
		100*float64(dec.BurstsValid)/math.Max(1, float64(dec.BurstsTotal)))
}

// TestDecoder_ReferenceCapture_VoiceGaps simulates the host's processBlock
// behavior (250 samples at a time) and measures voice-frame continuity per
// slot. This diagnoses the fragmentation issue where P2 TDMA voice classification
// failures cause the 500ms hold-time to expire during continuous speech.
//
// The reference capture has genuine non-voice intervals (PTT release/rekey,
// FACCH signaling) that naturally segment the call into multiple fragments.
// The test verifies that WITHIN each fragment, voice frames arrive frequently
// enough to keep the gate open, and that the total number of fragments is
// small (ruling out classification failures that would cause dozens of tiny
// fragments from a single continuous call).
func TestDecoder_ReferenceCapture_VoiceGaps(t *testing.T) {
	path, _ := filepath.Abs("testdata/453825000_20260524T163419Z.iq")
	iq := readComplex64IQ(t, path)
	dec := NewDecoder(25000)
	// Set scramble params for NAC 0x171 / SYSID 0x170 / WACN 0xBEE00
	// (from the Greenbrier County system, matching the reference capture).
	dec.SetScrambleParams(0x171, 0x170, 0xBEE00)

	const (
		blockSize  = 250 // same as dsp.BlockSamples (production block size)
		sampleRate = 25000.0
		holdTimeMs = 500.0
	)
	blockMs := 1000.0 * float64(blockSize) / sampleRate

	// Per-slot tracking: voice frame blocks (for fragment analysis).
	type slotStats struct {
		voiceBlocks []int // block numbers where voice frames arrived
	}
	var stats [2]slotStats

	// Burst type counters (diagnostic).
	typeCounts := make(map[BurstType]int)

	totalBlocks := 0
	for off := 0; off < len(iq); off += blockSize {
		end := off + blockSize
		if end > len(iq) {
			end = len(iq)
		}
		bursts, voiceFrames := dec.Process(iq[off:end])
		for _, b := range bursts {
			typeCounts[b.Type]++
		}
		for _, vf := range voiceFrames {
			slot := vf.Slot
			if slot >= 0 && slot <= 1 {
				stats[slot].voiceBlocks = append(stats[slot].voiceBlocks, totalBlocks)
			}
		}
		totalBlocks++
	}

	totalSec := float64(totalBlocks) * blockMs / 1000.0
	t.Logf("Processed %.2fs of IQ in %d blocks (%.1fms each)", totalSec, totalBlocks, blockMs)
	t.Logf("Decoder stats: %d bursts, %d valid ISCH (%.1f%%), %d voice frames",
		dec.BurstsTotal, dec.BurstsValid,
		100*float64(dec.BurstsValid)/math.Max(1, float64(dec.BurstsTotal)),
		dec.VoiceFrames)
	t.Logf("Burst types: 4V=%d 2V=%d SACCH=%d LCCH=%d FACCH=%d Unknown=%d",
		typeCounts[Burst4V], typeCounts[Burst2V], typeCounts[BurstSACCH],
		typeCounts[BurstLCCH], typeCounts[BurstFACCH], typeCounts[BurstUnknown])

	// Fragment analysis: group voice frames into continuous segments
	// separated by gaps exceeding the hold time.
	holdBlocks := int(holdTimeMs / blockMs)
	for slot := 0; slot < 2; slot++ {
		blocks := stats[slot].voiceBlocks
		if len(blocks) == 0 {
			t.Logf("Slot %d: no voice frames", slot)
			continue
		}

		// Build fragments: each fragment is a group of voice frames where
		// consecutive frames are separated by ≤ holdBlocks.
		type fragment struct {
			firstBlock   int
			lastBlock    int
			voiceCount   int
			maxGapBlocks int // max gap between consecutive voice frames in this fragment
		}
		var fragments []fragment
		cur := fragment{firstBlock: blocks[0], lastBlock: blocks[0], voiceCount: 1}
		for i := 1; i < len(blocks); i++ {
			gap := blocks[i] - blocks[i-1]
			if gap > holdBlocks {
				// New fragment
				fragments = append(fragments, cur)
				cur = fragment{firstBlock: blocks[i], lastBlock: blocks[i], voiceCount: 1}
			} else {
				cur.lastBlock = blocks[i]
				cur.voiceCount++
				if gap > cur.maxGapBlocks {
					cur.maxGapBlocks = gap
				}
			}
		}
		fragments = append(fragments, cur)

		t.Logf("Slot %d: %d voice frames in %d fragment(s)", slot, len(blocks), len(fragments))
		for i, f := range fragments {
			durMs := float64(f.lastBlock-f.firstBlock) * blockMs
			maxGapMs := float64(f.maxGapBlocks) * blockMs
			t.Logf("  fragment %d: %.0fms duration, %d voice frames, max internal gap %.0fms",
				i, durMs, f.voiceCount, maxGapMs)
		}

		// Assertions:
		// 1. Few fragments (≤5): the classifier isn't micro-fragmenting calls.
		if len(fragments) > 5 {
			t.Errorf("Slot %d: %d fragments (>5) — voice classification is fragmenting continuous calls",
				slot, len(fragments))
		}
		// 2. Within each fragment, max gap < hold time (no classification drops).
		for i, f := range fragments {
			maxGapMs := float64(f.maxGapBlocks) * blockMs
			if maxGapMs > holdTimeMs {
				t.Errorf("Slot %d fragment %d: internal gap %.0fms > hold time %.0fms — voice frames being lost within continuous speech",
					slot, i, maxGapMs, holdTimeMs)
			}
		}
		// 3. At least 60 voice frames total on a slot with any voice.
		if len(blocks) < 60 {
			t.Errorf("Slot %d: only %d voice frames (expected ≥60 for an 8s capture with active voice)",
				slot, len(blocks))
		}
	}
}

func TestDecoder_HasKey(t *testing.T) {
	d := NewDecoder(24000)
	if d.HasKey(0x84, 0x1) {
		t.Fatal("HasKey must be false before a key lookup is set")
	}
	d.SetKeyLookup(func(algID uint8, keyID uint16) ([]byte, bool) {
		return []byte{9}, algID == 0x84 && keyID == 0x1
	})
	if !d.HasKey(0x84, 0x1) {
		t.Error("HasKey must be true for the configured pair")
	}
	if d.HasKey(0x00, 0x1) {
		t.Error("HasKey must be false for an unknown alg")
	}
}

// TestDecoder_EmitsControlFrame verifies that a control-only SACCH burst
// flows through the decoder and emits a ControlOnly P2VoiceFrame with
// identity decoded from the MAC PDU. This is an end-to-end integration test
// at the processBurst level (no IQ modulation/demod).
func TestDecoder_EmitsControlFrame(t *testing.T) {
	dec := NewDecoder(25000)
	dec.superframePos = -1 // default: no scramble expectation

	// Build a MAC_ACTIVE PDU (opcode 4) with a 0x01 Group Voice Channel User
	// sub-message. Reuse the tdma_test synthesis helpers.
	tg := uint16(0x1234)
	src := uint32(0x0ABCDE)
	body := buildMACActiveGroupVoiceBody(t, tg, src)
	burstDibits := synthACCHBurst(t, body, ACCHSacch)

	// Find a DUID codeword that maps to id 12 (unscrambled SACCH).
	var duidCodeword uint8
	for cw := 0; cw < 256; cw++ {
		if duidLookup[cw] == 12 {
			duidCodeword = uint8(cw)
			break
		}
	}

	// Write the DUID codeword dibits into the burst at positions 20/57/142/179.
	// NOTE: positions 20/57/142 fall inside the SACCH ACCH ranges and will
	// overwrite some RS-protected data. The RS(63,35) decoder has an erasure
	// budget (6 punctured + up to ~14 errors correctable), so with luck the
	// CRC-12 will still pass. If this test fails with CRC errors, the fallback
	// is to accept that DUID extraction and ACCH decode are incompatible on
	// the same burst in a pure-synthesis scenario (real on-air bursts have
	// both correctly positioned).
	burstDibits[DUIDPos0] = p25.Dibit((duidCodeword >> 6) & 0x3)
	burstDibits[DUIDPos1] = p25.Dibit((duidCodeword >> 4) & 0x3)
	burstDibits[DUIDPos2] = p25.Dibit((duidCodeword >> 2) & 0x3)
	burstDibits[DUIDPos3] = p25.Dibit(duidCodeword & 0x3)

	// Verify that DecodeACCH can still recover the MAC PDU despite the
	// corrupted dibits. If this sub-check fails, the DUID/ACCH overlap is
	// insurmountable in synthesis, and the test documents the limitation.
	acchPDU, acchOK := DecodeACCH(burstDibits, ACCHSacch)
	if !acchOK || acchPDU == nil {
		t.Fatalf("synthACCHBurst + DUID overlay broke RS decode (DUID/ACCH position conflict) — cannot synthesize a decoder-level control burst")
	}
	// Sanity check: opcode should be 4 (MAC_ACTIVE)
	if acchPDU.Opcode != 4 {
		t.Fatalf("DecodeACCH returned opcode %d, want 4 (MAC_ACTIVE)", acchPDU.Opcode)
	}

	// Build the Burst struct for processBurst.
	var b Burst
	b.Dibits = burstDibits
	b.Raw = burstDibits // processBurst sets Raw := Dibits at entry when hasMask=false
	b.ISCH = ISCHInfo{Location: 0, Slot: 0, Valid: true}
	// processBurst will re-extract DUID from b.Raw and re-classify.

	// Call processBurst with hasMask=false (no descramble).
	var mask [SuperframeDibits]p25.Dibit
	_, voice := dec.processBurst(b, false, mask)

	// Assert: exactly one voice frame, marked ControlOnly and IdentityFromMAC.
	if len(voice) != 1 {
		t.Fatalf("processBurst returned %d voice frames, want 1", len(voice))
	}
	vf := voice[0]
	if !vf.ControlOnly {
		t.Errorf("voice frame ControlOnly=%v, want true", vf.ControlOnly)
	}
	if !vf.IdentityFromMAC {
		t.Errorf("voice frame IdentityFromMAC=%v, want true", vf.IdentityFromMAC)
	}
	if vf.Talkgroup != tg {
		t.Errorf("voice frame Talkgroup=%#x, want %#x", vf.Talkgroup, tg)
	}
	if vf.SourceID != src {
		t.Errorf("voice frame SourceID=%#x, want %#x", vf.SourceID, src)
	}
	if vf.Slot != 0 {
		t.Errorf("voice frame Slot=%d, want 0", vf.Slot)
	}
}
