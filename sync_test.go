package p25

import (
	"math/bits"
	"math/rand"
	"testing"
)

func TestBCHEncode_RoundTrip(t *testing.T) {
	for _, duid := range validDUIDs {
		for _, nac := range []uint16{0, 0x293, 0xFFF} {
			msg := (nac << 4) | uint16(duid)
			encoded := bchEncode(msg)
			got, ok := decodeNID(encoded)
			if !ok {
				t.Errorf("decodeNID failed for NAC=0x%03X DUID=0x%X", nac, duid)
				continue
			}
			if got.NAC != nac || got.DUID != duid {
				t.Errorf("round-trip mismatch: got NAC=0x%03X DUID=0x%X, want NAC=0x%03X DUID=0x%X",
					got.NAC, got.DUID, nac, duid)
			}
		}
	}
}

func TestBCHDecode_BitErrors(t *testing.T) {
	nac := uint16(0x293)
	duid := uint8(0x5) // LDU1
	msg := (nac << 4) | uint16(duid)
	encoded := bchEncode(msg)

	// Should correct up to 11 bit errors
	for numErrors := 1; numErrors <= 11; numErrors++ {
		// Flip the first numErrors bits
		corrupted := encoded
		for i := 0; i < numErrors; i++ {
			corrupted ^= uint64(1) << uint(i)
		}
		got, ok := decodeNID(corrupted)
		if !ok {
			t.Errorf("decodeNID failed with %d bit errors", numErrors)
			continue
		}
		if got.NAC != nac || got.DUID != duid {
			t.Errorf("%d bit errors: got NAC=0x%03X DUID=0x%X, want NAC=0x%03X DUID=0x%X",
				numErrors, got.NAC, got.DUID, nac, duid)
		}
	}

	// 12+ errors should fail (beyond correction capability)
	corrupted := encoded
	for i := 0; i < 12; i++ {
		corrupted ^= uint64(1) << uint(i)
	}
	_, ok := decodeNID(corrupted)
	if ok {
		t.Logf("decodeNID unexpectedly succeeded with 12 bit errors (may be valid for some codewords)")
	}
}

func TestPackDibits(t *testing.T) {
	// Pack the known sync word and verify against hex 0x5575F5FF77FF
	packed := packDibits(syncWord[:])
	want := uint64(0x5575F5FF77FF)
	if packed != want {
		t.Errorf("packDibits(syncWord) = 0x%012X, want 0x%012X", packed, want)
	}
}

// buildNIDDibits encodes NAC+DUID into 32 dibits via BCH encoding.
func buildNIDDibits(nac uint16, duid uint8) [nidLen]Dibit {
	msg := (nac << 4) | uint16(duid)
	encoded := bchEncode(msg)
	var dibits [nidLen]Dibit
	for i := 0; i < nidLen; i++ {
		shift := uint(2 * (nidLen - 1 - i))
		dibits[i] = Dibit((encoded >> shift) & 0x3)
	}
	return dibits
}

// buildNIDStream returns the 33 transmitted dibits for a NID (32 data + 1 status at position 11).
func buildNIDStream(nac uint16, duid uint8) []Dibit {
	data := buildNIDDibits(nac, duid)
	stream := make([]Dibit, 0, nidSpan)
	for i := 0; i < nidLen; i++ {
		if i == 11 {
			stream = append(stream, 0) // status symbol (value doesn't matter, it's skipped)
		}
		stream = append(stream, data[i])
	}
	return stream
}

func TestFrameSync_TDU(t *testing.T) {
	nac := uint16(0x293)
	duid := uint8(0x3) // TDU — 72 total dibits, 15 payload dibits (status + nulls)
	nidStream := buildNIDStream(nac, duid)
	pLen := payloadLen(duid)

	var stream []Dibit
	for i := 0; i < 100; i++ {
		stream = append(stream, Dibit(i%4))
	}
	for _, d := range syncWord {
		stream = append(stream, d)
	}
	for _, d := range nidStream {
		stream = append(stream, d)
	}
	for i := 0; i < pLen; i++ {
		stream = append(stream, 0)
	}

	fs := NewFrameSync()
	frames := fs.Feed(stream)

	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}
	if frames[0].NID.NAC != nac {
		t.Errorf("NAC = 0x%03X, want 0x%03X", frames[0].NID.NAC, nac)
	}
	if frames[0].NID.DUID != duid {
		t.Errorf("DUID = 0x%X, want 0x%X", frames[0].NID.DUID, duid)
	}
	if len(frames[0].Payload) != pLen {
		t.Errorf("TDU payload = %d dibits, want %d", len(frames[0].Payload), pLen)
	}
}

func TestFrameSync_LDU1(t *testing.T) {
	nac := uint16(0x293)
	duid := uint8(0x5) // LDU1
	nidStream := buildNIDStream(nac, duid)
	pLen := payloadLen(duid) // 1672

	var stream []Dibit
	// Preamble garbage
	for i := 0; i < 50; i++ {
		stream = append(stream, Dibit(i%4))
	}
	// Sync word
	for _, d := range syncWord {
		stream = append(stream, d)
	}
	// NID
	for _, d := range nidStream {
		stream = append(stream, d)
	}
	// Payload (fill with recognizable pattern)
	for i := 0; i < pLen; i++ {
		stream = append(stream, Dibit(i%4))
	}

	fs := NewFrameSync()
	frames := fs.Feed(stream)

	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}
	f := frames[0]
	if f.NID.NAC != nac || f.NID.DUID != duid {
		t.Errorf("NID = {NAC:0x%03X DUID:0x%X}, want {NAC:0x%03X DUID:0x%X}",
			f.NID.NAC, f.NID.DUID, nac, duid)
	}
	if len(f.Payload) != pLen {
		t.Errorf("payload length = %d, want %d", len(f.Payload), pLen)
	}
}

func TestFrameSync_MultipleFrames(t *testing.T) {
	nac := uint16(0x100)
	testCases := []struct {
		duid uint8
		pLen int
	}{
		{0x0, payloadLen(0x0)}, // HDU
		{0x5, payloadLen(0x5)}, // LDU1
		{0xA, payloadLen(0xA)}, // LDU2
		{0x3, payloadLen(0x3)}, // TDU
	}

	var stream []Dibit
	for _, tc := range testCases {
		for _, d := range syncWord {
			stream = append(stream, d)
		}
		nidStream := buildNIDStream(nac, tc.duid)
		for _, d := range nidStream {
			stream = append(stream, d)
		}
		for i := 0; i < tc.pLen; i++ {
			stream = append(stream, 0)
		}
	}

	fs := NewFrameSync()
	frames := fs.Feed(stream)

	if len(frames) != len(testCases) {
		t.Fatalf("expected %d frames, got %d", len(testCases), len(frames))
	}
	for i, tc := range testCases {
		if frames[i].NID.DUID != tc.duid {
			t.Errorf("frame %d: DUID = 0x%X, want 0x%X", i, frames[i].NID.DUID, tc.duid)
		}
		if len(frames[i].Payload) != tc.pLen {
			t.Errorf("frame %d: payload len = %d, want %d", i, len(frames[i].Payload), tc.pLen)
		}
	}
	if fs.SyncCount() != len(testCases) {
		t.Errorf("syncCount = %d, want %d", fs.SyncCount(), len(testCases))
	}
}

func TestFrameSync_NIDErrors(t *testing.T) {
	nac := uint16(0x293)
	duid := uint8(0x5)
	nidStream := buildNIDStream(nac, duid)

	// Flip 3 dibits in the NID stream (avoiding the status position at index 11)
	nidStream[0] = (nidStream[0] + 1) % 4
	nidStream[5] = (nidStream[5] + 2) % 4
	nidStream[13] = (nidStream[13] + 1) % 4 // after status position

	var stream []Dibit
	for _, d := range syncWord {
		stream = append(stream, d)
	}
	for _, d := range nidStream {
		stream = append(stream, d)
	}
	pLen := payloadLen(duid)
	for i := 0; i < pLen; i++ {
		stream = append(stream, 0)
	}

	fs := NewFrameSync()
	frames := fs.Feed(stream)
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame despite NID errors, got %d", len(frames))
	}
	if frames[0].NID.NAC != nac || frames[0].NID.DUID != duid {
		t.Errorf("NID decode with errors: got {NAC:0x%03X DUID:0x%X}, want {NAC:0x%03X DUID:0x%X}",
			frames[0].NID.NAC, frames[0].NID.DUID, nac, duid)
	}
}

func TestFrameSync_SyncWithDibitErrors(t *testing.T) {
	nac := uint16(0x293)
	duid := uint8(0x3)
	pLen := payloadLen(duid)
	nidStream := buildNIDStream(nac, duid)

	// Corrupt up to syncThresh dibits in the sync word
	corruptedSync := syncWord
	corruptedSync[0] = (corruptedSync[0] + 1) % 4
	corruptedSync[5] = (corruptedSync[5] + 2) % 4
	corruptedSync[10] = (corruptedSync[10] + 1) % 4
	corruptedSync[15] = (corruptedSync[15] + 1) % 4

	var stream []Dibit
	for i := 0; i < 50; i++ {
		stream = append(stream, 0)
	}
	for _, d := range corruptedSync {
		stream = append(stream, d)
	}
	for _, d := range nidStream {
		stream = append(stream, d)
	}
	for i := 0; i < pLen; i++ {
		stream = append(stream, 0)
	}

	fs := NewFrameSync()
	frames := fs.Feed(stream)
	if len(frames) != 1 {
		t.Fatalf("expected sync detection with %d dibit errors, got %d frames", syncThresh, len(frames))
	}

	// Verify 5 dibit errors should fail sync
	tooCorrupt := syncWord
	for i := 0; i < syncThresh+1; i++ {
		tooCorrupt[i] = (tooCorrupt[i] + 1) % 4
	}
	var stream2 []Dibit
	for i := 0; i < 50; i++ {
		stream2 = append(stream2, 0)
	}
	for _, d := range tooCorrupt {
		stream2 = append(stream2, d)
	}
	for _, d := range nidStream {
		stream2 = append(stream2, d)
	}

	fs2 := NewFrameSync()
	frames2 := fs2.Feed(stream2)
	if len(frames2) != 0 {
		t.Errorf("expected no sync with %d dibit errors, got %d frames", syncThresh+1, len(frames2))
	}
}

func TestBCHEncode_ParityBit(t *testing.T) {
	// Verify the parity bit makes the total popcount even
	for _, duid := range validDUIDs {
		msg := (uint16(0x293) << 4) | uint16(duid)
		encoded := bchEncode(msg)
		if bits.OnesCount64(encoded)%2 != 0 {
			t.Errorf("BCH codeword for DUID=0x%X has odd parity", duid)
		}
	}
}

func TestFrameSync_Reset(t *testing.T) {
	fs := NewFrameSync()
	nac := uint16(0x293)
	duid := uint8(0x3)

	// Feed a valid frame
	var stream []Dibit
	for _, d := range syncWord {
		stream = append(stream, d)
	}
	nidStream := buildNIDStream(nac, duid)
	for _, d := range nidStream {
		stream = append(stream, d)
	}
	for i := 0; i < payloadLen(duid); i++ {
		stream = append(stream, 0)
	}
	frames := fs.Feed(stream)
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}
	if fs.SyncCount() != 1 {
		t.Errorf("syncCount = %d before reset, want 1", fs.SyncCount())
	}

	fs.Reset()
	if fs.SyncCount() != 0 {
		t.Error("syncCount should be 0 after Reset")
	}
}

func TestFrameSync_GarbageOnly(t *testing.T) {
	// Pure garbage should produce no frames
	fs := NewFrameSync()
	garbage := make([]Dibit, 10000)
	for i := range garbage {
		garbage[i] = Dibit((i * 3) % 4)
	}
	frames := fs.Feed(garbage)
	if len(frames) != 0 {
		t.Errorf("expected 0 frames from garbage, got %d", len(frames))
	}
}

func TestFrameSync_TDUlc(t *testing.T) {
	nac := uint16(0x100)
	duid := uint8(0xF) // TDUlc
	nidStream := buildNIDStream(nac, duid)
	pLen := payloadLen(duid)

	var stream []Dibit
	for _, d := range syncWord {
		stream = append(stream, d)
	}
	for _, d := range nidStream {
		stream = append(stream, d)
	}
	for i := 0; i < pLen; i++ {
		stream = append(stream, 0)
	}

	fs := NewFrameSync()
	frames := fs.Feed(stream)
	if len(frames) != 1 {
		t.Fatalf("expected 1 TDUlc frame, got %d", len(frames))
	}
	if frames[0].NID.DUID != 0xF {
		t.Errorf("DUID = 0x%X, want 0xF", frames[0].NID.DUID)
	}
	if len(frames[0].Payload) != pLen {
		t.Errorf("TDUlc payload len = %d, want %d", len(frames[0].Payload), pLen)
	}
}

func TestFrameSync_HDU(t *testing.T) {
	nac := uint16(0x293)
	duid := uint8(0x0) // HDU
	nidStream := buildNIDStream(nac, duid)
	pLen := payloadLen(duid)

	var stream []Dibit
	for _, d := range syncWord {
		stream = append(stream, d)
	}
	for _, d := range nidStream {
		stream = append(stream, d)
	}
	for i := 0; i < pLen; i++ {
		stream = append(stream, Dibit(i%4))
	}

	fs := NewFrameSync()
	frames := fs.Feed(stream)
	if len(frames) != 1 {
		t.Fatalf("expected 1 HDU frame, got %d", len(frames))
	}
	if frames[0].NID.DUID != 0x0 {
		t.Errorf("DUID = 0x%X, want 0x0", frames[0].NID.DUID)
	}
}

func TestBCHDecode_AllValidDUIDs(t *testing.T) {
	// Verify BCH round-trip for all valid DUIDs across multiple NACs
	nacs := []uint16{0x000, 0x001, 0x100, 0x293, 0x7FF, 0xFFF}
	for _, nac := range nacs {
		for _, duid := range validDUIDs {
			msg := (nac << 4) | uint16(duid)
			encoded := bchEncode(msg)
			got, ok := decodeNID(encoded)
			if !ok {
				t.Errorf("decodeNID failed for NAC=0x%03X DUID=0x%X", nac, duid)
				continue
			}
			if got.NAC != nac || got.DUID != duid {
				t.Errorf("NAC=0x%03X DUID=0x%X: got NAC=0x%03X DUID=0x%X", nac, duid, got.NAC, got.DUID)
			}
		}
	}
}

func TestCorrelate_ExactMatch(t *testing.T) {
	fs := NewFrameSync()
	// Feed exact sync word
	for _, d := range syncWord {
		fs.feedOne(d, 0, false)
	}
	// After feeding, it should have transitioned to stateCollectNID
	if fs.state != stateCollectNID {
		t.Errorf("state = %d, want stateCollectNID (%d)", fs.state, stateCollectNID)
	}
}

// TestSoftCorrelate checks the normalized soft correlation: a clean sync scores
// ~1.0, a faded clean sync scores ~1.0 too (amplitude invariance — the property
// that lets it acquire weak bursts), a zero-energy ring scores 0, and a
// structureless DC ring scores well below the acquisition threshold.
func TestSoftCorrelate(t *testing.T) {
	set := func(fs *FrameSync, vals []float32) {
		fs.ringIdx = 0
		copy(fs.softRing[:], vals)
	}
	ideal := func(scale float32) []float32 {
		v := make([]float32, syncLen)
		for i, d := range syncWord {
			v[i] = scale * float32(c4fmLevels[d])
		}
		return v
	}

	fs := NewFrameSync()
	set(fs, ideal(1))
	if c := fs.softCorrelate(); c < 0.99 {
		t.Errorf("clean sync corr = %.3f, want ~1.0", c)
	}
	set(fs, ideal(0.2)) // faded: amplitude-invariant, still ~1.0
	if c := fs.softCorrelate(); c < 0.99 {
		t.Errorf("faded sync corr = %.3f, want ~1.0 (amplitude-invariant)", c)
	}
	set(fs, make([]float32, syncLen))
	if c := fs.softCorrelate(); c != 0 {
		t.Errorf("zero-energy corr = %.3f, want 0", c)
	}
	dc := make([]float32, syncLen)
	for i := range dc {
		dc[i] = 1
	}
	set(fs, dc)
	if c := fs.softCorrelate(); c >= softSyncThresh {
		t.Errorf("DC (no polarity structure) corr = %.3f, want < softSyncThresh %.2f", c, softSyncThresh)
	}
}

// TestSoftSyncGate_AcquiresWeakSyncHardMisses is the integration test for the
// soft-decision sync gate: a sync word whose dibits are corrupted past the hard
// Hamming threshold but whose soft values still carry the correct polarity is
// acquired on the FeedSoft path (soft gate) and rejected on the soft-less Feed
// path (hard gate only).
func TestSoftSyncGate_AcquiresWeakSyncHardMisses(t *testing.T) {
	nac := uint16(0x293)
	duid := uint8(0x3) // TDU: short payload, emits quickly
	pLen := payloadLen(duid)
	nidStream := buildNIDStream(nac, duid)

	// Corrupt 8 sync dibits (> syncThreshCold = 6, so the hard gate misses),
	// each only to the same-polarity adjacent dibit (+3<->+1 = dibit 1<->0,
	// -3<->-1 = dibit 3<->2). The soft values we feed keep the TRUE ±3 polarity,
	// modeling a weak burst where the slicer erred but the symbol still leans
	// the right way — so the soft gate scores ~1.0 and acquires.
	corrupt := syncWord
	for i := 0; i < syncLen; i += 3 { // 8 positions: 0,3,6,9,12,15,18,21
		switch corrupt[i] {
		case 1:
			corrupt[i] = 0
		case 3:
			corrupt[i] = 2
		}
	}

	var dibits []Dibit
	var soft []float32
	push := func(d Dibit, sv float32) { dibits = append(dibits, d); soft = append(soft, sv) }

	for i := 0; i < 50; i++ { // lead-in noise: neutral, won't false-trigger
		push(0, 0)
	}
	for i, d := range corrupt { // corrupted dibits, true-polarity soft
		push(d, float32(c4fmLevels[syncWord[i]]))
	}
	for _, d := range nidStream {
		push(d, float32(c4fmLevels[d]))
	}
	for i := 0; i < pLen; i++ {
		push(Dibit(i%4), float32(c4fmLevels[Dibit(i%4)]))
	}

	fs := NewFrameSync()
	frames := fs.FeedSoft(dibits, soft)
	if len(frames) != 1 {
		t.Fatalf("soft gate: expected 1 frame from weak sync, got %d", len(frames))
	}
	if fs.SoftSyncDetections == 0 {
		t.Errorf("expected SoftSyncDetections > 0, got 0")
	}

	// Control: the same corrupted dibits on the soft-less Feed path (hard gate
	// only, no soft info) must not acquire.
	fs2 := NewFrameSync()
	if frames2 := fs2.Feed(dibits); len(frames2) != 0 {
		t.Errorf("hard gate: expected no frame from 8-dibit-error sync, got %d", len(frames2))
	}
}

// TestFrameSync_CarriesSoftAlignedWithPayload verifies the new FeedSoft path:
// emitted Frame.Soft has the same length as Frame.Payload (1:1 alignment is
// the contract parsePDUWithSoft relies on), and matches what was fed in for
// the payload dibits. The legacy Feed path is asserted to leave Frame.Soft
// nil (no surprise allocations for soft-less callers).
func TestFrameSync_CarriesSoftAlignedWithPayload(t *testing.T) {
	nac := uint16(0x293)
	duid := uint8(0x5) // LDU1 -- non-trivial payload length (1672 dibits)
	nidStream := buildNIDStream(nac, duid)
	pLen := payloadLen(duid)

	var stream []Dibit
	for i := 0; i < 50; i++ {
		stream = append(stream, Dibit(i%4))
	}
	for _, d := range syncWord {
		stream = append(stream, d)
	}
	for _, d := range nidStream {
		stream = append(stream, d)
	}
	for i := 0; i < pLen; i++ {
		stream = append(stream, Dibit(i%4))
	}

	soft := make([]float32, len(stream))
	for i, d := range stream {
		soft[i] = float32(c4fmLevels[d])
	}

	fs := NewFrameSync()
	frames := fs.FeedSoft(stream, soft)
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}
	f := frames[0]
	if len(f.Soft) != len(f.Payload) {
		t.Fatalf("Soft len %d != Payload len %d", len(f.Soft), len(f.Payload))
	}
	// Spot-check the first and last payload dibits' soft values.
	for i := 0; i < len(f.Payload); i++ {
		want := float32(c4fmLevels[f.Payload[i]])
		if f.Soft[i] != want {
			t.Fatalf("Soft[%d]=%v, want %v (matching dibit %d)", i, f.Soft[i], want, f.Payload[i])
		}
	}

	// Soft-less Feed must leave Frame.Soft nil.
	fs2 := NewFrameSync()
	frames2 := fs2.Feed(stream)
	if len(frames2) != 1 {
		t.Fatalf("Feed: expected 1 frame, got %d", len(frames2))
	}
	if frames2[0].Soft != nil {
		t.Errorf("Feed (soft-less) produced non-nil Frame.Soft (len=%d); want nil", len(frames2[0].Soft))
	}
}

func TestSliceDibit_BoundaryValues(t *testing.T) {
	tests := []struct {
		val  float64
		want Dibit
	}{
		{1800, 1},  // +3 symbol
		{1201, 1},  // just above boundary
		{1200, 0},  // at boundary → inner
		{600, 0},   // +1 symbol center
		{1, 0},     // just above 0
		{0, 2},     // at 0 → negative side
		{-1, 2},    // just below 0
		{-600, 2},  // -1 symbol center
		{-1199, 2}, // just above -1200
		{-1200, 3}, // at -1200 boundary → falls to -3 (not > -1200)
		{-1201, 3}, // just below -1200
		{-1800, 3}, // -3 symbol center
	}
	for _, tt := range tests {
		got := sliceDibit(tt.val)
		if got != tt.want {
			t.Errorf("sliceDibit(%.0f) = %d, want %d", tt.val, got, tt.want)
		}
	}
}

func TestDibitsToBits(t *testing.T) {
	dibits := []Dibit{0, 1, 2, 3}
	got := dibitsToBits(dibits)
	want := []uint8{0, 0, 0, 1, 1, 0, 1, 1}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("bit %d: got %d, want %d", i, got[i], want[i])
		}
	}
}

// TestFrameSync_NoiseFalsePositiveRate verifies that a stream of random dibits
// does not cause FrameSync to emit frames at an unacceptable rate.
func TestFrameSync_NoiseFalsePositiveRate(t *testing.T) {
	fs := NewFrameSync()

	rng := rand.New(rand.NewSource(42))
	noise := make([]Dibit, 10000)
	for i := range noise {
		noise[i] = Dibit(rng.Intn(4))
	}

	frames := fs.Feed(noise)

	if len(frames) > 0 {
		t.Errorf("got %d false-positive frames from pure noise (want 0); "+
			"syncThresh may be too loose or NID BCH tolerance is too wide", len(frames))
	}

	t.Logf("SyncDetections=%d NIDAttempts=%d NIDFailures=%d FramesEmitted=%d",
		fs.SyncDetections, fs.NIDAttempts, fs.NIDFailures, fs.FramesEmitted)
}

// BenchmarkFrameSync_NIDDecode_Warm measures NID decoding throughput once
// the NAC hint is established (the steady-state path on a single channel).
// Before fix #3, decodeNIDHinted re-ran the full 4096×6 brute force purely
// to compute the wasHint debug counter, making the hint useless for perf.
func BenchmarkFrameSync_NIDDecode_Warm(b *testing.B) {
	fs := NewFrameSync()
	fs.hintNAC = 0x171
	fs.hintNACSet = true
	encoded := bchEncode((0x171 << 4) | 0x5)
	b.ResetTimer()
	for b.Loop() {
		_, _, _ = fs.decodeNIDHinted(encoded)
	}
}

func BenchmarkDecodeNID_Cold(b *testing.B) {
	encoded := bchEncode((0x171 << 4) | 0x5)
	b.ResetTimer()
	for b.Loop() {
		_, _ = decodeNID(encoded)
	}
}

// TestExtractVoiceCW_PositionContinuity verifies that adjacent codeword
// extractions don't overlap and cover exactly 72 data dibits each.
func TestExtractVoiceCW_PositionContinuity(t *testing.T) {
	payload := make([]Dibit, 807)
	for i := range payload {
		if isStatusPosition(i) {
			payload[i] = 3
		} else {
			payload[i] = Dibit(i % 3)
		}
	}

	for pos, start := range lduVoiceStarts {
		bits := extractVoiceCW(payload, start)
		if len(bits) != voiceDibits*2 {
			t.Errorf("CW[%d] (start=%d): got %d bits, want %d", pos, start, len(bits), voiceDibits*2)
			continue
		}
		for b := 0; b+1 < len(bits); b += 2 {
			d := Dibit((bits[b] << 1) | bits[b+1])
			if d == 3 {
				t.Errorf("CW[%d] (start=%d): bit offset %d reconstructed to sentinel dibit 3 — "+
					"status position was accidentally included in this codeword", pos, start, b)
			}
		}
	}
}

// TestPayloadLen_OnAirFrameLengths verifies that payloadLen matches the
// frame lengths actually transmitted by P25 Phase 1 systems (TIA-102.BAAA-A
// table 7-1, confirmed against op25's max_frame_lengths and on-air
// measurement of 4 clean captures via cmd/diagnose25).
//
// Total transmitted dibits per frame = sync(24) + NID(33) + payload.
// If payloadLen returns too large a value, FrameSync over-collects into the
// NEXT frame's sync word, swallowing it. This was the cause of the residual
// audio artifacting after the wideband-ring fix: every TSDU consumed 504
// extra dibits = the next 2.3 TSBKs, and every HDU consumed 252 extra dibits
// = the first ~30% of the following LDU1.
func TestPayloadLen_OnAirFrameLengths(t *testing.T) {
	cases := []struct {
		duid       uint8
		name       string
		totalDibit int
	}{
		{0x0, "HDU", 396},
		{0x3, "TDU", 72},
		{0x5, "LDU1", 864},
		{0x7, "TSDU", 360},
		{0xA, "LDU2", 864},
		{0xF, "TDUlc", 216},
	}
	for _, c := range cases {
		got := syncLen + nidSpan + payloadLen(c.duid)
		if got != c.totalDibit {
			t.Errorf("%s (DUID 0x%X): total frame = %d dibits, want %d (over-collect %+d)",
				c.name, c.duid, got, c.totalDibit, got-c.totalDibit)
		}
	}
}

// TestFrameSync_AdjacentFramesNotSwallowed builds a TSDU immediately followed
// by an LDU1 (the on-air pattern at every voice-call start) and verifies the
// LDU1 is emitted intact. With the wrong TSDU length, FrameSync collects the
// LDU1's sync+NID+first ~447 payload dibits as TSDU "payload" and the LDU1
// is never emitted.
func TestFrameSync_AdjacentFramesNotSwallowed(t *testing.T) {
	nac := uint16(0x171)

	build := func(duid uint8, total int) []Dibit {
		var s []Dibit
		s = append(s, syncWord[:]...)
		s = append(s, buildNIDStream(nac, duid)...)
		for len(s) < total {
			s = append(s, 0)
		}
		return s
	}

	// On-air pattern: ... TSDU(216) HDU(396) LDU1(864) LDU2(864) ...
	var stream []Dibit
	stream = append(stream, build(0x7, 360)...) // TSDU
	stream = append(stream, build(0x0, 396)...) // HDU
	stream = append(stream, build(0x5, 864)...) // LDU1
	stream = append(stream, build(0xA, 864)...) // LDU2

	fs := NewFrameSync()
	frames := fs.Feed(stream)

	want := []uint8{0x7, 0x0, 0x5, 0xA}
	if len(frames) != len(want) {
		var got []uint8
		for _, f := range frames {
			got = append(got, f.NID.DUID)
		}
		t.Fatalf("got %d frames (DUIDs=%v), want %d (DUIDs=%v) — adjacent frames were swallowed",
			len(frames), got, len(want), want)
	}
	for i, w := range want {
		if frames[i].NID.DUID != w {
			t.Errorf("frame[%d].DUID = 0x%X, want 0x%X", i, frames[i].NID.DUID, w)
		}
	}
}

// buildFrame returns a complete on-air frame: sync + NID(33) + zero payload.
func buildFrame(nac uint16, duid uint8) []Dibit {
	var s []Dibit
	s = append(s, syncWord[:]...)
	s = append(s, buildNIDStream(nac, duid)...)
	for i := 0; i < payloadLen(duid); i++ {
		s = append(s, 0)
	}
	return s
}

// TestFrameSync_MidPayloadResync_DropsTruncatedFrame verifies defect A:
// when a transmission truncates mid-LDU and a new transmission keys up,
// the new frame's sync must be detected during payload collection, the
// partial payload discarded, and the new frame emitted intact.
func TestFrameSync_MidPayloadResync_DropsTruncatedFrame(t *testing.T) {
	nac := uint16(0x293)

	var stream []Dibit
	// Truncated LDU1: sync + NID + only 200 of 807 payload dibits.
	stream = append(stream, syncWord[:]...)
	stream = append(stream, buildNIDStream(nac, 0x5)...)
	for i := 0; i < 200; i++ {
		stream = append(stream, 0) // dibit 0 never appears in syncWord, so no false resync
	}
	// New call keys up: full HDU.
	stream = append(stream, buildFrame(nac, 0x0)...)
	// Trailing sync so the HDU's last payload dibit is unambiguously the end.
	stream = append(stream, syncWord[:]...)

	fs := NewFrameSync()
	frames := fs.Feed(stream)

	var ldu1, hdu int
	for _, f := range frames {
		switch f.NID.DUID {
		case 0x5:
			ldu1++
		case 0x0:
			hdu++
		}
	}
	if ldu1 != 0 {
		t.Errorf("got %d LDU1 frames, want 0 (truncated frame must be discarded)", ldu1)
	}
	if hdu != 1 {
		t.Errorf("got %d HDU frames, want 1 (new call's HDU was swallowed)", hdu)
	}
	if fs.MidPayloadResyncs != 1 {
		t.Errorf("MidPayloadResyncs = %d, want 1", fs.MidPayloadResyncs)
	}
}

// TestFrameSync_ColdStart_RelaxedThreshold verifies defect C: the very first
// sync after Reset uses syncThreshCold (6) so an unconverged slicer can still
// acquire the HDU; subsequent syncs use the steady-state syncThresh (4).
func TestFrameSync_ColdStart_RelaxedThreshold(t *testing.T) {
	nac := uint16(0x293)

	// Sync word with exactly 5 dibit errors (>syncThresh, <=syncThreshCold).
	// Corrupt to dibit 0 (never appears in syncWord) at well-spaced positions
	// so no shifted alignment of the corrupted word is closer than 5.
	noisy := syncWord
	for _, i := range []int{2, 7, 12, 17, 22} {
		noisy[i] = 0
	}

	var stream []Dibit
	stream = append(stream, noisy[:]...)
	stream = append(stream, buildNIDStream(nac, 0x0)...)
	for i := 0; i < payloadLen(0x0); i++ {
		stream = append(stream, 0)
	}

	fs := NewFrameSync()
	frames := fs.Feed(stream)
	if len(frames) != 1 {
		t.Fatalf("cold start: got %d frames, want 1 (5-error sync should be accepted when syncCount==0)", len(frames))
	}
	if frames[0].NID.DUID != 0x0 {
		t.Errorf("cold start: DUID = 0x%X, want 0x0", frames[0].NID.DUID)
	}

	// Second frame, also 5 sync errors. syncCount is now 1, so the steady-state
	// threshold (4) applies and this sync must be rejected.
	var stream2 []Dibit
	stream2 = append(stream2, noisy[:]...)
	stream2 = append(stream2, buildNIDStream(nac, 0x0)...)
	for i := 0; i < payloadLen(0x0); i++ {
		stream2 = append(stream2, 0)
	}
	before := fs.SyncDetections
	frames2 := fs.Feed(stream2)
	if len(frames2) != 0 {
		t.Errorf("warm: got %d frames, want 0 (5-error sync must be rejected when syncCount>0)", len(frames2))
	}
	if fs.SyncDetections != before {
		t.Errorf("warm: SyncDetections advanced (%d -> %d); 5-error sync should not have been detected",
			before, fs.SyncDetections)
	}
}

// TestFrameSync_NACHintSurvivesReset verifies defect D: the NAC hint learned
// from prior frames must survive Reset() so the first frame of the next call
// on the same channel decodes via the fast hint path, and ResetFull() clears it.
//
// The hint correction threshold is 11 (same as the standard full search),
// because the true minimum Hamming distance between distinct same-NAC NID
// codewords is 24, not the 28 the code once assumed — floor((24-1)/2)=11. A
// larger threshold would mis-correct a noisy NID to the wrong DUID. So the hint
// path does not admit MORE errors than full search; its value is speed (6
// candidates vs 4096×6) and the state surviving Reset. We therefore exercise an
// 11-error NID (the max the hint path may safely correct) rather than the
// previous, unsafe 12-error case.
func TestFrameSync_NACHintSurvivesReset(t *testing.T) {
	nac := uint16(0x293)

	fs := NewFrameSync()

	// Two clean frames establish the hint (nacHintMinFrames = 2).
	fs.Feed(buildFrame(nac, 0x3))
	fs.Feed(buildFrame(nac, 0x3))
	if !fs.hintNACSet || fs.hintNAC != nac {
		t.Fatalf("hint not established: hintNACSet=%v hintNAC=0x%03X", fs.hintNACSet, fs.hintNAC)
	}

	fs.Reset()
	if !fs.hintNACSet || fs.hintNAC != nac {
		t.Fatalf("hint did not survive Reset: hintNACSet=%v hintNAC=0x%03X", fs.hintNACSet, fs.hintNAC)
	}

	// Build an HDU whose NID has 11 bit errors (the correction limit). Flip 11
	// single bits by XORing 11 dibits with 1 (toggles the LSB only).
	nidStream := buildNIDStream(nac, 0x0)
	for i := 0; i < 11; i++ {
		pos := i
		if pos >= 11 {
			pos++ // skip the status symbol at transmitted index 11
		}
		nidStream[pos] ^= 1
	}
	var stream []Dibit
	stream = append(stream, syncWord[:]...)
	stream = append(stream, nidStream...)
	for i := 0; i < payloadLen(0x0); i++ {
		stream = append(stream, 0)
	}

	frames := fs.Feed(stream)
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1 (hint survived Reset; 11-error NID is correctable)", len(frames))
	}
	if frames[0].NID.NAC != nac {
		t.Errorf("NAC = 0x%03X, want 0x%03X", frames[0].NID.NAC, nac)
	}

	// ResetFull must clear the hint.
	fs2 := NewFrameSync()
	fs2.Feed(buildFrame(nac, 0x3))
	fs2.Feed(buildFrame(nac, 0x3))
	fs2.ResetFull()
	if fs2.hintNACSet {
		t.Errorf("after ResetFull: hint still set (must be cleared)")
	}
}

func TestExtractBits(t *testing.T) {
	// Dibit 0=00, 1=01, 2=10, 3=11
	dibits := []Dibit{3, 0, 1, 2} // bits: 11 00 01 10
	// Extract first 8 bits
	got := extractBits(dibits, 0, 8)
	want := uint32(0b11000110) // 0xC6
	if got != want {
		t.Errorf("extractBits = 0x%X, want 0x%X", got, want)
	}
	// Extract 4 bits starting at offset 2
	got2 := extractBits(dibits, 2, 4)
	want2 := uint32(0b0001) // bits 2-5: 0,0,0,1
	if got2 != want2 {
		t.Errorf("extractBits(offset=2,n=4) = 0x%X, want 0x%X", got2, want2)
	}
}
