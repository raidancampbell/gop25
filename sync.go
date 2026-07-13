package p25

import "math"

const (
	syncLen        = 24 // frame sync: 24 dibits (48 bits)
	nidLen         = 32 // NID: 32 data dibits (64 bits) — but 33 transmitted (includes 1 status)
	nidSpan        = 33 // transmitted dibits in NID region (32 data + 1 status at position 11)
	syncThresh     = 4  // max dibit errors for steady-state sync detection
	syncThreshCold = 6  // relaxed threshold for first sync after Reset, before slicer convergence

	// softSyncThresh is the minimum normalized soft correlation (cosine, range
	// [-1,+1]) for the soft-decision sync gate to admit acquisition when the
	// hard dibit-Hamming gate has missed. softCorrelate is amplitude-invariant,
	// so a faded-but-clean sync scores ~1.0 regardless of signal level; pure
	// noise scores ~0 with std ≈ 1/sqrt(syncLen) ≈ 0.20. 0.62 (~3σ above noise)
	// recovers weak real syncs while leaving false acquisitions rare and gated
	// by the downstream NID-BCH + DUID-0xC peek-CRC backstops. Calibrated on the
	// 2026-06-17 uplink corpus (see data/sndcp-uplink-analysis-20260617).
	softSyncThresh = 0.62
)

// syncPol is the per-symbol polarity (+1/-1) of the frame sync word in C4FM
// level space. Every sync dibit is 1 or 3, so its ideal level (c4fmLevels) is
// +3 or -3; softCorrelate matches the received soft stream against these signs.
var syncPol [syncLen]float32

func init() {
	for i, d := range syncWord {
		if c4fmLevels[d] < 0 {
			syncPol[i] = -1
		} else {
			syncPol[i] = +1
		}
	}
}

// syncWord is the P25 Phase 1 frame sync pattern (TIA-102.BAAA).
// Hex 0x5575F5FF77FF unpacked to 24 dibits (MSB-first pairs).
var syncWord = [syncLen]Dibit{
	1, 1, 1, 1, // 0x55
	1, 3, 1, 1, // 0x75
	3, 3, 1, 1, // 0xF5
	3, 3, 3, 3, // 0xFF
	1, 3, 1, 3, // 0x77
	3, 3, 3, 3, // 0xFF
}

// payloadLen returns the number of payload dibits following the NID for each DUID.
// Total frame lengths (dibits) are from TIA-102.BAAA-A table 7-1, cross-checked
// against op25's max_frame_lengths (p25_framer.cc:18) and verified by on-air
// measurement of inter-sync gaps (cmd/diagnose25, May 8 captures).
//
// Payload = total - syncLen(24) - nidSpan(33).
//
// NOTE: per the TIA spec DUID 0x7 is the TSDU and 0xF is the TDU-with-LC; the
// rest of this codebase currently has those names swapped. The lengths below
// are correct for the on-air DUID values regardless of naming.
func payloadLen(duid uint8) int {
	switch duid {
	case 0x0: // HDU — 792 bits
		return 396 - syncLen - nidSpan
	case 0x3: // TDU — 144 bits
		return 72 - syncLen - nidSpan
	case 0x5: // LDU1 — 1728 bits
		return 864 - syncLen - nidSpan
	case 0x7: // TSDU (single-block) — 720 bits
		return 360 - syncLen - nidSpan
	case 0xA: // LDU2 — 1728 bits
		return 864 - syncLen - nidSpan
	case 0xC: // PDU — variable; op25 uses 962 bits as a cap
		return 481 - syncLen - nidSpan
	case 0xF: // TDU with Link Control — 432 bits
		return 216 - syncLen - nidSpan
	default:
		return 0
	}
}

// NID holds a decoded P25 Network ID (NAC + DUID).
type NID struct {
	NAC  uint16
	DUID uint8
}

// Frame is a single P25 data unit extracted from the dibit stream.
type Frame struct {
	NID     NID
	Payload []Dibit   // raw dibits after sync + NID (length depends on DUID)
	Soft    []float32 // normalized soft value per Payload dibit, 1:1 aligned;
	// nil when the upstream demod has no soft info (legacy Feed callers).
	// Consumers (e.g. parsePDUWithSoft) MUST nil-check rather than blindly
	// indexing.
}

type syncState int

const (
	stateSearching      syncState = iota
	stateCollectNID               // collecting 32 NID dibits
	stateCollectPayload           // collecting payload dibits
)

// FrameSync detects P25 frame boundaries and extracts NID + payload.
type FrameSync struct {
	state     syncState
	ring      [syncLen]Dibit   // sliding window for sync correlation
	softRing  [syncLen]float32 // soft values 1:1 with ring; used by softCorrelate
	ringIdx   int
	ringFull  bool
	nidBuf    [nidLen]Dibit
	nidIdx    int // data dibits collected so far
	nidRawIdx int // total dibits received (including status positions)
	payload   []Dibit
	// softPayload holds the normalized soft value for each Dibit in payload,
	// 1:1 aligned, when the caller is using FeedSoft. Empty (nil-or-zero-len)
	// when the legacy soft-less Feed path is in use; emitted Frame.Soft is then
	// nil. Reset everywhere payload is reset.
	softPayload []float32
	payloadCap  int  // expected payload dibits for current DUID
	pduPeeked   bool // true once the PDU header peek has run for the current frame
	currentNID  NID
	syncCount   int // consecutive successful syncs

	// NAC hint: once we have decoded at least nacHintMinFrames consecutive frames
	// with the same NAC, we record it and use decodeNIDWithHintDist for subsequent
	// NID decodes.  This extends the effective correction threshold from 11 to 13
	// bit errors for the known NAC, reducing frame loss on marginal signals.
	hintNAC          uint16
	hintNACSet       bool
	hintNACCount     int // how many consecutive frames have matched hintNAC
	nacHintMinFrames int // minimum consecutive matches before enabling hint

	// Debug counters
	SyncDetections     int
	SoftSyncDetections int // acquisitions admitted by the soft gate that the hard gate missed
	NIDAttempts        int
	NIDFailures        int
	FramesEmitted      int
	HintRecoveries     int // frames recovered by hint-based decode
	MidPayloadResyncs  int // truncated frames discarded due to sync detected mid-payload
	ColdPeekRejects    int // cold-sync DUID-0xC frames discarded because PDU header peek CRC failed
}

// NewFrameSync creates a FrameSync in searching state.
func NewFrameSync() *FrameSync {
	return &FrameSync{
		nacHintMinFrames: 2,
	}
}

// Feed processes incoming dibits and returns any complete frames. Soft
// information is unavailable on this path; emitted Frame.Soft is nil.
// Production code paths (P25Decoder.Process / ProcessRaw) use FeedSoft to
// thread the demodulator's soft symbol stream through; this signature is
// retained for diagnostic CLIs and existing tests that build dibit streams
// directly.
func (fs *FrameSync) Feed(dibits []Dibit) []Frame {
	var frames []Frame
	for _, d := range dibits {
		if f, ok := fs.feedOne(d, 0, false); ok {
			frames = append(frames, f)
		}
	}
	return frames
}

// FeedSoft processes incoming dibits with their 1:1-aligned soft values and
// returns any complete frames. soft must have the same length as dibits.
// Emitted Frame.Soft carries the normalized per-payload-dibit soft values,
// to be consumed by the soft-decision Viterbi in parsePDUWithSoft.
func (fs *FrameSync) FeedSoft(dibits []Dibit, soft []float32) []Frame {
	var frames []Frame
	for i, d := range dibits {
		var sv float32
		if i < len(soft) {
			sv = soft[i]
		}
		if f, ok := fs.feedOne(d, sv, true); ok {
			frames = append(frames, f)
		}
	}
	return frames
}

// SyncCount returns how many consecutive frame syncs have been detected.
func (fs *FrameSync) SyncCount() int {
	return fs.syncCount
}

// Reset returns the FrameSync to the searching state.
// The NAC hint is preserved across resets so that back-to-back transmissions
// on the same channel can immediately benefit from hint-assisted decoding.
func (fs *FrameSync) Reset() {
	fs.state = stateSearching
	fs.ringIdx = 0
	fs.ringFull = false
	fs.nidIdx = 0
	fs.payload = fs.payload[:0]
	fs.softPayload = fs.softPayload[:0]
	fs.payloadCap = 0
	fs.pduPeeked = false
	fs.syncCount = 0
	// hintNAC / hintNACSet / hintNACCount deliberately preserved
}

// ResetFull is Reset plus clearing the NAC hint. Use this when the channel
// is retuned to a different frequency where the previously-learned NAC is
// no longer applicable.
func (fs *FrameSync) ResetFull() {
	fs.Reset()
	fs.hintNAC = 0
	fs.hintNACSet = false
	fs.hintNACCount = 0
}

// SoftReset returns the FrameSync to the searching state without clearing the
// ring buffer. This is used on squelch close so that the ring remains warm
// for immediate HDU detection on the next call, while still aborting any
// in-progress payload collection from a frame that was cut short.
func (fs *FrameSync) SoftReset() {
	fs.state = stateSearching
	fs.nidIdx = 0
	fs.payload = fs.payload[:0]
	fs.softPayload = fs.softPayload[:0]
	fs.payloadCap = 0
	fs.pduPeeked = false
	fs.syncCount = 0
	// Ring buffer, hintNAC deliberately preserved
}

// feedOne advances the state machine by one dibit and returns the completed
// frame, if any. sv is the dibit's normalized soft value (only meaningful when
// haveSoft is true; ignored otherwise). When haveSoft, sv is appended to
// softPayload in lockstep with payload, and the eventual Frame.Soft is filled
// from softPayload; on the soft-less path Frame.Soft is left nil.
func (fs *FrameSync) feedOne(d Dibit, sv float32, haveSoft bool) (Frame, bool) {
	switch fs.state {
	case stateSearching:
		fs.ring[fs.ringIdx] = d
		fs.softRing[fs.ringIdx] = sv
		fs.ringIdx = (fs.ringIdx + 1) % syncLen
		if !fs.ringFull {
			if fs.ringIdx == 0 {
				fs.ringFull = true
				// Fall through to check correlation on the now-full ring.
			} else {
				return Frame{}, false
			}
		}
		thresh := syncThresh
		if fs.syncCount == 0 {
			// Slicer is unconverged before the first frame of a call, so
			// tolerate a few extra dibit errors when acquiring initial sync.
			thresh = syncThreshCold
		}
		// Soft-decision sync gate: when the hard dibit-Hamming correlation
		// misses, fall back to the amplitude-invariant soft correlation. This
		// recovers weak bursts whose individual symbols slice to the wrong
		// dibit (hard miss) but still lean the right polarity (soft hit). Only
		// available when the caller threads soft values (FeedSoft); the legacy
		// Feed path leaves softRing zero, so softCorrelate returns 0 and never
		// fires. A soft-admitted sync still has to clear the NID-BCH gate (and,
		// for DUID 0xC, the cold peek-CRC), so false soft acquisitions on noise
		// are rejected downstream rather than emitted.
		hardHit := fs.correlate() <= thresh
		softHit := !hardHit && haveSoft && fs.softCorrelate() >= softSyncThresh
		if hardHit || softHit {
			fs.state = stateCollectNID
			fs.nidIdx = 0
			fs.nidRawIdx = 0
			fs.SyncDetections++
			if softHit {
				fs.SoftSyncDetections++
			}
		}
		return Frame{}, false

	case stateCollectNID:
		// Status symbol falls at NID raw position 11 (full-frame position 35).
		// Skip it — don't store it in nidBuf.
		if fs.nidRawIdx == 11 {
			fs.nidRawIdx++
			return Frame{}, false
		}
		fs.nidBuf[fs.nidIdx] = d
		fs.nidIdx++
		fs.nidRawIdx++
		// Keep ring warm during NID collection so we can immediately
		// detect a sync if the NID decode fails (false sync case).
		fs.ring[fs.ringIdx] = d
		fs.softRing[fs.ringIdx] = sv
		fs.ringIdx = (fs.ringIdx + 1) % syncLen
		if fs.ringIdx == 0 {
			fs.ringFull = true
		}
		if fs.nidIdx < nidLen {
			return Frame{}, false
		}
		fs.NIDAttempts++
		// Pack 32 dibits into a 64-bit word for BCH decode
		received := packDibits(fs.nidBuf[:])
		var nid NID
		var ok bool
		if fs.hintNACSet {
			var wasHint bool
			nid, ok, wasHint = fs.decodeNIDHinted(received)
			if ok && wasHint {
				fs.HintRecoveries++
			}
		} else {
			nid, ok = decodeNID(received)
		}
		if !ok {
			// NID decode failed — return to searching.
			// Ring is already warm from the NID dibits fed above.
			fs.state = stateSearching
			fs.syncCount = 0
			fs.NIDFailures++
			fs.hintNACCount = 0
			return Frame{}, false
		}
		// Update NAC hint tracking
		if nid.NAC == fs.hintNAC {
			fs.hintNACCount++
		} else {
			fs.hintNAC = nid.NAC
			fs.hintNACCount = 1
			fs.hintNACSet = false
		}
		if !fs.hintNACSet && fs.hintNACCount >= fs.nacHintMinFrames {
			fs.hintNACSet = true
		}
		fs.currentNID = nid
		fs.syncCount++
		pLen := payloadLen(nid.DUID)
		if pLen == 0 {
			// TDU or unknown: no payload, emit immediately.
			// Ring is already warm from NID collection above.
			fs.state = stateSearching
			return Frame{NID: nid, Payload: nil}, true
		}
		fs.payloadCap = pLen
		fs.payload = ensureCap(fs.payload, pLen)
		fs.payload = fs.payload[:0]
		fs.softPayload = fs.softPayload[:0]
		fs.pduPeeked = false
		fs.state = stateCollectPayload
		return Frame{}, false

	case stateCollectPayload:
		fs.payload = append(fs.payload, d)
		if haveSoft {
			fs.softPayload = append(fs.softPayload, sv)
		}
		// PDU (DUID 0xC) frames are variable-length: payloadLen(0xC) returns the
		// minimum span (1 header + 3 data blocks). Once one full header block
		// worth of payload has arrived, peek-decode the header and extend the
		// cap to (1+BlocksToFollow)*pduBlockBits non-status bits if the CRC
		// passes.
		//
		// On a cold-start sync (syncCount==1, admitted with the relaxed
		// syncThreshCold=6 plus the standard NID threshold of 11), a peek-CRC
		// failure means the dibits at the sync site don't form a valid PDU
		// header — the timing PLL had locked to a wrong attractor on the
		// noise lead-in and produced 32 NID dibits that happened to BCH-decode
		// to the local NAC by luck (4096 NACs × 7 DUIDs occupy enough of the
		// 64-bit BCH(63,16) codeword space that distance ≤11 is achievable on
		// noise). Emitting a 424-dibit junk frame here is harmless on its own
		// (hdrCRC=false is reported correctly) but consumes ~96 ms of dibit
		// stream that could have contained a real later burst, and fills
		// pcaps with confusing "blks=42 hdrCRC=false" rows. Drop the frame
		// instead so the decoder returns to searching.
		//
		// Once syncCount > 1 the sync threshold tightens to syncThresh=4 and
		// peek failures from then on are real SNR-marginal frames; keep them
		// (callers want to see hdrCRC=false to know the signal is degraded).
		if !fs.pduPeeked && fs.currentNID.DUID == 0xC && len(fs.payload) >= pduHeaderPeekDibits {
			fs.pduPeeked = true
			blks, ok := peekPDUHeader(fs.payload[:pduHeaderPeekDibits])
			if ok {
				if newCap := pduPayloadDibits(int(blks)); newCap > fs.payloadCap {
					fs.payloadCap = newCap
					// append() grows fs.payload on demand; no pre-grow needed.
				}
			} else if fs.syncCount == 1 {
				fs.payload = fs.payload[:0]
				fs.softPayload = fs.softPayload[:0]
				fs.payloadCap = 0
				fs.pduPeeked = false
				fs.state = stateSearching
				fs.syncCount = 0
				fs.ColdPeekRejects++
				return Frame{}, false
			}
		}
		// Continue feeding the ring buffer during payload collection so it's
		// already full and warm when the frame completes. This eliminates the
		// 24-dibit (5ms) blind window that previously existed between frames,
		// improving HDU detection on back-to-back calls.
		fs.ring[fs.ringIdx] = d
		fs.softRing[fs.ringIdx] = sv
		fs.ringIdx = (fs.ringIdx + 1) % syncLen
		if fs.ringIdx == 0 {
			fs.ringFull = true
		}
		// Mid-payload resync: if a TX truncates mid-frame and a new TX keys
		// up, its sync would otherwise be absorbed as this frame's payload
		// tail and the new HDU lost. Once the ring is fully past the
		// legitimate sync that started this frame (>=syncLen payload dibits),
		// any sync match before payloadCap is a genuine truncation. Use the
		// steady-state threshold here, not the cold one, to avoid spurious
		// truncations on noisy payloads.
		if len(fs.payload) >= syncLen && len(fs.payload) < fs.payloadCap &&
			fs.correlate() <= syncThresh {
			fs.MidPayloadResyncs++
			fs.payload = fs.payload[:0]
			fs.softPayload = fs.softPayload[:0]
			fs.state = stateCollectNID
			fs.nidIdx = 0
			fs.nidRawIdx = 0
			fs.SyncDetections++
			return Frame{}, false
		}
		if len(fs.payload) < fs.payloadCap {
			return Frame{}, false
		}
		f := Frame{
			NID:     fs.currentNID,
			Payload: make([]Dibit, len(fs.payload)),
		}
		copy(f.Payload, fs.payload)
		if len(fs.softPayload) > 0 {
			f.Soft = make([]float32, len(fs.softPayload))
			copy(f.Soft, fs.softPayload)
		}
		// Ring is already warm from the payload dibits above — no need to reset it.
		fs.state = stateSearching
		fs.FramesEmitted++
		return f, true
	}
	return Frame{}, false
}

// correlate computes Hamming distance (dibit-level) between the ring buffer
// contents and the sync word.
func (fs *FrameSync) correlate() int {
	dist := 0
	for i := 0; i < syncLen; i++ {
		if fs.ring[(fs.ringIdx+i)%syncLen] != syncWord[i] {
			dist++
		}
	}
	return dist
}

// softCorrelate computes the normalized soft correlation (cosine) between the
// soft-value ring and the sync word's polarity pattern, in [-1,+1]. It is the
// soft-decision analogue of correlate: where correlate counts hard dibit
// mismatches (so a near-threshold symbol sliced to the wrong dibit counts as a
// full miss), softCorrelate weights each symbol by how strongly its soft value
// leans toward the expected polarity. Because it normalizes by the ring's own
// energy, it is amplitude-invariant — a faded clean sync still scores ~1.0,
// which is exactly what lets it acquire weak bursts the hard gate drops. Pure
// noise scores ~0. Returns 0 if the ring carries no soft energy (e.g. the
// soft-less Feed path, where softRing stays zero).
func (fs *FrameSync) softCorrelate() float32 {
	var dot, energy float64
	for i := 0; i < syncLen; i++ {
		v := float64(fs.softRing[(fs.ringIdx+i)%syncLen])
		dot += v * float64(syncPol[i])
		energy += v * v
	}
	if energy == 0 {
		return 0
	}
	return float32(dot / math.Sqrt(energy*float64(syncLen)))
}

// packDibits packs a slice of dibits into a uint64, MSB-first (2 bits per dibit).
func packDibits(dibits []Dibit) uint64 {
	var v uint64
	for _, d := range dibits {
		v = (v << 2) | uint64(d)
	}
	return v
}

func ensureCap(s []Dibit, n int) []Dibit {
	if cap(s) >= n {
		return s
	}
	return make([]Dibit, 0, n)
}

// decodeNIDHinted tries hint-based decode first (known NAC, threshold 13),
// then falls back to the standard full search (threshold 11).
// wasHint reports whether the hint path admitted a frame the standard
// decode could not (i.e. 12-13 bit errors); used only for the debug counter.
func (fs *FrameSync) decodeNIDHinted(received uint64) (nid NID, ok bool, wasHint bool) {
	nid, dist, ok := decodeNIDWithHintDist(received, fs.hintNAC)
	if !ok {
		return NID{}, false, false
	}
	return nid, true, dist > 11
}
