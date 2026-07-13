// Package phase2 implements P25 Phase 2 (H-DQPSK TDMA) demodulation and
// framing. Output is classified bursts with slot/location/DUID metadata.
// Voice decode, descrambling, and audio output are handled by callers.
package phase2

const (
	// SymbolRate is the H-DQPSK channel symbol rate.
	SymbolRate = 6000.0

	// BurstDibits is the per-burst payload length (180 dibits = 360 bits = 30 ms
	// at SymbolRate 6000 sym/s).
	BurstDibits = 180

	// SuperframeBursts is the number of bursts in one superframe (12 x 30 ms = 360 ms).
	SuperframeBursts = 12

	// SyncDibits is the length of the Phase 2 frame sync pattern.
	SyncDibits = 20

	// SyncBits is SyncDibits * 2.
	SyncBits = 40

	// SyncMagic is the P25 Phase 2 frame sync pattern, 40 bits, MSB-first.
	// Source: op25 frame_sync_magics.h (P25P2_FRAME_SYNC_MAGIC).
	SyncMagic uint64 = 0x575D57F7FF

	// SyncMask masks the relevant 40 bits.
	SyncMask uint64 = 0xFFFFFFFFFF

	// SyncErrorThreshold is the maximum bit-error count for sync detection.
	// op25 uses 4. Matches the 10% threshold typical for marginal SNR.
	SyncErrorThreshold = 4

	// DUIDPositions are the ABSOLUTE dibit indices within a 180-dibit burst
	// that carry the DUID bits. op25 extract_duid reads burstp[10/47/132/169]
	// where burstp = &dibits[10], i.e. absolute 20/57/142/179, on the RAW
	// (pre-descramble) burst. Source: op25 p25p2_duid.cc::extract_duid +
	// p25p2_tdma.cc:698 (burstp = &dibits[10]).
	DUIDPos0 = 20
	DUIDPos1 = 57
	DUIDPos2 = 142
	DUIDPos3 = 179

	// PayloadOffset is where the descrambled payload starts within the
	// 180-dibit burst. op25 calls this "burstp = &dibits[10]".
	PayloadOffset = 10

	// VCW (voice codeword) offsets relative to PayloadOffset.
	// Full burst position = PayloadOffset + offset.
	// Source: op25 p25p2_tdma.cc lines 737-741.
	VCW1Offset = 11  // burst[21]: first 36-dibit voice codeword
	VCW2Offset = 48  // burst[58]: second voice codeword
	VCW3Offset = 96  // burst[106]: third voice codeword (4V only)
	VCW4Offset = 133 // burst[143]: fourth voice codeword (4V only)

	// ESSOffset is the ESS position relative to PayloadOffset.
	// 12 dibits carrying encryption sync signal (algid/keyid/MI fragments).
	// Source: op25 p25p2_tdma.cc line 736.
	ESSOffset = 84 // burst[94]
	ESSDibits = 12
)

// WhichSlot maps the 12 superframe burst positions (ISCH "location" field)
// to slot index (0 or 1). Note position 10 maps to slot 1, not 0 — the
// pattern is asymmetric. Source: op25 p25p2_tdma.cc.
var WhichSlot = [SuperframeBursts]int{0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0}
