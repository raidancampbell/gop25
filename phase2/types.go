package phase2

import "github.com/raidancampbell/gop25"

// Burst is one Phase 2 burst: 180 dibits plus decoded metadata.
type Burst struct {
	Dibits [BurstDibits]p25.Dibit // descrambled payload after Decoder.processBurst
	Raw    [BurstDibits]p25.Dibit // raw pre-descramble dibits; set by the decoder
	ISCH   ISCHInfo
	DUID   uint8 // raw 8-bit DUID extracted from RAW dibits 20/57/142/179
	Type   BurstType
}

// ISCHInfo is the decoded Inter-Slot Signalling CHannel field.
// Identifies which superframe burst and which slot a burst belongs to.
type ISCHInfo struct {
	Location int  // 0..11, burst position within superframe; -1 if unknown
	Slot     int  // 0 or 1, derived from WhichSlot[Location]; -1 if Location is -1
	IsSISCH  bool // true for the rare "super-ISCH" sync indicator codeword
	Valid    bool // false if Hamming decode failed
}

// BurstType is the high-level classification of a burst.
type BurstType int

const (
	BurstUnknown BurstType = iota
	Burst4V                // four voice codewords (FEC-detected; DUID id 0)
	Burst2V                // two voice codewords + SACCH/FACCH (FEC-detected; DUID id 6)
	BurstSACCH             // DUID id 3 (scrambled) or 12 (unscrambled) SACCH; no voice
	BurstLCCH              // DUID id 13: unscrambled LCCH (CRC-16); no voice
	BurstFACCH             // DUID id 9 (scrambled) or 15 (unscrambled) FACCH; no voice
)

// MAC control opcodes (3-bit). Source: op25 process_mac_pdu (p25p2_tdma.cc:171).
const (
	MACOpSignal   uint8 = 0
	MACOpPTT      uint8 = 1
	MACOpEndPTT   uint8 = 2
	MACOpIdle     uint8 = 3
	MACOpActive   uint8 = 4
	MACOpHangtime uint8 = 6
)

// P2VoiceFrame holds decoded PCM audio from one Phase 2 TDMA voice burst.
// A 4V burst produces up to 640 PCM samples (4 × 160); a 2V burst up to 320.
type P2VoiceFrame struct {
	PCM  []float32 // decoded 8 kHz float32 PCM samples
	Slot int       // 0 or 1 — which TDMA slot this came from
	Errs int       // total FEC errors summed across all voice codewords

	// ControlOnly is true for frames decoded from a voice-less control burst
	// (SACCH/FACCH/LCCH). PCM is nil for these; they carry MAC identity / alias /
	// encryption and a MACOpcode for the pipeline lifecycle layer.
	ControlOnly bool
	MACOpcode   uint8 // MAC control opcode (MACOp*); only meaningful when ControlOnly

	// Encryption metadata from ESS decode. Updated after each complete
	// superframe cycle (4×4V + 1×2V). AlgID 0x80 = clear, 0x00 = N/A.
	AlgID     uint8
	KeyID     uint16
	MI        [9]byte
	Encrypted bool // true if AlgID indicates active encryption
	Decrypted bool // true if encrypted AND successfully decrypted (PCM is clear)

	// Call identity decoded from the in-call MAC signalling (FACCH on the 2V
	// burst), independent of the Phase 1 control-channel grant. Zero/false when
	// no MAC identity has been seen on this slot yet.
	Talkgroup       uint16
	SourceID        uint32
	ServiceOpts     uint8 // MAC service options byte (emergency/enc/priority bits)
	IdentityFromMAC bool

	// Talker alias decoded from vendor-specific MAC sub-messages (0x91/0x95
	// Motorola, 0xA8 Harris) on the in-call FACCH. Empty until a complete alias
	// is assembled; TalkerAliasTGID is the talkgroup from the Motorola header.
	TalkerAlias     string
	TalkerAliasTGID uint16
	TalkerAliasUnit uint32 // SUID unit ID from the Motorola alias (0 for Harris)

	// In-call GPS decoded from a Harris Talker GPS MAC sub-message (op=0xAA,
	// MFID=0xA4) on the FACCH. GPSOK is false until a position has been seen.
	GPS   p25.GPSPosition
	GPSOK bool
}
