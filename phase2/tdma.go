package phase2

import (
	"sync"

	"github.com/raidancampbell/gop25"
)

// KeyLookupFunc resolves an encryption key from algorithm ID and key ID.
// Returns the raw key bytes and true if found, or nil and false if not.
type KeyLookupFunc func(algID uint8, keyID uint16) (key []byte, ok bool)

// TDMAProcessor manages the two-slot TDMA state machine for P25 Phase 2.
// It descrambles voice bursts, extracts voice codewords, decodes FEC, and
// invokes the AMBE+2 vocoder. One TDMAProcessor handles both timeslots.
//
// Usage: call ProcessBurst for each classified burst; returned P2VoiceFrames
// contain decoded PCM audio ready for playback or recording.
//
// SetScrambleParams / SetXORMask / SetKeyLookup may be called from a
// different goroutine (e.g. a control-channel decoder propagating
// WACN/SYSID or key config). A mutex guards shared fields; the lock is
// uncontended on the hot ProcessBurst path.
type TDMAProcessor struct {
	mu        sync.Mutex
	xorMask   [SuperframeDibits]p25.Dibit
	hasMask   bool
	keyLookup KeyLookupFunc
	slots     [2]slotState
}

type slotState struct {
	vocoder *p25.AMBE2Decoder
	ess     *ESSState
	adp     *p25.ADP // ADP cipher state (nil until first key match)
	adpKey  []byte   // raw key bytes for the active ADP cipher
	hasMI   bool     // true after first Prepare(); false until ESS yields MI

	// Latched call identity from the most recent MAC PDU on this slot.
	macTG   uint16
	macSrc  uint32
	macOpts uint8
	macSeen bool

	// Phase 2 talker-alias reassembly state and latched alias.
	aliasAsm     p2AliasAssembler
	macAlias     string
	macAliasTGID uint16
	macAliasUnit uint32

	// Latched in-call GPS from the most recent Harris GPS MAC sub-message.
	macGPS     p25.GPSPosition
	macGPSSeen bool
}

// NewTDMAProcessor creates a processor. Call SetScrambleParams once system
// identity parameters are known (from the control channel).
func NewTDMAProcessor() *TDMAProcessor {
	t := &TDMAProcessor{}
	t.slots[0].vocoder = p25.NewAMBE2Decoder()
	t.slots[0].ess = NewESSState()
	t.slots[1].vocoder = p25.NewAMBE2Decoder()
	t.slots[1].ess = NewESSState()
	return t
}

// SetScrambleParams configures the XOR descrambling mask from the system
// identity. Must be called before voice bursts can be descrambled.
// Thread-safe: may be called from any goroutine.
func (t *TDMAProcessor) SetScrambleParams(nac uint16, sysid uint16, wacn uint32) {
	mask := GenerateXORMask(nac, sysid, wacn)
	t.mu.Lock()
	t.xorMask = mask
	t.hasMask = true
	t.mu.Unlock()
}

// SetXORMask sets the XOR mask directly (e.g. from an external source).
// Thread-safe: may be called from any goroutine.
func (t *TDMAProcessor) SetXORMask(mask [SuperframeDibits]p25.Dibit) {
	t.mu.Lock()
	t.xorMask = mask
	t.hasMask = true
	t.mu.Unlock()
}

// SetKeyLookup configures the key-resolution function used for ADP decryption.
// Thread-safe: may be called from any goroutine.
func (t *TDMAProcessor) SetKeyLookup(fn KeyLookupFunc) {
	t.mu.Lock()
	t.keyLookup = fn
	t.mu.Unlock()
}

// HasKey reports whether a usable decryption key exists for (algID, keyID)
// via the configured key lookup, WITHOUT decrypting. The slot-open gate uses
// this as a deterministic key-availability signal: the per-frame Decrypted
// flag only goes true after the ADP cipher is primed (one superframe into the
// call), which would clip the head of a keyed call joined mid-stream.
func (t *TDMAProcessor) HasKey(algID uint8, keyID uint16) bool {
	t.mu.Lock()
	fn := t.keyLookup
	t.mu.Unlock()
	if fn == nil {
		return false
	}
	_, ok := fn(algID, keyID)
	return ok
}

// ProcessBurst handles one classified, already-descrambled burst. Returns a
// P2VoiceFrame if the burst is voice-bearing (4V or 2V) and decoding succeeds,
// or nil otherwise. Descrambling and DUID classification are performed by
// Decoder.Process before this method is called.
//
// For encrypted calls with a matching key, ADP decryption is applied between
// FEC decode and vocoder. The cipher is prepared once per superframe cycle
// on the 2V burst, after that burst's voice codewords have been processed
// (matching op25 timing: current 2V voice uses the old cipher state, then
// prepare() sets up the keystream for the next cycle).
func (t *TDMAProcessor) ProcessBurst(b Burst) *P2VoiceFrame {
	// Control bursts (voice-less SACCH/FACCH/LCCH): decode the MAC PDU and emit
	// a voice-less P2VoiceFrame carrying identity/alias/encryption. The raw DUID
	// selects scrambled (ids 3/9 -> descrambled b.Dibits) vs unscrambled (ids
	// 12/13/15 -> raw b.Raw); op25 handle_packet:754-766.
	if b.Type == BurstSACCH || b.Type == BurstFACCH || b.Type == BurstLCCH {
		return t.processControlBurst(b)
	}

	if b.Type != Burst4V && b.Type != Burst2V {
		return nil
	}
	if !b.ISCH.Valid || b.ISCH.Slot < 0 {
		return nil
	}

	slot := b.ISCH.Slot
	if slot > 1 {
		slot = 1
	}
	ss := &t.slots[slot]
	voc := ss.vocoder

	// Feed ESS from the descrambled burst (must happen before voice decode
	// so encryption state is current). op25 calls handle_4V2V_ess before
	// handle_voice_frame.
	ss.ess.Feed(b.Type, b.Dibits)

	// The 2V burst carries a FACCH alongside its two voice codewords. Decode it
	// to recover call identity (talkgroup/source/service-opts) directly from the
	// voice channel, independent of the Phase 1 control-channel grant. Also feed
	// any vendor alias sub-messages to the per-slot assembler (regardless of
	// HasIdentity, as alias sub-messages can arrive on MAC PDUs without 0x01).
	if b.Type == Burst2V {
		if pdu, ok := DecodeACCH(b.Dibits, ACCHFacch); ok {
			// Latch identity if present
			if pdu.HasIdentity {
				ss.macTG = pdu.Talkgroup
				ss.macSrc = pdu.SourceID
				ss.macOpts = pdu.ServiceOpts
				ss.macSeen = true
			}
			// Feed alias sub-messages (regardless of HasIdentity)
			for _, msg := range pdu.vendorAliasMsgs {
				alias, tg, unit, complete := ss.aliasAsm.feed(msg)
				if complete {
					ss.macAlias = alias
					ss.macAliasTGID = tg
					ss.macAliasUnit = unit
				}
			}
			// Latch in-call GPS (last-known wins).
			if pdu.GPSOK {
				ss.macGPS = pdu.GPS
				ss.macGPSSeen = true
			}
		}
	}

	burstID := ss.ess.BurstPosition()

	// Determine VCW offsets for this burst type.
	offsets := []int{
		PayloadOffset + VCW1Offset,
		PayloadOffset + VCW2Offset,
	}
	if b.Type == Burst4V {
		offsets = append(offsets,
			PayloadOffset+VCW3Offset,
			PayloadOffset+VCW4Offset,
		)
	}

	pcm := make([]float32, 0, len(offsets)*160)
	totalErrs := 0
	totalCW := 0
	uncorrectable := 0
	decrypted := false

	// Snapshot key lookup (thread-safe field).
	t.mu.Lock()
	keyLookup := t.keyLookup
	t.mu.Unlock()

	for cwIdx, off := range offsets {
		if off+VoiceCWDibits > BurstDibits {
			continue
		}
		vcwDibits := b.Dibits[off : off+VoiceCWDibits]
		result := DecodeVoiceCW(vcwDibits)
		totalErrs += result.Errs
		totalCW++ // count every processed codeword
		if result.C0Uncorrectable {
			uncorrectable++ // c0 had a detected weight->=4 error
		}

		if result.OK {
			// ADP decryption: XOR packed codeword with keystream.
			if ss.hasMI && ss.adp != nil && burstID >= 0 {
				packed := PackCW(result.U)
				ss.adp.XORCodewordP2(&packed, burstID, cwIdx)
				result.U = UnpackCW(packed)
				decrypted = true
			}

			ambeD := PackAMBE(result.U)
			// Decode returns fecErrs unchanged; result.Errs was counted above.
			samples, _ := voc.Decode(ambeD, result.Errs)
			pcm = append(pcm, samples[:]...)
		} else {
			// FEC failed — emit silence to keep timing and advance vocoder state.
			var silence [49]uint8
			samples, _ := voc.Decode(silence, 99)
			pcm = append(pcm, samples[:]...)
		}
	}

	// After processing voice on a 2V burst, prepare the ADP cipher for the
	// NEXT superframe cycle. This matches op25 timing: the 2V burst's own
	// codewords used the previous cipher state; prepare() here generates the
	// keystream for the following 4V+2V cycle.
	if b.Type == Burst2V && ss.ess.Encrypted() && keyLookup != nil {
		if key, ok := keyLookup(ss.ess.AlgID, ss.ess.KeyID); ok {
			if ss.adp == nil {
				ss.adp = &p25.ADP{}
			}
			ss.adpKey = key
			_ = ss.adp.Prepare(key, ss.ess.MI)
			ss.hasMI = true
		}
	}

	return &P2VoiceFrame{
		PCM:           pcm,
		Slot:          slot,
		Errs:          totalErrs,
		Total:         totalCW,
		Uncorrectable: uncorrectable,
		AlgID:         ss.ess.AlgID,
		KeyID:     ss.ess.KeyID,
		MI:        ss.ess.MI,
		Encrypted: ss.ess.Encrypted(),
		Decrypted: decrypted,

		Talkgroup:       ss.macTG,
		SourceID:        ss.macSrc,
		ServiceOpts:     ss.macOpts,
		IdentityFromMAC: ss.macSeen,

		TalkerAlias:     ss.macAlias,
		TalkerAliasTGID: ss.macAliasTGID,
		TalkerAliasUnit: ss.macAliasUnit,

		GPS:   ss.macGPS,
		GPSOK: ss.macGPSSeen,
	}
}

// processControlBurst decodes a voice-less control burst's MAC PDU and returns a
// ControlOnly P2VoiceFrame. Returns nil if the slot is unknown or the ACCH FEC
// fails. Identity / alias / encryption are latched into the per-slot state (same
// latches the 2V FACCH path uses) so they carry to subsequent voice frames.
func (t *TDMAProcessor) processControlBurst(b Burst) *P2VoiceFrame {
	if !b.ISCH.Valid || b.ISCH.Slot < 0 {
		return nil
	}
	slot := b.ISCH.Slot
	if slot > 1 {
		slot = 1
	}
	ss := &t.slots[slot]

	// Scrambled (DUID 3/9) decode from descrambled b.Dibits; unscrambled
	// (12/13/15) from raw b.Raw. LCCH (13) is always unscrambled.
	var src [BurstDibits]p25.Dibit
	switch duidLookup[b.DUID] {
	case 3, 9: // scrambled SACCH/FACCH
		src = b.Dibits
	default: // 12/13/15 unscrambled
		src = b.Raw
	}

	var typ ACCHType
	switch b.Type {
	case BurstSACCH:
		typ = ACCHSacch
	case BurstLCCH:
		typ = ACCHLcch
	default: // BurstFACCH
		typ = ACCHFacch
	}

	pdu, ok := DecodeACCH(src, typ)
	if !ok {
		return nil
	}

	vf := &P2VoiceFrame{
		PCM:         nil,
		Slot:        slot,
		ControlOnly: true,
		MACOpcode:   pdu.Opcode,
	}

	// Latch identity (same fields the 2V FACCH path latches).
	if pdu.HasIdentity {
		ss.macTG = pdu.Talkgroup
		ss.macSrc = pdu.SourceID
		ss.macOpts = pdu.ServiceOpts
		ss.macSeen = true
	}
	// Feed alias sub-messages.
	for _, msg := range pdu.vendorAliasMsgs {
		if alias, tg, unit, complete := ss.aliasAsm.feed(msg); complete {
			ss.macAlias = alias
			ss.macAliasTGID = tg
			ss.macAliasUnit = unit
		}
	}
	// Latch in-call GPS (last-known wins).
	if pdu.GPSOK {
		ss.macGPS = pdu.GPS
		ss.macGPSSeen = true
	}
	// Surface encryption from MAC_PTT / MAC_END_PTT.
	if pdu.HasEncryption {
		vf.AlgID = pdu.AlgID
		vf.KeyID = pdu.KeyID
		vf.MI = pdu.MI
		vf.Encrypted = true
	}

	// Populate identity/alias on the frame from the per-slot latches.
	vf.Talkgroup = ss.macTG
	vf.SourceID = ss.macSrc
	vf.ServiceOpts = ss.macOpts
	vf.IdentityFromMAC = ss.macSeen
	vf.TalkerAlias = ss.macAlias
	vf.TalkerAliasTGID = ss.macAliasTGID
	vf.TalkerAliasUnit = ss.macAliasUnit
	vf.GPS = ss.macGPS
	vf.GPSOK = ss.macGPSSeen

	return vf
}

// ResetSlot reinitializes the vocoder and encryption state for the given slot
// (0 or 1). Call at call boundaries to prevent state leakage between
// conversations.
func (t *TDMAProcessor) ResetSlot(slot int) {
	if slot >= 0 && slot <= 1 {
		t.slots[slot].vocoder.Reset()
		t.slots[slot].ess.Reset()
		t.slots[slot].adp = nil
		t.slots[slot].adpKey = nil
		t.slots[slot].hasMI = false
		t.slots[slot].macTG = 0
		t.slots[slot].macSrc = 0
		t.slots[slot].macOpts = 0
		t.slots[slot].macSeen = false
		t.slots[slot].aliasAsm = p2AliasAssembler{}
		t.slots[slot].macAlias = ""
		t.slots[slot].macAliasTGID = 0
		t.slots[slot].macAliasUnit = 0
		t.slots[slot].macGPS = p25.GPSPosition{}
		t.slots[slot].macGPSSeen = false
	}
}

// Close releases resources.
func (t *TDMAProcessor) Close() {
	t.slots[0].vocoder.Close()
	t.slots[1].vocoder.Close()
}
