package p25

import (
	"github.com/raidancampbell/godsp"
	"github.com/raidancampbell/gop25/mbe"
)

// VoiceFrame contains decoded voice data from one LDU.
type VoiceFrame struct {
	IMBE            [9][144]uint8 // 9 IMBE voice codewords, 144 raw transmitted bits each (1 bit per byte)
	UnitID          uint32        // from LDU1 Link Control (0 if from LDU2)
	Talkgroup       uint16        // from LDU1 Link Control
	MFID            uint8         // manufacturer ID from LDU1 LC
	LCO             uint8         // link control opcode from LDU1/TDULC LC (0=group, 3=unit-to-unit)
	ServiceOpts     uint8         // LCO=0 service-options byte; 0x80 = emergency (0 if no LC seen)
	DestID          uint32        // target/destination unit for LCO=3 unit-to-unit; 0 otherwise
	Encrypted       bool          // from LDU2 encryption sync (algo != 0x80 and != 0x00)
	AlgoID          uint8         // encryption algorithm ID from LDU2
	KeyID           uint16        // encryption key ID from LDU2
	MI              [9]uint8      // 72-bit Message Indicator from LDU2 ES (zero on LDU1/HDU/etc.)
	MIValid         bool          // true when MI was obtained from a successfully decoded HDU or ES
	RawLC           [9]uint8      // 72-bit RS-corrected LCW bytes from LDU1 (ciphertext if P bit set)
	RawLCOK         bool          // true if RawLC was successfully RS-decoded
	TalkerAlias     string        // Phase 1 talker alias from LCO 0x15/0x17 (Motorola) or 50-53 (Harris)
	TalkerAliasTGID uint16        // talkgroup from alias header (Motorola only; 0 for Harris)
	TalkerAliasUnit uint32        // SUID unit ID from the Motorola alias (0 for Harris)
	GPS             GPSPosition   // in-call GPS position (Motorola LCO=6 or Harris LCO 42/43)
	GPSOK           bool          // true when GPS holds a decoded in-call position
	NAC             uint16
	DUID            uint8
	EVM             float64 // decoder's cumulative EVM at emission (0 if unmeasured)
	IMBEErrors      int     // Golay/Hamming FEC error count summed across this frame's 9 IMBE codewords
}

// discClampHz bounds the FM discriminator output (in Hz) before the C4FM
// channel filter. On a weak signal the phase-difference discriminator produces
// impulsive "clicks" — full ±π phase jumps that rail to ±Fs/2 (±12.5 kHz at
// 25 kSPS) whenever noise momentarily dominates the instantaneous phase. Each
// click is then smeared across the C4FM receive filter's span by the filter,
// corrupting every symbol decision in its neighbourhood and inflating EVM far
// beyond what the underlying constellation warrants (measured: 0.49 % of
// samples railing drove EVM from ~0.25 to ~0.6 on the 460.8375 control channel).
//
// Clamping to 3000 Hz removes the clicks before the filter spreads them while
// leaving all valid C4FM content untouched: the outer symbol sits at ±1800 Hz,
// the decision loop's deviation tracker runs hot transmitters up to 1.4×1800 =
// 2520 Hz, and 3000 Hz keeps headroom above that for between-symbol pulse
// overshoot. The existing 5 kHz audio-path devLimit in the FM demodulator is
// deliberately looser; symbol recovery needs the tighter bound because the
// filter turns an out-of-band spike into in-band ISI rather than an audible tick.
const discClampHz = 3000.0

// c4fmRxTaps is the length of the C4FM receive matched filter at the fixed
// 25 kSPS channel rate. The un-windowed frequency-sampled design (designC4FMRx)
// has slowly-decaying sinc tails, so EVM is mildly non-monotonic in tap count;
// 81 was the empirical minimum on on-air fixtures (≈0.020 EVM on the NAC 0x171
// CC vs ≈0.062 for the old generic LPF) and is a wide, signal-independent
// sweet spot (61/81/101 all good; 67/73/87 ring slightly higher).
const c4fmRxTaps = 81

// P25Decoder is the top-level decoder combining the C4FM receive matched
// filter, symbol recovery, frame sync, and data unit parsing.
type P25Decoder struct {
	rxFilter  *dsp.FIRFilterReal
	symbols   *SymbolRecovery
	framesync *FrameSync
	lastLC    linkControl
	alias     aliasAssembler // Phase 1 talker-alias reassembler (Motorola/Harris)
	clampBuf  []float32      // scratch for the discriminator click limiter
}

type linkControl struct {
	unitID    uint32
	talkgroup uint16
	mfid      uint8
	lco       uint8
	svcOpts   uint8       // LCO=0 service-options byte (LCW byte 2); 0x80 = emergency
	destID    uint32      // target unit for LCO=3 unit-to-unit; 0 otherwise
	gps       GPSPosition // in-call GPS (LCO=6 Motorola, or LCO 42/43 Harris reassembly)
	gpsOK     bool        // true when gps holds a decoded in-call position
	raw       [9]uint8
	valid     bool
}

func NewP25Decoder(sampleRate float64) *P25Decoder {
	// C4FM receive matched filter (designC4FMRx), applied in the FM-discriminator
	// domain before the Gardner TED. Cascaded with the C4FM transmit shaping it
	// forms a Nyquist, zero-ISI response, which (a) lowers the decision-instant
	// EVM ~40% vs the previous generic 3 kHz window-sinc LPF, and (b) removes the
	// Gardner timing bias: the matched pulse is symmetric, so the TED locks on the
	// peak and the decision sample needs no offset. This mirrors op25, which only
	// trusts Gardner in a matched-filtered domain (its discriminator-domain FSK4
	// path likewise uses the C4FM rx filter, not a brick-wall LPF).
	taps := designC4FMRx(symbolRate, sampleRate, c4fmRxTaps)
	return &P25Decoder{
		rxFilter:  dsp.NewFIRFilterReal(taps),
		symbols:   NewSymbolRecovery(sampleRate),
		framesync: NewFrameSync(),
	}
}

// NewP25DecoderNoFilter creates a P25 decoder without the matched filter (for testing).
func NewP25DecoderNoFilter(sampleRate float64) *P25Decoder {
	return &P25Decoder{
		symbols:   NewSymbolRecovery(sampleRate),
		framesync: NewFrameSync(),
	}
}

// Process takes FM discriminator output (Hz) and returns decoded voice frames
// and control frames. Control frames are emitted for HDU, TDU, TDUlc, and TSDU
// data units; voice frames for LDU1 and LDU2.
//
// A NAC-only VoiceFrame is still emitted for every non-LDU frame so the squelch
// can open as soon as the NID is decoded (~135 ms for HDU) rather than waiting
// for the first LDU1 (~495 ms).
func (d *P25Decoder) Process(rawDiscriminator []float32) ([]VoiceFrame, []ControlFrame) {
	// Apply matched filter to reduce ISI before symbol recovery (if configured)
	input := d.clampDisc(rawDiscriminator)
	if d.rxFilter != nil {
		input = d.rxFilter.ProcessReuse(input)
	}
	dibits := d.symbols.Process(input)
	frames := d.framesync.FeedSoft(dibits, d.symbols.LastSoft())

	var voice []VoiceFrame
	var control []ControlFrame
	for _, f := range frames {
		v, c := d.processFrame(f)
		voice = append(voice, v...)
		control = append(control, c...)
	}
	// Stamp each emitted voice frame with the decoder's current cumulative EVM
	// so downstream consumers can record per-call signal quality from the voice
	// frames alone (via the host's per-voice-frame callback).
	if evm := d.EVM(); evm > 0 {
		for i := range voice {
			voice[i].EVM = evm
		}
	}
	return voice, control
}

// processFrame dispatches one demodulated Frame by DUID into zero-or-more
// VoiceFrames and ControlFrames. Split out of Process so tests can drive a
// synthetic Frame without going through SymbolRecovery + FrameSync.
func (d *P25Decoder) processFrame(f Frame) ([]VoiceFrame, []ControlFrame) {
	switch f.NID.DUID {
	case 0x5: // LDU1
		if vf := d.parseLDU1(f); vf != nil {
			return []VoiceFrame{*vf}, nil
		}
		return nil, nil
	case 0xA: // LDU2
		if vf := d.parseLDU2(f); vf != nil {
			return []VoiceFrame{*vf}, nil
		}
		return nil, nil
	case 0x0: // HDU — Header Data Unit (pre-call encryption header)
		vf := VoiceFrame{NAC: f.NID.NAC, DUID: f.NID.DUID}
		hdu := parseHDU(f.Payload)
		if hdu != nil {
			vf.AlgoID = hdu.AlgoID
			vf.KeyID = hdu.KeyID
			vf.MI = hdu.MI
			vf.MIValid = true
			vf.Encrypted = hdu.AlgoID != 0x80 && hdu.AlgoID != 0x00
			// Carry the header talkgroup. The HDU is the first frame of a call and
			// is RS(36,20,17)-protected, so it can label a call whose recurring
			// LDU1 link control never RS-decodes cleanly.
			vf.Talkgroup = hdu.TalkgroupID
		}
		return []VoiceFrame{vf}, []ControlFrame{{NAC: f.NID.NAC, DUID: f.NID.DUID, HDU: hdu}}
	case 0x3: // TDU — simple terminator (28 null bits + status, no LC)
		return []VoiceFrame{{NAC: f.NID.NAC, DUID: f.NID.DUID}},
			[]ControlFrame{{NAC: f.NID.NAC, DUID: f.NID.DUID}}
	case 0x7: // TSDU — Trunking Signaling Data Unit (one or more TSBKs)
		tsbks := parseTSBKs(f.Payload)
		cfs := make([]ControlFrame, len(tsbks))
		for i := range tsbks {
			cfs[i] = ControlFrame{NAC: f.NID.NAC, DUID: f.NID.DUID, TSBK: &tsbks[i]}
		}
		return []VoiceFrame{{NAC: f.NID.NAC, DUID: f.NID.DUID}}, cfs
	case 0xF: // TDUlc — Terminator Data Unit with Link Control
		lc := parseTDUlc(f.Payload)
		vf := VoiceFrame{NAC: f.NID.NAC, DUID: f.NID.DUID}
		// Dispatch talker-alias LCOs (Motorola 0x15/0x17, Harris 50-53) to the
		// reassembler. Surface the completed alias on the VoiceFrame.
		if lc != nil {
			switch lc.LCF & 0x3F {
			case 0x15: // Motorola talker alias header
				if a, tg, unit, done := d.alias.addMotorolaHeader(lc.Raw); done {
					vf.TalkerAlias, vf.TalkerAliasTGID, vf.TalkerAliasUnit = a, tg, unit
				}
			case 0x17: // Motorola talker alias data block
				if a, tg, unit, done := d.alias.addMotorolaBlock(lc.Raw); done {
					vf.TalkerAlias, vf.TalkerAliasTGID, vf.TalkerAliasUnit = a, tg, unit
				}
			case 6: // Motorola Unit GPS
				if lc.MFID == 0x90 {
					if pos, ok := decodeMotorolaUnitGPS(lc.Raw); ok {
						vf.GPS, vf.GPSOK = pos, true
					}
				}
			case 42, 43: // Harris Talker GPS blocks 1/2
				if lc.MFID == 0xA4 {
					if pos, ok := d.alias.addHarrisGPSBlock(lc.LCF&0x3F, lc.Raw); ok {
						vf.GPS, vf.GPSOK = pos, true
					}
				}
			case 50, 51, 52, 53: // Harris talker alias blocks 1-4
				if a, tg, unit, done := d.alias.addHarris(lc.Raw); done {
					vf.TalkerAlias, vf.TalkerAliasTGID, vf.TalkerAliasUnit = a, tg, unit
				}
			}
		}
		return []VoiceFrame{vf},
			[]ControlFrame{{NAC: f.NID.NAC, DUID: f.NID.DUID, LC: lc}}
	case 0xC: // PDU - Packet Data Unit (SNDCP/data)
		pdu := parsePDUWithSoft(f.Payload, f.Soft)
		var sn *SNDCPData
		var lrrp *LRRPData
		var ars *ARSData
		if pdu != nil && pdu.HeaderCRCOK {
			sn = parseSNDCP(pdu)
			// Only parse IPv4 when the SN-DATA header is either absent
			// (sdrtrunk defaults to IPHeaderCompression.NONE) or present
			// and reports no IP header compression. With a present header
			// reporting compression != NONE the bytes after the SN-DATA
			// header are ROHC/etc, not raw IPv4.
			if sn != nil && (!sn.HasHeader || sn.IPHeaderCompression == 0) {
				if ip := parseIPv4(sn.UserPayload); ip != nil && ip.Protocol == 17 {
					if udp := parseUDP(ip.Payload); udp != nil {
						switch udp.DstPort {
						case 4001: // Location Service (LRRP)
							lrrp = parseLRRP(udp.Payload)
						case 4005: // Automatic Registration Service (ARS)
							ars = parseARS(udp.Payload)
						}
					}
				}
			}
		}
		return []VoiceFrame{{NAC: f.NID.NAC, DUID: f.NID.DUID}},
			[]ControlFrame{{NAC: f.NID.NAC, DUID: f.NID.DUID, PDU: pdu, SNDCP: sn, LRRP: lrrp, ARS: ars}}
	default:
		return []VoiceFrame{{NAC: f.NID.NAC, DUID: f.NID.DUID}}, nil
	}
}

func (d *P25Decoder) CarrierOffset() float64 { return d.symbols.CarrierOffset() }
func (d *P25Decoder) TimingOffset() float64  { return d.symbols.TimingOffset() }
func (d *P25Decoder) EVM() float64           { return d.symbols.EVM() }
func (d *P25Decoder) SyncCount() int         { return d.framesync.SyncCount() }

type FrameSyncDebug struct {
	SyncDetections     int
	SoftSyncDetections int // sync acquisitions admitted by the soft gate (hard gate missed)
	NIDAttempts        int
	NIDFailures        int
	FramesEmitted      int
	HintRecoveries     int // frames recovered by NAC hint-assisted decode
}

func (d *P25Decoder) FrameSyncStats() FrameSyncDebug {
	return FrameSyncDebug{
		SyncDetections:     d.framesync.SyncDetections,
		SoftSyncDetections: d.framesync.SoftSyncDetections,
		NIDAttempts:        d.framesync.NIDAttempts,
		NIDFailures:        d.framesync.NIDFailures,
		FramesEmitted:      d.framesync.FramesEmitted,
		HintRecoveries:     d.framesync.HintRecoveries,
	}
}

func (d *P25Decoder) Reset() {
	if d.rxFilter != nil {
		d.rxFilter.ResetFIR()
	}
	d.symbols.Reset()
	d.framesync.Reset()
	d.lastLC = linkControl{}
}

// SoftReset aborts any in-progress frame collection without clearing the
// symbol recovery state or FrameSync ring buffer. Use this on squelch close
// so that the decoder can immediately detect the next call's HDU sync while
// still discarding stale partial frames from a call that ended mid-LDU.
func (d *P25Decoder) SoftReset() {
	d.framesync.SoftReset()
	d.lastLC = linkControl{}
}

// ResetStats clears carrier/timing/EVM accumulators without losing frame sync.
// Use this at squelch open so the decoder can continue tracking the current signal.
func (d *P25Decoder) ResetStats() {
	d.symbols.ResetStats()
	d.lastLC = linkControl{}
}

// LDU1/LDU2 structure (807 payload positions including status symbols):
//
// V1 and V2 are adjacent (no LC between them). After V2, LC/ES fragments
// separate each subsequent pair. In transmitted (including-status) space:
//
//   V1(74) V2(74) [LC/ES(~21) VC(74)] × 7
//
// Each LC/ES block covers ~20 data dibits (status-stripped) followed by one VC.
// The gap varies slightly (90–95 transmitted positions per VC after V2) because
// status symbols are inserted at fixed intervals across the frame.
//
// Start positions are in transmitted payload coordinates; extractVoiceCW
// skips status positions on-the-fly when collecting voiceDibits.

// lduVoiceStarts contains the starting payload position of each of the 9 IMBE
// voice codewords in an LDU. These are transmitted positions (including status
// symbols); extractVoiceCW skips status positions on-the-fly.
//
// Empirically derived from a P25 Phase 1 signal: V1 and V2 are adjacent at
// positions 0 and 74; V3–V9 follow at ~94–95-position spacing that covers one
// LC/ES fragment (~20 data dibits) plus status symbols.
var lduVoiceStarts = [9]int{
	0, 74, 169, 263, 358, 453, 547, 642, 732,
}

const voiceDibits = 72 // non-status data dibits per IMBE codeword (= 144 bits)

// P25 Phase 1 status symbol positions within the LDU payload.
// In the full transmitted frame, status symbols are inserted every 36 symbols,
// at full-frame positions 35, 71, 107, 143, ... (= 35 + 36*k).
// The payload starts at full-frame position 57 (after 24 sync + 33 NID-with-status).
// Therefore, in the payload, status falls at positions where (p + 22) % 36 == 0:
// payload positions 14, 50, 86, 122, 158, ...

// isStatusPosition reports whether payload position p is a status symbol.
func isStatusPosition(p int) bool {
	return (p+22)%36 == 0
}

// extractVoiceCW extracts one IMBE voice codeword from the payload.
// It begins at start and skips status symbol positions, collecting exactly
// voiceDibits (72) non-status dibits → 144 bits returned as a bit-per-byte slice.
func extractVoiceCW(payload []Dibit, start int) []uint8 {
	rawBits := make([]uint8, 0, voiceDibits*2)
	for i := start; len(rawBits) < voiceDibits*2 && i < len(payload); i++ {
		if isStatusPosition(i) {
			continue
		}
		rawBits = append(rawBits, uint8((payload[i]>>1)&1), uint8(payload[i]&1))
	}
	return rawBits
}

// ProcessRaw takes FM discriminator output and returns raw frames with payloads,
// for diagnostic use.
func (d *P25Decoder) ProcessRaw(rawDiscriminator []float32) []Frame {
	input := d.clampDisc(rawDiscriminator)
	if d.rxFilter != nil {
		input = d.rxFilter.ProcessReuse(input)
	}
	dibits := d.symbols.Process(input)
	return d.framesync.FeedSoft(dibits, d.symbols.LastSoft())
}

// clampDisc limits impulsive discriminator clicks to ±discClampHz, copying into
// a reusable scratch buffer so the caller's slice (a shared demodulator buffer)
// is left intact. See discClampHz for the rationale.
func (d *P25Decoder) clampDisc(in []float32) []float32 {
	if cap(d.clampBuf) < len(in) {
		d.clampBuf = make([]float32, len(in))
	}
	out := d.clampBuf[:len(in)]
	for i, v := range in {
		if v > discClampHz {
			v = discClampHz
		} else if v < -discClampHz {
			v = -discClampHz
		}
		out[i] = v
	}
	return out
}

// ExtractVoiceCWAt extracts one IMBE voice codeword starting at the given payload offset.
// Exported for diagnostic use.
func ExtractVoiceCWAt(payload []Dibit, start int) []uint8 {
	return extractVoiceCW(payload, start)
}

// IsStatusPos reports whether the given payload position is a status symbol.
// Exported for diagnostic use.
func IsStatusPos(p int) bool {
	return isStatusPosition(p)
}
func (d *P25Decoder) parseLDU1(f Frame) *VoiceFrame {
	if len(f.Payload) < 750 {
		return nil
	}

	vf := &VoiceFrame{
		NAC:  f.NID.NAC,
		DUID: f.NID.DUID,
	}

	// Extract 9 IMBE voice codewords (raw 144 bits each, for mbelib to FEC-decode)
	// and sum each codeword's Golay/Hamming FEC error count. Encryption XORs the
	// post-FEC u-vector, not the on-air codeword, so this count is meaningful
	// (a real channel-quality signal) even for encrypted calls.
	for i := 0; i < 9; i++ {
		raw := extractVoiceCW(f.Payload, lduVoiceStarts[i])
		if len(raw) >= 144 {
			copy(vf.IMBE[i][:], raw[:144])
			_, _, errs := mbe.IMBEFECDecode(vf.IMBE[i], imbeIW, imbeIX, imbeIY, imbeIZ)
			vf.IMBEErrors += errs
		}
	}

	// Extract Link Control fragments (between voice codewords).
	// LC occupies 6 fragments × 24 dibits = 144 dibits = 288 bits.
	// After Hamming/Golay FEC: 72 bits of LC data.
	// Layout: LCF[8] | MFID[8] | Talkgroup[16] | UnitID[24] | CRC[16]
	lc := extractLC(f.Payload)
	if lc != nil {
		vf.UnitID = lc.unitID
		vf.Talkgroup = lc.talkgroup
		vf.MFID = lc.mfid
		vf.LCO = lc.lco
		vf.ServiceOpts = lc.svcOpts
		vf.DestID = lc.destID
		vf.RawLC = lc.raw
		vf.RawLCOK = true
		d.lastLC = *lc

		// Dispatch talker-alias LCOs to the reassembler. Motorola LCO 0x15 (header)
		// and 0x17 (data blocks); Harris LCO 50-53 (blocks 1-4). When complete, the
		// reassembler returns the decoded alias and talkgroup (Motorola only).
		// References: TIA-102.AABD Annex A, sdrtrunk LCMotorolaTalkerAliasAssembler.java,
		// sdrtrunk LCHarrisTalkerAliasComplete.java.
		switch lc.lco {
		case 0x15: // Motorola talker alias header
			if a, tg, unit, done := d.alias.addMotorolaHeader(lc.raw); done {
				vf.TalkerAlias, vf.TalkerAliasTGID, vf.TalkerAliasUnit = a, tg, unit
			}
		case 0x17: // Motorola talker alias data block
			if a, tg, unit, done := d.alias.addMotorolaBlock(lc.raw); done {
				vf.TalkerAlias, vf.TalkerAliasTGID, vf.TalkerAliasUnit = a, tg, unit
			}
		case 50, 51, 52, 53: // Harris talker alias blocks 1-4
			if a, tg, unit, done := d.alias.addHarris(lc.raw); done {
				vf.TalkerAlias, vf.TalkerAliasTGID, vf.TalkerAliasUnit = a, tg, unit
			}
		case 6: // Motorola Unit GPS (self-reported position)
			if lc.mfid == 0x90 {
				if pos, ok := decodeMotorolaUnitGPS(lc.raw); ok {
					vf.GPS, vf.GPSOK = pos, true
				}
			}
		case 42, 43: // Harris Talker GPS blocks 1/2
			if lc.mfid == 0xA4 {
				if pos, ok := d.alias.addHarrisGPSBlock(lc.lco, lc.raw); ok {
					vf.GPS, vf.GPSOK = pos, true
				}
			}
		}
	} else if d.lastLC.valid {
		vf.UnitID = d.lastLC.unitID
		vf.Talkgroup = d.lastLC.talkgroup
		vf.MFID = d.lastLC.mfid
	}

	return vf
}

// parseLDU2 extracts voice codewords and encryption sync from an LDU2 frame.
func (d *P25Decoder) parseLDU2(f Frame) *VoiceFrame {
	if len(f.Payload) < 750 {
		return nil
	}

	vf := &VoiceFrame{
		NAC:  f.NID.NAC,
		DUID: f.NID.DUID,
	}

	// Carry forward LC from last LDU1
	if d.lastLC.valid {
		vf.UnitID = d.lastLC.unitID
		vf.Talkgroup = d.lastLC.talkgroup
		vf.MFID = d.lastLC.mfid
	}

	// Extract 9 IMBE voice codewords (same positions as LDU1)
	for i := 0; i < 9; i++ {
		raw := extractVoiceCW(f.Payload, lduVoiceStarts[i])
		if len(raw) >= 144 {
			copy(vf.IMBE[i][:], raw[:144])
		}
	}

	// Extract encryption sync (same positions as LC in LDU1).
	// ES layout: AlgoID[8] | KeyID[16] | MI[72] (Message Indicator)
	es := extractES(f.Payload)
	if es != nil {
		vf.AlgoID = es.algoID
		vf.KeyID = es.keyID
		vf.MI = es.mi
		vf.MIValid = true
		vf.Encrypted = es.algoID != 0x80 && es.algoID != 0x00
	}

	return vf
}

// extractLC recovers the LDU1 Link Control Word.
//
// On-air encoding (TIA-102.BAAA §7.3): the 72-bit LCW is packed into 12
// hexbits, RS(24,12,13)-encoded to 24 hexbits, each hexbit Hamming(10,6,3)-
// encoded to 10 bits, and the resulting 240 bits are interleaved into the
// six gaps between voice codewords V2..V8 at the bit positions in
// lduLCBitPositions. extractLDUHexbits inverts the interleave + Hamming
// decode; rsDecode63 inverts the RS code.
//
// LCW layout for LCO=0 "Group Voice Channel User" (the common case on
// conventional repeaters and trunked voice channels):
//
//	LCO[8] MFID[8] SvcOpts[8] rsvd[8] TGID[16] SrcID[24]
func extractLC(payload []Dibit) *linkControl {
	hb, ok := extractLDUHexbits(payload)
	if !ok {
		return nil
	}
	hb, nerr, ok := rsDecode63(hb, 12)
	if !ok || nerr > 6 {
		return nil
	}

	lcBits := make([]uint8, 72)
	for i := range 12 {
		for j := range 6 {
			lcBits[i*6+j] = (hb[i] >> uint(5-j)) & 1
		}
	}

	lc := &linkControl{valid: true}
	for i := range 9 {
		lc.raw[i] = uint8(bitsToUint32(lcBits[i*8 : i*8+8]))
	}
	lc.lco = uint8(bitsToUint32(lcBits[0:8]))
	lc.mfid = uint8(bitsToUint32(lcBits[8:16]))
	switch lc.lco {
	case 0: // Group Voice Channel User: SvcOpts[16:24] TGID[32:48] SrcID[48:72]
		lc.svcOpts = uint8(bitsToUint32(lcBits[16:24]))
		lc.talkgroup = uint16(bitsToUint32(lcBits[32:48]))
		lc.unitID = bitsToUint32(lcBits[48:72])
	case 3: // Unit-to-Unit Voice Channel User (sdrtrunk LCUnitToUnitVoiceChannelUser.java:35-36):
		// TARGET[24:48] SOURCE[48:72]. Private call: no talkgroup. Label by the
		// talker (source); carry the target for completeness (not persisted).
		lc.destID = bitsToUint32(lcBits[24:48])
		lc.unitID = bitsToUint32(lcBits[48:72])
	}
	return lc
}

type encSync struct {
	algoID uint8
	keyID  uint16
	mi     [9]uint8
}

// extractES recovers the LDU2 Encryption Sync word.
//
// On-air encoding (TIA-102.BAAA §7.4): same fragment positions and Hamming
// encoding as the LDU1 LCW, but the inner code is RS(24,16,9) (16 data
// hexbits = 96 bits, 8 parity hexbits, t=4).
//
// ES layout: MI[72] | AlgoID[8] | KeyID[16].
func extractES(payload []Dibit) *encSync {
	hb, ok := extractLDUHexbits(payload)
	if !ok {
		return nil
	}
	hb, nerr, ok := rsDecode63(hb, 8)
	if !ok || nerr > 4 {
		return nil
	}

	esBits := make([]uint8, 96)
	for i := range 16 {
		for j := range 6 {
			esBits[i*6+j] = (hb[i] >> uint(5-j)) & 1
		}
	}

	es := &encSync{}
	for i := range 9 {
		es.mi[i] = uint8(bitsToUint32(esBits[i*8 : i*8+8]))
	}
	es.algoID = uint8(bitsToUint32(esBits[72:80]))
	es.keyID = uint16(bitsToUint32(esBits[80:96]))
	return es
}
