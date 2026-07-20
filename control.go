package p25

import (
	"fmt"
	"time"
)

// ControlFrame is emitted by Process() for non-voice frames. HDU, LC, and
// TSBK are mutually exclusive by DUID. PDU is set for DUID=0xC; SNDCP is
// set when the PDU is Format=0x16 packet-data; LRRP/ARS are set when the SNDCP
// payload decodes to a UDP/4001 location report / UDP/4005 registration message.
type ControlFrame struct {
	NAC   uint16
	DUID  uint8
	HDU   *HDUData   // non-nil for DUID=0x0
	LC    *LCData    // non-nil for DUID=0xF (TDUlc)
	TSBK  *TSBKData  // non-nil for DUID=0x7 (TSDU), one per decoded TSBK
	PDU   *PDUData   // non-nil for DUID=0xC (Packet Data Unit, block layer)
	SNDCP *SNDCPData // non-nil for DUID=0xC + Format=0x16 (SN-DATA / packet-data)
	LRRP  *LRRPData  // non-nil for SNDCP UserPayload that decodes IPv4/UDP:4001/LRRP
	ARS   *ARSData   // non-nil for SNDCP UserPayload that decodes IPv4/UDP:4005/ARS
}

// HDUData carries fields from the Header Data Unit (DUID=0x0).
// The HDU is the first frame of an encrypted voice call and carries
// encryption parameters before any LDU voice frames arrive.
// Decoded using shortened Golay(24,12,8) hexbit codewords wrapped in a
// shortened RS(36,20,17) outer code (TIA-102.BAAA; see parseHDU).
type HDUData struct {
	MFID        uint8
	AlgoID      uint8
	KeyID       uint16
	TalkgroupID uint16
	MI          [9]uint8 // 72-bit Message Indicator (9 bytes)
}

// LCData is the decoded Link Control word, shared by LDU1 and TDUlc.
type LCData struct {
	LCF       uint8 // Link Control Format
	MFID      uint8
	Talkgroup uint16
	UnitID    uint32
	DestID    uint32   // target unit for LCO=3 unit-to-unit; 0 otherwise
	Raw       [9]uint8 // 72-bit RS-corrected LCW bytes (for alias reassembly)
}

// TSBKOpcode identifies the purpose of a Trunking Signaling BlocK.
// Values defined by TIA-102.AABF.
type TSBKOpcode uint8

// tdulcDataBits is the number of status-stripped payload bits carrying the
// TDULC link control: 12 Golay(24,12,8) codewords × 24 bits.
const tdulcDataBits = 12 * 24

const (
	OpcodeGroupVoiceGrant        TSBKOpcode = 0x00
	OpcodeGroupVoiceGrantUpdate  TSBKOpcode = 0x02
	OpcodeGroupVoiceGrantUpdtExp TSBKOpcode = 0x03
	OpcodeUnitVoiceGrant         TSBKOpcode = 0x04
	// TELE_INT_CH_GRANT / TELE_INT_CH_GRANT_UPDT (TIA-102.AABC standard opcodes).
	// These are STANDARD-MFID opcodes; 0x09 does NOT collide with the Motorola
	// OpcodeMotLoadPct=0x09 because vendor opcodes dispatch only under MFID 0x90.
	OpcodeTeleIntVoiceGrant       TSBKOpcode = 0x08
	OpcodeTeleIntVoiceGrantUpdate TSBKOpcode = 0x09
	OpcodeGroupDataGrant          TSBKOpcode = 0x14
	OpcodeSNDCPDataPageReq       TSBKOpcode = 0x15
	OpcodeSNDCPDataChAnn         TSBKOpcode = 0x16
	OpcodeAckRspFNE              TSBKOpcode = 0x20
	OpcodeQueRsp                 TSBKOpcode = 0x21
	OpcodeExtFuncCmd             TSBKOpcode = 0x24
	OpcodeDenyRsp                TSBKOpcode = 0x27
	OpcodeGrpAffRsp              TSBKOpcode = 0x28
	OpcodeSCCBExp                TSBKOpcode = 0x29
	OpcodeGroupAffQuery          TSBKOpcode = 0x2A
	OpcodeLocRegResp             TSBKOpcode = 0x2B
	OpcodeUnitRegResp            TSBKOpcode = 0x2C
	OpcodeUnitRegCmd             TSBKOpcode = 0x2D
	OpcodeUnitDeRegAck           TSBKOpcode = 0x2F
	OpcodeSyncBcast              TSBKOpcode = 0x30
	OpcodeIdenUpTDMA             TSBKOpcode = 0x33
	OpcodeIdenUpVU               TSBKOpcode = 0x34
	OpcodeSystemServiceBcast     TSBKOpcode = 0x38
	OpcodeSecondaryCCBcast       TSBKOpcode = 0x39
	OpcodeRFSSStatusBcast        TSBKOpcode = 0x3A
	OpcodeNetworkStatusBcast     TSBKOpcode = 0x3B
	OpcodeAdjacentSiteBcast      TSBKOpcode = 0x3C
	OpcodeIdenUp                 TSBKOpcode = 0x3D
	// OpcodeIdentifierUpdate is the legacy name kept for callers that
	// matched 0x3C; now an alias for the standard IDEN_UP (0x3D).
	OpcodeIdentifierUpdate = OpcodeIdenUp

	// Legacy aliases for renamed opcodes. Kept so out-of-scope callers compile.
	OpcodeGroupAffiliationResp = OpcodeAckRspFNE
	OpcodeGroupVoiceUser       = OpcodeGrpAffRsp
	OpcodeUnitVoiceUser        = OpcodeSCCBExp

	// Motorola (MFID=0x90) opcodes. Values overlap standard opcodes; the
	// discriminant is MFID, not the 6-bit opcode field.
	OpcodeMotSiteFlags TSBKOpcode = 0x05 // undocumented; static bitfield broadcast at IDEN rate
	OpcodeMotLoadPct   TSBKOpcode = 0x09 // leading 10-bit field alternates per-TSBK; not a simple util%
	OpcodeMotBSI       TSBKOpcode = 0x0B // MOT_BSI_GRANT: 8x6-bit callsign + ch[16] (op25 tk_p25.py:863)

	// Motorola Group Regroup (patch / dynamic-supergroup) command family
	// (op25 tk_p25.py MOT_GRG_*). ADD/DEL manage the supergroup->member map;
	// CN_GRANT/CN_GRANT_UPDT are voice-channel grants keyed by the supergroup.
	// 0x0A is observed on-air but undocumented even in op25; its field layout
	// is best-effort and MUST be treated as tentative.
	OpcodeMotGRGAdd         TSBKOpcode = 0x00 // MOT_GRG_ADD_CMD: sg[16] ga1[16] ga2[16] ga3[16]
	OpcodeMotGRGDel         TSBKOpcode = 0x01 // MOT_GRG_DEL_CMD: sg[16] ga1[16] ga2[16] ga3[16]
	OpcodeMotGRGCNGrant     TSBKOpcode = 0x02 // MOT_GRG_CN_GRANT: rsvd[8] ch[16] sg[16] sa[24]
	OpcodeMotGRGCNGrantUpdt TSBKOpcode = 0x03 // MOT_GRG_CN_GRANT_UPDT: ch1[16] sg1[16] ch2[16] sg2[16]
	OpcodeMotGRGUnk0A       TSBKOpcode = 0x0A // undocumented; tentative group[16]+unit[24] decode
)

// TSBKData is one decoded Trunking Signaling BlocK (TIA-102.AABF).
// The TSBK is 96 bits: 1 LastBlock + 1 Protected + 6 Opcode + 8 MFID +
// 64 Args + 16 CRC-CCITT. The TSBK is trellis-encoded (rate 1/2, K=3) in the
// TSDU payload; Viterbi decoding corrects up to ~1 bit error per 196-bit block.
type TSBKData struct {
	LastBlock bool
	Protected bool
	Opcode    TSBKOpcode
	MFID      uint8
	RawArgs   [8]byte

	// Voice grant fields (0x00, 0x02, 0x03, 0x04)
	ChannelID  uint16
	GroupID    uint32
	SourceID   uint32
	DestID     uint32
	ChannelID2 uint16 // 0x02 second pair / 0x03 ch_R
	GroupID2   uint32 // 0x02 second talkgroup

	// Identifier-update fields (0x33, 0x34, 0x3D)
	Iden        uint8
	BaseFreqHz  int64
	SpacingHz   int
	TxOffsetHz  int64
	BandwidthHz int
	TDMASlots   int // 0 = FDMA Phase 1

	// Motorola MFID=0x90 broadcast fields (opcodes 0x05/0x09/0x0B).
	Callsign    string // 0x0B: up-to-8-char base-station ID, "" if all-null
	MotAltField uint8  // 0x09: leading 10-bit value (observed 50..100 step 5)
	SiteFlags   uint64 // 0x05: full 64-bit args, semantics unknown

	// Motorola Group Regroup fields (MFID 0x90 opcodes 0x00/0x01/0x02/0x03).
	// SuperGroup is the dynamic-regroup talkgroup; PatchGroups[:PatchGroupN]
	// are its member talkgroups (ADD/DEL only). CN_GRANT variants reuse
	// ChannelID/ChannelID2/SourceID and set SuperGroup (+ GroupID2 = sg2).
	SuperGroup  uint16
	PatchGroups [3]uint16
	PatchGroupN int

	// RFSS/site identity (0x3A RFSS_STS, 0x3C ADJ_STS). SysID also in 0x3B.
	RFSS  uint8
	Site  uint8
	SysID uint16
	CFVA  uint8 // 0x3C cfva / 0x3A flags nibble: C(8) F(4) V(2) A(1)

	// AIV-style response fields (0x21 QUE_RSP, 0x27 DENY_RSP). Reason codes
	// are vendor-specific within the AABF reason-class ranges. AIV=1 means
	// AddlInfo carries a meaningful service-context value.
	AIV      bool
	Reason   uint8
	AddlInfo uint32 // 24 bits

	// 0x30 SYNC_BCST date/time. Zero if month/day decode out of range.
	SyncTime time.Time
}

// parseTDUlc extracts the Link Control word from a TDUlc (DUID 0xF) frame.
//
// TDULC FEC (TIA-102.BAAA §7.2; matches op25 process_TDU15/process_LCW): the
// 72-bit LCW is RS(24,12,13)-encoded to 24 hexbits (144 bits); those are split
// into 12 groups of 12 bits, each Golay(24,12,8)-encoded to 24 bits, and the
// resulting 288 bits are sent sequentially in the payload (status symbols
// interleaved at fixed positions). Decode inverts: read 288 data bits,
// Golay-decode the 12 codewords back to 24 hexbits, then RS-decode to the LCW.
func parseTDUlc(payload []Dibit) *LCData {
	bits := make([]uint8, 0, tdulcDataBits)
	for i := 0; len(bits) < tdulcDataBits && i < len(payload); i++ {
		if isStatusPosition(i) {
			continue
		}
		bits = append(bits, uint8((payload[i]>>1)&1), uint8(payload[i]&1))
	}
	if len(bits) < tdulcDataBits {
		return nil
	}

	// Golay-decode 12 codewords (24 bits each) → 24 RS hexbits.
	// The hexbit ordering matches op25's process_TDU15 / rsDecode63 convention
	// (TIA-102.BAAA §7.2): the 24 hexbits form a shortened RS(24,12,13) codeword
	// compatible with rsDecode63(hb, 12), where hb[0..11] are the 12 data hexbits
	// and hb[12..23] are the 12 parity hexbits. This is the same algebraic
	// convention used by extractLC for LDU1 link control words.
	var hb [rsN]uint8
	for c := 0; c < 12; c++ {
		cw := bitsToUint32(bits[c*24 : c*24+24])
		d, _, ok := Golay24Decode(cw)
		if !ok {
			return nil
		}
		hb[2*c] = uint8(d >> 6)
		hb[2*c+1] = uint8(d & 0x3F)
	}

	corrected, _, ok := rsDecode63(hb, rsN-rsK)
	if !ok {
		return nil
	}

	// 12 data hexbits (corrected[0..11]) → 72-bit LCW.
	lcBits := make([]uint8, 72)
	for i := 0; i < rsK; i++ {
		for j := 0; j < 6; j++ {
			lcBits[i*6+j] = (corrected[i] >> uint(5-j)) & 1
		}
	}

	lc := &LCData{
		LCF:  uint8(bitsToUint32(lcBits[0:8])),
		MFID: uint8(bitsToUint32(lcBits[8:16])),
	}
	// Pack the 72-bit LCW to 9 bytes for alias reassembly (mirrors extractLC).
	for i := range 9 {
		lc.Raw[i] = uint8(bitsToUint32(lcBits[i*8 : i*8+8]))
	}
	switch lc.LCF & 0x3F {
	case 0: // Group Voice Channel User (same layout as extractLC, frame.go)
		lc.Talkgroup = uint16(bitsToUint32(lcBits[32:48]))
		lc.UnitID = bitsToUint32(lcBits[48:72])
	case 3: // Unit-to-Unit Voice Channel User: TARGET[24:48] SOURCE[48:72]
		lc.DestID = bitsToUint32(lcBits[24:48])
		lc.UnitID = bitsToUint32(lcBits[48:72])
	}
	return lc
}

// parseHDU decodes the Header Data Unit payload (DUID=0x0) per TIA-102.BAAA
// and op25 process_HDU (reference/op25/.../p25p1_fdma.cc:244-262):
//
//  1. Strip status symbols from the 339-dibit payload, yielding 648 data bits
//     (plus 10 transmitted pad bits, ignored).
//  2. Slice into 36 x 18-bit shortened Golay(24,12,8) codewords. Each codeword
//     encodes one 6-bit hexbit (the upper 6 message bits are always zero on
//     air, so the leading 6 of the 24-bit codeword are not transmitted).
//     Golay-decode each, t=3.
//  3. The 36 hexbits form a shortened RS(36,20,17) codeword: the first 20 are
//     data (the 120-bit HDU message), the last 16 are parity. RS-decode, t=8.
//  4. Unpack: MI[72] | MFID[8] | ALGID[8] | KID[16] | TGID[16].
//
// Returns nil if the RS decode fails — never an unverified HDU. The previous
// implementation's "fall through to raw bits on RS failure" produced garbage
// AlgoID/MI on noisy starts, mis-priming the ADP keystream.
func parseHDU(payload []Dibit) *HDUData {
	dataBits := make([]uint8, 0, len(payload)*2)
	for i := 0; i < len(payload); i++ {
		if isStatusPosition(i) {
			continue
		}
		dataBits = append(dataBits, uint8((payload[i]>>1)&1), uint8(payload[i]&1))
	}
	if len(dataBits) < rsHDUN*18 {
		return nil
	}

	// op25 places hexbit i at HB[27+i] of a length-63 vector, where ezpwd
	// treats HB[j] as the coefficient of x^{62-j}; rsDecodeGenericN treats
	// received[j] as the coefficient of x^j. The two conventions meet at
	// rsSyms[35-i] = hexbit i.
	var rsSyms [rsHDUN]uint8
	for i := 0; i < rsHDUN; i++ {
		cw18 := bitsToUint32(dataBits[i*18 : i*18+18])
		hb, _, _ := Golay24Decode(uint32(cw18))
		rsSyms[rsHDUN-1-i] = uint8(hb) & 0x3F
	}

	data, ok := rsDecodeHDU(rsSyms)
	if !ok {
		return nil
	}

	msgBits := make([]uint8, 120)
	for i := 0; i < rsHDUK; i++ {
		for j := 0; j < 6; j++ {
			msgBits[i*6+j] = (data[i] >> uint(5-j)) & 1
		}
	}
	hdu := &HDUData{}
	for i := 0; i < 9; i++ {
		hdu.MI[i] = uint8(bitsToUint32(msgBits[i*8 : i*8+8]))
	}
	hdu.MFID = uint8(bitsToUint32(msgBits[72:80]))
	hdu.AlgoID = uint8(bitsToUint32(msgBits[80:88]))
	hdu.KeyID = uint16(bitsToUint32(msgBits[88:104]))
	hdu.TalkgroupID = uint16(bitsToUint32(msgBits[104:120]))
	return hdu
}

// parseTSBKs extracts all TSBKs from a TSDU payload.
//
// Each TSBK is trellis-encoded at rate 1/2 (K=3, G0=7, G1=5) before
// transmission, occupying 196 encoded bits (98 dibits) per block in the
// payload (TIA-102.BAAB §7.9). Viterbi decoding recovers 96 TSBK data bits
// including the embedded CRC-CCITT-16 for error detection.
//
// Blocks whose Viterbi decode or CRC fails are silently dropped.
// Iteration stops at the first block with LastBlock=1.
func parseTSBKs(payload []Dibit) []TSBKData {
	// Collect all data bits from payload (skipping status symbol positions).
	dataBits := make([]uint8, 0, len(payload)*2)
	for i := 0; i < len(payload); i++ {
		if isStatusPosition(i) {
			continue
		}
		dataBits = append(dataBits, uint8((payload[i]>>1)&1), uint8(payload[i]&1))
	}

	var blocks []TSBKData
	offset := 0
	for offset+trellisOut <= len(dataBits) {
		// Viterbi-decode the 196 encoded bits → 96 TSBK data bits.
		// viterbiDecode also verifies the CRC-CCITT-16 internally.
		block, ok := viterbiDecode(dataBits[offset : offset+trellisOut])
		offset += trellisOut
		if !ok {
			continue
		}

		tsbk := TSBKData{
			LastBlock: block[0] == 1,
			Protected: block[1] == 1,
			Opcode:    TSBKOpcode(bitsToUint32(block[2:8])),
			MFID:      uint8(bitsToUint32(block[8:16])),
		}
		for i := 0; i < 8; i++ {
			tsbk.RawArgs[i] = uint8(bitsToUint32(block[16+i*8 : 24+i*8]))
		}
		parseTSBKArgs(&tsbk, block[16:80])
		blocks = append(blocks, tsbk)

		if tsbk.LastBlock {
			break
		}
	}
	return blocks
}

// parseTSBKArgs populates the decoded common fields of a TSBK from the 64-bit
// args field (TIA-102.AABF). args is a 64-element bit-per-byte slice.
func parseTSBKArgs(t *TSBKData, args []uint8) {
	if len(args) < 64 {
		return
	}
	if t.MFID == 0x90 {
		switch t.Opcode {
		case OpcodeMotBSI:
			// op25 tk_p25.py:865 reads (tsbk>>i)&0x3f for i=74..32 step -6,
			// i.e. eight 6-bit chars at args[0:48); ch[16] at args[48:64).
			var b [8]byte
			n := 0
			for i := range 8 {
				c := bitsToUint32(args[i*6 : i*6+6])
				if c != 0 {
					b[n] = byte(c + 43)
					n++
				}
			}
			t.Callsign = string(b[:n])
			t.ChannelID = uint16(bitsToUint32(args[48:64]))
		case OpcodeMotLoadPct:
			t.MotAltField = uint8(bitsToUint32(args[0:10]))
		case OpcodeMotSiteFlags:
			t.SiteFlags = uint64(bitsToUint32(args[0:32]))<<32 |
				uint64(bitsToUint32(args[32:64]))
		case OpcodeMotGRGAdd, OpcodeMotGRGDel:
			// sg[0:16] ga1[16:32] ga2[32:48] ga3[48:64] (op25 tk_p25.py:778).
			// A member of 0 is an unused slot, not a real talkgroup. A member
			// equal to the supergroup is the teardown sentinel: real on-air DEL
			// frames name the supergroup as its own members (e.g. sg=5105,
			// members=[5105,5105,5105]) to signal "drop the whole patch". Both
			// are dropped so a genuine teardown surfaces as an empty member list
			// (patchDelLocked then tears down the supergroup). This is shared
			// with GRG_ADD, where patchAddLocked already skips m==sg, so the
			// filter is harmless there.
			t.SuperGroup = uint16(bitsToUint32(args[0:16]))
			for i := range 3 {
				g := uint16(bitsToUint32(args[16+i*16 : 32+i*16]))
				if g != 0 && g != t.SuperGroup {
					t.PatchGroups[t.PatchGroupN] = g
					t.PatchGroupN++
				}
			}
		case OpcodeMotGRGCNGrant:
			// rsvd[0:8] ch[8:24] sg[24:40] sa[40:64] (op25 tk_p25.py:809).
			t.ChannelID = uint16(bitsToUint32(args[8:24]))
			t.SuperGroup = uint16(bitsToUint32(args[24:40]))
			t.SourceID = bitsToUint32(args[40:64])
		case OpcodeMotGRGCNGrantUpdt:
			// ch1[0:16] sg1[16:32] ch2[32:48] sg2[48:64] (op25 tk_p25.py:837).
			t.ChannelID = uint16(bitsToUint32(args[0:16]))
			t.SuperGroup = uint16(bitsToUint32(args[16:32]))
			t.ChannelID2 = uint16(bitsToUint32(args[32:48]))
			t.GroupID2 = bitsToUint32(args[48:64])
		case OpcodeMotGRGUnk0A:
			// Undocumented. Structurally the trailing 40 bits carry a
			// group[24:40] + unit[40:64] pair (matches GRP_AFF_QUERY-style
			// addressing); the interpretation is TENTATIVE, unverified
			// against any spec, and may be wrong.
			t.GroupID = bitsToUint32(args[24:40])
			t.SourceID = bitsToUint32(args[40:64])
		}
		return
	}
	switch t.Opcode {
	case OpcodeGroupVoiceGrant: // svc[8] ch[16] tg[16] src[24]
		t.ChannelID = uint16(bitsToUint32(args[8:24]))
		t.GroupID = bitsToUint32(args[24:40])
		t.SourceID = bitsToUint32(args[40:64])

	case OpcodeGroupVoiceGrantUpdate: // ch1[16] tg1[16] ch2[16] tg2[16]
		t.ChannelID = uint16(bitsToUint32(args[0:16]))
		t.GroupID = bitsToUint32(args[16:32])
		t.ChannelID2 = uint16(bitsToUint32(args[32:48]))
		t.GroupID2 = bitsToUint32(args[48:64])

	case OpcodeGroupVoiceGrantUpdtExp: // svc[8] rsvd[8] chT[16] chR[16] tg[16]
		// TIA-102.AABC-B GRP_V_CH_GRANT_UPDT_EXP carries an 8-bit reserved octet
		// between service options and the downlink channel. op25 trunking.py 0x03
		// (mfrid==0): ch1=tsbk>>48, ch2=tsbk>>32, ga=tsbk>>16; sdrtrunk
		// GroupVoiceChannelGrantUpdateExplicit RESERVED={24..31}. Skipping the
		// reserved octet would shift every field 8 bits early -> wrong RF channel
		// and garbage talkgroup.
		t.ChannelID = uint16(bitsToUint32(args[16:32]))
		t.ChannelID2 = uint16(bitsToUint32(args[32:48]))
		t.GroupID = bitsToUint32(args[48:64])

	case OpcodeUnitVoiceGrant: // ch[16] dst[24] src[24]
		t.ChannelID = uint16(bitsToUint32(args[0:16]))
		t.DestID = bitsToUint32(args[16:40])
		t.SourceID = bitsToUint32(args[40:64])

	case OpcodeTeleIntVoiceGrant: // svc[8] ch[16] callTimer[16] tgt[24]
		// Telephone interconnect: the call timer replaces the source field of
		// a group grant; the granted party is the target RID (DestID).
		t.ChannelID = uint16(bitsToUint32(args[8:24]))
		t.DestID = bitsToUint32(args[40:64])

	case OpcodeAckRspFNE: // aiv(1) ex(1) rsvd(6) svc(8) tgt(24) src(24)
		t.DestID = bitsToUint32(args[16:40])
		t.SourceID = bitsToUint32(args[40:64])

	case OpcodeGrpAffRsp: // lg(1) gav(1) rsvd(6) anncGrp(16) grp(16) tgt(24)
		t.GroupID2 = bitsToUint32(args[8:24]) // announcement group
		t.GroupID = bitsToUint32(args[24:40]) // affiliated group
		t.DestID = bitsToUint32(args[40:64])  // target address

	case OpcodeSCCBExp: // rfssid(8) siteid(8) ch1(16) sysSvc1(8) ch2(16) sysSvc2(8)
		t.RFSS = uint8(bitsToUint32(args[0:8]))
		t.Site = uint8(bitsToUint32(args[8:16]))
		t.ChannelID = uint16(bitsToUint32(args[16:32]))
		t.ChannelID2 = uint16(bitsToUint32(args[40:56]))

	case OpcodeGroupDataGrant: // svc[8] ch[16] dac[16] src[24]
		t.ChannelID = uint16(bitsToUint32(args[8:24]))
		t.GroupID = bitsToUint32(args[24:40])
		t.SourceID = bitsToUint32(args[40:64])

	case OpcodeSNDCPDataPageReq: // svc[8] rsvd[16] dac[16] dst[24]
		t.GroupID = bitsToUint32(args[24:40])
		t.DestID = bitsToUint32(args[40:64])

	case OpcodeGroupAffQuery: // rsvd[16] src[24] tgt[24]
		t.SourceID = bitsToUint32(args[16:40])
		t.DestID = bitsToUint32(args[40:64])

	case OpcodeLocRegResp: // rv[8] ga[16] rfss[8] site[8] ta[24]
		t.GroupID = bitsToUint32(args[8:24])
		t.RFSS = uint8(bitsToUint32(args[24:32]))
		t.Site = uint8(bitsToUint32(args[32:40]))
		t.SourceID = bitsToUint32(args[40:64])

	case OpcodeUnitRegResp: // rv[4] syid[12] sid[24] sa[24]
		t.SysID = uint16(bitsToUint32(args[4:16]))
		t.SourceID = bitsToUint32(args[16:40])
		t.DestID = bitsToUint32(args[40:64])

	case OpcodeQueRsp, OpcodeDenyRsp: // aiv[1] svc[7] reason[8] addl_info[24] target[24]
		t.AIV = args[0] == 1
		t.Reason = uint8(bitsToUint32(args[8:16]))
		t.AddlInfo = bitsToUint32(args[16:40])
		t.DestID = bitsToUint32(args[40:64])

	case OpcodeUnitRegCmd: // rsvd[16] src[24] tgt[24]
		t.SourceID = bitsToUint32(args[16:40])
		t.DestID = bitsToUint32(args[40:64])

	case OpcodeUnitDeRegAck: // rsvd[8] wacn[20] syid[12] sid[24]
		t.GroupID = bitsToUint32(args[8:28])
		t.SysID = uint16(bitsToUint32(args[28:40]))
		t.SourceID = bitsToUint32(args[40:64])

	case OpcodeIdenUp: // iden[4] bw[9] toff[9 sign-mag *250kHz] spac[10] base[32]
		t.Iden = uint8(bitsToUint32(args[0:4]))
		bw := int(bitsToUint32(args[4:13]))
		t.BandwidthHz = bw * 125
		// The 9-bit transmit offset is SIGN-MAGNITUDE, not two's-complement:
		// bit 8 = sign (1 = mobile transmits above the base/positive), bits 0-7 =
		// magnitude. Matches op25 trunking.py opcode 0x3d and the sibling
		// IDEN_UP_VU/IDEN_UP_TDMA branches below (TIA-102.AABC).
		toff := int64(bitsToUint32(args[13:22]))
		mag := toff & 0xFF
		if toff&0x100 == 0 {
			mag = -mag
		}
		t.TxOffsetHz = mag * 250_000
		t.SpacingHz = int(bitsToUint32(args[22:32])) * 125
		t.BaseFreqHz = int64(bitsToUint32(args[32:64])) * 5

	case OpcodeIdenUpVU: // iden[4] bwvu[4] toff[14 sign-mag *spacing] spac[10] base[32]
		t.Iden = uint8(bitsToUint32(args[0:4]))
		switch bitsToUint32(args[4:8]) {
		case 4:
			t.BandwidthHz = 6250
		case 5:
			t.BandwidthHz = 12500
		}
		t.SpacingHz = int(bitsToUint32(args[22:32])) * 125
		toff := int64(bitsToUint32(args[8:22]))
		mag := toff & 0x1FFF
		if toff&0x2000 == 0 {
			mag = -mag
		}
		t.TxOffsetHz = mag * int64(t.SpacingHz)
		t.BaseFreqHz = int64(bitsToUint32(args[32:64])) * 5

	case OpcodeIdenUpTDMA: // iden[4] chtype[4] toff[14 sign-mag *spacing] spac[10] base[32]
		t.Iden = uint8(bitsToUint32(args[0:4]))
		ct := bitsToUint32(args[4:8])
		slots := [16]int{1, 1, 1, 2, 4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
		t.TDMASlots = slots[ct]
		t.SpacingHz = int(bitsToUint32(args[22:32])) * 125
		toff := int64(bitsToUint32(args[8:22]))
		mag := toff & 0x1FFF
		if toff&0x2000 == 0 {
			mag = -mag
		}
		t.TxOffsetHz = mag * int64(t.SpacingHz)
		t.BaseFreqHz = int64(bitsToUint32(args[32:64])) * 5

	case OpcodeSNDCPDataChAnn: // ...[16] ch1[16] ch2[16] ...
		t.ChannelID = uint16(bitsToUint32(args[16:32]))
		t.ChannelID2 = uint16(bitsToUint32(args[32:48]))

	case OpcodeSyncBcast:
		// Date/time at args[24:51) verified against on-air samples
		// 00046A34AF52BCFC -> 2026-05-15T10:21 and ...AF568C62 -> 10:52,
		// each matching its trunking_events.ts.
		yr := 2000 + int(bitsToUint32(args[24:31]))
		mo := time.Month(bitsToUint32(args[31:35]))
		dy := int(bitsToUint32(args[35:40]))
		hh := int(bitsToUint32(args[40:45]))
		mn := int(bitsToUint32(args[45:51]))
		if mo >= 1 && mo <= 12 && dy >= 1 && dy <= 31 {
			t.SyncTime = time.Date(yr, mo, dy, hh, mn, 0, 0, time.UTC)
		}

	case OpcodeSecondaryCCBcast: // rfss[8] site[8] ch1[16] svc1[8] ch2[16] svc2[8]
		t.ChannelID = uint16(bitsToUint32(args[16:32]))
		t.ChannelID2 = uint16(bitsToUint32(args[40:56]))

	case OpcodeRFSSStatusBcast: // lra[8] flags[4] sys[12] rfss[8] site[8] ch[16] svc[8]
		t.CFVA = uint8(bitsToUint32(args[8:12]))
		t.SysID = uint16(bitsToUint32(args[12:24]))
		t.RFSS = uint8(bitsToUint32(args[24:32]))
		t.Site = uint8(bitsToUint32(args[32:40]))
		t.ChannelID = uint16(bitsToUint32(args[40:56]))

	case OpcodeNetworkStatusBcast: // lra[8] wacn[20] sys[12] chan[16] svc[8]
		t.GroupID = bitsToUint32(args[8:28])   // WACN
		t.SourceID = bitsToUint32(args[28:40]) // SysID
		t.SysID = uint16(bitsToUint32(args[28:40]))
		t.ChannelID = uint16(bitsToUint32(args[40:56]))

	case OpcodeAdjacentSiteBcast: // lra[8] cfva[4] sys[12] rfss[8] site[8] ch[16] svc[8]
		t.CFVA = uint8(bitsToUint32(args[8:12]))
		t.SysID = uint16(bitsToUint32(args[12:24]))
		t.RFSS = uint8(bitsToUint32(args[24:32]))
		t.Site = uint8(bitsToUint32(args[32:40]))
		t.ChannelID = uint16(bitsToUint32(args[40:56]))
	}
}

// HandledTSBK reports whether parseTSBKArgs populates any typed field
// (beyond RawArgs/MFID/Opcode/LastBlock/Protected) for the given
// (mfid, opcode) pair. Used by diagnostic tooling to flag on-air opcodes that
// fall through unparsed. Keep in lockstep with parseTSBKArgs;
// TestHandledTSBK_TracksParser enforces it.
func HandledTSBK(mfid uint8, op TSBKOpcode) bool {
	if mfid == 0x90 {
		switch op {
		case OpcodeMotBSI, OpcodeMotLoadPct, OpcodeMotSiteFlags,
			OpcodeMotGRGAdd, OpcodeMotGRGDel, OpcodeMotGRGCNGrant,
			OpcodeMotGRGCNGrantUpdt, OpcodeMotGRGUnk0A:
			return true
		}
		return false
	}
	switch op {
	case OpcodeGroupVoiceGrant, OpcodeGroupVoiceGrantUpdate,
		OpcodeGroupVoiceGrantUpdtExp, OpcodeUnitVoiceGrant, OpcodeTeleIntVoiceGrant,
		OpcodeGroupDataGrant, OpcodeSNDCPDataPageReq, OpcodeSNDCPDataChAnn,
		OpcodeAckRspFNE, OpcodeGrpAffRsp, OpcodeSCCBExp,
		OpcodeGroupAffQuery, OpcodeLocRegResp, OpcodeUnitRegResp, OpcodeUnitDeRegAck,
		OpcodeQueRsp, OpcodeDenyRsp, OpcodeUnitRegCmd,
		OpcodeIdenUp, OpcodeIdenUpVU, OpcodeIdenUpTDMA, OpcodeSyncBcast,
		OpcodeSecondaryCCBcast, OpcodeRFSSStatusBcast, OpcodeNetworkStatusBcast,
		OpcodeAdjacentSiteBcast:
		return true
	}
	return false
}

// OpcodeName returns the TIA-102.AABC mnemonic for a (mfid, opcode) pair,
// or "UNK_<hex>" if not known.
func OpcodeName(mfid uint8, op TSBKOpcode) string {
	if mfid == 0x90 {
		switch op {
		case OpcodeMotSiteFlags:
			return "MOT_SITE_FLAGS"
		case OpcodeMotLoadPct:
			return "MOT_LOAD"
		case OpcodeMotBSI:
			return "MOT_BSI_GRANT"
		case OpcodeMotGRGAdd:
			return "MOT_GRG_ADD_CMD"
		case OpcodeMotGRGDel:
			return "MOT_GRG_DEL_CMD"
		case OpcodeMotGRGCNGrant:
			return "MOT_GRG_CN_GRANT"
		case OpcodeMotGRGCNGrantUpdt:
			return "MOT_GRG_CN_GRANT_UPDT"
		case OpcodeMotGRGUnk0A:
			return "MOT_GRG_UNK_0A"
		}
		return fmt.Sprintf("MOT_UNK_%02X", uint8(op))
	}
	switch op {
	case OpcodeGroupVoiceGrant:
		return "GRP_V_CH_GRANT"
	case OpcodeGroupVoiceGrantUpdate:
		return "GRP_V_CH_GRANT_UPDT"
	case OpcodeGroupVoiceGrantUpdtExp:
		return "GRP_V_CH_GRANT_UPDT_EXP"
	case OpcodeUnitVoiceGrant:
		return "UU_V_CH_GRANT"
	case OpcodeTeleIntVoiceGrant:
		return "TELE_INT_CH_GRANT"
	case OpcodeTeleIntVoiceGrantUpdate:
		return "TELE_INT_CH_GRANT_UPDT"
	case OpcodeGroupDataGrant:
		return "SNDCP_DATA_CH_GRANT"
	case OpcodeSNDCPDataPageReq:
		return "SNDCP_DATA_PAGE_REQ"
	case OpcodeSNDCPDataChAnn:
		return "SNDCP_DATA_CH_ANN"
	case OpcodeAckRspFNE:
		return "ACK_RSP_FNE"
	case OpcodeQueRsp:
		return "QUE_RSP"
	case OpcodeExtFuncCmd:
		return "EXT_FNCT_CMD"
	case OpcodeDenyRsp:
		return "DENY_RSP"
	case OpcodeGrpAffRsp:
		return "GRP_AFF_RSP"
	case OpcodeSCCBExp:
		return "SCCB_EXP"
	case OpcodeGroupAffQuery:
		return "GRP_AFF_QUERY"
	case OpcodeLocRegResp:
		return "LOC_REG_RSP"
	case OpcodeUnitRegResp:
		return "U_REG_RSP"
	case OpcodeUnitRegCmd:
		return "U_REG_CMD"
	case OpcodeUnitDeRegAck:
		return "U_DE_REG_ACK"
	case OpcodeSyncBcast:
		return "SYNC_BCST"
	case OpcodeIdenUpTDMA:
		return "IDEN_UP_TDMA"
	case OpcodeIdenUpVU:
		return "IDEN_UP_VU"
	case OpcodeSystemServiceBcast:
		return "SYS_SRV_BCST"
	case OpcodeSecondaryCCBcast:
		return "SCCB"
	case OpcodeRFSSStatusBcast:
		return "RFSS_STS_BCST"
	case OpcodeNetworkStatusBcast:
		return "NET_STS_BCST"
	case OpcodeAdjacentSiteBcast:
		return "ADJ_STS_BCST"
	case OpcodeIdenUp:
		return "IDEN_UP"
	}
	return fmt.Sprintf("UNK_%02X", uint8(op))
}

// AlgoName returns the mnemonic for a P25 encryption Algorithm ID. Only the
// values implemented in op25 (reference/op25/.../op25_crypt.h) are mapped; the
// remainder of the TIA-102.AACA-A reservation table is intentionally not
// inlined here because we don't have the spec locally to verify it. Unknown
// IDs return "UNK_<hex>".
func AlgoName(algoID uint8) string {
	switch algoID {
	case 0x80:
		return "CLEAR"
	case 0x81:
		return "DES_OFB"
	case 0x84:
		return "AES_256"
	case 0xAA:
		return "ADP_RC4"
	}
	return fmt.Sprintf("UNK_%02X", algoID)
}

// crc32P25 computes the P25 PDU payload CRC-32 (TIA-102.BAAA; op25
// p25p1_fdma.cc:71). Polynomial 0x04c11db7, MSB-first, init 0, final XOR
// 0xffffffff. lenBits is the number of leading bits of buf to cover; it
// panics if lenBits > len(buf)*8.
func crc32P25(buf []byte, lenBits int) uint32 {
	const poly = 0x04c11db7
	var crc uint64
	for i := 0; i < lenBits; i++ {
		b := uint64(buf[i/8]>>(7-uint(i%8))) & 1
		crc <<= 1
		if ((crc>>32)^b)&1 != 0 {
			crc ^= poly
		}
	}
	return uint32(crc&0xffffffff) ^ 0xffffffff
}

// bitsToBytes packs a bit-per-byte slice (MSB first) into bytes.
// The slice length must be a multiple of 8.
func bitsToBytes(bits []uint8) []byte {
	out := make([]byte, len(bits)/8)
	for i, b := range bits {
		out[i/8] |= b << uint(7-i%8)
	}
	return out
}

// crcCCITT16 computes the P25 TSBK CRC (TIA-102.BAAC): polynomial 0x1021,
// init 0x0000, MSB-first, final XOR 0xFFFF. The transmitted 16-bit CRC field
// is computed over the first 80 bits and stored in bits 80..95; equivalently,
// crcCCITT16 over the full 12-byte block (data||CRC) yields 0 when valid.
//
// Verified against on-air NAC 0x171 control-channel TSBKs (see
// TestViterbiDecode_OnAirTSBK) and matches op25's p25p1_fdma.cc:crc16.
func crcCCITT16(data []byte) uint16 {
	const poly = 0x1021
	var crc uint32
	for _, b := range data {
		for j := 7; j >= 0; j-- {
			bit := uint32((b >> uint(j)) & 1)
			crc = ((crc << 1) | bit) & 0x1FFFF
			if crc&0x10000 != 0 {
				crc = (crc & 0xFFFF) ^ poly
			}
		}
	}
	return uint16(crc) ^ 0xFFFF
}
