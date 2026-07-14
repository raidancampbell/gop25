package p25

import (
	"testing"
	"time"
)

// encodeTDUlcPayload builds a TDULC payload []Dibit carrying the given Group
// Voice Channel User (LCO=0) link control, using the same FEC chain parseTDUlc
// inverts: LCW -> 12 data hexbits -> rsEncode63 -> 24 hexbits [data|parity] ->
// 12 Golay(24,12) codewords (each encoding 2 hexbits) -> 288 bits written
// sequentially into payload dibits, skipping status positions.
func encodeTDUlcPayload(t *testing.T, lco, mfid uint8, tg uint16, unit uint32) []Dibit {
	t.Helper()
	lcBits := make([]uint8, 72)
	put := func(start, width int, val uint32) {
		for j := 0; j < width; j++ {
			lcBits[start+j] = uint8((val >> uint(width-1-j)) & 1)
		}
	}
	put(0, 8, uint32(lco)) // LCO=0 here; pb/sf bits left 0
	put(8, 8, uint32(mfid))
	put(32, 16, uint32(tg))
	put(48, 24, unit)

	// Convert 72-bit LCW to 12 data hexbits.
	var hb [rsN]uint8
	for i := 0; i < rsK; i++ {
		hb[i] = uint8(bitsToUint32(lcBits[i*6 : i*6+6]))
	}
	// RS-encode: hb[0..11]=data, hb[12..23]=parity after rsEncode63.
	hb = rsEncode63(hb, rsN-rsK)

	out := make([]uint8, 0, 288)
	for c := 0; c < 12; c++ {
		// Each Golay codeword encodes 2 adjacent hexbits.
		// hb[0..11]=RS data (codewords 0..5), hb[12..23]=RS parity (codewords 6..11).
		msg12 := (uint16(hb[2*c]) << 6) | uint16(hb[2*c+1])
		g := golayEncode(msg12) // 23-bit
		// append overall even-parity bit as LSB to form the 24-bit word
		par := uint32(0)
		for x := g; x != 0; x >>= 1 {
			par ^= x & 1
		}
		cw24 := (g << 1) | par
		for b := 23; b >= 0; b-- {
			out = append(out, uint8((cw24>>uint(b))&1))
		}
	}

	payload := make([]Dibit, payloadLen(0xF))
	bi := 0
	for i := 0; i < len(payload) && bi+1 < tdulcDataBits; i++ {
		if isStatusPosition(i) {
			continue
		}
		payload[i] = Dibit(out[bi]<<1 | out[bi+1])
		bi += 2
	}
	return payload
}

// encodeTDUlcPayloadLCW builds a TDULC payload []Dibit carrying an arbitrary
// 72-bit LCW (MSB-first), using the same FEC chain as encodeTDUlcPayload.
func encodeTDUlcPayloadLCW(t *testing.T, lcBits []uint8) []Dibit {
	t.Helper()
	var hb [rsN]uint8
	for i := 0; i < rsK; i++ {
		hb[i] = uint8(bitsToUint32(lcBits[i*6 : i*6+6]))
	}
	hb = rsEncode63(hb, rsN-rsK)

	out := make([]uint8, 0, 288)
	for c := 0; c < 12; c++ {
		msg12 := (uint16(hb[2*c]) << 6) | uint16(hb[2*c+1])
		g := golayEncode(msg12)
		par := uint32(0)
		for x := g; x != 0; x >>= 1 {
			par ^= x & 1
		}
		cw24 := (g << 1) | par
		for b := 23; b >= 0; b-- {
			out = append(out, uint8((cw24>>uint(b))&1))
		}
	}

	payload := make([]Dibit, payloadLen(0xF))
	bi := 0
	for i := 0; i < len(payload) && bi+1 < tdulcDataBits; i++ {
		if isStatusPosition(i) {
			continue
		}
		payload[i] = Dibit(out[bi]<<1 | out[bi+1])
		bi += 2
	}
	return payload
}

func TestParseTDUlc_KnownLCW(t *testing.T) {
	// TG 5307 / unit 530001 chosen to match values seen on the NAC 0x171
	// 453.x voice channel, so a field-offset bug shows up as a wrong TG.
	const wantTG, wantUID = uint16(5307), uint32(530001)
	payload := encodeTDUlcPayload(t, 0x00, 0x00, wantTG, wantUID)

	lc := parseTDUlc(payload)
	if lc == nil {
		t.Fatal("parseTDUlc returned nil for a well-formed TDULC payload")
	}
	if lc.Talkgroup != wantTG {
		t.Errorf("Talkgroup = %d, want %d", lc.Talkgroup, wantTG)
	}
	if lc.UnitID != wantUID {
		t.Errorf("UnitID = %d, want %d", lc.UnitID, wantUID)
	}
	if lc.LCF&0x3F != 0 {
		t.Errorf("LCO = %d, want 0 (GRP_V_CH_USER)", lc.LCF&0x3F)
	}
}

// TestParseTDUlc_GolayCorrects verifies single-bit errors per Golay codeword
// are corrected (TDULC must survive light corruption like real captures).
func TestParseTDUlc_GolayCorrects(t *testing.T) {
	payload := encodeTDUlcPayload(t, 0x00, 0x00, 5307, 530001)
	// Flip one bit in the first non-status data dibit's high bit.
	for i := 0; i < len(payload); i++ {
		if !isStatusPosition(i) {
			payload[i] ^= 0b10
			break
		}
	}
	lc := parseTDUlc(payload)
	if lc == nil || lc.Talkgroup != 5307 {
		t.Fatalf("Golay failed to correct 1 bit error: got %+v", lc)
	}
}

func TestParseTDUlc_UnitToUnit(t *testing.T) {
	// LCO=3 unit-to-unit: TARGET[24:48]=0xABCD, SOURCE[48:72]=0x1234
	lcw := []byte{0x03, 0x00, 0x00, 0x00, 0xAB, 0xCD, 0x00, 0x12, 0x34}
	lcBits := make([]uint8, 72)
	for i := 0; i < 9; i++ {
		for j := 0; j < 8; j++ {
			lcBits[i*8+j] = (lcw[i] >> uint(7-j)) & 1
		}
	}
	var hb [rsN]uint8
	for i := 0; i < rsK; i++ {
		hb[i] = uint8(bitsToUint32(lcBits[i*6 : i*6+6]))
	}
	hb = rsEncode63(hb, rsN-rsK)

	out := make([]uint8, 0, 288)
	for c := 0; c < 12; c++ {
		msg12 := (uint16(hb[2*c]) << 6) | uint16(hb[2*c+1])
		g := golayEncode(msg12)
		par := uint32(0)
		for x := g; x != 0; x >>= 1 {
			par ^= x & 1
		}
		cw24 := (g << 1) | par
		for b := 23; b >= 0; b-- {
			out = append(out, uint8((cw24>>uint(b))&1))
		}
	}

	payload := make([]Dibit, payloadLen(0xF))
	bi := 0
	for i := 0; i < len(payload) && bi+1 < tdulcDataBits; i++ {
		if isStatusPosition(i) {
			continue
		}
		payload[i] = Dibit(out[bi]<<1 | out[bi+1])
		bi += 2
	}

	lc := parseTDUlc(payload)
	if lc == nil {
		t.Fatal("parseTDUlc returned nil for a well-formed TDULC payload")
	}
	if lc.LCF&0x3F != 3 {
		t.Errorf("LCO = %d, want 3 (UNIT_TO_UNIT_V_CH_USER)", lc.LCF&0x3F)
	}
	if lc.UnitID != 0x1234 {
		t.Errorf("UnitID = 0x%04X, want 0x1234", lc.UnitID)
	}
	if lc.DestID != 0xABCD {
		t.Errorf("DestID = 0x%04X, want 0xABCD", lc.DestID)
	}
	if lc.Talkgroup != 0 {
		t.Errorf("Talkgroup = %d, want 0", lc.Talkgroup)
	}
}

func parseOne(t *testing.T, opcode, mfid uint8, args [8]byte) TSBKData {
	t.Helper()
	bits := makeTSBKBits(t, opcode, mfid, args)
	payload := buildPayloadWithStatus(trellisEncode(bits))
	got := parseTSBKs(payload)
	if len(got) != 1 {
		t.Fatalf("expected 1 TSBK, got %d", len(got))
	}
	return got[0]
}

func TestParseTSBK_TelephoneInterconnectGrant(t *testing.T) {
	// 0x08 TELE_INT_CH_GRANT: svc[8] ch[16] callTimer[16] tgt[24].
	// svc=0x00 ch=0x1023 callTimer=0x003C tgt=0x00ABCD
	tsbk := parseOne(t, 0x08, 0x00,
		[8]byte{0x00, 0x10, 0x23, 0x00, 0x3C, 0x00, 0xAB, 0xCD})
	if tsbk.Opcode != OpcodeTeleIntVoiceGrant {
		t.Fatalf("Opcode = 0x%02X, want 0x08", uint8(tsbk.Opcode))
	}
	if tsbk.ChannelID != 0x1023 {
		t.Errorf("ChannelID = 0x%04X, want 0x1023", tsbk.ChannelID)
	}
	if tsbk.DestID != 0x00ABCD {
		t.Errorf("DestID = 0x%06X, want 0x00ABCD", tsbk.DestID)
	}
}

func TestParseTSBK_KnownGrant(t *testing.T) {
	// 0x00 GRP_V_CH_GRANT: svc=0x00 ch=0x100A tg=0x0064 src=0x003039 (12345)
	tsbk := parseOne(t, 0x00, 0x00,
		[8]byte{0x00, 0x10, 0x0A, 0x00, 0x64, 0x00, 0x30, 0x39})
	if tsbk.ChannelID != 0x100A {
		t.Errorf("ChannelID: want 0x100A, got 0x%04X", tsbk.ChannelID)
	}
	if tsbk.GroupID != 100 {
		t.Errorf("GroupID: want 100, got %d", tsbk.GroupID)
	}
	if tsbk.SourceID != 12345 {
		t.Errorf("SourceID: want 12345, got %d", tsbk.SourceID)
	}
}

func TestParseTSBK_GrantUpdate(t *testing.T) {
	// 0x02 GRP_V_CH_GRANT_UPDT: ch1=0x100A tg1=100 ch2=0x100B tg2=200
	tsbk := parseOne(t, 0x02, 0x00,
		[8]byte{0x10, 0x0A, 0x00, 0x64, 0x10, 0x0B, 0x00, 0xC8})
	if tsbk.ChannelID != 0x100A || tsbk.GroupID != 100 {
		t.Errorf("ch1/tg1: want 0x100A/100, got 0x%04X/%d", tsbk.ChannelID, tsbk.GroupID)
	}
	if tsbk.ChannelID2 != 0x100B || tsbk.GroupID2 != 200 {
		t.Errorf("ch2/tg2: want 0x100B/200, got 0x%04X/%d", tsbk.ChannelID2, tsbk.GroupID2)
	}
}

func TestParseTSBK_IdenUpVU(t *testing.T) {
	// 0x34 IDEN_UP_VU: iden=1 bwvu=4 toff=0 spacing=100(*125=12.5kHz)
	// base=90_000_000(*5=450MHz)
	// args bits: iden[4]=0001 bwvu[4]=0100 toff[14]=0 spac[10]=0001100100 base[32]=90e6
	// byte0 = 0001 0100 = 0x14
	// byte1 = 00000000   (toff hi 8)
	// byte2 = 000000 | 00 (toff lo 6 | spac hi 2) = 0x00
	// byte3 = 01100100   (spac lo 8) = 0x64
	// 90_000_000 = 0x055D4A80 -> bytes 4..7
	tsbk := parseOne(t, 0x34, 0x00,
		[8]byte{0x14, 0x00, 0x00, 0x64, 0x05, 0x5D, 0x4A, 0x80})
	if tsbk.Iden != 1 {
		t.Errorf("Iden: want 1, got %d", tsbk.Iden)
	}
	if tsbk.SpacingHz != 12500 {
		t.Errorf("SpacingHz: want 12500, got %d", tsbk.SpacingHz)
	}
	if tsbk.BaseFreqHz != 450_000_000 {
		t.Errorf("BaseFreqHz: want 450000000, got %d", tsbk.BaseFreqHz)
	}
	if tsbk.TDMASlots != 0 {
		t.Errorf("TDMASlots: want 0 for VU, got %d", tsbk.TDMASlots)
	}
}

func TestParseTSBK_IdenUp(t *testing.T) {
	// 0x3D IDEN_UP: iden=2 bw=0x004(=4) toff=0x000 spac=100 base=90e6
	// bits: iden[4]=0010 bw[9]=000000100 toff[9]=000000000 spac[10]=0001100100 base[32]
	// byte0 = 0010 0000 = 0x20  (iden | bw[8:5])
	// byte1 = 0010 0|000 = 0x20 (bw[4:0] | toff[8:6])
	// byte2 = 000000|00 = 0x00 (toff[5:0] | spac[9:8])
	// byte3 = 01100100 = 0x64
	tsbk := parseOne(t, 0x3D, 0x00,
		[8]byte{0x20, 0x20, 0x00, 0x64, 0x05, 0x5D, 0x4A, 0x80})
	if tsbk.Iden != 2 {
		t.Errorf("Iden: want 2, got %d", tsbk.Iden)
	}
	if tsbk.SpacingHz != 12500 {
		t.Errorf("SpacingHz: want 12500, got %d", tsbk.SpacingHz)
	}
	if tsbk.BaseFreqHz != 450_000_000 {
		t.Errorf("BaseFreqHz: want 450000000, got %d", tsbk.BaseFreqHz)
	}
}

// On-air vector from NAC 0x171 IDEN_UP_VU (raw TSBK b4 00 35 8c 80 32 05 5d 4a 80 a3 8d):
// iden=3 bwvu=5(12.5kHz) toff=sign1/mag800 spacing=50(*125=6250Hz) base=90_000_000(*5=450MHz)
// TIA-102.AABC: 14-bit toff is sign-magnitude (bit13=sign, bits0-12=mag), NOT two's-complement.
// 800 * 6250 = 5_000_000 -> -5 MHz. The previous two's-complement decode produced -46.2 MHz.
func TestParseTSBK_IdenUpVU_TxOffset(t *testing.T) {
	tsbk := parseOne(t, 0x34, 0x00,
		[8]byte{0x35, 0x8C, 0x80, 0x32, 0x05, 0x5D, 0x4A, 0x80})
	if tsbk.Iden != 3 {
		t.Errorf("Iden: want 3, got %d", tsbk.Iden)
	}
	if tsbk.SpacingHz != 6250 {
		t.Errorf("SpacingHz: want 6250, got %d", tsbk.SpacingHz)
	}
	if tsbk.BaseFreqHz != 450_000_000 {
		t.Errorf("BaseFreqHz: want 450000000, got %d", tsbk.BaseFreqHz)
	}
	if tsbk.TxOffsetHz != 5_000_000 {
		t.Errorf("TxOffsetHz: want 5000000, got %d", tsbk.TxOffsetHz)
	}
}

// IDEN_UP (0x3D) transmit offset is sign-magnitude (bit 8 = sign, 1 = positive;
// bits 0-7 = magnitude), NOT two's-complement. Regression for the bug where the
// 0x3D branch used two's-complement while the VU/TDMA branches were sign-magnitude.
// iden=2 bw=4 spac=100(*125=12.5kHz) base=90_000_000(*5=450MHz), magnitude=180
// (0xB4) -> 180*250kHz = 45 MHz. Sign bit clear -> -45 MHz; set -> +45 MHz.
func TestParseTSBK_IdenUp_TxOffsetNegative(t *testing.T) {
	// toff9=0x0B4 (sign bit clear, magnitude 180) -> -45 MHz.
	tsbk := parseOne(t, 0x3D, 0x00,
		[8]byte{0x20, 0x22, 0xD0, 0x64, 0x05, 0x5D, 0x4A, 0x80})
	if tsbk.Iden != 2 {
		t.Errorf("Iden: want 2, got %d", tsbk.Iden)
	}
	if tsbk.SpacingHz != 12500 {
		t.Errorf("SpacingHz: want 12500, got %d", tsbk.SpacingHz)
	}
	if tsbk.BaseFreqHz != 450_000_000 {
		t.Errorf("BaseFreqHz: want 450000000, got %d", tsbk.BaseFreqHz)
	}
	if tsbk.TxOffsetHz != -45_000_000 {
		t.Errorf("TxOffsetHz: want -45000000, got %d", tsbk.TxOffsetHz)
	}
}

func TestParseTSBK_IdenUp_TxOffsetPositive(t *testing.T) {
	// toff9=0x1B4 (sign bit set, magnitude 180) -> +45 MHz.
	tsbk := parseOne(t, 0x3D, 0x00,
		[8]byte{0x20, 0x26, 0xD0, 0x64, 0x05, 0x5D, 0x4A, 0x80})
	if tsbk.TxOffsetHz != 45_000_000 {
		t.Errorf("TxOffsetHz: want 45000000, got %d", tsbk.TxOffsetHz)
	}
}

func TestParseTSBK_IdenUpTDMA_TxOffset(t *testing.T) {
	// iden=5 chtype=3(2-slot) toff=sign1/mag800 spacing=50(*125=6250) base=450MHz
	// bits: 0101 0011 | 10 0011 0010 0000 | 00 0011 0010 | base
	// byte0=0x53 byte1=0x8C byte2=0x80 byte3=0x32 bytes4-7=0x055D4A80
	tsbk := parseOne(t, 0x33, 0x00,
		[8]byte{0x53, 0x8C, 0x80, 0x32, 0x05, 0x5D, 0x4A, 0x80})
	if tsbk.Iden != 5 || tsbk.TDMASlots != 2 {
		t.Errorf("Iden/TDMASlots: want 5/2, got %d/%d", tsbk.Iden, tsbk.TDMASlots)
	}
	if tsbk.TxOffsetHz != 5_000_000 {
		t.Errorf("TxOffsetHz: want 5000000, got %d", tsbk.TxOffsetHz)
	}
}

func TestParseTSBK_NetStatChannel(t *testing.T) {
	// 0x3B NET_STS_BCST: lra[8] wacn[20] sysid[12] chan[16] svc[8]
	// chan at args bits 40:56 -> bytes 5,6
	tsbk := parseOne(t, 0x3B, 0x00,
		[8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00})
	if tsbk.ChannelID != 0x1234 {
		t.Errorf("ChannelID: want 0x1234, got 0x%04X", tsbk.ChannelID)
	}
}

// On-air vector from NAC 0x171 MOT_BSI_GRANT (raw 8b 90 b2 5b 17 38 e1 80 36 a2 ...).
// Eight 6-bit chars at args[0:48), each non-zero mapped to ASCII via +43, then
// ch[16] at args[48:64). Verified against op25 tk_p25.py:863-877.
func TestParseTSBK_MotBSI(t *testing.T) {
	tsbk := parseOne(t, 0x0B, 0x90,
		[8]byte{0xB2, 0x5B, 0x17, 0x38, 0xE1, 0x80, 0x36, 0xA2})
	if tsbk.Callsign != "WPWB991" {
		t.Errorf("Callsign: want %q, got %q", "WPWB991", tsbk.Callsign)
	}
	if tsbk.ChannelID != 0x36A2 {
		t.Errorf("ChannelID: want 0x36A2, got 0x%04X", tsbk.ChannelID)
	}

	// Empty-BSI variant (97% of on-air 0x0B): all-zero chars, ch=CC itself.
	tsbk = parseOne(t, 0x0B, 0x90,
		[8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x82})
	if tsbk.Callsign != "" {
		t.Errorf("empty BSI: want \"\", got %q", tsbk.Callsign)
	}
	if tsbk.ChannelID != 0x3682 {
		t.Errorf("empty BSI ChannelID: want 0x3682, got 0x%04X", tsbk.ChannelID)
	}
}

// On-air: first 10 bits = N in {50,55,..,100}, trailing 54 bits zero.
// Interpretation (utilization %) is inferred from the histogram, not documented.
func TestParseTSBK_MotAltField(t *testing.T) {
	tsbk := parseOne(t, 0x09, 0x90,
		[8]byte{0x0D, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if tsbk.MotAltField != 55 {
		t.Errorf("MotAltField: want 55, got %d", tsbk.MotAltField)
	}
	tsbk = parseOne(t, 0x09, 0x90,
		[8]byte{0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if tsbk.MotAltField != 100 {
		t.Errorf("MotAltField: want 100, got %d", tsbk.MotAltField)
	}
}

func TestParseTSBK_MotSiteFlags(t *testing.T) {
	tsbk := parseOne(t, 0x05, 0x90,
		[8]byte{0x40, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x08, 0x00})
	if tsbk.SiteFlags != 0x4000C00000000800 {
		t.Errorf("SiteFlags: want 0x4000C00000000800, got 0x%016X", tsbk.SiteFlags)
	}
}

// Regression for the removed inline 0x90 guards: an MFID90 frame whose
// opcode collides with a standard one must NOT be decoded with the standard
// layout. MFID90 op00 is MOT_GRG_ADD_CMD (supergroup + member talkgroups),
// not the standard Group Voice Channel Grant, so the standard grant fields
// (ChannelID/GroupID/SourceID via the svc[8]ch[16]tg[16]src[24] layout) must
// stay zero even though the GRG fields populate.
func TestParseTSBK_MFID90Opcode00_NoStandardDecode(t *testing.T) {
	// Args that *would* parse as ch=0x1234 tg=5305 src=12345 if the
	// standard 0x00 layout were applied.
	tsbk := parseOne(t, 0x00, 0x90,
		[8]byte{0x00, 0x12, 0x34, 0x14, 0xB9, 0x00, 0x30, 0x39})
	if tsbk.ChannelID != 0 || tsbk.GroupID != 0 || tsbk.SourceID != 0 {
		t.Errorf("MFID90 op00 must not standard-decode: got ch=0x%04X tg=%d src=%d",
			tsbk.ChannelID, tsbk.GroupID, tsbk.SourceID)
	}
	// It IS the GRG add command: sg[0:16]=0x0012, ga1[16:32]=0x3414, etc.
	if tsbk.SuperGroup != 0x0012 {
		t.Errorf("SuperGroup: want 0x0012, got 0x%04X", tsbk.SuperGroup)
	}
}

// On-air MFID90 Group Regroup (patch/supergroup) command family. Vectors are
// the real raw_args_hex from db/tsbk_opcode_samples.csv (WV SIRN Greenbrier,
// NAC 0x171). Layouts per op25 tk_p25.py (MOT_GRG_*). These five close the
// control-channel opcode frontier.
func TestParseTSBK_MotGRGAdd(t *testing.T) {
	// 0x00 MOT_GRG_ADD_CMD 13F113EF13EF13EF: sg=5105 members=[5103,5103,5103].
	tsbk := parseOne(t, 0x00, 0x90,
		[8]byte{0x13, 0xF1, 0x13, 0xEF, 0x13, 0xEF, 0x13, 0xEF})
	if tsbk.SuperGroup != 5105 {
		t.Errorf("SuperGroup: want 5105, got %d", tsbk.SuperGroup)
	}
	if tsbk.PatchGroupN != 3 || tsbk.PatchGroups != [3]uint16{5103, 5103, 5103} {
		t.Errorf("PatchGroups: want [5103 5103 5103] n=3, got %v n=%d",
			tsbk.PatchGroups, tsbk.PatchGroupN)
	}
}

func TestParseTSBK_MotGRGDel(t *testing.T) {
	// 0x01 MOT_GRG_DEL_CMD 13F113F113F113F1: sg=5105 members=[5105,5105,5105].
	// The real on-air teardown DEL names the supergroup as its own members. Those
	// self-referential members are the teardown sentinel, not real member groups,
	// so the parser drops them (g==sg) and surfaces an EMPTY member list. That
	// empty list is what drives patchDelLocked to tear down the whole supergroup
	// instead of trying (and failing) to remove 5105 from the real members.
	tsbk := parseOne(t, 0x01, 0x90,
		[8]byte{0x13, 0xF1, 0x13, 0xF1, 0x13, 0xF1, 0x13, 0xF1})
	if tsbk.SuperGroup != 5105 {
		t.Errorf("SuperGroup: want 5105, got %d", tsbk.SuperGroup)
	}
	if tsbk.PatchGroupN != 0 {
		t.Errorf("PatchGroups: want empty (sg-as-members is the teardown sentinel), got %v n=%d",
			tsbk.PatchGroups, tsbk.PatchGroupN)
	}
}

// A DEL that names a genuine member (distinct from the supergroup) must NOT be
// mistaken for the teardown sentinel: the real member survives parsing so
// patchDelLocked removes just that one member.
func TestParseTSBK_MotGRGDel_GenuineMember(t *testing.T) {
	// sg=5105 (0x13F1), member=5103 (0x13EF) in the first slot, remaining slots
	// unused (0). Only the real member 5103 should survive.
	tsbk := parseOne(t, 0x01, 0x90,
		[8]byte{0x13, 0xF1, 0x13, 0xEF, 0x00, 0x00, 0x00, 0x00})
	if tsbk.SuperGroup != 5105 {
		t.Errorf("SuperGroup: want 5105, got %d", tsbk.SuperGroup)
	}
	if tsbk.PatchGroupN != 1 || tsbk.PatchGroups[0] != 5103 {
		t.Errorf("PatchGroups: want [5103] n=1, got %v n=%d",
			tsbk.PatchGroups, tsbk.PatchGroupN)
	}
}

func TestParseTSBK_MotGRGCNGrant(t *testing.T) {
	// 0x02 MOT_GRG_CN_GRANT 00377213F107C849: ch=0x3772 sg=5105 src=510025.
	tsbk := parseOne(t, 0x02, 0x90,
		[8]byte{0x00, 0x37, 0x72, 0x13, 0xF1, 0x07, 0xC8, 0x49})
	if tsbk.ChannelID != 0x3772 {
		t.Errorf("ChannelID: want 0x3772, got 0x%04X", tsbk.ChannelID)
	}
	if tsbk.SuperGroup != 5105 {
		t.Errorf("SuperGroup: want 5105, got %d", tsbk.SuperGroup)
	}
	if tsbk.SourceID != 510025 {
		t.Errorf("SourceID: want 510025, got %d", tsbk.SourceID)
	}
}

func TestParseTSBK_MotGRGCNGrantUpdt(t *testing.T) {
	// 0x03 MOT_GRG_CN_GRANT_UPDT 377213F1377213F1:
	// ch1=0x3772 sg1=5105 ch2=0x3772 sg2=5105.
	tsbk := parseOne(t, 0x03, 0x90,
		[8]byte{0x37, 0x72, 0x13, 0xF1, 0x37, 0x72, 0x13, 0xF1})
	if tsbk.ChannelID != 0x3772 || tsbk.ChannelID2 != 0x3772 {
		t.Errorf("channels: want 0x3772/0x3772, got 0x%04X/0x%04X",
			tsbk.ChannelID, tsbk.ChannelID2)
	}
	if tsbk.SuperGroup != 5105 || tsbk.GroupID2 != 5105 {
		t.Errorf("supergroups: want 5105/5105, got %d/%d", tsbk.SuperGroup, tsbk.GroupID2)
	}
}

func TestParseTSBK_MotGRGUnk0A(t *testing.T) {
	// 0x0A MOT_GRG_UNK_0A 00000014B60829FE: best-effort group[16:32]=5302,
	// unit[40:64]=535038. Interpretation is tentative (no reference layout).
	tsbk := parseOne(t, 0x0A, 0x90,
		[8]byte{0x00, 0x00, 0x00, 0x14, 0xB6, 0x08, 0x29, 0xFE})
	if tsbk.GroupID != 5302 {
		t.Errorf("GroupID: want 5302, got %d", tsbk.GroupID)
	}
	if tsbk.SourceID != 535038 {
		t.Errorf("SourceID: want 535038, got %d", tsbk.SourceID)
	}
}

// On-air NAC 0x171 ADJ_STS_BCST: lra=0 cfva=3 sys=0x170 rfss=2 site=44 ch=0x3282 svc=0x70.
func TestParseTSBK_AdjStatus(t *testing.T) {
	tsbk := parseOne(t, 0x3C, 0x00,
		[8]byte{0x00, 0x31, 0x70, 0x02, 0x2C, 0x32, 0x82, 0x70})
	if tsbk.SysID != 0x170 || tsbk.RFSS != 2 || tsbk.Site != 44 {
		t.Errorf("ident: want sys=0x170 rfss=2 site=44, got sys=0x%X rfss=%d site=%d",
			tsbk.SysID, tsbk.RFSS, tsbk.Site)
	}
	if tsbk.ChannelID != 0x3282 {
		t.Errorf("ChannelID: want 0x3282, got 0x%04X", tsbk.ChannelID)
	}
}

// On-air NAC 0x171 RFSS_STS_BCST: sys=0x170 rfss=2 site=41 ch=0x3682.
func TestParseTSBK_RFSSStatus_Identity(t *testing.T) {
	tsbk := parseOne(t, 0x3A, 0x00,
		[8]byte{0x00, 0x31, 0x70, 0x02, 0x29, 0x36, 0x82, 0x70})
	if tsbk.SysID != 0x170 || tsbk.RFSS != 2 || tsbk.Site != 41 {
		t.Errorf("ident: want sys=0x170 rfss=2 site=41, got sys=0x%X rfss=%d site=%d",
			tsbk.SysID, tsbk.RFSS, tsbk.Site)
	}
	if tsbk.ChannelID != 0x3682 {
		t.Errorf("ChannelID: want 0x3682, got 0x%04X", tsbk.ChannelID)
	}
}

// On-air SNDCP_DATA_CH_ANN: ch1=0x3226 (453.4375 MHz data ch), ch2=0xFFFF.
func TestParseTSBK_SNDCPDataChAnn(t *testing.T) {
	tsbk := parseOne(t, 0x16, 0x00,
		[8]byte{0x00, 0xC0, 0x32, 0x26, 0xFF, 0xFF, 0x00, 0x01})
	if tsbk.ChannelID != 0x3226 || tsbk.ChannelID2 != 0xFFFF {
		t.Errorf("ch: want 0x3226/0xFFFF, got 0x%04X/0x%04X",
			tsbk.ChannelID, tsbk.ChannelID2)
	}
}

// On-air SYNC_BCST: args[24:51) = yr/mo/dy/hh/mn. Sample 00046A34AF568C62
// decodes to 2026-05-15T10:52, matching the DB ts of that row.
func TestParseTSBK_SyncBcast(t *testing.T) {
	tsbk := parseOne(t, 0x30, 0x00,
		[8]byte{0x00, 0x04, 0x6A, 0x34, 0xAF, 0x56, 0x8C, 0x62})
	want := time.Date(2026, 5, 15, 10, 52, 0, 0, time.UTC)
	if !tsbk.SyncTime.Equal(want) {
		t.Errorf("SyncTime: want %v, got %v", want, tsbk.SyncTime)
	}
}

func TestParseTSBKArgs_CFVA(t *testing.T) {
	// args is a bit-slice (one bit per uint8). cfva occupies bits 8..11.
	mkArgs := func(cfva uint8) []uint8 {
		a := make([]uint8, 64)
		for i := 0; i < 4; i++ {
			a[8+i] = (cfva >> uint(3-i)) & 1 // MSB-first
		}
		return a
	}
	for _, op := range []TSBKOpcode{OpcodeAdjacentSiteBcast, OpcodeRFSSStatusBcast} {
		d := TSBKData{Opcode: op}
		parseTSBKArgs(&d, mkArgs(0b0011)) // Valid|Active
		if d.CFVA != 0b0011 {
			t.Errorf("op=0x%02X: CFVA=0x%X, want 0x3", op, d.CFVA)
		}
	}
}

// TestHandledTSBK_TracksParser feeds every (mfid,opcode) through
// parseTSBKArgs and checks HandledTSBK agrees with whether any typed
// field was populated. Catches "added a parse case but forgot to update
// HandledTSBK" (and vice versa).
func TestHandledTSBK_TracksParser(t *testing.T) {
	var ones, sync [64]uint8
	for i := range ones {
		ones[i] = 1
	}
	// All-ones makes SyncBcast mo=15 -> range check fails -> SyncTime stays
	// zero. Use the on-air vector for that one opcode.
	for i, by := range [8]byte{0x00, 0x04, 0x6A, 0x34, 0xAF, 0x56, 0x8C, 0x62} {
		for j := range 8 {
			sync[i*8+j] = (by >> uint(7-j)) & 1
		}
	}
	for _, mfid := range []uint8{0x00, 0x90} {
		for op := range TSBKOpcode(0x40) {
			d := TSBKData{Opcode: op, MFID: mfid}
			args := ones[:]
			if mfid == 0x00 && op == OpcodeSyncBcast {
				args = sync[:]
			}
			parseTSBKArgs(&d, args)
			populated := d.ChannelID != 0 || d.ChannelID2 != 0 ||
				d.GroupID != 0 || d.GroupID2 != 0 ||
				d.SourceID != 0 || d.DestID != 0 ||
				d.Iden != 0 || d.BaseFreqHz != 0 ||
				d.Callsign != "" || d.MotAltField != 0 || d.SiteFlags != 0 ||
				d.RFSS != 0 || d.Site != 0 || d.SysID != 0 || d.CFVA != 0 ||
				d.SuperGroup != 0 || d.PatchGroupN != 0 ||
				!d.SyncTime.IsZero()
			if populated != HandledTSBK(mfid, op) {
				t.Errorf("mfid=0x%02X op=0x%02X: populated=%v HandledTSBK=%v",
					mfid, op, populated, HandledTSBK(mfid, op))
			}
		}
	}
}

func TestOpcodeName_Coverage(t *testing.T) {
	for _, mfid := range []uint8{0x00, 0x90} {
		for op := range TSBKOpcode(0x40) {
			if HandledTSBK(mfid, op) {
				if got := OpcodeName(mfid, op); len(got) < 3 || got[:3] == "UNK" {
					t.Errorf("handled mfid=0x%02X op=0x%02X has no name: %q", mfid, op, got)
				}
			}
		}
	}
	if got := OpcodeName(0, 0x3F); got != "UNK_3F" {
		t.Errorf("OpcodeName(0,0x3F): want UNK_3F, got %q", got)
	}
}

// On-air SNDCP_DATA_CH_GRANT 013226FFFF0179A6: svc[8] ch[16] dac[16] src[24].
// ch=0x3226 (453.4375 MHz, same as SNDCP_DATA_CH_ANN), src=96678.
func TestParseTSBK_SNDCPDataChGrant(t *testing.T) {
	tsbk := parseOne(t, 0x14, 0x00,
		[8]byte{0x01, 0x32, 0x26, 0xFF, 0xFF, 0x01, 0x79, 0xA6})
	if tsbk.ChannelID != 0x3226 || tsbk.GroupID != 0xFFFF || tsbk.SourceID != 96678 {
		t.Errorf("got ch=0x%04X dac=%d src=%d", tsbk.ChannelID, tsbk.GroupID, tsbk.SourceID)
	}
}

// On-air SNDCP_DATA_PAGE_REQ 010000FFFF0179A6: dac[16]@[24:40], dst[24]@[40:64].
func TestParseTSBK_SNDCPDataPageReq(t *testing.T) {
	tsbk := parseOne(t, 0x15, 0x00,
		[8]byte{0x01, 0x00, 0x00, 0xFF, 0xFF, 0x01, 0x79, 0xA6})
	if tsbk.GroupID != 0xFFFF || tsbk.DestID != 96678 {
		t.Errorf("got dac=%d dst=%d", tsbk.GroupID, tsbk.DestID)
	}
}

// On-air GRP_AFF_QUERY 0000088BE4FFFFFD: src[24]@[16:40], tgt[24]@[40:64].
func TestParseTSBK_GroupAffQuery(t *testing.T) {
	tsbk := parseOne(t, 0x2A, 0x00,
		[8]byte{0x00, 0x00, 0x08, 0x8B, 0xE4, 0xFF, 0xFF, 0xFD})
	if tsbk.SourceID != 560100 || tsbk.DestID != 0xFFFFFD {
		t.Errorf("got src=%d dst=%d", tsbk.SourceID, tsbk.DestID)
	}
}

// On-air LOC_REG_RSP 00233B0229088B83 (op25 tk_p25.py:908):
// rv[8] ga[16] rfss[8] site[8] ta[24] -> ga=9019 rfss=2 site=41 ta=560003.
func TestParseTSBK_LocRegResp(t *testing.T) {
	tsbk := parseOne(t, 0x2B, 0x00,
		[8]byte{0x00, 0x23, 0x3B, 0x02, 0x29, 0x08, 0x8B, 0x83})
	if tsbk.GroupID != 9019 || tsbk.RFSS != 2 || tsbk.Site != 41 || tsbk.SourceID != 560003 {
		t.Errorf("got ga=%d rfss=%d site=%d ta=%d",
			tsbk.GroupID, tsbk.RFSS, tsbk.Site, tsbk.SourceID)
	}
}

// On-air U_REG_RSP 0170081846081846 (op25 tk_p25.py:919):
// rv[4] syid[12] sid[24] sa[24] -> syid=0x170 sid=sa=530502.
func TestParseTSBK_UnitRegResp(t *testing.T) {
	tsbk := parseOne(t, 0x2C, 0x00,
		[8]byte{0x01, 0x70, 0x08, 0x18, 0x46, 0x08, 0x18, 0x46})
	if tsbk.SysID != 0x170 || tsbk.SourceID != 530502 || tsbk.DestID != 530502 {
		t.Errorf("got syid=0x%X sid=%d sa=%d", tsbk.SysID, tsbk.SourceID, tsbk.DestID)
	}
}

// On-air U_DE_REG_ACK 00BEE001700829E4 (op25 tk_p25.py:929):
// wacn[20]@[8:28] syid[12]@[28:40] sid[24]@[40:64] -> 0xBEE00/0x170/535012.
func TestParseTSBK_UnitDeRegAck(t *testing.T) {
	tsbk := parseOne(t, 0x2F, 0x00,
		[8]byte{0x00, 0xBE, 0xE0, 0x01, 0x70, 0x08, 0x29, 0xE4})
	if tsbk.GroupID != 0xBEE00 || tsbk.SysID != 0x170 || tsbk.SourceID != 535012 {
		t.Errorf("got wacn=0x%X syid=0x%X sid=%d", tsbk.GroupID, tsbk.SysID, tsbk.SourceID)
	}
}

// On-air QUE_RSP 80400019B50A0294 (TIA-102.AABF-A §7.16):
// aiv[1] svc[7] reason[8] addl_info[24] target[24] ->
// aiv=1 reason=0x40 ("Target Queued") addl=0x0019B5 target=0x0A0294.
func TestParseTSBK_QueRsp(t *testing.T) {
	tsbk := parseOne(t, 0x21, 0x00,
		[8]byte{0x80, 0x40, 0x00, 0x19, 0xB5, 0x0A, 0x02, 0x94})
	if !tsbk.AIV || tsbk.Reason != 0x40 ||
		tsbk.AddlInfo != 0x0019B5 || tsbk.DestID != 0x0A0294 {
		t.Errorf("got aiv=%v reason=0x%X addl=0x%X tgt=0x%X",
			tsbk.AIV, tsbk.Reason, tsbk.AddlInfo, tsbk.DestID)
	}
}

// On-air DENY_RSP 80770019B509FDFC: same wire layout as QUE_RSP.
// reason=0x77 falls in the AABF-A "service-not-authorized" range.
func TestParseTSBK_DenyRsp(t *testing.T) {
	tsbk := parseOne(t, 0x27, 0x00,
		[8]byte{0x80, 0x77, 0x00, 0x19, 0xB5, 0x09, 0xFD, 0xFC})
	if !tsbk.AIV || tsbk.Reason != 0x77 ||
		tsbk.AddlInfo != 0x0019B5 || tsbk.DestID != 0x09FDFC {
		t.Errorf("got aiv=%v reason=0x%X addl=0x%X tgt=0x%X",
			tsbk.AIV, tsbk.Reason, tsbk.AddlInfo, tsbk.DestID)
	}
}

// On-air U_REG_CMD 00000825F0FFFFFE (TIA-102.AABF-A §7.27):
// rsvd[16] src[24] tgt[24]. Target 0xFFFFFE = "all units" wildcard,
// i.e. the FNE commanding every unit on the site to re-register.
func TestParseTSBK_UnitRegCmd(t *testing.T) {
	tsbk := parseOne(t, 0x2D, 0x00,
		[8]byte{0x00, 0x00, 0x08, 0x25, 0xF0, 0xFF, 0xFF, 0xFE})
	if tsbk.SourceID != 0x0825F0 || tsbk.DestID != 0xFFFFFE {
		t.Errorf("got src=0x%X tgt=0x%X", tsbk.SourceID, tsbk.DestID)
	}
}

// Synthetic test for 0x28 GRP_AFF_RSP: lg(1) gav(1) rsvd(6) anncGrp(16) grp(16) tgt(24).
// anncGrp=0x1234 grp=0x5678 tgt=0xABCDEF.
func TestParseTSBK_GrpAffRsp(t *testing.T) {
	// byte0: lg=0 gav=0 rsvd=0 + anncGrp[15:8] -> 0x00 | but anncGrp starts at bit 8
	// layout over 64 args bits:
	// bits[0:1]=lg, bits[1:2]=gav, bits[2:8]=rsvd, bits[8:24]=anncGrp,
	// bits[24:40]=grp, bits[40:64]=tgt
	// byte0 = bits[0:8] = lg|gav|rsvd = 0x00
	// byte1 = bits[8:16] = anncGrp high = 0x12
	// byte2 = bits[16:24] = anncGrp low = 0x34
	// byte3 = bits[24:32] = grp high = 0x56
	// byte4 = bits[32:40] = grp low = 0x78
	// byte5 = bits[40:48] = tgt[23:16] = 0xAB
	// byte6 = bits[48:56] = tgt[15:8] = 0xCD
	// byte7 = bits[56:64] = tgt[7:0] = 0xEF
	tsbk := parseOne(t, 0x28, 0x00,
		[8]byte{0x00, 0x12, 0x34, 0x56, 0x78, 0xAB, 0xCD, 0xEF})
	if tsbk.GroupID2 != 0x1234 {
		t.Errorf("AnncGrp (GroupID2): want 0x1234, got 0x%04X", tsbk.GroupID2)
	}
	if tsbk.GroupID != 0x5678 {
		t.Errorf("Grp (GroupID): want 0x5678, got 0x%04X", tsbk.GroupID)
	}
	if tsbk.DestID != 0xABCDEF {
		t.Errorf("Tgt (DestID): want 0xABCDEF, got 0x%06X", tsbk.DestID)
	}
}

// Synthetic test for 0x29 SCCB_EXP: rfssid(8) siteid(8) ch1(16) sysSvc1(8) ch2(16) sysSvc2(8).
func TestParseTSBK_SCCBExp(t *testing.T) {
	// rfss=0x02 site=0x29 ch1=0x3682 svc1=0x70 ch2=0x3282 svc2=0x70
	tsbk := parseOne(t, 0x29, 0x00,
		[8]byte{0x02, 0x29, 0x36, 0x82, 0x70, 0x32, 0x82, 0x70})
	if tsbk.RFSS != 2 || tsbk.Site != 0x29 {
		t.Errorf("RFSS/Site: want 2/0x29, got %d/0x%02X", tsbk.RFSS, tsbk.Site)
	}
	if tsbk.ChannelID != 0x3682 {
		t.Errorf("ChannelID: want 0x3682, got 0x%04X", tsbk.ChannelID)
	}
	if tsbk.ChannelID2 != 0x3282 {
		t.Errorf("ChannelID2: want 0x3282, got 0x%04X", tsbk.ChannelID2)
	}
}

// Synthetic test for 0x20 ACK_RSP_FNE: aiv(1) ex(1) rsvd(6) svc(8) tgt(24) src(24).
func TestParseTSBK_AckRspFNE(t *testing.T) {
	// tgt=0x088BE4 src=0x088B83
	tsbk := parseOne(t, 0x20, 0x00,
		[8]byte{0x00, 0x00, 0x08, 0x8B, 0xE4, 0x08, 0x8B, 0x83})
	if tsbk.DestID != 0x088BE4 {
		t.Errorf("DestID: want 0x088BE4, got 0x%06X", tsbk.DestID)
	}
	if tsbk.SourceID != 0x088B83 {
		t.Errorf("SourceID: want 0x088B83, got 0x%06X", tsbk.SourceID)
	}
}

func TestAlgoName(t *testing.T) {
	cases := []struct {
		id   uint8
		want string
	}{
		{0x80, "CLEAR"},
		{0x81, "DES_OFB"},
		{0x84, "AES_256"},
		{0xAA, "ADP_RC4"},
		{0x00, "UNK_00"},
		{0xFF, "UNK_FF"},
	}
	for _, c := range cases {
		if got := AlgoName(c.id); got != c.want {
			t.Errorf("AlgoName(0x%02X) = %q, want %q", c.id, got, c.want)
		}
	}
}
