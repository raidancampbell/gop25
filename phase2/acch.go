package phase2

import "github.com/raidancampbell/gop25"

// ACCHType selects the ACCH layout/CRC for a control burst.
type ACCHType int

const (
	ACCHFacch ACCHType = iota // 2V FACCH / scrambled-or-unscrambled FACCH; CRC-12, 144-bit
	ACCHSacch                 // SACCH; CRC-12, 168-bit
	ACCHLcch                  // LCCH; SACCH RS layout, CRC-16, 180-bit, 23-byte out
)

// acchSpec describes the dibit ranges and RS/hexbit layout for one ACCH type.
// Source: op25 p25p2_tdma.cc:437-510 (handle_acch_frame).
type acchSpec struct {
	ranges          [][2]int // [start, count] dibit ranges within the 180-dibit burst
	rsStart         int      // first hexbit index j in the length-63 HB vector
	dataBits        int      // bit length after RS decode (before CRC strip)
	puncturedParity int      // # of punctured-parity codeword positions (erasures)
	crc16           bool     // true for LCCH (CRC-16/CCITT); false for CRC-12
	olen            int      // packed output byte count
}

// acchSpecFor returns the layout for the given ACCH type. FACCH/SACCH values
// are op25 p25p2_tdma.cc:437-485 verbatim. LCCH (is_lcch) shares SACCH's RS
// layout (ranges, rsStart, erasures) but takes a 180-bit body validated by
// CRC-16 and packs 23 output bytes. Source: op25 handle_acch_frame:492-510.
func acchSpecFor(typ ACCHType) acchSpec {
	switch typ {
	case ACCHFacch:
		return acchSpec{
			ranges:          [][2]int{{11, 36}, {48, 31}, {100, 32}, {133, 36}},
			rsStart:         9,
			dataBits:        144,
			puncturedParity: 9, // cw[0..8]
			crc16:           false,
			olen:            18, // 144/8
		}
	case ACCHLcch:
		return acchSpec{
			ranges:          [][2]int{{11, 36}, {48, 84}, {133, 36}}, // SACCH ranges
			rsStart:         5,
			dataBits:        180, // is_lcch body length
			puncturedParity: 6,   // cw[0..5], same as SACCH
			crc16:           true,
			olen:            23, // op25 olen = 23 for is_lcch
		}
	default: // ACCHSacch
		return acchSpec{
			ranges:          [][2]int{{11, 36}, {48, 84}, {133, 36}},
			rsStart:         5,
			dataBits:        168,
			puncturedParity: 6, // cw[0..5]
			crc16:           false,
			olen:            21, // 168/8
		}
	}
}

// decodeACCHBytes extracts, RS(63,35)-corrects, and CRC-validates the ACCH
// from one DESCRAMBLED 180-dibit burst, returning the packed MAC PDU bytes
// (18 for FACCH, 21 for SACCH, 23 for LCCH) or (nil,false). typ selects
// FACCH/SACCH/LCCH layout and CRC (CRC-12 for FACCH/SACCH, CRC-16 for LCCH).
//
// Source: op25 handle_acch_frame (p25p2_tdma.cc:427-519). The RS placement
// mirrors phase2/ess.go and internal/p25/rs.go rsDecode63: ezpwd treats the
// hexbit vector index i as the coefficient of x^{62-i}, whereas RSDecodeN uses
// received[i]=coeff of x^i, so the HB vector is reversed into the codeword.
//
// RS decode strategy: this uses ERASURE decoding (p25.RSDecodeWithErasures),
// the same family as op25's rs28.decode(HB, Erasures) at p25p2_tdma.cc:484, but
// declares ONLY the punctured-parity positions as erasures -- NOT op25's literal
// {0-8,54-62} set. op25's list also erases the shortened-DATA positions, which
// are provably zero (the acch round-trip test decodes a clean burst with them
// zero-filled), so erasing them would waste budget; under the errata identity
// 2*errors + erasures <= 28 that would cap FACCH at e<=5. By erasing only the
// punctured parity (cw[0..8] FACCH / cw[0..5] SACCH, see acchSpec) and leaving
// the shortened data zero-filled (free), we get the full real-error budget:
// 2e + 9 <= 28 => e <= 9 (FACCH); 2e + 6 <= 28 => e <= 11 (SACCH). The deferred
// live gate must confirm the real on-air FACCH/SACCH decode rate.
func decodeACCHBytes(dibits []p25.Dibit, typ ACCHType) ([]byte, bool) {
	spec := acchSpecFor(typ)

	// 1. Extract bits from the declared dibit ranges (high bit then low bit).
	//    op25 p25p2_tdma.cc:438-466. The ranges are op25 burstp-relative
	//    (burstp = &dibits[10], p25p2_tdma.cc:698), so add PayloadOffset to index
	//    the absolute 180-dibit burst — matching the voice (VCW*Offset), ESS
	//    (ESSOffset), and DUID (DUIDPos*) paths, which all add PayloadOffset too.
	//    Without it every ACCH field reads 10 dibits early and RS+CRC fail on
	//    real on-air bursts.
	var bits []uint8
	for _, r := range spec.ranges {
		for i := r[0] + PayloadOffset; i < r[0]+r[1]+PayloadOffset; i++ {
			if i >= len(dibits) {
				return nil, false
			}
			d := dibits[i]
			bits = append(bits, uint8((d>>1)&1), uint8(d&1))
		}
	}

	// 2. Group bits into 6-bit hexbits at HB[rsStart..]; unwritten positions
	//    stay zero (punctured parity -> declared as erasures below; shortened
	//    data -> provably zero, free). op25 p25p2_tdma.cc:480-483.
	var hb [63]uint8
	j := spec.rsStart
	for i := 0; i+6 <= len(bits); i += 6 {
		hb[j] = bits[i]<<5 | bits[i+1]<<4 | bits[i+2]<<3 |
			bits[i+3]<<2 | bits[i+4]<<1 | bits[i+5]
		j++
	}

	// 3. Reverse HB (ezpwd, coeff x^{62-i}) into the RSDecodeN codeword
	//    (received[i]=coeff x^i), matching ess.go's convention.
	var cw [63]uint8
	for i := 0; i < 63; i++ {
		cw[62-i] = hb[i]
	}
	// Declare the punctured-parity positions cw[0 .. P-1] as erasures (P from
	// acchSpec: 9 FACCH / 6 SACCH); the shortened-data positions stay zero.
	erasures := make([]int, spec.puncturedParity)
	for i := range erasures {
		erasures[i] = i
	}
	corrected, _, ok := p25.RSDecodeWithErasures(63, 35, cw[:], erasures)
	if !ok {
		return nil, false
	}
	// Reverse back to HB order to read the data hexbits at HB[rsStart..].
	for i := 0; i < 63; i++ {
		hb[i] = corrected[62-i]
	}

	// 4. Hexbits back to bits (dataBits of them, starting at rsStart).
	//    op25 p25p2_tdma.cc:494-503.
	out := make([]uint8, spec.dataBits)
	j = spec.rsStart
	for i := 0; i+6 <= spec.dataBits; i += 6 {
		h := hb[j]
		out[i] = (h >> 5) & 1
		out[i+1] = (h >> 4) & 1
		out[i+2] = (h >> 3) & 1
		out[i+3] = (h >> 2) & 1
		out[i+4] = (h >> 1) & 1
		out[i+5] = h & 1
		j++
	}

	// 5. CRC over the data bits: CRC-16/CCITT for LCCH, CRC-12 otherwise.
	if spec.crc16 {
		if !crc16CCITTOK(out) {
			return nil, false
		}
	} else {
		if !crc12OK(out) {
			return nil, false
		}
	}

	// 6. Pack MSB-first into spec.olen bytes. For LCCH, olen (23) needs 184 bits;
	//    pad with zero beyond dataBits (matches op25, which reads past the 180-bit
	//    body into a zeroed buffer tail). op25:506-510.
	packed := make([]uint8, spec.olen*8)
	copy(packed, out)
	pdu := make([]byte, spec.olen)
	for i := 0; i < spec.olen; i++ {
		var b byte
		for k := 0; k < 8; k++ {
			b = (b << 1) | packed[i*8+k]
		}
		pdu[i] = b
	}
	return pdu, true
}

// MACPDU is a decoded Phase 2 MAC PDU from a FACCH/SACCH burst.
// Opcode is the 3-bit MAC control opcode (0 SIGNAL,1 PTT,2 END_PTT,3 IDLE,
// 4 ACTIVE,6 HANGTIME). Source: op25 process_mac_pdu (p25p2_tdma.cc:171-221).
type MACPDU struct {
	Opcode uint8
	Offset uint8
	Bytes  []byte

	HasIdentity bool
	Talkgroup   uint16
	SourceID    uint32
	ServiceOpts uint8

	HasEncryption bool
	AlgID         uint8
	KeyID         uint16
	MI            [9]byte

	// GPS holds an in-call Harris Talker GPS position (vendor sub-message op=0xAA,
	// MFID=0xA4); GPSOK is true when decoded.
	GPS   p25.GPSPosition
	GPSOK bool

	// vendorAliasMsgs holds vendor-specific talker-alias sub-messages recognized
	// during MAC_IDLE/MAC_ACTIVE multiplex walk. Body is the complete sub-message
	// byte slice [op, mfid, len, ...payload] for E2 reassembly.
	vendorAliasMsgs []vendorSubMsg
}

// vendorSubMsg is one recognized vendor alias sub-message extracted by the
// walker. Op is the full 8-bit sub-opcode, mfid is the manufacturer ID at
// byte_buf[ptr+1], and body is the sub-message slice buf[ptr:ptr+msgLen].
type vendorSubMsg struct {
	op   uint8
	mfid uint8
	body []byte
}

// DecodeACCH decodes one burst's ACCH into a MAC PDU. typ selects FACCH / SACCH
// / LCCH (layout + CRC). It runs the FEC pipeline (decodeACCHBytes) then parses
// call identity per op25's MAC opcode handlers. Returns (nil,false) on FEC/CRC
// failure. Source: op25 process_mac_pdu (p25p2_tdma.cc:171-221).
func DecodeACCH(dibits [BurstDibits]p25.Dibit, typ ACCHType) (*MACPDU, bool) {
	buf, ok := decodeACCHBytes(dibits[:], typ)
	if !ok || len(buf) < 1 {
		return nil, false
	}
	p := &MACPDU{
		Opcode: (buf[0] >> 5) & 0x7,
		Offset: (buf[0] >> 2) & 0x7,
		Bytes:  buf,
	}
	switch p.Opcode {
	case 1, 2: // MAC_PTT / MAC_END_PTT: fixed layout.
		// op25 handle_mac_ptt:244-255 (END_PTT identical, :280-281): MI=buf[1:10],
		// algid=buf[10], keyid=buf[11:13], srcaddr=buf[13:16], grpaddr=buf[16:18].
		if len(buf) >= 18 {
			for i := 0; i < 9; i++ {
				p.MI[i] = buf[1+i]
			}
			p.AlgID = buf[10]
			p.KeyID = uint16(buf[11])<<8 | uint16(buf[12])
			p.SourceID = uint32(buf[13])<<16 | uint32(buf[14])<<8 | uint32(buf[15])
			p.Talkgroup = uint16(buf[16])<<8 | uint16(buf[17])
			p.HasIdentity = true
			// op25 encrypted(): algid != 0x80 (ALGID_UNENC). 0x00 is also clear.
			p.HasEncryption = p.AlgID != 0 && p.AlgID != 0x80
		}
	case 3, 4: // MAC_IDLE / MAC_ACTIVE: embedded MAC sub-messages from byte 1.
		walkMACSubMessages(p)
	}
	return p, true
}

// macMsgLenTable maps a MAC sub-opcode to its fixed byte length (0 = variable
// or unknown). Verbatim from op25 p25p2_tdma.cc:73-89.
var macMsgLenTable = [256]uint8{
	0, 7, 8, 7, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 14, 15, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	5, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	9, 7, 9, 0, 9, 8, 9, 0, 10, 10, 9, 0, 10, 0, 0, 0,
	0, 0, 0, 0, 9, 7, 0, 0, 10, 0, 7, 0, 10, 8, 14, 7,
	9, 9, 0, 0, 9, 0, 0, 9, 10, 0, 7, 10, 10, 7, 0, 9,
	9, 29, 9, 9, 9, 9, 10, 13, 9, 9, 9, 11, 9, 9, 0, 0,
	8, 0, 0, 7, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	16, 0, 0, 11, 13, 11, 11, 11, 10, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	11, 0, 0, 8, 15, 12, 15, 32, 12, 12, 0, 27, 14, 29, 29, 32,
	0, 0, 0, 0, 0, 0, 9, 0, 14, 29, 11, 27, 14, 0, 40, 11,
	28, 0, 0, 14, 17, 14, 0, 0, 16, 8, 11, 0, 13, 19, 0, 0,
	0, 0, 16, 14, 0, 0, 12, 0, 22, 0, 11, 13, 11, 0, 15, 0,
}

// walkMACSubMessages decodes MAC sub-messages in a MAC_IDLE/MAC_ACTIVE PDU.
// Sub-messages are packed back-to-back starting at byte_buf[1], each with an
// 8-bit opcode (top 2 bits b1b2, low 6 bits mco) and a variable length. The
// walker loops over all sub-messages, extracting 0x01 Group Voice Channel User
// identity (preserves the existing behavior) and stashing vendor alias sub-
// messages (0x91/0x95/0xA8 with b1b2==2) for Task E2 reassembly.
//
// Length resolution mirrors op25 decode_mac_msg (p25p2_tdma.cc:328-410):
// special cases (0x00 consumes rest, 0x08/0x11/0x12 carry length in the next
// byte), vendor messages (b1b2==2, mfid@+1, len@+2&0x3f), else macMsgLenTable.
//
// Source: op25 p25p2_tdma.cc:73-89 (mac_msg_len) + :328-410 (decode_mac_msg).
func walkMACSubMessages(p *MACPDU) {
	buf := p.Bytes
	ptr := 1 // sub-messages start at byte_buf[1] (after the 1-byte PDU header)

walkerLoop:
	for ptr < len(buf) {
		op := buf[ptr]
		b1b2 := op >> 6
		lenRemaining := len(buf) - ptr

		// Resolve msgLen per op25 decode_mac_msg special cases + table.
		var msgLen int
		switch op {
		case 0x00: // Null Information: consumes rest of PDU
			msgLen = lenRemaining
		case 0x08: // Null/Avoid Zero Bias: length at next byte & 0x3f
			if ptr+1 < len(buf) {
				msgLen = int(buf[ptr+1] & 0x3f)
			} else {
				break walkerLoop // truncated
			}
		case 0x11: // Indirect Group Paging: ((buf[ptr+1]&0x3)+1)*2 + 2
			if ptr+1 < len(buf) {
				msgLen = (int(buf[ptr+1]&0x3)+1)*2 + 2
			} else {
				break walkerLoop
			}
		case 0x12: // Individual Paging: ((buf[ptr+1]&0x3)+1)*3 + 2
			if ptr+1 < len(buf) {
				msgLen = (int(buf[ptr+1]&0x3)+1)*3 + 2
			} else {
				break walkerLoop
			}
		default:
			// Vendor sub-messages (b1b2==2) carry mfid@+1, length@+2&0x3f.
			if b1b2 == 0x2 {
				if ptr+2 < len(buf) {
					msgLen = int(buf[ptr+2] & 0x3f)
				} else {
					break walkerLoop
				}
			}
			// Table fallback: the vendor length field is not always populated
			// (op25 decode_mac_msg p25p2_tdma.cc:355-361 does the same
			// `if (msg_len == 0) msg_len = mac_msg_len[op]` after the vendor
			// read). Without this, a zero-length vendor sub-message hits the
			// msgLen==0 guard below and aborts the whole walk, silently dropping
			// every later sub-message in the PDU (e.g. a trailing 0x01 Group
			// Voice Channel User identity or 0x91/0x95/0xA8 alias fragment).
			if msgLen == 0 {
				msgLen = int(macMsgLenTable[op])
			}
		}

		// Guard: if msgLen would run past buf or is zero, stop.
		if msgLen == 0 || ptr+msgLen > len(buf) {
			break
		}

		// Dispatch per sub-opcode.
		switch op {
		case 0x01: // Group Voice Channel User (abbreviated): extract identity.
			// tk_p25.py:1113-1119 reads opts=msg[1], ga=msg[2:4], sa=msg[4:7]
			// where msg starts at the sub-opcode byte buf[ptr]. So opts=buf[ptr+1],
			// ga=buf[ptr+2:ptr+4], sa=buf[ptr+4:ptr+7].
			if ptr+7 <= len(buf) {
				p.ServiceOpts = buf[ptr+1]
				p.Talkgroup = uint16(buf[ptr+2])<<8 | uint16(buf[ptr+3])
				p.SourceID = uint32(buf[ptr+4])<<16 | uint32(buf[ptr+5])<<8 | uint32(buf[ptr+6])
				p.HasIdentity = true
			}
		case 0xAA: // Harris Talker GPS (vendor sub-message, b1b2==2 implied).
			// Field starts +24 bits (3 bytes: op, mfid, len) past the sub-opcode
			// and spans 112 bits (14 bytes). Reference: L3HarrisTalkerGpsLocation
			// (DATA_OFFSET=24) + L3HarrisGPS field layout.
			if b1b2 == 0x2 && buf[ptr+1] == 0xA4 && ptr+3+14 <= len(buf) {
				field := bytesToBits(buf[ptr+3 : ptr+3+14])
				if pos, ok := p25.DecodeHarrisGPS(field); ok {
					p.GPS = pos
					p.GPSOK = true
				}
			}
		case 0x91, 0x95, 0xA8: // Vendor alias sub-messages (b1b2==2 implied).
			// Stash {op, mfid, body} for E2. Body is the full sub-message slice
			// buf[ptr:ptr+msgLen], including op+mfid+len+payload.
			if b1b2 == 0x2 && ptr+1 < len(buf) {
				mfid := buf[ptr+1]
				body := make([]byte, msgLen)
				copy(body, buf[ptr:ptr+msgLen])
				p.vendorAliasMsgs = append(p.vendorAliasMsgs, vendorSubMsg{
					op:   op,
					mfid: mfid,
					body: body,
				})
			}
		}

		ptr += msgLen
	}
}

// crc12Poly is the P25 Phase 2 CRC-12 generator as a degree-12 bit vector,
// poly[i] = coefficient of x^(12-i). Source: op25 p25p2_tdma.cc:45
//
//	{1,1,0,0,0,1,0,0,1,0,1,1,1} == x^12+x^11+x^7+x^4+x^2+x+1.
var crc12Poly = [13]uint8{1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1}

// crc12 computes the P25 Phase 2 CRC-12 over len(bits) data bits (1 bit per
// byte, MSB-first), returning the 12-bit CRC. Final XOR 0xfff.
// Direct port of op25 p25p2_tdma.cc:42-63.
func crc12(bits []uint8) uint16 {
	const k = 12
	buf := make([]uint8, len(bits)+k)
	copy(buf, bits)
	for i := 0; i < len(bits); i++ {
		if buf[i] != 0 {
			for j := 0; j < k+1; j++ {
				buf[i+j] ^= crc12Poly[j]
			}
		}
	}
	var crc uint16
	for i := 0; i < k; i++ {
		crc = (crc << 1) + uint16(buf[len(bits)+i])
	}
	return crc ^ 0xfff
}

// crc12OK reports whether a bit slice of the form (data || 12-bit CRC) carries
// a valid trailing CRC-12. Mirrors op25 crc12_ok (p25p2_tdma.cc:65-71).
func crc12OK(bits []uint8) bool {
	if len(bits) < 12 {
		return false
	}
	dataLen := len(bits) - 12
	var stored uint16
	for i := 0; i < 12; i++ {
		stored = (stored << 1) + uint16(bits[dataLen+i])
	}
	return stored == crc12(bits[:dataLen])
}

// crc16CCITT computes the P25 Phase 2 LCCH CRC-16 over len(bits) bits (1 bit
// per byte, MSB-first). poly = x^12 + x^5 + 1 (0x1021), final XOR 0xffff.
// Direct port of op25 crc16.h:80 crc16().
func crc16CCITT(bits []uint8) uint16 {
	const poly = (1 << 12) | (1 << 5) | (1 << 0)
	var crc uint32
	for _, b := range bits {
		crc = ((crc << 1) | uint32(b&1)) & 0x1ffff
		if crc&0x10000 != 0 {
			crc = (crc & 0xffff) ^ poly
		}
	}
	crc ^= 0xffff
	return uint16(crc & 0xffff)
}

// crc16CCITTOK reports whether a (data || 16-bit CRC) bit slice carries a valid
// trailing CRC-16/CCITT. op25 validates LCCH with crc16(bits, len) == 0 over the
// full body including the CRC (remainder-zero formulation).
func crc16CCITTOK(bits []uint8) bool {
	if len(bits) < 16 {
		return false
	}
	return crc16CCITT(bits) == 0
}
