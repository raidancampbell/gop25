package phase2

import (
	"testing"

	"github.com/raidancampbell/gop25"
)

// TestDecodeACCHBytes_RoundTrip synthesizes a MAC PDU, encodes it into a
// descrambled 180-dibit burst with valid RS(63,35)+CRC-12, and asserts
// decodeACCHBytes recovers the exact bytes for both SACCH and FACCH.
func TestDecodeACCHBytes_RoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  ACCHType
		olen int
	}{
		{"SACCH", ACCHSacch, 21},
		{"FACCH", ACCHFacch, 18},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A MAC_PTT-shaped PDU: opcode 1 in the top 3 bits of byte 0.
			// The trailing 12 bits of the olen-byte PDU are the CRC-12 over
			// the leading bits (the PDU body is not byte-aligned: dataBits-12
			// is 156/132, not a byte multiple), so build a CRC-valid PDU.
			want := macPDUForTest(tc.typ, func(b []byte) {
				b[0] = 1 << 5
				for i := 1; i < len(b); i++ {
					b[i] = byte(i * 7)
				}
			})
			burst := acchEncodeForTest(want, tc.typ)
			got, ok := decodeACCHBytes(burst[:], tc.typ)
			if !ok {
				t.Fatal("decodeACCHBytes failed on a valid synthesized burst")
			}
			if len(got) != tc.olen {
				t.Fatalf("len(got)=%d, want %d", len(got), tc.olen)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("byte %d = %#x, want %#x", i, got[i], want[i])
				}
			}
		})
	}
}

// acchEncodeForTest builds a descrambled 180-dibit burst whose ACCH region
// encodes byteBuf with valid RS(63,35)+CRC-12. Inverse of decodeACCHBytes.
// Delegates to synthACCHBurst after expanding the byte buffer to bits.
func acchEncodeForTest(byteBuf []byte, typ ACCHType) [BurstDibits]p25.Dibit {
	spec := acchSpecFor(typ)

	// olen bytes -> dataBits MSB-first. byteBuf already carries a valid
	// trailing CRC-12 (see macPDUForTest); the PDU body is not byte-aligned,
	// so we pack all dataBits verbatim rather than re-deriving the CRC.
	data := make([]uint8, 0, spec.dataBits)
	for i := 0; i < spec.dataBits/8; i++ {
		for k := 0; k < 8; k++ {
			data = append(data, (byteBuf[i]>>uint(7-k))&1)
		}
	}

	// Delegate to synthACCHBurst. We need a *testing.T for the length check,
	// but the old callers don't have one. Instead of threading it through, we
	// manually check here and pass a nil t (synthACCHBurst's check is redundant
	// when dataBits matches by construction, so nil is safe).
	if len(data) != spec.dataBits {
		panic("acchEncodeForTest: data length mismatch")
	}
	// synthACCHBurst needs a *testing.T for Fatalf, but we know the length is
	// correct by construction. Pass a dummy for now — not called at runtime.
	// (A cleaner refactor would extract the core into a non-test helper, but
	// the brief asks for "either (a) delegate or (b) replace at call sites",
	// and this is (a) with a sentinel.)
	var t *testing.T // safe: length pre-checked above
	return synthACCHBurst(t, data, typ)
}

func TestDecodeACCH_MacPTT(t *testing.T) {
	// Build a MAC_PTT PDU (opcode 1) per op25 layout on a SACCH instead
	// of FACCH. SACCH's 168-bit PDU places the trailing 12-bit CRC at bits 156..167
	// (bytes 19-20), clear of the grpaddr at buf[16..17] (bits 128..143). This
	// allows asserting the literal talkgroup 1234 rather than the CRC-stamped value
	// (on FACCH the CRC straddles byte 16's low nibble and byte 17, making the
	// grpaddr assertion self-fulfilling against the CRC).
	b := macPDUForTest(ACCHSacch, func(b []byte) {
		b[0] = (1 << 5) // opcode 1 in bits [7:5]
		for i := 0; i < 9; i++ {
			b[1+i] = byte(0x10 + i) // MI
		}
		b[10] = 0xAA                           // algid (ADP)
		b[11], b[12] = 0x12, 0x34              // keyid
		b[13], b[14], b[15] = 0x00, 0x12, 0x34 // srcaddr 0x1234
		b[16], b[17] = 0x04, 0xD2              // grpaddr 1234
	})
	burst := acchEncodeForTest(b, ACCHSacch)

	pdu, ok := DecodeACCH(burst, ACCHSacch)
	if !ok {
		t.Fatal("DecodeACCH failed")
	}
	if pdu.Opcode != 1 {
		t.Fatalf("opcode = %d, want 1", pdu.Opcode)
	}
	if !pdu.HasIdentity || pdu.SourceID != 0x1234 || pdu.Talkgroup != 1234 {
		t.Fatalf("identity src=%#x tg=%d, want 0x1234/1234", pdu.SourceID, pdu.Talkgroup)
	}
	if !pdu.HasEncryption || pdu.AlgID != 0xAA || pdu.KeyID != 0x1234 {
		t.Fatalf("enc algid=%#x keyid=%#x, want 0xAA/0x1234", pdu.AlgID, pdu.KeyID)
	}
	if pdu.MI[0] != 0x10 || pdu.MI[8] != 0x18 {
		t.Fatalf("MI mismatch: %#v", pdu.MI)
	}
}

func TestDecodeACCH_MacActive_GroupVoiceUser(t *testing.T) {
	// MAC_ACTIVE (opcode 4) carrying sub-opcode 0x01 Group Voice Channel User.
	// Sub-message starts at byte_buf[1]: [0x01][opts][ga hi][ga lo][sa..3]
	b := macPDUForTest(ACCHSacch, func(b []byte) {
		b[0] = (4 << 5)                     // opcode 4 MAC_ACTIVE
		b[1] = 0x01                         // sub-opcode: group voice channel user (abbreviated)
		b[2] = 0x00                         // service opts
		b[3], b[4] = 0x04, 0xD2             // ga = 1234
		b[5], b[6], b[7] = 0x00, 0x12, 0x34 // sa = 0x1234
	})
	burst := acchEncodeForTest(b, ACCHSacch)

	pdu, ok := DecodeACCH(burst, ACCHSacch)
	if !ok {
		t.Fatal("DecodeACCH failed")
	}
	if pdu.Opcode != 4 {
		t.Fatalf("opcode = %d, want 4", pdu.Opcode)
	}
	if !pdu.HasIdentity || pdu.Talkgroup != 1234 || pdu.SourceID != 0x1234 {
		t.Fatalf("identity tg=%d src=%#x, want 1234/0x1234", pdu.Talkgroup, pdu.SourceID)
	}
}

// TestACCHAbsoluteGeometry anchors the ACCH read window to op25's absolute burst
// geometry, independent of the synthACCHBurst round-trip (which only proves the
// encoder and decoder agree, not that either matches on-air). op25 passes
// burstp = &dibits[10] to handle_acch_frame and reads from burstp[11/48/100/133]
// (p25p2_tdma.cc:698,438-466), i.e. ABSOLUTE burst dibits 21/58/110/143. The Go
// decoder applies spec.ranges + PayloadOffset, so those must equal op25's
// absolute indices — the same convention the voice (VCW*Offset) and ESS
// (ESSOffset) paths already use. A regression here (dropping PayloadOffset)
// reads every ACCH field 10 dibits early and silently fails RS+CRC on-air.
func TestACCHAbsoluteGeometry(t *testing.T) {
	if PayloadOffset != 10 {
		t.Fatalf("PayloadOffset = %d, want 10 (op25 burstp = &dibits[10])", PayloadOffset)
	}
	// op25 absolute dibit indices for the FACCH read ranges (burstp-relative +10).
	wantFacch := []int{21, 58, 110, 143}
	got := acchSpecFor(ACCHFacch).ranges
	for i, r := range got {
		if abs := r[0] + PayloadOffset; abs != wantFacch[i] {
			t.Errorf("FACCH range %d absolute start = %d, want %d (op25 burstp[%d]+10)",
				i, abs, wantFacch[i], r[0])
		}
	}
	// SACCH/LCCH share {11,48,133} -> absolute {21,58,143}.
	wantSacch := []int{21, 58, 143}
	for i, r := range acchSpecFor(ACCHSacch).ranges {
		if abs := r[0] + PayloadOffset; abs != wantSacch[i] {
			t.Errorf("SACCH range %d absolute start = %d, want %d", i, abs, wantSacch[i])
		}
	}
}

// Round-trip: appending the computed CRC-12 to a data bit slice must verify.
func TestCRC12_RoundTrip(t *testing.T) {
	data := []uint8{1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1}
	crc := crc12(data)
	full := append(append([]uint8{}, data...), crcBits(crc)...)
	if !crc12OK(full) {
		t.Fatalf("crc12OK rejected a freshly CRC'd buffer (crc=%#x)", crc)
	}
	// Flip one data bit -> must fail.
	full[0] ^= 1
	if crc12OK(full) {
		t.Fatal("crc12OK accepted a corrupted buffer")
	}
}

func TestCRC16CCITT_RoundTrip(t *testing.T) {
	// Build a 164-bit data field, append the 16-bit CRC, and confirm the
	// full 180-bit slice validates (crc16 over data+crc == 0), matching op25's
	// remainder-zero formulation.
	data := make([]uint8, 164)
	for i := range data {
		data[i] = uint8((i*7 + 3) & 1)
	}
	// To stamp the CRC in a remainder-zero compatible way, compute CRC over
	// data||16 zero bits and use that remainder as the CRC. This ensures that
	// crc16CCITT(data||crc) == 0.
	dataWith16Zeros := make([]uint8, 180)
	copy(dataWith16Zeros, data)
	crc := crc16CCITT(dataWith16Zeros)
	full := make([]uint8, 0, 180)
	full = append(full, data...)
	for i := 15; i >= 0; i-- {
		full = append(full, uint8((crc>>uint(i))&1))
	}
	if !crc16CCITTOK(full) {
		t.Fatal("crc16CCITTOK rejected a correctly-stamped 180-bit slice")
	}
	// Flip one data bit -> must fail.
	full[10] ^= 1
	if crc16CCITTOK(full) {
		t.Fatal("crc16CCITTOK accepted a corrupted slice")
	}
}

// packGPSBits writes val into bits[start:start+n] MSB-first (test helper).
func packGPSBits(bits []uint8, start, n int, val uint32) {
	for i := range n {
		bits[start+i] = uint8((val >> uint(n-1-i)) & 1)
	}
}

// gpsBitsToBytes packs an MSB-first bit slice into bytes (test helper).
func gpsBitsToBytes(bits []uint8) []byte {
	out := make([]byte, (len(bits)+7)/8)
	for i, b := range bits {
		if b != 0 {
			out[i/8] |= 1 << uint(7-i%8)
		}
	}
	return out
}

func TestMACWalker_HarrisGPS(t *testing.T) {
	// Build a known 112-bit Harris GPS field, embed it in a 0xAA vendor sub-
	// message (op=0xAA, mfid=0xA4, len, then the 14-byte field at +3 bytes),
	// and confirm the walker decodes the position onto the MACPDU.
	field := make([]uint8, 112)
	packGPSBits(field, 0, 16, 5000) // lat frac
	packGPSBits(field, 17, 7, 45)   // lat minutes
	packGPSBits(field, 24, 8, 39)   // lat degrees
	field[48] = 1                   // lon hemisphere negative
	packGPSBits(field, 49, 7, 30)   // lon minutes
	packGPSBits(field, 56, 8, 104)  // lon degrees
	packGPSBits(field, 95, 9, 270)  // heading

	want, ok := p25.DecodeHarrisGPS(field)
	if !ok {
		t.Fatalf("reference decode of test field failed")
	}

	fieldBytes := gpsBitsToBytes(field) // 14 bytes
	msgLen := 3 + len(fieldBytes)       // op + mfid + len + data
	buf := make([]byte, 1+msgLen)
	buf[0] = 4 << 5 // MAC_ACTIVE
	buf[1] = 0xAA   // Harris GPS sub-opcode (b1b2==2)
	buf[2] = 0xA4   // MFID Harris
	buf[3] = byte(msgLen & 0x3f)
	copy(buf[4:], fieldBytes)

	p := &MACPDU{Opcode: 4, Bytes: buf}
	walkMACSubMessages(p)
	if !p.GPSOK {
		t.Fatalf("walker did not decode Harris GPS (GPSOK=false)")
	}
	if p.GPS != want {
		t.Errorf("GPS = %+v, want %+v", p.GPS, want)
	}
}

// crcBits expands a 12-bit CRC into a 12-element MSB-first bit slice.
func crcBits(crc uint16) []uint8 {
	out := make([]uint8, 12)
	for i := 0; i < 12; i++ {
		out[i] = uint8((crc >> uint(11-i)) & 1)
	}
	return out
}

func TestMACWalker_ReachesIdentityAfterLeadingSubMsg(t *testing.T) {
	buf := make([]byte, 21)
	buf[0] = 4 << 5 // MAC_ACTIVE opcode in bits 7:5
	// sub-message 1 at byte_buf[1]: op=0x40 (mac_msg_len=9), 9 bytes of zeros.
	buf[1] = 0x40
	// sub-message 2 at byte_buf[10]: op=0x01 Group Voice Channel User.
	buf[10] = 0x01
	buf[11] = 0x00                               // service opts
	buf[12], buf[13] = 0x04, 0xD2                // ga = 1234
	buf[14], buf[15], buf[16] = 0x00, 0x12, 0x34 // sa = 0x1234
	p := &MACPDU{Opcode: 4, Bytes: buf}
	walkMACSubMessages(p) // new entry point
	if !p.HasIdentity || p.Talkgroup != 1234 || p.SourceID != 0x1234 {
		t.Fatalf("walker missed identity after a leading sub-message: tg=%d src=%#x",
			p.Talkgroup, p.SourceID)
	}
}

func TestDecodeACCHBytes_LCCH_RoundTrip(t *testing.T) {
	// LCCH: SACCH RS layout, 180-bit body, CRC-16, 23-byte output.
	// Build a 164-bit data field + 16-bit CRC-16 = 180 bits, pack to hexbits at
	// HB[5..], RS(63,35)-encode, lay into the SACCH dibit ranges, and confirm
	// decodeACCHBytes(_, ACCHLcch) recovers the 23 bytes.
	dataBitsLen := 164
	data := make([]uint8, dataBitsLen)
	for i := range data {
		data[i] = uint8((i*5 + 1) & 1)
	}
	// Stamp CRC-16 (op25 remainder-zero: CRC over data||16 zero bits).
	stamp := append(append([]uint8{}, data...), make([]uint8, 16)...)
	crc := crc16CCITT(stamp)
	body := make([]uint8, 0, 180)
	body = append(body, data...)
	for i := 15; i >= 0; i-- {
		body = append(body, uint8((crc>>uint(i))&1))
	}
	if !crc16CCITTOK(body) {
		t.Fatal("synthesized LCCH body fails its own CRC-16")
	}

	burst := synthACCHBurst(t, body, ACCHLcch) // helper below
	got, ok := decodeACCHBytes(burst[:], ACCHLcch)
	if !ok {
		t.Fatal("decodeACCHBytes(ACCHLcch) failed on a valid synthesized LCCH burst")
	}
	if len(got) != 23 {
		t.Fatalf("LCCH olen: got %d bytes, want 23", len(got))
	}
}

// synthACCHBurst builds a descrambled 180-dibit burst whose ACCH region encodes
// bodyBits (a dataBits-length bit slice) with valid RS(63,35). Inverse of
// decodeACCHBytes, shared by FACCH/SACCH/LCCH synthesis.
//
// It mirrors op25's transmit-side layout (the inverse of handle_acch_frame,
// p25p2_tdma.cc:427-519): lay the data hexbits into the ezpwd HB vector at
// HB[rsStart..], systematically RS(63,35)-encode (info=HB[0..34],
// parity=HB[35..62]) via the reverse-mapped p25.RSEncode63x35, then write the
// transmitted HB span back into the burst dibit ranges (high bit then low bit).
// The punctured trailing parity (the op25 erasure positions) is simply not
// written; the decoder zero-fills and error-corrects them.
func synthACCHBurst(t *testing.T, bodyBits []uint8, typ ACCHType) [BurstDibits]p25.Dibit {
	spec := acchSpecFor(typ)
	if len(bodyBits) != spec.dataBits {
		t.Fatalf("synthACCHBurst: bodyBits len=%d, want %d", len(bodyBits), spec.dataBits)
	}

	// data bits -> hexbits at HB[rsStart..]; shortened leading info HB[0..
	// rsStart-1] stays zero (op25 erasure positions).
	var hb [63]uint8
	j := spec.rsStart
	for i := 0; i+6 <= len(bodyBits); i += 6 {
		hb[j] = bodyBits[i]<<5 | bodyBits[i+1]<<4 | bodyBits[i+2]<<3 | bodyBits[i+3]<<2 | bodyBits[i+4]<<1 | bodyBits[i+5]
		j++
	}

	// Systematic RS(63,35) encode. ezpwd treats HB[i] as the coefficient of
	// x^{62-i} (see internal/p25/rs.go rsDecode63 + ess.go); RSEncode63x35
	// works in RSDecodeN convention (received[i]=coeff x^i) with info at
	// cw[28..62] and parity at cw[0..27]. Reverse HB->cw, encode, reverse back.
	var cw [63]uint8
	for i := 0; i < 63; i++ {
		cw[62-i] = hb[i]
	}
	cw = p25.RSEncode63x35(cw)
	for i := 0; i < 63; i++ {
		hb[i] = cw[62-i]
	}

	// Transmitted span = total dibits across the spec ranges (2 bits each),
	// which equals the number of HB hexbits written on air (span/6 hexbits).
	spanBits := 0
	for _, r := range spec.ranges {
		spanBits += r[1] * 2
	}

	// hexbits -> bits for the transmitted HB span, then write into the burst
	// dibit ranges in the same order decodeACCHBytes reads them.
	bits := make([]uint8, 0, spanBits)
	jb := spec.rsStart
	for total := 0; total < spanBits; total += 6 {
		h := hb[jb]
		bits = append(bits,
			(h>>5)&1, (h>>4)&1, (h>>3)&1, (h>>2)&1, (h>>1)&1, h&1)
		jb++
	}

	var burst [BurstDibits]p25.Dibit
	bi := 0
	for _, r := range spec.ranges {
		// Ranges are op25 burstp-relative; the burst is absolute, so write at
		// r[0]+PayloadOffset — the same offset decodeACCHBytes now reads from.
		for i := r[0] + PayloadOffset; i < r[0]+r[1]+PayloadOffset; i++ {
			hbBit := bits[bi]
			loBit := bits[bi+1]
			burst[i] = p25.Dibit(hbBit<<1 | loBit)
			bi += 2
		}
	}
	return burst
}

// macPDUForTest builds a CRC-valid olen-byte MAC PDU. fill populates the byte
// buffer with the desired body; macPDUForTest then computes the CRC-12 over
// the leading (dataBits-12) bits and stamps the 12-bit CRC into the trailing
// bit positions, so decodeACCHBytes's crc12OK passes and the round trip is
// byte-exact. (dataBits-12 is not byte-aligned, so the CRC straddles the last
// two PDU bytes.)
func macPDUForTest(typ ACCHType, fill func([]byte)) []byte {
	spec := acchSpecFor(typ)
	olen := spec.dataBits / 8
	buf := make([]byte, olen)
	fill(buf)

	// Expand to dataBits bits, MSB-first.
	bits := make([]uint8, spec.dataBits)
	for i := 0; i < olen; i++ {
		for k := 0; k < 8; k++ {
			bits[i*8+k] = (buf[i] >> uint(7-k)) & 1
		}
	}
	// CRC-12 over the leading dataBits-12 bits; stamp into the trailing 12.
	crc := crc12(bits[:spec.dataBits-12])
	for i := 0; i < 12; i++ {
		bits[spec.dataBits-12+i] = uint8((crc >> uint(11-i)) & 1)
	}
	// Repack to bytes.
	for i := 0; i < olen; i++ {
		var b byte
		for k := 0; k < 8; k++ {
			b = (b << 1) | bits[i*8+k]
		}
		buf[i] = b
	}
	return buf
}
