package p25

import (
	"bytes"
	"math"
	"strings"
	"testing"
	"time"
)

// Build a minimal LRRP TRIGGERED_LOCATION (0x0D) carrying a single
// VERSION token (id 0x36, fixed length 1) with value 1, and a single
// HEADING token (id 0x56, fixed length 1) with value 0x2D (raw byte).
//
// Header byte 0 = 0x0D (type), byte 1 = 0x04 (4 bytes of payload).
// Payload = 0x36 0x01 0x56 0x2D.
func lrrpTriggeredVersionHeading() []byte {
	return []byte{0x0D, 0x04, 0x36, 0x01, 0x56, 0x2D}
}

func TestParseLRRP_HeaderAndTokenWalk(t *testing.T) {
	pkt := lrrpTriggeredVersionHeading()
	lrrp := parseLRRP(pkt)
	if lrrp == nil {
		t.Fatal("parseLRRP returned nil for a valid 6-byte packet")
	}
	if lrrp.PacketType != 0x0D {
		t.Errorf("PacketType = 0x%02x, want 0x0D", lrrp.PacketType)
	}
	if lrrp.PayloadLength != 4 {
		t.Errorf("PayloadLength = %d, want 4", lrrp.PayloadLength)
	}
	if !bytes.Equal(lrrp.RawPayload, pkt[2:]) {
		t.Errorf("RawPayload = % x, want % x", lrrp.RawPayload, pkt[2:])
	}
	if len(lrrp.Tokens) != 2 {
		t.Fatalf("Tokens length = %d, want 2", len(lrrp.Tokens))
	}
	if lrrp.Tokens[0].ID != 0x36 || lrrp.Tokens[1].ID != 0x56 {
		t.Errorf("token ids = 0x%02x/0x%02x, want 0x36/0x56",
			lrrp.Tokens[0].ID, lrrp.Tokens[1].ID)
	}
	if !bytes.Equal(lrrp.Tokens[0].Raw, []byte{0x01}) {
		t.Errorf("VERSION token raw = % x, want 01", lrrp.Tokens[0].Raw)
	}
	if !bytes.Equal(lrrp.Tokens[1].Raw, []byte{0x2D}) {
		t.Errorf("HEADING token raw = % x, want 2D", lrrp.Tokens[1].Raw)
	}
}

// Motorola packs several short LRRP PDUs back-to-back in one UDP/4001
// datagram. parseLRRP must walk every [type][len][payload] sub-message and
// aggregate their tokens, not stop after the first. Two PDUs here: the first
// carries a VERSION token, the second a HEADING token; both must surface.
func TestParseLRRP_ConcatenatedPDUs(t *testing.T) {
	// PDU A: type 0x0D, len 2, payload [VERSION=0x36, 0x01]
	// PDU B: type 0x0D, len 2, payload [HEADING=0x56, 0x2D]
	pkt := []byte{0x0D, 0x02, 0x36, 0x01, 0x0D, 0x02, 0x56, 0x2D}
	lrrp := parseLRRP(pkt)
	if lrrp == nil {
		t.Fatal("parseLRRP returned nil for concatenated datagram")
	}
	if lrrp.PacketType != 0x0D || lrrp.PayloadLength != 2 {
		t.Errorf("header = type 0x%02x len %d, want 0x0D/2 (first PDU)",
			lrrp.PacketType, lrrp.PayloadLength)
	}
	if len(lrrp.Tokens) != 2 {
		t.Fatalf("Tokens length = %d, want 2 (one per PDU)", len(lrrp.Tokens))
	}
	if lrrp.Tokens[0].ID != 0x36 || lrrp.Tokens[1].ID != 0x56 {
		t.Errorf("token ids = 0x%02x/0x%02x, want 0x36/0x56",
			lrrp.Tokens[0].ID, lrrp.Tokens[1].ID)
	}
	// The HEADING token lives in the SECOND PDU; the accessor must find it.
	if h, ok := lrrp.Heading(); !ok || h != float64(0x2D)*2.0 {
		t.Errorf("Heading() = (%v, %v), want (%v, true)", h, ok, float64(0x2D)*2.0)
	}
	if len(lrrp.Trailing) != 0 {
		t.Errorf("Trailing = % x, want empty (both PDUs parse clean)", lrrp.Trailing)
	}
}

// Real on-air datagram: the 70-byte UDP/4001 payload captured 2026-06-17 on
// 462.0875 (NAC 0x172) is four concatenated LRRP PDUs (lengths 16/16/15/15).
// Each sub-PDU contributes an IDENTITY (0x22) + TIME (0x52) token before an
// unknown 0x44 token spills the rest to Trailing. The pre-fix parser saw only
// the first PDU (2 tokens); the fix must frame all four (8 tokens).
func TestParseLRRP_RealConcatenatedDatagram(t *testing.T) {
	pkt := []byte{
		0x09, 0x10, 0x22, 0x03, 0xff, 0xff, 0x02, 0x52, 0x44, 0x64, 0x42, 0x9c, 0x10, 0x62, 0x57, 0x34, 0x4a, 0x02,
		0x09, 0x10, 0x22, 0x03, 0xff, 0xff, 0xcc, 0x52, 0x44, 0x64, 0x42, 0x9c, 0x10, 0x62, 0x57, 0x34, 0x78, 0x63,
		0x09, 0x0f, 0x22, 0x02, 0xff, 0x00, 0x52, 0x44, 0x64, 0x42, 0x9c, 0x10, 0x62, 0x57, 0x33, 0x4a, 0x00,
		0x09, 0x0f, 0x22, 0x02, 0xff, 0x01, 0x52, 0x44, 0x64, 0x42, 0x9c, 0x10, 0x62, 0x57, 0x33, 0x4a, 0x01,
	}
	if len(pkt) != 70 {
		t.Fatalf("fixture is %d bytes, want 70", len(pkt))
	}
	lrrp := parseLRRP(pkt)
	if lrrp == nil {
		t.Fatal("parseLRRP returned nil for real concatenated datagram")
	}
	if len(lrrp.Tokens) != 8 {
		t.Fatalf("Tokens length = %d, want 8 (IDENTITY+TIME per 4 PDUs)", len(lrrp.Tokens))
	}
	for i := 0; i < 8; i += 2 {
		if lrrp.Tokens[i].ID != 0x22 || lrrp.Tokens[i+1].ID != 0x52 {
			t.Errorf("PDU %d tokens = 0x%02x/0x%02x, want 0x22/0x52",
				i/2, lrrp.Tokens[i].ID, lrrp.Tokens[i+1].ID)
		}
	}
}

func TestParseLRRP_VariableLengthTokenRawExcludesLengthByte(t *testing.T) {
	pkt := []byte{0x09, 0x05, 0x22, 0x03, 0xaa, 0xbb, 0xcc}
	lrrp := parseLRRP(pkt)
	if lrrp == nil {
		t.Fatal("parseLRRP returned nil")
	}
	if len(lrrp.Tokens) != 1 {
		t.Fatalf("Tokens length = %d, want 1", len(lrrp.Tokens))
	}
	if !bytes.Equal(lrrp.Tokens[0].Raw, []byte{0xaa, 0xbb, 0xcc}) {
		t.Errorf("IDENTITY token raw = % x, want aa bb cc", lrrp.Tokens[0].Raw)
	}
}

// A truncated trailing PDU (header claims more payload than remains) must not
// discard the already-parsed leading PDUs; its unparsed bytes go to Trailing.
func TestParseLRRP_ConcatenatedTruncatedTail(t *testing.T) {
	// PDU A parses clean (VERSION); PDU B header claims 16 payload bytes but
	// only 1 remains.
	pkt := []byte{0x0D, 0x02, 0x36, 0x01, 0x0D, 0x10, 0x56}
	lrrp := parseLRRP(pkt)
	if lrrp == nil {
		t.Fatal("parseLRRP returned nil")
	}
	if len(lrrp.Tokens) != 1 || lrrp.Tokens[0].ID != 0x36 {
		t.Fatalf("Tokens = %+v, want one VERSION token from PDU A", lrrp.Tokens)
	}
	if !bytes.Equal(lrrp.Trailing, []byte{0x0D, 0x10, 0x56}) {
		t.Errorf("Trailing = % x, want the truncated PDU-B bytes 0d 10 56", lrrp.Trailing)
	}
}

// PayloadLength longer than the buffer must return nil rather than read OOB.
func TestParseLRRP_RejectsTruncatedHeader(t *testing.T) {
	if parseLRRP(nil) != nil {
		t.Errorf("nil should return nil")
	}
	if parseLRRP([]byte{0x0D}) != nil {
		t.Errorf("1-byte should return nil (no payload-length byte)")
	}
	if parseLRRP([]byte{0x0D, 0x10, 0x36, 0x01}) != nil {
		t.Errorf("PayloadLength > buffer should return nil")
	}
}

// Unknown token id stops the walker; remaining bytes go to Trailing.
func TestParseLRRP_UnknownTokenStops(t *testing.T) {
	// 0xFF is not a defined token type. Walker should record one token before
	// it (VERSION), then put 0xFF and onward into Trailing.
	pkt := []byte{0x0D, 0x05, 0x36, 0x01, 0xFF, 0x99, 0x99}
	lrrp := parseLRRP(pkt)
	if lrrp == nil {
		t.Fatal("parseLRRP returned nil for parseable header")
	}
	if len(lrrp.Tokens) != 1 || lrrp.Tokens[0].ID != 0x36 {
		t.Fatalf("Tokens = %+v, want one VERSION token", lrrp.Tokens)
	}
	if !bytes.Equal(lrrp.Trailing, []byte{0xFF, 0x99, 0x99}) {
		t.Errorf("Trailing = % x, want ff 99 99", lrrp.Trailing)
	}
}

// Build a POINT_2D token payload for lat=37.5, lon=-80.0 (positive lat,
// negative lon - typical North American coverage).
func point2dPayload(lat, lon float64) []byte {
	const latMul = 180.0 / 4294967295.0
	const lonMul = 360.0 / 4294967295.0
	hemisphere := uint32(0)
	if lat < 0 {
		hemisphere = 1
		lat = -lat
	}
	latRaw := uint32(math.Round(lat / latMul))
	if latRaw > 0x7FFFFFFF {
		latRaw = 0x7FFFFFFF
	}
	// Pack: bit 0 = hemisphere, bits 1..31 = latitude, bits 32..63 = longitude
	// (two's complement signed). MSB-first.
	combined := (uint64(hemisphere&1) << 63) | (uint64(latRaw&0x7FFFFFFF) << 32)
	lonRaw := int64(math.Round(lon / lonMul))
	combined |= uint64(uint32(lonRaw))
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = byte(combined >> uint(56-8*i))
	}
	return out
}

func TestLRRPData_Point2D(t *testing.T) {
	body := point2dPayload(37.5, -80.0)
	pkt := append([]byte{0x0D, byte(1 + len(body)), 0x66}, body...)
	lrrp := parseLRRP(pkt)
	if lrrp == nil {
		t.Fatal("parseLRRP returned nil")
	}
	lat, lon, alt, ok := lrrp.Position()
	if !ok {
		t.Fatal("Position() returned ok=false for a POINT_2D token")
	}
	if alt != 0 {
		t.Errorf("alt = %f, want 0 for POINT_2D", alt)
	}
	if math.Abs(lat-37.5) > 0.0001 {
		t.Errorf("lat = %f, want ~37.5", lat)
	}
	if math.Abs(lon-(-80.0)) > 0.0001 {
		t.Errorf("lon = %f, want ~-80.0", lon)
	}
}

func TestLRRPData_Speed(t *testing.T) {
	// SPEED token: id 0x6C, 16-bit raw value 1234 (= 12.34).
	pkt := []byte{0x0D, 0x03, 0x6C, 0x04, 0xD2}
	lrrp := parseLRRP(pkt)
	if lrrp == nil {
		t.Fatal("parseLRRP returned nil")
	}
	sp, ok := lrrp.Speed()
	if !ok {
		t.Fatal("Speed() returned ok=false")
	}
	if math.Abs(sp-12.34) > 0.001 {
		t.Errorf("Speed = %f, want 12.34", sp)
	}
}

func TestLRRPData_Heading(t *testing.T) {
	// HEADING token: id 0x56, raw value 90 -> 180.0 degrees.
	pkt := []byte{0x0D, 0x02, 0x56, 0x5A}
	lrrp := parseLRRP(pkt)
	if lrrp == nil {
		t.Fatal("parseLRRP returned nil")
	}
	h, ok := lrrp.Heading()
	if !ok {
		t.Fatal("Heading() returned ok=false")
	}
	if math.Abs(h-180.0) > 0.0001 {
		t.Errorf("Heading = %f, want 180.0", h)
	}
}

// CIRCLE_2D (0x51) is a POINT_2D plus a 16-bit radius. Position() must surface
// the embedded fix (pre-fix it returned ok=false for a circle-only packet), and
// Circle() must return the radius.
func TestLRRPData_Circle2D(t *testing.T) {
	point := point2dPayload(37.5, -80.0) // 8 bytes
	// radius 15.00 m -> raw 1500 = 0x05DC (×0.01).
	body := append(point, 0x05, 0xDC) // 10-byte fixed CIRCLE_2D payload
	pkt := append([]byte{0x0D, byte(1 + len(body)), 0x51}, body...)
	lrrp := parseLRRP(pkt)
	if lrrp == nil {
		t.Fatal("parseLRRP returned nil")
	}
	lat, lon, alt, ok := lrrp.Position()
	if !ok {
		t.Fatal("Position() ok=false for a CIRCLE_2D token")
	}
	if alt != 0 {
		t.Errorf("alt = %f, want 0 for CIRCLE_2D", alt)
	}
	if math.Abs(lat-37.5) > 0.0001 || math.Abs(lon-(-80.0)) > 0.0001 {
		t.Errorf("lat/lon = %f/%f, want ~37.5/-80.0", lat, lon)
	}
	r, ok := lrrp.Circle()
	if !ok || math.Abs(r-15.0) > 0.001 {
		t.Errorf("Circle() = (%f, %v), want (15.0, true)", r, ok)
	}
	if _, val := (LRRPToken{ID: 0x51, Raw: body}).Describe(); !strings.Contains(val, "r 15.0m") {
		t.Errorf("Describe val = %q, want a radius", val)
	}
}

// CIRCLE_3D (0x55) adds a 16-bit altitude (Raw[10:12]) after the radius.
func TestLRRPData_Circle3D(t *testing.T) {
	point := point2dPayload(37.5, -80.0) // 8 bytes
	// radius 15.00 m (0x05DC), altitude 100.00 m -> raw 10000 = 0x2710,
	// alt-accuracy 0x0000, then one pad byte (fixed length 15).
	body := append(point, 0x05, 0xDC, 0x27, 0x10, 0x00, 0x00, 0x00) // 15 bytes
	pkt := append([]byte{0x0D, byte(1 + len(body)), 0x55}, body...)
	lrrp := parseLRRP(pkt)
	if lrrp == nil {
		t.Fatal("parseLRRP returned nil")
	}
	lat, lon, alt, ok := lrrp.Position()
	if !ok {
		t.Fatal("Position() ok=false for a CIRCLE_3D token")
	}
	if math.Abs(lat-37.5) > 0.0001 || math.Abs(lon-(-80.0)) > 0.0001 {
		t.Errorf("lat/lon = %f/%f, want ~37.5/-80.0", lat, lon)
	}
	if math.Abs(alt-100.0) > 0.001 {
		t.Errorf("alt = %f, want 100.0", alt)
	}
	if r, ok := lrrp.Circle(); !ok || math.Abs(r-15.0) > 0.001 {
		t.Errorf("Circle() = (%f, %v), want (15.0, true)", r, ok)
	}
}

// RESPONSE (0x37): Raw[0] bit 7 selects short (7-bit) vs extended (15-bit) code.
func TestLRRPData_Response(t *testing.T) {
	// Short form: code 0x10 (NO GPS), bit 7 clear.
	shortPkt := []byte{0x0D, 0x02, 0x37, 0x10}
	if lrrp := parseLRRP(shortPkt); lrrp == nil {
		t.Fatal("parseLRRP returned nil (short)")
	} else if code, label, ok := lrrp.Response(); !ok || code != 0x10 || label != "NO GPS" {
		t.Errorf("Response() = (%#x, %q, %v), want (0x10, NO GPS, true)", code, label, ok)
	}

	// Extended form: code 0x200 (GPS INITIALIZING). 15-bit split -> Raw={0x82,0x00}.
	extPkt := []byte{0x0D, 0x03, 0x37, 0x82, 0x00}
	if lrrp := parseLRRP(extPkt); lrrp == nil {
		t.Fatal("parseLRRP returned nil (ext)")
	} else if code, label, ok := lrrp.Response(); !ok || code != 0x200 || label != "GPS INITIALIZING" {
		t.Errorf("Response() = (%#x, %q, %v), want (0x200, GPS INITIALIZING, true)", code, label, ok)
	}

	// Describe no longer hex-dumps the RESPONSE payload.
	if _, val := (LRRPToken{ID: 0x37, Raw: []byte{0x10}}).Describe(); val != "NO GPS" {
		t.Errorf("Describe val = %q, want \"NO GPS\"", val)
	}
}

func TestLRRPData_NoToken(t *testing.T) {
	pkt := []byte{0x0D, 0x00}
	lrrp := parseLRRP(pkt)
	if lrrp == nil {
		t.Fatal("parseLRRP returned nil")
	}
	if _, _, _, ok := lrrp.Position(); ok {
		t.Errorf("Position() ok = true for empty packet, want false")
	}
	if _, ok := lrrp.Speed(); ok {
		t.Errorf("Speed() ok = true for empty packet, want false")
	}
	if _, ok := lrrp.Heading(); ok {
		t.Errorf("Heading() ok = true for empty packet, want false")
	}
}

func TestProcessFrame_LRRP_PointEmitted(t *testing.T) {
	// Build the LRRP packet
	body := point2dPayload(37.8, -80.4)
	lrrp := append([]byte{0x0D, byte(1 + len(body)), 0x66}, body...)

	// Wrap LRRP in UDP (dst port 4001).
	udpLen := uint16(8 + len(lrrp))
	udp := []byte{
		0x0F, 0xA1, // src 4001
		0x0F, 0xA1, // dst 4001
		byte(udpLen >> 8), byte(udpLen & 0xff),
		0x00, 0x00, // checksum (not verified)
	}
	udp = append(udp, lrrp...)

	// Wrap UDP in IPv4 (proto=17).
	totalLen := uint16(20 + len(udp))
	ip := []byte{
		0x45,
		0x00,
		byte(totalLen >> 8), byte(totalLen & 0xff),
		0x12, 0x34,
		0x40, 0x00,
		0x40,
		0x11,
		0x00, 0x00, // checksum (not verified)
		10, 0, 0, 1,
		10, 0, 0, 2,
	}
	ip = append(ip, udp...)

	// Build a single-block PDU with this IP datagram in UserPayload.
	// 12-byte block layout: SN-DATA(2) + UserPayload + CRC-32(4) + pad
	// We need len(ip) + 6 (SN-DATA + CRC) <= 12*N. For len(ip)~46+ we need
	// 5 blocks (=60). Synth helper handles CRC.
	const blocksNeeded = 5
	blockBytes := blocksNeeded * 12
	user := make([]byte, blockBytes-6) // SN-DATA(2) + CRC(4) trailer
	copy(user, ip)
	pad := byte(len(user) - len(ip))

	header := [12]byte{
		0x36,             // fmt=0x16 (22), confirmed=0, outbound=1
		0x04,             // SAP=4 (USER DATA / PACKET_DATA)
		0x90,             // MFID
		0x01, 0x79, 0xa6, // LLID
		blocksNeeded, // BlocksToFollow
		pad & 0x1f,   // PadOctets
		0x00,         // sync=0
		0x02,         // DataHeaderOffset=2
		0x00, 0x00,
	}
	data := make([][12]byte, blocksNeeded)
	// SN-DATA header: PDUType=4, NSAPI=5, no compression
	dataBytes := append([]byte{0x45, 0x00}, user...)
	dataBytes = append(dataBytes, 0x00, 0x00, 0x00, 0x00) // CRC slot (overwritten)
	for i := 0; i < blocksNeeded; i++ {
		copy(data[i][:], dataBytes[i*12:(i+1)*12])
	}
	payload := synthPDUPayload(header, data)

	d := NewP25Decoder(25000)
	f := Frame{NID: NID{NAC: 0x171, DUID: 0xC}, Payload: payload}
	_, cfs := d.processFrame(f)

	var got *ControlFrame
	for i := range cfs {
		if cfs[i].LRRP != nil {
			got = &cfs[i]
		}
	}
	if got == nil {
		t.Fatal("no ControlFrame had LRRP populated")
	}
	if got.PDU == nil || got.SNDCP == nil {
		t.Errorf("PDU/SNDCP must still be populated alongside LRRP: pdu=%v sndcp=%v",
			got.PDU != nil, got.SNDCP != nil)
	}
	lat, lon, _, ok := got.LRRP.Position()
	if !ok {
		t.Fatal("LRRP.Position() ok=false")
	}
	if math.Abs(lat-37.8) > 0.001 || math.Abs(lon-(-80.4)) > 0.001 {
		t.Errorf("lat/lon = %f / %f, want 37.8 / -80.4", lat, lon)
	}
}

// MBT (non-packet-data) PDUs must still leave LRRP nil.
func TestProcessFrame_LRRP_MBTHasNilLRRP(t *testing.T) {
	header := [12]byte{
		0x35, 0x3d, 0x90, 0x01, 0x79, 0xa6,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	data := [][12]byte{{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}}
	payload := synthPDUPayload(header, data)
	d := NewP25Decoder(25000)
	f := Frame{NID: NID{NAC: 0x171, DUID: 0xC}, Payload: payload}
	_, cfs := d.processFrame(f)
	for _, cf := range cfs {
		if cf.LRRP != nil {
			t.Errorf("MBT frame got LRRP=%+v, want nil", cf.LRRP)
		}
	}
}

func TestLRRPToken_Describe(t *testing.T) {
	cases := []struct {
		id       uint8
		raw      []byte
		wantName string
		wantVal  string // substring that must appear in val ("" = exact empty)
	}{
		{0x36, []byte{0x04}, "VERSION", "4"},
		{0x6C, []byte{0x01, 0x2C}, "SPEED", "3.00"},   // 300 * 0.01
		{0x56, []byte{0x2D}, "HEADING", "90"},          // 45 * 2.0
		{0x38, nil, "SUCCESS", ""},                     // flag, no value
		{0x22, []byte{'A', 'B', 'C'}, "IDENTITY", "ABC"},
		{0xEE, []byte{0xde, 0xad}, "UNKNOWN_0xEE", "de ad"},
	}
	for _, c := range cases {
		name, val := LRRPToken{ID: c.id, Raw: c.raw}.Describe()
		if name != c.wantName {
			t.Errorf("id 0x%02x: name=%q, want %q", c.id, name, c.wantName)
		}
		if c.wantVal == "" {
			if val != "" {
				t.Errorf("id 0x%02x: val=%q, want empty", c.id, val)
			}
		} else if !strings.Contains(val, c.wantVal) {
			t.Errorf("id 0x%02x: val=%q, want substring %q", c.id, val, c.wantVal)
		}
	}
}

func TestLRRPToken_DescribeTimestamp(t *testing.T) {
	// 5-byte payload: 4 epoch bytes + 1 trailing byte whose encoding is unverified.
	raw := []byte{0x68, 0x46, 0x9C, 0x10, 0xAB}
	name, val := LRRPToken{ID: 0x34, Raw: raw}.Describe()
	if name != "TIMESTAMP" {
		t.Errorf("name = %q, want TIMESTAMP", name)
	}
	wantVal := time.Unix(int64(0x68469C10), 0).UTC().Format("2006-01-02 15:04:05Z") + " +ab"
	if val != wantVal {
		t.Errorf("val = %q, want %q", val, wantVal)
	}
}

func TestLRRPToken_DescribePoint2D(t *testing.T) {
	// 8-byte POINT_2D: hemisphere bit 0, lat ~ small, lon ~ small. Just assert
	// the name and that a degree value is rendered.
	raw := []byte{0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00}
	name, val := LRRPToken{ID: 0x66, Raw: raw}.Describe()
	if name != "POINT_2D" || !strings.Contains(val, "°") {
		t.Errorf("got %q / %q, want POINT_2D with a degree value", name, val)
	}
}

// A SN-DATA packet with header compression set must NOT attempt IPv4 parse.
func TestProcessFrame_LRRP_CompressedIPSkipped(t *testing.T) {
	// Same shape as TestProcessFrame_SNDCP_PacketDataEmitsBoth, but
	// IPHeaderCompression=1 so we expect LRRP nil.
	header := [12]byte{
		0x36, 0x04, 0x90, 0x01, 0x79, 0xa6,
		0x01, 0x00, 0x00, 0x02, 0x00, 0x00,
	}
	user := [6]byte{0xde, 0xad, 0xbe, 0xef, 0x12, 0x34}
	data := [][12]byte{
		{
			0x45, 0x10, // PDUType=4, NSAPI=5, IPComp=1, UDPComp=0
			user[0], user[1], user[2], user[3], user[4], user[5],
			0x00, 0x00, 0x00, 0x00,
		},
	}
	payload := synthPDUPayload(header, data)
	d := NewP25Decoder(25000)
	f := Frame{NID: NID{NAC: 0x171, DUID: 0xC}, Payload: payload}
	_, cfs := d.processFrame(f)
	for _, cf := range cfs {
		if cf.LRRP != nil {
			t.Errorf("Compressed-IP packet got LRRP=%+v, want nil", cf.LRRP)
		}
	}
}
