package p25

import (
	"bytes"
	"testing"
)

// Hand-built minimal IPv4 header: version=4, IHL=5 (20 bytes), no options.
// total_length = 28 (header + 8-byte UDP), protocol=17 (UDP), src=10.0.0.1,
// dst=10.0.0.2. Identification, flags, ttl, checksum filled in arbitrarily;
// our parser does not verify the checksum.
func ipv4MinHeader() []byte {
	return []byte{
		0x45,       // version=4, IHL=5
		0x00,       // DSCP/ECN
		0x00, 0x1C, // total length = 28
		0x12, 0x34, // identification
		0x40, 0x00, // flags=DF, frag-offset=0
		0x40,       // TTL=64
		0x11,       // protocol=17 (UDP)
		0xab, 0xcd, // header checksum (not verified)
		10, 0, 0, 1,
		10, 0, 0, 2,
	}
}

func TestParseIPv4_Minimal(t *testing.T) {
	hdr := ipv4MinHeader()
	// Append a fake 8-byte UDP body so HeaderLen+TotalLen are consistent.
	pkt := append(append([]byte{}, hdr...), []byte{1, 2, 3, 4, 5, 6, 7, 8}...)

	ip := parseIPv4(pkt)
	if ip == nil {
		t.Fatal("parseIPv4 returned nil for a valid header")
	}
	if ip.Version != 4 {
		t.Errorf("Version = %d, want 4", ip.Version)
	}
	if ip.HeaderLen != 20 {
		t.Errorf("HeaderLen = %d, want 20", ip.HeaderLen)
	}
	if ip.TotalLen != 28 {
		t.Errorf("TotalLen = %d, want 28", ip.TotalLen)
	}
	if ip.Protocol != 17 {
		t.Errorf("Protocol = %d, want 17 (UDP)", ip.Protocol)
	}
	if !bytes.Equal(ip.Src[:], []byte{10, 0, 0, 1}) {
		t.Errorf("Src = %v, want 10.0.0.1", ip.Src)
	}
	if !bytes.Equal(ip.Dst[:], []byte{10, 0, 0, 2}) {
		t.Errorf("Dst = %v, want 10.0.0.2", ip.Dst)
	}
	if !bytes.Equal(ip.Payload, []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Errorf("Payload = % x, want 01 02 03 04 05 06 07 08", ip.Payload)
	}
}

// Reject obviously malformed packets:
//   - non-v4
//   - IHL < 5 (header below 20 bytes)
//   - TotalLen < HeaderLen
//   - buffer too small for the declared header / total
func TestParseIPv4_Rejects(t *testing.T) {
	if parseIPv4(nil) != nil {
		t.Errorf("nil input should return nil")
	}
	if parseIPv4([]byte{0x45}) != nil {
		t.Errorf("1-byte input should return nil")
	}

	v6 := append([]byte{}, ipv4MinHeader()...)
	v6[0] = 0x65 // version=6
	if parseIPv4(v6) != nil {
		t.Errorf("non-v4 should return nil")
	}

	shortIHL := append([]byte{}, ipv4MinHeader()...)
	shortIHL[0] = 0x44 // IHL=4 -> 16 bytes, illegal
	if parseIPv4(shortIHL) != nil {
		t.Errorf("IHL<5 should return nil")
	}

	shortTotal := append([]byte{}, ipv4MinHeader()...)
	shortTotal[2], shortTotal[3] = 0x00, 0x10 // total=16 < header=20
	if parseIPv4(shortTotal) != nil {
		t.Errorf("TotalLen<HeaderLen should return nil")
	}

	bufTooSmall := append([]byte{}, ipv4MinHeader()...)
	// declares total=28 but buffer is only 20 bytes
	if parseIPv4(bufTooSmall) != nil {
		t.Errorf("buffer shorter than TotalLen should return nil")
	}
}
