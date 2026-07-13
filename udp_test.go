package p25

import (
	"bytes"
	"testing"
)

func TestParseUDP_PortAndPayload(t *testing.T) {
	// dst port 4001 (LRRP), src port 4001 too, length 12 (8+4), checksum 0.
	hdr := []byte{
		0x0F, 0xA1, // src port 4001
		0x0F, 0xA1, // dst port 4001
		0x00, 0x0C, // length 12
		0x00, 0x00, // checksum (not verified)
	}
	body := []byte{0xde, 0xad, 0xbe, 0xef}
	buf := append(append([]byte{}, hdr...), body...)

	udp := parseUDP(buf)
	if udp == nil {
		t.Fatal("parseUDP returned nil for a valid datagram")
	}
	if udp.SrcPort != 4001 {
		t.Errorf("SrcPort = %d, want 4001", udp.SrcPort)
	}
	if udp.DstPort != 4001 {
		t.Errorf("DstPort = %d, want 4001", udp.DstPort)
	}
	if udp.Length != 12 {
		t.Errorf("Length = %d, want 12", udp.Length)
	}
	if !bytes.Equal(udp.Payload, body) {
		t.Errorf("Payload = % x, want % x", udp.Payload, body)
	}
}

// Length<8 (header alone is 8 B) and length>buffer must return nil rather
// than emit garbage.
func TestParseUDP_RejectsBadLength(t *testing.T) {
	if parseUDP(nil) != nil {
		t.Errorf("nil should return nil")
	}
	if parseUDP([]byte{0, 0, 0, 0}) != nil {
		t.Errorf("4-byte input should return nil")
	}

	hdr := []byte{0x00, 0x00, 0x0F, 0xA1, 0x00, 0x07, 0x00, 0x00}
	if parseUDP(hdr) != nil {
		t.Errorf("Length<8 should return nil")
	}

	hdr2 := []byte{0x00, 0x00, 0x0F, 0xA1, 0xFF, 0xFF, 0x00, 0x00}
	if parseUDP(hdr2) != nil {
		t.Errorf("Length>buffer should return nil")
	}
}
