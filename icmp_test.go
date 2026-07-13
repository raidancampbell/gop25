package p25

import "testing"

func TestParseICMP_EchoRequest(t *testing.T) {
	// type 8 (echo request), code 0, 2-byte checksum.
	got := parseICMP([]byte{8, 0, 0x12, 0x34})
	if got == nil {
		t.Fatal("parseICMP returned nil")
	}
	if got.Type != 8 || got.TypeName != "echo request" {
		t.Errorf("type=%d name=%q, want 8/echo request", got.Type, got.TypeName)
	}
	if got.HasOrigPort {
		t.Error("echo request must not report an original port")
	}
}

func TestParseICMP_PortUnreachable(t *testing.T) {
	// type 3 code 3 (port unreachable), 2-byte checksum, 4-byte unused,
	// then an embedded original IPv4 (IHL 5) + UDP header with dst port 4001.
	buf := []byte{3, 3, 0, 0, 0, 0, 0, 0}
	orig := make([]byte, 28)
	orig[0] = 0x45 // IPv4, IHL 5
	orig[9] = 17   // UDP
	orig[20], orig[21] = 0xC0, 0x00
	orig[22], orig[23] = 0x0F, 0xA1 // dst port 4001
	buf = append(buf, orig...)
	got := parseICMP(buf)
	if got == nil {
		t.Fatal("parseICMP returned nil")
	}
	if got.CodeName != "port" {
		t.Errorf("code name = %q, want port", got.CodeName)
	}
	if !got.HasOrigPort || got.OrigDstPort != 4001 {
		t.Errorf("orig port = %d (has=%v), want 4001", got.OrigDstPort, got.HasOrigPort)
	}
}

func TestParseICMP_Short(t *testing.T) {
	if parseICMP([]byte{8}) != nil {
		t.Error("len<2 must return nil")
	}
}
