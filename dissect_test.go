package p25

import (
	"encoding/binary"
	"testing"
	"time"
)

// ipUDP builds an IPv4+UDP datagram with the given dst port and UDP payload.
func ipUDP(dstPort uint16, payload []byte) []byte {
	total := 20 + 8 + len(payload)
	b := make([]byte, total)
	b[0] = 0x45 // IPv4, IHL 5
	binary.BigEndian.PutUint16(b[2:], uint16(total))
	b[8] = 64 // TTL
	b[9] = 17 // UDP
	copy(b[12:16], []byte{10, 4, 2, 17})
	copy(b[16:20], []byte{10, 0, 0, 1})
	binary.BigEndian.PutUint16(b[20:], 49152)                   // src port
	binary.BigEndian.PutUint16(b[22:], dstPort)                 // dst port
	binary.BigEndian.PutUint16(b[24:], uint16(8+len(payload))) // UDP length
	copy(b[28:], payload)
	return b
}

func layerByName(d *Dissection, name string) *Layer {
	for i := range d.Layers {
		if d.Layers[i].Name == name {
			return &d.Layers[i]
		}
	}
	return nil
}

func TestDissect_LRRP(t *testing.T) {
	// LRRP payload: type 0x0D len 4, VERSION=4 then HEADING=0x2D.
	d := Dissect(ipUDP(4001, []byte{0x0D, 0x04, 0x36, 0x04, 0x56, 0x2D}))
	if layerByName(d, "IPv4") == nil || layerByName(d, "UDP") == nil {
		t.Fatal("missing IPv4/UDP layers")
	}
	lrrp := layerByName(d, "LRRP")
	if lrrp == nil {
		t.Fatal("missing LRRP layer")
	}
	// Field 0 is the LRRP packet "type"; tokens follow in order.
	if len(lrrp.Fields) != 3 || lrrp.Fields[0].Key != "type" ||
		lrrp.Fields[1].Key != "VERSION" || lrrp.Fields[2].Key != "HEADING" {
		t.Errorf("LRRP fields = %+v, want type/VERSION/HEADING", lrrp.Fields)
	}
}

func TestDissect_ARSTimestamp(t *testing.T) {
	// ARS reg-ack with timestamp: len=0x0007, header 0xBF, ext, 0x04, ts32.
	pay := []byte{0x00, 0x07, 0xBF, 0x00, 0x04, 0x68, 0x46, 0x9C, 0x10}
	d := Dissect(ipUDP(4005, pay))
	ars := layerByName(d, "ARS")
	if ars == nil {
		t.Fatal("missing ARS layer")
	}
	var sawType, sawTS bool
	var tsVal string
	for _, f := range ars.Fields {
		if f.Key == "type" {
			sawType = true
		}
		if f.Key == "timestamp" {
			sawTS = true
			tsVal = f.Val
		}
	}
	if !sawType || !sawTS {
		t.Errorf("ARS fields = %+v, want type+timestamp", ars.Fields)
	}
	wantTS := time.Unix(int64(0x68469C10), 0).UTC().Format("2006-01-02 15:04:05Z")
	if tsVal != wantTS {
		t.Errorf("timestamp val = %q, want %q", tsVal, wantTS)
	}
}

func TestDissect_UnknownUDPPort(t *testing.T) {
	d := Dissect(ipUDP(9999, []byte{0xde, 0xad, 0xbe, 0xef}))
	udp := layerByName(d, "UDP")
	if udp == nil || len(udp.Undecoded) != 4 {
		t.Fatalf("want UDP layer with 4 undecoded bytes, got %+v", udp)
	}
}

func TestDissect_NonIPv4(t *testing.T) {
	d := Dissect([]byte{0x00, 0x01, 0x02})
	if len(d.Layers) != 1 || d.Layers[0].Name != "raw" || len(d.Layers[0].Undecoded) != 3 {
		t.Errorf("non-IPv4 must yield one raw layer, got %+v", d.Layers)
	}
}

func TestDissect_ICMP(t *testing.T) {
	b := make([]byte, 20+4)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[9] = 1 // ICMP
	copy(b[12:16], []byte{10, 4, 2, 17})
	copy(b[16:20], []byte{10, 0, 0, 1})
	b[20] = 8 // echo request
	if layerByName(Dissect(b), "ICMP") == nil {
		t.Fatal("missing ICMP layer")
	}
}
