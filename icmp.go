package p25

import "fmt"

// ICMPData is a shallow ICMP message decode: type/code with human names, plus
// (for Destination Unreachable) the dst port of the embedded original
// datagram. Reference: RFC 792. Kept here so the p25.Dissect facade owns all
// protocol semantics for a host UI's detail pane.
type ICMPData struct {
	Type, Code  uint8
	TypeName    string
	CodeName    string // "" unless Type is Destination Unreachable (3)
	HasOrigPort bool
	OrigDstPort uint16
}

// parseICMP decodes the ICMP message in buf (the IPv4 payload). Returns nil
// only when buf is too short to hold the 2-byte type/code.
func parseICMP(buf []byte) *ICMPData {
	if len(buf) < 2 {
		return nil
	}
	d := &ICMPData{Type: buf[0], Code: buf[1]}
	switch buf[0] {
	case 0:
		d.TypeName = "echo reply"
	case 3:
		d.TypeName = "dest unreachable"
		d.CodeName = icmpUnreachName(buf[1])
		// 4-byte type/code/checksum + 4-byte unused, then original IP header.
		if len(buf) >= 8+20 {
			orig := buf[8:]
			origIHL := int(orig[0]&0x0f) * 4
			if origIHL >= 20 && len(orig) >= origIHL+4 {
				d.OrigDstPort = uint16(orig[origIHL+2])<<8 | uint16(orig[origIHL+3])
				d.HasOrigPort = true
			}
		}
	case 8:
		d.TypeName = "echo request"
	case 11:
		d.TypeName = "TTL exceeded"
	default:
		d.TypeName = fmt.Sprintf("type%d", buf[0])
	}
	return d
}

func icmpUnreachName(code uint8) string {
	switch code {
	case 0:
		return "net"
	case 1:
		return "host"
	case 2:
		return "proto"
	case 3:
		return "port"
	case 4:
		return "frag-needed"
	}
	return fmt.Sprintf("code%d", code)
}
