package p25

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// LRRPToken is one (id, raw payload) pair pulled out of an LRRP packet
// payload. Per-token interpretation lives in the typed accessor methods on
// LRRPData (see Task 4).
type LRRPToken struct {
	ID  uint8
	Raw []byte // payload bytes excluding the id (and excluding the length byte
	// for variable-length tokens). Caller owns the underlying buffer.
}

// LRRPData is the result of running parseLRRP over a UDP/4001 datagram. The
// raw payload is preserved alongside the parsed token list so a downstream
// audit can ignore Tokens and walk RawPayload directly.
//
// Reference: sdrtrunk module/decode/ip/mototrbo/lrrp/.
type LRRPData struct {
	PacketType    uint8
	PayloadLength uint16
	RawPayload    []byte // the bytes after the 2-byte header, length=PayloadLength

	Tokens []LRRPToken

	// Trailing holds bytes inside the declared payload that were unreachable
	// because the walker hit an unknown token id. Empty on a clean walk.
	Trailing []byte
}

// lrrpTokenLength returns the byte count for a token (including the id byte)
// given the bytes starting at the id. Returns 0 when the id is unknown or the
// length byte for a variable-length token is missing/inconsistent.
//
// The fixed-length values come straight from sdrtrunk's TokenType.java
// `length` field (which excludes the id, so we add 1 here).
func lrrpTokenLength(buf []byte) int {
	if len(buf) < 1 {
		return 0
	}
	switch buf[0] {
	case 0x23: // UNKNOWN_23: 1+id
		return 2
	case 0x31: // TRIGGER_PERIODIC: 1+id
		return 2
	case 0x34: // TIMESTAMP: 5+id
		return 6
	case 0x36: // VERSION: 1+id
		return 2
	case 0x38: // SUCCESS: 0+id
		return 1
	case 0x3A: // REQUEST_3A: 0+id
		return 1
	case 0x42: // TRIGGER_GPIO: 0+id
		return 1
	case 0x4A: // TRIGGER_DISTANCE: 1+id
		return 2
	case 0x50: // ALTITUDE_ACCURACY: 0+id
		return 1
	case 0x51: // CIRCLE_2D: 10+id
		return 11
	case 0x52: // TIME: 0+id
		return 1
	case 0x54: // ALTITUDE: 0+id
		return 1
	case 0x55: // CIRCLE_3D: 15+id
		return 16
	case 0x56: // HEADING: 1+id
		return 2
	case 0x57: // HORIZONTAL_DIRECTION: 0+id
		return 1
	case 0x61: // REQUEST_61: 1+id
		return 2
	case 0x62: // REQUEST_62: 0+id
		return 1
	case 0x64: // REQUEST_64: 0+id
		return 1
	case 0x66: // POINT_2D: 8+id
		return 9
	case 0x69: // POINT_3D: 11+id
		return 12
	case 0x6C: // SPEED: 2+id
		return 3
	case 0x73: // REQUEST_73: 1+id
		return 2
	case 0x78: // TRIGGER_ON_MOVE: 1+id
		return 2

	// Variable-length: byte after id is the payload byte count (id + len + payload).
	case 0x22: // IDENTITY
		if len(buf) < 2 {
			return 0
		}
		return int(buf[1]) + 2
	// RESPONSE token (0x37) per sdrtrunk Response.java: byte 1 bit 7 selects
	// extended (3-byte) vs short (2-byte) form. Not length-prefixed.
	case 0x37:
		if len(buf) < 2 {
			return 0
		}
		if buf[1]&0x80 != 0 {
			return 3
		}
		return 2
	}
	return 0
}

// parseLRRP returns nil only if the first 2-byte header cannot be read or the
// first PDU's PayloadLength runs past the buffer. A successful decode always
// returns a non-nil result; unknown-token bytes inside a payload are kept in
// Trailing rather than silently dropped.
//
// Motorola packs several short LRRP PDUs back-to-back in a single UDP/4001
// datagram (e.g. four [type][len][payload] records in one 70-byte payload).
// This walks every sub-message and aggregates their tokens, so the typed
// accessors (Position/Speed/Heading/Version) see the whole datagram rather
// than only the first PDU. PacketType/PayloadLength/RawPayload describe the
// first PDU, preserving single-message semantics.
func parseLRRP(buf []byte) *LRRPData {
	if len(buf) < 2 {
		return nil
	}
	firstLen := int(buf[1])
	if 2+firstLen > len(buf) {
		return nil
	}
	out := &LRRPData{
		PacketType:    buf[0],
		PayloadLength: uint16(firstLen),
	}
	out.RawPayload = append([]byte(nil), buf[2:2+firstLen]...)

	off := 0
	for off+2 <= len(buf) {
		payloadLen := int(buf[off+1])
		if off+2+payloadLen > len(buf) {
			// Truncated trailing PDU: header claims more payload than remains.
			// Keep the leading PDUs already parsed; stash the rest.
			out.Trailing = append(out.Trailing, buf[off:]...)
			break
		}
		payload := buf[off+2 : off+2+payloadLen]
		for i := 0; i < payloadLen; {
			n := lrrpTokenLength(payload[i:])
			if n == 0 || i+n > payloadLen {
				out.Trailing = append(out.Trailing, payload[i:]...)
				break
			}
			rawStart := i + 1
			if payload[i] == 0x22 {
				rawStart = i + 2
			}
			out.Tokens = append(out.Tokens, LRRPToken{
				ID:  payload[i],
				Raw: append([]byte(nil), payload[rawStart:i+n]...),
			})
			i += n
		}
		off += 2 + payloadLen
	}
	return out
}

// Position returns latitude (degrees), longitude (degrees), and altitude
// (meters; 0 for POINT_2D), together with ok=true if a POINT_2D or POINT_3D
// token was present and decodable. Reference: sdrtrunk Point2d.java /
// Point3d.java; the latitude hemisphere flag is the MSB of payload byte 0,
// the next 31 bits are an unsigned latitude scaled by 180/(2^32-1), the
// next 32 bits are a two's complement longitude scaled by 360/(2^32-1),
// and (POINT_3D only) the trailing 24 bits are an unsigned altitude in
// centimeters.
func (l *LRRPData) Position() (lat, lon, altMeters float64, ok bool) {
	if l == nil {
		return 0, 0, 0, false
	}
	for _, tok := range l.Tokens {
		switch tok.ID {
		case 0x66: // POINT_2D
			if len(tok.Raw) < 8 {
				continue
			}
			lat, lon = decodeLRRPLatLon(tok.Raw[:8])
			return lat, lon, 0, true
		case 0x69: // POINT_3D
			if len(tok.Raw) < 11 {
				continue
			}
			lat, lon = decodeLRRPLatLon(tok.Raw[:8])
			altRaw := uint32(tok.Raw[8])<<16 | uint32(tok.Raw[9])<<8 | uint32(tok.Raw[10])
			return lat, lon, float64(altRaw) * 0.01, true
		}
	}
	return 0, 0, 0, false
}

func decodeLRRPLatLon(p []byte) (lat, lon float64) {
	const latMul = 180.0 / 4294967295.0
	const lonMul = 360.0 / 4294967295.0
	hemisphere := (p[0] >> 7) & 1
	latRaw := (uint32(p[0]&0x7F) << 24) | (uint32(p[1]) << 16) |
		(uint32(p[2]) << 8) | uint32(p[3])
	lat = float64(latRaw) * latMul
	if hemisphere == 1 {
		lat = -lat
	}
	lonRaw := int32(uint32(p[4])<<24 | uint32(p[5])<<16 |
		uint32(p[6])<<8 | uint32(p[7]))
	lon = float64(lonRaw) * lonMul
	return lat, lon
}

// Speed returns the SPEED token value scaled by 0.01 (sdrtrunk Speed.java
// SPEED_MULTIPLIER), and ok=true if a SPEED token was present.
func (l *LRRPData) Speed() (float64, bool) {
	if l == nil {
		return 0, false
	}
	for _, tok := range l.Tokens {
		if tok.ID == 0x6C && len(tok.Raw) >= 2 {
			raw := uint16(tok.Raw[0])<<8 | uint16(tok.Raw[1])
			return float64(raw) * 0.01, true
		}
	}
	return 0, false
}

// Heading returns the HEADING token value in degrees from true north
// (sdrtrunk Heading.java HEADING_MULTIPLIER = 2.0), ok=true if present.
func (l *LRRPData) Heading() (float64, bool) {
	if l == nil {
		return 0, false
	}
	for _, tok := range l.Tokens {
		if tok.ID == 0x56 && len(tok.Raw) >= 1 {
			return float64(tok.Raw[0]) * 2.0, true
		}
	}
	return 0, false
}

// Version returns the LRRP protocol version reported by the VERSION token
// (id 0x36), ok=true if present.
func (l *LRRPData) Version() (uint8, bool) {
	if l == nil {
		return 0, false
	}
	for _, tok := range l.Tokens {
		if tok.ID == 0x36 && len(tok.Raw) >= 1 {
			return tok.Raw[0], true
		}
	}
	return 0, false
}

// lrrpTokenName maps a token id to its sdrtrunk mnemonic. Ids come from
// lrrpTokenLength above.
func lrrpTokenName(id uint8) string {
	switch id {
	case 0x22:
		return "IDENTITY"
	case 0x23:
		return "UNKNOWN_23"
	case 0x31:
		return "TRIGGER_PERIODIC"
	case 0x34:
		return "TIMESTAMP"
	case 0x36:
		return "VERSION"
	case 0x37:
		return "RESPONSE"
	case 0x38:
		return "SUCCESS"
	case 0x3A:
		return "REQUEST_3A"
	case 0x42:
		return "TRIGGER_GPIO"
	case 0x4A:
		return "TRIGGER_DISTANCE"
	case 0x50:
		return "ALTITUDE_ACCURACY"
	case 0x51:
		return "CIRCLE_2D"
	case 0x52:
		return "TIME"
	case 0x54:
		return "ALTITUDE"
	case 0x55:
		return "CIRCLE_3D"
	case 0x56:
		return "HEADING"
	case 0x57:
		return "HORIZONTAL_DIRECTION"
	case 0x61:
		return "REQUEST_61"
	case 0x62:
		return "REQUEST_62"
	case 0x64:
		return "REQUEST_64"
	case 0x66:
		return "POINT_2D"
	case 0x69:
		return "POINT_3D"
	case 0x6C:
		return "SPEED"
	case 0x73:
		return "REQUEST_73"
	case 0x78:
		return "TRIGGER_ON_MOVE"
	}
	return fmt.Sprintf("UNKNOWN_0x%02X", id)
}

// Describe returns a human label and decoded value for one LRRP token. val is
// "" for flag-only tokens. Tokens with established scaling (position, speed,
// heading, version, timestamp, identity) are decoded to physical units; the
// rest render their mnemonic plus the raw payload as hex so nothing is lost.
func (t LRRPToken) Describe() (name, val string) {
	name = lrrpTokenName(t.ID)
	switch t.ID {
	case 0x36: // VERSION
		if len(t.Raw) >= 1 {
			return name, strconv.Itoa(int(t.Raw[0]))
		}
	case 0x6C: // SPEED, ×0.01 m/s
		if len(t.Raw) >= 2 {
			raw := uint16(t.Raw[0])<<8 | uint16(t.Raw[1])
			return name, fmt.Sprintf("%.2f m/s", float64(raw)*0.01)
		}
	case 0x56: // HEADING, ×2.0 deg
		if len(t.Raw) >= 1 {
			return name, fmt.Sprintf("%.0f°", float64(t.Raw[0])*2.0)
		}
	case 0x66: // POINT_2D
		if len(t.Raw) >= 8 {
			lat, lon := decodeLRRPLatLon(t.Raw[:8])
			return name, fmt.Sprintf("%.5f°, %.5f°", lat, lon)
		}
	case 0x69: // POINT_3D
		if len(t.Raw) >= 11 {
			lat, lon := decodeLRRPLatLon(t.Raw[:8])
			alt := float64(uint32(t.Raw[8])<<16|uint32(t.Raw[9])<<8|uint32(t.Raw[10])) * 0.01
			return name, fmt.Sprintf("%.5f°, %.5f°  alt %.1fm", lat, lon, alt)
		}
	case 0x34: // TIMESTAMP: first 4 bytes big-endian Unix epoch seconds. Any
		// trailing bytes are surfaced as hex rather than dropped — the encoding
		// of the 5th byte is not corpus-validated.
		if len(t.Raw) >= 4 {
			epoch := uint32(t.Raw[0])<<24 | uint32(t.Raw[1])<<16 | uint32(t.Raw[2])<<8 | uint32(t.Raw[3])
			val := time.Unix(int64(epoch), 0).UTC().Format("2006-01-02 15:04:05Z")
			if len(t.Raw) > 4 {
				val += " +" + hexBytes(t.Raw[4:])
			}
			return name, val
		}
	case 0x22: // IDENTITY: printable string, else hex
		return name, lrrpString(t.Raw)
	case 0x38, 0x3A, 0x42, 0x50, 0x52, 0x54, 0x57, 0x62, 0x64: // flag-only
		return name, ""
	}
	// Fallback: any token with payload bytes we don't specifically decode.
	if len(t.Raw) == 0 {
		return name, ""
	}
	return name, hexBytes(t.Raw)
}

// lrrpString renders bytes as ASCII when fully printable, otherwise as hex.
func lrrpString(b []byte) string {
	for _, c := range b {
		if c < 0x20 || c > 0x7e || !unicode.IsPrint(rune(c)) {
			return hexBytes(b)
		}
	}
	return string(b)
}

func hexBytes(b []byte) string {
	var sb strings.Builder
	for i, c := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%02x", c)
	}
	return sb.String()
}
