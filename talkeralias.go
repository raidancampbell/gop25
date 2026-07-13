package p25

import "strings"

// Talker-alias assembler bounds (shared Phase 1 / Phase 2).
const (
	// aliasMaxBlocks caps a sane Motorola alias BLOCK_COUNT. Real aliases are a
	// few blocks; this rejects an obviously garbage header (0 or 0xFF) that the
	// LC FEC did not catch. Far above any real alias.
	aliasMaxBlocks = 16
	// aliasMaxFailedSets bounds CRC-failed reassembly retries within one latched
	// header, so a persistently-corrupt alias can't cause unbounded rework.
	aliasMaxFailedSets = 4
)

// Talker Alias shared codec (vendor-neutral). Sources:
//   - Motorola obfuscation + LUT: sdrtrunk MotorolaTalkerAliasComplete.java:41-203
//     (op25 tk_p25.py:2043-2154 runs the same transform but never emits text).
//   - CRC-16/GSM: sdrtrunk CRC16.java (poly 0x1021, init 0x0000, xorout 0xFFFF).
// The Motorola text decode has NO independent correctness oracle; semantic
// correctness is gated to the live on-air capture.

// motorolaAliasLUT is the 256-entry signed-byte lookup table.
// Verbatim from sdrtrunk MotorolaTalkerAliasComplete.java:41-59.
var motorolaAliasLUT = [256]int8{
	-14, 46, 102, -112, 116, -118, 111, 120, -69, 83, 3, 17, 104, -51, 68, 23,
	40, 95, 30, -124, 117, 121, 110, -101, 44, -66, 98, 45, -15, 124, -72, -125,
	-39, 78, 109, 2, 97, 61, -88, 6, -71, -8, -100, 55, 58, 35, -63, 80,
	-19, -97, -81, 59, -67, -126, -70, -96, -33, -62, 71, 34, -16, -18, -95, -2,
	-94, 16, 91, 72, 87, -93, 5, 96, 123, 13, -7, 108, -77, 86, 76, -68,
	41, -92, 15, -20, -74, -91, -90, 60, 127, 107, -76, 33, -83, -82, -60, -56,
	-59, 93, -34, -32, 29, 25, 75, -58, 12, 63, 90, -57, -31, 89, 85, 84,
	74, 67, 66, -30, -29, -6, 0, -28, -27, 24, 65, 11, 10, -26, -4, -3,
	-46, -10, -44, 43, 99, 73, -108, 94, -89, 92, 112, 105, -9, 8, -79, 125,
	56, -49, -52, -40, 81, -113, -43, -109, 106, -13, -17, 126, -5, 100, -12, 53,
	39, 7, 49, 20, -121, -104, 118, 52, -54, -110, 51, 27, 79, -116, 9, 64,
	50, 54, 119, 18, -45, -61, 1, -85, 114, -127, -107, -55, -64, -23, 101, 82,
	36, 48, 28, -37, -120, -24, -105, -99, 88, 38, 4, 57, -84, 42, -98, -86,
	37, -41, -50, -21, -106, -11, 14, -115, -36, -87, 47, -35, 31, -22, -111, -73,
	-42, -119, -117, -47, -80, -103, 19, 122, -25, -102, -75, -122, -1, 70, -123, -78,
	115, -38, -65, -48, 113, -53, 77, -128, 21, 103, 22, 26, 32, -114, 69, 62,
}

// CRC16GSM computes CRC-16/GSM (poly 0x1021, init 0x0000, no reflect) over data
// and returns it un-xored-with-FFFF caller-side; we apply xorout here.
func CRC16GSM(data []byte) uint16 {
	var crc uint16 // init 0x0000
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc ^ 0xFFFF // xorout
}

// CRC16GSMOK reports whether data (payload || 2-byte big-endian CRC) carries a
// valid trailing CRC-16/GSM.
func CRC16GSMOK(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	n := len(data) - 2
	stored := uint16(data[n])<<8 | uint16(data[n+1])
	return CRC16GSM(data[:n]) == stored
}

// MotorolaAliasDecode validates the reassembled buffer's CRC-16, then runs the
// Motorola obfuscation over the alias bytes (after the 56-bit/7-byte SUID,
// before the 2-byte CRC) and returns the decoded UTF-16-code-unit string plus
// the 24-bit SUID unit ID. reassembled = [SUID 7B | encoded alias | CRC 2B].
// Returns ok=false (and unit 0) on CRC fail or a too-short buffer.
// sdrtrunk MotorolaTalkerAliasComplete.java:137-203.
func MotorolaAliasDecode(reassembled []byte) (string, uint32, bool) {
	const suidLen = 7
	if len(reassembled) < suidLen+2 || !CRC16GSMOK(reassembled) {
		return "", 0, false
	}
	// SUID layout: WACN(20)|SYSTEM(12)|UNIT(24). The 24-bit unit ID is the last
	// 3 bytes of the 7-byte SUID (bytes 4-6). sdrtrunk MotorolaTalkerAliasComplete.java:144-197.
	unit := uint32(reassembled[4])<<16 | uint32(reassembled[5])<<8 | uint32(reassembled[6])
	encoded := reassembled[suidLen:] // alias bytes + 2 CRC bytes
	nBytes := len(encoded) - 2       // alias byte count (excl CRC)
	if nBytes <= 0 {
		return "", 0, false
	}
	decoded := make([]int8, nBytes)
	accumulator := uint16(nBytes)
	for i := 0; i < nBytes; i++ {
		accumMult := accumulator*293 + 0x72E9
		lut := motorolaAliasLUT[(int(encoded[i])+128)&0xFF]
		mult1 := int8(lut) - int8(accumMult>>8)
		mult2 := int8(1)
		shortstop := int8(accumMult | 0x1)
		increment := int8(shortstop << 1)
		for mult2 != -1 && shortstop != 1 {
			shortstop += increment
			mult2 += 2
		}
		decoded[i] = int8(mult1 * mult2)
		accumulator += uint16(encoded[i]) + 1
	}
	nChars := nBytes / 2
	out := make([]rune, 0, nChars)
	for i := 0; i < nChars; i++ {
		code := uint16(uint8(decoded[i*2]))<<8 | uint16(uint8(decoded[i*2+1]))
		out = append(out, rune(code))
	}
	return string(out), unit, true
}

// HarrisAliasString concatenates L3Harris ASCII alias fragments (7 bytes each),
// skipping any fragment whose trimmed text is already contained in the
// accumulation (blocks 3-4 commonly repeat 1-2). sdrtrunk
// LCHarrisTalkerAliasComplete.java:92-117.
//
// DIVERGENCE from sdrtrunk: sdrtrunk trims every 7-byte fragment before
// concatenating (LCHarrisTalkerAliasBase.getPayloadFragmentString -> trim),
// which silently drops a space that happens to land on a block boundary and
// would also drop one that pads the seam between two words. We instead
// concatenate the RAW payloads and trim only the final trailing pad, so a
// boundary space ("ENGINE "+"12 CAPT" -> "ENGINE 12 CAPT") and a word that
// spans a block ("BATTALI"+"ON CHIE" -> "BATTALION CHIE") are both preserved.
// The dedup containment test still uses the trimmed fragment so it is robust
// to differing trailing pad on a repeated block. Synth-verified; live gate
// deferred (real on-air Harris aliases will confirm the boundary handling).
func HarrisAliasString(blocks [][]byte) string {
	var alias string
	for _, b := range blocks {
		if b == nil {
			continue
		}
		trimmed := strings.Trim(string(b), " \x00")
		if trimmed == "" || strings.Contains(alias, trimmed) {
			continue
		}
		alias += string(b) // raw payload: preserve boundary/seam spaces
	}
	return strings.TrimRight(alias, " \x00")
}
