package p25

import "testing"

func TestCRC16GSM_RoundTrip(t *testing.T) {
	data := []byte{0xBE, 0xE0, 0x02, 0xAE, 0xE6, 0x78, 0x52, 0x10, 0x20, 0x30}
	crc := CRC16GSM(data)
	full := append(append([]byte{}, data...), byte(crc>>8), byte(crc))
	if !CRC16GSMOK(full) {
		t.Fatalf("CRC16GSMOK rejected a freshly CRC'd buffer (crc=%#x)", crc)
	}
	full[0] ^= 0x01
	if CRC16GSMOK(full) {
		t.Fatal("CRC16GSMOK accepted a corrupted buffer")
	}
}

// Characterization/regression lock: the Motorola obfuscation has NO independent
// correctness oracle (op25 does not emit the string). This pins the decoder's
// output for a fixed input so a future refactor can't silently change it. The
// SEMANTIC correctness of these bytes is gated to the live capture.
func TestMotorolaAliasDecode_Characterization(t *testing.T) {
	// 7-byte SUID (WACN=0xBEE00, SYS=0x2AE, ID=0xE67852) + 4 alias bytes + CRC.
	suid := []byte{0xBE, 0xE0, 0x02, 0xAE, 0xE6, 0x78, 0x52}
	aliasBytes := []byte{0x83, 0xED, 0x10, 0x81} // 2 chars
	buf := append(append([]byte{}, suid...), aliasBytes...)
	crc := CRC16GSM(buf)
	buf = append(buf, byte(crc>>8), byte(crc))

	got, _, ok := MotorolaAliasDecode(buf)
	if !ok {
		t.Fatal("MotorolaAliasDecode failed CRC on a self-CRC'd buffer")
	}
	// LOCK the current output. The Motorola obfuscation has no independent
	// oracle, so this pins the observed code units (U+CD1B U+366C) as a
	// regression lock, not a correctness proof. ASCII-escaped to keep source
	// 7-bit clean; the value is identical to the raw glyphs.
	const want = "\uCD1B\u366C"
	if got != want {
		t.Fatalf("decoded alias = %q, want %q (update lock if intentional)", got, want)
	}
}

func TestMotorolaAliasDecode_UnitID(t *testing.T) {
	// SUID: WACN(20)|SYSTEM(12)|UNIT(24). Bytes 4-6 are the 24-bit unit ID.
	suid := []byte{0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56}
	// One character (2 alias bytes) so nBytes=2, nChars=1. Values are arbitrary;
	// we only assert the unit ID and ok here, not the text.
	alias := []byte{0x41, 0x00}
	buf := append(append([]byte{}, suid...), alias...)
	crc := CRC16GSM(buf)
	buf = append(buf, byte(crc>>8), byte(crc))

	_, unit, ok := MotorolaAliasDecode(buf)
	if !ok {
		t.Fatalf("MotorolaAliasDecode: ok=false, want true")
	}
	if unit != 0x123456 {
		t.Fatalf("unit = %#x, want 0x123456", unit)
	}
}

func TestHarrisAliasString(t *testing.T) {
	// Boundary space: block1 ends with a space that separates it from block2.
	// Raw concat preserves it; sdrtrunk's per-fragment trim would drop it.
	// block3/4 repeat block1/2 content (real-world behavior) -> must be skipped
	// by the trimmed-containment dedup.
	b1 := []byte("ENGINE ") // 7 bytes
	b2 := []byte("12 CAPT")
	got := HarrisAliasString([][]byte{b1, b2, b1, b2})
	if got != "ENGINE 12 CAPT" {
		t.Fatalf("boundary-space alias = %q, want %q", got, "ENGINE 12 CAPT")
	}

	// Word spanning a block boundary: "BATTALION" is split across block1/2 with
	// no seam space, and block3 carries the trailing pad. Raw concat keeps the
	// word intact and the final trim removes only the pad.
	c1 := []byte("BATTALI")
	c2 := []byte("ON CHIE")
	c3 := []byte("F      ") // 7 bytes incl. trailing pad
	got = HarrisAliasString([][]byte{c1, c2, c3})
	if got != "BATTALION CHIEF" {
		t.Fatalf("word-spanning alias = %q, want %q", got, "BATTALION CHIEF")
	}

	// Trailing pad on the final fragment is trimmed; empty/nil blocks skipped.
	got = HarrisAliasString([][]byte{[]byte("UNIT 7 "), nil, []byte("       ")})
	if got != "UNIT 7" {
		t.Fatalf("padded alias = %q, want %q", got, "UNIT 7")
	}
}
