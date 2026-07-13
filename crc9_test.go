package p25

import "testing"

// embedCRC9 computes the 9-bit CRC over a 144-bit confirmed data block
// (DBSN[0:7] + payload[16:144], with the CRC field at [7:16]) and writes it
// into the CRC field so that checkCRC9 passes. Used only to build test vectors.
func embedCRC9(b []uint8) {
	var calc uint16
	for i := 0; i < 144; i++ {
		if b[i] == 0 {
			continue
		}
		if i < 7 {
			calc ^= crc9Checksums[i]
		} else if i > 15 {
			calc ^= crc9Checksums[i-9]
		}
	}
	for k := 0; k < 9; k++ {
		b[7+k] = uint8((calc >> uint(8-k)) & 1)
	}
}

func TestCRC9_AllZeroPasses(t *testing.T) {
	if !checkCRC9(make([]uint8, 144)) {
		t.Fatal("all-zero block should pass CRC-9")
	}
}

func TestCRC9_ValidBlockPasses(t *testing.T) {
	b := make([]uint8, 144)
	// DBSN = 5 (bits 0..6 MSB-first => ...0000101)
	b[4], b[6] = 1, 1
	for _, i := range []int{16, 20, 33, 100, 143} {
		b[i] = 1
	}
	embedCRC9(b)
	if !checkCRC9(b) {
		t.Fatal("block with embedded CRC-9 should pass")
	}
}

func TestCRC9_DetectsSingleBitError(t *testing.T) {
	b := make([]uint8, 144)
	for _, i := range []int{16, 20, 33, 100, 143} {
		b[i] = 1
	}
	embedCRC9(b)
	b[50] ^= 1 // corrupt one payload bit
	if checkCRC9(b) {
		t.Fatal("single-bit payload error should fail CRC-9")
	}
}

func TestCRC9_DetectsDBSNError(t *testing.T) {
	b := make([]uint8, 144)
	b[3] = 1 // DBSN bit
	for _, i := range []int{40, 60, 120} {
		b[i] = 1
	}
	embedCRC9(b)
	b[3] ^= 1 // corrupt the DBSN
	if checkCRC9(b) {
		t.Fatal("DBSN bit error should fail CRC-9")
	}
}
