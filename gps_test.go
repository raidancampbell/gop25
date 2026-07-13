package p25

import (
	"math"
	"testing"
)

// packBits writes val into bits[start:start+n] MSB-first. Test-only; independent
// of the decode logic so a round-trip genuinely exercises bit positions + scaling.
func packBits(bits []uint8, start, n int, val uint32) {
	for i := range n {
		bits[start+i] = uint8((val >> uint(n-1-i)) & 1)
	}
}

func TestDecodeMotorolaUnitGPS(t *testing.T) {
	// Motorola Unit GPS (LCO=6, MFID=0x90). LCW bit layout (LCMotorolaUnitGPS.java):
	//   lat sign @24, lat mag bits[25:48] (23 bits), mult 90/0x7FFFFF
	//   lon sign @48, lon mag bits[49:72] (23 bits), mult 180/0x7FFFFF, sign is -180 offset
	const latMag = 0x400000 // ~ half scale
	const lonMag = 0x200000
	wantLat := float64(latMag) * 90.0 / float64(0x7FFFFF)        // positive
	wantLon := float64(lonMag)*180.0/float64(0x7FFFFF) - 180.0   // sign bit set -> -180 offset

	bits := make([]uint8, 72)
	packBits(bits, 0, 8, 6)     // LCO=6
	packBits(bits, 8, 8, 0x90)  // MFID (not read by decode, realistic)
	bits[24] = 0                // lat sign positive
	packBits(bits, 25, 23, latMag)
	bits[48] = 1 // lon sign -> -180 offset
	packBits(bits, 49, 23, lonMag)

	var lcw [9]byte
	copy(lcw[:], bitsToBytes(bits))

	got, ok := decodeMotorolaUnitGPS(lcw)
	if !ok {
		t.Fatalf("decodeMotorolaUnitGPS returned ok=false, want true")
	}
	if math.Abs(got.Lat-wantLat) > 1e-4 {
		t.Errorf("Lat = %.6f, want %.6f", got.Lat, wantLat)
	}
	if math.Abs(got.Lon-wantLon) > 1e-4 {
		t.Errorf("Lon = %.6f, want %.6f", got.Lon, wantLon)
	}
}

func TestDecodeMotorolaUnitGPS_NegativeLat(t *testing.T) {
	const latMag = 0x100000
	wantLat := -float64(latMag) * 90.0 / float64(0x7FFFFF)

	bits := make([]uint8, 72)
	bits[24] = 1 // lat sign negative
	packBits(bits, 25, 23, latMag)
	// lon left zero -> 0.0

	var lcw [9]byte
	copy(lcw[:], bitsToBytes(bits))

	got, ok := decodeMotorolaUnitGPS(lcw)
	if !ok {
		t.Fatalf("ok=false, want true")
	}
	if math.Abs(got.Lat-wantLat) > 1e-4 {
		t.Errorf("Lat = %.6f, want %.6f", got.Lat, wantLat)
	}
}

func TestDecodeHarrisGPS(t *testing.T) {
	// Harris GPS 112-bit field (L3HarrisGPS.java), parsed at offset 0:
	//   lat: frac[0:16], hemi@16, min[17:24], deg[24:32]
	//   lon: frac[32:48], hemi@48, min[49:56], deg[56:64]
	//   gpsTime[64:80], timeMSB@80, heading[95:104]
	//   coord = deg + (min + frac/10000)/60, negate if hemi
	bits := make([]uint8, 112)

	// Latitude: 39 deg, 45.5 minutes (frac=5000), positive.
	packBits(bits, 0, 16, 5000) // frac
	bits[16] = 0                // hemi positive
	packBits(bits, 17, 7, 45)   // minutes
	packBits(bits, 24, 8, 39)   // degrees
	wantLat := 39.0 + (45.0+5000.0/10000.0)/60.0

	// Longitude: 104 deg, 30 minutes, negative.
	packBits(bits, 32, 16, 0) // frac
	bits[48] = 1              // hemi negative
	packBits(bits, 49, 7, 30) // minutes
	packBits(bits, 56, 8, 104)
	wantLon := -(104.0 + (30.0+0.0)/60.0)

	packBits(bits, 95, 9, 180) // heading (9-bit field, value 180)

	got, ok := DecodeHarrisGPS(bits)
	if !ok {
		t.Fatalf("DecodeHarrisGPS returned ok=false, want true")
	}
	if math.Abs(got.Lat-wantLat) > 1e-6 {
		t.Errorf("Lat = %.6f, want %.6f", got.Lat, wantLat)
	}
	if math.Abs(got.Lon-wantLon) > 1e-6 {
		t.Errorf("Lon = %.6f, want %.6f", got.Lon, wantLon)
	}
	if !got.HasHeading || got.Heading != 180 {
		t.Errorf("Heading = %d (has=%v), want 180", got.Heading, got.HasHeading)
	}
}

func TestDecodeHarrisGPS_OutOfRange(t *testing.T) {
	// Degrees field maxed (255) -> latitude well over 90 -> rejected.
	bits := make([]uint8, 112)
	packBits(bits, 24, 8, 255) // lat degrees = 255
	if _, ok := DecodeHarrisGPS(bits); ok {
		t.Errorf("ok=true for out-of-range latitude, want false")
	}
}

func TestDecodeHarrisGPS_ShortInput(t *testing.T) {
	if _, ok := DecodeHarrisGPS(make([]uint8, 50)); ok {
		t.Errorf("ok=true for short input, want false")
	}
}
