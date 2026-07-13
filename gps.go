package p25

// In-call GPS carried directly in P25 Link Control / MAC signalling (distinct
// from LRRP-over-SNDCP GPS uploads on the data channel, handled in lrrp.go).
// Three on-air carriers share these decoders:
//   - Motorola Unit GPS:   Phase 1 LCW, LCO=6, MFID=0x90 (decodeMotorolaUnitGPS)
//   - Harris Talker GPS:   Phase 1 LCW, LCO=42+43, MFID=0xA4 (two-block reassembly
//                          in alias_assembler.go, then DecodeHarrisGPS)
//   - Harris Talker GPS:   Phase 2 MAC vendor sub-message op=0xAA, MFID=0xA4
//                          (DecodeHarrisGPS on the sub-message body)
//
// References (vendored sdrtrunk):
//   - lc/motorola/LCMotorolaUnitGPS.java
//   - lc/l3harris/LCHarrisTalkerGPSComplete.java + phase2/.../l3harris/L3HarrisGPS.java

// GPSPosition is a decoded in-call position report. Heading/GPSTimeSec are only
// populated for Harris messages (Motorola Unit GPS carries lat/lon only).
type GPSPosition struct {
	Lat        float64
	Lon        float64
	Heading    int  // degrees from true north (Harris only)
	HasHeading bool // true when Heading was decoded
	GPSTimeSec uint32
}

// inRange rejects coordinates the LC FEC let through corrupt: a valid fix has
// |lat|<=90 and |lon|<=180.
func (g GPSPosition) inRange() bool {
	return g.Lat >= -90 && g.Lat <= 90 && g.Lon >= -180 && g.Lon <= 180
}

// decodeMotorolaUnitGPS decodes a Motorola Unit Self-Reported GPS Location LCW
// (LCO=6, MFID=0x90). Bit layout (LCMotorolaUnitGPS.java):
//
//	lat sign @24, lat magnitude bits[25:48] (23 bits), * 90/0x7FFFFF
//	lon sign @48, lon magnitude bits[49:72] (23 bits), * 180/0x7FFFFF, sign = -180 offset
func decodeMotorolaUnitGPS(lcw [9]byte) (GPSPosition, bool) {
	const latMul = 90.0 / float64(0x7FFFFF)
	const lonMul = 180.0 / float64(0x7FFFFF)

	bits := lcwBits(lcw)

	latMag := bitsToUint32(bits[25:48])
	lat := float64(latMag) * latMul
	if bits[24] == 1 {
		lat = -lat
	}

	lonMag := bitsToUint32(bits[49:72])
	lon := float64(lonMag) * lonMul
	if bits[48] == 1 {
		lon -= 180.0
	}

	g := GPSPosition{Lat: lat, Lon: lon}
	if !g.inRange() {
		return GPSPosition{}, false
	}
	return g, true
}

// DecodeHarrisGPS decodes the Harris Talker GPS 112-bit field shared by the
// Phase 1 (reassembled from blocks 1/2) and Phase 2 (MAC sub-message) carriers.
// Field layout at offset 0 (L3HarrisGPS.java):
//
//	lat: frac bits[0:16], hemisphere @16, minutes bits[17:24], degrees bits[24:32]
//	lon: frac bits[32:48], hemisphere @48, minutes bits[49:56], degrees bits[56:64]
//	gps time bits[64:80], time-MSB @80 (doubles seconds), heading bits[95:104]
//	coord = deg + (min + frac/10000)/60, negated when the hemisphere bit is set.
func DecodeHarrisGPS(bits []uint8) (GPSPosition, bool) {
	if len(bits) < 104 {
		return GPSPosition{}, false
	}

	lat := harrisCoord(bits, 24, 8, 17, 7, 0, 16, 16)
	lon := harrisCoord(bits, 56, 8, 49, 7, 32, 16, 48)

	gpsTime := bitsToUint32(bits[64:80])
	if bits[80] == 1 {
		gpsTime *= 2
	}

	g := GPSPosition{
		Lat:        lat,
		Lon:        lon,
		Heading:    int(bitsToUint32(bits[95:104])),
		HasHeading: true,
		GPSTimeSec: gpsTime,
	}
	if !g.inRange() {
		return GPSPosition{}, false
	}
	return g, true
}

// harrisCoord assembles one deg/min/frac coordinate. Field positions are passed
// as (start,len) pairs for degrees, minutes, fractional, plus the hemisphere bit
// index; mirrors L3HarrisGPS.parseCoordinate.
func harrisCoord(bits []uint8, degStart, degLen, minStart, minLen, fracStart, fracLen, hemiBit int) float64 {
	deg := float64(bitsToUint32(bits[degStart : degStart+degLen]))
	min := float64(bitsToUint32(bits[minStart : minStart+minLen]))
	frac := float64(bitsToUint32(bits[fracStart : fracStart+fracLen]))
	v := deg + (min+frac/10000.0)/60.0
	if bits[hemiBit] == 1 {
		v = -v
	}
	return v
}
