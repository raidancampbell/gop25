package p25

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
	"testing"
)

// ─── Golay(23,12) ──────────────────────────────────────────────────────────────

func FuzzGolayDecode_NoPanic(f *testing.F) {
	f.Add(uint32(0))
	f.Add(uint32(0x7FFFFF)) // max 23-bit value
	f.Add(golayEncode(0xABC))
	f.Add(uint32(0xDEADBE))

	f.Fuzz(func(t *testing.T, received uint32) {
		received &= 0x7FFFFF // mask to 23 bits
		// Must not panic. Either decodes or returns ok=false.
		_, _ = golayDecode(received)
	})
}

func FuzzGolayRoundTrip(f *testing.F) {
	f.Add(uint16(0), uint32(0))
	f.Add(uint16(0xABC), uint32(0x15))
	f.Add(uint16(0xFFF), uint32(0x7FFFFF))

	f.Fuzz(func(t *testing.T, msg uint16, errMask uint32) {
		msg &= 0xFFF // 12-bit message
		errMask &= 0x7FFFFF
		errBits := bits.OnesCount32(errMask)

		encoded := golayEncode(msg)
		corrupted := encoded ^ errMask

		decoded, ok := golayDecode(corrupted)
		if errBits <= 3 {
			// Must correct up to 3 errors
			if !ok {
				t.Fatalf("golayDecode failed for msg=0x%03X with %d-bit error mask=0x%06X",
					msg, errBits, errMask)
			}
			if decoded != msg {
				t.Fatalf("golayDecode wrong: msg=0x%03X, got=0x%03X, %d-bit error mask=0x%06X",
					msg, decoded, errBits, errMask)
			}
		}
		// >3 errors: may or may not decode, but must not panic
	})
}

// ─── BCH / NID decode ───────────────────────────────────────────────────────────

func FuzzDecodeNID_NoPanic(f *testing.F) {
	f.Add(uint64(0))
	f.Add(uint64(math.MaxUint64))
	f.Add(bchEncode(0x2935)) // NAC=0x293, DUID=0x5

	f.Fuzz(func(t *testing.T, received uint64) {
		// Must not panic regardless of input
		nid, ok := decodeNID(received)
		if ok {
			// If it claims success, NAC must be valid and DUID must be one of the known set
			if nid.NAC > 0xFFF {
				t.Fatalf("decoded NAC=0x%03X out of range from received=0x%016X", nid.NAC, received)
			}
			validDUID := false
			for _, d := range validDUIDs {
				if nid.DUID == d {
					validDUID = true
					break
				}
			}
			if !validDUID {
				t.Fatalf("decoded invalid DUID=0x%X from received=0x%016X", nid.DUID, received)
			}
		}
	})
}

func FuzzBCHRoundTrip(f *testing.F) {
	f.Add(uint16(0x293), uint8(0x5), uint64(0))
	f.Add(uint16(0xFFF), uint8(0xF), uint64(0x7FF))

	f.Fuzz(func(t *testing.T, nac uint16, duidIdx uint8, errMask uint64) {
		nac &= 0xFFF
		duid := validDUIDs[int(duidIdx)%len(validDUIDs)]
		msg := (nac << 4) | uint16(duid)
		encoded := bchEncode(msg)
		corrupted := encoded ^ errMask
		errBits := bits.OnesCount64(errMask)

		nid, ok := decodeNID(corrupted)
		if errBits <= 11 {
			if !ok {
				t.Fatalf("decodeNID failed for NAC=0x%03X DUID=0x%X with %d-bit error mask=0x%016X",
					nac, duid, errBits, errMask)
			}
			if nid.NAC != nac || nid.DUID != duid {
				t.Fatalf("decodeNID wrong: want NAC=0x%03X DUID=0x%X, got NAC=0x%03X DUID=0x%X, %d errors, mask=0x%016X",
					nac, duid, nid.NAC, nid.DUID, errBits, errMask)
			}
		}
	})
}

// ─── FrameSync ──────────────────────────────────────────────────────────────────

func FuzzFrameSync_NoPanic(f *testing.F) {
	f.Add([]byte{})
	// Seed with a valid frame (sync + NID + minimal payload)
	seed := frameSyncSeed(0x293, 0x3) // TDU has no payload
	f.Add(seed)
	// Seed with an LDU1 to exercise payload collection
	f.Add(frameSyncSeed(0x293, 0x5))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Convert bytes to dibits (2 dibits per byte, lower 2 bits each)
		dibits := bytesToDibits(data)
		fs := NewFrameSync()
		frames := fs.Feed(dibits)

		// Validate invariants on any emitted frames
		for i, fr := range frames {
			if fr.NID.NAC > 0xFFF {
				t.Fatalf("frame %d: NAC=0x%03X out of range (input len=%d)",
					i, fr.NID.NAC, len(data))
			}
			validDUID := false
			for _, d := range validDUIDs {
				if fr.NID.DUID == d {
					validDUID = true
					break
				}
			}
			if !validDUID {
				t.Fatalf("frame %d: invalid DUID=0x%X (input len=%d)", i, fr.NID.DUID, len(data))
			}
			expectedPLen := payloadLen(fr.NID.DUID)
			if expectedPLen == 0 {
				if fr.Payload != nil {
					t.Fatalf("frame %d: DUID=0x%X should have nil payload, got len=%d",
						i, fr.NID.DUID, len(fr.Payload))
				}
			} else if fr.NID.DUID == 0xC {
				// PDU is variable-length: FrameSync's two-stage header peek
				// extends payloadCap from the floor (payloadLen(0xC) = 424)
				// up to (1+pduMaxBlocks)*pduBlockBits non-status bits when
				// the header CRC passes. Anything between [floor, ceiling]
				// is valid; on noise the header CRC fails and the floor holds.
				maxPLen := pduPayloadDibits(0x7f)
				if len(fr.Payload) < expectedPLen || len(fr.Payload) > maxPLen {
					t.Fatalf("frame %d: PDU payload len=%d, want [%d, %d]",
						i, len(fr.Payload), expectedPLen, maxPLen)
				}
			} else if len(fr.Payload) != expectedPLen {
				t.Fatalf("frame %d: DUID=0x%X payload len=%d, want %d",
					i, fr.NID.DUID, len(fr.Payload), expectedPLen)
			}
		}
	})
}

// ─── LDU parsing ────────────────────────────────────────────────────────────────

func FuzzParseLDU1_NoPanic(f *testing.F) {
	f.Add(make([]byte, 900))
	f.Add(make([]byte, 10)) // too short

	f.Fuzz(func(t *testing.T, data []byte) {
		payload := bytesToDibits(data)
		fr := Frame{
			NID:     NID{NAC: 0x293, DUID: 0x5},
			Payload: payload,
		}
		dec := NewP25Decoder(25000)
		vf := dec.parseLDU1(fr)
		if vf != nil {
			validateVoiceFrame(t, vf, data)
		}
	})
}

func FuzzParseLDU2_NoPanic(f *testing.F) {
	f.Add(make([]byte, 900))
	f.Add(make([]byte, 10))

	f.Fuzz(func(t *testing.T, data []byte) {
		payload := bytesToDibits(data)
		fr := Frame{
			NID:     NID{NAC: 0x293, DUID: 0xA},
			Payload: payload,
		}
		dec := NewP25Decoder(25000)
		vf := dec.parseLDU2(fr)
		if vf != nil {
			validateVoiceFrame(t, vf, data)
		}
	})
}

// ─── Symbol recovery ────────────────────────────────────────────────────────────

func FuzzSymbolRecovery_NoPanic(f *testing.F) {
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 100))
	// Seed with valid-looking discriminator data
	pattern := []Dibit{0, 1, 2, 3, 1, 3, 0, 2}
	samples := generateC4FM(pattern, 25000, 0)
	f.Add(float32SliceToBytes(samples))

	f.Fuzz(func(t *testing.T, data []byte) {
		samples := bytesToFloat32s(data)
		if len(samples) < 2 {
			return // need at least 2 samples for lerp
		}
		// Check for NaN/Inf which would cause undefined behavior
		for i, s := range samples {
			if math.IsNaN(float64(s)) || math.IsInf(float64(s), 0) {
				samples[i] = 0
			}
		}
		sr := NewSymbolRecovery(25000)
		dibits := sr.Process(samples)
		// Every dibit must be 0-3
		for i, d := range dibits {
			if d > 3 {
				t.Fatalf("dibit %d = %d (>3), input len=%d bytes", i, d, len(data))
			}
		}
	})
}

// ─── Full pipeline ──────────────────────────────────────────────────────────────

func FuzzP25Decoder_NoPanic(f *testing.F) {
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 200))

	f.Fuzz(func(t *testing.T, data []byte) {
		samples := bytesToFloat32s(data)
		if len(samples) < 2 {
			return
		}
		for i, s := range samples {
			if math.IsNaN(float64(s)) || math.IsInf(float64(s), 0) {
				samples[i] = 0
			}
		}
		dec := NewP25Decoder(25000)
		voiceFrames, _ := dec.Process(samples)
		for i, vf := range voiceFrames {
			if vf.NAC > 0xFFF {
				t.Fatalf("voice frame %d: NAC=0x%03X out of range (input len=%d)",
					i, vf.NAC, len(data))
			}
			for cwIdx, cw := range vf.IMBE {
				for bitIdx, b := range cw {
					if b > 1 {
						t.Fatalf("voice frame %d, codeword %d, bit %d = %d (not 0/1)",
							i, cwIdx, bitIdx, b)
					}
				}
			}
		}
	})
}

// ─── extractBits ────────────────────────────────────────────────────────────────

func FuzzExtractBits_NoPanic(f *testing.F) {
	f.Add([]byte{0xFF, 0x00, 0xAB}, uint8(0), uint8(8))

	f.Fuzz(func(t *testing.T, data []byte, offsetByte uint8, nBitsByte uint8) {
		dibits := bytesToDibits(data)
		if len(dibits) == 0 {
			return
		}
		offset := int(offsetByte) % (len(dibits) * 2)
		nBits := int(nBitsByte)%32 + 1

		// Must not panic
		result := extractBits(dibits, offset, nBits)
		_ = result
	})
}

// ─── Helpers ────────────────────────────────────────────────────────────────────

// bytesToDibits converts raw bytes to a dibit slice. Each byte produces one dibit (& 0x3).
func bytesToDibits(data []byte) []Dibit {
	dibits := make([]Dibit, len(data))
	for i, b := range data {
		dibits[i] = Dibit(b & 0x3)
	}
	return dibits
}

// bytesToFloat32s reinterprets raw bytes as little-endian float32 values.
func bytesToFloat32s(data []byte) []float32 {
	n := len(data) / 4
	samples := make([]float32, n)
	for i := 0; i < n; i++ {
		b := binary.LittleEndian.Uint32(data[i*4 : i*4+4])
		samples[i] = math.Float32frombits(b)
	}
	return samples
}

// float32SliceToBytes converts float32 samples to raw bytes for fuzzing seeds.
func float32SliceToBytes(samples []float32) []byte {
	buf := make([]byte, len(samples)*4)
	for i, s := range samples {
		binary.LittleEndian.PutUint32(buf[i*4:], math.Float32bits(s))
	}
	return buf
}

// frameSyncSeed builds a valid byte sequence that will be converted to a frame via bytesToDibits.
// Since bytesToDibits masks each byte to 2 bits, we encode dibits directly as bytes.
func frameSyncSeed(nac uint16, duid uint8) []byte {
	var stream []byte

	// sync word dibits
	for _, d := range syncWord {
		stream = append(stream, byte(d))
	}

	// NID dibits
	msg := (nac << 4) | uint16(duid)
	encoded := bchEncode(msg)
	for i := 0; i < nidLen; i++ {
		shift := uint(2 * (nidLen - 1 - i))
		stream = append(stream, byte((encoded>>shift)&0x3))
	}

	// Payload dibits (zeros)
	pLen := payloadLen(duid)
	for i := 0; i < pLen; i++ {
		stream = append(stream, 0)
	}

	return stream
}

// validateVoiceFrame checks invariants on a parsed VoiceFrame.
func validateVoiceFrame(t *testing.T, vf *VoiceFrame, inputData []byte) {
	t.Helper()
	if vf.NAC > 0xFFF {
		t.Fatalf("NAC=0x%03X out of range, input=%s", vf.NAC, truncHex(inputData))
	}
	for cwIdx, cw := range vf.IMBE {
		for bitIdx, b := range cw {
			if b > 1 {
				t.Fatalf("IMBE[%d][%d] = %d (not 0/1), input=%s", cwIdx, bitIdx, b, truncHex(inputData))
			}
		}
	}
}

// truncHex returns a hex string of data, truncated for readability in error messages.
func truncHex(data []byte) string {
	if len(data) > 32 {
		return fmt.Sprintf("%x...(len=%d)", data[:32], len(data))
	}
	return fmt.Sprintf("%x", data)
}
