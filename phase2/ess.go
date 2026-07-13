package phase2

import "github.com/raidancampbell/gop25"

// ESSState tracks ESS (Encryption Sync Signal) accumulation for one TDMA slot.
//
// In P25 Phase 2, encryption metadata (AlgID/KeyID/MI) is distributed across
// a superframe's voice bursts:
//   - ESS-B: 4 hexbits per 4V burst × 4 bursts = 16 data hexbits
//   - ESS-A: 28 parity hexbits from the 2V burst
//
// After a complete cycle (4 × 4V + 1 × 2V), RS(44,16) decode over GF(2^6)
// yields the 96-bit encryption metadata: AlgID(8) + KeyID(16) + MI(72).
//
// Source: op25 p25p2_tdma.cc handle_4V2V_ess().
type ESSState struct {
	essB    [16]uint8 // 16 data hexbits accumulated from 4V bursts (4 per burst)
	essA    [28]uint8 // 28 parity hexbits extracted from 2V burst
	burstID int       // voice burst position: 0-3 for 4V, 4 for 2V; -1 = not synced

	// Decoded encryption parameters. Updated on successful RS decode.
	AlgID uint8
	KeyID uint16
	MI    [9]byte
	Valid bool // true after at least one successful RS decode
}

// NewESSState creates an ESS accumulator in the initial (not-synced) state.
func NewESSState() *ESSState {
	return &ESSState{
		burstID: -1,
		AlgID:   0x80, // "clear" / no encryption (P25 standard default)
	}
}

// Feed processes ESS dibits from a descrambled voice burst. burstType must
// be Burst4V or Burst2V; other types are ignored. The full descrambled
// 180-dibit burst is required (ESS spans positions 94–178).
//
// For 4V bursts: accumulates 4 ESS-B hexbits from 12 dibits at ESSOffset.
// For 2V bursts: extracts 28 ESS-A hexbits, then performs RS decode.
func (e *ESSState) Feed(burstType BurstType, dibits [BurstDibits]p25.Dibit) {
	// Advance burst position within the voice burst sequence.
	// op25: track_vb() increments for 4V, sets to 4 for 2V.
	switch burstType {
	case Burst4V:
		e.burstID = (e.burstID + 1) % 5
		if e.burstID > 3 {
			e.burstID = 0
		}
	case Burst2V:
		e.burstID = 4
	default:
		return
	}

	// ESS area starts at PayloadOffset + ESSOffset = burst[94].
	essStart := PayloadOffset + ESSOffset

	if e.burstID < 4 {
		// 4V burst: extract 4 hexbits from 12 ESS dibits → ESS_B.
		// Each hexbit is 3 consecutive dibits packed as: (d0<<4)|(d1<<2)|d2.
		// Source: op25 p25p2_tdma.cc:785-788.
		for i := 0; i < ESSDibits; i += 3 {
			e.essB[4*e.burstID+i/3] = uint8(dibits[essStart+i])<<4 |
				uint8(dibits[essStart+i+1])<<2 |
				uint8(dibits[essStart+i+2])
		}
	} else {
		// 2V burst: extract 28 parity hexbits from 85 dibits → ESS_A,
		// then RS decode.
		e.extract2V(dibits[essStart:])
		e.decode()
	}
}

// extract2V converts dibits from the 2V burst's ESS-A area into 28 hexbits.
// The data spans 85 dibits (28 hexbits × 3 dibits + 1 skipped DUID dibit).
// After hexbit 15 (48 dibits), one dibit is skipped per op25.
// Source: op25 p25p2_tdma.cc:790-796.
func (e *ESSState) extract2V(dibits []p25.Dibit) {
	j := 0
	for i := 0; i < 28; i++ {
		e.essA[i] = uint8(dibits[j])<<4 |
			uint8(dibits[j+1])<<2 |
			uint8(dibits[j+2])
		if i == 15 {
			j += 4 // skip one dibit (DUID position)
		} else {
			j += 3
		}
	}
}

// decode performs RS(44,16) decode on accumulated ESS_B (data) + ESS_A (parity)
// and extracts AlgID, KeyID, MI on success.
//
// The RS code is a shortened RS(63,35) over GF(2^6) with 28 roots:
//   - Full codeword: 63 symbols (35 data + 28 parity)
//   - Shortened to 44 symbols: 16 data (ESS_B) + 28 parity (ESS_A)
//   - 19 implicit zero symbols at the high data positions
//   - Error correction: t = 14 symbols
//
// Source: op25 p25p2_tdma.cc:798-818.
func (e *ESSState) decode() {
	// Build the 63-symbol codeword. Convention (matching rsDecodeGenericN):
	// received[i] = coefficient of x^i.
	//   received[0..27]  = parity (ESS_A, reversed)
	//   received[28..43] = data   (ESS_B, reversed)
	//   received[44..62] = zero padding (shortened positions)
	var cw [63]uint8
	for i := 0; i < 28; i++ {
		cw[27-i] = e.essA[i]
	}
	for i := 0; i < 16; i++ {
		cw[43-i] = e.essB[i]
	}

	corrected, nErrs, ok := p25.RSDecodeN(63, 35, 14, cw[:])
	if !ok || nErrs > 14 {
		return
	}
	// Shortened-code invariant: cw[44..62] are phantom zero-pad positions (only
	// the 44 symbols cw[0..43] are transmitted — 28 parity + 16 data). A correct
	// shortened-RS decode must leave them zero. On an over-budget (>14-error)
	// word, bounded-distance decoding can converge on a different valid length-63
	// codeword by placing corrections in the phantom region; syndromes verify
	// clean, so RSDecodeN returns ok=true with garbage AlgID/KeyID/MI. Reject any
	// decode that dirtied the padding so it fails cleanly instead of tagging a
	// clear Phase 2 call with a spurious encryption algorithm.
	for i := 44; i < 63; i++ {
		if corrected[i] != 0 {
			return
		}
	}

	// Extract corrected data hexbits (positions 28..43, reversed to match
	// ESS_B ordering: data[0] = highest-order data coefficient).
	var data [16]uint8
	for i := 0; i < 16; i++ {
		data[i] = corrected[43-i]
	}

	// Unpack 16 hexbits (96 bits) → AlgID(8) + KeyID(16) + MI(72).
	// Source: op25 p25p2_tdma.cc:802-811.
	e.AlgID = data[0]<<2 | data[1]>>4
	e.KeyID = uint16(data[1]&0x0F)<<12 | uint16(data[2])<<6 | uint16(data[3])

	// MI: 12 hexbits (72 bits) → 9 bytes, 4 hexbits per 3 bytes.
	j := 0
	for i := 0; i < 9; {
		e.MI[i] = data[j+4]<<2 | data[j+5]>>4
		i++
		e.MI[i] = (data[j+5]&0x0F)<<4 | data[j+6]>>2
		i++
		e.MI[i] = (data[j+6]&0x03)<<6 | data[j+7]
		i++
		j += 4
	}

	e.Valid = true
}

// BurstPosition returns the current burst position within the superframe
// voice cycle: 0-3 for 4V bursts, 4 for 2V, -1 if not synced. This is used
// by the ADP decryption offset calculation.
func (e *ESSState) BurstPosition() int {
	return e.burstID
}

// Encrypted returns true if the decoded AlgID indicates encryption.
// AlgID 0x80 means "unencrypted" and 0x00 means "not applicable".
func (e *ESSState) Encrypted() bool {
	return e.Valid && e.AlgID != 0 && e.AlgID != 0x80
}

// Reset clears the ESS accumulation state. Call at call boundaries.
func (e *ESSState) Reset() {
	e.burstID = -1
	e.Valid = false
	e.AlgID = 0x80
	e.KeyID = 0
	e.MI = [9]byte{}
}
