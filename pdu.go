package p25

// PDUData is one decoded P25 Phase-1 FDMA Packet Data Unit (DUID 0xC).
// Field offsets follow op25 p25p1_fdma.cc:487-489 and the TIA-102.BAAA data
// header. RawHeader/RawBlocks are retained for reconnaissance and so higher
// layers (SNDCP, LRRP) can re-slice without re-decoding.
type PDUData struct {
	// Common header fields (bits 0..47 of RawHeader).
	Confirmed bool   // header[0] bit 1 - 3/4-rate confirmed data blocks
	Outbound  bool   // header[0] bit 2 - true = FNE->SU, false = SU->FNE
	Format    uint8  // header[0] & 0x1f - PDUFormat (22=PACKET_DATA, 21/23=MBT)
	SAP       uint8  // header[1] & 0x3f
	MFID      uint8  // header[2]
	LLID      uint32 // header[3..5], 24-bit logical link ID

	BlocksToFollow uint8 // header[6] & 0x7f

	// Packet-data header extras (sdrtrunk PacketHeader.java).
	PadOctets        uint8 // header[7] & 0x1f - pad bytes appended to last data block
	Synchronize      bool  // header[8] & 0x80 - packet/fragment seq numbers valid
	PacketSequence   uint8 // (header[8] >> 5) & 0x3
	FragmentSequence uint8 // (header[8] >> 2) & 0x7
	DataHeaderOffset uint8 // header[9] & 0x3f - bytes of additional header inside data blocks

	HeaderCRCOK  bool
	PayloadCRCOK bool // CRC-32 over data blocks (MBT/multi-block forms)
	// Payload is the reassembled data-block bytes: blks*12 for unconfirmed
	// 1/2-rate blocks, or blks*16 for confirmed 3/4-rate blocks (after each
	// block's DBSN + CRC-9 are stripped). The trailing 4 bytes (before any pad
	// octets) are the transmitted packet CRC-32, not application data.
	Payload []byte

	// ConfirmedCRC9OK counts how many confirmed data blocks passed their
	// per-block CRC-9. Zero for unconfirmed PDUs. A high ratio of
	// ConfirmedCRC9OK to BlocksToFollow is the strongest signal the 3/4-rate
	// decode is correct on real traffic.
	ConfirmedCRC9OK int

	RawHeader [12]byte
	RawBlocks [][12]byte // populated for unconfirmed (1/2-rate) blocks only
}

// pduBlockBits is the trellis-encoded size of one PDU block (196 bits).
const pduBlockBits = trellisOut

// pduMaxBlocks is the maximum valid value of BlocksToFollow, equal to the
// full 7-bit range of the on-air field (TIA-102.BAAA). peekPDUHeader returns
// the exact value from a CRC-valid header; callers must fall back to the
// legacy fixed cap when the header CRC fails (see sync.go warm-peek path).
const pduMaxBlocks = 0x7f

// pduHeaderPeekDibits is how many payload dibits FrameSync must collect before
// it can peek-decode the header block. The header is one trellis block (196
// bits = 98 non-status dibits), but a status dibit falls at payload position 14,
// so 99 transmitted dibits are required.
var pduHeaderPeekDibits = pduPayloadDibits(0)

// peekPDUHeader trellis-decodes the first pduBlockBits of a PDU payload (after
// status-symbol removal) and returns BlocksToFollow if and only if the header
// CRC-16 passes. Used by FrameSync to size a PDU frame to its actual on-air
// length: a P25 Phase 1 PDU is variable-length, so the fixed payloadLen(0xC)
// gives only enough room for ~3 data blocks. The caller extends payloadCap to
// fit (1+blks)*pduBlockBits non-status bits when this returns ok=true.
//
// The result is the exact BlocksToFollow value (0–127) from the header;
// callers should fall back to the legacy fixed length when ok=false.
func peekPDUHeader(payload []Dibit) (blocksToFollow uint8, ok bool) {
	dataBits := make([]uint8, 0, len(payload)*2)
	for i := 0; i < len(payload) && len(dataBits) < pduBlockBits; i++ {
		if isStatusPosition(i) {
			continue
		}
		dataBits = append(dataBits, uint8((payload[i]>>1)&1), uint8(payload[i]&1))
	}
	if len(dataBits) < pduBlockBits {
		return 0, false
	}
	hbits, hcrc := viterbiDecodeRaw(dataBits[:pduBlockBits])
	if !hcrc {
		return 0, false
	}
	hdr := bitsToBytes(hbits)
	return hdr[6] & 0x7f, true
}

// pduPayloadDibits returns the number of payload dibits (status-bearing) needed
// to carry one header block plus blocksToFollow data blocks: each block needs
// pduBlockBits non-status bits = pduBlockBits/2 non-status dibits, and status
// dibits at payload positions 14, 50, 86, ... (every 36 starting at 14) are
// interspersed. The returned count covers the span up to and including the
// last data dibit of the final block.
func pduPayloadDibits(blocksToFollow int) int {
	const dibitsPerBlock = pduBlockBits / 2 // 98 non-status dibits per block
	wantData := (1 + blocksToFollow) * dibitsPerBlock
	data, total := 0, 0
	for data < wantData {
		if !isStatusPosition(total) {
			data++
		}
		total++
	}
	return total
}

// parsePDU decodes a PDU frame payload (DUID 0xC) with the legacy hard
// decoder. Equivalent to parsePDUWithSoft(payload, nil); kept as a thin
// wrapper for callers/tests with no soft information.
func parsePDU(payload []Dibit) *PDUData { return parsePDUWithSoft(payload, nil) }

// parsePDUWithSoft decodes a PDU frame payload. When soft is non-nil and 1:1
// aligned with payload, the header (1/2-rate) and confirmed data blocks
// (3/4-rate) are decoded with the soft-decision Viterbi (~2 dB more coding
// gain on AWGN); when soft is nil it falls back to the hard decoders. The
// status-symbol stride is identical for both, so the soft index tracks the
// hard dataBits index. Returns nil only when no header block can be recovered.
func parsePDUWithSoft(payload []Dibit, soft []float32) *PDUData {
	useSoft := soft != nil && len(soft) >= len(payload)
	dataBits := make([]uint8, 0, len(payload)*2)
	var softBits []SoftBit
	if useSoft {
		softBits = make([]SoftBit, 0, len(payload)*2)
	}
	for i := 0; i < len(payload); i++ {
		if isStatusPosition(i) {
			continue
		}
		dataBits = append(dataBits, uint8((payload[i]>>1)&1), uint8(payload[i]&1))
		if useSoft {
			hi, lo := softDemapSymbol(float64(soft[i]))
			softBits = append(softBits, hi, lo)
		}
	}
	if len(dataBits) < pduBlockBits {
		return nil
	}

	// Header block (block 0).
	var hbits []uint8
	var hcrc bool
	if useSoft {
		hbits, hcrc = viterbiSoftDecodeRaw(softBits[:pduBlockBits])
	} else {
		hbits, hcrc = viterbiDecodeRaw(dataBits[:pduBlockBits])
	}
	pdu := &PDUData{HeaderCRCOK: hcrc}
	hdr := bitsToBytes(hbits)
	copy(pdu.RawHeader[:], hdr)
	pdu.Format = hdr[0] & 0x1f
	pdu.SAP = hdr[1] & 0x3f
	pdu.MFID = hdr[2]
	pdu.LLID = uint32(hdr[3])<<16 | uint32(hdr[4])<<8 | uint32(hdr[5])
	pdu.BlocksToFollow = hdr[6] & 0x7f
	pdu.Confirmed = hdr[0]&0x40 != 0
	pdu.Outbound = hdr[0]&0x20 != 0
	pdu.PadOctets = hdr[7] & 0x1f
	pdu.Synchronize = hdr[8]&0x80 != 0
	pdu.PacketSequence = (hdr[8] >> 5) & 0x3
	pdu.FragmentSequence = (hdr[8] >> 2) & 0x7
	pdu.DataHeaderOffset = hdr[9] & 0x3f

	// Data blocks. Decode up to BlocksToFollow, bounded by available bits.
	// Confirmed-delivery PDUs carry 3/4-rate blocks (7-bit data block serial
	// number + 9-bit CRC-9 + 16 octets of payload = 144 bits); unconfirmed PDUs
	// carry 1/2-rate, 12-octet (96-bit) blocks. Both occupy 196 on-air bits, so
	// the windowing is identical -- only the per-block decode differs.
	offset := pduBlockBits
	decoded := 0
	for b := 0; b < int(pdu.BlocksToFollow) && offset+pduBlockBits <= len(dataBits); b++ {
		blockBits := dataBits[offset : offset+pduBlockBits]
		var blockSoft []SoftBit
		if useSoft {
			blockSoft = softBits[offset : offset+pduBlockBits]
		}
		offset += pduBlockBits
		decoded++
		if pdu.Confirmed {
			var d144 []uint8
			if useSoft {
				d144 = viterbi34SoftDecodeRaw(blockSoft)
			} else {
				d144 = viterbi34DecodeRaw(blockBits)
			}
			if checkCRC9(d144) {
				pdu.ConfirmedCRC9OK++
			}
			// User payload is bits [16:144] = 16 octets, after the DBSN + CRC-9.
			pdu.Payload = append(pdu.Payload, bitsToBytes(d144[16:144])...)
		} else {
			// Unconfirmed (1/2-rate) blocks. The hard decoder ran here even
			// pre-soft because the block carries no per-block CRC-9 to gate on;
			// keep using it to avoid false-positive blocks the soft path could
			// invent on heavy noise without a CRC to reject them. (Soft-CC and
			// soft-unconfirmed are noted as follow-ups in the plan.)
			dbits, _ := viterbiDecodeRaw(blockBits)
			var blk [12]byte
			copy(blk[:], bitsToBytes(dbits))
			pdu.RawBlocks = append(pdu.RawBlocks, blk)
			pdu.Payload = append(pdu.Payload, blk[:]...)
		}
	}

	// Multi-block packet CRC-32. The transmitted CRC-32 is the final 4 octets
	// of the reassembled payload and covers everything before it, INCLUDING any
	// pad octets (the on-air order is [data header][user data][pad][CRC-32]).
	// This holds for both unconfirmed (12-octet) and confirmed (16-octet,
	// DBSN/CRC-9-stripped) blocks; matches op25 p25p1_fdma.cc.
	if decoded == int(pdu.BlocksToFollow) && len(pdu.Payload) >= 4 {
		n := len(pdu.Payload)
		want := uint32(pdu.Payload[n-4])<<24 | uint32(pdu.Payload[n-3])<<16 |
			uint32(pdu.Payload[n-2])<<8 | uint32(pdu.Payload[n-1])
		got := crc32P25(pdu.Payload, (n-4)*8)
		pdu.PayloadCRCOK = got == want
	}
	return pdu
}
