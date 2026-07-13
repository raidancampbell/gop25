package p25

// SNDCPData is the SN-DATA layer parsed out of a Packet-Data (Format=0x16)
// PDU. Field meanings track sdrtrunk's SNDCPPacketHeader.java
// (PDU_TYPE/NSAPI/PACKET_HEADER_COMPRESSION/DATAGRAM_HEADER_COMPRESSION).
//
// PDUType is the SN-DATA PDU type - interpretation depends on direction
// (sdrtrunk PDUType.java); 4=OUTBOUND_RF_UNCONFIRMED_DATA, 5=RF_CONFIRMED_DATA,
// 0..3=ACTIVATE/DEACTIVATE TDS CONTEXT variants. Higher layers (LRRP) consume
// UserPayload directly; the type/compression fields steer them and feed
// reconnaissance dumps.
//
// HasHeader is true only when DataHeaderOffset == 2 (the only on-air shape
// for which sdrtrunk treats Payload[0:2] as a valid SN-DATA header). When
// false, PDUType/NSAPI/IPHeaderCompression/UDPHeaderCompression are zeroed
// and only UserPayload is meaningful — callers should not gate downstream
// parsing on the compression fields in that case (matches sdrtrunk's
// "empty SNDCPPacketHeader returns IPHeaderCompression.NONE by default").
type SNDCPData struct {
	HasHeader            bool  // true iff DataHeaderOffset == 2
	PDUType              uint8 // top nibble of byte 0 (bits 0..3)
	NSAPI                uint8 // bottom nibble of byte 0 (bits 4..7)
	IPHeaderCompression  uint8 // top nibble of byte 1 (bits 8..11)
	UDPHeaderCompression uint8 // bottom nibble of byte 1 (bits 12..15)

	// UserPayload is the raw datagram between the SN-DATA header and the pad
	// octets / CRC-32. For LRRP reports, this is what the LRRP parser reads.
	UserPayload []byte
}

// What "payload-free" SNDCP traffic actually is (taxonomy, verified 2026-06-18)
// ---------------------------------------------------------------------------
// Most P25 packet-data airtime carries no user IP datagram and is NOT an error
// or a decode failure — it is the data network's housekeeping. Four legitimate
// categories produce a clean PDU with little or no UserPayload:
//
//  1. SNDCP context management (PDUType 0..3): ACTIVATE/DEACTIVATE TDS CONTEXT
//     request/accept. A radio entering/leaving data service negotiates the data
//     link (NSAPI assignment, IP/UDP header-compression mode) and tears it down.
//     Header-only: UserPayload collapses to ~0 after off/pad/CRC stripping.
//  2. Delivery acknowledgments: confirmed-data PDUs (pdu.Confirmed) elicit
//     ACK/NACK response PDUs that are pure data-link signaling, no user octets.
//  3. MBT / alternate trunking control (Format 21/23): registration, affiliation,
//     etc. — never user data. These hit the Format != 0x16 gate below and are
//     dropped *unclassified* today (see TODO).
//  4. Keepalives: even when an IP datagram does come out, LRRP <=2-byte payloads
//     and ARS registration (port 4005) are heartbeats, not content. Real LRRP
//     GPS reports (port 4001, multi-byte) are the minority.
//
// Distinct from the above: RF-limited empties (weak uplinks dying at the sync/NID
// gates) also yield a bare 24-byte pcap, but those ARE sending data — we just
// can't decode them. Don't conflate the two when tallying.
//
// TODO: surface this taxonomy to consumers (e.g. a host UI). We currently keep PDUType/NSAPI
// on SNDCPData but render nothing, and MBT-format (21/23) PDUs are discarded at
// the Format != 0x16 return below without any classification. To distinguish
// "context/ACK housekeeping" from "discarded MBT control" from "real datagram"
// in the UI, tally Format + PDUType (+ keepalive vs. report) per transmission
// and show the breakdown rather than a single empty/non-empty count.
//
// parseSNDCP runs Stage B over a decoded Stage-A PDU. Returns nil if the PDU
// is not the SNDCP packet-data path:
//   - Format != 0x16 (PACKET_DATA): MBT or unknown - skip (see category 3 above).
//   - Payload too small for offset+pad+CRC trailer: skip rather than panic.
//
// Both confirmed and unconfirmed packet data flow through here: parsePDU has
// already reassembled pdu.Payload (12-octet 1/2-rate blocks, or 16-octet
// 3/4-rate blocks with the DBSN + CRC-9 stripped), so the SN-DATA layout
// below is identical for both.
//
// Layout (sdrtrunk PacketMessage.java:79-211, SNDCPPacketHeader.java:37-40):
//   - The 2-byte SN-DATA header is at Payload[0:2] only when
//     DataHeaderOffset == 2 (HasHeader=true). For other offsets, sdrtrunk
//     treats SN-DATA as absent (hasData()=false) and falls back to the
//     default IPHeaderCompression.NONE behavior, parsing IPv4 directly from
//     Payload[DataHeaderOffset:].
//   - User payload spans Payload[DataHeaderOffset : len-4(CRC32)-PadOctets].
func parseSNDCP(pdu *PDUData) *SNDCPData {
	if pdu == nil {
		return nil
	}
	if pdu.Format != 0x16 {
		return nil
	}
	off := int(pdu.DataHeaderOffset)
	pad := int(pdu.PadOctets)
	const crcBytes = 4
	if len(pdu.Payload) < off+crcBytes+pad {
		return nil
	}
	userEnd := len(pdu.Payload) - crcBytes - pad
	if userEnd < off {
		return nil
	}
	sn := &SNDCPData{}
	if off == 2 {
		hdr := pdu.Payload[0:2]
		sn.HasHeader = true
		sn.PDUType = (hdr[0] >> 4) & 0x0f
		sn.NSAPI = hdr[0] & 0x0f
		sn.IPHeaderCompression = (hdr[1] >> 4) & 0x0f
		sn.UDPHeaderCompression = hdr[1] & 0x0f
	}
	sn.UserPayload = append([]byte(nil), pdu.Payload[off:userEnd]...)
	return sn
}
