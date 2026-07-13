package p25

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/raidancampbell/godsp"
)

// TestSDRTrunkBaseband_DecodesP25 feeds the SDRTrunk 50 kHz int16 baseband
// recording through the FM demodulator + frame sync + P25 pipeline and asserts
// that the decoder produces a meaningful number of control frames.
//
// The fixture is from 453.4375 MHz which is a conventional repeater, NOT a
// trunked control channel. It carries voice calls terminated by TDUlc frames
// (DUID 0xF) but contains NO TSDU frames (DUID 0x7) and therefore NO TSBKs.
// This test validates the end-to-end demod pipeline (FM discriminator, symbol
// recovery, frame sync, NID decode) on a real on-air signal. Trellis decode
// validation requires a control-channel capture with TSDUs.
//
// Asserts: >=100 TDUlc frames decoded (verifying the pipeline works on real
// signals). Also reports TSBK counts for diagnostic purposes -- if any TSDUs
// appear in a future fixture update, the threshold can be raised.
func TestSDRTrunkBaseband_DecodesP25(t *testing.T) {
	const path = "testdata/baseband/20260503_094027_453437500_Interop_Greenbrier_Grnbrier_Co_MuAd_8_baseband.wav"
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("baseband fixture not present: %v", err)
	}
	defer f.Close()

	// Skip 44-byte WAV header; format is 50 kHz, int16, 2ch interleaved (I,Q).
	hdr := make([]byte, 44)
	if _, err := f.Read(hdr); err != nil {
		t.Fatal(err)
	}
	rate := int(binary.LittleEndian.Uint32(hdr[24:28]))
	if rate != 50000 {
		t.Fatalf("expected 50 kHz baseband, header says %d", rate)
	}

	// P25Decoder.Process takes post-FM-discriminator []float32 at the
	// constructor's sample rate.
	demod := dsp.NewFMDemodulator(50000)
	dec := NewP25Decoder(50000)

	tsbks := 0
	idenUp := 0
	tdulcFrames := 0
	tsduFrames := 0
	totalControl := 0
	buf := make([]byte, 50000*4) // 0.5 s of int16 stereo per chunk

	for {
		n, err := f.Read(buf)
		if n < 4 {
			break
		}
		iq := make([]complex64, n/4)
		for i := range iq {
			re := int16(binary.LittleEndian.Uint16(buf[i*4:]))
			im := int16(binary.LittleEndian.Uint16(buf[i*4+2:]))
			iq[i] = complex(float32(re)/32768, float32(im)/32768)
		}
		raw, _ := demod.Demodulate(iq)
		_, ctrl := dec.Process(raw)
		for _, cf := range ctrl {
			totalControl++
			switch cf.DUID {
			case 0xF: // TDUlc
				tdulcFrames++
			case 0x7: // TSDU
				tsduFrames++
				if cf.TSBK != nil {
					tsbks++
					switch cf.TSBK.Opcode {
					case OpcodeIdenUp, OpcodeIdenUpVU, OpcodeIdenUpTDMA:
						idenUp++
					}
				}
			}
		}
		if err != nil {
			break
		}
	}

	t.Logf("TDUlc: %d, TSDU: %d, CRC-passing TSBKs: %d (IDEN_UP*: %d), total control: %d",
		tdulcFrames, tsduFrames, tsbks, idenUp, totalControl)

	// The conventional repeater fixture produces ~1200+ TDUlc frames.
	// Assert a conservative lower bound to verify the pipeline works.
	if tdulcFrames < 100 {
		t.Errorf("expected >=100 TDUlc frames from conventional repeater fixture, got %d", tdulcFrames)
	}
	if totalControl < 100 {
		t.Errorf("expected >=100 total control frames, got %d", totalControl)
	}

	// TSBK assertions: this fixture has no TSDUs (conventional channel), so we
	// do not assert on TSBK counts. Log the values for diagnostic use. When a
	// real control-channel fixture is available, replace this with:
	//   if tsbks < 300 { t.Errorf(...) }
	if tsduFrames > 0 && tsbks == 0 {
		t.Errorf("TSDU frames present (%d) but 0 CRC-passing TSBKs -- trellis decode may be broken", tsduFrames)
	}
}
