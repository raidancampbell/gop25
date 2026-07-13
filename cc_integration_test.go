package p25

import (
	"encoding/binary"
	"math"
	"os"
	"testing"

	"github.com/raidancampbell/godsp"
)

// TestControlChannel_OnAirDecode is an integration test against a real
// on-air P25 control channel: 1 s of 25 kSPS narrowband IQ extracted from
// the 460.4125 MHz NAC 0x171 CC (sweep capture 2026-05-15). It exercises
// the full demod -> sync -> NID -> trellis -> CRC -> TSBK-parse chain.
//
// Failure here means a regression in the on-air decode path that the
// synthetic round-trip tests would not catch (e.g. wrong CRC variant,
// wrong status-symbol stripping, wrong interleave direction).
func TestControlChannel_OnAirDecode(t *testing.T) {
	const fixture = "testdata/cc_460412_25k.iq"
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Skipf("fixture %s not present: %v", fixture, err)
	}
	n := len(data) / 8
	iq := make([]complex64, n)
	for i := 0; i < n; i++ {
		re := math.Float32frombits(binary.LittleEndian.Uint32(data[i*8:]))
		im := math.Float32frombits(binary.LittleEndian.Uint32(data[i*8+4:]))
		iq[i] = complex(re, im)
	}

	demod := dsp.NewFMDemodulator(25000)
	raw, _ := demod.Demodulate(iq)
	dec := NewP25Decoder(25000)
	_, ctrl := dec.Process(raw)

	var tsbks, idenUpVU, netStat, rfssStat int
	for _, cf := range ctrl {
		if cf.DUID != 0x7 || cf.TSBK == nil {
			continue
		}
		if cf.NAC != 0x171 {
			t.Errorf("unexpected NAC 0x%03X (want 0x171)", cf.NAC)
		}
		tsbks++
		switch cf.TSBK.Opcode {
		case OpcodeIdenUpVU:
			idenUpVU++
			if cf.TSBK.Iden == 3 {
				if cf.TSBK.BaseFreqHz != 450_000_000 {
					t.Errorf("IDEN_UP_VU iden=3: BaseFreqHz=%d, want 450000000", cf.TSBK.BaseFreqHz)
				}
				if cf.TSBK.SpacingHz != 6250 {
					t.Errorf("IDEN_UP_VU iden=3: SpacingHz=%d, want 6250", cf.TSBK.SpacingHz)
				}
			}
		case OpcodeNetworkStatusBcast:
			netStat++
			if cf.TSBK.ChannelID != 0x3682 {
				t.Errorf("NET_STS ChannelID=0x%04X, want 0x3682", cf.TSBK.ChannelID)
			}
		case OpcodeRFSSStatusBcast:
			rfssStat++
		}
	}

	t.Logf("decoded %d TSBKs (IDEN_UP_VU=%d NET_STS=%d RFSS_STS=%d) from %.3f s",
		tsbks, idenUpVU, netStat, rfssStat, float64(n)/25000)

	if tsbks < 30 {
		t.Errorf("decoded only %d TSBKs from 1 s of CC IQ; want >=30 (~36 expected)", tsbks)
	}
	if idenUpVU == 0 || netStat == 0 || rfssStat == 0 {
		t.Errorf("missing expected broadcast TSBKs: IDEN_UP_VU=%d NET_STS=%d RFSS_STS=%d",
			idenUpVU, netStat, rfssStat)
	}
}

// TestControlChannel_EVMFloor pins the symbol-recovery EVM achievable on the
// real on-air control-channel fixture. With the C4FM receive matched filter +
// deviation tracking + 1-tap DFE the steady-state EVM is ~0.020 (vs ~0.062
// with a generic 3 kHz LPF, ~0.130 with fixed nominal levels and no equaliser).
// Threshold of 0.030 leaves headroom while still failing if the matched filter
// or the tracking/DFE loops are removed or broken.
//
// Stats are reset after a 0.4 s burn-in so the threshold reflects the
// converged loops, not the initial sweep from devScale=1 / dfeTap=0.
func TestControlChannel_EVMFloor(t *testing.T) {
	const fixture = "testdata/cc_460412_25k.iq"
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Skipf("fixture %s not present: %v", fixture, err)
	}
	n := len(data) / 8
	iq := make([]complex64, n)
	for i := 0; i < n; i++ {
		re := math.Float32frombits(binary.LittleEndian.Uint32(data[i*8:]))
		im := math.Float32frombits(binary.LittleEndian.Uint32(data[i*8+4:]))
		iq[i] = complex(re, im)
	}

	demod := dsp.NewFMDemodulator(25000)
	dec := NewP25Decoder(25000)

	const burn = 10000 // 0.4 s
	r0, _ := demod.Demodulate(iq[:burn])
	dec.Process(r0)
	dec.ResetStats()
	r1, _ := demod.Demodulate(iq[burn:])
	dec.Process(r1)

	evm := dec.EVM()
	t.Logf("on-air CC EVM after burn-in: %.4f", evm)
	if evm > 0.030 {
		t.Errorf("on-air CC EVM = %.4f; want <= 0.030 (matched filter + dev-tracking + DFE expected ~0.020)", evm)
	}
}

// TestControlChannel_MatchedFilterLowersEVM pins the C4FM matched-filter fix:
// the proper receive filter (designC4FMRx) forms a Nyquist response with the
// C4FM tx shaping, both lowering EVM and removing the Gardner timing bias that
// a generic LPF leaves. Decoding the real CC fixture through the old generic
// 3 kHz window-sinc LPF must yield clearly higher EVM than through the matched
// filter (the production default).
func TestControlChannel_MatchedFilterLowersEVM(t *testing.T) {
	const fixture = "testdata/cc_460412_25k.iq"
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Skipf("fixture %s not present: %v", fixture, err)
	}
	n := len(data) / 8
	iq := make([]complex64, n)
	for i := 0; i < n; i++ {
		re := math.Float32frombits(binary.LittleEndian.Uint32(data[i*8:]))
		im := math.Float32frombits(binary.LittleEndian.Uint32(data[i*8+4:]))
		iq[i] = complex(re, im)
	}

	measure := func(taps []float32) float64 {
		demod := dsp.NewFMDemodulator(25000)
		dec := NewP25Decoder(25000)
		dec.rxFilter = dsp.NewFIRFilterReal(taps) // override the production filter
		const burn = 10000
		r0, _ := demod.Demodulate(iq[:burn])
		dec.Process(r0)
		dec.ResetStats()
		r1, _ := demod.Demodulate(iq[burn:])
		dec.Process(r1)
		return dec.EVM()
	}

	lpf := measure(dsp.DesignLPF(3000, 25000, 201))                 // the old generic LPF
	matched := measure(designC4FMRx(symbolRate, 25000, c4fmRxTaps)) // production default
	t.Logf("EVM with generic LPF=%.4f, with C4FM matched filter=%.4f (%.1f%% lower)",
		lpf, matched, 100*(lpf-matched)/lpf)
	if matched >= lpf {
		t.Errorf("matched-filter EVM %.4f not lower than LPF EVM %.4f", matched, lpf)
	}
	// Measured ~3x lower on this fixture; require a clear margin.
	if (lpf-matched)/lpf < 0.30 {
		t.Errorf("matched filter only lowered EVM by %.1f%%; want >=30%% (filter wired in?)",
			100*(lpf-matched)/lpf)
	}
}

// TestCCFixture_DrivesSystem proves the on-air control-channel fixture
// decoded in TestControlChannel_OnAirDecode can also drive p25.System via
// its tracker. Any voice grants in the fixture should cause System to call
// SpawnVoice with frequencies on the iden-3 6.25 kHz raster (base 450 MHz).
//
// If the 1-second fixture contains no grants, the test skips (acceptable).
func TestCCFixture_DrivesSystem(t *testing.T) {
	const fixture = "testdata/cc_460412_25k.iq"
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Skipf("fixture %s not present: %v", fixture, err)
	}
	n := len(data) / 8
	iq := make([]complex64, n)
	for i := 0; i < n; i++ {
		re := math.Float32frombits(binary.LittleEndian.Uint32(data[i*8:]))
		im := math.Float32frombits(binary.LittleEndian.Uint32(data[i*8+4:]))
		iq[i] = complex(re, im)
	}

	demod := dsp.NewFMDemodulator(25000)
	raw, _ := demod.Demodulate(iq)
	dec := NewP25Decoder(25000)
	_, ctrl := dec.Process(raw)

	h := newFakeHost()
	h.inWin = func(f uint32) bool { return f >= 451_800_000 && f <= 461_800_000 }
	s := NewSystem(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "T"}, h)
	s.Start()

	for _, cf := range ctrl {
		if cf.DUID == 0x7 && cf.TSBK != nil {
			s.tracker.Apply(cf.TSBK)
		}
	}

	if len(h.spawnedV) == 0 {
		t.Skip("fixture contains no voice grants in this 1s window; extend fixture or accept skip")
	}
	for f := range h.spawnedV {
		if (int64(f)-450_000_000)%6250 != 0 {
			t.Errorf("spawned freq %d is not on iden-3 6.25 kHz raster", f)
		}
		t.Logf("spawned voice pipeline at %d Hz", f)
	}
}
