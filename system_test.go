package p25

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeVoice struct {
	mu             sync.Mutex
	freq           uint32
	site           uint8
	grants         int
	tdmaGrants     int
	fdmaGrants     int
	p2params       int
	lastTGID       uint16
	lastSrcID      uint32
	lastFDMATGID   uint16
	unitGrants     int
	lastUnitSrc    uint32
	reassigns      int
	lastReassignTG uint16
	gotNAC         uint16
	gotSYSID       uint16
	gotWACN        uint32
	// SNDCP data-session staging (StageDataSession).
	dataStaged       bool
	stagedNAC        uint16
	stagedCCFreq     uint32
	stagedTargetFreq uint32
	stagedSourceID   uint32
	stagedGroupID    uint32
	stagedOpcode     uint8
	stagedUplink     bool
}

func (f *fakeVoice) NotifyGrant(time.Duration) { f.mu.Lock(); f.grants++; f.mu.Unlock() }
func (f *fakeVoice) NotifyFDMAGrant(_ time.Duration, tg uint16) {
	f.mu.Lock()
	f.fdmaGrants++
	f.lastFDMATGID = tg
	f.mu.Unlock()
}
func (f *fakeVoice) NotifyUnitGrant(_ time.Duration, src uint32) {
	f.mu.Lock()
	f.unitGrants++
	f.lastUnitSrc = src
	f.mu.Unlock()
}
func (f *fakeVoice) NotifyTDMAGrant(_ time.Duration, tg uint16, src uint32, _ uint16, _ int) {
	f.mu.Lock()
	f.tdmaGrants++
	f.lastTGID = tg
	f.lastSrcID = src
	f.mu.Unlock()
}
func (f *fakeVoice) NotifyReassigned(tg uint16) {
	f.mu.Lock()
	f.reassigns++
	f.lastReassignTG = tg
	f.mu.Unlock()
}
func (f *fakeVoice) SetP2ScrambleParams(nac, sysid uint16, wacn uint32) {
	f.mu.Lock()
	f.p2params++
	f.gotNAC = nac
	f.gotSYSID = sysid
	f.gotWACN = wacn
	f.mu.Unlock()
}
func (f *fakeVoice) StageDataSession(nac uint16, ccFreq, targetFreq, sourceID, groupID uint32, opcode uint8, uplink bool) {
	f.mu.Lock()
	f.dataStaged = true
	f.stagedNAC = nac
	f.stagedCCFreq = ccFreq
	f.stagedTargetFreq = targetFreq
	f.stagedSourceID = sourceID
	f.stagedGroupID = groupID
	f.stagedOpcode = opcode
	f.stagedUplink = uplink
	f.mu.Unlock()
}
func (f *fakeVoice) Freq() uint32 { return f.freq }

type fakeCC struct {
	mu           sync.Mutex
	tracker      *TrunkTracker
	freq         uint32
	nac          uint16
	lastActivity time.Time
}

type fakeDataUpsert struct {
	freq     uint32
	uplink   bool
	inWindow bool
}

func (f *fakeCC) SetTrunkTracker(t *TrunkTracker) { f.tracker = t }
func (f *fakeCC) TrunkSnapshot() []VoiceChannel   { return nil }
func (f *fakeCC) ObservedNAC() uint16 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nac
}
func (f *fakeCC) LastActivity() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastActivity
}
func (f *fakeCC) setLastActivity(t time.Time) {
	f.mu.Lock()
	f.lastActivity = t
	f.mu.Unlock()
}

type fakeHost struct {
	mu        sync.Mutex
	log       *slog.Logger
	inWin     func(uint32) bool
	idenSeed  map[uint8]IdenEntry
	vcSeed    []uint32
	dcSeed    []DataChannelSeed
	nextCCNAC uint16 // NAC stamped on the next spawned CC's ObservedNAC
	ccSpawns  int
	spawnedCC []uint32
	// ccByFreq holds every CC this host has spawned, keyed by freq; SpawnCC
	// stamps each with nextCCNAC so the RFSS supervisor can read distinct NACs.
	ccByFreq  map[uint32]*fakeCC
	despawned []uint32 // freqs passed to DespawnCC, in call order
	spawnedV  map[uint32]*fakeVoice
	// spawnedD records pipelines created via SpawnData (SNDCP data-bearer
	// grants). Parallel to spawnedV; tests assert that voice and data don't
	// double-allocate on the same freq.
	spawnedD map[uint32]*fakeVoice
	// spawnDataReturnsNil, when true, makes SpawnData return nil (modeling a
	// closed channelizer). Used by TestSystem_OnDataDiscover_SpawnDataNil.
	spawnDataReturnsNil bool
	upsertedVC          []Discovery
	upsertedDC          []fakeDataUpsert
	upsertedSt          []SiteUpdate
	upsertedPatch       []PatchUpdate
	// despawnHook, if set, is invoked synchronously at the start of DespawnCC
	// (before any lock) to model the real host joining the CC's decode-pump
	// goroutine — which re-enters the supervisor's onSiteDiscover under r.mu.
	// A test uses this to prove DespawnCC is never called while holding r.mu.
	despawnHook func(CCHandle)
}

func newFakeHost() *fakeHost {
	return &fakeHost{
		log:      slog.New(slog.DiscardHandler),
		inWin:    func(uint32) bool { return true },
		spawnedV: map[uint32]*fakeVoice{},
		spawnedD: map[uint32]*fakeVoice{},
		ccByFreq: map[uint32]*fakeCC{},
	}
}
func (h *fakeHost) SpawnCC(f uint32, _ uint16, _ string, _ float64, _ bool) CCHandle {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.spawnedCC = append(h.spawnedCC, f)
	h.ccSpawns++
	cc := &fakeCC{freq: f, nac: h.nextCCNAC}
	h.ccByFreq[f] = cc
	return cc
}
func (h *fakeHost) DespawnCC(cc CCHandle) {
	if h.despawnHook != nil {
		h.despawnHook(cc) // models the pump-goroutine join (before any host lock)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if fc, ok := cc.(*fakeCC); ok {
		h.despawned = append(h.despawned, fc.freq)
		delete(h.ccByFreq, fc.freq)
	}
}
func (h *fakeHost) setLastActivityFreq(freq uint32, t time.Time) {
	h.mu.Lock()
	cc := h.ccByFreq[freq]
	h.mu.Unlock()
	if cc != nil {
		cc.setLastActivity(t)
	}
}
func (h *fakeHost) SpawnVoice(f uint32, _ uint16, _ string, site uint8) VoiceHandle {
	h.mu.Lock()
	defer h.mu.Unlock()
	v := &fakeVoice{freq: f, site: site}
	h.spawnedV[f] = v
	return v
}

// SpawnData satisfies p25.Host. Returns a fresh fakeVoice keyed in spawnedD,
// or nil when spawnDataReturnsNil is set (modeling a closed channelizer).
func (h *fakeHost) SpawnData(f uint32, _ uint16, _ string, site uint8) VoiceHandle {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.spawnDataReturnsNil {
		return nil
	}
	v := &fakeVoice{freq: f, site: site}
	h.spawnedD[f] = v
	return v
}
func (h *fakeHost) InWindow(f uint32) bool { return h.inWin(f) }
func (h *fakeHost) UpsertVoiceChannel(d Discovery, _ bool) {
	h.mu.Lock()
	h.upsertedVC = append(h.upsertedVC, d)
	h.mu.Unlock()
}
func (h *fakeHost) UpsertDataChannel(_ uint16, freqHz uint32, uplink bool, inWindow bool) {
	h.mu.Lock()
	h.upsertedDC = append(h.upsertedDC, fakeDataUpsert{
		freq: freqHz, uplink: uplink, inWindow: inWindow,
	})
	h.mu.Unlock()
}
func (h *fakeHost) UpsertTrunkSite(s SiteUpdate) {
	h.mu.Lock()
	h.upsertedSt = append(h.upsertedSt, s)
	h.mu.Unlock()
}
func (h *fakeHost) UpsertTrunkPatch(u PatchUpdate) {
	h.mu.Lock()
	h.upsertedPatch = append(h.upsertedPatch, u)
	h.mu.Unlock()
}
func (h *fakeHost) LoadIdenTable(uint16) map[uint8]IdenEntry  { return h.idenSeed }
func (h *fakeHost) LoadVoiceChannels(uint16) []uint32         { return h.vcSeed }
func (h *fakeHost) LoadDataChannels(uint16) []DataChannelSeed { return h.dcSeed }
func (h *fakeHost) Log() *slog.Logger                         { return h.log }

func TestSystem_WarmStart(t *testing.T) {
	h := newFakeHost()
	h.vcSeed = []uint32{453_537_500, 460_612_500, 999_000_000}
	h.inWin = func(f uint32) bool { return f < 500_000_000 }
	s := NewSystem(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "T"}, h)
	s.Start()
	if len(h.spawnedCC) != 1 || h.spawnedCC[0] != 460_412_500 {
		t.Errorf("SpawnCC calls = %v, want [460412500]", h.spawnedCC)
	}
	if len(h.spawnedV) != 2 {
		t.Errorf("SpawnVoice count = %d, want 2", len(h.spawnedV))
	}
	if _, ok := h.spawnedV[999_000_000]; ok {
		t.Error("out-of-window 999 MHz should not be spawned")
	}
}

func TestSystem_WarmStartData(t *testing.T) {
	h := newFakeHost()
	h.dcSeed = []DataChannelSeed{
		{FreqHz: 453_537_500, Uplink: false},
		{FreqHz: 458_537_500, Uplink: true},
		{FreqHz: 999_000_000, Uplink: false},
	}
	h.inWin = func(f uint32) bool { return f < 500_000_000 }
	s := NewSystem(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "T"}, h)
	s.Start()
	if len(h.spawnedD) != 2 {
		t.Fatalf("SpawnData count = %d, want 2", len(h.spawnedD))
	}
	if h.spawnedD[453_537_500] == nil {
		t.Error("warm start must seed downlink data bearer")
	}
	if h.spawnedD[458_537_500] == nil {
		t.Error("warm start must seed uplink data bearer")
	}
	if h.spawnedD[999_000_000] != nil {
		t.Error("out-of-window 999 MHz data bearer should not be spawned")
	}
}

func TestSystem_DiscoverSpawnsOnce(t *testing.T) {
	h := newFakeHost()
	s := NewSystem(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "T"}, h)
	s.Start()
	d := Discovery{NAC: 0x171, FreqHz: 453_537_500, TDMASlots: 0, TGID: 5309, New: true}
	s.onDiscover(d)
	s.onDiscover(d)
	if len(h.spawnedV) != 1 {
		t.Fatalf("SpawnVoice count = %d, want 1", len(h.spawnedV))
	}
	v := h.spawnedV[453_537_500]
	if v.fdmaGrants != 2 {
		t.Errorf("fdmaGrants = %d, want 2", v.fdmaGrants)
	}
	// The FDMA grant must carry its talkgroup so analog/clear FM calls on a
	// trunk voice channel can be labeled even without in-band link control.
	if v.lastFDMATGID != 5309 {
		t.Errorf("lastFDMATGID = %d, want 5309", v.lastFDMATGID)
	}
}

func TestSystem_FDMAReassignClosesStaleSibling(t *testing.T) {
	h := newFakeHost()
	s := NewSystem(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "T"}, h)
	s.Start()
	freqA := uint32(453_537_500)
	freqB := uint32(453_437_500)
	// TG 5307 is granted on freqA: a call starts there.
	s.onDiscover(Discovery{NAC: 0x171, FreqHz: freqA, TGID: 5307, TDMASlots: 0, New: true})
	// The same TG is then granted on a DIFFERENT freq: the call moved. The stale
	// freqA pipeline must be told to wind down so it stops recording concurrently
	// with freqB (the same-CC "twin").
	s.onDiscover(Discovery{NAC: 0x171, FreqHz: freqB, TGID: 5307, TDMASlots: 0, New: true})

	vA := h.spawnedV[freqA]
	vB := h.spawnedV[freqB]
	if vA == nil || vB == nil {
		t.Fatalf("expected both freq pipelines spawned (A=%v B=%v)", vA, vB)
	}
	if got := vA.reassigns; got != 1 {
		t.Errorf("stale sibling freqA reassign-close count = %d, want 1", got)
	}
	if got := vA.lastReassignTG; got != 5307 {
		t.Errorf("stale sibling reassign talkgroup = %d, want 5307 (the moved TG)", got)
	}
	if got := vB.reassigns; got != 0 {
		t.Errorf("new-owner freqB reassign-close count = %d, want 0", got)
	}
}

func TestSystem_FDMAReassign_DifferentTGDoesNotClose(t *testing.T) {
	h := newFakeHost()
	s := NewSystem(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "T"}, h)
	s.Start()
	freqA := uint32(453_537_500)
	freqB := uint32(453_437_500)
	s.onDiscover(Discovery{NAC: 0x171, FreqHz: freqA, TGID: 5307, TDMASlots: 0, New: true})
	// A DIFFERENT talkgroup on another freq is an independent, concurrent call —
	// it must not disturb freqA.
	s.onDiscover(Discovery{NAC: 0x171, FreqHz: freqB, TGID: 6581, TDMASlots: 0, New: true})
	if got := h.spawnedV[freqA].reassigns; got != 0 {
		t.Errorf("different-TG grant closed freqA %d times, want 0", got)
	}
}

func TestSystem_FDMAReassign_SameFreqRegrantDoesNotSelfClose(t *testing.T) {
	h := newFakeHost()
	s := NewSystem(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "T"}, h)
	s.Start()
	freqA := uint32(453_537_500)
	// The CC re-announces the same active grant on the same freq many times; the
	// pipeline must never reassign-close itself.
	for i := 0; i < 3; i++ {
		s.onDiscover(Discovery{NAC: 0x171, FreqHz: freqA, TGID: 5307, TDMASlots: 0})
	}
	if got := h.spawnedV[freqA].reassigns; got != 0 {
		t.Errorf("same-freq re-grant self-closed freqA %d times, want 0", got)
	}
}

func TestSystem_TDMAGrantPrimesScramble(t *testing.T) {
	h := newFakeHost()
	s := NewSystem(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "T"}, h)
	s.Start()
	s.tracker.Apply(&TSBKData{Opcode: OpcodeNetworkStatusBcast, GroupID: 0xBEE00, SysID: 0x170})
	d := Discovery{NAC: 0x171, FreqHz: 453_537_500, TDMASlots: 2, TGID: 9019, SrcID: 1234}
	s.onDiscover(d)
	v := h.spawnedV[453_537_500]
	if v.tdmaGrants != 1 || v.lastTGID != 9019 {
		t.Errorf("tdmaGrants=%d lastTGID=%d, want 1/9019", v.tdmaGrants, v.lastTGID)
	}
	if v.p2params < 1 || v.gotWACN != 0xBEE00 || v.gotSYSID != 0x170 {
		t.Errorf("p2params=%d wacn=0x%X sysid=0x%X, want >=1/0xBEE00/0x170",
			v.p2params, v.gotWACN, v.gotSYSID)
	}
	before := v.p2params
	s.onDiscover(d)
	if v.p2params != before {
		t.Errorf("second grant should not re-prime: p2params went %d -> %d", before, v.p2params)
	}
}

func TestSystem_OutOfWindowGrant(t *testing.T) {
	h := newFakeHost()
	h.inWin = func(uint32) bool { return false }
	s := NewSystem(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "T"}, h)
	s.Start()
	s.onDiscover(Discovery{NAC: 0x171, FreqHz: 770_000_000})
	if len(h.spawnedV) != 0 {
		t.Errorf("out-of-window grant spawned %d voice pipelines, want 0", len(h.spawnedV))
	}
	if len(h.upsertedVC) != 1 {
		t.Errorf("UpsertVoiceChannel calls = %d, want 1", len(h.upsertedVC))
	}
}

func TestSystem_OnSitePushesScrambleToExisting(t *testing.T) {
	h := newFakeHost()
	h.vcSeed = []uint32{453_537_500, 460_612_500}
	s := NewSystem(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "T"}, h)
	s.Start()
	s.onSite(SiteUpdate{NAC: 0x171, SiteState: SiteState{WACN: 0xBEE00, SYSID: 0x170}})
	for f, v := range h.spawnedV {
		if v.p2params != 1 {
			t.Errorf("freq %d: p2params=%d, want 1", f, v.p2params)
		}
	}
	s.onSite(SiteUpdate{NAC: 0x171, SiteState: SiteState{WACN: 0xBEE00, SYSID: 0x170}})
	for f, v := range h.spawnedV {
		if v.p2params != 1 {
			t.Errorf("freq %d: p2params=%d after second onSite, want 1", f, v.p2params)
		}
	}
}

func TestSystem_DenyTGIDNotFollowed(t *testing.T) {
	h := newFakeHost()
	s := NewSystem(SystemDef{
		ControlFreq: 460_412_500, NAC: 0x176, Label: "Alderson",
		DenyTGIDs: []uint16{1234, 5678},
	}, h)
	s.Start()
	// Denied TG: discovered (upserted) but no voice pipeline spawned.
	s.onDiscover(Discovery{NAC: 0x176, FreqHz: 460_837_500, TGID: 1234, New: true})
	if len(h.spawnedV) != 0 {
		t.Errorf("denied TGID spawned %d voice pipelines, want 0", len(h.spawnedV))
	}
	if len(h.upsertedVC) != 1 {
		t.Errorf("denied TGID UpsertVoiceChannel calls = %d, want 1 (discovery still recorded)", len(h.upsertedVC))
	}
	// A non-denied TG on the same trunk is still followed.
	s.onDiscover(Discovery{NAC: 0x176, FreqHz: 460_862_500, TGID: 4321, New: true})
	if len(h.spawnedV) != 1 {
		t.Fatalf("allowed TGID spawned %d voice pipelines, want 1", len(h.spawnedV))
	}
	if _, ok := h.spawnedV[460_862_500]; !ok {
		t.Error("expected voice pipeline for allowed TGID on 460.8625")
	}
}

func TestSystem_AllowTGIDsWhitelist(t *testing.T) {
	h := newFakeHost()
	s := NewSystem(SystemDef{
		ControlFreq: 460_412_500, NAC: 0x176, Label: "Alderson",
		AllowTGIDs: []uint16{4321},
	}, h)
	s.Start()
	// Not on the whitelist: dropped.
	s.onDiscover(Discovery{NAC: 0x176, FreqHz: 460_837_500, TGID: 1234})
	if len(h.spawnedV) != 0 {
		t.Errorf("non-whitelisted TGID spawned %d pipelines, want 0", len(h.spawnedV))
	}
	// On the whitelist: followed.
	s.onDiscover(Discovery{NAC: 0x176, FreqHz: 460_862_500, TGID: 4321})
	if _, ok := h.spawnedV[460_862_500]; !ok {
		t.Error("whitelisted TGID 4321 should have spawned a voice pipeline")
	}
}

func TestSystem_DenyOverridesAllow(t *testing.T) {
	h := newFakeHost()
	s := NewSystem(SystemDef{
		ControlFreq: 460_412_500, NAC: 0x176, Label: "Alderson",
		AllowTGIDs: []uint16{4321},
		DenyTGIDs:  []uint16{4321},
	}, h)
	s.Start()
	s.onDiscover(Discovery{NAC: 0x176, FreqHz: 460_862_500, TGID: 4321})
	if len(h.spawnedV) != 0 {
		t.Errorf("deny must override allow: spawned %d pipelines, want 0", len(h.spawnedV))
	}
}

func TestSystem_NoFilterAllowsAll(t *testing.T) {
	h := newFakeHost()
	s := NewSystem(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "T"}, h)
	s.Start()
	s.onDiscover(Discovery{NAC: 0x171, FreqHz: 453_537_500, TGID: 5309})
	if _, ok := h.spawnedV[453_537_500]; !ok {
		t.Error("with no filter configured, all TGIDs should be followed")
	}
}

func TestSystem_UnitToUnitBypassesAllowList(t *testing.T) {
	h := newFakeHost()
	s := NewSystem(SystemDef{
		ControlFreq: 460_412_500, NAC: 0x176, Label: "T",
		AllowTGIDs: []uint16{4321},
	}, h)
	s.Start()
	// Unit-to-unit grant with TGID=0 should bypass the allow-list.
	s.onDiscover(Discovery{
		NAC: 0x176, FreqHz: 460_862_500, TGID: 0,
		SrcID: 0x1234, DestID: 0xABCD, UnitToUnit: true, New: true,
	})
	v, ok := h.spawnedV[460_862_500]
	if !ok {
		t.Fatal("unit-to-unit grant did not spawn voice pipeline despite allow-list")
	}
	// A private call drives NotifyUnitGrant with the calling-radio source, not
	// NotifyFDMAGrant (which carries a talkgroup the private call lacks).
	if v.unitGrants != 1 || v.lastUnitSrc != 0x1234 {
		t.Errorf("unitGrants=%d lastUnitSrc=0x%X, want 1/0x1234", v.unitGrants, v.lastUnitSrc)
	}
	if v.fdmaGrants != 0 {
		t.Errorf("fdmaGrants=%d, want 0 (private call must not use FDMA-grant talkgroup path)", v.fdmaGrants)
	}
}

func TestSystem_CCFreqNotSpawnedAsVoice(t *testing.T) {
	h := newFakeHost()
	h.vcSeed = []uint32{460_412_500, 453_537_500}
	s := NewSystem(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "T"}, h)
	s.Start()
	if _, ok := h.spawnedV[460_412_500]; ok {
		t.Error("CC freq should not be spawned as voice")
	}
	s.onDiscover(Discovery{NAC: 0x171, FreqHz: 460_412_500})
	if _, ok := h.spawnedV[460_412_500]; ok {
		t.Error("grant on CC freq should not spawn voice")
	}
}

func TestSystem_SiteDiscoverDedupsLogging(t *testing.T) {
	var buf bytes.Buffer
	h := newFakeHost()
	h.log = slog.New(slog.NewJSONHandler(&buf, nil))
	s := NewSystem(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "T"}, h)

	site40 := SiteDiscovery{SysID: 368, RFSS: 2, Site: 40, CCFreq: 460_587_500, Active: true}
	s.onSiteDiscover(site40) // new → log
	s.onSiteDiscover(site40) // unchanged → suppress
	s.onSiteDiscover(site40) // unchanged → suppress

	site26 := SiteDiscovery{SysID: 368, RFSS: 2, Site: 26, CCFreq: 460_862_500, Active: true}
	s.onSiteDiscover(site26) // different site → log

	site40.Failed = true // same site, changed flags → log
	s.onSiteDiscover(site40)
	s.onSiteDiscover(site40) // unchanged again → suppress

	got := strings.Count(buf.String(), `"trunk site advertised"`)
	if got != 3 {
		t.Errorf("logged %d site-advertised lines, want 3 (site40 new, site26 new, site40 flag-change)", got)
	}
}

func TestSystem_StartWithCC_AdoptsHandle(t *testing.T) {
	host := newFakeHost()
	pre := host.SpawnCC(460_862_500, 0x176, "pre", 12500, false)
	sys := NewSystem(SystemDef{ControlFreq: 460_862_500, NAC: 0x176, Label: "S26"}, host)
	sys.StartWithCC(pre)
	if sys.CC() != pre {
		t.Errorf("StartWithCC did not adopt the provided handle")
	}
	if host.ccSpawns != 1 { // only the manual SpawnCC above; StartWithCC must NOT spawn another
		t.Errorf("ccSpawns = %d, want 1 (no extra spawn)", host.ccSpawns)
	}
}

func TestSystem_SiteObserver_Fires(t *testing.T) {
	host := newFakeHost()
	sys := NewSystem(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "S41"}, host)
	var seen []SiteDiscovery
	sys.SetSiteObserver(func(d SiteDiscovery) { seen = append(seen, d) })
	sys.Start()
	sys.onSiteDiscover(SiteDiscovery{Site: 26, CCFreq: 460_862_500, Active: true})
	if len(seen) != 1 || seen[0].Site != 26 {
		t.Fatalf("observer got %+v, want one site 26", seen)
	}
}

func TestSystem_SpawnVoiceCarriesSite(t *testing.T) {
	h := newFakeHost()
	s := NewSystem(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "S41"}, h)
	s.Start()
	// RFSS_STS sets this tracker's own site number; voice spawns must carry it.
	s.tracker.Apply(&TSBKData{Opcode: OpcodeRFSSStatusBcast, SysID: 368, RFSS: 2, Site: 41})
	if _, _, site := s.tracker.Site(); site != 41 {
		t.Fatalf("precondition: tracker.Site() = %d, want 41", site)
	}
	s.onDiscover(Discovery{NAC: 0x171, FreqHz: 453_537_500, TGID: 100})
	v := h.spawnedV[453_537_500]
	if v == nil {
		t.Fatal("expected a spawned voice pipeline")
	}
	if v.site != 41 {
		t.Errorf("spawned voice site = %d, want 41 (from tracker RFSS_STS)", v.site)
	}
}

// TestSystem_OnDataDiscover_DedupAndMultiFreq exercises the System-level data
// pipeline lifecycle: 0x14 grants spawn one pipeline per freq, and retransmits
// keep that single pipeline alive via NotifyGrant rather than re-spawning.
func TestSystem_OnDataDiscover_DedupAndMultiFreq(t *testing.T) {
	h := newFakeHost()
	s := NewSystem(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "T"}, h)
	s.Start()

	freqA := uint32(453_537_500)
	freqB := uint32(453_550_000)

	// First grant on A: 1 SpawnData, 1 NotifyGrant.
	s.onDataDiscover(DataDiscovery{NAC: 0x171, FreqHz: freqA, SourceID: 0x111, GroupID: 0xABCD,
		Opcode: uint8(OpcodeGroupDataGrant)})
	if len(h.spawnedD) != 1 {
		t.Fatalf("after 1st A grant: SpawnData count = %d, want 1", len(h.spawnedD))
	}
	vA := h.spawnedD[freqA]
	if vA == nil {
		t.Fatalf("after 1st A grant: no fakeVoice keyed at freqA")
	}
	if vA.grants != 1 {
		t.Errorf("after 1st A grant: NotifyGrant count = %d, want 1", vA.grants)
	}

	// Second grant on A: still 1 SpawnData (de-duped), 2 NotifyGrants.
	s.onDataDiscover(DataDiscovery{NAC: 0x171, FreqHz: freqA, SourceID: 0x111, GroupID: 0xABCD,
		Opcode: uint8(OpcodeGroupDataGrant)})
	if len(h.spawnedD) != 1 {
		t.Errorf("after 2nd A grant: SpawnData count = %d, want 1 (de-dup)", len(h.spawnedD))
	}
	if vA.grants != 2 {
		t.Errorf("after 2nd A grant: NotifyGrant count = %d, want 2", vA.grants)
	}

	// Grant on B: 2 SpawnData total, 3 NotifyGrants total (1 on B, 2 on A).
	s.onDataDiscover(DataDiscovery{NAC: 0x171, FreqHz: freqB, SourceID: 0x222, GroupID: 0xBEEF,
		Opcode: uint8(OpcodeGroupDataGrant)})
	if len(h.spawnedD) != 2 {
		t.Errorf("after B grant: SpawnData count = %d, want 2", len(h.spawnedD))
	}
	vB := h.spawnedD[freqB]
	if vB == nil {
		t.Fatal("after B grant: no fakeVoice keyed at freqB")
	}
	if total := vA.grants + vB.grants; total != 3 {
		t.Errorf("total NotifyGrant = %d, want 3 (A=2, B=1); got A=%d B=%d",
			total, vA.grants, vB.grants)
	}
}

func TestSystem_OnDataDiscover_PersistsBearers(t *testing.T) {
	h := newFakeHost()
	s := NewSystem(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "T"}, h)
	s.Start()

	s.onDataDiscover(DataDiscovery{
		NAC: 0x171, FreqHz: 453_537_500, UplinkHz: 458_537_500,
		SourceID: 0x111, GroupID: 0xABCD, Opcode: uint8(OpcodeGroupDataGrant),
	})

	if len(h.upsertedDC) != 2 {
		t.Fatalf("UpsertDataChannel calls = %d, want 2 (downlink + uplink)", len(h.upsertedDC))
	}
	if got := h.upsertedDC[0]; got.freq != 453_537_500 || got.uplink || !got.inWindow {
		t.Errorf("first upsert = %+v, want downlink 453537500 in-window", got)
	}
	if got := h.upsertedDC[1]; got.freq != 458_537_500 || !got.uplink || !got.inWindow {
		t.Errorf("second upsert = %+v, want uplink 458537500 in-window", got)
	}
}

// TestSystem_DataHandles_ReturnsSpawnedBearersSorted verifies DataHandles()
// exposes the data-bearer pipelines spawned by 0x14 grants, sorted by freq,
// the same way VoiceHandles() exposes voice pipelines.
func TestSystem_DataHandles_ReturnsSpawnedBearersSorted(t *testing.T) {
	h := newFakeHost()
	s := NewSystem(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "T"}, h)
	s.Start()

	// Grant on the higher freq first, then the lower, to prove sorting.
	s.onDataDiscover(DataDiscovery{NAC: 0x171, FreqHz: 453_550_000, SourceID: 0x222,
		GroupID: 0xBEEF, Opcode: uint8(OpcodeGroupDataGrant)})
	s.onDataDiscover(DataDiscovery{NAC: 0x171, FreqHz: 453_537_500, SourceID: 0x111,
		GroupID: 0xABCD, Opcode: uint8(OpcodeGroupDataGrant)})

	dh := s.DataHandles()
	if len(dh) != 2 {
		t.Fatalf("DataHandles() len = %d, want 2", len(dh))
	}
	if dh[0].Freq() != 453_537_500 || dh[1].Freq() != 453_550_000 {
		t.Errorf("DataHandles() not sorted by freq: got %d, %d", dh[0].Freq(), dh[1].Freq())
	}

	// A system with no data grants returns an empty (non-nil-panicking) slice.
	s2 := NewSystem(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "T2"}, newFakeHost())
	s2.Start()
	if dh2 := s2.DataHandles(); len(dh2) != 0 {
		t.Errorf("DataHandles() on idle system len = %d, want 0", len(dh2))
	}
}

// TestSystem_OnDataDiscover_CoexistsWithVoice verifies voice/data coexistence:
// on this system the SNDCP data bearers reuse voice-pool frequencies, so a data
// grant on a freq already owned by a voice pipeline must spawn a *coexisting*
// data pipeline (the host can fan one channel out to both) rather than being
// dropped. The data pipeline's own grant-gated capture keeps it from recording
// the voice traffic that shares the freq. The voice pipeline is left untouched
// by the data grant.
func TestSystem_OnDataDiscover_CoexistsWithVoice(t *testing.T) {
	h := newFakeHost()
	s := NewSystem(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "T"}, h)
	s.Start()

	freq := uint32(453_537_500)
	// Establish voice on this freq first.
	s.onDiscover(Discovery{NAC: 0x171, FreqHz: freq, TGID: 100})
	if len(h.spawnedV) != 1 {
		t.Fatalf("precondition: SpawnVoice count = %d, want 1", len(h.spawnedV))
	}
	voiceGrants := h.spawnedV[freq].grants

	// SNDCP grant on the same freq now spawns a coexisting data pipeline.
	s.onDataDiscover(DataDiscovery{NAC: 0x171, FreqHz: freq, SourceID: 0x111, GroupID: 0xABCD,
		Opcode: uint8(OpcodeGroupDataGrant)})
	if len(h.spawnedD) != 1 {
		t.Fatalf("coexist: SpawnData count = %d, want 1", len(h.spawnedD))
	}
	if h.spawnedD[freq] == nil {
		t.Fatal("coexist: no data pipeline keyed at the voice-owned freq")
	}
	if h.spawnedD[freq].grants != 1 {
		t.Errorf("coexist: data NotifyGrant = %d, want 1", h.spawnedD[freq].grants)
	}
	// The voice pipeline must be left untouched by the data grant.
	if h.spawnedV[freq].grants != voiceGrants {
		t.Errorf("coexist: voice NotifyGrant changed %d -> %d (data grant must not touch voice)",
			voiceGrants, h.spawnedV[freq].grants)
	}
}

// TestSystem_OnDataDiscover_StagesGrantMetadata verifies that onDataDiscover
// threads the SNDCP grant metadata onto the data pipeline (via StageDataSession)
// so the corpus capture is stamped with the NAC / CC freq / target freq /
// source / group / opcode instead of zero-valued placeholders.
func TestSystem_OnDataDiscover_StagesGrantMetadata(t *testing.T) {
	h := newFakeHost()
	cc := uint32(460_412_500)
	s := NewSystem(SystemDef{ControlFreq: cc, NAC: 0x176, Label: "T"}, h)
	s.Start()

	freq := uint32(461_912_500)
	s.onDataDiscover(DataDiscovery{NAC: 0x176, FreqHz: freq, SourceID: 0xABCDEF,
		GroupID: 0x4321, Opcode: uint8(OpcodeGroupDataGrant)})

	v := h.spawnedD[freq]
	if v == nil {
		t.Fatal("no data pipeline spawned for the grant")
	}
	if !v.dataStaged {
		t.Fatal("StageDataSession was not called on the data pipeline")
	}
	if v.stagedNAC != 0x176 {
		t.Errorf("staged nac = %#x, want 0x176", v.stagedNAC)
	}
	if v.stagedCCFreq != cc {
		t.Errorf("staged ccFreq = %d, want %d", v.stagedCCFreq, cc)
	}
	if v.stagedTargetFreq != freq {
		t.Errorf("staged targetFreq = %d, want %d", v.stagedTargetFreq, freq)
	}
	if v.stagedSourceID != 0xABCDEF {
		t.Errorf("staged sourceID = %#x, want 0xABCDEF", v.stagedSourceID)
	}
	if v.stagedGroupID != 0x4321 {
		t.Errorf("staged groupID = %#x, want 0x4321", v.stagedGroupID)
	}
	if v.stagedOpcode != uint8(OpcodeGroupDataGrant) {
		t.Errorf("staged opcode = %#x, want %#x", v.stagedOpcode, uint8(OpcodeGroupDataGrant))
	}
}

// TestSystem_OnDataDiscover_SpawnsUplink verifies that a data grant carrying a
// resolved UplinkHz spawns TWO freq-keyed pipelines (downlink + uplink), stages
// each with the matching targetFreq and uplink flag, and that a retransmit
// refreshes both without re-spawning either.
func TestSystem_OnDataDiscover_SpawnsUplink(t *testing.T) {
	h := newFakeHost()
	cc := uint32(460_412_500)
	s := NewSystem(SystemDef{ControlFreq: cc, NAC: 0x176, Label: "T"}, h)
	s.Start()

	dl := uint32(461_912_500)
	ul := dl + 5_000_000 // 466.9125 MHz
	d := DataDiscovery{NAC: 0x176, FreqHz: dl, UplinkHz: ul, SourceID: 0xABCDEF,
		GroupID: 0x4321, Opcode: uint8(OpcodeGroupDataGrant)}
	s.onDataDiscover(d)

	if len(h.spawnedD) != 2 {
		t.Fatalf("SpawnData count = %d, want 2 (downlink + uplink)", len(h.spawnedD))
	}
	down, up := h.spawnedD[dl], h.spawnedD[ul]
	if down == nil || up == nil {
		t.Fatalf("missing pipeline: downlink=%v uplink=%v", down != nil, up != nil)
	}
	if down.stagedUplink {
		t.Error("downlink pipeline staged with uplink=true")
	}
	if !up.stagedUplink {
		t.Error("uplink pipeline staged with uplink=false")
	}
	if up.stagedTargetFreq != ul {
		t.Errorf("uplink staged targetFreq = %d, want %d", up.stagedTargetFreq, ul)
	}
	if down.grants != 1 || up.grants != 1 {
		t.Errorf("first grant: NotifyGrant down=%d up=%d, want 1/1", down.grants, up.grants)
	}

	// Retransmit: de-dup keeps both pipelines, extends both grants, no new spawn.
	s.onDataDiscover(d)
	if len(h.spawnedD) != 2 {
		t.Errorf("after retransmit: SpawnData count = %d, want 2 (de-dup)", len(h.spawnedD))
	}
	if down.grants != 2 || up.grants != 2 {
		t.Errorf("after retransmit: NotifyGrant down=%d up=%d, want 2/2", down.grants, up.grants)
	}
}

// TestSystem_OnDataDiscover_UplinkOutOfWindow verifies that an out-of-window
// uplink is skipped while the in-window downlink still spawns.
func TestSystem_OnDataDiscover_UplinkOutOfWindow(t *testing.T) {
	h := newFakeHost()
	h.inWin = func(f uint32) bool { return f < 465_000_000 }
	cc := uint32(460_412_500)
	s := NewSystem(SystemDef{ControlFreq: cc, NAC: 0x176, Label: "T"}, h)
	s.Start()

	dl := uint32(461_912_500)
	ul := dl + 5_000_000 // 466.9125 MHz -> out of window
	s.onDataDiscover(DataDiscovery{NAC: 0x176, FreqHz: dl, UplinkHz: ul,
		GroupID: 0x4321, Opcode: uint8(OpcodeGroupDataGrant)})

	if len(h.spawnedD) != 1 {
		t.Fatalf("SpawnData count = %d, want 1 (downlink only; uplink out of window)", len(h.spawnedD))
	}
	if h.spawnedD[dl] == nil {
		t.Error("downlink pipeline missing")
	}
	if h.spawnedD[ul] != nil {
		t.Error("out-of-window uplink pipeline must not spawn")
	}
}

// TestSystem_OnDataDiscover_SkipsOutOfWindowAndCC verifies the early-return
// guards: data grants outside InWindow or for the CC freq itself spawn nothing.
func TestSystem_OnDataDiscover_SkipsOutOfWindowAndCC(t *testing.T) {
	h := newFakeHost()
	h.inWin = func(f uint32) bool { return f < 500_000_000 }
	cc := uint32(460_412_500)
	s := NewSystem(SystemDef{ControlFreq: cc, NAC: 0x171, Label: "T"}, h)
	s.Start()

	// Out-of-window: not spawned.
	s.onDataDiscover(DataDiscovery{NAC: 0x171, FreqHz: 770_000_000, GroupID: 0xABCD,
		Opcode: uint8(OpcodeGroupDataGrant)})
	if len(h.spawnedD) != 0 {
		t.Errorf("out-of-window: SpawnData count = %d, want 0", len(h.spawnedD))
	}

	// CC freq: not spawned even though InWindow returns true.
	s.onDataDiscover(DataDiscovery{NAC: 0x171, FreqHz: cc, GroupID: 0xABCD,
		Opcode: uint8(OpcodeGroupDataGrant)})
	if len(h.spawnedD) != 0 {
		t.Errorf("CC freq: SpawnData count = %d, want 0", len(h.spawnedD))
	}
}

// TestSystem_OnDataDiscover_SpawnDataNil verifies the nil-handle guard: when
// Host.SpawnData returns nil (channelizer closed), the freq is NOT cached in
// s.data so the next grant retries cleanly.
func TestSystem_OnDataDiscover_SpawnDataNil(t *testing.T) {
	var buf bytes.Buffer
	h := newFakeHost()
	h.log = slog.New(slog.NewJSONHandler(&buf, nil))
	h.spawnDataReturnsNil = true
	s := NewSystem(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "T"}, h)
	s.Start()

	s.onDataDiscover(DataDiscovery{NAC: 0x171, FreqHz: 453_537_500, GroupID: 0xABCD,
		Opcode: uint8(OpcodeGroupDataGrant)})
	if len(h.spawnedD) != 0 {
		t.Errorf("nil SpawnData: spawnedD count = %d, want 0", len(h.spawnedD))
	}
	if !strings.Contains(buf.String(), "SpawnData returned nil") {
		t.Errorf("nil SpawnData: warning log not emitted; buf=%s", buf.String())
	}
	// Retry succeeds after the channelizer recovers.
	h.mu.Lock()
	h.spawnDataReturnsNil = false
	h.mu.Unlock()
	s.onDataDiscover(DataDiscovery{NAC: 0x171, FreqHz: 453_537_500, GroupID: 0xABCD,
		Opcode: uint8(OpcodeGroupDataGrant)})
	if len(h.spawnedD) != 1 {
		t.Errorf("after recovery: spawnedD count = %d, want 1", len(h.spawnedD))
	}
}

// TestSystem_GRGAddUpsertsPatch verifies the onPatch -> UpsertTrunkPatch wiring:
// a Group Regroup ADD flowing through the tracker fires the patch handler, which
// must persist the current patch set via Host.UpsertTrunkPatch.
func TestSystem_GRGAddUpsertsPatch(t *testing.T) {
	h := newFakeHost()
	s := NewSystem(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "T"}, h)
	s.Start()

	add := &TSBKData{Opcode: OpcodeMotGRGAdd, MFID: 0x90, SuperGroup: 5105}
	add.PatchGroups[0], add.PatchGroups[1] = 5103, 5104
	add.PatchGroupN = 2
	s.tracker.Apply(add)

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.upsertedPatch) != 1 {
		t.Fatalf("UpsertTrunkPatch calls = %d, want 1", len(h.upsertedPatch))
	}
	u := h.upsertedPatch[0]
	if u.NAC != 0x171 {
		t.Errorf("upserted patch NAC = %#x, want 0x171", u.NAC)
	}
	if len(u.Active) != 1 || u.Active[0].SuperGroup != 5105 {
		t.Fatalf("upserted patch Active = %+v, want one supergroup 5105", u.Active)
	}
	if got := u.Active[0].Members; len(got) != 2 || got[0] != 5103 || got[1] != 5104 {
		t.Errorf("upserted patch members = %v, want [5103 5104]", got)
	}
}
