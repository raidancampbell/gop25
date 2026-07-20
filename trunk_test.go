package p25

import (
	"testing"
	"time"
)

func TestTrunkTracker_ChannelToHz(t *testing.T) {
	tt := NewTrunkTracker(0x123, nil, nil)
	tt.SeedIden(map[uint8]IdenEntry{
		1: {BaseHz: 450_000_000, StepHz: 12_500},
	})
	got, ok := tt.ChannelToHz(0x100A) // iden=1 ch=10
	if !ok || got != 450_125_000 {
		t.Fatalf("want 450125000/true, got %d/%v", got, ok)
	}
	if _, ok := tt.ChannelToHz(0x200A); ok {
		t.Fatal("iden 2 not seeded; want ok=false")
	}
}

func TestTrunkTracker_ChannelToHz_TDMA(t *testing.T) {
	tt := NewTrunkTracker(0, nil, nil)
	tt.SeedIden(map[uint8]IdenEntry{
		3: {BaseHz: 770_000_000, StepHz: 12_500, TDMASlots: 2},
	})
	// ch=10, slots=2 -> base + step*(10/2) = +62500
	got, _ := tt.ChannelToHz(0x300A)
	if got != 770_062_500 {
		t.Fatalf("want 770062500, got %d", got)
	}
}

// TestTrunkTracker_TDMASlotChanNum guards against the bug where grantLocked
// returned the cached (first-seen) channel number for every grant on a shared
// Phase 2 TDMA frequency. Both slots map to the same RF frequency, so a grant
// for slot 1 (odd chnum) must still report its own channel number so downstream
// slot mapping (chanNum & (slots-1)) routes per-slot metadata correctly.
func TestTrunkTracker_TDMASlotChanNum(t *testing.T) {
	var fired []Discovery
	tt := NewTrunkTracker(0x123, func(d Discovery) { fired = append(fired, d) }, nil)
	tt.SeedIden(map[uint8]IdenEntry{
		3: {BaseHz: 770_000_000, StepHz: 12_500, TDMASlots: 2},
	})
	// Slot 0: chnum 0x300A (LSB 0). Slot 1: chnum 0x300B (LSB 1). Both resolve to
	// the same frequency (10/2 == 11/2).
	d0 := tt.Apply(&TSBKData{Opcode: OpcodeGroupVoiceGrant, ChannelID: 0x300A, GroupID: 100, SourceID: 1})
	d1 := tt.Apply(&TSBKData{Opcode: OpcodeGroupVoiceGrant, ChannelID: 0x300B, GroupID: 200, SourceID: 2})
	if d0 == nil || d1 == nil {
		t.Fatalf("both grants should resolve: d0=%+v d1=%+v", d0, d1)
	}
	if d0.FreqHz != d1.FreqHz {
		t.Fatalf("both TDMA slots must share one frequency: %d vs %d", d0.FreqHz, d1.FreqHz)
	}
	if d0.ChanNum != 0x00A {
		t.Errorf("slot-0 ChanNum: want 0x00A, got 0x%03X", d0.ChanNum)
	}
	if d1.ChanNum != 0x00B {
		t.Errorf("slot-1 ChanNum: want 0x00B (its own, not the cached slot-0 value), got 0x%03X", d1.ChanNum)
	}
	// LSB (physical slot) must differ so tdmaGrantSlot routes them to distinct slots.
	if d0.ChanNum&1 == d1.ChanNum&1 {
		t.Errorf("slot LSBs must differ: d0=0x%03X d1=0x%03X", d0.ChanNum, d1.ChanNum)
	}
}

func TestTrunkTracker_Apply_GrantBeforeIden(t *testing.T) {
	tt := NewTrunkTracker(0x123, nil, nil)
	grant := &TSBKData{Opcode: OpcodeGroupVoiceGrant, ChannelID: 0x100A, GroupID: 100, SourceID: 12345}
	if d := tt.Apply(grant); d != nil {
		t.Fatal("expected nil discovery before iden table populated")
	}
	tt.Apply(&TSBKData{Opcode: OpcodeIdenUpVU, Iden: 1, BaseFreqHz: 450_000_000, SpacingHz: 12_500})
	d := tt.Apply(grant)
	if d == nil || d.FreqHz != 450_125_000 {
		t.Fatalf("expected resolved 450125000, got %+v", d)
	}
}

func TestTrunkTracker_Discovery_NewVsRepeat(t *testing.T) {
	var fired []Discovery
	tt := NewTrunkTracker(0x123, func(d Discovery) { fired = append(fired, d) }, nil)
	tt.Apply(&TSBKData{Opcode: OpcodeIdenUp, Iden: 1, BaseFreqHz: 450_000_000, SpacingHz: 12_500})
	g := &TSBKData{Opcode: OpcodeGroupVoiceGrant, ChannelID: 0x100A, GroupID: 100, SourceID: 1}

	d1 := tt.Apply(g)
	if d1 == nil || !d1.New {
		t.Fatalf("first grant: want New=true, got %+v", d1)
	}
	d2 := tt.Apply(g)
	if d2 == nil || d2.New {
		t.Fatalf("second grant: want New=false, got %+v", d2)
	}
	snap := tt.Snapshot()
	if len(snap) != 1 || snap[0].GrantCount != 2 {
		t.Fatalf("snapshot: want 1 vc with GrantCount=2, got %+v", snap)
	}
	if len(fired) != 2 {
		t.Fatalf("onDiscover: want 2 calls, got %d", len(fired))
	}
	if !snap[0].FirstSeen.Before(time.Now().Add(time.Second)) {
		t.Fatal("FirstSeen not set")
	}
}

func TestTrunkTracker_GrantUpdate_TwoChannels(t *testing.T) {
	tt := NewTrunkTracker(0, nil, nil)
	tt.Apply(&TSBKData{Opcode: OpcodeIdenUp, Iden: 1, BaseFreqHz: 450_000_000, SpacingHz: 12_500})
	tt.Apply(&TSBKData{
		Opcode:    OpcodeGroupVoiceGrantUpdate,
		ChannelID: 0x1004, GroupID: 50,
		ChannelID2: 0x1008, GroupID2: 60,
	})
	snap := tt.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("want 2 voice channels, got %d: %+v", len(snap), snap)
	}
}

func TestTrunkTracker_SiteChangeDetection(t *testing.T) {
	var fired []SiteUpdate
	tt := NewTrunkTracker(0x171, nil, func(s SiteUpdate) { fired = append(fired, s) })

	mk := func(op TSBKOpcode, mut func(*TSBKData)) *TSBKData {
		d := &TSBKData{Opcode: op, MFID: 0x90}
		mut(d)
		return d
	}

	// MotAltField: same value twice -> one fire; new value -> second fire.
	tt.Apply(mk(OpcodeMotLoadPct, func(d *TSBKData) { d.MotAltField = 55 }))
	tt.Apply(mk(OpcodeMotLoadPct, func(d *TSBKData) { d.MotAltField = 55 }))
	if len(fired) != 1 || fired[0].LoadPct != 55 || !fired[0].HaveLoadPct {
		t.Fatalf("after 2x load=55: want 1 fire load=55, got %+v", fired)
	}
	tt.Apply(mk(OpcodeMotLoadPct, func(d *TSBKData) { d.MotAltField = 60 }))
	if len(fired) != 2 || fired[1].LoadPct != 60 {
		t.Fatalf("after load=60: want 2 fires, got %+v", fired)
	}

	// SiteFlags: same value twice -> one (additional) fire.
	tt.Apply(mk(OpcodeMotSiteFlags, func(d *TSBKData) { d.SiteFlags = 0x4000C00000000800 }))
	tt.Apply(mk(OpcodeMotSiteFlags, func(d *TSBKData) { d.SiteFlags = 0x4000C00000000800 }))
	if len(fired) != 3 || !fired[2].HaveSiteFlags {
		t.Fatalf("after 2x siteflags: want 3 fires total, got %d", len(fired))
	}

	// BSI: empty-BSI advertises ch only -> fire; non-empty -> fire with callsign.
	tt.Apply(mk(OpcodeMotBSI, func(d *TSBKData) { d.ChannelID = 0x3682 }))
	if len(fired) != 4 || fired[3].BSIChannelID != 0x3682 || fired[3].Callsign != "" {
		t.Fatalf("after empty BSI: want 4 fires ch=0x3682, got %+v", fired)
	}
	tt.Apply(mk(OpcodeMotBSI, func(d *TSBKData) { d.Callsign = "WPWB991"; d.ChannelID = 0x36A2 }))
	if len(fired) != 5 || fired[4].Callsign != "WPWB991" || fired[4].BSIChannelID != 0x36A2 {
		t.Fatalf("after WPWB991: want 5 fires, got %+v", fired)
	}
	// Repeat identical BSI -> no fire.
	tt.Apply(mk(OpcodeMotBSI, func(d *TSBKData) { d.Callsign = "WPWB991"; d.ChannelID = 0x36A2 }))
	if len(fired) != 5 {
		t.Fatalf("repeat BSI must not fire: got %d", len(fired))
	}

	// Non-Motorola 0x0B must not fire.
	tt.Apply(&TSBKData{Opcode: OpcodeMotBSI, MFID: 0x00, ChannelID: 0xDEAD})
	if len(fired) != 5 {
		t.Fatalf("MFID00 op0x0B must not fire: got %d", len(fired))
	}

	if fired[4].NAC != 0x171 {
		t.Errorf("NAC: want 0x171, got 0x%X", fired[4].NAC)
	}
}

func TestTrunkTracker_Patch_AddDelExpire(t *testing.T) {
	var fired []PatchUpdate
	tt := NewTrunkTracker(0x171, nil, nil)
	tt.SetPatchHandler(func(u PatchUpdate) { fired = append(fired, u) })

	add := func(sg uint16, members ...uint16) *TSBKData {
		d := &TSBKData{Opcode: OpcodeMotGRGAdd, MFID: 0x90, SuperGroup: sg}
		for _, m := range members {
			d.PatchGroups[d.PatchGroupN] = m
			d.PatchGroupN++
		}
		return d
	}

	// ADD supergroup 5105 with two members.
	tt.Apply(add(5105, 5103, 5104))
	if len(fired) != 1 {
		t.Fatalf("after add: want 1 fire, got %d", len(fired))
	}
	ps := tt.GetPatches()
	if len(ps) != 1 || ps[0].SuperGroup != 5105 {
		t.Fatalf("after add: want supergroup 5105, got %+v", ps)
	}
	if len(ps[0].Members) != 2 || ps[0].Members[0] != 5103 || ps[0].Members[1] != 5104 {
		t.Fatalf("members: want [5103 5104], got %v", ps[0].Members)
	}

	// Identical ADD -> no additional fire (membership unchanged).
	tt.Apply(add(5105, 5103, 5104))
	if len(fired) != 1 {
		t.Fatalf("identical add must not fire: got %d", len(fired))
	}

	// DEL a member -> membership changes -> fire.
	del := &TSBKData{Opcode: OpcodeMotGRGDel, MFID: 0x90, SuperGroup: 5105}
	del.PatchGroups[0] = 5103
	del.PatchGroupN = 1
	tt.Apply(del)
	if len(fired) != 2 {
		t.Fatalf("after del: want 2 fires, got %d", len(fired))
	}
	ps = tt.GetPatches()
	if len(ps) != 1 || len(ps[0].Members) != 1 || ps[0].Members[0] != 5104 {
		t.Fatalf("after del 5103: want members [5104], got %+v", ps)
	}

	// DEL the last member -> supergroup dropped entirely.
	del2 := &TSBKData{Opcode: OpcodeMotGRGDel, MFID: 0x90, SuperGroup: 5105}
	del2.PatchGroups[0] = 5104
	del2.PatchGroupN = 1
	tt.Apply(del2)
	if len(tt.GetPatches()) != 0 {
		t.Fatalf("after del last member: want 0 patches, got %+v", tt.GetPatches())
	}

	// Expiry: an ADD whose Updated is old is filtered out by GetPatches.
	tt.Apply(add(6000, 6001))
	tt.mu.Lock()
	tt.patches[6000].Updated = time.Now().Add(-2 * patchExpiry)
	tt.mu.Unlock()
	if got := tt.GetPatches(); len(got) != 0 {
		t.Fatalf("stale patch must expire: got %+v", got)
	}
}

// TestTrunkTracker_Patch_RealTeardownDrops proves the real on-air teardown
// path: the DEL frame names the supergroup as its own members (sg=5105,
// members=[5105,5105,5105]) rather than the actual member talkgroups. The
// parser drops those self-referential sentinels (g==sg), so patchDelLocked
// receives an empty member list and tears down the whole supergroup
// immediately -- WITHOUT waiting for patchExpiry.
func TestTrunkTracker_Patch_RealTeardownDrops(t *testing.T) {
	tt := NewTrunkTracker(0x171, nil, nil)

	// Build a DEL exactly as parseTSBKArgs would: filter g==0 || g==sg. This
	// mirrors the on-air 13F113F113F113F1 vector (sg=5105, all members=5105).
	teardown := func(sg uint16, rawMembers ...uint16) *TSBKData {
		d := &TSBKData{Opcode: OpcodeMotGRGDel, MFID: 0x90, SuperGroup: sg}
		for _, m := range rawMembers {
			if m == 0 || m == sg {
				continue
			}
			d.PatchGroups[d.PatchGroupN] = m
			d.PatchGroupN++
		}
		return d
	}
	add := func(sg uint16, members ...uint16) *TSBKData {
		d := &TSBKData{Opcode: OpcodeMotGRGAdd, MFID: 0x90, SuperGroup: sg}
		for _, m := range members {
			d.PatchGroups[d.PatchGroupN] = m
			d.PatchGroupN++
		}
		return d
	}

	// ADD supergroup 5105 with real members [5103,5104].
	tt.Apply(add(5105, 5103, 5104))
	ps := tt.GetPatches()
	if len(ps) != 1 || ps[0].SuperGroup != 5105 {
		t.Fatalf("after add: want supergroup 5105, got %+v", ps)
	}

	// Real teardown DEL vector 13F113F113F1: sg-as-members. After the parser
	// drops the sentinels the DEL carries no members, so the patch must vanish
	// entirely -- not linger until patchExpiry.
	tt.Apply(teardown(5105, 5105, 5105, 5105))
	if got := tt.GetPatches(); len(got) != 0 {
		t.Fatalf("real teardown DEL must drop supergroup 5105 immediately, got %+v", got)
	}
}

// TestTrunkTracker_Patch_PartialMemberDel verifies a genuine partial DEL
// (naming one real member, distinct from the supergroup) still removes just
// that member and leaves the rest of the patch intact.
func TestTrunkTracker_Patch_PartialMemberDel(t *testing.T) {
	tt := NewTrunkTracker(0x171, nil, nil)

	add := &TSBKData{Opcode: OpcodeMotGRGAdd, MFID: 0x90, SuperGroup: 5105}
	add.PatchGroups[0], add.PatchGroups[1] = 5103, 5104
	add.PatchGroupN = 2
	tt.Apply(add)

	// DEL the real member 5103 (distinct from sg): survives parser filtering.
	del := &TSBKData{Opcode: OpcodeMotGRGDel, MFID: 0x90, SuperGroup: 5105}
	del.PatchGroups[0] = 5103
	del.PatchGroupN = 1
	tt.Apply(del)

	ps := tt.GetPatches()
	if len(ps) != 1 || len(ps[0].Members) != 1 || ps[0].Members[0] != 5104 {
		t.Fatalf("partial del 5103: want patch 5105 members [5104], got %+v", ps)
	}
}

func TestTrunkTracker_Patch_CNGrantFollows(t *testing.T) {
	var fired []Discovery
	tt := NewTrunkTracker(0x171, func(d Discovery) { fired = append(fired, d) }, nil)
	tt.Apply(&TSBKData{Opcode: OpcodeIdenUp, Iden: 1, BaseFreqHz: 450_000_000, SpacingHz: 12_500})

	// MOT_GRG_CN_GRANT: supergroup voice grant on channel 0x100A.
	g := &TSBKData{
		Opcode: OpcodeMotGRGCNGrant, MFID: 0x90,
		ChannelID: 0x100A, SuperGroup: 5105, SourceID: 510025,
	}
	d := tt.Apply(g)
	if d == nil {
		t.Fatal("CN_GRANT must resolve to a Discovery")
	}
	if d.TGID != 5105 {
		t.Errorf("Discovery TGID: want supergroup 5105, got %d", d.TGID)
	}
	if d.SrcID != 510025 {
		t.Errorf("Discovery SrcID: want 510025, got %d", d.SrcID)
	}
	if len(fired) != 1 {
		t.Errorf("onDiscover must fire once, got %d", len(fired))
	}
}

func TestTrunkTracker_Apply_DataGrant(t *testing.T) {
	var fired []DataDiscovery
	tt := NewTrunkTracker(0x171, nil, nil)
	tt.SetDataDiscoverHandler(func(d DataDiscovery) { fired = append(fired, d) })

	// Before iden table is seeded, a 0x14 must NOT fire (channelToHzLocked fails).
	pre := &TSBKData{Opcode: OpcodeGroupDataGrant, ChannelID: 0x100A, GroupID: 0xABCD, SourceID: 0x123456}
	if d := tt.Apply(pre); d != nil {
		t.Fatalf("Apply must return nil for any 0x14, got %+v", d)
	}
	if len(fired) != 0 {
		t.Fatalf("0x14 before iden seed: want 0 fires, got %d (%+v)", len(fired), fired)
	}

	// Seed iden 1: base 450 MHz, step 12.5 kHz, FDMA.
	tt.Apply(&TSBKData{Opcode: OpcodeIdenUp, Iden: 1, BaseFreqHz: 450_000_000, SpacingHz: 12_500})

	// First 0x14: ch=0x100A (iden 1, ch 10) -> 450.125 MHz.
	g1 := &TSBKData{Opcode: OpcodeGroupDataGrant, ChannelID: 0x100A, GroupID: 0xABCD, SourceID: 0x123456}
	tt.Apply(g1)
	if len(fired) != 1 {
		t.Fatalf("first 0x14: want 1 fire, got %d", len(fired))
	}
	got := fired[0]
	if got.NAC != 0x171 {
		t.Errorf("NAC = 0x%X, want 0x171", got.NAC)
	}
	if got.FreqHz != 450_125_000 {
		t.Errorf("FreqHz = %d, want 450125000", got.FreqHz)
	}
	if got.Iden != 1 || got.ChanNum != 10 {
		t.Errorf("Iden/ChanNum = %d/%d, want 1/10", got.Iden, got.ChanNum)
	}
	if got.SourceID != 0x123456 {
		t.Errorf("SourceID = 0x%X, want 0x123456", got.SourceID)
	}
	if got.GroupID != 0xABCD {
		t.Errorf("GroupID (dac) = 0x%X, want 0xABCD", got.GroupID)
	}
	if got.Opcode != uint8(OpcodeGroupDataGrant) {
		t.Errorf("Opcode = 0x%X, want 0x14", got.Opcode)
	}
	// Iden 1 was seeded with no transmit offset, so there is no uplink to tune.
	if got.UplinkHz != 0 {
		t.Errorf("UplinkHz = %d, want 0 (iden has no TxOffset)", got.UplinkHz)
	}

	// Second 0x14 on the same freq: tracker MUST fire again (de-dup is in System,
	// not Tracker). This guarantees retransmits keep the System pipeline alive.
	tt.Apply(g1)
	if len(fired) != 2 {
		t.Fatalf("second 0x14 on same freq: want 2 fires total, got %d", len(fired))
	}
}

// TestTrunkTracker_Apply_DataGrant_Uplink verifies that when the granting iden
// carries a transmit offset, the DataDiscovery resolves the mobile->FNE uplink
// bearer as downlink + offset (and that a downlink-only iden leaves it zero).
func TestTrunkTracker_Apply_DataGrant_Uplink(t *testing.T) {
	var fired []DataDiscovery
	tt := NewTrunkTracker(0x172, nil, nil)
	tt.SetDataDiscoverHandler(func(d DataDiscovery) { fired = append(fired, d) })

	// Seed iden 3 like the live WV SIRN plan: base 450 MHz, 6.25 kHz step,
	// +5 MHz transmit offset (mobiles transmit 5 MHz above the downlink).
	tt.Apply(&TSBKData{
		Opcode: OpcodeIdenUp, Iden: 3,
		BaseFreqHz: 450_000_000, SpacingHz: 6_250, TxOffsetHz: 5_000_000,
	})

	// ch 0x3F40: iden 3, ch 0xF40=3904 -> 450 MHz + 3904*6.25 kHz = 474.4 MHz?
	// Use a smaller channel so the math is obvious: ch 0x3010 = iden 3, ch 16
	// -> 450.0 MHz + 16*6.25 kHz = 450.1 MHz downlink, 455.1 MHz uplink.
	tt.Apply(&TSBKData{Opcode: OpcodeGroupDataGrant, ChannelID: 0x3010, GroupID: 0x1, SourceID: 0x2})
	if len(fired) != 1 {
		t.Fatalf("want 1 fire, got %d", len(fired))
	}
	got := fired[0]
	if got.FreqHz != 450_100_000 {
		t.Errorf("FreqHz (downlink) = %d, want 450100000", got.FreqHz)
	}
	if got.UplinkHz != 455_100_000 {
		t.Errorf("UplinkHz = %d, want 455100000 (downlink + 5 MHz)", got.UplinkHz)
	}
}

func TestTrunkTracker_Apply_SNDCPPageAndChAnnDoNotFire(t *testing.T) {
	var fired []DataDiscovery
	tt := NewTrunkTracker(0x171, nil, nil)
	tt.SetDataDiscoverHandler(func(d DataDiscovery) { fired = append(fired, d) })
	tt.Apply(&TSBKData{Opcode: OpcodeIdenUp, Iden: 1, BaseFreqHz: 450_000_000, SpacingHz: 12_500})

	// 0x15 SNDCP_DATA_PAGE_REQ: advertises data service; not a bearer grant.
	tt.Apply(&TSBKData{Opcode: OpcodeSNDCPDataPageReq, ChannelID: 0x100A, GroupID: 0xABCD})
	// 0x16 SNDCP_DATA_CH_ANN: channel announcement; not a bearer grant.
	tt.Apply(&TSBKData{Opcode: OpcodeSNDCPDataChAnn, ChannelID: 0x100A})

	if len(fired) != 0 {
		t.Errorf("0x15/0x16 must not fire DataDiscovery; got %d fires (%+v)", len(fired), fired)
	}
}

func TestApply_SiteDiscovery(t *testing.T) {
	var got []SiteDiscovery
	tt := NewTrunkTracker(0x171, nil, nil)
	tt.SetSiteDiscoverHandler(func(d SiteDiscovery) { got = append(got, d) })
	// iden 3: base 450 MHz, step 6250 Hz, FDMA — resolves channel IDs to freq.
	tt.SeedIden(map[uint8]IdenEntry{3: {BaseHz: 450_000_000, StepHz: 6250}})

	// RFSS_STS: self = site 41, cfva Valid, CC channel iden3/1666 = 460.4125 MHz.
	tt.Apply(&TSBKData{Opcode: OpcodeRFSSStatusBcast, SysID: 368, RFSS: 2, Site: 41,
		CFVA: 0b0010, ChannelID: (3 << 12) | 1666})
	// ADJ_STS: neighbor = site 26, cfva Active, CC iden3/1738 = 460.8625 MHz.
	tt.Apply(&TSBKData{Opcode: OpcodeAdjacentSiteBcast, SysID: 368, RFSS: 2, Site: 26,
		CFVA: 0b0001, ChannelID: (3 << 12) | 1738})

	if len(got) != 2 {
		t.Fatalf("got %d SiteDiscovery, want 2", len(got))
	}
	if !got[0].Self || got[0].Site != 41 || got[0].CCFreq != 460_412_500 || !got[0].Valid {
		t.Errorf("self: %+v", got[0])
	}
	if got[1].Self || got[1].Site != 26 || got[1].CCFreq != 460_862_500 || !got[1].Active {
		t.Errorf("adj: %+v", got[1])
	}
	if sys, rfss, site := tt.Site(); sys != 368 || rfss != 2 || site != 41 {
		t.Errorf("Site() = %d/%d/%d, want 368/2/41", sys, rfss, site)
	}
}

func TestApply_UnitVoiceGrant_FiresDiscovery(t *testing.T) {
	var got []Discovery
	tr := NewTrunkTracker(0x171, func(d Discovery) { got = append(got, d) }, nil)
	// Seed an iden so ChannelID resolves to a frequency.
	// iden 1, base 851.0 MHz, 12.5 kHz spacing, FDMA.
	tr.SeedIden(map[uint8]IdenEntry{
		1: {BaseHz: 851_000_000, StepHz: 12_500, TxOffsetHz: 0, BandwidthHz: 12_500, TDMASlots: 0},
	})
	// ChannelID = iden(1)<<12 | chan(2) = 0x1002 -> 851.0 MHz + 2*12.5k = 851.025 MHz
	tsbk := &TSBKData{
		Opcode:    OpcodeUnitVoiceGrant,
		ChannelID: 0x1002,
		DestID:    0x00ABCD,
		SourceID:  0x001234,
	}
	d := tr.Apply(tsbk)
	if d == nil {
		t.Fatal("Apply returned nil for unit voice grant")
	}
	if d.FreqHz != 851_025_000 {
		t.Errorf("FreqHz = %d, want 851025000", d.FreqHz)
	}
	if d.DestID != 0x00ABCD {
		t.Errorf("DestID = %#x, want 0xABCD", d.DestID)
	}
	if d.SrcID != 0x001234 {
		t.Errorf("SrcID = %#x, want 0x1234", d.SrcID)
	}
	if !d.UnitToUnit {
		t.Error("UnitToUnit = false, want true")
	}
	if len(got) != 1 {
		t.Errorf("onDiscover fired %d times, want 1", len(got))
	}
}

func TestApply_TelephoneInterconnectGrant_FiresDiscovery(t *testing.T) {
	var got []Discovery
	tr := NewTrunkTracker(0x171, func(d Discovery) { got = append(got, d) }, nil)
	// Seed an iden so ChannelID resolves to a frequency.
	tr.SeedIden(map[uint8]IdenEntry{
		1: {BaseHz: 851_000_000, StepHz: 12_500, TxOffsetHz: 0, BandwidthHz: 12_500, TDMASlots: 0},
	})
	// ChannelID = iden(1)<<12 | chan(2) = 0x1002 -> 851.0 MHz + 2*12.5k = 851.025 MHz
	tsbk := &TSBKData{
		Opcode:    OpcodeTeleIntVoiceGrant,
		ChannelID: 0x1002,
		DestID:    0x00ABCD,
	}
	d := tr.Apply(tsbk)
	if d == nil {
		t.Fatal("Apply returned nil for telephone interconnect grant")
	}
	if d.FreqHz != 851_025_000 {
		t.Errorf("FreqHz = %d, want 851025000", d.FreqHz)
	}
	if d.DestID != 0x00ABCD {
		t.Errorf("DestID = %#x, want 0xABCD", d.DestID)
	}
	if len(got) != 1 {
		t.Errorf("onDiscover fired %d times, want 1", len(got))
	}
}
