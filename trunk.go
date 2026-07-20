package p25

import (
	"slices"
	"sort"
	"sync"
	"time"
)

type IdenEntry struct {
	BaseHz, StepHz, TxOffsetHz int64
	BandwidthHz                int
	TDMASlots                  int
}

type VoiceChannel struct {
	FreqHz              uint32
	Iden                uint8
	ChanNum             uint16
	FirstSeen, LastSeen time.Time
	GrantCount          int
	LastTGID            uint16
	LastSrcID           uint32
}

// DataChannelSeed is the warm-start shape for a discovered SNDCP bearer.
// FreqHz is the actual RF frequency to seed; Uplink distinguishes the
// mobile->FNE partner from the downlink bearer so labels stay directional.
type DataChannelSeed struct {
	FreqHz uint32
	Uplink bool
}

type Discovery struct {
	NAC        uint16
	FreqHz     uint32
	Iden       uint8
	ChanNum    uint16
	TGID       uint16
	SrcID      uint32
	DestID     uint32 // called unit ID for unit-to-unit grants; 0 for group grants
	TDMASlots  int    // >1 means Phase 2 TDMA grant
	New        bool
	UnitToUnit bool // true for OpcodeUnitVoiceGrant (0x04): no talkgroup, label by unit IDs
}

// DataDiscovery is emitted for SNDCP data-bearer grants (OpcodeGroupDataGrant,
// 0x14). It is parallel to Discovery but separate because data grants carry a
// dac (data access code) instead of a talkgroup, and the consumer wires them to
// the SNDCP corpus pipeline rather than the voice pipeline. Tracker fires on
// every 0x14 with a resolvable channel; de-dup lives in System.onDataDiscover.
//
// 0x15 (SNDCP_DATA_PAGE_REQ) and 0x16 (SNDCP_DATA_CH_ANN) do NOT produce a
// DataDiscovery: they advertise data service availability but do not grant a
// specific bearer the way 0x14 does.
type DataDiscovery struct {
	NAC      uint16
	FreqHz   uint32 // downlink (FNE->mobile) bearer frequency
	UplinkHz uint32 // mobile->FNE bearer = downlink + iden TxOffsetHz; 0 if the
	// iden carries no transmit offset. Carries the bulk of mobile-originated
	// SNDCP/LRRP (GPS uploads), which never appear on the downlink.
	Iden     uint8
	ChanNum  uint16
	SourceID uint32
	GroupID  uint32 // dac (data access code) field from the TSBK
	Opcode   uint8  // always 0x14 OpcodeGroupDataGrant
}

// Site status flags from the cfva/flags nibble of ADJ_STS (0x3C) / RFSS_STS (0x3A).
const (
	siteFlagActive  = 0x1
	siteFlagValid   = 0x2
	siteFlagFailure = 0x4
	// siteFlagConventional = 0x8 is added in Phase 2 (it gates conventional ADJ
	// entries out of auto-spawn). Omitted here so there is no unused constant.
)

// SiteDiscovery is emitted for each RFSS_STS (Self=true) and ADJ_STS (Self=false)
// broadcast. CCFreq is the site's control-channel frequency resolved via the
// tracker iden table (0 if the relevant iden is not yet known).
type SiteDiscovery struct {
	SysID  uint16
	RFSS   uint8
	Site   uint8
	CCFreq uint32
	Active bool
	Valid  bool
	Failed bool
	Self   bool
}

// SiteState is the per-NAC view derived from Motorola (MFID 0x90) broadcast
// TSBKs and standard P25 broadcast TSBKs. Fields are independently optional:
// a CC may emit 0x09 without ever emitting 0x0B. Have* flags distinguish
// "seen as zero" from "never seen".
type SiteState struct {
	Callsign      string
	BSIChannelID  uint16
	SiteFlags     uint64
	LoadPct       uint8
	HaveSiteFlags bool
	HaveLoadPct   bool

	// WACN and SYSID from standard broadcast TSBKs (0x3A RFSS_STS_BCAST,
	// 0x3B NET_STS_BCAST). Needed for Phase 2 XOR descramble mask generation.
	WACN  uint32
	SYSID uint16
}

// SiteUpdate is fired by Apply() when any SiteState field changes. It carries
// the full state so the consumer can whole-row upsert without read-modify-write.
type SiteUpdate struct {
	NAC uint16
	SiteState
}

// patchExpiry bounds how long a Group Regroup (patch) is considered active
// without a refreshing ADD or supergroup grant. Matches op25's PATCH_EXPIRY_TIME.
const patchExpiry = 20 * time.Second

// Patch is one active Motorola Group Regroup: a dynamic SuperGroup talkgroup
// that aggregates one or more member talkgroups. Built from MOT_GRG_ADD/DEL
// commands and refreshed by supergroup voice grants.
type Patch struct {
	SuperGroup uint16
	Members    []uint16
	Updated    time.Time
}

// PatchUpdate is fired by Apply() when patch membership changes. Active holds
// the full current (non-expired) patch set so the consumer can replace its view
// without read-modify-write, mirroring SiteUpdate.
type PatchUpdate struct {
	NAC    uint16
	Active []Patch
}

type TrunkTracker struct {
	mu         sync.Mutex
	nac        uint16
	iden       [16]*IdenEntry
	voiceChans map[uint32]*VoiceChannel
	site       SiteState
	onDiscover func(Discovery)
	onSite     func(SiteUpdate)

	onSiteDiscover func(SiteDiscovery)
	onDataDiscover func(DataDiscovery)
	selfSysID      uint16
	selfRFSS       uint8
	selfSite       uint8

	// patches maps SuperGroup -> active regroup, built from MOT_GRG commands.
	patches map[uint16]*Patch
	onPatch func(PatchUpdate)
}

func NewTrunkTracker(nac uint16, onDiscover func(Discovery), onSite func(SiteUpdate)) *TrunkTracker {
	return &TrunkTracker{
		nac:        nac,
		voiceChans: make(map[uint32]*VoiceChannel),
		patches:    make(map[uint16]*Patch),
		onDiscover: onDiscover,
		onSite:     onSite,
	}
}

func (t *TrunkTracker) SeedIden(entries map[uint8]IdenEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, v := range entries {
		e := v
		t.iden[k&0xF] = &e
	}
}

// SetSiteDiscoverHandler installs the callback for RFSS_STS/ADJ_STS site
// broadcasts. Set before Start; read without a lock, like onDiscover/onSite.
func (t *TrunkTracker) SetSiteDiscoverHandler(fn func(SiteDiscovery)) {
	t.onSiteDiscover = fn
}

// SetDataDiscoverHandler installs the callback for OpcodeGroupDataGrant (0x14)
// SNDCP data-bearer grants. Parallel to SetSiteDiscoverHandler: set before
// Start; read without a lock. Distinct from the voice onDiscover callback so
// the System can route data grants to a separate pipeline (no de-dup here;
// every 0x14 with a resolvable channel fires).
func (t *TrunkTracker) SetDataDiscoverHandler(fn func(DataDiscovery)) {
	t.onDataDiscover = fn
}

// SetPatchHandler installs the callback fired when Group Regroup (patch)
// membership changes. Parallel to SetSiteDiscoverHandler: set before Start;
// read without a lock.
func (t *TrunkTracker) SetPatchHandler(fn func(PatchUpdate)) {
	t.onPatch = fn
}

// Site returns this tracker's own (SysID, RFSS, Site) as last seen in RFSS_STS.
// Zero values until the first RFSS_STS decodes.
func (t *TrunkTracker) Site() (sysID uint16, rfss, site uint8) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.selfSysID, t.selfRFSS, t.selfSite
}

func (t *TrunkTracker) fireSiteDiscovery(d SiteDiscovery) {
	if t.onSiteDiscover != nil {
		t.onSiteDiscover(d)
	}
}

func (t *TrunkTracker) fireDataDiscovery(d DataDiscovery) {
	if t.onDataDiscover != nil {
		t.onDataDiscover(d)
	}
}

func (t *TrunkTracker) ChannelToHz(id uint16) (uint32, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.channelToHzLocked(id)
}

func (t *TrunkTracker) channelToHzLocked(id uint16) (uint32, bool) {
	e := t.iden[id>>12]
	if e == nil {
		return 0, false
	}
	ch := int64(id & 0xFFF)
	div := int64(1)
	if e.TDMASlots > 1 {
		div = int64(e.TDMASlots)
	}
	return uint32(e.BaseHz + e.StepHz*(ch/div)), true
}

// uplinkHzLocked resolves the mobile->FNE (uplink) frequency for a channel id:
// the downlink frequency plus the iden's signed transmit offset. Returns
// (0, false) when the iden is unknown or carries no transmit offset (a
// downlink-only iden, e.g. a receive-only data advertisement). The sign of
// TxOffsetHz comes straight from the IDEN_UP decode (control.go), so systems
// whose mobiles transmit below the base produce a freq below the downlink.
func (t *TrunkTracker) uplinkHzLocked(id uint16) (uint32, bool) {
	e := t.iden[id>>12]
	if e == nil || e.TxOffsetHz == 0 {
		return 0, false
	}
	dl, ok := t.channelToHzLocked(id)
	if !ok {
		return 0, false
	}
	return uint32(int64(dl) + e.TxOffsetHz), true
}

// Apply updates tracker state from one TSBK. Returns a *Discovery for grant
// opcodes that resolved to a frequency, nil otherwise.
func (t *TrunkTracker) Apply(tsbk *TSBKData) *Discovery {
	t.mu.Lock()
	// Motorola broadcast opcodes (0x05/0x09/0x0B with MFID=0x90) overlap
	// the standard opcode space (0x05 = UU_V_CH_GRANT_UPDT). Discriminate
	// on MFID first so a future standard-0x05 handler isn't shadowed.
	if tsbk.MFID == 0x90 {
		switch tsbk.Opcode {
		case OpcodeMotBSI:
			changed := false
			if tsbk.Callsign != "" && tsbk.Callsign != t.site.Callsign {
				t.site.Callsign = tsbk.Callsign
				changed = true
			}
			if tsbk.ChannelID != 0 && tsbk.ChannelID != t.site.BSIChannelID {
				t.site.BSIChannelID = tsbk.ChannelID
				changed = true
			}
			t.mu.Unlock()
			if changed {
				t.fireSite()
			}
			return nil
		case OpcodeMotSiteFlags:
			changed := !t.site.HaveSiteFlags || t.site.SiteFlags != tsbk.SiteFlags
			t.site.SiteFlags, t.site.HaveSiteFlags = tsbk.SiteFlags, true
			t.mu.Unlock()
			if changed {
				t.fireSite()
			}
			return nil
		case OpcodeMotLoadPct:
			changed := !t.site.HaveLoadPct || t.site.LoadPct != tsbk.MotAltField
			t.site.LoadPct, t.site.HaveLoadPct = tsbk.MotAltField, true
			t.mu.Unlock()
			if changed {
				t.fireSite()
			}
			return nil
		case OpcodeMotGRGAdd:
			changed := t.patchAddLocked(tsbk.SuperGroup,
				tsbk.PatchGroups[:tsbk.PatchGroupN])
			t.mu.Unlock()
			if changed {
				t.firePatch()
			}
			return nil
		case OpcodeMotGRGDel:
			changed := t.patchDelLocked(tsbk.SuperGroup,
				tsbk.PatchGroups[:tsbk.PatchGroupN])
			t.mu.Unlock()
			if changed {
				t.firePatch()
			}
			return nil
		case OpcodeMotGRGCNGrant:
			// Supergroup voice grant: follow the channel like a group grant,
			// labeled by the supergroup, and refresh the patch's liveness.
			t.patchTouchLocked(tsbk.SuperGroup)
			d := t.grantLocked(tsbk.ChannelID, tsbk.SuperGroup, tsbk.SourceID)
			t.mu.Unlock()
			t.fire(d)
			return d
		case OpcodeMotGRGCNGrantUpdt:
			// Two supergroup channel/sg pairs (op25 MOT_GRG_CN_GRANT_UPDT).
			t.patchTouchLocked(tsbk.SuperGroup)
			d1 := t.grantLocked(tsbk.ChannelID, tsbk.SuperGroup, 0)
			var d2 *Discovery
			if tsbk.ChannelID2 != 0 && tsbk.ChannelID2 != tsbk.ChannelID {
				t.patchTouchLocked(uint16(tsbk.GroupID2))
				d2 = t.grantLocked(tsbk.ChannelID2, uint16(tsbk.GroupID2), 0)
			}
			t.mu.Unlock()
			t.fire(d1)
			t.fire(d2)
			if d1 != nil {
				return d1
			}
			return d2
		case OpcodeMotGRGUnk0A:
			// Undocumented; field interpretation is tentative. Do not drive
			// any tracker state off it — just acknowledge (handled) so it
			// leaves the frontier without acting on unverified fields.
			t.mu.Unlock()
			return nil
		}
		t.mu.Unlock()
		return nil
	}
	switch tsbk.Opcode {
	case OpcodeIdenUp, OpcodeIdenUpVU, OpcodeIdenUpTDMA:
		if tsbk.BaseFreqHz > 0 {
			t.iden[tsbk.Iden&0xF] = &IdenEntry{
				BaseHz:      tsbk.BaseFreqHz,
				StepHz:      int64(tsbk.SpacingHz),
				TxOffsetHz:  tsbk.TxOffsetHz,
				BandwidthHz: tsbk.BandwidthHz,
				TDMASlots:   tsbk.TDMASlots,
			}
		}
		t.mu.Unlock()
		return nil

	case OpcodeGroupVoiceGrant, OpcodeGroupVoiceGrantUpdtExp:
		d := t.grantLocked(tsbk.ChannelID, uint16(tsbk.GroupID), tsbk.SourceID)
		t.mu.Unlock()
		t.fire(d)
		return d

	case OpcodeGroupVoiceGrantUpdate:
		d1 := t.grantLocked(tsbk.ChannelID, uint16(tsbk.GroupID), 0)
		var d2 *Discovery
		if tsbk.ChannelID2 != 0 && tsbk.ChannelID2 != tsbk.ChannelID {
			d2 = t.grantLocked(tsbk.ChannelID2, uint16(tsbk.GroupID2), 0)
		}
		t.mu.Unlock()
		t.fire(d1)
		t.fire(d2)
		if d1 != nil {
			return d1
		}
		return d2

	case OpcodeUnitVoiceGrant:
		// 0x04 UU_V_CH_GRANT: ch[16] dst[24] src[24]. Private call between two
		// radios; no talkgroup. Resolve and follow like a group grant so the
		// voice pipeline tunes the assigned channel.
		d := t.unitGrantLocked(tsbk.ChannelID, tsbk.DestID, tsbk.SourceID)
		t.mu.Unlock()
		t.fire(d)
		return d

	case OpcodeTeleIntVoiceGrant:
		// 0x08 TELE_INT_CH_GRANT: a call bridged to the phone network. No
		// talkgroup; follow like a unit grant so the voice pipeline tunes the
		// assigned channel. DestID is the on-system party; there is no source.
		d := t.unitGrantLocked(tsbk.ChannelID, tsbk.DestID, 0)
		t.mu.Unlock()
		t.fire(d)
		return d

	case OpcodeGroupDataGrant:
		// 0x14 SNDCP_DATA_CH_GRANT: svc[8] ch[16] dac[16] src[24].
		// Resolve the channel via the iden table; do nothing if not yet seeded.
		// Unlike voice grants we keep no per-freq tracker state here; the
		// System de-dups in onDataDiscover so retransmits all reach it.
		freq, ok := t.channelToHzLocked(tsbk.ChannelID)
		uplink, _ := t.uplinkHzLocked(tsbk.ChannelID)
		t.mu.Unlock()
		if !ok {
			return nil
		}
		t.fireDataDiscovery(DataDiscovery{
			NAC:      t.nac,
			FreqHz:   freq,
			UplinkHz: uplink,
			Iden:     uint8(tsbk.ChannelID >> 12),
			ChanNum:  tsbk.ChannelID & 0xFFF,
			SourceID: tsbk.SourceID,
			GroupID:  tsbk.GroupID,
			Opcode:   uint8(OpcodeGroupDataGrant),
		})
		return nil

	case OpcodeNetworkStatusBcast:
		// 0x3B: lra[8] wacn[20] sys[12] chan[16] svc[8]
		// GroupID carries WACN, SysID carries system ID.
		changed := false
		if tsbk.GroupID != 0 && uint32(tsbk.GroupID) != t.site.WACN {
			t.site.WACN = uint32(tsbk.GroupID)
			changed = true
		}
		if tsbk.SysID != 0 && tsbk.SysID != t.site.SYSID {
			t.site.SYSID = tsbk.SysID
			changed = true
		}
		t.mu.Unlock()
		if changed {
			t.fireSite()
		}
		return nil

	case OpcodeRFSSStatusBcast:
		// 0x3A: lra[8] flags[4] sys[12] rfss[8] site[8] ch[16] svc[8]
		changed := false
		if tsbk.SysID != 0 && tsbk.SysID != t.site.SYSID {
			t.site.SYSID = tsbk.SysID
			changed = true
		}
		t.selfSysID, t.selfRFSS, t.selfSite = tsbk.SysID, tsbk.RFSS, tsbk.Site
		ccFreq, _ := t.channelToHzLocked(tsbk.ChannelID)
		sd := SiteDiscovery{
			SysID: tsbk.SysID, RFSS: tsbk.RFSS, Site: tsbk.Site, CCFreq: ccFreq,
			Active: tsbk.CFVA&siteFlagActive != 0,
			Valid:  tsbk.CFVA&siteFlagValid != 0,
			Failed: tsbk.CFVA&siteFlagFailure != 0,
			Self:   true,
		}
		t.mu.Unlock()
		if changed {
			t.fireSite()
		}
		t.fireSiteDiscovery(sd)
		return nil

	case OpcodeAdjacentSiteBcast:
		// 0x3C: lra[8] cfva[4] sys[12] rfss[8] site[8] ch[16] svc[8]
		ccFreq, _ := t.channelToHzLocked(tsbk.ChannelID)
		sd := SiteDiscovery{
			SysID: tsbk.SysID, RFSS: tsbk.RFSS, Site: tsbk.Site, CCFreq: ccFreq,
			Active: tsbk.CFVA&siteFlagActive != 0,
			Valid:  tsbk.CFVA&siteFlagValid != 0,
			Failed: tsbk.CFVA&siteFlagFailure != 0,
		}
		t.mu.Unlock()
		t.fireSiteDiscovery(sd)
		return nil
	}
	t.mu.Unlock()
	return nil
}

func (t *TrunkTracker) grantLocked(chID, tgid uint16, srcID uint32) *Discovery {
	if chID == 0 {
		return nil
	}
	freq, ok := t.channelToHzLocked(chID)
	if !ok {
		return nil
	}
	now := time.Now()
	vc, existed := t.voiceChans[freq]
	if !existed {
		vc = &VoiceChannel{
			FreqHz: freq, Iden: uint8(chID >> 12), ChanNum: chID & 0xFFF,
			FirstSeen: now,
		}
		t.voiceChans[freq] = vc
	}
	vc.LastSeen = now
	vc.GrantCount++
	vc.LastTGID = tgid
	if srcID != 0 {
		vc.LastSrcID = srcID
	}
	tdmaSlots := 0
	if e := t.iden[chID>>12]; e != nil {
		tdmaSlots = e.TDMASlots
	}
	// Report the ACTUAL granted channel identifiers, not the cached first-seen
	// ones. On Phase 2 TDMA both logical slots (e.g. chnum 10 and 11) map to the
	// same RF frequency, so voiceChans (keyed by freq) is shared across slots;
	// vc.ChanNum froze at the first grant's slot. Downstream slot mapping
	// (tdmaGrantSlot: chanNum & (slots-1)) needs the current grant's channel LSB
	// to route per-slot TGID/SrcID correctly.
	return &Discovery{
		NAC: t.nac, FreqHz: freq, Iden: uint8(chID >> 12), ChanNum: chID & 0xFFF,
		TGID: tgid, SrcID: srcID, TDMASlots: tdmaSlots, New: !existed,
	}
}

// unitGrantLocked resolves a unit-to-unit (private call) grant to a frequency
// and records it in voiceChans like a group grant, but carries the destination
// unit ID instead of a talkgroup. Returns nil if the channel can't be resolved
// (iden table not yet seeded). Caller must hold t.mu.
func (t *TrunkTracker) unitGrantLocked(chID uint16, destID, srcID uint32) *Discovery {
	if chID == 0 {
		return nil
	}
	freq, ok := t.channelToHzLocked(chID)
	if !ok {
		return nil
	}
	now := time.Now()
	vc, existed := t.voiceChans[freq]
	if !existed {
		vc = &VoiceChannel{
			FreqHz: freq, Iden: uint8(chID >> 12), ChanNum: chID & 0xFFF,
			FirstSeen: now,
		}
		t.voiceChans[freq] = vc
	}
	vc.LastSeen = now
	vc.GrantCount++
	vc.LastTGID = 0 // unit-to-unit has no talkgroup
	if srcID != 0 {
		vc.LastSrcID = srcID
	}
	tdmaSlots := 0
	if e := t.iden[chID>>12]; e != nil {
		tdmaSlots = e.TDMASlots
	}
	// Report the actual granted channel identifiers (see grantLocked): the cached
	// vc.ChanNum belongs to the first grant seen on this shared TDMA frequency.
	return &Discovery{
		NAC: t.nac, FreqHz: freq, Iden: uint8(chID >> 12), ChanNum: chID & 0xFFF,
		TGID: 0, SrcID: srcID, DestID: destID, TDMASlots: tdmaSlots,
		New: !existed, UnitToUnit: true,
	}
}

func (t *TrunkTracker) fire(d *Discovery) {
	if d != nil && t.onDiscover != nil {
		t.onDiscover(*d)
	}
}

func (t *TrunkTracker) fireSite() {
	if t.onSite == nil {
		return
	}
	t.mu.Lock()
	s := t.site
	t.mu.Unlock()
	t.onSite(SiteUpdate{NAC: t.nac, SiteState: s})
}

// GetSiteState returns a snapshot of the current site state. Thread-safe.
func (t *TrunkTracker) GetSiteState() SiteState {
	t.mu.Lock()
	s := t.site
	t.mu.Unlock()
	return s
}

// patchAddLocked merges members into the SuperGroup's patch, creating it if
// needed. Returns true if membership changed (a new supergroup or a new
// member). Always refreshes Updated. Caller must hold t.mu.
func (t *TrunkTracker) patchAddLocked(sg uint16, members []uint16) bool {
	if sg == 0 {
		return false
	}
	now := time.Now()
	p, ok := t.patches[sg]
	if !ok {
		p = &Patch{SuperGroup: sg}
		t.patches[sg] = p
	}
	changed := !ok
	for _, m := range members {
		if m == 0 || m == sg {
			continue
		}
		if !slices.Contains(p.Members, m) {
			p.Members = append(p.Members, m)
			changed = true
		}
	}
	p.Updated = now
	return changed
}

// patchDelLocked removes members from the SuperGroup's patch; if no members
// were named or none remain, the whole supergroup is dropped. Returns true if
// anything changed. Caller must hold t.mu.
func (t *TrunkTracker) patchDelLocked(sg uint16, members []uint16) bool {
	p, ok := t.patches[sg]
	if !ok {
		return false
	}
	// A DEL with no (post-filter) members tears down the whole patch, matching
	// op25's del_patch(sg, [sg]) teardown path. Real on-air teardown frames name
	// the supergroup as its own members; the parser drops those self-referential
	// sentinels (g==sg), so a genuine teardown arrives here as an empty list.
	if len(members) == 0 {
		delete(t.patches, sg)
		return true
	}
	changed := false
	for _, m := range members {
		for i, e := range p.Members {
			if e == m {
				p.Members = append(p.Members[:i], p.Members[i+1:]...)
				changed = true
				break
			}
		}
	}
	if len(p.Members) == 0 {
		delete(t.patches, sg)
		changed = true
	} else if changed {
		p.Updated = time.Now()
	}
	return changed
}

// patchTouchLocked refreshes a supergroup's liveness if it is already known,
// so an active supergroup grant keeps the patch from expiring. It does not
// create a patch (a grant alone carries no membership). Caller must hold t.mu.
func (t *TrunkTracker) patchTouchLocked(sg uint16) {
	if p, ok := t.patches[sg]; ok {
		p.Updated = time.Now()
	}
}

// firePatch delivers the current non-expired patch set to the handler.
func (t *TrunkTracker) firePatch() {
	if t.onPatch == nil {
		return
	}
	t.onPatch(PatchUpdate{NAC: t.nac, Active: t.GetPatches()})
}

// GetPatches returns a snapshot of the active (non-expired) patches, dropping
// any that have not been refreshed within patchExpiry. Thread-safe.
func (t *TrunkTracker) GetPatches() []Patch {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := time.Now().Add(-patchExpiry)
	var out []Patch
	for sg, p := range t.patches {
		if p.Updated.Before(cutoff) {
			delete(t.patches, sg)
			continue
		}
		members := make([]uint16, len(p.Members))
		copy(members, p.Members)
		out = append(out, Patch{SuperGroup: p.SuperGroup, Members: members, Updated: p.Updated})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SuperGroup < out[j].SuperGroup })
	return out
}

func (t *TrunkTracker) Snapshot() []VoiceChannel {
	t.mu.Lock()
	out := make([]VoiceChannel, 0, len(t.voiceChans))
	for _, vc := range t.voiceChans {
		out = append(out, *vc)
	}
	t.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].FreqHz < out[j].FreqHz })
	return out
}
