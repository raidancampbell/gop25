package p25

import (
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"
)

const grantHold = 5 * time.Second

type VoiceHandle interface {
	NotifyGrant(d time.Duration)
	NotifyTDMAGrant(d time.Duration, tgid uint16, srcID uint32, chanNum uint16, slots int)
	NotifyFDMAGrant(d time.Duration, tgid uint16)
	// NotifyUnitGrant signals an FDMA (Phase 1) unit-to-unit (private) voice
	// grant. It mirrors NotifyFDMAGrant but carries the calling-radio source ID
	// instead of a talkgroup, since private calls have none. The pipeline uses
	// srcID to label the recording's unit_id (private-call voice frames carry
	// LCO=3 link control this decoder does not parse). SOURCE-ONLY: the
	// destination unit is not threaded (no DB column for it).
	NotifyUnitGrant(d time.Duration, srcID uint32)
	// NotifyReassigned signals that talkgroup tgid — which this pipeline may be
	// recording — has been granted to a DIFFERENT frequency (a channel
	// reassignment or a new call for the same talkgroup on a fresh voice-pool
	// channel). The pipeline winds down its current transmission ONLY if that
	// transmission actually belongs to tgid, so it stops recording concurrently
	// with the new channel — otherwise a weak/latched carrier holds the abandoned
	// channel open (to the runaway cap), producing a same-CC "twin" that the
	// cross-site arbiter then collapses. The tgid guard makes this safe against a
	// stale mapping: if the pipeline has since moved to another talkgroup, the
	// signal is ignored. A no-op when nothing matching is being recorded.
	NotifyReassigned(tgid uint16)
	SetP2ScrambleParams(nac, sysid uint16, wacn uint32)
	// StageDataSession stages the SNDCP grant metadata to stamp onto the next
	// Kind="data" IQ capture (NAC, CC freq, target freq, source/group IDs,
	// opcode, and whether this is the mobile->FNE uplink bearer). onDataDiscover
	// calls it before NotifyGrant; the data pipeline consumes it when grant-gated
	// capture opens. A no-op for voice handles (their path never reads the staged session).
	StageDataSession(nac uint16, ccFreq, targetFreq, sourceID, groupID uint32, opcode uint8, uplink bool)
	Freq() uint32
}

type CCHandle interface {
	SetTrunkTracker(*TrunkTracker)
	TrunkSnapshot() []VoiceChannel
	// ObservedNAC is the NAC most recently decoded from this CC's NID, or 0 if
	// no frame has decoded yet. Used by the RFSS supervisor to bind a
	// NAC-agnostic discovered site to its real NAC.
	ObservedNAC() uint16
	// LastActivity is the arrival time of the most recent decoded TSBK, or the
	// zero time if none. Used to detect a silent site for despawn.
	LastActivity() time.Time
}

type Host interface {
	SpawnCC(freq uint32, nac uint16, label string, bw float64, contIQ bool) CCHandle
	SpawnVoice(freq uint32, nac uint16, label string, site uint8) VoiceHandle
	// SpawnData allocates a pipeline for a P25 data-bearer channel granted via
	// OpcodeGroupDataGrant (0x14). Returns the same VoiceHandle interface so
	// System.onDataDiscover can call NotifyGrant to keep the pipeline alive,
	// even though TDMA/scramble notifications are irrelevant for SNDCP data.
	SpawnData(freq uint32, nac uint16, label string, site uint8) VoiceHandle
	// DespawnCC stops a CC pipeline previously returned by SpawnCC and frees
	// its channelizer slot. The RFSS supervisor calls this to release a sibling
	// site that went Failed, left the window, or fell silent.
	DespawnCC(cc CCHandle)
	InWindow(freq uint32) bool
	UpsertVoiceChannel(d Discovery, inWindow bool)
	UpsertDataChannel(nac uint16, freqHz uint32, uplink bool, inWindow bool)
	UpsertTrunkSite(s SiteUpdate)
	UpsertTrunkPatch(u PatchUpdate)
	LoadIdenTable(nac uint16) map[uint8]IdenEntry
	LoadVoiceChannels(nac uint16) []uint32
	LoadDataChannels(nac uint16) []DataChannelSeed
	// Log returns the structured logger the decoder emits through. It is a
	// stdlib *slog.Logger so gop25 carries no logging dependency of its own;
	// a host that uses a different logging library supplies a slog.Handler
	// bridging to it (see the sdr app's zerolog harness for an example).
	Log() *slog.Logger
}

type System struct {
	def     SystemDef
	host    Host
	cc      CCHandle
	tracker *TrunkTracker
	mu      sync.Mutex
	voice   map[uint32]VoiceHandle
	// data tracks SNDCP data-bearer pipelines spawned via Host.SpawnData in
	// response to OpcodeGroupDataGrant (0x14). It is parallel to voice: the
	// same frequency may have both pipeline kinds because the channelizer can
	// fan one FFT bin out to multiple consumers. The data pipeline's grant gate
	// limits IQ capture to the active data exchange.
	data         map[uint32]VoiceHandle
	p2primed     map[uint32]bool
	wacnSeen     bool
	lastCallsign string

	// tgLastFreq maps a group talkgroup to the frequency of its most recent FDMA
	// grant. When a grant for the same talkgroup lands on a different frequency,
	// the call has been reassigned (or re-keyed onto a fresh voice-pool channel);
	// onDiscover signals the stale pipeline via NotifyReassigned so it stops
	// recording concurrently with the new channel. FDMA-only: Phase 2 packs two
	// talkgroups per frequency across TDMA slots, so a per-freq close is unsafe.
	tgLastFreq map[uint16]uint32

	// allowTG/denyTG are the precomputed per-trunk talkgroup filter sets from
	// def.AllowTGIDs/DenyTGIDs. allowTG is nil when no whitelist is configured
	// ("allow all"). See tgAllowed.
	allowTG map[uint16]bool
	denyTG  map[uint16]bool

	// siteSeen dedups onSiteDiscover logging: a site is re-logged only when its
	// advertised state (CC freq + C/F/V/A flags) changes, not on every broadcast.
	// P25 re-advertises the full neighbor list several times a second.
	siteSeen map[uint8]uint64

	// siteObserver, when set, is invoked on every SiteDiscovery broadcast,
	// before the logging-dedup early-return. The RFSS supervisor uses it to act
	// on all site advertisements, not just state-change transitions. nil when
	// running a bare (non-following) System.
	siteObserver func(SiteDiscovery)
}

func NewSystem(def SystemDef, host Host) *System {
	s := &System{
		def:        def,
		host:       host,
		voice:      make(map[uint32]VoiceHandle),
		data:       make(map[uint32]VoiceHandle),
		p2primed:   make(map[uint32]bool),
		tgLastFreq: make(map[uint16]uint32),
		siteSeen:   make(map[uint8]uint64),
		denyTG:     make(map[uint16]bool, len(def.DenyTGIDs)),
	}
	for _, tg := range def.DenyTGIDs {
		s.denyTG[tg] = true
	}
	if len(def.AllowTGIDs) > 0 {
		s.allowTG = make(map[uint16]bool, len(def.AllowTGIDs))
		for _, tg := range def.AllowTGIDs {
			s.allowTG[tg] = true
		}
	}
	return s
}

// SetSiteObserver installs a callback invoked for every decoded SiteDiscovery,
// in addition to the built-in logging. Set before Start.
func (s *System) SetSiteObserver(fn func(SiteDiscovery)) { s.siteObserver = fn }

// tgAllowed reports whether voice grants for tgid should be followed on this
// trunk. DenyTGIDs takes precedence; a non-empty AllowTGIDs acts as a whitelist.
// With neither configured, every talkgroup is allowed.
func (s *System) tgAllowed(tgid uint16) bool {
	if s.denyTG[tgid] {
		return false
	}
	if s.allowTG != nil && !s.allowTG[tgid] {
		return false
	}
	return true
}

// Start spawns the control channel from the System's configured frequency and
// then wires the System around it via StartWithCC.
func (s *System) Start() {
	cc := s.host.SpawnCC(s.def.ControlFreq, s.def.NAC, s.def.Label+" CC",
		s.def.Bandwidth, s.def.ContinuousIQ)
	s.StartWithCC(cc)
}

// StartWithCC wires the System around an already-spawned control channel,
// instead of spawning one itself. The supervisor uses this to adopt a
// NAC-agnostic CC it spawned to learn the site's NAC. cc may be nil (the
// channelizer rejected the channel), in which case the System is inert.
func (s *System) StartWithCC(cc CCHandle) {
	s.cc = cc
	s.tracker = NewTrunkTracker(s.def.NAC, s.onDiscover, s.onSite)
	s.tracker.SetSiteDiscoverHandler(s.onSiteDiscover)
	s.tracker.SetDataDiscoverHandler(s.onDataDiscover)
	s.tracker.SetPatchHandler(s.onPatch)
	if s.cc == nil {
		s.host.Log().Error("SpawnCC returned nil (channelizer closed?); trunk system inert",
			"nac", s.def.NAC)
		return
	}
	s.cc.SetTrunkTracker(s.tracker)
	if seed := s.host.LoadIdenTable(s.def.NAC); len(seed) > 0 {
		s.tracker.SeedIden(seed)
	}
	for _, f := range s.host.LoadVoiceChannels(s.def.NAC) {
		if f == s.def.ControlFreq || !s.host.InWindow(f) {
			continue
		}
		if _, ok := s.voice[f]; ok {
			continue
		}
		s.spawn(f, "seed")
	}
	for _, seed := range s.host.LoadDataChannels(s.def.NAC) {
		if seed.FreqHz == s.def.ControlFreq || !s.host.InWindow(seed.FreqHz) {
			continue
		}
		if _, ok := s.data[seed.FreqHz]; ok {
			continue
		}
		s.spawnDataSeed(seed)
	}
}

func (s *System) NAC() uint16            { return s.def.NAC }
func (s *System) Label() string          { return s.def.Label }
func (s *System) CC() CCHandle           { return s.cc }
func (s *System) Tracker() *TrunkTracker { return s.tracker }

func (s *System) VoiceHandles() []VoiceHandle {
	s.mu.Lock()
	out := make([]VoiceHandle, 0, len(s.voice))
	for _, v := range s.voice {
		out = append(out, v)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Freq() < out[j].Freq() })
	return out
}

// DataHandles returns the SNDCP data-bearer pipelines spawned via Host.SpawnData
// (OpcodeGroupDataGrant), sorted by frequency — the data-channel analogue of
// VoiceHandles(). Callers walk these to surface active data bearers alongside
// voice. Returns an empty slice when no data grant is active.
func (s *System) DataHandles() []VoiceHandle {
	s.mu.Lock()
	out := make([]VoiceHandle, 0, len(s.data))
	for _, v := range s.data {
		out = append(out, v)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Freq() < out[j].Freq() })
	return out
}

// spawn must be called with s.mu held, OR from Start() before any concurrent
// access begins. Returns nil if the host could not create a pipeline
// (channelizer closed); the freq is not stored in s.voice in that case.
func (s *System) spawn(freq uint32, reason string) VoiceHandle {
	// Label intentionally omits the freq — a host UI's recent-calls panel
	// typically renders the freq column separately, so including it here
	// produced "WVSP 460.087  460.087".
	// The freq is already keyed in s.voice and on the resulting txState.Freq.
	label := s.def.Label
	// Stamp the capturing site so transmissions record which site recorded
	// them. tracker.Site() is 0 until this System's RFSS_STS decodes (e.g. for
	// warm-start channels), which is the intended "unknown" sentinel.
	_, _, site := s.tracker.Site()
	vh := s.host.SpawnVoice(freq, s.def.NAC, label, site)
	if vh == nil {
		s.host.Log().Warn("SpawnVoice returned nil; skipping",
			"freq_hz", freq, "nac", s.def.NAC, "reason", reason)
		return nil
	}
	s.voice[freq] = vh
	s.host.Log().Info("voice pipeline spawned",
		"freq_hz", freq, "nac", s.def.NAC, "reason", reason)
	return vh
}

func (s *System) onDiscover(d Discovery) {
	inWin := s.host.InWindow(d.FreqHz)
	s.host.UpsertVoiceChannel(d, inWin)
	if d.New {
		s.host.Log().Info("trunked voice channel discovered",
			"nac", d.NAC, "freq_hz", d.FreqHz,
			"iden", d.Iden, "chnum", d.ChanNum,
			"tgid", d.TGID, "srcid", d.SrcID,
			"tdma_slots", d.TDMASlots, "in_window", inWin)
	}
	if !inWin || d.FreqHz == s.def.ControlFreq {
		return
	}
	// Group calls honor the talkgroup allow/deny list. Unit-to-unit calls have
	// no talkgroup; follow them unless they fall on the control frequency.
	if !d.UnitToUnit && !s.tgAllowed(d.TGID) {
		return
	}
	s.mu.Lock()
	vh, ok := s.voice[d.FreqHz]
	if !ok {
		vh = s.spawn(d.FreqHz, "grant")
	}
	s.mu.Unlock()
	if vh == nil {
		return
	}

	vh.NotifyGrant(grantHold)
	if d.TDMASlots > 1 {
		vh.NotifyTDMAGrant(grantHold, d.TGID, d.SrcID, d.ChanNum, d.TDMASlots)
		site := s.tracker.GetSiteState()
		s.mu.Lock()
		if !s.p2primed[d.FreqHz] && site.WACN != 0 {
			s.p2primed[d.FreqHz] = true
			s.mu.Unlock()
			vh.SetP2ScrambleParams(d.NAC, site.SYSID, site.WACN)
		} else {
			s.mu.Unlock()
		}
	} else if d.UnitToUnit {
		// Private call: thread the calling-radio source into the recording's
		// unit_id. Group-call talkgroup labeling does not apply (no talkgroup).
		vh.NotifyUnitGrant(grantHold, d.SrcID)
	} else {
		// Same-talkgroup channel reassignment: if this group's previous FDMA grant
		// was on a different frequency, that pipeline is now stale. Signal it to
		// wind down so it stops recording concurrently with this channel (the
		// same-CC "twin" the cross-site arbiter would otherwise collapse).
		if d.TGID != 0 {
			s.mu.Lock()
			prev, ok := s.tgLastFreq[d.TGID]
			s.tgLastFreq[d.TGID] = d.FreqHz
			var stale VoiceHandle
			if ok && prev != d.FreqHz {
				stale = s.voice[prev]
			}
			s.mu.Unlock()
			if stale != nil {
				stale.NotifyReassigned(d.TGID)
			}
		}
		vh.NotifyFDMAGrant(grantHold, d.TGID)
	}
}

func (s *System) onSite(u SiteUpdate) {
	s.host.UpsertTrunkSite(u)
	s.mu.Lock()
	csChanged := u.Callsign != "" && u.Callsign != s.lastCallsign
	if csChanged {
		s.lastCallsign = u.Callsign
	}
	s.mu.Unlock()
	if csChanged {
		s.host.Log().Info("trunk site identified",
			"nac", u.NAC, "callsign", u.Callsign, "bsi_ch", u.BSIChannelID)
	}
	if u.WACN == 0 {
		return
	}
	s.mu.Lock()
	if s.wacnSeen {
		s.mu.Unlock()
		return
	}
	s.wacnSeen = true
	var todo []VoiceHandle
	for f, vh := range s.voice {
		if !s.p2primed[f] {
			s.p2primed[f] = true
			todo = append(todo, vh)
		}
	}
	s.mu.Unlock()
	for _, vh := range todo {
		vh.SetP2ScrambleParams(s.def.NAC, u.SYSID, u.WACN)
	}
}

func (s *System) onPatch(u PatchUpdate) {
	s.host.UpsertTrunkPatch(u)
}

func (s *System) onSiteDiscover(d SiteDiscovery) {
	// P25 re-advertises its full neighbor list continuously; only log a site the
	// first time it appears or when its CC freq / flags actually change.
	state := uint64(d.CCFreq) << 4
	if d.Active {
		state |= 1
	}
	if d.Valid {
		state |= 2
	}
	if d.Failed {
		state |= 4
	}
	if d.Self {
		state |= 8
	}
	s.mu.Lock()
	prev, ok := s.siteSeen[d.Site]
	s.siteSeen[d.Site] = state
	s.mu.Unlock()
	if s.siteObserver != nil {
		s.siteObserver(d)
	}
	if ok && prev == state {
		return
	}
	s.host.Log().Info("trunk site advertised",
		"sysid", d.SysID, "rfss", d.RFSS, "site", d.Site,
		"cc_freq", d.CCFreq,
		"active", d.Active, "valid", d.Valid, "failed", d.Failed,
		"self", d.Self, "in_window", s.host.InWindow(d.CCFreq))
}

// onDataDiscover routes a P25 SNDCP data-bearer grant (OpcodeGroupDataGrant,
// 0x14) into a Host.SpawnData pipeline so the IQ for the data exchange can be
// captured into the SNDCP corpus. The tracker fires every 0x14 with a
// resolvable channel; this method de-dups on freq so retransmits keep the
// existing pipeline alive (NotifyGrant) instead of double-spawning.
//
// Voice/data coexistence: on this system the SNDCP data bearers reuse
// voice-pool frequencies, so the same freq is often already owned by a (idle)
// voice pipeline when a data grant lands. The channelizer fans an FFT bin out
// to any number of consumers (AddChannel does not key by freq), so a data
// pipeline is spawned alongside the voice one rather than dropped. Capturing
// the wrong traffic is prevented downstream: the data pipeline gates its IQ
// capture on an active grant (the host application gates it), so it
// records only during the data exchange and ignores voice carriers on the
// shared freq.
func (s *System) onDataDiscover(d DataDiscovery) {
	s.host.UpsertDataChannel(d.NAC, d.FreqHz, false, s.host.InWindow(d.FreqHz))
	if d.UplinkHz != 0 {
		s.host.UpsertDataChannel(d.NAC, d.UplinkHz, true, s.host.InWindow(d.UplinkHz))
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Downlink (FNE->mobile): the bearer carrying acks/polls and FNE-originated
	// data. This is the strong, tower-sourced side and decodes reliably.
	s.spawnOrRefreshDataLocked(d, d.FreqHz, false)

	// Uplink (mobile->FNE): downlink + iden TxOffsetHz, where the bulk of
	// mobile-originated SNDCP/LRRP (GPS uploads) actually rides. Reception is
	// proximity-limited (a single field radio, not the simulcast network), so
	// this may capture nothing decodable at a fixed monitoring site even when
	// the downlink is clean. Spawned as a separate freq-keyed pipeline, gated by
	// the same grant; skipped if the iden has no offset or it falls out of window.
	if d.UplinkHz != 0 {
		s.spawnOrRefreshDataLocked(d, d.UplinkHz, true)
	}
}

func (s *System) spawnDataSeed(seed DataChannelSeed) {
	dir := "data"
	if seed.Uplink {
		dir = "data↑"
	}
	label := fmt.Sprintf("%s %s %d.%04d", s.def.Label, dir,
		seed.FreqHz/1_000_000, (seed.FreqHz/100)%10000)
	_, _, site := s.tracker.Site()
	vh := s.host.SpawnData(seed.FreqHz, s.def.NAC, label, site)
	if vh == nil {
		s.host.Log().Warn("SpawnData returned nil; skipping warm seed",
			"freq_hz", seed.FreqHz, "nac", s.def.NAC, "uplink", seed.Uplink)
		return
	}
	s.data[seed.FreqHz] = vh
	s.host.Log().Info("SNDCP data pipeline warm-seeded",
		"freq_hz", seed.FreqHz, "nac", s.def.NAC, "uplink", seed.Uplink)
}

// spawnOrRefreshDataLocked spawns a Kind="data" pipeline for one bearer freq
// (downlink or uplink) on its first grant and refreshes it (re-stage + extend
// grant) on every retransmit. De-dup is keyed on freq, so the downlink and its
// +offset uplink occupy independent map entries and coexist. Caller holds s.mu.
func (s *System) spawnOrRefreshDataLocked(d DataDiscovery, freqHz uint32, uplink bool) {
	// Skip if outside the capture window or this is the CC itself.
	if !s.host.InWindow(freqHz) || freqHz == s.def.ControlFreq {
		return
	}
	vh, exists := s.data[freqHz]
	if !exists {
		dir := "data"
		if uplink {
			dir = "data↑" // data↑: mobile->FNE uplink bearer
		}
		label := fmt.Sprintf("%s %s %d.%04d", s.def.Label, dir,
			freqHz/1_000_000, (freqHz/100)%10000)
		_, _, site := s.tracker.Site()
		vh = s.host.SpawnData(freqHz, s.def.NAC, label, site)
		if vh == nil {
			s.host.Log().Warn("SpawnData returned nil; SNDCP grant ignored",
				"freq_hz", freqHz, "nac", s.def.NAC, "uplink", uplink)
			return
		}
		s.data[freqHz] = vh
		s.host.Log().Info("SNDCP data pipeline spawned",
			"freq_hz", freqHz, "nac", d.NAC, "uplink", uplink,
			"source_id", d.SourceID, "dac", d.GroupID)
	}
	// Stage the grant metadata onto the next capture before refreshing the
	// grant. onOpenData consumes (clears) the pending session on each open, so
	// re-staging on every announcement keeps fresh metadata available for the
	// next capture session on this freq.
	vh.StageDataSession(d.NAC, s.def.ControlFreq, freqHz, d.SourceID, d.GroupID, d.Opcode, uplink)
	vh.NotifyGrant(grantHold)
}
