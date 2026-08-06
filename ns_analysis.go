package main

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// IPMetadata 是 NS 端点的离线 ASN/国家归属信息。未知数据不会参与网络风险升高判断。
type IPMetadata struct {
	ASN             uint32 `json:"asn,omitempty"`
	ASNOrganization string `json:"asn_organization,omitempty"`
	Country         string `json:"country,omitempty"`
	Source          string `json:"source,omitempty"`
	Available       bool   `json:"available"`
}

type IPMetadataProvider interface {
	LookupIP(netip.Addr) IPMetadata
}

type ipv4Range struct {
	start uint32
	end   uint32
	meta  IPMetadata
}

type ipv6Range struct {
	start [16]byte
	end   [16]byte
	meta  IPMetadata
}

// GeoLiteResolver 直接读取本地 GeoLite CSV，不依赖 ClickHouse。
// 每个 IP 只在生成 NS 观测时查询一次，避免为全量 RR 做重复归属查询。
type GeoLiteResolver struct {
	asn4     []ipv4Range
	asn6     []ipv6Range
	country4 []ipv4Range
	country6 []ipv6Range
	version  string
}

func (r *GeoLiteResolver) LookupIP(addr netip.Addr) IPMetadata {
	if r == nil || !addr.IsValid() {
		return IPMetadata{}
	}

	var asn, country IPMetadata
	if addr.Is4() {
		value := ipv4ToUint32(addr)
		asn = lookupIPv4Range(r.asn4, value)
		country = lookupIPv4Range(r.country4, value)
	} else {
		value := addr.As16()
		asn = lookupIPv6Range(r.asn6, value)
		country = lookupIPv6Range(r.country6, value)
	}

	meta := IPMetadata{
		ASN:             asn.ASN,
		ASNOrganization: asn.ASNOrganization,
		Country:         country.Country,
		Source:          r.version,
	}
	meta.Available = meta.ASN != 0 || meta.Country != ""
	return meta
}

func lookupIPv4Range(ranges []ipv4Range, value uint32) IPMetadata {
	idx := sort.Search(len(ranges), func(i int) bool { return ranges[i].start > value }) - 1
	if idx >= 0 && value <= ranges[idx].end {
		return ranges[idx].meta
	}
	return IPMetadata{}
}

func lookupIPv6Range(ranges []ipv6Range, value [16]byte) IPMetadata {
	idx := sort.Search(len(ranges), func(i int) bool { return bytesCompare16(ranges[i].start, value) > 0 }) - 1
	if idx >= 0 && bytesCompare16(value, ranges[idx].end) <= 0 {
		return ranges[idx].meta
	}
	return IPMetadata{}
}

func bytesCompare16(left, right [16]byte) int {
	for i := range left {
		if left[i] < right[i] {
			return -1
		}
		if left[i] > right[i] {
			return 1
		}
	}
	return 0
}

// LoadGeoLiteResolver 自动选择 geoip_data 中最新的 ASN/Country CSV 版本。
func LoadGeoLiteResolver(dir string) (*GeoLiteResolver, error) {
	asn4, asn6, err := latestGeoLiteFiles(dir, "GeoLite2-ASN-CSV_*", "GeoLite2-ASN-Blocks-IPv4.csv", "GeoLite2-ASN-Blocks-IPv6.csv")
	if err != nil {
		return nil, err
	}
	country4, country6, err := latestGeoLiteFiles(dir, "GeoLite2-Country-CSV_*", "GeoLite2-Country-Blocks-IPv4.csv", "GeoLite2-Country-Blocks-IPv6.csv")
	if err != nil {
		return nil, err
	}

	locationFile, err := latestGeoLiteFile(dir, "GeoLite2-Country-CSV_*/GeoLite2-Country-Locations-en.csv")
	if err != nil {
		return nil, err
	}
	countryCodes, err := loadCountryCodes(locationFile)
	if err != nil {
		return nil, err
	}

	resolver := &GeoLiteResolver{version: "GeoLite2"}
	if err := loadASNBlocks(asn4, resolver); err != nil {
		return nil, err
	}
	if err := loadASNBlocks(asn6, resolver); err != nil {
		return nil, err
	}
	if err := loadCountryBlocks(country4, countryCodes, resolver); err != nil {
		return nil, err
	}
	if err := loadCountryBlocks(country6, countryCodes, resolver); err != nil {
		return nil, err
	}

	sort.Slice(resolver.asn4, func(i, j int) bool { return resolver.asn4[i].start < resolver.asn4[j].start })
	sort.Slice(resolver.country4, func(i, j int) bool { return resolver.country4[i].start < resolver.country4[j].start })
	sort.Slice(resolver.asn6, func(i, j int) bool { return bytesCompare16(resolver.asn6[i].start, resolver.asn6[j].start) < 0 })
	sort.Slice(resolver.country6, func(i, j int) bool { return bytesCompare16(resolver.country6[i].start, resolver.country6[j].start) < 0 })
	return resolver, nil
}

func latestGeoLiteFiles(dir, versionPattern, ipv4Name, ipv6Name string) (string, string, error) {
	versionDirs, err := filepath.Glob(filepath.Join(dir, versionPattern))
	if err != nil || len(versionDirs) == 0 {
		return "", "", fmt.Errorf("未找到 %s 离线目录", versionPattern)
	}
	sort.Strings(versionDirs)
	latest := versionDirs[len(versionDirs)-1]
	return filepath.Join(latest, ipv4Name), filepath.Join(latest, ipv6Name), nil
}

func latestGeoLiteFile(dir, pattern string) (string, error) {
	paths, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil || len(paths) == 0 {
		return "", fmt.Errorf("未找到 GeoLite 文件 %s", pattern)
	}
	sort.Strings(paths)
	return paths[len(paths)-1], nil
}

func loadCountryCodes(filename string) (map[string]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	header, err := reader.Read()
	if err != nil {
		return nil, err
	}
	indices := csvIndices(header)
	result := make(map[string]string)
	for {
		row, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		id := csvValue(row, indices, "geoname_id")
		country := csvValue(row, indices, "country_iso_code")
		if id != "" && country != "" {
			result[id] = country
		}
	}
	return result, nil
}

func loadASNBlocks(filename string, resolver *GeoLiteResolver) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	header, err := reader.Read()
	if err != nil {
		return err
	}
	indices := csvIndices(header)
	for {
		row, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		prefix, err := netip.ParsePrefix(csvValue(row, indices, "network"))
		if err != nil {
			continue
		}
		asn, _ := strconv.ParseUint(csvValue(row, indices, "autonomous_system_number"), 10, 32)
		meta := IPMetadata{ASN: uint32(asn), ASNOrganization: csvValue(row, indices, "autonomous_system_organization"), Source: "GeoLite2"}
		appendRange(prefix, meta, &resolver.asn4, &resolver.asn6)
	}
	return nil
}

func loadCountryBlocks(filename string, countryCodes map[string]string, resolver *GeoLiteResolver) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	header, err := reader.Read()
	if err != nil {
		return err
	}
	indices := csvIndices(header)
	for {
		row, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		prefix, err := netip.ParsePrefix(csvValue(row, indices, "network"))
		if err != nil {
			continue
		}
		locationID := csvValue(row, indices, "geoname_id")
		if locationID == "" {
			locationID = csvValue(row, indices, "registered_country_geoname_id")
		}
		if locationID == "" {
			locationID = csvValue(row, indices, "represented_country_geoname_id")
		}
		if country := countryCodes[locationID]; country != "" {
			appendRange(prefix, IPMetadata{Country: country, Source: "GeoLite2"}, &resolver.country4, &resolver.country6)
		}
	}
	return nil
}

func csvIndices(header []string) map[string]int {
	indices := make(map[string]int, len(header))
	for i, name := range header {
		indices[name] = i
	}
	return indices
}

func csvValue(row []string, indices map[string]int, name string) string {
	idx, ok := indices[name]
	if !ok || idx >= len(row) {
		return ""
	}
	return row[idx]
}

func appendRange(prefix netip.Prefix, meta IPMetadata, ipv4 *[]ipv4Range, ipv6 *[]ipv6Range) {
	prefix = prefix.Masked()
	if prefix.Addr().Is4() {
		start := ipv4ToUint32(prefix.Addr())
		hostBits := 32 - prefix.Bits()
		end := start
		if hostBits == 32 {
			end = ^uint32(0)
		} else if hostBits > 0 {
			end |= uint32(1<<hostBits) - 1
		}
		*ipv4 = append(*ipv4, ipv4Range{start: start, end: end, meta: meta})
		return
	}

	start := prefix.Addr().As16()
	end := start
	for bit := prefix.Bits(); bit < 128; bit++ {
		byteIndex := bit / 8
		bitIndex := uint(7 - bit%8)
		end[byteIndex] |= 1 << bitIndex
	}
	*ipv6 = append(*ipv6, ipv6Range{start: start, end: end, meta: meta})
}

func ipv4ToUint32(addr netip.Addr) uint32 {
	bytes := addr.Unmap().As4()
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}

type NSAddress struct {
	Address           string `json:"address"`
	Family            string `json:"family"`
	ASN               uint32 `json:"asn,omitempty"`
	ASNOrganization   string `json:"asn_organization,omitempty"`
	Country           string `json:"country,omitempty"`
	MetadataAvailable bool   `json:"metadata_available"`
	Reserved          bool   `json:"reserved"`
}

type NSHostObservation struct {
	Name             string      `json:"name"`
	RegisteredDomain string      `json:"registered_domain"`
	Attribute        string      `json:"attribute"`
	TrustLevel       int         `json:"trust_level"`
	Addresses        []NSAddress `json:"addresses"`
}

type DomainNSObservation struct {
	Domain      string              `json:"domain"`
	CapturedAt  time.Time           `json:"captured_at"`
	Nameservers []NSHostObservation `json:"nameservers"`
	Fingerprint string              `json:"fingerprint"`
}

// NSBaselineConsecutiveRequired 是建立或滚动替换基线所需的连续有效观测次数。
// 10 分钟一个 dump 时，12 次约覆盖两小时；没有缓存到该域名的快照不参与计数，
// 也不会中断连续性。
const NSBaselineConsecutiveRequired uint16 = 12

// NSBaselineState 保存某域名的基线确认进度。Confirmed 为 true 时，正式基线
// 存在于 ns_domain_baseline；Candidate 则保存正在积累的同一指纹结果，用于
// 首次建基线和合法/持续变更后的滚动更新。
type NSBaselineState struct {
	Domain               string              `json:"domain"`
	Confirmed            bool                `json:"confirmed"`
	Candidate            DomainNSObservation `json:"candidate,omitempty"`
	CandidateFingerprint string              `json:"candidate_fingerprint,omitempty"`
	ConsecutiveCount     uint16              `json:"consecutive_count"`
	CandidateFirstSeen   time.Time           `json:"candidate_first_seen,omitempty"`
	CandidateLastSeen    time.Time           `json:"candidate_last_seen,omitempty"`
}

type SnapshotSummary struct {
	ID             string    `json:"id"`
	Source         string    `json:"source"`
	View           string    `json:"view"`
	CapturedAt     time.Time `json:"captured_at"`
	Domains        int       `json:"domains"`
	NSObservations int       `json:"ns_observations"`
}

type NSTimelinePoint struct {
	CapturedAt  time.Time `json:"captured_at"`
	NSCount     int       `json:"ns_count"`
	Fingerprint string    `json:"fingerprint"`
	SnapshotID  string    `json:"snapshot_id"`
	State       string    `json:"state"` // baseline, normal, event_started, event_active, event_resolved, baseline_rolled
	Severity    string    `json:"severity,omitempty"`
	EventID     string    `json:"event_id,omitempty"`
	Summary     string    `json:"summary,omitempty"`
}

type NSChangeEvent struct {
	ID          string              `json:"id"`
	Domain      string              `json:"domain"`
	Severity    string              `json:"severity"`
	Evidence    string              `json:"evidence"`
	Status      string              `json:"status"`
	Summary     string              `json:"summary"`
	ChangeTypes []string            `json:"change_types"`
	FirstSeen   time.Time           `json:"first_seen"`
	LastSeen    time.Time           `json:"last_seen"`
	ResolvedAt  *time.Time          `json:"resolved_at,omitempty"`
	Occurrences int                 `json:"occurrences"`
	Baseline    DomainNSObservation `json:"baseline"`
	Current     DomainNSObservation `json:"current"`
	signature   string
}

type DomainNSDetail struct {
	Domain         string              `json:"domain"`
	Baseline       DomainNSObservation `json:"baseline"`
	BaselineSource string              `json:"baseline_source,omitempty"` // confirmed, event_history, candidate, current_only
	Current        DomainNSObservation `json:"current"`
	Timeline       []NSTimelinePoint   `json:"timeline"`
	Events         []NSChangeEvent     `json:"events"`
}

type NSOverview struct {
	LatestSnapshot SnapshotSummary `json:"latest_snapshot"`
	Snapshots      int             `json:"snapshots"`
	TrackedDomains int             `json:"tracked_domains"`
	EventCounts    map[string]int  `json:"event_counts"`
	ActiveEvents   int             `json:"active_events"`
	GeoLiteLoaded  bool            `json:"geolite_loaded"`
	GeoLiteSource  string          `json:"geolite_source,omitempty"`
	Warnings       []string        `json:"warnings"`
}

type NSAnalysis struct {
	Snapshots []SnapshotSummary
	Events    []NSChangeEvent
	Baseline  map[string]DomainNSObservation
	Current   map[string]DomainNSObservation
	Timeline  map[string][]NSTimelinePoint
	Warnings  []string
	geoLoaded bool
	geoSource string
	// baselineStates 是每域名连续观测确认状态；只有 Confirmed=true 的域名会
	// 出现在 Baseline 中。两个标记集合只供持久化层增量写入。
	baselineStates     map[string]NSBaselineState
	baselineStateDirty map[string]struct{}
	baselineUpdates    map[string]struct{}
	// snapshotSources 仅在内存 API 内部使用，前端只能传递不透明的 SnapshotSummary.ID。
	snapshotSources map[string]string
	snapshotIndex   map[string]SnapshotSummary
}

type namedCacheSnapshot struct {
	// Source 是写入目录表和页面展示的来源名。常规导入保持 basename，目录
	// 监测器使用相对于 dump 根目录的路径以避免子目录同名文件发生冲突。
	Source     string
	SourcePath string
	Identity   string
	CapturedAt time.Time
	Cache      *BindCache
}

// NSSnapshotObserver 在每份快照完成 NS 提取后被调用。
// 观察器可将仅 NS 的结果批量写入外部存储；完整 BindCache 在回调后即可释放。
type NSSnapshotObserver func(SnapshotSummary, map[string]DomainNSObservation, *BindCache) error

func AnalyzeNSFiles(files []string, geo IPMetadataProvider) (*NSAnalysis, error) {
	return AnalyzeNSFilesWithObserver(files, geo, nil)
}

// AnalyzeNSFilesWithObserver 以流式方式解析文件，避免同时保留多份完整缓存快照。
func AnalyzeNSFilesWithObserver(files []string, geo IPMetadataProvider, observer NSSnapshotObserver) (*NSAnalysis, error) {
	orderedFiles := append([]string(nil), files...)
	sortSnapshotFiles(orderedFiles)
	builder := newNSAnalysisBuilder(geo)
	for _, filename := range orderedFiles {
		cache, err := ParseDNSCacheFile(filename)
		if err != nil {
			return nil, fmt.Errorf("解析快照 %s: %w", filename, err)
		}
		capturedAt := parseSnapshotTime(cache.Date, filename)
		summary, observations := builder.add(namedCacheSnapshot{Source: filename, CapturedAt: capturedAt, Cache: cache})
		if observer != nil {
			if err := observer(summary, observations, cache); err != nil {
				return nil, fmt.Errorf("处理快照 %s: %w", filename, err)
			}
		}
	}
	return builder.finish(), nil
}

func AnalyzeNSCaches(snapshots []namedCacheSnapshot, geo IPMetadataProvider) *NSAnalysis {
	sort.Slice(snapshots, func(i, j int) bool {
		if snapshots[i].CapturedAt.Equal(snapshots[j].CapturedAt) {
			return snapshots[i].Source < snapshots[j].Source
		}
		return snapshots[i].CapturedAt.Before(snapshots[j].CapturedAt)
	})

	builder := newNSAnalysisBuilder(geo)
	for _, snapshot := range snapshots {
		builder.add(snapshot)
	}
	return builder.finish()
}

type nsAnalysisBuilder struct {
	result             *NSAnalysis
	geo                IPMetadataProvider
	activeByDomain     map[string]int
	persistedBaselines bool
	baselineHolds      map[string]string
}

func newNSAnalysisBuilder(geo IPMetadataProvider) *nsAnalysisBuilder {
	return newNSAnalysisBuilderWithState(geo, nil, nil, nil)
}

// newNSAnalysisBuilderWithState 复用已落库的正式基线和未解决事件，
// 使后续单个 10 分钟快照不会被错误地当作一轮新的基线。
func newNSAnalysisBuilderWithState(geo IPMetadataProvider, baselines map[string]DomainNSObservation, baselineStates map[string]NSBaselineState, activeEvents []NSChangeEvent) *nsAnalysisBuilder {
	result := &NSAnalysis{
		Baseline:           make(map[string]DomainNSObservation),
		Current:            make(map[string]DomainNSObservation),
		Timeline:           make(map[string][]NSTimelinePoint),
		baselineStates:     make(map[string]NSBaselineState),
		baselineStateDirty: make(map[string]struct{}),
		baselineUpdates:    make(map[string]struct{}),
		snapshotSources:    make(map[string]string),
		snapshotIndex:      make(map[string]SnapshotSummary),
	}
	if resolver, ok := geo.(*GeoLiteResolver); ok && resolver != nil {
		result.geoLoaded = true
		result.geoSource = resolver.version
	}
	for domain, state := range baselineStates {
		state.Domain = normalizeFQDN(domain)
		result.baselineStates[state.Domain] = state
	}
	for domain, baseline := range baselines {
		domain = normalizeFQDN(domain)
		state, hasState := result.baselineStates[domain]
		if !hasState {
			// 兼容升级前的首次观测基线：不再直接信任它，而是把该观测
			// 作为连续 12 次确认的第 1 次。这样无需清空旧表即可平滑迁移。
			state = newNSBaselineCandidate(baseline)
			result.baselineStates[domain] = state
			result.baselineStateDirty[domain] = struct{}{}
			continue
		}
		if !state.Confirmed {
			continue
		}
		result.Baseline[domain] = baseline
		result.Current[domain] = baseline
	}
	for domain, state := range result.baselineStates {
		if !state.Confirmed {
			continue
		}
		if _, exists := result.Baseline[domain]; exists {
			continue
		}
		// 状态与正式基线不完整时优先降级为候选，避免把不完整数据误作可信基线。
		state.Confirmed = false
		result.baselineStates[domain] = state
		result.baselineStateDirty[domain] = struct{}{}
	}
	activeByDomain := make(map[string]int)
	for _, event := range activeEvents {
		result.Events = append(result.Events, event)
		activeByDomain[event.Domain] = len(result.Events) - 1
		if event.Current.Domain != "" {
			result.Current[event.Domain] = event.Current
		}
	}
	return &nsAnalysisBuilder{result: result, geo: geo, activeByDomain: activeByDomain, persistedBaselines: len(result.Baseline) > 0}
}

func (b *nsAnalysisBuilder) setBaselineHolds(holds map[string]string) {
	b.baselineHolds = holds
}

func (b *nsAnalysisBuilder) baselineHeld(domain string) (string, bool) {
	if b == nil || len(b.baselineHolds) == 0 {
		return "", false
	}
	id, ok := b.baselineHolds[normalizeFQDN(domain)]
	return id, ok
}

func newNSBaselineCandidate(observation DomainNSObservation) NSBaselineState {
	return NSBaselineState{
		Domain:               normalizeFQDN(observation.Domain),
		Candidate:            observation,
		CandidateFingerprint: observation.Fingerprint,
		ConsecutiveCount:     1,
		CandidateFirstSeen:   observation.CapturedAt,
		CandidateLastSeen:    observation.CapturedAt,
	}
}

func (b *nsAnalysisBuilder) baselineState(domain string) NSBaselineState {
	domain = normalizeFQDN(domain)
	state, exists := b.result.baselineStates[domain]
	if !exists {
		state.Domain = domain
	}
	return state
}

func (b *nsAnalysisBuilder) saveBaselineState(state NSBaselineState) {
	state.Domain = normalizeFQDN(state.Domain)
	b.result.baselineStates[state.Domain] = state
	b.result.baselineStateDirty[state.Domain] = struct{}{}
}

func resetNSBaselineCandidate(state *NSBaselineState) {
	state.Candidate = DomainNSObservation{}
	state.CandidateFingerprint = ""
	state.ConsecutiveCount = 0
	state.CandidateFirstSeen = time.Time{}
	state.CandidateLastSeen = time.Time{}
}

func advanceNSBaselineCandidate(state *NSBaselineState, observation DomainNSObservation) {
	if state.CandidateFingerprint == observation.Fingerprint && state.ConsecutiveCount > 0 {
		state.ConsecutiveCount++
		state.CandidateLastSeen = observation.CapturedAt
		state.Candidate = observation
		return
	}
	confirmed := state.Confirmed
	*state = newNSBaselineCandidate(observation)
	state.Confirmed = confirmed
}

func (b *nsAnalysisBuilder) add(snapshot namedCacheSnapshot) (SnapshotSummary, map[string]DomainNSObservation) {
	result := b.result
	observations := BuildNSObservations(snapshot.Cache, snapshot.CapturedAt, b.geo)
	id := snapshotID(snapshot.Source, snapshot.CapturedAt)
	if snapshot.Identity != "" {
		id = shortHash(snapshot.Identity + "|" + snapshot.CapturedAt.UTC().Format(time.RFC3339Nano))
	}
	sourceName := filepath.Base(snapshot.Source)
	sourcePath := snapshot.Source
	if snapshot.SourcePath != "" {
		sourceName = snapshot.Source
		sourcePath = snapshot.SourcePath
	}
	summary := SnapshotSummary{
		ID:             id,
		Source:         sourceName,
		View:           snapshot.Cache.View,
		CapturedAt:     snapshot.CapturedAt,
		Domains:        len(snapshot.Cache.records),
		NSObservations: len(observations),
	}
	result.Snapshots = append(result.Snapshots, summary)
	result.snapshotSources[summary.ID] = sourcePath
	result.snapshotIndex[summary.ID] = summary

	for domain, observation := range observations {
		state := b.baselineState(domain)
		baseline, confirmed := result.Baseline[domain]
		if !confirmed {
			advanceNSBaselineCandidate(&state, observation)
			if state.ConsecutiveCount < NSBaselineConsecutiveRequired {
				b.saveBaselineState(state)
				result.Current[domain] = observation
				continue
			}
			if campaignID, held := b.baselineHeld(domain); held {
				b.saveBaselineState(state)
				result.Current[domain] = observation
				if state.ConsecutiveCount == NSBaselineConsecutiveRequired {
					appendTimelinePoint(result.Timeline, domain, NSTimelinePoint{CapturedAt: observation.CapturedAt, NSCount: len(observation.Nameservers), Fingerprint: observation.Fingerprint, SnapshotID: summary.ID, State: "baseline_held", Severity: "medium", EventID: campaignID, Summary: "命中批量协同变化，连续12次仍冻结基线提升"})
				}
				continue
			}

			// 连续 12 次相同结果后才将候选提升为正式基线。候选过程只写
			// 轻量状态表，避免把首次缓存观察误称为可信基线。
			state.Confirmed = true
			resetNSBaselineCandidate(&state)
			b.saveBaselineState(state)
			result.Baseline[domain] = observation
			result.baselineUpdates[domain] = struct{}{}
			result.Current[domain] = observation
			appendTimelinePoint(result.Timeline, domain, NSTimelinePoint{CapturedAt: observation.CapturedAt, NSCount: len(observation.Nameservers), Fingerprint: observation.Fingerprint, SnapshotID: summary.ID, State: "baseline", Severity: "low", Summary: "连续12次同一 NS 结果，建立权威基线"})
			continue
		}

		diff := compareNSObservations(baseline, observation)
		if !diff.changed {
			if state.ConsecutiveCount > 0 || state.CandidateFingerprint != "" {
				resetNSBaselineCandidate(&state)
				state.Confirmed = true
				b.saveBaselineState(state)
			}
			if eventIndex, active := b.activeByDomain[domain]; active {
				event := &result.Events[eventIndex]
				event.Status = "resolved"
				resolvedAt := observation.CapturedAt
				event.ResolvedAt = &resolvedAt
				appendTimelinePoint(result.Timeline, domain, NSTimelinePoint{CapturedAt: observation.CapturedAt, NSCount: len(observation.Nameservers), Fingerprint: observation.Fingerprint, SnapshotID: summary.ID, State: "event_resolved", Severity: event.Severity, EventID: event.ID, Summary: "NS 状态已恢复至权威基线"})
				delete(b.activeByDomain, domain)
			} else if !b.persistedBaselines || len(result.Timeline[domain]) > 0 {
				// 历史回灌保留首次“基线一致”节点；常驻增量导入不会为每个
				// 稳定域名每 10 分钟额外写一条时间线，避免无效写入。
				appendTimelinePoint(result.Timeline, domain, NSTimelinePoint{CapturedAt: observation.CapturedAt, NSCount: len(observation.Nameservers), Fingerprint: observation.Fingerprint, SnapshotID: summary.ID, State: "normal", Severity: "low", Summary: "与权威基线一致"})
			}
			result.Current[domain] = observation
			continue
		}

		signature := diff.signature
		currentEventIndex := -1
		if eventIndex, active := b.activeByDomain[domain]; active && result.Events[eventIndex].signature == signature {
			event := &result.Events[eventIndex]
			event.LastSeen = observation.CapturedAt
			event.Occurrences++
			event.Current = observation
			if event.Occurrences >= 2 && event.Evidence != "verified" {
				event.Evidence = "repeated"
			}
			appendTimelinePoint(result.Timeline, domain, NSTimelinePoint{CapturedAt: observation.CapturedAt, NSCount: len(observation.Nameservers), Fingerprint: observation.Fingerprint, SnapshotID: summary.ID, State: "event_active", Severity: event.Severity, EventID: event.ID, Summary: "风险状态持续观测中"})
			currentEventIndex = eventIndex
		} else {
			event := NSChangeEvent{
				ID:          eventID(domain, observation.CapturedAt, signature),
				Domain:      domain,
				Severity:    diff.severity,
				Evidence:    "observed",
				Status:      "pending_verification",
				Summary:     diff.summary,
				ChangeTypes: diff.changeTypes,
				FirstSeen:   observation.CapturedAt,
				LastSeen:    observation.CapturedAt,
				Occurrences: 1,
				Baseline:    baseline,
				Current:     observation,
				signature:   signature,
			}
			result.Events = append(result.Events, event)
			currentEventIndex = len(result.Events) - 1
			b.activeByDomain[domain] = currentEventIndex
			appendTimelinePoint(result.Timeline, domain, NSTimelinePoint{CapturedAt: observation.CapturedAt, NSCount: len(observation.Nameservers), Fingerprint: observation.Fingerprint, SnapshotID: summary.ID, State: "event_started", Severity: event.Severity, EventID: event.ID, Summary: event.Summary})
		}

		advanceNSBaselineCandidate(&state, observation)
		if state.ConsecutiveCount >= NSBaselineConsecutiveRequired {
			if campaignID, held := b.baselineHeld(domain); held {
				b.saveBaselineState(state)
				if state.ConsecutiveCount == NSBaselineConsecutiveRequired {
					appendTimelinePoint(result.Timeline, domain, NSTimelinePoint{CapturedAt: observation.CapturedAt, NSCount: len(observation.Nameservers), Fingerprint: observation.Fingerprint, SnapshotID: summary.ID, State: "baseline_held", Severity: "medium", EventID: campaignID, Summary: "命中批量协同变化，连续12次仍冻结基线滚动"})
				}
				result.Current[domain] = observation
				continue
			}
			// 新指纹连续 12 次出现后滚动更新基线。此前的风险事件仍保留，
			// 仅以“基线已滚动”关闭，便于后续审计这次自动迁移。
			state.Confirmed = true
			resetNSBaselineCandidate(&state)
			b.saveBaselineState(state)
			result.Baseline[domain] = observation
			result.baselineUpdates[domain] = struct{}{}
			if currentEventIndex >= 0 {
				event := &result.Events[currentEventIndex]
				event.Status = "resolved"
				resolvedAt := observation.CapturedAt
				event.ResolvedAt = &resolvedAt
				event.Summary += "；新结果连续12次出现，基线已滚动更新"
				delete(b.activeByDomain, domain)
				appendTimelinePoint(result.Timeline, domain, NSTimelinePoint{CapturedAt: observation.CapturedAt, NSCount: len(observation.Nameservers), Fingerprint: observation.Fingerprint, SnapshotID: summary.ID, State: "baseline_rolled", Severity: event.Severity, EventID: event.ID, Summary: "新结果连续12次出现，基线已滚动更新"})
			}
		} else {
			b.saveBaselineState(state)
		}
		result.Current[domain] = observation
	}
	return summary, observations
}

func (b *nsAnalysisBuilder) finish() *NSAnalysis {
	result := b.result
	sort.Slice(result.Events, func(i, j int) bool {
		left, right := riskRank(result.Events[i].Severity), riskRank(result.Events[j].Severity)
		if left == right {
			return result.Events[i].LastSeen.After(result.Events[j].LastSeen)
		}
		return left > right
	})
	if len(result.Snapshots) == 0 {
		result.Warnings = append(result.Warnings, "未加载快照文件")
	}
	if !result.geoLoaded {
		result.Warnings = append(result.Warnings, "GeoLite 未加载：ASN/国家变化仅显示为网络元数据未知，不会提升风险等级")
	}
	return result
}

func appendTimelinePoint(timelines map[string][]NSTimelinePoint, domain string, point NSTimelinePoint) {
	points := timelines[domain]
	if len(points) > 0 {
		last := points[len(points)-1]
		if last.Fingerprint == point.Fingerprint && last.State == point.State && last.Severity == point.Severity && last.EventID == point.EventID {
			if point.State == "event_active" {
				points[len(points)-1] = point
				timelines[domain] = points
			}
			return
		}
	}
	timelines[domain] = append(points, point)
}

func BuildNSObservations(cache *BindCache, capturedAt time.Time, geo IPMetadataProvider) map[string]DomainNSObservation {
	observations := make(map[string]DomainNSObservation)
	for domain, record := range cache.records {
		byHost := make(map[string]NSHostObservation)
		for _, ns := range record.NSs {
			if ns.NsDomain == "" || mapAttributeToTrustLevel(ns.Attribute) < 7 {
				continue
			}
			host := normalizeFQDN(ns.NsDomain)
			candidate := NSHostObservation{Name: host, RegisteredDomain: registeredDomain(host), Attribute: ns.Attribute, TrustLevel: mapAttributeToTrustLevel(ns.Attribute)}
			if existing, ok := byHost[host]; !ok || candidate.TrustLevel > existing.TrustLevel {
				byHost[host] = candidate
			}
		}
		if len(byHost) == 0 {
			continue
		}

		hosts := make([]NSHostObservation, 0, len(byHost))
		for host, observation := range byHost {
			observation.Addresses = lookupNSAddresses(cache.records[host], geo)
			hosts = append(hosts, observation)
		}
		sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })
		observation := DomainNSObservation{Domain: domain, CapturedAt: capturedAt, Nameservers: hosts}
		observation.Fingerprint = nsFingerprint(observation)
		observations[domain] = observation
	}
	return observations
}

func lookupNSAddresses(record Record, geo IPMetadataProvider) []NSAddress {
	seen := make(map[string]struct{})
	addresses := make([]NSAddress, 0, len(record.As)+len(record.AAAAs))
	appendAddress := func(raw, family string) {
		if raw == "" {
			return
		}
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return
		}
		key := addr.String()
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		meta := IPMetadata{}
		if geo != nil {
			meta = geo.LookupIP(addr)
		}
		addresses = append(addresses, NSAddress{Address: key, Family: family, ASN: meta.ASN, ASNOrganization: meta.ASNOrganization, Country: meta.Country, MetadataAvailable: meta.Available, Reserved: isReservedNSAddress(addr)})
	}
	for _, a := range record.As {
		if a.Rcode == "" {
			appendAddress(a.IP, "IPv4")
		}
	}
	for _, aaaa := range record.AAAAs {
		if aaaa.Rcode == "" {
			appendAddress(aaaa.IP, "IPv6")
		}
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Address < addresses[j].Address })
	return addresses
}

func isReservedNSAddress(addr netip.Addr) bool {
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() || addr.IsMulticast()
}

func normalizeFQDN(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name != "" && !strings.HasSuffix(name, ".") {
		return name + "."
	}
	return name
}

func registeredDomain(name string) string {
	name = strings.TrimSuffix(normalizeFQDN(name), ".")
	if name == "" {
		return ""
	}
	registered, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err == nil {
		return registered
	}
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return name
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

func nsFingerprint(observation DomainNSObservation) string {
	parts := make([]string, 0, len(observation.Nameservers))
	for _, host := range observation.Nameservers {
		addresses := make([]string, 0, len(host.Addresses))
		for _, address := range host.Addresses {
			addresses = append(addresses, address.Address)
		}
		parts = append(parts, host.Name+"|"+strings.Join(addresses, ","))
	}
	return shortHash(strings.Join(parts, ";"))
}

type nsObservationDiff struct {
	changed     bool
	severity    string
	changeTypes []string
	summary     string
	signature   string
}

func compareNSObservations(baseline, current DomainNSObservation) nsObservationDiff {
	baseHosts := nsHostMap(baseline.Nameservers)
	currentHosts := nsHostMap(current.Nameservers)
	added, removed := setDifference(currentHosts, baseHosts), setDifference(baseHosts, currentHosts)
	changeTypes := make([]string, 0, 5)
	severity := "low"
	if len(added) > 0 {
		changeTypes = append(changeTypes, "ns_added")
	}
	if len(removed) > 0 {
		changeTypes = append(changeTypes, "ns_removed")
	}
	if len(baseline.Nameservers) != len(current.Nameservers) {
		changeTypes = append(changeTypes, "ns_count_changed")
	}

	baseOwners := ownerSet(baseline.Nameservers)
	foreignOwner := false
	for _, host := range added {
		if _, exists := baseOwners[currentHosts[host].RegisteredDomain]; !exists {
			foreignOwner = true
			break
		}
	}
	if foreignOwner {
		severity = "high"
		changeTypes = append(changeTypes, "ns_owner_changed")
	}

	networkSeverity, networkChanged, privateAddress, metadataUnknown, familyReductionOnly := compareNSEndpoints(baseHosts, currentHosts)
	if networkChanged {
		if familyReductionOnly {
			changeTypes = append(changeTypes, "ns_address_family_reduced")
		} else {
			changeTypes = append(changeTypes, "ns_ip_changed")
		}
	}
	if metadataUnknown {
		changeTypes = append(changeTypes, "network_metadata_unknown")
	}
	if privateAddress {
		severity = "critical"
		changeTypes = append(changeTypes, "reserved_ns_ip")
	} else if riskRank(networkSeverity) > riskRank(severity) {
		severity = networkSeverity
		if networkSeverity == "high" || networkSeverity == "medium" {
			changeTypes = append(changeTypes, "ns_network_changed")
		}
	}

	changed := len(changeTypes) > 0 && !(len(changeTypes) == 1 && changeTypes[0] == "network_metadata_unknown")
	if !changed {
		return nsObservationDiff{}
	}

	summaryParts := make([]string, 0, 3)
	if len(added) > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("新增 %d 个 NS", len(added)))
	}
	if len(removed) > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("减少 %d 个 NS", len(removed)))
	}
	if foreignOwner {
		summaryParts = append(summaryParts, "新增 NS 跨主域")
	}
	if privateAddress {
		summaryParts = append(summaryParts, "NS 指向保留或私网地址")
	} else if networkSeverity == "high" {
		summaryParts = append(summaryParts, "NS IP 的 ASN 与国家均变化")
	} else if networkSeverity == "medium" {
		summaryParts = append(summaryParts, "NS IP 的 ASN 或国家变化")
	} else if familyReductionOnly {
		summaryParts = append(summaryParts, "NS 地址族减少但仍保留可用地址")
	} else if networkChanged {
		summaryParts = append(summaryParts, "NS IP 变化但网络归属一致")
	}
	if len(summaryParts) == 0 {
		summaryParts = append(summaryParts, "NS 集合发生变化")
	}

	signature := strings.Join([]string{baseline.Fingerprint, current.Fingerprint, strings.Join(changeTypes, ",")}, "|")
	return nsObservationDiff{changed: true, severity: severity, changeTypes: changeTypes, summary: strings.Join(summaryParts, "；"), signature: signature}
}

func nsHostMap(hosts []NSHostObservation) map[string]NSHostObservation {
	result := make(map[string]NSHostObservation, len(hosts))
	for _, host := range hosts {
		result[host.Name] = host
	}
	return result
}

func ownerSet(hosts []NSHostObservation) map[string]struct{} {
	result := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		result[host.RegisteredDomain] = struct{}{}
	}
	return result
}

func setDifference(left, right map[string]NSHostObservation) []string {
	result := make([]string, 0)
	for key := range left {
		if _, exists := right[key]; !exists {
			result = append(result, key)
		}
	}
	sort.Strings(result)
	return result
}

func compareNSEndpoints(baseline, current map[string]NSHostObservation) (severity string, changed, privateAddress, metadataUnknown, familyReductionOnly bool) {
	severity = "low"
	familyReductionOnly = true
	for host, currentHost := range current {
		baselineHost, exists := baseline[host]
		if !exists {
			for _, address := range currentHost.Addresses {
				privateAddress = privateAddress || address.Reserved
			}
			continue
		}
		if addressesFingerprint(baselineHost.Addresses) == addressesFingerprint(currentHost.Addresses) {
			continue
		}
		changed = true
		if !isAddressFamilyReduction(baselineHost.Addresses, currentHost.Addresses) {
			familyReductionOnly = false
		}
		for _, address := range currentHost.Addresses {
			privateAddress = privateAddress || address.Reserved
		}

		oldASNs, newASNs := asnSet(baselineHost.Addresses), asnSet(currentHost.Addresses)
		oldCountries, newCountries := countrySet(baselineHost.Addresses), countrySet(currentHost.Addresses)
		if len(oldASNs) == 0 || len(newASNs) == 0 || len(oldCountries) == 0 || len(newCountries) == 0 {
			metadataUnknown = true
			continue
		}
		asnChanged := disjointStringSets(oldASNs, newASNs)
		countryChanged := disjointStringSets(oldCountries, newCountries)
		switch {
		case asnChanged && countryChanged:
			severity = maxRisk(severity, "high")
		case asnChanged || countryChanged:
			severity = maxRisk(severity, "medium")
		}
	}
	if !changed {
		familyReductionOnly = false
	}
	return severity, changed, privateAddress, metadataUnknown, familyReductionOnly
}

func isAddressFamilyReduction(previous, current []NSAddress) bool {
	if len(previous) == 0 || len(current) == 0 || len(current) >= len(previous) {
		return false
	}
	previousSet := make(map[string]struct{}, len(previous))
	currentFamilies, removedFamilies := make(map[bool]struct{}), make(map[bool]struct{})
	for _, address := range previous {
		addr, err := netip.ParseAddr(address.Address)
		if err == nil {
			previousSet[addr.String()] = struct{}{}
		}
	}
	for _, address := range current {
		addr, err := netip.ParseAddr(address.Address)
		if err != nil {
			return false
		}
		if _, existed := previousSet[addr.String()]; !existed {
			return false
		}
		currentFamilies[addr.Is4()] = struct{}{}
		delete(previousSet, addr.String())
	}
	for address := range previousSet {
		addr, _ := netip.ParseAddr(address)
		removedFamilies[addr.Is4()] = struct{}{}
	}
	for family := range removedFamilies {
		if _, retained := currentFamilies[family]; !retained {
			return true
		}
	}
	return false
}

func addressesFingerprint(addresses []NSAddress) string {
	values := make([]string, 0, len(addresses))
	for _, address := range addresses {
		values = append(values, address.Address)
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func asnSet(addresses []NSAddress) map[string]struct{} {
	result := make(map[string]struct{})
	for _, address := range addresses {
		if address.ASN != 0 {
			result[strconv.FormatUint(uint64(address.ASN), 10)] = struct{}{}
		}
	}
	return result
}

func countrySet(addresses []NSAddress) map[string]struct{} {
	result := make(map[string]struct{})
	for _, address := range addresses {
		if address.Country != "" {
			result[address.Country] = struct{}{}
		}
	}
	return result
}

func disjointStringSets(left, right map[string]struct{}) bool {
	for value := range left {
		if _, exists := right[value]; exists {
			return false
		}
	}
	return true
}

func maxRisk(left, right string) string {
	if riskRank(right) > riskRank(left) {
		return right
	}
	return left
}

func riskRank(level string) int {
	switch level {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func snapshotID(source string, capturedAt time.Time) string {
	return shortHash(filepath.Base(source) + "|" + capturedAt.UTC().Format(time.RFC3339Nano))
}

func eventID(domain string, capturedAt time.Time, signature string) string {
	return shortHash(domain + "|" + capturedAt.UTC().Format(time.RFC3339Nano) + "|" + signature)
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

var snapshotFilenameTimePattern = regexp.MustCompile(`\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}`)

func parseSnapshotTime(raw, filename string) time.Time {
	// BIND dump 的 $DATE 使用 UTC；示例文件名使用本地采集时间（UTC+8）。
	for _, layout := range []string{"20060102150405", "2006-01-02 15:04:05", time.RFC3339} {
		if parsed, err := time.ParseInLocation(layout, raw, time.UTC); err == nil {
			return parsed.UTC()
		}
	}
	if parsed, ok := snapshotTimeFromFilename(filename); ok {
		return parsed.UTC()
	}
	if info, err := os.Stat(filename); err == nil {
		return info.ModTime().UTC()
	}
	return time.Now().UTC()
}

func snapshotTimeFromFilename(filename string) (time.Time, bool) {
	match := snapshotFilenameTimePattern.FindString(filepath.Base(filename))
	if match == "" {
		return time.Time{}, false
	}
	parsed, err := time.ParseInLocation("2006-01-02_15-04-05", match, time.Local)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

func sortSnapshotFiles(files []string) {
	sort.SliceStable(files, func(i, j int) bool {
		left, leftOK := snapshotTimeFromFilename(files[i])
		right, rightOK := snapshotTimeFromFilename(files[j])
		if leftOK && rightOK && !left.Equal(right) {
			return left.Before(right)
		}
		return files[i] < files[j]
	})
}

func ParseSnapshotInputs(defaultFile, supplied string) ([]string, error) {
	inputs := []string{defaultFile}
	if strings.TrimSpace(supplied) != "" {
		inputs = strings.Split(supplied, ",")
	}
	files := make([]string, 0, len(inputs))
	seen := make(map[string]struct{})
	for _, input := range inputs {
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}
		info, err := os.Stat(input)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			if _, exists := seen[input]; !exists {
				seen[input] = struct{}{}
				files = append(files, input)
			}
			continue
		}
		entries, err := os.ReadDir(input)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".db") {
				continue
			}
			filename := filepath.Join(input, entry.Name())
			if _, exists := seen[filename]; !exists {
				seen[filename] = struct{}{}
				files = append(files, filename)
			}
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("未提供可解析的快照文件")
	}
	sortSnapshotFiles(files)
	return files, nil
}

func (a *NSAnalysis) Overview() NSOverview {
	overview := NSOverview{Snapshots: len(a.Snapshots), TrackedDomains: len(a.Baseline), EventCounts: map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}, GeoLiteLoaded: a.geoLoaded, GeoLiteSource: a.geoSource, Warnings: a.Warnings}
	if len(a.Snapshots) > 0 {
		overview.LatestSnapshot = a.Snapshots[len(a.Snapshots)-1]
	}
	for _, event := range a.Events {
		overview.EventCounts[event.Severity]++
		if event.Status != "resolved" {
			overview.ActiveEvents++
		}
	}
	return overview
}

func (a *NSAnalysis) DomainDetail(domain string) (DomainNSDetail, bool) {
	domain = normalizeFQDN(domain)
	baseline, exists := a.Baseline[domain]
	if !exists {
		return DomainNSDetail{}, false
	}
	events := make([]NSChangeEvent, 0)
	for _, event := range a.Events {
		if event.Domain == domain {
			events = append(events, event)
		}
	}
	return DomainNSDetail{Domain: domain, Baseline: baseline, BaselineSource: "confirmed", Current: a.Current[domain], Timeline: a.Timeline[domain], Events: events}, true
}
