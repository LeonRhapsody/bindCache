package main

import (
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const campaignStateVersion = 1

type CampaignRuntimeConfig struct {
	Enabled          bool   `json:"enabled"`
	MinDistinctZones int    `json:"min_distinct_zones"`
	HoldBaseline     bool   `json:"hold_baseline"`
	StatePath        string `json:"state_path"`
	MaxSnapshotGap   string `json:"max_snapshot_gap"`
}

type DNSCampaignEvent struct {
	ID                 string              `json:"id"`
	Type               string              `json:"type"`
	Target             string              `json:"target"`
	Severity           string              `json:"severity"`
	Evidence           string              `json:"evidence"`
	Status             string              `json:"status"`
	PreviousSnapshotID string              `json:"previous_snapshot_id"`
	CurrentSnapshotID  string              `json:"current_snapshot_id"`
	FirstSeen          time.Time           `json:"first_seen"`
	LastSeen           time.Time           `json:"last_seen"`
	ZoneCount          int                 `json:"zone_count"`
	NSHostCount        int                 `json:"ns_host_count"`
	RecordCount        int                 `json:"record_count"`
	Zones              []string            `json:"zones"`
	Changes            []DNSCampaignChange `json:"changes"`
	Summary            string              `json:"summary"`
	Signature          string              `json:"-"`
}

type DNSCampaignChange struct {
	Zone           string   `json:"zone"`
	RecordName     string   `json:"record_name,omitempty"`
	NSHost         string   `json:"ns_host,omitempty"`
	PreviousOwners []string `json:"previous_owners"`
	CurrentOwners  []string `json:"current_owners"`
	PreviousValues []string `json:"previous_values"`
	CurrentValues  []string `json:"current_values"`
}

type campaignSnapshotState struct {
	Version    int                            `json:"version"`
	SnapshotID string                         `json:"snapshot_id"`
	CapturedAt time.Time                      `json:"captured_at"`
	View       string                         `json:"view"`
	NS         map[string]map[string][]string `json:"ns"`
	A          map[string][]string            `json:"a"`
}

type nsCampaignTracker struct {
	config   CampaignRuntimeConfig
	path     string
	previous *campaignSnapshotState
	next     *campaignSnapshotState
	events   []DNSCampaignEvent
}

func newNSCampaignTracker(config CampaignRuntimeConfig, ledgerPath string) (*nsCampaignTracker, error) {
	if !config.Enabled {
		return nil, nil
	}
	if config.MinDistinctZones <= 0 {
		config.MinDistinctZones = 10
	}
	path := strings.TrimSpace(config.StatePath)
	if path == "" {
		path = strings.TrimSuffix(strings.TrimSpace(ledgerPath), filepath.Ext(ledgerPath)) + "-campaign-state.json.gz"
	}
	if path == "-campaign-state.json.gz" {
		path = filepath.Join(os.TempDir(), "bind-cache-analyze-campaign-state.json.gz")
	}
	state, err := loadCampaignSnapshotState(path)
	if err != nil {
		return nil, err
	}
	return &nsCampaignTracker{config: config, path: path, previous: state}, nil
}

func (t *nsCampaignTracker) observe(summary SnapshotSummary, observations map[string]DomainNSObservation, cache *BindCache) {
	if t == nil {
		return
	}
	current := buildCampaignSnapshotState(summary, observations, cache)
	if t.previous != nil && t.previous.View == current.View && campaignSnapshotsAdjacent(*t.previous, *current, t.config.MaxSnapshotGap) {
		t.events = append(t.events, detectDNSCampaigns(*t.previous, *current, t.config.MinDistinctZones)...)
	}
	t.previous = current
	t.next = current
}

func campaignSnapshotsAdjacent(previous, current campaignSnapshotState, configuredGap string) bool {
	if !current.CapturedAt.After(previous.CapturedAt) {
		return false
	}
	maxGap := 30 * time.Minute
	if parsed, err := time.ParseDuration(strings.TrimSpace(configuredGap)); err == nil && parsed > 0 {
		maxGap = parsed
	}
	return current.CapturedAt.Sub(previous.CapturedAt) <= maxGap
}

func buildCampaignSnapshotState(summary SnapshotSummary, observations map[string]DomainNSObservation, cache *BindCache) *campaignSnapshotState {
	state := &campaignSnapshotState{Version: campaignStateVersion, SnapshotID: summary.ID, CapturedAt: summary.CapturedAt, View: summary.View, NS: make(map[string]map[string][]string), A: make(map[string][]string)}
	nsOwners := make(map[string]struct{})
	for zone, observation := range observations {
		zone = normalizeFQDN(zone)
		state.NS[zone] = make(map[string][]string)
		for _, host := range observation.Nameservers {
			name := normalizeFQDN(host.Name)
			nsOwners[name] = struct{}{}
			ips := make([]string, 0, len(host.Addresses))
			for _, address := range host.Addresses {
				if ip, err := netip.ParseAddr(address.Address); err == nil {
					ips = append(ips, ip.String())
				}
			}
			sort.Strings(ips)
			state.NS[zone][name] = uniqueStrings(ips)
		}
	}
	if cache != nil {
		for owner, record := range cache.records {
			owner = normalizeFQDN(owner)
			if _, isNSHost := nsOwners[owner]; isNSHost {
				continue
			}
			ips := make([]string, 0, len(record.As))
			for _, answer := range record.As {
				if answer.Rcode != "" {
					continue
				}
				if ip, err := netip.ParseAddr(answer.IP); err == nil && ip.Is4() {
					ips = append(ips, ip.String())
				}
			}
			if len(ips) > 0 {
				sort.Strings(ips)
				state.A[owner] = uniqueStrings(ips)
			}
		}
	}
	return state
}

func detectDNSCampaigns(previous, current campaignSnapshotState, threshold int) []DNSCampaignEvent {
	if threshold <= 0 {
		threshold = 10
	}
	type bucket struct {
		zones, hosts, records map[string]struct{}
		changes               map[string]DNSCampaignChange
	}
	newBucket := func() *bucket {
		return &bucket{zones: map[string]struct{}{}, hosts: map[string]struct{}{}, records: map[string]struct{}{}, changes: map[string]DNSCampaignChange{}}
	}
	nsNames := map[string]*bucket{}
	nsIPs := map[string]*bucket{}
	aIPs := map[string]*bucket{}
	for zone, currentHosts := range current.NS {
		previousHosts, existed := previous.NS[zone]
		if !existed { // 只比较相邻快照中都存在的 zone，避免“首次看见”被当作变更。
			continue
		}
		previousOwners, currentOwners := campaignNSOwners(previousHosts), campaignNSOwners(currentHosts)
		previousZoneIPs, currentZoneIPs := campaignNSIPs(previousHosts), campaignNSIPs(currentHosts)
		for _, owner := range stringDifference(currentOwners, previousOwners) {
			b := nsNames[owner]
			if b == nil {
				b = newBucket()
				nsNames[owner] = b
			}
			b.zones[zone] = struct{}{}
			for host := range currentHosts {
				if campaignNSOwner(host) == owner {
					b.hosts[host] = struct{}{}
				}
			}
			b.changes[zone] = DNSCampaignChange{Zone: zone, PreviousOwners: previousOwners, CurrentOwners: currentOwners, PreviousValues: campaignNSHostNames(previousHosts), CurrentValues: campaignNSHostNames(currentHosts)}
		}
		// IP 协同变化要求相邻两侧都有有效观测。前值为空只表示该 NS
		// 端点首次被解析出来，不能证明它从其他 IP “换指”到了当前 IP。
		if len(previousZoneIPs) > 0 && len(currentZoneIPs) > 0 {
			for _, ip := range stringDifference(currentZoneIPs, previousZoneIPs) {
				b := nsIPs[ip]
				if b == nil {
					b = newBucket()
					nsIPs[ip] = b
				}
				b.zones[zone] = struct{}{}
				for host, ips := range currentHosts {
					if stringSetContains(ips, ip) {
						b.hosts[host] = struct{}{}
					}
				}
				b.changes[zone] = DNSCampaignChange{Zone: zone, PreviousOwners: previousOwners, CurrentOwners: currentOwners, PreviousValues: previousZoneIPs, CurrentValues: currentZoneIPs}
			}
		}
		for host, currentIPs := range currentHosts {
			previousIPs, hostExisted := previousHosts[host]
			if !hostExisted || len(previousIPs) == 0 || len(currentIPs) == 0 {
				continue
			}
			for _, ip := range stringDifference(currentIPs, previousIPs) {
				b := nsIPs[ip]
				if b == nil {
					b = newBucket()
					nsIPs[ip] = b
				}
				b.zones[zone] = struct{}{}
				b.hosts[host] = struct{}{}
				change := b.changes[zone]
				change.Zone, change.NSHost = zone, host
				change.PreviousOwners, change.CurrentOwners = previousOwners, currentOwners
				change.PreviousValues, change.CurrentValues = previousIPs, currentIPs
				b.changes[zone] = change
			}
		}
	}
	zones := make([]string, 0, len(previous.NS)+len(current.NS))
	seenZones := make(map[string]struct{})
	for zone := range previous.NS {
		seenZones[zone] = struct{}{}
	}
	for zone := range current.NS {
		seenZones[zone] = struct{}{}
	}
	for zone := range seenZones {
		zones = append(zones, zone)
	}
	sort.Slice(zones, func(i, j int) bool { return len(zones[i]) > len(zones[j]) })
	for owner, currentIPs := range current.A {
		previousIPs, existed := previous.A[owner]
		if !existed || len(previousIPs) == 0 || len(currentIPs) == 0 {
			continue
		}
		zone := nearestObservedZone(owner, zones)
		if zone == "" {
			continue
		}
		for _, ip := range stringDifference(currentIPs, previousIPs) {
			b := aIPs[ip]
			if b == nil {
				b = newBucket()
				aIPs[ip] = b
			}
			b.zones[zone] = struct{}{}
			b.records[owner] = struct{}{}
			b.changes[zone] = DNSCampaignChange{Zone: zone, RecordName: owner, PreviousValues: previousIPs, CurrentValues: currentIPs, PreviousOwners: []string{}, CurrentOwners: []string{}}
		}
	}
	events := make([]DNSCampaignEvent, 0)
	appendBuckets := func(kind string, buckets map[string]*bucket) {
		for target, b := range buckets {
			if len(b.zones) < threshold {
				continue
			}
			zoneList := setKeys(b.zones)
			severity := "medium"
			if len(zoneList) >= threshold*2 {
				severity = "high"
			}
			if ip, err := netip.ParseAddr(target); err == nil && isReservedNSAddress(ip) {
				severity = "critical"
			}
			label := map[string]string{"same_new_ns": "NS 归属同时转入同一 NS 主域", "same_ns_ip": "NS 端点同时指向同一 IP", "same_a_ip": "A 记录同时指向同一 IP"}[kind]
			signature := kind + "|" + target
			changes := make([]DNSCampaignChange, 0, len(zoneList))
			for _, zone := range zoneList {
				changes = append(changes, b.changes[zone])
			}
			events = append(events, DNSCampaignEvent{ID: "CAM-" + shortHash(previous.SnapshotID+"|"+current.SnapshotID+"|"+signature), Type: kind, Target: target, Severity: severity, Evidence: "observed", Status: "active", PreviousSnapshotID: previous.SnapshotID, CurrentSnapshotID: current.SnapshotID, FirstSeen: current.CapturedAt, LastSeen: current.CapturedAt, ZoneCount: len(zoneList), NSHostCount: len(b.hosts), RecordCount: len(b.records), Zones: zoneList, Changes: changes, Summary: fmt.Sprintf("相邻快照中 %d 个不同 zone %s：%s", len(zoneList), label, target), Signature: signature})
		}
	}
	appendBuckets("same_new_ns", nsNames)
	appendBuckets("same_ns_ip", nsIPs)
	appendBuckets("same_a_ip", aIPs)
	sort.Slice(events, func(i, j int) bool {
		if events[i].ZoneCount == events[j].ZoneCount {
			return events[i].ID < events[j].ID
		}
		return events[i].ZoneCount > events[j].ZoneCount
	})
	return events
}

// isFirstIPObservationCampaign identifies historical same-IP events that were
// created only because the previous snapshot had no usable IP value. Keep the
// stored row for audit, but do not expose it as a coordinated change or use it
// to freeze baseline promotion.
func isFirstIPObservationCampaign(event DNSCampaignEvent) bool {
	if event.Type != "same_ns_ip" && event.Type != "same_a_ip" {
		return false
	}
	if len(event.Changes) == 0 {
		return false
	}
	for _, change := range event.Changes {
		if len(change.PreviousValues) > 0 {
			return false
		}
	}
	return true
}

func campaignNSOwner(host string) string {
	owner := registeredDomain(host)
	if owner == "" {
		return normalizeFQDN(host)
	}
	return normalizeFQDN(owner)
}

func campaignNSOwners(hosts map[string][]string) []string {
	values := make([]string, 0, len(hosts))
	for host := range hosts {
		values = append(values, campaignNSOwner(host))
	}
	sort.Strings(values)
	return uniqueStrings(values)
}

func campaignNSHostNames(hosts map[string][]string) []string {
	values := make([]string, 0, len(hosts))
	for host := range hosts {
		values = append(values, normalizeFQDN(host))
	}
	sort.Strings(values)
	return values
}

func campaignNSIPs(hosts map[string][]string) []string {
	values := make([]string, 0)
	for _, ips := range hosts {
		values = append(values, ips...)
	}
	sort.Strings(values)
	return uniqueStrings(values)
}

func stringSetContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func nearestObservedZone(owner string, zones []string) string {
	owner = normalizeFQDN(owner)
	for _, zone := range zones {
		zone = normalizeFQDN(zone)
		if owner == zone || strings.HasSuffix(owner, "."+zone) {
			return zone
		}
	}
	return ""
}

func stringDifference(current, previous []string) []string {
	seen := make(map[string]struct{}, len(previous))
	for _, value := range previous {
		seen[value] = struct{}{}
	}
	result := make([]string, 0)
	for _, value := range current {
		if _, ok := seen[value]; !ok {
			result = append(result, value)
		}
	}
	return uniqueStrings(result)
}
func uniqueStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:0]
	var last string
	for i, v := range values {
		if i == 0 || v != last {
			out = append(out, v)
			last = v
		}
	}
	return out
}
func setKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for v := range values {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func loadCampaignSnapshotState(path string) (*campaignSnapshotState, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读取批量变化状态: %w", err)
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("解压批量变化状态: %w", err)
	}
	defer reader.Close()
	var state campaignSnapshotState
	if err := json.NewDecoder(reader).Decode(&state); err != nil {
		return nil, fmt.Errorf("解析批量变化状态: %w", err)
	}
	if state.Version != campaignStateVersion {
		return nil, fmt.Errorf("不支持的批量变化状态版本 %d", state.Version)
	}
	return &state, nil
}

func saveCampaignSnapshotState(path string, state *campaignSnapshotState) error {
	if state == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	temporary := path + ".tmp"
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	writer := gzip.NewWriter(file)
	encodeErr := json.NewEncoder(writer).Encode(state)
	closeErr := writer.Close()
	fileErr := file.Close()
	if encodeErr != nil {
		return encodeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if fileErr != nil {
		return fileErr
	}
	return os.Rename(temporary, path)
}

func insertDNSCampaignEvents(writer *nsClickHouseWriter, events []DNSCampaignEvent) error {
	if len(events) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	batch, err := writer.conn.PrepareBatch(ctx, `INSERT INTO dns_campaign_events (event_id,campaign_type,target,severity,evidence,status,previous_snapshot_id,current_snapshot_id,first_seen,last_seen,zone_count,ns_host_count,record_count,zones_json,changes_json,summary,signature)`)
	if err != nil {
		return err
	}
	for _, event := range events {
		zonesRaw, _ := json.Marshal(event.Zones)
		changesRaw, _ := json.Marshal(event.Changes)
		if err := batch.Append(event.ID, event.Type, event.Target, event.Severity, event.Evidence, event.Status, event.PreviousSnapshotID, event.CurrentSnapshotID, event.FirstSeen, event.LastSeen, uint32(event.ZoneCount), uint32(event.NSHostCount), uint32(event.RecordCount), string(zonesRaw), string(changesRaw), event.Summary, event.Signature); err != nil {
			return err
		}
	}
	return batch.Send()
}

func loadActiveCampaignHolds(db *sql.DB) (map[string]string, error) {
	rows, err := db.Query(`SELECT zone, campaign_id FROM ns_campaign_holds GROUP BY zone, campaign_id HAVING argMax(active, updated_at)=1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type holdPair struct{ zone, eventID string }
	pairs := make([]holdPair, 0)
	for rows.Next() {
		var zone, id string
		if err := rows.Scan(&zone, &id); err != nil {
			return nil, err
		}
		pairs = append(pairs, holdPair{normalizeFQDN(zone), id})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	invalidCampaigns, err := loadFirstIPObservationCampaignIDs(db)
	if err != nil {
		return nil, err
	}
	actionRows, err := db.Query(`SELECT event_id, argMax(action, acted_at), argMax(expires_at, acted_at) FROM ns_event_actions GROUP BY event_id`)
	if err != nil {
		return nil, err
	}
	defer actionRows.Close()
	released := map[string]struct{}{}
	for actionRows.Next() {
		var eventID, action string
		var expires sql.NullTime
		if err := actionRows.Scan(&eventID, &action, &expires); err != nil {
			return nil, err
		}
		if action == "ignore" || (action == "whitelist" && expires.Valid && expires.Time.After(time.Now())) {
			released[eventID] = struct{}{}
		}
	}
	if err := actionRows.Err(); err != nil {
		return nil, err
	}
	holds := map[string]string{}
	for _, pair := range pairs {
		if _, invalid := invalidCampaigns[pair.eventID]; invalid {
			continue
		}
		if _, ok := released[pair.eventID]; !ok {
			holds[pair.zone] = pair.eventID
		}
	}
	return holds, nil
}

func loadFirstIPObservationCampaignIDs(db *sql.DB) (map[string]struct{}, error) {
	rows, err := db.Query(`SELECT event_id,campaign_type,changes_json FROM dns_campaign_events FINAL WHERE campaign_type IN ('same_ns_ip','same_a_ip')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]struct{}{}
	for rows.Next() {
		var event DNSCampaignEvent
		var changes string
		if err := rows.Scan(&event.ID, &event.Type, &changes); err != nil {
			return nil, err
		}
		if json.Unmarshal([]byte(changes), &event.Changes) == nil && isFirstIPObservationCampaign(event) {
			result[event.ID] = struct{}{}
		}
	}
	return result, rows.Err()
}

func insertCampaignHolds(writer *nsClickHouseWriter, events []DNSCampaignEvent) error {
	if len(events) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	batch, err := writer.conn.PrepareBatch(ctx, `INSERT INTO ns_campaign_holds (zone,campaign_id,target_fingerprint,active)`)
	if err != nil {
		return err
	}
	for _, event := range events {
		for _, zone := range event.Zones {
			if err := batch.Append(zone, event.ID, event.Signature, uint8(1)); err != nil {
				return err
			}
		}
	}
	return batch.Send()
}

// backfillLatestNSCampaignsIfEmpty performs a one-time upgrade backfill from the
// two newest persisted real snapshots. Persisted observations contain NS data but
// not arbitrary A RRs, so same_a_ip starts with the next adjacent raw dump pair.
func backfillLatestNSCampaignsIfEmpty(db *sql.DB, writer *nsClickHouseWriter, config CampaignRuntimeConfig) ([]DNSCampaignEvent, error) {
	if !config.Enabled {
		return nil, nil
	}
	var existing uint64
	if err := db.QueryRow(`SELECT count() FROM dns_campaign_events`).Scan(&existing); err != nil || existing > 0 {
		return nil, err
	}
	states, err := loadLatestPersistedCampaignStates(db)
	if err != nil || len(states) < 2 {
		return nil, err
	}
	events := detectDNSCampaigns(states[1], states[0], config.MinDistinctZones)
	if err := insertDNSCampaignEvents(writer, events); err != nil {
		return nil, err
	}
	if config.HoldBaseline {
		if err := insertCampaignHolds(writer, events); err != nil {
			return nil, err
		}
	}
	return events, nil
}

func loadLatestPersistedCampaignStates(db *sql.DB) ([]campaignSnapshotState, error) {
	rows, err := db.Query(`SELECT snapshot_id, view, captured_at FROM ns_snapshot_catalog FINAL ORDER BY captured_at DESC LIMIT 2`)
	if err != nil {
		return nil, err
	}
	type catalog struct {
		id, view string
		captured time.Time
	}
	latest := make([]catalog, 0, 2)
	for rows.Next() {
		var value catalog
		if err := rows.Scan(&value.id, &value.view, &value.captured); err != nil {
			_ = rows.Close()
			return nil, err
		}
		latest = append(latest, value)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	states := make([]campaignSnapshotState, 0, len(latest))
	for _, value := range latest {
		state := campaignSnapshotState{Version: campaignStateVersion, SnapshotID: value.id, CapturedAt: value.captured, View: value.view, NS: map[string]map[string][]string{}, A: map[string][]string{}}
		observationRows, err := db.Query(`SELECT domain, nameservers_json FROM ns_domain_observations FINAL WHERE snapshot_id=?`, value.id)
		if err != nil {
			return nil, err
		}
		for observationRows.Next() {
			var domain, raw string
			if err := observationRows.Scan(&domain, &raw); err != nil {
				_ = observationRows.Close()
				return nil, err
			}
			var hosts []NSHostObservation
			if err := json.Unmarshal([]byte(raw), &hosts); err != nil {
				_ = observationRows.Close()
				return nil, err
			}
			domain = normalizeFQDN(domain)
			state.NS[domain] = map[string][]string{}
			for _, host := range hosts {
				name := normalizeFQDN(host.Name)
				for _, address := range host.Addresses {
					state.NS[domain][name] = append(state.NS[domain][name], address.Address)
				}
				sort.Strings(state.NS[domain][name])
				state.NS[domain][name] = uniqueStrings(state.NS[domain][name])
			}
		}
		if err := observationRows.Close(); err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	return states, nil
}

// applyCurrentCampaignHolds covers the upgrade/backfill edge where a campaign is
// first recognized on exactly the 12th candidate snapshot, after builder.add has
// tentatively promoted it. Normal continuous imports are already protected by the
// persisted hold loaded before analysis.
func applyCurrentCampaignHolds(analysis *NSAnalysis, previousBaselines map[string]DomainNSObservation, events []DNSCampaignEvent) {
	if analysis == nil || len(events) == 0 {
		return
	}
	for _, event := range events {
		for _, zone := range event.Zones {
			zone = normalizeFQDN(zone)
			if _, promoted := analysis.baselineUpdates[zone]; !promoted {
				continue
			}
			current := analysis.Current[zone]
			state := newNSBaselineCandidate(current)
			state.ConsecutiveCount = NSBaselineConsecutiveRequired
			state.Confirmed = previousBaselines[zone].Domain != ""
			analysis.baselineStates[zone] = state
			analysis.baselineStateDirty[zone] = struct{}{}
			delete(analysis.baselineUpdates, zone)
			if baseline, existed := previousBaselines[zone]; existed {
				analysis.Baseline[zone] = baseline
			} else {
				delete(analysis.Baseline, zone)
			}
			points := analysis.Timeline[zone][:0]
			for _, point := range analysis.Timeline[zone] {
				if point.SnapshotID == event.CurrentSnapshotID && (point.State == "baseline" || point.State == "baseline_rolled") {
					continue
				}
				points = append(points, point)
			}
			analysis.Timeline[zone] = points
			appendTimelinePoint(analysis.Timeline, zone, NSTimelinePoint{CapturedAt: current.CapturedAt, NSCount: len(current.Nameservers), Fingerprint: current.Fingerprint, SnapshotID: event.CurrentSnapshotID, State: "baseline_held", Severity: event.Severity, EventID: event.ID, Summary: "命中批量协同变化，连续12次仍冻结基线提升"})
			for index := range analysis.Events {
				if analysis.Events[index].Domain == zone && analysis.Events[index].ResolvedAt != nil && analysis.Events[index].ResolvedAt.Equal(current.CapturedAt) {
					analysis.Events[index].Status = "pending_verification"
					analysis.Events[index].ResolvedAt = nil
					analysis.Events[index].Summary = strings.TrimSuffix(analysis.Events[index].Summary, "；新结果连续12次出现，基线已滚动更新")
				}
			}
		}
	}
}
