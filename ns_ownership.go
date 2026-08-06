package main

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type NSOwnershipSnapshot struct {
	ID         string    `json:"id"`
	CapturedAt time.Time `json:"captured_at"`
	View       string    `json:"view"`
}

type NSOwnershipOwner struct {
	Owner             string   `json:"owner"`
	ZoneCount         int      `json:"zone_count"`
	PreviousZoneCount int      `json:"previous_zone_count"`
	AddedCount        int      `json:"added_count"`
	RemovedCount      int      `json:"removed_count"`
	CrossDomainCount  int      `json:"cross_domain_count"`
	Hosts             []string `json:"hosts"`
}

type NSOwnershipZoneEdge struct {
	Zone           string   `json:"zone"`
	Status         string   `json:"status"`
	PreviousOwners []string `json:"previous_owners"`
	CurrentOwners  []string `json:"current_owners"`
	PreviousHosts  []string `json:"previous_hosts"`
	CurrentHosts   []string `json:"current_hosts"`
	CrossDomain    bool     `json:"cross_domain"`
}

type NSOwnershipResponse struct {
	Snapshots     []NSOwnershipSnapshot `json:"snapshots"`
	Current       NSOwnershipSnapshot   `json:"current"`
	Previous      *NSOwnershipSnapshot  `json:"previous,omitempty"`
	Owners        []NSOwnershipOwner    `json:"owners"`
	SelectedOwner string                `json:"selected_owner"`
	Edges         []NSOwnershipZoneEdge `json:"edges"`
	GraphEdges    []NSOwnershipZoneEdge `json:"graph_edges"`
	TotalEdges    int                   `json:"total_edges"`
	Truncated     bool                  `json:"truncated"`
}

type nsOwnershipIndex struct {
	ownerZones map[string]map[string]struct{}
	ownerHosts map[string]map[string]struct{}
	zoneOwners map[string][]string
	zoneHosts  map[string][]string
}

type nsOwnershipStateCache struct {
	selectedID string
	expiresAt  time.Time
	snapshots  []NSOwnershipSnapshot
	current    campaignSnapshotState
	previous   *campaignSnapshotState
}

func buildNSOwnershipIndex(state campaignSnapshotState) nsOwnershipIndex {
	index := nsOwnershipIndex{ownerZones: map[string]map[string]struct{}{}, ownerHosts: map[string]map[string]struct{}{}, zoneOwners: map[string][]string{}, zoneHosts: map[string][]string{}}
	for zone, hosts := range state.NS {
		zone = normalizeFQDN(zone)
		owners := campaignNSOwners(hosts)
		index.zoneOwners[zone] = owners
		index.zoneHosts[zone] = campaignNSHostNames(hosts)
		for host := range hosts {
			owner := campaignNSOwner(host)
			if index.ownerZones[owner] == nil {
				index.ownerZones[owner] = map[string]struct{}{}
				index.ownerHosts[owner] = map[string]struct{}{}
			}
			index.ownerZones[owner][zone] = struct{}{}
			index.ownerHosts[owner][normalizeFQDN(host)] = struct{}{}
		}
	}
	return index
}

func buildNSOwnershipResponse(snapshots []NSOwnershipSnapshot, current campaignSnapshotState, previous *campaignSnapshotState, selectedOwner, graphQuery string, edgeLimit int) NSOwnershipResponse {
	currentIndex := buildNSOwnershipIndex(current)
	previousIndex := nsOwnershipIndex{ownerZones: map[string]map[string]struct{}{}, ownerHosts: map[string]map[string]struct{}{}, zoneOwners: map[string][]string{}, zoneHosts: map[string][]string{}}
	if previous != nil {
		previousIndex = buildNSOwnershipIndex(*previous)
	}
	ownersSet := map[string]struct{}{}
	for owner := range currentIndex.ownerZones {
		ownersSet[owner] = struct{}{}
	}
	for owner := range previousIndex.ownerZones {
		ownersSet[owner] = struct{}{}
	}
	owners := make([]NSOwnershipOwner, 0, len(ownersSet))
	for owner := range ownersSet {
		currentZones, previousZones := currentIndex.ownerZones[owner], previousIndex.ownerZones[owner]
		crossDomain := 0
		for zone := range currentZones {
			if len(currentIndex.zoneOwners[zone]) > 1 {
				crossDomain++
			}
		}
		hosts := setKeys(currentIndex.ownerHosts[owner])
		owners = append(owners, NSOwnershipOwner{Owner: owner, ZoneCount: len(currentZones), PreviousZoneCount: len(previousZones), AddedCount: setDifferenceCount(currentZones, previousZones), RemovedCount: setDifferenceCount(previousZones, currentZones), CrossDomainCount: crossDomain, Hosts: hosts})
	}
	sort.Slice(owners, func(i, j int) bool {
		if owners[i].ZoneCount == owners[j].ZoneCount {
			return owners[i].Owner < owners[j].Owner
		}
		return owners[i].ZoneCount > owners[j].ZoneCount
	})
	selectedOwner = normalizeFQDN(selectedOwner)
	if selectedOwner == "" && len(owners) > 0 {
		selectedOwner = owners[0].Owner
	}
	graphEdges := buildGlobalNSOwnershipGraph(currentIndex, previousIndex, graphQuery, 220)
	zoneSet := map[string]struct{}{}
	for zone := range currentIndex.ownerZones[selectedOwner] {
		zoneSet[zone] = struct{}{}
	}
	for zone := range previousIndex.ownerZones[selectedOwner] {
		zoneSet[zone] = struct{}{}
	}
	zones := setKeys(zoneSet)
	edges := make([]NSOwnershipZoneEdge, 0, len(zones))
	for _, zone := range zones {
		previousOwners, currentOwners := previousIndex.zoneOwners[zone], currentIndex.zoneOwners[zone]
		was, is := stringSetContains(previousOwners, selectedOwner), stringSetContains(currentOwners, selectedOwner)
		status := "unchanged"
		if !was && is {
			status = "added"
			if len(previousOwners) > 0 {
				status = "moved_in"
			}
		} else if was && !is {
			status = "removed"
			if len(currentOwners) > 0 {
				status = "moved_out"
			}
		}
		edges = append(edges, NSOwnershipZoneEdge{Zone: zone, Status: status, PreviousOwners: nonNilStrings(previousOwners), CurrentOwners: nonNilStrings(currentOwners), PreviousHosts: nonNilStrings(previousIndex.zoneHosts[zone]), CurrentHosts: nonNilStrings(currentIndex.zoneHosts[zone]), CrossDomain: len(currentOwners) > 1})
	}
	sort.SliceStable(edges, func(i, j int) bool {
		rank := map[string]int{"moved_in": 0, "moved_out": 1, "added": 2, "removed": 3, "unchanged": 4}
		if rank[edges[i].Status] == rank[edges[j].Status] {
			return edges[i].Zone < edges[j].Zone
		}
		return rank[edges[i].Status] < rank[edges[j].Status]
	})
	totalEdges := len(edges)
	if edgeLimit < 1 {
		edgeLimit = 200
	}
	truncated := len(edges) > edgeLimit
	if truncated {
		edges = edges[:edgeLimit]
	}
	response := NSOwnershipResponse{Snapshots: snapshots, Current: NSOwnershipSnapshot{ID: current.SnapshotID, CapturedAt: current.CapturedAt, View: current.View}, Owners: owners, SelectedOwner: selectedOwner, Edges: edges, GraphEdges: graphEdges, TotalEdges: totalEdges, Truncated: truncated}
	if previous != nil {
		response.Previous = &NSOwnershipSnapshot{ID: previous.SnapshotID, CapturedAt: previous.CapturedAt, View: previous.View}
	}
	return response
}

func buildGlobalNSOwnershipGraph(current, previous nsOwnershipIndex, query string, limit int) []NSOwnershipZoneEdge {
	zoneSet := map[string]struct{}{}
	for zone := range current.zoneOwners {
		zoneSet[zone] = struct{}{}
	}
	for zone := range previous.zoneOwners {
		zoneSet[zone] = struct{}{}
	}
	all := make([]NSOwnershipZoneEdge, 0, len(zoneSet))
	for zone := range zoneSet {
		previousOwners, currentOwners := previous.zoneOwners[zone], current.zoneOwners[zone]
		status := "unchanged"
		if len(previousOwners) == 0 && len(currentOwners) > 0 {
			status = "added"
		} else if len(previousOwners) > 0 && len(currentOwners) == 0 {
			status = "removed"
		} else if !equalStrings(previousOwners, currentOwners) {
			status = "moved_in"
		}
		all = append(all, NSOwnershipZoneEdge{Zone: zone, Status: status, PreviousOwners: nonNilStrings(previousOwners), CurrentOwners: nonNilStrings(currentOwners), PreviousHosts: nonNilStrings(previous.zoneHosts[zone]), CurrentHosts: nonNilStrings(current.zoneHosts[zone]), CrossDomain: len(currentOwners) > 1})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Zone < all[j].Zone })
	if limit < 1 {
		limit = 220
	}
	selected := make([]NSOwnershipZoneEdge, 0, limit)
	seen := map[string]struct{}{}
	appendGroup := func(predicate func(NSOwnershipZoneEdge) bool, target int) {
		candidates := make([]NSOwnershipZoneEdge, 0)
		for _, edge := range all {
			if predicate(edge) {
				if _, exists := seen[edge.Zone]; !exists {
					candidates = append(candidates, edge)
				}
			}
		}
		for _, edge := range diverseOwnershipEdges(candidates, target-len(selected)) {
			selected = append(selected, edge)
			seen[edge.Zone] = struct{}{}
		}
	}
	appendGroup(func(edge NSOwnershipZoneEdge) bool { return edge.CrossDomain && edge.Status != "unchanged" }, minInt(limit, 40))
	appendGroup(func(edge NSOwnershipZoneEdge) bool { return edge.Status != "unchanged" }, minInt(limit, 100))
	appendGroup(func(edge NSOwnershipZoneEdge) bool { return edge.CrossDomain }, minInt(limit, 150))
	appendGroup(func(NSOwnershipZoneEdge) bool { return true }, limit)
	query = strings.ToLower(strings.TrimSpace(query))
	if query != "" {
		for _, edge := range all {
			if _, exists := seen[edge.Zone]; exists {
				continue
			}
			matched := strings.Contains(strings.ToLower(edge.Zone), query)
			for _, owner := range edge.PreviousOwners {
				matched = matched || strings.Contains(strings.ToLower(owner), query)
			}
			for _, owner := range edge.CurrentOwners {
				matched = matched || strings.Contains(strings.ToLower(owner), query)
			}
			if matched {
				selected = append(selected, edge)
				seen[edge.Zone] = struct{}{}
				if len(selected) >= limit+50 {
					break
				}
			}
		}
	}
	return selected
}

func diverseOwnershipEdges(edges []NSOwnershipZoneEdge, limit int) []NSOwnershipZoneEdge {
	if limit <= 0 || len(edges) == 0 {
		return nil
	}
	groups := map[string][]NSOwnershipZoneEdge{}
	for _, edge := range edges {
		owners := edge.CurrentOwners
		if len(owners) == 0 {
			owners = edge.PreviousOwners
		}
		key := "~unknown"
		if len(owners) > 0 {
			key = owners[0]
		}
		groups[key] = append(groups[key], edge)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(groups[keys[i]]) == len(groups[keys[j]]) {
			return keys[i] < keys[j]
		}
		return len(groups[keys[i]]) > len(groups[keys[j]])
	})
	result := make([]NSOwnershipZoneEdge, 0, minInt(limit, len(edges)))
	for round := 0; len(result) < limit; round++ {
		added := false
		for _, key := range keys {
			if round >= len(groups[key]) {
				continue
			}
			result = append(result, groups[key][round])
			added = true
			if len(result) == limit {
				break
			}
		}
		if !added {
			break
		}
	}
	return result
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func setDifferenceCount(left, right map[string]struct{}) int {
	count := 0
	for value := range left {
		if _, exists := right[value]; !exists {
			count++
		}
	}
	return count
}

func nonNilStrings(values []string) []string {
	if len(values) == 0 {
		return make([]string, 0)
	}
	return append([]string(nil), values...)
}

func (s *nsPersistentStore) ownershipSnapshotPair(ctx context.Context, selectedID string) ([]NSOwnershipSnapshot, campaignSnapshotState, *campaignSnapshotState, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT snapshot_id, captured_at, view FROM ns_snapshot_catalog FINAL ORDER BY captured_at DESC, snapshot_id DESC LIMIT 100`)
	if err != nil {
		return nil, campaignSnapshotState{}, nil, err
	}
	defer rows.Close()
	snapshots := make([]NSOwnershipSnapshot, 0, 100)
	for rows.Next() {
		var snapshot NSOwnershipSnapshot
		if err := rows.Scan(&snapshot.ID, &snapshot.CapturedAt, &snapshot.View); err != nil {
			return nil, campaignSnapshotState{}, nil, err
		}
		snapshots = append(snapshots, snapshot)
	}
	if err := rows.Err(); err != nil {
		return nil, campaignSnapshotState{}, nil, err
	}
	if len(snapshots) == 0 {
		return snapshots, campaignSnapshotState{}, nil, errNSPersistentNotFound
	}
	currentIndex := 0
	if selectedID != "" {
		currentIndex = -1
		for index, snapshot := range snapshots {
			if snapshot.ID == selectedID {
				currentIndex = index
				break
			}
		}
		if currentIndex < 0 {
			return snapshots, campaignSnapshotState{}, nil, errNSPersistentNotFound
		}
	}
	selectedSnapshots := []NSOwnershipSnapshot{snapshots[currentIndex]}
	for index := currentIndex + 1; index < len(snapshots); index++ {
		if snapshots[index].View != snapshots[currentIndex].View {
			continue
		}
		selectedSnapshots = append(selectedSnapshots, snapshots[index])
		break
	}
	states, err := s.loadOwnershipSnapshotStates(ctx, selectedSnapshots)
	if err != nil {
		return snapshots, campaignSnapshotState{}, nil, err
	}
	current := states[snapshots[currentIndex].ID]
	var previous *campaignSnapshotState
	if len(selectedSnapshots) > 1 {
		value := states[selectedSnapshots[1].ID]
		previous = &value
	}
	return snapshots, current, previous, nil
}

func (s *nsPersistentMonitorServer) cachedOwnershipSnapshotPair(ctx context.Context, selectedID string) ([]NSOwnershipSnapshot, campaignSnapshotState, *campaignSnapshotState, error) {
	s.ownershipMu.Lock()
	defer s.ownershipMu.Unlock()
	now := time.Now()
	if cache := s.ownershipCache; cache != nil && cache.selectedID == selectedID && now.Before(cache.expiresAt) {
		return cache.snapshots, cache.current, cache.previous, nil
	}
	snapshots, current, previous, err := s.store.ownershipSnapshotPair(ctx, selectedID)
	if err != nil {
		return nil, campaignSnapshotState{}, nil, err
	}
	s.ownershipCache = &nsOwnershipStateCache{selectedID: selectedID, expiresAt: now.Add(time.Minute), snapshots: snapshots, current: current, previous: previous}
	return snapshots, current, previous, nil
}

func (s *nsPersistentStore) loadOwnershipSnapshotState(ctx context.Context, snapshot NSOwnershipSnapshot) (campaignSnapshotState, error) {
	states, err := s.loadOwnershipSnapshotStates(ctx, []NSOwnershipSnapshot{snapshot})
	return states[snapshot.ID], err
}

func (s *nsPersistentStore) loadOwnershipSnapshotStates(ctx context.Context, snapshots []NSOwnershipSnapshot) (map[string]campaignSnapshotState, error) {
	states := make(map[string]campaignSnapshotState, len(snapshots))
	ids := make([]string, 0, len(snapshots))
	for _, snapshot := range snapshots {
		ids = append(ids, snapshot.ID)
		states[snapshot.ID] = campaignSnapshotState{Version: campaignStateVersion, SnapshotID: snapshot.ID, CapturedAt: snapshot.CapturedAt, View: snapshot.View, NS: map[string]map[string][]string{}, A: map[string][]string{}}
	}
	if len(ids) == 0 {
		return states, nil
	}
	// 归属图谱只需要 NS 主机名。让 ClickHouse 在服务端从 JSON 中提取 name，
	// 避免把地址、ASN、国家等大段无关元数据跨连接传回 Web 进程。
	rows, err := s.db.QueryContext(ctx, `SELECT snapshot_id, domain, arrayMap(item -> JSONExtractString(item, 'name'), JSONExtractArrayRaw(nameservers_json)) AS ns_names FROM ns_domain_observations FINAL WHERE snapshot_id IN (?)`, ids)
	if err != nil {
		return states, err
	}
	defer rows.Close()
	for rows.Next() {
		var snapshotID, domain string
		var names []string
		if err := rows.Scan(&snapshotID, &domain, &names); err != nil {
			return states, err
		}
		state, exists := states[snapshotID]
		if !exists {
			continue
		}
		domain = normalizeFQDN(domain)
		state.NS[domain] = map[string][]string{}
		for _, name := range names {
			state.NS[domain][normalizeFQDN(name)] = make([]string, 0)
		}
		states[snapshotID] = state
	}
	return states, rows.Err()
}

func (s *nsPersistentMonitorServer) v1NSOwnership(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeNSJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 GET"})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	snapshots, current, previous, err := s.cachedOwnershipSnapshotPair(ctx, strings.TrimSpace(r.URL.Query().Get("snapshot_id")))
	if errors.Is(err, errNSPersistentNotFound) {
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "快照不存在"})
		return
	}
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	writeNSJSON(w, http.StatusOK, buildNSOwnershipResponse(snapshots, current, previous, r.URL.Query().Get("owner"), r.URL.Query().Get("q"), limit))
}

func (s *nsMonitorServer) v1NSOwnership(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeNSJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 GET"})
		return
	}
	writeNSJSON(w, http.StatusOK, NSOwnershipResponse{Snapshots: []NSOwnershipSnapshot{}, Owners: []NSOwnershipOwner{}, Edges: []NSOwnershipZoneEdge{}, GraphEdges: []NSOwnershipZoneEdge{}})
}
