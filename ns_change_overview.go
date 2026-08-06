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

type NSChangeOverviewPoint struct {
	SnapshotID         string    `json:"snapshot_id"`
	PreviousSnapshotID string    `json:"previous_snapshot_id"`
	CapturedAt         time.Time `json:"captured_at"`
	PreviousCapturedAt time.Time `json:"previous_captured_at"`
	View               string    `json:"view"`
	TotalZones         int       `json:"total_zones"`
	Unchanged          int       `json:"unchanged"`
	Modified           int       `json:"modified"`
	Added              int       `json:"added"`
	Removed            int       `json:"removed"`
	Changed            int       `json:"changed"`
	ChangeRate         float64   `json:"change_rate"`
}

type NSChangeOverviewItem struct {
	Zone           string   `json:"zone"`
	Type           string   `json:"type"`
	PreviousOwners []string `json:"previous_owners"`
	CurrentOwners  []string `json:"current_owners"`
	PreviousHosts  []string `json:"previous_hosts"`
	CurrentHosts   []string `json:"current_hosts"`
}

type NSChangeOverviewResponse struct {
	Points       []NSChangeOverviewPoint `json:"points"`
	Selected     *NSChangeOverviewPoint  `json:"selected,omitempty"`
	Changes      []NSChangeOverviewItem  `json:"changes"`
	TotalChanges int                     `json:"total_changes"`
	Page         int                     `json:"page"`
	Limit        int                     `json:"limit"`
}

type nsChangeOverviewCache struct {
	expiresAt time.Time
	limit     int
	points    []NSChangeOverviewPoint
}

func compareNSFingerprints(current, previous map[string]string) (unchanged, modified, added, removed int) {
	for zone, fingerprint := range current {
		previousFingerprint, exists := previous[zone]
		if !exists {
			added++
		} else if fingerprint == previousFingerprint {
			unchanged++
		} else {
			modified++
		}
	}
	for zone := range previous {
		if _, exists := current[zone]; !exists {
			removed++
		}
	}
	return
}

func buildNSChangeOverviewPoints(snapshots []NSOwnershipSnapshot, fingerprints map[string]map[string]string, limit int) []NSChangeOverviewPoint {
	if limit < 1 {
		return make([]NSChangeOverviewPoint, 0)
	}
	points := make([]NSChangeOverviewPoint, 0, limit)
	for currentIndex, current := range snapshots {
		previousIndex := -1
		for index := currentIndex + 1; index < len(snapshots); index++ {
			if snapshots[index].View == current.View {
				previousIndex = index
				break
			}
		}
		if previousIndex < 0 {
			continue
		}
		previous := snapshots[previousIndex]
		currentZones := fingerprints[current.ID]
		previousZones := fingerprints[previous.ID]
		unchanged, modified, added, removed := compareNSFingerprints(currentZones, previousZones)
		changed := modified + added + removed
		denominator := unchanged + changed
		changeRate := 0.0
		if denominator > 0 {
			changeRate = float64(changed) / float64(denominator)
		}
		points = append(points, NSChangeOverviewPoint{
			SnapshotID: current.ID, PreviousSnapshotID: previous.ID, CapturedAt: current.CapturedAt, PreviousCapturedAt: previous.CapturedAt, View: current.View,
			TotalZones: len(currentZones), Unchanged: unchanged, Modified: modified, Added: added, Removed: removed, Changed: changed, ChangeRate: changeRate,
		})
		if len(points) == limit {
			break
		}
	}
	return points
}

func buildNSChangeOverviewItems(current, previous campaignSnapshotState, query, changeType string) []NSChangeOverviewItem {
	currentIndex := buildNSOwnershipIndex(current)
	previousIndex := buildNSOwnershipIndex(previous)
	zones := map[string]struct{}{}
	for zone := range currentIndex.zoneOwners {
		zones[zone] = struct{}{}
	}
	for zone := range previousIndex.zoneOwners {
		zones[zone] = struct{}{}
	}
	query = strings.ToLower(strings.TrimSpace(query))
	changeType = strings.ToLower(strings.TrimSpace(changeType))
	items := make([]NSChangeOverviewItem, 0)
	for zone := range zones {
		previousOwners, currentOwners := previousIndex.zoneOwners[zone], currentIndex.zoneOwners[zone]
		previousHosts := nonNilStrings(previousIndex.zoneHosts[zone])
		currentHosts := nonNilStrings(currentIndex.zoneHosts[zone])
		kind := "modified"
		if len(previousHosts) == 0 && len(currentHosts) > 0 {
			kind = "added"
		} else if len(previousHosts) > 0 && len(currentHosts) == 0 {
			kind = "removed"
		} else if equalStrings(previousHosts, currentHosts) {
			continue
		}
		if changeType != "" && changeType != "all" && kind != changeType {
			continue
		}
		if query != "" {
			values := append([]string{zone}, previousOwners...)
			values = append(values, currentOwners...)
			values = append(values, previousHosts...)
			values = append(values, currentHosts...)
			matched := false
			for _, value := range values {
				if strings.Contains(strings.ToLower(value), query) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		items = append(items, NSChangeOverviewItem{Zone: zone, Type: kind, PreviousOwners: nonNilStrings(previousOwners), CurrentOwners: nonNilStrings(currentOwners), PreviousHosts: previousHosts, CurrentHosts: currentHosts})
	}
	rank := map[string]int{"modified": 0, "added": 1, "removed": 2}
	sort.Slice(items, func(i, j int) bool {
		if rank[items[i].Type] == rank[items[j].Type] {
			return items[i].Zone < items[j].Zone
		}
		return rank[items[i].Type] < rank[items[j].Type]
	})
	return items
}

func (s *nsPersistentStore) loadNSChangeOverviewPoints(ctx context.Context, limit int) ([]NSChangeOverviewPoint, error) {
	var latestView string
	if err := s.db.QueryRowContext(ctx, `SELECT view FROM ns_snapshot_catalog FINAL ORDER BY captured_at DESC, snapshot_id DESC LIMIT 1`).Scan(&latestView); err != nil {
		return nil, err
	}
	catalogLimit := minInt(500, limit+1)
	rows, err := s.db.QueryContext(ctx, `SELECT snapshot_id, captured_at, view FROM ns_snapshot_catalog FINAL WHERE view = ? ORDER BY captured_at DESC, snapshot_id DESC LIMIT `+strconv.Itoa(catalogLimit), latestView)
	if err != nil {
		return nil, err
	}
	snapshots := make([]NSOwnershipSnapshot, 0, catalogLimit)
	for rows.Next() {
		var snapshot NSOwnershipSnapshot
		if err := rows.Scan(&snapshot.ID, &snapshot.CapturedAt, &snapshot.View); err != nil {
			_ = rows.Close()
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if len(snapshots) < 2 {
		return make([]NSChangeOverviewPoint, 0), nil
	}
	ids := make([]string, 0, len(snapshots))
	for _, snapshot := range snapshots {
		ids = append(ids, snapshot.ID)
	}
	fingerprints := make(map[string]map[string]string, len(ids))
	// 这里刻意比较 NS 主机名集合，而不是 observation fingerprint。后者还包含
	// NS 地址变化，会把同一 NS 主机的 A/AAAA 波动混入“NS 记录变更”口径。
	observationRows, err := s.db.QueryContext(ctx, `SELECT snapshot_id, domain, arrayStringConcat(arraySort(arrayMap(item -> lower(JSONExtractString(item, 'name')), JSONExtractArrayRaw(nameservers_json))), '|') AS ns_signature FROM ns_domain_observations FINAL WHERE snapshot_id IN (?)`, ids)
	if err != nil {
		return nil, err
	}
	defer observationRows.Close()
	for observationRows.Next() {
		var snapshotID, domain, fingerprint string
		if err := observationRows.Scan(&snapshotID, &domain, &fingerprint); err != nil {
			return nil, err
		}
		if fingerprints[snapshotID] == nil {
			fingerprints[snapshotID] = map[string]string{}
		}
		fingerprints[snapshotID][normalizeFQDN(domain)] = fingerprint
	}
	if err := observationRows.Err(); err != nil {
		return nil, err
	}
	return buildNSChangeOverviewPoints(snapshots, fingerprints, limit), nil
}

func (s *nsPersistentMonitorServer) cachedNSChangeOverviewPoints(ctx context.Context, limit int) ([]NSChangeOverviewPoint, error) {
	s.changeOverviewMu.Lock()
	defer s.changeOverviewMu.Unlock()
	now := time.Now()
	if cache := s.changeOverviewCache; cache != nil && now.Before(cache.expiresAt) && cache.limit >= limit {
		end := minInt(limit, len(cache.points))
		return append([]NSChangeOverviewPoint(nil), cache.points[:end]...), nil
	}
	points, err := s.store.loadNSChangeOverviewPoints(ctx, limit)
	if err != nil {
		return nil, err
	}
	s.changeOverviewCache = &nsChangeOverviewCache{expiresAt: now.Add(time.Minute), limit: limit, points: points}
	if len(points) > limit {
		points = points[:limit]
	}
	return append([]NSChangeOverviewPoint(nil), points...), nil
}

func (s *nsPersistentMonitorServer) v1NSChangeOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeNSJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 GET"})
		return
	}
	trendLimit := parseNSPositiveInt(r.URL.Query().Get("trend_limit"), 48, 2, 100)
	page := parseNSPositiveInt(r.URL.Query().Get("page"), 1, 1, 10000)
	pageLimit := parseNSPositiveInt(r.URL.Query().Get("limit"), 100, 1, 300)
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	points, err := s.cachedNSChangeOverviewPoints(ctx, trendLimit)
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	response := NSChangeOverviewResponse{Points: points, Changes: make([]NSChangeOverviewItem, 0), Page: page, Limit: pageLimit}
	if len(points) == 0 {
		writeNSJSON(w, http.StatusOK, response)
		return
	}
	selectedID := strings.TrimSpace(r.URL.Query().Get("snapshot_id"))
	if selectedID == "" {
		selectedID = points[0].SnapshotID
	}
	for index := range points {
		if points[index].SnapshotID == selectedID {
			selected := points[index]
			response.Selected = &selected
			break
		}
	}
	if response.Selected == nil {
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "变更窗口不存在或不在当前趋势范围"})
		return
	}
	_, current, previous, err := s.cachedOwnershipSnapshotPair(ctx, selectedID)
	if errors.Is(err, errNSPersistentNotFound) || previous == nil {
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "相邻快照不存在"})
		return
	}
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	items := buildNSChangeOverviewItems(current, *previous, r.URL.Query().Get("q"), r.URL.Query().Get("type"))
	response.TotalChanges = len(items)
	start := (page - 1) * pageLimit
	if start < len(items) {
		end := minInt(start+pageLimit, len(items))
		response.Changes = items[start:end]
	}
	writeNSJSON(w, http.StatusOK, response)
}

func (s *nsMonitorServer) v1NSChangeOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeNSJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 GET"})
		return
	}
	writeNSJSON(w, http.StatusOK, NSChangeOverviewResponse{Points: make([]NSChangeOverviewPoint, 0), Changes: make([]NSChangeOverviewItem, 0), Page: 1, Limit: 100})
}
