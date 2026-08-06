package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type dnsCampaignsResponse struct {
	Items []DNSCampaignEvent `json:"items"`
	Total int                `json:"total"`
	Page  int                `json:"page"`
	Limit int                `json:"limit"`
}

func (s *nsMonitorServer) v1Campaigns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeNSJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 GET"})
		return
	}
	writeNSJSON(w, http.StatusOK, dnsCampaignsResponse{Items: []DNSCampaignEvent{}, Page: 1, Limit: 50})
}

func (s *nsPersistentMonitorServer) v1Campaigns(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/campaigns"), "/")
	if path != "" {
		parts := strings.Split(path, "/")
		if len(parts) == 2 && parts[1] == "actions" {
			s.v1CampaignAction(w, r, parts[0])
			return
		}
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "批量协同变化事件不存在"})
		return
	}
	if r.Method != http.MethodGet {
		writeNSJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 GET"})
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 200 {
		limit = 50
	}
	ctx, cancel := context.WithTimeout(r.Context(), nsWebQueryTimeout)
	defer cancel()
	items, err := s.store.campaigns(ctx)
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	kind := strings.TrimSpace(r.URL.Query().Get("type"))
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	filtered := items[:0]
	for _, item := range items {
		if isFirstIPObservationCampaign(item) {
			continue
		}
		if kind != "" && kind != "all" && item.Type != kind {
			continue
		}
		if status != "" && status != "all" && item.Status != status {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(item.Target+" "+item.Summary+" "+strings.Join(item.Zones, " ")), query) {
			continue
		}
		filtered = append(filtered, item)
	}
	total := len(filtered)
	start := (page - 1) * limit
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}
	writeNSJSON(w, http.StatusOK, dnsCampaignsResponse{Items: filtered[start:end], Total: total, Page: page, Limit: limit})
}

func (s *nsPersistentStore) campaigns(ctx context.Context) ([]DNSCampaignEvent, error) {
	actions, err := s.latestEventActions(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT event_id,campaign_type,target,severity,evidence,status,previous_snapshot_id,current_snapshot_id,first_seen,last_seen,zone_count,ns_host_count,record_count,zones_json,changes_json,summary,signature FROM dns_campaign_events FINAL ORDER BY last_seen DESC LIMIT 5000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]DNSCampaignEvent, 0)
	for rows.Next() {
		var item DNSCampaignEvent
		var zones, changes string
		var zoneCount, hostCount, recordCount uint32
		if err := rows.Scan(&item.ID, &item.Type, &item.Target, &item.Severity, &item.Evidence, &item.Status, &item.PreviousSnapshotID, &item.CurrentSnapshotID, &item.FirstSeen, &item.LastSeen, &zoneCount, &hostCount, &recordCount, &zones, &changes, &item.Summary, &item.Signature); err != nil {
			return nil, err
		}
		item.ZoneCount = int(zoneCount)
		item.NSHostCount = int(hostCount)
		item.RecordCount = int(recordCount)
		_ = json.Unmarshal([]byte(zones), &item.Zones)
		_ = json.Unmarshal([]byte(changes), &item.Changes)
		if action, ok := actions[item.ID]; ok {
			if action.Action == "ignore" {
				item.Status = "ignored"
			}
			if action.Action == "whitelist" && (action.ExpiresAt == nil || action.ExpiresAt.After(time.Now())) {
				item.Status = "excluded"
			}
			if action.Action == "confirm" {
				item.Status = "confirmed"
			}
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *nsPersistentMonitorServer) v1CampaignAction(w http.ResponseWriter, r *http.Request, eventID string) {
	if r.Method != http.MethodPost {
		writeNSJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 POST"})
		return
	}
	user, ok := requireNSWriteRole(w, r, "operator")
	if !ok {
		return
	}
	var request nsEventActionRequest
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "无效请求: " + err.Error()})
		return
	}
	if err := ensureJSONEOF(decoder); err != nil {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	request.Action = strings.ToLower(strings.TrimSpace(request.Action))
	request.Reason = strings.TrimSpace(request.Reason)
	if request.Action != "confirm" && request.Action != "ignore" && request.Action != "whitelist" {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "action 仅支持 confirm、ignore、whitelist"})
		return
	}
	if request.Action != "confirm" && request.Reason == "" {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "忽略或白名单必须填写理由"})
		return
	}
	var expiresAt *time.Time
	if request.Action == "whitelist" {
		value, err := time.Parse(time.RFC3339, request.ExpiresAt)
		if err != nil || !value.After(time.Now()) {
			writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "expiresAt 必须是未来的 RFC3339 时间"})
			return
		}
		value = value.UTC()
		expiresAt = &value
	}
	ctx, cancel := context.WithTimeout(r.Context(), nsWebQueryTimeout)
	defer cancel()
	var zonesRaw string
	err := s.store.db.QueryRowContext(ctx, `SELECT zones_json FROM dns_campaign_events FINAL WHERE event_id=? LIMIT 1`, eventID).Scan(&zonesRaw)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		nsPersistentError(w, err)
		return
	}
	if err != nil {
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "批量协同变化事件不存在"})
		return
	}
	actedAt := time.Now().UTC()
	var expires any
	if expiresAt != nil {
		expires = *expiresAt
	}
	details, _ := json.Marshal(map[string]string{"remote_addr": r.RemoteAddr, "user_agent": r.UserAgent()})
	if _, err := s.store.db.ExecContext(ctx, `INSERT INTO ns_event_actions (event_id,action,reason,actor,actor_role,acted_at,expires_at,details_json) VALUES (?,?,?,?,?,?,?,?)`, eventID, request.Action, request.Reason, user.Username, user.Role, actedAt, expires, string(details)); err != nil {
		nsPersistentError(w, err)
		return
	}
	if request.Action == "ignore" {
		var zones []string
		_ = json.Unmarshal([]byte(zonesRaw), &zones)
		for _, zone := range zones {
			_, _ = s.store.db.ExecContext(ctx, `INSERT INTO ns_campaign_holds (zone,campaign_id,target_fingerprint,active) VALUES (?,?,?,0)`, zone, eventID, "")
		}
	}
	writeNSJSON(w, http.StatusCreated, nsEventAction{EventID: eventID, Action: request.Action, Reason: request.Reason, Actor: user.Username, ActorRole: user.Role, ActedAt: actedAt, ExpiresAt: expiresAt})
}
