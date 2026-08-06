package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// v1 API 是正式前端使用的稳定契约。旧 /api/ns 接口继续保留，便于已有部署
// 平滑升级；v1 将存储层字段归一化成统一事件生命周期，后续风险类型也复用此模型。
type nsV1Record struct {
	Host      string   `json:"host"`
	IPs       []string `json:"ips"`
	ASN       string   `json:"asn"`
	ASNOrg    string   `json:"asnOrg"`
	Country   string   `json:"country"`
	Reachable *bool    `json:"reachable,omitempty"`
	RTTMS     *int64   `json:"rttMs,omitempty"`
}

type nsV1ProbeResult struct {
	Domain           string               `json:"domain"`
	Role             string               `json:"role"`
	NS               string               `json:"ns"`
	IP               string               `json:"ip"`
	Reachable        *bool                `json:"reachable"`
	RTTMS            *int64               `json:"rttMs"`
	AnswerConsistent *bool                `json:"answerConsistent"`
	Detail           string               `json:"detail"`
	Answer           *nsV1ProbeAnswer     `json:"answer,omitempty"`
	StableConsensus  *nsV1ProbeAnswer     `json:"stableConsensus,omitempty"`
	Differences      []nsV1ProbeFieldDiff `json:"differences,omitempty"`
}

type nsV1ProbeAnswer struct {
	RCode       string   `json:"rcode"`
	CNAME       []string `json:"cname"`
	A           []string `json:"a"`
	AAAA        []string `json:"aaaa"`
	AuthorityNS []string `json:"authorityNs"`
	Error       string   `json:"error,omitempty"`
}

type nsV1ProbeFieldDiff struct {
	Field   string   `json:"field"`
	Label   string   `json:"label"`
	Stable  []string `json:"stable"`
	Current []string `json:"current"`
	Changed bool     `json:"changed"`
	Note    string   `json:"note,omitempty"`
}

type nsV1ProbeComparison struct {
	Domain               string               `json:"domain"`
	Verdict              string               `json:"verdict"`
	Summary              string               `json:"summary"`
	Stable               *nsV1ProbeAnswer     `json:"stable,omitempty"`
	Trusted              *nsV1ProbeAnswer     `json:"trusted,omitempty"`
	Recursive            nsV1ProbeAnswer      `json:"recursive"`
	TrustedDifferences   []nsV1ProbeFieldDiff `json:"trustedDifferences,omitempty"`
	RecursiveDifferences []nsV1ProbeFieldDiff `json:"recursiveDifferences,omitempty"`
}

type nsV1TimelineNode struct {
	Time   string `json:"time"`
	Kind   string `json:"kind"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
}

type nsV1AlertRecord struct {
	Time    string `json:"time"`
	Channel string `json:"channel"`
	Target  string `json:"target"`
	Status  string `json:"status"`
	Content string `json:"content"`
}

type nsV1RiskEvent struct {
	ID               string                `json:"id"`
	Type             string                `json:"type"`
	Domain           string                `json:"domain"`
	Level            string                `json:"level"`
	Evidence         string                `json:"evidence"`
	Status           string                `json:"status"`
	FirstSeen        string                `json:"firstSeen"`
	LastSeen         string                `json:"lastSeen"`
	DurationMin      int                   `json:"durationMin"`
	Observations     int                   `json:"observations"`
	ClusterSize      int                   `json:"clusterSize"`
	Snapshot         string                `json:"snapshot"`
	Summary          string                `json:"summary"`
	ChangeFields     []string              `json:"changeFields"`
	BaselineNS       []nsV1Record          `json:"baselineNs"`
	CurrentNS        []nsV1Record          `json:"currentNs"`
	Probes           []nsV1ProbeResult     `json:"probes"`
	ProbeVerdict     string                `json:"probeVerdict,omitempty"`
	ProbeSummary     string                `json:"probeSummary,omitempty"`
	ProbeComparisons []nsV1ProbeComparison `json:"probeComparisons,omitempty"`
	TrustedAnswer    string                `json:"trustedAnswer"`
	RecursiveAnswer  string                `json:"recursiveAnswer"`
	AffectedNames    []any                 `json:"affectedNames"`
	AffectedCount    int                   `json:"affectedCount"`
	RRSet            []any                 `json:"rrSet"`
	Alerts           []nsV1AlertRecord     `json:"alerts"`
	Timeline         []nsV1TimelineNode    `json:"timeline"`
	RecoveredAt      string                `json:"recoveredAt,omitempty"`
	PartialEvidence  bool                  `json:"partialEvidence"`
	Extra            map[string]any        `json:"extra,omitempty"`
}

type nsV1EventsResponse struct {
	Items []nsV1RiskEvent `json:"items"`
	Total int             `json:"total"`
	Page  int             `json:"page"`
	Limit int             `json:"limit"`
}

type nsV1OverviewKPIs struct {
	ActiveEvents    int    `json:"activeEvents"`
	CriticalEvents  int    `json:"criticalEvents"`
	HighEvents      int    `json:"highEvents"`
	PendingVerify   int    `json:"pendingVerify"`
	New24H          int    `json:"new24h"`
	Recovered24H    int    `json:"recovered24h"`
	BaselineDomains int    `json:"baselineDomains"`
	LatestSnapshot  string `json:"latestSnapshot"`
	DataDelayMin    int    `json:"dataDelayMin"`
}

type nsV1OverviewResponse struct {
	KPIs         nsV1OverviewKPIs  `json:"kpis"`
	RecentEvents []nsV1RiskEvent   `json:"recentEvents"`
	Snapshots    []SnapshotSummary `json:"snapshots"`
	Mode         string            `json:"mode"`
	Warnings     []string          `json:"warnings"`
	GeneratedAt  string            `json:"generatedAt"`
}

type nsV1DomainDetail struct {
	Domain              string             `json:"domain"`
	BaselineEstablished bool               `json:"baselineEstablished"`
	BaselineSnapshots   int                `json:"baselineSnapshots"`
	BaselineSource      string             `json:"baselineSource"`
	FirstObserved       string             `json:"firstObserved"`
	BaselineNS          []nsV1Record       `json:"baselineNs"`
	CurrentNS           []nsV1Record       `json:"currentNs"`
	RelatedEvents       []nsV1RiskEvent    `json:"relatedEvents"`
	Timeline            []nsV1TimelineNode `json:"timeline"`
}

func eventToV1(event NSChangeEvent, mergedEvents int) nsV1RiskEvent {
	status, evidence := normalizeV1Lifecycle(event)
	clusterSize := mergedEvents
	if clusterSize < event.Occurrences {
		clusterSize = event.Occurrences
	}
	if clusterSize < 1 {
		clusterSize = 1
	}
	result := nsV1RiskEvent{
		ID:              event.ID,
		Type:            "ns_change",
		Domain:          event.Domain,
		Level:           normalizeV1Level(event.Severity),
		Evidence:        evidence,
		Status:          status,
		FirstSeen:       formatV1Time(event.FirstSeen),
		LastSeen:        formatV1Time(event.LastSeen),
		DurationMin:     durationMinutes(event.FirstSeen, event.LastSeen),
		Observations:    maxInt(event.Occurrences, 1),
		ClusterSize:     clusterSize,
		Summary:         event.Summary,
		ChangeFields:    append(make([]string, 0, len(event.ChangeTypes)), event.ChangeTypes...),
		BaselineNS:      observationToV1(event.Baseline),
		CurrentNS:       observationToV1(event.Current),
		AffectedNames:   make([]any, 0),
		RRSet:           make([]any, 0),
		Alerts:          make([]nsV1AlertRecord, 0),
		Timeline:        make([]nsV1TimelineNode, 0),
		Probes:          make([]nsV1ProbeResult, 0),
		TrustedAnswer:   "尚无可用拨测证据",
		RecursiveAnswer: "尚无可用拨测证据",
		PartialEvidence: true,
	}
	if event.ResolvedAt != nil {
		result.RecoveredAt = formatV1Time(*event.ResolvedAt)
	}
	return result
}

func auxEventToV1(event NSAuxRiskEvent) nsV1RiskEvent {
	status := "active"
	if event.Status == "resolved" {
		status = "recovered"
	} else if event.Status == "verified_ns_divergence" || event.Status == "verified_impact" || event.Evidence == "verified" {
		status = "confirmed"
	} else if event.Status == "pending_verification" {
		status = "pending"
	} else if event.Evidence == "observed" {
		status = "pending"
	}
	evidence := "cache_hint"
	if event.Evidence == "repeated" {
		evidence = "repeated"
	} else if event.Status == "verified_impact" {
		evidence = "impact_confirmed"
	} else if event.Status == "verified_ns_divergence" || event.Evidence == "verified" {
		evidence = "auth_divergence"
	} else if event.Status == "pending_verification" {
		evidence = "pending_verify"
	}
	result := nsV1RiskEvent{
		ID: event.ID, Type: event.Type, Domain: event.Domain, Level: normalizeV1Level(event.Severity),
		Evidence: evidence, Status: status, FirstSeen: formatV1Time(event.FirstSeen), LastSeen: formatV1Time(event.LastSeen),
		DurationMin: durationMinutes(event.FirstSeen, event.LastSeen), Observations: maxInt(event.Occurrences, 1),
		ClusterSize: maxInt(event.Occurrences, 1), Snapshot: event.SnapshotID, Summary: event.Summary,
		ChangeFields: append(make([]string, 0, len(event.ChangeFields)), event.ChangeFields...), CurrentNS: observationToV1(event.Current),
		BaselineNS: make([]nsV1Record, 0), Probes: make([]nsV1ProbeResult, 0),
		TrustedAnswer: "尚无可用拨测证据", RecursiveAnswer: "尚无可用拨测证据",
		AffectedNames: make([]any, 0), RRSet: make([]any, 0), Alerts: make([]nsV1AlertRecord, 0),
		Timeline: make([]nsV1TimelineNode, 0), PartialEvidence: true, Extra: event.Extra,
	}
	if event.ResolvedAt != nil {
		result.RecoveredAt = formatV1Time(*event.ResolvedAt)
	}
	return result
}

func normalizeV1Lifecycle(event NSChangeEvent) (string, string) {
	switch event.Status {
	case "resolved":
		return "recovered", mapV1Evidence(event.Evidence)
	case "verified_impact":
		return "confirmed", "impact_confirmed"
	case "verified_ns_divergence":
		return "confirmed", "auth_divergence"
	case "pending_verification":
		return "pending", "pending_verify"
	}
	switch event.Evidence {
	case "repeated":
		return "pending", "repeated"
	case "verified":
		return "confirmed", "auth_divergence"
	default:
		return "pending", "cache_hint"
	}
}

func mapV1Evidence(evidence string) string {
	switch evidence {
	case "repeated":
		return "repeated"
	case "verified":
		return "auth_divergence"
	default:
		return "cache_hint"
	}
}

func normalizeV1Level(level string) string {
	switch level {
	case "critical", "high", "medium", "low":
		return level
	default:
		return "unknown"
	}
}

func observationToV1(observation DomainNSObservation) []nsV1Record {
	records := make([]nsV1Record, 0, len(observation.Nameservers))
	for _, host := range observation.Nameservers {
		ips := make([]string, 0, len(host.Addresses))
		asns, organizations, countries := make([]string, 0), make([]string, 0), make([]string, 0)
		for _, address := range host.Addresses {
			if address.Address != "" {
				ips = append(ips, address.Address)
			}
			if address.ASN > 0 {
				asns = append(asns, fmt.Sprintf("AS%d", address.ASN))
			}
			if address.ASNOrganization != "" {
				organizations = append(organizations, address.ASNOrganization)
			}
			if address.Country != "" {
				countries = append(countries, address.Country)
			}
		}
		records = append(records, nsV1Record{
			Host:    host.Name,
			IPs:     uniqueSortedStrings(ips),
			ASN:     joinUnknown(uniqueSortedStrings(asns)),
			ASNOrg:  joinUnknown(uniqueSortedStrings(organizations)),
			Country: joinUnknown(uniqueSortedStrings(countries)),
		})
	}
	return records
}

func joinUnknown(values []string) string {
	if len(values) == 0 {
		return "未知"
	}
	return strings.Join(values, " / ")
}

func formatV1Time(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format("2006-01-02 15:04:05")
}

func durationMinutes(first, last time.Time) int {
	if first.IsZero() || last.Before(first) {
		return 0
	}
	return int(last.Sub(first).Round(time.Minute) / time.Minute)
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func v1EventFilterFromRequest(r *http.Request) nsEventFilter {
	level := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("level")))
	if level == "all" {
		level = ""
	}
	status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	switch status {
	case "recovered":
		status = "resolved"
	case "pending", "active":
		status = "pending_verification"
	case "confirmed":
		// 两个已确认状态无法用旧接口的单值过滤表达，在 handler 中二次过滤。
		status = ""
	case "all":
		status = ""
	}
	return nsEventFilter{
		Query:    strings.TrimSpace(r.URL.Query().Get("q")),
		Severity: level,
		Status:   status,
		Page:     parseNSPositiveInt(r.URL.Query().Get("page"), 1, 1, 10_000),
		Limit:    parseNSPositiveInt(r.URL.Query().Get("limit"), 50, 1, 100),
	}
}

func (s *nsMonitorServer) v1Events(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	filter := v1EventFilterFromRequest(r)
	evidence := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("evidence")))
	eventType := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("type")))
	status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	items := make([]nsV1RiskEvent, 0)
	for _, event := range s.analysis.Events {
		item := eventToV1(event, 1)
		if !matchesV1Event(item, filter, evidence, eventType, status) {
			continue
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].LastSeen > items[j].LastSeen })
	total := len(items)
	start := (filter.Page - 1) * filter.Limit
	if start > total {
		start = total
	}
	end := start + filter.Limit
	if end > total {
		end = total
	}
	writeNSJSON(w, http.StatusOK, nsV1EventsResponse{Items: items[start:end], Total: total, Page: filter.Page, Limit: filter.Limit})
}

func matchesV1Event(item nsV1RiskEvent, filter nsEventFilter, evidence, eventType, status string) bool {
	if filter.Query != "" {
		query := strings.ToLower(filter.Query)
		if !strings.Contains(strings.ToLower(item.Domain), query) && !strings.Contains(strings.ToLower(item.ID), query) && !strings.Contains(strings.ToLower(item.Summary), query) {
			return false
		}
	}
	if filter.Severity != "" && item.Level != filter.Severity {
		return false
	}
	if eventType != "" && eventType != "all" && item.Type != eventType {
		return false
	}
	if evidence != "" && evidence != "all" && item.Evidence != evidence {
		return false
	}
	return status == "" || status == "all" || item.Status == status
}

func (s *nsPersistentMonitorServer) v1Events(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	filter := v1EventFilterFromRequest(r)
	evidence := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("evidence")))
	eventType := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("type")))
	status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))

	ctx, cancel := context.WithTimeout(r.Context(), nsWebQueryTimeout)
	defer cancel()
	items, total, err := s.store.v1EventsPage(ctx, filter, evidence, eventType, status)
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	writeNSJSON(w, http.StatusOK, nsV1EventsResponse{Items: items, Total: total, Page: filter.Page, Limit: filter.Limit})
}

const nsV1EventRowsSQL = `WITH
	action_latest AS (
		SELECT event_id, argMax(action, acted_at) AS action, argMax(expires_at, acted_at) AS expires_at
		FROM ns_event_actions GROUP BY event_id
	),
	change_clusters AS (
		SELECT argMax(event_id, last_seen) AS event_id, 'ns_change' AS risk_type, domain, severity,
			argMax(evidence, last_seen) AS raw_evidence, argMax(status, last_seen) AS raw_status,
			summary, arraySort(change_types) AS normalized_change_fields,
			min(first_seen) AS cluster_first_seen, max(last_seen) AS cluster_last_seen,
			if(argMax(status, last_seen) = 'resolved', argMax(resolved_at, last_seen),
				CAST(NULL AS Nullable(DateTime64(3, 'UTC')))) AS cluster_resolved_at,
			sum(occurrences) AS cluster_occurrences,
			count() AS cluster_size, '' AS snapshot_id,
			argMax(baseline_json, last_seen) AS baseline_json,
			argMax(current_json, last_seen) AS current_json, '{}' AS extra_json
		FROM ns_change_events FINAL
		GROUP BY domain, severity, summary, normalized_change_fields
	),
	raw_events AS (
		SELECT event_id, risk_type, domain, severity, raw_evidence, raw_status, summary,
			normalized_change_fields, cluster_first_seen AS first_seen, cluster_last_seen AS last_seen,
			cluster_resolved_at AS resolved_at, cluster_occurrences AS occurrences, cluster_size,
			snapshot_id, baseline_json, current_json, extra_json
		FROM change_clusters
		UNION ALL
		SELECT event_id, risk_type, domain, severity, evidence AS raw_evidence, status AS raw_status,
			summary, change_fields AS normalized_change_fields, first_seen, last_seen, resolved_at,
			toUInt64(occurrences) AS occurrences, greatest(toUInt64(occurrences), toUInt64(1)) AS cluster_size,
			snapshot_id, '{}' AS baseline_json, current_json, extra_json
		FROM ns_risk_events FINAL
	),
	action_events AS (
		SELECT raw_events.*,
			if(action_latest.action = 'whitelist' AND
				(isNull(action_latest.expires_at) OR action_latest.expires_at <= now64(3)),
				'', action_latest.action) AS effective_action
		FROM raw_events LEFT JOIN action_latest USING (event_id)
	),
	normalized_events AS (
		SELECT *,
			multiIf(
				effective_action = 'confirm', 'confirmed',
				effective_action IN ('ignore', 'whitelist'), 'ignored',
				raw_status = 'resolved', 'recovered',
				raw_status IN ('verified_impact', 'verified_ns_divergence') OR raw_evidence = 'verified', 'confirmed',
				raw_status = 'pending_verification', 'pending',
				risk_type = 'ns_change' OR raw_evidence = 'observed', 'pending',
				'active') AS normalized_status,
			multiIf(
				raw_status = 'verified_impact', 'impact_confirmed',
				raw_status = 'verified_ns_divergence' OR raw_evidence = 'verified', 'auth_divergence',
				raw_status = 'pending_verification', 'pending_verify',
				raw_evidence = 'repeated', 'repeated',
				'cache_hint') AS normalized_evidence
		FROM action_events
	)
`

func buildV1EventWhere(filter nsEventFilter, evidence, eventType, status string) (string, []any) {
	clauses := make([]string, 0, 5)
	args := make([]any, 0, 7)
	if query := strings.ToLower(strings.TrimSpace(filter.Query)); query != "" {
		pattern := "%" + query + "%"
		clauses = append(clauses, "(lower(domain) LIKE ? OR lower(event_id) LIKE ? OR lower(summary) LIKE ?)")
		args = append(args, pattern, pattern, pattern)
	}
	if filter.Severity != "" {
		clauses = append(clauses, "severity = ?")
		args = append(args, filter.Severity)
	}
	if eventType != "" && eventType != "all" {
		clauses = append(clauses, "risk_type = ?")
		args = append(args, eventType)
	}
	if evidence != "" && evidence != "all" {
		clauses = append(clauses, "normalized_evidence = ?")
		args = append(args, evidence)
	}
	if status != "" && status != "all" {
		clauses = append(clauses, "normalized_status = ?")
		args = append(args, status)
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func (s *nsPersistentStore) v1EventsPage(ctx context.Context, filter nsEventFilter, evidence, eventType, status string) ([]nsV1RiskEvent, int, error) {
	where, args := buildV1EventWhere(filter, evidence, eventType, status)
	var total uint64
	if err := s.db.QueryRowContext(ctx, nsV1EventRowsSQL+"SELECT count() FROM normalized_events"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := nsV1EventRowsSQL + `SELECT event_id, risk_type, domain, severity, raw_evidence, raw_status,
		summary, normalized_change_fields, first_seen, last_seen, resolved_at, occurrences, cluster_size,
		snapshot_id, baseline_json, current_json, extra_json
		FROM normalized_events` + where + `
		ORDER BY multiIf(severity = 'critical', 4, severity = 'high', 3, severity = 'medium', 2, 1) DESC,
			last_seen DESC, event_id DESC LIMIT ? OFFSET ?`
	queryArgs := append(append([]any(nil), args...), filter.Limit, (filter.Page-1)*filter.Limit)
	rows, err := s.db.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	actions, err := s.latestEventActions(ctx)
	if err != nil {
		return nil, 0, err
	}
	items := make([]nsV1RiskEvent, 0, filter.Limit)
	for rows.Next() {
		var id, riskType, domain, severity, rawEvidence, rawStatus, summary, snapshotID string
		var baselineRaw, currentRaw, extraRaw string
		var changeFields []string
		var firstSeen, lastSeen time.Time
		var resolvedAt sql.NullTime
		var occurrences, clusterSize uint64
		if err := rows.Scan(&id, &riskType, &domain, &severity, &rawEvidence, &rawStatus, &summary,
			&changeFields, &firstSeen, &lastSeen, &resolvedAt, &occurrences, &clusterSize, &snapshotID,
			&baselineRaw, &currentRaw, &extraRaw); err != nil {
			return nil, 0, err
		}
		if riskType == "ns_change" {
			event := NSChangeEvent{ID: id, Domain: domain, Severity: severity, Evidence: rawEvidence, Status: rawStatus,
				Summary: summary, ChangeTypes: changeFields, FirstSeen: firstSeen, LastSeen: lastSeen, Occurrences: int(occurrences)}
			if resolvedAt.Valid {
				value := resolvedAt.Time
				event.ResolvedAt = &value
			}
			if err := json.Unmarshal([]byte(baselineRaw), &event.Baseline); err != nil {
				return nil, 0, fmt.Errorf("解析事件 %s 基线: %w", id, err)
			}
			if err := json.Unmarshal([]byte(currentRaw), &event.Current); err != nil {
				return nil, 0, fmt.Errorf("解析事件 %s 当前观测: %w", id, err)
			}
			item := eventToV1(event, int(clusterSize))
			if action, exists := actions[id]; exists {
				applyV1EventAction(&item, &action)
			}
			items = append(items, item)
			continue
		}
		aux := NSAuxRiskEvent{ID: id, Type: riskType, Domain: domain, Severity: severity, Evidence: rawEvidence,
			Status: rawStatus, Summary: summary, ChangeFields: changeFields, FirstSeen: firstSeen, LastSeen: lastSeen,
			Occurrences: int(occurrences), SnapshotID: snapshotID}
		if resolvedAt.Valid {
			value := resolvedAt.Time
			aux.ResolvedAt = &value
		}
		if err := json.Unmarshal([]byte(currentRaw), &aux.Current); err != nil {
			return nil, 0, fmt.Errorf("解析事件 %s 当前观测: %w", id, err)
		}
		if extraRaw != "" {
			if err := json.Unmarshal([]byte(extraRaw), &aux.Extra); err != nil {
				return nil, 0, fmt.Errorf("解析事件 %s 扩展证据: %w", id, err)
			}
		}
		if obsoleteNSRedundancyEvent(aux) {
			continue
		}
		item := auxEventToV1(aux)
		if action, exists := actions[id]; exists {
			applyV1EventAction(&item, &action)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, int(total), nil
}

func summaryToEvent(summary nsEventSummary) NSChangeEvent {
	event := NSChangeEvent{
		ID: summary.ID, Domain: summary.Domain, Severity: summary.Severity, Evidence: summary.Evidence,
		Status: summary.Status, Summary: summary.Summary, ChangeTypes: summary.ChangeTypes,
		Occurrences: summary.Occurrences,
	}
	event.FirstSeen, _ = time.Parse(timeLayoutForJSON, summary.FirstSeen)
	event.LastSeen, _ = time.Parse(timeLayoutForJSON, summary.LastSeen)
	if summary.ResolvedAt != "" {
		resolved, err := time.Parse(timeLayoutForJSON, summary.ResolvedAt)
		if err == nil {
			event.ResolvedAt = &resolved
		}
	}
	return event
}

func (s *nsMonitorServer) v1EventDetail(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/events/"), "/"), "/")
	if len(parts) == 2 && parts[0] != "" {
		switch parts[1] {
		case "actions":
			s.v1EventAction(w, r, parts[0])
			return
		case "impact":
			s.eventImpact(w, nsRequestWithQuery(r, "event_id", parts[0]))
			return
		case "probe":
			s.v1EventProbe(w, r, parts[0])
			return
		case "rr":
			s.v1EventRR(w, r, parts[0])
			return
		}
	}
	if !requireNSMethod(w, r) {
		return
	}
	if len(parts) != 1 || parts[0] == "" {
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "事件不存在"})
		return
	}
	eventID := parts[0]
	for _, event := range s.analysis.Events {
		if event.ID != eventID {
			continue
		}
		item := eventToV1(event, 1)
		if detail, ok := s.analysis.DomainDetail(event.Domain); ok {
			item.Timeline = timelineToV1(detail.Timeline)
			for _, point := range detail.Timeline {
				if point.EventID == event.ID && point.SnapshotID != "" {
					item.Snapshot = point.SnapshotID
				}
			}
		}
		writeNSJSON(w, http.StatusOK, item)
		return
	}
	writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "事件不存在或已超出保留周期"})
}

func (s *nsPersistentMonitorServer) v1EventDetail(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/events/"), "/"), "/")
	if len(parts) == 2 && parts[0] != "" {
		switch parts[1] {
		case "actions":
			s.v1EventAction(w, r, parts[0])
			return
		case "impact":
			s.eventImpact(w, nsRequestWithQuery(r, "event_id", parts[0]))
			return
		case "probe":
			s.eventProbe(w, nsRequestWithQuery(r, "event_id", parts[0]))
			return
		case "rr":
			s.v1EventRR(w, r, parts[0])
			return
		}
	}
	if !requireNSMethod(w, r) {
		return
	}
	if len(parts) != 1 || parts[0] == "" {
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "事件不存在"})
		return
	}
	eventID := parts[0]
	ctx, cancel := context.WithTimeout(r.Context(), nsWebQueryTimeout)
	defer cancel()
	event, err := s.store.eventByID(ctx, eventID)
	if errors.Is(err, errNSPersistentNotFound) {
		auxEvent, auxErr := s.store.auxEventByID(ctx, eventID)
		if errors.Is(auxErr, errNSPersistentNotFound) {
			writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "事件不存在或已超出保留周期"})
			return
		}
		if auxErr != nil {
			nsPersistentError(w, auxErr)
			return
		}
		item := auxEventToV1(auxEvent)
		action, actionErr := s.store.latestEventAction(ctx, eventID)
		if actionErr != nil {
			nsPersistentError(w, actionErr)
			return
		}
		applyV1EventAction(&item, action)
		if probe, probeErr := s.store.latestEventProbe(ctx, eventID); probeErr == nil {
			applyProbeToV1(&item, probe)
		} else if !errors.Is(probeErr, errNSPersistentNotFound) {
			nsPersistentError(w, probeErr)
			return
		}
		item.Timeline = auxTimelineToV1(auxEvent)
		alerts, alertErr := s.store.eventAlerts(ctx, eventID)
		if alertErr != nil {
			nsPersistentError(w, alertErr)
			return
		}
		item.Alerts = alerts
		writeNSJSON(w, http.StatusOK, item)
		return
	}
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	item := eventToV1(event, 1)
	action, actionErr := s.store.latestEventAction(ctx, eventID)
	if actionErr != nil {
		nsPersistentError(w, actionErr)
		return
	}
	applyV1EventAction(&item, action)
	if snapshotID, snapshotErr := s.store.snapshotIDForEvent(ctx, event); snapshotErr == nil {
		item.Snapshot = snapshotID
	}
	if probe, probeErr := s.store.latestEventProbe(ctx, eventID); probeErr == nil {
		applyProbeToV1(&item, probe)
	} else if !errors.Is(probeErr, errNSPersistentNotFound) {
		nsPersistentError(w, probeErr)
		return
	}
	if timeline, timelineErr := s.store.eventTimeline(ctx, event); timelineErr == nil {
		item.Timeline = timelineToV1(timeline)
	} else {
		nsPersistentError(w, timelineErr)
		return
	}
	alerts, alertErr := s.store.eventAlerts(ctx, eventID)
	if alertErr != nil {
		nsPersistentError(w, alertErr)
		return
	}
	item.Alerts = alerts
	writeNSJSON(w, http.StatusOK, item)
}

func auxTimelineToV1(event NSAuxRiskEvent) []nsV1TimelineNode {
	points := []nsV1TimelineNode{{
		Time: formatV1Time(event.FirstSeen), Kind: "start",
		Title: "风险事件开始", Detail: event.Summary,
	}}
	if event.LastSeen.After(event.FirstSeen) {
		points = append(points, nsV1TimelineNode{
			Time: formatV1Time(event.LastSeen), Kind: "repeat",
			Title: fmt.Sprintf("连续观测 %d 次", maxInt(event.Occurrences, 1)), Detail: event.Summary,
		})
	}
	if event.Evidence == "verified" || event.Status == "verified_ns_divergence" || event.Status == "verified_impact" {
		points = append(points, nsV1TimelineNode{
			Time: formatV1Time(event.LastSeen), Kind: "verify",
			Title: "主动拨测形成验证证据", Detail: stringValue(event.Extra["activeProbeSummary"]),
		})
	}
	if event.ResolvedAt != nil {
		points = append(points, nsV1TimelineNode{
			Time: formatV1Time(*event.ResolvedAt), Kind: "recover",
			Title: "风险事件恢复", Detail: "当前快照已不再满足该风险条件",
		})
	}
	sort.SliceStable(points, func(i, j int) bool { return points[i].Time > points[j].Time })
	return points
}

func stringValue(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

func domainDetailToV1(detail DomainNSDetail) nsV1DomainDetail {
	firstObserved := ""
	if len(detail.Timeline) > 0 {
		first := detail.Timeline[0].CapturedAt
		for _, point := range detail.Timeline[1:] {
			if point.CapturedAt.Before(first) {
				first = point.CapturedAt
			}
		}
		firstObserved = formatV1Time(first)
	}
	events := make([]nsV1RiskEvent, 0, len(detail.Events))
	for _, event := range detail.Events {
		item := eventToV1(event, 1)
		item.Timeline = timelineToV1(detail.Timeline)
		events = append(events, item)
	}
	confirmed := detail.BaselineSource == "confirmed"
	baselineSnapshots := 0
	if confirmed {
		baselineSnapshots = int(NSBaselineConsecutiveRequired)
	}
	return nsV1DomainDetail{
		Domain: detail.Domain, BaselineEstablished: confirmed, BaselineSnapshots: baselineSnapshots,
		BaselineSource: detail.BaselineSource, FirstObserved: firstObserved,
		BaselineNS: observationToV1(detail.Baseline), CurrentNS: observationToV1(detail.Current),
		RelatedEvents: events, Timeline: timelineToV1(detail.Timeline),
	}
}

func v1DomainFromPath(r *http.Request) string {
	value := strings.TrimPrefix(r.URL.Path, "/api/v1/domains/")
	if value == "" || strings.Contains(value, "/") {
		return ""
	}
	return normalizeFQDN(value)
}

func (s *nsMonitorServer) v1Domains(w http.ResponseWriter, r *http.Request) {
	s.domains(w, r)
}

func (s *nsPersistentMonitorServer) v1Domains(w http.ResponseWriter, r *http.Request) {
	s.domains(w, r)
}

func nsRequestWithQuery(r *http.Request, key, value string) *http.Request {
	clone := r.Clone(r.Context())
	urlCopy := *r.URL
	query := urlCopy.Query()
	query.Set(key, value)
	urlCopy.RawQuery = query.Encode()
	clone.URL = &urlCopy
	return clone
}

func (s *nsMonitorServer) v1EventProbe(w http.ResponseWriter, r *http.Request, eventID string) {
	if !requireNSMethod(w, r) {
		return
	}
	for _, event := range s.analysis.Events {
		if event.ID == eventID {
			writeNSJSON(w, http.StatusOK, nsEventProbeResponse{Available: false})
			return
		}
	}
	writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "事件不存在或已超出保留周期"})
}

func (s *nsMonitorServer) v1EventRR(w http.ResponseWriter, r *http.Request, eventID string) {
	if !requireNSMethod(w, r) {
		return
	}
	var event *NSChangeEvent
	for index := range s.analysis.Events {
		if s.analysis.Events[index].ID == eventID {
			event = &s.analysis.Events[index]
			break
		}
	}
	if event == nil {
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "事件不存在或已超出保留周期"})
		return
	}
	snapshotID := strings.TrimSpace(r.URL.Query().Get("snapshot_id"))
	if snapshotID == "" {
		if detail, ok := s.analysis.DomainDetail(event.Domain); ok {
			for _, point := range detail.Timeline {
				if point.EventID == eventID && point.SnapshotID != "" {
					snapshotID = point.SnapshotID
				}
			}
		}
	}
	if snapshotID == "" {
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "事件没有可用的原始快照"})
		return
	}
	request := nsRequestWithQuery(r, "snapshot_id", snapshotID)
	request = nsRequestWithQuery(request, "domain", event.Domain)
	s.record(w, request)
}

func (s *nsPersistentMonitorServer) v1EventRR(w http.ResponseWriter, r *http.Request, eventID string) {
	if !requireNSMethod(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nsWebQueryTimeout)
	defer cancel()
	event, err := s.store.eventByID(ctx, eventID)
	domain := event.Domain
	snapshotID := strings.TrimSpace(r.URL.Query().Get("snapshot_id"))
	if errors.Is(err, errNSPersistentNotFound) {
		aux, auxErr := s.store.auxEventByID(ctx, eventID)
		if errors.Is(auxErr, errNSPersistentNotFound) {
			writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "事件不存在或已超出保留周期"})
			return
		}
		if auxErr != nil {
			nsPersistentError(w, auxErr)
			return
		}
		domain = aux.Domain
		if snapshotID == "" {
			snapshotID = aux.SnapshotID
		}
	} else if err != nil {
		nsPersistentError(w, err)
		return
	} else if snapshotID == "" {
		snapshotID, err = s.store.snapshotIDForEvent(ctx, event)
		if err != nil {
			if errors.Is(err, errNSPersistentNotFound) {
				writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "事件没有可用的原始快照"})
			} else {
				nsPersistentError(w, err)
			}
			return
		}
	}
	if snapshotID == "" || domain == "" {
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "事件没有可用的原始快照"})
		return
	}
	request := nsRequestWithQuery(r, "snapshot_id", snapshotID)
	request = nsRequestWithQuery(request, "domain", domain)
	s.record(w, request)
}

func (s *nsMonitorServer) v1DomainDetail(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	domain := v1DomainFromPath(r)
	if domain == "" {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "域名不能为空"})
		return
	}
	detail, ok := s.analysis.DomainDetail(domain)
	if !ok {
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "当前观测中未找到该域名"})
		return
	}
	writeNSJSON(w, http.StatusOK, domainDetailToV1(detail))
}

func (s *nsPersistentMonitorServer) v1DomainDetail(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	domain := v1DomainFromPath(r)
	if domain == "" {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "域名不能为空"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nsWebQueryTimeout)
	defer cancel()
	detail, err := s.store.domainDetail(ctx, domain)
	if errors.Is(err, errNSPersistentNotFound) {
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "持久化观测中未找到该域名"})
		return
	}
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	response := domainDetailToV1(detail)
	auxEvents, auxErr := s.store.auxEventsForDomain(ctx, domain)
	if auxErr != nil {
		nsPersistentError(w, auxErr)
		return
	}
	for _, event := range auxEvents {
		response.RelatedEvents = append(response.RelatedEvents, auxEventToV1(event))
		response.Timeline = append(response.Timeline, auxTimelineToV1(event)...)
	}
	sort.Slice(response.RelatedEvents, func(i, j int) bool {
		return response.RelatedEvents[i].LastSeen > response.RelatedEvents[j].LastSeen
	})
	sort.SliceStable(response.Timeline, func(i, j int) bool { return response.Timeline[i].Time > response.Timeline[j].Time })
	writeNSJSON(w, http.StatusOK, response)
}

func timelineToV1(points []NSTimelinePoint) []nsV1TimelineNode {
	result := make([]nsV1TimelineNode, 0, len(points))
	for _, point := range points {
		kind, title := "repeat", point.Summary
		switch point.State {
		case "baseline", "baseline_rolled":
			kind, title = "baseline", "建立或滚动更新权威基线"
		case "event_started":
			kind, title = "start", "首次观测到 NS 变化"
		case "event_resolved":
			kind, title = "recover", "风险事件恢复"
		case "event_active":
			kind, title = "repeat", "异常状态持续"
		}
		if point.Summary != "" {
			title = point.Summary
		}
		result = append(result, nsV1TimelineNode{Time: formatV1Time(point.CapturedAt), Kind: kind, Title: title, Detail: point.SnapshotID})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Time > result[j].Time })
	return result
}

func applyProbeToV1(item *nsV1RiskEvent, probe *NSProbeResult) {
	if item == nil || probe == nil {
		return
	}
	item.PartialEvidence = probe.Verdict == "inconclusive"
	item.ProbeVerdict = probe.Verdict
	item.ProbeSummary = probe.Summary
	for _, domain := range probe.Domains {
		for _, host := range append(append([]NSProbeHostResult(nil), domain.StableNS...), domain.VariantNS...) {
			result := nsV1ProbeResult{Domain: domain.Domain, Role: host.Role, NS: host.Host, Detail: domain.Summary}
			if host.Effective != nil {
				answer := host.Effective
				reachable := answer.Error == ""
				result.Reachable = &reachable
				if len(answer.IPv4) > 0 {
					result.IP = answer.IPv4[0]
				} else if len(answer.IPv6) > 0 {
					result.IP = answer.IPv6[0]
				}
				if answer.Error != "" {
					result.Detail = answer.Error
				}
				duration := answer.DurationMS
				result.RTTMS = &duration
				view := probeAnswerToV1(*answer)
				result.Answer = &view
				if domain.StableConsensus != nil {
					stable := probeAnswerToV1(*domain.StableConsensus)
					result.StableConsensus = &stable
					result.Differences = diffProbeAnswers(*domain.StableConsensus, *answer)
				}
			}
			if host.MatchesStable != nil {
				matches := *host.MatchesStable
				result.AnswerConsistent = &matches
			}
			item.Probes = append(item.Probes, result)
		}
		if domain.TrustedConsensus != nil {
			item.TrustedAnswer = formatProbeAnswer(*domain.TrustedConsensus)
		}
		item.RecursiveAnswer = formatProbeAnswer(domain.RecursiveResult)
		comparison := nsV1ProbeComparison{Domain: domain.Domain, Verdict: domain.Verdict, Summary: domain.Summary, Recursive: probeAnswerToV1(domain.RecursiveResult)}
		if domain.StableConsensus != nil {
			stable := probeAnswerToV1(*domain.StableConsensus)
			comparison.Stable = &stable
			comparison.RecursiveDifferences = diffProbeAnswers(*domain.StableConsensus, domain.RecursiveResult)
		}
		if domain.TrustedConsensus != nil {
			trusted := probeAnswerToV1(*domain.TrustedConsensus)
			comparison.Trusted = &trusted
			if domain.StableConsensus != nil {
				comparison.TrustedDifferences = diffProbeAnswers(*domain.StableConsensus, *domain.TrustedConsensus)
			}
		}
		item.ProbeComparisons = append(item.ProbeComparisons, comparison)
	}
}

func probeAnswerToV1(answer DNSProbeAnswer) nsV1ProbeAnswer {
	return nsV1ProbeAnswer{
		RCode: answer.RCode, CNAME: uniqueSortedStrings(answer.CNAME), A: uniqueSortedStrings(answer.IPv4),
		AAAA: uniqueSortedStrings(answer.IPv6), AuthorityNS: uniqueSortedStrings(answer.NS), Error: answer.Error,
	}
}

func diffProbeAnswers(stable, current DNSProbeAnswer) []nsV1ProbeFieldDiff {
	rows := []nsV1ProbeFieldDiff{
		{Field: "rcode", Label: "RCode", Stable: probeStringSlice(stable.RCode), Current: probeStringSlice(current.RCode)},
		{Field: "cname", Label: "CNAME 链", Stable: append([]string(nil), stable.CNAME...), Current: append([]string(nil), current.CNAME...)},
		{Field: "a", Label: "A 记录", Stable: append([]string(nil), stable.IPv4...), Current: append([]string(nil), current.IPv4...)},
		{Field: "aaaa", Label: "AAAA 记录", Stable: append([]string(nil), stable.IPv6...), Current: append([]string(nil), current.IPv6...)},
		{Field: "authority_ns", Label: "Authority 附加 NS", Stable: append([]string(nil), stable.NS...), Current: append([]string(nil), current.NS...), Note: "来自响应 Authority 段，不等同于 A/AAAA 最终答案"},
	}
	for index := range rows {
		rows[index].Stable = uniqueSortedStrings(rows[index].Stable)
		rows[index].Current = uniqueSortedStrings(rows[index].Current)
		rows[index].Changed = strings.Join(rows[index].Stable, "\x00") != strings.Join(rows[index].Current, "\x00")
	}
	return rows
}

func probeStringSlice(value string) []string {
	if strings.TrimSpace(value) == "" {
		return make([]string, 0)
	}
	return []string{value}
}

func formatProbeAnswer(answer DNSProbeAnswer) string {
	if answer.Error != "" {
		return "查询失败：" + answer.Error
	}
	values := append(append(append(append([]string(nil), answer.CNAME...), answer.IPv4...), answer.IPv6...), answer.NS...)
	if len(values) == 0 {
		return answer.RCode + "（无所查询类型的结果）"
	}
	return strings.Join(values, ", ") + "（" + answer.RCode + "）"
}

func (s *nsPersistentStore) eventTimeline(ctx context.Context, event NSChangeEvent) ([]NSTimelinePoint, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT captured_at, ns_count, fingerprint, snapshot_id, state, severity, event_id, summary
		FROM ns_domain_timeline FINAL
		WHERE domain = ? AND (event_id = ? OR (captured_at >= ? AND captured_at <= ?))
		ORDER BY captured_at DESC, snapshot_id DESC LIMIT 500`,
		event.Domain, event.ID, event.FirstSeen, event.LastSeen)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]NSTimelinePoint, 0)
	for rows.Next() {
		var point NSTimelinePoint
		var nsCount uint16
		if err := rows.Scan(&point.CapturedAt, &nsCount, &point.Fingerprint, &point.SnapshotID, &point.State, &point.Severity, &point.EventID, &point.Summary); err != nil {
			return nil, err
		}
		point.NSCount = int(nsCount)
		result = append(result, point)
	}
	return result, rows.Err()
}

func (s *nsPersistentStore) eventAlerts(ctx context.Context, eventID string) ([]nsV1AlertRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT recipient, status, attempted_at, message
		FROM ns_alert_notifications
		WHERE event_id = ? ORDER BY attempted_at DESC LIMIT 200`, eventID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]nsV1AlertRecord, 0)
	for rows.Next() {
		var recipient, status, attemptedAtMessage, message string
		var attemptedAt time.Time
		if err := rows.Scan(&recipient, &status, &attemptedAt, &message); err != nil {
			return nil, err
		}
		attemptedAtMessage = formatV1Time(attemptedAt)
		displayStatus := "发送失败"
		if status == "sent" {
			displayStatus = "已送达"
		}
		result = append(result, nsV1AlertRecord{Time: attemptedAtMessage, Channel: "邮件", Target: recipient, Status: displayStatus, Content: message})
	}
	return result, rows.Err()
}

func buildV1Overview(overview nsOverviewResponse, recent []nsV1RiskEvent) nsV1OverviewResponse {
	now := time.Now().UTC()
	kpis := nsV1OverviewKPIs{
		BaselineDomains: overview.Overview.TrackedDomains,
		LatestSnapshot:  formatV1Time(overview.Overview.LatestSnapshot.CapturedAt),
	}
	if !overview.Overview.LatestSnapshot.CapturedAt.IsZero() {
		delay := now.Sub(overview.Overview.LatestSnapshot.CapturedAt.UTC())
		if delay > 0 {
			kpis.DataDelayMin = int(delay.Round(time.Minute) / time.Minute)
		}
	}
	for _, item := range recent {
		if item.Status != "recovered" {
			kpis.ActiveEvents++
			switch item.Level {
			case "critical":
				kpis.CriticalEvents++
			case "high":
				kpis.HighEvents++
			}
			if item.Status == "pending" {
				kpis.PendingVerify++
			}
		}
		firstSeen, _ := time.Parse("2006-01-02 15:04:05", item.FirstSeen)
		if !firstSeen.IsZero() && now.Sub(firstSeen) <= 24*time.Hour {
			kpis.New24H++
		}
		if item.RecoveredAt != "" {
			recoveredAt, _ := time.Parse("2006-01-02 15:04:05", item.RecoveredAt)
			if !recoveredAt.IsZero() && now.Sub(recoveredAt) <= 24*time.Hour {
				kpis.Recovered24H++
			}
		}
	}
	return nsV1OverviewResponse{
		KPIs: kpis, RecentEvents: recent, Snapshots: overview.Snapshots, Mode: overview.Mode,
		Warnings: overview.Overview.Warnings, GeneratedAt: formatV1Time(now),
	}
}

func (s *nsMonitorServer) v1Overview(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	recent := make([]nsV1RiskEvent, 0, len(s.analysis.Events))
	for _, event := range s.analysis.Events {
		recent = append(recent, eventToV1(event, 1))
	}
	sort.Slice(recent, func(i, j int) bool { return recent[i].LastSeen > recent[j].LastSeen })
	writeNSJSON(w, http.StatusOK, buildV1Overview(nsOverviewResponse{
		Overview: s.analysis.Overview(), Snapshots: s.analysis.Snapshots, Mode: "memory",
	}, recent))
}

func (s *nsPersistentMonitorServer) v1Overview(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nsWebQueryTimeout)
	defer cancel()
	overview, err := s.store.overview(ctx)
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	events, err := s.store.events(ctx, nsEventFilter{Page: 1, Limit: 100})
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	recent := make([]nsV1RiskEvent, 0, len(events.Events))
	for _, summary := range events.Events {
		recent = append(recent, eventToV1(summaryToEvent(summary), summary.MergedEvents))
	}
	auxEvents, err := s.store.auxEvents(ctx, 100)
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	for _, event := range auxEvents {
		recent = append(recent, auxEventToV1(event))
	}
	sort.Slice(recent, func(i, j int) bool { return recent[i].LastSeen > recent[j].LastSeen })
	response := buildV1Overview(overview, recent)
	kpis, err := s.store.v1OverviewKPIs(ctx, response.KPIs)
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	response.KPIs = kpis
	writeNSJSON(w, http.StatusOK, response)
}

func v1BlacklistSources(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	index, err := LoadNSBlacklistDirectory(GlobalConfig.Blacklist, time.Now().UTC())
	if err != nil {
		writeNSJSON(w, http.StatusServiceUnavailable, map[string]any{"sources": []NSBlacklistSource{}, "error": err.Error()})
		return
	}
	if index == nil {
		writeNSJSON(w, http.StatusOK, map[string]any{"sources": []NSBlacklistSource{}, "warning": "未配置离线黑名单目录"})
		return
	}
	writeNSJSON(w, http.StatusOK, map[string]any{"sources": index.Sources})
}

func (s *nsPersistentStore) v1OverviewKPIs(ctx context.Context, base nsV1OverviewKPIs) (nsV1OverviewKPIs, error) {
	var active, critical, high, pending, new24h, recovered24h uint64
	err := s.db.QueryRowContext(ctx, `SELECT
		countIf(status != 'resolved'),
		countIf(status != 'resolved' AND severity = 'critical'),
		countIf(status != 'resolved' AND severity = 'high'),
		countIf(status != 'resolved' AND (status = 'pending_verification' OR evidence = 'observed')),
		countIf(first_seen >= now64(3) - INTERVAL 24 HOUR),
		countIf(resolved_at IS NOT NULL AND resolved_at >= now64(3) - INTERVAL 24 HOUR)
		FROM (
			SELECT severity, evidence, status, first_seen, resolved_at FROM ns_change_events FINAL
			UNION ALL
			SELECT severity, evidence, status, first_seen, resolved_at FROM ns_risk_events FINAL
		)`).Scan(&active, &critical, &high, &pending, &new24h, &recovered24h)
	if err != nil {
		return nsV1OverviewKPIs{}, err
	}
	base.ActiveEvents = int(active)
	base.CriticalEvents = int(critical)
	base.HighEvents = int(high)
	base.PendingVerify = int(pending)
	base.New24H = int(new24h)
	base.Recovered24H = int(recovered24h)
	return base, nil
}
