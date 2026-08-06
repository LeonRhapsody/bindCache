package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

type NSAuxRiskEvent struct {
	ID           string              `json:"id"`
	Type         string              `json:"type"`
	Domain       string              `json:"domain"`
	Severity     string              `json:"severity"`
	Evidence     string              `json:"evidence"`
	Status       string              `json:"status"`
	Summary      string              `json:"summary"`
	ChangeFields []string            `json:"change_fields"`
	FirstSeen    time.Time           `json:"first_seen"`
	LastSeen     time.Time           `json:"last_seen"`
	ResolvedAt   *time.Time          `json:"resolved_at,omitempty"`
	Occurrences  int                 `json:"occurrences"`
	SnapshotID   string              `json:"snapshot_id"`
	Current      DomainNSObservation `json:"current"`
	Extra        map[string]any      `json:"extra"`
	Signature    string              `json:"signature"`
}

type nsAuxRiskTracker struct {
	active    map[string]NSAuxRiskEvent
	changed   map[string]NSAuxRiskEvent
	blacklist *NSBlacklistIndex
	whitelist map[string]nsWhitelistScope
}

func newNSAuxRiskTracker(active []NSAuxRiskEvent, blacklist *NSBlacklistIndex, whitelists ...map[string]nsWhitelistScope) *nsAuxRiskTracker {
	tracker := &nsAuxRiskTracker{active: make(map[string]NSAuxRiskEvent), changed: make(map[string]NSAuxRiskEvent)}
	tracker.blacklist = blacklist
	if len(whitelists) > 0 {
		tracker.whitelist = whitelists[0]
	}
	for _, event := range active {
		tracker.active[auxRiskKey(event.Type, event.Domain, event.Signature)] = event
	}
	return tracker
}

func auxRiskKey(riskType, domain, signature string) string {
	return strings.Join([]string{riskType, normalizeFQDN(domain), signature}, "\x00")
}

func (t *nsAuxRiskTracker) apply(summary SnapshotSummary, observations map[string]DomainNSObservation, cache *BindCache, additionalFindings ...[]NSRiskFinding) {
	if t == nil {
		return
	}
	findings := DetectNSSnapshotRisksWithBlacklist(cache, observations, t.blacklist)
	for _, extra := range additionalFindings {
		findings = append(findings, extra...)
	}
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		if _, suppressed := t.whitelist[finding.Type+"\x00"+normalizeFQDN(finding.Domain)]; suppressed {
			continue
		}
		key := auxRiskKey(finding.Type, finding.Domain, finding.Signature)
		seen[key] = struct{}{}
		event, exists := t.active[key]
		if exists {
			historyMaxNS := extraInt(event.Extra, "historyMaxNs")
			previousEvidence, previousStatus := event.Evidence, event.Status
			previousProbeVerdict := stringValue(event.Extra["activeProbeVerdict"])
			previousProbeSummary := stringValue(event.Extra["activeProbeSummary"])
			event.LastSeen = summary.CapturedAt
			event.Occurrences++
			event.SnapshotID = summary.ID
			event.Current = finding.Current
			event.Extra = finding.Extra
			if previousProbeVerdict != "" {
				event.Extra["activeProbeVerdict"] = previousProbeVerdict
			}
			if previousProbeSummary != "" {
				event.Extra["activeProbeSummary"] = previousProbeSummary
			}
			event.Summary = finding.Summary
			event.ChangeFields = append([]string(nil), finding.ChangeFields...)
			if event.Type == "ns_single" {
				currentCount := len(finding.Current.Nameservers)
				historyMax := historyMaxNS
				if historyMax < currentCount {
					historyMax = currentCount
				}
				event.Extra["historyMaxNs"] = historyMax
			}
			if previousEvidence == "verified" {
				event.Evidence = previousEvidence
				event.Status = previousStatus
				if previousProbeSummary != "" && !strings.Contains(event.Summary, previousProbeSummary) {
					event.Summary += "；" + previousProbeSummary
				}
			} else if event.Occurrences >= 2 {
				event.Evidence = "repeated"
				event.Status = "active"
			}
		} else {
			event = NSAuxRiskEvent{
				ID:   "RISK-" + strings.ToUpper(shortHash(strings.Join([]string{finding.Type, finding.Domain, finding.Signature, summary.CapturedAt.UTC().Format(time.RFC3339Nano)}, "\x00"))),
				Type: finding.Type, Domain: finding.Domain, Severity: finding.Severity,
				Evidence: "observed", Status: "active", Summary: finding.Summary,
				ChangeFields: append([]string(nil), finding.ChangeFields...),
				FirstSeen:    summary.CapturedAt, LastSeen: summary.CapturedAt, Occurrences: 1,
				SnapshotID: summary.ID, Current: finding.Current, Extra: finding.Extra, Signature: finding.Signature,
			}
			if event.Type == "ns_single" {
				event.Extra["historyMaxNs"] = len(finding.Current.Nameservers)
			}
		}
		t.active[key] = event
		t.changed[event.ID] = event
	}

	// 只有该域在当前快照仍有有效 NS 观测时，缺失的风险条件才代表恢复。
	// 整个域未进入缓存不能作为恢复证据。
	for key, event := range t.active {
		if _, stillRisky := seen[key]; stillRisky {
			continue
		}
		if _, domainObserved := observations[normalizeFQDN(event.Domain)]; !domainObserved {
			continue
		}
		resolvedAt := summary.CapturedAt
		event.Status = "resolved"
		event.ResolvedAt = &resolvedAt
		event.LastSeen = summary.CapturedAt
		event.SnapshotID = summary.ID
		t.changed[event.ID] = event
		delete(t.active, key)
	}
}

func extraInt(extra map[string]any, key string) int {
	switch value := extra[key].(type) {
	case int:
		return value
	case float64:
		return int(value)
	case json.Number:
		result, _ := value.Int64()
		return int(result)
	default:
		return 0
	}
}

func removeString(values []string, target string) []string {
	result := values[:0]
	for _, value := range values {
		if value != target {
			result = append(result, value)
		}
	}
	return result
}

func (t *nsAuxRiskTracker) changedEvents() []NSAuxRiskEvent {
	if t == nil {
		return nil
	}
	result := make([]NSAuxRiskEvent, 0, len(t.changed))
	for _, event := range t.changed {
		result = append(result, event)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].LastSeen.Equal(result[j].LastSeen) {
			return result[i].ID < result[j].ID
		}
		return result[i].LastSeen.Before(result[j].LastSeen)
	})
	return result
}

func loadActiveNSAuxRiskEvents(db *sql.DB) ([]NSAuxRiskEvent, error) {
	rows, err := db.Query(`SELECT event_id, risk_type, domain, severity, evidence, status, summary, change_fields,
		first_seen, last_seen, resolved_at, occurrences, snapshot_id, current_json, extra_json, signature
		FROM ns_risk_events FINAL WHERE status != 'resolved'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]NSAuxRiskEvent, 0)
	for rows.Next() {
		event, err := scanNSAuxRiskEvent(rows)
		if err != nil {
			return nil, err
		}
		if obsoleteNSRedundancyEvent(event) {
			continue
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

type nsAuxEventScanner interface {
	Scan(dest ...any) error
}

func scanNSAuxRiskEvent(scanner nsAuxEventScanner) (NSAuxRiskEvent, error) {
	var event NSAuxRiskEvent
	var resolvedAt sql.NullTime
	var occurrences uint32
	var currentRaw, extraRaw string
	err := scanner.Scan(&event.ID, &event.Type, &event.Domain, &event.Severity, &event.Evidence, &event.Status, &event.Summary,
		&event.ChangeFields, &event.FirstSeen, &event.LastSeen, &resolvedAt, &occurrences, &event.SnapshotID, &currentRaw, &extraRaw, &event.Signature)
	if err != nil {
		return NSAuxRiskEvent{}, err
	}
	event.Occurrences = int(occurrences)
	if resolvedAt.Valid {
		value := resolvedAt.Time
		event.ResolvedAt = &value
	}
	if err := json.Unmarshal([]byte(currentRaw), &event.Current); err != nil {
		return NSAuxRiskEvent{}, fmt.Errorf("解析风险事件 %s 当前 NS: %w", event.ID, err)
	}
	if err := json.Unmarshal([]byte(extraRaw), &event.Extra); err != nil {
		return NSAuxRiskEvent{}, fmt.Errorf("解析风险事件 %s 扩展证据: %w", event.ID, err)
	}
	return event, nil
}

func insertNSAuxRiskEvents(writer *nsClickHouseWriter, events []NSAuxRiskEvent) (int, error) {
	rows := make([][]any, 0, len(events))
	for _, event := range events {
		current, err := json.Marshal(event.Current)
		if err != nil {
			return 0, err
		}
		extra, err := json.Marshal(event.Extra)
		if err != nil {
			return 0, err
		}
		var resolvedAt any
		if event.ResolvedAt != nil {
			resolvedAt = event.ResolvedAt.UTC()
		}
		rows = append(rows, []any{
			event.ID, event.Type, event.Domain, event.Severity, event.Evidence, event.Status, event.Summary,
			event.ChangeFields, event.FirstSeen.UTC(), event.LastSeen.UTC(), resolvedAt, uint32(event.Occurrences),
			event.SnapshotID, string(current), string(extra), event.Signature,
		})
	}
	err := writer.batchInsert("ns_risk_events", []string{
		"event_id", "risk_type", "domain", "severity", "evidence", "status", "summary", "change_fields",
		"first_seen", "last_seen", "resolved_at", "occurrences", "snapshot_id", "current_json", "extra_json", "signature",
	}, rows, 500)
	if err != nil {
		return 0, err
	}
	return len(rows), nil
}

func (s *nsPersistentStore) auxEventByID(ctx context.Context, eventID string) (NSAuxRiskEvent, error) {
	row := s.db.QueryRowContext(ctx, `SELECT event_id, risk_type, domain, severity, evidence, status, summary, change_fields,
		first_seen, last_seen, resolved_at, occurrences, snapshot_id, current_json, extra_json, signature
		FROM ns_risk_events FINAL WHERE event_id = ? LIMIT 1`, eventID)
	event, err := scanNSAuxRiskEvent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return NSAuxRiskEvent{}, errNSPersistentNotFound
	}
	return event, err
}

func (s *nsPersistentStore) auxEvents(ctx context.Context, limit int) ([]NSAuxRiskEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT event_id, risk_type, domain, severity, evidence, status, summary, change_fields,
		first_seen, last_seen, resolved_at, occurrences, snapshot_id, current_json, extra_json, signature
		FROM ns_risk_events FINAL
		ORDER BY multiIf(severity = 'critical', 4, severity = 'high', 3, severity = 'medium', 2, 1) DESC, last_seen DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]NSAuxRiskEvent, 0)
	for rows.Next() {
		event, err := scanNSAuxRiskEvent(rows)
		if err != nil {
			return nil, err
		}
		if obsoleteNSRedundancyEvent(event) {
			continue
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

func (s *nsPersistentStore) auxEventsForDomain(ctx context.Context, domain string) ([]NSAuxRiskEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT event_id, risk_type, domain, severity, evidence, status, summary, change_fields,
		first_seen, last_seen, resolved_at, occurrences, snapshot_id, current_json, extra_json, signature
		FROM ns_risk_events FINAL WHERE domain = ?
		ORDER BY first_seen DESC, event_id DESC LIMIT 500`, normalizeFQDN(domain))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]NSAuxRiskEvent, 0)
	for rows.Next() {
		event, err := scanNSAuxRiskEvent(rows)
		if err != nil {
			return nil, err
		}
		if obsoleteNSRedundancyEvent(event) {
			continue
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

func obsoleteNSRedundancyEvent(event NSAuxRiskEvent) bool {
	if event.Type != "ns_single" {
		return false
	}
	_, valid := detectNSRedundancyRisk(event.Domain, event.Current)
	return !valid
}

func auxRiskEventsAsNSChange(events []NSAuxRiskEvent) []NSChangeEvent {
	result := make([]NSChangeEvent, 0, len(events))
	for _, event := range events {
		result = append(result, NSChangeEvent{
			ID: event.ID, Domain: event.Domain, Severity: event.Severity, Evidence: event.Evidence,
			Status: event.Status, Summary: "[" + event.Type + "] " + event.Summary,
			ChangeTypes: append([]string{event.Type}, event.ChangeFields...),
			FirstSeen:   event.FirstSeen, LastSeen: event.LastSeen, ResolvedAt: event.ResolvedAt,
			Occurrences: event.Occurrences, Current: event.Current, signature: event.Signature,
		})
	}
	return result
}

// ADB/SRTT 只是递归器内部的短期候选证据；NS 可用性事件必须经主动拨测
// 确认后才允许进入告警通道，避免将历史超时计数当成当前不可达。
func alertableNSAuxRiskEvents(events []NSAuxRiskEvent) []NSAuxRiskEvent {
	result := make([]NSAuxRiskEvent, 0, len(events))
	for _, event := range events {
		if event.Type == "ns_availability" && event.Evidence != "verified" {
			continue
		}
		if event.Type == "ns_parent_child" {
			continue
		}
		result = append(result, event)
	}
	return result
}
