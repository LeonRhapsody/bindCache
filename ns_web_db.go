package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	nsWebQueryTimeout      = 8 * time.Second
	nsWebSnapshotListLimit = 500
)

var errNSPersistentNotFound = errors.New("NS 持久化数据不存在")

// StartNSMonitorDatabaseServer 启动正式 NS 只读 Web。所有概览、事件和时间线
// 均从 ClickHouse 读取；原始 dump 只用于用户展开某个时间线节点时展示完整 RR。
func StartNSMonitorDatabaseServer(listenAddr string, db *sql.DB, rawDumpDir string) error {
	if err := validateNSWebAuthConfig(GlobalConfig.Web); err != nil {
		return fmt.Errorf("Web 认证配置: %w", err)
	}
	server := &nsPersistentMonitorServer{
		store:       &nsPersistentStore{db: db},
		rawDumpDir:  strings.TrimSpace(rawDumpDir),
		recordCache: make(map[string]nsSnapshotRecordResponse),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", server.health)
	mux.HandleFunc("/api/ns/overview", server.overview)
	mux.HandleFunc("/api/ns/events", server.events)
	mux.HandleFunc("/api/ns/event-impact", server.eventImpact)
	mux.HandleFunc("/api/ns/event-probe", server.eventProbe)
	mux.HandleFunc("/api/ns/domain", server.domain)
	mux.HandleFunc("/api/ns/record", server.record)
	mux.HandleFunc("/api/ns/domains", server.domains)
	mux.HandleFunc("/api/v1/overview", server.v1Overview)
	mux.HandleFunc("/api/v1/events", server.v1Events)
	mux.HandleFunc("/api/v1/events/", server.v1EventDetail)
	mux.HandleFunc("/api/v1/campaigns", server.v1Campaigns)
	mux.HandleFunc("/api/v1/campaigns/", server.v1Campaigns)
	mux.HandleFunc("/api/v1/ns-ownership", server.v1NSOwnership)
	mux.HandleFunc("/api/v1/ns-change-overview", server.v1NSChangeOverview)
	mux.HandleFunc("/api/v1/ns-dependencies", server.v1NSDependencies)
	mux.HandleFunc("/api/v1/ns-health", server.v1NSHealth)
	mux.HandleFunc("/api/v1/domains", server.v1Domains)
	mux.HandleFunc("/api/v1/domains/", server.v1DomainDetail)
	mux.HandleFunc("/api/v1/blacklists", server.v1Blacklists)
	mux.HandleFunc("/api/v1/alerts", server.v1Alerts)
	mux.HandleFunc("/api/v1/alerts/retry", server.v1AlertRetry)
	mux.HandleFunc("/api/v1/probes", server.v1Probes)
	mux.HandleFunc("/api/v1/system", server.v1System)
	mux.HandleFunc("/api/v1/settings", server.v1Settings)
	mux.HandleFunc("/api/v1/audit", server.v1Audit)
	mux.HandleFunc("/api/v1/session", v1Session)
	mux.HandleFunc("/", server.index)

	httpServer := &http.Server{
		Addr:              listenAddr,
		Handler:           nsMonitorAuth(mux, GlobalConfig.Web),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	fmt.Printf("NS 正式数据 Web 已启动: http://%s\n", listenAddr)
	if rawDumpDir == "" {
		fmt.Println("完整 RR 展开未配置原始 dump 目录：仅展示持久化 NS 信息")
	} else {
		fmt.Printf("完整 RR 原始 dump 目录: %s\n", rawDumpDir)
	}
	return httpServer.ListenAndServe()
}

type nsPersistentMonitorServer struct {
	store               *nsPersistentStore
	rawDumpDir          string
	recordMu            sync.RWMutex
	recordCache         map[string]nsSnapshotRecordResponse
	ownershipMu         sync.Mutex
	ownershipCache      *nsOwnershipStateCache
	changeOverviewMu    sync.Mutex
	changeOverviewCache *nsChangeOverviewCache
	dependencyMu        sync.Mutex
	dependencyCache     *nsDependencyCache
	healthMu            sync.Mutex
	healthCache         *nsHealthCache
}

type nsPersistentStore struct {
	db *sql.DB
}

type nsEventProbeResponse struct {
	Available bool           `json:"available"`
	Probe     *NSProbeResult `json:"probe,omitempty"`
}

func (s *nsPersistentMonitorServer) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeNSJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 GET"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nsWebQueryTimeout)
	defer cancel()
	if err := s.store.db.PingContext(ctx); err != nil {
		writeNSJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "degraded"})
		return
	}
	writeNSJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *nsPersistentMonitorServer) overview(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nsWebQueryTimeout)
	defer cancel()
	response, err := s.store.overview(ctx)
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	writeNSJSON(w, http.StatusOK, response)
}

func (s *nsPersistentMonitorServer) events(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nsWebQueryTimeout)
	defer cancel()
	response, err := s.store.events(ctx, nsEventFilter{
		Query:    strings.TrimSpace(r.URL.Query().Get("q")),
		Severity: strings.ToLower(strings.TrimSpace(r.URL.Query().Get("severity"))),
		Status:   strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status"))),
		Page:     parseNSPositiveInt(r.URL.Query().Get("page"), 1, 1, 10_000),
		Limit:    parseNSPositiveInt(r.URL.Query().Get("limit"), 50, 1, 100),
	})
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	writeNSJSON(w, http.StatusOK, response)
}

func (s *nsPersistentMonitorServer) eventImpact(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	eventID := strings.TrimSpace(r.URL.Query().Get("event_id"))
	if eventID == "" {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "event_id 参数不能为空"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nsWebQueryTimeout)
	defer cancel()
	event, err := s.store.eventByID(ctx, eventID)
	var auxEvent *NSAuxRiskEvent
	if errors.Is(err, errNSPersistentNotFound) {
		loaded, auxErr := s.store.auxEventByID(ctx, eventID)
		if errors.Is(auxErr, errNSPersistentNotFound) {
			writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "风险事件或其风险状态快照不存在"})
			return
		}
		if auxErr != nil {
			nsPersistentError(w, auxErr)
			return
		}
		auxEvent = &loaded
		event = auxRiskEventsAsNSChange([]NSAuxRiskEvent{loaded})[0]
		event.Current.CapturedAt = loaded.LastSeen
	}
	if err != nil {
		if !errors.Is(err, errNSPersistentNotFound) {
			nsPersistentError(w, err)
			return
		}
	}
	snapshotID := ""
	if auxEvent != nil {
		snapshotID = auxEvent.SnapshotID
	} else {
		snapshotID, err = s.store.snapshotIDForEvent(ctx, event)
	}
	if errors.Is(err, errNSPersistentNotFound) {
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "NS 事件对应的风险状态快照不存在"})
		return
	}
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	_, sourceName, err := s.store.snapshot(ctx, snapshotID)
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	source, err := resolveRawDumpPath(s.rawDumpDir, sourceName)
	if err != nil {
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "该风险快照的原始 dump 不在保留目录中，无法计算子域与 CNAME 影响面"})
		return
	}
	cache, err := ParseDNSCacheFile(source)
	if err != nil {
		nsPersistentError(w, fmt.Errorf("解析风险快照 %s: %w", sourceName, err))
		return
	}
	writeNSJSON(w, http.StatusOK, buildNSEventImpact(event, snapshotID, cache))
}

// eventProbe 返回事件最近一轮自动拨测的完整证据。正式 Web 只读取已入库结果，
// 不会因页面点击触发外部 DNS 请求。
func (s *nsPersistentMonitorServer) eventProbe(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	eventID := strings.TrimSpace(r.URL.Query().Get("event_id"))
	if eventID == "" {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "event_id 参数不能为空"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nsWebQueryTimeout)
	defer cancel()
	probe, err := s.store.latestEventProbe(ctx, eventID)
	if errors.Is(err, errNSPersistentNotFound) {
		writeNSJSON(w, http.StatusOK, nsEventProbeResponse{Available: false})
		return
	}
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	writeNSJSON(w, http.StatusOK, nsEventProbeResponse{Available: true, Probe: probe})
}

func (s *nsPersistentMonitorServer) domain(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	domain := normalizeFQDN(r.URL.Query().Get("domain"))
	if domain == "" {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "domain 参数不能为空"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nsWebQueryTimeout)
	defer cancel()
	detail, err := s.store.domainDetail(ctx, domain)
	if errors.Is(err, errNSPersistentNotFound) {
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "持久化快照中未找到该域名"})
		return
	}
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	writeNSJSON(w, http.StatusOK, detail)
}

func (s *nsPersistentMonitorServer) domains(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nsWebQueryTimeout)
	defer cancel()
	domains, err := s.store.domains(ctx, strings.TrimSpace(r.URL.Query().Get("q")), parseNSPositiveInt(r.URL.Query().Get("limit"), 30, 1, 100))
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	writeNSJSON(w, http.StatusOK, map[string]any{"domains": domains})
}

func (s *nsPersistentMonitorServer) record(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	snapshotID := strings.TrimSpace(r.URL.Query().Get("snapshot_id"))
	domain := normalizeFQDN(r.URL.Query().Get("domain"))
	if snapshotID == "" || domain == "" {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "snapshot_id 和 domain 参数不能为空"})
		return
	}
	cacheKey := snapshotID + "\x00" + domain
	s.recordMu.RLock()
	cached, exists := s.recordCache[cacheKey]
	s.recordMu.RUnlock()
	if exists {
		writeNSJSON(w, http.StatusOK, cached)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), nsWebQueryTimeout)
	defer cancel()
	snapshot, sourceName, err := s.store.snapshot(ctx, snapshotID)
	if errors.Is(err, errNSPersistentNotFound) {
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "快照 ID 不存在"})
		return
	}
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	nsObservation, err := s.store.snapshotNSObservation(ctx, snapshotID, domain)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		nsPersistentError(w, err)
		return
	}
	source, err := resolveRawDumpPath(s.rawDumpDir, sourceName)
	if err != nil {
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "该快照的原始 dump 不在保留目录中，无法展开完整 RR"})
		return
	}
	cache, err := ParseDNSCacheFile(source)
	if err != nil {
		nsPersistentError(w, fmt.Errorf("按需解析 %s: %w", sourceName, err))
		return
	}
	record, kind, found := findSnapshotDomainRecord(cache, domain)
	if !found {
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "该域名在所选快照中没有可展示的缓存记录"})
		return
	}
	response := nsSnapshotRecordResponse{Snapshot: snapshot, Domain: domain, RecordKind: kind, NSObservation: nsObservation, Groups: buildNSRRGroups(record)}
	s.recordMu.Lock()
	if len(s.recordCache) < 64 {
		s.recordCache[cacheKey] = response
	}
	s.recordMu.Unlock()
	writeNSJSON(w, http.StatusOK, response)
}

func (s *nsPersistentStore) snapshotNSObservation(ctx context.Context, snapshotID, domain string) ([]NSHostObservation, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT nameservers_json FROM ns_domain_observations FINAL
		WHERE snapshot_id = ? AND domain = ? LIMIT 1`, snapshotID, domain).Scan(&raw)
	if err != nil {
		return nil, err
	}
	var nameservers []NSHostObservation
	if err := json.Unmarshal([]byte(raw), &nameservers); err != nil {
		return nil, fmt.Errorf("解析快照 %s 域名 %s 的 NS 端点: %w", snapshotID, domain, err)
	}
	return nameservers, nil
}

func (s *nsPersistentMonitorServer) index(w http.ResponseWriter, r *http.Request) {
	serveNSMonitorFrontend(w, r)
}

func nsPersistentError(w http.ResponseWriter, err error) {
	fmt.Printf("NS 正式数据 Web 查询失败: %v\n", err)
	writeNSJSON(w, http.StatusInternalServerError, map[string]string{"error": "读取持久化 NS 数据失败"})
}

func (s *nsPersistentStore) overview(ctx context.Context) (nsOverviewResponse, error) {
	var totalSnapshots uint64
	if err := s.db.QueryRowContext(ctx, "SELECT count() FROM ns_snapshot_catalog FINAL").Scan(&totalSnapshots); err != nil {
		return nsOverviewResponse{}, err
	}
	var trackedDomains uint64
	if err := s.db.QueryRowContext(ctx, `SELECT count()
		FROM ns_domain_baseline AS baseline FINAL
		INNER JOIN ns_domain_baseline_state AS state FINAL ON baseline.domain = state.domain
		WHERE state.confirmed = 1`).Scan(&trackedDomains); err != nil {
		return nsOverviewResponse{}, err
	}

	eventCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	var activeEvents uint64
	rows, err := s.db.QueryContext(ctx, "SELECT severity, status, count() FROM ns_change_events FINAL GROUP BY severity, status")
	if err != nil {
		return nsOverviewResponse{}, err
	}
	for rows.Next() {
		var severity, status string
		var count uint64
		if err := rows.Scan(&severity, &status, &count); err != nil {
			_ = rows.Close()
			return nsOverviewResponse{}, err
		}
		eventCounts[severity] += int(count)
		if status != "resolved" {
			activeEvents += count
		}
	}
	if err := rows.Close(); err != nil {
		return nsOverviewResponse{}, err
	}

	snapshots, err := s.snapshots(ctx, nsWebSnapshotListLimit)
	if err != nil {
		return nsOverviewResponse{}, err
	}
	overview := NSOverview{
		Snapshots:      int(totalSnapshots),
		TrackedDomains: int(trackedDomains),
		EventCounts:    eventCounts,
		ActiveEvents:   int(activeEvents),
		Warnings: []string{
			"当前页面读取 ClickHouse 持久化 NS 时序数据。事件代表缓存观测，不能单独视为投毒结论。",
		},
	}
	if len(snapshots) > 0 {
		overview.LatestSnapshot = snapshots[len(snapshots)-1]
	}
	return nsOverviewResponse{Overview: overview, Snapshots: snapshots, Mode: "clickhouse"}, nil
}

func (s *nsPersistentStore) snapshots(ctx context.Context, limit int) ([]SnapshotSummary, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT snapshot_id, captured_at, source_name, view, total_domains, ns_observations
		FROM ns_snapshot_catalog FINAL ORDER BY captured_at DESC, snapshot_id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]SnapshotSummary, 0)
	for rows.Next() {
		var item SnapshotSummary
		var domains, observations uint64
		if err := rows.Scan(&item.ID, &item.CapturedAt, &item.Source, &item.View, &domains, &observations); err != nil {
			return nil, err
		}
		item.Domains = int(domains)
		item.NSObservations = int(observations)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CapturedAt.Before(items[j].CapturedAt) })
	return items, nil
}

func (s *nsPersistentStore) snapshot(ctx context.Context, snapshotID string) (SnapshotSummary, string, error) {
	var summary SnapshotSummary
	var totalDomains, observations uint64
	err := s.db.QueryRowContext(ctx, `SELECT snapshot_id, captured_at, source_name, view, total_domains, ns_observations
		FROM ns_snapshot_catalog FINAL WHERE snapshot_id = ? LIMIT 1`, snapshotID).Scan(&summary.ID, &summary.CapturedAt, &summary.Source, &summary.View, &totalDomains, &observations)
	if errors.Is(err, sql.ErrNoRows) {
		return SnapshotSummary{}, "", errNSPersistentNotFound
	}
	if err != nil {
		return SnapshotSummary{}, "", err
	}
	summary.Domains = int(totalDomains)
	summary.NSObservations = int(observations)
	return summary, summary.Source, nil
}

type nsEventFilter struct {
	Query    string
	Severity string
	Status   string
	Page     int
	Limit    int
}

func (s *nsPersistentStore) events(ctx context.Context, filter nsEventFilter) (nsEventsResponse, error) {
	where, args := buildNSEventWhere(filter)
	var total uint64
	// 事件页按“同域名、同等级、同摘要、同变化类型”合并。原始事件继续保留在
	// ns_change_events 和域名时间线中，页面只是在列表层面降噪。
	cluster := `SELECT domain, severity, summary, arraySort(change_types) AS normalized_change_types
		FROM ns_change_events FINAL ` + where + `
		GROUP BY domain, severity, summary, normalized_change_types`
	if err := s.db.QueryRowContext(ctx, "SELECT count() FROM ("+cluster+")", args...).Scan(&total); err != nil {
		return nsEventsResponse{}, err
	}
	query := `SELECT
		argMax(event_id, last_seen) AS event_id,
		domain,
		severity,
		argMax(evidence, last_seen) AS evidence,
		argMax(status, last_seen) AS status,
		summary,
		arraySort(change_types) AS normalized_change_types,
		min(first_seen) AS cluster_first_seen,
		max(last_seen) AS cluster_last_seen,
		argMax(resolved_at, last_seen) AS cluster_resolved_at,
		sum(occurrences) AS occurrences,
		count() AS merged_events
		FROM ns_change_events FINAL ` + where + `
		GROUP BY domain, severity, summary, normalized_change_types
		ORDER BY multiIf(severity = 'critical', 4, severity = 'high', 3, severity = 'medium', 2, 1) DESC, cluster_last_seen DESC
		LIMIT ? OFFSET ?`
	queryArgs := append(args, filter.Limit, (filter.Page-1)*filter.Limit)
	rows, err := s.db.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return nsEventsResponse{}, err
	}
	defer rows.Close()
	items := make([]nsEventSummary, 0)
	for rows.Next() {
		var event NSChangeEvent
		var resolvedAt sql.NullTime
		var occurrences, mergedEvents uint64
		if err := rows.Scan(&event.ID, &event.Domain, &event.Severity, &event.Evidence, &event.Status, &event.Summary, &event.ChangeTypes, &event.FirstSeen, &event.LastSeen, &resolvedAt, &occurrences, &mergedEvents); err != nil {
			return nsEventsResponse{}, err
		}
		event.Occurrences = int(occurrences)
		if resolvedAt.Valid {
			resolved := resolvedAt.Time
			event.ResolvedAt = &resolved
		}
		summary := summarizeNSEvent(event)
		summary.MergedEvents = int(mergedEvents)
		items = append(items, summary)
	}
	if err := rows.Err(); err != nil {
		return nsEventsResponse{}, err
	}
	return nsEventsResponse{Events: items, Total: int(total), Page: filter.Page, Limit: filter.Limit}, nil
}

func (s *nsPersistentStore) eventByID(ctx context.Context, eventID string) (NSChangeEvent, error) {
	var event NSChangeEvent
	var resolvedAt sql.NullTime
	var occurrences uint32
	var baselineRaw, currentRaw string
	err := s.db.QueryRowContext(ctx, `SELECT event_id, domain, severity, evidence, status, summary, change_types,
		first_seen, last_seen, resolved_at, occurrences, baseline_json, current_json, signature
		FROM ns_change_events FINAL WHERE event_id = ? LIMIT 1`, eventID).Scan(
		&event.ID, &event.Domain, &event.Severity, &event.Evidence, &event.Status, &event.Summary, &event.ChangeTypes,
		&event.FirstSeen, &event.LastSeen, &resolvedAt, &occurrences, &baselineRaw, &currentRaw, &event.signature,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return NSChangeEvent{}, errNSPersistentNotFound
	}
	if err != nil {
		return NSChangeEvent{}, err
	}
	event.Occurrences = int(occurrences)
	if resolvedAt.Valid {
		resolved := resolvedAt.Time
		event.ResolvedAt = &resolved
	}
	if err := json.Unmarshal([]byte(baselineRaw), &event.Baseline); err != nil {
		return NSChangeEvent{}, fmt.Errorf("解析事件 %s 的基线观测: %w", eventID, err)
	}
	if err := json.Unmarshal([]byte(currentRaw), &event.Current); err != nil {
		return NSChangeEvent{}, fmt.Errorf("解析事件 %s 的风险观测: %w", eventID, err)
	}
	return event, nil
}

func (s *nsPersistentStore) latestEventProbe(ctx context.Context, eventID string) (*NSProbeResult, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT result_json FROM ns_event_probes FINAL
		WHERE event_id = ? ORDER BY probed_at DESC LIMIT 1`, eventID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNSPersistentNotFound
	}
	if err != nil {
		return nil, err
	}
	var result NSProbeResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("解析事件 %s 的 NS 拨测结果: %w", eventID, err)
	}
	return &result, nil
}

func (s *nsPersistentStore) snapshotIDForEvent(ctx context.Context, event NSChangeEvent) (string, error) {
	var snapshotID string
	err := s.db.QueryRowContext(ctx, `SELECT snapshot_id FROM ns_domain_timeline FINAL
		WHERE domain = ? AND event_id = ? ORDER BY captured_at DESC, snapshot_id DESC LIMIT 1`, event.Domain, event.ID).Scan(&snapshotID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errNSPersistentNotFound
	}
	if err != nil {
		return "", err
	}
	return snapshotID, nil
}

func buildNSEventWhere(filter nsEventFilter) (string, []any) {
	clauses := make([]string, 0, 3)
	args := make([]any, 0, 4)
	if filter.Severity != "" {
		clauses = append(clauses, "severity = ?")
		args = append(args, filter.Severity)
	}
	if filter.Status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, filter.Status)
	}
	if query := strings.ToLower(strings.TrimSpace(filter.Query)); query != "" {
		clauses = append(clauses, "(lower(domain) LIKE ? OR lower(summary) LIKE ?)")
		pattern := "%" + query + "%"
		args = append(args, pattern, pattern)
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func (s *nsPersistentStore) domainDetail(ctx context.Context, domain string) (DomainNSDetail, error) {
	events, err := s.domainEvents(ctx, domain)
	if err != nil {
		return DomainNSDetail{}, err
	}
	current, currentErr := s.observation(ctx, `SELECT captured_at, fingerprint, nameservers_json FROM ns_domain_observations FINAL WHERE domain = ? ORDER BY captured_at DESC, snapshot_id DESC LIMIT 1`, domain, false)
	if errors.Is(currentErr, sql.ErrNoRows) && len(events) > 0 {
		// 兼容上线新表前写入的历史事件：即使当时没有写完整的逐快照观测，
		// 事件本身仍保存了风险时的 NS 端点，可用于只读追溯。
		current = events[len(events)-1].Current
		currentErr = nil
	}
	if errors.Is(currentErr, sql.ErrNoRows) {
		return DomainNSDetail{}, errNSPersistentNotFound
	}
	if currentErr != nil {
		return DomainNSDetail{}, currentErr
	}

	baseline, baselineErr := s.observation(ctx, `SELECT baseline.captured_at, baseline.fingerprint, baseline.observation_json
		FROM ns_domain_baseline AS baseline FINAL
		INNER JOIN ns_domain_baseline_state AS state FINAL ON baseline.domain = state.domain
		WHERE baseline.domain = ? AND state.confirmed = 1 LIMIT 1`, domain, true)
	baselineSource := "confirmed"
	if errors.Is(baselineErr, sql.ErrNoRows) {
		baseline, baselineSource, baselineErr = s.fallbackDomainBaseline(ctx, domain, events, current)
	}
	if baselineErr != nil {
		return DomainNSDetail{}, baselineErr
	}
	baseline.Domain = domain
	current.Domain = domain
	timeline, err := s.timeline(ctx, domain)
	if err != nil {
		return DomainNSDetail{}, err
	}
	return DomainNSDetail{Domain: domain, Baseline: baseline, BaselineSource: baselineSource, Current: current, Timeline: timeline, Events: events}, nil
}

// fallbackDomainBaseline 不把最新快照伪装成权威基线。优先使用历史风险事件中
// 固化的基线；没有时才展示正在积累的候选观察，最后才退化为“仅有当前观测”。
func (s *nsPersistentStore) fallbackDomainBaseline(ctx context.Context, domain string, events []NSChangeEvent, current DomainNSObservation) (DomainNSObservation, string, error) {
	for _, event := range events {
		if hasNSObservation(event.Baseline) {
			return event.Baseline, "event_history", nil
		}
	}
	candidate, err := s.observation(ctx, `SELECT candidate_last_seen, candidate_fingerprint, candidate_observation_json
		FROM ns_domain_baseline_state FINAL
		WHERE domain = ? AND candidate_fingerprint != '' AND consecutive_count > 0
		ORDER BY candidate_last_seen DESC LIMIT 1`, domain, true)
	if err == nil && hasNSObservation(candidate) {
		return candidate, "candidate", nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return DomainNSObservation{}, "", err
	}
	return current, "current_only", nil
}

func hasNSObservation(observation DomainNSObservation) bool {
	return !observation.CapturedAt.IsZero() || observation.Fingerprint != "" || len(observation.Nameservers) > 0
}

func (s *nsPersistentStore) observation(ctx context.Context, query, domain string, isFullObservation bool) (DomainNSObservation, error) {
	var observation DomainNSObservation
	var raw string
	if err := s.db.QueryRowContext(ctx, query, domain).Scan(&observation.CapturedAt, &observation.Fingerprint, &raw); err != nil {
		return DomainNSObservation{}, err
	}
	return decodeNSPersistentObservation(domain, observation.CapturedAt, observation.Fingerprint, raw, isFullObservation)
}

func decodeNSPersistentObservation(domain string, capturedAt time.Time, fingerprint, raw string, isFullObservation bool) (DomainNSObservation, error) {
	observation := DomainNSObservation{Domain: domain, CapturedAt: capturedAt, Fingerprint: fingerprint}
	if isFullObservation {
		if err := json.Unmarshal([]byte(raw), &observation); err != nil {
			return DomainNSObservation{}, fmt.Errorf("解析 %s 的持久化基线: %w", domain, err)
		}
		if observation.Domain == "" {
			observation.Domain = domain
		}
		return observation, nil
	}
	if err := json.Unmarshal([]byte(raw), &observation.Nameservers); err != nil {
		return DomainNSObservation{}, fmt.Errorf("解析 %s 的持久化 NS: %w", domain, err)
	}
	return observation, nil
}

func (s *nsPersistentStore) timeline(ctx context.Context, domain string) ([]NSTimelinePoint, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT snapshot_id, captured_at, ns_count, fingerprint, state, severity, event_id, summary
		FROM ns_domain_timeline FINAL WHERE domain = ? ORDER BY captured_at ASC, snapshot_id ASC`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	points := make([]NSTimelinePoint, 0)
	for rows.Next() {
		var point NSTimelinePoint
		var count uint16
		if err := rows.Scan(&point.SnapshotID, &point.CapturedAt, &count, &point.Fingerprint, &point.State, &point.Severity, &point.EventID, &point.Summary); err != nil {
			return nil, err
		}
		point.NSCount = int(count)
		points = append(points, point)
	}
	return points, rows.Err()
}

func (s *nsPersistentStore) domainEvents(ctx context.Context, domain string) ([]NSChangeEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT event_id, domain, severity, evidence, status, summary, change_types,
		first_seen, last_seen, resolved_at, occurrences, baseline_json, current_json, signature
		FROM ns_change_events FINAL WHERE domain = ?
		ORDER BY first_seen ASC, event_id ASC`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := make([]NSChangeEvent, 0)
	for rows.Next() {
		var event NSChangeEvent
		var resolvedAt sql.NullTime
		var occurrences uint32
		var baselineRaw, currentRaw string
		if err := rows.Scan(&event.ID, &event.Domain, &event.Severity, &event.Evidence, &event.Status, &event.Summary, &event.ChangeTypes,
			&event.FirstSeen, &event.LastSeen, &resolvedAt, &occurrences, &baselineRaw, &currentRaw, &event.signature); err != nil {
			return nil, err
		}
		event.Occurrences = int(occurrences)
		if resolvedAt.Valid {
			resolved := resolvedAt.Time
			event.ResolvedAt = &resolved
		}
		if err := json.Unmarshal([]byte(baselineRaw), &event.Baseline); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(currentRaw), &event.Current); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *nsPersistentStore) domains(ctx context.Context, query string, limit int) ([]string, error) {
	pattern := "%" + strings.ToLower(strings.TrimSpace(query)) + "%"
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT domain
		FROM (
			SELECT baseline.domain AS domain FROM ns_domain_baseline AS baseline FINAL
			INNER JOIN ns_domain_baseline_state AS state FINAL ON baseline.domain = state.domain
			WHERE state.confirmed = 1
			UNION ALL
			SELECT domain FROM ns_domain_observations FINAL
			UNION ALL
			SELECT domain FROM ns_change_events FINAL
			UNION ALL
			SELECT domain FROM ns_risk_events FINAL
		)
		WHERE lower(domain) LIKE ?
		ORDER BY domain ASC LIMIT ?`, pattern, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]string, 0)
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		items = append(items, domain)
	}
	return items, rows.Err()
}

func resolveRawDumpPath(directory, sourceName string) (string, error) {
	if strings.TrimSpace(directory) == "" {
		return "", os.ErrNotExist
	}
	cleanSource := filepath.Clean(strings.TrimSpace(sourceName))
	if cleanSource == "." || filepath.IsAbs(cleanSource) || cleanSource == ".." || strings.HasPrefix(cleanSource, ".."+string(filepath.Separator)) {
		return "", os.ErrNotExist
	}
	root, err := filepath.Abs(directory)
	if err != nil {
		return "", os.ErrNotExist
	}
	candidate := filepath.Join(root, cleanSource)
	relative, err := filepath.Rel(root, candidate)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", os.ErrNotExist
	}
	info, err := os.Stat(candidate)
	if err != nil || info.IsDir() {
		return "", os.ErrNotExist
	}
	return candidate, nil
}
