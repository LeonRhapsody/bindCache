package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
)

//go:embed frontend/dist/index.html frontend/dist/assets/*
var nsMonitorAssets embed.FS

var nsMonitorHTML = func() []byte {
	content, err := nsMonitorAssets.ReadFile("frontend/dist/index.html")
	if err != nil {
		panic(fmt.Sprintf("读取嵌入的 NS 前端首页: %v", err))
	}
	return content
}()

// StartNSMonitorServer 提供只读的内存 NS 变更调试台。
// 它刻意不初始化 ClickHouse；进程退出后，分析状态随之释放。
func StartNSMonitorServer(port string, analysis *NSAnalysis) error {
	if err := validateNSWebAuthConfig(GlobalConfig.Web); err != nil {
		return fmt.Errorf("Web 认证配置: %w", err)
	}
	server := &nsMonitorServer{analysis: analysis, recordCache: make(map[string]nsSnapshotRecordResponse)}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/ns/overview", server.overview)
	mux.HandleFunc("/api/ns/events", server.events)
	mux.HandleFunc("/api/ns/event-impact", server.eventImpact)
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
	mux.HandleFunc("/api/v1/blacklists", v1BlacklistSources)
	mux.HandleFunc("/api/v1/alerts", server.v1Alerts)
	mux.HandleFunc("/api/v1/alerts/retry", server.v1AlertRetry)
	mux.HandleFunc("/api/v1/probes", server.v1Probes)
	mux.HandleFunc("/api/v1/system", server.v1System)
	mux.HandleFunc("/api/v1/settings", server.v1Settings)
	mux.HandleFunc("/api/v1/audit", server.v1Audit)
	mux.HandleFunc("/api/v1/session", v1Session)
	mux.HandleFunc("/", server.index)

	address := ":" + port
	fmt.Printf("NS 内存监测台已启动: http://127.0.0.1:%s\n", port)
	return http.ListenAndServe(address, nsMonitorAuth(nsMonitorCORS(mux), GlobalConfig.Web))
}

type nsMonitorServer struct {
	analysis    *NSAnalysis
	recordMu    sync.RWMutex
	recordCache map[string]nsSnapshotRecordResponse
}

type nsOverviewResponse struct {
	Overview  NSOverview        `json:"overview"`
	Snapshots []SnapshotSummary `json:"snapshots"`
	Mode      string            `json:"mode"`
}

type nsEventSummary struct {
	ID          string   `json:"id"`
	Domain      string   `json:"domain"`
	Severity    string   `json:"severity"`
	Evidence    string   `json:"evidence"`
	Status      string   `json:"status"`
	Summary     string   `json:"summary"`
	ChangeTypes []string `json:"change_types"`
	FirstSeen   string   `json:"first_seen"`
	LastSeen    string   `json:"last_seen"`
	ResolvedAt  string   `json:"resolved_at,omitempty"`
	Occurrences int      `json:"occurrences"`
	// MergedEvents 是事件页中被归并到同一个风险簇的原始事件数。单域详情
	// 仍保留原始事件，便于从开始、持续到恢复逐条审计。
	MergedEvents int `json:"merged_events"`
}

type nsEventsResponse struct {
	Events []nsEventSummary `json:"events"`
	Total  int              `json:"total"`
	Page   int              `json:"page"`
	Limit  int              `json:"limit"`
}

// nsSnapshotRecordResponse 是按需展开的单域名完整缓存记录。
// NSObservation 包含 NS 主机的 A/AAAA、ASN 与国家；Groups 则包含被查询域名的
// 所有原始 RR 类型，NS 组始终排在首位。
type nsSnapshotRecordResponse struct {
	Snapshot      SnapshotSummary     `json:"snapshot"`
	Domain        string              `json:"domain"`
	RecordKind    string              `json:"record_kind"`
	NSObservation []NSHostObservation `json:"ns_observation"`
	Groups        []nsRRGroup         `json:"groups"`
}

type nsRRGroup struct {
	Type    string `json:"type"`
	Count   int    `json:"count"`
	Records any    `json:"records"`
}

func (s *nsMonitorServer) overview(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	writeNSJSON(w, http.StatusOK, nsOverviewResponse{Overview: s.analysis.Overview(), Snapshots: s.analysis.Snapshots, Mode: "memory"})
}

func (s *nsMonitorServer) events(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}

	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	severity := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("severity")))
	status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	page := parseNSPositiveInt(r.URL.Query().Get("page"), 1, 1, 1_000_000)
	limit := parseNSPositiveInt(r.URL.Query().Get("limit"), 50, 1, 100)

	filtered := make([]NSChangeEvent, 0)
	for _, event := range s.analysis.Events {
		if severity != "" && event.Severity != severity {
			continue
		}
		if status != "" && event.Status != status {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(event.Domain), query) && !strings.Contains(strings.ToLower(event.Summary), query) {
			continue
		}
		filtered = append(filtered, event)
	}

	start := (page - 1) * limit
	if start > len(filtered) {
		start = len(filtered)
	}
	end := start + limit
	if end > len(filtered) {
		end = len(filtered)
	}
	items := make([]nsEventSummary, 0, end-start)
	for _, event := range filtered[start:end] {
		items = append(items, summarizeNSEvent(event))
	}
	writeNSJSON(w, http.StatusOK, nsEventsResponse{Events: items, Total: len(filtered), Page: page, Limit: limit})
}

// eventImpact 按需重新解析风险状态所在的单个 dump，列出事件域的已缓存子域和
// CNAME 反向引用者。它不会常驻保存影响面索引，避免给每 10 分钟快照增加额外写入。
func (s *nsMonitorServer) eventImpact(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	eventID := strings.TrimSpace(r.URL.Query().Get("event_id"))
	if eventID == "" {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "event_id 参数不能为空"})
		return
	}

	var event NSChangeEvent
	found := false
	for _, candidate := range s.analysis.Events {
		if candidate.ID == eventID {
			event = candidate
			found = true
			break
		}
	}
	if !found {
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "NS 事件不存在"})
		return
	}

	var summary SnapshotSummary
	for _, candidate := range s.analysis.Snapshots {
		if candidate.CapturedAt.Equal(event.Current.CapturedAt) {
			summary = candidate
			break
		}
	}
	if summary.ID == "" {
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "风险状态对应的快照不在当前内存中"})
		return
	}
	source := s.analysis.snapshotSources[summary.ID]
	cache, err := ParseDNSCacheFile(source)
	if err != nil {
		writeNSJSON(w, http.StatusInternalServerError, map[string]string{"error": "读取风险状态快照失败"})
		return
	}
	writeNSJSON(w, http.StatusOK, buildNSEventImpact(event, summary.ID, cache))
}

func (s *nsMonitorServer) domain(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain == "" {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "domain 参数不能为空"})
		return
	}
	detail, ok := s.analysis.DomainDetail(domain)
	if !ok {
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "当前内存快照中未找到该域名"})
		return
	}
	writeNSJSON(w, http.StatusOK, detail)
}

// record 只在用户展开一个时间线节点时解析对应 dump，并缓存最多 64 份“快照+域名”响应。
// 这避免为前端详情把所有快照的全量 RR 常驻于内存。
func (s *nsMonitorServer) record(w http.ResponseWriter, r *http.Request) {
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

	source, knownSnapshot := s.analysis.snapshotSources[snapshotID]
	summary, knownSummary := s.analysis.snapshotIndex[snapshotID]
	if !knownSnapshot || !knownSummary {
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "快照 ID 不存在于当前内存分析"})
		return
	}
	cache, err := ParseDNSCacheFile(source)
	if err != nil {
		writeNSJSON(w, http.StatusInternalServerError, map[string]string{"error": "按需解析快照失败"})
		return
	}
	record, kind, found := findSnapshotDomainRecord(cache, domain)
	if !found {
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "该域名在所选快照中没有可展示的缓存记录"})
		return
	}

	nsObservation := BuildNSObservations(cache, summary.CapturedAt, nil)[domain]
	response := nsSnapshotRecordResponse{Snapshot: summary, Domain: domain, RecordKind: kind, NSObservation: nsObservation.Nameservers, Groups: buildNSRRGroups(record)}
	s.recordMu.Lock()
	if len(s.recordCache) < 64 {
		s.recordCache[cacheKey] = response
	}
	s.recordMu.Unlock()
	writeNSJSON(w, http.StatusOK, response)
}

func findSnapshotDomainRecord(cache *BindCache, domain string) (Record, string, bool) {
	if record, ok := cache.records[domain]; ok {
		return record, "positive", true
	}
	if record, ok := cache.nxdomainRecords[domain]; ok {
		return record, "nxdomain", true
	}
	if record, ok := cache.nxrrsetRecords[domain]; ok {
		return record, "nxrrset", true
	}
	return Record{}, "", false
}

func buildNSRRGroups(record Record) []nsRRGroup {
	groups := make([]nsRRGroup, 0, 20)
	appendGroup := func(recordType string, count int, records any) {
		if count > 0 {
			groups = append(groups, nsRRGroup{Type: recordType, Count: count, Records: records})
		}
	}
	appendGroup("NS", len(record.NSs), record.NSs)
	appendGroup("A", len(record.As), record.As)
	appendGroup("AAAA", len(record.AAAAs), record.AAAAs)
	appendGroup("CNAME", len(record.CNAMEs), record.CNAMEs)
	appendGroup("DNAME", len(record.DNAMEs), record.DNAMEs)
	appendGroup("MX", len(record.MXs), record.MXs)
	appendGroup("PTR", len(record.PTRs), record.PTRs)
	appendGroup("TXT", len(record.TXTs), record.TXTs)
	appendGroup("SRV", len(record.SRVs), record.SRVs)
	appendGroup("CAA", len(record.CAAs), record.CAAs)
	appendGroup("TLSA", len(record.TLSAs), record.TLSAs)
	appendGroup("NAPTR", len(record.NAPTRs), record.NAPTRs)
	appendGroup("SOA", len(record.SOAs), record.SOAs)
	appendGroup("RRSIG", len(record.RRSIGs), record.RRSIGs)
	appendGroup("DNSKEY", len(record.DNSKEYs), record.DNSKEYs)
	appendGroup("DS", len(record.DSs), record.DSs)
	appendGroup("NSEC", len(record.NSECs), record.NSECs)
	appendGroup("NSEC3", len(record.NSEC3s), record.NSEC3s)
	appendGroup("ANY", len(record.ANYs), record.ANYs)
	appendGroup("TYPE64", len(record.TYPE64), record.TYPE64)
	appendGroup("TYPE65", len(record.TYPE65), record.TYPE65)
	return groups
}

func (s *nsMonitorServer) domains(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit := parseNSPositiveInt(r.URL.Query().Get("limit"), 30, 1, 100)
	domains := make([]string, 0)
	for domain := range s.analysis.Current {
		if query == "" || strings.Contains(strings.ToLower(domain), query) {
			domains = append(domains, domain)
		}
	}
	sort.Strings(domains)
	if len(domains) > limit {
		domains = domains[:limit]
	}
	writeNSJSON(w, http.StatusOK, map[string]any{"domains": domains})
}

func (s *nsMonitorServer) index(w http.ResponseWriter, r *http.Request) {
	serveNSMonitorFrontend(w, r)
}

func summarizeNSEvent(event NSChangeEvent) nsEventSummary {
	summary := nsEventSummary{
		ID:           event.ID,
		Domain:       event.Domain,
		Severity:     event.Severity,
		Evidence:     event.Evidence,
		Status:       event.Status,
		Summary:      event.Summary,
		ChangeTypes:  event.ChangeTypes,
		FirstSeen:    event.FirstSeen.Format(timeLayoutForJSON),
		LastSeen:     event.LastSeen.Format(timeLayoutForJSON),
		Occurrences:  event.Occurrences,
		MergedEvents: 1,
	}
	if event.ResolvedAt != nil {
		summary.ResolvedAt = event.ResolvedAt.Format(timeLayoutForJSON)
	}
	return summary
}

// isNSMonitorRoute 让静态控制台支持浏览器历史记录和直接刷新。API 路径仍由
// 更精确的 HandleFunc 匹配，不会落到这里。
func isNSMonitorRoute(path string) bool {
	switch path {
	case "/", "/overview", "/events", "/domain", "/probe", "/alerts", "/system", "/settings",
		"/ns-change", "/ns-redundancy", "/ns-parent-child", "/ns-blacklist":
		return true
	default:
		return strings.HasPrefix(path, "/event/") || strings.HasPrefix(path, "/domain/")
	}
}

func serveNSMonitorFrontend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/assets/") {
		cleanPath := path.Clean(r.URL.Path)
		if !strings.HasPrefix(cleanPath, "/assets/") {
			http.NotFound(w, r)
			return
		}
		content, err := nsMonitorAssets.ReadFile("frontend/dist" + cleanPath)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if contentType := mime.TypeByExtension(path.Ext(cleanPath)); contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		if r.Method == http.MethodGet {
			_, _ = w.Write(content)
		}
		return
	}
	if !isNSMonitorRoute(r.URL.Path) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	if r.Method == http.MethodGet {
		_, _ = w.Write(nsMonitorHTML)
	}
}

const timeLayoutForJSON = "2006-01-02 15:04:05 MST"

func parseNSPositiveInt(raw string, fallback, minimum, maximum int) int {
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum {
		return fallback
	}
	if value > maximum {
		return maximum
	}
	return value
}

func requireNSMethod(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet {
		return true
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return false
	}
	writeNSJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 GET"})
	return false
}

func writeNSJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func nsMonitorCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		next.ServeHTTP(w, r)
	})
}
