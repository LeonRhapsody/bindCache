package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type nsV1AlertItem struct {
	Time    string `json:"time"`
	EventID string `json:"eventId"`
	Domain  string `json:"domain"`
	Level   string `json:"level"`
	Channel string `json:"channel"`
	Target  string `json:"target"`
	Status  string `json:"status"`
	Content string `json:"content"`
}

type nsV1ProbeItem struct {
	ID      string `json:"id"`
	EventID string `json:"eventId"`
	Target  string `json:"target"`
	Domain  string `json:"domain"`
	Time    string `json:"time"`
	Node    string `json:"node"`
	RTTMS   *int64 `json:"rtt"`
	Result  string `json:"result"`
	Detail  string `json:"detail"`
}

type nsV1SystemComponent struct {
	Name      string `json:"name"`
	Category  string `json:"category"`
	Status    string `json:"status"`
	Detail    string `json:"detail"`
	Impact    string `json:"impact,omitempty"`
	UpdatedAt string `json:"updatedAt"`
}

type nsV1SystemResponse struct {
	Components []nsV1SystemComponent `json:"components"`
	Snapshots  []SnapshotSummary     `json:"snapshots"`
}

type nsV1AuditItem struct {
	Time      string `json:"time"`
	Action    string `json:"action"`
	Actor     string `json:"actor"`
	ActorRole string `json:"actorRole"`
	Target    string `json:"target"`
	Details   string `json:"details"`
}

func (s *nsMonitorServer) v1Alerts(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	writeNSJSON(w, http.StatusOK, map[string]any{
		"items": []nsV1AlertItem{}, "total": 0, "mode": "memory", "policy": v1AlertPolicy(),
	})
}

func (s *nsMonitorServer) v1AlertRetry(w http.ResponseWriter, r *http.Request) {
	writeNSJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "内存调试模式不支持告警重试"})
}

func (s *nsPersistentMonitorServer) v1AlertRetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeNSJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 POST"})
		return
	}
	user, ok := requireNSWriteRole(w, r, "operator")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	defer r.Body.Close()
	var request struct {
		EventID   string `json:"eventId"`
		Recipient string `json:"recipient"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || ensureJSONEOF(decoder) != nil {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "请求必须包含 eventId 和 recipient"})
		return
	}
	request.EventID = strings.TrimSpace(request.EventID)
	request.Recipient = strings.TrimSpace(request.Recipient)
	if request.EventID == "" || request.Recipient == "" {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "eventId 和 recipient 不能为空"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	var latestStatus string
	err := s.store.db.QueryRowContext(ctx, `SELECT status FROM ns_alert_notifications
		WHERE event_id = ? AND recipient = ? ORDER BY attempted_at DESC LIMIT 1`,
		request.EventID, request.Recipient).Scan(&latestStatus)
	if err != nil {
		if err == sql.ErrNoRows {
			writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "未找到该事件与接收人的投递记录"})
		} else {
			nsPersistentError(w, err)
		}
		return
	}
	if latestStatus != "failed" {
		writeNSJSON(w, http.StatusConflict, map[string]string{"error": "仅允许重试最近一次状态为失败的投递"})
		return
	}
	relay, err := NewNSRelayClient(GlobalConfig.RelayClient)
	if err != nil {
		writeNSJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "relay 配置不可用: " + err.Error()})
		return
	}
	alerts, err := BuildNSAlertConfig(GlobalConfig.Alerts, relay)
	if err != nil || !alerts.Enabled || alerts.Sender == nil {
		message := "邮件告警未启用或配置不可用"
		if err != nil {
			message = err.Error()
		}
		writeNSJSON(w, http.StatusServiceUnavailable, map[string]string{"error": message})
		return
	}
	allowed := false
	for _, recipient := range alerts.Recipients {
		if recipient == request.Recipient {
			allowed = true
			break
		}
	}
	if !allowed {
		writeNSJSON(w, http.StatusForbidden, map[string]string{"error": "接收人已不在当前告警配置中"})
		return
	}
	event, err := s.store.eventByID(ctx, request.EventID)
	if errors.Is(err, errNSPersistentNotFound) {
		aux, auxErr := s.store.auxEventByID(ctx, request.EventID)
		if auxErr != nil {
			if errors.Is(auxErr, errNSPersistentNotFound) {
				writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "事件不存在或已超出保留周期"})
			} else {
				nsPersistentError(w, auxErr)
			}
			return
		}
		event = auxRiskEventsAsNSChange([]NSAuxRiskEvent{aux})[0]
	} else if err != nil {
		nsPersistentError(w, err)
		return
	}
	subject, text := buildNSAlertMessage(event, NSProbeResult{}, false, alerts.SubjectPrefix)
	sendCtx, sendCancel := context.WithTimeout(ctx, alerts.Timeout)
	accepted, sendErr := alerts.Sender.SendNSAlert(sendCtx, []string{request.Recipient}, subject, text)
	sendCancel()
	status, message := "sent", "relay accepted"
	if sendErr != nil || accepted != 1 {
		status = "failed"
		if sendErr != nil {
			message = sendErr.Error()
		} else {
			message = fmt.Sprintf("relay 接受收件人数量 %d，期望 1", accepted)
		}
	}
	attemptedAt := time.Now().UTC()
	if _, err := s.store.db.ExecContext(ctx, `INSERT INTO ns_alert_notifications
		(event_id, alert_type, recipient, status, attempted_at, message) VALUES (?, ?, ?, ?, ?, ?)`,
		event.ID, nsAlertClusterType(event), request.Recipient, status, attemptedAt, message); err != nil {
		nsPersistentError(w, err)
		return
	}
	details, _ := json.Marshal(map[string]any{"recipient": request.Recipient, "status": status})
	if _, err := s.store.db.ExecContext(ctx, `INSERT INTO ns_audit_log
		(action, actor, actor_role, target, acted_at, details_json) VALUES (?, ?, ?, ?, ?, ?)`,
		"alert_retry", user.Username, user.Role, event.ID, attemptedAt, string(details)); err != nil {
		fmt.Printf("NS 告警重试审计写入失败 %s: %v\n", event.ID, err)
	}
	code := http.StatusCreated
	if status == "failed" {
		code = http.StatusBadGateway
	}
	writeNSJSON(w, code, map[string]any{"eventId": event.ID, "recipient": request.Recipient, "status": status, "message": message})
}

func (s *nsMonitorServer) v1Audit(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	writeNSJSON(w, http.StatusOK, map[string]any{"items": []nsV1AuditItem{}, "total": 0, "mode": "memory"})
}

func (s *nsPersistentMonitorServer) v1Audit(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	limit := parseNSPositiveInt(r.URL.Query().Get("limit"), 100, 1, 500)
	ctx, cancel := context.WithTimeout(r.Context(), nsWebQueryTimeout)
	defer cancel()
	rows, err := s.store.db.QueryContext(ctx, `SELECT acted_at, action, actor, actor_role, target, details
		FROM (
			SELECT acted_at, action, actor, actor_role, target, details_json AS details
			FROM ns_audit_log
			UNION ALL
			SELECT acted_at, concat('event_', action) AS action, actor, actor_role, event_id AS target, reason AS details
			FROM ns_event_actions
		)
		ORDER BY acted_at DESC LIMIT ?`, limit)
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	defer rows.Close()
	items := make([]nsV1AuditItem, 0, limit)
	for rows.Next() {
		var actedAt time.Time
		var item nsV1AuditItem
		if err := rows.Scan(&actedAt, &item.Action, &item.Actor, &item.ActorRole, &item.Target, &item.Details); err != nil {
			nsPersistentError(w, err)
			return
		}
		item.Time = formatV1Time(actedAt)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		nsPersistentError(w, err)
		return
	}
	writeNSJSON(w, http.StatusOK, map[string]any{
		"items": items, "total": len(items), "mode": "clickhouse", "policy": v1AlertPolicy(),
	})
}

func v1AlertPolicy() map[string]any {
	return map[string]any{
		"enabled": GlobalConfig.Alerts.Enabled, "severities": GlobalConfig.Alerts.Severities,
		"recipients": GlobalConfig.Alerts.Recipients, "cooldown": GlobalConfig.Alerts.Cooldown,
		"subjectPrefix": GlobalConfig.Alerts.SubjectPrefix, "recoveryEnabled": true,
	}
}

func (s *nsPersistentMonitorServer) v1Alerts(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	limit := parseNSPositiveInt(r.URL.Query().Get("limit"), 100, 1, 500)
	ctx, cancel := context.WithTimeout(r.Context(), nsWebQueryTimeout)
	defer cancel()
	rows, err := s.store.db.QueryContext(ctx, `SELECT n.attempted_at, n.event_id, ifNull(e.domain, ''), ifNull(e.severity, 'unknown'),
		n.recipient, n.status, n.message
		FROM ns_alert_notifications AS n
		LEFT JOIN (
			SELECT event_id, domain, severity FROM ns_change_events FINAL
			UNION ALL
			SELECT event_id, domain, severity FROM ns_risk_events FINAL
		) AS e ON n.event_id = e.event_id
		ORDER BY n.attempted_at DESC LIMIT ?`, limit)
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	defer rows.Close()
	items := make([]nsV1AlertItem, 0)
	for rows.Next() {
		var attemptedAt time.Time
		var eventID, domain, level, recipient, status, message string
		if err := rows.Scan(&attemptedAt, &eventID, &domain, &level, &recipient, &status, &message); err != nil {
			nsPersistentError(w, err)
			return
		}
		displayStatus := "发送失败"
		if status == "sent" {
			displayStatus = "已送达"
		} else if status == "suppressed" {
			displayStatus = "已抑制(合并)"
		}
		items = append(items, nsV1AlertItem{
			Time: formatV1Time(attemptedAt), EventID: eventID, Domain: domain, Level: normalizeV1Level(level),
			Channel: "邮件", Target: recipient, Status: displayStatus, Content: message,
		})
	}
	if err := rows.Err(); err != nil {
		nsPersistentError(w, err)
		return
	}
	writeNSJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items), "mode": "clickhouse"})
}

func (s *nsMonitorServer) v1Probes(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	writeNSJSON(w, http.StatusOK, map[string]any{
		"items": []nsV1ProbeItem{}, "total": 0, "mode": "memory", "policy": v1ProbePolicy(),
	})
}

func (s *nsPersistentMonitorServer) v1Probes(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.v1ManualProbe(w, r)
		return
	}
	if !requireNSMethod(w, r) {
		return
	}
	limit := parseNSPositiveInt(r.URL.Query().Get("limit"), 100, 1, 500)
	ctx, cancel := context.WithTimeout(r.Context(), nsWebQueryTimeout)
	defer cancel()
	rows, err := s.store.db.QueryContext(ctx, `SELECT event_id, probed_at, result_json
		FROM ns_event_probes FINAL ORDER BY probed_at DESC LIMIT ?`, limit)
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	defer rows.Close()
	items := make([]nsV1ProbeItem, 0)
	for rows.Next() {
		var eventID, raw string
		var probedAt time.Time
		if err := rows.Scan(&eventID, &probedAt, &raw); err != nil {
			nsPersistentError(w, err)
			return
		}
		var result NSProbeResult
		if err := json.Unmarshal([]byte(raw), &result); err != nil {
			nsPersistentError(w, err)
			return
		}
		items = append(items, flattenV1ProbeResult(eventID, probedAt, result)...)
		if len(items) >= limit {
			items = items[:limit]
			break
		}
	}
	if err := rows.Err(); err != nil {
		nsPersistentError(w, err)
		return
	}
	writeNSJSON(w, http.StatusOK, map[string]any{
		"items": items, "total": len(items), "mode": "clickhouse", "policy": v1ProbePolicy(),
	})
}

func v1ProbePolicy() map[string]any {
	return map[string]any{
		"execution":          "同步限额执行，无常驻内存队列",
		"maxEventsPerImport": GlobalConfig.Probe.MaxEventsPerImport,
		"maxParallel":        GlobalConfig.Probe.MaxParallel,
		"eventTimeout":       GlobalConfig.Probe.EventTimeout,
		"backend":            GlobalConfig.Probe.Backend,
	}
}

func (s *nsPersistentMonitorServer) v1ManualProbe(w http.ResponseWriter, r *http.Request) {
	_, ok := requireNSWriteRole(w, r, "operator")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	defer r.Body.Close()
	var request struct {
		EventID string `json:"eventId"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || ensureJSONEOF(decoder) != nil {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "请求必须包含唯一的 eventId"})
		return
	}
	request.EventID = strings.TrimSpace(request.EventID)
	if request.EventID == "" {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "eventId 不能为空"})
		return
	}
	timeout, err := configDuration(GlobalConfig.Probe.Timeout, DefaultNSProbeConfig().Timeout)
	if err != nil {
		writeNSJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}
	probe, _, err := buildRuntimeNSControls(
		GlobalConfig.Probe.Enabled, GlobalConfig.Probe.Backend, GlobalConfig.Probe.RecursiveResolver,
		strings.Join(GlobalConfig.Probe.TrustedResolvers, ","), timeout,
		GlobalConfig.Probe.MaxDomains, GlobalConfig.Probe.MaxParallel, GlobalConfig.Probe.MaxEventsPerImport,
	)
	if err != nil {
		writeNSJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "拨测配置不可用: " + err.Error()})
		return
	}
	result, err := ProbePersistedNSEvent(s.store.db, GlobalConfig.ClickhouseDSN, s.rawDumpDir, request.EventID, *probe)
	if err != nil {
		writeNSJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeNSJSON(w, http.StatusCreated, result)
}

func flattenV1ProbeResult(eventID string, probedAt time.Time, result NSProbeResult) []nsV1ProbeItem {
	items := make([]nsV1ProbeItem, 0)
	for _, domain := range result.Domains {
		hosts := append(append([]NSProbeHostResult(nil), domain.StableNS...), domain.VariantNS...)
		for _, host := range hosts {
			item := nsV1ProbeItem{
				ID:      "PRB-" + shortHash(strings.Join([]string{eventID, domain.Domain, host.Host, probedAt.UTC().Format(time.RFC3339Nano)}, "\x00")),
				EventID: eventID, Target: host.Host, Domain: domain.Domain, Time: formatV1Time(probedAt),
				Node: "relay", Result: "超时", Detail: domain.Summary,
			}
			if host.Effective != nil {
				answer := host.Effective
				duration := answer.DurationMS
				item.RTTMS = &duration
				if answer.Error == "" {
					item.Result = "一致"
					if len(answer.NS) > 0 && domain.Verdict == "verified_ns_divergence" {
						item.Result = "集合A"
					}
					if host.MatchesStable != nil && !*host.MatchesStable {
						item.Result = "不一致"
					}
				}
				if answer.Error != "" {
					item.Detail = answer.Error
				}
			}
			items = append(items, item)
		}
		for _, answer := range domain.TrustedResolvers {
			item := probeAnswerToV1Item(eventID, domain.Domain, "可信 DNS", probedAt, answer)
			if answer.Error == "" && len(answer.NS) > 0 && domain.Verdict == "verified_ns_divergence" {
				item.Result = "集合B"
			}
			items = append(items, item)
		}
		if domain.RecursiveResult.Resolver != "" {
			item := probeAnswerToV1Item(eventID, domain.Domain, "受监控递归", probedAt, domain.RecursiveResult)
			if domain.RecursiveResult.Error == "" && domain.StableConsensus != nil &&
				!nsProbeAnswersEqual(domain.RecursiveResult, *domain.StableConsensus) {
				item.Result = "不一致"
				if domain.TrustedConsensus != nil && nsProbeAnswersEqual(domain.RecursiveResult, *domain.TrustedConsensus) {
					item.Result = "集合B"
				}
			}
			items = append(items, item)
		}
	}
	return items
}

func probeAnswerToV1Item(eventID, domain, node string, probedAt time.Time, answer DNSProbeAnswer) nsV1ProbeItem {
	duration := answer.DurationMS
	item := nsV1ProbeItem{
		ID: "PRB-" + shortHash(strings.Join([]string{
			eventID, domain, node, answer.Resolver, probedAt.UTC().Format(time.RFC3339Nano),
		}, "\x00")),
		EventID: eventID, Target: answer.Resolver, Domain: domain, Time: formatV1Time(probedAt),
		Node: node, RTTMS: &duration, Result: "一致", Detail: formatProbeAnswer(answer),
	}
	if answer.Error != "" {
		item.Result = "超时"
		item.Detail = answer.Error
	}
	return item
}

func (s *nsMonitorServer) v1System(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	now := formatV1Time(time.Now())
	writeNSJSON(w, http.StatusOK, nsV1SystemResponse{
		Components: []nsV1SystemComponent{{
			Name: "内存分析", Category: "数据链路", Status: "warning",
			Detail: "当前运行于无 ClickHouse 的内存调试模式", Impact: "进程退出后分析状态不会保留", UpdatedAt: now,
		}},
		Snapshots: s.analysis.Snapshots,
	})
}

func (s *nsPersistentMonitorServer) v1System(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nsWebQueryTimeout)
	defer cancel()
	now := time.Now().UTC()
	components := make([]nsV1SystemComponent, 0, 6)
	add := func(name, category, status, detail, impact string) {
		components = append(components, nsV1SystemComponent{Name: name, Category: category, Status: status, Detail: detail, Impact: impact, UpdatedAt: formatV1Time(now)})
	}
	if err := s.store.db.PingContext(ctx); err != nil {
		add("ClickHouse", "存储", "error", err.Error(), "所有持久化列表、趋势和证据查询不可用")
	} else {
		add("ClickHouse", "存储", "normal", "持久化查询连接正常", "")
	}
	snapshotLimit := parseNSPositiveInt(r.URL.Query().Get("snapshotLimit"), 100, 10, 500)
	snapshots, err := s.store.snapshots(ctx, snapshotLimit)
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	if len(snapshots) == 0 {
		add("数据导入", "数据链路", "error", "尚无已入库快照", "无法建立基线或发现风险事件")
	} else {
		latest := snapshots[len(snapshots)-1]
		delay := now.Sub(latest.CapturedAt.UTC()).Round(time.Minute)
		status := "normal"
		impact := ""
		if delay > 30*time.Minute {
			status, impact = "warning", "事件状态冻结在最后观测时刻，新的变化无法被发现"
		}
		add("数据导入", "数据链路", status, fmt.Sprintf("最新快照 %s，延迟 %s", latest.Source, delay), impact)
	}
	if info, err := os.Stat(GlobalConfig.GeoIP.Directory); err != nil || !info.IsDir() {
		add("GeoLite 离线库", "外部能力", "warning", "离线库目录不可用", "ASN 与国家/地区显示为未知，网络风险不升级")
	} else {
		_, _, asnErr := latestGeoLiteFiles(GlobalConfig.GeoIP.Directory, "GeoLite2-ASN-CSV_*", "GeoLite2-ASN-Blocks-IPv4.csv", "GeoLite2-ASN-Blocks-IPv6.csv")
		_, _, countryErr := latestGeoLiteFiles(GlobalConfig.GeoIP.Directory, "GeoLite2-Country-CSV_*", "GeoLite2-Country-Blocks-IPv4.csv", "GeoLite2-Country-Blocks-IPv6.csv")
		_, locationErr := latestGeoLiteFile(GlobalConfig.GeoIP.Directory, "GeoLite2-Country-CSV_*/GeoLite2-Country-Locations-en.csv")
		if asnErr != nil || countryErr != nil || locationErr != nil {
			add("GeoLite 离线库", "外部能力", "warning",
				fmt.Sprintf("目录可读但文件不完整：ASN=%v；Country=%v；Location=%v", asnErr, countryErr, locationErr),
				"ASN 与国家/地区显示为未知，网络风险不升级")
		} else {
			add("GeoLite 离线库", "外部能力", "normal", "ASN、Country 与 Location CSV 均已发现", "")
		}
	}
	if strings.TrimSpace(GlobalConfig.RelayClient.URL) == "" {
		add("relay 拨测服务", "外部能力", "warning", "未配置 relay_client.url", "主动拨测与邮件中继不可用")
	} else {
		relay, relayErr := NewNSRelayClient(GlobalConfig.RelayClient)
		if relayErr == nil {
			healthCtx, healthCancel := context.WithTimeout(r.Context(), 3*time.Second)
			relayErr = relay.Health(healthCtx)
			healthCancel()
		}
		if relayErr != nil {
			add("relay 拨测服务", "外部能力", "warning", relayErr.Error(), "主动拨测与邮件中继暂不可用，事件保留为待验证")
		} else {
			add("relay 拨测服务", "外部能力", "normal", "relay 健康检查通过", "")
		}
	}
	if _, err := LoadNSBlacklistDirectory(GlobalConfig.Blacklist, now); err != nil {
		add("离线黑名单", "外部能力", "warning", err.Error(), "黑名单匹配暂停")
	} else {
		add("离线黑名单", "外部能力", "normal", "离线名单目录校验通过", "")
	}
	if GlobalConfig.Alerts.Enabled {
		add("邮件告警", "通知", "normal", fmt.Sprintf("已启用，接收人 %d 个", len(GlobalConfig.Alerts.Recipients)), "投递状态以告警中心记录为准")
	} else {
		add("邮件告警", "通知", "warning", "告警发送未启用", "严重事件只入库不发送邮件")
	}
	writeNSJSON(w, http.StatusOK, nsV1SystemResponse{Components: components, Snapshots: snapshots})
}
