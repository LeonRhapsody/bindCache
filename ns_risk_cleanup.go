package main

import (
	"database/sql"
	"fmt"
	"strings"
)

const obsoleteNSLocationRiskWhere = `risk_type = 'ns_single' AND
	(has(change_fields, '多 NS 位于同一 ASN') OR has(change_fields, '多 NS 位于同一国家/地区'))`

const retainedNSSingleRiskWhere = `(has(change_fields, '仅一个 NS 主机名') OR
	has(change_fields, '多 NS 指向同一 IP') OR has(change_fields, '多 NS 位于同一网段'))`

type nsRiskCleanupReport struct {
	DeletedPure int
	Migrated    int
}

type nsSingleHistoryCleanupReport struct {
	Events, Probes, Alerts, Actions, AuditLogs uint64
}

const nsSingleEventIDs = `(SELECT event_id FROM ns_risk_events FINAL WHERE risk_type = 'ns_single')`

func countNSSingleRiskHistory(db *sql.DB) (nsSingleHistoryCleanupReport, error) {
	var report nsSingleHistoryCleanupReport
	queries := []struct {
		name  string
		query string
		value *uint64
	}{
		{"事件", `SELECT count() FROM ns_risk_events FINAL WHERE risk_type = 'ns_single'`, &report.Events},
		{"拨测", `SELECT count() FROM ns_event_probes WHERE event_id IN ` + nsSingleEventIDs, &report.Probes},
		{"告警", `SELECT count() FROM ns_alert_notifications WHERE event_id IN ` + nsSingleEventIDs, &report.Alerts},
		{"处置", `SELECT count() FROM ns_event_actions WHERE event_id IN ` + nsSingleEventIDs, &report.Actions},
		{"审计", `SELECT count() FROM ns_audit_log WHERE target IN ` + nsSingleEventIDs, &report.AuditLogs},
	}
	for _, item := range queries {
		if err := db.QueryRow(item.query).Scan(item.value); err != nil {
			return report, fmt.Errorf("统计 NS 单一与冗余%s记录: %w", item.name, err)
		}
	}
	return report, nil
}

// cleanupNSSingleRiskHistory 删除 NS 单一与冗余事件及以 event_id 为外键的全部历史证据。
// 必须先删关联表，最后删事件表，否则 ID 子查询会在主事件删除后变空。
func cleanupNSSingleRiskHistory(db *sql.DB) (nsSingleHistoryCleanupReport, error) {
	report, err := countNSSingleRiskHistory(db)
	if err != nil {
		return report, err
	}
	mutations := []struct {
		name      string
		statement string
	}{
		{"拨测", `ALTER TABLE ns_event_probes DELETE WHERE event_id IN ` + nsSingleEventIDs + ` SETTINGS mutations_sync = 2`},
		{"告警", `ALTER TABLE ns_alert_notifications DELETE WHERE event_id IN ` + nsSingleEventIDs + ` SETTINGS mutations_sync = 2`},
		{"处置", `ALTER TABLE ns_event_actions DELETE WHERE event_id IN ` + nsSingleEventIDs + ` SETTINGS mutations_sync = 2`},
		{"审计", `ALTER TABLE ns_audit_log DELETE WHERE target IN ` + nsSingleEventIDs + ` SETTINGS mutations_sync = 2`},
		{"事件", `ALTER TABLE ns_risk_events DELETE WHERE risk_type = 'ns_single' SETTINGS mutations_sync = 2`},
	}
	for _, mutation := range mutations {
		if _, err := db.Exec(mutation.statement); err != nil {
			return report, fmt.Errorf("删除 NS 单一与冗余%s历史: %w", mutation.name, err)
		}
	}
	remaining, err := countNSSingleRiskHistory(db)
	if err != nil {
		return report, fmt.Errorf("复核 NS 单一与冗余历史: %w", err)
	}
	if remaining.Events+remaining.Probes+remaining.Alerts+remaining.Actions+remaining.AuditLogs != 0 {
		return report, fmt.Errorf("清理后仍有残留：%+v", remaining)
	}
	return report, nil
}

// cleanupObsoleteNSLocationRisks 删除只由同 ASN/同国家规则形成的事件，并将仍有
// 同 IP/同网段等有效原因的混合事件原地迁移到新签名。事件 ID、首次发现时间、
// 观测次数、验证状态与主动拨测证据均保留。
func cleanupObsoleteNSLocationRisks(db *sql.DB, dsn string) (nsRiskCleanupReport, error) {
	var report nsRiskCleanupReport
	var pure uint64
	if err := db.QueryRow(`SELECT count() FROM ns_risk_events FINAL WHERE ` + obsoleteNSLocationRiskWhere + ` AND NOT ` + retainedNSSingleRiskWhere).Scan(&pure); err != nil {
		return report, fmt.Errorf("统计纯旧规则事件: %w", err)
	}
	report.DeletedPure = int(pure)

	mixed, err := loadMixedNSLocationRiskEvents(db)
	if err != nil {
		return report, err
	}
	migrated := make([]NSAuxRiskEvent, 0, len(mixed))
	for _, event := range mixed {
		updated, ok := migrateNSLocationRiskEvent(event)
		if !ok {
			return report, fmt.Errorf("混合事件 %s 不再包含有效 NS 单点原因", event.ID)
		}
		migrated = append(migrated, updated)
	}

	// 当前数据中关联表均为 0；仍防御性清理由纯旧规则事件产生的关联数据。
	pureIDs := `(SELECT event_id FROM ns_risk_events FINAL WHERE ` + obsoleteNSLocationRiskWhere + ` AND NOT ` + retainedNSSingleRiskWhere + `)`
	for _, table := range []string{"ns_event_probes", "ns_alert_notifications", "ns_event_actions"} {
		var count uint64
		if err := db.QueryRow(fmt.Sprintf("SELECT count() FROM %s WHERE event_id IN %s", table, pureIDs)).Scan(&count); err != nil {
			return report, fmt.Errorf("统计 %s 纯旧规则关联数据: %w", table, err)
		}
		if count == 0 {
			continue
		}
		if _, err := db.Exec(fmt.Sprintf("ALTER TABLE %s DELETE WHERE event_id IN %s SETTINGS mutations_sync = 2", table, pureIDs)); err != nil {
			return report, fmt.Errorf("清理 %s 纯旧规则关联数据: %w", table, err)
		}
	}

	// 先写入不含旧原因的新版本，再同步删除所有仍带旧原因的物理版本。删除条件
	// 不匹配新版本，因此过程中 FINAL 始终至少可见一份有效混合事件。
	if len(migrated) > 0 {
		writer, err := openNSClickHouseWriter(dsn)
		if err != nil {
			return report, err
		}
		if _, err := insertNSAuxRiskEvents(writer, migrated); err != nil {
			_ = writer.Close()
			return report, fmt.Errorf("写入迁移后的 NS 单点事件: %w", err)
		}
		if err := writer.Close(); err != nil {
			return report, fmt.Errorf("关闭 NS 事件写入连接: %w", err)
		}
	}
	report.Migrated = len(migrated)
	if _, err := db.Exec(`ALTER TABLE ns_risk_events DELETE WHERE ` + obsoleteNSLocationRiskWhere + ` SETTINGS mutations_sync = 2`); err != nil {
		return report, fmt.Errorf("删除旧同 ASN/同国家事件版本: %w", err)
	}

	var obsolete uint64
	if err := db.QueryRow(`SELECT count() FROM ns_risk_events FINAL WHERE ` + obsoleteNSLocationRiskWhere).Scan(&obsolete); err != nil {
		return report, fmt.Errorf("复核旧规则事件: %w", err)
	}
	if obsolete != 0 {
		return report, fmt.Errorf("清理后仍存在 %d 个旧规则事件", obsolete)
	}
	return report, nil
}

func loadMixedNSLocationRiskEvents(db *sql.DB) ([]NSAuxRiskEvent, error) {
	rows, err := db.Query(`SELECT event_id, risk_type, domain, severity, evidence, status, summary, change_fields,
		first_seen, last_seen, resolved_at, occurrences, snapshot_id, current_json, extra_json, signature
		FROM ns_risk_events FINAL WHERE ` + obsoleteNSLocationRiskWhere + ` AND ` + retainedNSSingleRiskWhere + ` ORDER BY event_id`)
	if err != nil {
		return nil, fmt.Errorf("读取混合旧规则事件: %w", err)
	}
	defer rows.Close()
	result := make([]NSAuxRiskEvent, 0)
	for rows.Next() {
		event, err := scanNSAuxRiskEvent(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

func migrateNSLocationRiskEvent(event NSAuxRiskEvent) (NSAuxRiskEvent, bool) {
	finding, ok := detectNSRedundancyRisk(event.Domain, event.Current)
	if !ok {
		return NSAuxRiskEvent{}, false
	}
	preserved := map[string]any{}
	for _, key := range []string{"historyMaxNs", "activeProbeVerdict", "activeProbeSummary"} {
		if value, exists := event.Extra[key]; exists {
			preserved[key] = value
		}
	}
	event.Severity = finding.Severity
	event.Summary = finding.Summary
	event.ChangeFields = append([]string(nil), finding.ChangeFields...)
	event.Extra = finding.Extra
	for key, value := range preserved {
		event.Extra[key] = value
	}
	if event.Evidence == "verified" {
		if summary := stringValue(preserved["activeProbeSummary"]); summary != "" && !strings.Contains(event.Summary, summary) {
			event.Summary += "；" + summary
		}
	}
	event.Signature = finding.Signature
	return event, true
}
