package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// NSImportReport 描述一次 NS 时序导入的实际写入量。
type NSImportReport struct {
	ImportedSnapshots  int
	SkippedSnapshots   int
	Observations       int
	TimelinePoints     int
	Events             int
	Probes             int
	AlertsSent         int
	AlertsFailed       int
	Baselines          int
	Campaigns          int
	ADBEndpointUpdates int
	Analysis           *NSAnalysis
}

// OpenNSClickHouseDatabase 确保 DSN 指向的数据库存在，再返回该数据库连接。
func OpenNSClickHouseDatabase(dsn string) (*sql.DB, error) {
	databaseName := getDatabaseName(dsn)
	if !isSafeClickHouseIdentifier(databaseName) {
		return nil, fmt.Errorf("不安全的 ClickHouse 数据库名 %q", databaseName)
	}

	adminDB, err := sql.Open("clickhouse", stripDatabaseName(dsn))
	if err != nil {
		return nil, fmt.Errorf("打开 ClickHouse 管理连接: %w", err)
	}
	defer adminDB.Close()
	if err := adminDB.Ping(); err != nil {
		return nil, fmt.Errorf("连接 ClickHouse: %w", err)
	}
	if _, err := adminDB.Exec("CREATE DATABASE IF NOT EXISTS `" + databaseName + "`"); err != nil {
		return nil, fmt.Errorf("创建数据库 %s: %w", databaseName, err)
	}

	db, err := sql.Open("clickhouse", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开业务数据库连接: %w", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("连接业务数据库 %s: %w", databaseName, err)
	}
	return db, nil
}

// OpenNSClickHouseReadDatabase 仅打开已存在的业务数据库，不执行建库或建表操作。
// 正式 Web 使用该连接，避免只读进程意外获得 DDL 行为。
func OpenNSClickHouseReadDatabase(dsn string) (*sql.DB, error) {
	db, err := sql.Open("clickhouse", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开 NS 时序只读数据库连接: %w", err)
	}
	db.SetMaxOpenConns(12)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("连接 NS 时序数据库: %w", err)
	}
	return db, nil
}

func isSafeClickHouseIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for i, ch := range value {
		if !(ch == '_' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || (i > 0 && ch >= '0' && ch <= '9')) {
			return false
		}
	}
	return true
}

// EnsureNSClickHouseSchema 创建独立于旧日粒度全量表的 NS 时序表。
// 所有时间使用 UTC，ReplacingMergeTree 允许同一快照安全重跑。
func EnsureNSClickHouseSchema(db *sql.DB) error {
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS ns_snapshot_catalog (
			snapshot_id String,
			captured_at DateTime64(3, 'UTC'),
			source_name String,
			view LowCardinality(String),
			total_domains UInt64,
			ns_observations UInt64,
			imported_at DateTime64(3, 'UTC') DEFAULT now64(3)
		) ENGINE = ReplacingMergeTree(imported_at)
		ORDER BY snapshot_id`,
		`CREATE TABLE IF NOT EXISTS ns_domain_observations (
			snapshot_id String,
			captured_at DateTime64(3, 'UTC'),
			domain String,
			ns_count UInt16,
			fingerprint String,
			nameservers_json String,
			imported_at DateTime64(3, 'UTC') DEFAULT now64(3)
		) ENGINE = ReplacingMergeTree(imported_at)
		PARTITION BY toYYYYMM(captured_at)
		ORDER BY (snapshot_id, domain)`,
		`CREATE TABLE IF NOT EXISTS ns_domain_timeline (
			snapshot_id String,
			captured_at DateTime64(3, 'UTC'),
			domain String,
			ns_count UInt16,
			fingerprint String,
			state LowCardinality(String),
			severity LowCardinality(String),
			event_id String,
			summary String,
			imported_at DateTime64(3, 'UTC') DEFAULT now64(3)
		) ENGINE = ReplacingMergeTree(imported_at)
		PARTITION BY toYYYYMM(captured_at)
		ORDER BY (domain, captured_at, snapshot_id)`,
		`CREATE TABLE IF NOT EXISTS ns_change_events (
			event_id String,
			domain String,
			severity LowCardinality(String),
			evidence LowCardinality(String),
			status LowCardinality(String),
			summary String,
			change_types Array(String),
			first_seen DateTime64(3, 'UTC'),
			last_seen DateTime64(3, 'UTC'),
			resolved_at Nullable(DateTime64(3, 'UTC')),
			occurrences UInt32,
			baseline_json String,
			current_json String,
			signature String,
			imported_at DateTime64(3, 'UTC') DEFAULT now64(3)
		) ENGINE = ReplacingMergeTree(imported_at)
		PARTITION BY toYYYYMM(first_seen)
		ORDER BY event_id`,
		`CREATE TABLE IF NOT EXISTS ns_domain_baseline (
			domain String,
			baseline_snapshot_id String,
			captured_at DateTime64(3, 'UTC'),
			fingerprint String,
			observation_json String,
			updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
		) ENGINE = ReplacingMergeTree(updated_at)
		ORDER BY domain`,
		`CREATE TABLE IF NOT EXISTS ns_domain_baseline_state (
			domain String,
			confirmed UInt8,
			candidate_fingerprint String,
			candidate_observation_json String,
			consecutive_count UInt16,
			candidate_first_seen Nullable(DateTime64(3, 'UTC')),
			candidate_last_seen Nullable(DateTime64(3, 'UTC')),
			updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
		) ENGINE = ReplacingMergeTree(updated_at)
		ORDER BY domain`,
		`CREATE TABLE IF NOT EXISTS ns_event_probes (
			event_id String,
			snapshot_id String,
			probed_at DateTime64(3, 'UTC'),
			verdict LowCardinality(String),
			summary String,
			result_json String,
			imported_at DateTime64(3, 'UTC') DEFAULT now64(3)
		) ENGINE = ReplacingMergeTree(imported_at)
		PARTITION BY toYYYYMM(probed_at)
		ORDER BY event_id`,
		`CREATE TABLE IF NOT EXISTS ns_alert_notifications (
			event_id String,
			alert_type LowCardinality(String),
			recipient String,
			status LowCardinality(String),
			attempted_at DateTime64(3, 'UTC'),
			message String,
			imported_at DateTime64(3, 'UTC') DEFAULT now64(3)
		) ENGINE = MergeTree
		PARTITION BY toYYYYMM(attempted_at)
		ORDER BY (event_id, alert_type, recipient, attempted_at)`,
		`CREATE TABLE IF NOT EXISTS ns_risk_events (
			event_id String,
			risk_type LowCardinality(String),
			domain String,
			severity LowCardinality(String),
			evidence LowCardinality(String),
			status LowCardinality(String),
			summary String,
			change_fields Array(String),
			first_seen DateTime64(3, 'UTC'),
			last_seen DateTime64(3, 'UTC'),
			resolved_at Nullable(DateTime64(3, 'UTC')),
			occurrences UInt32,
			snapshot_id String,
			current_json String,
			extra_json String,
			signature String,
			updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
		) ENGINE = ReplacingMergeTree(updated_at)
		PARTITION BY toYYYYMM(first_seen)
		ORDER BY event_id`,
		`CREATE TABLE IF NOT EXISTS ns_adb_endpoint_state (
			view LowCardinality(String),
			ns_name String,
			ip String,
			last_snapshot_id String,
			last_seen DateTime64(3, 'UTC'),
			srtt UInt32,
			flags String,
			edns_success UInt32,
			edns_timeout_4096 UInt32,
			edns_timeout_1432 UInt32,
			edns_timeout_1232 UInt32,
			edns_timeout_512 UInt32,
			plain_success UInt32,
			plain_timeout UInt32,
			udp_size UInt16,
			adb_ttl Int32,
			health LowCardinality(String),
			consecutive_suspect UInt16,
			detail String,
			updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
		) ENGINE = ReplacingMergeTree(updated_at)
		ORDER BY (view, ns_name, ip)`,
		`CREATE TABLE IF NOT EXISTS ns_adb_endpoint_history (
			snapshot_id String,
			captured_at DateTime64(3, 'UTC'),
			view LowCardinality(String),
			ns_name String,
			ip String,
			previous_health LowCardinality(String),
			health LowCardinality(String),
			consecutive_suspect UInt16,
			srtt UInt32,
			plain_success UInt32,
			plain_timeout UInt32,
			edns_success UInt32,
			edns_timeout UInt32,
			detail String
		) ENGINE = MergeTree
		PARTITION BY toYYYYMM(captured_at)
		ORDER BY (ns_name, ip, captured_at, snapshot_id)`,
		`CREATE TABLE IF NOT EXISTS ns_event_actions (
			event_id String,
			action LowCardinality(String),
			reason String,
			actor String,
			actor_role LowCardinality(String),
			acted_at DateTime64(3, 'UTC'),
			expires_at Nullable(DateTime64(3, 'UTC')),
			details_json String
		) ENGINE = MergeTree
		PARTITION BY toYYYYMM(acted_at)
		ORDER BY (event_id, acted_at)`,
		`CREATE TABLE IF NOT EXISTS dns_campaign_events (
			event_id String,
			campaign_type LowCardinality(String),
			target String,
			severity LowCardinality(String),
			evidence LowCardinality(String),
			status LowCardinality(String),
			previous_snapshot_id String,
			current_snapshot_id String,
			first_seen DateTime64(3, 'UTC'),
			last_seen DateTime64(3, 'UTC'),
			zone_count UInt32,
			ns_host_count UInt32,
			record_count UInt32,
			zones_json String,
			changes_json String DEFAULT '[]',
			summary String,
			signature String,
			updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
		) ENGINE = ReplacingMergeTree(updated_at)
		PARTITION BY toYYYYMM(first_seen)
		ORDER BY event_id`,
		`ALTER TABLE dns_campaign_events ADD COLUMN IF NOT EXISTS changes_json String DEFAULT '[]' AFTER zones_json`,
		`CREATE TABLE IF NOT EXISTS ns_campaign_holds (
			zone String,
			campaign_id String,
			target_fingerprint String,
			active UInt8,
			updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
		) ENGINE = ReplacingMergeTree(updated_at)
		ORDER BY (zone, campaign_id)`,
		`CREATE TABLE IF NOT EXISTS ns_audit_log (
			action LowCardinality(String),
			actor String,
			actor_role LowCardinality(String),
			target String,
			acted_at DateTime64(3, 'UTC'),
			details_json String
		) ENGINE = MergeTree
		PARTITION BY toYYYYMM(acted_at)
		ORDER BY (acted_at, actor, action)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			return fmt.Errorf("创建 NS 时序表: %w", err)
		}
	}
	return nil
}

// ImportNSSnapshots 导入高可信 NS 观测、基线和变更事件。
// 它刻意不把全量 RR 写入数据库，避免 10 分钟快照产生无边界的存储与小分区成本。
func ImportNSSnapshots(db *sql.DB, dsn string, files []string, geo IPMetadataProvider) (NSImportReport, error) {
	return ImportNSSnapshotsWithProbe(db, dsn, files, geo, nil)
}

// ImportNSSnapshotsWithProbe 在常规时序导入之外，针对本轮新增或更新的 NS
// 事件执行受限拨测。probe 为 nil 或 Disabled 时严格保持原有纯离线导入语义。
func ImportNSSnapshotsWithProbe(db *sql.DB, dsn string, files []string, geo IPMetadataProvider, probe *NSProbeConfig) (NSImportReport, error) {
	return ImportNSSnapshotsWithProbeAndAlerts(db, dsn, files, geo, probe, nil)
}

// ImportNSSnapshotsWithProbeAndAlerts 在处理新 dump 后按配置执行拨测和严重
// 线索告警。发送失败只记录失败状态，不回滚已安全写入的快照/事件数据。
func ImportNSSnapshotsWithProbeAndAlerts(db *sql.DB, dsn string, files []string, geo IPMetadataProvider, probe *NSProbeConfig, alerts *NSAlertConfig) (NSImportReport, error) {
	return importNSSnapshotsWithSourceLabels(db, dsn, files, geo, probe, alerts, nil)
}

// ImportNSSnapshotsWithSourceLabels 供递归目录监测器使用。labels 的键是实际
// 文件路径、值是 dump 根目录下的相对路径；它既用于 UI 回读，也参与快照 ID。
func ImportNSSnapshotsWithSourceLabels(db *sql.DB, dsn string, files []string, geo IPMetadataProvider, probe *NSProbeConfig, alerts *NSAlertConfig, labels map[string]string) (NSImportReport, error) {
	return importNSSnapshotsWithSourceLabels(db, dsn, files, geo, probe, alerts, labels)
}

func importNSSnapshotsWithSourceLabels(db *sql.DB, dsn string, files []string, geo IPMetadataProvider, probe *NSProbeConfig, alerts *NSAlertConfig, labels map[string]string) (NSImportReport, error) {
	startedAt := time.Now()
	probeEnabled := probe != nil && probe.Enabled
	fmt.Printf("NS 导入开始：文件 %d，自动拨测 %t\n", len(files), probeEnabled)
	if err := EnsureNSClickHouseSchema(db); err != nil {
		return NSImportReport{}, err
	}
	writer, err := openNSClickHouseWriter(dsn)
	if err != nil {
		return NSImportReport{}, err
	}
	defer writer.Close()
	backfilledCampaigns, err := backfillLatestNSCampaignsIfEmpty(db, writer, GlobalConfig.Campaign)
	if err != nil {
		return NSImportReport{}, fmt.Errorf("回灌最近真实快照的批量变化: %w", err)
	}
	if len(backfilledCampaigns) > 0 {
		fmt.Printf("批量变化升级回灌完成：最近两份真实 NS 快照命中 %d 个事件\n", len(backfilledCampaigns))
	}

	existingSnapshots, err := loadExistingNSSnapshotIDs(db)
	if err != nil {
		return NSImportReport{}, err
	}
	baselines, baselineStates, activeEvents, err := loadNSAnalysisState(db)
	if err != nil {
		return NSImportReport{}, err
	}
	baselineHolds, err := loadActiveCampaignHolds(db)
	if err != nil {
		return NSImportReport{}, fmt.Errorf("读取批量变化基线冻结: %w", err)
	}
	campaignTracker, err := newNSCampaignTracker(GlobalConfig.Campaign, GlobalConfig.DumpMonitor.LedgerPath)
	if err != nil {
		return NSImportReport{}, err
	}
	auxActiveEvents, err := loadActiveNSAuxRiskEvents(db)
	if err != nil {
		return NSImportReport{}, err
	}
	blacklist, err := LoadNSBlacklistDirectory(GlobalConfig.Blacklist, time.Now().UTC())
	if err != nil {
		return NSImportReport{}, fmt.Errorf("加载 NS 离线黑名单: %w", err)
	}
	whitelistCtx, whitelistCancel := context.WithTimeout(context.Background(), 10*time.Second)
	whitelistScopes, err := loadActiveNSWhitelistScopes(whitelistCtx, db)
	whitelistCancel()
	if err != nil {
		return NSImportReport{}, fmt.Errorf("加载事件白名单: %w", err)
	}
	auxTracker := newNSAuxRiskTracker(auxActiveEvents, blacklist, whitelistScopes)
	adbEndpointStates, err := loadNSADBEndpointStates(db)
	if err != nil {
		return NSImportReport{}, fmt.Errorf("读取 ADB 端点状态: %w", err)
	}

	report := NSImportReport{Campaigns: len(backfilledCampaigns)}
	analysis, err := analyzeNSFilesWithStateAndSourceLabelsWithHolds(files, geo, baselines, baselineStates, activeEvents, labels, baselineHolds, func(summary SnapshotSummary, observations map[string]DomainNSObservation, cache *BindCache) error {
		if campaignTracker != nil {
			campaignTracker.observe(summary, observations, cache)
		}
		if _, exists := existingSnapshots[summary.ID]; exists {
			fmt.Printf("NS 快照已存在，跳过写入：%s（%s）\n", summary.Source, summary.ID)
			report.SkippedSnapshots++
			return nil
		}
		writeStarted := time.Now()
		fmt.Printf("NS 快照写入开始：%s，NS 观测 %d\n", summary.Source, len(observations))
		adbUpdates, adbHistory, availabilityFindings := processNSADBEndpointHealth(summary, observations, cache.ADBRecords, adbEndpointStates)
		if err := insertNSADBEndpointStates(writer, adbUpdates); err != nil {
			return fmt.Errorf("写入 ADB 端点最新状态: %w", err)
		}
		if err := insertNSADBEndpointHistory(writer, adbHistory); err != nil {
			return fmt.Errorf("写入 ADB 端点变化历史: %w", err)
		}
		if err := insertNSSnapshot(writer, summary, observations); err != nil {
			return err
		}
		fmt.Printf("NS 快照写入完成：%s，ADB 状态更新 %d、变化 %d、可用性候选 %d，耗时 %s\n",
			summary.Source, len(adbUpdates), len(adbHistory), len(availabilityFindings), time.Since(writeStarted).Round(time.Millisecond))
		existingSnapshots[summary.ID] = struct{}{}
		auxTracker.apply(summary, observations, cache, availabilityFindings)
		report.ImportedSnapshots++
		report.Observations += len(observations)
		report.ADBEndpointUpdates += len(adbUpdates)
		return nil
	})
	if err != nil {
		return report, err
	}
	report.Analysis = analysis
	if campaignTracker != nil {
		if GlobalConfig.Campaign.HoldBaseline {
			applyCurrentCampaignHolds(analysis, baselines, campaignTracker.events)
		}
		if err := insertDNSCampaignEvents(writer, campaignTracker.events); err != nil {
			return report, fmt.Errorf("写入批量协同变化事件: %w", err)
		}
		if GlobalConfig.Campaign.HoldBaseline {
			if err := insertCampaignHolds(writer, campaignTracker.events); err != nil {
				return report, fmt.Errorf("写入批量变化基线冻结: %w", err)
			}
		}
		if err := saveCampaignSnapshotState(campaignTracker.path, campaignTracker.next); err != nil {
			return report, fmt.Errorf("保存批量变化相邻快照状态: %w", err)
		}
		report.Campaigns += len(campaignTracker.events)
	}
	if report.ImportedSnapshots == 0 {
		fmt.Printf("NS 导入完成：仅跳过已存在快照，耗时 %s\n", time.Since(startedAt).Round(time.Millisecond))
		return report, nil
	}

	eventsToWrite := changedNSEvents(analysis.Events, activeEvents)
	auxChangedEvents := auxTracker.changedEvents()
	fmt.Printf("NS 变更分析完成：新增/更新事件 %d，准备拨测 %t\n", len(eventsToWrite), probeEnabled)
	changeProbeConfig := probe
	reservedAvailabilityProbes := 0
	if probe != nil && probe.Enabled && hasNSAuxRiskType(auxChangedEvents, "ns_availability") {
		totalLimit := probe.MaxEventsPerImport
		if totalLimit <= 0 {
			totalLimit = DefaultNSProbeConfig().MaxEventsPerImport
		}
		if totalLimit == 1 {
			changeProbeConfig = nil
			reservedAvailabilityProbes = 1
		} else if totalLimit > 1 {
			copyConfig := *probe
			copyConfig.MaxEventsPerImport = totalLimit - 1
			changeProbeConfig = &copyConfig
			reservedAvailabilityProbes = 1
		}
	}
	probeResults, probeAttempts := probeNSChangeEventsWithAttempts(analysis, eventsToWrite, changeProbeConfig)
	var auxProbeResults []NSProbeResult
	if probe != nil && probe.Enabled {
		remaining := probe.MaxEventsPerImport
		if remaining <= 0 {
			remaining = DefaultNSProbeConfig().MaxEventsPerImport
		}
		remaining -= probeAttempts
		if remaining > 0 {
			availabilityEvents, otherAuxEvents := splitNSAuxRiskEvents(auxChangedEvents, "ns_availability")
			if reservedAvailabilityProbes > 0 && len(availabilityEvents) > 0 {
				availabilityProbeConfig := *probe
				availabilityProbeConfig.MaxEventsPerImport = 1
				availabilityResults := probeNSAuxRiskEvents(analysis, availabilityEvents, &availabilityProbeConfig)
				auxProbeResults = append(auxProbeResults, availabilityResults...)
				remaining--
			}
			if remaining > 0 {
				auxProbeConfig := *probe
				auxProbeConfig.MaxEventsPerImport = remaining
				auxProbeResults = append(auxProbeResults, probeNSAuxRiskEvents(analysis, otherAuxEvents, &auxProbeConfig)...)
			}
		} else if len(auxChangedEvents) > 0 {
			fmt.Printf("NS 辅助风险拨测跳过：本轮共享拨测限额已由 NS 变化事件用完（尝试 %d，成功 %d）\n", probeAttempts, len(probeResults))
		}
	}
	auxProbesByEvent := make(map[string]NSProbeResult, len(auxProbeResults))
	for _, result := range auxProbeResults {
		auxProbesByEvent[result.EventID] = result
	}
	for index := range auxChangedEvents {
		if result, ok := auxProbesByEvent[auxChangedEvents[index].ID]; ok {
			applyNSAuxProbeResult(&auxChangedEvents[index], result)
		}
	}
	allProbeResults := append(append([]NSProbeResult(nil), probeResults...), auxProbeResults...)
	if len(allProbeResults) > 0 {
		if err := insertNSProbeResults(writer, allProbeResults); err != nil {
			return report, err
		}
		report.Probes = len(allProbeResults)
	}

	points, err := insertNSTimeline(writer, analysis, existingSnapshots)
	if err != nil {
		return report, err
	}
	report.TimelinePoints = points
	events, err := insertNSEvents(writer, eventsToWrite)
	if err != nil {
		return report, err
	}
	report.Events = events
	auxEvents, err := insertNSAuxRiskEvents(writer, auxChangedEvents)
	if err != nil {
		return report, err
	}
	report.Events += auxEvents
	report.AlertsSent, report.AlertsFailed = dispatchNSAlerts(db, writer, filterWhitelistedNSChangeEvents(eventsToWrite, whitelistScopes), probeResults, alerts)
	auxAlertsSent, auxAlertsFailed := dispatchNSAlerts(db, writer, auxRiskEventsAsNSChange(alertableNSAuxRiskEvents(auxChangedEvents)), auxProbeResults, alerts)
	report.AlertsSent += auxAlertsSent
	report.AlertsFailed += auxAlertsFailed
	baselinesWritten, err := insertNSBaselines(writer, analysis)
	if err != nil {
		return report, err
	}
	if err := insertNSBaselineStates(writer, analysis); err != nil {
		return report, err
	}
	report.Baselines = baselinesWritten
	fmt.Printf("NS 导入完成：新增快照 %d，观测 %d，ADB 状态更新 %d，事件 %d，拨测 %d，基线 %d，总耗时 %s\n",
		report.ImportedSnapshots, report.Observations, report.ADBEndpointUpdates, report.Events, report.Probes, report.Baselines, time.Since(startedAt).Round(time.Millisecond))
	return report, nil
}

func hasNSAuxRiskType(events []NSAuxRiskEvent, riskType string) bool {
	for _, event := range events {
		if event.Type == riskType && event.Status != "resolved" {
			return true
		}
	}
	return false
}

func splitNSAuxRiskEvents(events []NSAuxRiskEvent, preferredType string) ([]NSAuxRiskEvent, []NSAuxRiskEvent) {
	preferred := make([]NSAuxRiskEvent, 0)
	other := make([]NSAuxRiskEvent, 0, len(events))
	for _, event := range events {
		if event.Type == preferredType {
			preferred = append(preferred, event)
		} else {
			other = append(other, event)
		}
	}
	return preferred, other
}

// probeNSChangeEvents 只处理本轮发生状态变化的未恢复事件。每个事件使用触发
// 风险状态的那份原始 dump，因而候选名称与告警证据始终来自同一时点。
func probeNSChangeEvents(analysis *NSAnalysis, events []NSChangeEvent, config *NSProbeConfig) []NSProbeResult {
	results, _ := probeNSChangeEventsWithAttempts(analysis, events, config)
	return results
}

func probeNSChangeEventsWithAttempts(analysis *NSAnalysis, events []NSChangeEvent, config *NSProbeConfig) ([]NSProbeResult, int) {
	if analysis == nil || config == nil || !config.Enabled || len(events) == 0 {
		return nil, 0
	}
	indices := make([]int, 0, len(events))
	for index := range events {
		if events[index].Status != "resolved" {
			indices = append(indices, index)
		}
	}
	sort.SliceStable(indices, func(i, j int) bool {
		left, right := events[indices[i]], events[indices[j]]
		if riskRank(left.Severity) == riskRank(right.Severity) {
			return left.FirstSeen.Before(right.FirstSeen)
		}
		return riskRank(left.Severity) > riskRank(right.Severity)
	})
	limit := config.MaxEventsPerImport
	if limit <= 0 {
		limit = DefaultNSProbeConfig().MaxEventsPerImport
	}
	if len(indices) > limit {
		fmt.Printf("NS 拨测限额：本轮待拨测事件 %d，仅执行最高优先级 %d 个，其余 %d 个保留事件并等待人工补测\n", len(indices), limit, len(indices)-limit)
	} else {
		fmt.Printf("NS 拨测计划：本轮待拨测事件 %d，限额 %d\n", len(indices), limit)
	}
	if len(indices) > limit {
		indices = indices[:limit]
	}
	results := make([]NSProbeResult, 0, len(indices))
	attempts := 0
	parsedCaches := make(map[string]*BindCache)
	for order, index := range indices {
		event := &events[index]
		attempts++
		eventStarted := time.Now()
		snapshotID, source, found := snapshotSourceForNSEvent(analysis, *event)
		if !found {
			fmt.Printf("NS 拨测跳过 %s：本轮分析中未找到风险快照原始文件\n", event.ID)
			continue
		}
		fmt.Printf("NS 拨测开始 %d/%d：事件 %s，域名 %s，等级 %s，来源 %s\n", order+1, len(indices), event.ID, event.Domain, event.Severity, filepath.Base(source))
		cache, cached := parsedCaches[source]
		if cached {
			fmt.Printf("NS 拨测复用已解析风险快照：事件 %s\n", event.ID)
		} else {
			parseStarted := time.Now()
			var err error
			cache, err = ParseDNSCacheFile(source)
			if err != nil {
				fmt.Printf("NS 拨测跳过 %s：解析风险快照失败: %v\n", event.ID, err)
				continue
			}
			parsedCaches[source] = cache
			fmt.Printf("NS 拨测快照解析完成：事件 %s，耗时 %s\n", event.ID, time.Since(parseStarted).Round(time.Millisecond))
		}
		// 除了每条 DNS 请求的超时，事件级总时限保证单个异常不会拖慢目录监测。
		eventTimeout := config.EventTimeout
		if eventTimeout <= 0 {
			eventTimeout = DefaultNSProbeConfig().EventTimeout
		}
		ctx, cancel := context.WithTimeout(context.Background(), eventTimeout)
		result, err := ProbeNSEvent(ctx, *event, snapshotID, cache, *config)
		cancel()
		if err != nil {
			fmt.Printf("NS 拨测失败：事件 %s，耗时 %s，错误 %v\n", event.ID, time.Since(eventStarted).Round(time.Millisecond), err)
			continue
		}
		fmt.Printf("NS 拨测完成：事件 %s，结论 %s，耗时 %s\n", event.ID, result.Verdict, time.Since(eventStarted).Round(time.Millisecond))
		results = append(results, result)
		if applyNSProbeResult(event, result) {
			updateNSTimelineForProbe(analysis, *event)
		}
	}
	return results, attempts
}

func probeNSAuxRiskEvents(analysis *NSAnalysis, events []NSAuxRiskEvent, config *NSProbeConfig) []NSProbeResult {
	if analysis == nil || config == nil || !config.Enabled || len(events) == 0 {
		return nil
	}
	candidates := make([]NSAuxRiskEvent, 0, len(events))
	for _, event := range events {
		if event.Status != "resolved" && event.Type != "ns_parent_child" {
			candidates = append(candidates, event)
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if riskRank(candidates[i].Severity) == riskRank(candidates[j].Severity) {
			return candidates[i].FirstSeen.Before(candidates[j].FirstSeen)
		}
		return riskRank(candidates[i].Severity) > riskRank(candidates[j].Severity)
	})
	limit := config.MaxEventsPerImport
	if limit <= 0 {
		limit = DefaultNSProbeConfig().MaxEventsPerImport
	}
	if len(candidates) > limit {
		fmt.Printf("NS 辅助风险拨测限额：待拨测 %d，仅执行最高优先级 %d 个\n", len(candidates), limit)
		candidates = candidates[:limit]
	}
	results := make([]NSProbeResult, 0, len(candidates))
	for index, event := range candidates {
		eventTimeout := config.EventTimeout
		if eventTimeout <= 0 {
			eventTimeout = DefaultNSProbeConfig().EventTimeout
		}
		fmt.Printf("NS 辅助风险拨测开始 %d/%d：事件 %s，类型 %s，域名 %s\n", index+1, len(candidates), event.ID, event.Type, event.Domain)
		ctx, cancel := context.WithTimeout(context.Background(), eventTimeout)
		result, err := ProbeNSAuxEvent(ctx, event, *config)
		cancel()
		if err != nil {
			fmt.Printf("NS 辅助风险拨测失败 %s: %v\n", event.ID, err)
			continue
		}
		fmt.Printf("NS 辅助风险拨测完成：事件 %s，结论 %s\n", event.ID, result.Verdict)
		results = append(results, result)
	}
	return results
}

func snapshotSourceForNSEvent(analysis *NSAnalysis, event NSChangeEvent) (string, string, bool) {
	for _, snapshot := range analysis.Snapshots {
		if snapshot.CapturedAt.Equal(event.Current.CapturedAt) {
			source, exists := analysis.snapshotSources[snapshot.ID]
			return snapshot.ID, source, exists
		}
	}
	return "", "", false
}

func updateNSTimelineForProbe(analysis *NSAnalysis, event NSChangeEvent) {
	for domain, points := range analysis.Timeline {
		for index := range points {
			if points[index].EventID != event.ID || points[index].State == "event_resolved" {
				continue
			}
			points[index].Severity = event.Severity
			points[index].Summary = event.Summary
		}
		analysis.Timeline[domain] = points
	}
}

// ProbePersistedNSEvent 用于对已有事件进行一次明确请求的补充拨测。常驻导入器
// 只处理新增/更新事件；这个入口让历史告警也可获得同一格式的证据，而不必伪造
// 或重复导入旧快照。
func ProbePersistedNSEvent(db *sql.DB, dsn, rawDumpDir, eventID string, config NSProbeConfig) (NSProbeResult, error) {
	if db == nil {
		return NSProbeResult{}, fmt.Errorf("NS 拨测缺少 ClickHouse 连接")
	}
	if !config.Enabled {
		return NSProbeResult{}, fmt.Errorf("NS 自动拨测已禁用")
	}
	if err := EnsureNSClickHouseSchema(db); err != nil {
		return NSProbeResult{}, err
	}
	store := &nsPersistentStore{db: db}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	eventID = strings.TrimSpace(eventID)
	event, err := store.eventByID(ctx, eventID)
	cancel()
	var auxEvent *NSAuxRiskEvent
	if errors.Is(err, errNSPersistentNotFound) {
		ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
		loaded, auxErr := store.auxEventByID(ctx, eventID)
		cancel()
		if auxErr != nil {
			return NSProbeResult{}, fmt.Errorf("读取风险事件: %w", auxErr)
		}
		auxEvent = &loaded
		event = auxRiskEventsAsNSChange([]NSAuxRiskEvent{loaded})[0]
	} else if err != nil {
		return NSProbeResult{}, fmt.Errorf("读取 NS 事件: %w", err)
	}
	if event.Status == "resolved" {
		return NSProbeResult{}, fmt.Errorf("NS 事件 %s 已恢复，不对历史恢复状态执行拨测", event.ID)
	}
	snapshotID := ""
	if auxEvent != nil {
		snapshotID = auxEvent.SnapshotID
	} else {
		ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
		snapshotID, err = store.snapshotIDForEvent(ctx, event)
		if err != nil {
			cancel()
			return NSProbeResult{}, fmt.Errorf("读取事件风险快照: %w", err)
		}
		cancel()
	}
	ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
	_, sourceName, err := store.snapshot(ctx, snapshotID)
	cancel()
	if err != nil {
		return NSProbeResult{}, fmt.Errorf("读取风险快照来源: %w", err)
	}
	var cache *BindCache
	if auxEvent == nil {
		source, resolveErr := resolveRawDumpPath(rawDumpDir, sourceName)
		if resolveErr != nil {
			return NSProbeResult{}, resolveErr
		}
		cache, err = ParseDNSCacheFile(source)
		if err != nil {
			return NSProbeResult{}, fmt.Errorf("解析风险快照 %s: %w", sourceName, err)
		}
	}
	eventTimeout := config.EventTimeout
	if eventTimeout <= 0 {
		eventTimeout = DefaultNSProbeConfig().EventTimeout
	}
	ctx, cancel = context.WithTimeout(context.Background(), eventTimeout)
	var result NSProbeResult
	if auxEvent != nil {
		result, err = ProbeNSAuxEvent(ctx, *auxEvent, config)
	} else {
		result, err = ProbeNSEvent(ctx, event, snapshotID, cache, config)
	}
	cancel()
	if err != nil {
		return NSProbeResult{}, err
	}
	writer, err := openNSClickHouseWriter(dsn)
	if err != nil {
		return NSProbeResult{}, err
	}
	defer writer.Close()
	if err := insertNSProbeResults(writer, []NSProbeResult{result}); err != nil {
		return NSProbeResult{}, err
	}
	if auxEvent != nil {
		if applyNSAuxProbeResult(auxEvent, result) {
			if _, err := insertNSAuxRiskEvents(writer, []NSAuxRiskEvent{*auxEvent}); err != nil {
				return NSProbeResult{}, err
			}
		}
	} else if applyNSProbeResult(&event, result) {
		if _, err := insertNSEvents(writer, []NSChangeEvent{event}); err != nil {
			return NSProbeResult{}, err
		}
	}
	return result, nil
}

// nsClickHouseWriter 使用 native 批处理协议：每个块只做一次协议往返，避免
// database/sql 多值 INSERT 在远程隧道上频繁等待服务端响应。
type nsClickHouseWriter struct {
	conn chdriver.Conn
}

func openNSClickHouseWriter(dsn string) (*nsClickHouseWriter, error) {
	options, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("解析 ClickHouse DSN: %w", err)
	}
	options.DialTimeout = 10 * time.Second
	options.ReadTimeout = 2 * time.Minute
	options.MaxOpenConns = 1
	options.MaxIdleConns = 1
	options.BlockBufferSize = 10
	// 大型 NS JSON 行会超过驱动默认 10 MiB 块缓冲。LZ4 使分块保持为有效的
	// Native 压缩数据帧，避免未压缩部分块被 ClickHouse 误判为独立协议包。
	options.Compression = &clickhouse.Compression{Method: clickhouse.CompressionLZ4}
	options.MaxCompressionBuffer = 4 << 20
	conn, err := clickhouse.Open(options)
	if err != nil {
		return nil, fmt.Errorf("打开 ClickHouse native 写入连接: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := conn.Ping(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("连接 ClickHouse native 写入端口: %w", err)
	}
	return &nsClickHouseWriter{conn: conn}, nil
}

func (w *nsClickHouseWriter) Close() error {
	if w == nil || w.conn == nil {
		return nil
	}
	return w.conn.Close()
}

func loadExistingNSSnapshotIDs(db *sql.DB) (map[string]struct{}, error) {
	rows, err := db.Query("SELECT snapshot_id FROM ns_snapshot_catalog FINAL")
	if err != nil {
		return nil, fmt.Errorf("读取已导入快照: %w", err)
	}
	defer rows.Close()
	result := make(map[string]struct{})
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		result[id] = struct{}{}
	}
	return result, rows.Err()
}

func loadNSAnalysisState(db *sql.DB) (map[string]DomainNSObservation, map[string]NSBaselineState, []NSChangeEvent, error) {
	baselines := make(map[string]DomainNSObservation)
	rows, err := db.Query("SELECT domain, observation_json FROM ns_domain_baseline FINAL")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("读取持久基线: %w", err)
	}
	for rows.Next() {
		var domain, raw string
		if err := rows.Scan(&domain, &raw); err != nil {
			_ = rows.Close()
			return nil, nil, nil, err
		}
		var observation DomainNSObservation
		if err := json.Unmarshal([]byte(raw), &observation); err != nil {
			_ = rows.Close()
			return nil, nil, nil, fmt.Errorf("解析基线 %s: %w", domain, err)
		}
		baselines[domain] = observation
	}
	if err := rows.Close(); err != nil {
		return nil, nil, nil, err
	}

	baselineStates := make(map[string]NSBaselineState)
	stateRows, err := db.Query(`SELECT domain, confirmed, candidate_fingerprint, candidate_observation_json,
		consecutive_count, candidate_first_seen, candidate_last_seen
		FROM ns_domain_baseline_state FINAL`)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("读取基线确认状态: %w", err)
	}
	for stateRows.Next() {
		var state NSBaselineState
		var confirmed uint8
		var candidateRaw string
		var firstSeen, lastSeen sql.NullTime
		if err := stateRows.Scan(&state.Domain, &confirmed, &state.CandidateFingerprint, &candidateRaw, &state.ConsecutiveCount, &firstSeen, &lastSeen); err != nil {
			_ = stateRows.Close()
			return nil, nil, nil, err
		}
		state.Confirmed = confirmed != 0
		if firstSeen.Valid {
			state.CandidateFirstSeen = firstSeen.Time
		}
		if lastSeen.Valid {
			state.CandidateLastSeen = lastSeen.Time
		}
		if candidateRaw != "" {
			if err := json.Unmarshal([]byte(candidateRaw), &state.Candidate); err != nil {
				_ = stateRows.Close()
				return nil, nil, nil, fmt.Errorf("解析候选基线 %s: %w", state.Domain, err)
			}
		}
		baselineStates[state.Domain] = state
	}
	if err := stateRows.Close(); err != nil {
		return nil, nil, nil, err
	}

	activeRows, err := db.Query(`SELECT event_id, domain, severity, evidence, status, summary, change_types,
		first_seen, last_seen, occurrences, baseline_json, current_json, signature
		FROM ns_change_events FINAL WHERE status != 'resolved'`)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("读取活跃 NS 事件: %w", err)
	}
	defer activeRows.Close()
	activeEvents := make([]NSChangeEvent, 0)
	for activeRows.Next() {
		var event NSChangeEvent
		var baselineRaw, currentRaw string
		if err := activeRows.Scan(&event.ID, &event.Domain, &event.Severity, &event.Evidence, &event.Status, &event.Summary, &event.ChangeTypes,
			&event.FirstSeen, &event.LastSeen, &event.Occurrences, &baselineRaw, &currentRaw, &event.signature); err != nil {
			return nil, nil, nil, err
		}
		if err := json.Unmarshal([]byte(baselineRaw), &event.Baseline); err != nil {
			return nil, nil, nil, fmt.Errorf("解析事件 %s 基线: %w", event.ID, err)
		}
		if err := json.Unmarshal([]byte(currentRaw), &event.Current); err != nil {
			return nil, nil, nil, fmt.Errorf("解析事件 %s 当前观测: %w", event.ID, err)
		}
		activeEvents = append(activeEvents, event)
	}
	return baselines, baselineStates, activeEvents, activeRows.Err()
}

func analyzeNSFilesWithState(files []string, geo IPMetadataProvider, baselines map[string]DomainNSObservation, activeEvents []NSChangeEvent, observer NSSnapshotObserver) (*NSAnalysis, error) {
	return analyzeNSFilesWithStateAndSourceLabels(files, geo, baselines, nil, activeEvents, nil, observer)
}

func analyzeNSFilesWithStateAndSourceLabels(files []string, geo IPMetadataProvider, baselines map[string]DomainNSObservation, baselineStates map[string]NSBaselineState, activeEvents []NSChangeEvent, labels map[string]string, observer NSSnapshotObserver) (*NSAnalysis, error) {
	return analyzeNSFilesWithStateAndSourceLabelsWithHolds(files, geo, baselines, baselineStates, activeEvents, labels, nil, observer)
}

func analyzeNSFilesWithStateAndSourceLabelsWithHolds(files []string, geo IPMetadataProvider, baselines map[string]DomainNSObservation, baselineStates map[string]NSBaselineState, activeEvents []NSChangeEvent, labels map[string]string, holds map[string]string, observer NSSnapshotObserver) (*NSAnalysis, error) {
	orderedFiles := append([]string(nil), files...)
	sortSnapshotFiles(orderedFiles)
	builder := newNSAnalysisBuilderWithState(geo, baselines, baselineStates, activeEvents)
	builder.setBaselineHolds(holds)
	for _, filename := range orderedFiles {
		fileStarted := time.Now()
		fmt.Printf("NS 快照解析开始：%s\n", filename)
		cache, err := ParseDNSCacheFile(filename)
		if err != nil {
			return nil, fmt.Errorf("解析快照 %s: %w", filename, err)
		}
		fmt.Printf("NS 快照解析完成：%s，缓存记录 %d，耗时 %s\n", filename, len(cache.records), time.Since(fileStarted).Round(time.Millisecond))
		snapshot := namedCacheSnapshot{Source: filename, CapturedAt: parseSnapshotTime(cache.Date, filename), Cache: cache}
		if label := strings.TrimSpace(labels[filename]); label != "" {
			label = filepath.ToSlash(filepath.Clean(label))
			// 顶层文件沿用历史 basename 快照 ID，避免首次升级目录监测器时
			// 将已入库存量重新写入；只有子目录来源才需要路径身份防碰撞。
			if strings.Contains(label, "/") {
				snapshot.Source = label
				snapshot.SourcePath = filename
				snapshot.Identity = "relative-source-v1:" + label
			}
		}
		summary, observations := builder.add(snapshot)
		fmt.Printf("NS 观测提取完成：%s，NS 观测 %d，累计耗时 %s\n", summary.Source, len(observations), time.Since(fileStarted).Round(time.Millisecond))
		if observer != nil {
			if err := observer(summary, observations, cache); err != nil {
				return nil, fmt.Errorf("处理快照 %s: %w", filename, err)
			}
		}
	}
	return builder.finish(), nil
}

func insertNSSnapshot(writer *nsClickHouseWriter, summary SnapshotSummary, observations map[string]DomainNSObservation) error {
	domains := make([]string, 0, len(observations))
	for domain := range observations {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	rows := make([][]any, 0, len(domains))
	for _, domain := range domains {
		observation := observations[domain]
		nameservers, err := json.Marshal(observation.Nameservers)
		if err != nil {
			return fmt.Errorf("序列化 %s 的 NS: %w", domain, err)
		}
		rows = append(rows, []any{summary.ID, summary.CapturedAt.UTC(), domain, uint16(len(observation.Nameservers)), observation.Fingerprint, string(nameservers)})
	}
	if err := writer.batchInsert("ns_domain_observations", []string{"snapshot_id", "captured_at", "domain", "ns_count", "fingerprint", "nameservers_json"}, rows, 2_000); err != nil {
		return err
	}
	// 目录表是快照的提交标识。只有所有观测成功写完，后续运行才会跳过该快照。
	return writer.batchInsert("ns_snapshot_catalog", []string{"snapshot_id", "captured_at", "source_name", "view", "total_domains", "ns_observations"}, [][]any{{summary.ID, summary.CapturedAt.UTC(), summary.Source, summary.View, uint64(summary.Domains), uint64(summary.NSObservations)}}, 1)
}

func insertNSTimeline(writer *nsClickHouseWriter, analysis *NSAnalysis, snapshotIDs map[string]struct{}) (int, error) {
	domains := make([]string, 0, len(analysis.Timeline))
	for domain := range analysis.Timeline {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	rows := make([][]any, 0)
	for _, domain := range domains {
		for _, point := range analysis.Timeline[domain] {
			if _, exists := snapshotIDs[point.SnapshotID]; !exists {
				continue
			}
			rows = append(rows, []any{point.SnapshotID, point.CapturedAt.UTC(), domain, uint16(point.NSCount), point.Fingerprint, point.State, point.Severity, point.EventID, point.Summary})
		}
	}
	if err := writer.batchInsert("ns_domain_timeline", []string{"snapshot_id", "captured_at", "domain", "ns_count", "fingerprint", "state", "severity", "event_id", "summary"}, rows, 2_000); err != nil {
		return 0, err
	}
	return len(rows), nil
}

func insertNSEvents(writer *nsClickHouseWriter, events []NSChangeEvent) (int, error) {
	rows := make([][]any, 0, len(events))
	for _, event := range events {
		baseline, err := json.Marshal(event.Baseline)
		if err != nil {
			return 0, err
		}
		current, err := json.Marshal(event.Current)
		if err != nil {
			return 0, err
		}
		var resolvedAt any
		if event.ResolvedAt != nil {
			resolvedAt = event.ResolvedAt.UTC()
		}
		rows = append(rows, []any{event.ID, event.Domain, event.Severity, event.Evidence, event.Status, event.Summary, event.ChangeTypes,
			event.FirstSeen.UTC(), event.LastSeen.UTC(), resolvedAt, uint32(event.Occurrences), string(baseline), string(current), event.signature})
	}
	if err := writer.batchInsert("ns_change_events", []string{"event_id", "domain", "severity", "evidence", "status", "summary", "change_types", "first_seen", "last_seen", "resolved_at", "occurrences", "baseline_json", "current_json", "signature"}, rows, 500); err != nil {
		return 0, err
	}
	return len(rows), nil
}

func insertNSProbeResults(writer *nsClickHouseWriter, results []NSProbeResult) error {
	rows := make([][]any, 0, len(results))
	for _, result := range results {
		raw, err := json.Marshal(result)
		if err != nil {
			return fmt.Errorf("序列化 NS 拨测 %s: %w", result.EventID, err)
		}
		rows = append(rows, []any{result.EventID, result.SnapshotID, result.ProbedAt.UTC(), result.Verdict, result.Summary, string(raw)})
	}
	return writer.batchInsert("ns_event_probes", []string{"event_id", "snapshot_id", "probed_at", "verdict", "summary", "result_json"}, rows, 200)
}

func insertNSAlertNotifications(writer *nsClickHouseWriter, notifications []nsAlertNotification) error {
	rows := make([][]any, 0, len(notifications))
	for _, notification := range notifications {
		rows = append(rows, []any{notification.EventID, notification.AlertType, notification.Recipient, notification.Status, notification.AttemptedAt.UTC(), notification.Message})
	}
	return writer.batchInsert("ns_alert_notifications", []string{"event_id", "alert_type", "recipient", "status", "attempted_at", "message"}, rows, 200)
}

func changedNSEvents(events, existing []NSChangeEvent) []NSChangeEvent {
	existingByID := make(map[string]NSChangeEvent, len(existing))
	for _, event := range existing {
		existingByID[event.ID] = event
	}
	changed := make([]NSChangeEvent, 0, len(events))
	for _, event := range events {
		previous, exists := existingByID[event.ID]
		if !exists || nsEventChanged(previous, event) {
			changed = append(changed, event)
		}
	}
	return changed
}

func nsEventChanged(previous, current NSChangeEvent) bool {
	if previous.Severity != current.Severity || previous.Evidence != current.Evidence || previous.Status != current.Status || previous.Summary != current.Summary || previous.Occurrences != current.Occurrences || !previous.FirstSeen.Equal(current.FirstSeen) || !previous.LastSeen.Equal(current.LastSeen) || previous.signature != current.signature || previous.Current.Fingerprint != current.Current.Fingerprint {
		return true
	}
	if (previous.ResolvedAt == nil) != (current.ResolvedAt == nil) {
		return true
	}
	return previous.ResolvedAt != nil && !previous.ResolvedAt.Equal(*current.ResolvedAt)
}

func insertNSBaselines(writer *nsClickHouseWriter, analysis *NSAnalysis) (int, error) {
	domains := make([]string, 0, len(analysis.baselineUpdates))
	for domain := range analysis.baselineUpdates {
		if _, exists := analysis.Baseline[domain]; exists {
			domains = append(domains, domain)
		}
	}
	sort.Strings(domains)
	baselineSnapshotByTime := make(map[time.Time]string)
	for _, snapshot := range analysis.Snapshots {
		baselineSnapshotByTime[snapshot.CapturedAt] = snapshot.ID
	}
	rows := make([][]any, 0, len(domains))
	for _, domain := range domains {
		baseline := analysis.Baseline[domain]
		raw, err := json.Marshal(baseline)
		if err != nil {
			return 0, err
		}
		rows = append(rows, []any{domain, baselineSnapshotByTime[baseline.CapturedAt], baseline.CapturedAt.UTC(), baseline.Fingerprint, string(raw)})
	}
	if err := writer.batchInsert("ns_domain_baseline", []string{"domain", "baseline_snapshot_id", "captured_at", "fingerprint", "observation_json"}, rows, 2_000); err != nil {
		return 0, err
	}
	return len(rows), nil
}

func insertNSBaselineStates(writer *nsClickHouseWriter, analysis *NSAnalysis) error {
	domains := make([]string, 0, len(analysis.baselineStateDirty))
	for domain := range analysis.baselineStateDirty {
		if _, exists := analysis.baselineStates[domain]; exists {
			domains = append(domains, domain)
		}
	}
	sort.Strings(domains)
	rows := make([][]any, 0, len(domains))
	for _, domain := range domains {
		state := analysis.baselineStates[domain]
		candidateRaw := ""
		if state.CandidateFingerprint != "" && state.ConsecutiveCount > 0 {
			raw, err := json.Marshal(state.Candidate)
			if err != nil {
				return fmt.Errorf("序列化候选基线 %s: %w", domain, err)
			}
			candidateRaw = string(raw)
		}
		var firstSeen, lastSeen any
		if !state.CandidateFirstSeen.IsZero() {
			firstSeen = state.CandidateFirstSeen.UTC()
		}
		if !state.CandidateLastSeen.IsZero() {
			lastSeen = state.CandidateLastSeen.UTC()
		}
		confirmed := uint8(0)
		if state.Confirmed {
			confirmed = 1
		}
		rows = append(rows, []any{domain, confirmed, state.CandidateFingerprint, candidateRaw, state.ConsecutiveCount, firstSeen, lastSeen})
	}
	return writer.batchInsert("ns_domain_baseline_state", []string{"domain", "confirmed", "candidate_fingerprint", "candidate_observation_json", "consecutive_count", "candidate_first_seen", "candidate_last_seen"}, rows, 2_000)
}

func (w *nsClickHouseWriter) batchInsert(table string, columns []string, rows [][]any, batchSize int) error {
	if len(rows) == 0 {
		return nil
	}
	if batchSize < 1 {
		batchSize = len(rows)
	}
	for start := 0; start < len(rows); start += batchSize {
		end := start + batchSize
		if end > len(rows) {
			end = len(rows)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		batch, err := w.conn.PrepareBatch(ctx, "INSERT INTO "+table+" ("+strings.Join(columns, ", ")+")")
		if err != nil {
			cancel()
			return fmt.Errorf("创建 %s 原生批写入: %w", table, err)
		}
		for index, row := range rows[start:end] {
			if len(row) != len(columns) {
				_ = batch.Close()
				cancel()
				return fmt.Errorf("表 %s 行列数不一致", table)
			}
			if err := batch.Append(row...); err != nil {
				_ = batch.Close()
				cancel()
				return fmt.Errorf("追加 %s 第 %d 行: %w", table, start+index+1, err)
			}
		}
		if err := batch.Send(); err != nil {
			_ = batch.Close()
			cancel()
			return fmt.Errorf("完成 %s 第 %d-%d 行批量写入: %w", table, start+1, end, err)
		}
		_ = batch.Close()
		cancel()
	}
	return nil
}
