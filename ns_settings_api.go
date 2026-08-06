package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type nsV1Settings struct {
	DumpMonitor NSDumpMonitorSettings `json:"dumpMonitor"`
	Probe       NSProbeSettings       `json:"probe"`
	Alerts      NSAlertSettings       `json:"alerts"`
	Blacklist   NSBlacklistSettings   `json:"blacklist"`
	Baseline    NSBaselineSettings    `json:"baseline"`
	Campaign    NSCampaignSettings    `json:"campaign"`
}

type NSDumpMonitorSettings struct {
	Directory       string `json:"directory"`
	PollInterval    string `json:"pollInterval"`
	StabilityWindow string `json:"stabilityWindow"`
}

type NSProbeSettings struct {
	Enabled            bool     `json:"enabled"`
	Backend            string   `json:"backend"`
	RecursiveResolver  string   `json:"recursiveResolver"`
	TrustedResolvers   []string `json:"trustedResolvers"`
	Timeout            string   `json:"timeout"`
	EventTimeout       string   `json:"eventTimeout"`
	MaxDomains         int      `json:"maxDomains"`
	MaxParallel        int      `json:"maxParallel"`
	MaxEventsPerImport int      `json:"maxEventsPerImport"`
}

type NSAlertSettings struct {
	Enabled       bool     `json:"enabled"`
	Severities    []string `json:"severities"`
	Recipients    []string `json:"recipients"`
	Cooldown      string   `json:"cooldown"`
	Timeout       string   `json:"timeout"`
	SubjectPrefix string   `json:"subjectPrefix"`
}

type NSBlacklistSettings struct {
	Directory    string `json:"directory"`
	MaxFileBytes int64  `json:"maxFileBytes"`
	MaxEntries   int    `json:"maxEntries"`
}

type NSBaselineSettings struct {
	ConsecutiveRequired int `json:"consecutiveRequired"`
}

type NSCampaignSettings struct {
	Enabled          bool   `json:"enabled"`
	MinDistinctZones int    `json:"minDistinctZones"`
	HoldBaseline     bool   `json:"holdBaseline"`
	MaxSnapshotGap   string `json:"maxSnapshotGap"`
}

func currentV1Settings() nsV1Settings {
	return nsV1Settings{
		DumpMonitor: NSDumpMonitorSettings{
			Directory: GlobalConfig.DumpMonitor.Directory, PollInterval: GlobalConfig.DumpMonitor.PollInterval,
			StabilityWindow: GlobalConfig.DumpMonitor.StabilityWindow,
		},
		Probe: NSProbeSettings{
			Enabled: GlobalConfig.Probe.Enabled, Backend: GlobalConfig.Probe.Backend,
			RecursiveResolver: GlobalConfig.Probe.RecursiveResolver, TrustedResolvers: append([]string(nil), GlobalConfig.Probe.TrustedResolvers...),
			Timeout: GlobalConfig.Probe.Timeout, EventTimeout: GlobalConfig.Probe.EventTimeout,
			MaxDomains: GlobalConfig.Probe.MaxDomains, MaxParallel: GlobalConfig.Probe.MaxParallel,
			MaxEventsPerImport: GlobalConfig.Probe.MaxEventsPerImport,
		},
		Alerts: NSAlertSettings{
			Enabled: GlobalConfig.Alerts.Enabled, Severities: append([]string(nil), GlobalConfig.Alerts.Severities...),
			Recipients: append([]string(nil), GlobalConfig.Alerts.Recipients...), Cooldown: GlobalConfig.Alerts.Cooldown,
			Timeout: GlobalConfig.Alerts.Timeout, SubjectPrefix: GlobalConfig.Alerts.SubjectPrefix,
		},
		Blacklist: NSBlacklistSettings{
			Directory: GlobalConfig.Blacklist.Directory, MaxFileBytes: GlobalConfig.Blacklist.MaxFileBytes,
			MaxEntries: GlobalConfig.Blacklist.MaxEntries,
		},
		Baseline: NSBaselineSettings{ConsecutiveRequired: int(NSBaselineConsecutiveRequired)},
		Campaign: NSCampaignSettings{Enabled: GlobalConfig.Campaign.Enabled, MinDistinctZones: GlobalConfig.Campaign.MinDistinctZones, HoldBaseline: GlobalConfig.Campaign.HoldBaseline, MaxSnapshotGap: GlobalConfig.Campaign.MaxSnapshotGap},
	}
}

func (s *nsMonitorServer) v1Settings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeNSJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "内存调试模式不支持配置写入"})
		return
	}
	writeNSJSON(w, http.StatusOK, currentV1Settings())
}

func (s *nsPersistentMonitorServer) v1Settings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeNSJSON(w, http.StatusOK, currentV1Settings())
		return
	}
	if r.Method != http.MethodPut {
		writeNSJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 GET、PUT"})
		return
	}
	user, ok := requireNSWriteRole(w, r, "admin")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	defer r.Body.Close()
	var settings nsV1Settings
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&settings); err != nil {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "无效配置: " + err.Error()})
		return
	}
	if err := ensureJSONEOF(decoder); err != nil {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := validateV1Settings(settings); err != nil {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	updated := GlobalConfig
	updated.DumpMonitor.Directory = strings.TrimSpace(settings.DumpMonitor.Directory)
	updated.DumpMonitor.PollInterval = settings.DumpMonitor.PollInterval
	updated.DumpMonitor.StabilityWindow = settings.DumpMonitor.StabilityWindow
	updated.Probe.Enabled = settings.Probe.Enabled
	updated.Probe.Backend = settings.Probe.Backend
	updated.Probe.RecursiveResolver = settings.Probe.RecursiveResolver
	updated.Probe.TrustedResolvers = uniqueSortedStrings(settings.Probe.TrustedResolvers)
	updated.Probe.Timeout = settings.Probe.Timeout
	updated.Probe.EventTimeout = settings.Probe.EventTimeout
	updated.Probe.MaxDomains = settings.Probe.MaxDomains
	updated.Probe.MaxParallel = settings.Probe.MaxParallel
	updated.Probe.MaxEventsPerImport = settings.Probe.MaxEventsPerImport
	updated.Alerts.Enabled = settings.Alerts.Enabled
	updated.Alerts.Severities = uniqueSortedStrings(settings.Alerts.Severities)
	updated.Alerts.Recipients = uniqueSortedStrings(settings.Alerts.Recipients)
	updated.Alerts.Cooldown = settings.Alerts.Cooldown
	updated.Alerts.Timeout = settings.Alerts.Timeout
	updated.Alerts.SubjectPrefix = strings.TrimSpace(settings.Alerts.SubjectPrefix)
	updated.Blacklist.Directory = strings.TrimSpace(settings.Blacklist.Directory)
	updated.Blacklist.MaxFileBytes = settings.Blacklist.MaxFileBytes
	updated.Blacklist.MaxEntries = settings.Blacklist.MaxEntries
	updated.Campaign.Enabled = settings.Campaign.Enabled
	updated.Campaign.MinDistinctZones = settings.Campaign.MinDistinctZones
	updated.Campaign.HoldBaseline = settings.Campaign.HoldBaseline
	updated.Campaign.MaxSnapshotGap = settings.Campaign.MaxSnapshotGap
	if err := writeAppConfigAtomically(GlobalConfigPath, updated); err != nil {
		nsPersistentError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nsWebQueryTimeout)
	defer cancel()
	details, _ := json.Marshal(settings)
	if _, err := s.store.db.ExecContext(ctx, `INSERT INTO ns_audit_log
		(action, actor, actor_role, target, acted_at, details_json) VALUES (?, ?, ?, ?, ?, ?)`,
		"settings_update", user.Username, user.Role, GlobalConfigPath, time.Now().UTC(), string(details)); err != nil {
		// 配置文件已完成原子替换，不能再向调用方谎报为“保存失败”，否则重试
		// 会造成二次覆盖。审计异常作为明确警告返回，并保留服务端日志供处置。
		fmt.Printf("NS 配置已保存但审计写入失败 %s: %v\n", GlobalConfigPath, err)
		writeNSJSON(w, http.StatusOK, map[string]any{
			"saved": true, "restartRequired": true, "path": GlobalConfigPath,
			"warning": "配置已保存，但审计日志写入失败；请立即检查 ClickHouse",
		})
		return
	}
	writeNSJSON(w, http.StatusOK, map[string]any{"saved": true, "restartRequired": true, "path": GlobalConfigPath})
}

func validateV1Settings(settings nsV1Settings) error {
	if strings.TrimSpace(settings.DumpMonitor.Directory) == "" {
		return fmt.Errorf("快照目录不能为空")
	}
	for name, value := range map[string]string{
		"dumpMonitor.pollInterval":    settings.DumpMonitor.PollInterval,
		"dumpMonitor.stabilityWindow": settings.DumpMonitor.StabilityWindow,
		"probe.timeout":               settings.Probe.Timeout,
		"probe.eventTimeout":          settings.Probe.EventTimeout,
		"alerts.cooldown":             settings.Alerts.Cooldown,
		"alerts.timeout":              settings.Alerts.Timeout,
		"campaign.maxSnapshotGap":     settings.Campaign.MaxSnapshotGap,
	} {
		if _, err := configDuration(value, time.Second); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if settings.Probe.Backend != "relay" && settings.Probe.Backend != "direct" {
		return fmt.Errorf("probe.backend 仅支持 relay 或 direct")
	}
	if settings.Probe.Enabled && len(uniqueSortedStrings(settings.Probe.TrustedResolvers)) < 2 {
		return fmt.Errorf("启用拨测时至少需要两个可信 DNS")
	}
	if settings.Probe.MaxDomains < 1 || settings.Probe.MaxParallel < 1 || settings.Probe.MaxEventsPerImport < 1 {
		return fmt.Errorf("拨测限额必须大于 0")
	}
	if settings.Alerts.Enabled && len(uniqueSortedStrings(settings.Alerts.Recipients)) == 0 {
		return fmt.Errorf("启用告警时接收人不能为空")
	}
	if settings.Blacklist.MaxFileBytes < 1 || settings.Blacklist.MaxEntries < 1 {
		return fmt.Errorf("黑名单文件和条目限制必须大于 0")
	}
	if settings.Campaign.MinDistinctZones < 2 {
		return fmt.Errorf("批量变化不同 zone 阈值至少为 2")
	}
	return nil
}

func writeAppConfigAtomically(path string, config AppConfig) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("配置文件路径为空")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	directory := filepath.Dir(absolute)
	temp, err := os.CreateTemp(directory, ".bind-cache-config-*.tmp")
	if err != nil {
		return fmt.Errorf("创建配置临时文件: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	encoder := json.NewEncoder(temp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, absolute); err != nil {
		return fmt.Errorf("原子替换配置文件: %w", err)
	}
	return nil
}

func (s *nsPersistentMonitorServer) v1Blacklists(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		v1BlacklistSources(w, r)
		return
	}
	if r.Method != http.MethodPost {
		writeNSJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 GET、POST"})
		return
	}
	user, ok := requireNSWriteRole(w, r, "operator")
	if !ok {
		return
	}
	directory := strings.TrimSpace(GlobalConfig.Blacklist.Directory)
	if directory == "" {
		writeNSJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "未配置 blacklist.directory"})
		return
	}
	filename := filepath.Base(strings.TrimSpace(r.Header.Get("X-Filename")))
	if filename == "." || filename == "" || strings.ToLower(filepath.Ext(filename)) != ".csv" {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "仅接受带 .csv 扩展名的 X-Filename"})
		return
	}
	if err := os.MkdirAll(directory, 0o750); err != nil {
		nsPersistentError(w, err)
		return
	}
	destination := filepath.Join(directory, filename)
	if _, err := os.Stat(destination); err == nil {
		writeNSJSON(w, http.StatusConflict, map[string]string{"error": "同名名单已存在；请使用新的版本文件名"})
		return
	} else if !os.IsNotExist(err) {
		nsPersistentError(w, err)
		return
	}
	temp, err := os.CreateTemp(directory, ".blacklist-upload-*.tmp")
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	maxBytes := GlobalConfig.Blacklist.MaxFileBytes
	if maxBytes <= 0 {
		maxBytes = 64 << 20
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	written, copyErr := io.Copy(temp, r.Body)
	if syncErr := temp.Sync(); copyErr == nil {
		copyErr = syncErr
	}
	if closeErr := temp.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "接收名单失败: " + copyErr.Error()})
		return
	}
	if written == 0 {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "名单文件为空"})
		return
	}
	info, err := os.Stat(tempPath)
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	source, entries, err := loadNSBlacklistCSV(tempPath, info.ModTime(), time.Now().UTC())
	if err != nil {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if GlobalConfig.Blacklist.MaxEntries > 0 && len(entries) > GlobalConfig.Blacklist.MaxEntries {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "名单条目超过配置上限"})
		return
	}
	if err := os.Chmod(tempPath, 0o640); err != nil {
		nsPersistentError(w, err)
		return
	}
	if err := os.Rename(tempPath, destination); err != nil {
		nsPersistentError(w, err)
		return
	}
	source.File = filename
	ctx, cancel := context.WithTimeout(r.Context(), nsWebQueryTimeout)
	defer cancel()
	details, _ := json.Marshal(source)
	if _, err := s.store.db.ExecContext(ctx, `INSERT INTO ns_audit_log
		(action, actor, actor_role, target, acted_at, details_json) VALUES (?, ?, ?, ?, ?, ?)`,
		"blacklist_import", user.Username, user.Role, destination, time.Now().UTC(), string(details)); err != nil {
		fmt.Printf("NS 黑名单已导入但审计写入失败 %s: %v\n", destination, err)
		writeNSJSON(w, http.StatusCreated, map[string]any{
			"source":  source,
			"warning": "名单已导入，但审计日志写入失败；请立即检查 ClickHouse",
		})
		return
	}
	writeNSJSON(w, http.StatusCreated, source)
}
