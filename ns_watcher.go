package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// NSDumpWatcherOptions 描述 dump 目录导入器的边界。Directory 可以是保存全部
// 历史 dump 的大目录；监测器仅读取文件，绝不会复制、移动或删除源文件。
type NSDumpWatcherOptions struct {
	Directory    string
	LedgerPath   string
	PollInterval time.Duration
	StableFor    time.Duration
	Geo          IPMetadataProvider
	Probe        *NSProbeConfig
	Alerts       *NSAlertConfig
}

type nsDumpWatcher struct {
	db     *sql.DB
	dsn    string
	opts   NSDumpWatcherOptions
	ledger *nsDumpLedger
}

// dumpFileSignature 不读取文件内容，只依据写入过程中自然变化的长度与 mtime
// 判断是否稳定。路径使用监测根目录下的相对路径，以便账本可随部署保留。
type dumpFileSignature struct {
	Size            int64 `json:"size"`
	ModTimeUnixNano int64 `json:"mod_time_unix_nano"`
}

func (s dumpFileSignature) Equal(other dumpFileSignature) bool {
	return s.Size == other.Size && s.ModTimeUnixNano == other.ModTimeUnixNano
}

type dumpPendingEntry struct {
	Signature dumpFileSignature `json:"signature"`
	FirstSeen time.Time         `json:"first_seen"`
	LastSeen  time.Time         `json:"last_seen"`
}

// nsDumpLedger 是输入目录之外的本地耐久状态：Pending 记录正在确认稳定性的文件，
// Processed 记录已经成功处理（包括 ClickHouse 已存在、无需重复写入）的文件。
type nsDumpLedger struct {
	Version   int                          `json:"version"`
	Processed map[string]dumpFileSignature `json:"processed"`
	Pending   map[string]dumpPendingEntry  `json:"pending"`
	mu        sync.Mutex
	path      string
}

type dumpCandidate struct {
	Path      string
	Relative  string
	Signature dumpFileSignature
	ModTime   time.Time
}

func NewNSDumpWatcher(db *sql.DB, dsn string, options NSDumpWatcherOptions) (*nsDumpWatcher, error) {
	if db == nil {
		return nil, fmt.Errorf("NS dump 监测器缺少 ClickHouse 连接")
	}
	options.Directory = strings.TrimSpace(options.Directory)
	if options.Directory == "" {
		return nil, fmt.Errorf("NS dump 监测目录不能为空")
	}
	directory, err := filepath.Abs(options.Directory)
	if err != nil {
		return nil, fmt.Errorf("规范化 NS dump 目录: %w", err)
	}
	info, err := os.Stat(directory)
	if err != nil {
		return nil, fmt.Errorf("读取 NS dump 目录: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("NS dump 路径不是目录: %s", directory)
	}
	options.Directory = directory
	if options.PollInterval <= 0 {
		options.PollInterval = 30 * time.Second
	}
	if options.StableFor <= 0 {
		options.StableFor = 90 * time.Second
	}
	if strings.TrimSpace(options.LedgerPath) == "" {
		options.LedgerPath = filepath.Join(directory, ".ns-dump-ledger.json")
	}
	ledger, err := loadNSDumpLedger(options.LedgerPath)
	if err != nil {
		return nil, err
	}
	if err := bootstrapCampaignStateFromLedger(directory, ledger, options.LedgerPath, GlobalConfig.Campaign, options.Geo); err != nil {
		return nil, fmt.Errorf("初始化批量变化相邻快照状态: %w", err)
	}
	return &nsDumpWatcher{db: db, dsn: dsn, opts: options, ledger: ledger}, nil
}

// bootstrapCampaignStateFromLedger 让升级后的首个新 dump 能与升级前最后一个已处理
// dump 比较；只读取源文件并写本地压缩状态，不回写或移动历史 dump。
func bootstrapCampaignStateFromLedger(directory string, ledger *nsDumpLedger, ledgerPath string, config CampaignRuntimeConfig, geo IPMetadataProvider) error {
	tracker, err := newNSCampaignTracker(config, ledgerPath)
	if err != nil || tracker == nil || tracker.previous != nil {
		return err
	}
	candidates, err := findDumpFilesRecursively(directory)
	if err != nil {
		return err
	}
	processed := make([]dumpCandidate, 0)
	for _, candidate := range candidates {
		if signature, ok := ledger.Processed[candidate.Relative]; ok && signature.Equal(candidate.Signature) {
			processed = append(processed, candidate)
		}
	}
	if len(processed) == 0 {
		return nil
	}
	sort.Slice(processed, func(i, j int) bool { return processed[i].ModTime.Before(processed[j].ModTime) })
	latest := processed[len(processed)-1]
	cache, err := ParseDNSCacheFile(latest.Path)
	if err != nil {
		return fmt.Errorf("读取最后已处理 dump %s: %w", latest.Relative, err)
	}
	capturedAt := parseSnapshotTime(cache.Date, latest.Path)
	source := latest.Path
	identity := ""
	if strings.Contains(filepath.ToSlash(latest.Relative), "/") {
		source = filepath.ToSlash(latest.Relative)
		identity = "relative-source-v1:" + source
	}
	id := snapshotID(source, capturedAt)
	if identity != "" {
		id = shortHash(identity + "|" + capturedAt.UTC().Format(time.RFC3339Nano))
	}
	summary := SnapshotSummary{ID: id, Source: filepath.Base(source), View: cache.View, CapturedAt: capturedAt, Domains: len(cache.records)}
	observations := BuildNSObservations(cache, capturedAt, geo)
	summary.NSObservations = len(observations)
	state := buildCampaignSnapshotState(summary, observations, cache)
	if err := saveCampaignSnapshotState(tracker.path, state); err != nil {
		return err
	}
	fmt.Printf("批量变化检测已从最后处理快照恢复相邻状态：%s（%s）\n", latest.Relative, capturedAt.Format(time.RFC3339))
	return nil
}

func loadNSDumpLedger(path string) (*nsDumpLedger, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("NS dump 本地账本路径不能为空")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("规范化 NS dump 本地账本路径: %w", err)
	}
	ledger := &nsDumpLedger{Version: 1, Processed: make(map[string]dumpFileSignature), Pending: make(map[string]dumpPendingEntry), path: path}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return ledger, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读取 NS dump 本地账本: %w", err)
	}
	if err := json.Unmarshal(raw, ledger); err != nil {
		return nil, fmt.Errorf("解析 NS dump 本地账本 %s: %w", path, err)
	}
	if ledger.Version != 1 {
		return nil, fmt.Errorf("不支持的 NS dump 本地账本版本 %d", ledger.Version)
	}
	if ledger.Processed == nil {
		ledger.Processed = make(map[string]dumpFileSignature)
	}
	if ledger.Pending == nil {
		ledger.Pending = make(map[string]dumpPendingEntry)
	}
	ledger.path = path
	return ledger, nil
}

func (l *nsDumpLedger) saveLocked() error {
	if l == nil {
		return fmt.Errorf("NS dump 本地账本未初始化")
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o750); err != nil {
		return fmt.Errorf("创建 NS dump 本地账本目录: %w", err)
	}
	raw, err := json.MarshalIndent(struct {
		Version   int                          `json:"version"`
		Processed map[string]dumpFileSignature `json:"processed"`
		Pending   map[string]dumpPendingEntry  `json:"pending"`
	}{Version: l.Version, Processed: l.Processed, Pending: l.Pending}, "", "  ")
	if err != nil {
		return err
	}
	temporary := l.path + ".tmp"
	if err := os.WriteFile(temporary, raw, 0o600); err != nil {
		return fmt.Errorf("写入 NS dump 本地账本临时文件: %w", err)
	}
	if err := os.Rename(temporary, l.path); err != nil {
		return fmt.Errorf("提交 NS dump 本地账本: %w", err)
	}
	return nil
}

// Run 首次扫描全部存量文件，后续按固定周期递归扫描新文件。文件只有在连续两次
// 观察到完全相同的签名、且最后修改时间已跨过 StableFor 后才会进入解析流程。
func (w *nsDumpWatcher) Run(ctx context.Context) {
	w.scan()
	ticker := time.NewTicker(w.opts.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.scan()
		}
	}
}

func (w *nsDumpWatcher) scan() {
	now := time.Now().UTC()
	candidates, err := findDumpFilesRecursively(w.opts.Directory)
	if err != nil {
		fmt.Printf("NS dump 监测器扫描目录失败: %v\n", err)
		return
	}
	ready := w.ledger.stage(candidates, now, w.opts.StableFor)
	if len(ready) > 0 {
		fmt.Printf("NS dump 监测器本轮发现 %d 个稳定文件待处理\n", len(ready))
	}
	for index, candidate := range ready {
		startedAt := time.Now()
		fmt.Printf("NS dump 监测器开始处理 %d/%d：%s，大小 %.1f MiB，修改时间 %s\n",
			index+1, len(ready), candidate.Relative, float64(candidate.Signature.Size)/(1024*1024), candidate.ModTime.Format(time.RFC3339))
		report, err := ImportNSSnapshotsWithSourceLabels(w.db, w.dsn, []string{candidate.Path}, w.opts.Geo, w.opts.Probe, w.opts.Alerts, map[string]string{candidate.Path: candidate.Relative})
		if err != nil {
			fmt.Printf("NS dump 监测器导入 %s 失败，耗时 %s，下个周期重试: %v\n", candidate.Relative, time.Since(startedAt).Round(time.Millisecond), err)
			continue
		}
		if err := w.ledger.markProcessed(candidate); err != nil {
			// 数据已成功写入；此处不再重读源文件，只提示运维修复账本写入权限。
			fmt.Printf("NS dump %s 已导入，但写入本地账本失败: %v\n", candidate.Relative, err)
			continue
		}
		fmt.Printf("NS dump 监测器已处理 %s：新增快照 %d，跳过 %d，NS 观测 %d，时间线 %d，事件 %d，批量变化 %d，拨测 %d，告警 %d，总耗时 %s\n",
			candidate.Relative, report.ImportedSnapshots, report.SkippedSnapshots, report.Observations, report.TimelinePoints, report.Events, report.Campaigns, report.Probes, report.AlertsSent, time.Since(startedAt).Round(time.Millisecond))
	}
}

func (l *nsDumpLedger) stage(candidates []dumpCandidate, now time.Time, stableFor time.Duration) []dumpCandidate {
	l.mu.Lock()
	defer l.mu.Unlock()
	ready := make([]dumpCandidate, 0)
	changed := false
	for _, candidate := range candidates {
		if processed, exists := l.Processed[candidate.Relative]; exists {
			if !processed.Equal(candidate.Signature) {
				// 成功处理后的源文件应视为不可变。安全起见不自动读取被改写的
				// 同路径文件，避免同一快照被重新解释；需要人为改名后再导入。
				fmt.Printf("NS dump 监测器发现已处理文件被改写，保留原账本且不重读: %s\n", candidate.Relative)
			}
			continue
		}
		pending, exists := l.Pending[candidate.Relative]
		if !exists || !pending.Signature.Equal(candidate.Signature) {
			l.Pending[candidate.Relative] = dumpPendingEntry{Signature: candidate.Signature, FirstSeen: now, LastSeen: now}
			changed = true
			continue
		}
		pending.LastSeen = now
		l.Pending[candidate.Relative] = pending
		if now.Sub(candidate.ModTime) < stableFor || now.Sub(pending.FirstSeen) < stableFor {
			changed = true
			continue
		}
		ready = append(ready, candidate)
	}
	if changed {
		if err := l.saveLocked(); err != nil {
			fmt.Printf("NS dump 监测器保存稳定性账本失败: %v\n", err)
		}
	}
	return ready
}

func (l *nsDumpLedger) markProcessed(candidate dumpCandidate) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Processed[candidate.Relative] = candidate.Signature
	delete(l.Pending, candidate.Relative)
	return l.saveLocked()
}

// findDumpFilesRecursively 不依赖文件名时间戳，解析器会优先使用 dump 内 $DATE；
// 因此历史目录与新目录可采用相同扫描逻辑。隐藏目录不进入扫描。
func findDumpFilesRecursively(directory string) ([]dumpCandidate, error) {
	files := make([]dumpCandidate, 0)
	err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != directory && strings.HasPrefix(entry.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(entry.Name(), ".") || !strings.HasSuffix(strings.ToLower(entry.Name()), ".db") {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
			return nil
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		files = append(files, dumpCandidate{Path: path, Relative: filepath.Clean(relative), Signature: dumpFileSignature{Size: info.Size(), ModTimeUnixNano: info.ModTime().UnixNano()}, ModTime: info.ModTime().UTC()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Relative < files[j].Relative })
	return files, nil
}

// findStableDumpFiles 保留给历史调用和单元测试；常驻监测器使用更严格的双观察
// stage 机制，而不是仅依赖 mtime。
func findStableDumpFiles(directory string, now time.Time, stableFor time.Duration) ([]string, error) {
	candidates, err := findDumpFilesRecursively(directory)
	if err != nil {
		return nil, err
	}
	files := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if now.Sub(candidate.ModTime) >= stableFor {
			files = append(files, candidate.Path)
		}
	}
	sortSnapshotFiles(files)
	return files, nil
}
