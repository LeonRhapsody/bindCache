package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFindStableDumpFilesIgnoresPartialAndNonDumpFiles(t *testing.T) {
	directory := t.TempDir()
	stable := filepath.Join(directory, "cache_dump_2026-07-28_12-00-01.db")
	partial := filepath.Join(directory, "cache_dump_2026-07-28_12-10-01.db")
	other := filepath.Join(directory, "notes.txt")
	for _, filename := range []string{stable, partial, other} {
		if err := os.WriteFile(filename, []byte("dump"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 7, 28, 12, 12, 0, 0, time.UTC)
	if err := os.Chtimes(stable, now.Add(-2*time.Minute), now.Add(-2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(partial, now.Add(-10*time.Second), now.Add(-10*time.Second)); err != nil {
		t.Fatal(err)
	}

	files, err := findStableDumpFiles(directory, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0] != stable {
		t.Fatalf("stable dump files = %#v, want [%s]", files, stable)
	}
}

func TestResolveRawDumpPathRejectsTraversal(t *testing.T) {
	directory := t.TempDir()
	filename := "cache_dump_2026-07-28_12-00-01.db"
	path := filepath.Join(directory, filename)
	if err := os.WriteFile(path, []byte("dump"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveRawDumpPath(directory, filename)
	if err != nil || resolved != path {
		t.Fatalf("resolve path = %q, %v; want %q, nil", resolved, err, path)
	}
	if _, err := resolveRawDumpPath(directory, "../outside.db"); err == nil {
		t.Fatal("path traversal source name must be rejected")
	}
	nestedDirectory := filepath.Join(directory, "2026", "07")
	if err := os.MkdirAll(nestedDirectory, 0o750); err != nil {
		t.Fatal(err)
	}
	nestedPath := filepath.Join(nestedDirectory, filename)
	if err := os.WriteFile(nestedPath, []byte("dump"), 0o600); err != nil {
		t.Fatal(err)
	}
	nestedResolved, err := resolveRawDumpPath(directory, filepath.Join("2026", "07", filename))
	if err != nil || nestedResolved != nestedPath {
		t.Fatalf("nested raw dump path = %q, %v; want %q", nestedResolved, err, nestedPath)
	}
}

func TestNSDumpLedgerRequiresTwoStableObservationsAndPersistsProcessed(t *testing.T) {
	directory := t.TempDir()
	nested := filepath.Join(directory, "2026", "07")
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(nested, "cache_dump_2026-07-28_12-00-01.db")
	if err := os.WriteFile(filename, []byte("stable dump"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 7, 28, 12, 10, 0, 0, time.UTC)
	if err := os.Chtimes(filename, base.Add(-5*time.Minute), base.Add(-5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	candidates, err := findDumpFilesRecursively(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].Relative != filepath.Join("2026", "07", filepath.Base(filename)) {
		t.Fatalf("递归候选文件 = %#v", candidates)
	}
	ledgerPath := filepath.Join(t.TempDir(), "state", "ledger.json")
	ledger, err := loadNSDumpLedger(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	if ready := ledger.stage(candidates, base, time.Minute); len(ready) != 0 {
		t.Fatalf("首次发现不应直接处理: %#v", ready)
	}
	if ready := ledger.stage(candidates, base.Add(30*time.Second), time.Minute); len(ready) != 0 {
		t.Fatalf("稳定窗口未到不应处理: %#v", ready)
	}
	ready := ledger.stage(candidates, base.Add(time.Minute), time.Minute)
	if len(ready) != 1 || ready[0].Path != filename {
		t.Fatalf("稳定两轮后应处理该文件: %#v", ready)
	}
	if err := ledger.markProcessed(ready[0]); err != nil {
		t.Fatal(err)
	}
	reloaded, err := loadNSDumpLedger(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := reloaded.Processed[ready[0].Relative]; !exists {
		t.Fatal("本地账本未持久化已处理文件")
	}
	if ready := reloaded.stage(candidates, base.Add(2*time.Minute), time.Minute); len(ready) != 0 {
		t.Fatalf("已处理文件不能重复入队: %#v", ready)
	}
}

func TestNestedDumpSourceIdentityAvoidsSameBasenameCollision(t *testing.T) {
	capturedAt := time.Date(2026, 7, 28, 12, 0, 1, 0, time.UTC)
	cache := newNSCache(map[string][]string{"example.test.": {"ns1.example.net."}}, map[string]string{"ns1.example.net.": "192.0.2.1"})
	analysis := AnalyzeNSCaches([]namedCacheSnapshot{
		{Source: filepath.Join("a", "cache_dump.db"), SourcePath: "/data/a/cache_dump.db", Identity: "relative-source-v1:a/cache_dump.db", CapturedAt: capturedAt, Cache: cache},
		{Source: filepath.Join("b", "cache_dump.db"), SourcePath: "/data/b/cache_dump.db", Identity: "relative-source-v1:b/cache_dump.db", CapturedAt: capturedAt, Cache: cache},
	}, nil)
	if len(analysis.Snapshots) != 2 || analysis.Snapshots[0].ID == analysis.Snapshots[1].ID || analysis.Snapshots[0].Source == analysis.Snapshots[1].Source {
		t.Fatalf("nested dump identity collision: %#v", analysis.Snapshots)
	}
}

func TestTopLevelDumpKeepsLegacySnapshotID(t *testing.T) {
	filename := filepath.Join("testdata", "ns-baseline.dump")
	legacy, err := AnalyzeNSFiles([]string{filename}, nil)
	if err != nil {
		t.Fatal(err)
	}
	withLabel, err := analyzeNSFilesWithStateAndSourceLabels([]string{filename}, nil, nil, nil, nil, map[string]string{filename: filepath.Base(filename)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Snapshots[0].ID != withLabel.Snapshots[0].ID || legacy.Snapshots[0].Source != withLabel.Snapshots[0].Source {
		t.Fatalf("顶层来源不应改变历史快照身份: legacy=%#v watcher=%#v", legacy.Snapshots[0], withLabel.Snapshots[0])
	}
}
