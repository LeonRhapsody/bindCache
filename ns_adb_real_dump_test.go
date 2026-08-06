package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestInspectRealDumpADBHealth 是显式启用的真实 dump 集成检查，不依赖固定机器路径。
// REAL_BIND_DUMP=/path/cache_dump.db go test -run TestInspectRealDumpADBHealth -v
func TestInspectRealDumpADBHealth(t *testing.T) {
	paths := filepath.SplitList(os.Getenv("REAL_BIND_DUMPS"))
	if len(paths) == 0 {
		if path := os.Getenv("REAL_BIND_DUMP"); path != "" {
			paths = []string{path}
		}
	}
	if len(paths) == 0 {
		t.Skip("set REAL_BIND_DUMP or REAL_BIND_DUMPS to inspect real BIND cache dumps")
	}
	states := make(map[string]NSADBEndpointState)
	for index, path := range paths {
		cache, err := ParseDNSCacheFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(cache.ADBRecords) == 0 {
			t.Fatalf("real dump %s contains no parsed ADB records", path)
		}
		capturedAt := parseSnapshotTime(cache.Date, path)
		if capturedAt.IsZero() {
			capturedAt = time.Now().UTC().Add(time.Duration(index) * 10 * time.Minute)
		}
		observations := BuildNSObservations(cache, capturedAt, nil)
		if len(observations) == 0 {
			t.Fatalf("real dump %s contains no NS observations", path)
		}
		view := cache.View
		if view == "" {
			view = "default"
		}
		updates, history, findings := processNSADBEndpointHealth(
			SnapshotSummary{ID: "real-" + shortHash(path), View: view, CapturedAt: capturedAt}, observations, cache.ADBRecords, states)
		parentChild := detectNSParentChildRisks(cache, observations)
		redundancy := 0
		for domain, observation := range observations {
			if _, ok := detectNSRedundancyRisk(domain, observation); ok {
				redundancy++
			}
		}
		if len(updates) > len(cache.ADBRecords) {
			t.Fatalf("mapped endpoint updates %d exceed parsed ADB records %d", len(updates), len(cache.ADBRecords))
		}
		t.Logf("%s: ADB=%d, zones=%d, state writes=%d, health changes=%d, availability candidates=%d, redundancy=%d, parent-child=%d",
			filepath.Base(path), len(cache.ADBRecords), len(observations), len(updates), len(history), len(findings), redundancy, len(parentChild))
	}
	if len(paths) == 1 {
		path := paths[0]
		cache, err := ParseDNSCacheFile(path)
		if err != nil {
			t.Fatal(err)
		}
		capturedAt := parseSnapshotTime(cache.Date, path).Add(10 * time.Minute)
		observations := BuildNSObservations(cache, capturedAt, nil)
		_, _, findings := processNSADBEndpointHealth(
			SnapshotSummary{ID: "real-repeat", View: cache.View, CapturedAt: capturedAt}, observations, cache.ADBRecords, states)
		t.Logf("same-dump consecutive-suspect simulation: availability candidates=%d", len(findings))
	}
}
