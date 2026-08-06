package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadNSBlacklistDirectoryAndDetectActiveHit(t *testing.T) {
	directory := t.TempDir()
	content := "object_type,object,source,version,confidence,category,effective_at,expires_at,description\n" +
		"ns,ns.bad.example,internal-watch,v3,high,malicious-ns,2026-07-01,2026-08-31,confirmed malicious infrastructure\n" +
		"ip,192.0.2.66,internal-watch,v3,medium,suspicious-ip,2026-07-01,2026-08-31,suspicious address\n"
	path := filepath.Join(directory, "internal-watch.csv")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
	index, err := LoadNSBlacklistDirectory(NSBlacklistRuntimeConfig{Directory: directory, MaxFileBytes: 1 << 20, MaxEntries: 100}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Sources) != 1 || index.Sources[0].Entries != 2 || index.Sources[0].SHA256 == "" {
		t.Fatalf("unexpected sources %#v", index.Sources)
	}
	observation := DomainNSObservation{
		Domain: "victim.example.", CapturedAt: now,
		Nameservers: []NSHostObservation{{
			Name: "ns.bad.example.", Addresses: []NSAddress{{Address: "192.0.2.66"}},
		}},
	}
	finding, ok := detectNSBlacklistRisk(observation.Domain, observation, index)
	if !ok {
		t.Fatal("expected blacklist finding")
	}
	if finding.Type != "ns_blacklist" || finding.Severity != "high" {
		t.Fatalf("unexpected finding %#v", finding)
	}
	hits, ok := finding.Extra["hits"].([]map[string]any)
	if !ok || len(hits) != 2 {
		t.Fatalf("unexpected hits %#v", finding.Extra["hits"])
	}
}

func TestBlacklistExpiredEntryDoesNotCreateRisk(t *testing.T) {
	index := &NSBlacklistIndex{
		byNS: map[string][]NSBlacklistEntry{
			"ns.old.example.": {{
				ObjectType: "ns", Object: "ns.old.example.", Source: "old", Version: "v1", Confidence: "high",
				Effective: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				Expires:   time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
			}},
		},
	}
	observation := DomainNSObservation{
		Domain: "safe.example.", CapturedAt: time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC),
		Nameservers: []NSHostObservation{{Name: "ns.old.example."}},
	}
	if finding, ok := detectNSBlacklistRisk(observation.Domain, observation, index); ok {
		t.Fatalf("expired rule must not create event: %#v", finding)
	}
}
