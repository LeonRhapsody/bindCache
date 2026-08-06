package main

import (
	"testing"
	"time"
)

func TestChangedNSEventsWritesOnlyNewOrUpdatedEvents(t *testing.T) {
	first := time.Date(2026, 7, 28, 4, 0, 0, 0, time.UTC)
	unchanged := NSChangeEvent{ID: "unchanged", Status: "pending_verification", Occurrences: 1, FirstSeen: first, LastSeen: first, signature: "a"}
	updated := NSChangeEvent{ID: "updated", Status: "pending_verification", Occurrences: 1, FirstSeen: first, LastSeen: first, signature: "b"}
	updatedAfter := updated
	updatedAfter.Occurrences = 2
	updatedAfter.LastSeen = first.Add(10 * time.Minute)
	newEvent := NSChangeEvent{ID: "new", Status: "pending_verification", Occurrences: 1, FirstSeen: first, LastSeen: first, signature: "c"}

	changed := changedNSEvents([]NSChangeEvent{unchanged, updatedAfter, newEvent}, []NSChangeEvent{unchanged, updated})
	if len(changed) != 2 || changed[0].ID != "updated" || changed[1].ID != "new" {
		t.Fatalf("changed events = %#v, want updated and new", changed)
	}
}

func TestProbeNSChangeEventsCapsPerSnapshotEventCount(t *testing.T) {
	capturedAt := time.Date(2026, 7, 29, 4, 0, 0, 0, time.UTC)
	analysis := &NSAnalysis{
		Snapshots:       []SnapshotSummary{{ID: "snapshot", CapturedAt: capturedAt}},
		snapshotSources: map[string]string{"snapshot": "testdata/ns-baseline.dump"},
	}
	events := []NSChangeEvent{
		{ID: "critical", Domain: "critical.example.", Severity: "critical", Status: "pending_verification", FirstSeen: capturedAt, Current: DomainNSObservation{CapturedAt: capturedAt}},
		{ID: "high", Domain: "high.example.", Severity: "high", Status: "pending_verification", FirstSeen: capturedAt, Current: DomainNSObservation{CapturedAt: capturedAt}},
		{ID: "low", Domain: "low.example.", Severity: "low", Status: "pending_verification", FirstSeen: capturedAt, Current: DomainNSObservation{CapturedAt: capturedAt}},
	}
	results, attempts := probeNSChangeEventsWithAttempts(analysis, events, &NSProbeConfig{Enabled: true, MaxEventsPerImport: 2})
	if len(results) != 2 || results[0].EventID != "critical" || results[1].EventID != "high" {
		t.Fatalf("probe cap must retain critical/high events only: %#v", results)
	}
	if attempts != 2 {
		t.Fatalf("shared budget attempts = %d, want 2", attempts)
	}
}
