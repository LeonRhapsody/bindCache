package main

import (
	"os"
	"testing"
	"time"
)

func TestEnsureNSADBClickHouseSchema(t *testing.T) {
	dsn := os.Getenv("TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("TEST_CLICKHOUSE_DSN not set")
	}
	db, err := OpenNSClickHouseDatabase(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := EnsureNSClickHouseSchema(db); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"ns_adb_endpoint_state", "ns_adb_endpoint_history"} {
		var columns uint64
		if err := db.QueryRow(`SELECT count() FROM system.columns WHERE database = currentDatabase() AND table = ?`, table).Scan(&columns); err != nil {
			t.Fatal(err)
		}
		if columns == 0 {
			t.Fatalf("table %s has no columns", table)
		}
		t.Logf("%s columns=%d", table, columns)
	}
}

func TestEvaluateNSADBRecordSeparatesEDNSCompatibilityFromUnresponsive(t *testing.T) {
	if health, _ := evaluateNSADBRecord(ADBRecord{SRTT: 45_000, EDNSTimeout: 8, PlainSuccess: 4}); health != nsADBHealthEDNSDegraded {
		t.Fatalf("EDNS compatibility issue health = %q", health)
	}
	if health, _ := evaluateNSADBRecord(ADBRecord{SRTT: 600_000, PlainTimeout: 3}); health != nsADBHealthSuspect {
		t.Fatalf("unresponsive endpoint health = %q", health)
	}
	if health, _ := evaluateNSADBRecord(ADBRecord{SRTT: 1_500_000, EDNSSuccess: 3}); health != nsADBHealthDegraded {
		t.Fatalf("extremely slow responding endpoint health = %q", health)
	}
	if health, _ := evaluateNSADBRecord(ADBRecord{SRTT: 600_000, EDNSSuccess: 17, PlainTimeout: 57}); health == nsADBHealthSuspect {
		t.Fatalf("EDNS successes must prevent full-unresponsive classification: %q", health)
	}
}

func TestNSADBSuspectContinuityRequiresAdjacentSnapshot(t *testing.T) {
	previous := NSADBEndpointState{LastSeen: time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC), Health: nsADBHealthSuspect, ConsecutiveSuspect: 5}
	record := ADBRecord{Name: "ns.example.", IP: "192.0.2.1", SRTT: 900_000, PlainTimeout: 6}
	health, _ := evaluateNSADBRecordWithPrevious(record, &previous, false)
	if health != nsADBHealthSuspect {
		t.Fatalf("raw timeout evidence should remain suspect after a gap, got %q", health)
	}
	states := map[string]NSADBEndpointState{nsADBEndpointKey("default", record.Name, record.IP): previous}
	observation := map[string]DomainNSObservation{"zone.example.": {Domain: "zone.example.", Nameservers: []NSHostObservation{{Name: record.Name, Addresses: []NSAddress{{Address: record.IP}}}}}}
	updates, _, findings := processNSADBEndpointHealth(SnapshotSummary{ID: "late", View: "default", CapturedAt: previous.LastSeen.Add(time.Hour)}, observation, []ADBRecord{record}, states)
	if len(updates) != 1 || updates[0].ConsecutiveSuspect != 1 || len(findings) != 0 {
		t.Fatalf("gap must reset suspect continuity: updates=%#v findings=%#v", updates, findings)
	}
}

func TestNSADBAvailabilityRequiresTwoConsecutiveSuspectSnapshots(t *testing.T) {
	states := make(map[string]NSADBEndpointState)
	observations := map[string]DomainNSObservation{
		"zone.example.": {
			Domain: "zone.example.",
			Nameservers: []NSHostObservation{
				{Name: "ns1.example.", Addresses: []NSAddress{{Address: "192.0.2.51"}}},
				{Name: "ns2.example.", Addresses: []NSAddress{{Address: "192.0.2.52"}}},
			},
		},
	}
	bad := ADBRecord{Name: "ns1.example.", IP: "192.0.2.51", SRTT: 700_000, PlainTimeout: 3}
	good := ADBRecord{Name: "ns2.example.", IP: "192.0.2.52", SRTT: 30_000, PlainSuccess: 5}
	first := time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC)
	updates, history, findings := processNSADBEndpointHealth(SnapshotSummary{ID: "s1", View: "default", CapturedAt: first}, observations, []ADBRecord{bad, good}, states)
	if len(updates) != 2 || len(history) != 1 || len(findings) != 0 {
		t.Fatalf("first snapshot updates=%d history=%d findings=%#v", len(updates), len(history), findings)
	}
	bad.PlainTimeout = 6
	_, _, findings = processNSADBEndpointHealth(SnapshotSummary{ID: "s2", View: "default", CapturedAt: first.Add(10 * time.Minute)}, observations, []ADBRecord{bad, good}, states)
	if len(findings) != 1 || findings[0].Type != "ns_availability" || findings[0].Severity != "high" {
		t.Fatalf("second snapshot findings = %#v", findings)
	}
	if extraInt(findings[0].Extra, "remainingNS") != 1 {
		t.Fatalf("remaining NS = %#v", findings[0].Extra)
	}
}

func TestNSADBHealthyHeartbeatIsHourly(t *testing.T) {
	states := make(map[string]NSADBEndpointState)
	observations := map[string]DomainNSObservation{
		"zone.example.": {Domain: "zone.example.", Nameservers: []NSHostObservation{
			{Name: "ns.example.", Addresses: []NSAddress{{Address: "192.0.2.61"}}},
		}},
	}
	record := ADBRecord{Name: "ns.example.", IP: "192.0.2.61", SRTT: 20_000, PlainSuccess: 3}
	first := time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC)
	updates, _, _ := processNSADBEndpointHealth(SnapshotSummary{ID: "s1", View: "default", CapturedAt: first}, observations, []ADBRecord{record}, states)
	if len(updates) != 1 {
		t.Fatalf("initial updates = %d", len(updates))
	}
	updates, _, _ = processNSADBEndpointHealth(SnapshotSummary{ID: "s2", View: "default", CapturedAt: first.Add(10 * time.Minute)}, observations, []ADBRecord{record}, states)
	if len(updates) != 0 {
		t.Fatalf("ten-minute healthy heartbeat updates = %d", len(updates))
	}
	updates, _, _ = processNSADBEndpointHealth(SnapshotSummary{ID: "s3", View: "default", CapturedAt: first.Add(70 * time.Minute)}, observations, []ADBRecord{record}, states)
	if len(updates) != 1 {
		t.Fatalf("hourly healthy heartbeat updates = %d", len(updates))
	}
}

func TestNSAvailabilityMustBeVerifiedBeforeAlerting(t *testing.T) {
	events := []NSAuxRiskEvent{
		{ID: "candidate", Type: "ns_availability", Evidence: "repeated", Severity: "high"},
		{ID: "verified", Type: "ns_availability", Evidence: "verified", Severity: "high"},
		{ID: "other", Type: "ns_single", Evidence: "observed", Severity: "high"},
	}
	filtered := alertableNSAuxRiskEvents(events)
	if len(filtered) != 2 || filtered[0].ID != "verified" || filtered[1].ID != "other" {
		t.Fatalf("alertable events = %#v", filtered)
	}
}

func TestSplitNSAuxRiskEventsReservesAvailabilityProbe(t *testing.T) {
	events := []NSAuxRiskEvent{{ID: "single", Type: "ns_single"}, {ID: "availability", Type: "ns_availability"}}
	availability, other := splitNSAuxRiskEvents(events, "ns_availability")
	if !hasNSAuxRiskType(events, "ns_availability") || len(availability) != 1 || availability[0].ID != "availability" || len(other) != 1 || other[0].ID != "single" {
		t.Fatalf("availability=%#v other=%#v", availability, other)
	}
}
