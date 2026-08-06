package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestDiffProbeAnswersExposesAuthorityOnlyDifference(t *testing.T) {
	stable := DNSProbeAnswer{RCode: "NOERROR", IPv4: []string{"204.141.42.172"}}
	current := DNSProbeAnswer{RCode: "NOERROR", IPv4: []string{"204.141.42.172"}, NS: []string{"ns1.example.", "ns2.example."}}
	rows := diffProbeAnswers(stable, current)
	changed := map[string]nsV1ProbeFieldDiff{}
	for _, row := range rows {
		if row.Changed {
			changed[row.Field] = row
		}
	}
	if len(changed) != 1 {
		t.Fatalf("changed=%#v, want authority_ns only", changed)
	}
	row, ok := changed["authority_ns"]
	if !ok {
		t.Fatalf("authority_ns missing: %#v", changed)
	}
	if row.Label != "Authority 附加 NS" || len(row.Current) != 2 || row.Note == "" {
		t.Fatalf("unexpected row: %#v", row)
	}
}

func TestInspectProductionV1EventJSON(t *testing.T) {
	dsn, eventID := os.Getenv("TEST_CLICKHOUSE_DSN"), os.Getenv("TEST_EVENT_ID")
	if dsn == "" || eventID == "" {
		t.Skip("TEST_CLICKHOUSE_DSN/TEST_EVENT_ID not set")
	}
	db, err := OpenNSClickHouseReadDatabase(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &nsPersistentMonitorServer{store: &nsPersistentStore{db: db}, recordCache: make(map[string]nsSnapshotRecordResponse)}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/events/"+eventID, nil)
	response := httptest.NewRecorder()
	server.v1EventDetail(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("event API status=%d body=%s", response.Code, response.Body.String())
	}
	for _, field := range []string{`"changeFields":null`, `"baselineNs":null`, `"currentNs":null`, `"probes":null`, `"cname":null`, `"a":null`, `"aaaa":null`, `"authorityNs":null`, `"stable":null`, `"current":null`} {
		if bytes.Contains(response.Body.Bytes(), []byte(field)) {
			t.Fatalf("production event response contains %s: %s", field, response.Body.String())
		}
	}
	t.Logf("production event %s normalized response bytes=%d", eventID, response.Body.Len())
}

func TestV1ProbeJSONUsesEmptyArraysInsteadOfNull(t *testing.T) {
	item := eventToV1(NSChangeEvent{ID: "event", Domain: "example."}, 1)
	applyProbeToV1(&item, &NSProbeResult{Domains: []NSProbeDomainResult{{
		Domain: "example.", StableNS: []NSProbeHostResult{{Host: "ns.example.", Effective: &DNSProbeAnswer{RCode: "NOERROR"}}},
		StableConsensus: &DNSProbeAnswer{RCode: "NOERROR"}, RecursiveResult: DNSProbeAnswer{RCode: "NOERROR"},
	}}})
	raw, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"changeFields":null`, `"cname":null`, `"a":null`, `"aaaa":null`, `"authorityNs":null`, `"stable":null`, `"current":null`} {
		if bytes.Contains(raw, []byte(field)) {
			t.Fatalf("v1 response contains %s: %s", field, raw)
		}
	}
}
