package main

import (
	"os"
	"testing"
)

func TestMigrateNSLocationRiskEventKeepsValidReasonAndHistory(t *testing.T) {
	event := NSAuxRiskEvent{
		ID: "RISK-mixed", Type: "ns_single", Domain: "mixed.example.", Severity: "medium",
		Evidence: "verified", Status: "verified_ns_divergence", Occurrences: 12,
		ChangeFields: []string{"多 NS 指向同一 IP", "多 NS 位于同一 ASN", "多 NS 位于同一国家/地区"},
		Current: DomainNSObservation{Domain: "mixed.example.", Nameservers: []NSHostObservation{
			{Name: "ns1.example.", Addresses: []NSAddress{{Address: "192.0.2.10", ASN: 64500, Country: "CN"}}},
			{Name: "ns2.example.", Addresses: []NSAddress{{Address: "192.0.2.10", ASN: 64500, Country: "CN"}}},
		}},
		Extra: map[string]any{
			"singleReason": "多 NS 指向同一 IP；多 NS 位于同一 ASN；多 NS 位于同一国家/地区",
			"historyMaxNs": 4, "activeProbeVerdict": "verified_ns_divergence", "activeProbeSummary": "拨测证据",
		},
		Signature: "old",
	}
	updated, ok := migrateNSLocationRiskEvent(event)
	if !ok {
		t.Fatal("混合事件应保留有效同 IP 原因")
	}
	if len(updated.ChangeFields) != 1 || updated.ChangeFields[0] != "多 NS 指向同一 IP" {
		t.Fatalf("迁移后原因错误: %#v", updated.ChangeFields)
	}
	if updated.Signature == "" || updated.Signature == "old" {
		t.Fatalf("迁移后签名未重算: %q", updated.Signature)
	}
	if extraInt(updated.Extra, "historyMaxNs") != 4 || stringValue(updated.Extra["activeProbeVerdict"]) != "verified_ns_divergence" {
		t.Fatalf("历史与拨测证据未保留: %#v", updated.Extra)
	}
	if updated.Occurrences != 12 || updated.Evidence != "verified" || updated.Status != "verified_ns_divergence" {
		t.Fatalf("事件生命周期字段被破坏: %#v", updated)
	}
}

func TestNSSingleHistoryCleanupQueriesStayScoped(t *testing.T) {
	if nsSingleEventIDs != `(SELECT event_id FROM ns_risk_events FINAL WHERE risk_type = 'ns_single')` {
		t.Fatalf("unexpected NS single scope: %s", nsSingleEventIDs)
	}
}

func TestInspectProductionNSSingleHistory(t *testing.T) {
	dsn := os.Getenv("TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("TEST_CLICKHOUSE_DSN not set")
	}
	db, err := OpenNSClickHouseReadDatabase(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	report, err := countNSSingleRiskHistory(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("NS single history: events=%d probes=%d alerts=%d actions=%d audit_logs=%d", report.Events, report.Probes, report.Alerts, report.Actions, report.AuditLogs)
}
