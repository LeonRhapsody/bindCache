package main

import (
	"strings"
	"testing"
	"time"
)

func TestBuildNSAlertMessageContainsEvidenceAndProbeVerdict(t *testing.T) {
	when := time.Date(2026, 7, 29, 1, 0, 0, 0, time.UTC)
	event := NSChangeEvent{ID: "alert-event", Domain: "victim.example.", Severity: "critical", Evidence: "verified", Status: "verified_impact", Summary: "变异 NS 返回错误 IP", ChangeTypes: []string{"ns_ip_changed"}, FirstSeen: when, LastSeen: when, Baseline: DomainNSObservation{Nameservers: []NSHostObservation{{Name: "ns1.example."}}}, Current: DomainNSObservation{Nameservers: []NSHostObservation{{Name: "ns1.changed."}}}}
	subject, text := buildNSAlertMessage(event, NSProbeResult{Verdict: "verified_impact", Summary: "192.0.2.53 命中异常结果", ProbedDomains: 1, DomainLimit: 20}, true, "[TEST]")
	if !strings.Contains(subject, "CRITICAL") || !strings.Contains(text, "alert-event") || !strings.Contains(text, "verified_impact") || !strings.Contains(text, "192.0.2.53") || !strings.Contains(text, "ns1.changed.") {
		t.Fatalf("告警内容缺少处置证据: subject=%q text=%q", subject, text)
	}
}

func TestNSAlertClusterTypeIgnoresChangeTypeOrderButSeparatesDifferentEvidence(t *testing.T) {
	base := NSChangeEvent{
		Domain:      "victim.example.",
		Severity:    "critical",
		Summary:     "NS 指向保留或私网地址",
		ChangeTypes: []string{"reserved_ns_ip", "ns_ip_changed"},
	}
	reordered := base
	reordered.ChangeTypes = []string{"ns_ip_changed", "reserved_ns_ip"}
	if nsAlertClusterType(base) != nsAlertClusterType(reordered) {
		t.Fatal("同一告警簇不应受变化类型顺序影响")
	}
	different := base
	different.Summary = "NS 新增跨注册域"
	if nsAlertClusterType(base) == nsAlertClusterType(different) {
		t.Fatal("不同变化摘要不应被合并为同一告警簇")
	}
}

func TestRecoveryAlertHasIndependentClusterAndRecoveryWording(t *testing.T) {
	when := time.Date(2026, 7, 30, 2, 0, 0, 0, time.UTC)
	active := NSChangeEvent{
		ID: "event-recovery", Domain: "victim.example.", Severity: "critical", Evidence: "verified",
		Status: "verified_impact", Summary: "异常结果已影响递归", FirstSeen: when, LastSeen: when,
	}
	recovered := active
	recovered.Status = "resolved"
	recovered.LastSeen = when.Add(20 * time.Minute)
	if nsAlertClusterType(active) == nsAlertClusterType(recovered) {
		t.Fatal("恢复通知不能被活动事件的冷却键抑制")
	}
	subject, body := buildNSAlertMessage(recovered, NSProbeResult{}, false, "[TEST]")
	if !strings.Contains(subject, "恢复") || !strings.Contains(body, "风险事件已恢复") {
		t.Fatalf("恢复通知措辞错误: subject=%q body=%q", subject, body)
	}
}
