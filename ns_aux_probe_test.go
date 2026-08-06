package main

import (
	"context"
	"testing"
	"time"
)

type fakeTypedDNSProbeExecutor struct {
	answers map[string]DNSProbeAnswer
}

func (f fakeTypedDNSProbeExecutor) QueryDNS(_ context.Context, _, resolver string, _ bool, _ time.Duration) DNSProbeAnswer {
	return f.answers[resolver]
}

func (f fakeTypedDNSProbeExecutor) QueryDNSRecords(_ context.Context, _, resolver string, _ bool, _ time.Duration, _ []string) DNSProbeAnswer {
	return f.answers[resolver]
}

func TestProbeNSAuxParentChildUsesTypedNSConsensus(t *testing.T) {
	event := NSAuxRiskEvent{
		ID: "RISK-parent", Type: "ns_parent_child", Domain: "delegated.example.", SnapshotID: "snap-1",
		Current: DomainNSObservation{Nameservers: []NSHostObservation{
			{Name: "ns1.child.example.", Addresses: []NSAddress{{Address: "192.0.2.10"}}},
			{Name: "ns2.child.example.", Addresses: []NSAddress{{Address: "192.0.2.11"}}},
		}},
	}
	executor := fakeTypedDNSProbeExecutor{answers: map[string]DNSProbeAnswer{
		"192.0.2.10:53":      {Resolver: "192.0.2.10:53", RCode: "NOERROR", NS: []string{"ns1.child.example.", "ns2.child.example."}},
		"192.0.2.11:53":      {Resolver: "192.0.2.11:53", RCode: "NOERROR", NS: []string{"ns1.child.example.", "ns2.child.example."}},
		"114.114.114.114:53": {Resolver: "114.114.114.114:53", RCode: "NOERROR", NS: []string{"ns1.parent.example.", "ns2.parent.example."}},
		"223.5.5.5:53":       {Resolver: "223.5.5.5:53", RCode: "NOERROR", NS: []string{"ns1.parent.example.", "ns2.parent.example."}},
		"192.0.2.53:53":      {Resolver: "192.0.2.53:53", RCode: "NOERROR", NS: []string{"ns1.parent.example.", "ns2.parent.example."}},
	}}
	config := DefaultNSProbeConfig()
	config.RecursiveResolver = "192.0.2.53:53"
	config.Executor = executor
	result, err := ProbeNSAuxEvent(context.Background(), event, config)
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != "verified_ns_divergence" || len(result.Domains) != 1 {
		t.Fatalf("result = %#v", result)
	}
	if result.Domains[0].StableConsensus == nil || result.Domains[0].TrustedConsensus == nil {
		t.Fatalf("missing authoritative/trusted consensus: %#v", result.Domains[0])
	}
}

func TestApplyNSAuxProbeResultAndNextObservationPreserveVerification(t *testing.T) {
	first := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
	observation := DomainNSObservation{
		Domain: "single.example.", CapturedAt: first,
		Nameservers: []NSHostObservation{{Name: "ns1.example.", Addresses: []NSAddress{{Address: "192.0.2.1"}}}},
	}
	cache := &BindCache{records: map[string]Record{}}
	tracker := newNSAuxRiskTracker(nil, nil)
	tracker.apply(SnapshotSummary{ID: "s1", CapturedAt: first}, map[string]DomainNSObservation{observation.Domain: observation}, cache)
	var key string
	var event NSAuxRiskEvent
	for candidateKey, candidate := range tracker.active {
		if candidate.Type == "ns_single" {
			key, event = candidateKey, candidate
		}
	}
	if !applyNSAuxProbeResult(&event, NSProbeResult{Verdict: "verified_ns_divergence", Summary: "唯一 NS 不可达"}) {
		t.Fatal("probe result should upgrade event")
	}
	tracker.active[key] = event
	observation.CapturedAt = first.Add(10 * time.Minute)
	tracker.apply(SnapshotSummary{ID: "s2", CapturedAt: observation.CapturedAt}, map[string]DomainNSObservation{observation.Domain: observation}, cache)
	updated := tracker.active[key]
	if updated.Evidence != "verified" || updated.Status != "verified_ns_divergence" {
		t.Fatalf("verification was downgraded: %#v", updated)
	}
}

func TestProbeNSAuxBlacklistConfirmsRecursiveImpact(t *testing.T) {
	event := NSAuxRiskEvent{
		ID: "RISK-blacklist", Type: "ns_blacklist", Domain: "victim.example.", SnapshotID: "snap-2",
		Current: DomainNSObservation{Nameservers: []NSHostObservation{
			{Name: "ns.bad.example.", Addresses: []NSAddress{{Address: "192.0.2.20"}}},
		}},
	}
	executor := fakeTypedDNSProbeExecutor{answers: map[string]DNSProbeAnswer{
		"192.0.2.20:53":      {Resolver: "192.0.2.20:53", RCode: "NOERROR", IPv4: []string{"203.0.113.66"}},
		"114.114.114.114:53": {Resolver: "114.114.114.114:53", RCode: "NOERROR", IPv4: []string{"198.51.100.8"}},
		"223.5.5.5:53":       {Resolver: "223.5.5.5:53", RCode: "NOERROR", IPv4: []string{"198.51.100.8"}},
		"192.0.2.53:53":      {Resolver: "192.0.2.53:53", RCode: "NOERROR", IPv4: []string{"203.0.113.66"}},
	}}
	config := DefaultNSProbeConfig()
	config.RecursiveResolver = "192.0.2.53:53"
	config.Executor = executor
	result, err := ProbeNSAuxEvent(context.Background(), event, config)
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != "verified_impact" {
		t.Fatalf("verdict = %q, result=%#v", result.Verdict, result)
	}
	if !applyNSAuxProbeResult(&event, result) || event.Severity != "critical" || event.Status != "verified_impact" {
		t.Fatalf("blacklist impact was not upgraded: %#v", event)
	}
}

func TestProbeNSAuxWithoutAuthoritativeAddressIsInconclusive(t *testing.T) {
	event := NSAuxRiskEvent{
		ID: "RISK-no-address", Type: "ns_single", Domain: "unknown.example.", SnapshotID: "snap-3",
		Current: DomainNSObservation{Nameservers: []NSHostObservation{{Name: "ns1.unknown.example."}}},
	}
	config := DefaultNSProbeConfig()
	config.Executor = fakeTypedDNSProbeExecutor{answers: map[string]DNSProbeAnswer{}}
	result, err := ProbeNSAuxEvent(context.Background(), event, config)
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != "inconclusive" {
		t.Fatalf("missing endpoint data must stay inconclusive: %#v", result)
	}
	if applyNSAuxProbeResult(&event, result) {
		t.Fatal("inconclusive result must not upgrade evidence")
	}
}

func TestProbeNSAvailabilityConfirmsOnlyUnresponsiveHost(t *testing.T) {
	event := NSAuxRiskEvent{
		ID: "RISK-availability", Type: "ns_availability", Domain: "availability.example.", SnapshotID: "snap-4",
		Current: DomainNSObservation{Nameservers: []NSHostObservation{
			{Name: "ns1.example.", Addresses: []NSAddress{{Address: "192.0.2.31"}}},
			{Name: "ns2.example.", Addresses: []NSAddress{{Address: "192.0.2.32"}}},
		}}, Extra: map[string]any{"remainingNS": 1},
	}
	executor := fakeTypedDNSProbeExecutor{answers: map[string]DNSProbeAnswer{
		"192.0.2.31:53": {Resolver: "192.0.2.31:53", Error: "timeout"},
		"192.0.2.32:53": {Resolver: "192.0.2.32:53", RCode: "NOERROR", NS: []string{"ns1.example.", "ns2.example."}},
	}}
	config := DefaultNSProbeConfig()
	config.Executor = executor
	result, err := ProbeNSAuxEvent(context.Background(), event, config)
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != "verified_ns_divergence" || len(result.Domains) != 1 {
		t.Fatalf("availability result = %#v", result)
	}
	if len(result.Domains[0].TrustedResolvers) != 0 {
		t.Fatalf("availability probe should not query trusted resolvers: %#v", result.Domains[0].TrustedResolvers)
	}
	if !applyNSAuxProbeResult(&event, result) || event.Severity != "high" {
		t.Fatalf("availability event was not upgraded: %#v", event)
	}
}

func TestProbeNSAvailabilityRejectsADBFalsePositive(t *testing.T) {
	event := NSAuxRiskEvent{
		ID: "RISK-availability-healthy", Type: "ns_availability", Domain: "healthy.example.", SnapshotID: "snap-5",
		Current: DomainNSObservation{Nameservers: []NSHostObservation{
			{Name: "ns1.example.", Addresses: []NSAddress{{Address: "192.0.2.41"}}},
		}}, Extra: map[string]any{"remainingNS": 0},
	}
	config := DefaultNSProbeConfig()
	config.Executor = fakeTypedDNSProbeExecutor{answers: map[string]DNSProbeAnswer{
		"192.0.2.41:53": {Resolver: "192.0.2.41:53", RCode: "NOERROR", NS: []string{"ns1.example."}},
	}}
	result, err := ProbeNSAuxEvent(context.Background(), event, config)
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != "consistent" || applyNSAuxProbeResult(&event, result) {
		t.Fatalf("ADB false positive must not be confirmed: result=%#v event=%#v", result, event)
	}
}
