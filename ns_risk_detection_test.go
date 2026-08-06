package main

import (
	"testing"
	"time"
)

func TestDetectNSRedundancyRiskFindsLogicalSinglePoint(t *testing.T) {
	observation := DomainNSObservation{
		Domain:     "single.example.",
		CapturedAt: time.Now(),
		Nameservers: []NSHostObservation{
			{Name: "ns1.example.", Addresses: []NSAddress{{Address: "192.0.2.10", ASN: 64500, Country: "CN"}}},
			{Name: "ns2.example.", Addresses: []NSAddress{{Address: "192.0.2.10", ASN: 64500, Country: "CN"}}},
		},
	}
	finding, ok := detectNSRedundancyRisk(observation.Domain, observation)
	if !ok {
		t.Fatal("expected redundancy finding")
	}
	if finding.Type != "ns_single" || finding.Severity != "medium" || len(finding.ChangeFields) != 1 || finding.ChangeFields[0] != "多 NS 指向同一 IP" {
		t.Fatalf("unexpected finding %#v", finding)
	}
	if finding.Signature == "" {
		t.Fatal("finding signature must be stable and non-empty")
	}
}

func TestDetectNSRedundancyRiskIgnoresDistributedNS(t *testing.T) {
	observation := DomainNSObservation{
		Domain: "distributed.example.",
		Nameservers: []NSHostObservation{
			{Name: "ns1.example.", Addresses: []NSAddress{{Address: "192.0.2.10", ASN: 64500, Country: "CN"}}},
			{Name: "ns2.example.", Addresses: []NSAddress{{Address: "198.51.100.20", ASN: 64501, Country: "US"}}},
		},
	}
	if finding, ok := detectNSRedundancyRisk(observation.Domain, observation); ok {
		t.Fatalf("unexpected finding %#v", finding)
	}
}

func TestDetectNSRedundancyRiskRequiresTwoResolvedHosts(t *testing.T) {
	observation := DomainNSObservation{
		Domain: "partial.example.",
		Nameservers: []NSHostObservation{
			{Name: "ns1.example.", Addresses: []NSAddress{{Address: "192.0.2.10"}}},
			{Name: "ns2.example."},
			{Name: "ns3.example."},
		},
	}
	if finding, ok := detectNSRedundancyRisk(observation.Domain, observation); ok {
		t.Fatalf("one resolved host must not be treated as shared infrastructure: %#v", finding)
	}
}

func TestDetectNSRedundancyRiskIgnoresSameASNOrCountry(t *testing.T) {
	tests := []struct {
		name  string
		left  NSAddress
		right NSAddress
	}{
		{
			name:  "same ASN",
			left:  NSAddress{Address: "192.0.2.10", ASN: 64500, Country: "CN"},
			right: NSAddress{Address: "198.51.100.20", ASN: 64500, Country: "US"},
		},
		{
			name:  "same country",
			left:  NSAddress{Address: "192.0.2.10", ASN: 64500, Country: "CN"},
			right: NSAddress{Address: "198.51.100.20", ASN: 64501, Country: "CN"},
		},
		{
			name:  "same ASN and country",
			left:  NSAddress{Address: "192.0.2.10", ASN: 64500, Country: "CN"},
			right: NSAddress{Address: "198.51.100.20", ASN: 64500, Country: "CN"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := DomainNSObservation{
				Domain: "not-single.example.",
				Nameservers: []NSHostObservation{
					{Name: "ns1.example.", Addresses: []NSAddress{test.left}},
					{Name: "ns2.example.", Addresses: []NSAddress{test.right}},
				},
			}
			if finding, ok := detectNSRedundancyRisk(observation.Domain, observation); ok {
				t.Fatalf("同 ASN 或同国家不应触发 NS 单一事件: %#v", finding)
			}
		})
	}
}

func TestDetectNSParentChildRisksUsesTrustLevels(t *testing.T) {
	cache := &BindCache{records: map[string]Record{}}
	cache.records["delegated.example."] = Record{NSs: []NS{
		{NsDomain: "ns-parent.example.", Attribute: "authauthority"},
		{NsDomain: "ns-child.example.", Attribute: "authanswer"},
	}}
	findings := detectNSParentChildRisks(cache, map[string]DomainNSObservation{
		"delegated.example.": {Domain: "delegated.example."},
	})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v", findings)
	}
	if findings[0].Type != "ns_parent_child" || findings[0].Severity != "medium" {
		t.Fatalf("unexpected finding %#v", findings[0])
	}
}

func TestDetectNSParentChildRisksAddsSnapshotGlueTTLDNSSECEvidence(t *testing.T) {
	cache := &BindCache{records: map[string]Record{}}
	cache.records["delegated.example."] = Record{
		NSs: []NS{
			{NsDomain: "ns1.example.", TTL: 300, Attribute: "authauthority"},
			{NsDomain: "ns2.example.", TTL: 120, Attribute: "authanswer"},
		},
		DSs: []DS{{Attribute: "authanswer"}},
	}
	cache.records["ns1.example."] = Record{
		As: []A{
			{IP: "192.0.2.10", Attribute: "glue"},
			{IP: "198.51.100.10", Attribute: "answer"},
		},
	}
	findings := detectNSParentChildRisks(cache, map[string]DomainNSObservation{
		"delegated.example.": {Domain: "delegated.example."},
	})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v", findings)
	}
	finding := findings[0]
	if finding.Severity != "medium" || finding.Extra["glueMismatch"] != true {
		t.Fatalf("missing glue/TTL evidence %#v", finding)
	}
	if value, _ := finding.Extra["dnssec"].(string); value == "" {
		t.Fatalf("missing DNSSEC evidence %#v", finding.Extra)
	}
}

func TestNSAuxParentChildRiskDoesNotEscalateByTTL(t *testing.T) {
	first := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
	cache := &BindCache{records: map[string]Record{
		"delegated.example.": {NSs: []NS{
			{NsDomain: "ns-parent.example.", TTL: 300, Attribute: "authauthority"},
			{NsDomain: "ns-child.example.", TTL: 300, Attribute: "authanswer"},
		}},
	}}
	observation := DomainNSObservation{Domain: "delegated.example.", CapturedAt: first, Nameservers: []NSHostObservation{
		{Name: "ns-child.example."},
	}}
	tracker := newNSAuxRiskTracker(nil, nil)
	tracker.apply(SnapshotSummary{ID: "s1", CapturedAt: first}, map[string]DomainNSObservation{observation.Domain: observation}, cache)
	tracker.apply(SnapshotSummary{ID: "s2", CapturedAt: first.Add(10 * time.Minute)}, map[string]DomainNSObservation{observation.Domain: observation}, cache)
	var parentChild NSAuxRiskEvent
	for _, event := range tracker.active {
		if event.Type == "ns_parent_child" {
			parentChild = event
		}
	}
	if parentChild.ID == "" || parentChild.Severity != "medium" {
		t.Fatalf("parent-child event changed severity unexpectedly: %#v", parentChild)
	}
	for _, field := range parentChild.ChangeFields {
		if field == "传播窗口内" || field == "超过 TTL 传播窗口" {
			t.Fatalf("TTL marker must not be present: %#v", parentChild.ChangeFields)
		}
	}
}

func TestParentChildGlueEvidenceIgnoresMissingAddressFamily(t *testing.T) {
	cache := &BindCache{records: map[string]Record{
		"ns.example.": {
			As:    []A{{IP: "192.0.2.10", Attribute: "glue"}, {IP: "192.0.2.10", Attribute: "answer"}},
			AAAAs: []AAAA{{IP: "2001:db8::10", Attribute: "glue"}},
		},
	}}
	pairs, mismatch := parentChildGlueEvidence(cache, []string{"ns.example."})
	if mismatch || len(pairs) != 1 {
		t.Fatalf("one-sided IPv6 cache evidence must not be a mismatch: %#v mismatch=%v", pairs, mismatch)
	}
}

func TestNSAuxRiskTrackerRepeatsAndRecoversOnlyWhenDomainObserved(t *testing.T) {
	first := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
	observation := DomainNSObservation{
		Domain: "single.example.", CapturedAt: first,
		Nameservers: []NSHostObservation{{Name: "ns1.example.", Addresses: []NSAddress{{Address: "192.0.2.1"}}}},
	}
	cache := &BindCache{records: map[string]Record{}}
	tracker := newNSAuxRiskTracker(nil, nil)
	tracker.apply(SnapshotSummary{ID: "s1", CapturedAt: first}, map[string]DomainNSObservation{observation.Domain: observation}, cache)
	tracker.apply(SnapshotSummary{ID: "s2", CapturedAt: first.Add(10 * time.Minute)}, map[string]DomainNSObservation{observation.Domain: observation}, cache)
	if len(tracker.active) != 1 {
		t.Fatalf("active events = %d", len(tracker.active))
	}
	for _, event := range tracker.active {
		if event.Occurrences != 2 || event.Evidence != "repeated" {
			t.Fatalf("unexpected repeated event %#v", event)
		}
	}

	// 缓存中完全没有该域，不能误判恢复。
	tracker.apply(SnapshotSummary{ID: "s3", CapturedAt: first.Add(20 * time.Minute)}, map[string]DomainNSObservation{}, cache)
	if len(tracker.active) != 1 {
		t.Fatal("missing cache observation must not resolve event")
	}

	healthy := observation
	healthy.Nameservers = []NSHostObservation{
		{Name: "ns1.example.", Addresses: []NSAddress{{Address: "192.0.2.1", ASN: 64500, Country: "CN"}}},
		{Name: "ns2.example.", Addresses: []NSAddress{{Address: "198.51.100.1", ASN: 64501, Country: "US"}}},
	}
	tracker.apply(SnapshotSummary{ID: "s4", CapturedAt: first.Add(30 * time.Minute)}, map[string]DomainNSObservation{healthy.Domain: healthy}, cache)
	if len(tracker.active) != 0 {
		t.Fatal("observed healthy domain should resolve event")
	}
	events := tracker.changedEvents()
	if len(events) != 1 || events[0].Status != "resolved" || events[0].ResolvedAt == nil {
		t.Fatalf("unexpected resolved events %#v", events)
	}
}
