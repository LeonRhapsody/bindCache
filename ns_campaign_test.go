package main

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func campaignTestStates(zones int) (campaignSnapshotState, campaignSnapshotState) {
	before := campaignSnapshotState{Version: 1, SnapshotID: "before", CapturedAt: time.Unix(1000, 0), View: "default", NS: map[string]map[string][]string{}, A: map[string][]string{}}
	after := campaignSnapshotState{Version: 1, SnapshotID: "after", CapturedAt: time.Unix(1600, 0), View: "default", NS: map[string]map[string][]string{}, A: map[string][]string{}}
	for i := 0; i < zones; i++ {
		zone := fmt.Sprintf("zone%d.example.", i)
		before.NS[zone] = map[string][]string{fmt.Sprintf("old%d.ns.", i): {fmt.Sprintf("192.0.2.%d", i+1)}, "shared.ns.": {fmt.Sprintf("198.51.100.%d", i+1)}}
		after.NS[zone] = map[string][]string{fmt.Sprintf("old%d.ns.", i): {fmt.Sprintf("192.0.2.%d", i+1)}, "shared.ns.": {"203.0.113.9"}, "new.provider.net.": {"203.0.113.8"}}
		owner := "www." + zone
		before.A[owner] = []string{fmt.Sprintf("198.51.100.%d", i+1)}
		after.A[owner] = []string{"203.0.113.7"}
	}
	return before, after
}

func TestDetectDNSCampaignsThreeRulesAndThreshold(t *testing.T) {
	before, after := campaignTestStates(10)
	events := detectDNSCampaigns(before, after, 10)
	if len(events) != 4 {
		t.Fatalf("events=%d, want 4: %#v", len(events), events)
	}
	typeTargets := map[string]DNSCampaignEvent{}
	for _, event := range events {
		typeTargets[event.Type+"|"+event.Target] = event
		if event.ZoneCount != 10 || len(event.Changes) != 10 {
			t.Fatalf("%s %s lacks threshold/change evidence: %#v", event.Type, event.Target, event)
		}
	}
	for _, key := range []string{
		"same_new_ns|provider.net.",
		"same_ns_ip|203.0.113.8",
		"same_ns_ip|203.0.113.9",
		"same_a_ip|203.0.113.7",
	} {
		if _, ok := typeTargets[key]; !ok {
			t.Fatalf("missing campaign %s: %#v", key, events)
		}
	}
	before, after = campaignTestStates(9)
	if got := detectDNSCampaigns(before, after, 10); len(got) != 0 {
		t.Fatalf("9 zones unexpectedly triggered %d events", len(got))
	}
}

func TestDetectDNSCampaignsDeduplicatesZonesAndIgnoresAbsence(t *testing.T) {
	before, after := campaignTestStates(10)
	for i := 0; i < 10; i++ {
		zone := fmt.Sprintf("zone%d.example.", i)
		owner := "api." + zone
		before.A[owner] = []string{"192.0.2.200"}
		after.A[owner] = []string{"203.0.113.7"}
	}
	delete(after.NS, "zone0.example.")
	events := detectDNSCampaigns(before, after, 10)
	for _, event := range events {
		if event.Type == "same_a_ip" && event.ZoneCount != 10 {
			t.Fatalf("same zone records were double counted: %d", event.ZoneCount)
		}
		if event.Type != "same_a_ip" {
			t.Fatalf("missing zone should prevent NS rule threshold, got %s", event.Type)
		}
	}
}

func TestDetectDNSCampaignsIgnoresFirstIPObservation(t *testing.T) {
	before := campaignSnapshotState{SnapshotID: "before", NS: map[string]map[string][]string{}, A: map[string][]string{}}
	after := campaignSnapshotState{SnapshotID: "after", NS: map[string]map[string][]string{}, A: map[string][]string{}}
	for i := 0; i < 10; i++ {
		zone := fmt.Sprintf("zone%d.example.", i)
		owner := "www." + zone
		before.NS[zone] = map[string][]string{"ns.provider.net.": {}}
		after.NS[zone] = map[string][]string{"ns.provider.net.": {"203.0.113.8"}}
		before.A[owner] = []string{}
		after.A[owner] = []string{"203.0.113.7"}
	}
	if events := detectDNSCampaigns(before, after, 10); len(events) != 0 {
		t.Fatalf("first IP observations unexpectedly triggered campaigns: %#v", events)
	}
}

func TestIsFirstIPObservationCampaign(t *testing.T) {
	emptyPrevious := DNSCampaignEvent{Type: "same_ns_ip", Changes: []DNSCampaignChange{{PreviousValues: nil, CurrentValues: []string{"203.0.113.8"}}, {PreviousValues: []string{}, CurrentValues: []string{"203.0.113.8"}}}}
	if !isFirstIPObservationCampaign(emptyPrevious) {
		t.Fatal("all-empty previous values should be classified as first observation")
	}
	changed := emptyPrevious
	changed.Changes = append(changed.Changes, DNSCampaignChange{PreviousValues: []string{"192.0.2.1"}, CurrentValues: []string{"203.0.113.8"}})
	if isFirstIPObservationCampaign(changed) {
		t.Fatal("mixed evidence containing a real IP change must be retained")
	}
	if isFirstIPObservationCampaign(DNSCampaignEvent{Type: "same_new_ns", Changes: emptyPrevious.Changes}) {
		t.Fatal("NS ownership campaigns must not be classified as first IP observations")
	}
	if isFirstIPObservationCampaign(DNSCampaignEvent{Type: "same_a_ip"}) {
		t.Fatal("events without detailed evidence must be retained for audit")
	}
}

func TestNearestObservedZoneUsesLongestSuffix(t *testing.T) {
	got := nearestObservedZone("www.child.example.", []string{"child.example.", "example."})
	if got != "child.example." {
		t.Fatalf("got %q", got)
	}
}

func TestCampaignStateRoundTrip(t *testing.T) {
	before, _ := campaignTestStates(2)
	path := filepath.Join(t.TempDir(), "campaign.json.gz")
	if err := saveCampaignSnapshotState(path, &before); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadCampaignSnapshotState(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.SnapshotID != before.SnapshotID || len(loaded.NS) != 2 {
		t.Fatalf("bad state: %#v", loaded)
	}
}

func TestCampaignHoldPreventsBaselinePromotion(t *testing.T) {
	observation := DomainNSObservation{Domain: "held.example.", CapturedAt: time.Unix(1000, 0), Fingerprint: "changed"}
	state := newNSBaselineCandidate(observation)
	state.ConsecutiveCount = NSBaselineConsecutiveRequired - 1
	builder := newNSAnalysisBuilderWithState(nil, nil, map[string]NSBaselineState{"held.example.": state}, nil)
	builder.setBaselineHolds(map[string]string{"held.example.": "CAM-test"})
	cache := &BindCache{records: map[string]Record{"held.example.": {NSs: []NS{{NsDomain: "ns.held.example.", Attribute: "authauthority"}}}}, View: "default"}
	// 直接用 BuildNSObservations 生成的指纹替换候选，确保是第 12 次同一结果。
	current := BuildNSObservations(cache, time.Unix(1600, 0), nil)["held.example."]
	state.Candidate = current
	state.CandidateFingerprint = current.Fingerprint
	state.ConsecutiveCount = NSBaselineConsecutiveRequired - 1
	builder.result.baselineStates["held.example."] = state
	builder.add(namedCacheSnapshot{Source: "held.dump", CapturedAt: time.Unix(1600, 0), Cache: cache})
	if _, promoted := builder.result.Baseline["held.example."]; promoted {
		t.Fatal("held campaign zone was promoted")
	}
	if got := builder.result.baselineStates["held.example."].ConsecutiveCount; got != NSBaselineConsecutiveRequired {
		t.Fatalf("candidate count=%d", got)
	}
}
