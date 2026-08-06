package main

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

type staticIPMetadata map[string]IPMetadata

func (m staticIPMetadata) LookupIP(addr netip.Addr) IPMetadata {
	meta := m[addr.String()]
	meta.Available = meta.ASN != 0 || meta.Country != ""
	return meta
}

func TestAnalyzeNSCachesClassifiesOwnerAndNetworkChanges(t *testing.T) {
	geo := staticIPMetadata{
		"1.1.1.1": {ASN: 13335, Country: "AU"},
		"1.0.0.1": {ASN: 13335, Country: "AU"},
		"8.8.8.8": {ASN: 15169, Country: "US"},
	}
	first := time.Date(2026, 7, 28, 9, 0, 0, 0, time.FixedZone("CST", 8*3600))
	second := first.Add(10 * time.Minute)
	baseline := newNSCache(map[string][]string{
		"owner.example.":   {"ns1.stable.example.net."},
		"network.example.": {"ns1.network.example.net."},
		"same.example.":    {"ns1.same.example.net."},
	}, map[string]string{
		"ns1.stable.example.net.":  "1.1.1.1",
		"ns1.network.example.net.": "1.1.1.1",
		"ns1.same.example.net.":    "1.1.1.1",
	})
	changed := newNSCache(map[string][]string{
		"owner.example.":   {"ns1.stable.example.net.", "ns1.evil-example.org."},
		"network.example.": {"ns1.network.example.net."},
		"same.example.":    {"ns1.same.example.net."},
	}, map[string]string{
		"ns1.stable.example.net.":  "1.1.1.1",
		"ns1.evil-example.org.":    "8.8.8.8",
		"ns1.network.example.net.": "8.8.8.8",
		"ns1.same.example.net.":    "1.0.0.1",
	})

	snapshots := repeatedNSCacheSnapshots("baseline", first, int(NSBaselineConsecutiveRequired), baseline)
	snapshots = append(snapshots, namedCacheSnapshot{Source: "changed.db", CapturedAt: second.Add(11 * 10 * time.Minute), Cache: changed})
	analysis := AnalyzeNSCaches(snapshots, geo)
	events := eventsByDomain(analysis.Events)

	assertEventSeverity(t, events, "owner.example.", "high")
	assertEventChange(t, events["owner.example."], "ns_owner_changed")
	assertEventSeverity(t, events, "network.example.", "high")
	assertEventChange(t, events["network.example."], "ns_network_changed")
	assertEventSeverity(t, events, "same.example.", "low")
	assertEventChange(t, events["same.example."], "ns_ip_changed")
}

func TestAnalyzeNSCachesMarksReservedNSAddressCritical(t *testing.T) {
	first := time.Date(2026, 7, 28, 9, 0, 0, 0, time.UTC)
	baseline := newNSCache(map[string][]string{"private.example.": {"ns1.stable.example.net."}}, map[string]string{"ns1.stable.example.net.": "1.1.1.1"})
	changed := newNSCache(map[string][]string{"private.example.": {"ns1.stable.example.net.", "ns1.private.evil.org."}}, map[string]string{"ns1.stable.example.net.": "1.1.1.1", "ns1.private.evil.org.": "10.0.0.53"})

	snapshots := repeatedNSCacheSnapshots("baseline", first, int(NSBaselineConsecutiveRequired), baseline)
	snapshots = append(snapshots, namedCacheSnapshot{Source: "changed.db", CapturedAt: first.Add(12 * 10 * time.Minute), Cache: changed})
	analysis := AnalyzeNSCaches(snapshots, nil)
	events := eventsByDomain(analysis.Events)
	assertEventSeverity(t, events, "private.example.", "critical")
	assertEventChange(t, events["private.example."], "reserved_ns_ip")
}

func TestAddressFamilyReductionIsLowRiskChange(t *testing.T) {
	baseline := DomainNSObservation{Nameservers: []NSHostObservation{{Name: "ns.example.", Addresses: []NSAddress{
		{Address: "156.154.67.90", ASN: 12008, Country: "US"},
		{Address: "2001:502:4612::7e", ASN: 12008, Country: "US"},
	}}}}
	current := DomainNSObservation{Nameservers: []NSHostObservation{{Name: "ns.example.", Addresses: []NSAddress{
		{Address: "156.154.67.90", ASN: 12008, Country: "US"},
	}}}}
	diff := compareNSObservations(baseline, current)
	if !diff.changed || diff.severity != "low" {
		t.Fatalf("unexpected family-reduction diff: %#v", diff)
	}
	found := false
	for _, change := range diff.changeTypes {
		found = found || change == "ns_address_family_reduced"
		if change == "ns_ip_changed" {
			t.Fatalf("family reduction must not be presented as generic IP replacement: %#v", diff.changeTypes)
		}
	}
	if !found {
		t.Fatalf("missing address-family reduction marker: %#v", diff.changeTypes)
	}
}

func TestAnalyzeNSCachesRecordsEventLifecycleAndRecovery(t *testing.T) {
	first := time.Date(2026, 7, 28, 9, 0, 0, 0, time.UTC)
	baseline := newNSCache(map[string][]string{"lifecycle.example.": {"ns1.stable.example.net."}}, map[string]string{"ns1.stable.example.net.": "1.1.1.1"})
	changed := newNSCache(map[string][]string{"lifecycle.example.": {"ns1.stable.example.net.", "ns1.evil-example.org."}}, map[string]string{"ns1.stable.example.net.": "1.1.1.1", "ns1.evil-example.org.": "8.8.8.8"})
	restored := newNSCache(map[string][]string{"lifecycle.example.": {"ns1.stable.example.net."}}, map[string]string{"ns1.stable.example.net.": "1.1.1.1"})
	changedAt := first.Add(12 * 10 * time.Minute)
	recoveredAt := changedAt.Add(10 * time.Minute)
	snapshots := repeatedNSCacheSnapshots("baseline", first, int(NSBaselineConsecutiveRequired), baseline)
	snapshots = append(snapshots,
		namedCacheSnapshot{Source: "changed.db", CapturedAt: changedAt, Cache: changed},
		namedCacheSnapshot{Source: "restored.db", CapturedAt: recoveredAt, Cache: restored},
	)
	analysis := AnalyzeNSCaches(snapshots, nil)
	event := eventsByDomain(analysis.Events)["lifecycle.example."]
	if event.Status != "resolved" || event.ResolvedAt == nil || !event.ResolvedAt.Equal(recoveredAt) {
		t.Fatalf("unexpected lifecycle status: %#v", event)
	}
	if !event.LastSeen.Equal(changedAt) {
		t.Fatalf("last risk observation = %s, want %s", event.LastSeen, changedAt)
	}
	points := analysis.Timeline["lifecycle.example."]
	if len(points) != 3 || points[0].State != "baseline" || points[1].State != "event_started" || points[2].State != "event_resolved" {
		t.Fatalf("unexpected timeline %#v", points)
	}
}

func TestNSBaselineRequiresTwelveConsecutiveObservations(t *testing.T) {
	first := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	cache := newNSCache(map[string][]string{"learning.example.": {"ns1.learning.example."}}, map[string]string{"ns1.learning.example.": "1.1.1.1"})
	beforeConfirmation := AnalyzeNSCaches(repeatedNSCacheSnapshots("learning", first, int(NSBaselineConsecutiveRequired)-1, cache), nil)
	if _, exists := beforeConfirmation.Baseline["learning.example."]; exists {
		t.Fatal("baseline must not exist before the 12th same observation")
	}
	state := beforeConfirmation.baselineStates["learning.example."]
	if state.Confirmed || state.ConsecutiveCount != NSBaselineConsecutiveRequired-1 {
		t.Fatalf("unexpected candidate state %#v", state)
	}

	confirmed := AnalyzeNSCaches(repeatedNSCacheSnapshots("learning", first, int(NSBaselineConsecutiveRequired), cache), nil)
	baseline, exists := confirmed.Baseline["learning.example."]
	if !exists || baseline.Fingerprint == "" {
		t.Fatalf("baseline not established on 12th observation: %#v", confirmed.Baseline)
	}
	state = confirmed.baselineStates["learning.example."]
	if !state.Confirmed || state.ConsecutiveCount != 0 {
		t.Fatalf("unexpected confirmed state %#v", state)
	}
}

func TestNSBaselineCandidateIgnoresAbsentSnapshot(t *testing.T) {
	first := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	cache := newNSCache(map[string][]string{"sporadic.example.": {"ns1.sporadic.example."}}, map[string]string{"ns1.sporadic.example.": "1.1.1.1"})
	empty := newNSCache(nil, nil)
	snapshots := repeatedNSCacheSnapshots("sporadic", first, 6, cache)
	snapshots = append(snapshots, namedCacheSnapshot{Source: "absent.db", CapturedAt: first.Add(6 * 10 * time.Minute), Cache: empty})
	for index := 0; index < 6; index++ {
		snapshots = append(snapshots, namedCacheSnapshot{Source: fmt.Sprintf("sporadic-after-%02d.db", index), CapturedAt: first.Add(time.Duration(index+7) * 10 * time.Minute), Cache: cache})
	}
	analysis := AnalyzeNSCaches(snapshots, nil)
	if _, exists := analysis.Baseline["sporadic.example."]; !exists {
		t.Fatal("an absent cache snapshot must not reset the 12-observation candidate")
	}
}

func TestNSBaselineRollsAfterTwelveConsecutiveChanges(t *testing.T) {
	first := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	stable := newNSCache(map[string][]string{"roll.example.": {"ns1.old.example."}}, map[string]string{"ns1.old.example.": "1.1.1.1"})
	replacement := newNSCache(map[string][]string{"roll.example.": {"ns1.new.example."}}, map[string]string{"ns1.new.example.": "2.2.2.2"})
	snapshots := repeatedNSCacheSnapshots("stable", first, int(NSBaselineConsecutiveRequired), stable)
	for index := 0; index < int(NSBaselineConsecutiveRequired)-1; index++ {
		snapshots = append(snapshots, namedCacheSnapshot{Source: fmt.Sprintf("replacement-%02d.db", index), CapturedAt: first.Add(time.Duration(index+12) * 10 * time.Minute), Cache: replacement})
	}
	beforeRoll := AnalyzeNSCaches(snapshots, nil)
	if baseline := beforeRoll.Baseline["roll.example."]; baseline.Nameservers[0].Name != "ns1.old.example." {
		t.Fatalf("baseline rolled too early: %#v", baseline)
	}
	if event := eventsByDomain(beforeRoll.Events)["roll.example."]; event.Status == "resolved" {
		t.Fatalf("event resolved before 12 replacement observations: %#v", event)
	}

	snapshots = append(snapshots, namedCacheSnapshot{Source: "replacement-12.db", CapturedAt: first.Add(23 * 10 * time.Minute), Cache: replacement})
	afterRoll := AnalyzeNSCaches(snapshots, nil)
	if baseline := afterRoll.Baseline["roll.example."]; baseline.Nameservers[0].Name != "ns1.new.example." {
		t.Fatalf("baseline was not rolled after 12 replacement observations: %#v", baseline)
	}
	event := eventsByDomain(afterRoll.Events)["roll.example."]
	if event.Status != "resolved" || event.ResolvedAt == nil {
		t.Fatalf("rolling update must retain and close event audit record: %#v", event)
	}
	points := afterRoll.Timeline["roll.example."]
	if len(points) == 0 || points[len(points)-1].State != "baseline_rolled" {
		t.Fatalf("missing baseline roll timeline point: %#v", points)
	}
}

func TestIPv4ZeroPrefixIncludesHighAddress(t *testing.T) {
	ranges := make([]ipv4Range, 0, 1)
	appendRange(netip.MustParsePrefix("0.0.0.0/0"), IPMetadata{Country: "ZZ"}, &ranges, nil)
	if got := lookupIPv4Range(ranges, ipv4ToUint32(netip.MustParseAddr("255.255.255.255"))); got.Country != "ZZ" {
		t.Fatalf("/0 range did not cover highest IPv4 address: %#v", got)
	}
}

func TestDemoSnapshotsParseIntoExpectedEvents(t *testing.T) {
	analysis, err := AnalyzeNSFiles([]string{"testdata/ns-baseline.dump", "testdata/ns-changed.dump"}, nil)
	if err != nil {
		t.Fatalf("parse demo snapshots: %v", err)
	}
	if len(analysis.Events) != 0 || len(analysis.Baseline) != 0 {
		t.Fatalf("two snapshots must remain candidate-only: events=%d baseline=%d", len(analysis.Events), len(analysis.Baseline))
	}
}

func repeatedNSCacheSnapshots(prefix string, first time.Time, count int, cache *BindCache) []namedCacheSnapshot {
	snapshots := make([]namedCacheSnapshot, 0, count)
	for index := 0; index < count; index++ {
		snapshots = append(snapshots, namedCacheSnapshot{Source: fmt.Sprintf("%s-%02d.db", prefix, index), CapturedAt: first.Add(time.Duration(index) * 10 * time.Minute), Cache: cache})
	}
	return snapshots
}

func TestParseSnapshotTimeUsesBindDateAsUTC(t *testing.T) {
	got := parseSnapshotTime("20260727040001", "cache_dump_2026-07-27_12-00-01.db")
	want := time.Date(2026, 7, 27, 4, 0, 1, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("BIND $DATE should be UTC: got %s, want %s", got, want)
	}
}

func TestIncrementalAnalysisSkipsStableTimelineWrites(t *testing.T) {
	first := time.Date(2026, 7, 28, 4, 0, 0, 0, time.UTC)
	cache := newNSCache(map[string][]string{"stable.example.": {"ns1.stable.example.net."}}, map[string]string{"ns1.stable.example.net.": "1.1.1.1"})
	baseline := BuildNSObservations(cache, first, nil)["stable.example."]
	builder := newNSAnalysisBuilderWithState(nil, map[string]DomainNSObservation{"stable.example.": baseline}, map[string]NSBaselineState{
		"stable.example.": {Domain: "stable.example.", Confirmed: true},
	}, nil)
	builder.add(namedCacheSnapshot{Source: "next.db", CapturedAt: first.Add(10 * time.Minute), Cache: cache})
	if points := builder.result.Timeline["stable.example."]; len(points) != 0 {
		t.Fatalf("incremental stable timeline points = %#v, want none", points)
	}
}

func newNSCache(delegations map[string][]string, addresses map[string]string) *BindCache {
	cache := &BindCache{records: make(map[string]Record)}
	for domain, hosts := range delegations {
		record := cache.records[domain]
		for _, host := range hosts {
			record.NSs = append(record.NSs, NS{NsDomain: host, Attribute: "authauthority"})
		}
		cache.records[domain] = record
	}
	for host, address := range addresses {
		cache.records[host] = Record{As: []A{{IP: address}}}
	}
	return cache
}

func eventsByDomain(events []NSChangeEvent) map[string]NSChangeEvent {
	result := make(map[string]NSChangeEvent, len(events))
	for _, event := range events {
		result[event.Domain] = event
	}
	return result
}

func assertEventSeverity(t *testing.T, events map[string]NSChangeEvent, domain, want string) {
	t.Helper()
	event, ok := events[domain]
	if !ok {
		t.Fatalf("missing event for %s", domain)
	}
	if event.Severity != want {
		t.Fatalf("event %s severity = %q, want %q", domain, event.Severity, want)
	}
}

func assertEventChange(t *testing.T, event NSChangeEvent, want string) {
	t.Helper()
	for _, change := range event.ChangeTypes {
		if change == want {
			return
		}
	}
	t.Fatalf("event %s change types %#v do not include %q", event.Domain, event.ChangeTypes, want)
}
