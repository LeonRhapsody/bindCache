package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"testing"
	"time"
)

func TestCampaignSchemaOnClickHouse(t *testing.T) {
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
	for _, table := range []string{"dns_campaign_events", "ns_campaign_holds"} {
		var count uint64
		if err := db.QueryRow("SELECT count() FROM system.tables WHERE database=currentDatabase() AND name=?", table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("table %s missing", table)
		}
	}
}

func TestProductionCampaignAPIReadsRealEvents(t *testing.T) {
	dsn := os.Getenv("TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("TEST_CLICKHOUSE_DSN not set")
	}
	db, err := OpenNSClickHouseReadDatabase(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &nsPersistentMonitorServer{store: &nsPersistentStore{db: db}}
	recorder := httptest.NewRecorder()
	server.v1Campaigns(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/campaigns?limit=200", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response dnsCampaignsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	t.Logf("campaign API returned %d real events", response.Total)
	counts := map[string]int{}
	zones := map[string]struct{}{}
	for _, item := range response.Items {
		if isFirstIPObservationCampaign(item) {
			t.Fatalf("API returned first-observation noise event %s", item.ID)
		}
		counts[item.Type]++
		for _, zone := range item.Zones {
			zones[zone] = struct{}{}
		}
	}
	t.Logf("real event types=%v, distinct held zones=%d", counts, len(zones))
	if response.Total == 0 {
		t.Fatal("expected persisted real campaign events")
	}
	invalidIDs, err := loadFirstIPObservationCampaignIDs(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := invalidIDs["CAM-0d88fd5209c0d2af"]; !ok {
		t.Fatal("expected screenshot event to be classified as first-observation noise")
	}
}

func TestProductionNSOwnershipAPIReadsRealSnapshots(t *testing.T) {
	dsn := os.Getenv("TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("TEST_CLICKHOUSE_DSN not set")
	}
	db, err := OpenNSClickHouseReadDatabase(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &nsPersistentMonitorServer{store: &nsPersistentStore{db: db}}
	recorder := httptest.NewRecorder()
	server.v1NSOwnership(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/ns-ownership?limit=300", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response NSOwnershipResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Current.ID == "" || len(response.Owners) == 0 {
		t.Fatalf("ownership API returned no real snapshot/owners: %#v", response)
	}
	t.Logf("ownership snapshot=%s previous=%v owners=%d selected=%s edges=%d/%d", response.Current.ID, response.Previous != nil, len(response.Owners), response.SelectedOwner, len(response.Edges), response.TotalEdges)
	if server.ownershipCache != nil && server.ownershipCache.previous != nil {
		events := detectDNSCampaigns(*server.ownershipCache.previous, server.ownershipCache.current, GlobalConfig.Campaign.MinDistinctZones)
		t.Logf("real adjacent snapshot NS campaign hits=%d", len(events))
		for _, event := range events {
			t.Logf("%s target=%s zones=%d changes=%d", event.Type, event.Target, event.ZoneCount, len(event.Changes))
		}
	}
	started := time.Now()
	recorder = httptest.NewRecorder()
	server.v1NSOwnership(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/ns-ownership?limit=300&owner="+response.Owners[len(response.Owners)-1].Owner, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("cached status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("cached owner switch took %s", elapsed)
	} else {
		t.Logf("cached owner switch=%s", elapsed.Round(time.Millisecond))
	}
}

func TestReplayLatestProductionNSSnapshotsForCampaigns(t *testing.T) {
	dsn := os.Getenv("TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("TEST_CLICKHOUSE_DSN not set")
	}
	db, err := OpenNSClickHouseReadDatabase(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	type catalog struct {
		id, view string
		captured time.Time
	}
	rows, err := db.Query(`SELECT snapshot_id, view, captured_at FROM ns_snapshot_catalog FINAL ORDER BY captured_at DESC LIMIT 2`)
	if err != nil {
		t.Fatal(err)
	}
	var latest []catalog
	for rows.Next() {
		var value catalog
		if err := rows.Scan(&value.id, &value.view, &value.captured); err != nil {
			t.Fatal(err)
		}
		latest = append(latest, value)
	}
	_ = rows.Close()
	if len(latest) < 2 {
		t.Skipf("only %d persisted snapshots", len(latest))
	}
	states := make([]campaignSnapshotState, 2)
	for i, value := range latest {
		state := campaignSnapshotState{Version: 1, SnapshotID: value.id, CapturedAt: value.captured, View: value.view, NS: map[string]map[string][]string{}, A: map[string][]string{}}
		obsRows, err := db.Query(`SELECT domain,nameservers_json FROM ns_domain_observations FINAL WHERE snapshot_id=?`, value.id)
		if err != nil {
			t.Fatal(err)
		}
		for obsRows.Next() {
			var domain, raw string
			if err := obsRows.Scan(&domain, &raw); err != nil {
				t.Fatal(err)
			}
			var hosts []NSHostObservation
			if err := json.Unmarshal([]byte(raw), &hosts); err != nil {
				t.Fatal(err)
			}
			state.NS[normalizeFQDN(domain)] = map[string][]string{}
			for _, host := range hosts {
				for _, address := range host.Addresses {
					state.NS[normalizeFQDN(domain)][normalizeFQDN(host.Name)] = append(state.NS[normalizeFQDN(domain)][normalizeFQDN(host.Name)], address.Address)
				}
			}
		}
		_ = obsRows.Close()
		states[i] = state
	}
	events := detectDNSCampaigns(states[1], states[0], GlobalConfig.Campaign.MinDistinctZones)
	t.Logf("real snapshots %s -> %s, zones %d -> %d, NS campaign hits %d", states[1].CapturedAt.Format(time.RFC3339), states[0].CapturedAt.Format(time.RFC3339), len(states[1].NS), len(states[0].NS), len(events))
	for _, event := range events {
		t.Logf("%s target=%s zones=%d", event.Type, event.Target, event.ZoneCount)
	}
}

func TestBackfillLatestProductionCampaigns(t *testing.T) {
	if os.Getenv("TEST_CAMPAIGN_BACKFILL") != "1" {
		t.Skip("TEST_CAMPAIGN_BACKFILL not set")
	}
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
	writer, err := openNSClickHouseWriter(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	events, err := backfillLatestNSCampaignsIfEmpty(db, writer, DefaultAppConfig().Campaign)
	if err != nil {
		t.Fatal(err)
	}
	var persisted uint64
	if err := db.QueryRow(`SELECT count() FROM dns_campaign_events FINAL`).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	t.Logf("new real campaign events=%d, persisted=%d", len(events), persisted)
	if persisted == 0 {
		t.Fatal("expected real campaign events from latest snapshots")
	}
}

func TestFiveMinuteProductionProbeCapacity(t *testing.T) {
	if os.Getenv("TEST_PROBE_CAPACITY") != "1" {
		t.Skip("TEST_PROBE_CAPACITY not set")
	}
	dsn := os.Getenv("TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("TEST_CLICKHOUSE_DSN not set")
	}
	db, err := OpenNSClickHouseReadDatabase(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, _, events, err := loadNSAnalysisState(db)
	if err != nil {
		t.Fatal(err)
	}
	var latest time.Time
	for _, event := range events {
		if event.LastSeen.After(latest) {
			latest = event.LastSeen
		}
	}
	candidates := make([]NSChangeEvent, 0)
	for _, event := range events {
		if event.Status != "resolved" && event.LastSeen.Equal(latest) {
			candidates = append(candidates, event)
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		left, right := riskRank(candidates[i].Severity), riskRank(candidates[j].Severity)
		if left == right {
			return candidates[i].FirstSeen.Before(candidates[j].FirstSeen)
		}
		return left > right
	})
	budget := 5 * time.Minute
	started := time.Now()
	deadline := started.Add(budget)
	attempted, withDNS, totalDNS := 0, 0, 0
	verdicts := map[string]int{}
	config := DefaultNSProbeConfig()
	config.MaxParallel = 12
	config.MaxDomains = 20
	emptyCache := &BindCache{records: map[string]Record{}}
	for _, event := range candidates {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		timeout := config.EventTimeout
		if remaining < timeout {
			timeout = remaining
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		result, probeErr := ProbeNSEvent(ctx, event, "capacity-read-only", emptyCache, config)
		cancel()
		attempted++
		if probeErr != nil {
			verdicts["error"]++
			continue
		}
		verdicts[result.Verdict]++
		if result.ProbedDomains > 0 {
			withDNS++
			stable, variant := nsProbeStableAndVariantHosts(event)
			tasks := len(config.TrustedResolvers) + 1
			for _, host := range append(stable, variant...) {
				tasks += len(host.addresses)
			}
			totalDNS += tasks
		}
	}
	t.Logf("latest=%s candidates=%d budget=%s elapsed=%s parallel=%d attempted=%d with_dns=%d estimated_dns_tasks=%d verdicts=%v", latest.Format(time.RFC3339), len(candidates), budget, time.Since(started).Round(time.Millisecond), config.MaxParallel, attempted, withDNS, totalDNS, verdicts)
}

func TestProductionProbeQuotaProfile(t *testing.T) {
	dsn := os.Getenv("TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("TEST_CLICKHOUSE_DSN not set")
	}
	db, err := OpenNSClickHouseReadDatabase(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, _, events, err := loadNSAnalysisState(db)
	if err != nil {
		t.Fatal(err)
	}
	var latest time.Time
	for _, event := range events {
		if event.LastSeen.After(latest) {
			latest = event.LastSeen
		}
	}
	candidates := make([]NSChangeEvent, 0)
	for _, event := range events {
		if event.Status != "resolved" && event.LastSeen.Equal(latest) {
			candidates = append(candidates, event)
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		left, right := riskRank(candidates[i].Severity), riskRank(candidates[j].Severity)
		if left == right {
			return candidates[i].FirstSeen.Before(candidates[j].FirstSeen)
		}
		return left > right
	})
	for _, limit := range []int{50, 100, 200, 300, 500, len(candidates)} {
		if limit > len(candidates) {
			continue
		}
		actionable, tasks := 0, 0
		for _, event := range candidates[:limit] {
			stable, variant := nsProbeStableAndVariantHosts(event)
			if len(stable) < 2 || len(variant) == 0 {
				continue
			}
			actionable++
			count := 3
			for _, host := range append(stable, variant...) {
				count += len(host.addresses)
			}
			tasks += count
		}
		t.Logf("quota=%d actionable=%d minimum_dns_tasks=%d", limit, actionable, tasks)
	}
}

func TestInspectProductionProbeEvent(t *testing.T) {
	id := os.Getenv("TEST_EVENT_ID")
	dsn := os.Getenv("TEST_CLICKHOUSE_DSN")
	if id == "" || dsn == "" {
		t.Skip("TEST_EVENT_ID/TEST_CLICKHOUSE_DSN not set")
	}
	db, err := OpenNSClickHouseReadDatabase(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := &nsPersistentStore{db: db}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	event, err := store.eventByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := store.latestEventProbe(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("event domain=%s severity=%s evidence=%s status=%s summary=%s", event.Domain, event.Severity, event.Evidence, event.Status, event.Summary)
	t.Logf("probe verdict=%s summary=%s domains=%d", probe.Verdict, probe.Summary, len(probe.Domains))
	for _, domain := range probe.Domains {
		if domain.StableConsensus != nil {
			t.Logf("domain=%s stable signature=%s A=%v AAAA=%v CNAME=%v NS=%v", domain.Domain, nsProbeSignature(*domain.StableConsensus), domain.StableConsensus.IPv4, domain.StableConsensus.IPv6, domain.StableConsensus.CNAME, domain.StableConsensus.NS)
		}
		if domain.TrustedConsensus != nil {
			t.Logf("trusted signature=%s A=%v AAAA=%v CNAME=%v NS=%v", nsProbeSignature(*domain.TrustedConsensus), domain.TrustedConsensus.IPv4, domain.TrustedConsensus.IPv6, domain.TrustedConsensus.CNAME, domain.TrustedConsensus.NS)
		}
		t.Logf("recursive signature=%s A=%v AAAA=%v CNAME=%v NS=%v error=%q", nsProbeSignature(domain.RecursiveResult), domain.RecursiveResult.IPv4, domain.RecursiveResult.IPv6, domain.RecursiveResult.CNAME, domain.RecursiveResult.NS, domain.RecursiveResult.Error)
		for _, host := range append(domain.StableNS, domain.VariantNS...) {
			if host.Effective == nil {
				t.Logf("host=%s role=%s effective=nil answers=%d", host.Host, host.Role, len(host.Answers))
				continue
			}
			t.Logf("host=%s role=%s matches=%v signature=%s A=%v AAAA=%v CNAME=%v NS=%v", host.Host, host.Role, host.MatchesStable, nsProbeSignature(*host.Effective), host.Effective.IPv4, host.Effective.IPv6, host.Effective.CNAME, host.Effective.NS)
		}
	}
	item := eventToV1(event, 1)
	applyProbeToV1(&item, probe)
	foundAuthorityOnly := false
	for _, row := range item.Probes {
		if row.Domain != "us4-files.zohopublic.com." || row.Role != "variant" {
			continue
		}
		changed := []nsV1ProbeFieldDiff{}
		for _, diff := range row.Differences {
			if diff.Changed {
				changed = append(changed, diff)
			}
		}
		if len(changed) == 1 && changed[0].Field == "authority_ns" {
			foundAuthorityOnly = true
		}
	}
	if !foundAuthorityOnly {
		t.Fatal("v1 API did not expose authority-only difference for variant host")
	}
}
