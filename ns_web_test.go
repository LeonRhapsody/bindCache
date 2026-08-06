package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNSMonitorHTTPAPI(t *testing.T) {
	first := time.Date(2026, 7, 28, 9, 0, 0, 0, time.UTC)
	baseline := newNSCache(map[string][]string{"api.example.": {"ns1.stable.example.net."}}, map[string]string{"ns1.stable.example.net.": "1.1.1.1"})
	changed := newNSCache(map[string][]string{"api.example.": {"ns1.stable.example.net.", "ns1.evil-example.org."}}, map[string]string{"ns1.stable.example.net.": "1.1.1.1", "ns1.evil-example.org.": "8.8.8.8"})
	snapshots := repeatedNSCacheSnapshots("api-baseline", first, int(NSBaselineConsecutiveRequired), baseline)
	snapshots = append(snapshots, namedCacheSnapshot{Source: "api-changed.db", CapturedAt: first.Add(12 * 10 * time.Minute), Cache: changed})
	analysis := AnalyzeNSCaches(snapshots, nil)
	server := &nsMonitorServer{analysis: analysis}

	t.Run("overview", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		server.overview(recorder, httptest.NewRequest(http.MethodGet, "/api/ns/overview", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
		}
		var response nsOverviewResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Overview.TrackedDomains != 1 || len(response.Snapshots) != int(NSBaselineConsecutiveRequired)+1 {
			t.Fatalf("unexpected overview %#v", response)
		}
	})

	t.Run("events return summaries", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		server.events(recorder, httptest.NewRequest(http.MethodGet, "/api/ns/events?severity=high", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
		}
		var response nsEventsResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Total != 1 || response.Events[0].Domain != "api.example." || response.Events[0].Severity != "high" {
			t.Fatalf("unexpected events %#v", response)
		}
	})

	t.Run("domain", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		server.domain(recorder, httptest.NewRequest(http.MethodGet, "/api/ns/domain?domain=api.example", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
		}
		var detail DomainNSDetail
		if err := json.Unmarshal(recorder.Body.Bytes(), &detail); err != nil {
			t.Fatal(err)
		}
		if len(detail.Current.Nameservers) != 2 || len(detail.Events) != 1 {
			t.Fatalf("unexpected detail %#v", detail)
		}
	})

	t.Run("v1 events normalize lifecycle", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		server.v1Events(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/events?type=ns_change&page=1&limit=20", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
		}
		var response nsV1EventsResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Total != 1 || len(response.Items) != 1 {
			t.Fatalf("unexpected v1 events %#v", response)
		}
		item := response.Items[0]
		if item.Type != "ns_change" || item.Status != "pending" || item.Evidence != "pending_verify" || item.Domain != "api.example." {
			t.Fatalf("unexpected normalized event %#v", item)
		}
	})

	t.Run("v1 pending verification evidence filter", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		server.v1Events(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/events?evidence=pending_verify", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
		}
		var response nsV1EventsResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Total != 1 || len(response.Items) != 1 || response.Items[0].Evidence != "pending_verify" {
			t.Fatalf("unexpected evidence response %#v", response)
		}
	})

	t.Run("v1 domains use stable path", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		server.v1Domains(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/domains?q=api", nil))
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "api.example.") {
			t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("v1 event probe exists in memory mode", func(t *testing.T) {
		eventID := analysis.Events[0].ID
		recorder := httptest.NewRecorder()
		server.v1EventDetail(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/events/"+eventID+"/probe", nil))
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"available":false`) {
			t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("v1 event detail contains baseline current and timeline", func(t *testing.T) {
		eventID := analysis.Events[0].ID
		recorder := httptest.NewRecorder()
		server.v1EventDetail(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/events/"+eventID, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
		}
		var response nsV1RiskEvent
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if len(response.BaselineNS) != 1 || len(response.CurrentNS) != 2 || len(response.Timeline) == 0 {
			t.Fatalf("unexpected detail %#v", response)
		}
	})

	t.Run("v1 overview uses production contract", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		server.v1Overview(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
		}
		var response nsV1OverviewResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Mode != "memory" || response.KPIs.BaselineDomains != 1 || len(response.RecentEvents) != 1 {
			t.Fatalf("unexpected overview %#v", response)
		}
	})
}

func TestApplyProbeToV1PreservesDomainRoleAndUnknownStates(t *testing.T) {
	matches := false
	probe := NSProbeResult{
		Verdict: "inconclusive",
		Summary: "稳定侧证据不足",
		Domains: []NSProbeDomainResult{{
			Domain:   "api.example.",
			StableNS: []NSProbeHostResult{{Host: "ns1.example.", Role: "stable"}},
			VariantNS: []NSProbeHostResult{{
				Host: "ns2.example.", Role: "variant",
				Effective:     &DNSProbeAnswer{IPv4: []string{"192.0.2.20"}, DurationMS: 12},
				MatchesStable: &matches,
			}},
		}},
	}
	item := nsV1RiskEvent{}
	applyProbeToV1(&item, &probe)
	if item.ProbeVerdict != "inconclusive" || item.ProbeSummary != "稳定侧证据不足" || len(item.Probes) != 2 {
		t.Fatalf("unexpected probe summary %#v", item)
	}
	stable := item.Probes[0]
	if stable.Domain != "api.example." || stable.Role != "stable" || stable.Reachable != nil || stable.AnswerConsistent != nil {
		t.Fatalf("unknown stable result collapsed into failure: %#v", stable)
	}
	variant := item.Probes[1]
	if variant.Domain != "api.example." || variant.Role != "variant" || variant.Reachable == nil || !*variant.Reachable || variant.AnswerConsistent == nil || *variant.AnswerConsistent {
		t.Fatalf("unexpected variant result %#v", variant)
	}
}

func TestNSMonitorRecordEndpointLoadsAndCachesOneDomain(t *testing.T) {
	analysis, err := AnalyzeNSFiles([]string{"testdata/ns-baseline.dump"}, nil)
	if err != nil {
		t.Fatalf("analyze demo snapshot: %v", err)
	}
	server := &nsMonitorServer{analysis: analysis, recordCache: make(map[string]nsSnapshotRecordResponse)}
	path := fmt.Sprintf("/api/ns/record?domain=example.test&snapshot_id=%s", analysis.Snapshots[0].ID)

	for attempt := 0; attempt < 2; attempt++ {
		recorder := httptest.NewRecorder()
		server.record(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("attempt %d status = %d, body = %s", attempt, recorder.Code, recorder.Body.String())
		}
		var response nsSnapshotRecordResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Domain != "example.test." || response.RecordKind != "positive" || len(response.NSObservation) != 2 || len(response.NSObservation[0].Addresses) == 0 || len(response.Groups) == 0 || response.Groups[0].Type != "NS" || response.Groups[0].Count != 2 {
			t.Fatalf("unexpected record response %#v", response)
		}
	}
	if len(server.recordCache) != 1 {
		t.Fatalf("record cache entries = %d, want 1", len(server.recordCache))
	}

	analysis.Events = []NSChangeEvent{{ID: "rr-event", Domain: "example.test."}}
	recorder := httptest.NewRecorder()
	v1Path := fmt.Sprintf("/api/v1/events/rr-event/rr?snapshot_id=%s", analysis.Snapshots[0].ID)
	server.v1EventDetail(recorder, httptest.NewRequest(http.MethodGet, v1Path, nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"domain":"example.test."`) {
		t.Fatalf("v1 rr status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestNSMonitorIndexSupportsBrowserHistoryRoutes(t *testing.T) {
	servers := []struct {
		name  string
		index http.HandlerFunc
	}{
		{name: "memory", index: (&nsMonitorServer{}).index},
		{name: "persistent", index: (&nsPersistentMonitorServer{}).index},
	}
	for _, server := range servers {
		t.Run(server.name, func(t *testing.T) {
			for _, path := range []string{"/", "/overview", "/events", "/domain", "/probe", "/alerts", "/system", "/settings", "/ns-change", "/ns-redundancy", "/ns-parent-child", "/ns-blacklist", "/event/EVT-1", "/domain/example.test"} {
				recorder := httptest.NewRecorder()
				server.index(recorder, httptest.NewRequest(http.MethodGet, path, nil))
				if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "递归DNS风险监测平台") {
					t.Fatalf("route %s status=%d", path, recorder.Code)
				}
			}
			recorder := httptest.NewRecorder()
			server.index(recorder, httptest.NewRequest(http.MethodGet, "/not-found", nil))
			if recorder.Code != http.StatusNotFound {
				t.Fatalf("unexpected route status=%d", recorder.Code)
			}
		})
	}
}

func TestNSMonitorServesEmbeddedFrontendAssets(t *testing.T) {
	entries, err := nsMonitorAssets.ReadDir("frontend/dist/assets")
	if err != nil || len(entries) == 0 {
		t.Fatalf("embedded frontend assets: entries=%d err=%v", len(entries), err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		recorder := httptest.NewRecorder()
		serveNSMonitorFrontend(recorder, httptest.NewRequest(http.MethodGet, "/assets/"+entry.Name(), nil))
		if recorder.Code != http.StatusOK || recorder.Body.Len() == 0 {
			t.Fatalf("asset %s status=%d size=%d", entry.Name(), recorder.Code, recorder.Body.Len())
		}
		if recorder.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
			t.Fatalf("asset %s cache-control=%q", entry.Name(), recorder.Header().Get("Cache-Control"))
		}
	}
}

func TestBuildNSRRGroupsPlacesNSFirst(t *testing.T) {
	groups := buildNSRRGroups(Record{
		NSs:   []NS{{NsDomain: "ns1.example.net."}},
		As:    []A{{IP: "192.0.2.1"}},
		AAAAs: []AAAA{{IP: "2001:db8::1"}},
		TXTs:  []TXT{{Content: "hello"}},
	})
	if len(groups) != 4 || groups[0].Type != "NS" || groups[1].Type != "A" || groups[2].Type != "AAAA" || groups[3].Type != "TXT" {
		t.Fatalf("unexpected group order %#v", groups)
	}
}
