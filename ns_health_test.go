package main

import (
	"testing"
	"time"
)

func TestBuildNSHealthResponseAggregatesEndpointAndZoneImpact(t *testing.T) {
	snapshot := NSOwnershipSnapshot{ID: "s2", View: "default", CapturedAt: time.Unix(2000, 0).UTC()}
	dependency := buildNSDependencyState(snapshot, map[string][]NSHostObservation{
		"a.example.": {
			{Name: "ns1.provider.net.", RegisteredDomain: "provider.net", Addresses: []NSAddress{{Address: "192.0.2.1"}}},
			{Name: "ns2.provider.net.", RegisteredDomain: "provider.net", Addresses: []NSAddress{{Address: "192.0.2.2"}}},
		},
		"b.example.": {
			{Name: "ns1.provider.net.", RegisteredDomain: "provider.net", Addresses: []NSAddress{{Address: "192.0.2.1"}}},
		},
		"c.example.": {
			{Name: "ns3.other.net.", RegisteredDomain: "other.net"},
		},
	})
	states := map[string]NSADBEndpointState{
		nsADBEndpointKey("default", "ns1.provider.net.", "192.0.2.1"): {
			View: "default", NSName: "ns1.provider.net.", IP: "192.0.2.1", SRTT: 800_000,
			PlainTimeout: 8, Health: nsADBHealthSuspect, ConsecutiveSuspect: 3, LastSeen: snapshot.CapturedAt,
		},
		nsADBEndpointKey("default", "ns2.provider.net.", "192.0.2.2"): {
			View: "default", NSName: "ns2.provider.net.", IP: "192.0.2.2", SRTT: 40_000,
			PlainSuccess: 5, Health: nsADBHealthHealthy, LastSeen: snapshot.CapturedAt,
		},
	}

	response := buildNSHealthResponse(dependency, states, 20)
	if response.Summary.TotalZones != 3 || response.Summary.HostsWithAddress != 2 || response.Summary.HostsWithADB != 2 {
		t.Fatalf("unexpected coverage summary: %#v", response.Summary)
	}
	if response.Summary.SuspectEndpoints != 1 || response.Summary.HealthyEndpoints != 1 {
		t.Fatalf("unexpected endpoint summary: %#v", response.Summary)
	}
	if response.Summary.AffectedZones != 2 || response.Summary.ReducedZones != 2 || response.Summary.UnavailableZones != 1 {
		t.Fatalf("unexpected zone impact: %#v", response.Summary)
	}
	if len(response.Endpoints) != 1 || response.Endpoints[0].AffectedZones != 2 || response.Endpoints[0].SoleDependency != 1 {
		t.Fatalf("unexpected endpoint ranking: %#v", response.Endpoints)
	}
	if len(response.Providers) != 1 || response.Providers[0].Owner != "provider.net." || response.Providers[0].AffectedZones != 2 {
		t.Fatalf("unexpected providers: %#v", response.Providers)
	}
}

func TestBuildNSHealthResponseDoesNotTreatSlowResponseAsUnavailable(t *testing.T) {
	snapshot := NSOwnershipSnapshot{ID: "s2", View: "default", CapturedAt: time.Unix(2000, 0).UTC()}
	dependency := buildNSDependencyState(snapshot, map[string][]NSHostObservation{
		"a.example.": {{Name: "ns1.provider.net.", Addresses: []NSAddress{{Address: "192.0.2.1"}}}},
	})
	states := map[string]NSADBEndpointState{
		nsADBEndpointKey("default", "ns1.provider.net.", "192.0.2.1"): {
			View: "default", NSName: "ns1.provider.net.", IP: "192.0.2.1", SRTT: 1_200_000,
			EDNSSuccess: 3, LastSeen: snapshot.CapturedAt,
		},
	}

	response := buildNSHealthResponse(dependency, states, 20)
	if response.Summary.DegradedEndpoints != 1 || response.Summary.AffectedZones != 1 {
		t.Fatalf("unexpected slow response summary: %#v", response.Summary)
	}
	if response.Summary.ReducedZones != 0 || response.Summary.UnavailableZones != 0 {
		t.Fatalf("slow response must not be reported as unavailable: %#v", response.Summary)
	}
}

func TestBuildNSHealthResponseIgnoresStaleADBState(t *testing.T) {
	snapshot := NSOwnershipSnapshot{ID: "s2", View: "default", CapturedAt: time.Unix(3600, 0).UTC()}
	dependency := buildNSDependencyState(snapshot, map[string][]NSHostObservation{
		"a.example.": {{Name: "ns1.provider.net.", Addresses: []NSAddress{{Address: "192.0.2.1"}}}},
	})
	states := map[string]NSADBEndpointState{
		nsADBEndpointKey("default", "ns1.provider.net.", "192.0.2.1"): {
			View: "default", NSName: "ns1.provider.net.", IP: "192.0.2.1", PlainTimeout: 9,
			LastSeen: snapshot.CapturedAt.Add(-30 * time.Minute),
		},
	}

	response := buildNSHealthResponse(dependency, states, 20)
	if response.Summary.HostsWithADB != 0 || response.Summary.TotalEndpoints != 0 || response.Summary.AffectedZones != 0 {
		t.Fatalf("stale ADB state must not affect the latest snapshot: %#v", response.Summary)
	}
}

func TestBuildNSHealthResponseDoesNotPromoteCumulativeTimeoutWithoutAdjacentEvidence(t *testing.T) {
	snapshot := NSOwnershipSnapshot{ID: "s2", View: "default", CapturedAt: time.Unix(3600, 0).UTC()}
	dependency := buildNSDependencyState(snapshot, map[string][]NSHostObservation{
		"a.example.": {{Name: "ns1.provider.net.", Addresses: []NSAddress{{Address: "192.0.2.1"}}}},
	})
	states := map[string]NSADBEndpointState{
		nsADBEndpointKey("default", "ns1.provider.net.", "192.0.2.1"): {
			View: "default", NSName: "ns1.provider.net.", IP: "192.0.2.1", EDNSTimeout4096: 4,
			LastSeen: snapshot.CapturedAt, ConsecutiveSuspect: 0,
		},
	}

	response := buildNSHealthResponse(dependency, states, 20)
	if response.Summary.SuspectEndpoints != 0 || response.Summary.UnknownEndpoints != 1 || response.Summary.AffectedZones != 0 {
		t.Fatalf("cumulative-only timeout must remain unknown: %#v", response.Summary)
	}
}
