package main

import (
	"testing"
	"time"
)

func TestBuildNSDependencyStateCountsDistinctAffectedZones(t *testing.T) {
	snapshot := NSOwnershipSnapshot{ID: "snapshot", CapturedAt: time.Unix(1000, 0), View: "default"}
	observations := map[string][]NSHostObservation{
		"a.example.": {{Name: "ns1.provider.net.", RegisteredDomain: "provider.net", Addresses: []NSAddress{{Address: "192.0.2.1", ASN: 64500, ASNOrganization: "Example Network", Country: "CN", MetadataAvailable: true}}}},
		"b.example.": {{Name: "ns1.provider.net.", RegisteredDomain: "provider.net", Addresses: []NSAddress{{Address: "192.0.2.1", ASN: 64500, ASNOrganization: "Example Network", Country: "CN", MetadataAvailable: true}}}},
		"c.example.": {{Name: "ns2.other.net.", RegisteredDomain: "other.net"}},
	}
	state := buildNSDependencyState(snapshot, observations)
	if state.totalZones != 3 || len(state.hosts) != 2 {
		t.Fatalf("state=%#v", state)
	}
	host := dependencyHostFromAggregate("ns1.provider.net.", state.hosts["ns1.provider.net."], 8)
	if host.ZoneCount != 2 || host.Owner != "provider.net." || len(host.Addresses) != 1 || host.ASNs[0] != "AS64500" || host.Countries[0] != "CN" || host.MetadataCoverage != 1 {
		t.Fatalf("host=%#v", host)
	}
	if len(state.zoneHosts["a.example."]) != 1 || len(state.zoneHosts["b.example."]) != 1 {
		t.Fatalf("zone hosts=%#v", state.zoneHosts)
	}
}

func TestFilterNSDependencyHostsMatchesZoneAndMetadata(t *testing.T) {
	state := buildNSDependencyState(NSOwnershipSnapshot{}, map[string][]NSHostObservation{
		"important.example.": {{Name: "ns1.provider.net.", RegisteredDomain: "provider.net", Addresses: []NSAddress{{Address: "192.0.2.1", ASNOrganization: "Example Network", Country: "US", MetadataAvailable: true}}}},
	})
	for _, query := range []string{"important.example", "provider.net", "example network", "US"} {
		hosts := filterNSDependencyHosts(state, query, 10)
		if len(hosts) != 1 || hosts[0].Host != "ns1.provider.net." {
			t.Fatalf("query=%q hosts=%#v", query, hosts)
		}
	}
}
