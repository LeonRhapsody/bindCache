package main

import (
	"fmt"
	"testing"
	"time"
)

func TestBuildNSOwnershipResponseShowsMovesAndCrossDomain(t *testing.T) {
	previous := campaignSnapshotState{Version: 1, SnapshotID: "before", CapturedAt: time.Unix(1000, 0), View: "default", NS: map[string]map[string][]string{
		"moved.example.": {"ns1.huawei.com.": {"192.0.2.1"}},
		"lost.example.":  {"ns2.huawei.com.": {"192.0.2.2"}},
	}}
	current := campaignSnapshotState{Version: 1, SnapshotID: "after", CapturedAt: time.Unix(1600, 0), View: "default", NS: map[string]map[string][]string{
		"moved.example.": {"ns1.aliyun.com.": {"198.51.100.1"}},
		"cross.example.": {"ns3.huawei.com.": {"192.0.2.3"}, "ns2.aliyun.com.": {"198.51.100.2"}},
	}}
	response := buildNSOwnershipResponse(nil, current, &previous, "huawei.com.", "", 100)
	if response.SelectedOwner != "huawei.com." || len(response.Edges) != 3 {
		t.Fatalf("response=%#v", response)
	}
	if len(response.GraphEdges) != 3 {
		t.Fatalf("global graph edges=%d, want 3", len(response.GraphEdges))
	}
	statuses := map[string]NSOwnershipZoneEdge{}
	for _, edge := range response.Edges {
		statuses[edge.Zone] = edge
	}
	if statuses["moved.example."].Status != "moved_out" || statuses["lost.example."].Status != "removed" {
		t.Fatalf("move/removal not exposed: %#v", statuses)
	}
	if statuses["cross.example."].Status != "added" || !statuses["cross.example."].CrossDomain || len(statuses["cross.example."].CurrentOwners) != 2 {
		t.Fatalf("cross-domain ownership not exposed: %#v", statuses["cross.example."])
	}
}

func TestGlobalNSOwnershipGraphIncludesSearchMatchOutsideSample(t *testing.T) {
	previous := campaignSnapshotState{NS: map[string]map[string][]string{}}
	current := campaignSnapshotState{NS: map[string]map[string][]string{}}
	for index := 0; index < 10; index++ {
		zone := fmt.Sprintf("zone-%02d.example.", index)
		previous.NS[zone] = map[string][]string{"ns.old.example.": {}}
		current.NS[zone] = map[string][]string{"ns.new.example.": {}}
	}
	edges := buildGlobalNSOwnershipGraph(buildNSOwnershipIndex(current), buildNSOwnershipIndex(previous), "zone-09.example.", 1)
	found := false
	for _, edge := range edges {
		found = found || edge.Zone == "zone-09.example."
	}
	if !found {
		t.Fatalf("searched zone missing from graph sample: %#v", edges)
	}
}
