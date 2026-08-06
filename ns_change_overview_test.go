package main

import (
	"testing"
	"time"
)

func TestBuildNSChangeOverviewPointsCountsDistinctZones(t *testing.T) {
	snapshots := []NSOwnershipSnapshot{
		{ID: "new", CapturedAt: time.Unix(2000, 0), View: "default"},
		{ID: "other-view", CapturedAt: time.Unix(1500, 0), View: "external"},
		{ID: "old", CapturedAt: time.Unix(1000, 0), View: "default"},
	}
	fingerprints := map[string]map[string]string{
		"new": {"same.example.": "a", "modified.example.": "new", "added.example.": "c"},
		"old": {"same.example.": "a", "modified.example.": "old", "removed.example.": "d"},
	}
	points := buildNSChangeOverviewPoints(snapshots, fingerprints, 10)
	if len(points) != 1 {
		t.Fatalf("points=%#v", points)
	}
	point := points[0]
	if point.PreviousSnapshotID != "old" || point.TotalZones != 3 || point.Unchanged != 1 || point.Modified != 1 || point.Added != 1 || point.Removed != 1 || point.Changed != 3 {
		t.Fatalf("point=%#v", point)
	}
	if point.ChangeRate != 0.75 {
		t.Fatalf("change rate=%v", point.ChangeRate)
	}
}

func TestBuildNSChangeOverviewItemsExposesHostsAndFilters(t *testing.T) {
	previous := campaignSnapshotState{NS: map[string]map[string][]string{
		"modified.example.": {"ns1.old-dns.com.": {}},
		"removed.example.":  {"ns1.gone-dns.com.": {}},
	}}
	current := campaignSnapshotState{NS: map[string]map[string][]string{
		"modified.example.": {"ns1.new-dns.com.": {}},
		"added.example.":    {"ns1.new-dns.com.": {}},
	}}
	items := buildNSChangeOverviewItems(current, previous, "new-dns", "modified")
	if len(items) != 1 || items[0].Zone != "modified.example." || items[0].Type != "modified" {
		t.Fatalf("items=%#v", items)
	}
	if len(items[0].PreviousHosts) != 1 || items[0].PreviousHosts[0] != "ns1.old-dns.com." || len(items[0].CurrentHosts) != 1 || items[0].CurrentHosts[0] != "ns1.new-dns.com." {
		t.Fatalf("hosts=%#v", items[0])
	}
	all := buildNSChangeOverviewItems(current, previous, "", "all")
	if len(all) != 3 || all[0].Type != "modified" || all[1].Type != "added" || all[2].Type != "removed" {
		t.Fatalf("all=%#v", all)
	}
}
