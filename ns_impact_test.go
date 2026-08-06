package main

import (
	"reflect"
	"testing"
	"time"
)

func TestBuildNSEventImpactListsZoneDescendantsAndCNAMEDependents(t *testing.T) {
	capturedAt := time.Date(2026, 7, 28, 4, 50, 2, 0, time.UTC)
	event := NSChangeEvent{ID: "event-1", Domain: "target.test.", Current: DomainNSObservation{CapturedAt: capturedAt}}
	cache := &BindCache{records: map[string]Record{
		"target.test.":        {NSs: []NS{{NsDomain: "ns1.target.test."}}},
		"api.target.test.":    {As: []A{{IP: "192.0.2.10"}}},
		"inside.target.test.": {CNAMEs: []CNAME{{IP: "external.example."}}},
		"edge.example.":       {CNAMEs: []CNAME{{IP: "api.target.test."}}},
		"app.example.":        {CNAMEs: []CNAME{{IP: "edge.example."}}},
		"other.example.":      {CNAMEs: []CNAME{{IP: "safe.example."}}},
	}}

	impact := buildNSEventImpact(event, "snapshot-1", cache)
	if impact.EventID != "event-1" || impact.EventDomain != "target.test." || impact.SnapshotID != "snapshot-1" || impact.TotalAffectedDomains != 5 {
		t.Fatalf("unexpected impact header %#v", impact)
	}
	if len(impact.Groups) != 3 {
		t.Fatalf("groups = %#v, want zone, direct CNAME and chain CNAME", impact.Groups)
	}
	if got, want := impact.Groups[0].Type, "zone_descendants"; got != want {
		t.Fatalf("group 0 type = %q, want %q", got, want)
	}
	if got, want := affectedDomainNames(impact.Groups[0].Domains), []string{"api.target.test.", "inside.target.test.", "target.test."}; !reflect.DeepEqual(got, want) {
		t.Fatalf("zone descendants = %#v, want %#v", got, want)
	}
	if got, want := affectedDomainNames(impact.Groups[1].Domains), []string{"edge.example."}; !reflect.DeepEqual(got, want) || impact.Groups[1].Domains[0].Target != "api.target.test." || impact.Groups[1].Domains[0].CNAMEHops != 1 {
		t.Fatalf("direct CNAME group = %#v", impact.Groups[1])
	}
	if got, want := affectedDomainNames(impact.Groups[2].Domains), []string{"app.example."}; !reflect.DeepEqual(got, want) || impact.Groups[2].Domains[0].Target != "edge.example." || impact.Groups[2].Domains[0].CNAMEHops != 2 {
		t.Fatalf("CNAME chain group = %#v", impact.Groups[2])
	}
}

func TestIsNameInDomainRequiresLabelBoundary(t *testing.T) {
	if !isNameInDomain("a.target.test.", "target.test.") || !isNameInDomain("target.test.", "target.test.") {
		t.Fatal("expected apex and child to match")
	}
	if isNameInDomain("not-target.test.", "target.test.") {
		t.Fatal("suffix without a label boundary must not match")
	}
}

func affectedDomainNames(items []NSEventAffectedDomain) []string {
	result := make([]string, 0, len(items))
	for _, item := range items {
		result = append(result, item.Domain)
	}
	return result
}
