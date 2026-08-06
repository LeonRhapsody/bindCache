package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDecodeNSPersistentObservationSupportsBaselineAndCurrentStorage(t *testing.T) {
	capturedAt := time.Date(2026, 7, 28, 4, 0, 1, 0, time.UTC)
	baseline := DomainNSObservation{
		Domain:      "example.test.",
		CapturedAt:  capturedAt,
		Fingerprint: "baseline-fingerprint",
		Nameservers: []NSHostObservation{{Name: "ns1.example.test.", TrustLevel: 8}},
	}
	baselineJSON, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	gotBaseline, err := decodeNSPersistentObservation("example.test.", capturedAt, "baseline-fingerprint", string(baselineJSON), true)
	if err != nil {
		t.Fatal(err)
	}
	if gotBaseline.Domain != baseline.Domain || len(gotBaseline.Nameservers) != 1 || gotBaseline.Nameservers[0].Name != "ns1.example.test." {
		t.Fatalf("unexpected decoded baseline %#v", gotBaseline)
	}

	currentJSON, err := json.Marshal(baseline.Nameservers)
	if err != nil {
		t.Fatal(err)
	}
	gotCurrent, err := decodeNSPersistentObservation("example.test.", capturedAt.Add(10*time.Minute), "current-fingerprint", string(currentJSON), false)
	if err != nil {
		t.Fatal(err)
	}
	if gotCurrent.Domain != "example.test." || gotCurrent.Fingerprint != "current-fingerprint" || len(gotCurrent.Nameservers) != 1 {
		t.Fatalf("unexpected decoded current observation %#v", gotCurrent)
	}
}

func TestFallbackDomainBaselineUsesHistoricalEventWithoutConfirmedBaseline(t *testing.T) {
	baselineAt := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	fromEvent := DomainNSObservation{
		Domain:      "dxc.com.",
		CapturedAt:  baselineAt,
		Fingerprint: "previous-delegation",
		Nameservers: []NSHostObservation{{Name: "ns1.stable.example."}},
	}
	store := &nsPersistentStore{}
	got, source, err := store.fallbackDomainBaseline(t.Context(), "dxc.com.", []NSChangeEvent{{Baseline: fromEvent}}, DomainNSObservation{})
	if err != nil {
		t.Fatal(err)
	}
	if source != "event_history" || got.Fingerprint != fromEvent.Fingerprint || len(got.Nameservers) != 1 {
		t.Fatalf("unexpected fallback: source=%q observation=%#v", source, got)
	}
}
