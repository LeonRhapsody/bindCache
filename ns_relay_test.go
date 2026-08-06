package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNSRelayClientUsesAuthenticatedStructuredDNSProtocol(t *testing.T) {
	t.Setenv("NS_RELAY_TEST_TOKEN", "relay-test-token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != nsRelayDNSProbePath || r.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer relay-test-token" {
			t.Fatalf("unexpected authorization header")
		}
		var request nsRelayDNSProbeRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Domain != "victim.example." || request.Resolver != "203.0.113.53:53" || !request.Recursive || request.TimeoutMS != 1500 || strings.Join(request.Types, ",") != "A,AAAA" {
			t.Fatalf("unexpected relay payload %#v", request)
		}
		relayJSON(w, http.StatusOK, nsRelayDNSProbeResponse{Answer: DNSProbeAnswer{Resolver: request.Resolver, Recursive: true, Transport: "udp", RCode: "NOERROR", IPv4: []string{"198.51.100.10"}}})
	}))
	defer server.Close()

	client, err := NewNSRelayClient(RelayClientConfig{URL: server.URL, TokenEnv: "NS_RELAY_TEST_TOKEN", Timeout: "2s"})
	if err != nil {
		t.Fatal(err)
	}
	answer := client.QueryDNS(context.Background(), "victim.example.", "203.0.113.53:53", true, 1500*time.Millisecond)
	if answer.Error != "" || answer.RCode != "NOERROR" || len(answer.IPv4) != 1 || answer.IPv4[0] != "198.51.100.10" {
		t.Fatalf("unexpected relay DNS answer %#v", answer)
	}
}

func TestNSRelayClientCarriesExplicitRecordTypes(t *testing.T) {
	t.Setenv("NS_RELAY_TEST_TOKEN", "relay-test-token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request nsRelayDNSProbeRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if strings.Join(request.Types, ",") != "NS,DS" {
			t.Fatalf("types = %#v", request.Types)
		}
		relayJSON(w, http.StatusOK, nsRelayDNSProbeResponse{Answer: DNSProbeAnswer{
			Resolver: request.Resolver, RCode: "NOERROR", NS: []string{"ns1.example."},
		}})
	}))
	defer server.Close()
	client, err := NewNSRelayClient(RelayClientConfig{URL: server.URL, TokenEnv: "NS_RELAY_TEST_TOKEN", Timeout: "2s"})
	if err != nil {
		t.Fatal(err)
	}
	answer := client.QueryDNSRecords(context.Background(), "victim.example.", "203.0.113.53:53", false, time.Second, []string{"NS", "DS"})
	if answer.Error != "" || len(answer.NS) != 1 {
		t.Fatalf("answer = %#v", answer)
	}
}

func TestNormalizeRelayQueryTypesRejectsUnknownType(t *testing.T) {
	if _, err := normalizeRelayQueryTypes([]string{"A", "AXFR"}); err == nil {
		t.Fatal("AXFR must not be accepted by relay")
	}
}

func TestNSRelayClientHealth(t *testing.T) {
	t.Setenv("NS_RELAY_TEST_TOKEN", "relay-test-token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" || r.Method != http.MethodGet {
			t.Fatalf("unexpected health request %s %s", r.Method, r.URL.Path)
		}
		relayJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}))
	defer server.Close()
	client, err := NewNSRelayClient(RelayClientConfig{URL: server.URL, TokenEnv: "NS_RELAY_TEST_TOKEN", Timeout: "2s"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Health(context.Background()); err != nil {
		t.Fatalf("health failed: %v", err)
	}
}

func TestNSRelayServerRejectsUnauthorizedClientAndNonDNSPort(t *testing.T) {
	t.Setenv("NS_RELAY_TEST_TOKEN", "relay-test-token")
	relay, err := newNSRelayServer(RelayServerConfig{Enabled: true, Listen: "127.0.0.1:0", TokenEnv: "NS_RELAY_TEST_TOKEN", AllowedCIDRs: []string{"127.0.0.0/8"}, MaxRequestBytes: 1 << 20, MaxDNSDuration: "1s"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, nsRelayDNSProbePath, strings.NewReader(`{"domain":"victim.example.","resolver":"203.0.113.53:5353","recursive":true,"timeout_ms":100}`))
	request.RemoteAddr = "127.0.0.1:32100"
	request.Header.Set("Authorization", "Bearer wrong-token")
	recorder := httptest.NewRecorder()
	relay.dnsProbe(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, body=%s", recorder.Code, recorder.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, nsRelayDNSProbePath, strings.NewReader(`{"domain":"victim.example.","resolver":"203.0.113.53:5353","recursive":true,"timeout_ms":100}`))
	request.RemoteAddr = "127.0.0.1:32100"
	request.Header.Set("Authorization", "Bearer relay-test-token")
	recorder = httptest.NewRecorder()
	relay.dnsProbe(recorder, request)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "53") {
		t.Fatalf("non-53 resolver must be rejected: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
