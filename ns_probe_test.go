package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func startNSProbeTestServer(t *testing.T, ipv4 string, delays ...time.Duration) string {
	t.Helper()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听测试 DNS: %v", err)
	}
	server := &dns.Server{
		PacketConn: listener,
		Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
			if len(delays) > 0 {
				time.Sleep(delays[0])
			}
			response := new(dns.Msg)
			response.SetReply(request)
			response.Authoritative = true
			for _, question := range request.Question {
				switch question.Qtype {
				case dns.TypeA:
					response.Answer = append(response.Answer, &dns.A{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(ipv4)})
				case dns.TypeAAAA:
					response.SetRcode(request, dns.RcodeSuccess)
				}
			}
			_ = writer.WriteMsg(response)
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return listener.LocalAddr().String()
}

func startNSProbeTCPOnlyTestServer(t *testing.T, ipv4 string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听测试 TCP DNS: %v", err)
	}
	server := &dns.Server{
		Listener: listener,
		Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
			response := new(dns.Msg)
			response.SetReply(request)
			for _, question := range request.Question {
				if question.Qtype == dns.TypeA {
					response.Answer = append(response.Answer, &dns.A{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(ipv4)})
				}
			}
			_ = writer.WriteMsg(response)
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return listener.Addr().String()
}

func nsProbeTestEvent(stableOne, stableTwo, variant string) NSChangeEvent {
	stable := func(name, address string) NSHostObservation {
		return NSHostObservation{Name: name, RegisteredDomain: "example.net.", Addresses: []NSAddress{{Address: address}}}
	}
	return NSChangeEvent{
		ID:       "event-probe-test",
		Domain:   "victim.test.",
		Severity: "high",
		Status:   "pending_verification",
		Baseline: DomainNSObservation{Nameservers: []NSHostObservation{stable("ns1.example.net.", stableOne), stable("ns2.example.net.", stableTwo)}},
		Current:  DomainNSObservation{Nameservers: []NSHostObservation{stable("ns1.example.net.", stableOne), stable("ns2.example.net.", stableTwo), stable("ns3.changed.net.", variant)}},
	}
}

func TestProbeNSEventVerifiedImpactFromMonitoredRecursive(t *testing.T) {
	stableOne := startNSProbeTestServer(t, "198.51.100.10")
	stableTwo := startNSProbeTestServer(t, "198.51.100.10")
	variant := startNSProbeTestServer(t, "203.0.113.99")
	trustedOne := startNSProbeTestServer(t, "198.51.100.10")
	trustedTwo := startNSProbeTestServer(t, "198.51.100.10")
	monitored := startNSProbeTestServer(t, "203.0.113.99")

	event := nsProbeTestEvent(stableOne, stableTwo, variant)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := ProbeNSEvent(ctx, event, "snapshot-test", &BindCache{records: map[string]Record{}}, NSProbeConfig{
		RecursiveResolver: monitored,
		TrustedResolvers:  []string{trustedOne, trustedTwo},
		Timeout:           time.Second,
		MaxDomains:        1,
		MaxParallel:       6,
	})
	if err != nil {
		t.Fatalf("拨测失败: %v", err)
	}
	if result.Verdict != "verified_impact" {
		t.Fatalf("判定 = %q, want verified_impact; result=%+v", result.Verdict, result)
	}
	if len(result.Domains) != 1 || result.Domains[0].StableConsensus == nil {
		t.Fatalf("未形成稳定 NS 共识: %+v", result.Domains)
	}
	if len(result.Domains[0].VariantNS) != 1 || result.Domains[0].VariantNS[0].MatchesStable == nil || *result.Domains[0].VariantNS[0].MatchesStable {
		t.Fatalf("变异 NS 未被标记为偏离共识: %+v", result.Domains[0].VariantNS)
	}
	if !applyNSProbeResult(&event, result) || event.Severity != "critical" || event.Status != "verified_impact" || event.Evidence != "verified" {
		t.Fatalf("拨测证据没有升级事件: %+v", event)
	}
}

func TestNSProbeSignatureIncludesCNAMEAlongsideAddress(t *testing.T) {
	left := DNSProbeAnswer{RCode: "NOERROR", CNAME: []string{"one.target."}, IPv4: []string{"198.51.100.10"}}
	right := DNSProbeAnswer{RCode: "NOERROR", CNAME: []string{"other.target."}, IPv4: []string{"198.51.100.10"}}
	if nsProbeAnswersEqual(left, right) {
		t.Fatal("CNAME 链变化不能因终端 IP 一致而被忽略")
	}
}

func TestNormalizeNSProbeConfigSetsPerImportEventLimit(t *testing.T) {
	config, err := normalizeNSProbeConfig(NSProbeConfig{
		RecursiveResolver: "192.0.2.53:53",
		TrustedResolvers:  []string{"114.114.114.114:53", "223.5.5.5:53"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.MaxEventsPerImport != 3 {
		t.Fatalf("max events per import = %d, want 3", config.MaxEventsPerImport)
	}
}

func TestQueryDNSProbeFallsBackToTCPAfterUDPFailure(t *testing.T) {
	endpoint := startNSProbeTCPOnlyTestServer(t, "198.51.100.42")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	answer := queryDNSProbe(ctx, "tcp-fallback.test.", endpoint, true, time.Second)
	if answer.Error != "" || answer.Transport != "tcp" || answer.RCode != "NOERROR" || len(answer.IPv4) != 1 || answer.IPv4[0] != "198.51.100.42" {
		t.Fatalf("UDP 失败后 TCP 回退结果不正确: %+v", answer)
	}
	if answer.DurationMS <= 0 {
		t.Fatalf("TCP 回退拨测耗时未记录: %+v", answer)
	}
}

func TestQueryDNSProbeReturnsMeasuredDuration(t *testing.T) {
	endpoint := startNSProbeTestServer(t, "198.51.100.43", 15*time.Millisecond)
	answer := queryDNSProbeTypes(context.Background(), "duration.test.", endpoint, true, time.Second, []string{"A"})
	if answer.Error != "" {
		t.Fatalf("DNS 拨测失败: %+v", answer)
	}
	if answer.DurationMS < 10 {
		t.Fatalf("DNS 拨测耗时 = %dms, want >= 10ms", answer.DurationMS)
	}
}

func TestQueryDNSProbeReturnsDurationOnTimeout(t *testing.T) {
	endpoint := startNSProbeTestServer(t, "198.51.100.44", 50*time.Millisecond)
	answer := queryDNSProbeTypes(context.Background(), "timeout.test.", endpoint, true, 10*time.Millisecond, []string{"A"})
	if answer.Error == "" {
		t.Fatalf("预期 DNS 拨测超时: %+v", answer)
	}
	if answer.DurationMS <= 0 {
		t.Fatalf("DNS 超时耗时未记录: %+v", answer)
	}
}
