package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// NSProbeConfig 控制异常 NS 的按需/自动拨测。限制针对的是单个事件，避免一次
// NS 变化把全部缓存名称拿去查询，从而影响后续 10 分钟快照导入。
type NSProbeConfig struct {
	Enabled            bool
	RecursiveResolver  string
	TrustedResolvers   []string
	Timeout            time.Duration
	EventTimeout       time.Duration
	MaxDomains         int
	MaxParallel        int
	MaxEventsPerImport int
	DirectPort         int
	Executor           DNSProbeExecutor
}

func DefaultNSProbeConfig() NSProbeConfig {
	return NSProbeConfig{
		Enabled:            true,
		RecursiveResolver:  "127.0.0.1:53",
		TrustedResolvers:   []string{"114.114.114.114:53", "223.5.5.5:53"},
		Timeout:            2 * time.Second,
		EventTimeout:       60 * time.Second,
		MaxDomains:         20,
		MaxParallel:        12,
		MaxEventsPerImport: 3,
		DirectPort:         53,
	}
}

// ParseNSProbeConfig 把命令行的紧凑参数转换为固定的拨测边界。可信 DNS 必须
// 保持两个独立目标，避免单一公共递归器的缓存污染变成误升级证据。
func ParseNSProbeConfig(enabled bool, recursiveResolver, trustedResolvers string, timeout time.Duration, maxDomains, maxParallel int) (*NSProbeConfig, error) {
	config := DefaultNSProbeConfig()
	config.Enabled = enabled
	if strings.TrimSpace(recursiveResolver) != "" {
		config.RecursiveResolver = recursiveResolver
	}
	if strings.TrimSpace(trustedResolvers) != "" {
		config.TrustedResolvers = strings.Split(trustedResolvers, ",")
	}
	if timeout > 0 {
		config.Timeout = timeout
	}
	if maxDomains > 0 {
		config.MaxDomains = maxDomains
	}
	if maxParallel > 0 {
		config.MaxParallel = maxParallel
	}
	normalized, err := normalizeNSProbeConfig(config)
	if err != nil {
		return nil, err
	}
	return &normalized, nil
}

func normalizeNSProbeConfig(config NSProbeConfig) (NSProbeConfig, error) {
	defaults := DefaultNSProbeConfig()
	if strings.TrimSpace(config.RecursiveResolver) == "" {
		config.RecursiveResolver = defaults.RecursiveResolver
	}
	if len(config.TrustedResolvers) == 0 {
		config.TrustedResolvers = defaults.TrustedResolvers
	}
	if config.Timeout <= 0 {
		config.Timeout = defaults.Timeout
	}
	if config.EventTimeout <= 0 {
		config.EventTimeout = defaults.EventTimeout
	}
	if config.MaxDomains <= 0 {
		config.MaxDomains = defaults.MaxDomains
	}
	if config.MaxParallel <= 0 {
		config.MaxParallel = defaults.MaxParallel
	}
	if config.MaxEventsPerImport <= 0 {
		config.MaxEventsPerImport = defaults.MaxEventsPerImport
	}
	if config.DirectPort <= 0 || config.DirectPort > 65535 {
		config.DirectPort = defaults.DirectPort
	}
	var err error
	if config.RecursiveResolver, err = normalizeDNSResolverAddress(config.RecursiveResolver, 53); err != nil {
		return NSProbeConfig{}, fmt.Errorf("递归 DNS 地址: %w", err)
	}
	trusted := make([]string, 0, len(config.TrustedResolvers))
	seen := make(map[string]struct{})
	for _, resolver := range config.TrustedResolvers {
		resolver, err = normalizeDNSResolverAddress(resolver, 53)
		if err != nil {
			return NSProbeConfig{}, fmt.Errorf("可信 DNS 地址: %w", err)
		}
		if _, exists := seen[resolver]; !exists {
			trusted = append(trusted, resolver)
			seen[resolver] = struct{}{}
		}
	}
	if len(trusted) < 2 {
		return NSProbeConfig{}, fmt.Errorf("可信 DNS 至少需要两个独立地址")
	}
	config.TrustedResolvers = trusted
	return config, nil
}

// DNSProbeAnswer 保存一次 A+AAAA 联合查询，Signature 是用于组内共识比较的
// 规范化结果，不包含 TTL 与时延，以免正常缓存差异造成误判。
type DNSProbeAnswer struct {
	Resolver      string              `json:"resolver"`
	Recursive     bool                `json:"recursive"`
	Transport     string              `json:"transport"`
	RCode         string              `json:"rcode"`
	CNAME         []string            `json:"cname,omitempty"`
	NS            []string            `json:"ns,omitempty"`
	IPv4          []string            `json:"ipv4,omitempty"`
	IPv6          []string            `json:"ipv6,omitempty"`
	Records       map[string][]string `json:"records,omitempty"`
	TTLMin        uint32              `json:"ttl_min,omitempty"`
	ReservedIPs   []string            `json:"reserved_ips,omitempty"`
	Authoritative bool                `json:"authoritative"`
	DurationMS    int64               `json:"duration_ms"`
	Error         string              `json:"error,omitempty"`
}

type NSProbeHostResult struct {
	Host          string           `json:"host"`
	Role          string           `json:"role"`
	Answers       []DNSProbeAnswer `json:"answers"`
	Effective     *DNSProbeAnswer  `json:"effective,omitempty"`
	MatchesStable *bool            `json:"matches_stable,omitempty"`
}

type NSProbeDomainResult struct {
	Domain           string              `json:"domain"`
	StableNS         []NSProbeHostResult `json:"stable_ns"`
	VariantNS        []NSProbeHostResult `json:"variant_ns"`
	StableConsensus  *DNSProbeAnswer     `json:"stable_consensus,omitempty"`
	TrustedResolvers []DNSProbeAnswer    `json:"trusted_resolvers"`
	TrustedConsensus *DNSProbeAnswer     `json:"trusted_consensus,omitempty"`
	RecursiveResult  DNSProbeAnswer      `json:"recursive_result"`
	Verdict          string              `json:"verdict"`
	Summary          string              `json:"summary"`
}

type NSProbeResult struct {
	EventID       string                `json:"event_id"`
	SnapshotID    string                `json:"snapshot_id"`
	EventDomain   string                `json:"event_domain"`
	ProbedAt      time.Time             `json:"probed_at"`
	Verdict       string                `json:"verdict"`
	Summary       string                `json:"summary"`
	Domains       []NSProbeDomainResult `json:"domains"`
	ProbedDomains int                   `json:"probed_domains"`
	DomainLimit   int                   `json:"domain_limit"`
}

type nsProbeHost struct {
	name      string
	addresses []string
	role      string
}

type nsProbeTask struct {
	domain    string
	host      string
	role      string
	resolver  string
	recursive bool
	types     []string
}

type nsProbeTaskResult struct {
	task   nsProbeTask
	answer DNSProbeAnswer
}

func normalizeDNSResolverAddress(value string, defaultPort int) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("地址为空")
	}
	if host, port, err := net.SplitHostPort(value); err == nil {
		if host == "" || port == "" {
			return "", fmt.Errorf("无效地址 %q", value)
		}
		return net.JoinHostPort(host, port), nil
	}
	return net.JoinHostPort(strings.Trim(value, "[]"), strconv.Itoa(defaultPort)), nil
}

func endpointForNSAddress(address string, port int) (string, error) {
	return normalizeDNSResolverAddress(address, port)
}

func nsProbeStableAndVariantHosts(event NSChangeEvent) ([]nsProbeHost, []nsProbeHost) {
	baseline := nsHostMap(event.Baseline.Nameservers)
	stable := make([]nsProbeHost, 0)
	variant := make([]nsProbeHost, 0)
	for _, current := range event.Current.Nameservers {
		addresses := make([]string, 0, len(current.Addresses))
		for _, address := range current.Addresses {
			if strings.TrimSpace(address.Address) != "" {
				addresses = append(addresses, address.Address)
			}
		}
		if len(addresses) == 0 {
			continue
		}
		candidate := nsProbeHost{name: current.Name, addresses: addresses}
		baselineHost, exists := baseline[current.Name]
		if exists && baselineHost.RegisteredDomain == current.RegisteredDomain && addressesFingerprint(baselineHost.Addresses) == addressesFingerprint(current.Addresses) {
			candidate.role = "stable"
			stable = append(stable, candidate)
		} else {
			candidate.role = "variant"
			variant = append(variant, candidate)
		}
	}
	sort.Slice(stable, func(i, j int) bool { return stable[i].name < stable[j].name })
	sort.Slice(variant, func(i, j int) bool { return variant[i].name < variant[j].name })
	return stable, variant
}

func nsProbeDomains(event NSChangeEvent, snapshotID string, cache *BindCache, limit int) []string {
	impact := buildNSEventImpact(event, snapshotID, cache)
	ordered := []string{normalizeFQDN(event.Domain)}
	for _, groupType := range []string{"cname_direct", "cname_chain", "zone_descendants"} {
		for _, group := range impact.Groups {
			if group.Type != groupType {
				continue
			}
			for _, item := range group.Domains {
				ordered = append(ordered, item.Domain)
			}
		}
	}
	seen := make(map[string]struct{})
	result := make([]string, 0, min(limit, len(ordered)))
	for _, domain := range ordered {
		domain = normalizeFQDN(domain)
		if domain == "" {
			continue
		}
		if _, exists := seen[domain]; exists {
			continue
		}
		seen[domain] = struct{}{}
		result = append(result, domain)
		if len(result) >= limit {
			break
		}
	}
	return result
}

func queryDNSProbe(ctx context.Context, domain, resolver string, recursive bool, timeout time.Duration) DNSProbeAnswer {
	return queryDNSProbeTypes(ctx, domain, resolver, recursive, timeout, []string{"A", "AAAA"})
}

func queryDNSProbeTypes(ctx context.Context, domain, resolver string, recursive bool, timeout time.Duration, queryTypes []string) (answer DNSProbeAnswer) {
	answer = DNSProbeAnswer{Resolver: resolver, Recursive: recursive, Transport: "udp", RCode: "UNKNOWN"}
	started := time.Now()
	defer func() {
		answer.DurationMS = time.Since(started).Milliseconds()
		// DurationMS 是页面和持久化使用的毫秒值。真实查询不足 1ms 时向上
		// 记为 1ms，避免与历史版本“未正确记录耗时”的 0 值混淆。
		if answer.DurationMS == 0 {
			answer.DurationMS = 1
		}
	}()
	answer.Records = make(map[string][]string)
	for _, queryTypeName := range queryTypes {
		queryType, ok := dns.StringToType[strings.ToUpper(queryTypeName)]
		if !ok {
			answer.Error = "不支持的 DNS 记录类型 " + queryTypeName
			return answer
		}
		message := new(dns.Msg)
		message.SetQuestion(dns.Fqdn(domain), queryType)
		message.RecursionDesired = recursive
		client := &dns.Client{Net: "udp", Timeout: timeout}
		response, _, err := client.ExchangeContext(ctx, message, resolver)
		// DNS 递归器、边界 ACL 或路径 MTU 可能只让 UDP 失败。UDP 超时/拒绝时
		// 仍以 TCP 做一次独立确认；只有两种传输都失败才视为不可判定。
		if err != nil || (response != nil && response.Truncated) {
			udpErr := err
			client.Net = "tcp"
			answer.Transport = "tcp"
			response, _, err = client.ExchangeContext(ctx, message, resolver)
			if err != nil && udpErr != nil {
				err = fmt.Errorf("UDP: %v；TCP: %w", udpErr, err)
			}
		}
		if err != nil {
			answer.Error = err.Error()
			return answer
		}
		if response == nil {
			answer.Error = "空 DNS 响应"
			return answer
		}
		answer.RCode = dns.RcodeToString[response.Rcode]
		answer.Authoritative = answer.Authoritative || response.Authoritative
		records := append(append([]dns.RR(nil), response.Answer...), response.Ns...)
		for _, record := range records {
			header := record.Header()
			if header != nil && (answer.TTLMin == 0 || header.Ttl < answer.TTLMin) {
				answer.TTLMin = header.Ttl
			}
			switch value := record.(type) {
			case *dns.A:
				answer.IPv4 = append(answer.IPv4, value.A.String())
				answer.Records["A"] = append(answer.Records["A"], value.A.String())
			case *dns.AAAA:
				answer.IPv6 = append(answer.IPv6, value.AAAA.String())
				answer.Records["AAAA"] = append(answer.Records["AAAA"], value.AAAA.String())
			case *dns.CNAME:
				answer.CNAME = append(answer.CNAME, normalizeFQDN(value.Target))
				answer.Records["CNAME"] = append(answer.Records["CNAME"], normalizeFQDN(value.Target))
			case *dns.NS:
				answer.NS = append(answer.NS, normalizeFQDN(value.Ns))
				answer.Records["NS"] = append(answer.Records["NS"], normalizeFQDN(value.Ns))
			case *dns.SOA:
				answer.Records["SOA"] = append(answer.Records["SOA"], fmt.Sprintf("%s %s %d", normalizeFQDN(value.Ns), normalizeFQDN(value.Mbox), value.Serial))
			case *dns.MX:
				answer.Records["MX"] = append(answer.Records["MX"], fmt.Sprintf("%d %s", value.Preference, normalizeFQDN(value.Mx)))
			case *dns.TXT:
				answer.Records["TXT"] = append(answer.Records["TXT"], strings.Join(value.Txt, ""))
			case *dns.DS:
				answer.Records["DS"] = append(answer.Records["DS"], value.String())
			case *dns.DNSKEY:
				answer.Records["DNSKEY"] = append(answer.Records["DNSKEY"], value.String())
			}
		}
	}
	answer.IPv4 = uniqueSortedStrings(answer.IPv4)
	answer.IPv6 = uniqueSortedStrings(answer.IPv6)
	answer.CNAME = uniqueSortedStrings(answer.CNAME)
	answer.NS = uniqueSortedStrings(answer.NS)
	for recordType, values := range answer.Records {
		answer.Records[recordType] = uniqueSortedStrings(values)
	}
	if len(answer.Records) == 0 {
		answer.Records = nil
	}
	for _, value := range append(append([]string(nil), answer.IPv4...), answer.IPv6...) {
		if addr, err := netip.ParseAddr(value); err == nil && isReservedNSAddress(addr) {
			answer.ReservedIPs = append(answer.ReservedIPs, value)
		}
	}
	answer.ReservedIPs = uniqueSortedStrings(answer.ReservedIPs)
	return answer
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return make([]string, 0)
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func nsProbeSignature(answer DNSProbeAnswer) string {
	if answer.Error != "" || answer.RCode != dns.RcodeToString[dns.RcodeSuccess] {
		return ""
	}
	// CNAME 链与终端 IP 都是比对对象。仅在有 IP 时忽略 CNAME 会遗漏
	// “IP 碰巧相同、别名已被替换”的劫持或错误委派信号。
	parts := []string{
		answer.RCode,
		"CNAME=" + strings.Join(answer.CNAME, ","),
		"A=" + strings.Join(answer.IPv4, ","),
		"AAAA=" + strings.Join(answer.IPv6, ","),
		"NS=" + strings.Join(answer.NS, ","),
	}
	return strings.Join(parts, "|")
}

func nsProbeAnswersEqual(left, right DNSProbeAnswer) bool {
	return nsProbeSignature(left) != "" && nsProbeSignature(left) == nsProbeSignature(right)
}

func effectiveNSProbeAnswer(answers []DNSProbeAnswer) *DNSProbeAnswer {
	groups := make(map[string][]DNSProbeAnswer)
	for _, answer := range answers {
		if signature := nsProbeSignature(answer); signature != "" {
			groups[signature] = append(groups[signature], answer)
		}
	}
	if len(groups) == 0 {
		return nil
	}
	keys := make([]string, 0, len(groups))
	for signature := range groups {
		keys = append(keys, signature)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(groups[keys[i]]) == len(groups[keys[j]]) {
			return keys[i] < keys[j]
		}
		return len(groups[keys[i]]) > len(groups[keys[j]])
	})
	result := groups[keys[0]][0]
	return &result
}

func nsProbeConsensus(answers []DNSProbeAnswer, minimum int) *DNSProbeAnswer {
	groups := make(map[string][]DNSProbeAnswer)
	for _, answer := range answers {
		if signature := nsProbeSignature(answer); signature != "" {
			groups[signature] = append(groups[signature], answer)
		}
	}
	keys := make([]string, 0, len(groups))
	for signature := range groups {
		if len(groups[signature]) >= minimum {
			keys = append(keys, signature)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(groups[keys[i]]) == len(groups[keys[j]]) {
			return keys[i] < keys[j]
		}
		return len(groups[keys[i]]) > len(groups[keys[j]])
	})
	result := groups[keys[0]][0]
	return &result
}

func runNSProbeTasks(ctx context.Context, tasks []nsProbeTask, timeout time.Duration, parallel int, executor DNSProbeExecutor) []nsProbeTaskResult {
	if len(tasks) == 0 {
		return nil
	}
	if parallel > len(tasks) {
		parallel = len(tasks)
	}
	if executor == nil {
		executor = directDNSProbeExecutor{}
	}
	jobs := make(chan nsProbeTask)
	results := make(chan nsProbeTaskResult, len(tasks))
	var workers sync.WaitGroup
	for index := 0; index < parallel; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for task := range jobs {
				var answer DNSProbeAnswer
				if len(task.types) > 0 {
					if typed, ok := executor.(typedDNSProbeExecutor); ok {
						answer = typed.QueryDNSRecords(ctx, task.domain, task.resolver, task.recursive, timeout, task.types)
					} else {
						answer = DNSProbeAnswer{Resolver: task.resolver, Recursive: task.recursive, RCode: "UNKNOWN", Error: "拨测执行器不支持指定 DNS 记录类型"}
					}
				} else {
					answer = executor.QueryDNS(ctx, task.domain, task.resolver, task.recursive, timeout)
				}
				results <- nsProbeTaskResult{task: task, answer: answer}
			}
		}()
	}
	go func() {
		for _, task := range tasks {
			jobs <- task
		}
		close(jobs)
		workers.Wait()
		close(results)
	}()
	output := make([]nsProbeTaskResult, 0, len(tasks))
	for result := range results {
		output = append(output, result)
	}
	return output
}

// ProbeNSAuxEvent 为非“NS 变化”风险提供真实拨测证据。父子不一致查询 NS，
// 可用性事件查询 SOA/NS，其他事件查询 A/AAAA；所有请求仍经配置的 relay 执行器。
func ProbeNSAuxEvent(ctx context.Context, event NSAuxRiskEvent, config NSProbeConfig) (NSProbeResult, error) {
	config, err := normalizeNSProbeConfig(config)
	if err != nil {
		return NSProbeResult{}, err
	}
	result := NSProbeResult{
		EventID: event.ID, SnapshotID: event.SnapshotID, EventDomain: normalizeFQDN(event.Domain),
		ProbedAt: time.Now().UTC(), DomainLimit: 1, Verdict: "inconclusive",
	}
	queryTypes := []string{"A", "AAAA"}
	if event.Type == "ns_parent_child" {
		queryTypes = []string{"NS"}
	} else if event.Type == "ns_availability" {
		queryTypes = []string{"SOA", "NS"}
	}
	tasks := make([]nsProbeTask, 0)
	authoritativeTaskCount := 0
	hosts := make([]NSProbeHostResult, 0, len(event.Current.Nameservers))
	for _, host := range event.Current.Nameservers {
		hosts = append(hosts, NSProbeHostResult{Host: host.Name, Role: "authoritative"})
		for _, address := range host.Addresses {
			endpoint, endpointErr := endpointForNSAddress(address.Address, config.DirectPort)
			if endpointErr != nil {
				continue
			}
			tasks = append(tasks, nsProbeTask{
				domain: event.Domain, host: host.Name, role: "authoritative",
				resolver: endpoint, types: queryTypes,
			})
			authoritativeTaskCount++
		}
	}
	// ADB 可用性复核只需要直连权威端点，避免额外消耗可信递归器和受监控递归器请求。
	if event.Type != "ns_availability" {
		for _, resolver := range config.TrustedResolvers {
			tasks = append(tasks, nsProbeTask{
				domain: event.Domain, host: resolver, role: "trusted",
				resolver: resolver, recursive: true, types: queryTypes,
			})
		}
		tasks = append(tasks, nsProbeTask{
			domain: event.Domain, host: config.RecursiveResolver, role: "recursive",
			resolver: config.RecursiveResolver, recursive: true, types: queryTypes,
		})
	}
	taskResults := runNSProbeTasks(ctx, tasks, config.Timeout, config.MaxParallel, config.Executor)
	domainResult := NSProbeDomainResult{Domain: normalizeFQDN(event.Domain), StableNS: hosts}
	byHost := make(map[string][]DNSProbeAnswer)
	for _, task := range taskResults {
		switch task.task.role {
		case "authoritative":
			byHost[task.task.host] = append(byHost[task.task.host], task.answer)
		case "trusted":
			domainResult.TrustedResolvers = append(domainResult.TrustedResolvers, task.answer)
		case "recursive":
			domainResult.RecursiveResult = task.answer
		}
	}
	effective := make([]DNSProbeAnswer, 0, len(domainResult.StableNS))
	for index := range domainResult.StableNS {
		domainResult.StableNS[index].Answers = byHost[domainResult.StableNS[index].Host]
		domainResult.StableNS[index].Effective = effectiveNSProbeAnswer(domainResult.StableNS[index].Answers)
		if domainResult.StableNS[index].Effective != nil {
			effective = append(effective, *domainResult.StableNS[index].Effective)
		}
	}
	domainResult.TrustedConsensus = nsProbeConsensus(domainResult.TrustedResolvers, 2)
	if len(effective) > 0 {
		domainResult.StableConsensus = nsProbeConsensus(effective, 1)
	}
	signatures := make(map[string]struct{})
	for _, answer := range effective {
		if signature := nsProbeSignature(answer); signature != "" {
			signatures[signature] = struct{}{}
		}
	}
	unavailableHosts := 0
	for _, host := range domainResult.StableNS {
		if len(host.Answers) > 0 && host.Effective == nil {
			unavailableHosts++
		}
	}
	switch {
	case authoritativeTaskCount == 0:
		domainResult.Verdict = "inconclusive"
		domainResult.Summary = "快照中缺少可拨测的权威 NS 地址，无法形成主动拨测结论"
	case len(effective) == 0:
		domainResult.Verdict = "verified_ns_divergence"
		domainResult.Summary = "快照提供的权威 NS 端点均未返回有效结果，主动拨测确认服务不可达"
	case event.Type == "ns_availability" && unavailableHosts > 0:
		domainResult.Verdict = "verified_ns_divergence"
		domainResult.Summary = fmt.Sprintf("主动拨测确认 %d 个 NS 主机的全部已知端点未返回有效 SOA/NS 响应", unavailableHosts)
	case event.Type == "ns_availability":
		domainResult.Verdict = "consistent"
		domainResult.Summary = "ADB 候选异常经主动拨测未复现，当前 NS 端点均可响应"
	case len(signatures) > 1:
		domainResult.Verdict = "verified_ns_divergence"
		domainResult.Summary = "NS 组内不同权威端点返回的结果不一致"
	case event.Type == "ns_blacklist" && domainResult.TrustedConsensus != nil &&
		domainResult.StableConsensus != nil && domainResult.RecursiveResult.Error == "" &&
		nsProbeAnswersEqual(domainResult.RecursiveResult, *domainResult.StableConsensus) &&
		!nsProbeAnswersEqual(*domainResult.TrustedConsensus, *domainResult.StableConsensus):
		domainResult.Verdict = "verified_impact"
		domainResult.Summary = "受监控递归命中黑名单权威 NS 的异常结果，且与两个可信 DNS 的共识不一致"
	case event.Type == "ns_parent_child" && domainResult.TrustedConsensus != nil &&
		domainResult.StableConsensus != nil && !nsProbeAnswersEqual(*domainResult.TrustedConsensus, *domainResult.StableConsensus):
		domainResult.Verdict = "verified_ns_divergence"
		domainResult.Summary = "子区权威 NS 集合与两个可信递归器形成的父区委派共识不一致"
	default:
		domainResult.Verdict = "consistent"
		domainResult.Summary = "本轮可用端点返回结果一致，未形成主动拨测分歧证据"
	}
	result.Domains = []NSProbeDomainResult{domainResult}
	result.ProbedDomains = 1
	result.Verdict = domainResult.Verdict
	result.Summary = domainResult.Summary
	return result, nil
}

func applyNSAuxProbeResult(event *NSAuxRiskEvent, probe NSProbeResult) bool {
	if event == nil || (probe.Verdict != "verified_ns_divergence" && probe.Verdict != "verified_impact") {
		return false
	}
	event.Evidence = "verified"
	event.Status = probe.Verdict
	if probe.Verdict == "verified_impact" || event.Type == "ns_single" ||
		(event.Type == "ns_availability" && extraInt(event.Extra, "remainingNS") == 0) {
		event.Severity = "critical"
	} else {
		event.Severity = maxRiskSeverity(event.Severity, "high")
	}
	if !strings.Contains(event.Summary, probe.Summary) {
		event.Summary += "；" + probe.Summary
	}
	if event.Extra == nil {
		event.Extra = make(map[string]any)
	}
	event.Extra["activeProbeVerdict"] = probe.Verdict
	event.Extra["activeProbeSummary"] = probe.Summary
	return true
}

func buildNSProbeDomainResult(domain string, stableHosts, variantHosts []nsProbeHost, tasks []nsProbeTaskResult) NSProbeDomainResult {
	result := NSProbeDomainResult{Domain: domain, StableNS: make([]NSProbeHostResult, 0, len(stableHosts)), VariantNS: make([]NSProbeHostResult, 0, len(variantHosts))}
	byHost := make(map[string][]DNSProbeAnswer)
	for _, task := range tasks {
		if task.task.domain != domain {
			continue
		}
		switch task.task.role {
		case "stable", "variant":
			byHost[task.task.role+"\x00"+task.task.host] = append(byHost[task.task.role+"\x00"+task.task.host], task.answer)
		case "trusted":
			result.TrustedResolvers = append(result.TrustedResolvers, task.answer)
		case "recursive":
			result.RecursiveResult = task.answer
		}
	}
	for _, host := range stableHosts {
		answers := byHost["stable\x00"+host.name]
		result.StableNS = append(result.StableNS, NSProbeHostResult{Host: host.name, Role: "stable", Answers: answers, Effective: effectiveNSProbeAnswer(answers)})
	}
	for _, host := range variantHosts {
		answers := byHost["variant\x00"+host.name]
		result.VariantNS = append(result.VariantNS, NSProbeHostResult{Host: host.name, Role: "variant", Answers: answers, Effective: effectiveNSProbeAnswer(answers)})
	}
	sort.Slice(result.TrustedResolvers, func(i, j int) bool { return result.TrustedResolvers[i].Resolver < result.TrustedResolvers[j].Resolver })
	stableAnswers := make([]DNSProbeAnswer, 0, len(result.StableNS))
	for _, host := range result.StableNS {
		if host.Effective != nil {
			stableAnswers = append(stableAnswers, *host.Effective)
		}
	}
	result.StableConsensus = nsProbeConsensus(stableAnswers, 2)
	result.TrustedConsensus = nsProbeConsensus(result.TrustedResolvers, 2)
	if result.StableConsensus == nil {
		result.Verdict = "inconclusive"
		result.Summary = "稳定 NS 少于两个有效且一致的响应，无法建立组内共识"
		return result
	}
	trustedSupportsStable := result.TrustedConsensus != nil && nsProbeAnswersEqual(*result.StableConsensus, *result.TrustedConsensus)
	mismatchedVariants := make([]string, 0)
	variantMatchedByRecursive := false
	variantReserved := false
	for index := range result.VariantNS {
		host := &result.VariantNS[index]
		if host.Effective == nil {
			continue
		}
		matches := nsProbeAnswersEqual(*host.Effective, *result.StableConsensus)
		host.MatchesStable = &matches
		if matches {
			continue
		}
		mismatchedVariants = append(mismatchedVariants, host.Host)
		variantReserved = variantReserved || len(host.Effective.ReservedIPs) > 0
		variantMatchedByRecursive = variantMatchedByRecursive || nsProbeAnswersEqual(result.RecursiveResult, *host.Effective)
	}
	if len(mismatchedVariants) == 0 {
		result.Verdict = "consistent"
		result.Summary = "变异 NS 的有效响应与稳定 NS 组内共识一致"
		return result
	}
	if !trustedSupportsStable {
		result.Verdict = "inconclusive"
		result.Summary = "变异 NS 与稳定 NS 存在差异，但两个可信 DNS 未形成支持稳定 NS 的共识"
		return result
	}
	if variantMatchedByRecursive || (len(result.RecursiveResult.ReservedIPs) > 0 && !nsProbeAnswersEqual(result.RecursiveResult, *result.StableConsensus)) {
		result.Verdict = "verified_impact"
		result.Summary = fmt.Sprintf("变异 NS（%s）与稳定 NS/可信 DNS 共识不一致，且被监控递归器返回了相同的异常结果", strings.Join(mismatchedVariants, ", "))
		return result
	}
	if variantReserved {
		result.Verdict = "verified_ns_divergence"
		result.Summary = fmt.Sprintf("变异 NS（%s）返回保留或私网地址，且与稳定 NS/可信 DNS 共识不一致", strings.Join(mismatchedVariants, ", "))
		return result
	}
	result.Verdict = "verified_ns_divergence"
	result.Summary = fmt.Sprintf("变异 NS（%s）返回的 IP 或 CNAME 链与稳定 NS/可信 DNS 共识不一致", strings.Join(mismatchedVariants, ", "))
	return result
}

// ProbeNSEvent 对受影响名称逐台查询稳定 NS、变异 NS、可信递归与被监控递归器。
// 只有稳定 NS 与两个可信 DNS 均形成一致参考时，才会产出可升级风险等级的结论。
func ProbeNSEvent(ctx context.Context, event NSChangeEvent, snapshotID string, cache *BindCache, config NSProbeConfig) (NSProbeResult, error) {
	config, err := normalizeNSProbeConfig(config)
	if err != nil {
		return NSProbeResult{}, err
	}
	result := NSProbeResult{EventID: event.ID, SnapshotID: snapshotID, EventDomain: normalizeFQDN(event.Domain), ProbedAt: time.Now().UTC(), DomainLimit: config.MaxDomains, Verdict: "inconclusive"}
	stableHosts, variantHosts := nsProbeStableAndVariantHosts(event)
	if len(stableHosts) < 2 {
		result.Summary = "当前委派组中少于两个稳定 NS，无法做组内多数派比对"
		return result, nil
	}
	if len(variantHosts) == 0 {
		result.Summary = "未找到可直连拨测的变异 NS 端点"
		return result, nil
	}
	domains := nsProbeDomains(event, snapshotID, cache, config.MaxDomains)
	if len(domains) == 0 {
		result.Summary = "风险快照未保留可拨测的受影响名称"
		return result, nil
	}
	tasks := make([]nsProbeTask, 0, len(domains)*(len(stableHosts)+len(variantHosts)+len(config.TrustedResolvers)+1))
	for _, domain := range domains {
		for _, host := range append(append([]nsProbeHost(nil), stableHosts...), variantHosts...) {
			for _, address := range host.addresses {
				endpoint, endpointErr := endpointForNSAddress(address, config.DirectPort)
				if endpointErr != nil {
					continue
				}
				tasks = append(tasks, nsProbeTask{domain: domain, host: host.name, role: host.role, resolver: endpoint})
			}
		}
		for _, resolver := range config.TrustedResolvers {
			tasks = append(tasks, nsProbeTask{domain: domain, host: resolver, role: "trusted", resolver: resolver, recursive: true})
		}
		tasks = append(tasks, nsProbeTask{domain: domain, host: config.RecursiveResolver, role: "recursive", resolver: config.RecursiveResolver, recursive: true})
	}
	fmt.Printf("NS 拨测 DNS 任务开始：事件 %s，受影响名称 %d，稳定 NS %d，变异 NS %d，DNS 请求 %d，并发 %d\n",
		event.ID, len(domains), len(stableHosts), len(variantHosts), len(tasks), config.MaxParallel)
	tasksStarted := time.Now()
	taskResults := runNSProbeTasks(ctx, tasks, config.Timeout, config.MaxParallel, config.Executor)
	fmt.Printf("NS 拨测 DNS 任务完成：事件 %s，返回 %d，耗时 %s\n", event.ID, len(taskResults), time.Since(tasksStarted).Round(time.Millisecond))
	result.Domains = make([]NSProbeDomainResult, 0, len(domains))
	verifiedDivergences, verifiedImpacts := 0, 0
	for _, domain := range domains {
		domainResult := buildNSProbeDomainResult(domain, stableHosts, variantHosts, taskResults)
		switch domainResult.Verdict {
		case "verified_ns_divergence":
			verifiedDivergences++
		case "verified_impact":
			verifiedDivergences++
			verifiedImpacts++
		}
		result.Domains = append(result.Domains, domainResult)
	}
	result.ProbedDomains = len(result.Domains)
	if verifiedImpacts > 0 {
		result.Verdict = "verified_impact"
		result.Summary = fmt.Sprintf("%d 个名称确认：受监控递归 DNS %s 已返回与变异 NS 一致、且偏离稳定 NS/可信 DNS 共识的结果", verifiedImpacts, config.RecursiveResolver)
	} else if verifiedDivergences > 0 {
		result.Verdict = "verified_ns_divergence"
		result.Summary = fmt.Sprintf("%d 个名称确认：变异 NS 返回结果与稳定 NS/可信 DNS 共识不一致", verifiedDivergences)
	} else {
		result.Summary = "本轮拨测未形成可验证的变异 NS 错误解析证据"
	}
	return result, nil
}

func applyNSProbeResult(event *NSChangeEvent, probe NSProbeResult) bool {
	if event == nil || (probe.Verdict != "verified_ns_divergence" && probe.Verdict != "verified_impact") {
		return false
	}
	event.Severity = "critical"
	event.Evidence = "verified"
	event.Status = probe.Verdict
	if !strings.Contains(event.Summary, probe.Summary) {
		event.Summary += "；" + probe.Summary
	}
	return true
}
