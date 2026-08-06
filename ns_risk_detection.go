package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// NSRiskFinding 是单份快照内可复算的风险事实。它不直接等于事件；
// 持久化层会把连续快照中的同一 signature 合并成事件，并在风险条件消失时恢复。
type NSRiskFinding struct {
	Type         string              `json:"type"`
	Domain       string              `json:"domain"`
	Severity     string              `json:"severity"`
	Summary      string              `json:"summary"`
	ChangeFields []string            `json:"change_fields"`
	Signature    string              `json:"signature"`
	Current      DomainNSObservation `json:"current"`
	Extra        map[string]any      `json:"extra"`
}

func DetectNSSnapshotRisks(cache *BindCache, observations map[string]DomainNSObservation) []NSRiskFinding {
	return DetectNSSnapshotRisksWithBlacklist(cache, observations, nil)
}

func DetectNSSnapshotRisksWithBlacklist(cache *BindCache, observations map[string]DomainNSObservation, blacklist *NSBlacklistIndex) []NSRiskFinding {
	findings := make([]NSRiskFinding, 0)
	for domain, observation := range observations {
		if finding, ok := detectNSRedundancyRisk(domain, observation); ok {
			findings = append(findings, finding)
		}
		if finding, ok := detectNSBlacklistRisk(domain, observation, blacklist); ok {
			findings = append(findings, finding)
		}
	}
	findings = append(findings, detectNSParentChildRisks(cache, observations)...)
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Type == findings[j].Type {
			return findings[i].Domain < findings[j].Domain
		}
		return findings[i].Type < findings[j].Type
	})
	return findings
}

func detectNSBlacklistRisk(domain string, observation DomainNSObservation, blacklist *NSBlacklistIndex) (NSRiskFinding, bool) {
	hits := blacklist.match(observation, observation.CapturedAt)
	if len(hits) == 0 {
		return NSRiskFinding{}, false
	}
	severity := "low"
	displayHits := make([]map[string]any, 0, len(hits))
	signatureHits := make([]string, 0, len(hits))
	for _, hit := range hits {
		confidence := map[string]string{"high": "高", "medium": "中", "low": "低"}[hit.Confidence]
		if hit.Confidence == "high" {
			severity = maxRiskSeverity(severity, "high")
		} else if hit.Confidence == "medium" {
			severity = maxRiskSeverity(severity, "medium")
		}
		displayHits = append(displayHits, map[string]any{
			"object": hit.Object, "rule": strings.ToUpper(hit.ObjectType) + " 匹配",
			"source": hit.Source, "version": hit.Version, "confidence": confidence,
			"category": hit.Category, "effective": hit.Effective.Format("2006-01-02"),
			"expire": hit.Expires.Format("2006-01-02"), "desc": hit.Description, "note": "",
		})
		signatureHits = append(signatureHits, hit.ObjectType+"|"+hit.Object+"|"+hit.Source+"|"+hit.Version)
	}
	sort.Strings(signatureHits)
	extra := map[string]any{"hits": displayHits, "stillInUse": true, "whitelisted": false, "matchKeys": signatureHits}
	return NSRiskFinding{
		Type: "ns_blacklist", Domain: normalizeFQDN(domain), Severity: severity,
		Summary:      fmt.Sprintf("当前 NS 命中 %d 条仍在有效期内的离线黑名单规则", len(hits)),
		ChangeFields: []string{"NS 黑名单命中"}, Signature: findingSignature("ns_blacklist", domain, map[string]any{"matchKeys": signatureHits}),
		Current: observation, Extra: extra,
	}, true
}

func detectNSRedundancyRisk(domain string, observation DomainNSObservation) (NSRiskFinding, bool) {
	hosts := observation.Nameservers
	if len(hosts) == 0 {
		return NSRiskFinding{}, false
	}

	reasons := make([]string, 0)
	severity := "low"
	uniqueIPs := make(map[string]struct{})
	uniqueNetworks := make(map[string]struct{})
	ipHosts := make(map[string]map[string]struct{})
	networkHosts := make(map[string]map[string]struct{})
	resolvedHosts := 0
	for _, host := range hosts {
		hasAddress := false
		for _, address := range host.Addresses {
			addr, err := netip.ParseAddr(address.Address)
			if err != nil {
				continue
			}
			hasAddress = true
			ip, network := addr.String(), redundancyNetwork(addr)
			uniqueIPs[ip] = struct{}{}
			uniqueNetworks[network] = struct{}{}
			if ipHosts[ip] == nil {
				ipHosts[ip] = make(map[string]struct{})
			}
			if networkHosts[network] == nil {
				networkHosts[network] = make(map[string]struct{})
			}
			ipHosts[ip][host.Name] = struct{}{}
			networkHosts[network][host.Name] = struct{}{}
		}
		if hasAddress {
			resolvedHosts++
		}
	}

	if len(hosts) == 1 {
		reasons = append(reasons, "仅一个 NS 主机名")
	}
	sharedIPs := sharedEndpointKeys(ipHosts)
	sharedNetworks := sharedEndpointKeys(networkHosts)
	if len(sharedIPs) > 0 {
		reasons = append(reasons, "多 NS 指向同一 IP")
		severity = maxRiskSeverity(severity, "medium")
	}
	if len(sharedIPs) == 0 && len(sharedNetworks) > 0 {
		reasons = append(reasons, "多 NS 位于同一网段")
		severity = maxRiskSeverity(severity, "medium")
	}
	if len(reasons) == 0 {
		return NSRiskFinding{}, false
	}

	extra := map[string]any{
		"singleReason":     strings.Join(reasons, "；"),
		"nsCount":          len(hosts),
		"resolvedNsCount":  resolvedHosts,
		"endpointCoverage": float64(resolvedHosts) / float64(len(hosts)),
		"uniqueIPs":        sortedStringKeys(uniqueIPs),
		"uniqueNetworks":   sortedStringKeys(uniqueNetworks),
		"sharedIPs":        sharedIPs,
		"sharedNetworks":   sharedNetworks,
	}
	signature := findingSignature("ns_single", domain, extra)
	return NSRiskFinding{
		Type: "ns_single", Domain: normalizeFQDN(domain), Severity: severity,
		Summary:      fmt.Sprintf("%s，存在 NS 冗余或基础设施单点风险", strings.Join(reasons, "；")),
		ChangeFields: append([]string(nil), reasons...), Signature: signature, Current: observation, Extra: extra,
	}, true
}

func sharedEndpointKeys(hostsByEndpoint map[string]map[string]struct{}) []string {
	result := make([]string, 0)
	for endpoint, hosts := range hostsByEndpoint {
		if len(hosts) >= 2 {
			result = append(result, endpoint)
		}
	}
	sort.Strings(result)
	return result
}

func redundancyNetwork(address netip.Addr) string {
	bits := 48
	if address.Is4() {
		bits = 24
	}
	return netip.PrefixFrom(address, bits).Masked().String()
}

func detectNSParentChildRisks(cache *BindCache, observations map[string]DomainNSObservation) []NSRiskFinding {
	if cache == nil {
		return nil
	}
	result := make([]NSRiskFinding, 0)
	for domain, record := range cache.records {
		parent := make(map[string]struct{})
		child := make(map[string]struct{})
		for _, ns := range record.NSs {
			host := normalizeFQDN(ns.NsDomain)
			if host == "" {
				continue
			}
			// authauthority 是权威响应 Authority 区中的委派线索；authanswer
			// 是直接权威 Answer。unknown/glue/additional 等不能证明 NS RRset
			// 的父子来源，不再用于构造父侧集合。
			switch ns.Attribute {
			case "authauthority":
				parent[host] = struct{}{}
			case "authanswer":
				child[host] = struct{}{}
			}
		}
		if len(parent) == 0 || len(child) == 0 {
			continue
		}
		parentNS, childNS := sortedStringKeys(parent), sortedStringKeys(child)
		gluePairs, glueMismatch := parentChildGlueEvidence(cache, parentNS)
		setMismatch := !sameStringSet(parent, child)
		if !setMismatch && !glueMismatch {
			continue
		}
		dnssec := "快照中未观察到 DS/DNSKEY/RRSIG（不能据此判定未部署）"
		if len(record.DSs) > 0 || len(record.DNSKEYs) > 0 || len(record.RRSIGs) > 0 {
			dnssec = "快照中存在 DNSSEC 相关记录（签名链尚未主动验证）"
		}
		changeFields := make([]string, 0, 2)
		summaryParts := make([]string, 0, 2)
		severity := "medium"
		if setMismatch {
			changeFields = append(changeFields, "父子 NS 集合不一致")
			summaryParts = append(summaryParts, fmt.Sprintf("父区委派 NS 与子区权威 NS 集合不一致（父区 %d，子区 %d）", len(parentNS), len(childNS)))
		}
		if glueMismatch {
			changeFields = append(changeFields, "Glue 与实际地址不一致")
			summaryParts = append(summaryParts, "可比地址族中的 Glue 与实际地址不一致")
		}
		extra := map[string]any{
			"parentNs": parentNS, "childNs": childNS,
			"sourceBasis":  "cache_authauthority_vs_authanswer",
			"glueMismatch": glueMismatch, "gluePairs": gluePairs,
			"dnssec":                  dnssec,
			"authoritativeProbeState": "按策略不自动拨测；当前仅为缓存快照线索",
		}
		observation := observations[normalizeFQDN(domain)]
		signature := findingSignature("ns_parent_child", domain, map[string]any{
			"parentNs": parentNS, "childNs": childNS,
			"glueMismatch": glueMismatch, "gluePairs": gluePairs,
		})
		result = append(result, NSRiskFinding{
			Type: "ns_parent_child", Domain: normalizeFQDN(domain), Severity: severity,
			Summary:      strings.Join(summaryParts, "；"),
			ChangeFields: changeFields, Signature: signature, Current: observation, Extra: extra,
		})
	}
	return result
}

func parentChildGlueEvidence(cache *BindCache, hosts []string) ([]map[string]string, bool) {
	pairs := make([]map[string]string, 0)
	mismatch := false
	for _, host := range hosts {
		record, exists := cache.records[normalizeFQDN(host)]
		if !exists {
			continue
		}
		glue4, glue6 := make([]string, 0), make([]string, 0)
		actual4, actual6 := make([]string, 0), make([]string, 0)
		appendAddress := func(raw, attribute string) {
			addr, err := netip.ParseAddr(strings.TrimSpace(raw))
			if err != nil {
				return
			}
			var target *[]string
			switch attribute {
			case "glue", "additional":
				if addr.Is4() {
					target = &glue4
				} else {
					target = &glue6
				}
			case "answer", "authanswer":
				if addr.Is4() {
					target = &actual4
				} else {
					target = &actual6
				}
			default:
				return
			}
			*target = append(*target, addr.String())
		}
		for _, address := range record.As {
			appendAddress(address.IP, address.Attribute)
		}
		for _, address := range record.AAAAs {
			appendAddress(address.IP, address.Attribute)
		}
		glue4, glue6 = uniqueSortedStrings(glue4), uniqueSortedStrings(glue6)
		actual4, actual6 = uniqueSortedStrings(actual4), uniqueSortedStrings(actual6)
		glue := append(append([]string(nil), glue4...), glue6...)
		actual := append(append([]string(nil), actual4...), actual6...)
		if len(glue) == 0 && len(actual) == 0 {
			continue
		}
		familyMismatch := (len(glue4) > 0 && len(actual4) > 0 && !equalStrings(glue4, actual4)) ||
			(len(glue6) > 0 && len(actual6) > 0 && !equalStrings(glue6, actual6))
		if familyMismatch {
			mismatch = true
		}
		pairs = append(pairs, map[string]string{
			"host": host, "glue": strings.Join(glue, ", "), "actual": strings.Join(actual, ", "),
			"comparison": map[bool]string{true: "mismatch", false: "incomplete_or_equal"}[familyMismatch],
		})
	}
	return pairs, mismatch
}

func maxRiskSeverity(left, right string) string {
	if riskRank(right) > riskRank(left) {
		return right
	}
	return left
}

func findingSignature(riskType, domain string, extra map[string]any) string {
	raw, _ := json.Marshal(extra)
	return shortHash(strings.Join([]string{riskType, normalizeFQDN(domain), string(raw)}, "\x00"))
}

func sameStringSet(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for value := range left {
		if _, ok := right[value]; !ok {
			return false
		}
	}
	return true
}

func sortedStringKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sortedUint32Keys(values map[uint32]struct{}) []uint32 {
	result := make([]uint32, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}
