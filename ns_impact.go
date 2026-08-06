package main

import (
	"sort"
	"strings"
	"time"
)

// NSEventAffectedDomain 是缓存快照中可追溯的受影响名称。Target 是 CNAME 的
// 下一跳；CNAMEHops=1 表示直接指向事件域或其子域，>1 表示 CNAME 链继续上游。
type NSEventAffectedDomain struct {
	Domain    string `json:"domain"`
	Target    string `json:"target,omitempty"`
	CNAMEHops int    `json:"cname_hops,omitempty"`
}

type NSEventImpactGroup struct {
	Type        string                  `json:"type"`
	Title       string                  `json:"title"`
	Description string                  `json:"description"`
	Domains     []NSEventAffectedDomain `json:"domains"`
}

// NSEventImpactResponse 是按需计算的影响面。它只陈述风险状态所在缓存快照中
// 实际观察到的名称，不把递归缓存误表述为权威区文件或全网域名清单。
type NSEventImpactResponse struct {
	EventID              string               `json:"event_id"`
	EventDomain          string               `json:"event_domain"`
	SnapshotID           string               `json:"snapshot_id"`
	ObservedAt           string               `json:"observed_at"`
	TotalAffectedDomains int                  `json:"total_affected_domains"`
	Groups               []NSEventImpactGroup `json:"groups"`
	Scope                string               `json:"scope"`
}

type cnameEdge struct {
	owner  string
	target string
}

type cnameImpact struct {
	domain string
	target string
	hops   int
}

func isNameInDomain(name, domain string) bool {
	name, domain = normalizeFQDN(name), normalizeFQDN(domain)
	if name == "" || domain == "" {
		return false
	}
	name = strings.TrimSuffix(name, ".")
	domain = strings.TrimSuffix(domain, ".")
	return name == domain || strings.HasSuffix(name, "."+domain)
}

func cacheCNAMEEdges(cache *BindCache) []cnameEdge {
	edges := make([]cnameEdge, 0)
	if cache == nil {
		return edges
	}
	for owner, record := range cache.records {
		for _, cname := range record.CNAMEs {
			if cname.Rcode != "" || strings.TrimSpace(cname.IP) == "" {
				continue
			}
			edges = append(edges, cnameEdge{owner: normalizeFQDN(owner), target: normalizeFQDN(cname.IP)})
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].owner == edges[j].owner {
			return edges[i].target < edges[j].target
		}
		return edges[i].owner < edges[j].owner
	})
	return edges
}

func sortedAffectedDomains(items map[string]cnameImpact) []NSEventAffectedDomain {
	keys := make([]string, 0, len(items))
	for domain := range items {
		keys = append(keys, domain)
	}
	sort.Strings(keys)
	result := make([]NSEventAffectedDomain, 0, len(keys))
	for _, domain := range keys {
		item := items[domain]
		result = append(result, NSEventAffectedDomain{Domain: item.domain, Target: item.target, CNAMEHops: item.hops})
	}
	return result
}

// buildNSEventImpact 以发生 NS 异常的事件域为根：
//  1. 事件域本身及所有已缓存子域均受影响；
//  2. 所有 CNAME 直接指向该域名空间的外部名称均受影响；
//  3. CNAME 的上游引用会继续递归追踪，以覆盖多跳别名链。
func buildNSEventImpact(event NSChangeEvent, snapshotID string, cache *BindCache) NSEventImpactResponse {
	eventDomain := normalizeFQDN(event.Domain)
	result := NSEventImpactResponse{
		EventID:     event.ID,
		EventDomain: eventDomain,
		SnapshotID:  snapshotID,
		ObservedAt:  event.Current.CapturedAt.UTC().Format(time.RFC3339),
		Groups:      make([]NSEventImpactGroup, 0, 3),
		Scope:       "同一风险状态缓存快照中：事件域及其已缓存子域，以及 CNAME 最终指向该域名空间的外部域名；不等同于权威区文件或全网域名清单。",
	}
	if cache == nil || eventDomain == "" {
		return result
	}

	zoneNames := make(map[string]cnameImpact)
	for domain := range cache.records {
		domain = normalizeFQDN(domain)
		if isNameInDomain(domain, eventDomain) {
			zoneNames[domain] = cnameImpact{domain: domain}
		}
	}
	if _, exists := zoneNames[eventDomain]; !exists {
		// 即使 dump 中未保留事件域的完整 RR，也应把产生告警的域本身纳入影响面。
		zoneNames[eventDomain] = cnameImpact{domain: eventDomain}
	}

	edges := cacheCNAMEEdges(cache)
	direct := make(map[string]cnameImpact)
	reverse := make(map[string][]cnameEdge)
	for _, edge := range edges {
		reverse[edge.target] = append(reverse[edge.target], edge)
		if !isNameInDomain(edge.owner, eventDomain) && isNameInDomain(edge.target, eventDomain) {
			if _, exists := direct[edge.owner]; !exists {
				direct[edge.owner] = cnameImpact{domain: edge.owner, target: edge.target, hops: 1}
			}
		}
	}

	chain := make(map[string]cnameImpact)
	queue := make([]cnameImpact, 0, len(direct))
	for _, item := range direct {
		queue = append(queue, item)
	}
	sort.Slice(queue, func(i, j int) bool { return queue[i].domain < queue[j].domain })
	for index := 0; index < len(queue); index++ {
		current := queue[index]
		for _, edge := range reverse[current.domain] {
			if isNameInDomain(edge.owner, eventDomain) {
				continue
			}
			if _, exists := direct[edge.owner]; exists {
				continue
			}
			if _, exists := chain[edge.owner]; exists {
				continue
			}
			item := cnameImpact{domain: edge.owner, target: edge.target, hops: current.hops + 1}
			chain[edge.owner] = item
			queue = append(queue, item)
		}
	}

	if items := sortedAffectedDomains(zoneNames); len(items) > 0 {
		result.Groups = append(result.Groups, NSEventImpactGroup{
			Type:        "zone_descendants",
			Title:       "事件域及其子域",
			Description: "缓存记录 owner 位于事件域名空间内。",
			Domains:     items,
		})
	}
	if items := sortedAffectedDomains(direct); len(items) > 0 {
		result.Groups = append(result.Groups, NSEventImpactGroup{
			Type:        "cname_direct",
			Title:       "CNAME 直接承载域名",
			Description: "外部域名的 CNAME 直接指向事件域或其子域。",
			Domains:     items,
		})
	}
	if items := sortedAffectedDomains(chain); len(items) > 0 {
		result.Groups = append(result.Groups, NSEventImpactGroup{
			Type:        "cname_chain",
			Title:       "CNAME 链上游域名",
			Description: "通过已命中的 CNAME 别名继续反向追踪得到。",
			Domains:     items,
		})
	}

	uniqueDomains := make(map[string]struct{})
	for _, group := range result.Groups {
		for _, domain := range group.Domains {
			uniqueDomains[domain.Domain] = struct{}{}
		}
	}
	result.TotalAffectedDomains = len(uniqueDomains)
	return result
}
