package main

import (
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	nsADBHealthHealthy      = "healthy"
	nsADBHealthUnknown      = "unknown"
	nsADBHealthSlow         = "slow"
	nsADBHealthDegraded     = "degraded"
	nsADBHealthEDNSDegraded = "edns_degraded"
	nsADBHealthSuspect      = "suspect"
)

type NSADBEndpointState struct {
	View, NSName, IP, LastSnapshotID string
	LastSeen                         time.Time
	SRTT                             uint32
	Flags                            string
	EDNSSuccess                      uint32
	EDNSTimeout4096                  uint32
	EDNSTimeout1432                  uint32
	EDNSTimeout1232                  uint32
	EDNSTimeout512                   uint32
	PlainSuccess                     uint32
	PlainTimeout                     uint32
	UDPSize                          uint16
	ADBTTL                           int32
	Health, Detail                   string
	ConsecutiveSuspect               uint16
}

type nsADBEndpointHistory struct {
	SnapshotID, View, NSName, IP, PreviousHealth, Health, Detail string
	CapturedAt                                                   time.Time
	ConsecutiveSuspect                                           uint16
	SRTT, PlainSuccess, PlainTimeout, EDNSSuccess, EDNSTimeout   uint32
}

func nsADBEndpointKey(view, name, ip string) string {
	return strings.Join([]string{view, normalizeFQDN(name), strings.TrimSpace(ip)}, "\x00")
}

func loadNSADBEndpointStates(db *sql.DB) (map[string]NSADBEndpointState, error) {
	rows, err := db.Query(`SELECT view, ns_name, ip, last_snapshot_id, last_seen, srtt, flags,
		edns_success, edns_timeout_4096, edns_timeout_1432, edns_timeout_1232, edns_timeout_512,
		plain_success, plain_timeout, udp_size, adb_ttl, health, consecutive_suspect, detail
		FROM ns_adb_endpoint_state FINAL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]NSADBEndpointState)
	for rows.Next() {
		var state NSADBEndpointState
		if err := rows.Scan(&state.View, &state.NSName, &state.IP, &state.LastSnapshotID, &state.LastSeen, &state.SRTT, &state.Flags,
			&state.EDNSSuccess, &state.EDNSTimeout4096, &state.EDNSTimeout1432, &state.EDNSTimeout1232, &state.EDNSTimeout512,
			&state.PlainSuccess, &state.PlainTimeout, &state.UDPSize, &state.ADBTTL, &state.Health, &state.ConsecutiveSuspect, &state.Detail); err != nil {
			return nil, err
		}
		result[nsADBEndpointKey(state.View, state.NSName, state.IP)] = state
	}
	return result, rows.Err()
}

func evaluateNSADBRecord(record ADBRecord) (string, string) {
	return evaluateNSADBRecordWithPrevious(record, nil, false)
}

func evaluateNSADBRecordWithPrevious(record ADBRecord, previous *NSADBEndpointState, adjacent bool) (string, string) {
	ednsTimeout := record.EDNSTimeout4096 + record.EDNSTimeout1432 + record.EDNSTimeout1232 + record.EDNSTimeout512
	if ednsTimeout == 0 {
		ednsTimeout = record.EDNSTimeout
	}
	ednsSuccess, plainSuccess := record.EDNSSuccess, record.PlainSuccess
	plainTimeout := record.PlainTimeout
	window := "当前 ADB 累计值"
	if adjacent && previous != nil {
		ednsSuccess = counterDelta(record.EDNSSuccess, int(previous.EDNSSuccess))
		ednsTimeout = counterDelta(ednsTimeout, int(previous.EDNSTimeout4096+previous.EDNSTimeout1432+previous.EDNSTimeout1232+previous.EDNSTimeout512))
		plainSuccess = counterDelta(record.PlainSuccess, int(previous.PlainSuccess))
		plainTimeout = counterDelta(record.PlainTimeout, int(previous.PlainTimeout))
		window = "相邻快照新增值"
	}
	totalSuccess, totalTimeout := ednsSuccess+plainSuccess, ednsTimeout+plainTimeout
	srttMS := float64(record.SRTT) / 1000
	if adbRecordDead(record.Flags) {
		return nsADBHealthSuspect, fmt.Sprintf("ADB 标记端点失效，SRTT %.1fms", srttMS)
	}
	if totalSuccess == 0 && totalTimeout >= 3 {
		return nsADBHealthSuspect, fmt.Sprintf("%s成功 0、超时 %d，SRTT %.1fms", window, totalTimeout, srttMS)
	}
	if record.SRTT >= 1_000_000 {
		return nsADBHealthDegraded, fmt.Sprintf("SRTT %.1fms，达到严重慢响应阈值", srttMS)
	}
	if record.SRTT >= 500_000 {
		if totalTimeout > 0 {
			return nsADBHealthDegraded, fmt.Sprintf("SRTT %.1fms 且%s超时 %d", srttMS, window, totalTimeout)
		}
		return nsADBHealthDegraded, fmt.Sprintf("SRTT %.1fms，超过 P99 近似阈值", srttMS)
	}
	if plainSuccess > 0 && ednsTimeout > 0 {
		return nsADBHealthEDNSDegraded, fmt.Sprintf("普通 DNS 可用，但%s EDNS 超时 %d", window, ednsTimeout)
	}
	if record.SRTT >= 250_000 {
		return nsADBHealthSlow, fmt.Sprintf("SRTT %.1fms，超过慢响应关注阈值", srttMS)
	}
	if record.SRTT == 0 && totalSuccess == 0 {
		return nsADBHealthUnknown, "ADB 尚无有效往返时延或成功响应样本"
	}
	return nsADBHealthHealthy, fmt.Sprintf("ADB 已观察到响应，SRTT %.1fms", srttMS)
}

func counterDelta(current, previous int) int {
	if current >= previous {
		return current - previous
	}
	return current
}

func adbRecordDead(flags string) bool {
	value, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(flags, "0x")), 16, 32)
	return err == nil && uint32(value)&0x80000000 != 0
}

func processNSADBEndpointHealth(summary SnapshotSummary, observations map[string]DomainNSObservation, records []ADBRecord, states map[string]NSADBEndpointState) ([]NSADBEndpointState, []nsADBEndpointHistory, []NSRiskFinding) {
	if states == nil {
		states = make(map[string]NSADBEndpointState)
	}
	referenced := make(map[string]struct{})
	for _, observation := range observations {
		for _, host := range observation.Nameservers {
			for _, address := range host.Addresses {
				referenced[nsADBEndpointKey(summary.View, host.Name, address.Address)] = struct{}{}
			}
		}
	}
	byKey := make(map[string]ADBRecord)
	for _, record := range records {
		key := nsADBEndpointKey(summary.View, record.Name, record.IP)
		if _, ok := referenced[key]; ok {
			byKey[key] = record
		}
	}

	updates := make([]NSADBEndpointState, 0)
	history := make([]nsADBEndpointHistory, 0)
	for key, record := range byKey {
		previous, exists := states[key]
		adjacent := exists && summary.CapturedAt.After(previous.LastSeen) && summary.CapturedAt.Sub(previous.LastSeen) <= 20*time.Minute
		var previousPtr *NSADBEndpointState
		if exists {
			previousPtr = &previous
		}
		health, detail := evaluateNSADBRecordWithPrevious(record, previousPtr, adjacent)
		consecutive := uint16(0)
		if health == nsADBHealthSuspect {
			consecutive = 1
			if adjacent && previous.Health == nsADBHealthSuspect {
				consecutive = previous.ConsecutiveSuspect + 1
			}
		}
		state := NSADBEndpointState{
			View: summary.View, NSName: normalizeFQDN(record.Name), IP: record.IP,
			LastSnapshotID: summary.ID, LastSeen: summary.CapturedAt.UTC(), SRTT: nonNegativeUint32(record.SRTT), Flags: record.Flags,
			EDNSSuccess: nonNegativeUint32(record.EDNSSuccess), EDNSTimeout4096: nonNegativeUint32(record.EDNSTimeout4096),
			EDNSTimeout1432: nonNegativeUint32(record.EDNSTimeout1432), EDNSTimeout1232: nonNegativeUint32(record.EDNSTimeout1232),
			EDNSTimeout512: nonNegativeUint32(record.EDNSTimeout512), PlainSuccess: nonNegativeUint32(record.PlainSuccess),
			PlainTimeout: nonNegativeUint32(record.PlainTimeout), UDPSize: nonNegativeUint16(record.UDPSize), ADBTTL: int32(record.TTL),
			Health: health, ConsecutiveSuspect: consecutive, Detail: detail,
		}
		states[key] = state
		shouldWrite := !exists || previous.Health != health || health == nsADBHealthSuspect || summary.CapturedAt.Sub(previous.LastSeen) >= time.Hour
		if shouldWrite {
			updates = append(updates, state)
		}
		if (!exists && health != nsADBHealthHealthy) || (exists && previous.Health != health) {
			history = append(history, nsADBEndpointHistory{
				SnapshotID: summary.ID, CapturedAt: summary.CapturedAt.UTC(), View: summary.View, NSName: state.NSName, IP: state.IP,
				PreviousHealth: previous.Health, Health: health, ConsecutiveSuspect: consecutive, SRTT: state.SRTT,
				PlainSuccess: state.PlainSuccess, PlainTimeout: state.PlainTimeout, EDNSSuccess: state.EDNSSuccess,
				EDNSTimeout: state.EDNSTimeout4096 + state.EDNSTimeout1432 + state.EDNSTimeout1232 + state.EDNSTimeout512, Detail: detail,
			})
		}
	}
	return updates, history, buildNSAvailabilityFindings(summary.View, observations, states)
}

func buildNSAvailabilityFindings(view string, observations map[string]DomainNSObservation, states map[string]NSADBEndpointState) []NSRiskFinding {
	findings := make([]NSRiskFinding, 0)
	for domain, observation := range observations {
		suspectHosts := make([]string, 0)
		endpointEvidence := make([]map[string]any, 0)
		for _, host := range observation.Nameservers {
			if len(host.Addresses) == 0 {
				continue
			}
			allSuspect := true
			matched := 0
			for _, address := range host.Addresses {
				state, ok := states[nsADBEndpointKey(view, host.Name, address.Address)]
				if !ok {
					allSuspect = false
					continue
				}
				matched++
				if state.Health != nsADBHealthSuspect || state.ConsecutiveSuspect < 2 {
					allSuspect = false
				}
				endpointEvidence = append(endpointEvidence, map[string]any{
					"ns": host.Name, "ip": address.Address, "health": state.Health, "consecutive": state.ConsecutiveSuspect,
					"srttMs": float64(state.SRTT) / 1000, "plainSuccess": state.PlainSuccess, "plainTimeout": state.PlainTimeout, "detail": state.Detail,
				})
			}
			if matched > 0 && allSuspect {
				suspectHosts = append(suspectHosts, host.Name)
			}
		}
		if len(suspectHosts) == 0 {
			continue
		}
		sort.Strings(suspectHosts)
		remaining := len(observation.Nameservers) - len(suspectHosts)
		severity := "medium"
		if remaining <= 1 {
			severity = "high"
		}
		extra := map[string]any{"suspectHosts": suspectHosts, "remainingNS": remaining, "endpoints": endpointEvidence}
		findings = append(findings, NSRiskFinding{
			Type: "ns_availability", Domain: normalizeFQDN(domain), Severity: severity,
			Summary:      fmt.Sprintf("%d 个 NS 主机的全部已知地址连续出现 ADB 超时/高时延，剩余 %d 个 NS，等待主动拨测确认", len(suspectHosts), remaining),
			ChangeFields: []string{"ADB 连续异常", fmt.Sprintf("剩余 NS %d", remaining)},
			Signature:    findingSignature("ns_availability", domain, map[string]any{"suspectHosts": suspectHosts}), Current: observation, Extra: extra,
		})
	}
	return findings
}

func insertNSADBEndpointStates(writer *nsClickHouseWriter, states []NSADBEndpointState) error {
	rows := make([][]any, 0, len(states))
	for _, state := range states {
		rows = append(rows, []any{state.View, state.NSName, state.IP, state.LastSnapshotID, state.LastSeen, state.SRTT, state.Flags,
			state.EDNSSuccess, state.EDNSTimeout4096, state.EDNSTimeout1432, state.EDNSTimeout1232, state.EDNSTimeout512,
			state.PlainSuccess, state.PlainTimeout, state.UDPSize, state.ADBTTL, state.Health, state.ConsecutiveSuspect, state.Detail})
	}
	return writer.batchInsert("ns_adb_endpoint_state", []string{"view", "ns_name", "ip", "last_snapshot_id", "last_seen", "srtt", "flags",
		"edns_success", "edns_timeout_4096", "edns_timeout_1432", "edns_timeout_1232", "edns_timeout_512", "plain_success", "plain_timeout",
		"udp_size", "adb_ttl", "health", "consecutive_suspect", "detail"}, rows, 1000)
}

func insertNSADBEndpointHistory(writer *nsClickHouseWriter, history []nsADBEndpointHistory) error {
	rows := make([][]any, 0, len(history))
	for _, item := range history {
		rows = append(rows, []any{item.SnapshotID, item.CapturedAt, item.View, item.NSName, item.IP, item.PreviousHealth, item.Health,
			item.ConsecutiveSuspect, item.SRTT, item.PlainSuccess, item.PlainTimeout, item.EDNSSuccess, item.EDNSTimeout, item.Detail})
	}
	return writer.batchInsert("ns_adb_endpoint_history", []string{"snapshot_id", "captured_at", "view", "ns_name", "ip", "previous_health", "health",
		"consecutive_suspect", "srtt", "plain_success", "plain_timeout", "edns_success", "edns_timeout", "detail"}, rows, 1000)
}

func nonNegativeUint32(value int) uint32 {
	if value <= 0 {
		return 0
	}
	return uint32(value)
}

func nonNegativeUint16(value int) uint16 {
	if value <= 0 {
		return 0
	}
	if value > int(^uint16(0)) {
		return ^uint16(0)
	}
	return uint16(value)
}
