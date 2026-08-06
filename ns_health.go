package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"sort"
	"time"
)

type NSHealthSummary struct {
	SnapshotID        string    `json:"snapshot_id"`
	CapturedAt        time.Time `json:"captured_at"`
	TotalZones        int       `json:"total_zones"`
	TotalHosts        int       `json:"total_hosts"`
	HostsWithAddress  int       `json:"hosts_with_address"`
	HostsWithADB      int       `json:"hosts_with_adb"`
	EndpointCoverage  float64   `json:"endpoint_coverage"`
	TotalEndpoints    int       `json:"total_endpoints"`
	HealthyEndpoints  int       `json:"healthy_endpoints"`
	SlowEndpoints     int       `json:"slow_endpoints"`
	DegradedEndpoints int       `json:"degraded_endpoints"`
	SuspectEndpoints  int       `json:"suspect_endpoints"`
	UnknownEndpoints  int       `json:"unknown_endpoints"`
	AffectedZones     int       `json:"affected_zones"`
	ReducedZones      int       `json:"reduced_zones"`
	UnavailableZones  int       `json:"unavailable_zones"`
	SRTTP50MS         float64   `json:"srtt_p50_ms"`
	SRTTP95MS         float64   `json:"srtt_p95_ms"`
	SRTTP99MS         float64   `json:"srtt_p99_ms"`
}

type NSHealthBucket struct {
	Label string `json:"label"`
	MinMS int    `json:"min_ms"`
	MaxMS int    `json:"max_ms"`
	Count int    `json:"count"`
}

type NSHealthEndpoint struct {
	NSName         string    `json:"ns_name"`
	Owner          string    `json:"owner"`
	IP             string    `json:"ip"`
	Health         string    `json:"health"`
	SRTTMS         float64   `json:"srtt_ms"`
	EDNSSuccess    uint32    `json:"edns_success"`
	EDNSTimeout    uint32    `json:"edns_timeout"`
	PlainSuccess   uint32    `json:"plain_success"`
	PlainTimeout   uint32    `json:"plain_timeout"`
	Consecutive    uint16    `json:"consecutive"`
	AffectedZones  int       `json:"affected_zones"`
	SoleDependency int       `json:"sole_dependency"`
	Flags          string    `json:"flags"`
	LastSeen       time.Time `json:"last_seen"`
	Detail         string    `json:"detail"`
}

type NSHealthProvider struct {
	Owner             string   `json:"owner"`
	HostCount         int      `json:"host_count"`
	EndpointCount     int      `json:"endpoint_count"`
	AbnormalEndpoints int      `json:"abnormal_endpoints"`
	AffectedZones     int      `json:"affected_zones"`
	MaxSRTTMS         float64  `json:"max_srtt_ms"`
	HostSample        []string `json:"host_sample"`
}

type NSHealthResponse struct {
	Summary     NSHealthSummary    `json:"summary"`
	Buckets     []NSHealthBucket   `json:"buckets"`
	Endpoints   []NSHealthEndpoint `json:"endpoints"`
	Providers   []NSHealthProvider `json:"providers"`
	Warnings    []string           `json:"warnings"`
	GeneratedAt time.Time          `json:"generated_at"`
}

type nsHealthCache struct {
	expiresAt time.Time
	response  NSHealthResponse
}

func (s *nsPersistentMonitorServer) v1NSHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeNSJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 GET"})
		return
	}
	limit := parseNSPositiveInt(r.URL.Query().Get("limit"), 100, 10, 500)
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	if cache := s.healthCache; cache != nil && time.Now().Before(cache.expiresAt) {
		writeNSJSON(w, http.StatusOK, nsHealthResponseWithLimit(cache.response, limit))
		return
	}
	dependency, err := s.cachedNSDependencyState(ctx, "")
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	states, err := loadNSADBEndpointStatesContext(ctx, s.store.db, dependency.snapshot.View, dependency.snapshot.CapturedAt)
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	response := buildNSHealthResponse(dependency, states, 500)
	s.healthCache = &nsHealthCache{expiresAt: time.Now().Add(2 * time.Minute), response: response}
	writeNSJSON(w, http.StatusOK, nsHealthResponseWithLimit(response, limit))
}

func (s *nsMonitorServer) v1NSHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeNSJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 GET"})
		return
	}
	writeNSJSON(w, http.StatusOK, NSHealthResponse{Buckets: []NSHealthBucket{}, Endpoints: []NSHealthEndpoint{}, Providers: []NSHealthProvider{}, Warnings: []string{}, GeneratedAt: time.Now().UTC()})
}

func loadNSADBEndpointStatesContext(ctx context.Context, db *sql.DB, view string, capturedAt time.Time) (map[string]NSADBEndpointState, error) {
	rows, err := db.QueryContext(ctx, `SELECT view, ns_name, ip, last_snapshot_id, last_seen, srtt, flags,
		edns_success, edns_timeout_4096, edns_timeout_1432, edns_timeout_1232, edns_timeout_512,
		plain_success, plain_timeout, udp_size, adb_ttl, health, consecutive_suspect, detail
		FROM ns_adb_endpoint_state FINAL
		WHERE view = ? AND last_seen >= ? AND last_seen <= ?`, view, capturedAt.Add(-20*time.Minute), capturedAt)
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

func nsHealthResponseWithLimit(response NSHealthResponse, limit int) NSHealthResponse {
	if limit >= len(response.Endpoints) {
		return response
	}
	copyResponse := response
	copyResponse.Endpoints = append([]NSHealthEndpoint(nil), response.Endpoints[:limit]...)
	return copyResponse
}

func buildNSHealthResponse(dependency nsDependencyState, states map[string]NSADBEndpointState, limit int) NSHealthResponse {
	response := NSHealthResponse{
		Summary:   NSHealthSummary{SnapshotID: dependency.snapshot.ID, CapturedAt: dependency.snapshot.CapturedAt, TotalZones: dependency.totalZones, TotalHosts: len(dependency.hosts)},
		Buckets:   []NSHealthBucket{{Label: "<50ms", MinMS: 0, MaxMS: 50}, {Label: "50–100ms", MinMS: 50, MaxMS: 100}, {Label: "100–250ms", MinMS: 100, MaxMS: 250}, {Label: "250–500ms", MinMS: 250, MaxMS: 500}, {Label: "500–1000ms", MinMS: 500, MaxMS: 1000}, {Label: "≥1000ms", MinMS: 1000, MaxMS: 0}},
		Endpoints: make([]NSHealthEndpoint, 0), Providers: make([]NSHealthProvider, 0), Warnings: make([]string, 0), GeneratedAt: time.Now().UTC(),
	}
	type hostStatus struct {
		matched, addresses int
		worst              string
		allSuspect         bool
	}
	hostStatuses := make(map[string]hostStatus, len(dependency.hosts))
	validSRTT := make([]float64, 0, len(states))
	providerHosts, providerZones := map[string]map[string]struct{}{}, map[string]map[string]struct{}{}
	providerEndpoints, providerAbnormal := map[string]int{}, map[string]int{}
	providerMaxSRTT := map[string]float64{}
	for host, aggregate := range dependency.hosts {
		if len(aggregate.addresses) > 0 {
			response.Summary.HostsWithAddress++
		}
		matched, allSuspect, worst := 0, len(aggregate.addresses) > 0, nsADBHealthUnknown
		for ip := range aggregate.addresses {
			state, ok := states[nsADBEndpointKey(dependency.snapshot.View, host, ip)]
			if !ok || !nsADBStateFreshForSnapshot(state, dependency.snapshot.CapturedAt) {
				allSuspect = false
				continue
			}
			matched++
			record := ADBRecord{SRTT: int(state.SRTT), Flags: state.Flags, EDNSSuccess: int(state.EDNSSuccess),
				EDNSTimeout4096: int(state.EDNSTimeout4096), EDNSTimeout1432: int(state.EDNSTimeout1432), EDNSTimeout1232: int(state.EDNSTimeout1232), EDNSTimeout512: int(state.EDNSTimeout512),
				PlainSuccess: int(state.PlainSuccess), PlainTimeout: int(state.PlainTimeout)}
			health, detail := evaluateNSADBState(state, record)
			if health != nsADBHealthSuspect {
				allSuspect = false
			}
			if nsADBHealthRank(health) > nsADBHealthRank(worst) {
				worst = health
			}
			response.Summary.TotalEndpoints++
			switch health {
			case nsADBHealthHealthy:
				response.Summary.HealthyEndpoints++
			case nsADBHealthSlow:
				response.Summary.SlowEndpoints++
			case nsADBHealthDegraded, nsADBHealthEDNSDegraded:
				response.Summary.DegradedEndpoints++
			case nsADBHealthSuspect:
				response.Summary.SuspectEndpoints++
			default:
				response.Summary.UnknownEndpoints++
			}
			totalSuccess := state.EDNSSuccess + state.PlainSuccess
			if state.SRTT > 0 && totalSuccess > 0 {
				value := float64(state.SRTT) / 1000
				validSRTT = append(validSRTT, value)
				for index := range response.Buckets {
					bucket := &response.Buckets[index]
					if int(value) >= bucket.MinMS && (bucket.MaxMS == 0 || int(value) < bucket.MaxMS) {
						bucket.Count++
						break
					}
				}
			}
			owner := aggregate.owner
			if owner == "" {
				owner = normalizeFQDN(registeredDomain(host))
			}
			if providerHosts[owner] == nil {
				providerHosts[owner], providerZones[owner] = map[string]struct{}{}, map[string]struct{}{}
			}
			providerHosts[owner][host] = struct{}{}
			providerEndpoints[owner]++
			if health != nsADBHealthHealthy && health != nsADBHealthUnknown {
				providerAbnormal[owner]++
			}
			if float64(state.SRTT)/1000 > providerMaxSRTT[owner] {
				providerMaxSRTT[owner] = float64(state.SRTT) / 1000
			}
			for zone := range aggregate.zones {
				providerZones[owner][zone] = struct{}{}
			}
			if health != nsADBHealthHealthy && health != nsADBHealthUnknown {
				sole := 0
				for zone := range aggregate.zones {
					if len(dependency.zoneHosts[zone]) == 1 {
						sole++
					}
				}
				response.Endpoints = append(response.Endpoints, NSHealthEndpoint{NSName: host, Owner: owner, IP: ip, Health: health, SRTTMS: float64(state.SRTT) / 1000,
					EDNSSuccess: state.EDNSSuccess, EDNSTimeout: state.EDNSTimeout4096 + state.EDNSTimeout1432 + state.EDNSTimeout1232 + state.EDNSTimeout512,
					PlainSuccess: state.PlainSuccess, PlainTimeout: state.PlainTimeout, Consecutive: state.ConsecutiveSuspect,
					AffectedZones: len(aggregate.zones), SoleDependency: sole, Flags: state.Flags, LastSeen: state.LastSeen, Detail: detail})
			}
		}
		if matched > 0 {
			response.Summary.HostsWithADB++
		}
		hostStatuses[host] = hostStatus{matched: matched, addresses: len(aggregate.addresses), worst: worst, allSuspect: allSuspect && matched == len(aggregate.addresses)}
	}
	if response.Summary.HostsWithAddress > 0 {
		response.Summary.EndpointCoverage = float64(response.Summary.HostsWithADB) / float64(response.Summary.HostsWithAddress)
	}
	for _, hosts := range dependency.zoneHosts {
		affected, unavailable, reduced := false, 0, false
		for host := range hosts {
			status := hostStatuses[host]
			if nsADBHealthRank(status.worst) >= nsADBHealthRank(nsADBHealthSlow) {
				affected = true
			}
			if status.allSuspect {
				unavailable++
				reduced = true
			}
		}
		if affected {
			response.Summary.AffectedZones++
		}
		if reduced {
			response.Summary.ReducedZones++
		}
		if len(hosts) > 0 && unavailable == len(hosts) {
			response.Summary.UnavailableZones++
		}
	}
	sort.Float64s(validSRTT)
	response.Summary.SRTTP50MS, response.Summary.SRTTP95MS, response.Summary.SRTTP99MS = percentile(validSRTT, .50), percentile(validSRTT, .95), percentile(validSRTT, .99)
	sort.Slice(response.Endpoints, func(i, j int) bool {
		left, right := response.Endpoints[i], response.Endpoints[j]
		if nsADBHealthRank(left.Health) != nsADBHealthRank(right.Health) {
			return nsADBHealthRank(left.Health) > nsADBHealthRank(right.Health)
		}
		if left.AffectedZones != right.AffectedZones {
			return left.AffectedZones > right.AffectedZones
		}
		return left.SRTTMS > right.SRTTMS
	})
	if len(response.Endpoints) > limit {
		response.Endpoints = response.Endpoints[:limit]
	}
	for owner, hosts := range providerHosts {
		if providerAbnormal[owner] == 0 {
			continue
		}
		response.Providers = append(response.Providers, NSHealthProvider{Owner: owner, HostCount: len(hosts), EndpointCount: providerEndpoints[owner], AbnormalEndpoints: providerAbnormal[owner], AffectedZones: len(providerZones[owner]), MaxSRTTMS: providerMaxSRTT[owner], HostSample: firstStrings(setKeys(hosts), 6)})
	}
	sort.Slice(response.Providers, func(i, j int) bool {
		if response.Providers[i].AffectedZones != response.Providers[j].AffectedZones {
			return response.Providers[i].AffectedZones > response.Providers[j].AffectedZones
		}
		return response.Providers[i].AbnormalEndpoints > response.Providers[j].AbnormalEndpoints
	})
	if len(response.Providers) > 30 {
		response.Providers = response.Providers[:30]
	}
	response.Warnings = append(response.Warnings, "SRTT 是当前递归器视角的平滑/惩罚状态，不代表全球网络时延；未主动拨测的疑似不可达仅作为快照线索。")
	return response
}

func evaluateNSADBState(state NSADBEndpointState, record ADBRecord) (string, string) {
	health, detail := evaluateNSADBRecord(record)
	if health != nsADBHealthSuspect || adbRecordDead(record.Flags) {
		return health, detail
	}
	if state.ConsecutiveSuspect > 0 {
		return health, fmt.Sprintf("相邻快照异常连续 %d 次；%s", state.ConsecutiveSuspect, detail)
	}
	// 只看累计计数无法确认超时是否发生在当前相邻快照。
	// 导入器已用相邻差值维护 consecutive_suspect；该值为 0 时
	// 降为证据不足，避免历史累计超时反复冒充本轮不可达。
	return nsADBHealthUnknown, "累计超时存在，但相邻快照未确认新增超时"
}

func nsADBStateFreshForSnapshot(state NSADBEndpointState, capturedAt time.Time) bool {
	if state.LastSeen.IsZero() || capturedAt.IsZero() {
		return false
	}
	delta := capturedAt.Sub(state.LastSeen)
	return delta >= 0 && delta <= 20*time.Minute
}

func nsADBHealthRank(health string) int {
	switch health {
	case nsADBHealthSuspect:
		return 5
	case nsADBHealthDegraded:
		return 4
	case nsADBHealthEDNSDegraded:
		return 3
	case nsADBHealthSlow:
		return 2
	case nsADBHealthHealthy:
		return 1
	default:
		return 0
	}
}

func percentile(sorted []float64, value float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	index := int(float64(len(sorted)-1)*value + .5)
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

func firstStrings(values []string, limit int) []string {
	if len(values) > limit {
		return values[:limit]
	}
	return values
}
