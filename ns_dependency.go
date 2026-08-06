package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type NSDependencyHost struct {
	Host             string   `json:"host"`
	Owner            string   `json:"owner"`
	ZoneCount        int      `json:"zone_count"`
	Addresses        []string `json:"addresses"`
	ASNs             []string `json:"asns"`
	ASNOrganizations []string `json:"asn_organizations"`
	Countries        []string `json:"countries"`
	MetadataCoverage float64  `json:"metadata_coverage"`
	ZoneSample       []string `json:"zone_sample"`
}

type NSDependencyResponse struct {
	Snapshot         NSOwnershipSnapshot `json:"snapshot"`
	TotalZones       int                 `json:"total_zones"`
	TotalHosts       int                 `json:"total_hosts"`
	TotalOwners      int                 `json:"total_owners"`
	TotalCountries   int                 `json:"total_countries"`
	Hosts            []NSDependencyHost  `json:"hosts"`
	SelectedHost     *NSDependencyHost   `json:"selected_host,omitempty"`
	AffectedZones    []string            `json:"affected_zones"`
	TotalAffected    int                 `json:"total_affected"`
	SoleDependency   int                 `json:"sole_dependency"`
	WithAlternatives int                 `json:"with_alternatives"`
	Page             int                 `json:"page"`
	Limit            int                 `json:"limit"`
}

type nsDependencyHostAggregate struct {
	owner            string
	zones            map[string]struct{}
	addresses        map[string]struct{}
	asns             map[string]struct{}
	asnOrganizations map[string]struct{}
	countries        map[string]struct{}
	addressCount     int
	metadataCount    int
}

type nsDependencyState struct {
	snapshot   NSOwnershipSnapshot
	totalZones int
	hosts      map[string]*nsDependencyHostAggregate
	zoneHosts  map[string]map[string]struct{}
}

type nsDependencyCache struct {
	snapshotID string
	expiresAt  time.Time
	state      nsDependencyState
}

func addStringValue(values map[string]struct{}, value string) {
	value = strings.TrimSpace(value)
	if value != "" {
		values[value] = struct{}{}
	}
}

func buildNSDependencyState(snapshot NSOwnershipSnapshot, observations map[string][]NSHostObservation) nsDependencyState {
	state := nsDependencyState{snapshot: snapshot, totalZones: len(observations), hosts: map[string]*nsDependencyHostAggregate{}, zoneHosts: map[string]map[string]struct{}{}}
	for zone, nameservers := range observations {
		zone = normalizeFQDN(zone)
		for _, nameserver := range nameservers {
			host := normalizeFQDN(nameserver.Name)
			if host == "" {
				continue
			}
			if state.zoneHosts[zone] == nil {
				state.zoneHosts[zone] = map[string]struct{}{}
			}
			state.zoneHosts[zone][host] = struct{}{}
			aggregate := state.hosts[host]
			if aggregate == nil {
				owner := nameserver.RegisteredDomain
				if owner == "" {
					owner = registeredDomain(host)
				}
				aggregate = &nsDependencyHostAggregate{owner: normalizeFQDN(owner), zones: map[string]struct{}{}, addresses: map[string]struct{}{}, asns: map[string]struct{}{}, asnOrganizations: map[string]struct{}{}, countries: map[string]struct{}{}}
				state.hosts[host] = aggregate
			}
			aggregate.zones[zone] = struct{}{}
			for _, address := range nameserver.Addresses {
				aggregate.addressCount++
				addStringValue(aggregate.addresses, address.Address)
				if address.MetadataAvailable {
					aggregate.metadataCount++
				}
				if address.ASN != 0 {
					addStringValue(aggregate.asns, "AS"+strconv.FormatUint(uint64(address.ASN), 10))
				}
				addStringValue(aggregate.asnOrganizations, address.ASNOrganization)
				addStringValue(aggregate.countries, address.Country)
			}
		}
	}
	return state
}

func dependencyHostFromAggregate(host string, aggregate *nsDependencyHostAggregate, sampleLimit int) NSDependencyHost {
	coverage := 0.0
	if aggregate.addressCount > 0 {
		coverage = float64(aggregate.metadataCount) / float64(aggregate.addressCount)
	}
	zones := setKeys(aggregate.zones)
	if sampleLimit >= 0 && len(zones) > sampleLimit {
		zones = zones[:sampleLimit]
	}
	return NSDependencyHost{
		Host: host, Owner: aggregate.owner, ZoneCount: len(aggregate.zones), Addresses: setKeys(aggregate.addresses), ASNs: setKeys(aggregate.asns),
		ASNOrganizations: setKeys(aggregate.asnOrganizations), Countries: setKeys(aggregate.countries), MetadataCoverage: coverage, ZoneSample: zones,
	}
}

func filterNSDependencyHosts(state nsDependencyState, query string, limit int) []NSDependencyHost {
	query = strings.ToLower(strings.TrimSpace(query))
	hosts := make([]NSDependencyHost, 0, len(state.hosts))
	for host, aggregate := range state.hosts {
		item := dependencyHostFromAggregate(host, aggregate, 8)
		if query != "" {
			values := append([]string{item.Host, item.Owner}, item.Addresses...)
			values = append(values, item.ASNs...)
			values = append(values, item.ASNOrganizations...)
			values = append(values, item.Countries...)
			matched := false
			for _, value := range values {
				if strings.Contains(strings.ToLower(value), query) {
					matched = true
					break
				}
			}
			if !matched {
				for zone := range aggregate.zones {
					if strings.Contains(strings.ToLower(zone), query) {
						matched = true
						break
					}
				}
			}
			if !matched {
				continue
			}
		}
		hosts = append(hosts, item)
	}
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].ZoneCount == hosts[j].ZoneCount {
			return hosts[i].Host < hosts[j].Host
		}
		return hosts[i].ZoneCount > hosts[j].ZoneCount
	})
	if limit > 0 && len(hosts) > limit {
		hosts = hosts[:limit]
	}
	return hosts
}

func (s *nsPersistentStore) loadNSDependencyState(ctx context.Context, selectedID string) (nsDependencyState, error) {
	// snapshot catalog 每个 snapshot_id 在导入账本中保证唯一；这里仅取
	// 最新时间点，避免 FINAL 在持续写入期间强制合并整张目录表。
	query := `SELECT snapshot_id, captured_at, view FROM ns_snapshot_catalog ORDER BY captured_at DESC, snapshot_id DESC LIMIT 1`
	args := make([]any, 0, 1)
	if selectedID != "" {
		query = `SELECT snapshot_id, captured_at, view FROM ns_snapshot_catalog WHERE snapshot_id = ? ORDER BY imported_at DESC LIMIT 1`
		args = append(args, selectedID)
	}
	var snapshot NSOwnershipSnapshot
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&snapshot.ID, &snapshot.CapturedAt, &snapshot.View); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nsDependencyState{}, errNSPersistentNotFound
		}
		return nsDependencyState{}, err
	}
	// snapshot_id 是表排序键的首列，且导入账本保证同一快照不重复写入。
	// 直接 PREWHERE 读取该快照；避免 FINAL 或 GROUP BY/argMax 在持续写入时
	// 对整个月分区做合并聚合。若历史上曾重复导入，后读到的同域名行会覆盖前值。
	monthStart := time.Date(snapshot.CapturedAt.Year(), snapshot.CapturedAt.Month(), 1, 0, 0, 0, 0, time.UTC)
	monthEnd := monthStart.AddDate(0, 1, 0)
	rows, err := s.db.QueryContext(ctx, `SELECT domain, nameservers_json
		FROM ns_domain_observations
		PREWHERE captured_at >= ? AND captured_at < ? AND snapshot_id = ?`, monthStart, monthEnd, snapshot.ID)
	if err != nil {
		return nsDependencyState{}, err
	}
	defer rows.Close()
	observations := map[string][]NSHostObservation{}
	for rows.Next() {
		var domain, raw string
		if err := rows.Scan(&domain, &raw); err != nil {
			return nsDependencyState{}, err
		}
		var nameservers []NSHostObservation
		if err := json.Unmarshal([]byte(raw), &nameservers); err != nil {
			return nsDependencyState{}, err
		}
		observations[normalizeFQDN(domain)] = nameservers
	}
	if err := rows.Err(); err != nil {
		return nsDependencyState{}, err
	}
	return buildNSDependencyState(snapshot, observations), nil
}

func (s *nsPersistentMonitorServer) cachedNSDependencyState(ctx context.Context, snapshotID string) (nsDependencyState, error) {
	s.dependencyMu.Lock()
	defer s.dependencyMu.Unlock()
	now := time.Now()
	if cache := s.dependencyCache; cache != nil && now.Before(cache.expiresAt) && (snapshotID == "" || cache.snapshotID == snapshotID) {
		return cache.state, nil
	}
	state, err := s.store.loadNSDependencyState(ctx, snapshotID)
	if err != nil {
		return nsDependencyState{}, err
	}
	s.dependencyCache = &nsDependencyCache{snapshotID: state.snapshot.ID, expiresAt: now.Add(2 * time.Minute), state: state}
	return state, nil
}

func (s *nsPersistentMonitorServer) v1NSDependencies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeNSJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 GET"})
		return
	}
	nodeLimit := parseNSPositiveInt(r.URL.Query().Get("node_limit"), 240, 20, 500)
	page := parseNSPositiveInt(r.URL.Query().Get("page"), 1, 1, 10000)
	pageLimit := parseNSPositiveInt(r.URL.Query().Get("limit"), 100, 1, 300)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	state, err := s.cachedNSDependencyState(ctx, strings.TrimSpace(r.URL.Query().Get("snapshot_id")))
	if errors.Is(err, errNSPersistentNotFound) {
		writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "快照不存在"})
		return
	}
	if err != nil {
		nsPersistentError(w, err)
		return
	}
	hosts := filterNSDependencyHosts(state, r.URL.Query().Get("q"), nodeLimit)
	owners, countries := map[string]struct{}{}, map[string]struct{}{}
	for _, aggregate := range state.hosts {
		owners[aggregate.owner] = struct{}{}
		for country := range aggregate.countries {
			countries[country] = struct{}{}
		}
	}
	response := NSDependencyResponse{Snapshot: state.snapshot, TotalZones: state.totalZones, TotalHosts: len(state.hosts), TotalOwners: len(owners), TotalCountries: len(countries), Hosts: hosts, AffectedZones: make([]string, 0), Page: page, Limit: pageLimit}
	selectedHost := normalizeFQDN(r.URL.Query().Get("host"))
	if selectedHost != "" {
		aggregate := state.hosts[selectedHost]
		if aggregate == nil {
			writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "NS主机不存在"})
			return
		}
		selected := dependencyHostFromAggregate(selectedHost, aggregate, 20)
		response.SelectedHost = &selected
		zones := setKeys(aggregate.zones)
		response.TotalAffected = len(zones)
		for _, zone := range zones {
			if len(state.zoneHosts[zone]) <= 1 {
				response.SoleDependency++
			} else {
				response.WithAlternatives++
			}
		}
		start := (page - 1) * pageLimit
		if start < len(zones) {
			response.AffectedZones = zones[start:minInt(start+pageLimit, len(zones))]
		}
	}
	writeNSJSON(w, http.StatusOK, response)
}

func (s *nsMonitorServer) v1NSDependencies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeNSJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 GET"})
		return
	}
	writeNSJSON(w, http.StatusOK, NSDependencyResponse{Hosts: make([]NSDependencyHost, 0), AffectedZones: make([]string, 0), Page: 1, Limit: 100})
}
