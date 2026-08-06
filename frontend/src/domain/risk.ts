export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'recovered' | 'unknown'
export type EvidenceLevel = 'cache_hint' | 'repeated' | 'pending_verify' | 'auth_divergence' | 'impact_confirmed'
export type EventStatus = 'active' | 'pending' | 'confirmed' | 'recovered' | 'excluded' | 'ignored'
export type RiskType = 'ns_change' | 'ns_single' | 'ns_parent_child' | 'ns_blacklist' | 'ns_availability'

export const RISK_TYPE_LABEL: Record<RiskType, string> = {
  ns_change: 'NS 变化',
  ns_single: 'NS 单一/冗余',
  ns_parent_child: '父子 NS 不一致',
  ns_blacklist: 'NS 黑名单命中',
  ns_availability: 'NS 可用性',
}

export const LEVEL_LABEL: Record<RiskLevel, string> = {
  critical: '严重', high: '高风险', medium: '中风险', low: '低风险', recovered: '已恢复', unknown: '未知',
}

export const EVIDENCE_LABEL: Record<EvidenceLevel, string> = {
  cache_hint: '缓存观测线索',
  repeated: '重复异常',
  pending_verify: '待验证',
  auth_divergence: '已确认权威分歧',
  impact_confirmed: '已确认实际影响',
}

export const STATUS_LABEL: Record<EventStatus, string> = {
  active: '活动中', pending: '待验证', confirmed: '已确认', recovered: '已恢复', excluded: '已排除', ignored: '已忽略',
}

export interface NsRecord {
  host: string
  ips: string[]
  asn: string
  asnOrg: string
  country: string
  reachable?: boolean
  rttMs?: number
}

export interface ProbeResult {
  domain?: string
  role?: 'stable' | 'variant' | string
  ns: string
  ip: string
  reachable: boolean | null
  rttMs: number | null
  answerConsistent: boolean | null
  detail: string
  answer?: ProbeAnswer
  stableConsensus?: ProbeAnswer
  differences?: ProbeFieldDiff[]
}

export interface ProbeAnswer {
  rcode: string
  cname: string[]
  a: string[]
  aaaa: string[]
  authorityNs: string[]
  error?: string
}

export interface ProbeFieldDiff {
  field: string
  label: string
  stable: string[]
  current: string[]
  changed: boolean
  note?: string
}

export interface ProbeComparison {
  domain: string
  verdict: string
  summary: string
  stable?: ProbeAnswer
  trusted?: ProbeAnswer
  recursive: ProbeAnswer
  trustedDifferences?: ProbeFieldDiff[]
  recursiveDifferences?: ProbeFieldDiff[]
}

export interface TimelineNode {
  time: string
  kind: 'start' | 'repeat' | 'baseline' | 'verify' | 'recover' | 'alert'
  title: string
  detail?: string
}

export interface AlertRecord {
  time: string
  channel: string
  target: string
  status: '已送达' | '发送失败' | '已抑制(合并)'
  content: string
}

export interface RiskEvent {
  id: string
  type: RiskType
  domain: string
  level: RiskLevel
  evidence: EvidenceLevel
  status: EventStatus
  firstSeen: string
  lastSeen: string
  durationMin: number
  observations: number
  clusterSize: number
  snapshot: string
  summary: string
  changeFields: string[]
  baselineNs: NsRecord[]
  currentNs: NsRecord[]
  probes: ProbeResult[]
  probeVerdict?: 'inconclusive' | 'consistent' | 'verified_ns_divergence' | 'verified_impact' | string
  probeSummary?: string
  probeComparisons?: ProbeComparison[]
  trustedAnswer: string
  recursiveAnswer: string
  affectedNames: { name: string; via: string }[]
  affectedCount: number
  rrSet: { type: string; value: string; ttl: number }[]
  alerts: AlertRecord[]
  timeline: TimelineNode[]
  handler?: string
  opinion?: string
  whitelistReason?: string
  recoveredAt?: string
  extra?: Record<string, unknown>
  partialEvidence?: boolean
}

function arrayOrEmpty<T>(value: T[] | null | undefined): T[] {
  return Array.isArray(value) ? value : []
}

function normalizeProbeAnswer(answer: ProbeAnswer): ProbeAnswer {
  return {
    ...answer,
    cname: arrayOrEmpty(answer?.cname),
    a: arrayOrEmpty(answer?.a),
    aaaa: arrayOrEmpty(answer?.aaaa),
    authorityNs: arrayOrEmpty(answer?.authorityNs),
  }
}

// 生产历史事件中的 Go nil slice 会编码成 JSON null。在 API 边界统一
// 规范化为空数组，避免单个旧事件将整个 React 详情页渲染成白屏。
export function normalizeRiskEvent(event: RiskEvent): RiskEvent {
  return {
    ...event,
    changeFields: arrayOrEmpty(event.changeFields),
    baselineNs: arrayOrEmpty(event.baselineNs).map((record) => ({ ...record, ips: arrayOrEmpty(record?.ips) })),
    currentNs: arrayOrEmpty(event.currentNs).map((record) => ({ ...record, ips: arrayOrEmpty(record?.ips) })),
    probes: arrayOrEmpty(event.probes).map((probe) => ({
      ...probe,
      answer: probe.answer ? normalizeProbeAnswer(probe.answer) : undefined,
      stableConsensus: probe.stableConsensus ? normalizeProbeAnswer(probe.stableConsensus) : undefined,
      differences: arrayOrEmpty(probe.differences).map((difference) => ({
        ...difference,
        stable: arrayOrEmpty(difference?.stable),
        current: arrayOrEmpty(difference?.current),
      })),
    })),
    probeComparisons: arrayOrEmpty(event.probeComparisons).map((comparison) => ({
      ...comparison,
      stable: comparison.stable ? normalizeProbeAnswer(comparison.stable) : undefined,
      trusted: comparison.trusted ? normalizeProbeAnswer(comparison.trusted) : undefined,
      recursive: normalizeProbeAnswer(comparison.recursive),
      trustedDifferences: arrayOrEmpty(comparison.trustedDifferences).map((difference) => ({
        ...difference, stable: arrayOrEmpty(difference?.stable), current: arrayOrEmpty(difference?.current),
      })),
      recursiveDifferences: arrayOrEmpty(comparison.recursiveDifferences).map((difference) => ({
        ...difference, stable: arrayOrEmpty(difference?.stable), current: arrayOrEmpty(difference?.current),
      })),
    })),
    affectedNames: arrayOrEmpty(event.affectedNames),
    rrSet: arrayOrEmpty(event.rrSet),
    alerts: arrayOrEmpty(event.alerts),
    timeline: arrayOrEmpty(event.timeline),
  }
}

export interface EventsResponse {
  items: RiskEvent[]
  total: number
  page: number
  limit: number
}

export interface CampaignEvent {
  id: string
  type: 'same_new_ns' | 'same_ns_ip' | 'same_a_ip'
  target: string
  severity: RiskLevel
  evidence: string
  status: string
  previous_snapshot_id: string
  current_snapshot_id: string
  first_seen: string
  last_seen: string
  zone_count: number
  ns_host_count: number
  record_count: number
  zones: string[]
  changes: CampaignChange[]
  summary: string
}

export interface CampaignsResponse { items: CampaignEvent[]; total: number; page: number; limit: number }

export interface CampaignChange {
  zone: string
  record_name?: string
  ns_host?: string
  previous_owners: string[]
  current_owners: string[]
  previous_values: string[]
  current_values: string[]
}

export interface NSOwnershipSnapshot {
  id: string
  captured_at: string
  view: string
}

export interface NSOwnershipOwner {
  owner: string
  zone_count: number
  previous_zone_count: number
  added_count: number
  removed_count: number
  cross_domain_count: number
  hosts: string[]
}

export type NSOwnershipEdgeStatus = 'added' | 'removed' | 'moved_in' | 'moved_out' | 'unchanged'

export interface NSOwnershipZoneEdge {
  zone: string
  status: NSOwnershipEdgeStatus
  previous_owners: string[]
  current_owners: string[]
  previous_hosts: string[]
  current_hosts: string[]
  cross_domain: boolean
}

export interface NSOwnershipResponse {
  snapshots: NSOwnershipSnapshot[]
  current: NSOwnershipSnapshot
  previous?: NSOwnershipSnapshot
  owners: NSOwnershipOwner[]
  selected_owner: string
  edges: NSOwnershipZoneEdge[]
  graph_edges: NSOwnershipZoneEdge[]
  total_edges: number
  truncated: boolean
}

export interface NSChangeOverviewPoint {
  snapshot_id: string
  previous_snapshot_id: string
  captured_at: string
  previous_captured_at: string
  view: string
  total_zones: number
  unchanged: number
  modified: number
  added: number
  removed: number
  changed: number
  change_rate: number
}

export interface NSChangeOverviewItem {
  zone: string
  type: 'modified' | 'added' | 'removed'
  previous_owners: string[]
  current_owners: string[]
  previous_hosts: string[]
  current_hosts: string[]
}

export interface NSChangeOverviewResponse {
  points: NSChangeOverviewPoint[]
  selected?: NSChangeOverviewPoint
  changes: NSChangeOverviewItem[]
  total_changes: number
  page: number
  limit: number
}

export interface NSDependencyHost {
  host: string
  owner: string
  zone_count: number
  addresses: string[]
  asns: string[]
  asn_organizations: string[]
  countries: string[]
  metadata_coverage: number
  zone_sample: string[]
}

export interface NSDependencyResponse {
  snapshot: NSOwnershipSnapshot
  total_zones: number
  total_hosts: number
  total_owners: number
  total_countries: number
  hosts: NSDependencyHost[]
  selected_host?: NSDependencyHost
  affected_zones: string[]
  total_affected: number
  sole_dependency: number
  with_alternatives: number
  page: number
  limit: number
}

export interface NSHealthResponse {
  summary: {
    snapshot_id: string; captured_at: string; total_zones: number; total_hosts: number
    hosts_with_address: number; hosts_with_adb: number; endpoint_coverage: number
    total_endpoints: number; healthy_endpoints: number; slow_endpoints: number
    degraded_endpoints: number; suspect_endpoints: number; unknown_endpoints: number
    affected_zones: number; reduced_zones: number; unavailable_zones: number
    srtt_p50_ms: number; srtt_p95_ms: number; srtt_p99_ms: number
  }
  buckets: { label: string; min_ms: number; max_ms: number; count: number }[]
  endpoints: {
    ns_name: string; owner: string; ip: string; health: string; srtt_ms: number
    edns_success: number; edns_timeout: number; plain_success: number; plain_timeout: number
    consecutive: number; affected_zones: number; sole_dependency: number
    flags: string; last_seen: string; detail: string
  }[]
  providers: {
    owner: string; host_count: number; endpoint_count: number; abnormal_endpoints: number
    affected_zones: number; max_srtt_ms: number; host_sample: string[]
  }[]
  warnings: string[]
  generated_at: string
}

export interface SnapshotSummary {
  id: string
  source: string
  view: string
  captured_at: string
  domains: number
  ns_observations: number
}

export interface OverviewResponse {
  kpis: {
    activeEvents: number
    criticalEvents: number
    highEvents: number
    pendingVerify: number
    new24h: number
    recovered24h: number
    baselineDomains: number
    latestSnapshot: string
    dataDelayMin: number
  }
  recentEvents: RiskEvent[]
  snapshots: SnapshotSummary[]
  mode: 'memory' | 'clickhouse'
  warnings: string[]
  generatedAt: string
}

export interface EventImpactResponse {
  event_id: string
  event_domain: string
  snapshot_id: string
  observed_at: string
  total_affected_domains: number
  groups: {
    type: string
    title: string
    description: string
    domains: { domain: string; target?: string; cname_hops?: number }[]
  }[]
  scope: string
}

export interface SnapshotRecordResponse {
  snapshot: SnapshotSummary
  domain: string
  record_kind: string
  ns_observation: unknown[]
  groups: { type: string; count: number; records: unknown[] }[]
}

export interface DomainDetailResponse {
  domain: string
  baselineEstablished: boolean
  baselineSnapshots: number
  baselineSource: 'confirmed' | 'event_history' | 'candidate' | 'current_only' | ''
  firstObserved: string
  baselineNs: NsRecord[]
  currentNs: NsRecord[]
  relatedEvents: RiskEvent[]
  timeline: TimelineNode[]
}

export interface BlacklistSource {
  name: string
  version: string
  updatedAt: string
  entries: number
  confidence: string
  state: 'current' | 'expired'
  sha256: string
  file: string
}

export interface AlertListItem {
  time: string
  eventId: string
  domain: string
  level: RiskLevel
  channel: string
  target: string
  status: '已送达' | '发送失败' | '已抑制(合并)'
  content: string
}

export interface AuditListItem {
  time: string
  action: string
  actor: string
  actorRole: string
  target: string
  details: string
}

export interface ProbeListItem {
  id: string
  eventId: string
  target: string
  domain: string
  time: string
  node: string
  rtt: number | null
  result: string
  detail: string
}

export interface SystemComponent {
  name: string
  category: string
  status: 'normal' | 'warning' | 'error'
  detail: string
  impact?: string
  updatedAt: string
}

export interface SettingsResponse {
  dumpMonitor: { directory: string; pollInterval: string; stabilityWindow: string }
  probe: {
    enabled: boolean; backend: string; recursiveResolver: string; trustedResolvers: string[]
    timeout: string; eventTimeout: string; maxDomains: number; maxParallel: number; maxEventsPerImport: number
  }
  alerts: {
    enabled: boolean; severities: string[]; recipients: string[]; cooldown: string; timeout: string; subjectPrefix: string
  }
  blacklist: { directory: string; maxFileBytes: number; maxEntries: number }
  baseline: { consecutiveRequired: number }
  campaign: { enabled: boolean; minDistinctZones: number; holdBaseline: boolean; maxSnapshotGap: string }
}

export interface SessionInfo {
  authenticated: boolean
  username: string
  role: 'observer' | 'operator' | 'admin' | 'disabled'
  canOperate: boolean
  canAdmin: boolean
  warning?: string
}

export function fmtDuration(min: number): string {
  if (min < 60) return `${min} 分钟`
  if (min < 1440) return `${Math.floor(min / 60)} 小时 ${min % 60 ? (min % 60) + ' 分' : ''}`
  return `${Math.floor(min / 1440)} 天 ${Math.floor((min % 1440) / 60)} 小时`
}
