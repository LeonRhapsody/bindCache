// ============================================================
// 递归 DNS 风险监测平台 — 仿真数据（不依赖真实 ClickHouse）
// 时间基准：2026-07-30 14:20（最新快照）
// ============================================================

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
  ns: string
  ip: string
  reachable: boolean
  rttMs: number | null
  answerConsistent: boolean
  detail: string
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
  // 场景扩展字段
  extra?: Record<string, unknown>
  partialEvidence?: boolean
}

// ---------- 通用 NS 记录 ----------
const ns = (host: string, ips: string[], asn: string, asnOrg: string, country: string, reachable = true, rttMs = 24): NsRecord =>
  ({ host, ips, asn, asnOrg, country, reachable, rttMs })

export const EVENTS: RiskEvent[] = [
  {
    id: 'EVT-20260730-001',
    type: 'ns_change',
    domain: 'mail.univ-a.example',
    level: 'critical',
    evidence: 'impact_confirmed',
    status: 'confirmed',
    firstSeen: '2026-07-30 06:10',
    lastSeen: '2026-07-30 14:20',
    durationMin: 490,
    observations: 49,
    clusterSize: 49,
    snapshot: 'snap-20260730-1420',
    summary: 'NS 数量 2→1，保留 NS 的 A 记录变更为境外新 ASN，且新 NS 与基线解析结果不一致，递归缓存已观测到错误应答。',
    changeFields: ['NS 数量减少', 'NS IP 变化', 'ASN 变化', '国家/地区变化', '解析结果不一致'],
    baselineNs: [
      ns('ns1.univ-a.example', ['192.0.2.110', '192.0.2.111'], 'AS64503', 'CERNET 教育网', '中国', true, 12),
      ns('ns2.univ-a.example', ['198.51.100.5'], 'AS64503', 'CERNET 教育网', '中国', true, 15),
    ],
    currentNs: [
      ns('ns1.univ-a.example', ['198.51.100.17'], 'AS64497', 'UCLOUD HK', '中国香港', true, 86),
    ],
    probes: [
      { ns: 'ns1.univ-a.example', ip: '198.51.100.17', reachable: true, rttMs: 86, answerConsistent: false, detail: 'A 记录应答与基线不符：返回 192.0.2.206（基线为 192.0.2.125）' },
      { ns: 'ns2.univ-a.example', ip: '198.51.100.5', reachable: false, rttMs: null, answerConsistent: false, detail: '拨测超时（3 次重试均无响应）' },
    ],
    trustedAnswer: 'mail.univ-a.example → 192.0.2.125（可信权威，TTL 3600）',
    recursiveAnswer: 'mail.univ-a.example → 192.0.2.206（受监控递归，与可信权威不一致）',
    affectedNames: [
      { name: 'mail.univ-a.example', via: '直接' },
      { name: 'smtp.univ-a.example', via: 'CNAME → mail.univ-a.example' },
      { name: 'imap.univ-a.example', via: 'CNAME → mail.univ-a.example' },
      { name: 'webmail.univ-a.example', via: 'CNAME → mail.univ-a.example' },
      { name: 'pop3.univ-a.example', via: 'CNAME → mail.univ-a.example' },
    ],
    affectedCount: 1247,
    rrSet: [
      { type: 'NS', value: 'ns1.univ-a.example', ttl: 86400 },
      { type: 'A', value: '192.0.2.206', ttl: 3600 },
      { type: 'MX', value: '10 mail.univ-a.example', ttl: 3600 },
      { type: 'TXT', value: 'v=spf1 ip4:192.0.2.100/24 -all', ttl: 3600 },
      { type: 'AAAA', value: '—（无记录）', ttl: 0 },
    ],
    alerts: [
      { time: '2026-07-30 06:20', channel: '邮件', target: 'dns-ops@example.com', status: '已送达', content: '[严重] mail.univ-a.example NS 发生变更，证据等级：缓存观测线索' },
      { time: '2026-07-30 08:10', channel: '邮件', target: 'dns-ops@example.com', status: '已送达', content: '[严重] 事件升级：拨测确认权威分歧' },
      { time: '2026-07-30 11:40', channel: '邮件', target: 'sec-team@example.com', status: '已送达', content: '[严重] 事件升级：已确认对递归解析产生实际影响' },
    ],
    timeline: [
      { time: '2026-07-30 14:20', kind: 'repeat', title: '第 49 次连续观测', detail: '异常状态持续，缓存快照与基线差异不变' },
      { time: '2026-07-30 11:40', kind: 'verify', title: '确认实际影响', detail: '受监控递归返回错误 A 记录，影响面 1,247 个名称，事件升级为严重' },
      { time: '2026-07-30 08:10', kind: 'verify', title: '确认权威分歧', detail: 'relay 拨测：新 NS 应答与可信权威结果不一致' },
      { time: '2026-07-30 06:30', kind: 'alert', title: '告警投递', detail: '邮件已送达 dns-ops@example.com' },
      { time: '2026-07-30 06:20', kind: 'repeat', title: '重复异常确认', detail: '连续 2 个快照观测到相同差异，进入待验证' },
      { time: '2026-07-30 06:10', kind: 'start', title: '首次观测到 NS 变化', detail: '缓存快照中 NS2 消失，NS1 A 记录变更' },
    ],
    handler: '张运维',
    opinion: '已联系高校信息化处核实，确认非授权变更，正在协助恢复原委派并清理递归缓存。',
    extra: { baselineEstablished: true, baselineSnapshots: 12 },
  },
  {
    id: 'EVT-20260730-002',
    type: 'ns_change',
    domain: 'www.shop-d.example',
    level: 'high',
    evidence: 'pending_verify',
    status: 'pending',
    firstSeen: '2026-07-30 11:50',
    lastSeen: '2026-07-30 14:20',
    durationMin: 150,
    observations: 15,
    clusterSize: 15,
    snapshot: 'snap-20260730-1420',
    summary: 'NS 主域由 dnspod 系变更为未知注册商 NS，relay 拨测服务暂不可用，尚未完成权威验证。',
    changeFields: ['NS 主域变化', 'NS 数量 2→3'],
    baselineNs: [ns('f1g1ns1.dnspod.net', ['192.0.2.34'], 'AS64496', 'DNSPod', '中国', true, 20)],
    currentNs: [
      ns('ns1.reg-xk7.net', ['192.0.2.9'], 'AS64504', 'BGP Network (SG)', '新加坡', true, 142),
      ns('ns2.reg-xk7.net', ['192.0.2.10'], 'AS64504', 'BGP Network (SG)', '新加坡', true, 138),
    ],
    probes: [],
    trustedAnswer: '待验证（relay 拨测服务不可用）',
    recursiveAnswer: 'www.shop-d.example → 203.0.113.19（缓存观测，未经权威验证）',
    affectedNames: [{ name: 'www.shop-d.example', via: '直接' }],
    affectedCount: 3,
    rrSet: [
      { type: 'NS', value: 'ns1.reg-xk7.net', ttl: 86400 },
      { type: 'NS', value: 'ns2.reg-xk7.net', ttl: 86400 },
      { type: 'A', value: '203.0.113.19', ttl: 300 },
    ],
    alerts: [
      { time: '2026-07-30 12:00', channel: '邮件', target: 'dns-ops@example.com', status: '已送达', content: '[高风险] www.shop-d.example NS 主域变化（缓存观测线索）' },
    ],
    timeline: [
      { time: '2026-07-30 14:20', kind: 'repeat', title: '第 15 次连续观测', detail: '差异持续存在' },
      { time: '2026-07-30 12:00', kind: 'alert', title: '告警投递', detail: '邮件已送达' },
      { time: '2026-07-30 11:50', kind: 'start', title: '首次观测到 NS 主域变化', detail: 'dnspod.net → reg-xk7.net' },
    ],
    partialEvidence: true,
  },
  {
    id: 'EVT-20260730-003',
    type: 'ns_single',
    domain: 'oa.cityc-gov.example',
    level: 'medium',
    evidence: 'repeated',
    status: 'active',
    firstSeen: '2026-07-28 09:30',
    lastSeen: '2026-07-30 14:20',
    durationMin: 3170,
    observations: 317,
    clusterSize: 317,
    snapshot: 'snap-20260730-1420',
    summary: '3 个 NS 主机名指向同一 IP，构成逻辑单点；当前服务可用，属配置隐患。',
    changeFields: ['多 NS 同 IP'],
    baselineNs: [],
    currentNs: [
      ns('ns1.cityc-gov.example', ['192.0.2.220'], 'AS64502', '中国电信', '中国', true, 9),
      ns('ns2.cityc-gov.example', ['192.0.2.220'], 'AS64502', '中国电信', '中国', true, 9),
      ns('ns3.cityc-gov.example', ['192.0.2.220'], 'AS64502', '中国电信', '中国', true, 9),
    ],
    probes: [
      { ns: 'ns1.cityc-gov.example', ip: '192.0.2.220', reachable: true, rttMs: 9, answerConsistent: true, detail: '应答正常' },
    ],
    trustedAnswer: '与递归观测一致',
    recursiveAnswer: 'oa.cityc-gov.example → 192.0.2.215（一致）',
    affectedNames: [{ name: 'oa.cityc-gov.example', via: '直接' }],
    affectedCount: 42,
    rrSet: [
      { type: 'NS', value: 'ns1.cityc-gov.example', ttl: 86400 },
      { type: 'NS', value: 'ns2.cityc-gov.example', ttl: 86400 },
      { type: 'NS', value: 'ns3.cityc-gov.example', ttl: 86400 },
      { type: 'A', value: '192.0.2.215', ttl: 600 },
    ],
    alerts: [],
    timeline: [
      { time: '2026-07-30 14:20', kind: 'repeat', title: '第 317 次连续观测', detail: '逻辑单点状态持续' },
      { time: '2026-07-28 09:30', kind: 'start', title: '首次识别多 NS 同 IP', detail: '3 个 NS 主机名均解析至 192.0.2.220' },
    ],
    extra: { singleReason: '多个 NS 主机名指向同一 IP', historyMaxNs: 3, sameSegment: true, sameAsn: true, sameCountry: true },
  },
  {
    id: 'EVT-20260730-004',
    type: 'ns_single',
    domain: 'api.fintech-e.example',
    level: 'high',
    evidence: 'auth_divergence',
    status: 'confirmed',
    firstSeen: '2026-07-30 02:40',
    lastSeen: '2026-07-30 14:20',
    durationMin: 700,
    observations: 70,
    clusterSize: 70,
    snapshot: 'snap-20260730-1420',
    summary: '唯一 NS 长期不可达（拨测持续超时），权威验证确认无法获取有效应答。',
    changeFields: ['唯一 NS 不可达', 'NS 数量 2→1'],
    baselineNs: [ns('ns1.fintech-e.example', ['203.0.113.8'], 'AS64501', '阿里云', '中国', true, 18)],
    currentNs: [ns('ns1.fintech-e.example', ['203.0.113.8'], 'AS64501', '阿里云', '中国', false)],
    probes: [
      { ns: 'ns1.fintech-e.example', ip: '203.0.113.8', reachable: false, rttMs: null, answerConsistent: false, detail: 'UDP/53 与 TCP/53 均超时（最近 24 次拨测全部失败）' },
    ],
    trustedAnswer: '无法获取（唯一权威不可达）',
    recursiveAnswer: 'api.fintech-e.example → 203.0.113.40（依赖缓存续命，TTL 到期后将解析失败）',
    affectedNames: [{ name: 'api.fintech-e.example', via: '直接' }],
    affectedCount: 18,
    rrSet: [
      { type: 'NS', value: 'ns1.fintech-e.example', ttl: 86400 },
      { type: 'A', value: '203.0.113.40', ttl: 120 },
    ],
    alerts: [
      { time: '2026-07-30 03:00', channel: '邮件', target: 'dns-ops@example.com', status: '已送达', content: '[高风险] api.fintech-e.example 唯一 NS 不可达' },
    ],
    timeline: [
      { time: '2026-07-30 14:20', kind: 'repeat', title: '第 70 次连续观测', detail: 'NS 仍不可达' },
      { time: '2026-07-30 05:10', kind: 'verify', title: '确认权威分歧', detail: '拨测连续 24 次失败，无法从权威获取应答' },
      { time: '2026-07-30 03:00', kind: 'alert', title: '告警投递', detail: '邮件已送达' },
      { time: '2026-07-30 02:40', kind: 'start', title: '首次观测到 NS 数量下降', detail: 'NS 2→1，且保留 NS 拨测超时' },
    ],
    handler: '李安全',
    opinion: '已通知业务方启用备用解析线路，待其 NS 恢复后复核。',
    extra: { singleReason: 'NS 数量从多个下降为一个，且唯一 NS 不可达', historyMaxNs: 2 },
  },
  {
    id: 'EVT-20260730-005',
    type: 'ns_parent_child',
    domain: 'lib.univ-b.example',
    level: 'medium',
    evidence: 'pending_verify',
    status: 'pending',
    firstSeen: '2026-07-30 12:30',
    lastSeen: '2026-07-30 14:20',
    durationMin: 110,
    observations: 11,
    clusterSize: 11,
    snapshot: 'snap-20260730-1420',
    summary: '父子 NS 集合部分不一致：子区新增 ns-cdn1，父区尚未委派；持续 110 分钟，仍在 TTL 传播窗口内。',
    changeFields: ['父子部分不一致', '传播窗口内'],
    baselineNs: [],
    currentNs: [],
    probes: [],
    trustedAnswer: '子区权威 NS：ns1.univ-b、ns2.univ-b、ns-cdn1.cdn-x.net',
    recursiveAnswer: '递归尚未观测到子区新 NS（传播中）',
    affectedNames: [],
    affectedCount: 0,
    rrSet: [],
    alerts: [],
    timeline: [
      { time: '2026-07-30 14:20', kind: 'repeat', title: '第 11 次连续观测', detail: '不一致持续，未超 TTL(7200s) 确认周期' },
      { time: '2026-07-30 12:30', kind: 'start', title: '首次观测到父子不一致', detail: '子区新增 ns-cdn1.cdn-x.net，父区 Glue 未更新' },
    ],
    extra: {
      parentNs: ['ns1.univ-b.example', 'ns2.univ-b.example'],
      childNs: ['ns1.univ-b.example', 'ns2.univ-b.example', 'ns-cdn1.cdn-x.net'],
      glueMismatch: false, ttl: 7200, propagationWindow: '预计窗口至 2026-07-30 14:30',
      dnssec: '已签名，DS 与 DNSKEY 匹配，验证通过',
    },
    partialEvidence: true,
  },
  {
    id: 'EVT-20260730-006',
    type: 'ns_parent_child',
    domain: 'data.cityf-gov.example',
    level: 'high',
    evidence: 'auth_divergence',
    status: 'confirmed',
    firstSeen: '2026-07-29 18:10',
    lastSeen: '2026-07-30 14:20',
    durationMin: 1210,
    observations: 121,
    clusterSize: 121,
    snapshot: 'snap-20260730-1420',
    summary: '父区 Glue 与 NS 主机实际 A 记录不一致，持续 20+ 小时远超 TTL；两台权威返回不同子区 NS 集合，已影响递归结果。',
    changeFields: ['Glue 与实际 IP 不一致', '权威间应答不一致', '超过确认周期'],
    baselineNs: [],
    currentNs: [],
    probes: [
      { ns: 'ns1.cityf-gov.example', ip: '203.0.113.106', reachable: true, rttMs: 11, answerConsistent: false, detail: '返回子区 NS 集合 A（含 ns-backup1）' },
      { ns: 'ns2.cityf-gov.example', ip: '203.0.113.107', reachable: true, rttMs: 12, answerConsistent: false, detail: '返回子区 NS 集合 B（不含 ns-backup1）' },
    ],
    trustedAnswer: '两台权威 NS 应答不一致（集合 A / 集合 B）',
    recursiveAnswer: '递归结果随选路不同在集合 A / B 间摆动',
    affectedNames: [{ name: 'data.cityf-gov.example', via: '直接' }],
    affectedCount: 96,
    rrSet: [],
    alerts: [
      { time: '2026-07-29 20:10', channel: '邮件', target: 'dns-ops@example.com', status: '已送达', content: '[高风险] data.cityf-gov.example 父子 NS 不一致超过确认周期' },
    ],
    timeline: [
      { time: '2026-07-30 14:20', kind: 'repeat', title: '第 121 次连续观测', detail: '不一致持续' },
      { time: '2026-07-29 20:10', kind: 'verify', title: '超过确认周期，确认权威分歧', detail: '持续 2 小时 > TTL(3600s)，升级高风险' },
      { time: '2026-07-29 18:10', kind: 'start', title: '首次观测到父子不一致', detail: 'Glue 203.0.113.166 与实际 203.0.113.106 不符' },
    ],
    handler: '张运维',
    extra: {
      parentNs: ['ns1.cityf-gov.example', 'ns2.cityf-gov.example'],
      childNs: ['ns1.cityf-gov.example', 'ns2.cityf-gov.example', 'ns-backup1.cityf-gov.example'],
      glueMismatch: true,
      gluePairs: [
        { host: 'ns1.cityf-gov.example', glue: '203.0.113.166', actual: '203.0.113.106' },
        { host: 'ns2.cityf-gov.example', glue: '203.0.113.107', actual: '203.0.113.107' },
      ],
      ttl: 3600, propagationWindow: '已超出确认周期 18 小时以上',
      dnssec: '未签名',
    },
  },
  {
    id: 'EVT-20260730-007',
    type: 'ns_blacklist',
    domain: 'cdn.media-g.example',
    level: 'high',
    evidence: 'impact_confirmed',
    status: 'confirmed',
    firstSeen: '2026-07-30 09:00',
    lastSeen: '2026-07-30 14:20',
    durationMin: 320,
    observations: 32,
    clusterSize: 32,
    snapshot: 'snap-20260730-1420',
    summary: '在用 NS 的 IP 命中高可信黑名单（恶意基础设施：C2 托管），当前仍生效且拨测确认已对递归解析产生影响。',
    changeFields: ['NS IP 命中黑名单', '高可信名单', '拨测确认影响'],
    baselineNs: [],
    currentNs: [ns('ns1.fastnode-cdn.net', ['192.0.2.172'], 'AS64498', 'Amarutu Technology', '荷兰', true, 155)],
    probes: [
      { ns: 'ns1.fastnode-cdn.net', ip: '192.0.2.172', reachable: true, rttMs: 155, answerConsistent: false, detail: '应答指向与可信权威不一致的 CDN 边缘地址' },
    ],
    trustedAnswer: 'cdn.media-g.example → 192.0.2.14（可信权威）',
    recursiveAnswer: 'cdn.media-g.example → 198.51.100.90（受监控递归，不一致）',
    affectedNames: [{ name: 'cdn.media-g.example', via: '直接' }, { name: 'static.media-g.example', via: 'CNAME → cdn.media-g.example' }],
    affectedCount: 214,
    rrSet: [
      { type: 'NS', value: 'ns1.fastnode-cdn.net', ttl: 86400 },
      { type: 'A', value: '198.51.100.90', ttl: 300 },
    ],
    alerts: [
      { time: '2026-07-30 09:10', channel: '邮件', target: 'sec-team@example.com', status: '已送达', content: '[高风险] cdn.media-g.example NS IP 命中黑名单 abuse-ch-v2.7' },
    ],
    timeline: [
      { time: '2026-07-30 14:20', kind: 'repeat', title: '第 32 次连续观测', detail: '命中条目仍生效' },
      { time: '2026-07-30 10:30', kind: 'verify', title: '确认实际影响', detail: '拨测确认递归返回不一致应答，升级高风险' },
      { time: '2026-07-30 09:00', kind: 'start', title: '首次命中黑名单', detail: '192.0.2.172 命中 abuse-ch-v2.7（IP 规则）' },
    ],
    handler: '李安全',
    opinion: '建议对 192.0.2.172 在递归侧做 RPZ 拦截，待域名持有方更换 NS。',
    extra: {
      hits: [
        { object: '192.0.2.172', rule: 'IP 精确匹配', source: 'abuse-ch-threatlist', version: 'v2.7 (2026-07-28)', confidence: '高', category: 'C2 托管', effective: '2026-07-20', expire: '2026-10-20', desc: '已知恶意基础设施，多起 DNS 劫持事件共用托管段', note: '重点关注' },
      ],
      stillInUse: true, hasTrustedAnswer: true, whitelisted: false,
    },
  },
  {
    id: 'EVT-20260725-008',
    type: 'ns_blacklist',
    domain: 'static.news-h.example',
    level: 'low',
    evidence: 'cache_hint',
    status: 'ignored',
    firstSeen: '2026-07-25 15:40',
    lastSeen: '2026-07-30 14:20',
    durationMin: 7120,
    observations: 712,
    clusterSize: 712,
    snapshot: 'snap-20260730-1420',
    summary: 'NS 注册主域命中低可信名单条目，经人工核实为名单误报，已加入白名单豁免。',
    changeFields: ['NS 主域命中黑名单'],
    baselineNs: [],
    currentNs: [ns('ns1.registrar-y.com', ['198.51.100.2'], 'AS64500', 'Namecheap', '美国', true, 168)],
    probes: [],
    trustedAnswer: '与递归观测一致',
    recursiveAnswer: 'static.news-h.example → 203.0.113.22（一致）',
    affectedNames: [],
    affectedCount: 0,
    rrSet: [],
    alerts: [
      { time: '2026-07-25 15:50', channel: '邮件', target: 'dns-ops@example.com', status: '已送达', content: '[低风险] static.news-h.example NS 主域命中 community-feed-v14' },
    ],
    timeline: [
      { time: '2026-07-26 10:00', kind: 'verify', title: '人工核实并加入白名单', detail: '命中条目为社区名单误报，处置人：李安全' },
      { time: '2026-07-25 15:40', kind: 'start', title: '首次命中黑名单', detail: 'registrar-y.com 命中 community-feed-v14（主域规则）' },
    ],
    handler: '李安全',
    whitelistReason: '社区名单误报：该注册商主域被批量收录，实际 NS 服务正常，2026-07-26 加入白名单（90 天）。',
    extra: {
      hits: [
        { object: 'registrar-y.com', rule: 'NS 注册主域匹配', source: 'community-feed', version: 'v14 (2026-07-24)', confidence: '低', category: '疑似停放', effective: '2026-07-24', expire: '2026-08-24', desc: '社区众包收录，未给出独立证据', note: '' },
      ],
      stillInUse: true, hasTrustedAnswer: true, whitelisted: true,
    },
    partialEvidence: true,
  },
  {
    id: 'EVT-20260729-009',
    type: 'ns_change',
    domain: 'mail.hospital-b.example',
    level: 'recovered',
    evidence: 'impact_confirmed',
    status: 'recovered',
    firstSeen: '2026-07-29 03:20',
    lastSeen: '2026-07-29 09:50',
    durationMin: 390,
    observations: 39,
    clusterSize: 39,
    snapshot: 'snap-20260729-0950',
    summary: 'NS IP 曾变更至保留地址段（私网 10.x），经确认被递归采用；运维修复委派后于 09:50 恢复，连续 12 个快照与基线一致。',
    changeFields: ['NS 指向保留地址', '实际影响（历史）'],
    baselineNs: [ns('ns1.hospital-b.example', ['198.51.100.30'], 'AS64505', '中国移动', '中国', true, 14)],
    currentNs: [ns('ns1.hospital-b.example', ['198.51.100.30'], 'AS64505', '中国移动', '中国', true, 14)],
    probes: [
      { ns: 'ns1.hospital-b.example', ip: '198.51.100.30', reachable: true, rttMs: 14, answerConsistent: true, detail: '应答与基线一致' },
    ],
    trustedAnswer: 'mail.hospital-b.example → 198.51.100.8（一致）',
    recursiveAnswer: 'mail.hospital-b.example → 198.51.100.8（一致）',
    affectedNames: [{ name: 'mail.hospital-b.example', via: '直接' }],
    affectedCount: 36,
    rrSet: [
      { type: 'NS', value: 'ns1.hospital-b.example', ttl: 86400 },
      { type: 'A', value: '198.51.100.8', ttl: 3600 },
    ],
    alerts: [
      { time: '2026-07-29 03:30', channel: '邮件', target: 'dns-ops@example.com', status: '已送达', content: '[高风险] mail.hospital-b.example NS 指向保留地址' },
      { time: '2026-07-29 09:50', channel: '邮件', target: 'dns-ops@example.com', status: '已送达', content: '[恢复] mail.hospital-b.example 已恢复至稳定基线' },
    ],
    timeline: [
      { time: '2026-07-29 09:50', kind: 'recover', title: '事件恢复', detail: '连续 12 个快照与稳定基线一致，恢复确认' },
      { time: '2026-07-29 08:10', kind: 'repeat', title: '恢复观测中', detail: '委派已修复，等待连续一致确认' },
      { time: '2026-07-29 05:00', kind: 'verify', title: '确认实际影响', detail: '递归曾将 NS 解析至 10.90.0.5，导致解析失败' },
      { time: '2026-07-29 03:30', kind: 'alert', title: '告警投递', detail: '邮件已送达' },
      { time: '2026-07-29 03:20', kind: 'start', title: '首次观测到 NS IP 异常', detail: 'NS1 A 记录变更为 10.90.0.5（私网保留地址）' },
    ],
    handler: '张运维',
    opinion: '医院信息科误操作 Glue 记录，已修复并完成缓存清理，归档复盘。',
    recoveredAt: '2026-07-29 09:50',
  },
  {
    id: 'EVT-20260730-010',
    type: 'ns_change',
    domain: 'vpn.univ-c.example',
    level: 'low',
    evidence: 'cache_hint',
    status: 'active',
    firstSeen: '2026-07-30 14:10',
    lastSeen: '2026-07-30 14:20',
    durationMin: 10,
    observations: 1,
    clusterSize: 1,
    snapshot: 'snap-20260730-1420',
    summary: '单次缓存观测到 NS 数量 3→2，尚未重复出现，属缓存观测线索，暂不升级。',
    changeFields: ['NS 数量减少'],
    baselineNs: [ns('ns1.univ-c.example', ['203.0.113.4'], 'AS64503', 'CERNET 教育网', '中国', true, 10)],
    currentNs: [ns('ns1.univ-c.example', ['203.0.113.4'], 'AS64503', 'CERNET 教育网', '中国', true, 10)],
    probes: [],
    trustedAnswer: '待重复观测确认后启动验证',
    recursiveAnswer: 'vpn.univ-c.example → 203.0.113.9（缓存观测）',
    affectedNames: [],
    affectedCount: 0,
    rrSet: [],
    alerts: [],
    timeline: [
      { time: '2026-07-30 14:10', kind: 'start', title: '单次观测到 NS 数量下降', detail: '快照 snap-20260730-1410 中 NS3 缺失' },
    ],
    partialEvidence: true,
  },
  {
    id: 'EVT-20260727-011',
    type: 'ns_single',
    domain: 'backup.cloud-i.example',
    level: 'low',
    evidence: 'repeated',
    status: 'active',
    firstSeen: '2026-07-27 10:00',
    lastSeen: '2026-07-30 14:20',
    durationMin: 4580,
    observations: 458,
    clusterSize: 458,
    snapshot: 'snap-20260730-1420',
    summary: '仅配置 1 个 NS 主机名，但持续可用，属低风险配置隐患。',
    changeFields: ['仅一个 NS 主机名'],
    baselineNs: [],
    currentNs: [ns('ns1.cloud-i.example', ['203.0.113.66'], 'AS64501', '阿里云', '中国', true, 16)],
    probes: [{ ns: 'ns1.cloud-i.example', ip: '203.0.113.66', reachable: true, rttMs: 16, answerConsistent: true, detail: '应答正常' }],
    trustedAnswer: '与递归观测一致',
    recursiveAnswer: 'backup.cloud-i.example → 203.0.113.110（一致）',
    affectedNames: [],
    affectedCount: 2,
    rrSet: [{ type: 'NS', value: 'ns1.cloud-i.example', ttl: 86400 }],
    alerts: [],
    timeline: [
      { time: '2026-07-30 14:20', kind: 'repeat', title: '第 458 次连续观测', detail: '单一 NS 但持续可用' },
      { time: '2026-07-27 10:00', kind: 'start', title: '识别单一 NS 配置', detail: '基线建立后持续观测' },
    ],
    extra: { singleReason: '只有一个 NS 主机名', historyMaxNs: 1 },
    partialEvidence: true,
  },
  {
    id: 'EVT-20260730-012',
    type: 'ns_blacklist',
    domain: 'img.adnet-j.example',
    level: 'medium',
    evidence: 'repeated',
    status: 'active',
    firstSeen: '2026-07-30 08:30',
    lastSeen: '2026-07-30 14:20',
    durationMin: 350,
    observations: 35,
    clusterSize: 35,
    snapshot: 'snap-20260730-1420',
    summary: '在用 NS 所在 ASN 命中中可信黑名单（垃圾邮件基础设施段），拨测暂未发现解析影响，保持观测。',
    changeFields: ['ASN 命中黑名单'],
    baselineNs: [],
    currentNs: [ns('ns1.adnet-j.example', ['198.51.100.210'], 'AS64499', 'HostGlobal PL', '波兰', true, 190)],
    probes: [{ ns: 'ns1.adnet-j.example', ip: '198.51.100.210', reachable: true, rttMs: 190, answerConsistent: true, detail: '应答与可信权威一致' }],
    trustedAnswer: 'img.adnet-j.example → 198.51.100.66（一致）',
    recursiveAnswer: 'img.adnet-j.example → 198.51.100.66（一致）',
    affectedNames: [],
    affectedCount: 0,
    rrSet: [{ type: 'NS', value: 'ns1.adnet-j.example', ttl: 86400 }],
    alerts: [],
    timeline: [
      { time: '2026-07-30 14:20', kind: 'repeat', title: '第 35 次连续观测', detail: '命中条目仍生效，未见解析影响' },
      { time: '2026-07-30 08:30', kind: 'start', title: '首次命中黑名单', detail: 'AS64499 命中 spam-infra-v9（ASN 规则）' },
    ],
    extra: {
      hits: [
        { object: 'AS64499', rule: 'ASN 匹配', source: 'spam-infra-list', version: 'v9 (2026-07-29)', confidence: '中', category: '垃圾邮件基础设施', effective: '2026-07-15', expire: '2026-09-15', desc: '该 ASN 段近 30 天多次用于批量垃圾邮件域名托管', note: '' },
      ],
      stillInUse: true, hasTrustedAnswer: true, whitelisted: false,
    },
    partialEvidence: true,
  },
]

// ---------- 总览指标 ----------
export const OVERVIEW_KPIS = {
  activeEvents: 8,
  criticalEvents: 1,
  highEvents: 4,
  pendingVerify: 3,
  new24h: 6,
  recovered24h: 1,
  baselineDomains: 1864,
  latestSnapshot: '2026-07-30 14:20',
  dataDelayMin: 6,
}

// 24h 趋势（按小时，严重/高/中/低）
export const TREND_24H = [
  { t: '15:00', 严重: 0, 高: 1, 中: 1, 低: 0 }, { t: '16:00', 严重: 0, 高: 1, 中: 1, 低: 0 },
  { t: '17:00', 严重: 0, 高: 1, 中: 1, 低: 1 }, { t: '18:00', 严重: 0, 高: 2, 中: 1, 低: 1 },
  { t: '19:00', 严重: 0, 高: 2, 中: 1, 低: 1 }, { t: '20:00', 严重: 0, 高: 2, 中: 2, 低: 1 },
  { t: '21:00', 严重: 0, 高: 2, 中: 2, 低: 1 }, { t: '22:00', 严重: 0, 高: 2, 中: 2, 低: 1 },
  { t: '23:00', 严重: 0, 高: 2, 中: 2, 低: 1 }, { t: '00:00', 严重: 0, 高: 2, 中: 2, 低: 1 },
  { t: '01:00', 严重: 0, 高: 2, 中: 2, 低: 1 }, { t: '02:00', 严重: 0, 高: 3, 中: 2, 低: 1 },
  { t: '03:00', 严重: 0, 高: 3, 中: 2, 低: 1 }, { t: '04:00', 严重: 0, 高: 3, 中: 2, 低: 1 },
  { t: '05:00', 严重: 0, 高: 3, 中: 2, 低: 1 }, { t: '06:00', 严重: 1, 高: 3, 中: 2, 低: 1 },
  { t: '07:00', 严重: 1, 高: 3, 中: 2, 低: 1 }, { t: '08:00', 严重: 1, 高: 4, 中: 2, 低: 1 },
  { t: '09:00', 严重: 1, 高: 4, 中: 3, 低: 1 }, { t: '10:00', 严重: 1, 高: 4, 中: 3, 低: 1 },
  { t: '11:00', 严重: 1, 高: 5, 中: 3, 低: 1 }, { t: '12:00', 严重: 1, 高: 5, 中: 4, 低: 1 },
  { t: '13:00', 严重: 1, 高: 5, 中: 4, 低: 1 }, { t: '14:00', 严重: 1, 高: 5, 中: 4, 低: 2 },
]

export const TREND_7D = [
  { t: '07-24', 严重: 0, 高: 1, 中: 1, 低: 1 }, { t: '07-25', 严重: 0, 高: 1, 中: 2, 低: 2 },
  { t: '07-26', 严重: 0, 高: 1, 中: 2, 低: 2 }, { t: '07-27', 严重: 0, 高: 2, 中: 2, 低: 3 },
  { t: '07-28', 严重: 0, 高: 2, 中: 3, 低: 3 }, { t: '07-29', 严重: 0, 高: 3, 中: 3, 低: 3 },
  { t: '07-30', 严重: 1, 高: 5, 中: 4, 低: 4 },
]

export const RANK_DOMAINS = [
  { domain: 'mail.univ-a.example', score: 98 },
  { domain: 'cdn.media-g.example', score: 82 },
  { domain: 'api.fintech-e.example', score: 74 },
  { domain: 'data.cityf-gov.example', score: 66 },
  { domain: 'www.shop-d.example', score: 51 },
  { domain: 'oa.cityc-gov.example', score: 33 },
]

export const RANK_AFFECTED = [
  { domain: 'mail.univ-a.example', count: 1247 },
  { domain: 'cdn.media-g.example', count: 214 },
  { domain: 'data.cityf-gov.example', count: 96 },
  { domain: 'oa.cityc-gov.example', count: 42 },
  { domain: 'mail.hospital-b.example', count: 36 },
  { domain: 'api.fintech-e.example', count: 18 },
]

export const RANK_BL_SOURCE = [
  { source: 'abuse-ch-threatlist', hits: 1 },
  { source: 'spam-infra-list', hits: 1 },
  { source: 'community-feed', hits: 1 },
  { source: 'internal-watchlist', hits: 0 },
]

export const RANK_PC_DURATION = [
  { domain: 'data.cityf-gov.example', hours: 20.2 },
  { domain: 'lib.univ-b.example', hours: 1.8 },
]

// ---------- 系统组件状态 ----------
export interface SystemComponent {
  name: string
  category: '数据链路' | '存储' | '外部能力' | '通知'
  status: 'normal' | 'warning' | 'error'
  detail: string
  impact?: string
  updatedAt: string
}

export const SYSTEM_COMPONENTS: SystemComponent[] = [
  { name: '数据导入', category: '数据链路', status: 'normal', detail: '最近导入 snap-20260730-1420，10 分钟周期正常', updatedAt: '2026-07-30 14:21' },
  { name: '快照目录监测', category: '数据链路', status: 'normal', detail: '监测 /data/recursive-snapshots/，文件到达延迟 1.2 分钟', updatedAt: '2026-07-30 14:21' },
  { name: 'ClickHouse', category: '存储', status: 'normal', detail: '3 节点集群可用，写入 42k rows/min，查询 P95 380ms', updatedAt: '2026-07-30 14:21' },
  { name: 'GeoLite 离线库', category: '外部能力', status: 'error', detail: 'GeoLite2-City.mmdb 缺失（上次更新 2026-06-30，文件校验失败）', impact: 'ASN/国家归属识别暂停：新事件的相关字段将标记为「未知」，不影响既有基线比对', updatedAt: '2026-07-30 14:20' },
  { name: 'relay 拨测服务', category: '外部能力', status: 'warning', detail: 'relay-02 节点心跳丢失 18 分钟，relay-01 单点运行中', impact: '拨测验证吞吐量下降约 50%，待验证事件可能排队延迟', updatedAt: '2026-07-30 14:19' },
  { name: '邮件告警', category: '通知', status: 'normal', detail: 'SMTP 中继可用，最近 24h 投递 12 封、失败 0 封', updatedAt: '2026-07-30 14:21' },
]

// ---------- 黑名单库 ----------
export const BLACKLIST_SOURCES = [
  { name: 'abuse-ch-threatlist', version: 'v2.7', updatedAt: '2026-07-28 02:00', entries: 18402, confidence: '高', state: 'current' as const },
  { name: 'spam-infra-list', version: 'v9', updatedAt: '2026-07-29 02:00', entries: 6210, confidence: '中', state: 'current' as const },
  { name: 'community-feed', version: 'v14', updatedAt: '2026-07-24 02:00', entries: 41205, confidence: '低', state: 'current' as const },
  { name: 'internal-watchlist', version: 'v3', updatedAt: '2026-06-12 10:00', entries: 87, confidence: '高', state: 'expired' as const },
]

// ---------- 告警记录 ----------
export const ALERT_RECORDS = EVENTS.flatMap((e) =>
  e.alerts.map((a) => ({ ...a, eventId: e.id, domain: e.domain, level: e.level })),
).sort((a, b) => (a.time < b.time ? 1 : -1))

// ---------- 域名画像 ----------
export interface DomainProfile {
  domain: string
  baselineEstablished: boolean
  baselineSnapshots: number
  firstObserved: string
  registrar: string
  baselineNs: NsRecord[]
  currentNs: NsRecord[]
  cnameTargets: string[]
  childNames: string[]
  relatedEvents: string[]
}

export const DOMAIN_PROFILES: Record<string, DomainProfile> = {
  'mail.univ-a.example': {
    domain: 'mail.univ-a.example',
    baselineEstablished: true,
    baselineSnapshots: 12,
    firstObserved: '2026-05-11 08:00',
    registrar: '教育网自有注册',
    baselineNs: EVENTS[0].baselineNs,
    currentNs: EVENTS[0].currentNs,
    cnameTargets: ['smtp.univ-a.example', 'imap.univ-a.example', 'webmail.univ-a.example', 'pop3.univ-a.example'],
    childNames: ['mail.univ-a.example', 'smtp.univ-a.example', 'imap.univ-a.example', 'webmail.univ-a.example', 'pop3.univ-a.example'],
    relatedEvents: ['EVT-20260730-001'],
  },
  'data.cityf-gov.example': {
    domain: 'data.cityf-gov.example',
    baselineEstablished: true,
    baselineSnapshots: 12,
    firstObserved: '2026-04-02 10:00',
    registrar: '政务和公益机构域名注册管理中心',
    baselineNs: [ns('ns1.cityf-gov.example', ['203.0.113.106'], 'AS64502', '中国电信', '中国'), ns('ns2.cityf-gov.example', ['203.0.113.107'], 'AS64502', '中国电信', '中国')],
    currentNs: [ns('ns1.cityf-gov.example', ['203.0.113.106'], 'AS64502', '中国电信', '中国'), ns('ns2.cityf-gov.example', ['203.0.113.107'], 'AS64502', '中国电信', '中国')],
    cnameTargets: ['open-data.cityf-gov.example'],
    childNames: ['data.cityf-gov.example', 'open-data.cityf-gov.example', 'api-data.cityf-gov.example'],
    relatedEvents: ['EVT-20260730-006'],
  },
  'cdn.media-g.example': {
    domain: 'cdn.media-g.example',
    baselineEstablished: false,
    baselineSnapshots: 7,
    firstObserved: '2026-07-28 22:10',
    registrar: '某境外注册商',
    baselineNs: [],
    currentNs: EVENTS[6].currentNs,
    cnameTargets: ['static.media-g.example'],
    childNames: ['cdn.media-g.example', 'static.media-g.example'],
    relatedEvents: ['EVT-20260730-007'],
  },
}

// ---------- 拨测任务 ----------
export const PROBE_TASKS = [
  { id: 'PRB-1042', target: 'ns1.univ-a.example', domain: 'mail.univ-a.example', time: '2026-07-30 14:15', node: 'relay-01', result: '不一致', rtt: 86 },
  { id: 'PRB-1041', target: 'ns2.univ-a.example', domain: 'mail.univ-a.example', time: '2026-07-30 14:15', node: 'relay-01', result: '超时', rtt: null },
  { id: 'PRB-1040', target: 'ns1.fastnode-cdn.net', domain: 'cdn.media-g.example', time: '2026-07-30 13:40', node: 'relay-01', result: '不一致', rtt: 155 },
  { id: 'PRB-1039', target: 'ns1.cityf-gov.example', domain: 'data.cityf-gov.example', time: '2026-07-30 13:20', node: 'relay-02', result: '集合A', rtt: 11 },
  { id: 'PRB-1038', target: 'ns2.cityf-gov.example', domain: 'data.cityf-gov.example', time: '2026-07-30 13:20', node: 'relay-02', result: '集合B', rtt: 12 },
  { id: 'PRB-1037', target: 'ns1.fintech-e.example', domain: 'api.fintech-e.example', time: '2026-07-30 12:50', node: 'relay-01', result: '超时', rtt: null },
  { id: 'PRB-1036', target: 'ns1.adnet-j.example', domain: 'img.adnet-j.example', time: '2026-07-30 12:30', node: 'relay-01', result: '一致', rtt: 190 },
  { id: 'PRB-1035', target: 'ns1.hospital-b.example', domain: 'mail.hospital-b.example', time: '2026-07-30 11:00', node: 'relay-01', result: '一致', rtt: 14 },
]

export const findEvent = (id: string) => EVENTS.find((e) => e.id === id)

export function fmtDuration(min: number): string {
  if (min < 60) return `${min} 分钟`
  if (min < 1440) return `${Math.floor(min / 60)} 小时 ${min % 60 ? (min % 60) + ' 分' : ''}`
  return `${Math.floor(min / 1440)} 天 ${Math.floor((min % 1440) / 60)} 小时`
}
