import { normalizeRiskEvent } from '@/domain/risk'
import type { AlertListItem, AuditListItem, BlacklistSource, CampaignsResponse, DomainDetailResponse, EventImpactResponse, EventsResponse, NSChangeOverviewResponse, NSDependencyResponse, NSHealthResponse, NSOwnershipResponse, OverviewResponse, ProbeListItem, RiskEvent, SessionInfo, SettingsResponse, SnapshotRecordResponse, SnapshotSummary, SystemComponent } from '@/domain/risk'

export class ApiError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function requestJSON<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, {
    method: 'GET',
    headers: { Accept: 'application/json' },
    credentials: 'same-origin',
    signal,
  })
  if (!response.ok) {
    let message = `请求失败（HTTP ${response.status}）`
    try {
      const body = await response.json() as { error?: string }
      if (body.error) message = body.error
    } catch {
      // 非 JSON 错误响应沿用 HTTP 状态。
    }
    throw new ApiError(message, response.status)
  }
  return response.json() as Promise<T>
}

async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(path, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      'X-Requested-With': 'bind-cache-analyze',
    },
    credentials: 'same-origin',
    body: JSON.stringify(body),
  })
  if (!response.ok) {
    let message = `请求失败（HTTP ${response.status}）`
    try {
      const payload = await response.json() as { error?: string }
      if (payload.error) message = payload.error
    } catch {
      // 保留 HTTP 状态。
    }
    throw new ApiError(message, response.status)
  }
  return response.json() as Promise<T>
}

export interface EventQuery {
  level?: string
  status?: string
  evidence?: string
  type?: string
  q?: string
  page?: number
  limit?: number
}

function queryString(query: EventQuery): string {
  const params = new URLSearchParams()
  Object.entries(query).forEach(([key, value]) => {
    if (value !== undefined && value !== '' && value !== 'all') params.set(key, String(value))
  })
  const encoded = params.toString()
  return encoded ? `?${encoded}` : ''
}

export const api = {
  overview: (signal?: AbortSignal) => requestJSON<OverviewResponse>('/api/v1/overview', signal)
    .then((response) => ({ ...response, recentEvents: (response.recentEvents ?? []).map(normalizeRiskEvent) })),
  events: (query: EventQuery, signal?: AbortSignal) => requestJSON<EventsResponse>(`/api/v1/events${queryString(query)}`, signal)
    .then((response) => ({ ...response, items: (response.items ?? []).map(normalizeRiskEvent) })),
  campaigns: (query: EventQuery, signal?: AbortSignal) => requestJSON<CampaignsResponse>(`/api/v1/campaigns${queryString(query)}`, signal)
    .then((response) => ({ ...response, items: (response.items ?? []).map((event) => ({
      ...event,
      zones: event.zones ?? [],
      changes: (event.changes ?? []).map((change) => ({
        ...change,
        previous_owners: change.previous_owners ?? [],
        current_owners: change.current_owners ?? [],
        previous_values: change.previous_values ?? [],
        current_values: change.current_values ?? [],
      })),
    })) })),
  nsOwnership: (snapshotID: string, owner: string, graphQuery: string, signal?: AbortSignal) => {
    const params = new URLSearchParams({ limit: '300' })
    if (snapshotID) params.set('snapshot_id', snapshotID)
    if (owner) params.set('owner', owner)
    if (graphQuery) params.set('q', graphQuery)
    return requestJSON<NSOwnershipResponse>(`/api/v1/ns-ownership?${params}`, signal)
  },
  nsChangeOverview: (options: { snapshotID?: string; q?: string; type?: string; page?: number; limit?: number; trendLimit?: number }, signal?: AbortSignal) => {
    const params = new URLSearchParams({
      page: String(options.page ?? 1),
      limit: String(options.limit ?? 100),
      trend_limit: String(options.trendLimit ?? 48),
    })
    if (options.snapshotID) params.set('snapshot_id', options.snapshotID)
    if (options.q) params.set('q', options.q)
    if (options.type && options.type !== 'all') params.set('type', options.type)
    return requestJSON<NSChangeOverviewResponse>(`/api/v1/ns-change-overview?${params}`, signal)
  },
  nsDependencies: (options: { snapshotID?: string; host?: string; q?: string; page?: number; limit?: number; nodeLimit?: number }, signal?: AbortSignal) => {
    const params = new URLSearchParams({
      page: String(options.page ?? 1),
      limit: String(options.limit ?? 100),
      node_limit: String(options.nodeLimit ?? 240),
    })
    if (options.snapshotID) params.set('snapshot_id', options.snapshotID)
    if (options.host) params.set('host', options.host)
    if (options.q) params.set('q', options.q)
    return requestJSON<NSDependencyResponse>(`/api/v1/ns-dependencies?${params}`, signal)
  },
  nsHealth: (signal?: AbortSignal) => requestJSON<NSHealthResponse>('/api/v1/ns-health?limit=200', signal),
  event: (id: string, signal?: AbortSignal) => requestJSON<RiskEvent>(`/api/v1/events/${encodeURIComponent(id)}`, signal).then(normalizeRiskEvent),
  eventImpact: (id: string, signal?: AbortSignal) => requestJSON<EventImpactResponse>(`/api/v1/events/${encodeURIComponent(id)}/impact`, signal),
  snapshotRecord: (eventID: string, snapshotID: string, signal?: AbortSignal) => requestJSON<SnapshotRecordResponse>(
    `/api/v1/events/${encodeURIComponent(eventID)}/rr?snapshot_id=${encodeURIComponent(snapshotID)}`,
    signal,
  ),
  domain: (domain: string, signal?: AbortSignal) => requestJSON<DomainDetailResponse>(`/api/v1/domains/${encodeURIComponent(domain)}`, signal)
    .then((response) => ({ ...response, relatedEvents: (response.relatedEvents ?? []).map(normalizeRiskEvent) })),
  domains: (q: string, signal?: AbortSignal) => requestJSON<{ domains: string[] }>(`/api/v1/domains?q=${encodeURIComponent(q)}&limit=20`, signal),
  blacklists: (signal?: AbortSignal) => requestJSON<{ sources: BlacklistSource[]; warning?: string }>('/api/v1/blacklists', signal),
  alerts: (signal?: AbortSignal) => requestJSON<{
    items: AlertListItem[]; total: number; mode: string
    policy?: { enabled: boolean; severities: string[]; recipients: string[]; cooldown: string; subjectPrefix: string; recoveryEnabled: boolean }
  }>('/api/v1/alerts?limit=200', signal),
  retryAlert: (eventId: string, recipient: string) => postJSON('/api/v1/alerts/retry', { eventId, recipient }),
  audit: (signal?: AbortSignal) => requestJSON<{ items: AuditListItem[]; total: number; mode: string }>('/api/v1/audit?limit=100', signal),
  probes: (signal?: AbortSignal) => requestJSON<{
    items: ProbeListItem[]; total: number; mode: string
    policy?: { execution: string; maxEventsPerImport: number; maxParallel: number; eventTimeout: string; backend: string }
  }>('/api/v1/probes?limit=200', signal),
  eventAction: (id: string, action: 'confirm' | 'ignore' | 'whitelist', reason: string, expiresAt?: string) =>
    postJSON(`/api/v1/events/${encodeURIComponent(id)}/actions`, { action, reason, expiresAt: expiresAt ?? '' }),
  campaignAction: (id: string, action: 'confirm' | 'ignore' | 'whitelist', reason: string, expiresAt?: string) =>
    postJSON(`/api/v1/campaigns/${encodeURIComponent(id)}/actions`, { action, reason, expiresAt: expiresAt ?? '' }),
  manualProbe: (eventId: string) => postJSON('/api/v1/probes', { eventId }),
  system: (signal?: AbortSignal) => requestJSON<{ components: SystemComponent[]; snapshots: SnapshotSummary[] }>('/api/v1/system?snapshotLimit=100', signal),
  settings: (signal?: AbortSignal) => requestJSON<SettingsResponse>('/api/v1/settings', signal),
  session: (signal?: AbortSignal) => requestJSON<SessionInfo>('/api/v1/session', signal),
  saveSettings: (settings: SettingsResponse) => fetch('/api/v1/settings', {
    method: 'PUT',
    credentials: 'same-origin',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-Requested-With': 'bind-cache-analyze' },
    body: JSON.stringify(settings),
  }).then(async (response) => {
    const body = await response.json() as { error?: string; saved?: boolean; restartRequired?: boolean }
    if (!response.ok) throw new ApiError(body.error ?? `请求失败（HTTP ${response.status}）`, response.status)
    return body
  }),
  uploadBlacklist: (file: File) => fetch('/api/v1/blacklists', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'text/csv',
      'X-Requested-With': 'bind-cache-analyze',
      'X-Filename': file.name,
    },
    body: file,
  }).then(async (response) => {
    const body = await response.json() as {
      error?: string; name?: string; version?: string; warning?: string
      source?: { name?: string; version?: string }
    }
    if (!response.ok) throw new ApiError(body.error ?? `请求失败（HTTP ${response.status}）`, response.status)
    return body
  }),
}
