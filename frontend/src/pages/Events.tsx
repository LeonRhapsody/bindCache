import { RotateCcw } from 'lucide-react'
import { Card, LevelBadge, StatusBadge, EvidenceBadge, EmptyState, Duration, StateBanner } from '@/components/kit'
import { EVENTS } from '@/data/mock'
import { RISK_TYPE_LABEL, LEVEL_LABEL, STATUS_LABEL, EVIDENCE_LABEL } from '@/domain/risk'
import type { RiskEvent, RiskLevel, EventStatus, EvidenceLevel, RiskType, EventsResponse } from '@/domain/risk'
import { api } from '@/api/client'
import { useApiResource } from '@/api/useApiResource'
import { useHashRoute, setQueryParams } from '@/lib/router'
import { cn } from '@/lib/utils'

export function useEventFilters(routeQuery: URLSearchParams) {
  return {
    level: (routeQuery.get('level') ?? 'all') as RiskLevel | 'all',
    status: (routeQuery.get('status') ?? 'all') as EventStatus | 'all',
    evidence: (routeQuery.get('evidence') ?? 'all') as EvidenceLevel | 'all',
    type: (routeQuery.get('type') ?? 'all') as RiskType | 'all',
    q: routeQuery.get('q') ?? '',
    page: Math.max(Number(routeQuery.get('page') ?? 1) || 1, 1),
  }
}

export function filterEvents(events: RiskEvent[], f: ReturnType<typeof useEventFilters>) {
  return events.filter((e) =>
    (f.level === 'all' || e.level === f.level) &&
    (f.status === 'all' || e.status === f.status) &&
    (f.evidence === 'all' || e.evidence === f.evidence) &&
    (f.type === 'all' || e.type === f.type) &&
    (!f.q || e.domain.includes(f.q) || e.id.toLowerCase().includes(f.q.toLowerCase())),
  )
}

function FilterSelect({ label, value, param, options }: {
  label: string; value: string; param: string; options: [string, string][]
}) {
  return (
    <label className="flex items-center gap-1.5 text-xs text-stone-500">
      {label}
      <select
        value={value}
        onChange={(e) => setQueryParams({ [param]: e.target.value, page: null })}
        className={cn('h-7 rounded-md border border-stone-200 bg-white px-1.5 text-xs text-stone-700 outline-none focus:border-cyan-500',
          value !== 'all' && 'border-cyan-300 bg-cyan-50/50 text-cyan-800')}
      >
        <option value="all">全部</option>
        {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
      </select>
    </label>
  )
}

export function EventFilterBar({ showType = true }: { showType?: boolean }) {
  const [route] = useHashRoute()
  const f = useEventFilters(route.query)
  const hasFilter = f.level !== 'all' || f.status !== 'all' || f.evidence !== 'all' || (showType && f.type !== 'all') || !!f.q
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
      <FilterSelect label="风险等级" value={f.level} param="level" options={(Object.keys(LEVEL_LABEL) as RiskLevel[]).map((k) => [k, LEVEL_LABEL[k]])} />
      <FilterSelect label="状态" value={f.status} param="status" options={(Object.keys(STATUS_LABEL) as EventStatus[]).map((k) => [k, STATUS_LABEL[k]])} />
      <FilterSelect label="证据" value={f.evidence} param="evidence" options={(Object.keys(EVIDENCE_LABEL) as EvidenceLevel[]).map((k) => [k, EVIDENCE_LABEL[k]])} />
      {showType && <FilterSelect label="类型" value={f.type} param="type" options={(Object.keys(RISK_TYPE_LABEL) as RiskType[]).map((k) => [k, RISK_TYPE_LABEL[k]])} />}
      <input
        defaultValue={f.q}
        placeholder="域名 / 事件 ID，回车确认"
        onKeyDown={(e) => { if (e.key === 'Enter') setQueryParams({ q: (e.target as HTMLInputElement).value.trim() || null, page: null }) }}
        className="h-7 w-44 rounded-md border border-stone-200 bg-white px-2 text-xs outline-none placeholder:text-stone-400 focus:border-cyan-500"
      />
      {hasFilter && (
        <button
          onClick={() => setQueryParams(showType
            ? { level: null, status: null, evidence: null, type: null, q: null, page: null }
            : { level: null, status: null, evidence: null, q: null, page: null })}
          className="inline-flex items-center gap-1 text-xs text-cyan-700 hover:underline"
        >
          <RotateCcw size={12} /> 清除筛选
        </button>
      )}
      <span className="ml-auto hidden text-[11px] text-stone-400 sm:inline">筛选条件已写入 URL，可直接分享</span>
    </div>
  )
}

const LEVEL_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4, recovered: 5 }

export function EventTable({ events, showType = true }: { events: RiskEvent[]; showType?: boolean }) {
  const [, navigate] = useHashRoute()
  const sorted = [...events].sort((a, b) => {
    const d = (LEVEL_RANK[a.level] ?? 9) - (LEVEL_RANK[b.level] ?? 9)
    return d !== 0 ? d : a.lastSeen < b.lastSeen ? 1 : -1
  })
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[880px] text-xs">
        <thead>
          <tr className="border-b border-stone-100 text-left text-stone-400">
            <th className="py-2 pl-4 pr-2 font-medium">等级</th>
            <th className="py-2 pr-2 font-medium">域名 / 事件</th>
            {showType && <th className="py-2 pr-2 font-medium">类型</th>}
            <th className="py-2 pr-2 font-medium">证据等级</th>
            <th className="py-2 pr-2 font-medium">状态</th>
            <th className="py-2 pr-2 font-medium">首次 → 最近</th>
            <th className="py-2 pr-2 font-medium">持续</th>
            <th className="py-2 pr-2 font-medium text-right">观测</th>
            <th className="py-2 pr-4 font-medium text-right">受影响</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((e) => (
            <tr key={e.id} onClick={() => navigate(`/event/${e.id}`)}
              className={cn('cursor-pointer border-b border-stone-50 last:border-0 hover:bg-cyan-50/40',
                e.id === 'EVT-20260730-010' && 'animate-[newRow_2.4s_ease-out_1]')}>
              <td className="py-2.5 pl-4 pr-2"><LevelBadge level={e.level} /></td>
              <td className="max-w-[280px] py-2.5 pr-2">
                <div className="truncate font-mono text-[13px] text-stone-700">{e.domain}</div>
                <div className="mt-0.5 truncate text-stone-400">{e.id} · {e.summary}</div>
              </td>
              {showType && <td className="py-2.5 pr-2 whitespace-nowrap text-stone-600">{RISK_TYPE_LABEL[e.type]}</td>}
              <td className="py-2.5 pr-2"><EvidenceBadge level={e.evidence} /></td>
              <td className="py-2.5 pr-2"><StatusBadge status={e.status} breathing={(e.level === 'critical' || e.level === 'high') && (e.status === 'active' || e.status === 'confirmed')} /></td>
              <td className="py-2.5 pr-2 whitespace-nowrap tabular-nums text-stone-500">{e.firstSeen.slice(5)}<br />{e.lastSeen.slice(5)}</td>
              <td className="py-2.5 pr-2 whitespace-nowrap"><Duration min={e.durationMin} /></td>
              <td className="py-2.5 pr-2 text-right tabular-nums text-stone-500">{e.observations}{e.clusterSize > e.observations ? '' : ''}</td>
              <td className="py-2.5 pr-4 text-right tabular-nums text-stone-500">{e.affectedCount || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function EventsPage() {
  const [route] = useHashRoute()
  const f = useEventFilters(route.query)
  const useMock = import.meta.env.VITE_USE_MOCK_DATA === 'true'
  const resource = useApiResource<EventsResponse>(
    (signal) => {
      if (useMock) {
        const filtered = filterEvents(EVENTS, f)
        const start = (f.page - 1) * 50
        return Promise.resolve({ items: filtered.slice(start, start + 50), total: filtered.length, page: f.page, limit: 50 })
      }
      return api.events({ level: f.level, status: f.status, evidence: f.evidence, type: f.type, q: f.q, page: f.page, limit: 50 }, signal)
    },
    [useMock, f.level, f.status, f.evidence, f.type, f.q, f.page],
  )
  const response = resource.data
  const events = response?.items ?? []
  const totalPages = response ? Math.max(Math.ceil(response.total / response.limit), 1) : 1

  return (
    <div className="mx-auto max-w-[1440px] space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h2 className="text-base font-semibold text-stone-800">统一风险事件</h2>
          <p className="mt-0.5 text-xs text-stone-400">四类检测场景的统一入口 · 相同事件已自动聚合降噪 · 当前筛选共 {response?.total ?? '—'} 个事件簇</p>
        </div>
        <div className="flex gap-2 text-[11px] text-stone-400">
          <span>生命周期：单次观测 → 重复出现 → 待验证 → 权威分歧 → 实际影响 → 恢复/排除</span>
        </div>
      </div>
      <Card pad={false}>
        <div className="border-b border-stone-100 px-4 py-3"><EventFilterBar /></div>
        {useMock && <div className="border-b border-amber-100 bg-amber-50 px-4 py-2 text-[11px] text-amber-700">开发预览模式：当前展示显式启用的仿真数据，生产构建默认只读取 /api/v1。</div>}
        {resource.loading && !response ? <StateBanner kind="loading" /> : resource.error ? (
          <StateBanner kind="query_failed" />
        ) : events.length === 0 ? (
          <EmptyState
            desc="当前筛选条件下没有匹配的事件。可以放宽筛选条件，或确认对应检测场景是否已产生观测数据。"
            action={
              <button onClick={() => setQueryParams({ level: null, status: null, evidence: null, type: null, q: null })}
                className="mt-1 inline-flex items-center gap-1 rounded-md border border-stone-200 px-3 py-1.5 text-xs text-stone-600 hover:bg-stone-50">
                <RotateCcw size={12} /> 清除全部筛选
              </button>
            }
          />
        ) : (
          <>
            <EventTable events={events} />
            <div className="flex items-center justify-between border-t border-stone-100 px-4 py-3 text-xs text-stone-500">
              <span>第 {response?.page ?? 1} / {totalPages} 页，共 {response?.total ?? 0} 条</span>
              <div className="flex gap-2">
                <button disabled={f.page <= 1} onClick={() => setQueryParams({ page: String(f.page - 1) })}
                  className="rounded border border-stone-200 px-2.5 py-1 disabled:cursor-not-allowed disabled:opacity-40 hover:bg-stone-50">上一页</button>
                <button disabled={f.page >= totalPages} onClick={() => setQueryParams({ page: String(f.page + 1) })}
                  className="rounded border border-stone-200 px-2.5 py-1 disabled:cursor-not-allowed disabled:opacity-40 hover:bg-stone-50">下一页</button>
              </div>
            </div>
          </>
        )}
      </Card>
    </div>
  )
}
