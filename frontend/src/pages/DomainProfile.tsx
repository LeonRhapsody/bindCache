import { useState } from 'react'
import { Search, Network } from 'lucide-react'
import { Card, LevelBadge, StatusBadge, EvidenceBadge, NsTable, EmptyState, StateBanner } from '@/components/kit'
import Timeline from '@/components/Timeline'
import { DOMAIN_PROFILES, findEvent, EVENTS } from '@/data/mock'
import type { DomainDetailResponse, EventImpactResponse } from '@/domain/risk'
import { api } from '@/api/client'
import { useApiResource } from '@/api/useApiResource'
import { useHashRoute } from '@/lib/router'
import { nsRecordChanged } from '@/domain/nsDiff'

export default function DomainProfile({ domain }: { domain: string }) {
  const [, navigate] = useHashRoute()
  const [q, setQ] = useState('')
  const useMock = import.meta.env.VITE_USE_MOCK_DATA === 'true'
  const profileResource = useApiResource<DomainDetailResponse>(
    (signal) => {
      if (!useMock) return api.domain(domain, signal)
      const mock = DOMAIN_PROFILES[domain]
      if (!mock) return Promise.reject(new Error(`「${domain}」不在当前监测范围内或观测数据不足`))
      const relatedEvents = mock.relatedEvents.map(findEvent).filter((event): event is NonNullable<typeof event> => Boolean(event))
      return Promise.resolve({
        domain: mock.domain,
        baselineEstablished: mock.baselineEstablished,
        baselineSnapshots: mock.baselineSnapshots,
        baselineSource: mock.baselineEstablished ? 'confirmed' : 'candidate',
        firstObserved: mock.firstObserved,
        baselineNs: mock.baselineNs,
        currentNs: mock.currentNs,
        relatedEvents,
        timeline: relatedEvents.flatMap((event) => event.timeline),
      })
    },
    [domain, useMock],
  )
  const suggestionsResource = useApiResource<{ domains: string[] }>(
    (signal) => {
      if (useMock) {
        const allDomains = [...new Set(EVENTS.map((event) => event.domain))]
        return Promise.resolve({ domains: q ? allDomains.filter((item) => item.includes(q)) : [] })
      }
      return q.length >= 2 ? api.domains(q, signal) : Promise.resolve({ domains: [] })
    },
    [q, useMock],
  )
  const profile = profileResource.data
  const relationEventID = profile?.relatedEvents[0]?.id ?? ''
  const relationsResource = useApiResource<EventImpactResponse | null>(
    (signal) => {
      if (useMock || !relationEventID) return Promise.resolve(null)
      return api.eventImpact(relationEventID, signal)
    },
    [relationEventID, useMock],
  )
  const suggestions = suggestionsResource.data?.domains ?? []

  if (profileResource.loading && !profile) {
    return <Card><StateBanner kind="loading" /></Card>
  }
  if (profileResource.error || !profile) {
    return (
      <div className="mx-auto max-w-[900px] space-y-4">
        <DomainSearch q={q} setQ={setQ} suggestions={suggestions} />
        <Card>
          <EmptyState
            title="未找到该域名的画像"
            desc={profileResource.error?.message ?? `「${domain}」不在当前监测范围内或观测数据不足。`}
            action={<button onClick={profileResource.retry} className="mt-2 rounded-md border border-stone-200 bg-white px-3 py-1.5 text-xs text-stone-600 hover:bg-stone-50">重试</button>}
          />
        </Card>
      </div>
    )
  }

  const events = profile.relatedEvents
  const mergedTimeline = profile.timeline
  const mockRelations = useMock ? DOMAIN_PROFILES[domain] : undefined
  const childNames = useMock
    ? (mockRelations?.childNames ?? [])
    : (relationsResource.data?.groups.find((group) => group.type === 'zone_descendants')?.domains
      .map((item) => item.domain).filter((item) => item !== profile.domain) ?? [])
  const cnameTargets = useMock
    ? (mockRelations?.cnameTargets ?? [])
    : (relationsResource.data?.groups.filter((group) => group.type === 'cname_direct' || group.type === 'cname_chain')
      .flatMap((group) => group.domains.map((item) => item.domain)) ?? [])

  return (
    <div className="mx-auto max-w-[1440px] space-y-4">
      <DomainSearch q={q} setQ={setQ} suggestions={suggestions} />

      {/* 画像头部 */}
      <Card>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="font-mono text-base font-semibold text-stone-800">{profile.domain}</h2>
            <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-stone-400">
              <span>首次观测：{profile.firstObserved}</span>
              <span>
                基线状态：
                {profile.baselineEstablished
                  ? <b className="text-emerald-700">已建立稳定基线（{profile.baselineSnapshots} 次快照）</b>
                  : <b className="text-amber-700">观测中（{profile.baselineSnapshots}/12 次）</b>}
              </span>
            </div>
          </div>
          <div className="flex gap-2">
            {events.map((e) => (
              <button key={e.id} onClick={() => navigate(`/event/${e.id}`)}
                className="rounded-md border border-stone-200 bg-white px-2.5 py-1.5 text-xs text-stone-600 hover:bg-stone-50">
                {e.id}
              </button>
            ))}
          </div>
        </div>
        {!profile.baselineEstablished && <div className="mt-3"><StateBanner kind="no_baseline" compact /></div>}
      </Card>

      {/* NS 对比 */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card title="稳定观测基线 NS">
          {profile.baselineNs.length === 0
            ? <p className="py-2 text-xs text-stone-400">基线尚未形成，暂无法展示。</p>
            : <NsTable records={profile.baselineNs} />}
        </Card>
        <Card title="当前观测 NS">
          <NsTable records={profile.currentNs} highlight={(record) => profile.baselineEstablished && nsRecordChanged(profile.baselineNs, record)} />
        </Card>
      </div>

      {/* 承载关系 */}
      <Card title={<span className="flex items-center gap-1.5"><Network size={13} className="text-stone-400" />名称承载关系</span>}>
        {relationsResource.loading && !useMock && relationEventID && <p className="mb-3 text-xs text-stone-400">正在按需读取最近风险快照的子域与 CNAME 关系…</p>}
        {relationsResource.error && !useMock && <p className="mb-3 text-xs text-amber-700">承载关系暂不可用：{relationsResource.error.message}</p>}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div>
            <div className="mb-1.5 text-xs font-medium text-stone-500">受监控子域（{childNames.length}）</div>
            <div className="flex flex-wrap gap-1.5">
              {childNames.map((n) => (
                <span key={n} className="rounded border border-stone-200 bg-stone-50 px-2 py-1 font-mono text-[11px] text-stone-600">{n}</span>
              ))}
              {!childNames.length && <span className="text-xs text-stone-400">{relationEventID ? '最近风险快照未观察到事件域下的其他缓存名称。' : '当前域名没有可用于按需分析的关联风险事件。'}</span>}
            </div>
          </div>
          <div>
            <div className="mb-1.5 text-xs font-medium text-stone-500">CNAME 承载名称（{cnameTargets.length}）</div>
            <div className="flex flex-wrap gap-1.5">
              {cnameTargets.length === 0
                ? <span className="text-xs text-stone-400">{relationEventID ? '最近风险快照未观察到指向该域名空间的 CNAME 承载名称。' : '当前域名没有可用于按需分析的关联风险事件。'}</span>
                : cnameTargets.map((n) => (
                  <span key={n} className="rounded border border-violet-200 bg-violet-50 px-2 py-1 font-mono text-[11px] text-violet-700">{n}</span>
                ))}
            </div>
          </div>
        </div>
      </Card>

      {/* 关联事件 + 时间线 */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card title="关联风险事件">
          <ul className="space-y-2">
            {events.map((e) => (
              <li key={e.id} onClick={() => navigate(`/event/${e.id}`)}
                className="cursor-pointer rounded-md border border-stone-200 p-3 hover:border-cyan-300 hover:bg-cyan-50/30">
                <div className="flex flex-wrap items-center gap-2">
                  <LevelBadge level={e.level} />
                  <span className="font-mono text-xs text-stone-700">{e.id}</span>
                  <StatusBadge status={e.status} />
                  <EvidenceBadge level={e.evidence} />
                </div>
                <p className="mt-1.5 text-xs leading-5 text-stone-500">{e.summary}</p>
              </li>
            ))}
          </ul>
        </Card>
        <Card title="域名事件时间线">
          <Timeline nodes={mergedTimeline}
            activeLevel={events.some((e) => e.level === 'critical' && e.status !== 'recovered') ? 'critical' : events.some((e) => e.level === 'high' && e.status !== 'recovered') ? 'high' : undefined} />
        </Card>
      </div>
    </div>
  )
}

function DomainSearch({ q, setQ, suggestions }: { q: string; setQ: (v: string) => void; suggestions: string[] }) {
  const [, navigate] = useHashRoute()
  return (
    <div className="relative max-w-xl">
      <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-stone-400" />
      <input
        value={q}
        onChange={(e) => setQ(e.target.value)}
        onKeyDown={(e) => { if (e.key === 'Enter' && suggestions[0]) { navigate(`/domain/${suggestions[0]}`); setQ('') } }}
        placeholder="输入域名进行追溯，如 mail.univ-a.example"
        className="h-9 w-full rounded-md border border-stone-200 bg-white pl-9 pr-3 text-xs outline-none placeholder:text-stone-400 focus:border-cyan-500"
      />
      {suggestions.length > 0 && (
        <ul className="absolute z-20 mt-1 w-full overflow-hidden rounded-md border border-stone-200 bg-white shadow-lg">
          {suggestions.map((d) => (
            <li key={d}>
              <button className="block w-full px-3 py-2 text-left font-mono text-xs text-stone-700 hover:bg-cyan-50"
                onClick={() => { navigate(`/domain/${d}`); setQ('') }}>{d}</button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
