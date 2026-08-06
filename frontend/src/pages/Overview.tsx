import { useState } from 'react'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, BarChart, Bar, LabelList,
} from 'recharts'
import { Activity, ShieldAlert, Flame, ShieldQuestion, PlusCircle, History, Database, Clock3 } from 'lucide-react'
import { Card, StatCard, LevelBadge, StatusBadge, EvidenceBadge, LEVEL_STYLE } from '@/components/kit'
import {
  OVERVIEW_KPIS, TREND_24H, TREND_7D, EVENTS, RANK_DOMAINS, RANK_AFFECTED, RANK_BL_SOURCE,
  RANK_PC_DURATION, SYSTEM_COMPONENTS,
} from '@/data/mock'
import { RISK_TYPE_LABEL, fmtDuration } from '@/domain/risk'
import type { OverviewResponse, RiskEvent } from '@/domain/risk'
import { api } from '@/api/client'
import { useApiResource } from '@/api/useApiResource'
import { useHashRoute } from '@/lib/router'
import { cn } from '@/lib/utils'

const LEVELS = ['critical', 'high', 'medium', 'low'] as const

function buildTrend(events: RiskEvent[], range: '24h' | '7d') {
  const now = new Date()
  const size = range === '24h' ? 24 : 7
  const buckets = Array.from({ length: size }, (_, index) => {
    const at = new Date(now)
    if (range === '24h') at.setHours(now.getHours() - (size - 1 - index), 0, 0, 0)
    else at.setDate(now.getDate() - (size - 1 - index))
    const key = range === '24h'
      ? `${String(at.getHours()).padStart(2, '0')}:00`
      : `${String(at.getMonth() + 1).padStart(2, '0')}-${String(at.getDate()).padStart(2, '0')}`
    return { t: key, 严重: 0, 高: 0, 中: 0, 低: 0, at }
  })
  events.forEach((event) => {
    const seen = new Date(event.lastSeen.replace(' ', 'T') + 'Z')
    let index = -1
    if (range === '24h') index = buckets.findIndex((bucket) => bucket.at.getUTCFullYear() === seen.getUTCFullYear() && bucket.at.getUTCMonth() === seen.getUTCMonth() && bucket.at.getUTCDate() === seen.getUTCDate() && bucket.at.getUTCHours() === seen.getUTCHours())
    else index = buckets.findIndex((bucket) => bucket.at.getUTCFullYear() === seen.getUTCFullYear() && bucket.at.getUTCMonth() === seen.getUTCMonth() && bucket.at.getUTCDate() === seen.getUTCDate())
    if (index < 0) return
    const field = event.level === 'critical' ? '严重'
      : event.level === 'high' ? '高'
        : event.level === 'medium' ? '中'
          : event.level === 'low' ? '低'
            : undefined
    if (field) buckets[index][field]++
  })
  return buckets.map((bucket) => ({ t: bucket.t, 严重: bucket.严重, 高: bucket.高, 中: bucket.中, 低: bucket.低 }))
}

export default function Overview() {
  const [, navigate] = useHashRoute()
  const [trendRange, setTrendRange] = useState<'24h' | '7d'>('24h')
  const useMock = import.meta.env.VITE_USE_MOCK_DATA === 'true'
  const resource = useApiResource<OverviewResponse>(
    (signal) => useMock
      ? Promise.resolve({
        kpis: OVERVIEW_KPIS,
        recentEvents: EVENTS,
        snapshots: [],
        mode: 'memory',
        warnings: [],
        generatedAt: OVERVIEW_KPIS.latestSnapshot,
      })
      : api.overview(signal),
    [useMock],
  )
  const systemResource = useApiResource(
    (signal) => useMock ? Promise.resolve({ components: SYSTEM_COMPONENTS, snapshots: [] }) : api.system(signal),
    [useMock],
  )
  const overview = resource.data
  const events = overview?.recentEvents ?? []
  const kpis = overview?.kpis ?? OVERVIEW_KPIS
  const trend = useMock
    ? (trendRange === '24h' ? TREND_24H : TREND_7D)
    : buildTrend(events, trendRange)

  const typeDist = (Object.keys(RISK_TYPE_LABEL) as (keyof typeof RISK_TYPE_LABEL)[]).map((t, i) => ({
    name: RISK_TYPE_LABEL[t],
    value: events.filter((e) => e.type === t && e.status !== 'recovered').length,
    color: ['#0e7490', '#7c3aed', '#b45309', '#be123c', '#059669'][i],
  }))
  const levelDist = LEVELS.map((l) => ({
    name: LEVEL_STYLE[l].hex,
    label: { critical: '严重', high: '高', medium: '中', low: '低' }[l],
    value: events.filter((e) => e.level === l && e.status !== 'recovered').length,
  }))
  const evidenceDist = [
    ['缓存观测线索', 'cache_hint'], ['重复异常', 'repeated'], ['待验证', 'pending_verify'],
    ['已确认权威分歧', 'auth_divergence'], ['已确认实际影响', 'impact_confirmed'],
  ].map(([name, evidence]) => ({ name, value: events.filter((event) => event.evidence === evidence).length }))

  const latestSevere = events.filter((e) => (e.level === 'critical' || e.level === 'high') && e.status !== 'recovered' && e.status !== 'ignored')
    .sort((a, b) => (a.lastSeen < b.lastSeen ? 1 : -1)).slice(0, 5)
  const levelScore = { critical: 100, high: 75, medium: 50, low: 25, recovered: 5, unknown: 0 }
  const domainRanks = useMock ? RANK_DOMAINS : events.slice()
    .sort((a, b) => levelScore[b.level] - levelScore[a.level] || b.observations - a.observations)
    .slice(0, 6).map((event) => ({ domain: event.domain, score: levelScore[event.level] }))
  const affectedRanks = useMock ? RANK_AFFECTED : events.filter((event) => event.affectedCount > 0).sort((a, b) => b.affectedCount - a.affectedCount).slice(0, 6).map((event) => ({ domain: event.domain, count: event.affectedCount }))
  const blacklistCounts = new Map<string, number>()
  if (!useMock) events.filter((event) => event.type === 'ns_blacklist').forEach((event) => {
    const hits = Array.isArray(event.extra?.hits) ? event.extra.hits as { source?: string }[] : []
    hits.forEach((hit) => {
      const source = hit.source?.trim()
      if (source) blacklistCounts.set(source, (blacklistCounts.get(source) ?? 0) + 1)
    })
  })
  const blacklistRanks = useMock
    ? RANK_BL_SOURCE.map((item) => ({ label: item.source, value: item.hits }))
    : [...blacklistCounts].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([label, value]) => ({ label, value }))
  const parentChildRanks = useMock
    ? RANK_PC_DURATION.map((item) => ({ label: item.domain, value: item.hours }))
    : events.filter((event) => event.type === 'ns_parent_child')
      .sort((a, b) => b.durationMin - a.durationMin).slice(0, 6)
      .map((event) => ({ label: event.domain, value: Math.round(event.durationMin / 6) / 10 }))
  const systemComponents = systemResource.data?.components ?? []

  if (resource.loading && !overview) return <Card><div className="py-12 text-center text-sm text-stone-500">正在加载生产数据…</div></Card>
  if (resource.error || !overview) return <Card><div className="py-12 text-center text-sm text-red-600">总览数据读取失败：{resource.error?.message}<br /><button onClick={resource.retry} className="mt-3 rounded border border-stone-200 px-3 py-1.5 text-xs text-stone-600">重试</button></div></Card>

  return (
    <div className="mx-auto max-w-[1440px] space-y-4">
      {/* 顶部指标 */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-9">
        <StatCard label="活动事件" value={kpis.activeEvents} icon={<Activity size={12} />} sub="全部风险类型" />
        <StatCard label="严重事件" value={kpis.criticalEvents} tone="critical" icon={<ShieldAlert size={12} />} sub="需立即处置" />
        <StatCard label="高风险事件" value={kpis.highEvents} tone="high" icon={<Flame size={12} />} sub="需要持续关注" />
        <StatCard label="待验证事件" value={kpis.pendingVerify} icon={<ShieldQuestion size={12} />} sub="等待拨测确认" />
        <StatCard label="24h 新增" value={kpis.new24h} icon={<PlusCircle size={12} />} />
        <StatCard label="24h 恢复" value={kpis.recovered24h} tone="ok" icon={<History size={12} />} />
        <StatCard label="稳定基线域名" value={kpis.baselineDomains.toLocaleString()} icon={<Database size={12} />} sub="≥12 次快照" />
        <StatCard label="最新快照" value={<span className="text-lg leading-8">{kpis.latestSnapshot.slice(11) || '—'}</span>} icon={<Clock3 size={12} />} sub={kpis.latestSnapshot.slice(0, 10) || '暂无快照'} />
        <StatCard label="数据延迟" value={<span className="text-lg leading-8">{kpis.dataDelayMin} 分钟</span>} sub="正常范围 <10 分钟" />
      </div>

      {/* 中部图表 */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card
          className="xl:col-span-2"
          title={useMock ? '风险事件趋势' : '风险事件趋势（最近事件窗口）'}
          extra={
            <div className="flex rounded-md border border-stone-200 p-0.5 text-xs">
              {(['24h', '7d'] as const).map((r) => (
                <button key={r} onClick={() => setTrendRange(r)}
                  className={cn('rounded px-2.5 py-0.5 transition-colors', trendRange === r ? 'bg-stone-800 text-white' : 'text-stone-500 hover:text-stone-700')}>
                  {r === '24h' ? '最近 24 小时' : '最近 7 天'}
                </button>
              ))}
            </div>
          }
        >
          <div className="h-56">
            <ResponsiveContainer>
              <AreaChart data={trend} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e7e5e4" vertical={false} />
                <XAxis dataKey="t" tick={{ fontSize: 10, fill: '#a8a29e' }} tickLine={false} axisLine={{ stroke: '#e7e5e4' }} interval={trendRange === '24h' ? 3 : 0} />
                <YAxis tick={{ fontSize: 10, fill: '#a8a29e' }} tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #e7e5e4' }} />
                <Area type="monotone" dataKey="严重" stackId="1" stroke="#dc2626" fill="#dc2626" fillOpacity={0.75} isAnimationActive={false} />
                <Area type="monotone" dataKey="高" stackId="1" stroke="#ea580c" fill="#ea580c" fillOpacity={0.65} isAnimationActive={false} />
                <Area type="monotone" dataKey="中" stackId="1" stroke="#d97706" fill="#d97706" fillOpacity={0.55} isAnimationActive={false} />
                <Area type="monotone" dataKey="低" stackId="1" stroke="#0284c7" fill="#0284c7" fillOpacity={0.45} isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-1 flex flex-wrap gap-4 text-[11px] text-stone-500">
            {(['严重', '高', '中', '低'] as const).map((k, i) => (
              <span key={k} className="inline-flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-sm" style={{ background: ['#dc2626', '#ea580c', '#d97706', '#0284c7'][i] }} />{k}风险
              </span>
            ))}
          </div>
        </Card>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3 xl:grid-cols-1">
          <Card title="按风险类型" pad={false}>
            <div className="flex items-center">
              <div className="h-28 w-28 shrink-0">
                <ResponsiveContainer>
                  <PieChart>
                    <Pie data={typeDist} dataKey="value" innerRadius={30} outerRadius={50} paddingAngle={2} isAnimationActive={false}>
                      {typeDist.map((d, i) => <Cell key={i} fill={d.color} />)}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <ul className="flex-1 space-y-1 pr-3 text-[11px]">
                {typeDist.map((d) => (
                  <li key={d.name} className="flex items-center gap-1.5 text-stone-600">
                    <span className="h-2 w-2 rounded-sm" style={{ background: d.color }} />
                    <span className="truncate">{d.name}</span>
                    <span className="ml-auto tabular-nums text-stone-400">{d.value}</span>
                  </li>
                ))}
              </ul>
            </div>
          </Card>
          <Card title="按风险等级" pad={false}>
            <div className="flex items-center">
              <div className="h-28 w-28 shrink-0">
                <ResponsiveContainer>
                  <PieChart>
                    <Pie data={levelDist} dataKey="value" innerRadius={30} outerRadius={50} paddingAngle={2} isAnimationActive={false}>
                      {levelDist.map((d, i) => <Cell key={i} fill={d.name} />)}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <ul className="flex-1 space-y-1 pr-3 text-[11px]">
                {levelDist.map((d) => (
                  <li key={d.label} className="flex items-center gap-1.5 text-stone-600">
                    <span className="h-2 w-2 rounded-sm" style={{ background: d.name }} />
                    <span>{d.label}风险</span>
                    <span className="ml-auto tabular-nums text-stone-400">{d.value}</span>
                  </li>
                ))}
              </ul>
            </div>
          </Card>
          <Card title="按证据状态" pad={false}>
            <div className="h-28 px-2">
              <ResponsiveContainer>
                <BarChart data={evidenceDist} layout="vertical" margin={{ top: 2, right: 22, left: 0, bottom: 2 }}>
                  <XAxis type="number" hide />
                  <YAxis type="category" dataKey="name" width={86} tick={{ fontSize: 10, fill: '#78716c' }} tickLine={false} axisLine={false} />
                  <Bar dataKey="value" fill="#0e7490" radius={[0, 3, 3, 0]} barSize={10} isAnimationActive={false}>
                    <LabelList dataKey="value" position="right" style={{ fontSize: 10, fill: '#a8a29e' }} />
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </div>
      </div>

      {/* 排名区 */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <RankCard title="风险域名排名" items={domainRanks.map((d) => ({ label: d.domain, value: d.score }))} unit="分" color="#dc2626" onClick={(l) => navigate(`/domain/${l}`)} />
        <RankCard title="受影响名称数量" items={affectedRanks.map((d) => ({ label: d.domain, value: d.count }))} unit="个" color="#ea580c" emptyText="影响面按需读取原始快照，当前列表暂无已计算数据" onClick={(l) => navigate(`/domain/${l}`)} />
        <RankCard title="黑名单来源分布" items={blacklistRanks} unit="次" color="#0e7490" emptyText="当前事件窗口无有效黑名单命中" onClick={() => navigate('/ns-blacklist')} />
        <RankCard title="父子不一致持续时间" items={parentChildRanks} unit="小时" color="#b45309" emptyText="当前事件窗口无父子不一致" onClick={() => navigate('/ns-parent-child')} />
      </div>

      {/* 底部：最新高危事件 + 系统组件状态（与 DNS 风险分开展示） */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
        <Card title="最新严重 / 高风险事件" className="xl:col-span-3" pad={false}
          extra={<button className="text-xs text-cyan-700 hover:underline" onClick={() => navigate('/events')}>查看全部</button>}>
          {latestSevere.length === 0 ? <p className="px-4 py-8 text-center text-xs text-stone-400">当前没有活动的严重或高风险事件。</p> : <table className="w-full text-xs">
            <tbody>
              {latestSevere.map((e) => (
                <tr key={e.id} className="cursor-pointer border-b border-stone-50 last:border-0 hover:bg-stone-50" onClick={() => navigate(`/event/${e.id}`)}>
                  <td className="py-2.5 pl-4 pr-2"><LevelBadge level={e.level} /></td>
                  <td className="py-2.5 pr-2">
                    <div className="font-mono text-[13px] text-stone-700">{e.domain}</div>
                    <div className="mt-0.5 line-clamp-1 text-stone-400">{e.summary}</div>
                  </td>
                  <td className="hidden py-2.5 pr-2 md:table-cell"><EvidenceBadge level={e.evidence} /></td>
                  <td className="py-2.5 pr-2 whitespace-nowrap"><StatusBadge status={e.status} breathing={e.level === 'critical'} /></td>
                  <td className="hidden py-2.5 pr-4 text-right tabular-nums text-stone-400 lg:table-cell">{fmtDuration(e.durationMin)}</td>
                </tr>
              ))}
            </tbody>
          </table>}
        </Card>

        <Card title="平台组件状态（系统异常，非 DNS 事件）" className="xl:col-span-2" pad={false}
          extra={<button className="text-xs text-cyan-700 hover:underline" onClick={() => navigate('/system')}>详情</button>}>
          {systemComponents.length === 0 ? <p className="px-4 py-8 text-center text-xs text-stone-400">系统组件状态尚未返回。</p> : <ul className="divide-y divide-stone-50">
            {systemComponents.map((c) => (
              <li key={c.name} className="flex items-center gap-2.5 px-4 py-2.5 text-xs">
                <span className={cn('h-2 w-2 shrink-0 rounded-full',
                  c.status === 'normal' ? 'bg-emerald-500' : c.status === 'warning' ? 'animate-pulse bg-amber-500' : 'animate-pulse bg-red-500')} />
                <span className="w-24 shrink-0 font-medium text-stone-700">{c.name}</span>
                <span className="min-w-0 flex-1 truncate text-stone-400" title={c.detail}>{c.detail}</span>
                <span className={cn('shrink-0 rounded border px-1.5 py-0.5 text-[10px]',
                  c.status === 'normal' ? 'border-emerald-200 bg-emerald-50 text-emerald-700'
                    : c.status === 'warning' ? 'border-amber-200 bg-amber-50 text-amber-700'
                      : 'border-red-200 bg-red-50 text-red-700')}>
                  {c.status === 'normal' ? '正常' : c.status === 'warning' ? '降级' : '异常'}
                </span>
              </li>
            ))}
          </ul>}
        </Card>
      </div>
    </div>
  )
}

function RankCard({ title, items, unit, color, emptyText, onClick }: {
  title: string; items: { label: string; value: number }[]; unit: string; color: string; emptyText?: string; onClick?: (label: string) => void
}) {
  const max = Math.max(...items.map((i) => i.value), 1)
  return (
    <Card title={title}>
      {items.length === 0 ? <p className="py-6 text-center text-[11px] leading-5 text-stone-400">{emptyText ?? '暂无数据'}</p> : <ul className="space-y-2.5">
        {items.map((it, i) => (
          <li key={it.label} className="cursor-pointer" onClick={() => onClick?.(it.label)} title={it.label}>
            <div className="mb-1 flex items-baseline gap-2 text-xs">
              <span className="w-4 shrink-0 text-stone-300 tabular-nums">{i + 1}</span>
              <span className="min-w-0 flex-1 truncate font-mono text-stone-600 hover:text-cyan-700">{it.label}</span>
              <span className="shrink-0 tabular-nums text-stone-500">{it.value} {unit}</span>
            </div>
            <div className="ml-6 h-1.5 rounded-full bg-stone-100">
              <div className="h-1.5 rounded-full transition-all duration-500" style={{ width: `${(it.value / max) * 100}%`, background: color, opacity: 1 - i * 0.12 }} />
            </div>
          </li>
        ))}
      </ul>}
    </Card>
  )
}
