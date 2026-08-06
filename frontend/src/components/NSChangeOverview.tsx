import { useMemo, useState } from 'react'
import { ChevronLeft, ChevronRight, Database, Search, TrendingDown, TrendingUp } from 'lucide-react'
import { CartesianGrid, Legend, Line, LineChart, ReferenceArea, ReferenceLine, ResponsiveContainer, Scatter, ScatterChart, Tooltip, XAxis, YAxis, ZAxis } from 'recharts'
import { api } from '@/api/client'
import { useApiResource } from '@/api/useApiResource'
import type { NSChangeOverviewItem, NSChangeOverviewPoint, NSChangeOverviewResponse } from '@/domain/risk'

const TYPE_LABEL = { modified: 'NS 修改', added: '新增观测', removed: '不再观测' } as const
const TYPE_STYLE = {
  modified: 'border-amber-200 bg-amber-50 text-amber-700',
  added: 'border-emerald-200 bg-emerald-50 text-emerald-700',
  removed: 'border-red-200 bg-red-50 text-red-700',
} as const

function formatTime(value: string, withDate = false) {
  const date = new Date(value)
  return withDate ? date.toLocaleString() : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function delta(current: number, previous?: number) {
  if (previous === undefined) return undefined
  if (previous === 0) return current === 0 ? 0 : undefined
  return (current - previous) / previous
}

function percentile(values: number[], ratio: number) {
  if (values.length === 0) return 0
  const sorted = [...values].sort((left, right) => left - right)
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.round((sorted.length - 1) * ratio)))]
}

function MetricCard({ label, value, tone, sub, change }: { label: string; value: number; tone: string; sub: string; change?: number }) {
  return <div className="relative overflow-hidden rounded-lg border border-stone-200 bg-white p-4 shadow-sm">
    <span className={`absolute inset-y-0 left-0 w-1 ${tone}`}/>
    <div className="text-[11px] font-medium text-stone-500">{label}</div>
    <div className="mt-2 text-2xl font-semibold tabular-nums text-stone-800">{value.toLocaleString()}</div>
    <div className="mt-2 flex items-center gap-1 text-[10px] text-stone-400">{change === undefined ? sub : <>{change >= 0 ? <TrendingUp size={11}/> : <TrendingDown size={11}/>}较上轮 {change >= 0 ? '+' : ''}{(change * 100).toFixed(1)}%</>}</div>
  </div>
}

function HostDiff({ item }: { item: NSChangeOverviewItem }) {
  return <div className="space-y-1 font-mono text-[10px] leading-5">
    {item.previous_hosts.length > 0 && <div className="text-red-600"><span className="mr-1 select-none">−</span>{item.previous_hosts.join(', ')}</div>}
    {item.current_hosts.length > 0 && <div className="text-emerald-700"><span className="mr-1 select-none">＋</span>{item.current_hosts.join(', ')}</div>}
    {(item.previous_owners.length > 0 || item.current_owners.length > 0) && <div className="text-stone-400">归属：{item.previous_owners.join(', ') || '无'} → {item.current_owners.join(', ') || '无'}</div>}
  </div>
}

type ChartSelection = { activePayload?: Array<{ payload?: NSChangeOverviewPoint }> }

export function NSChangeOverview() {
  const [snapshotID, setSnapshotID] = useState('')
  const [type, setType] = useState('all')
  const [draftQuery, setDraftQuery] = useState('')
  const [query, setQuery] = useState('')
  const [page, setPage] = useState(1)
  const [trendLimit, setTrendLimit] = useState(48)
  const resource = useApiResource<NSChangeOverviewResponse>(
    (signal) => api.nsChangeOverview({ snapshotID, type, q: query, page, limit: 100, trendLimit }, signal),
    [snapshotID, type, query, page, trendLimit],
  )
  const data = resource.data
  const points = useMemo(() => data?.points ?? [], [data?.points])
  const selected = data?.selected
  const chartData = useMemo(() => [...points].reverse().map((point) => ({
    ...point,
    time: formatTime(point.captured_at),
    churn_rate: point.unchanged + point.changed > 0 ? (point.added + point.removed) / (point.unchanged + point.changed) : 0,
  })), [points])
  const control = useMemo(() => {
    const changed = points.map((point) => point.changed)
    const median = percentile(changed, 0.5)
    const deviations = changed.map((value) => Math.abs(value - median))
    const robustSigma = percentile(deviations, 0.5) * 1.4826
    return { median, lower: Math.max(0, median - robustSigma * 3), upper: median + robustSigma * 3, p95: percentile(changed, 0.95) }
  }, [points])
  const selectedIndex = selected ? points.findIndex((point) => point.snapshot_id === selected.snapshot_id) : -1
  const previousWindow = selectedIndex >= 0 ? points[selectedIndex + 1] : undefined
  const maxPage = Math.max(1, Math.ceil((data?.total_changes ?? 0) / (data?.limit ?? 100)))

  function selectSnapshot(id: string) {
    setSnapshotID(id)
    setPage(1)
  }

  function selectChartPoint(state: unknown) {
    const point = (state as ChartSelection | undefined)?.activePayload?.[0]?.payload
    if (point?.snapshot_id) selectSnapshot(point.snapshot_id)
  }

  if (resource.loading && !data) return <div className="rounded-lg border border-stone-200 bg-white py-20 text-center text-sm text-stone-400">正在计算相邻快照变更趋势…</div>
  if (resource.error && !data) return <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700">更新总览读取失败：{resource.error.message}</div>
  if (!selected) return <div className="rounded-lg border border-stone-200 bg-white py-20 text-center text-sm text-stone-400">至少需要两个同视图快照才能计算变更趋势</div>

  return <div className="space-y-4">
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-stone-200 bg-white p-3">
      <div><div className="flex items-center gap-2 text-xs font-medium text-stone-700"><Database size={14} className="text-cyan-700"/>相邻快照 NS 记录 Diff</div><p className="mt-1 text-[11px] text-stone-500">每个 zone 每轮只计一次；新增/不再观测反映递归缓存可见性，不直接等同于权威委派新增或删除。</p></div>
      <div className="flex flex-wrap items-center gap-3"><label className="text-[11px] text-stone-500">趋势窗口 <select value={trendLimit} onChange={(event) => { setTrendLimit(Number(event.target.value)); setSnapshotID(''); setPage(1) }} className="ml-2 h-8 rounded-md border border-stone-200 bg-white px-2 text-[11px] text-stone-700"><option value={24}>24 次</option><option value={48}>48 次</option><option value={100}>100 次</option></select></label><label className="text-[11px] text-stone-500">当前窗口 <select value={selected.snapshot_id} onChange={(event) => selectSnapshot(event.target.value)} className="ml-2 h-8 max-w-[390px] rounded-md border border-stone-200 bg-white px-2 font-mono text-[11px] text-stone-700">{points.map((point) => <option key={point.snapshot_id} value={point.snapshot_id}>{formatTime(point.captured_at, true)} · {point.snapshot_id}</option>)}</select></label></div>
    </div>

    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <MetricCard label="本轮观测 zone" value={selected.total_zones} tone="bg-violet-500" sub={`未变化 ${selected.unchanged.toLocaleString()}（${selected.total_zones > 0 ? (selected.unchanged * 100 / selected.total_zones).toFixed(2) : '0.00'}%）`}/>
      <MetricCard label="NS 修改" value={selected.modified} tone="bg-amber-500" sub="前后快照均存在，NS 主机集合不同" change={delta(selected.modified, previousWindow?.modified)}/>
      <MetricCard label="新增观测" value={selected.added} tone="bg-emerald-500" sub="当前快照出现、前一快照未出现" change={delta(selected.added, previousWindow?.added)}/>
      <MetricCard label="不再观测" value={selected.removed} tone="bg-red-500" sub="前一快照出现、当前快照未出现" change={delta(selected.removed, previousWindow?.removed)}/>
    </div>

    <section className="grid gap-4 xl:grid-cols-5">
      <div className="rounded-lg border border-stone-200 bg-white p-4 shadow-sm xl:col-span-3">
        <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2"><div><h3 className="text-xs font-semibold text-stone-700">变更控制图（最近 {points.length} 次更新）</h3><p className="mt-1 text-[10px] text-stone-400">阴影为历史中位数±3×MAD稳健波动带；超过上界表示相对近期模式异常放大，不直接代表风险确认。</p></div><div className="text-[10px] text-stone-500">中位数 {Math.round(control.median).toLocaleString()} · P95 {Math.round(control.p95).toLocaleString()} · 上界 {Math.round(control.upper).toLocaleString()}</div></div>
        <div className="h-72"><ResponsiveContainer><LineChart data={chartData} margin={{ top: 8, right: 12, left: 0, bottom: 4 }} onClick={selectChartPoint}>
          <CartesianGrid stroke="#e7e5e4" strokeDasharray="3 3" vertical={false}/><XAxis dataKey="time" tick={{ fontSize: 10, fill: '#78716c' }} interval="preserveStartEnd" minTickGap={28}/><YAxis tick={{ fontSize: 10, fill: '#78716c' }} allowDecimals={false} width={44}/>
          <ReferenceArea y1={control.lower} y2={control.upper} fill="#cffafe" fillOpacity={0.55}/><ReferenceLine y={control.median} stroke="#0891b2" strokeDasharray="4 4"/><ReferenceLine y={control.upper} stroke="#e11d48" strokeDasharray="4 4"/>
          <Tooltip labelFormatter={(_, payload) => payload?.[0]?.payload?.captured_at ? formatTime(payload[0].payload.captured_at, true) : ''} contentStyle={{ border: '1px solid #e7e5e4', borderRadius: 8, fontSize: 11 }}/><Legend wrapperStyle={{ fontSize: 10 }}/>
          <Line type="monotone" dataKey="changed" name="不同zone总变化" stroke="#0e7490" strokeWidth={2.5} dot={{ r: 2 }} activeDot={{ r: 5 }} isAnimationActive={false}/><Line type="monotone" dataKey="modified" name="NS修改" stroke="#d97706" strokeWidth={1.2} dot={false} isAnimationActive={false}/><Line type="monotone" dataKey="added" name="新增观测" stroke="#059669" strokeWidth={1.2} dot={false} isAnimationActive={false}/><Line type="monotone" dataKey="removed" name="不再观测" stroke="#dc2626" strokeWidth={1.2} dot={false} isAnimationActive={false}/>
        </LineChart></ResponsiveContainer></div>
      </div>
      <div className="rounded-lg border border-stone-200 bg-white p-4 shadow-sm xl:col-span-2">
        <div className="mb-3"><h3 className="text-xs font-semibold text-stone-700">快照质量散点图</h3><p className="mt-1 text-[10px] text-stone-400">横轴为本轮观测zone数，纵轴为缓存新增+移除占比；左上方点通常需要优先检查dump覆盖和采集质量。</p></div>
        <div className="h-72"><ResponsiveContainer><ScatterChart margin={{ top: 8, right: 12, left: 4, bottom: 8 }} onClick={selectChartPoint}>
          <CartesianGrid stroke="#e7e5e4" strokeDasharray="3 3"/><XAxis type="number" dataKey="total_zones" name="观测zone" tick={{ fontSize: 9, fill: '#78716c' }} domain={['auto', 'auto']}/><YAxis type="number" dataKey="churn_rate" name="缓存可见性变动率" tick={{ fontSize: 9, fill: '#78716c' }} tickFormatter={(value) => `${(Number(value) * 100).toFixed(0)}%`} width={42}/><ZAxis range={[48, 48]}/>
          <Tooltip cursor={{ strokeDasharray: '3 3' }} formatter={(value, name) => [name === '缓存可见性变动率' ? `${(Number(value) * 100).toFixed(2)}%` : Number(value).toLocaleString(), name]} labelFormatter={(_, payload) => payload?.[0]?.payload?.captured_at ? formatTime(payload[0].payload.captured_at, true) : ''} contentStyle={{ border: '1px solid #e7e5e4', borderRadius: 8, fontSize: 11 }}/><Scatter data={chartData} name="更新窗口" fill="#7c3aed" isAnimationActive={false}/>
        </ScatterChart></ResponsiveContainer></div>
      </div>
    </section>

    <section className="rounded-lg border border-stone-200 bg-white shadow-sm">
      <div className="flex flex-wrap items-center gap-2 border-b border-stone-100 p-3">
        <div className="mr-auto"><h3 className="text-xs font-semibold text-stone-700">{formatTime(selected.captured_at, true)} 窗口变更明细</h3><p className="mt-1 font-mono text-[9px] text-stone-400">{selected.previous_snapshot_id} → {selected.snapshot_id}</p></div>
        <label className="relative min-w-[240px]"><Search size={13} className="absolute left-2.5 top-2.5 text-stone-400"/><input value={draftQuery} onChange={(event) => setDraftQuery(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') { setQuery(draftQuery.trim()); setPage(1) } }} placeholder="搜索 zone、NS 主域或 NS 主机" className="h-8 w-full rounded-md border border-stone-200 pl-8 pr-2 text-[11px] outline-none focus:border-cyan-500"/></label>
        <button onClick={() => { setQuery(draftQuery.trim()); setPage(1) }} className="h-8 rounded-md border border-stone-200 px-3 text-[11px] text-stone-600 hover:bg-stone-50">搜索</button>
        <div className="inline-flex rounded-md border border-stone-200 p-0.5">{(['all', 'modified', 'added', 'removed'] as const).map((value) => <button key={value} onClick={() => { setType(value); setPage(1) }} className={`rounded px-2.5 py-1 text-[11px] ${type === value ? 'bg-cyan-700 text-white' : 'text-stone-500 hover:bg-stone-50'}`}>{value === 'all' ? `全部（${selected.changed}）` : TYPE_LABEL[value]}</button>)}</div>
      </div>
      <div className="max-h-[560px] overflow-auto">
        <table className="w-full min-w-[820px] text-left"><thead className="sticky top-0 z-10 bg-stone-50 text-[10px] text-stone-500"><tr><th className="px-4 py-2.5">zone</th><th className="w-28 px-3 py-2.5">类型</th><th className="px-3 py-2.5">相邻快照 NS 差异（Old → New）</th></tr></thead>
          <tbody>{data.changes.map((item) => <tr key={item.zone} className="border-t border-stone-100 align-top"><td className="px-4 py-3"><code className="text-[11px] font-semibold text-stone-700">{item.zone}</code></td><td className="px-3 py-3"><span className={`inline-flex rounded border px-2 py-0.5 text-[10px] font-medium ${TYPE_STYLE[item.type]}`}>{TYPE_LABEL[item.type]}</span></td><td className="px-3 py-3"><HostDiff item={item}/></td></tr>)}</tbody>
        </table>
        {data.changes.length === 0 && <div className="py-14 text-center text-sm text-stone-400">当前筛选条件下没有变更 zone</div>}
      </div>
      <div className="flex items-center justify-between border-t border-stone-100 px-4 py-2 text-[10px] text-stone-400"><span>共 {data.total_changes.toLocaleString()} 个不同 zone</span><span className="flex items-center gap-2"><button disabled={page <= 1} onClick={() => setPage((value) => value - 1)} className="rounded border border-stone-200 p-1 disabled:opacity-30"><ChevronLeft size={13}/></button>第 {page} / {maxPage} 页<button disabled={page >= maxPage} onClick={() => setPage((value) => value + 1)} className="rounded border border-stone-200 p-1 disabled:opacity-30"><ChevronRight size={13}/></button></span></div>
    </section>
  </div>
}
