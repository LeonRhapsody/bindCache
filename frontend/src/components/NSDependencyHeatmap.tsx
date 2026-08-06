import { useMemo, useState } from 'react'
import { ChevronLeft, ChevronRight, Network, Search } from 'lucide-react'
import { ResponsiveContainer, Treemap } from 'recharts'
import { api } from '@/api/client'
import { useApiResource } from '@/api/useApiResource'
import type { NSDependencyHost, NSDependencyResponse } from '@/domain/risk'
import { classifyNSProvider, normalizeNSOwner } from '@/domain/nsProvider'

type GroupMode = 'provider' | 'country' | 'asn'

interface DependencyTileProps {
  x?: number
  y?: number
  width?: number
  height?: number
  name?: string
  hosts?: Map<string, NSDependencyHost>
  maxZones?: number
  mode?: GroupMode
  selectedHost?: string
  onSelect?: (host: string) => void
}

function category(host: NSDependencyHost, mode: GroupMode) {
  if (mode === 'provider') return classifyNSProvider(host.owner)?.label ?? (normalizeNSOwner(host.owner) || '未知归属')
  if (mode === 'country') return host.countries.length > 0 ? host.countries.join(' / ') : '地区未知'
  return host.asn_organizations[0] || host.asns[0] || 'ASN未知'
}

function categoryColor(value: string) {
  let hash = 2166136261
  for (let index = 0; index < value.length; index++) {
    hash ^= value.charCodeAt(index)
    hash = Math.imul(hash, 16777619)
  }
  return `hsl(${Math.abs(hash) % 360} 62% 43%)`
}

function DependencyTile({ x = 0, y = 0, width = 0, height = 0, name = '', hosts, maxZones = 1, mode = 'provider', selectedHost, onSelect }: DependencyTileProps) {
  const host = hosts?.get(name)
  if (!host || width < 1 || height < 1) return null
  const group = category(host, mode)
  const intensity = 0.32 + 0.68 * Math.log2(host.zone_count + 1) / Math.max(1, Math.log2(maxZones + 1))
  const selected = selectedHost === host.host
  return <g role="button" tabIndex={0} aria-label={`${host.host} 负责 ${host.zone_count} 个 zone，${group}`} onClick={() => onSelect?.(host.host)} onKeyDown={(event) => { if (event.key === 'Enter') onSelect?.(host.host) }} className="cursor-pointer outline-none">
    <rect x={x + 1} y={y + 1} width={Math.max(0, width - 2)} height={Math.max(0, height - 2)} rx={3} fill={categoryColor(group)} fillOpacity={intensity} stroke={selected ? '#0f172a' : '#ffffff'} strokeWidth={selected ? 2.5 : 1}/>
    {width > 58 && height > 28 && <text x={x + 6} y={y + 15} fill="#fff" fontSize={10} fontWeight={600}>{host.host.length > Math.floor(width / 6.5) ? `${host.host.slice(0, Math.max(5, Math.floor(width / 6.5) - 1))}…` : host.host}</text>}
    {width > 45 && height > 44 && <text x={x + 6} y={y + 31} fill="#fff" fillOpacity={0.88} fontSize={9}>{host.zone_count.toLocaleString()} zones</text>}
  </g>
}

function Values({ values, empty = '未知' }: { values: string[]; empty?: string }) {
  return <div className="flex flex-wrap gap-1">{values.length > 0 ? values.map((value) => <code key={value} className="rounded bg-stone-100 px-1.5 py-0.5 text-[10px] text-stone-600">{value}</code>) : <span className="text-[10px] text-stone-400">{empty}</span>}</div>
}

export function NSDependencyHeatmap() {
  const [mode, setMode] = useState<GroupMode>('provider')
  const [selectedHost, setSelectedHost] = useState('')
  const [draftQuery, setDraftQuery] = useState('')
  const [query, setQuery] = useState('')
  const [page, setPage] = useState(1)
  const resource = useApiResource<NSDependencyResponse>(
    (signal) => api.nsDependencies({ host: selectedHost, q: query, page, limit: 100, nodeLimit: 260 }, signal),
    [selectedHost, query, page],
  )
  const data = resource.data
  const hosts = useMemo(() => data?.hosts ?? [], [data?.hosts])
  const hostsByName = useMemo(() => new Map(hosts.map((host) => [host.host, host])), [hosts])
  const maxZones = hosts[0]?.zone_count ?? 1
  const treeData = useMemo(() => hosts.map((host) => ({ name: host.host, size: host.zone_count })), [hosts])
  const categoryTotals = useMemo(() => {
    const totals = new Map<string, number>()
    for (const host of hosts) totals.set(category(host, mode), (totals.get(category(host, mode)) ?? 0) + host.zone_count)
    return [...totals].sort((left, right) => right[1] - left[1]).slice(0, 10)
  }, [hosts, mode])
  const selected = data?.selected_host
  const maxPage = Math.max(1, Math.ceil((data?.total_affected ?? 0) / (data?.limit ?? 100)))

  function selectHost(host: string) {
    setSelectedHost(host)
    setPage(1)
  }

  if (resource.loading && !data) return <div className="rounded-lg border border-stone-200 bg-white py-20 text-center text-sm text-stone-400">正在构建NS依赖路径…</div>
  if (resource.error && !data) return <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700">NS依赖路径读取失败：{resource.error.message}</div>
  if (!data) return null

  return <div className="space-y-4">
    <div className="flex flex-wrap items-center gap-3 rounded-lg border border-stone-200 bg-white p-3">
      <div className="min-w-[320px] flex-1"><div className="flex items-center gap-2 text-xs font-medium text-stone-700"><Network size={14} className="text-cyan-700"/>域名依赖NS路径</div><p className="mt-1 text-[11px] text-stone-500">每个矩形代表一个NS主机，面积和颜色强度均反映其负责的不同zone数量；点击后查看完整依赖路径和可能受影响zone。</p></div>
      <label className="relative min-w-[260px]"><Search size={13} className="absolute left-2.5 top-2.5 text-stone-400"/><input value={draftQuery} onChange={(event) => setDraftQuery(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') { setQuery(draftQuery.trim()); setSelectedHost(''); setPage(1) } }} placeholder="搜索NS、IP、ASN、国家或zone" className="h-8 w-full rounded-md border border-stone-200 pl-8 pr-2 text-[11px] outline-none focus:border-cyan-500"/></label>
      <button onClick={() => { setQuery(draftQuery.trim()); setSelectedHost(''); setPage(1) }} className="h-8 rounded-md border border-stone-200 px-3 text-[11px] text-stone-600 hover:bg-stone-50">搜索</button>
      <div className="inline-flex rounded-md border border-stone-200 p-0.5">{([['provider', '服务商'], ['country', '基础设施地区'], ['asn', 'ASN']] as const).map(([value, label]) => <button key={value} onClick={() => setMode(value)} className={`rounded px-2.5 py-1 text-[11px] ${mode === value ? 'bg-cyan-700 text-white' : 'text-stone-500 hover:bg-stone-50'}`}>{label}</button>)}</div>
    </div>

    <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
      {[['观测zone', data.total_zones], ['NS主机', data.total_hosts], ['NS主域', data.total_owners], ['基础设施国家/地区', data.total_countries]].map(([label, value]) => <div key={label} className="rounded-lg border border-stone-200 bg-white p-3"><div className="text-[10px] text-stone-400">{label}</div><div className="mt-1 text-xl font-semibold tabular-nums text-stone-800">{Number(value).toLocaleString()}</div></div>)}
    </div>

    <section className="rounded-lg border border-stone-200 bg-white p-4 shadow-sm">
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3"><div><h3 className="text-xs font-semibold text-stone-700">NS节点zone覆盖热力图</h3><p className="mt-1 text-[10px] text-stone-400">当前展示覆盖量最高或搜索命中的 {hosts.length} 个NS主机。分组颜色用于识别归属，不能替代可用性拨测。</p></div><div className="flex max-w-[720px] flex-wrap justify-end gap-x-3 gap-y-1 text-[9px] text-stone-500">{categoryTotals.map(([label, total]) => <span key={label} className="inline-flex items-center gap-1"><i className="h-2 w-2 rounded-sm" style={{ backgroundColor: categoryColor(label) }}/>{label} · {total.toLocaleString()} 条依赖</span>)}</div></div>
      <div className="h-[520px] overflow-hidden rounded-md border border-stone-100 bg-stone-50">
        <ResponsiveContainer>
          <Treemap data={treeData} dataKey="size" nameKey="name" isAnimationActive={false} content={<DependencyTile hosts={hostsByName} maxZones={maxZones} mode={mode} selectedHost={selectedHost} onSelect={selectHost}/>}/>
        </ResponsiveContainer>
      </div>
    </section>

    {selected ? <section className="rounded-lg border border-cyan-200 bg-white shadow-sm">
      <div className="border-b border-stone-100 p-4"><div className="flex flex-wrap items-start justify-between gap-3"><div><div className="text-[10px] text-stone-400">选中NS主机</div><code className="mt-1 block text-sm font-semibold text-stone-800">{selected.host}</code><div className="mt-1 text-[10px] text-stone-500">{classifyNSProvider(selected.owner)?.label ?? normalizeNSOwner(selected.owner)} → {selected.owner} → {selected.host}</div></div><div className="flex gap-5 text-right"><div><div className="text-2xl font-semibold tabular-nums text-cyan-800">{data.total_affected.toLocaleString()}</div><div className="text-[10px] text-stone-400">存在该NS依赖</div></div><div><div className="text-2xl font-semibold tabular-nums text-red-700">{data.sole_dependency.toLocaleString()}</div><div className="text-[10px] text-stone-400">快照中仅观测到该NS</div></div><div><div className="text-2xl font-semibold tabular-nums text-emerald-700">{data.with_alternatives.toLocaleString()}</div><div className="text-[10px] text-stone-400">仍观测到其他NS</div></div></div></div>
        <div className="mt-4 grid gap-3 text-[10px] md:grid-cols-3"><div><div className="mb-1 text-stone-400">IP地址</div><Values values={selected.addresses}/></div><div><div className="mb-1 text-stone-400">ASN / 组织</div><Values values={[...selected.asns, ...selected.asn_organizations]}/></div><div><div className="mb-1 text-stone-400">NS基础设施所在国家/地区</div><Values values={selected.countries}/><p className="mt-1 text-[9px] text-amber-700">不是用户影响地域；用户地域需要多地域递归观测。</p></div></div>
      </div>
      <div className="max-h-72 overflow-auto p-3"><div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2 lg:grid-cols-4">{data.affected_zones.map((zone) => <code key={zone} className="truncate rounded bg-stone-50 px-2 py-1.5 text-[10px] text-stone-600" title={zone}>{zone}</code>)}</div></div>
      <div className="flex items-center justify-between border-t border-stone-100 px-4 py-2 text-[10px] text-stone-400"><span>依赖路径：zone → 服务商/NS主域 → NS主机 → IP → ASN/国家</span><span className="flex items-center gap-2"><button disabled={page <= 1} onClick={() => setPage((value) => value - 1)} className="rounded border border-stone-200 p-1 disabled:opacity-30"><ChevronLeft size={13}/></button>第 {page} / {maxPage} 页<button disabled={page >= maxPage} onClick={() => setPage((value) => value + 1)} className="rounded border border-stone-200 p-1 disabled:opacity-30"><ChevronRight size={13}/></button></span></div>
    </section> : <div className="rounded-lg border border-dashed border-stone-300 bg-stone-50 py-8 text-center text-xs text-stone-400">点击任意NS节点，查看该节点的基础设施路径和可能受影响zone。</div>}
  </div>
}
