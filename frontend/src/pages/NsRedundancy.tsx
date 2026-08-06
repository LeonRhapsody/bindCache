import { useState } from 'react'
import { Card, LevelBadge, StatusBadge, EmptyState, StateBanner } from '@/components/kit'
import { fmtDuration } from '@/domain/risk'
import type { RiskEvent, NsRecord } from '@/domain/risk'
import { useRiskEvents } from '@/api/useRiskEvents'
import { useHashRoute } from '@/lib/router'
import { EventFilterBar, useEventFilters } from './Events'
import { cn } from '@/lib/utils'

const CATEGORIES = [
  { label: '仅一个 NS 主机名', risk: 'low', desc: '物理单点' },
  { label: '多 NS 指向同一 IP', risk: 'medium', desc: '逻辑单点' },
  { label: '多 NS 同一网段', risk: 'medium', desc: '逻辑单点' },
  { label: '同一 CNAME/设施承载', risk: 'medium', desc: '逻辑单点' },
  { label: 'NS 数量多降为一', risk: 'high', desc: '冗余退化' },
  { label: '唯一 NS 不可达/异常', risk: 'critical', desc: '服务中断风险' },
] as const

const RISK_TONE: Record<string, string> = {
  low: 'border-sky-200 bg-sky-50/50 text-sky-800',
  medium: 'border-amber-200 bg-amber-50/50 text-amber-800',
  high: 'border-orange-200 bg-orange-50/50 text-orange-800',
  critical: 'border-red-200 bg-red-50/50 text-red-800',
}

// ---------- NS 逻辑拓扑图 ----------
interface TNode { id: string; label: string; sub?: string; bad?: boolean }
interface Layer { name: string; nodes: TNode[] }

function endpointNetwork(ip: string): string {
  if (ip.includes(':')) {
    const parts = ip.split(':').filter(Boolean).slice(0, 3)
    return `${parts.join(':')}::/48`
  }
  return `${ip.split('.').slice(0, 3).join('.')}.0/24`
}

function buildLayers(domain: string, records: NsRecord[]): Layer[] {
	const resolved = records.filter((record) => record.ips.length > 0)
  const layers: Layer[] = [
    { name: '域名', nodes: [{ id: 'd', label: domain }] },
    { name: 'NS 主机名', nodes: records.map((r) => ({ id: `h:${r.host}`, label: r.host, bad: r.reachable === false })) },
    { name: 'IP', nodes: [...new Set(records.flatMap((r) => r.ips))].map((ip) => ({ id: `ip:${ip}`, label: ip, bad: records.some((r) => r.ips.includes(ip) && r.reachable === false) })) },
	{ name: '网段', nodes: [...new Set(resolved.flatMap((r) => r.ips.map(endpointNetwork)))].map((s) => ({ id: `s:${s}`, label: s })) },
	{ name: 'ASN', nodes: [...new Set(resolved.map((r) => `${r.asn} ${r.asnOrg}`))].map((a) => ({ id: `a:${a}`, label: a })) },
	{ name: '国家/地区', nodes: [...new Set(resolved.map((r) => r.country))].map((c) => ({ id: `c:${c}`, label: c })) },
  ]
  return layers
}

function edges(records: NsRecord[]): [string, string][] {
  const out: [string, string][] = []
  for (const r of records) {
    out.push(['d', `h:${r.host}`])
    for (const ip of r.ips) {
      out.push([`h:${r.host}`, `ip:${ip}`])
		out.push([`ip:${ip}`, `s:${endpointNetwork(ip)}`])
    }
	for (const ip of r.ips) out.push([`s:${endpointNetwork(ip)}`, `a:${r.asn} ${r.asnOrg}`])
	if (r.ips.length > 0) out.push([`a:${r.asn} ${r.asnOrg}`, `c:${r.country}`])
  }
  return [...new Set(out.map((e) => e.join('|')))].map((s) => s.split('|') as [string, string])
}

function NsTopology({ domain, records }: { domain: string; records: NsRecord[] }) {
  const layers = buildLayers(domain, records)
  const es = edges(records)
  const colW = 156
  const nodeH = 34
  const gapY = 14
  const maxRows = Math.max(...layers.map((l) => l.nodes.length))
  const height = maxRows * (nodeH + gapY) + 34
  const pos = new Map<string, { x: number; y: number; w: number }>()
  layers.forEach((l, li) => {
    const totalH = l.nodes.length * (nodeH + gapY) - gapY
    const offsetY = (height - totalH) / 2 + 8
    l.nodes.forEach((n, ni) => {
      pos.set(n.id, { x: li * colW + 8, y: offsetY + ni * (nodeH + gapY), w: colW - 24 })
    })
  })
  const convergeIds = new Set(layers.slice(2).flatMap((l) => l.nodes.length === 1 ? l.nodes.map((n) => n.id) : []))

  return (
    <div className="overflow-x-auto">
      <svg width={layers.length * colW} height={height} className="min-w-[860px]">
        {layers.map((l, li) => (
          <text key={l.name} x={li * colW + 8} y={14} fontSize={10} fill="#a8a29e">{l.name}</text>
        ))}
        {es.map(([a, b], i) => {
          const pa = pos.get(a)!; const pb = pos.get(b)!
          if (!pa || !pb) return null
          const x1 = pa.x + pa.w; const y1 = pa.y + nodeH / 2
          const x2 = pb.x; const y2 = pb.y + nodeH / 2
          const mx = (x1 + x2) / 2
          return <path key={i} d={`M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`} fill="none" stroke={convergeIds.has(b) ? '#f87171' : '#d6d3d1'} strokeWidth={1.2} />
        })}
        {layers.flatMap((l) => l.nodes.map((n) => {
          const p = pos.get(n.id)!
          const converge = convergeIds.has(n.id)
          return (
            <g key={n.id}>
              <rect x={p.x} y={p.y} width={p.w} height={nodeH} rx={6}
                fill={n.bad ? '#fef2f2' : converge ? '#fff7ed' : '#ffffff'}
                stroke={n.bad ? '#dc2626' : converge ? '#fb923c' : '#d6d3d1'} strokeWidth={n.bad || converge ? 1.4 : 1} />
              <text x={p.x + 8} y={p.y + nodeH / 2 + 1} fontSize={10.5} fill="#44403c" fontFamily="ui-monospace, monospace"
                dominantBaseline="middle" style={{ whiteSpace: 'nowrap' }}>
                {n.label.length > 26 ? n.label.slice(0, 25) + '…' : n.label}
              </text>
              {n.bad && <text x={p.x + p.w - 6} y={p.y + nodeH / 2} fontSize={9} fill="#dc2626" textAnchor="end" dominantBaseline="middle">不可达</text>}
              {converge && !n.bad && <text x={p.x + p.w - 6} y={p.y + nodeH / 2} fontSize={9} fill="#ea580c" textAnchor="end" dominantBaseline="middle">汇聚</text>}
            </g>
          )
        }))}
      </svg>
    </div>
  )
}

// ---------- 页面 ----------
export default function NsRedundancyPage() {
  const [route, navigate] = useHashRoute()
  const f = useEventFilters(route.query)
  const resource = useRiskEvents('ns_single', f)
  const base = resource.data?.items ?? []
  const filtered = base
  const [selected, setSelected] = useState('EVT-20260730-003')
  const sel: RiskEvent | undefined = base.find((e) => e.id === selected) ?? filtered[0]

  return (
    <div className="mx-auto max-w-[1440px] space-y-4">
      <div>
        <h2 className="text-base font-semibold text-stone-800">NS 单一与冗余风险</h2>
        <p className="mt-0.5 text-xs text-stone-400">识别仅一个 NS、多个 NS 同 IP/同网段等明确单点，以及冗余退化与唯一 NS 不可用；同 ASN 或同国家不单独判定为单点。</p>
      </div>

      {/* 检测分类 */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {CATEGORIES.map((c) => (
          <div key={c.label} className={cn('rounded-md border px-3 py-2 text-xs', RISK_TONE[c.risk])}>
            <div className="font-medium">{c.label}</div>
            <div className="mt-0.5 text-[10px] opacity-70">{c.desc}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        {/* 事件列表 */}
        <Card pad={false} title="风险事件" className="xl:col-span-1">
          <div className="border-b border-stone-100 px-3 py-2.5"><EventFilterBar showType={false} /></div>
          {resource.loading && !resource.data ? <StateBanner kind="loading" /> : resource.error ? <StateBanner kind="query_failed" /> : filtered.length === 0 ? <EmptyState desc="当前筛选条件下没有单一/冗余风险事件。" /> : (
            <ul className="divide-y divide-stone-50">
              {filtered.sort((a, b) => (a.lastSeen < b.lastSeen ? 1 : -1)).map((e) => (
                <li key={e.id}
                  onClick={() => setSelected(e.id)}
                  className={cn('cursor-pointer px-3 py-2.5 hover:bg-stone-50', selected === e.id && 'border-l-2 border-cyan-600 bg-cyan-50/40')}>
                  <div className="flex items-center gap-2">
                    <LevelBadge level={e.level} />
                    <button className="truncate font-mono text-xs text-cyan-800 hover:underline"
                      onClick={(ev) => { ev.stopPropagation(); navigate(`/event/${e.id}`) }}>{e.domain}</button>
                  </div>
                  <div className="mt-1 line-clamp-2 text-[11px] leading-4 text-stone-400">{e.summary}</div>
                  <div className="mt-1 flex items-center gap-2">
                    <StatusBadge status={e.status} />
                    <span className="text-[10px] text-stone-400">持续 {fmtDuration(e.durationMin)}</span>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>

        {/* 拓扑与事实 */}
        {sel && (
          <div className="space-y-4 xl:col-span-2">
            <Card title={<span>NS 逻辑拓扑 — <span className="font-mono font-normal">{sel.domain}</span></span>}
              extra={<span className="text-[10px] text-stone-400">红色为不可达 · 橙色为收敛汇聚点（单点）</span>}>
              <NsTopology domain={sel.domain} records={sel.currentNs} />
            </Card>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
              <Fact label="单点形成原因" value={String(sel.extra?.singleReason ?? '—')} wide />
              <Fact label="历史最大 NS 数量" value={String(sel.extra?.historyMaxNs ?? '—')} />
              <Fact label="持续时间" value={fmtDuration(sel.durationMin)} />
              <Fact label="观测次数" value={`${sel.observations} 次`} />
              <Fact label="受影响域名规模" value={`${sel.affectedCount} 个名称`} />
              <Fact label="最近可用性拨测" value={sel.probes.length ? (sel.probes[0].reachable ? `可达 ${sel.probes[0].rttMs}ms` : '超时不可达') : '暂无拨测数据'} />
            </div>
            {sel.probes.length > 0 && (
              <Card title="拨测明细">
                <table className="w-full text-xs">
                  <tbody>
                    {sel.probes.map((p, i) => (
                      <tr key={i} className="border-b border-stone-50 last:border-0">
                        <td className="py-1.5 pr-2 font-mono text-stone-600">{p.ns} ({p.ip})</td>
                        <td className="py-1.5 pr-2">{p.reachable ? <span className="text-emerald-600">可达 {p.rttMs}ms</span> : <span className="font-medium text-red-600">不可达</span>}</td>
                        <td className="py-1.5 text-stone-400">{p.detail}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Card>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function Fact({ label, value, wide }: { label: string; value: string; wide?: boolean }) {
  return (
    <div className={cn('rounded-md border border-stone-200 bg-white px-3 py-2', wide && 'col-span-2')}>
      <div className="text-[10px] text-stone-400">{label}</div>
      <div className="mt-0.5 text-xs font-medium text-stone-700">{value}</div>
    </div>
  )
}

// 供详情页复用
export { NsTopology }
