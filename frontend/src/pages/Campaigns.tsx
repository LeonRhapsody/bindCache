import { useState } from 'react'
import { Activity, ArrowRight, GitCompareArrows, Layers3, Network, Search, ShieldCheck, ShieldX } from 'lucide-react'
import { api } from '@/api/client'
import { useApiResource } from '@/api/useApiResource'
import { useSession } from '@/api/SessionContext'
import { NSOwnershipGraph } from '@/components/NSOwnershipGraph'
import { NSChangeOverview } from '@/components/NSChangeOverview'
import { NSDependencyHeatmap } from '@/components/NSDependencyHeatmap'
import type { CampaignChange, CampaignEvent, CampaignsResponse, NSOwnershipResponse } from '@/domain/risk'

const TYPE_LABEL: Record<CampaignEvent['type'], string> = {
  same_new_ns: 'NS 主域归属指向同一服务商',
  same_ns_ip: 'NS 解析同时指向同一 IP',
  same_a_ip: 'A 记录同时指向同一 IP',
}

function Values({ values, empty = '无' }: { values: string[]; empty?: string }) {
  return <div className="flex flex-wrap gap-1">{values.length > 0 ? values.map((value) => <code key={value} className="rounded bg-stone-100 px-1.5 py-0.5 text-[10px] text-stone-600">{value}</code>) : <span className="text-[10px] text-stone-400">{empty}</span>}</div>
}

function OwnershipView() {
  const [snapshotID, setSnapshotID] = useState('')
  const [owner, setOwner] = useState('')
  const [graphQuery, setGraphQuery] = useState('')
  const resource = useApiResource<NSOwnershipResponse>((signal) => api.nsOwnership(snapshotID, owner, graphQuery, signal), [snapshotID, owner, graphQuery])
  const data = resource.data
  return <div className="space-y-3">
    <div className="flex flex-wrap items-center gap-3 rounded-lg border border-stone-200 bg-white p-3">
      <div className="min-w-[260px] flex-1"><div className="text-xs font-medium text-stone-700">服务商聚合 + 相邻版本差异</div><p className="mt-1 text-[11px] text-stone-500">默认按可审计规则将 NS 主域聚合为 DNS 服务商，无法可靠识别的主域保持独立；可展开服务商查看原始 NS 主域，或切换为完整主域图。蓝线表示服务商内部 NS 调整，橙线表示 zone 在不同归属之间迁移。</p></div>
      <label className="text-[11px] text-stone-500">当前快照 <select value={data?.current.id ?? snapshotID} onChange={(event) => { setSnapshotID(event.target.value); setOwner(''); setGraphQuery('') }} className="ml-2 h-9 max-w-[360px] rounded-md border border-stone-200 bg-white px-2 font-mono text-xs text-stone-700">
        {(data?.snapshots ?? []).map((snapshot) => <option key={snapshot.id} value={snapshot.id}>{new Date(snapshot.captured_at).toLocaleString()} · {snapshot.id}</option>)}
      </select></label>
      {data?.previous && <div className="text-[10px] text-stone-400">对比：{new Date(data.previous.captured_at).toLocaleString()}</div>}
    </div>
    {resource.loading && !data ? <div className="py-20 text-center text-sm text-stone-400">正在构建 NS 归属图谱…</div> : resource.error ? <div className="rounded-md border border-red-200 bg-red-50 p-3 text-xs text-red-700">读取失败：{resource.error.message}</div> : data ? <NSOwnershipGraph data={data} onOwner={setOwner} onSearch={setGraphQuery}/> : null}
  </div>
}

function ChangeEvidence({ change }: { change: CampaignChange }) {
  return <tr className="border-t border-stone-100 align-top">
    <td className="px-3 py-2"><code className="text-[11px] font-semibold text-stone-700">{change.zone}</code>{(change.record_name || change.ns_host) && <div className="mt-1 font-mono text-[10px] text-stone-400">{change.record_name || change.ns_host}</div>}</td>
    <td className="px-3 py-2"><Values values={change.previous_values}/>{change.previous_owners.length > 0 && <div className="mt-1"><Values values={change.previous_owners}/></div>}</td>
    <td className="w-6 px-0 py-2 text-stone-300"><ArrowRight size={13}/></td>
    <td className="px-3 py-2"><Values values={change.current_values}/>{change.current_owners.length > 0 && <div className="mt-1"><Values values={change.current_owners}/></div>}</td>
  </tr>
}

function EventsView() {
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState('all')
  const [expanded, setExpanded] = useState('')
  const { session } = useSession()
  const resource = useApiResource<CampaignsResponse>((signal) => api.campaigns({ q: query, type: kind, limit: 200 }, signal), [query, kind])
  const items = resource.data?.items ?? []

  async function act(event: CampaignEvent, action: 'confirm' | 'ignore') {
    const reason = action === 'ignore' ? window.prompt('请输入忽略理由；确认后将解除这些 zone 的基线冻结：') : '人工确认批量协同变化'
    if (reason === null || (action === 'ignore' && !reason.trim())) return
    await api.campaignAction(event.id, action, reason)
    resource.retry()
  }

  return <div className="space-y-3">
    <div className="flex flex-wrap gap-2 rounded-lg border border-stone-200 bg-white p-3">
      <label className="relative min-w-[260px] flex-1"><Search size={14} className="absolute left-2.5 top-2.5 text-stone-400"/><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索目标、zone 或事件 ID" className="h-9 w-full rounded-md border border-stone-200 pl-8 pr-3 text-xs outline-none focus:border-cyan-500"/></label>
      <select value={kind} onChange={(event) => setKind(event.target.value)} className="h-9 rounded-md border border-stone-200 bg-white px-3 text-xs"><option value="all">全部规则</option><option value="same_new_ns">同一 NS 主域</option><option value="same_ns_ip">同一 NS IP</option><option value="same_a_ip">同一 A IP</option></select>
    </div>
    {resource.loading && !resource.data ? <div className="py-16 text-center text-sm text-stone-400">正在读取批量事件…</div> : resource.error ? <div className="rounded-md border border-red-200 bg-red-50 p-3 text-xs text-red-700">读取失败：{resource.error.message}</div> : items.length === 0 ? <div className="rounded-lg border border-stone-200 bg-white py-16 text-center text-sm text-stone-400">当前没有达到阈值的批量协同变化</div> :
      <div className="space-y-3">{items.map((event) => <section key={event.id} className="rounded-lg border border-stone-200 bg-white shadow-sm">
        <button onClick={() => setExpanded(expanded === event.id ? '' : event.id)} className="grid w-full grid-cols-1 gap-3 p-4 text-left md:grid-cols-[1fr_140px_140px]">
          <div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><GitCompareArrows size={15} className="text-cyan-700"/><span className="rounded bg-cyan-50 px-2 py-0.5 text-[11px] font-medium text-cyan-800">{TYPE_LABEL[event.type]}</span><code className="break-all text-sm font-semibold text-stone-800">{event.target}</code></div><p className="mt-2 text-xs text-stone-500">{event.summary}</p><p className="mt-1 font-mono text-[10px] text-stone-400">{event.id} · {event.previous_snapshot_id} → {event.current_snapshot_id}</p></div>
          <div><div className="text-2xl font-semibold tabular-nums text-stone-800">{event.zone_count}</div><div className="text-[11px] text-stone-400">同时变化的不同 zone</div></div>
          <div><div className="text-xs font-medium text-stone-700">{event.status}</div><div className="mt-1 text-[11px] text-stone-400">{new Date(event.last_seen).toLocaleString()}</div></div>
        </button>
        {expanded === event.id && <div className="border-t border-stone-100 p-4"><div className="mb-3 flex items-center justify-between"><span className="text-xs font-medium text-stone-700">相邻快照逐 zone 差异（同一 zone 多条记录只计 1 次）</span>{session?.canOperate && <span className="flex gap-2"><button onClick={() => act(event, 'confirm')} className="inline-flex items-center gap-1 rounded border border-cyan-200 px-2 py-1 text-[11px] text-cyan-700"><ShieldCheck size={12}/>确认</button><button onClick={() => act(event, 'ignore')} className="inline-flex items-center gap-1 rounded border border-stone-200 px-2 py-1 text-[11px] text-stone-600"><ShieldX size={12}/>忽略并解除冻结</button></span>}</div>
          {event.changes.length > 0 ? <div className="max-h-[420px] overflow-auto rounded-md border border-stone-200"><table className="w-full min-w-[760px] text-left"><thead className="sticky top-0 bg-stone-50 text-[10px] text-stone-500"><tr><th className="px-3 py-2">zone / 记录</th><th className="px-3 py-2">前一快照</th><th/><th className="px-3 py-2">当前快照</th></tr></thead><tbody>{event.changes.map((change) => <ChangeEvidence key={`${change.zone}-${change.record_name ?? change.ns_host ?? ''}`} change={change}/>)}</tbody></table></div> : <div><p className="mb-2 text-[11px] text-amber-700">该历史事件生成于逐 zone 证据字段上线前，仅保留 zone 列表。</p><div className="flex max-h-56 flex-wrap gap-1.5 overflow-y-auto">{event.zones.map((zone) => <code key={zone} className="rounded bg-stone-100 px-2 py-1 text-[11px] text-stone-600">{zone}</code>)}</div></div>}
        </div>}
      </section>)}</div>}
  </div>
}

export default function CampaignsPage() {
  const [tab, setTab] = useState<'overview' | 'dependency' | 'ownership' | 'events'>('overview')
  return <div className="mx-auto max-w-[1440px] space-y-4">
    <div><h2 className="text-base font-semibold text-stone-800">NS 更新、归属与批量协同变化</h2><p className="mt-1 text-xs text-stone-500">更新总览感知每轮变化规模，归属图谱描述 zone 迁移方向；只有达到阈值的同步指向变化才转换为协同事件。</p></div>
    <div className="inline-flex rounded-lg border border-stone-200 bg-white p-1">
      <button onClick={() => setTab('overview')} className={`inline-flex items-center gap-1.5 rounded-md px-4 py-2 text-xs ${tab === 'overview' ? 'bg-cyan-700 text-white' : 'text-stone-600 hover:bg-stone-50'}`}><Activity size={14}/>更新总览</button>
      <button onClick={() => setTab('dependency')} className={`inline-flex items-center gap-1.5 rounded-md px-4 py-2 text-xs ${tab === 'dependency' ? 'bg-cyan-700 text-white' : 'text-stone-600 hover:bg-stone-50'}`}><Network size={14}/>NS依赖热力图</button>
      <button onClick={() => setTab('ownership')} className={`inline-flex items-center gap-1.5 rounded-md px-4 py-2 text-xs ${tab === 'ownership' ? 'bg-cyan-700 text-white' : 'text-stone-600 hover:bg-stone-50'}`}><Layers3 size={14}/>NS 归属图谱</button>
      <button onClick={() => setTab('events')} className={`inline-flex items-center gap-1.5 rounded-md px-4 py-2 text-xs ${tab === 'events' ? 'bg-cyan-700 text-white' : 'text-stone-600 hover:bg-stone-50'}`}><GitCompareArrows size={14}/>协同变化事件</button>
    </div>
    {tab === 'overview' ? <NSChangeOverview/> : tab === 'dependency' ? <NSDependencyHeatmap/> : tab === 'ownership' ? <OwnershipView/> : <EventsView/>}
  </div>
}
