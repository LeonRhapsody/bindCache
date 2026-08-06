import { useMemo, useState } from 'react'
import { Activity, AlertTriangle, Gauge, Network, Search, ServerCrash } from 'lucide-react'
import { api } from '@/api/client'
import { useApiResource } from '@/api/useApiResource'
import { Card, EmptyState, StateBanner } from '@/components/kit'
import type { NSHealthResponse } from '@/domain/risk'
import { cn } from '@/lib/utils'

const HEALTH: Record<string, { label: string; tone: string }> = {
  suspect: { label: '疑似不可达', tone: 'border-red-200 bg-red-50 text-red-700' },
  degraded: { label: '严重慢响应', tone: 'border-orange-200 bg-orange-50 text-orange-700' },
  edns_degraded: { label: 'EDNS 退化', tone: 'border-amber-200 bg-amber-50 text-amber-700' },
  slow: { label: '慢响应', tone: 'border-yellow-200 bg-yellow-50 text-yellow-700' },
  unknown: { label: '证据不足', tone: 'border-stone-200 bg-stone-50 text-stone-500' },
}

function HealthBadge({ value }: { value: string }) {
  const meta = HEALTH[value] ?? { label: value, tone: 'border-stone-200 bg-stone-50 text-stone-600' }
  return <span className={cn('inline-flex rounded border px-1.5 py-0.5 text-[10px] font-medium', meta.tone)}>{meta.label}</span>
}

function Kpi({ label, value, detail, tone = 'text-stone-800' }: { label: string; value: string | number; detail: string; tone?: string }) {
  return <div className="rounded-lg border border-stone-200 bg-white px-4 py-3 shadow-sm">
    <div className="text-[11px] text-stone-400">{label}</div>
    <div className={cn('mt-1 text-2xl font-semibold tabular-nums', tone)}>{value}</div>
    <div className="mt-1 text-[10px] text-stone-400">{detail}</div>
  </div>
}

export default function NsHealthPage() {
  const resource = useApiResource<NSHealthResponse>((signal) => api.nsHealth(signal), [])
  const [query, setQuery] = useState('')
  const data = resource.data
  const endpoints = useMemo(() => {
    const value = query.trim().toLowerCase()
    if (!value) return data?.endpoints ?? []
    return (data?.endpoints ?? []).filter((item) => `${item.ns_name} ${item.owner} ${item.ip} ${item.detail}`.toLowerCase().includes(value))
  }, [data, query])

  if (resource.loading && !data) return <StateBanner kind="loading" />
  if (resource.error || !data) return <StateBanner kind="query_failed" />
  const s = data.summary
  const maxBucket = Math.max(1, ...data.buckets.map((bucket) => bucket.count))
  const abnormal = s.slow_endpoints + s.degraded_endpoints + s.suspect_endpoints

  return <div className="mx-auto max-w-[1500px] space-y-4">
    <div className="flex flex-wrap items-end justify-between gap-3">
      <div>
        <h2 className="text-base font-semibold text-stone-800">全局 NS 健康</h2>
        <p className="mt-0.5 text-xs text-stone-400">仅依赖递归快照与 BIND ADB：从端点 SRTT/超时聚合到 NS、zone 和服务商影响面。</p>
      </div>
      <div className="text-right text-[10px] text-stone-400">快照 {s.snapshot_id.slice(0, 12)} · {new Date(s.captured_at).toLocaleString()}</div>
    </div>

    <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
      <Kpi label="ADB 端点覆盖" value={`${(s.endpoint_coverage * 100).toFixed(1)}%`} detail={`${s.hosts_with_adb}/${s.hosts_with_address} 个有地址 NS`} />
      <Kpi label="异常端点" value={abnormal} detail={`慢 ${s.slow_endpoints} · 退化 ${s.degraded_endpoints}`} tone="text-amber-700" />
      <Kpi label="疑似不可达端点" value={s.suspect_endpoints} detail="零成功并出现新增超时/失效标志" tone="text-red-700" />
      <Kpi label="受影响 zone" value={s.affected_zones} detail={`冗余下降 ${s.reduced_zones} · 全不可用 ${s.unavailable_zones}`} tone="text-orange-700" />
      <Kpi label="SRTT P99" value={`${s.srtt_p99_ms.toFixed(1)}ms`} detail={`P50 ${s.srtt_p50_ms.toFixed(1)} · P95 ${s.srtt_p95_ms.toFixed(1)}`} />
    </div>

    {data.warnings.map((warning) => <div key={warning} className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-[11px] text-amber-800">{warning}</div>)}

    <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
      <Card title={<span className="inline-flex items-center gap-2"><Gauge size={15} />SRTT 分布</span>}>
        <div className="space-y-2.5">
          {data.buckets.map((bucket) => <div key={bucket.label} className="grid grid-cols-[72px_1fr_52px] items-center gap-2 text-[11px]">
            <span className="text-stone-500">{bucket.label}</span>
            <div className="h-2 rounded-full bg-stone-100"><div className="h-2 rounded-full bg-cyan-600" style={{ width: `${Math.max(1, bucket.count / maxBucket * 100)}%` }} /></div>
            <span className="text-right tabular-nums text-stone-500">{bucket.count}</span>
          </div>)}
        </div>
        <div className="mt-4 grid grid-cols-3 gap-2 border-t border-stone-100 pt-3 text-center text-[10px] text-stone-400">
          <div><div className="font-mono text-sm text-stone-700">250ms</div>慢响应关注</div>
          <div><div className="font-mono text-sm text-orange-700">500ms</div>性能退化</div>
          <div><div className="font-mono text-sm text-red-700">1000ms</div>严重慢响应</div>
        </div>
      </Card>
      <Card title={<span className="inline-flex items-center gap-2"><Network size={15} />共享设施影响面</span>} className="xl:col-span-2">
        <div className="grid max-h-72 grid-cols-1 gap-2 overflow-y-auto md:grid-cols-2">
          {data.providers.slice(0, 16).map((provider) => <div key={provider.owner} className="rounded-md border border-stone-200 p-2.5">
            <div className="flex items-center justify-between gap-2"><span className="truncate font-mono text-xs text-cyan-800">{provider.owner}</span><span className="text-[10px] text-orange-700">影响 {provider.affected_zones} zone</span></div>
            <div className="mt-1 text-[10px] text-stone-400">异常端点 {provider.abnormal_endpoints}/{provider.endpoint_count} · NS {provider.host_count} · 最大 {provider.max_srtt_ms.toFixed(1)}ms</div>
            <div className="mt-1 truncate font-mono text-[9px] text-stone-400">{provider.host_sample.join(' · ')}</div>
          </div>)}
          {data.providers.length === 0 && <EmptyState desc="当前没有共享设施异常。" />}
        </div>
      </Card>
    </div>

    <Card pad={false} title={<span className="inline-flex items-center gap-2"><Activity size={15} />异常端点与 zone 影响</span>}
      extra={<div className="relative"><Search size={13} className="absolute left-2 top-1/2 -translate-y-1/2 text-stone-400" /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索 NS / IP / 服务商" className="h-7 w-60 rounded border border-stone-200 pl-7 pr-2 text-[11px] outline-none focus:border-cyan-500" /></div>}>
      {endpoints.length === 0 ? <EmptyState desc="当前筛选条件下没有异常端点。" /> : <div className="overflow-x-auto"><table className="w-full min-w-[1080px] text-[11px]">
        <thead><tr className="border-b border-stone-100 bg-stone-50 text-left text-stone-400"><th className="px-3 py-2 font-medium">状态</th><th className="py-2 font-medium">NS / IP</th><th className="py-2 font-medium">SRTT</th><th className="py-2 font-medium">EDNS 成功/超时</th><th className="py-2 font-medium">普通成功/超时</th><th className="py-2 font-medium">影响面</th><th className="py-2 font-medium">证据说明</th><th className="px-3 py-2 font-medium">最近观测</th></tr></thead>
        <tbody>{endpoints.map((endpoint) => <tr key={`${endpoint.ns_name}|${endpoint.ip}`} className="border-b border-stone-50 align-top last:border-0">
          <td className="px-3 py-2"><HealthBadge value={endpoint.health} /></td>
          <td className="py-2"><div className="font-mono text-stone-700">{endpoint.ns_name}</div><div className="font-mono text-[10px] text-stone-400">{endpoint.ip}</div></td>
          <td className="py-2 font-mono tabular-nums text-stone-700">{endpoint.srtt_ms.toFixed(1)}ms</td>
          <td className="py-2 tabular-nums">{endpoint.edns_success} / <span className="text-red-600">{endpoint.edns_timeout}</span></td>
          <td className="py-2 tabular-nums">{endpoint.plain_success} / <span className="text-red-600">{endpoint.plain_timeout}</span></td>
          <td className="py-2"><div>{endpoint.affected_zones} zone</div>{endpoint.sole_dependency > 0 && <div className="text-red-600">其中 {endpoint.sole_dependency} 个无替代 NS</div>}</td>
          <td className="max-w-[320px] py-2 text-stone-500"><span className="line-clamp-2">{endpoint.detail}</span></td>
          <td className="px-3 py-2 text-stone-400">{new Date(endpoint.last_seen).toLocaleString()}</td>
        </tr>)}</tbody>
      </table></div>}
    </Card>

    <div className="grid grid-cols-1 gap-3 text-[11px] text-stone-500 md:grid-cols-3">
      <div className="rounded-md border border-stone-200 bg-white p-3"><ServerCrash size={14} className="mb-1 text-red-600" /><b className="text-stone-700">疑似不可达</b><p className="mt-1">要求总成功为零且相邻快照新增超时，或出现经版本确认的 ADB 失效标志；高 SRTT 本身不等于不可达。</p></div>
      <div className="rounded-md border border-stone-200 bg-white p-3"><AlertTriangle size={14} className="mb-1 text-amber-600" /><b className="text-stone-700">协议退化</b><p className="mt-1">EDNS 大包超时而普通 DNS 可用时单独标记，避免误报整个 NS 不响应。</p></div>
      <div className="rounded-md border border-stone-200 bg-white p-3"><Network size={14} className="mb-1 text-cyan-700" /><b className="text-stone-700">全局优先级</b><p className="mt-1">异常端点按健康等级、依赖 zone 数和唯一依赖数量排序，优先处理共享基础设施问题。</p></div>
    </div>
  </div>
}
