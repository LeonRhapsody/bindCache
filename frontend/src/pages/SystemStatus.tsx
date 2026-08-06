import { useState } from 'react'
import { CheckCircle2, AlertTriangle, XCircle } from 'lucide-react'
import { Card, StateBanner } from '@/components/kit'
import { SYSTEM_COMPONENTS } from '@/data/mock'
import type { SystemComponent, SnapshotSummary } from '@/domain/risk'
import { api } from '@/api/client'
import { useApiResource } from '@/api/useApiResource'
import { cn } from '@/lib/utils'

const STATUS_META = {
  normal: { icon: CheckCircle2, cls: 'text-emerald-600', label: '正常', badge: 'border-emerald-200 bg-emerald-50 text-emerald-700' },
  warning: { icon: AlertTriangle, cls: 'text-amber-600', label: '降级', badge: 'border-amber-200 bg-amber-50 text-amber-700' },
  error: { icon: XCircle, cls: 'text-red-600', label: '异常', badge: 'border-red-200 bg-red-50 text-red-700' },
}

const RECENT_SNAPSHOTS = [
  { id: 'snap-20260730-1420', time: '14:20', size: '18.2 MB', rows: '412,508', state: '已导入' },
  { id: 'snap-20260730-1410', time: '14:10', size: '18.1 MB', rows: '411,972', state: '已导入' },
  { id: 'snap-20260730-1400', time: '14:00', size: '18.2 MB', rows: '412,116', state: '已导入' },
  { id: 'snap-20260730-1350', time: '13:50', size: '18.0 MB', rows: '411,640', state: '已导入' },
  { id: 'snap-20260730-1340', time: '13:40', size: '18.1 MB', rows: '411,803', state: '已导入' },
]

export default function SystemStatusPage() {
  const useMock = import.meta.env.VITE_USE_MOCK_DATA === 'true'
  const resource = useApiResource<{ components: SystemComponent[]; snapshots: SnapshotSummary[] }>(
    (signal) => useMock
      ? Promise.resolve({ components: SYSTEM_COMPONENTS, snapshots: [] })
      : api.system(signal),
    [useMock],
  )
  const components = resource.data?.components ?? []
  const snapshots = resource.data?.snapshots ?? []
  const abnormal = components.filter((c) => c.status !== 'normal')
  const [snapshotPage, setSnapshotPage] = useState(1)
  const pageSize = 10
  const orderedSnapshots = useMock ? RECENT_SNAPSHOTS : [...snapshots].reverse()
  const snapshotPages = Math.max(1, Math.ceil(orderedSnapshots.length / pageSize))
  const displayedSnapshots = orderedSnapshots.slice((snapshotPage - 1) * pageSize, snapshotPage * pageSize)

  return (
    <div className="mx-auto max-w-[1440px] space-y-4">
      <div>
        <h2 className="text-base font-semibold text-stone-800">数据与系统状态</h2>
        <p className="mt-0.5 text-xs text-stone-400">平台自身组件的健康状态。<b className="text-stone-500">系统异常与 DNS 风险事件分开展示</b>——此处的异常说明缺少哪类数据、会影响什么功能。</p>
      </div>
      {resource.loading && !resource.data && <Card><StateBanner kind="loading" /></Card>}
      {resource.error && <Card><StateBanner kind="query_failed" /></Card>}

      {/* 异常影响说明 */}
      {abnormal.length > 0 && (
        <Card title={`数据源异常（${abnormal.length}）— 影响范围说明`} className="border-amber-200">
          <div className="space-y-3">
            {abnormal.map((c) => (
              <div key={c.name} className="rounded-md border border-stone-200 p-3">
                <div className="flex items-center gap-2">
                  <span className={cn('rounded border px-1.5 py-0.5 text-[11px]', STATUS_META[c.status].badge)}>{STATUS_META[c.status].label}</span>
                  <span className="text-sm font-medium text-stone-700">{c.name}</span>
                  <span className="text-[11px] text-stone-400">更新于 {c.updatedAt}</span>
                </div>
                <p className="mt-1.5 text-xs text-stone-600">{c.detail}</p>
                {c.impact && <p className="mt-1 text-xs leading-5 text-amber-800"><b>影响：</b>{c.impact}</p>}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* 各组件状态卡 */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {components.map((c) => <ComponentCard key={c.name} c={c} />)}
      </div>

      {/* 快照导入记录 */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card title="最近快照导入" pad={false} extra={<button onClick={resource.retry} disabled={resource.loading}
          className="rounded border border-stone-200 bg-white px-2 py-1 text-[11px] text-stone-600 disabled:opacity-50">刷新状态</button>}>
          <table className="w-full text-xs">
            <tbody>
              {displayedSnapshots.map((s) => (
                <tr key={s.id} className="border-b border-stone-50 last:border-0">
                  <td className="py-2 pl-4 pr-2 font-mono text-stone-600">{s.id}</td>
                  <td className="py-2 pr-2 tabular-nums text-stone-500">{'time' in s ? s.time : s.captured_at.slice(11, 19)}</td>
                  <td className="py-2 pr-2 tabular-nums text-stone-500">{'size' in s ? s.size : s.source}</td>
                  <td className="py-2 pr-2 tabular-nums text-stone-500">{'rows' in s ? `${s.rows} 行` : `${s.ns_observations.toLocaleString()} NS 观测`}</td>
                  <td className="py-2 pr-4 text-right"><span className="rounded border border-emerald-200 bg-emerald-50 px-1.5 py-0.5 text-emerald-700">{'state' in s ? s.state : '已入库'}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
          {orderedSnapshots.length > pageSize && <div className="flex items-center justify-end gap-2 border-t border-stone-100 px-4 py-2 text-[11px] text-stone-500">
            <button disabled={snapshotPage <= 1} onClick={() => setSnapshotPage((page) => Math.max(1, page - 1))}
              className="rounded border border-stone-200 px-2 py-1 disabled:opacity-40">上一页</button>
            <span>{snapshotPage} / {snapshotPages}</span>
            <button disabled={snapshotPage >= snapshotPages} onClick={() => setSnapshotPage((page) => Math.min(snapshotPages, page + 1))}
              className="rounded border border-stone-200 px-2 py-1 disabled:opacity-40">下一页</button>
          </div>}
        </Card>
        <Card title="状态异常时的页面行为约定">
          <ul className="space-y-2 text-xs leading-5 text-stone-500">
            <li><b className="text-stone-700">ClickHouse 不可用</b> — 列表与图表区域显示专用占位，说明影响范围，不混报为「系统错误」。</li>
            <li><b className="text-stone-700">快照停止更新</b> — 顶栏快照时间变为醒目的滞留提示，事件状态冻结在最后观测时刻。</li>
            <li><b className="text-stone-700">GeoLite 缺失</b> — ASN/国家字段显示「未知」，其余检测继续运行。</li>
            <li><b className="text-stone-700">relay 不可用</b> — 拨测证据区显示排队/不可用状态，事件无法升级为「已确认」。</li>
            <li><b className="text-stone-700">基线未形成（&lt;12 次快照）</b> — 域名画像仅展示原始观测，不做变化判定。</li>
            <li><b className="text-stone-700">黑名单过期</b> — 命中结果附带可信度下降提示，建议重新导入。</li>
          </ul>
        </Card>
      </div>
    </div>
  )
}

function ComponentCard({ c }: { c: SystemComponent }) {
  const m = STATUS_META[c.status]
  const Icon = m.icon
  return (
    <div className={cn('rounded-lg border bg-white px-4 py-3 shadow-[0_1px_2px_rgba(0,0,0,0.04)]',
      c.status === 'error' ? 'border-red-200' : c.status === 'warning' ? 'border-amber-200' : 'border-stone-200')}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Icon size={16} className={m.cls} />
          <span className="text-[13px] font-medium text-stone-700">{c.name}</span>
        </div>
        <span className={cn('rounded border px-1.5 py-0.5 text-[10px]', m.badge)}>{m.label}</span>
      </div>
      <div className="mt-1 text-[10px] text-stone-400">{c.category} · 更新于 {c.updatedAt.slice(11)}</div>
      <p className="mt-1.5 text-xs leading-5 text-stone-500">{c.detail}</p>
    </div>
  )
}
