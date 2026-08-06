import { useState } from 'react'
import { Radar, CheckCircle2, XCircle, Clock3, RefreshCw } from 'lucide-react'
import { Card, EmptyState, StateBanner } from '@/components/kit'
import { PROBE_TASKS } from '@/data/mock'
import { api } from '@/api/client'
import { useApiResource } from '@/api/useApiResource'
import { useSession } from '@/api/SessionContext'
import type { ProbeListItem } from '@/domain/risk'
import { useHashRoute } from '@/lib/router'
import { cn } from '@/lib/utils'

const RESULT_TONE: Record<string, string> = {
  一致: 'border-emerald-200 bg-emerald-50 text-emerald-700',
  不一致: 'border-red-200 bg-red-50 text-red-700',
  超时: 'border-stone-200 bg-stone-100 text-stone-500',
  集合A: 'border-violet-200 bg-violet-50 text-violet-700',
  集合B: 'border-amber-200 bg-amber-50 text-amber-700',
}

export default function ProbePage() {
  const [, navigate] = useHashRoute()
  const useMock = import.meta.env.VITE_USE_MOCK_DATA === 'true'
  const { session } = useSession()
  const resource = useApiResource<{
    items: ProbeListItem[]; total: number; mode: string
    policy?: { execution: string; maxEventsPerImport: number; maxParallel: number; eventTimeout: string; backend: string }
  }>(
    (signal) => useMock
      ? Promise.resolve({
        items: PROBE_TASKS.map((task) => ({ ...task, eventId: '', detail: '' })),
        total: PROBE_TASKS.length,
        mode: 'memory',
        policy: { execution: '开发预览', maxEventsPerImport: 3, maxParallel: 12, eventTimeout: '60s', backend: 'relay' },
      })
      : api.probes(signal),
    [useMock],
  )
  const tasks = resource.data?.items ?? []
  const [eventID, setEventID] = useState('')
  const [probeBusy, setProbeBusy] = useState(false)
  const [probeMessage, setProbeMessage] = useState('')
  const [query, setQuery] = useState('')
  const [resultFilter, setResultFilter] = useState('all')
  const filteredTasks = tasks.filter((task) => {
    const matchesResult = resultFilter === 'all' || task.result === resultFilter
    const needle = query.trim().toLowerCase()
    return matchesResult && (!needle || `${task.eventId} ${task.target} ${task.domain}`.toLowerCase().includes(needle))
  })
  const successful = tasks.filter((task) => task.result !== '超时').length
  const inconsistent = tasks.filter((task) => task.result === '不一致').length

  return (
    <div className="mx-auto max-w-[1440px] space-y-4">
      <div>
        <h2 className="text-base font-semibold text-stone-800">拨测验证</h2>
        <p className="mt-0.5 text-xs text-stone-400">通过 relay 节点对权威 NS 发起主动查询，为事件提供「权威验证」证据，区分缓存观测与实际影响。</p>
      </div>
      <Card title="人工补充拨测">
        <div className="flex flex-wrap items-center gap-2">
          <input value={eventID} onChange={(event) => setEventID(event.target.value)}
            placeholder="输入任意未恢复风险事件 ID"
            className="h-8 min-w-[280px] flex-1 rounded-md border border-stone-200 px-2.5 font-mono text-xs outline-none focus:border-cyan-500" />
          <button disabled={probeBusy || !eventID.trim() || !session?.canOperate} onClick={async () => {
            setProbeBusy(true)
            setProbeMessage('')
            try {
              if (useMock) throw new Error('开发预览模式不执行真实拨测')
              await api.manualProbe(eventID.trim())
              setProbeMessage('拨测已完成并写入证据库')
              resource.retry()
            } catch (error) {
              setProbeMessage(error instanceof Error ? error.message : String(error))
            } finally {
              setProbeBusy(false)
            }
          }} className="h-8 rounded-md bg-cyan-600 px-3 text-xs text-white disabled:cursor-not-allowed disabled:opacity-50">
            {probeBusy ? '拨测中…' : '立即拨测'}
          </button>
        </div>
        {probeMessage && <p className="mt-2 text-xs text-stone-500">{probeMessage}</p>}
        {!session?.canOperate && <p className="mt-2 text-xs text-amber-700">当前账号为只读角色，人工补测已禁用。</p>}
        <p className="mt-2 text-[11px] text-stone-400">支持 NS 变化、单一/冗余、父子不一致和黑名单事件；由服务器通过 relay 执行，页面不会直连外部 DNS。</p>
      </Card>

      {/* relay 状态 */}
      <Card title="relay 拨测服务状态" pad={false}>
        <div className="grid grid-cols-1 gap-px bg-stone-100 sm:grid-cols-3">
          <div className="bg-white px-4 py-3">
            <div className="flex items-center gap-2 text-xs text-stone-500"><Radar size={13} /> relay 拨测结果</div>
            <div className="mt-1 flex items-center gap-1.5 text-sm font-medium text-emerald-700"><CheckCircle2 size={15} /> 已形成 {tasks.length} 条拨测证据</div>
            <div className="mt-0.5 text-[11px] text-stone-400">成功应答 {successful} 条 · 权威分歧 {inconsistent} 条</div>
          </div>
          <div className="bg-white px-4 py-3">
            <div className="flex items-center gap-2 text-xs text-stone-500"><Radar size={13} /> 拨测执行器</div>
            <div className="mt-1 flex items-center gap-1.5 text-sm font-medium text-stone-700"><XCircle size={15} /> {resource.data?.mode === 'clickhouse' ? '结果来自正式持久化' : '内存预览模式'}</div>
            <div className="mt-0.5 text-[11px] text-stone-400">页面只读已入库证据，不因打开页面触发外部 DNS 请求</div>
          </div>
          <div className="bg-white px-4 py-3">
            <div className="flex items-center gap-2 text-xs text-stone-500"><Clock3 size={13} /> 拨测队列</div>
            <div className="mt-1 text-sm font-medium text-stone-700 tabular-nums">{resource.loading ? '正在查询' : resource.data?.policy?.execution ?? '策略未知'}</div>
            <div className="mt-0.5 text-[11px] text-stone-400">
              每轮最多 {resource.data?.policy?.maxEventsPerImport ?? '—'} 个事件 · 并发 {resource.data?.policy?.maxParallel ?? '—'} · 单事件 {resource.data?.policy?.eventTimeout || '—'}
            </div>
          </div>
        </div>
      </Card>
      {resource.error && <StateBanner kind="relay_down" compact />}

      {/* 拨测任务记录 */}
      <Card title="最近拨测任务" pad={false} extra={<button onClick={resource.retry} disabled={resource.loading}
        className="inline-flex h-7 items-center gap-1 rounded border border-stone-200 bg-white px-2 text-[11px] text-stone-600 disabled:opacity-50">
        <RefreshCw size={11} className={resource.loading ? 'animate-spin' : ''} />刷新
      </button>}>
        <div className="flex flex-wrap gap-2 border-b border-stone-100 px-4 py-2.5">
          <input value={query} onChange={(event) => setQuery(event.target.value)}
            placeholder="筛选事件 ID / 域名 / NS"
            className="h-8 min-w-[240px] flex-1 rounded border border-stone-200 px-2.5 text-xs outline-none focus:border-cyan-500" />
          <select value={resultFilter} onChange={(event) => setResultFilter(event.target.value)}
            className="h-8 rounded border border-stone-200 bg-white px-2 text-xs text-stone-600">
            <option value="all">全部结果</option><option value="一致">一致</option><option value="不一致">不一致</option><option value="超时">超时</option>
          </select>
        </div>
        {filteredTasks.length === 0 ? <EmptyState desc={tasks.length ? '当前筛选条件下没有拨测记录。' : '当前保留周期内没有拨测记录。'} /> : <>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[760px] text-xs">
            <thead>
              <tr className="border-b border-stone-100 text-left text-stone-400">
                <th className="py-2 pl-4 pr-2 font-medium">任务</th>
                <th className="py-2 pr-2 font-medium">目标 NS</th>
                <th className="py-2 pr-2 font-medium">关联域名</th>
                <th className="py-2 pr-2 font-medium">时间</th>
                <th className="py-2 pr-2 font-medium">节点</th>
                <th className="py-2 pr-2 font-medium">RTT</th>
                <th className="py-2 pr-4 font-medium">结果</th>
              </tr>
            </thead>
            <tbody>
              {filteredTasks.map((t) => (
                <tr key={t.id} className="border-b border-stone-50 last:border-0 hover:bg-stone-50/60">
                  <td className="py-2 pl-4 pr-2 font-mono text-stone-500">{t.id}</td>
                  <td className="py-2 pr-2 font-mono text-stone-700">{t.target}</td>
                  <td className="py-2 pr-2">
                    <button className="font-mono text-cyan-700 hover:underline" onClick={() => navigate(`/domain/${t.domain}`)}>{t.domain}</button>
                  </td>
                  <td className="py-2 pr-2 tabular-nums text-stone-500">{t.time.slice(5)}</td>
                  <td className="py-2 pr-2 text-stone-500">{t.node}</td>
                  <td className="py-2 pr-2 tabular-nums text-stone-500">{t.rtt === null ? '—' : `${t.rtt}ms`}</td>
                  <td className="py-2 pr-4">
                    <span className={cn('rounded border px-1.5 py-0.5', RESULT_TONE[t.result] ?? 'border-stone-200 text-stone-500')}>{t.result}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="border-t border-stone-100 px-4 py-2.5 text-[11px] text-stone-400">
          「一致」表示权威应答与可信 DNS 相符；「不一致」将驱动事件升级为「已确认权威分歧」；「超时」连续出现将触发可用性风险。
        </p>
        </>}
      </Card>
    </div>
  )
}
