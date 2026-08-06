import { useState } from 'react'
import { ChevronDown, ArrowRight } from 'lucide-react'
import { Card, LevelBadge, StatusBadge, EvidenceBadge, NsTable, EmptyState, Duration, StateBanner } from '@/components/kit'
import Timeline from '@/components/Timeline'
import { useRiskEvents } from '@/api/useRiskEvents'
import { useHashRoute } from '@/lib/router'
import { EventFilterBar, useEventFilters } from './Events'
import { cn } from '@/lib/utils'
import { formatChangeField, nsRecordChanged } from '@/domain/nsDiff'

/** NS 变化检测场景页 */
export default function NsChangePage() {
  const [route, navigate] = useHashRoute()
  const f = useEventFilters(route.query)
  const resource = useRiskEvents('ns_change', f)
  const filtered = resource.data?.items ?? []
  const [expanded, setExpanded] = useState<string | null>('EVT-20260730-001')

  return (
    <div className="mx-auto max-w-[1440px] space-y-4">
      <div>
        <h2 className="text-base font-semibold text-stone-800">NS 变化检测</h2>
        <p className="mt-0.5 text-xs text-stone-400">
          比对稳定观测基线与当前 NS 状态：NS 增减 / 主域变化 / IP·ASN·国家变化 / 指向保留地址 / 新旧 NS 解析结果不一致。
          <b className="text-stone-500">「稳定观测基线」与「权威验证结果」分开展示</b>，未经拨测验证的缓存差异不判定为已确认投毒。
        </p>
      </div>

      <Card pad={false}>
        <div className="border-b border-stone-100 px-4 py-3"><EventFilterBar showType={false} /></div>
        {resource.loading && !resource.data ? <StateBanner kind="loading" /> : resource.error ? <StateBanner kind="query_failed" /> : filtered.length === 0 ? <EmptyState desc="当前筛选条件下没有 NS 变化事件。" /> : (
          <div className="divide-y divide-stone-100">
            {filtered.sort((a, b) => (a.lastSeen < b.lastSeen ? 1 : -1)).map((e) => {
              const open = expanded === e.id
              return (
                <div key={e.id}>
                  <div className="grid cursor-pointer grid-cols-[auto_1fr_auto] items-center gap-3 px-4 py-3 hover:bg-stone-50/60 lg:grid-cols-[auto_minmax(200px,1.2fr)_auto_minmax(260px,2fr)_auto_auto_auto]"
                    onClick={() => setExpanded(open ? null : e.id)}>
                    <LevelBadge level={e.level} />
                    <div className="min-w-0">
                      <button className="block truncate font-mono text-[13px] text-cyan-800 hover:underline"
                        onClick={(ev) => { ev.stopPropagation(); navigate(`/event/${e.id}`) }}>{e.domain}</button>
                      <div className="mt-0.5 text-[11px] text-stone-400">{e.id}</div>
                    </div>
                    <div className="hidden flex-wrap gap-1 lg:flex">
                      {e.changeFields.slice(0, 3).map((c) => (
                        <span key={c} className="rounded border border-stone-200 bg-stone-50 px-1.5 py-0.5 text-[10px] text-stone-500">{formatChangeField(c)}</span>
                      ))}
                    </div>
                    <div className="hidden min-w-0 lg:block">
                      {e.baselineNs.length > 0 && (
                        <span className="mr-2 inline-flex items-center gap-1 rounded bg-stone-100 px-1.5 py-0.5 font-mono text-[11px] text-stone-600">
                          NS {e.baselineNs.length} <ArrowRight size={10} /> {e.currentNs.length}
                        </span>
                      )}
                      <span className="line-clamp-1 text-xs text-stone-500">{e.summary}</span>
                    </div>
                    <div className="hidden lg:block"><EvidenceBadge level={e.evidence} /></div>
                    <div className="hidden lg:block"><StatusBadge status={e.status} breathing={e.level === 'critical' && e.status !== 'recovered'} /></div>
                    <ChevronDown size={15} className={cn('justify-self-end text-stone-400 transition-transform', open && 'rotate-180')} />
                  </div>

                  {open && (
                    <div className="border-t border-stone-100 bg-stone-50/50 px-4 py-4">
                      <div className="mb-3 flex flex-wrap gap-x-6 gap-y-1 text-xs text-stone-500">
                        <span>首次出现 <b className="tabular-nums text-stone-700">{e.firstSeen}</b></span>
                        <span>最近出现 <b className="tabular-nums text-stone-700">{e.lastSeen}</b></span>
                        <span>持续 <Duration min={e.durationMin} /></span>
                        <span>观测 {e.observations} 次</span>
                        <span>受影响名称 {e.affectedCount} 个</span>
                      </div>
                      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
                        <div className="rounded-md border border-stone-200 bg-white p-3">
                          <div className="mb-2 text-xs font-medium text-sky-800">稳定观测基线（12 次快照）</div>
                          <NsTable records={e.baselineNs} />
                        </div>
                        <div className="rounded-md border border-stone-200 bg-white p-3">
                          <div className="mb-2 text-xs font-medium text-orange-800">
                            {e.status === 'recovered' ? '事件发生时异常观测' : '事件观测'}（缓存快照）
                          </div>
                          <NsTable records={e.currentNs} highlight={(record) => nsRecordChanged(e.baselineNs, record)} />
                        </div>
                        <div className="rounded-md border border-stone-200 bg-white p-3">
                          <div className="mb-2 text-xs font-medium text-stone-600">时间线</div>
                          <Timeline nodes={e.timeline.slice(0, 4)} activeLevel={e.level === 'critical' ? 'critical' : e.level === 'high' ? 'high' : undefined} />
                        </div>
                      </div>
                      <div className="mt-3 text-right">
                        <button className="rounded-md border border-cyan-600 px-3 py-1.5 text-xs text-cyan-700 hover:bg-cyan-50"
                          onClick={() => navigate(`/event/${e.id}`)}>查看完整证据详情</button>
                      </div>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </Card>
    </div>
  )
}
