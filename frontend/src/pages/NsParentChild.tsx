import { useState } from 'react'
import { ShieldCheck, ShieldX } from 'lucide-react'
import { Card, LevelBadge, StatusBadge, EvidenceBadge, EmptyState, OldNew, StateBanner } from '@/components/kit'
import { fmtDuration } from '@/domain/risk'
import { useRiskEvents } from '@/api/useRiskEvents'
import { useHashRoute } from '@/lib/router'
import { EventFilterBar, useEventFilters } from './Events'
import { cn } from '@/lib/utils'

interface PcExtra {
  parentNs: string[]
  childNs: string[]
  glueMismatch?: boolean
  gluePairs?: { host: string; glue: string; actual: string; comparison?: 'mismatch' | 'incomplete_or_equal' }[]
  sourceBasis?: string
  dnssec?: string
  authoritativeProbeState?: string
}

function SetBox({ title, items, tone }: { title: string; items: string[]; tone: 'parent' | 'common' | 'child' }) {
  const cls = {
    parent: 'border-violet-200 bg-violet-50/50',
    common: 'border-emerald-200 bg-emerald-50/50',
    child: 'border-orange-200 bg-orange-50/50',
  }[tone]
  return (
    <div className={cn('flex-1 rounded-md border p-3', cls)}>
      <div className="mb-1.5 text-xs font-medium text-stone-600">{title}（{items.length}）</div>
      {items.length === 0 ? <div className="text-[11px] text-stone-400">无</div> : (
        <ul className="space-y-1">
          {items.map((i) => <li key={i} className="rounded bg-white/80 px-2 py-1 font-mono text-[11px] text-stone-700">{i}</li>)}
        </ul>
      )}
    </div>
  )
}

export default function NsParentChildPage() {
  const [route, navigate] = useHashRoute()
  const f = useEventFilters(route.query)
  const resource = useRiskEvents('ns_parent_child', f)
  const base = resource.data?.items ?? []
  const filtered = base
  const [selected, setSelected] = useState('EVT-20260730-006')
  const sel = base.find((e) => e.id === selected) ?? filtered[0]
  const ex = (sel?.extra ?? {}) as unknown as PcExtra

  const parentNs = ex.parentNs ?? []
  const childNs = ex.childNs ?? []
  const common = parentNs.filter((n) => childNs.includes(n))
  const parentOnly = parentNs.filter((n) => !childNs.includes(n))
  const childOnly = childNs.filter((n) => !parentNs.includes(n))
  return (
    <div className="mx-auto max-w-[1440px] space-y-4">
      <div>
        <h2 className="text-base font-semibold text-stone-800">父子 NS 不一致</h2>
        <p className="mt-0.5 text-xs text-stone-400">
          只比对同一快照中的父区权威 Authority 委派与子区权威 Answer NS 集合，并对可比地址族检查 Glue。<b className="text-stone-500">不使用 TTL 升级，不自动拨测</b>。
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card pad={false} title="不一致事件" className="xl:col-span-1">
          <div className="border-b border-stone-100 px-3 py-2.5"><EventFilterBar showType={false} /></div>
          {resource.loading && !resource.data ? <StateBanner kind="loading" /> : resource.error ? <StateBanner kind="query_failed" /> : filtered.length === 0 ? <EmptyState desc="当前筛选条件下没有父子 NS 不一致事件。" /> : (
            <ul className="divide-y divide-stone-50">
              {filtered.sort((a, b) => (a.lastSeen < b.lastSeen ? 1 : -1)).map((e) => (
                <li key={e.id} onClick={() => setSelected(e.id)}
                  className={cn('cursor-pointer px-3 py-2.5 hover:bg-stone-50', selected === e.id && 'border-l-2 border-cyan-600 bg-cyan-50/40')}>
                  <div className="flex items-center gap-2">
                    <LevelBadge level={e.level} />
                    <button className="truncate font-mono text-xs text-cyan-800 hover:underline"
                      onClick={(ev) => { ev.stopPropagation(); navigate(`/event/${e.id}`) }}>{e.domain}</button>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {e.changeFields.map((c) => (
                      <span key={c} className="rounded border border-stone-200 bg-stone-50 px-1.5 py-0.5 text-[10px] text-stone-500">{c}</span>
                    ))}
                  </div>
                  <div className="mt-1.5 flex items-center gap-2">
                    <StatusBadge status={e.status} />
                    <EvidenceBadge level={e.evidence} />
                    <span className="text-[10px] text-stone-400">{fmtDuration(e.durationMin)}</span>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>

        {sel && (
          <div className="space-y-4 xl:col-span-2">
            {/* 集合对比 */}
            <Card title={<span>NS 集合对比 — <span className="font-mono font-normal">{sel.domain}</span></span>}>
              <div className="flex flex-col gap-3 sm:flex-row">
                <SetBox title="仅父区存在" items={parentOnly} tone="parent" />
                <SetBox title="父子共同 NS" items={common} tone="common" />
                <SetBox title="仅子区存在" items={childOnly} tone="child" />
              </div>
              <div className="mt-3 grid grid-cols-2 gap-x-6 gap-y-2 border-t border-stone-100 pt-3 text-xs sm:grid-cols-4">
                <div><span className="text-stone-400">父区委派 NS：</span><b className="tabular-nums">{parentNs.length} 台</b></div>
                <div><span className="text-stone-400">子区权威 NS：</span><b className="tabular-nums">{childNs.length} 台</b></div>
                <div><span className="text-stone-400">首次出现：</span><b className="tabular-nums">{sel.firstSeen.slice(5)}</b></div>
                <div><span className="text-stone-400">持续时间：</span><b className="tabular-nums">{fmtDuration(sel.durationMin)}</b></div>
              </div>
            </Card>

            {/* Glue 对比 */}
            <Card title="Glue 记录 vs 实际 A/AAAA">
              {ex.glueMismatch && ex.gluePairs ? (
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-stone-100 text-left text-stone-400">
                      <th className="py-1.5 pr-3 font-medium">NS 主机</th>
                      <th className="py-1.5 pr-3 font-medium">Glue → 实际</th>
                      <th className="py-1.5 font-medium">结论</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ex.gluePairs.map((g) => (
                      <tr key={g.host} className="border-b border-stone-50 last:border-0">
                        <td className="py-2 pr-3 font-mono text-stone-600">{g.host}</td>
                        <td className="py-2 pr-3"><OldNew oldV={g.glue} newV={g.actual} changed={g.glue !== g.actual} /></td>
                        <td className="py-2">
                          {g.comparison === 'mismatch'
                            ? <span className="rounded border border-red-200 bg-red-50 px-1.5 py-0.5 text-red-700">可比地址族不一致</span>
                            : g.glue === g.actual && g.glue
                              ? <span className="text-emerald-600">一致</span>
                              : <span className="text-stone-400">地址族不完整，不判定</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p className="py-1 text-xs text-stone-500">
                  {ex.gluePairs?.length
                    ? '当前快照可比对的 Glue 与 NS 主机地址未发现差异。'
                    : '当前快照没有同时包含可比对的 Glue 与实际 A/AAAA；此项保持未验证。'}
                </p>
              )}
            </Card>

            {/* 人工权威应答 + 快照证据 */}
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              <Card title="每台权威 NS 查询结果">
                {sel.probes.length === 0 ? (
                  <p className="py-1 text-xs text-stone-400">当前事件尚未形成各权威 NS 的有效拨测对比，可在拨测验证页人工补测。</p>
                ) : (
                  <table className="w-full text-xs">
                    <tbody>
                      {sel.probes.map((p, i) => (
                        <tr key={i} className="border-b border-stone-50 last:border-0">
                          <td className="py-2 pr-2 font-mono text-stone-600">{p.ns}</td>
                          <td className="py-2 text-stone-500">{p.detail}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </Card>
              <Card title="快照证据与处置策略">
                <dl className="space-y-2 text-xs">
                  <div className="flex justify-between gap-2">
                    <dt className="text-stone-400">集合证据来源</dt>
                    <dd className="text-right text-stone-700">{ex.sourceBasis === 'cache_authauthority_vs_authanswer' ? 'Authority 委派 vs 权威 Answer' : '快照来源未标记'}</dd>
                  </div>
                  <div className="flex justify-between gap-2">
                    <dt className="text-stone-400">自动拨测</dt>
                    <dd className="text-right text-stone-700">已关闭，不占用共享拨测限额</dd>
                  </div>
                  <div className="flex items-center justify-between gap-2 border-t border-stone-100 pt-2">
                    <dt className="text-stone-400">DNSSEC</dt>
                    <dd className="flex items-center gap-1.5 text-stone-700">
                      {ex.dnssec?.includes('通过')
                        ? <><ShieldCheck size={13} className="text-emerald-600" />{ex.dnssec}</>
                        : <><ShieldX size={13} className="text-stone-400" />{ex.dnssec ?? '无数据'}</>}
                    </dd>
                  </div>
                  <div className="flex justify-between gap-2 border-t border-stone-100 pt-2">
                    <dt className="text-stone-400">人工权威验证</dt>
                    <dd className="text-right text-stone-500">{ex.authoritativeProbeState ?? (sel.probes.length ? '已有拨测结果' : '尚未执行')}</dd>
                  </div>
                </dl>
              </Card>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
