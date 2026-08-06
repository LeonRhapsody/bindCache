import { useState } from 'react'
import { ArrowLeft, Download, UserCheck, EyeOff, ListPlus, Scale } from 'lucide-react'
import { Card, LevelBadge, StatusBadge, EvidenceBadge, NsTable, OldNew, StateBanner, EmptyState } from '@/components/kit'
import Timeline from '@/components/Timeline'
import { findEvent } from '@/data/mock'
import { RISK_TYPE_LABEL, fmtDuration } from '@/domain/risk'
import type { ProbeAnswer, ProbeComparison, ProbeFieldDiff, ProbeResult, RiskEvent } from '@/domain/risk'
import { buildNsDiffRows, nsRecordChanged } from '@/domain/nsDiff'
import { api } from '@/api/client'
import { useApiResource } from '@/api/useApiResource'
import { useSession } from '@/api/SessionContext'
import type { EventImpactResponse, SnapshotRecordResponse } from '@/domain/risk'
import { useHashRoute } from '@/lib/router'
import { cn } from '@/lib/utils'

const LIFECYCLE = ['单次观测', '重复出现', '待验证', '已确认权威分歧', '已确认实际影响', '已恢复 / 已排除']

function lifecycleStage(e: RiskEvent): number {
  if (e.status === 'recovered' || e.status === 'excluded') return 5
  if (e.evidence === 'impact_confirmed') return 4
  if (e.evidence === 'auth_divergence') return 3
  if (e.evidence === 'pending_verify') return 2
  if (e.evidence === 'repeated') return 1
  return 0
}

function LifecycleStepper({ e }: { e: RiskEvent }) {
  const stage = lifecycleStage(e)
  return (
    <div className="flex flex-wrap items-center gap-y-2">
      {LIFECYCLE.map((s, i) => {
        const done = i < stage
        const current = i === stage
        return (
          <div key={s} className="flex items-center">
            <div className={cn('flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px]',
              current ? 'border-cyan-500 bg-cyan-50 font-medium text-cyan-800'
                : done ? 'border-stone-200 bg-stone-100 text-stone-500'
                  : 'border-stone-100 bg-white text-stone-300')}>
              <span className={cn('flex h-3.5 w-3.5 items-center justify-center rounded-full text-[9px]',
                current ? 'bg-cyan-600 text-white' : done ? 'bg-stone-400 text-white' : 'bg-stone-100 text-stone-300')}>
                {i + 1}
              </span>
              {s}
            </div>
            {i < LIFECYCLE.length - 1 && <span className={cn('mx-1 h-px w-4', i < stage ? 'bg-stone-300' : 'bg-stone-150 bg-stone-200')} />}
          </div>
        )
      })}
    </div>
  )
}

export default function EventDetail({ id }: { id: string }) {
  const [, navigate] = useHashRoute()
  const useMock = import.meta.env.VITE_USE_MOCK_DATA === 'true'
  const { session } = useSession()
  const canOperate = session?.canOperate === true
  const [actionBusy, setActionBusy] = useState(false)
  const [actionError, setActionError] = useState('')
  const resource = useApiResource<RiskEvent>(
    (signal) => {
      if (!useMock) return api.event(id, signal)
      const event = findEvent(id)
      return event ? Promise.resolve(event) : Promise.reject(new Error(`事件 ${id} 不存在或已超出保留周期`))
    },
    [id, useMock],
  )
  const snapshotID = resource.data?.snapshot ?? ''
  const impactResource = useApiResource<EventImpactResponse | null>(
    (signal) => {
      if (useMock) return Promise.resolve(null)
      return api.eventImpact(id, signal)
    },
    [id, useMock],
  )
  const recordResource = useApiResource<SnapshotRecordResponse | null>(
    (signal) => {
      if (useMock || !snapshotID || !resource.data) return Promise.resolve(null)
      return api.snapshotRecord(id, snapshotID, signal)
    },
    [snapshotID, resource.data?.domain, useMock],
  )
  if (resource.loading && !resource.data) {
    return <Card><StateBanner kind="loading" /></Card>
  }
  if (resource.error || !resource.data) {
    return (
      <Card>
        <EmptyState title="未找到事件" desc={resource.error?.message ?? `事件 ${id} 不存在或已超出保留周期。`}
          action={<div className="mt-1 flex gap-2">
            <button className="rounded-md border border-stone-200 px-3 py-1.5 text-xs hover:bg-stone-50" onClick={resource.retry}>重试</button>
            <button className="rounded-md border border-stone-200 px-3 py-1.5 text-xs hover:bg-stone-50" onClick={() => navigate('/events')}>返回事件列表</button>
          </div>} />
      </Card>
    )
  }
  const e = resource.data
  const nsDiffRows = buildNsDiffRows(e.baselineNs, e.currentNs)
  const handleAction = async (action: 'confirm' | 'ignore' | 'whitelist') => {
    if (!canOperate) {
      setActionError(session?.warning ?? '当前角色没有事件处置权限')
      return
    }
    if (useMock) {
      setActionError('开发预览模式不执行处置写操作')
      return
    }
    const reason = action === 'confirm'
      ? (window.prompt('可选：填写确认意见') ?? '')
      : window.prompt(action === 'ignore' ? '请输入忽略理由（必填）' : '请输入白名单理由（必填）')
    if (reason === null || ((action === 'ignore' || action === 'whitelist') && !reason.trim())) return
    const expiresAt = action === 'whitelist'
      ? new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString()
      : undefined
    setActionBusy(true)
    setActionError('')
    try {
      await api.eventAction(e.id, action, reason.trim(), expiresAt)
      resource.retry()
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error))
    } finally {
      setActionBusy(false)
    }
  }
  const exportEvidence = () => {
    const payload = {
      exportedAt: new Date().toISOString(),
      event: e,
      impact: impactResource.data,
      snapshotRecord: recordResource.data,
    }
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `${e.id}-evidence.json`
    anchor.click()
    URL.revokeObjectURL(url)
  }
  const exportEvidenceCSV = () => {
    const rows: (string | number)[][] = [
      ['event_id', 'domain', 'risk_type', 'level', 'evidence', 'status', 'first_seen', 'last_seen', 'summary'],
      [e.id, e.domain, e.type, e.level, e.evidence, e.status, e.firstSeen, e.lastSeen, e.summary],
      [],
      ['side', 'ns_host', 'ip', 'asn', 'asn_org', 'country'],
      ...e.baselineNs.flatMap((record) => (record.ips.length ? record.ips : ['']).map((ip) => ['baseline', record.host, ip, record.asn, record.asnOrg, record.country])),
      ...e.currentNs.flatMap((record) => (record.ips.length ? record.ips : ['']).map((ip) => ['current', record.host, ip, record.asn, record.asnOrg, record.country])),
    ]
    const escape = (value: string | number) => `"${String(value).replaceAll('"', '""')}"`
    const blob = new Blob(['\uFEFF' + rows.map((row) => row.map(escape).join(',')).join('\r\n')], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `${e.id}-evidence.csv`
    anchor.click()
    URL.revokeObjectURL(url)
  }

  const isNsChange = e.type === 'ns_change'
  const isNsAvailability = e.type === 'ns_availability'
  const breathing = (e.level === 'critical' || e.level === 'high') && (e.status === 'active' || e.status === 'confirmed' || e.status === 'pending')

  return (
    <div className="mx-auto max-w-[1440px] space-y-4">
      {/* 头部 */}
      <div className="flex flex-wrap items-start gap-3">
        <button onClick={() => navigate('/events')} className="mt-0.5 rounded-md border border-stone-200 bg-white p-1.5 text-stone-500 hover:bg-stone-50" aria-label="返回风险事件列表">
          <ArrowLeft size={15} />
        </button>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="font-mono text-base font-semibold text-stone-800">{e.id}</h2>
            <LevelBadge level={e.level} />
            <EvidenceBadge level={e.evidence} />
            <StatusBadge status={e.status} breathing={breathing} />
            <span className="rounded border border-stone-200 bg-white px-1.5 py-0.5 text-xs text-stone-500">{RISK_TYPE_LABEL[e.type]}</span>
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-stone-400">
            <button className="font-mono text-cyan-700 hover:underline" onClick={() => navigate(`/domain/${e.domain}`)}>{e.domain}</button>
            <span>关联快照 {e.snapshot}</span>
            <span>事件簇合并 {e.clusterSize} 次观测</span>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <ActionBtn icon={<UserCheck size={13} />} label="确认" primary disabled={actionBusy || !canOperate} onClick={() => handleAction('confirm')} />
          <ActionBtn icon={<EyeOff size={13} />} label="忽略" disabled={actionBusy || !canOperate} onClick={() => handleAction('ignore')} />
          <ActionBtn icon={<ListPlus size={13} />} label="加白名单" disabled={actionBusy || !canOperate} onClick={() => handleAction('whitelist')} />
          <ActionBtn icon={<Download size={13} />} label="导出证据 JSON" onClick={exportEvidence} />
          <ActionBtn icon={<Download size={13} />} label="导出摘要 CSV" onClick={exportEvidenceCSV} />
        </div>
      </div>
      <p className="-mt-1 text-right text-[10px] text-stone-400">处置操作需具备「事件处置」权限，全部动作计入审计日志</p>
      {actionError && <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700">{actionError}</div>}
      {useMock && <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-700">开发预览模式：此页使用显式启用的仿真数据；生产构建只接受后端事件证据。</div>}

      {/* 状态提示 */}
      {e.status === 'recovered' && (
        <div className="flex items-start gap-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-xs text-emerald-800">
          <span className="mt-0.5 h-2 w-2 shrink-0 animate-[confirmOnce_1.2s_ease-out_1] rounded-full bg-emerald-500" />
          <span><b>事件已恢复</b> — 恢复时间 {e.recoveredAt}，连续 12 个快照与稳定基线一致后确认。历史证据完整保留。</span>
        </div>
      )}
      {e.status === 'ignored' && e.whitelistReason && (
        <div className="rounded-md border border-stone-200 bg-stone-50 px-3 py-2 text-xs text-stone-600">
          <b>白名单 / 忽略原因：</b>{e.whitelistReason}
        </div>
      )}
      {e.evidence !== 'impact_confirmed' && e.evidence !== 'auth_divergence' && e.status !== 'recovered' && (
        <StateBanner kind="evidence_weak" compact />
      )}
      {e.partialEvidence && <StateBanner kind="partial_evidence" compact />}

      {/* 生命周期 + 摘要 */}
      <Card title="统一生命周期">
        <LifecycleStepper e={e} />
        <p className="mt-3 rounded-md bg-stone-50 px-3 py-2 text-[13px] leading-6 text-stone-600">{e.summary}</p>
        <div className="mt-3 grid grid-cols-2 gap-x-6 gap-y-2 text-xs sm:grid-cols-4">
          <Meta label="首次发现" value={e.firstSeen} />
          <Meta label="最近发现" value={e.lastSeen} />
          <Meta label="持续时间" value={fmtDuration(e.durationMin)} />
          <Meta label="观测次数" value={`${e.observations} 次（簇内 ${e.clusterSize}）`} />
          {e.handler && <Meta label="处置人" value={e.handler} />}
          {e.recoveredAt && <Meta label="恢复时间" value={e.recoveredAt} />}
        </div>
        {e.opinion && (
          <div className="mt-3 border-t border-stone-100 pt-3 text-xs text-stone-500">
            <span className="font-medium text-stone-600">处置意见：</span>{e.opinion}
          </div>
        )}
      </Card>

      {/* 基线 vs 当前（NS 变化类） */}
      {isNsChange && e.baselineNs.length > 0 && (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <Card title={<span className="flex items-center gap-2"><Scale size={13} className="text-sky-600" />稳定观测基线<span className="text-[10px] font-normal text-stone-400">12 次快照一致形成</span></span>}>
            <NsTable records={e.baselineNs} />
          </Card>
          <Card title={<span className="flex items-center gap-2"><Scale size={13} className="text-orange-600" />{e.status === 'recovered' ? '事件发生时异常观测' : '事件观测'}<span className="text-[10px] font-normal text-stone-400">缓存快照 {displaySnapshotID(e.snapshot)}</span></span>}>
            <NsTable records={e.currentNs} highlight={(r) =>
              nsRecordChanged(e.baselineNs, r)} />
          </Card>
        </div>
      )}

      {isNsAvailability && <AvailabilityEvidence extra={e.extra} />}

      {/* 逐字段差异 */}
      {isNsChange && e.baselineNs.length > 0 && (
        <Card title="逐字段差异（基线 → 事件观测）">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[560px] text-xs">
              <thead>
                <tr className="border-b border-stone-100 text-left text-stone-400">
                  <th className="py-1.5 pr-3 font-medium">字段</th>
                  <th className="py-1.5 pr-3 font-medium">变化</th>
                  <th className="py-1.5 font-medium">说明</th>
                </tr>
              </thead>
              <tbody className="text-stone-600">
                {nsDiffRows.map((row) => (
                  <DiffRow key={row.key} field={row.field} oldV={row.oldValue} newV={row.newValue} note={row.note} />
                ))}
                {nsDiffRows.length === 0 && (
                  <tr><td colSpan={3} className="py-4 text-center text-stone-400">基线与该事件观测的结构化字段一致，未发现可展示差异。</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* 拨测 + 权威对比 */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card title="每台 NS 拨测结果" extra={<span className="text-[10px] text-stone-400">relay 服务 · 权威验证证据</span>}>
          {e.probes.length === 0 ? (
            <StateBanner kind="relay_down" compact />
          ) : (
            <ProbeResults probes={e.probes} />
          )}
        </Card>
        <Card title="可信权威 vs 受监控递归" extra={<span className="text-[10px] text-stone-400">逐字段对照稳定 NS 共识</span>}>
          {e.probeComparisons && e.probeComparisons.length > 0 ? (
            <ProbeComparisons comparisons={e.probeComparisons} />
          ) : <div className="space-y-2 text-xs">
            <div className="rounded-md border border-sky-200 bg-sky-50/60 px-3 py-2">
              <div className="mb-0.5 font-medium text-sky-800">可信 DNS 结果</div>
              <div className="font-mono text-stone-600">{e.trustedAnswer}</div>
            </div>
            <div className={cn('rounded-md border px-3 py-2', probeVerdictClass(e.probeVerdict))}>
              <div className="mb-0.5 font-medium text-stone-700">受监控递归 DNS 结果</div>
              <div className="font-mono text-stone-600">{e.recursiveAnswer}</div>
            </div>
            {e.probeSummary && <p className="text-[11px] text-stone-500">拨测结论：{e.probeSummary}</p>}
            <p className="text-[11px] text-stone-400">两侧结果不一致且经拨测复核后，方可标记为「已确认实际影响」；仅有缓存差异不构成确认投毒。</p>
          </div>}
        </Card>
      </div>

      {/* 影响面 + RR */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card title={`受影响名称（${impactResource.data?.total_affected_domains ?? e.affectedCount}）`}>
          {impactResource.loading && !useMock ? (
            <p className="py-2 text-xs text-stone-400">正在按需分析风险快照中的子域与 CNAME 影响链…</p>
          ) : impactResource.data ? (
            <>
              <div className="max-h-80 overflow-auto">
                {impactResource.data.groups.map((group) => (
                  <div key={group.type} className="mb-3 last:mb-0">
                    <div className="mb-1 text-[11px] font-medium text-stone-500">{group.title} · {group.domains.length}</div>
                    <table className="w-full text-xs">
                      <tbody>
                        {group.domains.map((name) => (
                          <tr key={`${group.type}-${name.domain}`} className="border-b border-stone-50 last:border-0">
                            <td className="py-1.5 pr-2 font-mono text-stone-600">{name.domain}</td>
                            <td className="py-1.5 text-right text-stone-400">
                              {name.target ? `CNAME${name.cname_hops && name.cname_hops > 1 ? ` ${name.cname_hops} 跳` : ''} → ${name.target}` : '域内名称'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ))}
              </div>
              <p className="mt-2 text-[11px] leading-5 text-stone-400">{impactResource.data.scope}</p>
            </>
          ) : impactResource.error && !useMock ? (
            <p className="py-2 text-xs text-amber-700">影响面暂不可用：{impactResource.error.message}</p>
          ) : e.affectedNames.length === 0 ? (
            <p className="py-2 text-xs text-stone-400">暂未观测到受影响的业务名称，或影响面分析依赖的证据不足。</p>
          ) : (
            <>
              <table className="w-full text-xs">
                <tbody>
                  {e.affectedNames.map((n, i) => (
                    <tr key={i} className="border-b border-stone-50 last:border-0">
                      <td className="py-1.5 pr-2 font-mono text-stone-600">{n.name}</td>
                      <td className="py-1.5 text-right text-stone-400">{n.via}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {e.affectedCount > e.affectedNames.length && (
                <p className="mt-2 text-[11px] text-stone-400">… 另有 {e.affectedCount - e.affectedNames.length} 个名称经 CNAME 链接受影响，完整清单见导出报告。</p>
              )}
            </>
          )}
        </Card>
        <Card title="完整 RR 记录（NS 置顶）">
          {recordResource.loading && !useMock ? (
            <p className="py-2 text-xs text-stone-400">正在按需读取原始 dump 的完整 RR…</p>
          ) : recordResource.data ? (
            <RawRRGroups groups={recordResource.data.groups} />
          ) : recordResource.error && !useMock ? (
            <p className="py-2 text-xs text-amber-700">完整 RR 暂不可用：{recordResource.error.message}</p>
          ) : e.rrSet.length === 0 ? (
            <p className="py-2 text-xs text-stone-400">RR 记录证据已超出保留周期，仅保留摘要。</p>
          ) : (
            <table className="w-full text-xs">
              <tbody>
                {[...e.rrSet].sort((a, b) => (a.type === 'NS' ? -1 : b.type === 'NS' ? 1 : 0)).map((r, i) => (
                  <tr key={i} className={cn('border-b border-stone-50 last:border-0', r.type === 'NS' && 'bg-cyan-50/40')}>
                    <td className="w-14 py-1.5 pr-2"><span className={cn('rounded border px-1 py-px text-[10px]', r.type === 'NS' ? 'border-cyan-200 bg-cyan-50 text-cyan-700' : 'border-stone-200 text-stone-500')}>{r.type}</span></td>
                    <td className="py-1.5 pr-2 font-mono text-stone-600">{r.value}</td>
                    <td className="py-1.5 text-right tabular-nums text-stone-400">TTL {r.ttl || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>

      {/* 时间线 + 告警 */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card title="风险开始 / 持续 / 恢复时间线">
          <Timeline nodes={e.timeline} activeLevel={e.level === 'critical' ? 'critical' : e.level === 'high' ? 'high' : undefined} />
        </Card>
        <Card title="告警投递记录" extra={<button className="text-xs text-cyan-700 hover:underline" onClick={() => navigate('/alerts')}>告警中心</button>}>
          {e.alerts.length === 0 ? (
            <p className="py-2 text-xs text-stone-400">该事件尚未触发告警（未达到告警阈值或被合并抑制）。</p>
          ) : (
            <table className="w-full text-xs">
              <tbody>
                {e.alerts.map((a, i) => (
                  <tr key={i} className="border-b border-stone-50 last:border-0">
                    <td className="py-2 pr-2 whitespace-nowrap tabular-nums text-stone-400">{a.time.slice(5)}</td>
                    <td className="py-2 pr-2 text-stone-600">{a.channel} → {a.target}</td>
                    <td className="py-2 pr-2 whitespace-nowrap">
                      <span className={cn('rounded border px-1.5 py-0.5', a.status === '已送达'
                        ? 'border-emerald-200 bg-emerald-50 text-emerald-700'
                        : a.status === '发送失败' ? 'border-red-200 bg-red-50 text-red-700' : 'border-stone-200 text-stone-500')}>{a.status}</span>
                    </td>
                    <td className="py-2 text-stone-400">{a.content}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <div className="mt-3 flex flex-wrap gap-2 border-t border-stone-100 pt-3 text-[11px] text-stone-400">
            <span>快捷跳转：</span>
            <button className="text-cyan-700 hover:underline" onClick={() => navigate(`/domain/${e.domain}`)}>域名画像</button>
            <button className="text-cyan-700 hover:underline" onClick={() => navigate('/probe')}>拨测结果</button>
            <button className="text-cyan-700 hover:underline" onClick={() => navigate(eventScenarioPath(e.type))}>所属场景</button>
          </div>
        </Card>
      </div>
    </div>
  )
}

function eventScenarioPath(type: RiskEvent['type']): string {
  if (type === 'ns_change') return '/ns-change'
  if (type === 'ns_single') return '/ns-redundancy'
  if (type === 'ns_parent_child') return '/ns-parent-child'
  if (type === 'ns_blacklist') return '/ns-blacklist'
  return '/events?type=ns_availability'
}

function AvailabilityEvidence({ extra }: { extra?: Record<string, unknown> }) {
  const suspectHosts = Array.isArray(extra?.suspectHosts) ? extra.suspectHosts.map(String) : []
  const remainingNS = typeof extra?.remainingNS === 'number' ? extra.remainingNS : Number(extra?.remainingNS ?? 0)
  const endpoints = Array.isArray(extra?.endpoints)
    ? extra.endpoints.filter((item): item is Record<string, unknown> => typeof item === 'object' && item !== null)
    : []
  return (
    <Card title="ADB / SRTT 可用性候选证据" extra={<span className="text-[10px] text-stone-400">连续快照候选 · 主动拨测后才确认</span>}>
      <div className="mb-3 grid grid-cols-1 gap-2 text-xs sm:grid-cols-2">
        <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2"><span className="text-amber-700">候选异常 NS：</span><span className="ml-1 font-mono text-stone-700">{suspectHosts.join(', ') || '—'}</span></div>
        <div className="rounded-md border border-stone-200 bg-stone-50 px-3 py-2"><span className="text-stone-500">扣除候选后剩余 NS：</span><b className="ml-1 text-stone-700">{Number.isFinite(remainingNS) ? remainingNS : '—'}</b></div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[720px] text-xs">
          <thead><tr className="border-b border-stone-100 text-left text-stone-400"><th className="py-1.5 pr-2 font-medium">NS</th><th className="pr-2 font-medium">IP</th><th className="pr-2 font-medium">SRTT</th><th className="pr-2 font-medium">普通 DNS 成功/超时</th><th className="pr-2 font-medium">连续异常</th><th className="font-medium">判定说明</th></tr></thead>
          <tbody>{endpoints.map((endpoint, index) => <tr key={`${String(endpoint.ns)}-${String(endpoint.ip)}-${index}`} className="border-b border-stone-50 text-stone-600">
            <td className="py-2 pr-2 font-mono">{String(endpoint.ns ?? '—')}</td><td className="pr-2 font-mono">{String(endpoint.ip ?? '—')}</td>
            <td className="pr-2 tabular-nums">{typeof endpoint.srttMs === 'number' ? `${endpoint.srttMs.toFixed(1)} ms` : '—'}</td>
            <td className="pr-2 tabular-nums">{String(endpoint.plainSuccess ?? 0)} / {String(endpoint.plainTimeout ?? 0)}</td>
            <td className="pr-2 tabular-nums">{String(endpoint.consecutive ?? 0)} 次</td><td>{String(endpoint.detail ?? '—')}</td>
          </tr>)}</tbody>
        </table>
        {endpoints.length === 0 && <p className="py-3 text-center text-xs text-stone-400">未保留端点级 ADB 详细证据。</p>}
      </div>
    </Card>
  )
}

function Meta({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-stone-400">{label}</div>
      <div className="mt-0.5 font-medium tabular-nums text-stone-700">{value}</div>
    </div>
  )
}

function displaySnapshotID(snapshotID: string): string {
  if (!snapshotID) return '未知'
  return snapshotID.startsWith('snap-') ? snapshotID.slice(5) : snapshotID
}

function ActionBtn({ icon, label, primary, disabled, onClick }: { icon: React.ReactNode; label: string; primary?: boolean; disabled?: boolean; onClick?: () => void }) {
  return (
    <button disabled={disabled} onClick={onClick} className={cn('inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs transition-colors disabled:cursor-not-allowed disabled:opacity-50',
      primary ? 'border-cyan-600 bg-cyan-600 text-white hover:bg-cyan-700' : 'border-stone-200 bg-white text-stone-600 hover:bg-stone-50')}>
      {icon}{label}
    </button>
  )
}

function probeVerdictClass(verdict: RiskEvent['probeVerdict']): string {
  switch (verdict) {
    case 'verified_impact':
    case 'verified_ns_divergence':
      return 'border-red-200 bg-red-50/60'
    case 'consistent':
      return 'border-emerald-200 bg-emerald-50/60'
    case 'inconclusive':
      return 'border-amber-200 bg-amber-50/60'
    default:
      return 'border-stone-200 bg-stone-50'
  }
}

function ProbeResults({ probes }: { probes: ProbeResult[] }) {
  const grouped = new Map<string, ProbeResult[]>()
  for (const probe of probes) {
    const domain = probe.domain || '事件域名'
    grouped.set(domain, [...(grouped.get(domain) ?? []), probe])
  }
  return (
    <div className="max-h-[32rem] space-y-2 overflow-auto">
      {[...grouped.entries()].map(([domain, rows], groupIndex) => (
        <details key={domain} open={groupIndex === 0} className="rounded-md border border-stone-200 bg-white">
          <summary className="cursor-pointer px-3 py-2 font-mono text-xs text-stone-700">
            {domain} <span className="font-sans text-[10px] text-stone-400">{rows.length} 条 NS 证据</span>
          </summary>
          <div className="overflow-x-auto border-t border-stone-100 px-3">
            <table className="w-full min-w-[980px] text-xs">
              <thead>
                <tr className="border-b border-stone-100 text-left text-stone-400">
                  <th className="py-1.5 pr-2 font-medium">角色 / NS</th>
                  <th className="py-1.5 pr-2 font-medium">查询状态</th>
                  <th className="py-1.5 pr-2 font-medium">共识比较</th>
                  <th className="py-1.5 pr-2 font-medium">逐字段差异</th>
                  <th className="py-1.5 font-medium">说明</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((probe, index) => (
                  <tr key={`${probe.role ?? 'unknown'}-${probe.ns}-${index}`} className="border-b border-stone-50 last:border-0">
                    <td className="py-2 pr-2 text-stone-600">
                      <span className={cn('mr-1.5 rounded border px-1 py-0.5 font-sans text-[10px]', probe.role === 'variant'
                        ? 'border-orange-200 bg-orange-50 text-orange-700'
                        : 'border-sky-200 bg-sky-50 text-sky-700')}>
                        {probe.role === 'variant' ? '变异侧' : probe.role === 'stable' ? '稳定侧' : '未标注'}
                      </span>
                      <span className="font-mono">{probe.ns}</span>
                      {probe.ip && <div className="mt-0.5 font-mono text-stone-400">{probe.ip}</div>}
                    </td>
                    <td className="py-2 pr-2 whitespace-nowrap">
                      {probe.reachable === true
                        ? <span className="text-emerald-600">可达{probe.rttMs !== null ? (probe.rttMs > 0 ? ` ${probe.rttMs}ms` : '（历史耗时未记录）') : ''}</span>
                        : probe.reachable === false
                          ? <span className="font-medium text-red-600">查询失败</span>
                          : <span className="text-amber-600">未获得有效结果</span>}
                    </td>
                    <td className="py-2 pr-2 whitespace-nowrap">
                      {probe.answerConsistent === true
                        ? <span className="rounded border border-emerald-200 bg-emerald-50 px-1.5 py-0.5 text-emerald-700">与稳定共识一致</span>
                        : probe.answerConsistent === false
                          ? <span className="rounded border border-red-200 bg-red-50 px-1.5 py-0.5 text-red-700">偏离稳定共识</span>
                          : <span className="rounded border border-stone-200 bg-stone-50 px-1.5 py-0.5 text-stone-500">
                            {probe.role === 'stable' ? '稳定侧基准' : '未形成可比结论'}
                          </span>}
                    </td>
                    <td className="max-w-[360px] py-2 pr-2 align-top"><ProbeDiffList differences={probe.differences} /></td>
                    <td className="py-2 text-stone-400">{probe.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      ))}
    </div>
  )
}

function ProbeDiffList({ differences, currentLabel = '该结果' }: { differences?: ProbeFieldDiff[]; currentLabel?: string }) {
  if (!differences) return <span className="text-stone-300">无结构化字段</span>
  const changed = differences.filter((row) => row.changed)
  if (changed.length === 0) return <span className="text-emerald-600">RCode、CNAME、A、AAAA、NS 均一致</span>
  return <div className="space-y-1.5">{changed.map((row) => (
    <div key={row.field} className={cn('rounded border px-2 py-1.5', row.field === 'authority_ns' ? 'border-amber-200 bg-amber-50/70' : 'border-red-200 bg-red-50/70')}>
      <div className={cn('font-medium', row.field === 'authority_ns' ? 'text-amber-800' : 'text-red-700')}>{row.label}</div>
      <div className="mt-0.5 grid grid-cols-[52px_1fr] gap-x-1 font-mono text-[10px] leading-4 text-stone-600">
        <span className="font-sans text-stone-400">稳定共识</span><span className="break-all">{probeValues(row.stable)}</span>
        <span className="font-sans text-stone-400">{currentLabel}</span><span className="break-all">{probeValues(row.current)}</span>
      </div>
      {row.note && <div className="mt-1 text-[10px] leading-4 text-amber-700">{row.note}</div>}
    </div>
  ))}</div>
}

function ProbeComparisons({ comparisons }: { comparisons: ProbeComparison[] }) {
  return <div className="max-h-[32rem] space-y-2 overflow-auto">{comparisons.map((comparison, index) => (
    <details key={`${comparison.domain}-${index}`} open={index === 0} className="rounded-md border border-stone-200 bg-white">
      <summary className="cursor-pointer px-3 py-2 text-xs text-stone-700">
        <span className="font-mono font-medium">{comparison.domain}</span>
        <span className="ml-2 text-[10px] text-stone-400">{comparison.summary}</span>
      </summary>
      <div className="space-y-2 border-t border-stone-100 p-3 text-xs">
        <ProbeAnswerCard title="稳定 NS 共识" tone="stable" answer={comparison.stable} />
        <ProbeAnswerCard title="可信 DNS 共识" tone="trusted" answer={comparison.trusted} differences={comparison.trustedDifferences} currentLabel="可信 DNS" />
        <ProbeAnswerCard title="受监控递归 DNS" tone="recursive" answer={comparison.recursive} differences={comparison.recursiveDifferences} currentLabel="受监控递归" />
      </div>
    </details>
  ))}</div>
}

function ProbeAnswerCard({ title, tone, answer, differences, currentLabel }: { title: string; tone: 'stable' | 'trusted' | 'recursive'; answer?: ProbeAnswer; differences?: ProbeFieldDiff[]; currentLabel?: string }) {
  const toneClass = tone === 'stable' ? 'border-stone-200 bg-stone-50/70' : tone === 'trusted' ? 'border-sky-200 bg-sky-50/60' : 'border-rose-200 bg-rose-50/40'
  return <div className={cn('rounded-md border px-3 py-2', toneClass)}>
    <div className="mb-1 font-medium text-stone-700">{title}</div>
    {answer ? <ProbeAnswerFields answer={answer} /> : <div className="text-stone-400">未形成有效共识</div>}
    {tone !== 'stable' && <div className="mt-2 border-t border-black/5 pt-2"><ProbeDiffList differences={differences} currentLabel={currentLabel} /></div>}
  </div>
}

function ProbeAnswerFields({ answer }: { answer: ProbeAnswer }) {
  if (answer.error) return <div className="break-all font-mono text-red-600">查询失败：{answer.error}</div>
  const fields: [string, string[]][] = [
    ['RCode', answer.rcode ? [answer.rcode] : []], ['CNAME', answer.cname], ['A', answer.a],
    ['AAAA', answer.aaaa], ['Authority NS', answer.authorityNs],
  ]
  return <div className="grid grid-cols-[88px_1fr] gap-x-2 gap-y-1 font-mono text-[11px] leading-5">{fields.map(([label, values]) => (
    <div key={label} className="contents"><span className="font-sans text-stone-400">{label}</span><span className="break-all text-stone-600">{probeValues(values)}</span></div>
  ))}</div>
}

function probeValues(values?: string[] | null): string { return values && values.length > 0 ? values.join(', ') : '∅' }

function DiffRow({ field, oldV, newV, note }: { field: string; oldV: string; newV: string; note: string }) {
  return (
    <tr className="border-b border-stone-50 last:border-0">
      <td className="py-2 pr-3 font-medium text-stone-700">{field}</td>
      <td className="py-2 pr-3"><OldNew oldV={oldV} newV={newV} /></td>
      <td className="py-2 text-stone-400">{note}</td>
    </tr>
  )
}

function RawRRGroups({ groups }: { groups: SnapshotRecordResponse['groups'] }) {
  return (
    <div className="max-h-96 space-y-2 overflow-auto">
      {[...groups].sort((a, b) => (a.type === 'NS' ? -1 : b.type === 'NS' ? 1 : a.type.localeCompare(b.type))).map((group) => (
        <details key={group.type} open={group.type === 'NS'} className={cn('rounded-md border', group.type === 'NS' ? 'border-cyan-200 bg-cyan-50/30' : 'border-stone-200 bg-white')}>
          <summary className="cursor-pointer px-3 py-2 text-xs font-medium text-stone-700">
            {group.type} <span className="ml-1 font-normal text-stone-400">{group.count} 条</span>
          </summary>
          <div className="space-y-1 border-t border-stone-100 px-3 py-2">
            {group.records.map((record, index) => (
              <pre key={index} className="overflow-x-auto whitespace-pre-wrap break-all rounded bg-white/80 px-2 py-1.5 font-mono text-[11px] leading-5 text-stone-600">
                {typeof record === 'string' ? record : JSON.stringify(record, null, 2)}
              </pre>
            ))}
          </div>
        </details>
      ))}
    </div>
  )
}
