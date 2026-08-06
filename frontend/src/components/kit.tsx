import React from 'react'
import {
  AlertOctagon, Flame, AlertTriangle, Info, CheckCircle2, HelpCircle,
  Inbox, DatabaseZap, Clock3, ShieldQuestion, FileWarning, ArrowRight,
} from 'lucide-react'
import type { RiskLevel, EvidenceLevel, EventStatus, NsRecord } from '@/domain/risk'
import { LEVEL_LABEL, EVIDENCE_LABEL, STATUS_LABEL, fmtDuration } from '@/domain/risk'
import { cn } from '@/lib/utils'

// ---------- 风险等级 ----------
export const LEVEL_STYLE: Record<RiskLevel, { fg: string; bg: string; ring: string; icon: React.ElementType; hex: string }> = {
  critical: { fg: 'text-red-700', bg: 'bg-red-50', ring: 'border-red-200', icon: AlertOctagon, hex: '#dc2626' },
  high: { fg: 'text-orange-700', bg: 'bg-orange-50', ring: 'border-orange-200', icon: Flame, hex: '#ea580c' },
  medium: { fg: 'text-amber-700', bg: 'bg-amber-50', ring: 'border-amber-200', icon: AlertTriangle, hex: '#d97706' },
  low: { fg: 'text-sky-700', bg: 'bg-sky-50', ring: 'border-sky-200', icon: Info, hex: '#0284c7' },
  recovered: { fg: 'text-emerald-700', bg: 'bg-emerald-50', ring: 'border-emerald-200', icon: CheckCircle2, hex: '#059669' },
  unknown: { fg: 'text-stone-500', bg: 'bg-stone-100', ring: 'border-stone-200', icon: HelpCircle, hex: '#78716c' },
}

export function LevelBadge({ level, className }: { level: RiskLevel; className?: string }) {
  const s = LEVEL_STYLE[level]
  const Icon = s.icon
  return (
    <span className={cn('inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs font-medium whitespace-nowrap', s.fg, s.bg, s.ring, className)}>
      <Icon size={12} strokeWidth={2.2} />
      {LEVEL_LABEL[level]}
    </span>
  )
}

const EVIDENCE_STYLE: Record<EvidenceLevel, string> = {
  cache_hint: 'text-stone-600 bg-stone-100 border-stone-200',
  repeated: 'text-indigo-700 bg-indigo-50 border-indigo-200',
  pending_verify: 'text-violet-700 bg-violet-50 border-violet-200',
  auth_divergence: 'text-orange-700 bg-orange-50 border-orange-200',
  impact_confirmed: 'text-red-700 bg-red-50 border-red-200',
}

export function EvidenceBadge({ level }: { level: EvidenceLevel }) {
  return (
    <span className={cn('inline-flex items-center rounded border px-1.5 py-0.5 text-xs whitespace-nowrap', EVIDENCE_STYLE[level])}>
      {EVIDENCE_LABEL[level]}
    </span>
  )
}

const STATUS_STYLE: Record<EventStatus, { cls: string; dot: string }> = {
  active: { cls: 'text-orange-700 bg-orange-50 border-orange-200', dot: 'bg-orange-500' },
  pending: { cls: 'text-violet-700 bg-violet-50 border-violet-200', dot: 'bg-violet-500' },
  confirmed: { cls: 'text-red-700 bg-red-50 border-red-200', dot: 'bg-red-500' },
  recovered: { cls: 'text-emerald-700 bg-emerald-50 border-emerald-200', dot: 'bg-emerald-500' },
  excluded: { cls: 'text-stone-600 bg-stone-100 border-stone-200', dot: 'bg-stone-400' },
  ignored: { cls: 'text-stone-500 bg-stone-100 border-stone-200', dot: 'bg-stone-400' },
}

export function StatusBadge({ status, breathing }: { status: EventStatus; breathing?: boolean }) {
  const s = STATUS_STYLE[status]
  return (
    <span className={cn('inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-xs whitespace-nowrap', s.cls)}>
      <span className={cn('h-1.5 w-1.5 rounded-full', s.dot, breathing && 'animate-pulse')} />
      {STATUS_LABEL[status]}
    </span>
  )
}

// ---------- 卡片与标题 ----------
export function Card({ title, extra, children, className, pad = true }: {
  title?: React.ReactNode; extra?: React.ReactNode; children: React.ReactNode; className?: string; pad?: boolean
}) {
  return (
    <section className={cn('rounded-lg border border-stone-200 bg-white shadow-[0_1px_2px_rgba(0,0,0,0.04)]', className)}>
      {title && (
        <header className="flex items-center justify-between gap-2 border-b border-stone-100 px-4 py-2.5">
          <h3 className="text-[13px] font-semibold text-stone-700">{title}</h3>
          {extra}
        </header>
      )}
      <div className={cn(pad && 'p-4')}>{children}</div>
    </section>
  )
}

export function StatCard({ label, value, sub, tone = 'default', icon }: {
  label: string; value: React.ReactNode; sub?: React.ReactNode
  tone?: 'default' | 'critical' | 'high' | 'ok'; icon?: React.ReactNode
}) {
  const toneCls = {
    default: 'text-stone-800',
    critical: 'text-red-700',
    high: 'text-orange-700',
    ok: 'text-emerald-700',
  }[tone]
  return (
    <div className="rounded-lg border border-stone-200 bg-white px-4 py-3 shadow-[0_1px_2px_rgba(0,0,0,0.04)]">
      <div className="flex items-center gap-1.5 text-xs text-stone-500">{icon}{label}</div>
      <div className={cn('mt-1 text-2xl font-semibold tabular-nums leading-7 transition-all duration-300', toneCls)}>{value}</div>
      {sub && <div className="mt-0.5 text-xs text-stone-400">{sub}</div>}
    </div>
  )
}

// ---------- 空状态 / 异常状态 ----------
export function EmptyState({ title = '无匹配事件', desc, action }: { title?: string; desc?: string; action?: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-16 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-stone-100 text-stone-400"><Inbox size={22} /></div>
      <p className="text-sm font-medium text-stone-600">{title}</p>
      {desc && <p className="max-w-md text-xs leading-5 text-stone-400">{desc}</p>}
      {action}
    </div>
  )
}

export type StateKind = 'loading' | 'query_failed' | 'clickhouse_down' | 'snapshot_stalled' | 'geolite_missing' | 'relay_down' | 'evidence_weak' | 'no_baseline' | 'partial_evidence' | 'blacklist_expired'

export const STATE_META: Record<StateKind, { icon: React.ElementType; title: string; desc: string }> = {
  loading: { icon: Clock3, title: '正在加载', desc: '正在查询最新快照数据…' },
  query_failed: { icon: ShieldQuestion, title: '查询失败', desc: '查询请求未成功返回，请检查查询条件或稍后重试。' },
  clickhouse_down: { icon: DatabaseZap, title: 'ClickHouse 不可用', desc: '分析库连接中断：事件列表、趋势图表与影响面统计暂不可用；快照目录监测仍在运行，恢复后自动补齐数据。' },
  snapshot_stalled: { icon: Clock3, title: '快照停止更新', desc: '快照目录超过 30 分钟无新文件：所有事件状态停留在最后观测时刻，新的 NS 变化将无法被发现。' },
  geolite_missing: { icon: FileWarning, title: 'GeoLite 离线库缺失', desc: 'ASN 与国家/地区归属识别暂停：新事件相关字段显示为「未知」，基线比对与变化检测不受影响。' },
  relay_down: { icon: ShieldQuestion, title: 'relay 拨测不可用', desc: '权威验证与可用性拨测暂停：事件只能停留在缓存观测/重复异常阶段，无法升级为「已确认」。' },
  evidence_weak: { icon: ShieldQuestion, title: '拨测证据不足', desc: '当前仅有缓存观测证据，未经权威或拨测验证，不能判定为已确认投毒。' },
  no_baseline: { icon: Clock3, title: '尚未形成稳定基线', desc: '该域名观测未满 12 次快照，暂不做变化判定；当前仅展示原始观测记录。' },
  partial_evidence: { icon: FileWarning, title: '部分证据缺失', desc: '该事件的部分证据（拨测详情 / RR 记录）已超出保留周期，仅展示可用的摘要信息。' },
  blacklist_expired: { icon: FileWarning, title: '黑名单文件过期', desc: '该名单超过更新周期未刷新，命中结果可信度下降，建议重新导入后再做处置。' },
}

export function StateBanner({ kind, compact }: { kind: StateKind; compact?: boolean }) {
  const m = STATE_META[kind]
  const Icon = m.icon
  if (compact) {
    return (
      <div className="flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
        <Icon size={14} className="mt-0.5 shrink-0" />
        <span><b className="font-medium">{m.title}</b> — {m.desc}</span>
      </div>
    )
  }
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-14 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-amber-50 text-amber-500"><Icon size={22} /></div>
      <p className="text-sm font-medium text-stone-700">{m.title}</p>
      <p className="max-w-lg text-xs leading-5 text-stone-500">{m.desc}</p>
    </div>
  )
}

// ---------- NS 记录表 ----------
export function NsTable({ records, highlight }: { records: NsRecord[]; highlight?: (r: NsRecord) => boolean }) {
  if (!records.length) return <p className="py-3 text-center text-xs text-stone-400">暂无记录</p>
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[680px] text-xs">
        <thead>
          <tr className="border-b border-stone-100 text-left text-stone-400">
            <th className="py-1.5 pr-3 font-medium">NS 主机名</th>
            <th className="py-1.5 pr-3 font-medium">IP</th>
            <th className="py-1.5 pr-3 font-medium">ASN</th>
            <th className="py-1.5 pr-3 font-medium">归属组织</th>
            <th className="py-1.5 pr-3 whitespace-nowrap font-medium">国家/地区</th>
            <th className="py-1.5 whitespace-nowrap font-medium">可用性</th>
          </tr>
        </thead>
        <tbody>
          {records.map((r, i) => (
            <tr key={i} className={cn('border-b border-stone-50 last:border-0', highlight?.(r) && 'bg-red-50/60')}>
              <td className="py-1.5 pr-3 font-mono text-stone-700">{r.host}</td>
              <td className="py-1.5 pr-3 font-mono text-stone-600">{r.ips.join(', ')}</td>
              <td className="py-1.5 pr-3 font-mono text-stone-600">{r.asn}</td>
              <td className="py-1.5 pr-3 text-stone-600">{r.asnOrg}</td>
              <td className="py-1.5 pr-3 whitespace-nowrap text-stone-600">{r.country}</td>
              <td className="py-1.5 whitespace-nowrap">
                {r.reachable === undefined ? <span className="text-stone-400">—</span>
                  : r.reachable ? <span className="text-emerald-600">可达 {r.rttMs}ms</span>
                    : <span className="font-medium text-red-600">不可达</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ---------- 旧值 → 新值 ----------
export function OldNew({ oldV, newV, changed = true }: { oldV: React.ReactNode; newV: React.ReactNode; changed?: boolean }) {
  if (!changed) {
    return (
      <span className="inline-flex items-center gap-1.5 font-mono text-xs text-stone-600">
        <span>{newV}</span>
        <span className="font-sans text-[10px] text-emerald-600">未变化</span>
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-xs">
      <span className="text-stone-500 line-through decoration-stone-300">{oldV}</span>
      <ArrowRight size={12} className="text-stone-400" />
      <span className="font-medium text-red-700">{newV}</span>
    </span>
  )
}

export function Duration({ min }: { min: number }) {
  return <span className="tabular-nums text-stone-600">{fmtDuration(min)}</span>
}
