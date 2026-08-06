import { cn } from '@/lib/utils'
import type { TimelineNode } from '@/data/mock'
import { CircleDot, Repeat2, Gauge, ShieldCheck, CheckCircle2, MailWarning } from 'lucide-react'

const KIND_META: Record<TimelineNode['kind'], { icon: React.ElementType; color: string; track: string; label: string }> = {
  start: { icon: CircleDot, color: 'text-red-600 bg-red-50 border-red-300', track: 'bg-red-200', label: '风险开始' },
  repeat: { icon: Repeat2, color: 'text-stone-500 bg-stone-100 border-stone-300', track: 'bg-stone-200', label: '持续观测' },
  baseline: { icon: Gauge, color: 'text-sky-600 bg-sky-50 border-sky-300', track: 'bg-sky-200', label: '基线更新' },
  verify: { icon: ShieldCheck, color: 'text-orange-600 bg-orange-50 border-orange-300', track: 'bg-orange-200', label: '验证节点' },
  recover: { icon: CheckCircle2, color: 'text-emerald-600 bg-emerald-50 border-emerald-300', track: 'bg-emerald-200', label: '恢复' },
  alert: { icon: MailWarning, color: 'text-violet-600 bg-violet-50 border-violet-300', track: 'bg-violet-200', label: '告警' },
}

/** 时间线：时间列 + 状态轨道 + 事件卡片（默认倒序，最新在上） */
export default function Timeline({ nodes, activeLevel }: { nodes: TimelineNode[]; activeLevel?: 'critical' | 'high' }) {
  const sorted = [...nodes].sort((a, b) => (a.time < b.time ? 1 : -1))
  // 连续重复观测自动合并显示
  const merged: (TimelineNode & { mergedCount?: number })[] = []
  for (const n of sorted) {
    const prev = merged[merged.length - 1]
    if (n.kind === 'repeat' && prev && prev.kind === 'repeat') {
      prev.mergedCount = (prev.mergedCount ?? 1) + 1
    } else {
      merged.push({ ...n })
    }
  }
  return (
    <div className="relative">
      {merged.map((n, i) => {
        const m = KIND_META[n.kind]
        const Icon = m.icon
        const isLast = i === merged.length - 1
        const breathing = n.kind === 'start' && activeLevel
        const recoverAnim = n.kind === 'recover'
        return (
          <div key={i} className="grid grid-cols-[92px_28px_1fr] items-start">
            <div className="pt-2 text-right text-xs tabular-nums text-stone-400">
              <div>{n.time.slice(5, 10)}</div>
              <div className="text-stone-500">{n.time.slice(11)}</div>
            </div>
            <div className="relative flex justify-center self-stretch">
              {!isLast && <span className={cn('absolute top-5 bottom-0 w-px', m.track)} />}
              <span className={cn(
                'z-10 mt-1.5 flex h-5 w-5 items-center justify-center rounded-full border',
                m.color,
                breathing && 'animate-[breath_2.4s_ease-in-out_infinite]',
                recoverAnim && 'animate-[confirmOnce_1.2s_ease-out_1]',
              )}>
                <Icon size={11} strokeWidth={2.4} />
              </span>
            </div>
            <div className={cn('pb-4 pl-3', isLast && 'pb-1')}>
              <div className="rounded-md border border-stone-200 bg-white px-3 py-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[13px] font-medium text-stone-700">{n.title}</span>
                  <span className={cn('rounded border px-1 py-px text-[10px]', m.color)}>{m.label}</span>
                  {n.mergedCount && n.mergedCount > 1 && (
                    <span className="text-[10px] text-stone-400">已合并 {n.mergedCount} 次连续观测</span>
                  )}
                </div>
                {n.detail && <p className="mt-1 text-xs leading-5 text-stone-500">{n.detail}</p>}
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}
