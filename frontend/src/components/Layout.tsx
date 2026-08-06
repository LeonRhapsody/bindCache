import React, { useEffect, useState } from 'react'
import { cn } from '@/lib/utils'
import { useHashRoute } from '@/lib/router'
import {
  LayoutDashboard, ShieldAlert, GitCompareArrows, Layers3, GitFork, Ban,
  Crosshair, Radar, BellRing, HeartPulse, Settings, Menu, X, Search, Globe, Network,
} from 'lucide-react'
import { OVERVIEW_KPIS, SYSTEM_COMPONENTS } from '@/data/mock'
import { api } from '@/api/client'
import { useApiResource } from '@/api/useApiResource'
import type { OverviewResponse, SnapshotSummary, SystemComponent } from '@/domain/risk'
import { useSession } from '@/api/SessionContext'

interface NavItem { path: string; label: string; icon: React.ElementType; match?: string }
interface NavGroup { name: string; items: NavItem[] }

const NAV: NavGroup[] = [
  {
    name: '监测',
    items: [
      { path: '/overview', label: '监测总览', icon: LayoutDashboard },
      { path: '/events', label: '风险事件', icon: ShieldAlert },
      { path: '/probe', label: '拨测验证', icon: Radar },
	  { path: '/ns-health', label: '全局 NS 健康', icon: HeartPulse },
    ],
  },
  {
    name: '检测场景',
    items: [
      { path: '/ns-change', label: 'NS 变化', icon: GitCompareArrows },
      { path: '/ns-redundancy', label: 'NS 单一与冗余', icon: Layers3 },
      { path: '/ns-parent-child', label: '父子 NS 不一致', icon: GitFork },
      { path: '/ns-blacklist', label: 'NS 黑名单命中', icon: Ban },
      { path: '/campaigns', label: '批量协同变化', icon: Network },
    ],
  },
  {
    name: '分析',
    items: [{ path: '/domain', label: '域名追溯', icon: Crosshair, match: '/domain' }],
  },
  {
    name: '系统',
    items: [
      { path: '/alerts', label: '告警中心', icon: BellRing },
      { path: '/system', label: '数据与系统状态', icon: HeartPulse },
      { path: '/settings', label: '系统配置', icon: Settings },
    ],
  },
]

export const PAGE_TITLES: [string, string][] = [
  ['/overview', '监测总览'], ['/events', '风险事件'], ['/probe', '拨测验证'],
  ['/ns-change', 'NS 变化'], ['/ns-redundancy', 'NS 单一与冗余风险'], ['/ns-parent-child', '父子 NS 不一致'],
  ['/ns-blacklist', 'NS 黑名单命中'], ['/domain', '域名追溯'], ['/event', '事件证据详情'],
	['/ns-health', '全局 NS 健康'],
  ['/campaigns', '批量协同变化'],
  ['/alerts', '告警中心'], ['/system', '数据与系统状态'], ['/settings', '系统配置'],
]

export default function Layout({ children }: { children: React.ReactNode }) {
  const [route, navigate] = useHashRoute()
  const [mobileOpen, setMobileOpen] = useState(false)
  const [reduceMotion, setReduceMotion] = useState(false)
  const useMock = import.meta.env.VITE_USE_MOCK_DATA === 'true'
  const { session } = useSession()
  const overviewResource = useApiResource<OverviewResponse>(
    (signal) => useMock
      ? Promise.resolve({ kpis: OVERVIEW_KPIS, recentEvents: [], snapshots: [], mode: 'memory', warnings: [], generatedAt: OVERVIEW_KPIS.latestSnapshot })
      : api.overview(signal),
    [useMock],
  )
  const systemResource = useApiResource<{ components: SystemComponent[]; snapshots: SnapshotSummary[] }>(
    (signal) => useMock ? Promise.resolve({ components: SYSTEM_COMPONENTS, snapshots: [] }) : api.system(signal),
    [useMock],
  )

  useEffect(() => {
    document.documentElement.classList.toggle('reduce-motion', reduceMotion)
  }, [reduceMotion])

  useEffect(() => {
    queueMicrotask(() => setMobileOpen(false))
  }, [route.path])

  const abnormal = (systemResource.data?.components ?? []).filter((c) => c.status !== 'normal').length
  const kpis = overviewResource.data?.kpis

  const sidebar = (
    <div className="flex h-full flex-col bg-[#14171c] text-stone-300">
      <div className="flex items-center gap-2.5 border-b border-white/5 px-4 py-4">
        <div className="flex h-8 w-8 items-center justify-center rounded-md bg-cyan-600/90 text-white">
          <Globe size={17} />
        </div>
        <div>
          <div className="text-[13px] font-semibold text-white leading-4">递归 DNS 风险监测平台</div>
          <div className="mt-0.5 text-[10px] text-stone-500">Recursive DNS Risk Monitor</div>
        </div>
      </div>
      <nav className="flex-1 overflow-y-auto px-2 py-3">
        {NAV.map((g) => (
          <div key={g.name} className="mb-3">
            <div className="px-2 pb-1 text-[10px] font-medium uppercase tracking-wider text-stone-500">{g.name}</div>
            {g.items.map((it) => {
              const matchPrefix = it.match ?? it.path
              const active = route.path === it.path || route.path.startsWith(matchPrefix + '/') || (matchPrefix === '/events' && route.path.startsWith('/event/'))
              const Icon = it.icon
              return (
                <button
                  key={it.path}
                  onClick={() => navigate(it.path)}
                  className={cn(
                    'mb-0.5 flex w-full items-center gap-2.5 rounded-md px-2.5 py-[7px] text-left text-[13px] transition-colors',
                    active ? 'bg-cyan-600/15 font-medium text-cyan-300' : 'text-stone-400 hover:bg-white/5 hover:text-stone-200',
                  )}
                >
                  <Icon size={15} strokeWidth={2} />
                  {it.label}
                  {active && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-cyan-400" />}
                </button>
              )
            })}
          </div>
        ))}
      </nav>
      <div className="border-t border-white/5 px-4 py-3 text-[10px] leading-4 text-stone-500">
        离线部署 · 连续 12 次稳定基线<br />{useMock ? '开发预览（仿真数据）' : '生产数据模式'}
      </div>
    </div>
  )

  return (
    <div className="flex h-screen overflow-hidden bg-[#f4f3f1] text-stone-800">
      {/* 桌面侧边栏 */}
      <aside className="hidden w-52 shrink-0 lg:block">{sidebar}</aside>
      {/* 移动端抽屉 */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/40" onClick={() => setMobileOpen(false)} />
          <aside className="absolute left-0 top-0 h-full w-60">{sidebar}</aside>
          <button className="absolute left-64 top-4 text-white" onClick={() => setMobileOpen(false)}><X size={20} /></button>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        {/* 顶栏 */}
        <header className="flex h-12 shrink-0 items-center gap-3 border-b border-stone-200 bg-white px-3 lg:px-5">
          <button className="text-stone-500 lg:hidden" onClick={() => setMobileOpen(true)}><Menu size={18} /></button>
          <div className="flex min-w-0 items-center gap-2 text-[13px]">
            <span className="hidden text-stone-400 sm:inline">递归 DNS 风险监测</span>
            <span className="hidden text-stone-300 sm:inline">/</span>
            <span className="truncate font-medium text-stone-700">
              {PAGE_TITLES.find(([p]) => route.path === p || route.path.startsWith(p + '/'))?.[1] ?? '监测总览'}
            </span>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <div className="relative hidden md:block">
              <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-stone-400" />
              <input
                placeholder="搜索域名 / 事件 ID"
                className="h-8 w-52 rounded-md border border-stone-200 bg-stone-50 pl-8 pr-3 text-xs outline-none placeholder:text-stone-400 focus:border-cyan-500 focus:bg-white"
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    const v = (e.target as HTMLInputElement).value.trim()
                    if (v.startsWith('EVT-') || v.startsWith('RISK-')) navigate(`/event/${v}`)
                    else if (v) navigate(`/events?q=${encodeURIComponent(v)}`)
                  }
                }}
              />
            </div>
            <span className="hidden items-center gap-1.5 rounded-full border border-stone-200 bg-stone-50 px-2.5 py-1 text-[11px] text-stone-500 sm:inline-flex">
              <span className={cn('h-1.5 w-1.5 rounded-full', kpis && kpis.dataDelayMin < 30 ? 'bg-emerald-500' : 'bg-amber-500')} />
              {kpis ? `快照 ${kpis.latestSnapshot.slice(11) || '—'} · 延迟 ${kpis.dataDelayMin} 分钟` : '正在读取快照状态'}
            </span>
            {abnormal > 0 && (
              <button
                onClick={() => navigate('/system')}
                className="inline-flex items-center gap-1.5 rounded-full border border-amber-200 bg-amber-50 px-2.5 py-1 text-[11px] font-medium text-amber-700 hover:bg-amber-100"
                title="存在数据源异常，点击查看"
              >
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-amber-500" />
                系统 {abnormal} 项异常
              </button>
            )}
            {session && (
              <span className="hidden rounded-full border border-stone-200 bg-white px-2.5 py-1 text-[11px] text-stone-500 2xl:inline-flex"
                title={session.warning ?? `当前角色：${session.role}`}>
                {session.username || '未启用认证'} · {session.role}
              </span>
            )}
            <label className="hidden cursor-pointer items-center gap-1.5 text-[11px] text-stone-400 xl:flex" title="减少动态效果">
              <input type="checkbox" checked={reduceMotion} onChange={(e) => setReduceMotion(e.target.checked)} className="accent-cyan-600" />
              减少动态
            </label>
          </div>
        </header>
        <main className="min-h-0 flex-1 overflow-y-auto px-3 py-4 lg:px-5 lg:py-5">{children}</main>
      </div>
    </div>
  )
}
