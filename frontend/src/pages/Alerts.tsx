import { useState } from 'react'
import { Mail, CheckCircle2, RotateCcw, RefreshCw } from 'lucide-react'
import { Card, LevelBadge, EmptyState, StateBanner } from '@/components/kit'
import { ALERT_RECORDS } from '@/data/mock'
import { api } from '@/api/client'
import { useApiResource } from '@/api/useApiResource'
import { useSession } from '@/api/SessionContext'
import type { AlertListItem } from '@/domain/risk'
import { useHashRoute } from '@/lib/router'
import { cn } from '@/lib/utils'

export default function AlertsPage() {
  const [, navigate] = useHashRoute()
  const useMock = import.meta.env.VITE_USE_MOCK_DATA === 'true'
  const { session } = useSession()
  const resource = useApiResource<{
    items: AlertListItem[]; total: number; mode: string
    policy?: { enabled: boolean; severities: string[]; recipients: string[]; cooldown: string; subjectPrefix: string; recoveryEnabled: boolean }
  }>(
    (signal) => useMock
      ? Promise.resolve({
        items: ALERT_RECORDS, total: ALERT_RECORDS.length, mode: 'memory',
        policy: { enabled: true, severities: ['critical', 'high'], recipients: ['dns-ops@example.com'], cooldown: '24h', subjectPrefix: '[DNS NS 告警]', recoveryEnabled: true },
      })
      : api.alerts(signal),
    [useMock],
  )
  const records = resource.data?.items ?? []
  const sent = records.filter((record) => record.status === '已送达').length
  const failed = records.filter((record) => record.status === '发送失败').length
  const suppressed = records.filter((record) => record.status === '已抑制(合并)').length
  const [retrying, setRetrying] = useState('')
  const [message, setMessage] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const filteredRecords = statusFilter === 'all' ? records : records.filter((record) => record.status === statusFilter)

  const retry = async (record: AlertListItem) => {
    if (!session?.canOperate) {
      setMessage('当前账号为只读角色，不能重试告警投递')
      return
    }
    const key = `${record.eventId}\x00${record.target}`
    setRetrying(key)
    setMessage('')
    try {
      await api.retryAlert(record.eventId, record.target)
      setMessage(`已重新投递 ${record.eventId} → ${record.target}`)
      resource.retry()
    } catch (error) {
      setMessage(error instanceof Error ? error.message : String(error))
    } finally {
      setRetrying('')
    }
  }

  return (
    <div className="mx-auto max-w-[1440px] space-y-4">
      <div>
        <h2 className="text-base font-semibold text-stone-800">告警中心</h2>
        <p className="mt-0.5 text-xs text-stone-400">事件升级、恢复与系统异常的邮件投递记录；相同事件簇的重复告警自动合并抑制。</p>
      </div>
      {message && <div className="rounded-md border border-stone-200 bg-white px-3 py-2 text-xs text-stone-600">{message}</div>}

      {/* 通道状态 */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <Card>
          <div className="flex items-center gap-2 text-xs text-stone-500"><Mail size={13} /> 邮件通道（SMTP 中继）</div>
          <div className="mt-1.5 flex items-center gap-1.5 text-sm font-medium text-emerald-700"><CheckCircle2 size={15} /> 已记录 {sent} 次成功投递</div>
          <div className="mt-1 text-[11px] text-stone-400">失败 {failed} 次；通道连通性以实际投递结果为准</div>
        </Card>
        <Card>
          <div className="text-xs text-stone-500">通知策略</div>
          <div className="mt-1.5 space-y-1 text-xs text-stone-600">
            <div>启用状态：{resource.data?.policy?.enabled ? '已启用' : '未启用'}</div>
            <div>即时等级：{resource.data?.policy?.severities.join(' / ') || '未配置'}</div>
            <div>恢复通知：{resource.data?.policy?.recoveryEnabled ? '启用' : '未启用'} · 冷却 {resource.data?.policy?.cooldown || '—'}</div>
            <div className="truncate" title={resource.data?.policy?.recipients.join('; ')}>接收人：{resource.data?.policy?.recipients.join('; ') || '未配置'}</div>
          </div>
        </Card>
        <Card>
          <div className="text-xs text-stone-500">合并抑制</div>
          <div className="mt-1.5 text-sm font-medium text-stone-700 tabular-nums">当前查询记录中抑制 {suppressed} 条</div>
          <div className="mt-1 text-[11px] text-stone-400">同一事件簇在状态未变化时不重复投递，原始观测记录完整保留</div>
        </Card>
      </div>

      {/* 投递记录 */}
      <Card title="投递记录（倒序）" pad={false} extra={<div className="flex items-center gap-2">
        <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}
          className="h-7 rounded border border-stone-200 bg-white px-2 text-[11px] text-stone-600">
          <option value="all">全部状态</option>
          <option value="已送达">已送达</option>
          <option value="发送失败">发送失败</option>
          <option value="已抑制(合并)">已抑制（合并）</option>
        </select>
        <button type="button" onClick={resource.retry} disabled={resource.loading}
          className="inline-flex h-7 items-center gap-1 rounded border border-stone-200 bg-white px-2 text-[11px] text-stone-600 disabled:opacity-50">
          <RefreshCw size={11} className={resource.loading ? 'animate-spin' : ''} />刷新
        </button>
      </div>}>
        {resource.loading && !resource.data ? <StateBanner kind="loading" /> : resource.error ? <StateBanner kind="query_failed" /> : records.length === 0 ? <EmptyState desc="当前保留周期内没有告警投递记录。" /> : filteredRecords.length === 0 ? <EmptyState desc="当前筛选条件下没有投递记录。" /> : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[820px] text-xs">
              <thead>
                <tr className="border-b border-stone-100 text-left text-stone-400">
                  <th className="py-2 pl-4 pr-2 font-medium">时间</th>
                  <th className="py-2 pr-2 font-medium">事件</th>
                  <th className="py-2 pr-2 font-medium">等级</th>
                  <th className="py-2 pr-2 font-medium">通道 / 接收人</th>
                  <th className="py-2 pr-2 font-medium">状态</th>
                  <th className="py-2 pr-4 font-medium">内容</th>
                  <th className="py-2 pr-4 font-medium">操作</th>
                </tr>
              </thead>
              <tbody>
                {filteredRecords.map((a, i) => (
                  <tr key={i} className="cursor-pointer border-b border-stone-50 last:border-0 hover:bg-cyan-50/40" onClick={() => navigate(`/event/${a.eventId}`)}>
                    <td className="py-2.5 pl-4 pr-2 whitespace-nowrap tabular-nums text-stone-500">{a.time}</td>
                    <td className="py-2.5 pr-2">
                      <div className="font-mono text-stone-700">{a.eventId}</div>
                      <div className="font-mono text-stone-400">{a.domain}</div>
                    </td>
                    <td className="py-2.5 pr-2"><LevelBadge level={a.level} /></td>
                    <td className="py-2.5 pr-2 whitespace-nowrap text-stone-600">{a.channel} → {a.target}</td>
                    <td className="py-2.5 pr-2">
                      <span className={cn('rounded border px-1.5 py-0.5 whitespace-nowrap',
                        a.status === '已送达' ? 'border-emerald-200 bg-emerald-50 text-emerald-700'
                          : a.status === '发送失败' ? 'border-red-200 bg-red-50 text-red-700'
                            : 'border-stone-200 bg-stone-50 text-stone-500')}>{a.status}</span>
                    </td>
                    <td className="max-w-[360px] py-2.5 pr-4"><span className="line-clamp-2 text-stone-500">{a.content}</span></td>
                    <td className="py-2.5 pr-4">
                      {a.status === '发送失败' ? (
                        <button type="button" disabled={retrying !== '' || !session?.canOperate} onClick={(event) => {
                          event.stopPropagation()
                          void retry(a)
                        }} className="inline-flex items-center gap-1 whitespace-nowrap rounded border border-cyan-200 bg-cyan-50 px-2 py-1 text-cyan-700 disabled:opacity-50">
                          <RotateCcw size={12} className={retrying === `${a.eventId}\x00${a.target}` ? 'animate-spin' : ''} />
                          重试
                        </button>
                      ) : <span className="text-stone-300">—</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}
