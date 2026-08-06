import { useState } from 'react'
import { Save } from 'lucide-react'
import { Card, StateBanner } from '@/components/kit'
import { api } from '@/api/client'
import { useApiResource } from '@/api/useApiResource'
import type { SettingsResponse } from '@/domain/risk'
import { cn } from '@/lib/utils'
import { useSession } from '@/api/SessionContext'

function Field({ name, label, value, unit, hint, type = 'text', disabled = false }: { name: string; label: string; value: string | number; unit?: string; hint?: string; type?: string; disabled?: boolean }) {
  return (
    <div>
      <label className="text-xs text-stone-500">{label}</label>
      <div className="mt-1 flex items-center gap-2">
        <input name={name} type={type} defaultValue={value} disabled={disabled}
          className="h-8 w-full max-w-[220px] rounded-md border border-stone-200 bg-white px-2.5 text-xs text-stone-700 outline-none focus:border-cyan-500 disabled:cursor-not-allowed disabled:bg-stone-100 disabled:text-stone-400" />
        {unit && <span className="text-xs text-stone-400">{unit}</span>}
      </div>
      {hint && <p className="mt-1 text-[11px] text-stone-400">{hint}</p>}
    </div>
  )
}

function Toggle({ name, label, defaultOn, hint, disabled = false }: { name: string; label: string; defaultOn?: boolean; hint?: string; disabled?: boolean }) {
  return (
    <label className={cn('flex items-start gap-2.5', disabled ? 'cursor-not-allowed opacity-60' : 'cursor-pointer')}>
      <input name={name} type="checkbox" defaultChecked={defaultOn} disabled={disabled} className="mt-0.5 accent-cyan-600" />
      <span>
        <span className="block text-xs font-medium text-stone-700">{label}</span>
        {hint && <span className="mt-0.5 block text-[11px] text-stone-400">{hint}</span>}
      </span>
    </label>
  )
}

export default function SettingsPage() {
  const { session } = useSession()
  const canAdmin = session?.canAdmin === true
  const useMock = import.meta.env.VITE_USE_MOCK_DATA === 'true'
  const resource = useApiResource<SettingsResponse>(
    (signal) => useMock ? Promise.resolve({
      dumpMonitor: { directory: '/data/recursive-snapshots/', pollInterval: '30s', stabilityWindow: '90s' },
      baseline: { consecutiveRequired: 12 },
      campaign: { enabled: true, minDistinctZones: 10, holdBaseline: true, maxSnapshotGap: '30m' },
      probe: {
        enabled: true, backend: 'relay', recursiveResolver: '127.0.0.1:53',
        trustedResolvers: ['114.114.114.114:53', '223.5.5.5:53'], timeout: '2s', eventTimeout: '60s',
        maxDomains: 20, maxParallel: 12, maxEventsPerImport: 3,
      },
      alerts: {
        enabled: true, severities: ['critical'], recipients: ['dns-ops@example.com'],
        cooldown: '24h', timeout: '10s', subjectPrefix: '[DNS NS 严重告警]',
      },
      blacklist: { directory: '/data/bind-cache/blacklists', maxFileBytes: 67108864, maxEntries: 2000000 },
    }) : api.settings(signal),
    [useMock],
  )
  const [message, setMessage] = useState('')
  const auditResource = useApiResource(
    (signal) => useMock ? Promise.resolve({ items: [], total: 0, mode: 'memory' }) : api.audit(signal),
    [useMock],
  )
  const settings = resource.data
  if (resource.loading && !settings) return <Card><StateBanner kind="loading" /></Card>
  if (resource.error || !settings) return <Card><StateBanner kind="query_failed" /><p className="pb-4 text-center text-xs text-stone-500">{resource.error?.message}</p></Card>

  return (
    <form key={JSON.stringify(settings)} className="mx-auto max-w-[1100px] space-y-4" onSubmit={async (event) => {
      event.preventDefault()
      if (!canAdmin) {
        setMessage('当前账号没有系统配置权限。')
        return
      }
      const data = new FormData(event.currentTarget)
      const list = (name: string) => String(data.get(name) ?? '').split(/[;,\n]/).map((value) => value.trim()).filter(Boolean)
      const next: SettingsResponse = {
        dumpMonitor: {
          directory: String(data.get('dumpDirectory') ?? ''),
          pollInterval: String(data.get('pollInterval') ?? ''),
          stabilityWindow: String(data.get('stabilityWindow') ?? ''),
        },
        baseline: settings.baseline,
        campaign: {
          enabled: data.has('campaignEnabled'), minDistinctZones: Number(data.get('minDistinctZones')),
          holdBaseline: data.has('campaignHoldBaseline'), maxSnapshotGap: String(data.get('maxSnapshotGap') ?? ''),
        },
        probe: {
          enabled: data.has('probeEnabled'), backend: String(data.get('probeBackend') ?? ''),
          recursiveResolver: String(data.get('recursiveResolver') ?? ''), trustedResolvers: list('trustedResolvers'),
          timeout: String(data.get('probeTimeout') ?? ''), eventTimeout: String(data.get('eventTimeout') ?? ''),
          maxDomains: Number(data.get('maxDomains')), maxParallel: Number(data.get('maxParallel')),
          maxEventsPerImport: Number(data.get('maxEventsPerImport')),
        },
        alerts: {
          enabled: data.has('alertsEnabled'), severities: list('alertSeverities'), recipients: list('alertRecipients'),
          cooldown: String(data.get('alertCooldown') ?? ''), timeout: String(data.get('alertTimeout') ?? ''),
          subjectPrefix: String(data.get('subjectPrefix') ?? ''),
        },
        blacklist: {
          directory: String(data.get('blacklistDirectory') ?? ''),
          maxFileBytes: Number(data.get('maxFileBytes')), maxEntries: Number(data.get('maxEntries')),
        },
      }
      setMessage('正在保存…')
      try {
        if (useMock) throw new Error('开发预览模式仅展示配置，不会写入服务器')
        const result = await api.saveSettings(next)
        setMessage(result.restartRequired ? '配置已原子写入；请重启服务使全部组件使用新配置。' : '配置已保存。')
      } catch (error) {
        setMessage(error instanceof Error ? error.message : String(error))
      }
    }}>
      <div className="flex items-end justify-between">
        <div>
          <h2 className="text-base font-semibold text-stone-800">系统配置</h2>
          <p className="mt-0.5 text-xs text-stone-400">配置变更需「系统管理」权限，全部写入审计日志（演示环境仅展示，不落库）。</p>
        </div>
        <button type="submit" disabled={!canAdmin} className="inline-flex items-center gap-1.5 rounded-md bg-cyan-600 px-3 py-1.5 text-xs text-white hover:bg-cyan-700 disabled:cursor-not-allowed disabled:bg-stone-300">
          <Save size={13} /> 保存配置
        </button>
      </div>
      {!canAdmin && <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-700">当前账号为只读或运维角色；系统配置仅安全管理员可修改。</div>}
      {message && <div className="rounded-md border border-stone-200 bg-white px-3 py-2 text-xs text-stone-600">{message}</div>}

      <fieldset disabled={!canAdmin} className="grid min-w-0 grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="快照与基线">
          <div className="space-y-4">
            <Field name="pollInterval" label="目录扫描间隔" value={settings.dumpMonitor.pollInterval} hint="建议小于快照生成周期" />
            <Field name="stabilityWindow" label="文件稳定等待窗口" value={settings.dumpMonitor.stabilityWindow} hint="文件大小与修改时间持续稳定后才分析" />
            <Field name="baselineRequired" label="稳定基线形成条件" value={settings.baseline.consecutiveRequired} unit="次连续一致快照" hint="固定安全策略，页面不可修改" disabled />
            <Field name="dumpDirectory" label="快照目录" value={settings.dumpMonitor.directory} />
            <div className="border-t border-stone-100 pt-4"><Toggle name="campaignEnabled" label="启用批量协同变化检测" defaultOn={settings.campaign.enabled} /><div className="mt-3 grid grid-cols-2 gap-3"><Field name="minDistinctZones" label="不同 zone 阈值" type="number" value={settings.campaign.minDistinctZones} /><Field name="maxSnapshotGap" label="最大相邻间隔" value={settings.campaign.maxSnapshotGap} /></div><div className="mt-3"><Toggle name="campaignHoldBaseline" label="命中后冻结自动基线提升" defaultOn={settings.campaign.holdBaseline} hint="忽略或白名单处置后解除对应事件冻结" /></div></div>
          </div>
        </Card>

        <Card title="风险判定">
          <div className="space-y-4">
            <Toggle name="probeEnabled" label="启用异常事件自动拨测" defaultOn={settings.probe.enabled} disabled={!canAdmin} />
            <Field name="probeBackend" label="拨测后端" value={settings.probe.backend} hint="relay 或 direct；生产建议 relay" />
            <Field name="recursiveResolver" label="受监控递归 DNS" value={settings.probe.recursiveResolver} />
            <Field name="trustedResolvers" label="可信 DNS（逗号分隔）" value={settings.probe.trustedResolvers.join(', ')} />
            <Field name="probeTimeout" label="单次查询超时" value={settings.probe.timeout} />
            <Field name="eventTimeout" label="单事件总超时" value={settings.probe.eventTimeout} />
            <Field name="maxDomains" label="每事件最大拨测域名" type="number" value={settings.probe.maxDomains} />
            <Field name="maxParallel" label="最大并发" type="number" value={settings.probe.maxParallel} />
            <Field name="maxEventsPerImport" label="每轮最大拨测事件" type="number" value={settings.probe.maxEventsPerImport} />
          </div>
        </Card>

        <Card title="离线黑名单">
          <div className="space-y-4">
            <Field name="blacklistDirectory" label="离线名单目录" value={settings.blacklist.directory} />
            <Field name="maxFileBytes" label="单文件大小上限" type="number" value={settings.blacklist.maxFileBytes} unit="字节" />
            <Field name="maxEntries" label="总条目上限" type="number" value={settings.blacklist.maxEntries} />
          </div>
        </Card>

        <Card title="告警通知">
          <div className="space-y-4">
            <Toggle name="alertsEnabled" label="启用邮件告警" defaultOn={settings.alerts.enabled} disabled={!canAdmin} />
            <Field name="alertRecipients" label="接收人（逗号/分号分隔）" value={settings.alerts.recipients.join('; ')} />
            <Field name="alertSeverities" label="告警等级" value={settings.alerts.severities.join(', ')} />
            <Field name="alertCooldown" label="同事件簇冷却时间" value={settings.alerts.cooldown} />
            <Field name="alertTimeout" label="投递超时" value={settings.alerts.timeout} />
            <Field name="subjectPrefix" label="邮件标题前缀" value={settings.alerts.subjectPrefix} />
          </div>
        </Card>

        <Card title="权限与审计" className="lg:col-span-2">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-stone-100 text-left text-stone-400">
                <th className="py-1.5 pr-3 font-medium">角色</th>
                <th className="py-1.5 pr-3 font-medium">查看</th>
                <th className="py-1.5 pr-3 font-medium">确认 / 忽略 / 白名单</th>
                <th className="py-1.5 pr-3 font-medium">名单导入</th>
                <th className="py-1.5 font-medium">系统配置</th>
              </tr>
            </thead>
            <tbody className="text-stone-600">
              {[['值班观察员', true, false, false, false], ['DNS 运维', true, true, true, false], ['安全管理员', true, true, true, true]].map(([r, ...perms]) => (
                <tr key={r as string} className="border-b border-stone-50 last:border-0">
                  <td className="py-2 pr-3 font-medium text-stone-700">{r as string}</td>
                  {(perms as boolean[]).map((p, i) => (
                    <td key={i} className={cn('py-2 pr-3', p ? 'text-emerald-600' : 'text-stone-300')}>{p ? '允许' : '—'}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-3 border-t border-stone-100 pt-3 text-[11px] text-stone-400">所有处置动作（确认 / 忽略 / 白名单 / 配置变更）记录操作人、时间与理由，可在审计日志中检索。</p>
          <div className="mt-3 overflow-x-auto border-t border-stone-100 pt-3">
            <div className="mb-2 text-xs font-medium text-stone-600">最近审计记录</div>
            {auditResource.loading && !auditResource.data ? <StateBanner kind="loading" compact /> : auditResource.error ? (
              <p className="text-xs text-red-600">审计日志读取失败：{auditResource.error.message}</p>
            ) : auditResource.data?.items.length ? (
              <table className="w-full min-w-[760px] text-xs">
                <thead><tr className="text-left text-stone-400">
                  <th className="py-1.5 pr-3 font-medium">时间</th><th className="py-1.5 pr-3 font-medium">动作</th>
                  <th className="py-1.5 pr-3 font-medium">操作人 / 角色</th><th className="py-1.5 pr-3 font-medium">对象</th>
                  <th className="py-1.5 font-medium">详情</th>
                </tr></thead>
                <tbody>{auditResource.data.items.map((item, index) => (
                  <tr key={`${item.time}-${item.action}-${index}`} className="border-t border-stone-50">
                    <td className="py-2 pr-3 whitespace-nowrap tabular-nums text-stone-500">{item.time}</td>
                    <td className="py-2 pr-3 font-mono text-stone-700">{item.action}</td>
                    <td className="py-2 pr-3 text-stone-600">{item.actor} / {item.actorRole}</td>
                    <td className="py-2 pr-3 font-mono text-stone-600">{item.target}</td>
                    <td className="max-w-[360px] truncate py-2 text-stone-400" title={item.details}>{item.details || '—'}</td>
                  </tr>
                ))}</tbody>
              </table>
            ) : <p className="text-xs text-stone-400">暂无配置、名单或告警重试审计记录。</p>}
          </div>
        </Card>
      </fieldset>
    </form>
  )
}
