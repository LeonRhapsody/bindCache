import { useState } from 'react'
import { Upload, CheckCircle2, AlertTriangle, Ban } from 'lucide-react'
import { Card, LevelBadge, StatusBadge, EmptyState, StateBanner } from '@/components/kit'
import { BLACKLIST_SOURCES } from '@/data/mock'
import { fmtDuration } from '@/domain/risk'
import { useRiskEvents } from '@/api/useRiskEvents'
import { api } from '@/api/client'
import { useApiResource } from '@/api/useApiResource'
import type { BlacklistSource } from '@/domain/risk'
import { useHashRoute } from '@/lib/router'
import { EventFilterBar, useEventFilters } from './Events'
import { cn } from '@/lib/utils'
import { useSession } from '@/api/SessionContext'

interface Hit {
  object: string; rule: string; source: string; version: string; confidence: string
  category: string; effective: string; expire: string; desc: string; note: string
}

const CONF_TONE: Record<string, string> = {
  高: 'border-red-200 bg-red-50 text-red-700',
  中: 'border-amber-200 bg-amber-50 text-amber-700',
  低: 'border-stone-200 bg-stone-50 text-stone-500',
}

const confidenceLabel = (value: string) => ({ high: '高', medium: '中', low: '低' }[value] ?? value)

export default function NsBlacklistPage() {
  const { session } = useSession()
  const canOperate = session?.canOperate === true
  const [route, navigate] = useHashRoute()
  const f = useEventFilters(route.query)
  const resource = useRiskEvents('ns_blacklist', f)
  const base = resource.data?.items ?? []
  const filtered = base
  const sourceResource = useApiResource<{ sources: BlacklistSource[]; warning?: string }>(
    (signal) => resource.useMock
      ? Promise.resolve({
        sources: BLACKLIST_SOURCES.map((source) => ({
          name: source.name, version: source.version, updatedAt: source.updatedAt, entries: source.entries,
          confidence: source.confidence, state: source.state, sha256: '', file: `${source.name}.csv`,
        })),
      })
      : api.blacklists(signal),
    [resource.useMock],
  )
  const sources = sourceResource.data?.sources ?? []
  const [selected, setSelected] = useState('EVT-20260730-007')
  const [uploadMessage, setUploadMessage] = useState('')
  const sel = base.find((e) => e.id === selected) ?? filtered[0]
  const hits = ((sel?.extra?.hits as Hit[] | undefined) ?? [])
  const stillInUse = sel?.extra?.stillInUse as boolean | undefined
  const whitelisted = sel?.extra?.whitelisted as boolean | undefined

  return (
    <div className="mx-auto max-w-[1440px] space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h2 className="text-base font-semibold text-stone-800">NS 黑名单命中</h2>
          <p className="mt-0.5 text-xs text-stone-400">
            完全离线的黑名单导入与版本管理。<b className="text-stone-500">命中本身是风险线索</b>——仅当高可信名单、当前仍生效且拨测确认影响时，才升级为严重。
          </p>
        </div>
        <label className={cn(
          'inline-flex items-center gap-1.5 rounded-md border border-stone-200 bg-white px-3 py-1.5 text-xs',
          canOperate ? 'cursor-pointer text-stone-600 hover:bg-stone-50' : 'cursor-not-allowed text-stone-300',
        )}>
          <Upload size={13} /> 离线导入名单
          <input type="file" accept=".csv,text/csv" className="hidden" disabled={!canOperate} onChange={async (event) => {
            const file = event.target.files?.[0]
            if (!file) return
            setUploadMessage('正在校验并导入…')
            try {
              if (resource.useMock) throw new Error('开发预览模式不执行文件导入')
              const result = await api.uploadBlacklist(file)
              setUploadMessage(`已导入 ${result.source?.name ?? result.name ?? file.name} ${result.source?.version ?? result.version ?? ''}${result.warning ? `；${result.warning}` : ''}`)
              sourceResource.retry()
            } catch (error) {
              setUploadMessage(error instanceof Error ? error.message : String(error))
            } finally {
              event.target.value = ''
            }
          }} />
        </label>
      </div>
      {!canOperate && <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-700">当前账号为只读角色，离线名单导入需要 DNS 运维或安全管理员权限。</div>}
      {uploadMessage && <div className="rounded-md border border-stone-200 bg-white px-3 py-2 text-xs text-stone-600">{uploadMessage}</div>}

      {/* 名单库版本 */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {sources.map((s) => (
          <div key={s.name} className={cn('rounded-lg border bg-white px-3 py-2.5 shadow-[0_1px_2px_rgba(0,0,0,0.04)]',
            s.state === 'expired' ? 'border-amber-300' : 'border-stone-200')}>
            <div className="flex items-center justify-between gap-2">
              <span className="truncate font-mono text-xs font-medium text-stone-700">{s.name}</span>
              <span className={cn('rounded border px-1.5 py-0.5 text-[10px]', CONF_TONE[confidenceLabel(s.confidence)])}>可信度 {confidenceLabel(s.confidence)}</span>
            </div>
            <div className="mt-1 flex items-center gap-2 text-[11px] text-stone-400">
              <span title={s.sha256 ? `SHA-256 ${s.sha256}` : undefined}>版本 {s.version}</span>
              <span>·</span>
              <span>{s.entries.toLocaleString()} 条</span>
            </div>
            <div className="mt-1 flex items-center gap-1.5 text-[11px]">
              {s.state === 'expired'
                ? <><AlertTriangle size={12} className="text-amber-500" /><span className="text-amber-700">已过期 · 更新于 {s.updatedAt.slice(0, 10)}</span></>
                : <><CheckCircle2 size={12} className="text-emerald-500" /><span className="text-stone-500">更新于 {s.updatedAt.slice(0, 10)}</span></>}
            </div>
          </div>
        ))}
      </div>
      {sourceResource.error && <StateBanner kind="query_failed" compact />}
      {sourceResource.data?.warning && <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-700">{sourceResource.data.warning}</div>}
      {sources.some((s) => s.state === 'expired') && <StateBanner kind="blacklist_expired" compact />}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card pad={false} title="命中事件" className="xl:col-span-1">
          <div className="border-b border-stone-100 px-3 py-2.5"><EventFilterBar showType={false} /></div>
          {resource.loading && !resource.data ? <StateBanner kind="loading" /> : resource.error ? <StateBanner kind="query_failed" /> : filtered.length === 0 ? <EmptyState desc="当前筛选条件下没有黑名单命中事件。" /> : (
            <ul className="divide-y divide-stone-50">
              {filtered.sort((a, b) => (a.lastSeen < b.lastSeen ? 1 : -1)).map((e) => (
                <li key={e.id} onClick={() => setSelected(e.id)}
                  className={cn('cursor-pointer px-3 py-2.5 hover:bg-stone-50', selected === e.id && 'border-l-2 border-cyan-600 bg-cyan-50/40')}>
                  <div className="flex items-center gap-2">
                    <LevelBadge level={e.level} />
                    <button className="truncate font-mono text-xs text-cyan-800 hover:underline"
                      onClick={(ev) => { ev.stopPropagation(); navigate(`/event/${e.id}`) }}>{e.domain}</button>
                    {!!e.extra?.whitelisted && <span className="rounded border border-stone-200 bg-stone-50 px-1 py-px text-[10px] text-stone-400">白名单</span>}
                  </div>
                  <div className="mt-1 line-clamp-2 text-[11px] leading-4 text-stone-400">{e.summary}</div>
                  <div className="mt-1 flex items-center gap-2">
                    <StatusBadge status={e.status} />
                    <span className="text-[10px] text-stone-400">{fmtDuration(e.durationMin)}</span>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>

        {sel && (
          <div className="space-y-4 xl:col-span-2">
            <Card title={<span>命中对象与规则 — <span className="font-mono font-normal">{sel.domain}</span></span>}>
              {hits.map((h, i) => (
                <div key={i} className="rounded-md border border-stone-200 p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded bg-stone-800 px-2 py-0.5 font-mono text-xs text-white">{h.object}</span>
                    <span className="rounded border border-stone-200 px-1.5 py-0.5 text-[11px] text-stone-600">{h.rule}</span>
                    <span className={cn('rounded border px-1.5 py-0.5 text-[11px]', CONF_TONE[h.confidence])}>可信度 {h.confidence}</span>
                    <span className="rounded border border-red-200 bg-red-50 px-1.5 py-0.5 text-[11px] text-red-700">{h.category}</span>
                  </div>
                  <div className="mt-2 grid grid-cols-2 gap-x-6 gap-y-1.5 text-xs sm:grid-cols-3">
                    <div><span className="text-stone-400">名单来源：</span><span className="font-mono">{h.source}</span></div>
                    <div><span className="text-stone-400">名单版本：</span><span className="font-mono">{h.version}</span></div>
                    <div><span className="text-stone-400">生效 → 过期：</span><span className="tabular-nums">{h.effective} → {h.expire}</span></div>
                  </div>
                  <div className="mt-2 text-xs text-stone-500"><span className="text-stone-400">原始描述：</span>{h.desc}</div>
                  {h.note && <div className="mt-1 text-xs text-stone-500"><span className="text-stone-400">本地备注：</span>{h.note}</div>}
                </div>
              ))}
            </Card>

            <Card title="影响判定">
              <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-xs sm:grid-cols-2">
                <div className="flex justify-between gap-2 border-b border-stone-50 pb-2">
                  <dt className="text-stone-400">当前是否仍在使用该 NS</dt>
                  <dd className={stillInUse ? 'font-medium text-red-700' : 'text-stone-700'}>{stillInUse ? '是' : '否'}</dd>
                </div>
                <div className="flex justify-between gap-2 border-b border-stone-50 pb-2">
                  <dt className="text-stone-400">是否存在可信权威结果</dt>
                  <dd className="text-stone-700">{sel.extra?.hasTrustedAnswer ? '是' : '否'}</dd>
                </div>
                <div className="flex justify-between gap-2 border-b border-stone-50 pb-2">
                  <dt className="text-stone-400">是否已对递归产生实际影响</dt>
                  <dd className={sel.evidence === 'impact_confirmed' ? 'font-medium text-red-700' : 'text-stone-700'}>
                    {sel.evidence === 'impact_confirmed' ? '是（拨测确认）' : '未确认 / 无影响'}
                  </dd>
                </div>
                <div className="flex justify-between gap-2 border-b border-stone-50 pb-2">
                  <dt className="text-stone-400">白名单 / 例外状态</dt>
                  <dd className="text-stone-700">{whitelisted ? '已豁免' : '无'}</dd>
                </div>
              </dl>
              {whitelisted && sel.whitelistReason && (
                <p className="mt-2 rounded-md bg-stone-50 px-3 py-2 text-xs text-stone-500">{sel.whitelistReason}</p>
              )}
              {sel.affectedCount > 0 && (
                <p className="mt-2 text-xs text-stone-500">
                  <Ban size={12} className="mr-1 inline text-red-500" />
                  受影响域名与 CNAME 名称共 <b className="text-red-700 tabular-nums">{sel.affectedCount}</b> 个，详见
                  <button className="ml-1 text-cyan-700 hover:underline" onClick={() => navigate(`/event/${sel.id}`)}>事件证据详情</button>。
                </p>
              )}
            </Card>
          </div>
        )}
      </div>
    </div>
  )
}
