import { useState } from 'react'
import { Search } from 'lucide-react'
import { Card, EmptyState, StateBanner } from '@/components/kit'
import { api } from '@/api/client'
import { useApiResource } from '@/api/useApiResource'
import { useHashRoute } from '@/lib/router'
import { EVENTS } from '@/data/mock'

export default function DomainLookup() {
  const [, navigate] = useHashRoute()
  const [query, setQuery] = useState('')
  const useMock = import.meta.env.VITE_USE_MOCK_DATA === 'true'
  const resource = useApiResource<{ domains: string[] }>(
    (signal) => {
      const term = query.trim()
      if (term.length < 2) return Promise.resolve({ domains: [] })
      if (useMock) {
        const domains = [...new Set(EVENTS.map((event) => event.domain))]
          .filter((domain) => domain.toLowerCase().includes(term.toLowerCase()))
          .slice(0, 50)
        return Promise.resolve({ domains })
      }
      return api.domains(term, signal)
    },
    [query, useMock],
  )
  const domains = resource.data?.domains ?? []
  const open = () => {
    const domain = query.trim()
    if (domain) navigate(`/domain/${encodeURIComponent(domain)}`)
  }

  return (
    <div className="mx-auto max-w-[1100px] space-y-4">
      <div>
        <h2 className="text-base font-semibold text-stone-800">域名追溯</h2>
        <p className="mt-0.5 text-xs text-stone-400">检索已观测域名，查看权威基线、最新状态、关联事件和受影响名称。</p>
      </div>
      <Card>
        <div className="flex gap-2">
          <div className="relative min-w-0 flex-1">
            <Search size={14} className="absolute left-3 top-2.5 text-stone-400" />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={(event) => { if (event.key === 'Enter') open() }}
              placeholder="输入域名，至少 2 个字符"
              className="h-9 w-full rounded-md border border-stone-200 bg-white pl-9 pr-3 text-sm outline-none focus:border-cyan-500"
            />
          </div>
          <button onClick={open} disabled={!query.trim()} className="rounded-md bg-cyan-600 px-4 text-xs text-white hover:bg-cyan-700 disabled:cursor-not-allowed disabled:bg-stone-300">查询</button>
        </div>
      </Card>
      {resource.error ? <StateBanner kind="query_failed" /> : resource.loading ? <StateBanner kind="loading" compact /> : query.trim().length < 2 ? (
        <EmptyState desc="输入域名后开始检索。" />
      ) : domains.length === 0 ? (
        <EmptyState desc="未找到已观测域名；仍可点击“查询”检查完整详情。" />
      ) : (
        <Card title={`匹配域名（${domains.length}）`} pad={false}>
          <ul className="divide-y divide-stone-100">
            {domains.map((domain) => (
              <li key={domain}>
                <button onClick={() => navigate(`/domain/${encodeURIComponent(domain)}`)} className="w-full px-4 py-2.5 text-left font-mono text-xs text-cyan-700 hover:bg-cyan-50/50 hover:underline">{domain}</button>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  )
}
