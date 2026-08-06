import { lazy, Suspense } from 'react'
import Layout from '@/components/Layout'
import { useHashRoute } from '@/lib/router'
import { SessionProvider } from '@/api/SessionContext'

const Overview = lazy(() => import('@/pages/Overview'))
const EventsPage = lazy(() => import('@/pages/Events'))
const EventDetail = lazy(() => import('@/pages/EventDetail'))
const NsChangePage = lazy(() => import('@/pages/NsChange'))
const NsRedundancyPage = lazy(() => import('@/pages/NsRedundancy'))
const NsParentChildPage = lazy(() => import('@/pages/NsParentChild'))
const NsBlacklistPage = lazy(() => import('@/pages/NsBlacklist'))
const NsHealthPage = lazy(() => import('@/pages/NsHealth'))
const CampaignsPage = lazy(() => import('@/pages/Campaigns'))
const DomainProfile = lazy(() => import('@/pages/DomainProfile'))
const DomainLookup = lazy(() => import('@/pages/DomainLookup'))
const ProbePage = lazy(() => import('@/pages/Probe'))
const AlertsPage = lazy(() => import('@/pages/Alerts'))
const SystemStatusPage = lazy(() => import('@/pages/SystemStatus'))
const SettingsPage = lazy(() => import('@/pages/Settings'))

export default function App() {
  const [route] = useHashRoute()
  const p = route.path

  let page: React.ReactNode
  if (p === '/events') page = <EventsPage />
  else if (p.startsWith('/event/')) page = <EventDetail id={decodeURIComponent(p.slice('/event/'.length))} />
  else if (p === '/ns-change') page = <NsChangePage />
  else if (p === '/ns-redundancy') page = <NsRedundancyPage />
  else if (p === '/ns-parent-child') page = <NsParentChildPage />
  else if (p === '/ns-blacklist') page = <NsBlacklistPage />
  else if (p === '/ns-health') page = <NsHealthPage />
  else if (p === '/campaigns') page = <CampaignsPage />
  else if (p === '/domain') page = <DomainLookup />
  else if (p.startsWith('/domain/')) page = <DomainProfile domain={decodeURIComponent(p.slice('/domain/'.length))} />
  else if (p === '/probe') page = <ProbePage />
  else if (p === '/alerts') page = <AlertsPage />
  else if (p === '/system') page = <SystemStatusPage />
  else if (p === '/settings') page = <SettingsPage />
  else page = <Overview />

  return (
    <SessionProvider>
      <Layout>
        <Suspense fallback={<div className="py-16 text-center text-sm text-stone-500">正在加载页面…</div>}>
          {page}
        </Suspense>
      </Layout>
    </SessionProvider>
  )
}
