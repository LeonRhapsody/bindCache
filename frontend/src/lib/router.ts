import { useCallback, useEffect, useState } from 'react'

export interface Route {
  path: string // e.g. /events, /event/EVT-001
  query: URLSearchParams
}

function parseHash(): Route {
  const raw = window.location.hash.replace(/^#/, '') || '/overview'
  const [path, qs] = raw.split('?')
  return { path: path || '/overview', query: new URLSearchParams(qs || '') }
}

export function useHashRoute(): [Route, (to: string) => void] {
  const [route, setRoute] = useState<Route>(parseHash)

  useEffect(() => {
    const onChange = () => setRoute(parseHash())
    window.addEventListener('hashchange', onChange)
    return () => window.removeEventListener('hashchange', onChange)
  }, [])

  const navigate = useCallback((to: string) => {
    window.location.hash = to.startsWith('#') ? to.slice(1) : to
  }, [])

  return [route, navigate]
}

/** 更新当前 URL 的查询参数（写回 hash，刷新/前进后退不丢失） */
export function setQueryParams(updates: Record<string, string | null>) {
  const { path, query } = parseHash()
  Object.entries(updates).forEach(([k, v]) => {
    if (v === null || v === '' || v === 'all') query.delete(k)
    else query.set(k, v)
  })
  const qs = query.toString()
  window.location.hash = qs ? `${path}?${qs}` : path
}
