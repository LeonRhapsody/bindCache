import { createContext, useContext } from 'react'
import type { ReactNode } from 'react'
import type { SessionInfo } from '@/domain/risk'
import { api } from './client'
import { useApiResource } from './useApiResource'

interface SessionState {
  session: SessionInfo | null
  loading: boolean
  error: Error | null
}

const SessionContext = createContext<SessionState>({ session: null, loading: true, error: null })

export function SessionProvider({ children }: { children: ReactNode }) {
  const useMock = import.meta.env.VITE_USE_MOCK_DATA === 'true'
  const resource = useApiResource<SessionInfo>(
    (signal) => useMock
      ? Promise.resolve({ authenticated: true, username: 'preview-admin', role: 'admin', canOperate: true, canAdmin: true })
      : api.session(signal),
    [useMock],
  )
  return <SessionContext.Provider value={{ session: resource.data, loading: resource.loading, error: resource.error }}>{children}</SessionContext.Provider>
}

export function useSession() {
  return useContext(SessionContext)
}
