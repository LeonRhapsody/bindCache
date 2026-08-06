import { EVENTS } from '@/data/mock'
import type { EvidenceLevel, EventStatus, EventsResponse, RiskLevel, RiskType } from '@/domain/risk'
import { api } from './client'
import { useApiResource } from './useApiResource'

export interface ScenarioFilters {
  level: RiskLevel | 'all'
  status: EventStatus | 'all'
  evidence: EvidenceLevel | 'all'
  q: string
}

export function useRiskEvents(type: RiskType, filters: ScenarioFilters) {
  const useMock = import.meta.env.VITE_USE_MOCK_DATA === 'true'
  const resource = useApiResource<EventsResponse>(
    (signal) => {
      if (useMock) {
        const items = EVENTS.filter((event) =>
          event.type === type &&
          (filters.level === 'all' || event.level === filters.level) &&
          (filters.status === 'all' || event.status === filters.status) &&
          (filters.evidence === 'all' || event.evidence === filters.evidence) &&
          (!filters.q || event.domain.includes(filters.q) || event.id.toLowerCase().includes(filters.q.toLowerCase())),
        )
        return Promise.resolve({ items, total: items.length, page: 1, limit: 100 })
      }
      return api.events({
        type,
        level: filters.level,
        status: filters.status,
        evidence: filters.evidence,
        q: filters.q,
        page: 1,
        limit: 100,
      }, signal)
    },
    [useMock, type, filters.level, filters.status, filters.evidence, filters.q],
  )
  return { ...resource, useMock }
}
