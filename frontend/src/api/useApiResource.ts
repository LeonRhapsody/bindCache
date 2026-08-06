import { useEffect, useState } from 'react'

export interface ApiResource<T> {
  data: T | null
  error: Error | null
  loading: boolean
  retry: () => void
}

export function useApiResource<T>(loader: (signal: AbortSignal) => Promise<T>, dependencies: readonly unknown[]): ApiResource<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<Error | null>(null)
  const [loading, setLoading] = useState(true)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    queueMicrotask(() => {
      if (!controller.signal.aborted) {
        setLoading(true)
        setError(null)
      }
    })
    loader(controller.signal)
      .then((value) => {
        if (!controller.signal.aborted) setData(value)
      })
      .catch((reason: unknown) => {
        if (!controller.signal.aborted) setError(reason instanceof Error ? reason : new Error(String(reason)))
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false)
      })
    return () => controller.abort()
    // loader is deliberately represented by explicit primitive dependencies.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...dependencies, attempt])

  return { data, error, loading, retry: () => setAttempt((value) => value + 1) }
}
