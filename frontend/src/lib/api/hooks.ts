import { useEffect, useState, useCallback, useRef } from 'react'
import { useCacheStore } from '@/stores/cache-store'
import apiClient, { ApiResponse, ApiRequestOptions } from './client'

export interface UseApiOptions extends ApiRequestOptions {
  cache?: boolean
  cacheTime?: number
  refetchInterval?: number
  refetchOnFocus?: boolean
  refetchOnReconnect?: boolean
  enabled?: boolean
  onSuccess?: (data: any) => void
  onError?: (error: any) => void
  optimisticUpdate?: (currentData: any) => any
}

export interface UseApiResult<T = any> {
  data: T | null
  error: any | null
  loading: boolean
  refetch: () => Promise<void>
  mutate: (newData: T) => void
}

export function useApi<T = any>(
  endpoint: string,
  options: UseApiOptions = {}
): UseApiResult<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<any | null>(null)
  const [loading, setLoading] = useState(false)
  const abortControllerRef = useRef<AbortController | null>(null)
  const { getCache, setCache } = useCacheStore()

  const {
    cache = true,
    cacheTime = 5 * 60 * 1000, // 5 minutes
    refetchInterval,
    refetchOnFocus = true,
    refetchOnReconnect = true,
    enabled = true,
    onSuccess,
    onError,
    ...requestOptions
  } = options

  const fetchData = useCallback(async () => {
    if (!enabled) return

    // Check cache first
    if (cache) {
      const cachedData = getCache(endpoint)
      if (cachedData) {
        setData(cachedData)
        return
      }
    }

    // Abort previous request
    if (abortControllerRef.current) {
      abortControllerRef.current.abort()
    }

    abortControllerRef.current = new AbortController()
    setLoading(true)
    setError(null)

    try {
      const response: ApiResponse<T> = await apiClient.get<T>(endpoint, {
        ...requestOptions,
        signal: abortControllerRef.current.signal,
      })

      if (response.success && response.data) {
        setData(response.data)

        if (cache) {
          setCache(endpoint, response.data, cacheTime)
        }

        onSuccess?.(response.data)
      } else {
        setError(response.error)
        onError?.(response.error)
      }
    } catch (err: any) {
      if (err.name !== 'AbortError') {
        setError(err)
        onError?.(err)
      }
    } finally {
      setLoading(false)
    }
  }, [endpoint, enabled, cache, cacheTime, onSuccess, onError])

  const refetch = useCallback(async () => {
    await fetchData()
  }, [fetchData])

  const mutate = useCallback((newData: T) => {
    setData(newData)
    if (cache) {
      setCache(endpoint, newData, cacheTime)
    }
  }, [endpoint, cache, cacheTime])

  // Initial fetch
  useEffect(() => {
    fetchData()

    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort()
      }
    }
  }, [fetchData])

  // Refetch interval
  useEffect(() => {
    if (!refetchInterval || !enabled) return

    const interval = setInterval(refetch, refetchInterval)
    return () => clearInterval(interval)
  }, [refetchInterval, refetch, enabled])

  // Refetch on focus
  useEffect(() => {
    if (!refetchOnFocus || !enabled) return

    const handleFocus = () => refetch()
    window.addEventListener('focus', handleFocus)
    return () => window.removeEventListener('focus', handleFocus)
  }, [refetchOnFocus, refetch, enabled])

  // Refetch on reconnect
  useEffect(() => {
    if (!refetchOnReconnect || !enabled) return

    const handleOnline = () => refetch()
    window.addEventListener('online', handleOnline)
    return () => window.removeEventListener('online', handleOnline)
  }, [refetchOnReconnect, refetch, enabled])

  return {
    data,
    error,
    loading,
    refetch,
    mutate,
  }
}

export interface UseMutationOptions<TData = any, TVariables = any>
  extends ApiRequestOptions {
  onSuccess?: (data: TData, variables: TVariables) => void
  onError?: (error: any, variables: TVariables) => void
  invalidateQueries?: string[]
}

export interface UseMutationResult<TData = any, TVariables = any> {
  mutate: (variables: TVariables) => Promise<void>
  mutateAsync: (variables: TVariables) => Promise<TData>
  data: TData | null
  error: any | null
  loading: boolean
  reset: () => void
}

export function useMutation<TData = any, TVariables = any>(
  mutationFn: (variables: TVariables) => Promise<ApiResponse<TData>>,
  options: UseMutationOptions<TData, TVariables> = {}
): UseMutationResult<TData, TVariables> {
  const [data, setData] = useState<TData | null>(null)
  const [error, setError] = useState<any | null>(null)
  const [loading, setLoading] = useState(false)
  const { invalidateCache } = useCacheStore()

  const { onSuccess, onError, invalidateQueries = [], ...requestOptions } = options

  const mutateAsync = useCallback(async (variables: TVariables): Promise<TData> => {
    setLoading(true)
    setError(null)

    try {
      const response = await mutationFn(variables)

      if (response.success && response.data) {
        setData(response.data)
        onSuccess?.(response.data, variables)

        // Invalidate related queries
        invalidateQueries.forEach(query => {
          invalidateCache(query)
        })

        return response.data
      } else {
        const err = response.error || new Error('Mutation failed')
        setError(err)
        onError?.(err, variables)
        throw err
      }
    } catch (err: any) {
      setError(err)
      onError?.(err, variables)
      throw err
    } finally {
      setLoading(false)
    }
  }, [mutationFn, onSuccess, onError, invalidateQueries])

  const mutate = useCallback(async (variables: TVariables): Promise<void> => {
    try {
      await mutateAsync(variables)
    } catch {
      // Error already handled in mutateAsync
    }
  }, [mutateAsync])

  const reset = useCallback(() => {
    setData(null)
    setError(null)
    setLoading(false)
  }, [])

  return {
    mutate,
    mutateAsync,
    data,
    error,
    loading,
    reset,
  }
}

// Pagination hook
export interface UsePaginatedApiOptions<T = any> extends UseApiOptions {
  page?: number
  limit?: number
  sort?: string
  filter?: Record<string, any>
}

export interface UsePaginatedApiResult<T = any> extends UseApiResult<T[]> {
  page: number
  limit: number
  total: number
  hasMore: boolean
  nextPage: () => void
  prevPage: () => void
  setPage: (page: number) => void
  setLimit: (limit: number) => void
}

export function usePaginatedApi<T = any>(
  baseEndpoint: string,
  options: UsePaginatedApiOptions<T> = {}
): UsePaginatedApiResult<T> {
  const [page, setPage] = useState(options.page || 1)
  const [limit, setLimit] = useState(options.limit || 20)
  const [total, setTotal] = useState(0)
  const [hasMore, setHasMore] = useState(false)

  const endpoint = `${baseEndpoint}?page=${page}&limit=${limit}${
    options.sort ? `&sort=${options.sort}` : ''
  }${options.filter ? `&filter=${JSON.stringify(options.filter)}` : ''}`

  const result = useApi<any>(endpoint, {
    ...options,
    onSuccess: (response) => {
      if (response.metadata?.pagination) {
        setTotal(response.metadata.pagination.total)
        setHasMore(response.metadata.pagination.hasMore)
      }
      options.onSuccess?.(response.data || response)
    },
  })

  const nextPage = useCallback(() => {
    if (hasMore) {
      setPage(prev => prev + 1)
    }
  }, [hasMore])

  const prevPage = useCallback(() => {
    if (page > 1) {
      setPage(prev => prev - 1)
    }
  }, [page])

  return {
    ...result,
    data: result.data?.data || result.data || [],
    page,
    limit,
    total,
    hasMore,
    nextPage,
    prevPage,
    setPage,
    setLimit,
  }
}

// Infinite scroll hook
export interface UseInfiniteApiOptions<T = any> extends UseApiOptions {
  limit?: number
  getNextPageParam?: (lastPage: any) => any
}

export interface UseInfiniteApiResult<T = any> {
  data: T[]
  error: any | null
  loading: boolean
  hasMore: boolean
  loadMore: () => Promise<void>
  refetch: () => Promise<void>
  reset: () => void
}

export function useInfiniteApi<T = any>(
  baseEndpoint: string,
  options: UseInfiniteApiOptions<T> = {}
): UseInfiniteApiResult<T> {
  const [data, setData] = useState<T[]>([])
  const [error, setError] = useState<any | null>(null)
  const [loading, setLoading] = useState(false)
  const [hasMore, setHasMore] = useState(true)
  const [nextCursor, setNextCursor] = useState<any>(null)
  const { getCache, setCache } = useCacheStore()

  const {
    limit = 20,
    getNextPageParam = (lastPage) => lastPage?.metadata?.nextCursor,
    cache = true,
    cacheTime = 5 * 60 * 1000,
    onSuccess,
    onError,
    ...requestOptions
  } = options

  const loadMore = useCallback(async () => {
    if (loading || !hasMore) return

    setLoading(true)
    setError(null)

    try {
      const endpoint = `${baseEndpoint}?limit=${limit}${
        nextCursor ? `&cursor=${nextCursor}` : ''
      }`

      const response: ApiResponse<T[]> = await apiClient.get<T[]>(endpoint, requestOptions)

      if (response.success && response.data) {
        const newData = [...data, ...(response.data as any)]
        setData(newData)

        const nextParam = getNextPageParam(response)
        setNextCursor(nextParam)
        setHasMore(!!nextParam)

        if (cache) {
          setCache(baseEndpoint, newData, cacheTime)
        }

        onSuccess?.(response.data)
      } else {
        setError(response.error)
        onError?.(response.error)
      }
    } catch (err: any) {
      setError(err)
      onError?.(err)
    } finally {
      setLoading(false)
    }
  }, [data, loading, hasMore, nextCursor, limit, baseEndpoint, cache, cacheTime])

  const refetch = useCallback(async () => {
    setData([])
    setNextCursor(null)
    setHasMore(true)
    await loadMore()
  }, [])

  const reset = useCallback(() => {
    setData([])
    setError(null)
    setLoading(false)
    setHasMore(true)
    setNextCursor(null)
  }, [])

  // Initial load
  useEffect(() => {
    if (data.length === 0 && hasMore) {
      loadMore()
    }
  }, [])

  return {
    data,
    error,
    loading,
    hasMore,
    loadMore,
    refetch,
    reset,
  }
}