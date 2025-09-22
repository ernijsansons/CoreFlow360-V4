/**
 * Cache Client Service
 * Frontend interface for intelligent caching with request deduplication
 */

import { toast } from 'sonner'

export interface CacheOptions {
  ttl?: number
  tags?: string[]
  invalidateOn?: string[]
  compression?: boolean
  priority?: 'low' | 'medium' | 'high' | 'critical'
  staleWhileRevalidate?: boolean
  background?: boolean
}

export interface CacheKey {
  widget_id?: string
  dashboard_id?: string
  filters?: Record<string, any>
  date_range?: { from: Date; to: Date }
  aggregation?: string
  user_id?: string
  [key: string]: any
}

interface RequestState {
  promise: Promise<any>
  timestamp: number
  subscribers: Array<(data: any) => void>
}

export class CacheClient {
  private baseURL: string
  private authToken: string | null = null
  private requestCache = new Map<string, any>()
  private requestQueue = new Map<string, RequestState>()
  private invalidationListeners = new Map<string, Set<() => void>>()

  constructor() {
    this.baseURL = process.env.NEXT_PUBLIC_API_URL || '/api'

    // Listen for cache invalidation events via WebSocket
    this.setupInvalidationListener()
  }

  setAuthToken(token: string) {
    this.authToken = token
  }

  // Main cache get method with intelligent features
  async get<T = any>(
    key: string | CacheKey,
    fetcher: () => Promise<T>,
    options: CacheOptions = {}
  ): Promise<T> {
    const cacheKey = this.buildCacheKey(key)
    const now = Date.now()

    try {
      // Check local cache first
      const cached = this.requestCache.get(cacheKey)
      if (cached && this.isValidCache(cached, options.ttl)) {
        // Background revalidation
        if (options.staleWhileRevalidate && this.shouldRevalidate(cached)) {
          this.revalidateInBackground(cacheKey, fetcher, options)
        }
        return cached.data
      }

      // Check for ongoing request to prevent duplicate fetches
      const ongoing = this.requestQueue.get(cacheKey)
      if (ongoing) {
        return new Promise((resolve) => {
          ongoing.subscribers.push(resolve)
        })
      }

      // Start new request
      const requestPromise = this.fetchWithRetry(cacheKey, fetcher, options)

      this.requestQueue.set(cacheKey, {
        promise: requestPromise,
        timestamp: now,
        subscribers: []
      })

      const result = await requestPromise

      // Cache the result
      this.requestCache.set(cacheKey, {
        data: result,
        timestamp: now,
        ttl: options.ttl || 300000, // 5 minutes default
        tags: options.tags || [],
        key: cacheKey
      })

      // Notify subscribers
      const request = this.requestQueue.get(cacheKey)
      if (request) {
        request.subscribers.forEach(callback => callback(result))
        this.requestQueue.delete(cacheKey)
      }

      // Send to server cache if not background request
      if (!options.background) {
        this.sendToServerCache(cacheKey, result, options)
      }

      return result

    } catch (error) {
      // Remove failed request from queue
      this.requestQueue.delete(cacheKey)

      // Return stale data if available
      const cached = this.requestCache.get(cacheKey)
      if (cached && options.staleWhileRevalidate) {
        console.warn('Returning stale data due to fetch error:', error)
        return cached.data
      }

      throw error
    }
  }

  // Specialized cache methods for common dashboard patterns
  async getWidgetData<T = any>(
    widgetId: string,
    filters: Record<string, any> = {},
    fetcher: () => Promise<T>,
    options: CacheOptions = {}
  ): Promise<T> {
    const key: CacheKey = {
      widget_id: widgetId,
      filters,
      user_id: this.getCurrentUserId()
    }

    return this.get(key, fetcher, {
      ttl: 300000, // 5 minutes
      tags: [`widget:${widgetId}`, 'widget-data'],
      invalidateOn: ['data_update', 'filter_change'],
      staleWhileRevalidate: true,
      ...options
    })
  }

  async getDashboardLayout<T = any>(
    dashboardId: string,
    fetcher: () => Promise<T>,
    options: CacheOptions = {}
  ): Promise<T> {
    const key: CacheKey = {
      dashboard_id: dashboardId,
      type: 'layout'
    }

    return this.get(key, fetcher, {
      ttl: 3600000, // 1 hour
      tags: [`dashboard:${dashboardId}`, 'layout'],
      invalidateOn: ['layout_change', 'widget_add', 'widget_remove'],
      ...options
    })
  }

  async getAggregatedData<T = any>(
    dataSource: string,
    aggregation: string,
    dateRange: { from: Date; to: Date },
    filters: Record<string, any>,
    fetcher: () => Promise<T>,
    options: CacheOptions = {}
  ): Promise<T> {
    const key: CacheKey = {
      data_source: dataSource,
      aggregation,
      date_range: dateRange,
      filters
    }

    return this.get(key, fetcher, {
      ttl: 1800000, // 30 minutes
      tags: [`datasource:${dataSource}`, 'aggregated-data'],
      invalidateOn: ['data_update', 'aggregation_change'],
      compression: true,
      priority: 'critical',
      staleWhileRevalidate: true,
      ...options
    })
  }

  async getUserPreferences<T = any>(
    userId: string,
    fetcher: () => Promise<T>,
    options: CacheOptions = {}
  ): Promise<T> {
    const key: CacheKey = {
      user_id: userId,
      type: 'preferences'
    }

    return this.get(key, fetcher, {
      ttl: 86400000, // 24 hours
      tags: [`user:${userId}`, 'preferences'],
      invalidateOn: ['preference_change'],
      ...options
    })
  }

  // Cache invalidation
  async invalidate(pattern: string | string[], options: {
    cascade?: boolean
    reason?: string
  } = {}): Promise<void> {
    const patterns = Array.isArray(pattern) ? pattern : [pattern]

    // Local cache invalidation
    for (const pat of patterns) {
      const keysToRemove = Array.from(this.requestCache.keys()).filter(key =>
        this.matchesPattern(key, pat)
      )

      keysToRemove.forEach(key => {
        this.requestCache.delete(key)
      })

      // Notify listeners
      const listeners = this.invalidationListeners.get(pat)
      if (listeners) {
        listeners.forEach(callback => callback())
      }
    }

    // Server cache invalidation
    try {
      await fetch(`${this.baseURL}/cache/invalidate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(this.authToken && { 'Authorization': `Bearer ${this.authToken}` })
        },
        body: JSON.stringify({
          patterns,
          cascade: options.cascade,
          reason: options.reason
        })
      })
    } catch (error) {
      console.error('Server cache invalidation failed:', error)
    }
  }

  // Cache warming
  async warmCache(keys: Array<{ key: CacheKey; fetcher: () => Promise<any>; options?: CacheOptions }>): Promise<void> {
    const promises = keys.map(({ key, fetcher, options }) =>
      this.get(key, fetcher, { ...options, background: true }).catch(console.error)
    )

    await Promise.allSettled(promises)
  }

  // Smart prefetching based on user behavior
  async prefetchLikelyData(context: {
    currentWidget?: string
    currentDashboard?: string
    userRole?: string
    timeOfDay?: number
  }): Promise<void> {
    try {
      const predictions = await this.getPrefetchPredictions(context)

      // Prefetch in background
      const prefetchPromises = predictions.map(prediction =>
        this.get(prediction.key, prediction.fetcher, {
          ...prediction.options,
          background: true,
          priority: 'low'
        }).catch(console.error)
      )

      await Promise.allSettled(prefetchPromises)
    } catch (error) {
      console.error('Prefetch failed:', error)
    }
  }

  // Mutation with optimistic updates
  async mutate<T = any>(
    key: string | CacheKey,
    updater: (current: T) => T | Promise<T>,
    options: {
      optimistic?: boolean
      revalidate?: boolean
      rollbackOnError?: boolean
    } = {}
  ): Promise<T> {
    const cacheKey = this.buildCacheKey(key)
    const current = this.requestCache.get(cacheKey)

    if (options.optimistic && current) {
      try {
        const optimisticData = await updater(current.data)

        // Apply optimistic update
        this.requestCache.set(cacheKey, {
          ...current,
          data: optimisticData,
          optimistic: true
        })

        // Trigger UI update
        this.notifySubscribers(cacheKey, optimisticData)

        return optimisticData
      } catch (error) {
        // Rollback on error
        if (options.rollbackOnError) {
          this.requestCache.set(cacheKey, current)
          this.notifySubscribers(cacheKey, current.data)
        }
        throw error
      }
    }

    // Regular mutation
    const newData = current ? await updater(current.data) : await updater(null as any)

    this.requestCache.set(cacheKey, {
      data: newData,
      timestamp: Date.now(),
      ttl: current?.ttl || 300000,
      tags: current?.tags || [],
      key: cacheKey
    })

    // Revalidate if needed
    if (options.revalidate) {
      // Trigger server revalidation
      await this.revalidateServerCache(cacheKey)
    }

    return newData
  }

  // Subscribe to cache changes
  onInvalidate(pattern: string, callback: () => void): () => void {
    if (!this.invalidationListeners.has(pattern)) {
      this.invalidationListeners.set(pattern, new Set())
    }

    this.invalidationListeners.get(pattern)!.add(callback)

    // Return unsubscribe function
    return () => {
      const listeners = this.invalidationListeners.get(pattern)
      if (listeners) {
        listeners.delete(callback)
        if (listeners.size === 0) {
          this.invalidationListeners.delete(pattern)
        }
      }
    }
  }

  // Get cache statistics
  async getStats(): Promise<any> {
    try {
      const response = await fetch(`${this.baseURL}/cache/stats`, {
        headers: {
          ...(this.authToken && { 'Authorization': `Bearer ${this.authToken}` })
        }
      })

      return await response.json()
    } catch (error) {
      console.error('Failed to get cache stats:', error)
      return null
    }
  }

  // Clear all cache
  async clearCache(): Promise<void> {
    this.requestCache.clear()
    this.requestQueue.clear()

    try {
      await fetch(`${this.baseURL}/cache/clear`, {
        method: 'POST',
        headers: {
          ...(this.authToken && { 'Authorization': `Bearer ${this.authToken}` })
        }
      })
    } catch (error) {
      console.error('Failed to clear server cache:', error)
    }
  }

  // Helper methods
  private buildCacheKey(key: string | CacheKey): string {
    if (typeof key === 'string') {
      return key
    }

    // Build deterministic key from object
    const parts = []
    const sortedKeys = Object.keys(key).sort()

    for (const k of sortedKeys) {
      const value = key[k]
      if (value !== undefined && value !== null) {
        if (typeof value === 'object') {
          parts.push(`${k}:${JSON.stringify(value)}`)
        } else {
          parts.push(`${k}:${value}`)
        }
      }
    }

    return parts.join('|')
  }

  private isValidCache(cached: any, ttl?: number): boolean {
    const maxAge = ttl || cached.ttl || 300000
    return (Date.now() - cached.timestamp) < maxAge
  }

  private shouldRevalidate(cached: any): boolean {
    const age = Date.now() - cached.timestamp
    const halfLife = cached.ttl / 2
    return age > halfLife
  }

  private async fetchWithRetry<T>(
    key: string,
    fetcher: () => Promise<T>,
    options: CacheOptions,
    attempt = 1
  ): Promise<T> {
    try {
      return await fetcher()
    } catch (error) {
      if (attempt < 3) {
        // Exponential backoff
        const delay = Math.pow(2, attempt) * 1000
        await new Promise(resolve => setTimeout(resolve, delay))
        return this.fetchWithRetry(key, fetcher, options, attempt + 1)
      }
      throw error
    }
  }

  private async revalidateInBackground(
    key: string,
    fetcher: () => Promise<any>,
    options: CacheOptions
  ): Promise<void> {
    try {
      const result = await fetcher()

      this.requestCache.set(key, {
        data: result,
        timestamp: Date.now(),
        ttl: options.ttl || 300000,
        tags: options.tags || [],
        key
      })

      this.notifySubscribers(key, result)
    } catch (error) {
      console.error('Background revalidation failed:', error)
    }
  }

  private async sendToServerCache(
    key: string,
    data: any,
    options: CacheOptions
  ): Promise<void> {
    try {
      await fetch(`${this.baseURL}/cache/set`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(this.authToken && { 'Authorization': `Bearer ${this.authToken}` })
        },
        body: JSON.stringify({
          key,
          data,
          options
        })
      })
    } catch (error) {
      // Fail silently for server cache
      console.debug('Server cache update failed:', error)
    }
  }

  private async revalidateServerCache(key: string): Promise<void> {
    try {
      await fetch(`${this.baseURL}/cache/revalidate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(this.authToken && { 'Authorization': `Bearer ${this.authToken}` })
        },
        body: JSON.stringify({ key })
      })
    } catch (error) {
      console.error('Server cache revalidation failed:', error)
    }
  }

  private matchesPattern(key: string, pattern: string): boolean {
    if (pattern.includes('*')) {
      const regex = new RegExp(pattern.replace(/\*/g, '.*'))
      return regex.test(key)
    }
    return key.includes(pattern)
  }

  private notifySubscribers(key: string, data: any): void {
    // Emit custom event for React components to listen to
    window.dispatchEvent(new CustomEvent('cache-update', {
      detail: { key, data }
    }))
  }

  private getCurrentUserId(): string {
    // Get from auth context or localStorage
    return localStorage.getItem('userId') || 'anonymous'
  }

  private async getPrefetchPredictions(context: any): Promise<any[]> {
    try {
      const response = await fetch(`${this.baseURL}/cache/predictions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(this.authToken && { 'Authorization': `Bearer ${this.authToken}` })
        },
        body: JSON.stringify(context)
      })

      const data = await response.json()
      return data.predictions || []
    } catch (error) {
      console.error('Failed to get prefetch predictions:', error)
      return []
    }
  }

  private setupInvalidationListener(): void {
    // WebSocket connection for real-time cache invalidation
    if (typeof window !== 'undefined') {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const ws = new WebSocket(`${protocol}//${window.location.host}/api/cache/invalidations`)

      ws.onmessage = (event) => {
        try {
          const { type, pattern } = JSON.parse(event.data)

          if (type === 'invalidate') {
            this.invalidate(pattern, { reason: 'server_broadcast' })
          }
        } catch (error) {
          console.error('Failed to process cache invalidation message:', error)
        }
      }

      ws.onerror = () => {
        // Reconnect logic would go here
        console.debug('Cache invalidation WebSocket disconnected')
      }
    }
  }
}

// Export singleton instance
export const cacheClient = new CacheClient()

// React hook for cache integration
export const useCache = <T = any>(
  key: string | CacheKey,
  fetcher: () => Promise<T>,
  options: CacheOptions = {}
) => {
  const [data, setData] = React.useState<T | null>(null)
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<Error | null>(null)

  const cacheKey = typeof key === 'string' ? key : JSON.stringify(key)

  React.useEffect(() => {
    let mounted = true

    const loadData = async () => {
      try {
        setLoading(true)
        const result = await cacheClient.get(key, fetcher, options)

        if (mounted) {
          setData(result)
          setError(null)
        }
      } catch (err) {
        if (mounted) {
          setError(err instanceof Error ? err : new Error('Cache fetch failed'))
        }
      } finally {
        if (mounted) {
          setLoading(false)
        }
      }
    }

    loadData()

    // Listen for cache updates
    const handleCacheUpdate = (event: CustomEvent) => {
      if (event.detail.key === cacheKey) {
        setData(event.detail.data)
      }
    }

    window.addEventListener('cache-update', handleCacheUpdate as EventListener)

    return () => {
      mounted = false
      window.removeEventListener('cache-update', handleCacheUpdate as EventListener)
    }
  }, [cacheKey])

  const mutate = React.useCallback((updater: (current: T) => T | Promise<T>, mutateOptions = {}) => {
    return cacheClient.mutate(key, updater, mutateOptions)
  }, [key])

  const revalidate = React.useCallback(() => {
    cacheClient.invalidate(cacheKey)
  }, [cacheKey])

  return {
    data,
    loading,
    error,
    mutate,
    revalidate
  }
}