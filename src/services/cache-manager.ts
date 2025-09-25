/**
 * Intelligent Cache Manager
 * Multi-tier caching strategy using Cloudflare KV, D1, and Durable Objects
 */

import { DurableObject } from 'cloudflare:workers'

export interface CacheEntry {
  key: string
  data: any
  metadata: CacheMetadata
  timestamp: number
  ttl: number
  version: string
  dependencies: string[]
  tags: string[]
}

export interface CacheMetadata {
  widget_id?: string
  dashboard_id?: string
  user_id?: string
  data_source?: string
  query_hash?: string
  filters?: string
  date_range?: string
  aggregation_level?: string
  refresh_frequency?: number
  compression?: 'gzip' | 'brotli' | 'none'
  size_bytes?: number
  hit_count?: number
  last_accessed?: number
}

export interface CachePolicy {
  ttl: number
  max_size?: number
  eviction_strategy: 'lru' | 'lfu' | 'ttl' | 'custom'
  invalidation_triggers: string[]
  compression: boolean
  priority: 'low' | 'medium' | 'high' | 'critical'
  distributed: boolean
}

export interface CacheStats {
  hits: number
  misses: number
  evictions: number
  total_size: number
  entries_count: number
  hit_ratio: number
  avg_response_time: number
  popular_keys: string[]
}

export class CacheManager extends DurableObject {
  private storage: DurableObjectStorage
  private env: any
  private cache: Map<string, CacheEntry> = new Map()
  private stats: CacheStats = {
    hits: 0,
    misses: 0,
    evictions: 0,
    total_size: 0,
    entries_count: 0,
    hit_ratio: 0,
    avg_response_time: 0,
    popular_keys: []
  }

  // Cache policies for different data types
  private policies: Record<string, CachePolicy> = {
    'widget:kpi': {
      ttl: 300, // 5 minutes
      eviction_strategy: 'lru',
      invalidation_triggers: ['data_update', 'filter_change'],
      compression: true,
      priority: 'high',
      distributed: true
    },
    'widget:chart': {
      ttl: 600, // 10 minutes
      eviction_strategy: 'lru',
      invalidation_triggers: ['data_update', 'filter_change', 'date_range_change'],
      compression: true,
      priority: 'medium',
      distributed: true
    },
    'widget:table': {
      ttl: 180, // 3 minutes
      max_size: 1024 * 1024, // 1MB
      eviction_strategy: 'lfu',
      invalidation_triggers: ['data_update', 'filter_change', 'sort_change'],
      compression: true,
      priority: 'medium',
      distributed: false
    },
    'dashboard:layout': {
      ttl: 3600, // 1 hour
      eviction_strategy: 'ttl',
      invalidation_triggers: ['layout_change', 'widget_add', 'widget_remove'],
      compression: false,
      priority: 'high',
      distributed: true
    },
    'user:preferences': {
      ttl: 86400, // 24 hours
      eviction_strategy: 'ttl',
      invalidation_triggers: ['preference_change'],
      compression: false,
      priority: 'low',
      distributed: true
    },
    'data:aggregated': {
      ttl: 1800, // 30 minutes
      max_size: 5 * 1024 * 1024, // 5MB
      eviction_strategy: 'lru',
      invalidation_triggers: ['data_update', 'aggregation_change'],
      compression: true,
      priority: 'critical',
      distributed: true
    }
  }

  constructor(ctx: DurableObjectState, env: any) {
    super(ctx, env)
    this.storage = ctx.storage
    this.env = env
    this.loadCacheFromStorage()
  }

  // Load existing cache entries from Durable Object storage
  private async loadCacheFromStorage(): Promise<void> {
    try {
      const entries = await this.storage.list({ prefix: 'cache:' })
      for (const [key, value] of entries.entries()) {
        const cacheKey = key.replace('cache:', '')
        this.cache.set(cacheKey, value as CacheEntry)
      }

      // Load stats
      const savedStats = await this.storage.get('cache:stats')
      if (savedStats) {
        this.stats = { ...this.stats, ...savedStats }
      }
    } catch (error) {
    }
  }

  // Multi-tier cache get with intelligent fallback
  async get(key: string, options?: {
    bypass_memory?: boolean
    bypass_kv?: boolean
    track_analytics?: boolean
  }): Promise<any> {
    const startTime = Date.now()
    let result: any = null
    let source = 'miss'

    try {
      // Tier 1: Memory cache (fastest)
      if (!options?.bypass_memory && this.cache.has(key)) {
        const entry = this.cache.get(key)!

        if (this.isValid(entry)) {
          result = await this.decompressData(entry.data, entry.metadata.compression)
          source = 'memory'

          // Update access metadata
          entry.metadata.hit_count = (entry.metadata.hit_count || 0) + 1
          entry.metadata.last_accessed = Date.now()
          this.cache.set(key, entry)
        } else {
          // Remove expired entry
          this.cache.delete(key)
          await this.storage.delete(`cache:${key}`)
        }
      }

      // Tier 2: Cloudflare KV (regional)
      if (!result && !options?.bypass_kv) {
        const kvData = await this.env.CACHE_KV.get(key, { type: 'json' })
        if (kvData && this.isValidKVEntry(kvData)) {
          result = kvData.data
          source = 'kv'

          // Promote to memory cache
          await this.set(key, result, kvData.metadata)
        }
      }

      // Tier 3: D1 Database (global)
      if (!result) {
        const dbResult = await this.env.CACHE_DB.prepare(
          'SELECT data, metadata, timestamp, ttl FROM cache_entries WHERE key = ? AND (timestamp + ttl) > ?'
        ).bind(key, Date.now()).first()

        if (dbResult) {
          const data = JSON.parse(dbResult.data)
          const metadata = JSON.parse(dbResult.metadata)
          result = await this.decompressData(data, metadata.compression)
          source = 'database'

          // Promote to higher tiers
          await this.set(key, result, metadata)
        }
      }

      // Update statistics
      if (result) {
        this.stats.hits++
      } else {
        this.stats.misses++
      }

      this.stats.hit_ratio = this.stats.hits / (this.stats.hits + this.stats.misses)
      this.stats.avg_response_time = (this.stats.avg_response_time + (Date.now() - startTime)) / 2

      // Track analytics
      if (options?.track_analytics) {
        await this.trackCacheAnalytics(key, source, Date.now() - startTime)
      }

      return result

    } catch (error) {
      this.stats.misses++
      return null
    }
  }

  // Intelligent cache set with compression and distribution
  async set(key: string, data: any, metadata?: Partial<CacheMetadata>, options?: {
    force_refresh?: boolean
    skip_distribution?: boolean
    custom_ttl?: number
  }): Promise<void> {
    try {
      const policy = this.getCachePolicy(key)
      const ttl = options?.custom_ttl || policy.ttl
      const compressedData = policy.compression
        ? await this.compressData(data)
        : data

      const entry: CacheEntry = {
        key,
        data: compressedData,
        metadata: {
          compression: policy.compression ? 'gzip' : 'none',
          size_bytes: JSON.stringify(compressedData).length,
          hit_count: 0,
          last_accessed: Date.now(),
          ...metadata
        },
        timestamp: Date.now(),
        ttl: ttl * 1000, // Convert to milliseconds
        version: this.generateVersion(),
        dependencies: this.extractDependencies(key, metadata),
        tags: this.extractTags(key, metadata)
      }

      // Memory cache
      this.cache.set(key, entry)
      await this.storage.put(`cache:${key}`, entry)

      // Distributed caching
      if (policy.distributed && !options?.skip_distribution) {
        // KV for regional caching
        await this.env.CACHE_KV.put(key, JSON.stringify({
          data: compressedData,
          metadata: entry.metadata,
          timestamp: entry.timestamp,
          ttl: entry.ttl
        }), { expirationTtl: ttl })

        // D1 for global persistence
        await this.env.CACHE_DB.prepare(
          'INSERT OR REPLACE INTO cache_entries (key, data, metadata, timestamp, ttl, tags) VALUES (?, ?, ?, ?, ?, ?)'
        ).bind(
          key,
          JSON.stringify(compressedData),
          JSON.stringify(entry.metadata),
          entry.timestamp,
          entry.ttl,
          JSON.stringify(entry.tags)
        ).run()
      }

      // Update stats
      this.stats.entries_count = this.cache.size
      this.stats.total_size += entry.metadata.size_bytes || 0

      // Check for eviction
      await this.checkEviction()

    } catch (error) {
    }
  }

  // Intelligent cache invalidation
  async invalidate(pattern: string | string[], options?: {
    cascade?: boolean
    global?: boolean
    reason?: string
  }): Promise<number> {
    let invalidatedCount = 0

    try {
      const patterns = Array.isArray(pattern) ? pattern : [pattern]

      for (const pat of patterns) {
        // Memory cache invalidation
        const keysToInvalidate = Array.from(this.cache.keys()).filter(key =>
          this.matchesPattern(key, pat)
        )

        for (const key of keysToInvalidate) {
          this.cache.delete(key)
          await this.storage.delete(`cache:${key}`)
          invalidatedCount++

          // Cascade invalidation for dependent entries
          if (options?.cascade) {
            const dependentKeys = await this.findDependentKeys(key)
            for (const depKey of dependentKeys) {
              this.cache.delete(depKey)
              await this.storage.delete(`cache:${depKey}`)
              invalidatedCount++
            }
          }
        }

        // Global invalidation
        if (options?.global) {
          // KV invalidation
          const kvKeys = await this.env.CACHE_KV.list({ prefix: pat })
          for (const kvKey of kvKeys.keys) {
            await this.env.CACHE_KV.delete(kvKey.name)
          }

          // D1 invalidation
          await this.env.CACHE_DB.prepare(
            'DELETE FROM cache_entries WHERE key LIKE ?'
          ).bind(`${pat}%`).run()
        }
      }

      // Update stats
      this.stats.evictions += invalidatedCount
      this.stats.entries_count = this.cache.size

      // Log invalidation
      await this.logCacheOperation('invalidation', {
        patterns,
        count: invalidatedCount,
        reason: options?.reason || 'manual',
        cascade: options?.cascade || false,
        global: options?.global || false
      })

    } catch (error) {
    }

    return invalidatedCount
  }

  // Intelligent warming based on usage patterns
  async warmCache(strategies: ('popular' | 'predicted' | 'scheduled')[] = ['popular']): Promise<void> {
    try {
      for (const strategy of strategies) {
        switch (strategy) {
          case 'popular':
            await this.warmPopularEntries()
            break
          case 'predicted':
            await this.warmPredictedEntries()
            break
          case 'scheduled':
            await this.warmScheduledEntries()
            break
        }
      }
    } catch (error) {
    }
  }

  // Predictive cache warming based on user patterns
  private async warmPredictedEntries(): Promise<void> {
    // Analyze user access patterns
    const accessPatterns = await this.analyzeAccessPatterns()

    // Predict likely cache misses
    const predictions = await this.predictCacheMisses(accessPatterns)

    // Pre-warm predicted entries
    for (const prediction of predictions) {
      try {
        // Fetch data proactively
        const data = await this.fetchDataForKey(prediction.key)
        if (data) {
          await this.set(prediction.key, data, {
            query_hash: prediction.query_hash,
            refresh_frequency: prediction.frequency
          })
        }
      } catch (error) {
      }
    }
  }

  // Cache compression
  private async compressData(data: any): Promise<string> {
    try {
      const jsonString = JSON.stringify(data)
      const encoder = new TextEncoder()
      const uint8Array = encoder.encode(jsonString)

      // Use compression stream for large data
      if (uint8Array.length > 1024) {
        const cs = new CompressionStream('gzip')
        const writer = cs.writable.getWriter()
        const reader = cs.readable.getReader()

        writer.write(uint8Array)
        writer.close()

        const chunks = []
        let done = false

        while (!done) {
          const { value, done: readerDone } = await reader.read()
          done = readerDone
          if (value) chunks.push(value)
        }

        const compressed = new Uint8Array(chunks.reduce((acc, chunk) => acc + chunk.length, 0))
        let offset = 0
        for (const chunk of chunks) {
          compressed.set(chunk, offset)
          offset += chunk.length
        }

        return btoa(String.fromCharCode(...compressed))
      }

      return jsonString
    } catch (error) {
      return JSON.stringify(data)
    }
  }

  // Cache decompression
  private async decompressData(data: any, compression?: string): Promise<any> {
    try {
      if (compression === 'gzip') {
        const binaryString = atob(data)
        const uint8Array = new Uint8Array(binaryString.length)
        for (let i = 0; i < binaryString.length; i++) {
          uint8Array[i] = binaryString.charCodeAt(i)
        }

        const ds = new DecompressionStream('gzip')
        const writer = ds.writable.getWriter()
        const reader = ds.readable.getReader()

        writer.write(uint8Array)
        writer.close()

        const chunks = []
        let done = false

        while (!done) {
          const { value, done: readerDone } = await reader.read()
          done = readerDone
          if (value) chunks.push(value)
        }

        const decompressed = new Uint8Array(chunks.reduce((acc, chunk) => acc + chunk.length, 0))
        let offset = 0
        for (const chunk of chunks) {
          decompressed.set(chunk, offset)
          offset += chunk.length
        }

        const decoder = new TextDecoder()
        const jsonString = decoder.decode(decompressed)
        return JSON.parse(jsonString)
      }

      return typeof data === 'string' ? JSON.parse(data) : data
    } catch (error) {
      return data
    }
  }

  // Helper methods
  private getCachePolicy(key: string): CachePolicy {
    for (const [pattern, policy] of Object.entries(this.policies)) {
      if (key.startsWith(pattern)) {
        return policy
      }
    }

    // Default policy
    return {
      ttl: 300,
      eviction_strategy: 'lru',
      invalidation_triggers: ['data_update'],
      compression: true,
      priority: 'medium',
      distributed: true
    }
  }

  private isValid(entry: CacheEntry): boolean {
    return (entry.timestamp + entry.ttl) > Date.now()
  }

  private isValidKVEntry(entry: any): boolean {
    return entry && (entry.timestamp + entry.ttl) > Date.now()
  }

  private generateVersion(): string {
    return `v${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
  }

  private extractDependencies(key: string, metadata?: Partial<CacheMetadata>): string[] {
    const deps = []

    if (metadata?.widget_id) deps.push(`widget:${metadata.widget_id}`)
    if (metadata?.dashboard_id) deps.push(`dashboard:${metadata.dashboard_id}`)
    if (metadata?.data_source) deps.push(`datasource:${metadata.data_source}`)

    return deps
  }

  private extractTags(key: string, metadata?: Partial<CacheMetadata>): string[] {
    const tags = []

    if (key.includes('widget')) tags.push('widget')
    if (key.includes('dashboard')) tags.push('dashboard')
    if (key.includes('user')) tags.push('user')
    if (metadata?.data_source) tags.push(`source:${metadata.data_source}`)

    return tags
  }

  private matchesPattern(key: string, pattern: string): boolean {
    if (pattern.includes('*')) {
      const regex = new RegExp(pattern.replace(/\*/g, '.*'))
      return regex.test(key)
    }
    return key.includes(pattern)
  }

  private async findDependentKeys(key: string): Promise<string[]> {
    const dependentKeys = []

    for (const [cacheKey, entry] of this.cache.entries()) {
      if (entry.dependencies.includes(key)) {
        dependentKeys.push(cacheKey)
      }
    }

    return dependentKeys
  }

  private async checkEviction(): Promise<void> {
    const maxMemorySize = 50 * 1024 * 1024 // 50MB

    if (this.stats.total_size > maxMemorySize) {
      const sortedEntries = Array.from(this.cache.entries()).sort((a, b) => {
        const policy = this.getCachePolicy(a[0])

        switch (policy.eviction_strategy) {
          case 'lru':
            return (a[1].metadata.last_accessed || 0) - (b[1].metadata.last_accessed || 0)
          case 'lfu':
            return (a[1].metadata.hit_count || 0) - (b[1].metadata.hit_count || 0)
          case 'ttl':
            return (a[1].timestamp + a[1].ttl) - (b[1].timestamp + b[1].ttl)
          default:
            return 0
        }
      })

      // Evict 20% of entries
      const evictCount = Math.floor(sortedEntries.length * 0.2)
      for (let i = 0; i < evictCount; i++) {
        const [key] = sortedEntries[i]
        this.cache.delete(key)
        await this.storage.delete(`cache:${key}`)
        this.stats.evictions++
      }

      this.stats.entries_count = this.cache.size
    }
  }

  private async analyzeAccessPatterns(): Promise<any[]> {
    // Implementation for access pattern analysis
    return []
  }

  private async predictCacheMisses(patterns: any[]): Promise<any[]> {
    // Implementation for cache miss prediction
    return []
  }

  private async fetchDataForKey(key: string): Promise<any> {
    // Implementation for proactive data fetching
    return null
  }

  private async warmPopularEntries(): Promise<void> {
    // Implementation for popular entry warming
  }

  private async warmScheduledEntries(): Promise<void> {
    // Implementation for scheduled entry warming
  }

  private async trackCacheAnalytics(key: string, source: string, responseTime: number): Promise<void> {
    // Implementation for cache analytics tracking
  }

  private async logCacheOperation(operation: string, details: any): Promise<void> {
    // Implementation for cache operation logging
  }

  // Public API methods
  async getStats(): Promise<CacheStats> {
    return this.stats
  }

  async clearCache(pattern?: string): Promise<number> {
    return await this.invalidate(pattern || '*', { global: true })
  }

  async configurePolicies(policies: Record<string, CachePolicy>): Promise<void> {
    this.policies = { ...this.policies, ...policies }
    await this.storage.put('cache:policies', this.policies)
  }
}

export { CacheManager }