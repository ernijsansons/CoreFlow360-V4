/**
 * Dashboard Metrics Durable Object
 * Handles real-time metric collection and aggregation
 */

import { z } from 'zod'
import { DurableObject } from 'cloudflare:workers'

const MetricConfigSchema = z.object({
  widgetId: z.string(),
  metricType: z.string(),
  filters: z.record(z.any()).optional(),
  aggregation: z.enum(['sum', 'avg', 'count', 'min', 'max']).optional(),
  interval: z.enum(['1s', '5s', '30s', '1m', '5m', '15m', '1h']).default('30s')
})

interface MetricDataPoint {
  value: number
  timestamp: number
  metadata?: Record<string, any>
}

interface AggregatedMetric {
  value: number
  count: number
  sum: number
  min: number
  max: number
  lastUpdate: number
  trend: number
}

export class DashboardMetrics extends DurableObject {
  private sql: SqlStorage
  private alarms = new Map<string, number>()
  private metrics = new Map<string, AggregatedMetric>()
  private config: z.infer<typeof MetricConfigSchema> | null = null
  private isCollecting = false

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env)
    this.sql = ctx.storage.sql
    this.initializeDatabase()
  }

  /**
   * Initialize SQLite database for metric storage
   */
  private initializeDatabase(): void {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS metric_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER NOT NULL,
        value REAL NOT NULL,
        metadata TEXT,
        created_at INTEGER DEFAULT (strftime('%s', 'now'))
      )
    `)

    this.sql.exec(`
      CREATE INDEX IF NOT EXISTS idx_metric_timestamp ON metric_data(timestamp)
    `)

    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS metric_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at INTEGER DEFAULT (strftime('%s', 'now'))
      )
    `)
  }

  /**
   * Handle HTTP requests
   */
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url)

    try {
      switch (url.pathname) {
        case '/start-collection':
          return await this.handleStartCollection(request)

        case '/stop-collection':
          return await this.handleStopCollection()

        case '/current-value':
          return await this.handleCurrentValue(request)

        case '/historical-data':
          return await this.handleHistoricalData(request)

        case '/aggregate':
          return await this.handleAggregate(request)

        default:
          return new Response('Not Found', { status: 404 })
      }
    } catch (error) {
      return new Response(
        JSON.stringify({ error: 'Internal server error' }),
        { status: 500, headers: { 'Content-Type': 'application/json' } }
      )
    }
  }

  /**
   * Start metric collection
   */
  private async handleStartCollection(request: Request): Promise<Response> {
    const config = MetricConfigSchema.parse(await request.json())
    this.config = config

    // Store config in durable storage
    this.sql.exec(
      'INSERT OR REPLACE INTO metric_config (key, value) VALUES (?, ?)',
      'config',
      JSON.stringify(config)
    )

    // Start collection if not already running
    if (!this.isCollecting) {
      this.isCollecting = true
      await this.startPeriodicCollection()
    }

    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json' }
    })
  }

  /**
   * Stop metric collection
   */
  private async handleStopCollection(): Promise<Response> {
    this.isCollecting = false

    // Clear alarms
    for (const alarmId of this.alarms.values()) {
      this.ctx.storage.deleteAlarm(alarmId)
    }
    this.alarms.clear()

    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json' }
    })
  }

  /**
   * Get current metric value
   */
  private async handleCurrentValue(request: Request): Promise<Response> {
    if (!this.config) {
      // Try to load config from storage
      const result = this.sql.exec('SELECT value FROM metric_config WHERE key = ?', 'config').one()
      if (result) {
        this.config = MetricConfigSchema.parse(JSON.parse(result.value as string))
      }
    }

    if (!this.config) {
      return new Response(
        JSON.stringify({ error: 'No configuration found' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      )
    }

    const currentValue = await this.calculateCurrentMetric()

    return new Response(JSON.stringify(currentValue), {
      headers: { 'Content-Type': 'application/json' }
    })
  }

  /**
   * Get historical data
   */
  private async handleHistoricalData(request: Request): Promise<Response> {
    const url = new URL(request.url)
    const from = parseInt(url.searchParams.get('from') || '0')
    const to = parseInt(url.searchParams.get('to') || Date.now().toString())
    const limit = parseInt(url.searchParams.get('limit') || '1000')

    const results = this.sql.exec(`
      SELECT timestamp, value, metadata
      FROM metric_data
      WHERE timestamp >= ? AND timestamp <= ?
      ORDER BY timestamp DESC
      LIMIT ?
    `, from, to, limit).toArray()

    const data = results.map(row => ({
      timestamp: row.timestamp as number,
      value: row.value as number,
      metadata: row.metadata ? JSON.parse(row.metadata as string) : undefined
    }))

    return new Response(JSON.stringify({ data, count: data.length }), {
      headers: { 'Content-Type': 'application/json' }
    })
  }

  /**
   * Handle aggregation requests
   */
  private async handleAggregate(request: Request): Promise<Response> {
    const { groupBy, aggregation, from, to } = await request.json()

    let interval: string
    switch (groupBy) {
      case 'minute': interval = '%Y-%m-%d %H:%M'; break
      case 'hour': interval = '%Y-%m-%d %H'; break
      case 'day': interval = '%Y-%m-%d'; break
      case 'week': interval = '%Y-W%W'; break
      case 'month': interval = '%Y-%m'; break
      default: interval = '%Y-%m-%d %H:%M'
    }

    const aggregateFunc = aggregation || 'avg'
    let sqlFunc: string
    switch (aggregateFunc) {
      case 'sum': sqlFunc = 'SUM'; break
      case 'avg': sqlFunc = 'AVG'; break
      case 'count': sqlFunc = 'COUNT'; break
      case 'min': sqlFunc = 'MIN'; break
      case 'max': sqlFunc = 'MAX'; break
      default: sqlFunc = 'AVG'
    }

    const results = this.sql.exec(`
      SELECT
        strftime('${interval}', datetime(timestamp/1000, 'unixepoch')) as period,
        ${sqlFunc}(value) as value,
        COUNT(*) as count,
        MIN(timestamp) as period_start,
        MAX(timestamp) as period_end
      FROM metric_data
      WHERE timestamp >= ? AND timestamp <= ?
      GROUP BY period
      ORDER BY period_start
    `, from, to).toArray()

    const data = results.map(row => ({
      period: row.period,
      value: row.value as number,
      count: row.count as number,
      periodStart: row.period_start as number,
      periodEnd: row.period_end as number
    }))

    return new Response(JSON.stringify({ data, aggregation: aggregateFunc, groupBy }), {
      headers: { 'Content-Type': 'application/json' }
    })
  }

  /**
   * Start periodic metric collection
   */
  private async startPeriodicCollection(): Promise<void> {
    if (!this.config) return

    const intervalMs = this.parseInterval(this.config.interval)
    const alarmTime = Date.now() + intervalMs

    await this.ctx.storage.setAlarm(alarmTime)
    this.alarms.set('collection', alarmTime)
  }

  /**
   * Handle alarm for periodic collection
   */
  async alarm(): Promise<void> {
    if (!this.isCollecting || !this.config) return

    try {
      // Collect current metric value
      const metricValue = await this.collectMetricValue()

      if (metricValue !== null) {
        // Store in database
        this.sql.exec(
          'INSERT INTO metric_data (timestamp, value, metadata) VALUES (?, ?, ?)',
          Date.now(),
          metricValue.value,
          metricValue.metadata ? JSON.stringify(metricValue.metadata) : null
        )

        // Update in-memory aggregated metric
        this.updateAggregatedMetric(metricValue)

        // Broadcast update to subscribers
        await this.broadcastUpdate(metricValue)
      }

      // Schedule next collection
      if (this.isCollecting) {
        await this.startPeriodicCollection()
      }

    } catch (error) {

      // Retry in case of error
      if (this.isCollecting) {
        setTimeout(() => this.startPeriodicCollection(), 5000)
      }
    }
  }

  /**
   * Collect metric value based on configuration
   */
  private async collectMetricValue(): Promise<MetricDataPoint | null> {
    if (!this.config) return null

    try {
      switch (this.config.metricType) {
        case 'revenue':
          return await this.collectRevenueMetric()

        case 'invoice_count':
          return await this.collectInvoiceCountMetric()

        case 'customer_count':
          return await this.collectCustomerCountMetric()

        case 'conversion_rate':
          return await this.collectConversionRateMetric()

        default:
          return null
      }
    } catch (error) {
      return null
    }
  }

  /**
   * Collect revenue metric
   */
  private async collectRevenueMetric(): Promise<MetricDataPoint | null> {
    const filters = this.config?.filters || {}
    const period = filters.period || '1d'

    // This would typically call an external API or database
    // For demo purposes, we'll simulate data
    const value = Math.random() * 10000 + 5000

    return {
      value,
      timestamp: Date.now(),
      metadata: { period, currency: 'USD' }
    }
  }

  /**
   * Collect invoice count metric
   */
  private async collectInvoiceCountMetric(): Promise<MetricDataPoint | null> {
    // Simulate invoice count
    const value = Math.floor(Math.random() * 50) + 10

    return {
      value,
      timestamp: Date.now(),
      metadata: { type: 'count' }
    }
  }

  /**
   * Collect customer count metric
   */
  private async collectCustomerCountMetric(): Promise<MetricDataPoint | null> {
    // Simulate customer count
    const value = Math.floor(Math.random() * 100) + 500

    return {
      value,
      timestamp: Date.now(),
      metadata: { type: 'count' }
    }
  }

  /**
   * Collect conversion rate metric
   */
  private async collectConversionRateMetric(): Promise<MetricDataPoint | null> {
    // Simulate conversion rate
    const value = Math.random() * 0.2 + 0.1 // 10-30%

    return {
      value,
      timestamp: Date.now(),
      metadata: { type: 'percentage' }
    }
  }

  /**
   * Calculate current aggregated metric
   */
  private async calculateCurrentMetric(): Promise<any> {
    const metricKey = this.config?.widgetId || 'default'
    const metric = this.metrics.get(metricKey)

    if (metric) {
      return {
        value: metric.value,
        trend: metric.trend,
        lastUpdate: metric.lastUpdate,
        count: metric.count
      }
    }

    // Fallback to latest value from database
    const result = this.sql.exec(`
      SELECT value, timestamp, metadata
      FROM metric_data
      ORDER BY timestamp DESC
      LIMIT 1
    `).one()

    if (result) {
      return {
        value: result.value as number,
        trend: 0,
        lastUpdate: result.timestamp as number,
        count: 1,
        metadata: result.metadata ? JSON.parse(result.metadata as string) : undefined
      }
    }

    return { value: 0, trend: 0, lastUpdate: Date.now(), count: 0 }
  }

  /**
   * Update in-memory aggregated metric
   */
  private updateAggregatedMetric(dataPoint: MetricDataPoint): void {
    if (!this.config) return

    const metricKey = this.config.widgetId
    const existing = this.metrics.get(metricKey)

    if (existing) {
      const aggregation = this.config.aggregation || 'avg'
      let newValue: number

      switch (aggregation) {
        case 'sum':
          newValue = existing.sum + dataPoint.value
          break
        case 'avg':
          newValue = (existing.sum + dataPoint.value) / (existing.count + 1)
          break
        case 'count':
          newValue = existing.count + 1
          break
        case 'min':
          newValue = Math.min(existing.min, dataPoint.value)
          break
        case 'max':
          newValue = Math.max(existing.max, dataPoint.value)
          break
        default:
          newValue = dataPoint.value
      }

      // Calculate trend
      const trend = existing.value > 0 ? ((newValue - existing.value) / existing.value) * 100 : 0

      this.metrics.set(metricKey, {
        value: newValue,
        count: existing.count + 1,
        sum: existing.sum + dataPoint.value,
        min: Math.min(existing.min, dataPoint.value),
        max: Math.max(existing.max, dataPoint.value),
        lastUpdate: dataPoint.timestamp,
        trend
      })
    } else {
      this.metrics.set(metricKey, {
        value: dataPoint.value,
        count: 1,
        sum: dataPoint.value,
        min: dataPoint.value,
        max: dataPoint.value,
        lastUpdate: dataPoint.timestamp,
        trend: 0
      })
    }
  }

  /**
   * Broadcast update to real-time service
   */
  private async broadcastUpdate(dataPoint: MetricDataPoint): Promise<void> {
    if (!this.config) return

    try {
      // Send update to real-time service via fetch
      const realtimeUrl = 'https://your-worker.example.com/api/v1/dashboard/realtime/update'

      await fetch(realtimeUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          metricType: this.config.metricType,
          widgetId: this.config.widgetId,
          data: {
            value: dataPoint.value,
            timestamp: dataPoint.timestamp,
            metadata: dataPoint.metadata
          }
        })
      })
    } catch (error) {
    }
  }

  /**
   * Parse interval string to milliseconds
   */
  private parseInterval(interval: string): number {
    const multipliers: Record<string, number> = {
      's': 1000,
      'm': 60 * 1000,
      'h': 60 * 60 * 1000
    }

    const match = interval.match(/^(\d+)([smh])$/)
    if (match) {
      const value = parseInt(match[1])
      const unit = match[2]
      return value * multipliers[unit]
    }

    return 30000 // Default 30 seconds
  }

  /**
   * Cleanup old data to prevent storage bloat
   */
  private async cleanupOldData(): Promise<void> {
    const cutoffTime = Date.now() - (7 * 24 * 60 * 60 * 1000) // 7 days ago

    this.sql.exec('DELETE FROM metric_data WHERE timestamp < ?', cutoffTime)
  }
}

export default DashboardMetrics