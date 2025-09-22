/**
 * Real-Time Dashboard Data Service
 * WebSocket-based live data pipeline with Cloudflare Durable Objects
 */

import { z } from 'zod'
import type { Env } from '@/types/env'
import { AppError } from '@/shared/errors/app-error'
import { AuditLogger } from '@/shared/services/audit-logger'

const MetricSubscriptionSchema = z.object({
  widgetId: z.string(),
  metricType: z.string(),
  filters: z.record(z.any()).optional(),
  aggregation: z.enum(['sum', 'avg', 'count', 'min', 'max']).optional(),
  interval: z.enum(['1s', '5s', '30s', '1m', '5m', '15m', '1h']).default('30s')
})

const DataUpdateSchema = z.object({
  type: z.enum(['metric_update', 'alert', 'heartbeat', 'error']),
  widgetId: z.string().optional(),
  data: z.any(),
  timestamp: z.string(),
  sequence: z.number().optional()
})

export type MetricSubscription = z.infer<typeof MetricSubscriptionSchema>
export type DataUpdate = z.infer<typeof DataUpdateSchema>

interface Connection {
  id: string
  userId: string
  businessId: string
  dashboardId: string
  websocket: WebSocket
  subscriptions: Set<string>
  lastPing: number
  isAlive: boolean
}

export // TODO: Consider splitting RealTimeService into smaller, focused classes
class RealTimeService {
  private connections = new Map<string, Connection>()
  private subscriptions = new Map<string, Set<string>>() // metric -> connectionIds
  private updateQueue = new Map<string, DataUpdate[]>() // connectionId -> updates
  private batchTimer: NodeJS.Timeout | null = null
  private heartbeatInterval: NodeJS.Timeout | null = null

  constructor(
    private env: Env,
    private auditLogger: AuditLogger
  ) {
    this.startHeartbeat()
    this.startBatchProcessor()
  }

  /**
   * Handle new WebSocket connection
   */
  async handleConnection(
    websocket: WebSocket,
    userId: string,
    businessId: string,
    dashboardId: string
  ): Promise<string> {
    const connectionId = crypto.randomUUID()

    const connection: Connection = {
      id: connectionId,
      userId,
      businessId,
      dashboardId,
      websocket,
      subscriptions: new Set(),
      lastPing: Date.now(),
      isAlive: true
    }

    this.connections.set(connectionId, connection)

    // Set up WebSocket event handlers
    websocket.addEventListener('message', (event) => {
      this.handleMessage(connectionId, event.data)
    })

    websocket.addEventListener('close', () => {
      this.handleDisconnection(connectionId)
    })

    websocket.addEventListener('error', (error) => {
      this.handleDisconnection(connectionId)
    })

    // Send connection confirmation
    this.sendToConnection(connectionId, {
      type: 'heartbeat',
      data: { status: 'connected', connectionId },
      timestamp: new Date().toISOString()
    })

    await this.auditLogger.log({
      action: 'dashboard_connection_established',
      userId,
      details: {
        connectionId,
        businessId,
        dashboardId
      }
    })

    return connectionId
  }

  /**
   * Handle WebSocket messages
   */
  private async handleMessage(connectionId: string, message: string): Promise<void> {
    const connection = this.connections.get(connectionId)
    if (!connection) return

    try {
      const data = JSON.parse(message)

      switch (data.type) {
        case 'subscribe':
          await this.handleSubscription(connectionId, data.payload)
          break

        case 'unsubscribe':
          await this.handleUnsubscription(connectionId, data.payload)
          break

        case 'ping':
          connection.lastPing = Date.now()
          connection.isAlive = true
          this.sendToConnection(connectionId, {
            type: 'heartbeat',
            data: { status: 'pong' },
            timestamp: new Date().toISOString()
          })
          break

        case 'request_snapshot':
          await this.sendSnapshot(connectionId, data.payload)
          break

        default:
      }

    } catch (error) {
      this.sendToConnection(connectionId, {
        type: 'error',
        data: { error: 'Invalid message format' },
        timestamp: new Date().toISOString()
      })
    }
  }

  /**
   * Handle metric subscription
   */
  private async handleSubscription(
    connectionId: string,
    payload: MetricSubscription
  ): Promise<void> {
    try {
      const subscription = MetricSubscriptionSchema.parse(payload)
      const connection = this.connections.get(connectionId)
      if (!connection) return

      const metricKey = this.buildMetricKey(subscription)

      // Add to connection subscriptions
      connection.subscriptions.add(metricKey)

      // Add to global subscriptions
      if (!this.subscriptions.has(metricKey)) {
        this.subscriptions.set(metricKey, new Set())
      }
      this.subscriptions.get(metricKey)!.add(connectionId)

      // Start metric collection if this is the first subscriber
      if (this.subscriptions.get(metricKey)!.size === 1) {
        await this.startMetricCollection(subscription)
      }

      // Send current value immediately
      const currentValue = await this.getCurrentMetricValue(subscription)
      this.sendToConnection(connectionId, {
        type: 'metric_update',
        widgetId: subscription.widgetId,
        data: currentValue,
        timestamp: new Date().toISOString()
      })

      await this.auditLogger.log({
        action: 'metric_subscribed',
        userId: connection.userId,
        details: {
          connectionId,
          metricKey,
          subscription
        }
      })

    } catch (error) {
      this.sendToConnection(connectionId, {
        type: 'error',
        data: { error: 'Invalid subscription format' },
        timestamp: new Date().toISOString()
      })
    }
  }

  /**
   * Handle metric unsubscription
   */
  private async handleUnsubscription(
    connectionId: string,
    payload: { widgetId: string; metricType: string }
  ): Promise<void> {
    const connection = this.connections.get(connectionId)
    if (!connection) return

    const metricKey = `${payload.metricType}:${payload.widgetId}`

    // Remove from connection subscriptions
    connection.subscriptions.delete(metricKey)

    // Remove from global subscriptions
    const subscribers = this.subscriptions.get(metricKey)
    if (subscribers) {
      subscribers.delete(connectionId)

      // Stop metric collection if no more subscribers
      if (subscribers.size === 0) {
        this.subscriptions.delete(metricKey)
        await this.stopMetricCollection(metricKey)
      }
    }
  }

  /**
   * Handle connection disconnection
   */
  private handleDisconnection(connectionId: string): void {
    const connection = this.connections.get(connectionId)
    if (!connection) return

    // Remove from all subscriptions
    for (const metricKey of connection.subscriptions) {
      const subscribers = this.subscriptions.get(metricKey)
      if (subscribers) {
        subscribers.delete(connectionId)
        if (subscribers.size === 0) {
          this.subscriptions.delete(metricKey)
          this.stopMetricCollection(metricKey)
        }
      }
    }

    // Clean up connection
    this.connections.delete(connectionId)
    this.updateQueue.delete(connectionId)

    this.auditLogger.log({
      action: 'dashboard_connection_closed',
      userId: connection.userId,
      details: {
        connectionId,
        duration: Date.now() - connection.lastPing
      }
    })
  }

  /**
   * Send data update to specific connection
   */
  private sendToConnection(connectionId: string, update: DataUpdate): void {
    const connection = this.connections.get(connectionId)
    if (!connection || !connection.isAlive) return

    try {
      if (connection.websocket.readyState === WebSocket.OPEN) {
        connection.websocket.send(JSON.stringify(update))
      }
    } catch (error) {
      this.handleDisconnection(connectionId)
    }
  }

  /**
   * Queue update for batching
   */
  private queueUpdate(connectionId: string, update: DataUpdate): void {
    if (!this.updateQueue.has(connectionId)) {
      this.updateQueue.set(connectionId, [])
    }
    this.updateQueue.get(connectionId)!.push(update)
  }

  /**
   * Broadcast metric update to all subscribers
   */
  async broadcastMetricUpdate(
    metricType: string,
    widgetId: string,
    data: any
  ): Promise<void> {
    const metricKey = `${metricType}:${widgetId}`
    const subscribers = this.subscriptions.get(metricKey)

    if (!subscribers || subscribers.size === 0) return

    const update: DataUpdate = {
      type: 'metric_update',
      widgetId,
      data,
      timestamp: new Date().toISOString(),
      sequence: Date.now()
    }

    // Queue updates for batching
    for (const connectionId of subscribers) {
      this.queueUpdate(connectionId, update)
    }
  }

  /**
   * Start metric collection from Durable Object
   */
  private async startMetricCollection(subscription: MetricSubscription): Promise<void> {
    const durableObjectId = this.env.DASHBOARD_METRICS.idFromName(
      `${subscription.metricType}:${subscription.widgetId}`
    )
    const durableObject = this.env.DASHBOARD_METRICS.get(durableObjectId)

    try {
      await durableObject.fetch('/start-collection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(subscription)
      })
    } catch (error) {
    }
  }

  /**
   * Stop metric collection
   */
  private async stopMetricCollection(metricKey: string): Promise<void> {
    const durableObjectId = this.env.DASHBOARD_METRICS.idFromName(metricKey)
    const durableObject = this.env.DASHBOARD_METRICS.get(durableObjectId)

    try {
      await durableObject.fetch('/stop-collection', {
        method: 'POST'
      })
    } catch (error) {
    }
  }

  /**
   * Get current metric value
   */
  private async getCurrentMetricValue(subscription: MetricSubscription): Promise<any> {
    const metricKey = this.buildMetricKey(subscription)
    const durableObjectId = this.env.DASHBOARD_METRICS.idFromName(metricKey)
    const durableObject = this.env.DASHBOARD_METRICS.get(durableObjectId)

    try {
      const response = await durableObject.fetch('/current-value', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(subscription)
      })

      if (response.ok) {
        return await response.json()
      }
    } catch (error) {
    }

    return null
  }

  /**
   * Send data snapshot for initial load
   */
  private async sendSnapshot(
    connectionId: string,
    payload: { widgetIds: string[] }
  ): Promise<void> {
    const connection = this.connections.get(connectionId)
    if (!connection) return

    try {
      // Get snapshot data for all requested widgets
      const snapshotData = await this.getSnapshotData(
        payload.widgetIds,
        connection.businessId
      )

      this.sendToConnection(connectionId, {
        type: 'metric_update',
        data: {
          type: 'snapshot',
          widgets: snapshotData
        },
        timestamp: new Date().toISOString()
      })

    } catch (error) {
      this.sendToConnection(connectionId, {
        type: 'error',
        data: { error: 'Failed to get snapshot data' },
        timestamp: new Date().toISOString()
      })
    }
  }

  /**
   * Get snapshot data from database
   */
  private async getSnapshotData(
    widgetIds: string[],
    businessId: string
  ): Promise<Record<string, any>> {
    const data: Record<string, any> = {}

    for (const widgetId of widgetIds) {
      try {
        // Get widget configuration
        const widget = await this.env.DB.prepare(`
          SELECT * FROM dashboard_widgets WHERE id = ? AND business_id = ?
        `).bind(widgetId, businessId).first()

        if (widget) {
          // Get metric data based on widget type
          const metricData = await this.getWidgetMetricData(widget)
          data[widgetId] = metricData
        }
      } catch (error) {
        data[widgetId] = { error: 'Failed to load data' }
      }
    }

    return data
  }

  /**
   * Get metric data for specific widget
   */
  private async getWidgetMetricData(widget: any): Promise<any> {
    const config = JSON.parse(widget.config || '{}')

    switch (widget.type) {
      case 'revenue_kpi':
        return await this.getRevenueMetrics(widget.business_id, config)

      case 'invoice_chart':
        return await this.getInvoiceChartData(widget.business_id, config)

      case 'customer_table':
        return await this.getCustomerTableData(widget.business_id, config)

      default:
        return { value: 0, trend: 0 }
    }
  }

  /**
   * Get revenue metrics
   */
  private async getRevenueMetrics(businessId: string, config: any): Promise<any> {
    const period = config.period || '30d'
    const dateFrom = this.getPeriodStartDate(period)

    const result = await this.env.DB.prepare(`
      SELECT
        SUM(total_amount) as current_revenue,
        COUNT(*) as invoice_count,
        AVG(total_amount) as avg_invoice
      FROM invoices
      WHERE business_id = ? AND created_at >= ? AND status = 'paid'
    `).bind(businessId, dateFrom).first()

    // Get previous period for comparison
    const prevPeriodStart = this.getPreviousPeriodDate(dateFrom, period)
    const prevResult = await this.env.DB.prepare(`
      SELECT SUM(total_amount) as prev_revenue
      FROM invoices
      WHERE business_id = ? AND created_at >= ? AND created_at < ? AND status = 'paid'
    `).bind(businessId, prevPeriodStart, dateFrom).first()

    const currentRevenue = result?.current_revenue || 0
    const previousRevenue = prevResult?.prev_revenue || 0
    const trend = previousRevenue > 0 ? ((currentRevenue - previousRevenue) / previousRevenue) * 100 : 0

    return {
      value: currentRevenue,
      trend,
      invoiceCount: result?.invoice_count || 0,
      avgInvoice: result?.avg_invoice || 0,
      period
    }
  }

  /**
   * Get invoice chart data
   */
  private async getInvoiceChartData(businessId: string, config: any): Promise<any> {
    const period = config.period || '30d'
    const groupBy = config.groupBy || 'day'

    let dateFormat: string
    let dateInterval: string

    switch (groupBy) {
      case 'hour':
        dateFormat = '%Y-%m-%d %H:00:00'
        dateInterval = 'hour'
        break
      case 'day':
        dateFormat = '%Y-%m-%d'
        dateInterval = 'day'
        break
      case 'week':
        dateFormat = '%Y-W%W'
        dateInterval = 'week'
        break
      case 'month':
        dateFormat = '%Y-%m'
        dateInterval = 'month'
        break
      default:
        dateFormat = '%Y-%m-%d'
        dateInterval = 'day'
    }

    const dateFrom = this.getPeriodStartDate(period)

    const results = await this.env.DB.prepare(`
      SELECT
        strftime('${dateFormat}', created_at) as date_group,
        COUNT(*) as count,
        SUM(total_amount) as revenue,
        SUM(CASE WHEN status = 'paid' THEN total_amount ELSE 0 END) as paid_revenue
      FROM invoices
      WHERE business_id = ? AND created_at >= ?
      GROUP BY date_group
      ORDER BY date_group
    `).bind(businessId, dateFrom).all()

    return {
      labels: results.results.map((r: any) => r.date_group),
      datasets: [
        {
          label: 'Revenue',
          data: results.results.map((r: any) => r.revenue || 0),
          type: 'line'
        },
        {
          label: 'Invoice Count',
          data: results.results.map((r: any) => r.count || 0),
          type: 'bar'
        }
      ],
      period,
      groupBy
    }
  }

  /**
   * Get customer table data
   */
  private async getCustomerTableData(businessId: string, config: any): Promise<any> {
    const limit = config.limit || 50
    const sortBy = config.sortBy || 'created_at'
    const sortOrder = config.sortOrder || 'DESC'

    const results = await this.env.DB.prepare(`
      SELECT
        c.*,
        COUNT(i.id) as invoice_count,
        SUM(i.total_amount) as total_spent,
        MAX(i.created_at) as last_invoice_date
      FROM customers c
      LEFT JOIN invoices i ON c.id = i.customer_id
      WHERE c.business_id = ?
      GROUP BY c.id
      ORDER BY ${sortBy} ${sortOrder}
      LIMIT ?
    `).bind(businessId, limit).all()

    return {
      customers: results.results,
      total: results.results.length,
      sortBy,
      sortOrder
    }
  }

  /**
   * Build metric key for subscription
   */
  private buildMetricKey(subscription: MetricSubscription): string {
    const filters = subscription.filters ? JSON.stringify(subscription.filters) : ''
    return `${subscription.metricType}:${subscription.widgetId}:${filters}:${subscription.interval}`
  }

  /**
   * Get period start date
   */
  private getPeriodStartDate(period: string): string {
    const now = new Date()
    let daysBack = 30

    switch (period) {
      case '1d': daysBack = 1; break
      case '7d': daysBack = 7; break
      case '30d': daysBack = 30; break
      case '90d': daysBack = 90; break
      case '1y': daysBack = 365; break
    }

    const startDate = new Date(now.getTime() - (daysBack * 24 * 60 * 60 * 1000))
    return startDate.toISOString()
  }

  /**
   * Get previous period start date
   */
  private getPreviousPeriodDate(currentStart: string, period: string): string {
    const currentDate = new Date(currentStart)
    let daysBack = 30

    switch (period) {
      case '1d': daysBack = 1; break
      case '7d': daysBack = 7; break
      case '30d': daysBack = 30; break
      case '90d': daysBack = 90; break
      case '1y': daysBack = 365; break
    }

    const prevDate = new Date(currentDate.getTime() - (daysBack * 24 * 60 * 60 * 1000))
    return prevDate.toISOString()
  }

  /**
   * Start heartbeat to maintain connections
   */
  private startHeartbeat(): void {
    this.heartbeatInterval = setInterval(() => {
      const now = Date.now()
      const staleThreshold = 60000 // 1 minute

      for (const [connectionId, connection] of this.connections) {
        if (now - connection.lastPing > staleThreshold) {
          connection.isAlive = false
          this.handleDisconnection(connectionId)
        }
      }
    }, 30000) // Check every 30 seconds
  }

  /**
   * Start batch processor for efficient updates
   */
  private startBatchProcessor(): void {
    this.batchTimer = setInterval(() => {
      for (const [connectionId, updates] of this.updateQueue) {
        if (updates.length === 0) continue

        const connection = this.connections.get(connectionId)
        if (!connection || !connection.isAlive) {
          this.updateQueue.delete(connectionId)
          continue
        }

        // Group updates by widget
        const groupedUpdates = new Map<string, DataUpdate[]>()
        for (const update of updates) {
          if (update.widgetId) {
            if (!groupedUpdates.has(update.widgetId)) {
              groupedUpdates.set(update.widgetId, [])
            }
            groupedUpdates.get(update.widgetId)!.push(update)
          }
        }

        // Send latest update for each widget
        for (const [widgetId, widgetUpdates] of groupedUpdates) {
          const latestUpdate = widgetUpdates[widgetUpdates.length - 1]
          this.sendToConnection(connectionId, latestUpdate)
        }

        // Clear processed updates
        this.updateQueue.set(connectionId, [])
      }
    }, 100) // Process every 100ms for 60fps max
  }

  /**
   * Cleanup resources
   */
  destroy(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval)
    }

    if (this.batchTimer) {
      clearInterval(this.batchTimer)
    }

    // Close all connections
    for (const connection of this.connections.values()) {
      if (connection.websocket.readyState === WebSocket.OPEN) {
        connection.websocket.close()
      }
    }

    this.connections.clear()
    this.subscriptions.clear()
    this.updateQueue.clear()
  }
}

export default RealTimeService