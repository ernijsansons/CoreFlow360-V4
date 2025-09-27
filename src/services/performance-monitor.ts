/**
 * Performance Monitor Service
 * Real-time performance tracking and optimization for dashboard components
 */

import { DurableObject } from 'cloudflare:workers'

export interface PerformanceMetric {
  id: string
  type: 'load_time' | 'render_time' | 'data_fetch'
  | 'user_interaction' | 'memory_usage' | 'bundle_size' | 'cache_hit_rate'
  value: number
  unit: 'ms' | 'mb' | 'percent' | 'count' | 'kb'
  timestamp: number
  context: PerformanceContext
  tags: string[]
  threshold?: {
    warning: number
    critical: number
  }
}

export interface PerformanceContext {
  widget_id?: string
  dashboard_id?: string
  user_id?: string
  session_id?: string
  device_type?: 'mobile' | 'tablet' | 'desktop'
  browser?: string
  connection?: 'slow-2g' | '2g' | '3g' | '4g' | 'wifi'
  viewport?: { width: number; height: number }
  memory?: { used: number; total: number }
  cpu_cores?: number
  location?: string
}

export interface PerformanceAlert {
  id: string
  metric_type: string
  severity: 'warning' | 'critical'
  message: string
  value: number
  threshold: number
  context: PerformanceContext
  timestamp: number
  resolved: boolean
  resolution_time?: number
}

export interface PerformanceBenchmark {
  metric_type: string
  percentiles: {
    p50: number
    p75: number
    p90: number
    p95: number
    p99: number
  }
  average: number
  min: number
  max: number
  sample_count: number
  period: string
}

export interface PerformanceInsight {
  type: 'recommendation' | 'optimization' | 'warning' | 'info'
  title: string
  description: string
  impact: 'low' | 'medium' | 'high' | 'critical'
  effort: 'low' | 'medium' | 'high'
  action?: string
  priority_score: number
  estimated_improvement: string
}

export class PerformanceMonitor extends DurableObject {
  private storage: DurableObjectStorage
  private env: any
  private metrics: Map<string, PerformanceMetric[]> = new Map()
  private alerts: PerformanceAlert[] = []
  private benchmarks: Map<string, PerformanceBenchmark> = new Map()

  // Performance thresholds
  private thresholds = {
    widget_load_time: { warning: 2000, critical: 5000 }, // ms
    data_fetch_time: { warning: 1000, critical: 3000 }, // ms
    render_time: { warning: 100, critical: 300 }, // ms
    memory_usage: { warning: 100, critical: 200 }, // MB
    cache_hit_rate: { warning: 70, critical: 50 }, // percent
    bundle_size: { warning: 2048, critical: 5120 }, // KB
    interaction_lag: { warning: 100, critical: 250 } // ms
  }

  constructor(ctx: DurableObjectState, env: any) {
    super(ctx, env)
    this.storage = ctx.storage
    this.env = env

    // Set up periodic cleanup and analysis
    this.schedulePeriodicTasks()
  }

  // Record performance metric
  async recordMetric(metric: Omit<PerformanceMetric, 'id' | 'timestamp'>): Promise<void> {
    const fullMetric: PerformanceMetric = {
      id: `${metric.type}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: Date.now(),
      threshold: this.thresholds[metric.type as keyof typeof this.thresholds],
      ...metric
    }

    // Store in memory for real-time access
    const key = `${metric.type}-${metric.context.widget_id || 'global'}`
    if (!this.metrics.has(key)) {
      this.metrics.set(key, [])
    }

    const metricsList = this.metrics.get(key)!
    metricsList.push(fullMetric)

    // Keep only last 1000 metrics per key
    if (metricsList.length > 1000) {
      metricsList.splice(0, metricsList.length - 1000)
    }

    // Persist to Durable Object storage
    await this.storage.put(`metric:${fullMetric.id}`, fullMetric)

    // Check for threshold violations
    await this.checkThresholds(fullMetric)

    // Send to Analytics Engine for aggregation
    await this.sendToAnalyticsEngine(fullMetric)

    // Trigger real-time updates
    await this.broadcastMetricUpdate(fullMetric)
  }

  // Check performance thresholds and create alerts
  private async checkThresholds(metric: PerformanceMetric): Promise<void> {
    if (!metric.threshold) return

    let severity: 'warning' | 'critical' | null = null

    if (metric.value >= metric.threshold.critical) {
      severity = 'critical'
    } else if (metric.value >= metric.threshold.warning) {
      severity = 'warning'
    }

    if (severity) {
      const alert: PerformanceAlert = {
        id: `alert-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        metric_type: metric.type,
        severity,
        message: this.generateAlertMessage(metric, severity),
        value: metric.value,
        threshold: severity === 'critical' ? metric.threshold.critical : metric.threshold.warning,
        context: metric.context,
        timestamp: Date.now(),
        resolved: false
      }

      this.alerts.push(alert)
      await this.storage.put(`alert:${alert.id}`, alert)

      // Send notification
      await this.sendAlertNotification(alert)
    }
  }

  // Generate performance insights and recommendations
  async generateInsights(dashboardId?: string, timeframe = '24h'): Promise<PerformanceInsight[]> {
    const insights: PerformanceInsight[] = []

    try {
      // Analyze recent metrics
      const recentMetrics = await this.getRecentMetrics(timeframe, dashboardId)

      // Widget load time analysis
      const loadTimeInsights = this.analyzeLoadTimes(recentMetrics)
      insights.push(...loadTimeInsights)

      // Memory usage analysis
      const memoryInsights = this.analyzeMemoryUsage(recentMetrics)
      insights.push(...memoryInsights)

      // Cache performance analysis
      const cacheInsights = this.analyzeCachePerformance(recentMetrics)
      insights.push(...cacheInsights)

      // Bundle size analysis
      const bundleInsights = this.analyzeBundleSize(recentMetrics)
      insights.push(...bundleInsights)

      // User interaction analysis
      const interactionInsights = this.analyzeUserInteractions(recentMetrics)
      insights.push(...interactionInsights)

      // Device-specific performance analysis
      const deviceInsights = this.analyzeDevicePerformance(recentMetrics)
      insights.push(...deviceInsights)

      // Sort by priority score
      insights.sort((a, b) => b.priority_score - a.priority_score)

      return insights.slice(0, 20) // Return top 20 insights

    } catch (error: any) {
      return []
    }
  }

  // Real-time performance monitoring
  async startRealTimeMonitoring(dashboardId: string): Promise<void> {
    // Set up performance observers
    await this.setupPerformanceObservers(dashboardId)

    // Start resource monitoring
    await this.startResourceMonitoring(dashboardId)

    // Initialize user interaction tracking
    await this.initializeInteractionTracking(dashboardId)
  }

  // Get performance benchmarks
  async getBenchmarks(metricType?: string): Promise<PerformanceBenchmark[]> {
    if (metricType) {
      const benchmark = this.benchmarks.get(metricType)
      return benchmark ? [benchmark] : []
    }

    return Array.from(this.benchmarks.values())
  }

  // Get active alerts
  async getActiveAlerts(dashboardId?: string): Promise<PerformanceAlert[]> {
    let alerts = this.alerts.filter((alert: any) => !alert.resolved)

    if (dashboardId) {
      alerts = alerts.filter((alert: any) => alert.context.dashboard_id === dashboardId)
    }

    return alerts.sort((a, b) => {
      // Sort by severity (critical first) then by timestamp
      if (a.severity !== b.severity) {
        return a.severity === 'critical' ? -1 : 1
      }
      return b.timestamp - a.timestamp
    })
  }

  // Resolve alert
  async resolveAlert(alertId: string): Promise<void> {
    const alertIndex = this.alerts.findIndex(alert => alert.id === alertId)
    if (alertIndex === -1) return

    this.alerts[alertIndex].resolved = true
    this.alerts[alertIndex].resolution_time = Date.now()

    await this.storage.put(`alert:${alertId}`, this.alerts[alertIndex])
  }

  // Performance optimization suggestions
  async getOptimizationSuggestions(context: Partial<PerformanceContext>): Promise<PerformanceInsight[]> {
    const suggestions: PerformanceInsight[] = []

    // Widget-specific optimizations
    if (context.widget_id) {
      const widgetMetrics = await this.getWidgetMetrics(context.widget_id)
      suggestions.push(...this.generateWidgetOptimizations(widgetMetrics))
    }

    // Dashboard-level optimizations
    if (context.dashboard_id) {
      const dashboardMetrics = await this.getDashboardMetrics(context.dashboard_id)
      suggestions.push(...this.generateDashboardOptimizations(dashboardMetrics))
    }

    // Device-specific optimizations
    if (context.device_type) {
      suggestions.push(...this.generateDeviceOptimizations(context.device_type))
    }

    return suggestions.sort((a, b) => b.priority_score - a.priority_score)
  }

  // Performance analytics and trends
  async getPerformanceTrends(
    metricType: string,
    timeframe: '1h' | '24h' | '7d' | '30d' = '24h',
    dashboardId?: string
  ): Promise<{ timestamp: number; value: number }[]> {
    try {
      const endTime = Date.now()
      const duration = this.parseTimeframe(timeframe)
      const startTime = endTime - duration

      // Query Analytics Engine for trend data
      const response = await this.env.ANALYTICS_ENGINE.prepare(`
        SELECT
          timestamp,
          AVG(value) as value
        FROM performance_metrics
        WHERE metric_type = ?
          AND timestamp BETWEEN ? AND ?
          ${dashboardId ? 'AND dashboard_id = ?' : ''}
        GROUP BY timestamp
        ORDER BY timestamp ASC
      `).bind(
        metricType,
        startTime,
        endTime,
        ...(dashboardId ? [dashboardId] : [])
      ).all()

      return response.results.map((row: any) => ({
        timestamp: row.timestamp,
        value: row.value
      }))

    } catch (error: any) {
      return []
    }
  }

  // Helper methods
  private async getRecentMetrics(timeframe: string, dashboardId?: string): Promise<PerformanceMetric[]> {
    const duration = this.parseTimeframe(timeframe)
    const cutoff = Date.now() - duration

    const allMetrics: PerformanceMetric[] = []

    for (const metricsList of this.metrics.values()) {
      const recentMetrics = metricsList.filter((metric: any) => {
        if (metric.timestamp < cutoff) return false
        if (dashboardId && metric.context.dashboard_id !== dashboardId) return false
        return true
      })
      allMetrics.push(...recentMetrics)
    }

    return allMetrics
  }

  private analyzeLoadTimes(metrics: PerformanceMetric[]): PerformanceInsight[] {
    const insights: PerformanceInsight[] = []
    const loadTimeMetrics = metrics.filter((m: any) => m.type === 'load_time')

    if (loadTimeMetrics.length === 0) return insights

    const avgLoadTime = loadTimeMetrics.reduce((sum, m) => sum + m.value, 0) / loadTimeMetrics.length
    const slowWidgets = loadTimeMetrics.filter((m: any) => m.value > 3000)

    if (avgLoadTime > 2000) {
      insights.push({
        type: 'optimization',
        title: 'High Average Load Time',
        description: `Average
  widget load time is ${Math.round(avgLoadTime)}ms. Consider optimizing data fetching and rendering.`,
        impact: avgLoadTime > 5000 ? 'critical' : 'high',
        effort: 'medium',
        action: 'Implement lazy loading and data pagination',
        priority_score: Math.min(100, avgLoadTime / 50),
        estimated_improvement: `${Math.round(avgLoadTime * 0.3)}ms faster load times`
      })
    }

    if (slowWidgets.length > 0) {
      insights.push({
        type: 'recommendation',
        title: 'Slow Loading Widgets',
        description: `${slowWidgets.length} widgets are loading slowly. Optimize their data sources and rendering.`,
        impact: 'medium',
        effort: 'low',
        action: 'Enable widget-level caching',
        priority_score: slowWidgets.length * 10,
        estimated_improvement: '50% faster widget loading'
      })
    }

    return insights
  }

  private analyzeMemoryUsage(metrics: PerformanceMetric[]): PerformanceInsight[] {
    const insights: PerformanceInsight[] = []
    const memoryMetrics = metrics.filter((m: any) => m.type === 'memory_usage')

    if (memoryMetrics.length === 0) return insights

    const maxMemory = Math.max(...memoryMetrics.map((m: any) => m.value))
    const avgMemory = memoryMetrics.reduce((sum, m) => sum + m.value, 0) / memoryMetrics.length

    if (maxMemory > 200) {
      insights.push({
        type: 'warning',
        title: 'High Memory Usage',
        description: `Peak memory
  usage reached ${Math.round(maxMemory)}MB. This may cause performance issues on lower-end devices.`,
        impact: 'high',
        effort: 'medium',
        action: 'Implement memory optimization strategies',
        priority_score: maxMemory / 2,
        estimated_improvement: '30% reduction in memory usage'
      })
    }

    return insights
  }

  private analyzeCachePerformance(metrics: PerformanceMetric[]): PerformanceInsight[] {
    const insights: PerformanceInsight[] = []
    const cacheMetrics = metrics.filter((m: any) => m.type === 'cache_hit_rate')

    if (cacheMetrics.length === 0) return insights

    const avgHitRate = cacheMetrics.reduce((sum, m) => sum + m.value, 0) / cacheMetrics.length

    if (avgHitRate < 70) {
      insights.push({
        type: 'optimization',
        title: 'Low Cache Hit Rate',
        description: `Cache hit rate is ${Math.round(avgHitRate)}%. Improve caching strategy to reduce load times.`,
        impact: 'medium',
        effort: 'low',
        action: 'Optimize cache policies and TTL settings',
        priority_score: (100 - avgHitRate) * 2,
        estimated_improvement: `${100 - avgHitRate}% improvement in cache efficiency`
      })
    }

    return insights
  }

  private analyzeBundleSize(metrics: PerformanceMetric[]): PerformanceInsight[] {
    const insights: PerformanceInsight[] = []
    const bundleMetrics = metrics.filter((m: any) => m.type === 'bundle_size')

    if (bundleMetrics.length === 0) return insights

    const maxBundle = Math.max(...bundleMetrics.map((m: any) => m.value))

    if (maxBundle > 2048) {
      insights.push({
        type: 'optimization',
        title: 'Large Bundle Size',
        description: `Bundle size is ${Math.round(maxBundle)}KB. Consider code splitting and tree shaking.`,
        impact: 'medium',
        effort: 'high',
        action: 'Implement dynamic imports and reduce bundle size',
        priority_score: maxBundle / 100,
        estimated_improvement: '40% smaller initial bundle'
      })
    }

    return insights
  }

  private analyzeUserInteractions(metrics: PerformanceMetric[]): PerformanceInsight[] {
    const insights: PerformanceInsight[] = []
    const interactionMetrics = metrics.filter((m: any) => m.type === 'user_interaction')

    if (interactionMetrics.length === 0) return insights

    const avgInteractionTime = interactionMetrics.reduce((sum, m) => sum + m.value, 0) / interactionMetrics.length

    if (avgInteractionTime > 100) {
      insights.push({
        type: 'recommendation',
        title: 'Slow User Interactions',
        description:
  `Average interaction response time is ${Math.round(avgInteractionTime)}ms. Users expect sub-100ms responses.`,
        impact: 'medium',
        effort: 'medium',
        action: 'Optimize event handlers and reduce main thread blocking',
        priority_score: avgInteractionTime / 2,
        estimated_improvement: 'Sub-100ms interaction responses'
      })
    }

    return insights
  }

  private analyzeDevicePerformance(metrics: PerformanceMetric[]): PerformanceInsight[] {
    const insights: PerformanceInsight[] = []

    // Group metrics by device type
    const deviceGroups = metrics.reduce((groups, metric) => {
      const deviceType = metric.context.device_type || 'unknown'
      if (!groups[deviceType]) groups[deviceType] = []
      groups[deviceType].push(metric)
      return groups
    }, {} as Record<string, PerformanceMetric[]>)

    // Analyze mobile performance
    if (deviceGroups.mobile?.length > 0) {
      const mobileMetrics = deviceGroups.mobile
      const avgLoadTime = mobileMetrics
        .filter((m: any) => m.type === 'load_time')
        .reduce((sum, m, _, arr) => sum + m.value / arr.length, 0)

      if (avgLoadTime > 3000) {
        insights.push({
          type: 'optimization',
          title: 'Poor Mobile Performance',
         
  description: `Mobile load times average ${Math.round(avgLoadTime)}ms. Mobile users expect faster experiences.`,
          impact: 'high',
          effort: 'medium',
          action: 'Implement mobile-specific optimizations',
          priority_score: 80,
          estimated_improvement: '50% faster mobile loading'
        })
      }
    }

    return insights
  }

  private generateWidgetOptimizations(metrics: PerformanceMetric[]): PerformanceInsight[] {
    // Widget-specific optimization logic
    return []
  }

  private generateDashboardOptimizations(metrics: PerformanceMetric[]): PerformanceInsight[] {
    // Dashboard-specific optimization logic
    return []
  }

  private generateDeviceOptimizations(deviceType: string): PerformanceInsight[] {
    const insights: PerformanceInsight[] = []

    if (deviceType === 'mobile') {
      insights.push({
        type: 'recommendation',
        title: 'Mobile Optimization',
        description: 'Enable mobile-specific optimizations for better performance on mobile devices.',
        impact: 'medium',
        effort: 'low',
        action: 'Enable mobile layout and reduce data loading',
        priority_score: 60,
        estimated_improvement: '30% better mobile performance'
      })
    }

    return insights
  }

  private async getWidgetMetrics(widgetId: string): Promise<PerformanceMetric[]> {
    const allMetrics: PerformanceMetric[] = []
    for (const metricsList of this.metrics.values()) {
      const widgetMetrics = metricsList.filter((m: any) => m.context.widget_id === widgetId)
      allMetrics.push(...widgetMetrics)
    }
    return allMetrics
  }

  private async getDashboardMetrics(dashboardId: string): Promise<PerformanceMetric[]> {
    const allMetrics: PerformanceMetric[] = []
    for (const metricsList of this.metrics.values()) {
      const dashboardMetrics = metricsList.filter((m: any) => m.context.dashboard_id === dashboardId)
      allMetrics.push(...dashboardMetrics)
    }
    return allMetrics
  }

  private parseTimeframe(timeframe: string): number {
    const multipliers = {
      '1h': 60 * 60 * 1000,
      '24h': 24 * 60 * 60 * 1000,
      '7d': 7 * 24 * 60 * 60 * 1000,
      '30d': 30 * 24 * 60 * 60 * 1000
    }
    return multipliers[timeframe as keyof typeof multipliers] || multipliers['24h']
  }

  private generateAlertMessage(metric: PerformanceMetric, severity: 'warning' | 'critical'): string {
    const messages = {
      load_time: `Widget load time ${severity}: ${metric.value}ms (threshold: ${metric.threshold?.[severity]}ms)`,
      render_time: `Render time ${severity}: ${metric.value}ms (threshold: ${metric.threshold?.[severity]}ms)`,
      memory_usage: `Memory usage ${severity}: ${metric.value}MB (threshold: ${metric.threshold?.[severity]}MB)`,
      cache_hit_rate: `Cache hit rate ${severity}: ${metric.value}% (threshold: ${metric.threshold?.[severity]}%)`,
      data_fetch: `Data fetch time ${severity}: ${metric.value}ms (threshold: ${metric.threshold?.[severity]}ms)`,
      user_interaction:
  `User interaction lag ${severity}: ${metric.value}ms (threshold: ${metric.threshold?.[severity]}ms)`,
      bundle_size: `Bundle size ${severity}: ${metric.value}KB (threshold: ${metric.threshold?.[severity]}KB)`
    }

    return messages[metric.type as keyof typeof messages] || `Performance ${severity}: ${metric.type} = ${metric.value}`
  }

  private async sendToAnalyticsEngine(metric: PerformanceMetric): Promise<void> {
    try {
      await this.env.ANALYTICS_ENGINE.writeDataPoint({
        blobs: [
          metric.type,
          metric.context.widget_id || '',
          metric.context.dashboard_id || '',
          metric.context.device_type || '',
          metric.context.browser || ''
        ],
        doubles: [metric.value],
        indexes: [metric.context.user_id || '']
      })
    } catch (error: any) {
    }
  }

  private async broadcastMetricUpdate(metric: PerformanceMetric): Promise<void> {
    // Broadcast to connected clients via WebSocket
    // Implementation would depend on WebSocket setup
  }

  private async sendAlertNotification(alert: PerformanceAlert): Promise<void> {
    // Send alert notification via email, Slack, etc.
    // Implementation would depend on notification setup
  }

  private async setupPerformanceObservers(dashboardId: string): Promise<void> {
    // Set up browser performance observers
    // This would be implemented on the client side
  }

  private async startResourceMonitoring(dashboardId: string): Promise<void> {
    // Start monitoring resource usage
    // This would be implemented on the client side
  }

  private async initializeInteractionTracking(dashboardId: string): Promise<void> {
    // Initialize user interaction tracking
    // This would be implemented on the client side
  }

  private schedulePeriodicTasks(): Promise<void> {
    // Schedule periodic cleanup and analysis tasks
    // This would use Durable Object alarms
    return Promise.resolve()
  }
}

// PerformanceMonitor is already exported as a class above