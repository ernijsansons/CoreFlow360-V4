/**
 * Performance Monitor Hook
 * Client-side performance monitoring and metrics collection
 */

import { useEffect, useCallback, useRef, useState } from 'react'
import { useRouter } from 'next/router'

export interface PerformanceMetric {
  type: 'load_time' | 'render_time' | 'data_fetch' | 'user_interaction' | 'memory_usage' | 'bundle_size' | 'cache_hit_rate'
  value: number
  unit: 'ms' | 'mb' | 'percent' | 'count' | 'kb'
  context: {
    widget_id?: string
    dashboard_id?: string
    user_id?: string
    session_id?: string
    device_type?: 'mobile' | 'tablet' | 'desktop'
    browser?: string
    connection?: string
    viewport?: { width: number; height: number }
    memory?: { used: number; total: number }
    cpu_cores?: number
    location?: string
  }
  tags?: string[]
}

export interface PerformanceAlert {
  id: string
  metric_type: string
  severity: 'warning' | 'critical'
  message: string
  value: number
  threshold: number
  timestamp: number
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

export const usePerformanceMonitor = (
  dashboardId?: string,
  widgetId?: string,
  options: {
    enabled?: boolean
    sampleRate?: number
    trackUserInteractions?: boolean
    trackMemoryUsage?: boolean
    trackNetworkRequests?: boolean
  } = {}
) => {
  const router = useRouter()
  const {
    enabled = true,
    sampleRate = 1.0,
    trackUserInteractions = true,
    trackMemoryUsage = true,
    trackNetworkRequests = true
  } = options

  const [alerts, setAlerts] = useState<PerformanceAlert[]>([])
  const [insights, setInsights] = useState<PerformanceInsight[]>([])
  const [isMonitoring, setIsMonitoring] = useState(false)

  const sessionId = useRef<string>()
  const startTime = useRef<number>()
  const observers = useRef<PerformanceObserver[]>([])
  const interactionStart = useRef<number>()

  // Initialize session
  useEffect(() => {
    if (!enabled) return

    sessionId.current = `session-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    startTime.current = performance.now()
    setIsMonitoring(true)

    return () => {
      cleanup()
    }
  }, [enabled])

  // Send metric to server
  const sendMetric = useCallback(async (metric: PerformanceMetric) => {
    if (!enabled || Math.random() > sampleRate) return

    try {
      const context = {
        dashboard_id: dashboardId,
        widget_id: widgetId,
        session_id: sessionId.current,
        user_id: getUserId(),
        device_type: getDeviceType(),
        browser: getBrowser(),
        connection: getConnectionType(),
        viewport: getViewport(),
        memory: getMemoryInfo(),
        cpu_cores: navigator.hardwareConcurrency,
        location: window.location.pathname,
        ...metric.context
      }

      await fetch('/api/performance/metrics', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${getAuthToken()}`
        },
        body: JSON.stringify({
          ...metric,
          context
        })
      })
    } catch (error) {
      console.debug('Failed to send performance metric:', error)
    }
  }, [enabled, sampleRate, dashboardId, widgetId])

  // Track widget load time
  const trackWidgetLoad = useCallback((widgetId: string, startTime: number) => {
    const loadTime = performance.now() - startTime

    sendMetric({
      type: 'load_time',
      value: loadTime,
      unit: 'ms',
      context: { widget_id: widgetId },
      tags: ['widget', 'load']
    })
  }, [sendMetric])

  // Track render time
  const trackRender = useCallback((componentName: string, renderTime: number) => {
    sendMetric({
      type: 'render_time',
      value: renderTime,
      unit: 'ms',
      context: { widget_id: widgetId },
      tags: ['render', componentName]
    })
  }, [sendMetric, widgetId])

  // Track data fetch time
  const trackDataFetch = useCallback((dataSource: string, fetchTime: number, success: boolean) => {
    sendMetric({
      type: 'data_fetch',
      value: fetchTime,
      unit: 'ms',
      context: { widget_id: widgetId },
      tags: ['data-fetch', dataSource, success ? 'success' : 'error']
    })
  }, [sendMetric, widgetId])

  // Track user interaction
  const trackInteraction = useCallback((interactionType: string, duration: number) => {
    sendMetric({
      type: 'user_interaction',
      value: duration,
      unit: 'ms',
      context: { widget_id: widgetId },
      tags: ['interaction', interactionType]
    })
  }, [sendMetric, widgetId])

  // Track cache performance
  const trackCacheHit = useCallback((hit: boolean, cacheType: string) => {
    sendMetric({
      type: 'cache_hit_rate',
      value: hit ? 100 : 0,
      unit: 'percent',
      context: { widget_id: widgetId },
      tags: ['cache', cacheType, hit ? 'hit' : 'miss']
    })
  }, [sendMetric, widgetId])

  // Set up performance observers
  useEffect(() => {
    if (!enabled || typeof window === 'undefined') return

    const setupObservers = () => {
      // Long Task Observer
      if ('PerformanceObserver' in window) {
        try {
          const longTaskObserver = new PerformanceObserver((list) => {
            list.getEntries().forEach((entry) => {
              sendMetric({
                type: 'user_interaction',
                value: entry.duration,
                unit: 'ms',
                context: {},
                tags: ['long-task']
              })
            })
          })

          longTaskObserver.observe({ entryTypes: ['longtask'] })
          observers.current.push(longTaskObserver)
        } catch (error) {
          console.debug('Long task observer not supported:', error)
        }

        // Layout Shift Observer
        try {
          const layoutShiftObserver = new PerformanceObserver((list) => {
            list.getEntries().forEach((entry: any) => {
              if (entry.value > 0.1) {
                sendMetric({
                  type: 'user_interaction',
                  value: entry.value,
                  unit: 'count',
                  context: {},
                  tags: ['layout-shift']
                })
              }
            })
          })

          layoutShiftObserver.observe({ entryTypes: ['layout-shift'] })
          observers.current.push(layoutShiftObserver)
        } catch (error) {
          console.debug('Layout shift observer not supported:', error)
        }

        // Largest Contentful Paint Observer
        try {
          const lcpObserver = new PerformanceObserver((list) => {
            list.getEntries().forEach((entry) => {
              sendMetric({
                type: 'render_time',
                value: entry.startTime,
                unit: 'ms',
                context: {},
                tags: ['lcp']
              })
            })
          })

          lcpObserver.observe({ entryTypes: ['largest-contentful-paint'] })
          observers.current.push(lcpObserver)
        } catch (error) {
          console.debug('LCP observer not supported:', error)
        }

        // First Input Delay Observer
        try {
          const fidObserver = new PerformanceObserver((list) => {
            list.getEntries().forEach((entry: any) => {
              sendMetric({
                type: 'user_interaction',
                value: entry.processingStart - entry.startTime,
                unit: 'ms',
                context: {},
                tags: ['first-input-delay']
              })
            })
          })

          fidObserver.observe({ entryTypes: ['first-input'] })
          observers.current.push(fidObserver)
        } catch (error) {
          console.debug('FID observer not supported:', error)
        }
      }
    }

    setupObservers()

    return () => {
      observers.current.forEach(observer => observer.disconnect())
      observers.current = []
    }
  }, [enabled, sendMetric])

  // Memory monitoring
  useEffect(() => {
    if (!enabled || !trackMemoryUsage || typeof window === 'undefined') return

    const trackMemory = () => {
      if ('memory' in performance) {
        const memory = (performance as any).memory
        sendMetric({
          type: 'memory_usage',
          value: memory.usedJSHeapSize / 1024 / 1024, // Convert to MB
          unit: 'mb',
          context: {
            memory: {
              used: memory.usedJSHeapSize,
              total: memory.totalJSHeapSize
            }
          },
          tags: ['memory']
        })
      }
    }

    // Track memory every 30 seconds
    const interval = setInterval(trackMemory, 30000)
    trackMemory() // Initial measurement

    return () => clearInterval(interval)
  }, [enabled, trackMemoryUsage, sendMetric])

  // User interaction tracking
  useEffect(() => {
    if (!enabled || !trackUserInteractions) return

    const handleInteractionStart = () => {
      interactionStart.current = performance.now()
    }

    const handleInteractionEnd = (eventType: string) => {
      if (interactionStart.current) {
        const duration = performance.now() - interactionStart.current
        trackInteraction(eventType, duration)
        interactionStart.current = undefined
      }
    }

    const events = ['click', 'keydown', 'scroll', 'touchstart']
    events.forEach(event => {
      document.addEventListener(event, handleInteractionStart, { passive: true })
    })

    const endEvents = ['click', 'keyup', 'scrollend', 'touchend']
    endEvents.forEach((event, index) => {
      document.addEventListener(event, () => handleInteractionEnd(events[index]), { passive: true })
    })

    return () => {
      events.forEach(event => {
        document.removeEventListener(event, handleInteractionStart)
      })
      endEvents.forEach((event, index) => {
        document.removeEventListener(event, () => handleInteractionEnd(events[index]))
      })
    }
  }, [enabled, trackUserInteractions, trackInteraction])

  // Network request monitoring
  useEffect(() => {
    if (!enabled || !trackNetworkRequests) return

    const originalFetch = window.fetch
    window.fetch = async (...args) => {
      const startTime = performance.now()
      try {
        const response = await originalFetch(...args)
        const endTime = performance.now()

        sendMetric({
          type: 'data_fetch',
          value: endTime - startTime,
          unit: 'ms',
          context: {},
          tags: ['fetch', response.ok ? 'success' : 'error']
        })

        return response
      } catch (error) {
        const endTime = performance.now()
        sendMetric({
          type: 'data_fetch',
          value: endTime - startTime,
          unit: 'ms',
          context: {},
          tags: ['fetch', 'error']
        })
        throw error
      }
    }

    return () => {
      window.fetch = originalFetch
    }
  }, [enabled, trackNetworkRequests, sendMetric])

  // Load insights and alerts
  const loadInsights = useCallback(async () => {
    try {
      const response = await fetch(`/api/performance/insights?dashboard=${dashboardId}`, {
        headers: {
          'Authorization': `Bearer ${getAuthToken()}`
        }
      })

      const data = await response.json()
      if (data.success) {
        setInsights(data.insights)
      }
    } catch (error) {
      console.error('Failed to load performance insights:', error)
    }
  }, [dashboardId])

  const loadAlerts = useCallback(async () => {
    try {
      const response = await fetch(`/api/performance/alerts?dashboard=${dashboardId}`, {
        headers: {
          'Authorization': `Bearer ${getAuthToken()}`
        }
      })

      const data = await response.json()
      if (data.success) {
        setAlerts(data.alerts)
      }
    } catch (error) {
      console.error('Failed to load performance alerts:', error)
    }
  }, [dashboardId])

  // Cleanup function
  const cleanup = useCallback(() => {
    observers.current.forEach(observer => observer.disconnect())
    observers.current = []
    setIsMonitoring(false)
  }, [])

  // Load data on mount
  useEffect(() => {
    if (enabled) {
      loadInsights()
      loadAlerts()
    }
  }, [enabled, loadInsights, loadAlerts])

  return {
    // Tracking methods
    trackWidgetLoad,
    trackRender,
    trackDataFetch,
    trackInteraction,
    trackCacheHit,
    sendMetric,

    // Data
    alerts,
    insights,
    isMonitoring,

    // Actions
    loadInsights,
    loadAlerts,
    cleanup
  }
}

// React component wrapper for performance monitoring
export const withPerformanceMonitoring = <P extends object>(
  Component: React.ComponentType<P>,
  options: {
    trackRender?: boolean
    trackProps?: boolean
    componentName?: string
  } = {}
) => {
  return React.forwardRef<any, P>((props, ref) => {
    const { trackRender = true, trackProps = false, componentName = Component.name } = options
    const { trackRender: trackRenderFn, sendMetric } = usePerformanceMonitor()
    const renderStart = useRef<number>()

    // Track render start
    useEffect(() => {
      if (trackRender) {
        renderStart.current = performance.now()
      }
    })

    // Track render end
    useEffect(() => {
      if (trackRender && renderStart.current) {
        const renderTime = performance.now() - renderStart.current
        trackRenderFn(componentName, renderTime)
      }
    })

    // Track prop changes
    useEffect(() => {
      if (trackProps) {
        sendMetric({
          type: 'user_interaction',
          value: 1,
          unit: 'count',
          context: {},
          tags: ['prop-change', componentName]
        })
      }
    }, [props, trackProps, sendMetric, componentName])

    return <Component {...props} ref={ref} />
  })
}

// Helper functions
function getDeviceType(): 'mobile' | 'tablet' | 'desktop' {
  const width = window.innerWidth
  if (width < 768) return 'mobile'
  if (width < 1024) return 'tablet'
  return 'desktop'
}

function getBrowser(): string {
  const userAgent = navigator.userAgent
  if (userAgent.includes('Chrome')) return 'chrome'
  if (userAgent.includes('Firefox')) return 'firefox'
  if (userAgent.includes('Safari')) return 'safari'
  if (userAgent.includes('Edge')) return 'edge'
  return 'unknown'
}

function getConnectionType(): string {
  if ('connection' in navigator) {
    return (navigator as any).connection?.effectiveType || 'unknown'
  }
  return 'unknown'
}

function getViewport(): { width: number; height: number } {
  return {
    width: window.innerWidth,
    height: window.innerHeight
  }
}

function getMemoryInfo(): { used: number; total: number } | undefined {
  if ('memory' in performance) {
    const memory = (performance as any).memory
    return {
      used: memory.usedJSHeapSize,
      total: memory.totalJSHeapSize
    }
  }
  return undefined
}

function getUserId(): string {
  return localStorage.getItem('userId') || 'anonymous'
}

function getAuthToken(): string {
  return localStorage.getItem('authToken') || ''
}

export default usePerformanceMonitor