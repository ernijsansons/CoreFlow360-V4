import { getCLS, getFID, getFCP, getLCP, getTTFB } from 'web-vitals'
import type { WebVitals } from '@/types'

interface PerformanceMetrics extends WebVitals {
  url: string
  userAgent: string
  timestamp: number
  sessionId: string
  userId?: string
  entityId?: string
}

class PerformanceMonitor {
  private metrics: PerformanceMetrics = {
    url: window.location.href,
    userAgent: navigator.userAgent,
    timestamp: Date.now(),
    sessionId: this.generateSessionId(),
  }

  private reportingEndpoint = '/api/analytics/performance'
  private buffer: PerformanceMetrics[] = []
  private bufferSize = 10
  private reportingInterval = 30000 // 30 seconds

  constructor() {
    this.initializeWebVitals()
    this.startReporting()
    this.setupNavigationTracking()
    this.setupResourceTracking()
    this.setupErrorTracking()
  }

  private generateSessionId(): string {
    return crypto.randomUUID()
  }

  private initializeWebVitals(): void {
    // Cumulative Layout Shift
    getCLS((metric) => {
      this.updateMetric('cls', metric.value)
    })

    // First Input Delay
    getFID((metric) => {
      this.updateMetric('fid', metric.value)
    })

    // First Contentful Paint
    getFCP((metric) => {
      this.updateMetric('fcp', metric.value)
    })

    // Largest Contentful Paint
    getLCP((metric) => {
      this.updateMetric('lcp', metric.value)
    })

    // Time to First Byte
    getTTFB((metric) => {
      this.updateMetric('ttfb', metric.value)
    })
  }

  private updateMetric(name: keyof WebVitals, value: number): void {
    this.metrics[name] = value
    this.reportMetric(name, value)
  }

  private reportMetric(name: string, value: number): void {
    console.log(`Performance metric ${name}:`, value)

    // Add to buffer for batch reporting
    this.buffer.push({
      ...this.metrics,
      [name]: value,
      timestamp: Date.now(),
    })

    // Report immediately for critical metrics
    if (name === 'lcp' && value > 2500) {
      this.sendMetrics([this.metrics])
    }

    if (name === 'fid' && value > 100) {
      this.sendMetrics([this.metrics])
    }

    if (name === 'cls' && value > 0.1) {
      this.sendMetrics([this.metrics])
    }
  }

  private startReporting(): void {
    setInterval(() => {
      if (this.buffer.length > 0) {
        this.sendMetrics([...this.buffer])
        this.buffer = []
      }
    }, this.reportingInterval)

    // Report on page visibility change
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'hidden' && this.buffer.length > 0) {
        this.sendMetrics([...this.buffer])
        this.buffer = []
      }
    })
  }

  private setupNavigationTracking(): void {
    // Track page load time
    window.addEventListener('load', () => {
      const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming

      if (navigation) {
        const pageLoadTime = navigation.loadEventEnd - navigation.fetchStart
        const domContentLoadedTime = navigation.domContentLoadedEventEnd - navigation.fetchStart
        const dnsTime = navigation.domainLookupEnd - navigation.domainLookupStart
        const tcpTime = navigation.connectEnd - navigation.connectStart

        this.reportCustomMetric('page_load_time', pageLoadTime)
        this.reportCustomMetric('dom_content_loaded_time', domContentLoadedTime)
        this.reportCustomMetric('dns_time', dnsTime)
        this.reportCustomMetric('tcp_time', tcpTime)
      }
    })

    // Track route changes (for SPA)
    let lastUrl = window.location.href

    const trackRouteChange = () => {
      const currentUrl = window.location.href
      if (currentUrl !== lastUrl) {
        const routeChangeTime = performance.now()
        this.reportCustomMetric('route_change_time', routeChangeTime)

        // Update metrics for new page
        this.metrics.url = currentUrl
        this.metrics.timestamp = Date.now()

        lastUrl = currentUrl
      }
    }

    // Use MutationObserver to detect URL changes
    const observer = new MutationObserver(trackRouteChange)
    observer.observe(document, { subtree: true, childList: true })

    // Also listen to popstate for browser navigation
    window.addEventListener('popstate', trackRouteChange)
  }

  private setupResourceTracking(): void {
    // Track resource loading performance
    const resourceObserver = new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        if (entry.entryType === 'resource') {
          const resource = entry as PerformanceResourceTiming

          // Track slow resources
          if (resource.duration > 1000) {
            this.reportCustomMetric('slow_resource', {
              name: resource.name,
              duration: resource.duration,
              size: resource.transferSize,
              type: resource.initiatorType,
            })
          }

          // Track failed resources
          if (resource.transferSize === 0 && resource.duration > 0) {
            this.reportCustomMetric('failed_resource', {
              name: resource.name,
              type: resource.initiatorType,
            })
          }
        }
      }
    })

    resourceObserver.observe({ type: 'resource', buffered: true })
  }

  private setupErrorTracking(): void {
    // Track JavaScript errors
    window.addEventListener('error', (event) => {
      this.reportCustomMetric('javascript_error', {
        message: event.message,
        filename: event.filename,
        lineno: event.lineno,
        colno: event.colno,
        stack: event.error?.stack,
      })
    })

    // Track unhandled promise rejections
    window.addEventListener('unhandledrejection', (event) => {
      this.reportCustomMetric('unhandled_rejection', {
        reason: event.reason,
        promise: event.promise,
      })
    })
  }

  private reportCustomMetric(name: string, value: any): void {
    console.log(`Custom metric ${name}:`, value)

    // Add to analytics
    if (window.gtag) {
      window.gtag('event', name, {
        custom_parameter: JSON.stringify(value),
      })
    }

    // Add to buffer for reporting
    this.buffer.push({
      ...this.metrics,
      customMetrics: {
        [name]: value,
      },
      timestamp: Date.now(),
    })
  }

  private async sendMetrics(metrics: PerformanceMetrics[]): Promise<void> {
    try {
      // Use sendBeacon for reliable delivery
      if (navigator.sendBeacon) {
        const payload = JSON.stringify({ metrics })
        navigator.sendBeacon(this.reportingEndpoint, payload)
      } else {
        // Fallback to fetch
        await fetch(this.reportingEndpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ metrics }),
          keepalive: true,
        })
      }
    } catch (error) {
      console.error('Failed to send performance metrics:', error)
    }
  }

  // Public methods for manual tracking
  public markStart(name: string): void {
    performance.mark(`${name}-start`)
  }

  public markEnd(name: string): void {
    performance.mark(`${name}-end`)
    performance.measure(name, `${name}-start`, `${name}-end`)

    const measure = performance.getEntriesByName(name, 'measure')[0]
    if (measure) {
      this.reportCustomMetric(`custom_${name}`, measure.duration)
    }
  }

  public recordTiming(name: string, duration: number): void {
    this.reportCustomMetric(`timing_${name}`, duration)
  }

  public recordCount(name: string, value = 1): void {
    this.reportCustomMetric(`count_${name}`, value)
  }

  public setUser(userId: string): void {
    this.metrics.userId = userId
  }

  public setEntity(entityId: string): void {
    this.metrics.entityId = entityId
  }

  // Get current performance summary
  public getPerformanceSummary(): PerformanceMetrics {
    return { ...this.metrics }
  }
}

// Global performance monitor instance
export const performanceMonitor = new PerformanceMonitor()

// React hook for component performance tracking
export function usePerformanceTracking(componentName: string) {
  React.useEffect(() => {
    const startTime = performance.now()
    performanceMonitor.markStart(`component-${componentName}`)

    return () => {
      const endTime = performance.now()
      const duration = endTime - startTime
      performanceMonitor.markEnd(`component-${componentName}`)
      performanceMonitor.recordTiming(`component-render-${componentName}`, duration)
    }
  }, [componentName])
}

// Hook for tracking user interactions
export function useInteractionTracking() {
  const trackClick = React.useCallback((elementName: string, additionalData?: any) => {
    performanceMonitor.recordCount(`click_${elementName}`)

    if (additionalData) {
      performanceMonitor.reportCustomMetric(`click_${elementName}_data`, additionalData)
    }
  }, [])

  const trackFormSubmit = React.useCallback((formName: string, success: boolean) => {
    performanceMonitor.recordCount(`form_submit_${formName}`)
    performanceMonitor.recordCount(`form_${success ? 'success' : 'error'}_${formName}`)
  }, [])

  const trackPageView = React.useCallback((pageName: string) => {
    performanceMonitor.recordCount(`page_view_${pageName}`)
  }, [])

  return {
    trackClick,
    trackFormSubmit,
    trackPageView,
  }
}

// Performance budget monitoring
export function checkPerformanceBudget(): {
  passed: boolean
  violations: string[]
} {
  const violations: string[] = []
  const metrics = performanceMonitor.getPerformanceSummary()

  // Check Core Web Vitals thresholds
  if (metrics.lcp && metrics.lcp > 2500) {
    violations.push(`LCP too slow: ${metrics.lcp}ms (should be < 2500ms)`)
  }

  if (metrics.fid && metrics.fid > 100) {
    violations.push(`FID too slow: ${metrics.fid}ms (should be < 100ms)`)
  }

  if (metrics.cls && metrics.cls > 0.1) {
    violations.push(`CLS too high: ${metrics.cls} (should be < 0.1)`)
  }

  if (metrics.fcp && metrics.fcp > 1800) {
    violations.push(`FCP too slow: ${metrics.fcp}ms (should be < 1800ms)`)
  }

  if (metrics.ttfb && metrics.ttfb > 800) {
    violations.push(`TTFB too slow: ${metrics.ttfb}ms (should be < 800ms)`)
  }

  return {
    passed: violations.length === 0,
    violations,
  }
}

// Bundle size monitoring
export function trackBundleSize(): void {
  if ('getEntriesByType' in performance) {
    const resources = performance.getEntriesByType('resource') as PerformanceResourceTiming[]

    let totalJSSize = 0
    let totalCSSSize = 0

    resources.forEach((resource) => {
      if (resource.name.includes('.js')) {
        totalJSSize += resource.transferSize || 0
      } else if (resource.name.includes('.css')) {
        totalCSSSize += resource.transferSize || 0
      }
    })

    performanceMonitor.recordTiming('bundle_js_size', totalJSSize)
    performanceMonitor.recordTiming('bundle_css_size', totalCSSSize)

    // Alert if bundles are too large
    if (totalJSSize > 500000) { // 500KB
      console.warn(`JS bundle size is large: ${(totalJSSize / 1024).toFixed(2)}KB`)
    }

    if (totalCSSSize > 100000) { // 100KB
      console.warn(`CSS bundle size is large: ${(totalCSSSize / 1024).toFixed(2)}KB`)
    }
  }
}