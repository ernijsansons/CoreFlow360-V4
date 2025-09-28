/**
 * CSS optimization utilities for CoreFlow360 V4
 * Critical CSS extraction, unused style removal, and performance optimization
 */

// Critical CSS configuration
export interface CriticalCSSConfig {
  viewport: {
    width: number
    height: number
  }
  timeout: number
  inlineThreshold: number
  extractCSS: boolean
  removeUnused: boolean
  minifyCSS: boolean
}

export const DEFAULT_CRITICAL_CSS_CONFIG: CriticalCSSConfig = {
  viewport: {
    width: 1920,
    height: 1080
  },
  timeout: 30000,
  inlineThreshold: 10000, // 10KB
  extractCSS: true,
  removeUnused: true,
  minifyCSS: true
}

// CSS performance monitoring
export class CSSPerformanceMonitor {
  private styleSheets: Map<string, StyleSheetMetrics> = new Map()
  private observers: MutationObserver[] = []

  constructor() {
    this.initializeMonitoring()
  }

  private initializeMonitoring(): void {
    if (typeof window === 'undefined') return

    // Monitor existing stylesheets
    this.analyzeExistingStyleSheets()

    // Monitor new stylesheets
    this.setupStyleSheetObserver()

    // Monitor CSS custom properties usage
    this.monitorCustomProperties()
  }

  private analyzeExistingStyleSheets(): void {
    Array.from(document.styleSheets).forEach((sheet, index) => {
      this.analyzeStyleSheet(sheet, `stylesheet-${index}`)
    })
  }

  private setupStyleSheetObserver(): void {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            const element = node as Element
            if (element.tagName === 'LINK' && (element as HTMLLinkElement).rel === 'stylesheet') {
              const link = element as HTMLLinkElement
              setTimeout(() => {
                if (link.sheet) {
                  this.analyzeStyleSheet(link.sheet, link.href || 'dynamic-stylesheet')
                }
              }, 100)
            } else if (element.tagName === 'STYLE') {
              const style = element as HTMLStyleElement
              if (style.sheet) {
                this.analyzeStyleSheet(style.sheet, 'inline-style')
              }
            }
          }
        })
      })
    })

    observer.observe(document.head, {
      childList: true,
      subtree: true
    })

    this.observers.push(observer)
  }

  private analyzeStyleSheet(sheet: CSSStyleSheet, identifier: string): void {
    try {
      const metrics: StyleSheetMetrics = {
        identifier,
        ruleCount: 0,
        selectorCount: 0,
        declarationCount: 0,
        size: 0,
        unusedRules: [],
        criticalRules: [],
        customProperties: new Set(),
        performance: {
          parseTime: 0,
          matchTime: 0,
          renderTime: 0
        }
      }

      const startTime = performance.now()

      if (sheet.cssRules) {
        this.analyzeRules(sheet.cssRules, metrics)
      }

      metrics.performance.parseTime = performance.now() - startTime
      this.styleSheets.set(identifier, metrics)

      // Report large stylesheets
      if (metrics.ruleCount > 1000) {
        console.warn(`Large stylesheet detected: ${identifier} (${metrics.ruleCount} rules)`)
      }

    } catch (error) {
      console.warn(`Could not analyze stylesheet ${identifier}:`, error)
    }
  }

  private analyzeRules(rules: CSSRuleList, metrics: StyleSheetMetrics): void {
    Array.from(rules).forEach((rule) => {
      metrics.ruleCount++

      if (rule instanceof CSSStyleRule) {
        metrics.selectorCount++
        metrics.declarationCount += rule.style.length

        // Check for custom properties
        Array.from(rule.style).forEach((property) => {
          if (property.startsWith('--')) {
            metrics.customProperties.add(property)
          }
        })

        // Analyze selector complexity
        const complexity = this.calculateSelectorComplexity(rule.selectorText)
        if (complexity > 10) {
          console.warn(`Complex selector detected: ${rule.selectorText} (complexity: ${complexity})`)
        }

        // Check if rule is used
        if (this.isRuleUnused(rule)) {
          metrics.unusedRules.push(rule.selectorText)
        }

        // Check if rule is critical (above the fold)
        if (this.isRuleCritical(rule)) {
          metrics.criticalRules.push(rule.selectorText)
        }

      } else if (rule instanceof CSSMediaRule) {
        this.analyzeRules(rule.cssRules, metrics)
      } else if (rule instanceof CSSSupportsRule) {
        this.analyzeRules(rule.cssRules, metrics)
      }
    })
  }

  private calculateSelectorComplexity(selector: string): number {
    // Simple complexity calculation based on selector parts
    const parts = selector.split(/[\s>+~]/)
    let complexity = parts.length

    // Add complexity for pseudo-selectors
    complexity += (selector.match(/:/g) || []).length

    // Add complexity for attribute selectors
    complexity += (selector.match(/\[/g) || []).length * 2

    // Add complexity for ID selectors (discouraged)
    complexity += (selector.match(/#/g) || []).length * 3

    return complexity
  }

  private isRuleUnused(rule: CSSStyleRule): boolean {
    try {
      return document.querySelectorAll(rule.selectorText).length === 0
    } catch {
      return false
    }
  }

  private isRuleCritical(rule: CSSStyleRule): boolean {
    try {
      const elements = document.querySelectorAll(rule.selectorText)
      return Array.from(elements).some((element) => {
        const rect = element.getBoundingClientRect()
        return rect.top < window.innerHeight && rect.left < window.innerWidth
      })
    } catch {
      return false
    }
  }

  private monitorCustomProperties(): void {
    const computedStyle = getComputedStyle(document.documentElement)
    const customProps = new Set<string>()

    // Extract all custom properties from root
    Array.from(computedStyle).forEach((property) => {
      if (property.startsWith('--')) {
        customProps.add(property)
      }
    })

    console.log(`Found ${customProps.size} CSS custom properties`)
  }

  public getMetrics(): Map<string, StyleSheetMetrics> {
    return new Map(this.styleSheets)
  }

  public generateReport(): CSSPerformanceReport {
    const metrics = Array.from(this.styleSheets.values())

    return {
      totalStyleSheets: metrics.length,
      totalRules: metrics.reduce((sum, m) => sum + m.ruleCount, 0),
      totalSelectors: metrics.reduce((sum, m) => sum + m.selectorCount, 0),
      totalDeclarations: metrics.reduce((sum, m) => sum + m.declarationCount, 0),
      unusedRules: metrics.flatMap(m => m.unusedRules),
      criticalRules: metrics.flatMap(m => m.criticalRules),
      customProperties: new Set(metrics.flatMap(m => Array.from(m.customProperties))),
      largestStyleSheet: metrics.reduce((largest, current) =>
        current.ruleCount > largest.ruleCount ? current : largest,
        metrics[0]
      ),
      recommendations: this.generateRecommendations(metrics)
    }
  }

  private generateRecommendations(metrics: StyleSheetMetrics[]): string[] {
    const recommendations: string[] = []

    const totalUnused = metrics.reduce((sum, m) => sum + m.unusedRules.length, 0)
    if (totalUnused > 100) {
      recommendations.push(`Remove ${totalUnused} unused CSS rules to reduce bundle size`)
    }

    const complexSelectors = metrics.flatMap(m =>
      Array.from(document.styleSheets).flatMap(sheet => {
        try {
          return Array.from(sheet.cssRules || [])
            .filter((rule): rule is CSSStyleRule => rule instanceof CSSStyleRule)
            .filter(rule => this.calculateSelectorComplexity(rule.selectorText) > 10)
            .map(rule => rule.selectorText)
        } catch {
          return []
        }
      })
    )

    if (complexSelectors.length > 0) {
      recommendations.push(`Simplify ${complexSelectors.length} complex selectors for better performance`)
    }

    const totalRules = metrics.reduce((sum, m) => sum + m.ruleCount, 0)
    if (totalRules > 5000) {
      recommendations.push('Consider code splitting CSS to reduce initial bundle size')
    }

    return recommendations
  }

  public cleanup(): void {
    this.observers.forEach(observer => observer.disconnect())
    this.observers = []
    this.styleSheets.clear()
  }
}

// CSS optimization utilities
export class CSSOptimizer {
  private config: CriticalCSSConfig

  constructor(config: CriticalCSSConfig = DEFAULT_CRITICAL_CSS_CONFIG) {
    this.config = config
  }

  // Extract critical CSS for above-the-fold content
  public async extractCriticalCSS(): Promise<string> {
    const criticalCSS: string[] = []

    // Get all stylesheets
    const styleSheets = Array.from(document.styleSheets)

    for (const sheet of styleSheets) {
      try {
        if (sheet.cssRules) {
          const critical = this.extractCriticalRulesFromSheet(sheet)
          criticalCSS.push(critical)
        }
      } catch (error) {
        console.warn('Could not access stylesheet:', error)
      }
    }

    let result = criticalCSS.join('\n')

    if (this.config.minifyCSS) {
      result = this.minifyCSS(result)
    }

    return result
  }

  private extractCriticalRulesFromSheet(sheet: CSSStyleSheet): string {
    const criticalRules: string[] = []

    Array.from(sheet.cssRules || []).forEach((rule) => {
      if (rule instanceof CSSStyleRule) {
        if (this.isRuleCritical(rule)) {
          criticalRules.push(rule.cssText)
        }
      } else if (rule instanceof CSSMediaRule) {
        // Check media queries that apply to current viewport
        if (window.matchMedia(rule.conditionText).matches) {
          Array.from(rule.cssRules).forEach((mediaRule) => {
            if (mediaRule instanceof CSSStyleRule && this.isRuleCritical(mediaRule)) {
              criticalRules.push(`@media ${rule.conditionText} { ${mediaRule.cssText} }`)
            }
          })
        }
      } else if (rule instanceof CSSFontFaceRule) {
        // Include font-face rules as they're often critical
        criticalRules.push(rule.cssText)
      }
    })

    return criticalRules.join('\n')
  }

  private isRuleCritical(rule: CSSStyleRule): boolean {
    try {
      const elements = document.querySelectorAll(rule.selectorText)
      return Array.from(elements).some((element) => {
        const rect = element.getBoundingClientRect()
        return (
          rect.top < this.config.viewport.height &&
          rect.left < this.config.viewport.width &&
          rect.bottom > 0 &&
          rect.right > 0
        )
      })
    } catch {
      return false
    }
  }

  private minifyCSS(css: string): string {
    return css
      .replace(/\/\*[\s\S]*?\*\//g, '') // Remove comments
      .replace(/\s+/g, ' ') // Collapse whitespace
      .replace(/;\s*}/g, '}') // Remove unnecessary semicolons
      .replace(/\s*{\s*/g, '{') // Remove spaces around braces
      .replace(/}\s*/g, '}') // Remove spaces after braces
      .replace(/;\s*/g, ';') // Remove spaces after semicolons
      .replace(/:\s*/g, ':') // Remove spaces after colons
      .trim()
  }

  // Remove unused CSS
  public removeUnusedCSS(): void {
    const styleSheets = Array.from(document.styleSheets)

    styleSheets.forEach((sheet) => {
      try {
        if (sheet.cssRules) {
          this.removeUnusedRulesFromSheet(sheet)
        }
      } catch (error) {
        console.warn('Could not process stylesheet:', error)
      }
    })
  }

  private removeUnusedRulesFromSheet(sheet: CSSStyleSheet): void {
    const rulesToRemove: number[] = []

    Array.from(sheet.cssRules || []).forEach((rule, index) => {
      if (rule instanceof CSSStyleRule) {
        try {
          if (document.querySelectorAll(rule.selectorText).length === 0) {
            rulesToRemove.push(index)
          }
        } catch {
          // Invalid selector, keep it
        }
      }
    })

    // Remove rules in reverse order to maintain indices
    rulesToRemove.reverse().forEach((index) => {
      try {
        sheet.deleteRule(index)
      } catch (error) {
        console.warn('Could not remove rule:', error)
      }
    })

    if (rulesToRemove.length > 0) {
      console.log(`Removed ${rulesToRemove.length} unused CSS rules`)
    }
  }
}

// Types for CSS metrics
interface StyleSheetMetrics {
  identifier: string
  ruleCount: number
  selectorCount: number
  declarationCount: number
  size: number
  unusedRules: string[]
  criticalRules: string[]
  customProperties: Set<string>
  performance: {
    parseTime: number
    matchTime: number
    renderTime: number
  }
}

interface CSSPerformanceReport {
  totalStyleSheets: number
  totalRules: number
  totalSelectors: number
  totalDeclarations: number
  unusedRules: string[]
  criticalRules: string[]
  customProperties: Set<string>
  largestStyleSheet: StyleSheetMetrics
  recommendations: string[]
}

// CSS loading optimization
export class CSSLoader {
  private loadedStylesheets = new Set<string>()

  // Load CSS conditionally based on media queries
  public loadConditionalCSS(href: string, condition: string): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.loadedStylesheets.has(href)) {
        resolve()
        return
      }

      const link = document.createElement('link')
      link.rel = 'stylesheet'
      link.href = href
      link.media = condition

      link.onload = () => {
        this.loadedStylesheets.add(href)
        // Change media to 'all' after loading
        link.media = 'all'
        resolve()
      }

      link.onerror = () => {
        reject(new Error(`Failed to load CSS: ${href}`))
      }

      document.head.appendChild(link)
    })
  }

  // Preload CSS for future use
  public preloadCSS(href: string): void {
    if (this.loadedStylesheets.has(href)) return

    const link = document.createElement('link')
    link.rel = 'preload'
    link.as = 'style'
    link.href = href

    // Convert to stylesheet when loaded
    link.onload = () => {
      link.rel = 'stylesheet'
      this.loadedStylesheets.add(href)
    }

    document.head.appendChild(link)
  }

  // Load CSS for specific components
  public async loadComponentCSS(componentName: string): Promise<void> {
    const href = `/css/components/${componentName}.css`
    return this.loadConditionalCSS(href, 'all')
  }

  // Load CSS for specific features
  public async loadFeatureCSS(featureName: string): Promise<void> {
    const href = `/css/features/${featureName}.css`
    return this.loadConditionalCSS(href, 'all')
  }
}

// Global CSS optimization instance
export const cssOptimizer = new CSSOptimizer()
export const cssMonitor = new CSSPerformanceMonitor()
export const cssLoader = new CSSLoader()

// Utility to inline critical CSS
export function inlineCriticalCSS(): void {
  cssOptimizer.extractCriticalCSS().then((criticalCSS) => {
    if (criticalCSS.length > 0 && criticalCSS.length < DEFAULT_CRITICAL_CSS_CONFIG.inlineThreshold) {
      const style = document.createElement('style')
      style.textContent = criticalCSS
      style.setAttribute('data-critical', 'true')
      document.head.appendChild(style)
    }
  })
}

// Performance monitoring hook
export function useCSSPerformance() {
  React.useEffect(() => {
    const monitor = new CSSPerformanceMonitor()

    // Generate report after component mount
    setTimeout(() => {
      const report = monitor.generateReport()
      console.log('CSS Performance Report:', report)
    }, 1000)

    return () => {
      monitor.cleanup()
    }
  }, [])
}