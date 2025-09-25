/**
 * Drill-Down Hook
 * Manages hierarchical data navigation and context preservation
 */

import { useState, useCallback, useEffect } from 'react'
import { useRouter } from 'next/router'

export interface DrillDownLevel {
  id: string
  label: string
  parentId?: string
  filters: Record<string, any>
  breadcrumb: string[]
  data?: any
  timestamp: number
}

export interface DrillDownContext {
  currentLevel: DrillDownLevel | null
  history: DrillDownLevel[]
  canDrillUp: boolean
  canDrillDown: boolean
  isLoading: boolean
}

export interface DrillDownOptions {
  maxLevels?: number
  preserveFilters?: boolean
  enableHistory?: boolean
  autoFetch?: boolean
}

const DEFAULT_OPTIONS: DrillDownOptions = {
  maxLevels: 5,
  preserveFilters: true,
  enableHistory: true,
  autoFetch: true
}

export const useDrillDown = (
  widgetId: string,
  initialLevel?: DrillDownLevel,
  options: DrillDownOptions = {}
) => {
  const router = useRouter()
  const config = { ...DEFAULT_OPTIONS, ...options }

  const [context, setContext] = useState<DrillDownContext>({
    currentLevel: initialLevel || null,
    history: initialLevel ? [initialLevel] : [],
    canDrillUp: false,
    canDrillDown: true,
    isLoading: false
  })

  // Update navigation capabilities
  useEffect(() => {
    setContext(prev => ({
      ...prev,
      canDrillUp: prev.history.length > 1,
      canDrillDown: prev.history.length < config.maxLevels!
    }))
  }, [context.history.length, config.maxLevels])

  // Drill down to a specific level
  const drillDown = useCallback(async (
    levelId: string,
    label: string,
    filters: Record<string, any>,
    fetchData?: () => Promise<any>
  ) => {
    if (!context.canDrillDown) {
      console.warn('Maximum drill-down levels reached')
      return
    }

    setContext(prev => ({ ...prev, isLoading: true }))

    try {
      const newLevel: DrillDownLevel = {
        id: levelId,
        label,
        parentId: prev.currentLevel?.id,
        filters: config.preserveFilters
          ? { ...prev.currentLevel?.filters, ...filters }
          : filters,
        breadcrumb: prev.currentLevel
          ? [...prev.currentLevel.breadcrumb, label]
          : [label],
        timestamp: Date.now()
      }

      // Fetch data if auto-fetch is enabled
      if (config.autoFetch && fetchData) {
        newLevel.data = await fetchData()
      }

      setContext(prev => ({
        currentLevel: newLevel,
        history: config.enableHistory
          ? [...prev.history, newLevel]
          : [newLevel],
        canDrillUp: true,
        canDrillDown: prev.history.length + 1 < config.maxLevels!,
        isLoading: false
      }))

      // Update URL if needed
      if (router && typeof window !== 'undefined') {
        const url = new URL(window.location.href)
        url.searchParams.set(`drill_${widgetId}`, levelId)
        router.push(url.pathname + url.search, undefined, { shallow: true })
      }

    } catch (error) {
      console.error('Failed to drill down:', error)
      setContext(prev => ({ ...prev, isLoading: false }))
    }
  }, [context.canDrillDown, config, router, widgetId])

  // Drill up to previous level
  const drillUp = useCallback(() => {
    if (!context.canDrillUp || context.history.length <= 1) {
      return
    }

    const newHistory = context.history.slice(0, -1)
    const previousLevel = newHistory[newHistory.length - 1]

    setContext({
      currentLevel: previousLevel,
      history: newHistory,
      canDrillUp: newHistory.length > 1,
      canDrillDown: true,
      isLoading: false
    })

    // Update URL
    if (router && typeof window !== 'undefined') {
      const url = new URL(window.location.href)
      if (previousLevel) {
        url.searchParams.set(`drill_${widgetId}`, previousLevel.id)
      } else {
        url.searchParams.delete(`drill_${widgetId}`)
      }
      router.push(url.pathname + url.search, undefined, { shallow: true })
    }
  }, [context.canDrillUp, context.history, router, widgetId])

  // Navigate to specific level in history
  const navigateToLevel = useCallback((levelIndex: number) => {
    if (levelIndex < 0 || levelIndex >= context.history.length) {
      return
    }

    const targetLevel = context.history[levelIndex]
    const newHistory = context.history.slice(0, levelIndex + 1)

    setContext({
      currentLevel: targetLevel,
      history: newHistory,
      canDrillUp: newHistory.length > 1,
      canDrillDown: true,
      isLoading: false
    })

    // Update URL
    if (router && typeof window !== 'undefined') {
      const url = new URL(window.location.href)
      url.searchParams.set(`drill_${widgetId}`, targetLevel.id)
      router.push(url.pathname + url.search, undefined, { shallow: true })
    }
  }, [context.history, router, widgetId])

  // Reset to root level
  const resetDrillDown = useCallback(() => {
    const rootLevel = context.history[0]

    setContext({
      currentLevel: rootLevel || null,
      history: rootLevel ? [rootLevel] : [],
      canDrillUp: false,
      canDrillDown: true,
      isLoading: false
    })

    // Update URL
    if (router && typeof window !== 'undefined') {
      const url = new URL(window.location.href)
      url.searchParams.delete(`drill_${widgetId}`)
      router.push(url.pathname + url.search, undefined, { shallow: true })
    }
  }, [context.history, router, widgetId])

  // Get drill-down suggestions based on current level
  const getDrillDownSuggestions = useCallback((dataType: string, currentData?: any) => {
    const suggestions: Array<{
      id: string
      label: string
      description: string
      icon: string
      estimatedResults?: number
    }> = []

    if (!context.currentLevel) {
      return suggestions
    }

    const currentFilters = context.currentLevel.filters

    switch (dataType) {
      case 'sales':
        if (!currentFilters.timeRange) {
          suggestions.push({
            id: 'time-monthly',
            label: 'Monthly Breakdown',
            description: 'Break down by months',
            icon: 'calendar',
            estimatedResults: 12
          })
        }
        if (!currentFilters.region) {
          suggestions.push({
            id: 'region',
            label: 'By Region',
            description: 'Break down by geographic regions',
            icon: 'globe',
            estimatedResults: currentData?.regions?.length || 5
          })
        }
        if (!currentFilters.product) {
          suggestions.push({
            id: 'product',
            label: 'By Product',
            description: 'Break down by product categories',
            icon: 'package',
            estimatedResults: currentData?.products?.length || 10
          })
        }
        break

      case 'marketing':
        if (!currentFilters.channel) {
          suggestions.push({
            id: 'channel',
            label: 'By Channel',
            description: 'Break down by marketing channels',
            icon: 'megaphone',
            estimatedResults: 8
          })
        }
        if (!currentFilters.campaign) {
          suggestions.push({
            id: 'campaign',
            label: 'By Campaign',
            description: 'Break down by campaigns',
            icon: 'target',
            estimatedResults: currentData?.campaigns?.length || 15
          })
        }
        break

      case 'finance':
        if (!currentFilters.department) {
          suggestions.push({
            id: 'department',
            label: 'By Department',
            description: 'Break down by departments',
            icon: 'building',
            estimatedResults: 12
          })
        }
        if (!currentFilters.expense_type) {
          suggestions.push({
            id: 'expense-type',
            label: 'By Expense Type',
            description: 'Break down by expense categories',
            icon: 'credit-card',
            estimatedResults: 8
          })
        }
        break
    }

    return suggestions
  }, [context.currentLevel])

  // Auto-restore drill-down state from URL
  useEffect(() => {
    if (typeof window !== 'undefined' && router.isReady) {
      const url = new URL(window.location.href)
      const drillParam = url.searchParams.get(`drill_${widgetId}`)

      if (drillParam && !context.currentLevel) {
        // Restore drill-down state from URL parameter
        // This would typically involve fetching the drill-down path from the server
        console.log('Restoring drill-down state:', drillParam)
      }
    }
  }, [router.isReady, widgetId, context.currentLevel])

  return {
    context,
    drillDown,
    drillUp,
    navigateToLevel,
    resetDrillDown,
    getDrillDownSuggestions,

    // Convenience getters
    currentLevel: context.currentLevel,
    breadcrumb: context.currentLevel?.breadcrumb || [],
    currentFilters: context.currentLevel?.filters || {},
    isAtRoot: context.history.length <= 1,
    canGoBack: context.canDrillUp,
    canGoDeeper: context.canDrillDown,
    isLoading: context.isLoading
  }
}