/**
 * Smart Suggestions Hook
 * Handles fetching and managing AI-powered suggestions
 */

import { useState, useEffect, useCallback } from 'react'
import type { SmartSuggestion } from '@/types/chat'

interface SmartSuggestionsOptions {
  userId: string
  businessId: string
  context?: any
  refreshInterval?: number
}

export const useSmartSuggestions = ({
  userId,
  businessId,
  context,
  refreshInterval = 5 * 60 * 1000 // 5 minutes
}: SmartSuggestionsOptions) => {
  const [suggestions, setSuggestions] = useState<SmartSuggestion[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null)

  const fetchSuggestions = useCallback(async () => {
    try {
      setIsLoading(true)
      setError(null)

      const response = await fetch('/api/v1/chat/suggestions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          userId,
          businessId,
          context: {
            ...context,
            timeContext: {
              timeOfDay: new Date().getHours() < 12 ? 'morning' : new Date().getHours() < 18 ? 'afternoon' : 'evening',
              dayOfWeek: new Date().toLocaleDateString('en-US', { weekday: 'long' }),
              isBusinessHours: isBusinessHours()
            }
          }
        })
      })

      if (!response.ok) {
        throw new Error(`Failed to fetch suggestions: ${response.statusText}`)
      }

      const result = await response.json()
      setSuggestions(result.suggestions || [])
      setLastRefresh(new Date())

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch suggestions'
      setError(errorMessage)
      console.error('Error fetching suggestions:', err)
    } finally {
      setIsLoading(false)
    }
  }, [userId, businessId, context])

  const refreshSuggestions = useCallback(() => {
    fetchSuggestions()
  }, [fetchSuggestions])

  const dismissSuggestion = useCallback(async (suggestionId: string) => {
    try {
      // Optimistically remove from state
      setSuggestions(prev => prev.filter(s => s.id !== suggestionId))

      // Send dismissal to server
      await fetch('/api/v1/chat/suggestions/dismiss', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          suggestionId,
          userId
        })
      })

    } catch (err) {
      console.error('Error dismissing suggestion:', err)
      // Could restore the suggestion if needed
    }
  }, [userId])

  // Initial fetch
  useEffect(() => {
    if (userId && businessId) {
      fetchSuggestions()
    }
  }, [userId, businessId, fetchSuggestions])

  // Auto-refresh
  useEffect(() => {
    if (!refreshInterval || refreshInterval <= 0) return

    const interval = setInterval(() => {
      if (!isLoading) {
        fetchSuggestions()
      }
    }, refreshInterval)

    return () => clearInterval(interval)
  }, [fetchSuggestions, refreshInterval, isLoading])

  // Refresh when context changes significantly
  useEffect(() => {
    if (context?.currentPage && lastRefresh) {
      const timeSinceRefresh = Date.now() - lastRefresh.getTime()
      // Refresh if page changed and it's been more than 30 seconds
      if (timeSinceRefresh > 30000) {
        fetchSuggestions()
      }
    }
  }, [context?.currentPage, lastRefresh, fetchSuggestions])

  return {
    suggestions,
    isLoading,
    error,
    lastRefresh,
    refreshSuggestions,
    dismissSuggestion
  }
}

// Helper function to determine business hours
const isBusinessHours = (): boolean => {
  const now = new Date()
  const hour = now.getHours()
  const day = now.getDay()

  // Monday to Friday, 9 AM to 5 PM
  return day >= 1 && day <= 5 && hour >= 9 && hour < 17
}

export default useSmartSuggestions