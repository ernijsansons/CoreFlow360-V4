/**
 * Smart Suggestions Component
 * AI-powered proactive suggestions and quick actions
 */

import React, { useState, useEffect, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Lightbulb,
  TrendingUp,
  AlertTriangle,
  Target,
  Zap,
  Clock,
  DollarSign,
  Users,
  Package,
  FileText,
  BarChart3,
  ChevronRight,
  X
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card } from '@/components/ui/card'
import { useSmartSuggestions } from '@/hooks/useSmartSuggestions'
import { useChatStore } from '@/stores/chatStore'
import type { SmartSuggestion, SuggestionType } from '@/types/chat'

export interface SmartSuggestionsProps {
  userId: string
  businessId: string
  currentContext?: any
  className?: string
  onSuggestionSelect?: (suggestion: SmartSuggestion) => void
}

const suggestionIcons: Record<SuggestionType, React.ComponentType<{ className?: string }>> = {
  insight: Lightbulb,
  action: Zap,
  optimization: TrendingUp,
  alert: AlertTriangle,
  opportunity: Target,
  reminder: Clock
}

const suggestionColors: Record<SuggestionType, string> = {
  insight: 'bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-700',
  action: 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-700',
  optimization: 'bg-purple-50 dark:bg-purple-900/20 border-purple-200 dark:border-purple-700',
  alert: 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-700',
  opportunity: 'bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-700',
  reminder: 'bg-gray-50 dark:bg-gray-900/20 border-gray-200 dark:border-gray-700'
}

const SuggestionCard: React.FC<{
  suggestion: SmartSuggestion
  onSelect: (suggestion: SmartSuggestion) => void
  onDismiss: (suggestionId: string) => void
}> = ({ suggestion, onSelect, onDismiss }) => {
  const Icon = suggestionIcons[suggestion.type]
  const colorClass = suggestionColors[suggestion.type]

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      className={cn(
        "relative p-4 rounded-lg border-2 cursor-pointer transition-all hover:shadow-md group",
        colorClass
      )}
      onClick={() => onSelect(suggestion)}
    >
      {/* Dismiss Button */}
      <Button
        variant="ghost"
        size="sm"
        className="absolute top-2 right-2 w-6 h-6 p-0 opacity-0 group-hover:opacity-100 transition-opacity"
        onClick={(e) => {
          e.stopPropagation()
          onDismiss(suggestion.id)
        }}
      >
        <X className="w-3 h-3" />
      </Button>

      {/* Header */}
      <div className="flex items-start space-x-3 mb-3">
        <div className={cn(
          "w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0",
          suggestion.type === 'insight' && "bg-blue-100 dark:bg-blue-800",
          suggestion.type === 'action' && "bg-green-100 dark:bg-green-800",
          suggestion.type === 'optimization' && "bg-purple-100 dark:bg-purple-800",
          suggestion.type === 'alert' && "bg-red-100 dark:bg-red-800",
          suggestion.type === 'opportunity' && "bg-yellow-100 dark:bg-yellow-800",
          suggestion.type === 'reminder' && "bg-gray-100 dark:bg-gray-800"
        )}>
          <Icon className="w-4 h-4" />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between mb-1">
            <h4 className="font-medium text-sm text-gray-900 dark:text-white">
              {suggestion.title}
            </h4>
            <div className="flex items-center space-x-1">
              {suggestion.priority && (
                <Badge
                  variant={suggestion.priority === 'high' ? 'destructive' : 'secondary'}
                  className="text-xs"
                >
                  {suggestion.priority}
                </Badge>
              )}
              {suggestion.impact && (
                <Badge variant="outline" className="text-xs">
                  {suggestion.impact}
                </Badge>
              )}
            </div>
          </div>

          <p className="text-xs text-gray-600 dark:text-gray-400 mb-2">
            {suggestion.description}
          </p>

          {/* Metrics */}
          {suggestion.metrics && suggestion.metrics.length > 0 && (
            <div className="flex items-center space-x-4 mb-2">
              {suggestion.metrics.map((metric, index) => (
                <div key={index} className="text-xs">
                  <span className="font-medium text-gray-900 dark:text-white">
                    {metric.value}
                  </span>
                  <span className="text-gray-500 dark:text-gray-400 ml-1">
                    {metric.label}
                  </span>
                </div>
              ))}
            </div>
          )}

          {/* Action Buttons */}
          {suggestion.actions && suggestion.actions.length > 0 && (
            <div className="flex items-center space-x-2">
              {suggestion.actions.slice(0, 2).map((action, index) => (
                <Button
                  key={index}
                  variant="outline"
                  size="sm"
                  className="h-7 px-2 text-xs"
                  onClick={(e) => {
                    e.stopPropagation()
                    onSelect({ ...suggestion, selectedAction: action })
                  }}
                >
                  {action.label}
                </Button>
              ))}
              {suggestion.actions.length > 2 && (
                <span className="text-xs text-gray-500">
                  +{suggestion.actions.length - 2} more
                </span>
              )}
            </div>
          )}
        </div>

        <ChevronRight className="w-4 h-4 text-gray-400 flex-shrink-0" />
      </div>
    </motion.div>
  )
}

export const SmartSuggestions: React.FC<SmartSuggestionsProps> = ({
  userId,
  businessId,
  currentContext,
  className,
  onSuggestionSelect
}) => {
  const [dismissedSuggestions, setDismissedSuggestions] = useState<Set<string>>(new Set())
  const [selectedCategory, setSelectedCategory] = useState<SuggestionType | 'all'>('all')

  const { sendMessage } = useChatStore()

  const {
    suggestions,
    isLoading,
    error,
    refreshSuggestions,
    dismissSuggestion
  } = useSmartSuggestions({
    userId,
    businessId,
    context: currentContext
  })

  // Filter suggestions
  const filteredSuggestions = useMemo(() => {
    return suggestions
      .filter(s => !dismissedSuggestions.has(s.id))
      .filter(s => selectedCategory === 'all' || s.type === selectedCategory)
      .sort((a, b) => {
        // Sort by priority (high -> medium -> low)
        const priorityOrder = { high: 3, medium: 2, low: 1 }
        const aPriority = priorityOrder[a.priority || 'low']
        const bPriority = priorityOrder[b.priority || 'low']

        if (aPriority !== bPriority) {
          return bPriority - aPriority
        }

        // Then by confidence
        return (b.confidence || 0) - (a.confidence || 0)
      })
  }, [suggestions, dismissedSuggestions, selectedCategory])

  // Get suggestion categories with counts
  const categories = useMemo(() => {
    const counts: Record<SuggestionType, number> = {
      insight: 0,
      action: 0,
      optimization: 0,
      alert: 0,
      opportunity: 0,
      reminder: 0
    }

    filteredSuggestions.forEach(s => {
      counts[s.type]++
    })

    return Object.entries(counts)
      .filter(([_, count]) => count > 0)
      .map(([type, count]) => ({ type: type as SuggestionType, count }))
  }, [filteredSuggestions])

  const handleSuggestionSelect = (suggestion: SmartSuggestion) => {
    // Convert suggestion to chat message
    let message = ''

    if (suggestion.selectedAction) {
      message = suggestion.selectedAction.command || suggestion.selectedAction.label
    } else {
      message = `Tell me more about: ${suggestion.title}`
    }

    sendMessage(message)
    onSuggestionSelect?.(suggestion)
  }

  const handleDismiss = (suggestionId: string) => {
    setDismissedSuggestions(prev => new Set([...prev, suggestionId]))
    dismissSuggestion(suggestionId)
  }

  if (isLoading) {
    return (
      <div className={cn("p-4", className)}>
        <div className="animate-pulse space-y-3">
          {[1, 2, 3].map(i => (
            <div key={i} className="h-20 bg-gray-200 dark:bg-gray-700 rounded-lg" />
          ))}
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className={cn("p-4 text-center", className)}>
        <AlertTriangle className="w-8 h-8 text-red-500 mx-auto mb-2" />
        <p className="text-sm text-red-600 dark:text-red-400">
          Failed to load suggestions
        </p>
        <Button
          variant="outline"
          size="sm"
          onClick={refreshSuggestions}
          className="mt-2"
        >
          Retry
        </Button>
      </div>
    )
  }

  if (filteredSuggestions.length === 0) {
    return (
      <div className={cn("p-4 text-center", className)}>
        <Lightbulb className="w-8 h-8 text-gray-400 mx-auto mb-2" />
        <p className="text-sm text-gray-500 dark:text-gray-400">
          No suggestions available right now
        </p>
        <Button
          variant="outline"
          size="sm"
          onClick={refreshSuggestions}
          className="mt-2"
        >
          Check for suggestions
        </Button>
      </div>
    )
  }

  return (
    <div className={cn("space-y-4", className)}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-gray-900 dark:text-white">
          Smart Suggestions
        </h3>
        <Button
          variant="outline"
          size="sm"
          onClick={refreshSuggestions}
          className="h-7 px-2"
        >
          Refresh
        </Button>
      </div>

      {/* Category Filter */}
      {categories.length > 1 && (
        <div className="flex items-center space-x-2 overflow-x-auto">
          <Button
            variant={selectedCategory === 'all' ? 'default' : 'outline'}
            size="sm"
            onClick={() => setSelectedCategory('all')}
            className="h-7 px-3 text-xs whitespace-nowrap"
          >
            All ({filteredSuggestions.length})
          </Button>
          {categories.map(({ type, count }) => {
            const Icon = suggestionIcons[type]
            return (
              <Button
                key={type}
                variant={selectedCategory === type ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSelectedCategory(type)}
                className="h-7 px-3 text-xs whitespace-nowrap"
              >
                <Icon className="w-3 h-3 mr-1" />
                {type} ({count})
              </Button>
            )
          })}
        </div>
      )}

      {/* Suggestions List */}
      <AnimatePresence mode="popLayout">
        <div className="space-y-3">
          {filteredSuggestions.map(suggestion => (
            <SuggestionCard
              key={suggestion.id}
              suggestion={suggestion}
              onSelect={handleSuggestionSelect}
              onDismiss={handleDismiss}
            />
          ))}
        </div>
      </AnimatePresence>
    </div>
  )
}

export default SmartSuggestions