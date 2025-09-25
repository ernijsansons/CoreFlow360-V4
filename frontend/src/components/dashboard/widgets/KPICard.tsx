/**
 * KPI Card Widget
 * Displays key performance indicators with trends and sparklines
 */

import React, { useMemo } from 'react'
import { motion } from 'framer-motion'
import {
  TrendingUp,
  TrendingDown,
  Minus,
  Target,
  AlertTriangle,
  CheckCircle,
  Circle
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Sparkline } from './charts/Sparkline'
import type { Widget } from '@/types/dashboard'

export interface KPICardProps {
  widget: Widget
  data?: {
    value: number
    target?: number
    trend: number
    previousValue?: number
    sparklineData?: number[]
    unit?: string
    prefix?: string
    suffix?: string
    status?: 'success' | 'warning' | 'danger' | 'neutral'
    threshold?: {
      good: number
      warning: number
    }
  }
  isExpanded?: boolean
  className?: string
}

const formatValue = (value: number, prefix = '', suffix = '', decimals = 0): string => {
  if (value >= 1e9) {
    return `${prefix}${(value / 1e9).toFixed(decimals)}B${suffix}`
  } else if (value >= 1e6) {
    return `${prefix}${(value / 1e6).toFixed(decimals)}M${suffix}`
  } else if (value >= 1e3) {
    return `${prefix}${(value / 1e3).toFixed(decimals)}K${suffix}`
  }
  return `${prefix}${value.toLocaleString(undefined, { maximumFractionDigits: decimals })}${suffix}`
}

const getTrendIcon = (trend: number) => {
  if (trend > 0) return TrendingUp
  if (trend < 0) return TrendingDown
  return Minus
}

const getTrendColor = (trend: number) => {
  if (trend > 0) return 'text-green-600 dark:text-green-400'
  if (trend < 0) return 'text-red-600 dark:text-red-400'
  return 'text-gray-500 dark:text-gray-400'
}

const getStatusColor = (status: string) => {
  switch (status) {
    case 'success': return 'text-green-600 dark:text-green-400'
    case 'warning': return 'text-yellow-600 dark:text-yellow-400'
    case 'danger': return 'text-red-600 dark:text-red-400'
    default: return 'text-gray-500 dark:text-gray-400'
  }
}

const getStatusIcon = (status: string) => {
  switch (status) {
    case 'success': return CheckCircle
    case 'warning': return AlertTriangle
    case 'danger': return AlertTriangle
    default: return Circle
  }
}

export const KPICard: React.FC<KPICardProps> = ({
  widget,
  data,
  isExpanded = false,
  className
}) => {
  const {
    value = 0,
    target,
    trend = 0,
    previousValue,
    sparklineData = [],
    unit = '',
    prefix = '',
    suffix = '',
    status = 'neutral',
    threshold
  } = data || {}

  // Calculate progress percentage for target
  const progressPercentage = useMemo(() => {
    if (!target || target === 0) return 0
    return Math.min((value / target) * 100, 100)
  }, [value, target])

  // Determine status based on threshold
  const calculatedStatus = useMemo(() => {
    if (threshold) {
      if (value >= threshold.good) return 'success'
      if (value >= threshold.warning) return 'warning'
      return 'danger'
    }
    return status
  }, [value, threshold, status])

  const TrendIcon = getTrendIcon(trend)
  const StatusIcon = getStatusIcon(calculatedStatus)

  const formattedValue = formatValue(
    value,
    prefix,
    suffix,
    value < 100 ? 2 : 0
  )

  const formattedTarget = target ? formatValue(
    target,
    prefix,
    suffix,
    target < 100 ? 2 : 0
  ) : null

  const formattedPreviousValue = previousValue ? formatValue(
    previousValue,
    prefix,
    suffix,
    previousValue < 100 ? 2 : 0
  ) : null

  return (
    <motion.div
      className={cn(
        "h-full p-4 bg-gradient-to-br from-white to-gray-50 dark:from-gray-800 dark:to-gray-900",
        "rounded-lg border border-gray-200 dark:border-gray-700",
        "hover:shadow-lg transition-all duration-200",
        className
      )}
      layout
    >
      {/* Header */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex-1">
          <h3 className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-1">
            {widget.title}
          </h3>
          {widget.description && isExpanded && (
            <p className="text-xs text-gray-500 dark:text-gray-500 mb-2">
              {widget.description}
            </p>
          )}
        </div>

        <div className="flex items-center space-x-2">
          <StatusIcon className={cn("w-4 h-4", getStatusColor(calculatedStatus))} />
          {trend !== 0 && (
            <Badge variant="outline" className="text-xs">
              <TrendIcon className={cn("w-3 h-3 mr-1", getTrendColor(trend))} />
              {Math.abs(trend).toFixed(1)}%
            </Badge>
          )}
        </div>
      </div>

      {/* Main Value */}
      <div className="mb-4">
        <div className="text-2xl font-bold text-gray-900 dark:text-white mb-1">
          {formattedValue}
        </div>
        {unit && (
          <div className="text-xs text-gray-500 dark:text-gray-400">
            {unit}
          </div>
        )}
      </div>

      {/* Target Progress */}
      {target && (
        <div className="mb-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-gray-600 dark:text-gray-400">
              Progress to target
            </span>
            <span className="text-xs font-medium text-gray-900 dark:text-white">
              {formattedTarget}
            </span>
          </div>
          <Progress
            value={progressPercentage}
            className="h-2"
            indicatorClassName={cn(
              progressPercentage >= 100 ? "bg-green-500" :
              progressPercentage >= 75 ? "bg-blue-500" :
              progressPercentage >= 50 ? "bg-yellow-500" :
              "bg-red-500"
            )}
          />
          <div className="flex justify-between mt-1">
            <span className="text-xs text-gray-500">
              {progressPercentage.toFixed(0)}% complete
            </span>
            <span className="text-xs text-gray-500">
              {formattedTarget}
            </span>
          </div>
        </div>
      )}

      {/* Previous Value Comparison */}
      {previousValue && !target && (
        <div className="mb-4 p-2 bg-gray-50 dark:bg-gray-800 rounded">
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-600 dark:text-gray-400">
              Previous period
            </span>
            <span className="text-xs font-medium text-gray-900 dark:text-white">
              {formattedPreviousValue}
            </span>
          </div>
          <div className="flex items-center justify-between mt-1">
            <span className="text-xs text-gray-500">
              Change
            </span>
            <div className={cn("flex items-center text-xs", getTrendColor(trend))}>
              <TrendIcon className="w-3 h-3 mr-1" />
              {trend > 0 ? '+' : ''}{trend.toFixed(1)}%
            </div>
          </div>
        </div>
      )}

      {/* Sparkline Chart */}
      {sparklineData.length > 0 && (
        <div className="mb-4">
          <div className="text-xs text-gray-600 dark:text-gray-400 mb-2">
            Trend (last 30 days)
          </div>
          <div className="h-12">
            <Sparkline
              data={sparklineData}
              color={trend >= 0 ? '#10b981' : '#ef4444'}
              strokeWidth={2}
            />
          </div>
        </div>
      )}

      {/* Additional Metrics (Expanded View) */}
      {isExpanded && (
        <div className="space-y-3">
          {/* Statistics Grid */}
          <div className="grid grid-cols-2 gap-3">
            <div className="p-3 bg-white dark:bg-gray-800 rounded border border-gray-200 dark:border-gray-700">
              <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
                Min Value
              </div>
              <div className="text-sm font-medium text-gray-900 dark:text-white">
                {formatValue(Math.min(...sparklineData, value), prefix, suffix, 2)}
              </div>
            </div>

            <div className="p-3 bg-white dark:bg-gray-800 rounded border border-gray-200 dark:border-gray-700">
              <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
                Max Value
              </div>
              <div className="text-sm font-medium text-gray-900 dark:text-white">
                {formatValue(Math.max(...sparklineData, value), prefix, suffix, 2)}
              </div>
            </div>

            <div className="p-3 bg-white dark:bg-gray-800 rounded border border-gray-200 dark:border-gray-700">
              <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
                Average
              </div>
              <div className="text-sm font-medium text-gray-900 dark:text-white">
                {formatValue(
                  sparklineData.length > 0
                    ? sparklineData.reduce((a, b) => a + b, 0) / sparklineData.length
                    : value,
                  prefix,
                  suffix,
                  2
                )}
              </div>
            </div>

            <div className="p-3 bg-white dark:bg-gray-800 rounded border border-gray-200 dark:border-gray-700">
              <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
                Volatility
              </div>
              <div className="text-sm font-medium text-gray-900 dark:text-white">
                {sparklineData.length > 1 ? (
                  Math.max(...sparklineData) - Math.min(...sparklineData)
                ).toFixed(1) : '0.0'}
              </div>
            </div>
          </div>

          {/* Threshold Indicators */}
          {threshold && (
            <div className="p-3 bg-gray-50 dark:bg-gray-800 rounded">
              <div className="text-xs text-gray-600 dark:text-gray-400 mb-2">
                Performance Thresholds
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <div className="w-2 h-2 bg-green-500 rounded-full mr-2" />
                    <span className="text-xs text-gray-600 dark:text-gray-400">
                      Excellent
                    </span>
                  </div>
                  <span className="text-xs font-medium">
                    ≥ {formatValue(threshold.good, prefix, suffix, 0)}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <div className="w-2 h-2 bg-yellow-500 rounded-full mr-2" />
                    <span className="text-xs text-gray-600 dark:text-gray-400">
                      Good
                    </span>
                  </div>
                  <span className="text-xs font-medium">
                    ≥ {formatValue(threshold.warning, prefix, suffix, 0)}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <div className="w-2 h-2 bg-red-500 rounded-full mr-2" />
                    <span className="text-xs text-gray-600 dark:text-gray-400">
                      Needs Attention
                    </span>
                  </div>
                  <span className="text-xs font-medium">
                    &lt; {formatValue(threshold.warning, prefix, suffix, 0)}
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </motion.div>
  )
}

export default KPICard