import * as React from 'react'
import { cn } from '@/lib/utils'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './card'
import {
  TrendingUp,
  TrendingDown,
  Minus,
  type LucideIcon,
  MoreVertical,
  ExternalLink
} from 'lucide-react'
import { Button } from './button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger
} from './dropdown-menu'

export interface MetricCardProps {
  title: string
  value: string | number
  previousValue?: string | number
  change?: number
  changeType?: 'increase' | 'decrease' | 'neutral'
  icon?: LucideIcon
  description?: string
  className?: string
  trend?: 'up' | 'down' | 'neutral'
  sparkline?: number[]
  actions?: Array<{
    label: string
    onClick: () => void
  }>
  href?: string
  loading?: boolean
  format?: 'currency' | 'percent' | 'number' | 'compact'
}

export function MetricCard({
  title,
  value,
  previousValue,
  change,
  changeType,
  icon: Icon,
  description,
  className,
  trend = 'neutral',
  sparkline,
  actions,
  href,
  loading,
  format = 'number'
}: MetricCardProps) {
  const trendIcons = {
    up: TrendingUp,
    down: TrendingDown,
    neutral: Minus
  }

  const trendColors = {
    up: 'text-green-600 dark:text-green-400',
    down: 'text-red-600 dark:text-red-400',
    neutral: 'text-gray-600 dark:text-gray-400'
  }

  const TrendIcon = trendIcons[trend]

  const formatValue = (val: string | number): string => {
    if (typeof val === 'string') return val
    
    switch (format) {
      case 'currency':
        return new Intl.NumberFormat('en-US', {
          style: 'currency',
          currency: 'USD',
          minimumFractionDigits: 0,
          maximumFractionDigits: 0
        }).format(val)
      case 'percent':
        return `${val}%`
      case 'compact':
        return new Intl.NumberFormat('en-US', {
          notation: 'compact',
          compactDisplay: 'short'
        }).format(val)
      default:
        return val.toLocaleString()
    }
  }

  if (loading) {
    return (
      <Card className={cn("relative", className)}>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <div className="h-4 w-24 bg-muted animate-pulse rounded" />
          <div className="h-8 w-8 bg-muted animate-pulse rounded" />
        </CardHeader>
        <CardContent>
          <div className="h-7 w-32 bg-muted animate-pulse rounded mb-1" />
          <div className="h-3 w-16 bg-muted animate-pulse rounded" />
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className={cn("relative hover:shadow-md transition-shadow", className)}>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        <div className="flex items-center gap-2">
          {Icon && <Icon className="h-4 w-4 text-muted-foreground" />}
          {actions && actions.length > 0 && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                  <MoreVertical className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                {actions.map((action, i) => (
                  <DropdownMenuItem key={i} onClick={action.onClick}>
                    {action.label}
                  </DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
          )}
          {href && (
            <Button variant="ghost" size="sm" className="h-8 w-8 p-0" asChild>
              <a href={href} target="_blank" rel="noopener noreferrer">
                <ExternalLink className="h-4 w-4" />
              </a>
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{formatValue(value)}</div>
        {(change !== undefined || previousValue !== undefined) && (
          <div className="flex items-center gap-1 text-xs mt-1">
            <TrendIcon className={cn("h-3 w-3", trendColors[trend])} />
            <span className={cn(trendColors[trend])}>
              {change !== undefined ? `${change > 0 ? '+' : ''}${change}%` : ''}
            </span>
            {previousValue !== undefined && (
              <span className="text-muted-foreground">
                from {formatValue(previousValue)}
              </span>
            )}
          </div>
        )}
        {description && (
          <CardDescription className="mt-2">{description}</CardDescription>
        )}
        {sparkline && sparkline.length > 0 && (
          <div className="mt-3 h-16">
            <Sparkline data={sparkline} trend={trend} />
          </div>
        )}
      </CardContent>
    </Card>
  )
}

interface SparklineProps {
  data: number[]
  trend: 'up' | 'down' | 'neutral'
}

function Sparkline({ data, trend }: SparklineProps) {
  const max = Math.max(...data)
  const min = Math.min(...data)
  const range = max - min || 1
  
  const points = data.map((value, index) => {
    const x = (index / (data.length - 1)) * 100
    const y = 100 - ((value - min) / range) * 100
    return `${x},${y}`
  }).join(' ')

  const trendColors = {
    up: 'stroke-green-500',
    down: 'stroke-red-500',
    neutral: 'stroke-gray-500'
  }

  return (
    <svg className="w-full h-full" viewBox="0 0 100 100" preserveAspectRatio="none">
      <polyline
        points={points}
        className={cn(trendColors[trend], "fill-none stroke-2")}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

export interface StatCardProps {
  label: string
  value: string | number
  icon?: LucideIcon
  variant?: 'default' | 'success' | 'warning' | 'danger'
  className?: string
  size?: 'sm' | 'md' | 'lg'
}

export function StatCard({
  label,
  value,
  icon: Icon,
  variant = 'default',
  className,
  size = 'md'
}: StatCardProps) {
  const variants = {
    default: 'bg-card',
    success: 'bg-green-50 dark:bg-green-950 border-green-200 dark:border-green-800',
    warning: 'bg-yellow-50 dark:bg-yellow-950 border-yellow-200 dark:border-yellow-800',
    danger: 'bg-red-50 dark:bg-red-950 border-red-200 dark:border-red-800'
  }

  const iconColors = {
    default: 'text-muted-foreground',
    success: 'text-green-600 dark:text-green-400',
    warning: 'text-yellow-600 dark:text-yellow-400',
    danger: 'text-red-600 dark:text-red-400'
  }

  const sizes = {
    sm: {
      padding: 'p-3',
      icon: 'h-4 w-4',
      label: 'text-xs',
      value: 'text-lg'
    },
    md: {
      padding: 'p-4',
      icon: 'h-5 w-5',
      label: 'text-sm',
      value: 'text-2xl'
    },
    lg: {
      padding: 'p-6',
      icon: 'h-6 w-6',
      label: 'text-base',
      value: 'text-3xl'
    }
  }

  const sizeClasses = sizes[size]

  return (
    <div className={cn(
      "rounded-lg border",
      variants[variant],
      sizeClasses.padding,
      className
    )}>
      <div className="flex items-center justify-between">
        <div>
          <p className={cn("text-muted-foreground", sizeClasses.label)}>
            {label}
          </p>
          <p className={cn("font-bold", sizeClasses.value)}>
            {value}
          </p>
        </div>
        {Icon && (
          <Icon className={cn(sizeClasses.icon, iconColors[variant])} />
        )}
      </div>
    </div>
  )
}

export interface KPICardProps {
  title: string
  value: string | number
  target?: string | number
  progress?: number
  icon?: LucideIcon
  period?: string
  className?: string
  status?: 'on-track' | 'at-risk' | 'off-track'
}

export function KPICard({
  title,
  value,
  target,
  progress,
  icon: Icon,
  period,
  className,
  status = 'on-track'
}: KPICardProps) {
  const statusColors = {
    'on-track': 'bg-green-500',
    'at-risk': 'bg-yellow-500',
    'off-track': 'bg-red-500'
  }

  const statusLabels = {
    'on-track': 'On Track',
    'at-risk': 'At Risk',
    'off-track': 'Off Track'
  }

  return (
    <Card className={cn("relative overflow-hidden", className)}>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-medium">{title}</CardTitle>
          {Icon && <Icon className="h-4 w-4 text-muted-foreground" />}
        </div>
        {period && (
          <CardDescription className="text-xs">{period}</CardDescription>
        )}
      </CardHeader>
      <CardContent className="pt-0">
        <div className="text-2xl font-bold">{value}</div>
        {target && (
          <p className="text-xs text-muted-foreground mt-1">
            Target: {target}
          </p>
        )}
        {progress !== undefined && (
          <div className="mt-3">
            <div className="flex items-center justify-between text-xs mb-1">
              <span>{progress}%</span>
              <span className={cn(
                "px-2 py-0.5 rounded-full text-white text-xs",
                statusColors[status]
              )}>
                {statusLabels[status]}
              </span>
            </div>
            <div className="h-2 bg-muted rounded-full overflow-hidden">
              <div
                className={cn("h-full transition-all", statusColors[status])}
                style={{ width: `${Math.min(100, Math.max(0, progress))}%` }}
              />
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}