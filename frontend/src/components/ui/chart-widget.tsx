import * as React from 'react'
import { cn } from '@/lib/utils'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './card'
import { Button } from './button'
import {
  Download,
  Maximize2,
  MoreVertical,
  RefreshCw,
  Filter,
  Calendar
} from 'lucide-react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator
} from './dropdown-menu'
import { LoadingSpinner } from './loading-state'

export interface ChartWidgetProps {
  title: string
  description?: string
  className?: string
  loading?: boolean
  error?: string
  onRefresh?: () => void
  onExport?: () => void
  onFullscreen?: () => void
  timeRange?: string
  onTimeRangeChange?: (range: string) => void
  filters?: Array<{
    label: string
    value: string
    active: boolean
    onClick: () => void
  }>
  actions?: Array<{
    label: string
    onClick: () => void
  }>
  children?: React.ReactNode
  height?: string | number
}

export function ChartWidget({
  title,
  description,
  className,
  loading = false,
  error,
  onRefresh,
  onExport,
  onFullscreen,
  timeRange,
  onTimeRangeChange,
  filters,
  actions,
  children,
  height = 400
}: ChartWidgetProps) {
  return (
    <Card className={cn("flex flex-col", className)}>
      <CardHeader className="flex flex-row items-start justify-between space-y-0 pb-3">
        <div>
          <CardTitle className="text-base font-medium">{title}</CardTitle>
          {description && (
            <CardDescription className="text-xs mt-1">
              {description}
            </CardDescription>
          )}
        </div>
        <div className="flex items-center gap-1">
          {timeRange && onTimeRangeChange && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="sm" className="h-8 gap-1">
                  <Calendar className="h-3 w-3" />
                  <span className="text-xs">{timeRange}</span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => onTimeRangeChange('1D')}>Last 24 hours</DropdownMenuItem>
                <DropdownMenuItem onClick={() => onTimeRangeChange('7D')}>Last 7 days</DropdownMenuItem>
                <DropdownMenuItem onClick={() => onTimeRangeChange('30D')}>Last 30 days</DropdownMenuItem>
                <DropdownMenuItem onClick={() => onTimeRangeChange('90D')}>Last 90 days</DropdownMenuItem>
                <DropdownMenuItem onClick={() => onTimeRangeChange('1Y')}>Last year</DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          )}
          {filters && filters.length > 0 && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                  <Filter className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                {filters.map((filter, i) => (
                  <DropdownMenuItem key={i} onClick={filter.onClick}>
                    <span className={cn(filter.active && "font-semibold")}>
                      {filter.label}
                    </span>
                  </DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
          )}
          {onRefresh && (
            <Button
              variant="ghost"
              size="sm"
              className="h-8 w-8 p-0"
              onClick={onRefresh}
              disabled={loading}
            >
              <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
            </Button>
          )}
          {onFullscreen && (
            <Button
              variant="ghost"
              size="sm"
              className="h-8 w-8 p-0"
              onClick={onFullscreen}
            >
              <Maximize2 className="h-4 w-4" />
            </Button>
          )}
          {(actions || onExport) && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                  <MoreVertical className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                {actions?.map((action, i) => (
                  <DropdownMenuItem key={i} onClick={action.onClick}>
                    {action.label}
                  </DropdownMenuItem>
                ))}
                {actions && onExport && <DropdownMenuSeparator />}
                {onExport && (
                  <DropdownMenuItem onClick={onExport}>
                    <Download className="h-4 w-4 mr-2" />
                    Export
                  </DropdownMenuItem>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </div>
      </CardHeader>
      <CardContent className="flex-1 pb-4">
        <div
          className={cn("relative", typeof height === 'number' && `h-[${height}px]`)}
          style={typeof height === 'string' ? { height } : { height: `${height}px` }}
        >
          {loading && (
            <div className="absolute inset-0 flex items-center justify-center bg-background/50">
              <LoadingSpinner size="lg" />
            </div>
          )}
          {error ? (
            <div className="flex flex-col items-center justify-center h-full text-center">
              <p className="text-sm text-muted-foreground mb-2">Failed to load chart</p>
              <p className="text-xs text-destructive">{error}</p>
              {onRefresh && (
                <Button onClick={onRefresh} variant="outline" size="sm" className="mt-4">
                  <RefreshCw className="h-3 w-3 mr-2" />
                  Retry
                </Button>
              )}
            </div>
          ) : (
            children || (
              <div className="flex items-center justify-center h-full border-2 border-dashed border-muted rounded-lg">
                <p className="text-sm text-muted-foreground">Chart placeholder</p>
              </div>
            )
          )}
        </div>
      </CardContent>
    </Card>
  )
}

export interface MiniChartProps {
  data: number[]
  type?: 'line' | 'bar' | 'area'
  color?: string
  className?: string
  height?: number
  showAxes?: boolean
  animated?: boolean
}

export function MiniChart({
  data,
  type = 'line',
  color = 'currentColor',
  className,
  height = 40,
  showAxes = false,
  animated = true
}: MiniChartProps) {
  const max = Math.max(...data)
  const min = Math.min(...data)
  const range = max - min || 1

  const points = data.map((value, index) => {
    const x = (index / (data.length - 1)) * 100
    const y = 100 - ((value - min) / range) * 100
    return { x, y, value }
  })

  if (type === 'bar') {
    const barWidth = 100 / data.length
    return (
      <svg
        className={cn("w-full", className)}
        height={height}
        viewBox={`0 0 100 ${height}`}
        preserveAspectRatio="none"
      >
        {showAxes && (
          <>
            <line x1="0" y1={height - 1} x2="100" y2={height - 1} stroke="currentColor" strokeOpacity="0.1" />
            <line x1="0" y1="0" x2="0" y2={height} stroke="currentColor" strokeOpacity="0.1" />
          </>
        )}
        {points.map((point, i) => (
          <rect
            key={i}
            x={point.x - barWidth / 2}
            y={(point.y / 100) * height}
            width={barWidth * 0.8}
            height={height - (point.y / 100) * height}
            fill={color}
            opacity="0.8"
            className={cn(animated && "transition-all duration-500")}
          />
        ))}
      </svg>
    )
  }

  const pathData = type === 'area'
    ? `M0,${height} ${points.map(p => `L${p.x},${(p.y / 100) * height}`).join(' ')} L100,${height} Z`
    : `M${points.map(p => `${p.x},${(p.y / 100) * height}`).join(' L')}`

  return (
    <svg
      className={cn("w-full", className)}
      height={height}
      viewBox={`0 0 100 ${height}`}
      preserveAspectRatio="none"
    >
      {showAxes && (
        <>
          <line x1="0" y1={height - 1} x2="100" y2={height - 1} stroke="currentColor" strokeOpacity="0.1" />
          <line x1="0" y1="0" x2="0" y2={height} stroke="currentColor" strokeOpacity="0.1" />
        </>
      )}
      <path
        d={pathData}
        fill={type === 'area' ? color : 'none'}
        fillOpacity={type === 'area' ? 0.2 : 0}
        stroke={color}
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        className={cn(animated && "transition-all duration-500")}
      />
      {type === 'line' && points.map((point, i) => (
        <circle
          key={i}
          cx={point.x}
          cy={(point.y / 100) * height}
          r="2"
          fill={color}
          className={cn(animated && "transition-all duration-500")}
        />
      ))}
    </svg>
  )
}

export interface ProgressChartProps {
  value: number
  max?: number
  size?: 'sm' | 'md' | 'lg'
  label?: string
  color?: 'primary' | 'success' | 'warning' | 'danger'
  className?: string
  showValue?: boolean
  thickness?: number
}

export function ProgressChart({
  value,
  max = 100,
  size = 'md',
  label,
  color = 'primary',
  className,
  showValue = true,
  thickness = 8
}: ProgressChartProps) {
  const percentage = Math.min(100, Math.max(0, (value / max) * 100))
  const sizes = {
    sm: 80,
    md: 120,
    lg: 160
  }

  const colors = {
    primary: 'stroke-primary',
    success: 'stroke-green-500',
    warning: 'stroke-yellow-500',
    danger: 'stroke-red-500'
  }

  const radius = sizes[size] / 2 - thickness
  const circumference = 2 * Math.PI * radius
  const strokeDashoffset = circumference - (percentage / 100) * circumference

  return (
    <div className={cn("relative inline-flex items-center justify-center", className)}>
      <svg width={sizes[size]} height={sizes[size]} className="transform -rotate-90">
        <circle
          cx={sizes[size] / 2}
          cy={sizes[size] / 2}
          r={radius}
          stroke="currentColor"
          strokeWidth={thickness}
          fill="none"
          className="text-muted opacity-20"
        />
        <circle
          cx={sizes[size] / 2}
          cy={sizes[size] / 2}
          r={radius}
          stroke="currentColor"
          strokeWidth={thickness}
          fill="none"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          className={cn(colors[color], "transition-all duration-500")}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        {showValue && (
          <span className={cn(
            "font-bold",
            size === 'sm' && "text-lg",
            size === 'md' && "text-2xl",
            size === 'lg' && "text-3xl"
          )}>
            {Math.round(percentage)}%
          </span>
        )}
        {label && (
          <span className={cn(
            "text-muted-foreground",
            size === 'sm' && "text-xs",
            size === 'md' && "text-sm",
            size === 'lg' && "text-base"
          )}>
            {label}
          </span>
        )}
      </div>
    </div>
  )
}