/**
 * Sparkline Chart Component
 * Minimal line chart for KPI trends
 */

import React, { useMemo } from 'react'
import { cn } from '@/lib/utils'

export interface SparklineProps {
  data: number[]
  width?: number
  height?: number
  color?: string
  strokeWidth?: number
  fill?: boolean
  className?: string
}

export const Sparkline: React.FC<SparklineProps> = ({
  data,
  width = 100,
  height = 40,
  color = '#3b82f6',
  strokeWidth = 2,
  fill = false,
  className
}) => {
  const pathData = useMemo(() => {
    if (data.length < 2) return ''

    const min = Math.min(...data)
    const max = Math.max(...data)
    const range = max - min || 1

    const points = data.map((value, index) => {
      const x = (index / (data.length - 1)) * width
      const y = height - ((value - min) / range) * height
      return `${x},${y}`
    })

    return `M ${points.join(' L ')}`
  }, [data, width, height])

  const fillPath = useMemo(() => {
    if (!fill || data.length < 2) return ''

    const min = Math.min(...data)
    const max = Math.max(...data)
    const range = max - min || 1

    const points = data.map((value, index) => {
      const x = (index / (data.length - 1)) * width
      const y = height - ((value - min) / range) * height
      return `${x},${y}`
    })

    return `M 0,${height} L ${points.join(' L ')} L ${width},${height} Z`
  }, [data, width, height, fill])

  if (data.length < 2) {
    return (
      <div
        className={cn("flex items-center justify-center text-gray-400", className)}
        style={{ width, height }}
      >
        <span className="text-xs">No data</span>
      </div>
    )
  }

  return (
    <svg
      width={width}
      height={height}
      className={cn("overflow-visible", className)}
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
    >
      {fill && (
        <path
          d={fillPath}
          fill={`${color}20`}
          stroke="none"
        />
      )}
      <path
        d={pathData}
        fill="none"
        stroke={color}
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  )
}

export default Sparkline