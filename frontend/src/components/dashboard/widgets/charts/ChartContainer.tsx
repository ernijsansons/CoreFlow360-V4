/**
 * Chart Container Component
 * Universal chart wrapper with Chart.js and D3.js integration
 */

import React, { useRef, useEffect, useState, useMemo } from 'react'
import { motion } from 'framer-motion'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  RadarLinearScale,
  Tooltip,
  Legend,
  Filler,
  ScriptableContext
} from 'chart.js'
import {
  Line,
  Bar,
  Pie,
  Doughnut,
  Radar,
  PolarArea,
  Scatter,
  Bubble
} from 'react-chartjs-2'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  MoreHorizontal,
  Download,
  Maximize2,
  RefreshCw,
  Settings,
  TrendingUp
} from 'lucide-react'
import type { Widget, ChartData, ChartOptions } from '@/types/dashboard'

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  RadarLinearScale,
  Tooltip,
  Legend,
  Filler
)

export interface ChartContainerProps {
  widget: Widget
  data?: ChartData
  isExpanded?: boolean
  isLoading?: boolean
  error?: string
  onRefresh?: () => void
  onExport?: (format: 'png' | 'svg' | 'pdf') => void
  onExpand?: () => void
  onConfigure?: () => void
  className?: string
}

const CHART_COLORS = {
  primary: '#3b82f6',
  secondary: '#8b5cf6',
  success: '#10b981',
  warning: '#f59e0b',
  danger: '#ef4444',
  info: '#06b6d4',
  light: '#6b7280',
  dark: '#374151'
}

const generateColorPalette = (count: number): string[] => {
  const colors = Object.values(CHART_COLORS)
  const palette: string[] = []

  for (let i = 0; i < count; i++) {
    if (i < colors.length) {
      palette.push(colors[i])
    } else {
      // Generate additional colors using HSL
      const hue = (i * 137.5) % 360
      palette.push(`hsl(${hue}, 70%, 50%)`)
    }
  }

  return palette
}

export const ChartContainer: React.FC<ChartContainerProps> = ({
  widget,
  data,
  isExpanded = false,
  isLoading = false,
  error,
  onRefresh,
  onExport,
  onExpand,
  onConfigure,
  className
}) => {
  const chartRef = useRef<any>(null)
  const [chartData, setChartData] = useState<any>(null)
  const [chartOptions, setChartOptions] = useState<any>(null)

  const config = widget.config as ChartOptions || {}

  // Process chart data
  useEffect(() => {
    if (!data) return

    const colorPalette = generateColorPalette(data.datasets?.length || 1)

    const processedData = {
      labels: data.labels || [],
      datasets: data.datasets?.map((dataset, index) => ({
        ...dataset,
        backgroundColor: dataset.backgroundColor || (
          widget.type === 'line_chart'
            ? `${colorPalette[index]}20`
            : colorPalette[index]
        ),
        borderColor: dataset.borderColor || colorPalette[index],
        borderWidth: dataset.borderWidth || (widget.type === 'line_chart' ? 2 : 1),
        fill: dataset.fill !== undefined ? dataset.fill : widget.type === 'area_chart',
        tension: dataset.tension || (widget.type === 'line_chart' ? 0.4 : 0),
        pointRadius: dataset.pointRadius || (isExpanded ? 4 : 2),
        pointHoverRadius: dataset.pointHoverRadius || (isExpanded ? 6 : 4)
      })) || []
    }

    setChartData(processedData)
  }, [data, widget.type, isExpanded])

  // Process chart options
  useEffect(() => {
    const baseOptions: any = {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: config.showLegend !== false,
          position: config.legendPosition || 'top',
          labels: {
            usePointStyle: true,
            padding: 20,
            font: {
              size: isExpanded ? 12 : 10
            }
          }
        },
        tooltip: {
          enabled: true,
          mode: 'index',
          intersect: false,
          backgroundColor: 'rgba(0, 0, 0, 0.8)',
          titleColor: 'white',
          bodyColor: 'white',
          borderColor: 'rgba(255, 255, 255, 0.1)',
          borderWidth: 1,
          cornerRadius: 8,
          padding: 12,
          displayColors: true,
          callbacks: {
            label: (context: any) => {
              const label = context.dataset.label || ''
              const value = context.parsed.y || context.parsed
              const prefix = config.valuePrefix || ''
              const suffix = config.valueSuffix || ''

              return `${label}: ${prefix}${value.toLocaleString()}${suffix}`
            }
          }
        }
      },
      scales: widget.type !== 'pie_chart' && widget.type !== 'doughnut_chart' ? {
        x: {
          display: config.showXAxis !== false,
          grid: {
            display: config.showGrid !== false,
            color: 'rgba(0, 0, 0, 0.1)'
          },
          ticks: {
            font: {
              size: isExpanded ? 11 : 9
            }
          }
        },
        y: {
          display: config.showYAxis !== false,
          beginAtZero: config.beginAtZero !== false,
          grid: {
            display: config.showGrid !== false,
            color: 'rgba(0, 0, 0, 0.1)'
          },
          ticks: {
            font: {
              size: isExpanded ? 11 : 9
            },
            callback: (value: any) => {
              const prefix = config.valuePrefix || ''
              const suffix = config.valueSuffix || ''
              return `${prefix}${value.toLocaleString()}${suffix}`
            }
          }
        }
      } : {},
      animation: {
        duration: isExpanded ? 1000 : 500,
        easing: 'easeInOutQuart'
      },
      interaction: {
        mode: 'nearest',
        axis: 'x',
        intersect: false
      }
    }

    // Chart-specific options
    switch (widget.type) {
      case 'line_chart':
      case 'area_chart':
        baseOptions.elements = {
          point: {
            hoverRadius: 8
          }
        }
        break

      case 'bar_chart':
        baseOptions.plugins.legend.display = data?.datasets && data.datasets.length > 1
        if (config.stacked) {
          baseOptions.scales.x.stacked = true
          baseOptions.scales.y.stacked = true
        }
        break

      case 'pie_chart':
      case 'doughnut_chart':
        baseOptions.cutout = widget.type === 'doughnut_chart' ? '60%' : '0%'
        baseOptions.plugins.legend.position = 'right'
        break

      case 'radar_chart':
        baseOptions.scales = {
          r: {
            beginAtZero: true,
            grid: {
              circular: true
            },
            pointLabels: {
              font: {
                size: isExpanded ? 12 : 10
              }
            }
          }
        }
        break
    }

    setChartOptions(baseOptions)
  }, [widget.type, config, isExpanded, data])

  // Chart component selector
  const renderChart = () => {
    if (!chartData || !chartOptions) return null

    const commonProps = {
      ref: chartRef,
      data: chartData,
      options: chartOptions
    }

    switch (widget.type) {
      case 'line_chart':
      case 'area_chart':
        return <Line {...commonProps} />
      case 'bar_chart':
        return <Bar {...commonProps} />
      case 'pie_chart':
        return <Pie {...commonProps} />
      case 'doughnut_chart':
        return <Doughnut {...commonProps} />
      case 'radar_chart':
        return <Radar {...commonProps} />
      case 'polar_chart':
        return <PolarArea {...commonProps} />
      case 'scatter_chart':
        return <Scatter {...commonProps} />
      case 'bubble_chart':
        return <Bubble {...commonProps} />
      default:
        return <Line {...commonProps} />
    }
  }

  const handleExport = (format: 'png' | 'svg' | 'pdf') => {
    if (chartRef.current) {
      const canvas = chartRef.current.canvas
      const url = canvas.toDataURL('image/png')

      const link = document.createElement('a')
      link.download = `${widget.title.replace(/\s+/g, '_').toLowerCase()}.${format}`
      link.href = url
      link.click()
    }

    onExport?.(format)
  }

  if (error) {
    return (
      <div className={cn("h-full flex items-center justify-center p-6", className)}>
        <div className="text-center">
          <div className="text-red-500 mb-2">
            <TrendingUp className="w-8 h-8 mx-auto" />
          </div>
          <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
            {error}
          </p>
          {onRefresh && (
            <Button variant="outline" size="sm" onClick={onRefresh}>
              <RefreshCw className="w-4 h-4 mr-2" />
              Retry
            </Button>
          )}
        </div>
      </div>
    )
  }

  return (
    <motion.div
      className={cn("h-full flex flex-col", className)}
      layout
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex-1">
          <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-1">
            {widget.title}
          </h3>
          {widget.description && (
            <p className="text-xs text-gray-500 dark:text-gray-400">
              {widget.description}
            </p>
          )}
        </div>

        <div className="flex items-center space-x-2">
          {data?.metadata?.lastUpdate && (
            <Badge variant="outline" className="text-xs">
              Updated {new Date(data.metadata.lastUpdate).toLocaleTimeString()}
            </Badge>
          )}

          {!isExpanded && (
            <div className="flex items-center space-x-1">
              {onRefresh && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="w-6 h-6 p-0"
                  onClick={onRefresh}
                  disabled={isLoading}
                >
                  <RefreshCw className={cn("w-3 h-3", isLoading && "animate-spin")} />
                </Button>
              )}

              {onConfigure && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="w-6 h-6 p-0"
                  onClick={onConfigure}
                >
                  <Settings className="w-3 h-3" />
                </Button>
              )}

              {onExpand && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="w-6 h-6 p-0"
                  onClick={onExpand}
                >
                  <Maximize2 className="w-3 h-3" />
                </Button>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Chart Area */}
      <div className="flex-1 relative min-h-0">
        {isLoading ? (
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="animate-spin w-8 h-8 border-2 border-blue-600 border-t-transparent rounded-full" />
          </div>
        ) : (
          <div className="w-full h-full">
            {renderChart()}
          </div>
        )}
      </div>

      {/* Footer (Expanded view only) */}
      {isExpanded && (
        <div className="flex items-center justify-between mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-2 text-xs text-gray-500">
            {data?.metadata?.dataPoints && (
              <span>{data.metadata.dataPoints} data points</span>
            )}
            {data?.metadata?.period && (
              <span>• {data.metadata.period}</span>
            )}
          </div>

          <div className="flex items-center space-x-1">
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleExport('png')}
            >
              <Download className="w-4 h-4 mr-2" />
              Export PNG
            </Button>

            {onRefresh && (
              <Button
                variant="outline"
                size="sm"
                onClick={onRefresh}
                disabled={isLoading}
              >
                <RefreshCw className={cn("w-4 h-4 mr-2", isLoading && "animate-spin")} />
                Refresh
              </Button>
            )}
          </div>
        </div>
      )}
    </motion.div>
  )
}

export default ChartContainer