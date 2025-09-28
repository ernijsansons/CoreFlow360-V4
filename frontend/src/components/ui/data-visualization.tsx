import * as React from "react"
import { motion, AnimatePresence } from "framer-motion"
import { ResponsiveContainer, LineChart, Line, AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, RadialBarChart, RadialBar } from "recharts"
import { cn } from "@/lib/utils"
import { Card, CardContent, CardHeader, CardTitle } from "./card"
import { HoverLift, NumberCounter } from "./micro-interactions"

// Chart container with animations
export interface AnimatedChartProps {
  children: React.ReactNode
  className?: string
  title?: string
  description?: string
  loading?: boolean
  error?: string
}

export const AnimatedChart: React.FC<AnimatedChartProps> = React.memo(({
  children,
  className,
  title,
  description,
  loading = false,
  error
}) => {
  if (loading) {
    return (
      <Card className={className}>
        {title && (
          <CardHeader>
            <CardTitle>{title}</CardTitle>
            {description && <p className="text-sm text-muted-foreground">{description}</p>}
          </CardHeader>
        )}
        <CardContent>
          <div className="h-64 flex items-center justify-center">
            <motion.div
              className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full"
              animate={{ rotate: 360 }}
              transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
            />
          </div>
        </CardContent>
      </Card>
    )
  }

  if (error) {
    return (
      <Card className={className}>
        {title && (
          <CardHeader>
            <CardTitle>{title}</CardTitle>
          </CardHeader>
        )}
        <CardContent>
          <div className="h-64 flex items-center justify-center text-destructive">
            <p>{error}</p>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <HoverLift intensity="subtle">
      <Card className={className}>
        {title && (
          <CardHeader>
            <CardTitle>{title}</CardTitle>
            {description && <p className="text-sm text-muted-foreground">{description}</p>}
          </CardHeader>
        )}
        <CardContent>
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            {children}
          </motion.div>
        </CardContent>
      </Card>
    </HoverLift>
  )
})

// Metric card with animation
export interface MetricCardProps {
  title: string
  value: number | string
  change?: number
  changeType?: 'increase' | 'decrease' | 'neutral'
  icon?: React.ReactNode
  className?: string
  prefix?: string
  suffix?: string
  decimals?: number
  loading?: boolean
}

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  change,
  changeType = 'neutral',
  icon,
  className,
  prefix = '',
  suffix = '',
  decimals = 0,
  loading = false
}) => {
  const getChangeColor = () => {
    switch (changeType) {
      case 'increase': return 'text-green-600'
      case 'decrease': return 'text-red-600'
      default: return 'text-gray-600'
    }
  }

  const getChangeIcon = () => {
    switch (changeType) {
      case 'increase':
        return (
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 10l7-7m0 0l7 7m-7-7v18" />
          </svg>
        )
      case 'decrease':
        return (
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 14l-7 7m0 0l-7-7m7 7V3" />
          </svg>
        )
      default:
        return null
    }
  }

  if (loading) {
    return (
      <Card className={className}>
        <CardContent className="p-6">
          <div className="space-y-3">
            <div className="h-4 bg-gray-200 rounded animate-pulse" />
            <div className="h-8 bg-gray-200 rounded animate-pulse" />
            <div className="h-4 bg-gray-200 rounded w-24 animate-pulse" />
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <HoverLift intensity="subtle">
      <Card className={className}>
        <CardContent className="p-6">
          <div className="flex items-center justify-between">
            <div className="space-y-2">
              <p className="text-sm font-medium text-muted-foreground">{title}</p>
              <div className="text-2xl font-bold">
                {typeof value === 'number' ? (
                  <NumberCounter
                    value={value}
                    prefix={prefix}
                    suffix={suffix}
                    decimals={decimals}
                  />
                ) : (
                  <motion.span
                    initial={{ scale: 0.8, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    transition={{ duration: 0.3 }}
                  >
                    {value}
                  </motion.span>
                )}
              </div>
              {change !== undefined && (
                <motion.div
                  className={cn("flex items-center space-x-1 text-xs", getChangeColor())}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.2 }}
                >
                  {getChangeIcon()}
                  <span>{Math.abs(change)}%</span>
                </motion.div>
              )}
            </div>
            {icon && (
              <motion.div
                className="text-muted-foreground"
                initial={{ scale: 0, rotate: -90 }}
                animate={{ scale: 1, rotate: 0 }}
                transition={{ delay: 0.1, type: "spring" }}
              >
                {icon}
              </motion.div>
            )}
          </div>
        </CardContent>
      </Card>
    </HoverLift>
  )
}

// Animated line chart
export interface AnimatedLineChartProps {
  data: Array<Record<string, any>>
  xKey: string
  yKey: string
  title?: string
  description?: string
  color?: string
  className?: string
  height?: number
}

export const AnimatedLineChart: React.FC<AnimatedLineChartProps> = ({
  data,
  xKey,
  yKey,
  title,
  description,
  color = '#3b82f6',
  className,
  height = 300
}) => {
  const [animatedData, setAnimatedData] = React.useState<typeof data>([])

  React.useEffect(() => {
    const timer = setTimeout(() => {
      setAnimatedData(data)
    }, 100)
    return () => clearTimeout(timer)
  }, [data])

  return (
    <AnimatedChart title={title} description={description} className={className}>
      <ResponsiveContainer width="100%" height={height}>
        <LineChart data={animatedData}>
          <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
          <XAxis
            dataKey={xKey}
            stroke="#6b7280"
            fontSize={12}
          />
          <YAxis
            stroke="#6b7280"
            fontSize={12}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: 'white',
              border: '1px solid #e5e7eb',
              borderRadius: '8px',
              boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
            }}
          />
          <Line
            type="monotone"
            dataKey={yKey}
            stroke={color}
            strokeWidth={2}
            dot={{ fill: color, strokeWidth: 2, r: 4 }}
            activeDot={{ r: 6, fill: color }}
            animationDuration={1000}
            animationEasing="ease-out"
          />
        </LineChart>
      </ResponsiveContainer>
    </AnimatedChart>
  )
}

// Animated area chart
export interface AnimatedAreaChartProps {
  data: Array<Record<string, any>>
  xKey: string
  yKey: string
  title?: string
  description?: string
  color?: string
  className?: string
  height?: number
}

export const AnimatedAreaChart: React.FC<AnimatedAreaChartProps> = ({
  data,
  xKey,
  yKey,
  title,
  description,
  color = '#3b82f6',
  className,
  height = 300
}) => {
  return (
    <AnimatedChart title={title} description={description} className={className}>
      <ResponsiveContainer width="100%" height={height}>
        <AreaChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
          <XAxis
            dataKey={xKey}
            stroke="#6b7280"
            fontSize={12}
          />
          <YAxis
            stroke="#6b7280"
            fontSize={12}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: 'white',
              border: '1px solid #e5e7eb',
              borderRadius: '8px',
              boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
            }}
          />
          <Area
            type="monotone"
            dataKey={yKey}
            stroke={color}
            fill={`${color}20`}
            strokeWidth={2}
            animationDuration={1000}
            animationEasing="ease-out"
          />
        </AreaChart>
      </ResponsiveContainer>
    </AnimatedChart>
  )
}

// Animated bar chart
export interface AnimatedBarChartProps {
  data: Array<Record<string, any>>
  xKey: string
  yKey: string
  title?: string
  description?: string
  color?: string
  className?: string
  height?: number
}

export const AnimatedBarChart: React.FC<AnimatedBarChartProps> = ({
  data,
  xKey,
  yKey,
  title,
  description,
  color = '#3b82f6',
  className,
  height = 300
}) => {
  return (
    <AnimatedChart title={title} description={description} className={className}>
      <ResponsiveContainer width="100%" height={height}>
        <BarChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
          <XAxis
            dataKey={xKey}
            stroke="#6b7280"
            fontSize={12}
          />
          <YAxis
            stroke="#6b7280"
            fontSize={12}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: 'white',
              border: '1px solid #e5e7eb',
              borderRadius: '8px',
              boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
            }}
          />
          <Bar
            dataKey={yKey}
            fill={color}
            radius={[4, 4, 0, 0]}
            animationDuration={1000}
            animationEasing="ease-out"
          />
        </BarChart>
      </ResponsiveContainer>
    </AnimatedChart>
  )
}

// Animated pie chart
export interface AnimatedPieChartProps {
  data: Array<{ name: string; value: number; color?: string }>
  title?: string
  description?: string
  className?: string
  height?: number
  showLabels?: boolean
}

export const AnimatedPieChart: React.FC<AnimatedPieChartProps> = ({
  data,
  title,
  description,
  className,
  height = 300,
  showLabels = true
}) => {
  const COLORS = ['#3b82f6', '#ef4444', '#10b981', '#f59e0b', '#8b5cf6', '#06b6d4']

  return (
    <AnimatedChart title={title} description={description} className={className}>
      <ResponsiveContainer width="100%" height={height}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            outerRadius={80}
            dataKey="value"
            animationDuration={1000}
            animationEasing="ease-out"
            label={showLabels ? ({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%` : false}
          >
            {data.map((entry, index) => (
              <Cell
                key={`cell-${index}`}
                fill={entry.color || COLORS[index % COLORS.length]}
              />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: 'white',
              border: '1px solid #e5e7eb',
              borderRadius: '8px',
              boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
            }}
          />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </AnimatedChart>
  )
}

// Progress ring
export interface ProgressRingProps {
  value: number
  max?: number
  size?: number
  strokeWidth?: number
  color?: string
  backgroundColor?: string
  className?: string
  showLabel?: boolean
  label?: string
}

export const ProgressRing: React.FC<ProgressRingProps> = ({
  value,
  max = 100,
  size = 120,
  strokeWidth = 8,
  color = '#3b82f6',
  backgroundColor = '#e5e7eb',
  className,
  showLabel = true,
  label
}) => {
  const radius = (size - strokeWidth) / 2
  const circumference = radius * 2 * Math.PI
  const offset = circumference - (value / max) * circumference
  const percentage = Math.round((value / max) * 100)

  return (
    <div className={cn("relative", className)}>
      <motion.svg
        width={size}
        height={size}
        className="transform -rotate-90"
        initial={{ scale: 0 }}
        animate={{ scale: 1 }}
        transition={{ duration: 0.5, type: "spring" }}
      >
        {/* Background circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={backgroundColor}
          strokeWidth={strokeWidth}
          fill="transparent"
        />
        {/* Progress circle */}
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={color}
          strokeWidth={strokeWidth}
          fill="transparent"
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 1, ease: "easeOut" }}
        />
      </motion.svg>
      {showLabel && (
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="text-center">
            <motion.div
              className="text-2xl font-bold"
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ delay: 0.5, duration: 0.3 }}
            >
              <NumberCounter value={percentage} suffix="%" />
            </motion.div>
            {label && (
              <motion.div
                className="text-sm text-muted-foreground"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.7 }}
              >
                {label}
              </motion.div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// Sparkline
export interface SparklineProps {
  data: number[]
  color?: string
  className?: string
  height?: number
  width?: number
}

export const Sparkline: React.FC<SparklineProps> = ({
  data,
  color = '#3b82f6',
  className,
  height = 40,
  width = 200
}) => {
  const max = Math.max(...data)
  const min = Math.min(...data)
  const range = max - min

  const points = data.map((value, index) => {
    const x = (index / (data.length - 1)) * width
    const y = height - ((value - min) / range) * height
    return `${x},${y}`
  }).join(' ')

  return (
    <div className={className}>
      <motion.svg
        width={width}
        height={height}
        initial={{ pathLength: 0 }}
        animate={{ pathLength: 1 }}
        transition={{ duration: 1, ease: "easeOut" }}
      >
        <motion.polyline
          fill="none"
          stroke={color}
          strokeWidth="2"
          points={points}
          initial={{ pathLength: 0 }}
          animate={{ pathLength: 1 }}
          transition={{ duration: 1, ease: "easeOut" }}
        />
      </motion.svg>
    </div>
  )
}

// Gauge chart
export interface GaugeChartProps {
  value: number
  max?: number
  title?: string
  className?: string
  size?: number
  color?: string
}

export const GaugeChart: React.FC<GaugeChartProps> = ({
  value,
  max = 100,
  title,
  className,
  size = 200,
  color = '#3b82f6'
}) => {
  const data = [
    { name: 'value', value: value, fill: color },
    { name: 'remaining', value: max - value, fill: '#e5e7eb' }
  ]

  return (
    <AnimatedChart title={title} className={className}>
      <ResponsiveContainer width="100%" height={size}>
        <RadialBarChart
          cx="50%"
          cy="50%"
          innerRadius="60%"
          outerRadius="90%"
          startAngle={180}
          endAngle={0}
          data={data}
        >
          <RadialBar
            dataKey="value"
            cornerRadius={10}
            animationDuration={1000}
            animationEasing="ease-out"
          />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex items-center justify-center">
        <div className="text-center">
          <div className="text-3xl font-bold">
            <NumberCounter value={value} suffix={`/${max}`} />
          </div>
          {title && (
            <div className="text-sm text-muted-foreground mt-1">
              {title}
            </div>
          )}
        </div>
      </div>
    </AnimatedChart>
  )
}

