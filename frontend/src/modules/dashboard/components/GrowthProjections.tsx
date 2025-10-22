import { useMemo } from 'react'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
  ReferenceLine
} from 'recharts'
import { Card } from '@/components/ui/card-refactored'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { TrendingUp, Sparkles, Download, Calendar, Target } from 'lucide-react'

// Generate projection data
const generateProjectionData = () => {
  const data = []
  const today = new Date()
  const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

  // Historical data (past 6 months)
  for (let i = 5; i >= 0; i--) {
    const date = new Date(today)
    date.setMonth(today.getMonth() - i)

    const baseValue = 35000 + (5 - i) * 3000 + Math.random() * 5000
    data.push({
      month: monthNames[date.getMonth()],
      actual: Math.round(baseValue),
      projected: null,
      optimistic: null,
      conservative: null,
      isHistorical: true
    })
  }

  // Current month (partial)
  const currentMonthValue = 52000 + Math.random() * 3000
  data.push({
    month: monthNames[today.getMonth()],
    actual: Math.round(currentMonthValue),
    projected: Math.round(currentMonthValue * 1.05),
    optimistic: null,
    conservative: null,
    isHistorical: false,
    isCurrent: true
  })

  // Future projections (next 5 months)
  let lastValue = currentMonthValue
  for (let i = 1; i <= 5; i++) {
    const date = new Date(today)
    date.setMonth(today.getMonth() + i)

    const growthRate = 1.08 + Math.random() * 0.04
    const projectedValue = lastValue * growthRate

    data.push({
      month: monthNames[date.getMonth()],
      actual: null,
      projected: Math.round(projectedValue),
      optimistic: Math.round(projectedValue * 1.15),
      conservative: Math.round(projectedValue * 0.9),
      isHistorical: false,
      isFuture: true
    })

    lastValue = projectedValue
  }

  return data
}

const CustomTooltip = ({ active, payload, label }: { active?: boolean; payload?: Array<{ value: number | null; name: string; color: string; payload?: { isHistorical?: boolean; isCurrent?: boolean; isFuture?: boolean } }>; label?: string }) => {
  if (active && payload && payload.length) {
    const isCurrent = payload[0]?.payload?.isCurrent

    return (
      <div className="bg-background border rounded-lg shadow-lg p-3">
        <p className="font-medium text-sm mb-2">
          {label}
          {isCurrent && (
            <Badge variant="outline" className="ml-2 text-xs">Current</Badge>
          )}
        </p>
        {payload.map((entry, index: number) => {
          if (entry.value === null) return null
          return (
            <div key={index} className="flex items-center justify-between gap-4 text-xs">
              <span className="flex items-center gap-1">
                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: entry.color }} />
                {entry.name}:
              </span>
              <span className="font-medium">${(entry.value / 1000).toFixed(1)}K</span>
            </div>
          )
        })}
        {isFuture && (
          <div className="mt-2 pt-2 border-t text-xs text-muted-foreground">
            AI-powered prediction
          </div>
        )}
      </div>
    )
  }
  return null
}

// Custom dot for current month
const CustomDot = (props: { cx?: number; cy?: number; payload?: { isCurrent?: boolean } }) => {
  const { cx, cy, payload } = props

  if (payload?.isCurrent) {
    return (
      <g>
        <circle cx={cx} cy={cy} r={6} fill="#3b82f6" className="animate-pulse" />
        <circle cx={cx} cy={cy} r={3} fill="white" />
      </g>
    )
  }

  return null
}

export default function GrowthProjections() {
  const data = useMemo(() => generateProjectionData(), [])

  // Calculate growth metrics
  const historicalData = data.filter(d => d.isHistorical)
  const futureData = data.filter(d => d.isFuture)

  const avgHistoricalGrowth = historicalData.length > 1
    ? ((historicalData[historicalData.length - 1].actual - historicalData[0].actual) / historicalData[0].actual * 100 / historicalData.length).toFixed(1)
    : 0

  const projectedGrowth = futureData.length > 0
    ? ((futureData[futureData.length - 1].projected - (data.find(d => d.isCurrent)?.actual || 0)) / (data.find(d => d.isCurrent)?.actual || 1) * 100).toFixed(1)
    : 0

  const nextTarget = futureData[0]?.projected || 0

  return (
    <Card className="p-6">
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h3 className="font-semibold text-lg flex items-center gap-2">
            <Sparkles className="h-5 w-5 text-brand-600 dark:text-brand-400" />
            Growth Projections
            <Badge variant="outline" className="ml-2">
              AI-Powered
            </Badge>
          </h3>
          <div className="flex items-center gap-4 mt-2">
            <div className="flex items-center gap-1">
              <span className="text-sm text-muted-foreground">Historical Growth:</span>
              <span className="text-sm font-semibold text-green-600 dark:text-green-400">
                +{avgHistoricalGrowth}%/mo
              </span>
            </div>
            <div className="flex items-center gap-1">
              <span className="text-sm text-muted-foreground">Projected:</span>
              <span className="text-sm font-semibold text-blue-600 dark:text-blue-400">
                +{projectedGrowth}%
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm">
            <Calendar className="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="sm">
            <Download className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Chart */}
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="actualGradient" x1="0" y1="0" x2="1" y2="0">
                <stop offset="0%" stopColor="#3b82f6" stopOpacity={1} />
                <stop offset="100%" stopColor="#3b82f6" stopOpacity={0.6} />
              </linearGradient>
              <linearGradient id="projectedGradient" x1="0" y1="0" x2="1" y2="0">
                <stop offset="0%" stopColor="#10b981" stopOpacity={0.6} />
                <stop offset="100%" stopColor="#10b981" stopOpacity={1} />
              </linearGradient>
            </defs>

            <CartesianGrid strokeDasharray="3 3" className="stroke-muted" opacity={0.3} />

            <XAxis
              dataKey="month"
              className="text-xs"
              tick={{ fill: 'currentColor' }}
              stroke="currentColor"
              strokeOpacity={0.1}
            />

            <YAxis
              className="text-xs"
              tick={{ fill: 'currentColor' }}
              stroke="currentColor"
              strokeOpacity={0.1}
              tickFormatter={(value) => `$${(value / 1000).toFixed(0)}K`}
            />

            <Tooltip content={<CustomTooltip />} />

            <Legend
              wrapperStyle={{ fontSize: '12px' }}
              verticalAlign="top"
              height={36}
            />

            {/* Reference line for current month */}
            <ReferenceLine
              x={data.find(d => d.isCurrent)?.month}
              stroke="#6b7280"
              strokeDasharray="5 5"
              label={{ value: "Today", position: "top", fontSize: 10 }}
            />

            {/* Actual revenue line */}
            <Line
              type="monotone"
              dataKey="actual"
              stroke="url(#actualGradient)"
              strokeWidth={3}
              name="Actual"
              dot={<CustomDot />}
              animationDuration={1000}
            />

            {/* Projected revenue line */}
            <Line
              type="monotone"
              dataKey="projected"
              stroke="#10b981"
              strokeWidth={3}
              strokeDasharray="5 5"
              name="Projected"
              dot={{ fill: '#10b981', strokeWidth: 2, r: 4 }}
              animationDuration={1200}
            />

            {/* Optimistic projection */}
            <Line
              type="monotone"
              dataKey="optimistic"
              stroke="#10b981"
              strokeWidth={1}
              strokeDasharray="2 2"
              name="Optimistic"
              dot={false}
              opacity={0.3}
              animationDuration={1400}
            />

            {/* Conservative projection */}
            <Line
              type="monotone"
              dataKey="conservative"
              stroke="#ef4444"
              strokeWidth={1}
              strokeDasharray="2 2"
              name="Conservative"
              dot={false}
              opacity={0.3}
              animationDuration={1400}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Projection Insights */}
      <div className="grid grid-cols-3 gap-4 mt-4 pt-4 border-t">
        <div>
          <div className="flex items-center gap-1 text-xs text-muted-foreground mb-1">
            <Target className="h-3 w-3" />
            Next Month Target
          </div>
          <p className="text-lg font-semibold">${(nextTarget / 1000).toFixed(1)}K</p>
        </div>
        <div>
          <div className="text-xs text-muted-foreground mb-1">Confidence Level</div>
          <div className="flex items-center gap-2">
            <p className="text-lg font-semibold">85%</p>
            <Badge variant="outline" className="text-xs">High</Badge>
          </div>
        </div>
        <div>
          <div className="text-xs text-muted-foreground mb-1">Growth Rate</div>
          <div className="flex items-center gap-1">
            <TrendingUp className="h-4 w-4 text-green-600 dark:text-green-400" />
            <p className="text-lg font-semibold text-green-600 dark:text-green-400">
              +8.2%
            </p>
          </div>
        </div>
      </div>

      {/* Action Buttons */}
      <div className="flex gap-2 mt-4">
        <Button variant="outline" size="sm" className="flex-1">
          Adjust Projections
        </Button>
        <Button variant="outline" size="sm" className="flex-1">
          View Assumptions
        </Button>
      </div>
    </Card>
  )
}