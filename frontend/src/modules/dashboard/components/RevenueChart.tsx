import { useMemo } from 'react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend
} from 'recharts'
import { Card } from '@/components/ui/card-refactored'
import { Button } from '@/components/ui/button'
import { TrendingUp, Download, Info } from 'lucide-react'
import { cn } from '@/lib/utils'

// Mock data generator
const generateRevenueData = () => {
  const baseValue = 4000
  const data = []
  const today = new Date()

  for (let i = 29; i >= 0; i--) {
    const date = new Date(today)
    date.setDate(today.getDate() - i)

    const dayRevenue = baseValue + Math.random() * 2000 + (30 - i) * 50
    const projectedRevenue = dayRevenue + Math.random() * 500

    data.push({
      date: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      revenue: Math.round(dayRevenue),
      projected: i <= 7 ? Math.round(projectedRevenue) : null,
      cost: Math.round(dayRevenue * 0.6 + Math.random() * 200)
    })
  }

  return data
}

const CustomTooltip = ({ active, payload, label }: { active?: boolean; payload?: Array<{ color: string; name: string; value: number }>; label?: string }) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-background border rounded-lg shadow-lg p-3">
        <p className="font-medium text-sm mb-2">{label}</p>
        {payload.map((entry, index: number) => (
          <div key={index} className="flex items-center justify-between gap-4 text-xs">
            <span className="flex items-center gap-1">
              <div className={cn("w-3 h-3 rounded-full")} style={{ backgroundColor: entry.color }} />
              {entry.name}:
            </span>
            <span className="font-medium">${entry.value?.toLocaleString()}</span>
          </div>
        ))}
      </div>
    )
  }
  return null
}

export default function RevenueChart() {
  const data = useMemo(() => generateRevenueData(), [])

  const totalRevenue = data.reduce((sum, item) => sum + (item.revenue || 0), 0)
  const avgRevenue = Math.round(totalRevenue / data.length)
  const growth = ((data[data.length - 1].revenue - data[0].revenue) / data[0].revenue * 100).toFixed(1)

  return (
    <Card className="p-6">
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h3 className="font-semibold text-lg flex items-center gap-2">
            Revenue Overview
            <Info className="h-4 w-4 text-muted-foreground cursor-help" />
          </h3>
          <div className="flex items-center gap-4 mt-2">
            <div className="flex items-center gap-1">
              <span className="text-sm text-muted-foreground">Total:</span>
              <span className="text-sm font-semibold">${(totalRevenue / 1000).toFixed(1)}K</span>
            </div>
            <div className="flex items-center gap-1">
              <span className="text-sm text-muted-foreground">Avg:</span>
              <span className="text-sm font-semibold">${avgRevenue.toLocaleString()}</span>
            </div>
            <div className="flex items-center gap-1">
              <TrendingUp className="h-3 w-3 text-green-600 dark:text-green-400" />
              <span className="text-sm font-semibold text-green-600 dark:text-green-400">
                +{growth}%
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm">
            <Download className="h-4 w-4" />
          </Button>
          <select className="text-sm border rounded-md px-2 py-1 bg-background">
            <option value="30d">Last 30 days</option>
            <option value="7d">Last 7 days</option>
            <option value="90d">Last 90 days</option>
            <option value="1y">Last year</option>
          </select>
        </div>
      </div>

      {/* Chart */}
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="revenueGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="costGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.2} />
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="projectedGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
              </linearGradient>
            </defs>

            <CartesianGrid strokeDasharray="3 3" className="stroke-muted" opacity={0.3} />

            <XAxis
              dataKey="date"
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
              iconType="line"
              verticalAlign="top"
              height={36}
            />

            <Area
              type="monotone"
              dataKey="revenue"
              stroke="#3b82f6"
              strokeWidth={2}
              fill="url(#revenueGradient)"
              name="Revenue"
              animationDuration={1000}
            />

            <Area
              type="monotone"
              dataKey="cost"
              stroke="#ef4444"
              strokeWidth={1}
              fill="url(#costGradient)"
              name="Cost"
              animationDuration={1200}
              strokeDasharray="3 3"
            />

            <Area
              type="monotone"
              dataKey="projected"
              stroke="#10b981"
              strokeWidth={2}
              fill="url(#projectedGradient)"
              name="Projected"
              animationDuration={1400}
              strokeDasharray="5 5"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Legend Info */}
      <div className="flex items-center justify-between mt-4 pt-4 border-t">
        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 rounded-full bg-blue-500" />
            <span className="text-muted-foreground">Actual Revenue</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 rounded-full bg-green-500" />
            <span className="text-muted-foreground">Projected (AI)</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 rounded-full bg-red-500 opacity-50" />
            <span className="text-muted-foreground">Operating Cost</span>
          </div>
        </div>
        <Button variant="link" size="sm" className="text-xs">
          View Details →
        </Button>
      </div>
    </Card>
  )
}