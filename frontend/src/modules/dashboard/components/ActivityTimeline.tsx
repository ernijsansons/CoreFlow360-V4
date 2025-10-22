import { useMemo } from 'react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell
} from 'recharts'
import { Card } from '@/components/ui/card-refactored'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Activity, Clock, Filter, TrendingUp } from 'lucide-react'

// Generate hourly activity data
const generateActivityData = () => {
  const data = []
  const now = new Date()

  for (let i = 23; i >= 0; i--) {
    const hour = new Date(now)
    hour.setHours(now.getHours() - i)

    const baseActivity = 20 + Math.random() * 30
    const peakHours = [9, 10, 11, 14, 15, 16, 17]
    const isPeakHour = peakHours.includes(hour.getHours())
    const activity = isPeakHour ? baseActivity * 2 : baseActivity

    data.push({
      time: hour.toLocaleTimeString('en-US', { hour: 'numeric', hour12: true }),
      hour: hour.getHours(),
      users: Math.round(activity + Math.random() * 20),
      events: Math.round(activity * 3 + Math.random() * 50),
      revenue: Math.round(activity * 15 + Math.random() * 100)
    })
  }

  return data
}

const CustomTooltip = ({ active, payload, label }: { active?: boolean; payload?: Array<{ payload: { users: number; events: number; revenue: number } }>; label?: string }) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-background border rounded-lg shadow-lg p-3">
        <p className="font-medium text-sm mb-2">{label}</p>
        {payload.map((entry, index: number) => (
          <div key={index} className="text-xs space-y-1">
            <div className="flex items-center justify-between gap-4">
              <span>Active Users:</span>
              <span className="font-medium">{entry.payload.users}</span>
            </div>
            <div className="flex items-center justify-between gap-4">
              <span>Events:</span>
              <span className="font-medium">{entry.payload.events}</span>
            </div>
            <div className="flex items-center justify-between gap-4">
              <span>Revenue:</span>
              <span className="font-medium">${entry.payload.revenue}</span>
            </div>
          </div>
        ))}
      </div>
    )
  }
  return null
}

// Custom bar shape with gradient
const CustomBar = (props: { fill?: string; x?: number; y?: number; width?: number; height?: number }) => {
  const { fill, x, y, width, height } = props

  return (
    <g>
      <defs>
        <linearGradient id={`barGradient-${x}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={fill} stopOpacity={0.8} />
          <stop offset="100%" stopColor={fill} stopOpacity={0.3} />
        </linearGradient>
      </defs>
      <rect
        x={x}
        y={y}
        width={width}
        height={height}
        fill={`url(#barGradient-${x})`}
        rx={2}
        ry={2}
      />
    </g>
  )
}

export default function ActivityTimeline() {
  const data = useMemo(() => generateActivityData(), [])

  const totalEvents = data.reduce((sum, item) => sum + item.events, 0)
  const activeUsers = data[data.length - 1].users
  const peakUsers = Math.max(...data.map(d => d.users))
  const avgUsers = Math.round(data.reduce((sum, item) => sum + item.users, 0) / data.length)

  // Color based on activity level
  const getBarColor = (value: number) => {
    const max = Math.max(...data.map(d => d.users))
    const percentage = value / max

    if (percentage > 0.8) return '#10b981' // High activity - green
    if (percentage > 0.5) return '#3b82f6' // Medium activity - blue
    if (percentage > 0.3) return '#f59e0b' // Low activity - amber
    return '#6b7280' // Very low - gray
  }

  return (
    <Card className="p-6">
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h3 className="font-semibold text-lg flex items-center gap-2">
            <Activity className="h-5 w-5 text-brand-600 dark:text-brand-400" />
            Activity Timeline
          </h3>
          <div className="flex items-center gap-3 mt-2">
            <Badge variant="outline" className="text-xs">
              <div className="h-2 w-2 rounded-full bg-green-500 animate-pulse mr-1" />
              {activeUsers} active now
            </Badge>
            <span className="text-xs text-muted-foreground">
              Peak: {peakUsers} users • Avg: {avgUsers} users
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm">
            <Filter className="h-4 w-4" />
          </Button>
          <select className="text-sm border rounded-md px-2 py-1 bg-background">
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
          </select>
        </div>
      </div>

      {/* Chart */}
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" className="stroke-muted" opacity={0.3} />

            <XAxis
              dataKey="time"
              className="text-xs"
              tick={{ fill: 'currentColor' }}
              stroke="currentColor"
              strokeOpacity={0.1}
              interval="preserveStartEnd"
            />

            <YAxis
              className="text-xs"
              tick={{ fill: 'currentColor' }}
              stroke="currentColor"
              strokeOpacity={0.1}
            />

            <Tooltip content={<CustomTooltip />} cursor={{ fill: 'transparent' }} />

            <Bar
              dataKey="users"
              radius={[4, 4, 0, 0]}
              animationDuration={1000}
              shape={CustomBar}
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={getBarColor(entry.users)} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-3 gap-4 mt-4 pt-4 border-t">
        <div>
          <div className="flex items-center gap-1 text-xs text-muted-foreground mb-1">
            <Clock className="h-3 w-3" />
            Total Events
          </div>
          <p className="text-lg font-semibold">{totalEvents.toLocaleString()}</p>
        </div>
        <div>
          <div className="flex items-center gap-1 text-xs text-muted-foreground mb-1">
            <TrendingUp className="h-3 w-3" />
            Peak Hour
          </div>
          <p className="text-lg font-semibold">
            {data.find(d => d.users === peakUsers)?.time || 'N/A'}
          </p>
        </div>
        <div>
          <div className="text-xs text-muted-foreground mb-1">Engagement Rate</div>
          <div className="flex items-center gap-2">
            <p className="text-lg font-semibold">84.2%</p>
            <Badge variant="outline" className="text-xs">
              <TrendingUp className="h-3 w-3 mr-1" />
              +5.1%
            </Badge>
          </div>
        </div>
      </div>

      {/* Activity Legend */}
      <div className="flex items-center gap-4 mt-3 text-xs">
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded bg-green-500" />
          <span className="text-muted-foreground">High Activity</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded bg-blue-500" />
          <span className="text-muted-foreground">Medium</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded bg-amber-500" />
          <span className="text-muted-foreground">Low</span>
        </div>
      </div>
    </Card>
  )
}