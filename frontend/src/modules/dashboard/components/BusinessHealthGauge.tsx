import { useMemo } from 'react'
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts'
import { Card } from '@/components/ui/card-refactored'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  Heart,
  AlertCircle,
  CheckCircle,
  XCircle,
  Activity,
  Info
} from 'lucide-react'
import { cn } from '@/lib/utils'

// Calculate health score
const calculateHealthMetrics = () => {
  return {
    overall: 87,
    financial: 92,
    operational: 85,
    customer: 88,
    growth: 81,
    compliance: 95
  }
}

// Custom gauge chart using pie chart
const GaugeChart = ({ score }: { score: number }) => {
  const data = [
    { name: 'Score', value: score },
    { name: 'Remaining', value: 100 - score }
  ]

  const getColor = (value: number) => {
    if (value >= 90) return '#10b981'
    if (value >= 75) return '#3b82f6'
    if (value >= 60) return '#f59e0b'
    return '#ef4444'
  }

  const scoreColor = getColor(score)

  return (
    <div className="relative">
      <ResponsiveContainer width="100%" height={200}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            startAngle={180}
            endAngle={0}
            innerRadius={60}
            outerRadius={80}
            paddingAngle={0}
            dataKey="value"
          >
            <Cell fill={scoreColor} />
            <Cell fill="#e5e7eb" className="dark:fill-gray-800" />
          </Pie>
        </PieChart>
      </ResponsiveContainer>

      {/* Center text */}
      <div className="absolute inset-0 flex flex-col items-center justify-center -mt-8">
        <div className="text-3xl font-bold" style={{ color: scoreColor }}>
          {score}%
        </div>
        <div className="text-xs text-muted-foreground">Health Score</div>
      </div>
    </div>
  )
}

// Health indicator component
const HealthIndicator = ({ label, value, max = 100 }: { label: string; value: number; max?: number }) => {
  const percentage = (value / max) * 100
  const getStatus = () => {
    if (percentage >= 90) return { icon: CheckCircle, color: 'text-green-600 dark:text-green-400' }
    if (percentage >= 75) return { icon: Activity, color: 'text-blue-600 dark:text-blue-400' }
    if (percentage >= 60) return { icon: AlertCircle, color: 'text-amber-600 dark:text-amber-400' }
    return { icon: XCircle, color: 'text-red-600 dark:text-red-400' }
  }

  const { icon: Icon, color } = getStatus()

  return (
    <div className="flex items-center justify-between py-2">
      <div className="flex items-center gap-2">
        <Icon className={cn("h-4 w-4", color)} />
        <span className="text-sm">{label}</span>
      </div>
      <div className="flex items-center gap-2">
        <div className="w-24 h-2 bg-muted rounded-full overflow-hidden">
          <div
            className={cn(
              "h-full transition-all duration-500",
              percentage >= 90 && "bg-green-500",
              percentage >= 75 && percentage < 90 && "bg-blue-500",
              percentage >= 60 && percentage < 75 && "bg-amber-500",
              percentage < 60 && "bg-red-500"
            )}
            style={{ width: `${percentage}%` }}
          />
        </div>
        <span className="text-sm font-medium w-10 text-right">{value}%</span>
      </div>
    </div>
  )
}

export default function BusinessHealthGauge() {
  const metrics = useMemo(() => calculateHealthMetrics(), [])

  const getOverallStatus = (score: number) => {
    if (score >= 90) return { label: 'Excellent', color: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' }
    if (score >= 75) return { label: 'Good', color: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400' }
    if (score >= 60) return { label: 'Fair', color: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400' }
    return { label: 'Needs Attention', color: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400' }
  }

  const status = getOverallStatus(metrics.overall)

  return (
    <Card className="p-6">
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div>
          <h3 className="font-semibold text-lg flex items-center gap-2">
            <Heart className="h-5 w-5 text-brand-600 dark:text-brand-400" />
            Business Health
          </h3>
          <Badge className={cn("mt-2", status.color)}>
            {status.label}
          </Badge>
        </div>
        <Button variant="ghost" size="icon" className="h-8 w-8">
          <Info className="h-4 w-4" />
        </Button>
      </div>

      {/* Gauge Chart */}
      <GaugeChart score={metrics.overall} />

      {/* Metrics Breakdown */}
      <div className="space-y-1 mt-4 pt-4 border-t">
        <HealthIndicator label="Financial" value={metrics.financial} />
        <HealthIndicator label="Operational" value={metrics.operational} />
        <HealthIndicator label="Customer" value={metrics.customer} />
        <HealthIndicator label="Growth" value={metrics.growth} />
        <HealthIndicator label="Compliance" value={metrics.compliance} />
      </div>

      {/* Action Button */}
      <Button variant="outline" className="w-full mt-4" size="sm">
        View Detailed Report
      </Button>
    </Card>
  )
}