import { useEffect, useState, lazy, Suspense } from 'react'
import { useAuthStore, useUIStore, useEntityStore } from '@/stores'
import { motion, AnimatePresence } from 'framer-motion'
import {
  TrendingUp,
  Users,
  DollarSign,
  ShoppingCart,
  Activity,
  FileText,
  UserPlus,
  Building2,
  Calendar,
  ArrowUpRight,
  Clock,
  AlertCircle,
  Sparkles,
  ChevronRight,
  Filter,
  Download,
  RefreshCw,
  MoreVertical,
  Target,
  Zap,
  TrendingDown
} from 'lucide-react'
import { Card } from '@/components/ui/card-refactored'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

// Lazy load chart components for performance
const RevenueChart = lazy(() => import('./components/RevenueChart'))
const ActivityTimeline = lazy(() => import('./components/ActivityTimeline'))
const BusinessHealthGauge = lazy(() => import('./components/BusinessHealthGauge'))
const GrowthProjections = lazy(() => import('./components/GrowthProjections'))

// Hero Metric Component
const HeroMetric = ({
  title,
  value,
  change,
  trend,
  icon: Icon,
  sparklineData,
  onClick,
  loading = false
}: { title: string; value: string; change: string; trend: "up" | "down"; icon: React.ComponentType<{ className?: string }>; sparklineData?: number[]; onClick?: () => void; loading?: boolean }) => {
  const isPositive = trend === 'up'
  const TrendIcon = isPositive ? TrendingUp : TrendingDown

  if (loading) {
    return (
      <Card className="p-6">
        <Skeleton className="h-4 w-24 mb-2" />
        <Skeleton className="h-10 w-32 mb-2" />
        <Skeleton className="h-4 w-28" />
      </Card>
    )
  }

  return (
    <motion.div
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      <Card
        className="relative overflow-hidden p-6 cursor-pointer group hover:shadow-lg transition-all duration-300"
        onClick={onClick}
      >
        {/* Background gradient - Brand colors */}
        <div className="absolute inset-0 bg-gradient-to-br from-brand-primary-50/30 via-transparent to-brand-primary-100/20 dark:from-brand-primary-900/5 dark:to-brand-primary-950/10" />

        {/* Content */}
        <div className="relative">
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className={cn(
                "p-2 rounded-lg shadow-sm transition-all",
                isPositive
                  ? "bg-success-100 dark:bg-success-900/30"
                  : "bg-error-100 dark:bg-error-900/30"
              )}>
                <Icon className={cn(
                  "h-5 w-5",
                  isPositive
                    ? "text-success-600 dark:text-success-400"
                    : "text-error-600 dark:text-error-400"
                )} />
              </div>
              <div>
                <p className="text-sm font-medium text-muted-foreground">{title}</p>
              </div>
            </div>
            <Button
              variant="ghost"
              size="sm"
              className="opacity-0 group-hover:opacity-100 transition-opacity"
            >
              <MoreVertical className="h-4 w-4" />
            </Button>
          </div>

          <div className="space-y-2">
            <div className="flex items-baseline gap-2">
              <h2 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-brand-primary-600 to-brand-primary-700 bg-clip-text text-transparent dark:from-brand-primary-400 dark:to-brand-primary-500">{value}</h2>
              <Badge
                variant={isPositive ? "success" : "error"}
                className="font-semibold shadow-sm"
              >
                <TrendIcon className="h-3 w-3 mr-1" />
                {change}
              </Badge>
            </div>

            {/* Sparkline preview */}
            {sparklineData && (
              <div className="h-12 mt-4">
                <Suspense fallback={<Skeleton className="h-full w-full" />}>
                  <SparklinePreview data={sparklineData} trend={trend} />
                </Suspense>
              </div>
            )}
          </div>
        </div>

        {/* Click indicator */}
        <div className="absolute bottom-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity">
          <ChevronRight className="h-4 w-4 text-muted-foreground" />
        </div>
      </Card>
    </motion.div>
  )
}

// Sparkline Preview Component - Using Design System Colors
const SparklinePreview = ({ data, trend }: { data: number[], trend: string }) => {
  const max = Math.max(...data)
  const min = Math.min(...data)
  const range = max - min

  // Design system colors from --semantic-success-500 (#22c55e) and --semantic-error-500 (#ef4444)
  const strokeColor = trend === 'up' ? '#22c55e' : '#ef4444'

  return (
    <svg className="w-full h-full" viewBox="0 0 100 40">
      <polyline
        fill="none"
        stroke={strokeColor}
        strokeWidth="2"
        points={data.map((value, index) => {
          const x = (index / (data.length - 1)) * 100
          const y = 40 - ((value - min) / range) * 40
          return `${x},${y}`
        }).join(' ')}
      />
      <defs>
        <linearGradient id={`gradient-${trend}`} x1="0%" y1="0%" x2="0%" y2="100%">
          <stop
            offset="0%"
            stopColor={strokeColor}
            stopOpacity="0.3"
          />
          <stop
            offset="100%"
            stopColor={strokeColor}
            stopOpacity="0"
          />
        </linearGradient>
      </defs>
      <polyline
        fill={`url(#gradient-${trend})`}
        stroke="none"
        points={`0,40 ${data.map((value, index) => {
          const x = (index / (data.length - 1)) * 100
          const y = 40 - ((value - min) / range) * 40
          return `${x},${y}`
        }).join(' ')} 100,40`}
      />
    </svg>
  )
}

// AI Insights Panel Component
const AIInsightsPanel = ({ insights = [], loading = false }: { insights?: Array<{ type: string; message: string; impact: string; priority: string }>; loading?: boolean }) => {
  if (loading) {
    return (
      <Card className="p-6">
        <div className="flex items-center gap-2 mb-4">
          <Sparkles className="h-5 w-5 text-brand-600" />
          <h3 className="font-semibold">AI Insights</h3>
        </div>
        <div className="space-y-3">
          <Skeleton className="h-20 w-full" />
          <Skeleton className="h-20 w-full" />
        </div>
      </Card>
    )
  }

  const defaultInsights = [
    {
      type: 'recommendation',
      icon: Target,
      title: 'Revenue Opportunity',
      description: 'Your conversion rate is 15% below industry average. Consider A/B testing your checkout flow.',
      action: 'View Details',
      priority: 'high'
    },
    {
      type: 'anomaly',
      icon: AlertCircle,
      title: 'Unusual Traffic Spike',
      description: 'Website traffic increased by 340% in the last hour. Investigate potential causes.',
      action: 'Analyze',
      priority: 'medium'
    },
    {
      type: 'prediction',
      icon: TrendingUp,
      title: 'Growth Forecast',
      description: 'Based on current trends, revenue will reach $75K next month (+25% MoM).',
      action: 'View Projection',
      priority: 'low'
    }
  ]

  const insightsToShow = insights.length > 0 ? insights : defaultInsights

  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.3, delay: 0.2 }}
    >
      <Card className="p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-brand-primary-100 dark:bg-brand-primary-900/30">
              <Sparkles className="h-5 w-5 text-brand-primary-600 dark:text-brand-primary-400" />
            </div>
            <h3 className="font-semibold text-brand-primary-900 dark:text-brand-primary-100">AI Insights</h3>
          </div>
          <Button variant="ghost" size="sm">
            <RefreshCw className="h-4 w-4" />
          </Button>
        </div>

        <div className="space-y-3">
          {insightsToShow.map((insight: { icon: React.ComponentType<{ className?: string }>; type: string; message: string; impact: string; priority: 'high' | 'medium' | 'low' }, index: number) => {
            const Icon = insight.icon
            const priorityColors = {
              high: 'bg-error-100 text-error-700 dark:bg-error-900/30 dark:text-error-400',
              medium: 'bg-warning-100 text-warning-700 dark:bg-warning-900/30 dark:text-warning-400',
              low: 'bg-info-100 text-info-700 dark:bg-info-900/30 dark:text-info-400'
            }

            return (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
                className="p-4 rounded-lg bg-muted/50 hover:bg-muted transition-colors cursor-pointer group"
              >
                <div className="flex items-start gap-3">
                  <div className={cn(
                    "p-2 rounded-lg",
                    priorityColors[insight.priority as keyof typeof priorityColors]
                  )}>
                    <Icon className="h-4 w-4" />
                  </div>
                  <div className="flex-1 space-y-1">
                    <div className="flex items-center justify-between">
                      <h4 className="font-medium text-sm">{insight.title}</h4>
                      <ChevronRight className="h-4 w-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                    </div>
                    <p className="text-sm text-muted-foreground">
                      {insight.description}
                    </p>
                    <Button variant="link" size="sm" className="h-auto p-0 text-brand-primary-600 hover:text-brand-primary-700 dark:text-brand-primary-400 dark:hover:text-brand-primary-300">
                      {insight.action} →
                    </Button>
                  </div>
                </div>
              </motion.div>
            )
          })}
        </div>

        <Button variant="outline" className="w-full mt-4">
          View All Insights
        </Button>
      </Card>
    </motion.div>
  )
}

// Quick Action Component
const QuickAction = ({ icon: Icon, title, description, onClick, color = 'brand' }: { icon: React.ComponentType<{ className?: string }>; title: string; description: string; onClick: () => void; color?: 'brand' | 'success' | 'warning' | 'info' }) => {
  const colorClasses = {
    brand: 'text-brand-600 dark:text-brand-400 bg-brand-100 dark:bg-brand-900/30',
    green: 'text-green-600 dark:text-green-400 bg-green-100 dark:bg-green-900/30',
    blue: 'text-blue-600 dark:text-blue-400 bg-blue-100 dark:bg-blue-900/30',
    purple: 'text-purple-600 dark:text-purple-400 bg-purple-100 dark:bg-purple-900/30'
  }

  return (
    <motion.button
      whileHover={{ scale: 1.05 }}
      whileTap={{ scale: 0.95 }}
      onClick={onClick}
      className="p-4 border rounded-lg hover:bg-accent hover:shadow-md transition-all duration-200 text-left group relative overflow-hidden"
    >
      <div className="absolute inset-0 bg-gradient-to-br from-transparent to-brand-50/10 dark:to-brand-900/5 opacity-0 group-hover:opacity-100 transition-opacity" />
      <div className="relative">
        <div className={cn("p-3 rounded-lg inline-block mb-3", colorClasses[color as keyof typeof colorClasses])}>
          <Icon className="h-6 w-6" />
        </div>
        <h3 className="font-semibold mb-1">{title}</h3>
        <p className="text-sm text-muted-foreground">{description}</p>
      </div>
      <ArrowUpRight className="absolute top-4 right-4 h-4 w-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
    </motion.button>
  )
}

// Activity Item Component
const ActivityItem = ({ activity, isLast = false }: { activity: { type: string; title: string; time: string; user: string; metadata?: Record<string, unknown> }; isLast?: boolean }) => {
  const getActivityIcon = (type: string) => {
    switch (type) {
      case 'invoice': return FileText
      case 'customer': return UserPlus
      case 'order': return ShoppingCart
      case 'payment': return DollarSign
      default: return Activity
    }
  }

  const getActivityColor = (type: string) => {
    switch (type) {
      case 'invoice': return 'text-blue-600 dark:text-blue-400'
      case 'customer': return 'text-green-600 dark:text-green-400'
      case 'order': return 'text-purple-600 dark:text-purple-400'
      case 'payment': return 'text-emerald-600 dark:text-emerald-400'
      default: return 'text-gray-600 dark:text-gray-400'
    }
  }

  const Icon = getActivityIcon(activity.type)
  const colorClass = getActivityColor(activity.type)

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      className="flex gap-4 group"
    >
      <div className="relative">
        <div className={cn(
          "p-2 rounded-full bg-muted",
        )}>
          <Icon className={cn("h-4 w-4", colorClass)} />
        </div>
        {!isLast && (
          <div className="absolute top-10 left-1/2 transform -translate-x-1/2 w-0.5 h-16 bg-border" />
        )}
      </div>

      <div className="flex-1 pb-8">
        <div className="flex items-center justify-between">
          <div>
            <p className="font-medium text-sm">{activity.title}</p>
            <p className="text-sm text-muted-foreground mt-1">{activity.description}</p>
            <p className="text-xs text-muted-foreground mt-1">
              <Clock className="h-3 w-3 inline mr-1" />
              {activity.time}
            </p>
          </div>
          {activity.value && (
            <span className={cn(
              "font-semibold text-sm",
              activity.value.startsWith('+') ? 'text-green-600 dark:text-green-400' : ''
            )}>
              {activity.value}
            </span>
          )}
        </div>
      </div>
    </motion.div>
  )
}

export function Dashboard() {
  const { user } = useAuthStore()
  const { setBreadcrumbs } = useUIStore()
  const { currentEntity } = useEntityStore()
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [metricsLoading, setMetricsLoading] = useState(true)

  useEffect(() => {
    setBreadcrumbs([{ label: 'Dashboard' }])
    // Simulate loading
    setTimeout(() => setMetricsLoading(false), 1000)
  }, [setBreadcrumbs])

  const handleRefresh = async () => {
    setIsRefreshing(true)
    // Simulate refresh
    await new Promise(resolve => setTimeout(resolve, 2000))
    setIsRefreshing(false)
  }

  // Mock data with sparklines
  const heroMetrics = [
    {
      title: 'Total Revenue',
      value: '$45,231.89',
      change: '+20.1%',
      trend: 'up',
      icon: DollarSign,
      sparklineData: [30, 35, 32, 38, 40, 42, 45, 43, 48, 52, 50, 55]
    },
    {
      title: 'Active Users',
      value: '2,350',
      change: '+180.1%',
      trend: 'up',
      icon: Users,
      sparklineData: [1200, 1400, 1350, 1600, 1750, 1900, 2100, 2200, 2350]
    },
    {
      title: 'Total Orders',
      value: '12,234',
      change: '+19%',
      trend: 'up',
      icon: ShoppingCart,
      sparklineData: [8000, 8500, 9000, 9200, 9800, 10500, 11000, 11500, 12234]
    },
    {
      title: 'Active Now',
      value: '573',
      change: '-8.2%',
      trend: 'down',
      icon: Activity,
      sparklineData: [620, 610, 590, 580, 575, 570, 573]
    }
  ]

  const quickActions = [
    {
      icon: FileText,
      title: 'Create Invoice',
      description: 'Generate and send invoice',
      color: 'blue',
      onClick: () => console.log('Create invoice')
    },
    {
      icon: UserPlus,
      title: 'Add Customer',
      description: 'Add new customer to CRM',
      color: 'green',
      onClick: () => console.log('Add customer')
    },
    {
      icon: Building2,
      title: 'New Business',
      description: 'Set up new business entity',
      color: 'purple',
      onClick: () => console.log('New business')
    },
    {
      icon: Calendar,
      title: 'Schedule Task',
      description: 'Create automated task',
      color: 'brand',
      onClick: () => console.log('Schedule task')
    }
  ]

  const recentActivities = [
    {
      type: 'invoice',
      title: 'Invoice #1234 paid',
      description: 'Payment received from Acme Corp',
      time: '2 hours ago',
      value: '+$2,500'
    },
    {
      type: 'customer',
      title: 'New customer added',
      description: 'John Smith joined via signup form',
      time: '5 hours ago',
      value: null
    },
    {
      type: 'order',
      title: 'Order #5678 shipped',
      description: 'Tracking: UPS-123456789',
      time: '1 day ago',
      value: null
    },
    {
      type: 'payment',
      title: 'Subscription renewed',
      description: 'Premium plan auto-renewed',
      time: '2 days ago',
      value: '+$99'
    }
  ]

  return (
    <div className="space-y-8 pb-8">
      {/* Header Section */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">
            Welcome back, {user?.firstName || 'User'}!
          </h1>
          <p className="text-muted-foreground mt-2">
            {currentEntity?.name
              ? `Here's what's happening with ${currentEntity.name} today.`
              : "Here's your business overview for today."}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleRefresh}
            disabled={isRefreshing}
          >
            <RefreshCw className={cn("h-4 w-4 mr-2", isRefreshing && "animate-spin")} />
            Refresh
          </Button>
          <Button variant="outline" size="sm">
            <Download className="h-4 w-4 mr-2" />
            Export
          </Button>
          <Button variant="outline" size="sm">
            <Filter className="h-4 w-4 mr-2" />
            Filter
          </Button>
        </div>
      </div>

      {/* Hero Metrics Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {heroMetrics.map((metric, index) => (
          <HeroMetric
            key={index}
            {...metric}
            loading={metricsLoading}
            onClick={() => console.log(`Clicked ${metric.title}`)}
          />
        ))}
      </div>

      {/* Charts Section */}
      <div className="grid gap-6 lg:grid-cols-2">
        <Suspense fallback={
          <Card className="p-6">
            <Skeleton className="h-8 w-32 mb-4" />
            <Skeleton className="h-64 w-full" />
          </Card>
        }>
          <RevenueChart />
        </Suspense>

        <Suspense fallback={
          <Card className="p-6">
            <Skeleton className="h-8 w-32 mb-4" />
            <Skeleton className="h-64 w-full" />
          </Card>
        }>
          <ActivityTimeline />
        </Suspense>
      </div>

      {/* Secondary Charts Row */}
      <div className="grid gap-6 lg:grid-cols-3">
        <Suspense fallback={
          <Card className="p-6">
            <Skeleton className="h-8 w-32 mb-4" />
            <Skeleton className="h-48 w-full" />
          </Card>
        }>
          <BusinessHealthGauge />
        </Suspense>

        <Suspense fallback={
          <Card className="p-6 lg:col-span-2">
            <Skeleton className="h-8 w-32 mb-4" />
            <Skeleton className="h-48 w-full" />
          </Card>
        }>
          <div className="lg:col-span-2">
            <GrowthProjections />
          </div>
        </Suspense>
      </div>

      {/* AI Insights and Quick Actions Row */}
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-1">
          <AIInsightsPanel />
        </div>

        <div className="lg:col-span-2">
          <Card className="p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold flex items-center gap-2">
                <Zap className="h-5 w-5 text-brand-600 dark:text-brand-400" />
                Quick Actions
              </h3>
              <Button variant="ghost" size="sm">
                View All
                <ChevronRight className="h-4 w-4 ml-1" />
              </Button>
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              {quickActions.map((action, index) => (
                <QuickAction key={index} {...action} />
              ))}
            </div>
          </Card>
        </div>
      </div>

      {/* Recent Activity Feed */}
      <Card className="p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="font-semibold flex items-center gap-2">
            <Activity className="h-5 w-5 text-brand-600 dark:text-brand-400" />
            Recent Activity
          </h3>
          <div className="flex items-center gap-2">
            <Badge variant="outline">
              <div className="h-2 w-2 rounded-full bg-green-500 animate-pulse mr-2" />
              Live
            </Badge>
            <Button variant="ghost" size="sm">
              View All
              <ChevronRight className="h-4 w-4 ml-1" />
            </Button>
          </div>
        </div>

        <div className="space-y-1">
          <AnimatePresence>
            {recentActivities.map((activity, index) => (
              <ActivityItem
                key={index}
                activity={activity}
                isLast={index === recentActivities.length - 1}
              />
            ))}
          </AnimatePresence>
        </div>
      </Card>
    </div>
  )
}