import * as React from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { MainLayout } from '@/layouts/main-layout'
import { TrafficChart } from '@/components/dashboard/TrafficChart'
import { ConversionFunnel } from '@/components/dashboard/ConversionFunnel'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import {
  BarChart3,
  TrendingUp,
  TrendingDown,
  Users,
  Eye,
  MousePointer,
  Clock,
  Globe,
  Smartphone,
  Monitor,
  Download,
  RefreshCw,
  ArrowUpRight,
  ArrowDownRight,
  Activity
} from 'lucide-react'
import { useUIStore } from '@/stores'

export const Route = createFileRoute('/dashboard/analytics/')({
  component: AnalyticsDashboard,
  beforeLoad: () => {
    useUIStore.getState().setBreadcrumbs([
      { label: 'Dashboard', href: '/dashboard' },
      { label: 'Analytics' }
    ])
  },
})

function AnalyticsDashboard() {
  const [dateRange, setDateRange] = React.useState('last-7-days')
  const [comparison, setComparison] = React.useState('previous-period')
  const [isRefreshing, setIsRefreshing] = React.useState(false)

  const handleRefresh = () => {
    setIsRefreshing(true)
    setTimeout(() => setIsRefreshing(false), 2000)
  }

  const analyticsMetrics = [
    {
      title: 'Page Views',
      value: '248,592',
      change: 12.3,
      icon: Eye,
      color: 'text-blue-600',
      bgColor: 'bg-blue-100 dark:bg-blue-900/20',
      sparkline: [40, 45, 50, 48, 55, 60, 58]
    },
    {
      title: 'Unique Visitors',
      value: '48,293',
      change: 8.7,
      icon: Users,
      color: 'text-green-600',
      bgColor: 'bg-green-100 dark:bg-green-900/20',
      sparkline: [30, 35, 32, 38, 42, 45, 48]
    },
    {
      title: 'Bounce Rate',
      value: '32.8%',
      change: -5.2,
      icon: TrendingDown,
      color: 'text-purple-600',
      bgColor: 'bg-purple-100 dark:bg-purple-900/20',
      sparkline: [45, 42, 40, 38, 35, 33, 32]
    },
    {
      title: 'Avg. Session',
      value: '3m 42s',
      change: 15.8,
      icon: Clock,
      color: 'text-orange-600',
      bgColor: 'bg-orange-100 dark:bg-orange-900/20',
      sparkline: [180, 195, 200, 210, 215, 220, 222]
    }
  ]

  const topPages = [
    { path: '/dashboard', views: 45892, change: 12.5, bounceRate: 28.3 },
    { path: '/products', views: 38421, change: 8.2, bounceRate: 35.7 },
    { path: '/pricing', views: 28937, change: -3.4, bounceRate: 42.1 },
    { path: '/blog', views: 24156, change: 18.9, bounceRate: 31.2 },
    { path: '/about', views: 18723, change: 5.6, bounceRate: 38.9 }
  ]

  const trafficSources = [
    { source: 'Organic Search', sessions: 125420, percentage: 42.3, trend: 'up' },
    { source: 'Direct', sessions: 89234, percentage: 30.1, trend: 'up' },
    { source: 'Social Media', sessions: 45678, percentage: 15.4, trend: 'down' },
    { source: 'Referral', sessions: 23456, percentage: 7.9, trend: 'up' },
    { source: 'Email', sessions: 12789, percentage: 4.3, trend: 'up' }
  ]

  const deviceStats = [
    { device: 'Desktop', users: 158420, percentage: 53.4, icon: Monitor },
    { device: 'Mobile', users: 112350, percentage: 37.9, icon: Smartphone },
    { device: 'Tablet', users: 25830, percentage: 8.7, icon: Smartphone }
  ]

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex justify-between items-start">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
              Analytics Dashboard
            </h1>
            <p className="mt-2 text-gray-600 dark:text-gray-400">
              Track and analyze your website performance and user behavior
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <Select value={dateRange} onValueChange={setDateRange}>
              <SelectTrigger className="w-40">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="today">Today</SelectItem>
                <SelectItem value="yesterday">Yesterday</SelectItem>
                <SelectItem value="last-7-days">Last 7 Days</SelectItem>
                <SelectItem value="last-30-days">Last 30 Days</SelectItem>
                <SelectItem value="last-90-days">Last 90 Days</SelectItem>
                <SelectItem value="custom">Custom Range</SelectItem>
              </SelectContent>
            </Select>
            <Select value={comparison} onValueChange={setComparison}>
              <SelectTrigger className="w-44">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="previous-period">Previous Period</SelectItem>
                <SelectItem value="previous-year">Previous Year</SelectItem>
                <SelectItem value="no-comparison">No Comparison</SelectItem>
              </SelectContent>
            </Select>
            <Button variant="outline" size="sm" onClick={handleRefresh}>
              <RefreshCw className={`h-4 w-4 ${isRefreshing ? 'animate-spin' : ''}`} />
            </Button>
            <Button variant="outline" size="sm">
              <Download className="h-4 w-4 mr-2" />
              Export
            </Button>
          </div>
        </div>

        {/* Metrics Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {analyticsMetrics.map((metric, index) => {
            const Icon = metric.icon
            const isPositive = metric.change >= 0

            return (
              <Card key={index}>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">{metric.title}</CardTitle>
                  <div className={`p-2 rounded-lg ${metric.bgColor}`}>
                    <Icon className={`h-4 w-4 ${metric.color}`} />
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{metric.value}</div>
                  <div className="flex items-center justify-between mt-2">
                    <div className="flex items-center text-xs">
                      {isPositive ? (
                        <ArrowUpRight className="h-4 w-4 text-green-600 mr-1" />
                      ) : (
                        <ArrowDownRight className="h-4 w-4 text-red-600 mr-1" />
                      )}
                      <span className={isPositive ? 'text-green-600' : 'text-red-600'}>
                        {Math.abs(metric.change)}%
                      </span>
                    </div>
                    <div className="h-8 w-20">
                      <div className="flex items-end space-x-1 h-full">
                        {metric.sparkline.map((value, i) => (
                          <div
                            key={i}
                            className="flex-1 bg-gray-300 dark:bg-gray-600 rounded-t"
                            style={{ height: `${(value / 60) * 100}%` }}
                          />
                        ))}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )
          })}
        </div>

        {/* Main Content */}
        <Tabs defaultValue="traffic" className="space-y-6">
          <TabsList>
            <TabsTrigger value="traffic">Traffic</TabsTrigger>
            <TabsTrigger value="engagement">Engagement</TabsTrigger>
            <TabsTrigger value="conversions">Conversions</TabsTrigger>
            <TabsTrigger value="behavior">Behavior</TabsTrigger>
          </TabsList>

          <TabsContent value="traffic" className="space-y-6">
            <TrafficChart />
            
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Traffic Sources */}
              <Card>
                <CardHeader>
                  <CardTitle>Traffic Sources</CardTitle>
                  <CardDescription>Where your visitors come from</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {trafficSources.map((source, index) => (
                    <div key={index} className="space-y-2">
                      <div className="flex justify-between items-center">
                        <span className="text-sm font-medium">{source.source}</span>
                        <div className="flex items-center space-x-2">
                          <span className="text-sm text-gray-500">
                            {source.sessions.toLocaleString()}
                          </span>
                          {source.trend === 'up' ? (
                            <TrendingUp className="h-3 w-3 text-green-500" />
                          ) : (
                            <TrendingDown className="h-3 w-3 text-red-500" />
                          )}
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Progress value={source.percentage} className="flex-1" />
                        <span className="text-xs text-gray-500 w-10">
                          {source.percentage}%
                        </span>
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>

              {/* Device Statistics */}
              <Card>
                <CardHeader>
                  <CardTitle>Device Statistics</CardTitle>
                  <CardDescription>User devices breakdown</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {deviceStats.map((device, index) => {
                    const Icon = device.icon
                    return (
                      <div key={index} className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <div className="p-2 bg-gray-100 dark:bg-gray-800 rounded-lg">
                            <Icon className="h-4 w-4 text-gray-600" />
                          </div>
                          <div>
                            <p className="font-medium">{device.device}</p>
                            <p className="text-xs text-gray-500">
                              {device.users.toLocaleString()} users
                            </p>
                          </div>
                        </div>
                        <Badge variant="outline">{device.percentage}%</Badge>
                      </div>
                    )
                  })}
                </CardContent>
              </Card>

              {/* Top Pages */}
              <Card>
                <CardHeader>
                  <CardTitle>Top Pages</CardTitle>
                  <CardDescription>Most visited pages</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {topPages.map((page, index) => (
                      <div key={index} className="flex items-center justify-between">
                        <div className="flex-1">
                          <p className="text-sm font-medium">{page.path}</p>
                          <p className="text-xs text-gray-500">
                            {page.views.toLocaleString()} views
                          </p>
                        </div>
                        <div className="text-right">
                          <div className="flex items-center space-x-1">
                            {page.change >= 0 ? (
                              <TrendingUp className="h-3 w-3 text-green-500" />
                            ) : (
                              <TrendingDown className="h-3 w-3 text-red-500" />
                            )}
                            <span className="text-xs font-medium">
                              {Math.abs(page.change)}%
                            </span>
                          </div>
                          <p className="text-xs text-gray-500">
                            {page.bounceRate}% bounce
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="engagement" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>User Engagement Metrics</CardTitle>
                  <CardDescription>How users interact with your site</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="h-64 bg-gray-100 dark:bg-gray-800 rounded-lg flex items-center justify-center">
                    <div className="text-center">
                      <Activity className="h-12 w-12 text-gray-400 mx-auto mb-2" />
                      <p className="text-sm text-gray-500">Engagement Chart</p>
                      <p className="text-xs text-gray-400 mt-1">Chart.js integration pending</p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Session Analysis</CardTitle>
                  <CardDescription>Session duration and page views</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="h-64 bg-gray-100 dark:bg-gray-800 rounded-lg flex items-center justify-center">
                    <div className="text-center">
                      <Clock className="h-12 w-12 text-gray-400 mx-auto mb-2" />
                      <p className="text-sm text-gray-500">Session Chart</p>
                      <p className="text-xs text-gray-400 mt-1">Chart.js integration pending</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="conversions" className="space-y-6">
            <ConversionFunnel />
            
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Goal Completions</CardTitle>
                  <CardDescription>Conversion goals achievement</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {[
                      { goal: 'Sign Up', completions: 1284, rate: 4.2, target: 1500 },
                      { goal: 'Purchase', completions: 423, rate: 1.4, target: 500 },
                      { goal: 'Newsletter', completions: 892, rate: 2.9, target: 1000 },
                      { goal: 'Contact Form', completions: 234, rate: 0.8, target: 300 }
                    ].map((goal, index) => (
                      <div key={index} className="space-y-2">
                        <div className="flex justify-between items-center">
                          <span className="text-sm font-medium">{goal.goal}</span>
                          <div className="text-right">
                            <span className="text-sm font-bold">{goal.completions}</span>
                            <span className="text-xs text-gray-500"> / {goal.target}</span>
                          </div>
                        </div>
                        <Progress value={(goal.completions / goal.target) * 100} />
                        <p className="text-xs text-gray-500">{goal.rate}% conversion rate</p>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>E-commerce Metrics</CardTitle>
                  <CardDescription>Online store performance</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex justify-between items-center p-3 border rounded-lg">
                      <span className="text-sm">Revenue</span>
                      <span className="font-bold">$124,592</span>
                    </div>
                    <div className="flex justify-between items-center p-3 border rounded-lg">
                      <span className="text-sm">Transactions</span>
                      <span className="font-bold">423</span>
                    </div>
                    <div className="flex justify-between items-center p-3 border rounded-lg">
                      <span className="text-sm">Avg. Order Value</span>
                      <span className="font-bold">$294.55</span>
                    </div>
                    <div className="flex justify-between items-center p-3 border rounded-lg">
                      <span className="text-sm">Cart Abandonment</span>
                      <span className="font-bold text-red-600">68.3%</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="behavior" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>User Flow</CardTitle>
                <CardDescription>How users navigate through your site</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-80 bg-gray-100 dark:bg-gray-800 rounded-lg flex items-center justify-center">
                  <div className="text-center">
                    <BarChart3 className="h-12 w-12 text-gray-400 mx-auto mb-2" />
                    <p className="text-sm text-gray-500">User Flow Visualization</p>
                    <p className="text-xs text-gray-400 mt-1">Sankey diagram pending</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </MainLayout>
  )
}