import * as React from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { MainLayout } from '@/layouts/main-layout'
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
import { Alert, AlertDescription } from '@/components/ui/alert'
import {
  Users,
  DollarSign,
  TrendingUp,
  TrendingDown,
  ShoppingCart,
  Activity,
  CreditCard,
  Package,
  ArrowUpRight,
  ArrowDownRight,
  BarChart3,
  Calendar,
  Download,
  RefreshCw,
  Bell
} from 'lucide-react'
import { useUIStore } from '@/stores'

export const Route = createFileRoute('/dashboard/')({
  component: MainDashboard,
  beforeLoad: () => {
    useUIStore.getState().setBreadcrumbs([
      { label: 'Dashboard' }
    ])
  },
})

function MainDashboard() {
  const [timeRange, setTimeRange] = React.useState('7d')
  const [isRefreshing, setIsRefreshing] = React.useState(false)

  const handleRefresh = () => {
    setIsRefreshing(true)
    setTimeout(() => setIsRefreshing(false), 2000)
  }

  const kpiData = [
    {
      title: 'Total Users',
      value: '12,847',
      change: 12.5,
      changeLabel: 'from last month',
      icon: Users,
      color: 'text-blue-600',
      bgColor: 'bg-blue-100 dark:bg-blue-900/20'
    },
    {
      title: 'Total Revenue',
      value: '$248,592',
      change: 18.3,
      changeLabel: 'from last month',
      icon: DollarSign,
      color: 'text-green-600',
      bgColor: 'bg-green-100 dark:bg-green-900/20'
    },
    {
      title: 'Churn Rate',
      value: '2.4%',
      change: -0.8,
      changeLabel: 'from last month',
      icon: TrendingDown,
      color: 'text-red-600',
      bgColor: 'bg-red-100 dark:bg-red-900/20'
    },
    {
      title: 'Active Projects',
      value: '847',
      change: 23.1,
      changeLabel: 'from last month',
      icon: Package,
      color: 'text-purple-600',
      bgColor: 'bg-purple-100 dark:bg-purple-900/20'
    }
  ]

  const recentActivities = [
    { type: 'user', message: 'New user registration', user: 'John Doe', time: '2 minutes ago' },
    { type: 'payment', message: 'Payment received', user: 'Acme Corp', amount: '$999', time: '15 minutes ago' },
    { type: 'project', message: 'Project created', user: 'Sarah Smith', time: '1 hour ago' },
    { type: 'alert', message: 'System update completed', time: '2 hours ago' },
    { type: 'user', message: 'User upgraded plan', user: 'Tech Solutions', time: '3 hours ago' }
  ]

  const upcomingTasks = [
    { title: 'Review Q1 Reports', due: 'Today', priority: 'high' },
    { title: 'Team Meeting', due: 'Tomorrow', priority: 'medium' },
    { title: 'Client Presentation', due: 'Feb 5', priority: 'high' },
    { title: 'Update Documentation', due: 'Feb 7', priority: 'low' },
    { title: 'Security Audit', due: 'Feb 10', priority: 'medium' }
  ]

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex justify-between items-start">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
              Dashboard Overview
            </h1>
            <p className="mt-2 text-gray-600 dark:text-gray-400">
              Welcome back! Here's what's happening with your business today.
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <Select value={timeRange} onValueChange={setTimeRange}>
              <SelectTrigger className="w-32">
                <Calendar className="h-4 w-4 mr-2" />
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="24h">Last 24 hours</SelectItem>
                <SelectItem value="7d">Last 7 days</SelectItem>
                <SelectItem value="30d">Last 30 days</SelectItem>
                <SelectItem value="90d">Last 90 days</SelectItem>
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

        {/* Alert */}
        <Alert className="bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800">
          <Bell className="h-4 w-4" />
          <AlertDescription>
            <strong>System Update:</strong> New features have been added to the analytics dashboard. 
            <Button variant="link" className="px-1 h-auto">
              Learn more →
            </Button>
          </AlertDescription>
        </Alert>

        {/* KPI Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {kpiData.map((kpi, index) => {
            const Icon = kpi.icon
            const isPositive = kpi.change >= 0

            return (
              <Card key={index} className="hover:shadow-lg transition-shadow">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">{kpi.title}</CardTitle>
                  <div className={`p-2 rounded-lg ${kpi.bgColor}`}>
                    <Icon className={`h-4 w-4 ${kpi.color}`} />
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{kpi.value}</div>
                  <div className="flex items-center text-xs mt-2">
                    {isPositive ? (
                      <ArrowUpRight className="h-4 w-4 text-green-600 mr-1" />
                    ) : (
                      <ArrowDownRight className="h-4 w-4 text-red-600 mr-1" />
                    )}
                    <span className={isPositive ? 'text-green-600' : 'text-red-600'}>
                      {Math.abs(kpi.change)}%
                    </span>
                    <span className="text-gray-500 ml-1">{kpi.changeLabel}</span>
                  </div>
                </CardContent>
              </Card>
            )
          })}
        </div>

        {/* Main Content Tabs */}
        <Tabs defaultValue="overview" className="space-y-6">
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="analytics">Analytics</TabsTrigger>
            <TabsTrigger value="reports">Reports</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Revenue Chart Placeholder */}
              <Card>
                <CardHeader>
                  <CardTitle>Revenue Overview</CardTitle>
                  <CardDescription>Monthly revenue for the last 6 months</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="h-64 bg-gray-100 dark:bg-gray-800 rounded-lg flex items-center justify-center">
                    <div className="text-center">
                      <BarChart3 className="h-12 w-12 text-gray-400 mx-auto mb-2" />
                      <p className="text-sm text-gray-500">Revenue Chart</p>
                      <p className="text-xs text-gray-400 mt-1">Chart.js integration pending</p>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4 mt-4">
                    <div>
                      <p className="text-sm text-gray-500">This Month</p>
                      <p className="text-lg font-bold">$48,592</p>
                      <p className="text-xs text-green-600">+18.3% from last month</p>
                    </div>
                    <div>
                      <p className="text-sm text-gray-500">Last Month</p>
                      <p className="text-lg font-bold">$41,054</p>
                      <p className="text-xs text-gray-500">+12.1% from previous</p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* User Growth Chart Placeholder */}
              <Card>
                <CardHeader>
                  <CardTitle>User Growth</CardTitle>
                  <CardDescription>New vs returning users over time</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="h-64 bg-gray-100 dark:bg-gray-800 rounded-lg flex items-center justify-center">
                    <div className="text-center">
                      <Activity className="h-12 w-12 text-gray-400 mx-auto mb-2" />
                      <p className="text-sm text-gray-500">User Growth Chart</p>
                      <p className="text-xs text-gray-400 mt-1">Chart.js integration pending</p>
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-4 mt-4">
                    <div>
                      <p className="text-sm text-gray-500">New Users</p>
                      <p className="text-lg font-bold">1,847</p>
                    </div>
                    <div>
                      <p className="text-sm text-gray-500">Returning</p>
                      <p className="text-lg font-bold">11,000</p>
                    </div>
                    <div>
                      <p className="text-sm text-gray-500">Churn</p>
                      <p className="text-lg font-bold">2.4%</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Recent Activity */}
              <Card className="lg:col-span-2">
                <CardHeader>
                  <CardTitle>Recent Activity</CardTitle>
                  <CardDescription>Latest events in your system</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {recentActivities.map((activity, index) => (
                      <div key={index} className="flex items-start space-x-3">
                        <div className={`p-2 rounded-full ${
                          activity.type === 'user' ? 'bg-blue-100 dark:bg-blue-900/20' :
                          activity.type === 'payment' ? 'bg-green-100 dark:bg-green-900/20' :
                          activity.type === 'project' ? 'bg-purple-100 dark:bg-purple-900/20' :
                          'bg-yellow-100 dark:bg-yellow-900/20'
                        }`}>
                          {activity.type === 'user' && <Users className="h-4 w-4 text-blue-600" />}
                          {activity.type === 'payment' && <CreditCard className="h-4 w-4 text-green-600" />}
                          {activity.type === 'project' && <Package className="h-4 w-4 text-purple-600" />}
                          {activity.type === 'alert' && <Bell className="h-4 w-4 text-yellow-600" />}
                        </div>
                        <div className="flex-1">
                          <p className="text-sm font-medium">{activity.message}</p>
                          <div className="flex items-center space-x-2 mt-1">
                            {activity.user && <span className="text-xs text-gray-500">{activity.user}</span>}
                            {activity.amount && <Badge variant="success" className="text-xs">{activity.amount}</Badge>}
                            <span className="text-xs text-gray-400">{activity.time}</span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                  <Button variant="outline" className="w-full mt-4" size="sm">
                    View all activity
                  </Button>
                </CardContent>
              </Card>

              {/* Upcoming Tasks */}
              <Card>
                <CardHeader>
                  <CardTitle>Upcoming Tasks</CardTitle>
                  <CardDescription>Tasks that need attention</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {upcomingTasks.map((task, index) => (
                      <div key={index} className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <div className={`w-2 h-2 rounded-full ${
                            task.priority === 'high' ? 'bg-red-500' :
                            task.priority === 'medium' ? 'bg-yellow-500' :
                            'bg-green-500'
                          }`} />
                          <span className="text-sm">{task.title}</span>
                        </div>
                        <Badge variant="outline" className="text-xs">
                          {task.due}
                        </Badge>
                      </div>
                    ))}
                  </div>
                  <Button variant="outline" className="w-full mt-4" size="sm">
                    View all tasks
                  </Button>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="analytics" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Conversion Rate</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="h-32 bg-gray-100 dark:bg-gray-800 rounded-lg flex items-center justify-center">
                    <p className="text-2xl font-bold">4.2%</p>
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle>Avg. Session Duration</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="h-32 bg-gray-100 dark:bg-gray-800 rounded-lg flex items-center justify-center">
                    <p className="text-2xl font-bold">3m 42s</p>
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle>Bounce Rate</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="h-32 bg-gray-100 dark:bg-gray-800 rounded-lg flex items-center justify-center">
                    <p className="text-2xl font-bold">32.8%</p>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="reports" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Generated Reports</CardTitle>
                <CardDescription>Download your business reports</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {['Monthly Revenue Report', 'User Analytics Report', 'Performance Metrics', 'Sales Forecast'].map((report) => (
                    <div key={report} className="flex items-center justify-between p-3 border rounded-lg">
                      <span className="text-sm">{report}</span>
                      <Button variant="ghost" size="sm">
                        <Download className="h-4 w-4" />
                      </Button>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </MainLayout>
  )
}