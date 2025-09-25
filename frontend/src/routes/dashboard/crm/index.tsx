import * as React from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { MainLayout } from '@/layouts/main-layout'
import { LeadsTable } from '@/components/dashboard/LeadsTable'
import { PipelineBoard } from '@/components/dashboard/PipelineBoard'
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
import {
  Users,
  UserPlus,
  TrendingUp,
  Target,
  DollarSign,
  Phone,
  Mail,
  Calendar,
  Filter,
  Plus,
  Download,
  ArrowUpRight,
  ArrowDownRight
} from 'lucide-react'
import { useUIStore } from '@/stores'

export const Route = createFileRoute('/dashboard/crm/')({
  component: CRMDashboard,
  beforeLoad: () => {
    useUIStore.getState().setBreadcrumbs([
      { label: 'Dashboard', href: '/dashboard' },
      { label: 'CRM' }
    ])
  },
})

function CRMDashboard() {
  const [activeTab, setActiveTab] = React.useState('pipeline')
  const [timeFilter, setTimeFilter] = React.useState('this-month')

  const crmMetrics = [
    {
      title: 'Total Leads',
      value: '1,284',
      change: 12.5,
      icon: Users,
      color: 'text-blue-600',
      bgColor: 'bg-blue-100 dark:bg-blue-900/20'
    },
    {
      title: 'Qualified Leads',
      value: '423',
      change: 8.2,
      icon: UserPlus,
      color: 'text-green-600',
      bgColor: 'bg-green-100 dark:bg-green-900/20'
    },
    {
      title: 'Conversion Rate',
      value: '32.8%',
      change: -2.4,
      icon: Target,
      color: 'text-purple-600',
      bgColor: 'bg-purple-100 dark:bg-purple-900/20'
    },
    {
      title: 'Pipeline Value',
      value: '$847,293',
      change: 18.7,
      icon: DollarSign,
      color: 'text-orange-600',
      bgColor: 'bg-orange-100 dark:bg-orange-900/20'
    }
  ]

  const recentActivities = [
    { type: 'call', contact: 'John Smith', company: 'Acme Corp', time: '10 minutes ago', outcome: 'Interested' },
    { type: 'email', contact: 'Sarah Johnson', company: 'Tech Solutions', time: '1 hour ago', outcome: 'Follow-up scheduled' },
    { type: 'meeting', contact: 'Mike Davis', company: 'Global Industries', time: '2 hours ago', outcome: 'Proposal sent' },
    { type: 'call', contact: 'Emily Brown', company: 'StartupHub', time: '3 hours ago', outcome: 'Not interested' },
    { type: 'email', contact: 'Robert Wilson', company: 'Enterprise Co', time: '4 hours ago', outcome: 'Demo scheduled' }
  ]

  const topDeals = [
    { name: 'Enterprise Package - Acme Corp', value: '$125,000', stage: 'Negotiation', probability: '80%' },
    { name: 'Annual License - Tech Solutions', value: '$89,000', stage: 'Proposal', probability: '60%' },
    { name: 'Custom Integration - Global Industries', value: '$67,500', stage: 'Qualification', probability: '40%' },
    { name: 'Premium Plan - StartupHub', value: '$45,000', stage: 'Demo', probability: '50%' },
    { name: 'Professional Services - Enterprise Co', value: '$38,000', stage: 'Negotiation', probability: '70%' }
  ]

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex justify-between items-start">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
              CRM Dashboard
            </h1>
            <p className="mt-2 text-gray-600 dark:text-gray-400">
              Manage your leads, deals, and customer relationships
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <Select value={timeFilter} onValueChange={setTimeFilter}>
              <SelectTrigger className="w-40">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="today">Today</SelectItem>
                <SelectItem value="this-week">This Week</SelectItem>
                <SelectItem value="this-month">This Month</SelectItem>
                <SelectItem value="this-quarter">This Quarter</SelectItem>
                <SelectItem value="this-year">This Year</SelectItem>
              </SelectContent>
            </Select>
            <Button>
              <Plus className="h-4 w-4 mr-2" />
              Add Lead
            </Button>
            <Button variant="outline">
              <Download className="h-4 w-4 mr-2" />
              Export
            </Button>
          </div>
        </div>

        {/* Metrics Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {crmMetrics.map((metric, index) => {
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
                  <div className="flex items-center text-xs mt-2">
                    {isPositive ? (
                      <ArrowUpRight className="h-4 w-4 text-green-600 mr-1" />
                    ) : (
                      <ArrowDownRight className="h-4 w-4 text-red-600 mr-1" />
                    )}
                    <span className={isPositive ? 'text-green-600' : 'text-red-600'}>
                      {Math.abs(metric.change)}%
                    </span>
                    <span className="text-gray-500 ml-1">from last period</span>
                  </div>
                </CardContent>
              </Card>
            )
          })}
        </div>

        {/* Main Content */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList>
            <TabsTrigger value="pipeline">Pipeline</TabsTrigger>
            <TabsTrigger value="leads">Leads</TabsTrigger>
            <TabsTrigger value="activities">Activities</TabsTrigger>
            <TabsTrigger value="analytics">Analytics</TabsTrigger>
          </TabsList>

          <TabsContent value="pipeline" className="space-y-6">
            <PipelineBoard />
            
            {/* Top Deals */}
            <Card>
              <CardHeader>
                <CardTitle>Top Deals</CardTitle>
                <CardDescription>Highest value opportunities in your pipeline</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {topDeals.map((deal, index) => (
                    <div key={index} className="flex items-center justify-between p-3 border rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800">
                      <div className="flex-1">
                        <p className="font-medium">{deal.name}</p>
                        <div className="flex items-center space-x-4 mt-1">
                          <span className="text-sm text-gray-500">Stage: {deal.stage}</span>
                          <Badge variant="outline" className="text-xs">
                            {deal.probability} probability
                          </Badge>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="font-bold text-lg">{deal.value}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="leads" className="space-y-6">
            <LeadsTable />
          </TabsContent>

          <TabsContent value="activities" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Recent Activities */}
              <Card>
                <CardHeader>
                  <CardTitle>Recent Activities</CardTitle>
                  <CardDescription>Latest interactions with leads and customers</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {recentActivities.map((activity, index) => (
                      <div key={index} className="flex items-start space-x-3">
                        <div className={`p-2 rounded-full ${
                          activity.type === 'call' ? 'bg-blue-100 dark:bg-blue-900/20' :
                          activity.type === 'email' ? 'bg-green-100 dark:bg-green-900/20' :
                          'bg-purple-100 dark:bg-purple-900/20'
                        }`}>
                          {activity.type === 'call' && <Phone className="h-4 w-4 text-blue-600" />}
                          {activity.type === 'email' && <Mail className="h-4 w-4 text-green-600" />}
                          {activity.type === 'meeting' && <Calendar className="h-4 w-4 text-purple-600" />}
                        </div>
                        <div className="flex-1">
                          <p className="text-sm font-medium">
                            {activity.type.charAt(0).toUpperCase() + activity.type.slice(1)} with {activity.contact}
                          </p>
                          <p className="text-xs text-gray-500">{activity.company}</p>
                          <div className="flex items-center space-x-2 mt-1">
                            <span className="text-xs text-gray-400">{activity.time}</span>
                            <Badge 
                              variant={activity.outcome.includes('Not') ? 'destructive' : 'success'}
                              className="text-xs"
                            >
                              {activity.outcome}
                            </Badge>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                  <Button variant="outline" className="w-full mt-4" size="sm">
                    View all activities
                  </Button>
                </CardContent>
              </Card>

              {/* Activity Stats */}
              <Card>
                <CardHeader>
                  <CardTitle>Activity Statistics</CardTitle>
                  <CardDescription>Your team's performance this month</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-6">
                    <div>
                      <div className="flex justify-between mb-2">
                        <span className="text-sm text-gray-500">Calls Made</span>
                        <span className="text-sm font-medium">284 / 300</span>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-2">
                        <div className="bg-blue-600 h-2 rounded-full" style={{ width: '94.7%' }} />
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between mb-2">
                        <span className="text-sm text-gray-500">Emails Sent</span>
                        <span className="text-sm font-medium">512 / 500</span>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-2">
                        <div className="bg-green-600 h-2 rounded-full" style={{ width: '102.4%' }} />
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between mb-2">
                        <span className="text-sm text-gray-500">Meetings Held</span>
                        <span className="text-sm font-medium">47 / 60</span>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-2">
                        <div className="bg-purple-600 h-2 rounded-full" style={{ width: '78.3%' }} />
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between mb-2">
                        <span className="text-sm text-gray-500">Demos Given</span>
                        <span className="text-sm font-medium">23 / 25</span>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-2">
                        <div className="bg-orange-600 h-2 rounded-full" style={{ width: '92%' }} />
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="analytics" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Lead Sources</CardTitle>
                  <CardDescription>Where your leads are coming from</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="h-64 bg-gray-100 dark:bg-gray-800 rounded-lg flex items-center justify-center">
                    <p className="text-sm text-gray-500">Lead Source Chart Placeholder</p>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Conversion Funnel</CardTitle>
                  <CardDescription>Lead progression through stages</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="h-64 bg-gray-100 dark:bg-gray-800 rounded-lg flex items-center justify-center">
                    <p className="text-sm text-gray-500">Conversion Funnel Chart Placeholder</p>
                  </div>
                </CardContent>
              </Card>
            </div>

            <Card>
              <CardHeader>
                <CardTitle>Sales Forecast</CardTitle>
                <CardDescription>Projected revenue for the next quarter</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-64 bg-gray-100 dark:bg-gray-800 rounded-lg flex items-center justify-center">
                  <p className="text-sm text-gray-500">Sales Forecast Chart Placeholder</p>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </MainLayout>
  )
}