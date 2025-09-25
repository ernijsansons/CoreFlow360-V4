import * as React from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { MainLayout } from '@/layouts/main-layout'
import { FinancialMetrics } from '@/components/finance/FinancialMetrics'
import { RevenueChart } from '@/components/finance/RevenueChart'
import { InvoicesTable } from '@/components/finance/InvoicesTable'
import { PaymentsHistory } from '@/components/finance/PaymentsHistory'
import { SubscriptionCard } from '@/components/finance/SubscriptionCard'
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
import {
  Download,
  FileText,
  TrendingUp,
  DollarSign,
  CreditCard,
  Calendar
} from 'lucide-react'
import { useUIStore } from '@/stores'

export const Route = createFileRoute('/finance/')({
  component: FinanceDashboard,
  beforeLoad: () => {
    useUIStore.getState().setBreadcrumbs([
      { label: 'Dashboard', href: '/' },
      { label: 'Finance' }
    ])
  },
})

function FinanceDashboard() {
  const [timeRange, setTimeRange] = React.useState('30d')
  const [activeTab, setActiveTab] = React.useState('overview')

  return (
    <MainLayout>
      <div className="space-y-8">
        <div className="flex justify-between items-start">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
              Finance Dashboard
            </h1>
            <p className="mt-2 text-gray-600 dark:text-gray-400">
              Track revenue, manage invoices, and monitor financial performance
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <Select value={timeRange} onValueChange={setTimeRange}>
              <SelectTrigger className="w-32">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="7d">Last 7 days</SelectItem>
                <SelectItem value="30d">Last 30 days</SelectItem>
                <SelectItem value="90d">Last 90 days</SelectItem>
                <SelectItem value="12m">Last 12 months</SelectItem>
              </SelectContent>
            </Select>
            <Button variant="outline" size="sm">
              <Download className="h-4 w-4 mr-2" />
              Export
            </Button>
          </div>
        </div>

        <FinancialMetrics timeRange={timeRange} />

        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-5">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="revenue">Revenue</TabsTrigger>
            <TabsTrigger value="invoices">Invoices</TabsTrigger>
            <TabsTrigger value="payments">Payments</TabsTrigger>
            <TabsTrigger value="subscriptions">Subscriptions</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <RevenueChart />
              <Card>
                <CardHeader>
                  <CardTitle>Expense Breakdown</CardTitle>
                  <CardDescription>Monthly operational expenses</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex justify-between items-center">
                      <div className="flex items-center space-x-2">
                        <div className="w-3 h-3 bg-blue-500 rounded-full" />
                        <span className="text-sm">Infrastructure</span>
                      </div>
                      <span className="font-medium">$12,450</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <div className="flex items-center space-x-2">
                        <div className="w-3 h-3 bg-green-500 rounded-full" />
                        <span className="text-sm">Marketing</span>
                      </div>
                      <span className="font-medium">$8,320</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <div className="flex items-center space-x-2">
                        <div className="w-3 h-3 bg-yellow-500 rounded-full" />
                        <span className="text-sm">Salaries</span>
                      </div>
                      <span className="font-medium">$45,000</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <div className="flex items-center space-x-2">
                        <div className="w-3 h-3 bg-purple-500 rounded-full" />
                        <span className="text-sm">Operations</span>
                      </div>
                      <span className="font-medium">$6,780</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <div className="flex items-center space-x-2">
                        <div className="w-3 h-3 bg-red-500 rounded-full" />
                        <span className="text-sm">Other</span>
                      </div>
                      <span className="font-medium">$3,200</span>
                    </div>
                    <div className="pt-4 border-t">
                      <div className="flex justify-between items-center">
                        <span className="font-medium">Total Expenses</span>
                        <span className="text-xl font-bold">$75,750</span>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Recent Transactions</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex justify-between items-center">
                    <div>
                      <p className="font-medium text-sm">Invoice #2024-001</p>
                      <p className="text-xs text-gray-500">2 hours ago</p>
                    </div>
                    <span className="text-green-600 font-medium">+$1,250</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <div>
                      <p className="font-medium text-sm">Refund #RF-042</p>
                      <p className="text-xs text-gray-500">5 hours ago</p>
                    </div>
                    <span className="text-red-600 font-medium">-$99</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <div>
                      <p className="font-medium text-sm">Payment #PAY-893</p>
                      <p className="text-xs text-gray-500">1 day ago</p>
                    </div>
                    <span className="text-green-600 font-medium">+$450</span>
                  </div>
                  <Button variant="outline" className="w-full mt-4" size="sm">
                    View all transactions
                  </Button>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Pending Invoices</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex justify-between items-center">
                    <div>
                      <p className="font-medium text-sm">Acme Corp</p>
                      <p className="text-xs text-gray-500">Due in 3 days</p>
                    </div>
                    <span className="font-medium">$2,450</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <div>
                      <p className="font-medium text-sm">TechStart Inc</p>
                      <p className="text-xs text-gray-500">Due in 7 days</p>
                    </div>
                    <span className="font-medium">$899</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <div>
                      <p className="font-medium text-sm">Global Solutions</p>
                      <p className="text-xs text-gray-500">Due in 14 days</p>
                    </div>
                    <span className="font-medium">$1,299</span>
                  </div>
                  <Button variant="outline" className="w-full mt-4" size="sm">
                    View all invoices
                  </Button>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Upcoming Renewals</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex justify-between items-center">
                    <div>
                      <p className="font-medium text-sm">Enterprise Plan</p>
                      <p className="text-xs text-gray-500">Feb 15, 2024</p>
                    </div>
                    <span className="font-medium">$999/mo</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <div>
                      <p className="font-medium text-sm">Pro Plan x3</p>
                      <p className="text-xs text-gray-500">Feb 28, 2024</p>
                    </div>
                    <span className="font-medium">$297/mo</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <div>
                      <p className="font-medium text-sm">Starter Plan x8</p>
                      <p className="text-xs text-gray-500">Mar 5, 2024</p>
                    </div>
                    <span className="font-medium">$232/mo</span>
                  </div>
                  <Button variant="outline" className="w-full mt-4" size="sm">
                    Manage subscriptions
                  </Button>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="revenue" className="space-y-6">
            <RevenueChart detailed={true} />
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Revenue by Product</CardTitle>
                  <CardDescription>Top performing products this month</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div>
                      <div className="flex justify-between mb-1">
                        <span className="text-sm">Enterprise Plan</span>
                        <span className="text-sm font-medium">$45,230</span>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-2">
                        <div className="bg-blue-600 h-2 rounded-full" style={{ width: '65%' }} />
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between mb-1">
                        <span className="text-sm">Professional Plan</span>
                        <span className="text-sm font-medium">$28,900</span>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-2">
                        <div className="bg-green-600 h-2 rounded-full" style={{ width: '42%' }} />
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between mb-1">
                        <span className="text-sm">Starter Plan</span>
                        <span className="text-sm font-medium">$15,670</span>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-2">
                        <div className="bg-yellow-600 h-2 rounded-full" style={{ width: '23%' }} />
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Revenue by Region</CardTitle>
                  <CardDescription>Geographic distribution of revenue</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex justify-between items-center">
                      <div className="flex items-center space-x-2">
                        <span className="text-sm">North America</span>
                      </div>
                      <div className="text-right">
                        <p className="font-medium">$52,340</p>
                        <p className="text-xs text-gray-500">58.2%</p>
                      </div>
                    </div>
                    <div className="flex justify-between items-center">
                      <div className="flex items-center space-x-2">
                        <span className="text-sm">Europe</span>
                      </div>
                      <div className="text-right">
                        <p className="font-medium">$23,450</p>
                        <p className="text-xs text-gray-500">26.1%</p>
                      </div>
                    </div>
                    <div className="flex justify-between items-center">
                      <div className="flex items-center space-x-2">
                        <span className="text-sm">Asia Pacific</span>
                      </div>
                      <div className="text-right">
                        <p className="font-medium">$14,010</p>
                        <p className="text-xs text-gray-500">15.7%</p>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="invoices" className="space-y-6">
            <InvoicesTable />
          </TabsContent>

          <TabsContent value="payments" className="space-y-6">
            <PaymentsHistory />
          </TabsContent>

          <TabsContent value="subscriptions" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <SubscriptionCard
                plan="Enterprise"
                price={999}
                customers={45}
                growth={12.5}
                revenue={44955}
              />
              <SubscriptionCard
                plan="Professional"
                price={99}
                customers={234}
                growth={8.3}
                revenue={23166}
              />
              <SubscriptionCard
                plan="Starter"
                price={29}
                customers={892}
                growth={-2.1}
                revenue={25868}
              />
            </div>

            <Card>
              <CardHeader>
                <CardTitle>Subscription Analytics</CardTitle>
                <CardDescription>Key subscription metrics and trends</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                  <div className="space-y-2">
                    <p className="text-sm text-gray-500">Monthly Recurring Revenue</p>
                    <p className="text-2xl font-bold">$93,989</p>
                    <p className="text-xs text-green-600">+15.3% from last month</p>
                  </div>
                  <div className="space-y-2">
                    <p className="text-sm text-gray-500">Annual Recurring Revenue</p>
                    <p className="text-2xl font-bold">$1.13M</p>
                    <p className="text-xs text-green-600">+42.1% YoY</p>
                  </div>
                  <div className="space-y-2">
                    <p className="text-sm text-gray-500">Customer Lifetime Value</p>
                    <p className="text-2xl font-bold">$2,847</p>
                    <p className="text-xs text-green-600">+8.7% improvement</p>
                  </div>
                  <div className="space-y-2">
                    <p className="text-sm text-gray-500">Churn Rate</p>
                    <p className="text-2xl font-bold">3.2%</p>
                    <p className="text-xs text-red-600">+0.5% from last month</p>
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