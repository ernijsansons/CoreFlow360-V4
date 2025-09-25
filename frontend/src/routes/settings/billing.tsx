import * as React from 'react'
import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { MainLayout } from '@/layouts/main-layout'
import { BillingForm } from '@/components/settings/BillingForm'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  CreditCard,
  Download,
  FileText,
  TrendingUp,
  AlertCircle,
  CheckCircle2,
  Calendar,
  DollarSign
} from 'lucide-react'
import { useUIStore } from '@/stores'

export const Route = createFileRoute('/settings/billing')({
  component: BillingPage,
  beforeLoad: () => {
    useUIStore.getState().setBreadcrumbs([
      { label: 'Dashboard', href: '/' },
      { label: 'Settings', href: '/settings' },
      { label: 'Billing' }
    ])
  },
})

function BillingPage() {
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = React.useState('overview')

  const currentPlan = {
    name: 'Professional',
    price: 99,
    billing: 'monthly',
    features: [
      'Unlimited users',
      'Advanced analytics',
      'API access',
      '24/7 support',
      'Custom integrations'
    ],
    usage: {
      users: { current: 12, limit: 'Unlimited' },
      storage: { current: 4.2, limit: 10, unit: 'GB' },
      apiCalls: { current: 45000, limit: 100000 },
    }
  }

  const invoices = [
    { id: 'INV-2024-001', date: '2024-02-01', amount: 99, status: 'paid' },
    { id: 'INV-2024-002', date: '2024-01-01', amount: 99, status: 'paid' },
    { id: 'INV-2023-012', date: '2023-12-01', amount: 99, status: 'paid' },
    { id: 'INV-2023-011', date: '2023-11-01', amount: 99, status: 'paid' },
  ]

  const paymentMethods = [
    { id: 1, type: 'Visa', last4: '4242', expiry: '12/25', isDefault: true },
    { id: 2, type: 'Mastercard', last4: '5555', expiry: '08/26', isDefault: false },
  ]

  return (
    <MainLayout>
      <div className="max-w-4xl mx-auto space-y-8">
        <div className="flex justify-between items-start">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
              Billing & Plans
            </h1>
            <p className="mt-2 text-gray-600 dark:text-gray-400">
              Manage your subscription, payment methods, and invoices
            </p>
          </div>
          <Button variant="outline" onClick={() => navigate({ to: '/settings' })}>
            Back to Settings
          </Button>
        </div>

        <Alert>
          <CheckCircle2 className="h-4 w-4" />
          <AlertTitle>Subscription Active</AlertTitle>
          <AlertDescription>
            Your subscription renews on February 1, 2024. You'll be charged $99.00.
          </AlertDescription>
        </Alert>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="plans">Plans</TabsTrigger>
            <TabsTrigger value="payment">Payment</TabsTrigger>
            <TabsTrigger value="invoices">Invoices</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6">
            <Card>
              <CardHeader>
                <div className="flex justify-between items-start">
                  <div>
                    <CardTitle>Current Plan</CardTitle>
                    <CardDescription>
                      {currentPlan.name} - ${currentPlan.price}/{currentPlan.billing}
                    </CardDescription>
                  </div>
                  <Badge variant="success">Active</Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="space-y-2">
                    <p className="text-sm text-gray-500">Users</p>
                    <p className="text-2xl font-bold">
                      {currentPlan.usage.users.current}
                    </p>
                    <p className="text-xs text-gray-500">
                      of {currentPlan.usage.users.limit}
                    </p>
                  </div>
                  <div className="space-y-2">
                    <p className="text-sm text-gray-500">Storage</p>
                    <p className="text-2xl font-bold">
                      {currentPlan.usage.storage.current} {currentPlan.usage.storage.unit}
                    </p>
                    <p className="text-xs text-gray-500">
                      of {currentPlan.usage.storage.limit} {currentPlan.usage.storage.unit}
                    </p>
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div 
                        className="bg-blue-600 h-2 rounded-full" 
                        style={{ width: `${(currentPlan.usage.storage.current / currentPlan.usage.storage.limit) * 100}%` }}
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <p className="text-sm text-gray-500">API Calls</p>
                    <p className="text-2xl font-bold">
                      {(currentPlan.usage.apiCalls.current / 1000).toFixed(0)}k
                    </p>
                    <p className="text-xs text-gray-500">
                      of {currentPlan.usage.apiCalls.limit / 1000}k
                    </p>
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div 
                        className="bg-green-600 h-2 rounded-full" 
                        style={{ width: `${(currentPlan.usage.apiCalls.current / currentPlan.usage.apiCalls.limit) * 100}%` }}
                      />
                    </div>
                  </div>
                </div>

                <div className="border-t pt-4">
                  <h4 className="font-medium mb-3">Plan Features</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {currentPlan.features.map((feature, index) => (
                      <div key={index} className="flex items-center space-x-2">
                        <CheckCircle2 className="h-4 w-4 text-green-500" />
                        <span className="text-sm">{feature}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="flex justify-between pt-4">
                  <Button variant="outline">
                    <TrendingUp className="h-4 w-4 mr-2" />
                    Upgrade Plan
                  </Button>
                  <Button variant="ghost" className="text-red-600">
                    Cancel Subscription
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="plans" className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Starter</CardTitle>
                  <CardDescription>
                    <span className="text-2xl font-bold">$29</span>
                    <span className="text-gray-500">/month</span>
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-2">
                    <li className="flex items-center space-x-2">
                      <CheckCircle2 className="h-4 w-4 text-green-500" />
                      <span className="text-sm">Up to 5 users</span>
                    </li>
                    <li className="flex items-center space-x-2">
                      <CheckCircle2 className="h-4 w-4 text-green-500" />
                      <span className="text-sm">2 GB storage</span>
                    </li>
                    <li className="flex items-center space-x-2">
                      <CheckCircle2 className="h-4 w-4 text-green-500" />
                      <span className="text-sm">Basic support</span>
                    </li>
                  </ul>
                  <Button variant="outline" className="w-full mt-6">
                    Downgrade
                  </Button>
                </CardContent>
              </Card>

              <Card className="border-blue-500">
                <CardHeader>
                  <div className="flex justify-between items-center">
                    <CardTitle>Professional</CardTitle>
                    <Badge>Current</Badge>
                  </div>
                  <CardDescription>
                    <span className="text-2xl font-bold">$99</span>
                    <span className="text-gray-500">/month</span>
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-2">
                    <li className="flex items-center space-x-2">
                      <CheckCircle2 className="h-4 w-4 text-green-500" />
                      <span className="text-sm">Unlimited users</span>
                    </li>
                    <li className="flex items-center space-x-2">
                      <CheckCircle2 className="h-4 w-4 text-green-500" />
                      <span className="text-sm">10 GB storage</span>
                    </li>
                    <li className="flex items-center space-x-2">
                      <CheckCircle2 className="h-4 w-4 text-green-500" />
                      <span className="text-sm">Priority support</span>
                    </li>
                    <li className="flex items-center space-x-2">
                      <CheckCircle2 className="h-4 w-4 text-green-500" />
                      <span className="text-sm">API access</span>
                    </li>
                  </ul>
                  <Button className="w-full mt-6" disabled>
                    Current Plan
                  </Button>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Enterprise</CardTitle>
                  <CardDescription>
                    <span className="text-2xl font-bold">Custom</span>
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-2">
                    <li className="flex items-center space-x-2">
                      <CheckCircle2 className="h-4 w-4 text-green-500" />
                      <span className="text-sm">Unlimited everything</span>
                    </li>
                    <li className="flex items-center space-x-2">
                      <CheckCircle2 className="h-4 w-4 text-green-500" />
                      <span className="text-sm">Dedicated support</span>
                    </li>
                    <li className="flex items-center space-x-2">
                      <CheckCircle2 className="h-4 w-4 text-green-500" />
                      <span className="text-sm">SLA guarantee</span>
                    </li>
                    <li className="flex items-center space-x-2">
                      <CheckCircle2 className="h-4 w-4 text-green-500" />
                      <span className="text-sm">Custom integrations</span>
                    </li>
                  </ul>
                  <Button variant="outline" className="w-full mt-6">
                    Contact Sales
                  </Button>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="payment" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Payment Methods</CardTitle>
                <CardDescription>
                  Manage your payment methods and billing details
                </CardDescription>
              </CardHeader>
              <CardContent>
                <BillingForm />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Saved Payment Methods</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {paymentMethods.map((method) => (
                  <div key={method.id} className="flex items-center justify-between p-4 border rounded-lg">
                    <div className="flex items-center space-x-4">
                      <CreditCard className="h-5 w-5 text-gray-400" />
                      <div>
                        <p className="font-medium">
                          {method.type} •••• {method.last4}
                        </p>
                        <p className="text-sm text-gray-500">Expires {method.expiry}</p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      {method.isDefault && <Badge variant="secondary">Default</Badge>}
                      <Button variant="ghost" size="sm">Remove</Button>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="invoices" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Billing History</CardTitle>
                <CardDescription>
                  Download invoices and receipts for your records
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {invoices.map((invoice) => (
                    <div key={invoice.id} className="flex items-center justify-between p-4 border rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800">
                      <div className="flex items-center space-x-4">
                        <FileText className="h-5 w-5 text-gray-400" />
                        <div>
                          <p className="font-medium">{invoice.id}</p>
                          <p className="text-sm text-gray-500">
                            {new Date(invoice.date).toLocaleDateString('en-US', {
                              month: 'long',
                              day: 'numeric',
                              year: 'numeric'
                            })}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-4">
                        <span className="font-medium">${invoice.amount}</span>
                        <Badge variant={invoice.status === 'paid' ? 'success' : 'secondary'}>
                          {invoice.status}
                        </Badge>
                        <Button variant="ghost" size="sm">
                          <Download className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>

                <Button variant="outline" className="w-full mt-4">
                  View all invoices
                </Button>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Billing Address</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <p className="font-medium">Acme Corporation</p>
                  <p className="text-sm text-gray-600">123 Business Ave</p>
                  <p className="text-sm text-gray-600">Suite 100</p>
                  <p className="text-sm text-gray-600">San Francisco, CA 94105</p>
                  <p className="text-sm text-gray-600">United States</p>
                </div>
                <Button variant="outline" className="mt-4">Edit Address</Button>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </MainLayout>
  )
}