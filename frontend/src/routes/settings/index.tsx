import * as React from 'react'
import { createFileRoute, Link, Outlet, useNavigate } from '@tanstack/react-router'
import {
  User,
  CreditCard,
  Shield,
  Building2,
  Users,
  Webhook,
  Key,
  Bell
} from 'lucide-react'
import { MainLayout } from '@/layouts/main-layout'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { useUIStore } from '@/stores'

export const Route = createFileRoute('/settings/')({
  component: SettingsPage,
  beforeLoad: () => {
    // Set breadcrumbs
    useUIStore.getState().setBreadcrumbs([
      { label: 'Dashboard', href: '/' },
      { label: 'Settings' }
    ])
  },
})

function SettingsPage() {
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = React.useState('profile')

  const settingsSections = [
    {
      id: 'profile',
      label: 'Profile',
      icon: User,
      description: 'Manage your personal information and preferences',
      href: '/settings/profile',
    },
    {
      id: 'billing',
      label: 'Billing & Plans',
      icon: CreditCard,
      description: 'Manage subscription, payment methods, and invoices',
      href: '/settings/billing',
      badge: 'Pro',
    },
    {
      id: 'security',
      label: 'Security',
      icon: Shield,
      description: 'Password, two-factor authentication, and sessions',
      href: '/settings/security',
      alert: true,
    },
    {
      id: 'organization',
      label: 'Organization',
      icon: Building2,
      description: 'Company settings, branding, and domains',
      href: '/settings/organization',
    },
    {
      id: 'team',
      label: 'Team Members',
      icon: Users,
      description: 'Invite users, manage roles and permissions',
      href: '/settings/team',
      badge: '12 members',
    },
    {
      id: 'integrations',
      label: 'Integrations',
      icon: Webhook,
      description: 'Connect third-party services and APIs',
      href: '/settings/integrations',
      badge: '5 active',
    },
    {
      id: 'api',
      label: 'API & Developers',
      icon: Key,
      description: 'API keys, webhooks, and developer tools',
      href: '/settings/api',
    },
    {
      id: 'notifications',
      label: 'Notifications',
      icon: Bell,
      description: 'Email, push, and in-app notification preferences',
      href: '/settings/notifications',
    },
  ]

  return (
    <MainLayout>
      <div className="max-w-7xl mx-auto space-y-8">
        {/* Page Header */}
        <div className="flex justify-between items-start">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
              Settings
            </h1>
            <p className="mt-2 text-gray-600 dark:text-gray-400">
              Manage your account settings and preferences
            </p>
          </div>
          <Button variant="outline" size="sm">
            View activity log
          </Button>
        </div>

        {/* Settings Navigation Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-8">
          <TabsList className="grid w-full grid-cols-4 lg:grid-cols-8">
            {settingsSections.map((section) => (
              <TabsTrigger
                key={section.id}
                value={section.id}
                className="relative"
              >
                <section.icon className="h-4 w-4 mr-2" />
                <span className="hidden sm:inline">{section.label}</span>
                {section.alert && (
                  <span className="absolute -top-1 -right-1 h-2 w-2 bg-red-500 rounded-full" />
                )}
              </TabsTrigger>
            ))}
          </TabsList>

          {/* Settings Content Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Main Content Area */}
            <div className="lg:col-span-2 space-y-6">
              {settingsSections.map((section) => (
                <TabsContent key={section.id} value={section.id} className="mt-0">
                  <Card>
                    <CardHeader>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <div className="p-2 bg-gray-100 dark:bg-gray-800 rounded-lg">
                            <section.icon className="h-5 w-5 text-gray-600 dark:text-gray-400" />
                          </div>
                          <div>
                            <CardTitle className="flex items-center gap-2">
                              {section.label}
                              {section.badge && (
                                <Badge variant="secondary">
                                  {section.badge}
                                </Badge>
                              )}
                            </CardTitle>
                            <CardDescription>
                              {section.description}
                            </CardDescription>
                          </div>
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      {/* Dynamic content based on section */}
                      {section.id === 'profile' && <ProfilePreview />}
                      {section.id === 'billing' && <BillingPreview />}
                      {section.id === 'security' && <SecurityPreview />}
                      {section.id === 'organization' && <OrganizationPreview />}
                      {section.id === 'team' && <TeamPreview />}
                      {section.id === 'integrations' && <IntegrationsPreview />}
                      {section.id === 'api' && <APIPreview />}
                      {section.id === 'notifications' && <NotificationsPreview />}

                      <div className="pt-4">
                        <Button asChild>
                          <Link to={section.href}>
                            Manage {section.label.toLowerCase()}
                          </Link>
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                </TabsContent>
              ))}
            </div>

            {/* Sidebar Information */}
            <div className="space-y-6">
              {/* Account Status Card */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Account Status</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-600 dark:text-gray-400">Plan</span>
                    <Badge>Pro Plan</Badge>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-600 dark:text-gray-400">Status</span>
                    <Badge variant="success">Active</Badge>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-600 dark:text-gray-400">Member since</span>
                    <span className="text-sm font-medium">Jan 2024</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-600 dark:text-gray-400">Storage</span>
                    <span className="text-sm font-medium">4.2 GB / 10 GB</span>
                  </div>
                </CardContent>
              </Card>

              {/* Quick Actions Card */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Quick Actions</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  <Button variant="outline" className="w-full justify-start" size="sm">
                    <Key className="h-4 w-4 mr-2" />
                    Generate API key
                  </Button>
                  <Button variant="outline" className="w-full justify-start" size="sm">
                    <Users className="h-4 w-4 mr-2" />
                    Invite team member
                  </Button>
                  <Button variant="outline" className="w-full justify-start" size="sm">
                    <CreditCard className="h-4 w-4 mr-2" />
                    Update payment method
                  </Button>
                  <Button variant="outline" className="w-full justify-start" size="sm">
                    <Shield className="h-4 w-4 mr-2" />
                    Enable 2FA
                  </Button>
                </CardContent>
              </Card>

              {/* Support Card */}
              <Card className="bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800">
                <CardHeader>
                  <CardTitle className="text-lg">Need help?</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Our support team is here to help you with any questions.
                  </p>
                  <div className="space-y-2">
                    <Button variant="secondary" className="w-full" size="sm">
                      Visit Help Center
                    </Button>
                    <Button variant="outline" className="w-full" size="sm">
                      Contact Support
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </Tabs>
      </div>
    </MainLayout>
  )
}

// Preview components for each section
function ProfilePreview() {
  return (
    <div className="space-y-3">
      <div className="flex items-center space-x-3">
        <div className="h-12 w-12 bg-gray-200 dark:bg-gray-700 rounded-full" />
        <div>
          <p className="font-medium">John Doe</p>
          <p className="text-sm text-gray-500">john@example.com</p>
        </div>
      </div>
      <p className="text-sm text-gray-600 dark:text-gray-400">
        Last updated 2 days ago
      </p>
    </div>
  )
}

function BillingPreview() {
  return (
    <div className="space-y-3">
      <div className="flex justify-between items-center">
        <span className="text-sm text-gray-600 dark:text-gray-400">Current period</span>
        <span className="font-medium">$99/month</span>
      </div>
      <div className="flex justify-between items-center">
        <span className="text-sm text-gray-600 dark:text-gray-400">Next billing</span>
        <span className="font-medium">Feb 1, 2024</span>
      </div>
    </div>
  )
}

function SecurityPreview() {
  return (
    <div className="space-y-3">
      <div className="flex justify-between items-center">
        <span className="text-sm text-gray-600 dark:text-gray-400">Two-factor auth</span>
        <Badge variant="destructive">Disabled</Badge>
      </div>
      <div className="flex justify-between items-center">
        <span className="text-sm text-gray-600 dark:text-gray-400">Active sessions</span>
        <span className="font-medium">3 devices</span>
      </div>
    </div>
  )
}

function OrganizationPreview() {
  return (
    <div className="space-y-3">
      <div>
        <p className="font-medium">Acme Corporation</p>
        <p className="text-sm text-gray-500">acme.example.com</p>
      </div>
    </div>
  )
}

function TeamPreview() {
  return (
    <div className="space-y-3">
      <div className="flex justify-between items-center">
        <span className="text-sm text-gray-600 dark:text-gray-400">Total members</span>
        <span className="font-medium">12</span>
      </div>
      <div className="flex justify-between items-center">
        <span className="text-sm text-gray-600 dark:text-gray-400">Pending invites</span>
        <span className="font-medium">2</span>
      </div>
    </div>
  )
}

function IntegrationsPreview() {
  return (
    <div className="space-y-3">
      <div className="flex justify-between items-center">
        <span className="text-sm text-gray-600 dark:text-gray-400">Connected</span>
        <span className="font-medium">5 services</span>
      </div>
      <div className="flex justify-between items-center">
        <span className="text-sm text-gray-600 dark:text-gray-400">Available</span>
        <span className="font-medium">20+ integrations</span>
      </div>
    </div>
  )
}

function APIPreview() {
  return (
    <div className="space-y-3">
      <div className="flex justify-between items-center">
        <span className="text-sm text-gray-600 dark:text-gray-400">API keys</span>
        <span className="font-medium">2 active</span>
      </div>
      <div className="flex justify-between items-center">
        <span className="text-sm text-gray-600 dark:text-gray-400">Webhooks</span>
        <span className="font-medium">3 configured</span>
      </div>
    </div>
  )
}

function NotificationsPreview() {
  return (
    <div className="space-y-3">
      <div className="flex justify-between items-center">
        <span className="text-sm text-gray-600 dark:text-gray-400">Email</span>
        <Badge variant="success">Enabled</Badge>
      </div>
      <div className="flex justify-between items-center">
        <span className="text-sm text-gray-600 dark:text-gray-400">Push</span>
        <Badge variant="secondary">Disabled</Badge>
      </div>
    </div>
  )
}