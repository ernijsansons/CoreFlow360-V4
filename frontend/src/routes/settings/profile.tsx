import * as React from 'react'
import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { MainLayout } from '@/layouts/main-layout'
import { ProfileForm } from '@/components/settings/ProfileForm'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  User,
  Mail,
  Globe,
  Briefcase,
  MapPin,
  Calendar,
  Shield,
  Activity
} from 'lucide-react'
import { useUIStore } from '@/stores'

export const Route = createFileRoute('/settings/profile')({
  component: ProfilePage,
  beforeLoad: () => {
    // Set breadcrumbs
    useUIStore.getState().setBreadcrumbs([
      { label: 'Dashboard', href: '/' },
      { label: 'Settings', href: '/settings' },
      { label: 'Profile' }
    ])
  },
})

function ProfilePage() {
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = React.useState('general')

  return (
    <MainLayout>
      <div className="max-w-4xl mx-auto space-y-8">
        {/* Page Header */}
        <div className="flex justify-between items-start">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
              Profile Settings
            </h1>
            <p className="mt-2 text-gray-600 dark:text-gray-400">
              Manage your personal information and public profile
            </p>
          </div>
          <Button variant="outline" onClick={() => navigate({ to: '/settings' })}>
            Back to Settings
          </Button>
        </div>

        {/* Profile Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="general">General</TabsTrigger>
            <TabsTrigger value="professional">Professional</TabsTrigger>
            <TabsTrigger value="preferences">Preferences</TabsTrigger>
            <TabsTrigger value="activity">Activity</TabsTrigger>
          </TabsList>

          {/* General Tab */}
          <TabsContent value="general" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Personal Information</CardTitle>
                <CardDescription>
                  Update your personal details and profile photo
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ProfileForm />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Contact Information</CardTitle>
                <CardDescription>
                  Manage your email addresses and phone numbers
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-4">
                  <div className="flex items-center justify-between p-4 border rounded-lg">
                    <div className="flex items-center space-x-3">
                      <Mail className="h-5 w-5 text-gray-400" />
                      <div>
                        <p className="font-medium">john.doe@example.com</p>
                        <p className="text-sm text-gray-500">Primary email</p>
                      </div>
                    </div>
                    <Badge variant="success">Verified</Badge>
                  </div>

                  <div className="flex items-center justify-between p-4 border rounded-lg">
                    <div className="flex items-center space-x-3">
                      <Mail className="h-5 w-5 text-gray-400" />
                      <div>
                        <p className="font-medium">john@company.com</p>
                        <p className="text-sm text-gray-500">Work email</p>
                      </div>
                    </div>
                    <Badge variant="secondary">Unverified</Badge>
                  </div>
                </div>

                <Button variant="outline" className="w-full">
                  Add email address
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Professional Tab */}
          <TabsContent value="professional" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Professional Details</CardTitle>
                <CardDescription>
                  Information about your role and organization
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Job Title</label>
                    <div className="flex items-center space-x-2">
                      <Briefcase className="h-4 w-4 text-gray-400" />
                      <input
                        type="text"
                        className="flex-1 px-3 py-2 border rounded-md"
                        defaultValue="Senior Product Manager"
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm font-medium">Department</label>
                    <input
                      type="text"
                      className="w-full px-3 py-2 border rounded-md"
                      defaultValue="Product Development"
                    />
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm font-medium">Location</label>
                    <div className="flex items-center space-x-2">
                      <MapPin className="h-4 w-4 text-gray-400" />
                      <input
                        type="text"
                        className="flex-1 px-3 py-2 border rounded-md"
                        defaultValue="San Francisco, CA"
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm font-medium">Time Zone</label>
                    <select className="w-full px-3 py-2 border rounded-md">
                      <option>Pacific Time (PT)</option>
                      <option>Eastern Time (ET)</option>
                      <option>Central Time (CT)</option>
                      <option>Mountain Time (MT)</option>
                    </select>
                  </div>
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium">Bio</label>
                  <textarea
                    className="w-full px-3 py-2 border rounded-md"
                    rows={4}
                    placeholder="Tell us about yourself..."
                    defaultValue="Experienced product manager focused on enterprise SaaS solutions."
                  />
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium">LinkedIn Profile</label>
                  <div className="flex items-center space-x-2">
                    <Globe className="h-4 w-4 text-gray-400" />
                    <input
                      type="url"
                      className="flex-1 px-3 py-2 border rounded-md"
                      placeholder="https://linkedin.com/in/yourprofile"
                    />
                  </div>
                </div>

                <Button className="w-full">Save Professional Details</Button>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Preferences Tab */}
          <TabsContent value="preferences" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Display Preferences</CardTitle>
                <CardDescription>
                  Customize how information is displayed to you
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="font-medium">Language</p>
                      <p className="text-sm text-gray-500">Choose your preferred language</p>
                    </div>
                    <select className="px-3 py-2 border rounded-md">
                      <option>English (US)</option>
                      <option>Spanish</option>
                      <option>French</option>
                      <option>German</option>
                    </select>
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <p className="font-medium">Date Format</p>
                      <p className="text-sm text-gray-500">Choose date display format</p>
                    </div>
                    <select className="px-3 py-2 border rounded-md">
                      <option>MM/DD/YYYY</option>
                      <option>DD/MM/YYYY</option>
                      <option>YYYY-MM-DD</option>
                    </select>
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <p className="font-medium">Time Format</p>
                      <p className="text-sm text-gray-500">12-hour or 24-hour format</p>
                    </div>
                    <select className="px-3 py-2 border rounded-md">
                      <option>12-hour</option>
                      <option>24-hour</option>
                    </select>
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <p className="font-medium">Currency</p>
                      <p className="text-sm text-gray-500">Default currency for financial data</p>
                    </div>
                    <select className="px-3 py-2 border rounded-md">
                      <option>USD ($)</option>
                      <option>EUR (€)</option>
                      <option>GBP (£)</option>
                      <option>JPY (¥)</option>
                    </select>
                  </div>
                </div>

                <Button className="w-full">Save Preferences</Button>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Activity Tab */}
          <TabsContent value="activity" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Account Activity</CardTitle>
                <CardDescription>
                  Recent activity and login history
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <Alert>
                  <Shield className="h-4 w-4" />
                  <AlertTitle>Security Status</AlertTitle>
                  <AlertDescription>
                    Your account is secure. No suspicious activity detected.
                  </AlertDescription>
                </Alert>

                <div className="space-y-4">
                  <h3 className="font-medium">Recent Activity</h3>

                  <div className="space-y-3">
                    <div className="flex items-center justify-between p-3 border rounded-lg">
                      <div className="flex items-center space-x-3">
                        <Activity className="h-4 w-4 text-gray-400" />
                        <div>
                          <p className="text-sm font-medium">Password changed</p>
                          <p className="text-xs text-gray-500">San Francisco, CA</p>
                        </div>
                      </div>
                      <span className="text-xs text-gray-500">2 hours ago</span>
                    </div>

                    <div className="flex items-center justify-between p-3 border rounded-lg">
                      <div className="flex items-center space-x-3">
                        <Activity className="h-4 w-4 text-gray-400" />
                        <div>
                          <p className="text-sm font-medium">Logged in from new device</p>
                          <p className="text-xs text-gray-500">Chrome on MacOS</p>
                        </div>
                      </div>
                      <span className="text-xs text-gray-500">1 day ago</span>
                    </div>

                    <div className="flex items-center justify-between p-3 border rounded-lg">
                      <div className="flex items-center space-x-3">
                        <Activity className="h-4 w-4 text-gray-400" />
                        <div>
                          <p className="text-sm font-medium">Profile updated</p>
                          <p className="text-xs text-gray-500">Name and email changed</p>
                        </div>
                      </div>
                      <span className="text-xs text-gray-500">3 days ago</span>
                    </div>
                  </div>
                </div>

                <Button variant="outline" className="w-full">
                  View full activity log
                </Button>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Account Statistics</CardTitle>
                <CardDescription>
                  Your account usage and statistics
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <p className="text-sm text-gray-500">Member Since</p>
                    <p className="text-2xl font-bold">Jan 2024</p>
                  </div>
                  <div className="space-y-2">
                    <p className="text-sm text-gray-500">Total Logins</p>
                    <p className="text-2xl font-bold">142</p>
                  </div>
                  <div className="space-y-2">
                    <p className="text-sm text-gray-500">Projects Created</p>
                    <p className="text-2xl font-bold">28</p>
                  </div>
                  <div className="space-y-2">
                    <p className="text-sm text-gray-500">Team Members Added</p>
                    <p className="text-2xl font-bold">12</p>
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