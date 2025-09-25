import * as React from 'react'
import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { MainLayout } from '@/layouts/main-layout'
import { SecurityForm } from '@/components/settings/SecurityForm'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/label'
import {
  Shield,
  Lock,
  Smartphone,
  Key,
  AlertTriangle,
  CheckCircle2,
  Monitor,
  MapPin,
  Clock,
  LogOut
} from 'lucide-react'
import { useUIStore } from '@/stores'

export const Route = createFileRoute('/settings/security')({
  component: SecurityPage,
  beforeLoad: () => {
    useUIStore.getState().setBreadcrumbs([
      { label: 'Dashboard', href: '/' },
      { label: 'Settings', href: '/settings' },
      { label: 'Security' }
    ])
  },
})

function SecurityPage() {
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = React.useState('password')
  const [twoFactorEnabled, setTwoFactorEnabled] = React.useState(false)
  const [sessionTimeout, setSessionTimeout] = React.useState(true)
  const [loginAlerts, setLoginAlerts] = React.useState(true)

  const activeSessions = [
    {
      id: 1,
      device: 'Chrome on MacBook Pro',
      location: 'San Francisco, CA',
      ip: '192.168.1.1',
      lastActive: '2 minutes ago',
      current: true
    },
    {
      id: 2,
      device: 'Safari on iPhone',
      location: 'San Francisco, CA',
      ip: '192.168.1.2',
      lastActive: '1 hour ago',
      current: false
    },
    {
      id: 3,
      device: 'Chrome on Windows',
      location: 'New York, NY',
      ip: '10.0.0.1',
      lastActive: '3 days ago',
      current: false
    }
  ]

  const loginHistory = [
    {
      id: 1,
      date: '2024-02-01 09:15:00',
      device: 'Chrome on MacBook Pro',
      location: 'San Francisco, CA',
      ip: '192.168.1.1',
      status: 'success'
    },
    {
      id: 2,
      date: '2024-01-31 14:23:00',
      device: 'Safari on iPhone',
      location: 'San Francisco, CA',
      ip: '192.168.1.2',
      status: 'success'
    },
    {
      id: 3,
      date: '2024-01-30 11:45:00',
      device: 'Unknown Browser',
      location: 'Moscow, Russia',
      ip: '185.220.101.1',
      status: 'blocked'
    },
    {
      id: 4,
      date: '2024-01-29 08:30:00',
      device: 'Chrome on Windows',
      location: 'New York, NY',
      ip: '10.0.0.1',
      status: 'success'
    }
  ]

  return (
    <MainLayout>
      <div className="max-w-4xl mx-auto space-y-8">
        <div className="flex justify-between items-start">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
              Security Settings
            </h1>
            <p className="mt-2 text-gray-600 dark:text-gray-400">
              Manage your account security and access controls
            </p>
          </div>
          <Button variant="outline" onClick={() => navigate({ to: '/settings' })}>
            Back to Settings
          </Button>
        </div>

        <Alert className="bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800">
          <AlertTriangle className="h-4 w-4 text-yellow-600 dark:text-yellow-400" />
          <AlertTitle className="text-yellow-900 dark:text-yellow-100">
            Security Recommendation
          </AlertTitle>
          <AlertDescription className="text-yellow-700 dark:text-yellow-300">
            Enable two-factor authentication to add an extra layer of security to your account.
          </AlertDescription>
        </Alert>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="password">Password</TabsTrigger>
            <TabsTrigger value="2fa">Two-Factor</TabsTrigger>
            <TabsTrigger value="sessions">Sessions</TabsTrigger>
            <TabsTrigger value="activity">Activity</TabsTrigger>
          </TabsList>

          <TabsContent value="password" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Change Password</CardTitle>
                <CardDescription>
                  Update your password regularly to keep your account secure
                </CardDescription>
              </CardHeader>
              <CardContent>
                <SecurityForm />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Password Requirements</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center space-x-2">
                  <CheckCircle2 className="h-4 w-4 text-green-500" />
                  <span className="text-sm">At least 8 characters long</span>
                </div>
                <div className="flex items-center space-x-2">
                  <CheckCircle2 className="h-4 w-4 text-green-500" />
                  <span className="text-sm">Contains uppercase and lowercase letters</span>
                </div>
                <div className="flex items-center space-x-2">
                  <CheckCircle2 className="h-4 w-4 text-green-500" />
                  <span className="text-sm">Contains at least one number</span>
                </div>
                <div className="flex items-center space-x-2">
                  <CheckCircle2 className="h-4 w-4 text-green-500" />
                  <span className="text-sm">Contains at least one special character</span>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="2fa" className="space-y-6">
            <Card>
              <CardHeader>
                <div className="flex justify-between items-start">
                  <div>
                    <CardTitle>Two-Factor Authentication</CardTitle>
                    <CardDescription>
                      Add an extra layer of security to your account
                    </CardDescription>
                  </div>
                  <Badge variant={twoFactorEnabled ? 'success' : 'secondary'}>
                    {twoFactorEnabled ? 'Enabled' : 'Disabled'}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <Label htmlFor="2fa-toggle" className="text-base font-medium">
                      Enable Two-Factor Authentication
                    </Label>
                    <p className="text-sm text-gray-500">
                      Require a verification code in addition to your password
                    </p>
                  </div>
                  <Switch
                    id="2fa-toggle"
                    checked={twoFactorEnabled}
                    onCheckedChange={setTwoFactorEnabled}
                  />
                </div>

                {twoFactorEnabled && (
                  <div className="space-y-4 pt-4 border-t">
                    <div className="bg-gray-50 dark:bg-gray-800 p-4 rounded-lg">
                      <h4 className="font-medium mb-2">Setup Instructions</h4>
                      <ol className="space-y-2 text-sm text-gray-600 dark:text-gray-400">
                        <li>1. Download an authenticator app (Google Authenticator, Authy, etc.)</li>
                        <li>2. Scan the QR code below with your authenticator app</li>
                        <li>3. Enter the verification code to confirm setup</li>
                      </ol>
                    </div>

                    <div className="flex justify-center p-8 border-2 border-dashed rounded-lg">
                      <div className="w-48 h-48 bg-gray-200 dark:bg-gray-700 rounded-lg flex items-center justify-center">
                        <span className="text-gray-500 dark:text-gray-400">QR Code</span>
                      </div>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="verify-code">Verification Code</Label>
                      <div className="flex space-x-2">
                        <input
                          id="verify-code"
                          type="text"
                          placeholder="000000"
                          className="flex-1 px-3 py-2 border rounded-md"
                          maxLength={6}
                        />
                        <Button>Verify</Button>
                      </div>
                    </div>

                    <Alert>
                      <Key className="h-4 w-4" />
                      <AlertTitle>Backup Codes</AlertTitle>
                      <AlertDescription>
                        Save these backup codes in a safe place. You can use them to access your account if you lose your device.
                      </AlertDescription>
                    </Alert>

                    <div className="grid grid-cols-2 gap-2 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg font-mono text-sm">
                      <span>XXXX-XXXX-XXXX</span>
                      <span>XXXX-XXXX-XXXX</span>
                      <span>XXXX-XXXX-XXXX</span>
                      <span>XXXX-XXXX-XXXX</span>
                      <span>XXXX-XXXX-XXXX</span>
                      <span>XXXX-XXXX-XXXX</span>
                    </div>

                    <Button variant="outline" className="w-full">
                      <Key className="h-4 w-4 mr-2" />
                      Generate New Backup Codes
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Additional Security Options</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <Label htmlFor="session-timeout" className="text-base font-medium">
                      Auto-logout on inactivity
                    </Label>
                    <p className="text-sm text-gray-500">
                      Automatically sign out after 30 minutes of inactivity
                    </p>
                  </div>
                  <Switch
                    id="session-timeout"
                    checked={sessionTimeout}
                    onCheckedChange={setSessionTimeout}
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <Label htmlFor="login-alerts" className="text-base font-medium">
                      Login alerts
                    </Label>
                    <p className="text-sm text-gray-500">
                      Get notified when someone logs into your account
                    </p>
                  </div>
                  <Switch
                    id="login-alerts"
                    checked={loginAlerts}
                    onCheckedChange={setLoginAlerts}
                  />
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="sessions" className="space-y-6">
            <Card>
              <CardHeader>
                <div className="flex justify-between items-center">
                  <div>
                    <CardTitle>Active Sessions</CardTitle>
                    <CardDescription>
                      Manage devices that are currently logged into your account
                    </CardDescription>
                  </div>
                  <Button variant="destructive" size="sm">
                    <LogOut className="h-4 w-4 mr-2" />
                    Sign out all devices
                  </Button>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {activeSessions.map((session) => (
                  <div key={session.id} className="flex items-center justify-between p-4 border rounded-lg">
                    <div className="flex items-center space-x-4">
                      <Monitor className="h-5 w-5 text-gray-400" />
                      <div>
                        <div className="flex items-center space-x-2">
                          <p className="font-medium">{session.device}</p>
                          {session.current && (
                            <Badge variant="success" className="text-xs">Current</Badge>
                          )}
                        </div>
                        <div className="flex items-center space-x-4 mt-1">
                          <span className="flex items-center text-xs text-gray-500">
                            <MapPin className="h-3 w-3 mr-1" />
                            {session.location}
                          </span>
                          <span className="text-xs text-gray-500">
                            IP: {session.ip}
                          </span>
                          <span className="flex items-center text-xs text-gray-500">
                            <Clock className="h-3 w-3 mr-1" />
                            {session.lastActive}
                          </span>
                        </div>
                      </div>
                    </div>
                    {!session.current && (
                      <Button variant="ghost" size="sm">
                        Sign out
                      </Button>
                    )}
                  </div>
                ))}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="activity" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Login History</CardTitle>
                <CardDescription>
                  Recent login attempts and security events
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {loginHistory.map((login) => (
                    <div key={login.id} className="flex items-center justify-between p-3 border rounded-lg">
                      <div className="flex items-center space-x-4">
                        <div className={`p-2 rounded-full ${
                          login.status === 'success' 
                            ? 'bg-green-100 dark:bg-green-900/20' 
                            : 'bg-red-100 dark:bg-red-900/20'
                        }`}>
                          {login.status === 'success' ? (
                            <CheckCircle2 className="h-4 w-4 text-green-600 dark:text-green-400" />
                          ) : (
                            <AlertTriangle className="h-4 w-4 text-red-600 dark:text-red-400" />
                          )}
                        </div>
                        <div>
                          <p className="font-medium text-sm">{login.device}</p>
                          <div className="flex items-center space-x-3 mt-1">
                            <span className="text-xs text-gray-500">
                              {new Date(login.date).toLocaleString()}
                            </span>
                            <span className="text-xs text-gray-500">
                              {login.location}
                            </span>
                            <span className="text-xs text-gray-500">
                              {login.ip}
                            </span>
                          </div>
                        </div>
                      </div>
                      <Badge 
                        variant={login.status === 'success' ? 'success' : 'destructive'}
                        className="text-xs"
                      >
                        {login.status}
                      </Badge>
                    </div>
                  ))}
                </div>

                <Button variant="outline" className="w-full mt-4">
                  View full activity log
                </Button>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Security Events</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm">Password last changed</span>
                  <span className="text-sm font-medium">30 days ago</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Two-factor authentication enabled</span>
                  <span className="text-sm font-medium">Never</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Recovery email verified</span>
                  <span className="text-sm font-medium">Yes</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Account created</span>
                  <span className="text-sm font-medium">Jan 15, 2024</span>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </MainLayout>
  )
}