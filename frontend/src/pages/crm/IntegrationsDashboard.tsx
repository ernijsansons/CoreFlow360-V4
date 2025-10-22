import {
  useIntegrations,
  useAuthorizeGmail,
  useSyncGmail,
  useAuthorizeOutlook,
  useSyncOutlook,
  useSyncTwilio,
  useTestTwilioConnection,
  useDeleteIntegration,
} from '@/hooks/api'
import { Card } from '@/components/ui/card-refactored'
import { Button } from '@/components/ui/button-refactored'
import { Badge } from '@/components/ui/badge-refactored'
import {
  Loader2,
  Mail,
  Phone,
  RefreshCw,
  Trash2,
  CheckCircle2,
  XCircle,
  Link as LinkIcon,
  Settings,
} from 'lucide-react'

export function IntegrationsDashboard() {
  const { data: integrations, isLoading } = useIntegrations()

  const authorizeGmail = useAuthorizeGmail()
  const syncGmail = useSyncGmail()
  const authorizeOutlook = useAuthorizeOutlook()
  const syncOutlook = useSyncOutlook()
  const syncTwilio = useSyncTwilio()
  const testTwilio = useTestTwilioConnection()
  const deleteIntegration = useDeleteIntegration()

  const getIntegrationIcon = (type: string) => {
    switch (type) {
      case 'gmail':
      case 'outlook':
        return <Mail className="h-6 w-6" />
      case 'twilio':
        return <Phone className="h-6 w-6" />
      default:
        return <LinkIcon className="h-6 w-6" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'bg-green-500'
      case 'error':
        return 'bg-red-500'
      case 'pending':
        return 'bg-yellow-500'
      default:
        return 'bg-gray-500'
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <Loader2 className="h-8 w-8 animate-spin text-brand-primary" />
      </div>
    )
  }

  return (
    <div className="container mx-auto py-8 space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">CRM Integrations</h1>
        <p className="text-gray-600 dark:text-gray-400 mt-2">
          Connect your communication channels to automatically sync leads and conversations
        </p>
      </div>

      {/* Available Integrations */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Gmail Integration */}
        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-3">
              <div className="p-3 bg-red-100 dark:bg-red-900/20 rounded-lg">
                <Mail className="h-6 w-6 text-red-600" />
              </div>
              <div>
                <h3 className="font-semibold">Gmail</h3>
                <p className="text-sm text-gray-500">Email sync</p>
              </div>
            </div>
            {integrations?.data?.some((i) => i.type === 'gmail' && i.status === 'active') ? (
              <Badge className="bg-green-500">Connected</Badge>
            ) : (
              <Badge variant="outline">Not connected</Badge>
            )}
          </div>

          <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
            Sync Gmail emails and automatically create leads from conversations
          </p>

          <div className="space-y-2">
            {integrations?.data?.some((i) => i.type === 'gmail' && i.status === 'active') ? (
              <>
                <Button
                  size="sm"
                  variant="outline"
                  className="w-full"
                  onClick={() => syncGmail.mutate()}
                  disabled={syncGmail.isPending}
                >
                  {syncGmail.isPending ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <RefreshCw className="h-4 w-4 mr-2" />
                  )}
                  Sync Now
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  className="w-full"
                  onClick={() => {
                    const gmailIntegration = integrations.data.find(
                      (i) => i.type === 'gmail' && i.status === 'active'
                    )
                    if (gmailIntegration) {
                      deleteIntegration.mutate(gmailIntegration.id)
                    }
                  }}
                >
                  <Trash2 className="h-4 w-4 mr-2" />
                  Disconnect
                </Button>
              </>
            ) : (
              <Button
                size="sm"
                className="w-full"
                onClick={() => authorizeGmail.mutate()}
                disabled={authorizeGmail.isPending}
              >
                {authorizeGmail.isPending ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <LinkIcon className="h-4 w-4 mr-2" />
                )}
                Connect Gmail
              </Button>
            )}
          </div>
        </Card>

        {/* Outlook Integration */}
        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-3">
              <div className="p-3 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
                <Mail className="h-6 w-6 text-blue-600" />
              </div>
              <div>
                <h3 className="font-semibold">Outlook</h3>
                <p className="text-sm text-gray-500">Email sync</p>
              </div>
            </div>
            {integrations?.data?.some((i) => i.type === 'outlook' && i.status === 'active') ? (
              <Badge className="bg-green-500">Connected</Badge>
            ) : (
              <Badge variant="outline">Not connected</Badge>
            )}
          </div>

          <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
            Sync Outlook emails and automatically create leads from conversations
          </p>

          <div className="space-y-2">
            {integrations?.data?.some((i) => i.type === 'outlook' && i.status === 'active') ? (
              <>
                <Button
                  size="sm"
                  variant="outline"
                  className="w-full"
                  onClick={() => syncOutlook.mutate()}
                  disabled={syncOutlook.isPending}
                >
                  {syncOutlook.isPending ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <RefreshCw className="h-4 w-4 mr-2" />
                  )}
                  Sync Now
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  className="w-full"
                  onClick={() => {
                    const outlookIntegration = integrations.data.find(
                      (i) => i.type === 'outlook' && i.status === 'active'
                    )
                    if (outlookIntegration) {
                      deleteIntegration.mutate(outlookIntegration.id)
                    }
                  }}
                >
                  <Trash2 className="h-4 w-4 mr-2" />
                  Disconnect
                </Button>
              </>
            ) : (
              <Button
                size="sm"
                className="w-full"
                onClick={() => authorizeOutlook.mutate()}
                disabled={authorizeOutlook.isPending}
              >
                {authorizeOutlook.isPending ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <LinkIcon className="h-4 w-4 mr-2" />
                )}
                Connect Outlook
              </Button>
            )}
          </div>
        </Card>

        {/* Twilio Integration */}
        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-3">
              <div className="p-3 bg-purple-100 dark:bg-purple-900/20 rounded-lg">
                <Phone className="h-6 w-6 text-purple-600" />
              </div>
              <div>
                <h3 className="font-semibold">Twilio</h3>
                <p className="text-sm text-gray-500">SMS & Voice</p>
              </div>
            </div>
            {integrations?.data?.some((i) => i.type === 'twilio' && i.status === 'active') ? (
              <Badge className="bg-green-500">Connected</Badge>
            ) : (
              <Badge variant="outline">Not connected</Badge>
            )}
          </div>

          <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
            Track calls and SMS messages, automatically log them to leads
          </p>

          <div className="space-y-2">
            {integrations?.data?.some((i) => i.type === 'twilio' && i.status === 'active') ? (
              <>
                <Button
                  size="sm"
                  variant="outline"
                  className="w-full"
                  onClick={() => testTwilio.mutate()}
                  disabled={testTwilio.isPending}
                >
                  {testTwilio.isPending ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <CheckCircle2 className="h-4 w-4 mr-2" />
                  )}
                  Test Connection
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  className="w-full"
                  onClick={() => syncTwilio.mutate()}
                  disabled={syncTwilio.isPending}
                >
                  {syncTwilio.isPending ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <RefreshCw className="h-4 w-4 mr-2" />
                  )}
                  Sync Now
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  className="w-full"
                  onClick={() => {
                    const twilioIntegration = integrations.data.find(
                      (i) => i.type === 'twilio' && i.status === 'active'
                    )
                    if (twilioIntegration) {
                      deleteIntegration.mutate(twilioIntegration.id)
                    }
                  }}
                >
                  <Trash2 className="h-4 w-4 mr-2" />
                  Disconnect
                </Button>
              </>
            ) : (
              <Button size="sm" variant="outline" className="w-full">
                <Settings className="h-4 w-4 mr-2" />
                Configure
              </Button>
            )}
          </div>
        </Card>
      </div>

      {/* Active Integrations List */}
      {integrations?.data && integrations.data.length > 0 && (
        <Card className="p-6">
          <h2 className="text-2xl font-bold mb-6">Active Integrations</h2>

          <div className="space-y-3">
            {integrations.data.map((integration) => (
              <div
                key={integration.id}
                className="flex items-center justify-between p-4 border border-gray-200 dark:border-gray-700 rounded-lg"
              >
                <div className="flex items-center space-x-4">
                  {getIntegrationIcon(integration.type)}
                  <div>
                    <div className="flex items-center space-x-2">
                      <p className="font-medium">{integration.name}</p>
                      <div className={`h-2 w-2 rounded-full ${getStatusColor(integration.status)}`} />
                    </div>
                    <p className="text-sm text-gray-500">
                      Last synced:{' '}
                      {integration.last_sync_at
                        ? new Date(integration.last_sync_at).toLocaleString()
                        : 'Never'}
                    </p>
                  </div>
                </div>

                <div className="flex items-center space-x-2">
                  <Badge
                    variant={integration.status === 'active' ? 'default' : 'destructive'}
                  >
                    {integration.status}
                  </Badge>
                  {integration.status === 'error' && (
                    <Badge variant="destructive" className="flex items-center space-x-1">
                      <XCircle className="h-3 w-3" />
                      <span>Error</span>
                    </Badge>
                  )}
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}
