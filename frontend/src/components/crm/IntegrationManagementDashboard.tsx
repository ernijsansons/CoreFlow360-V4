/**
 * Integration Management Dashboard
 * Central hub for viewing and managing all CRM integrations
 */

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import {
  Mail, Phone, MessageSquare, Plug, Trash2, RefreshCw, Settings,
  CheckCircle, XCircle, AlertTriangle, ExternalLink, Plus, Activity
} from 'lucide-react';
import apiClient from '@/lib/api/client';

interface EmailIntegration {
  provider: string;
  email_address: string;
  sync_enabled: boolean;
  last_sync_at: string | null;
  emails_synced: number;
  last_sync_status?: string;
  sync_error?: string;
}

interface CallIntegration {
  provider: string;
  auto_create_activities: boolean;
  auto_transcribe: boolean;
  last_call_at: string | null;
  calls_captured: number;
}

interface ChatIntegration {
  provider: string;
  auto_capture_enabled: boolean;
  monitored_channels: string[];
  last_message_at: string | null;
  messages_captured: number;
}

interface IntegrationListResponse {
  email: EmailIntegration[];
  calls: CallIntegration[];
  chat?: ChatIntegration[];
}

const PROVIDER_ICONS: Record<string, string> = {
  gmail: '📧',
  outlook: '📨',
  twilio: '📞',
  slack: '💬',
  teams: '👥',
  aircall: '☎️',
  dialpad: '📱',
  ringcentral: '📲',
  intercom: '💭'
};

const PROVIDER_NAMES: Record<string, string> = {
  gmail: 'Gmail',
  outlook: 'Outlook',
  twilio: 'Twilio',
  slack: 'Slack',
  teams: 'Microsoft Teams',
  aircall: 'Aircall',
  dialpad: 'Dialpad',
  ringcentral: 'RingCentral',
  intercom: 'Intercom'
};

export function IntegrationManagementDashboard() {
  const [selectedTab, setSelectedTab] = useState<'email' | 'calls' | 'chat'>('email');
  const queryClient = useQueryClient();

  // Fetch all integrations
  const { data, isLoading, error } = useQuery({
    queryKey: ['crm', 'integrations', 'list'],
    queryFn: async () => {
      const response = await apiClient.get('/api/v1/crm/integrations/list');
      return response.data.data as IntegrationListResponse;
    },
    refetchInterval: 30000 // Refresh every 30 seconds
  });

  // Delete integration mutation
  const deleteMutation = useMutation({
    mutationFn: async ({ type, provider }: { type: string; provider: string }) => {
      await apiClient.delete(`/api/v1/crm/integrations/${type}/${provider}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['crm', 'integrations', 'list'] });
    }
  });

  // Sync integration mutation
  const syncMutation = useMutation({
    mutationFn: async ({ provider }: { provider: string }) => {
      await apiClient.post(`/api/v1/crm/integrations/${provider}/sync`, { maxResults: 50 });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['crm', 'integrations', 'list'] });
    }
  });

  if (isLoading) {
    return (
      <Card className="p-8">
        <div className="flex items-center justify-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-primary"></div>
        </div>
      </Card>
    );
  }

  if (error) {
    return (
      <Alert variant="destructive">
        <AlertTriangle className="h-4 w-4" />
        <AlertDescription>
          Failed to load integrations. Please try again.
        </AlertDescription>
      </Alert>
    );
  }

  const emailIntegrations = data?.email || [];
  const callIntegrations = data?.calls || [];
  const chatIntegrations = data?.chat || [];

  const totalIntegrations = emailIntegrations.length + callIntegrations.length + chatIntegrations.length;
  const activeIntegrations = [
    ...emailIntegrations.filter(i => i.sync_enabled),
    ...callIntegrations.filter(i => i.auto_create_activities),
    ...chatIntegrations.filter(i => i.auto_capture_enabled)
  ].length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            Integration Management
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            Manage your CRM data capture integrations
          </p>
        </div>
        <Button className="bg-brand-primary hover:bg-brand-primary/90">
          <Plus className="w-4 h-4 mr-2" />
          Add Integration
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Total Integrations</p>
              <p className="text-3xl font-bold text-gray-900 dark:text-white mt-1">
                {totalIntegrations}
              </p>
            </div>
            <Plug className="w-8 h-8 text-brand-primary opacity-50" />
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Active</p>
              <p className="text-3xl font-bold text-green-600 mt-1">
                {activeIntegrations}
              </p>
            </div>
            <Activity className="w-8 h-8 text-green-500 opacity-50" />
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Emails Synced</p>
              <p className="text-3xl font-bold text-blue-600 mt-1">
                {emailIntegrations.reduce((sum, i) => sum + i.emails_synced, 0)}
              </p>
            </div>
            <Mail className="w-8 h-8 text-blue-500 opacity-50" />
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Calls Captured</p>
              <p className="text-3xl font-bold text-purple-600 mt-1">
                {callIntegrations.reduce((sum, i) => sum + i.calls_captured, 0)}
              </p>
            </div>
            <Phone className="w-8 h-8 text-purple-500 opacity-50" />
          </div>
        </Card>
      </div>

      {/* Tabs */}
      <Card className="p-1">
        <div className="flex gap-2">
          <Button
            variant={selectedTab === 'email' ? 'default' : 'ghost'}
            onClick={() => setSelectedTab('email')}
            className="flex-1"
          >
            <Mail className="w-4 h-4 mr-2" />
            Email ({emailIntegrations.length})
          </Button>
          <Button
            variant={selectedTab === 'calls' ? 'default' : 'ghost'}
            onClick={() => setSelectedTab('calls')}
            className="flex-1"
          >
            <Phone className="w-4 h-4 mr-2" />
            Calls ({callIntegrations.length})
          </Button>
          <Button
            variant={selectedTab === 'chat' ? 'default' : 'ghost'}
            onClick={() => setSelectedTab('chat')}
            className="flex-1"
          >
            <MessageSquare className="w-4 h-4 mr-2" />
            Chat ({chatIntegrations.length})
          </Button>
        </div>
      </Card>

      {/* Integration Lists */}
      {selectedTab === 'email' && (
        <div className="space-y-4">
          {emailIntegrations.length === 0 ? (
            <Card className="p-12 text-center">
              <Mail className="w-16 h-16 text-gray-400 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
                No Email Integrations
              </h3>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Connect your email to automatically capture customer conversations
              </p>
              <Button className="bg-brand-primary hover:bg-brand-primary/90">
                <Plus className="w-4 h-4 mr-2" />
                Add Email Integration
              </Button>
            </Card>
          ) : (
            emailIntegrations.map((integration, index) => (
              <EmailIntegrationCard
                key={index}
                integration={integration}
                onDelete={() => deleteMutation.mutate({ type: 'email', provider: integration.provider })}
                onSync={() => syncMutation.mutate({ provider: integration.provider })}
                isSyncing={syncMutation.isPending}
              />
            ))
          )}
        </div>
      )}

      {selectedTab === 'calls' && (
        <div className="space-y-4">
          {callIntegrations.length === 0 ? (
            <Card className="p-12 text-center">
              <Phone className="w-16 h-16 text-gray-400 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
                No Call Integrations
              </h3>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Connect your phone system to automatically capture calls
              </p>
              <Button className="bg-brand-primary hover:bg-brand-primary/90">
                <Plus className="w-4 h-4 mr-2" />
                Add Call Integration
              </Button>
            </Card>
          ) : (
            callIntegrations.map((integration, index) => (
              <CallIntegrationCard
                key={index}
                integration={integration}
                onDelete={() => deleteMutation.mutate({ type: 'call', provider: integration.provider })}
              />
            ))
          )}
        </div>
      )}

      {selectedTab === 'chat' && (
        <div className="space-y-4">
          {chatIntegrations.length === 0 ? (
            <Card className="p-12 text-center">
              <MessageSquare className="w-16 h-16 text-gray-400 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
                No Chat Integrations
              </h3>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Connect chat platforms to automatically capture conversations
              </p>
              <Button className="bg-brand-primary hover:bg-brand-primary/90">
                <Plus className="w-4 h-4 mr-2" />
                Add Chat Integration
              </Button>
            </Card>
          ) : (
            chatIntegrations.map((integration, index) => (
              <ChatIntegrationCard
                key={index}
                integration={integration}
                onDelete={() => deleteMutation.mutate({ type: 'chat', provider: integration.provider })}
              />
            ))
          )}
        </div>
      )}
    </div>
  );
}

function EmailIntegrationCard({
  integration,
  onDelete,
  onSync,
  isSyncing
}: {
  integration: EmailIntegration;
  onDelete: () => void;
  onSync: () => void;
  isSyncing: boolean;
}) {
  const icon = PROVIDER_ICONS[integration.provider] || '📧';
  const name = PROVIDER_NAMES[integration.provider] || integration.provider;

  return (
    <Card className="p-6">
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-4 flex-1">
          <div className="text-4xl">{icon}</div>
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-2">
              <h3 className="text-xl font-semibold text-gray-900 dark:text-white">
                {name}
              </h3>
              {integration.sync_enabled ? (
                <Badge className="bg-green-100 text-green-800 border-green-200">
                  <CheckCircle className="w-3 h-3 mr-1" />
                  Active
                </Badge>
              ) : (
                <Badge variant="outline" className="text-gray-600">
                  <XCircle className="w-3 h-3 mr-1" />
                  Disabled
                </Badge>
              )}
            </div>

            <p className="text-gray-600 dark:text-gray-400 mb-3">
              {integration.email_address}
            </p>

            <div className="grid grid-cols-3 gap-4">
              <div>
                <p className="text-xs text-gray-500 mb-1">Emails Synced</p>
                <p className="text-lg font-semibold text-gray-900 dark:text-white">
                  {integration.emails_synced.toLocaleString()}
                </p>
              </div>
              <div>
                <p className="text-xs text-gray-500 mb-1">Last Sync</p>
                <p className="text-sm text-gray-900 dark:text-white">
                  {integration.last_sync_at
                    ? new Date(integration.last_sync_at).toLocaleDateString()
                    : 'Never'}
                </p>
              </div>
              <div>
                <p className="text-xs text-gray-500 mb-1">Status</p>
                <p className="text-sm text-gray-900 dark:text-white">
                  {integration.last_sync_status || 'Unknown'}
                </p>
              </div>
            </div>

            {integration.sync_error && (
              <Alert variant="destructive" className="mt-3">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription className="text-xs">
                  {integration.sync_error}
                </AlertDescription>
              </Alert>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2 ml-4">
          <Button
            variant="outline"
            size="sm"
            onClick={onSync}
            disabled={isSyncing}
          >
            <RefreshCw className={`w-4 h-4 ${isSyncing ? 'animate-spin' : ''}`} />
          </Button>
          <Button variant="outline" size="sm">
            <Settings className="w-4 h-4" />
          </Button>
          <Button variant="outline" size="sm" onClick={onDelete}>
            <Trash2 className="w-4 h-4 text-red-600" />
          </Button>
        </div>
      </div>
    </Card>
  );
}

function CallIntegrationCard({
  integration,
  onDelete
}: {
  integration: CallIntegration;
  onDelete: () => void;
}) {
  const icon = PROVIDER_ICONS[integration.provider] || '📞';
  const name = PROVIDER_NAMES[integration.provider] || integration.provider;

  return (
    <Card className="p-6">
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-4 flex-1">
          <div className="text-4xl">{icon}</div>
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-2">
              <h3 className="text-xl font-semibold text-gray-900 dark:text-white">
                {name}
              </h3>
              <Badge className="bg-green-100 text-green-800 border-green-200">
                <CheckCircle className="w-3 h-3 mr-1" />
                Active
              </Badge>
            </div>

            <div className="grid grid-cols-3 gap-4 mt-3">
              <div>
                <p className="text-xs text-gray-500 mb-1">Calls Captured</p>
                <p className="text-lg font-semibold text-gray-900 dark:text-white">
                  {integration.calls_captured.toLocaleString()}
                </p>
              </div>
              <div>
                <p className="text-xs text-gray-500 mb-1">Last Call</p>
                <p className="text-sm text-gray-900 dark:text-white">
                  {integration.last_call_at
                    ? new Date(integration.last_call_at).toLocaleDateString()
                    : 'Never'}
                </p>
              </div>
              <div>
                <p className="text-xs text-gray-500 mb-1">Features</p>
                <div className="flex gap-1">
                  {integration.auto_transcribe && (
                    <Badge variant="outline" className="text-xs">Transcribe</Badge>
                  )}
                  {integration.auto_create_activities && (
                    <Badge variant="outline" className="text-xs">Auto-Log</Badge>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 ml-4">
          <Button variant="outline" size="sm">
            <Settings className="w-4 h-4" />
          </Button>
          <Button variant="outline" size="sm" onClick={onDelete}>
            <Trash2 className="w-4 h-4 text-red-600" />
          </Button>
        </div>
      </div>
    </Card>
  );
}

function ChatIntegrationCard({
  integration,
  onDelete
}: {
  integration: ChatIntegration;
  onDelete: () => void;
}) {
  const icon = PROVIDER_ICONS[integration.provider] || '💬';
  const name = PROVIDER_NAMES[integration.provider] || integration.provider;

  return (
    <Card className="p-6">
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-4 flex-1">
          <div className="text-4xl">{icon}</div>
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-2">
              <h3 className="text-xl font-semibold text-gray-900 dark:text-white">
                {name}
              </h3>
              {integration.auto_capture_enabled ? (
                <Badge className="bg-green-100 text-green-800 border-green-200">
                  <CheckCircle className="w-3 h-3 mr-1" />
                  Active
                </Badge>
              ) : (
                <Badge variant="outline" className="text-gray-600">
                  <XCircle className="w-3 h-3 mr-1" />
                  Disabled
                </Badge>
              )}
            </div>

            <div className="grid grid-cols-3 gap-4 mt-3">
              <div>
                <p className="text-xs text-gray-500 mb-1">Messages Captured</p>
                <p className="text-lg font-semibold text-gray-900 dark:text-white">
                  {integration.messages_captured.toLocaleString()}
                </p>
              </div>
              <div>
                <p className="text-xs text-gray-500 mb-1">Last Message</p>
                <p className="text-sm text-gray-900 dark:text-white">
                  {integration.last_message_at
                    ? new Date(integration.last_message_at).toLocaleDateString()
                    : 'Never'}
                </p>
              </div>
              <div>
                <p className="text-xs text-gray-500 mb-1">Channels Monitored</p>
                <p className="text-sm text-gray-900 dark:text-white">
                  {integration.monitored_channels.length}
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 ml-4">
          <Button variant="outline" size="sm">
            <Settings className="w-4 h-4" />
          </Button>
          <Button variant="outline" size="sm" onClick={onDelete}>
            <Trash2 className="w-4 h-4 text-red-600" />
          </Button>
        </div>
      </div>
    </Card>
  );
}

export default IntegrationManagementDashboard;
