/**
 * Integration Configuration Forms
 * Provider-specific configuration forms for detailed settings
 */

import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Alert, AlertDescription } from '@/components/ui/alert';
import {
  Save, AlertTriangle, CheckCircle, Mail, Phone, MessageSquare,
  Settings, Key, Globe
} from 'lucide-react';
import apiClient from '@/lib/api/client';

interface IntegrationConfigFormProps {
  provider: 'gmail' | 'outlook' | 'twilio' | 'slack' | 'teams';
  existingConfig?: any;
  onSuccess?: () => void;
  onCancel?: () => void;
}

export function IntegrationConfigForm({
  provider,
  existingConfig,
  onSuccess,
  onCancel
}: IntegrationConfigFormProps) {
  switch (provider) {
    case 'gmail':
      return <GmailConfigForm existingConfig={existingConfig} onSuccess={onSuccess} onCancel={onCancel} />;
    case 'outlook':
      return <OutlookConfigForm existingConfig={existingConfig} onSuccess={onSuccess} onCancel={onCancel} />;
    case 'twilio':
      return <TwilioConfigForm existingConfig={existingConfig} onSuccess={onSuccess} onCancel={onCancel} />;
    case 'slack':
      return <SlackConfigForm existingConfig={existingConfig} onSuccess={onSuccess} onCancel={onCancel} />;
    case 'teams':
      return <TeamsConfigForm existingConfig={existingConfig} onSuccess={onSuccess} onCancel={onCancel} />;
    default:
      return <div>Unknown provider</div>;
  }
}

// ============================================================
// GMAIL CONFIG FORM
// ============================================================

function GmailConfigForm({ existingConfig, onSuccess, onCancel }: any) {
  const [config, setConfig] = useState({
    sync_enabled: existingConfig?.sync_enabled ?? true,
    auto_create_activities: existingConfig?.auto_create_activities ?? true,
    auto_link_contacts: existingConfig?.auto_link_contacts ?? true,
    sync_sent_emails: existingConfig?.sync_sent_emails ?? true,
    sync_labels: existingConfig?.sync_labels ?? ['INBOX', 'SENT'],
    max_results_per_sync: existingConfig?.max_results_per_sync ?? 50
  });

  const queryClient = useQueryClient();

  const saveMutation = useMutation({
    mutationFn: async () => {
      await apiClient.put('/api/v1/crm/integrations/gmail/config', config);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['crm', 'integrations'] });
      onSuccess?.();
    }
  });

  return (
    <Card className="p-6">
      <div className="flex items-center gap-3 mb-6">
        <Mail className="w-6 h-6 text-blue-600" />
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
          Gmail Configuration
        </h2>
      </div>

      <div className="space-y-6">
        {/* Sync Settings */}
        <div>
          <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
            Sync Settings
          </h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <Label>Enable Sync</Label>
                <p className="text-xs text-gray-500">Automatically sync emails from Gmail</p>
              </div>
              <Switch
                checked={config.sync_enabled}
                onCheckedChange={(checked) => setConfig({ ...config, sync_enabled: checked })}
              />
            </div>

            <div className="flex items-center justify-between">
              <div>
                <Label>Auto-Create Activities</Label>
                <p className="text-xs text-gray-500">Automatically create CRM activities</p>
              </div>
              <Switch
                checked={config.auto_create_activities}
                onCheckedChange={(checked) => setConfig({ ...config, auto_create_activities: checked })}
              />
            </div>

            <div className="flex items-center justify-between">
              <div>
                <Label>Auto-Link Contacts</Label>
                <p className="text-xs text-gray-500">Automatically link to CRM contacts</p>
              </div>
              <Switch
                checked={config.auto_link_contacts}
                onCheckedChange={(checked) => setConfig({ ...config, auto_link_contacts: checked })}
              />
            </div>

            <div className="flex items-center justify-between">
              <div>
                <Label>Sync Sent Emails</Label>
                <p className="text-xs text-gray-500">Include sent emails in sync</p>
              </div>
              <Switch
                checked={config.sync_sent_emails}
                onCheckedChange={(checked) => setConfig({ ...config, sync_sent_emails: checked })}
              />
            </div>
          </div>
        </div>

        {/* Performance Settings */}
        <div>
          <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
            Performance Settings
          </h3>
          <div>
            <Label>Max Results Per Sync</Label>
            <Input
              type="number"
              value={config.max_results_per_sync}
              onChange={(e) => setConfig({ ...config, max_results_per_sync: parseInt(e.target.value) })}
              min={10}
              max={500}
              className="mt-2"
            />
            <p className="text-xs text-gray-500 mt-1">
              Number of emails to sync per run (10-500)
            </p>
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-3 pt-4 border-t border-gray-200 dark:border-gray-700">
          {onCancel && (
            <Button variant="outline" onClick={onCancel}>
              Cancel
            </Button>
          )}
          <Button
            onClick={() => saveMutation.mutate()}
            disabled={saveMutation.isPending}
            className="bg-brand-primary hover:bg-brand-primary/90"
          >
            <Save className="w-4 h-4 mr-2" />
            {saveMutation.isPending ? 'Saving...' : 'Save Configuration'}
          </Button>
        </div>

        {/* Success/Error Messages */}
        {saveMutation.isSuccess && (
          <Alert>
            <CheckCircle className="h-4 w-4" />
            <AlertDescription>Configuration saved successfully!</AlertDescription>
          </Alert>
        )}
        {saveMutation.isError && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>Failed to save configuration. Please try again.</AlertDescription>
          </Alert>
        )}
      </div>
    </Card>
  );
}

// ============================================================
// OUTLOOK CONFIG FORM
// ============================================================

function OutlookConfigForm({ existingConfig, onSuccess, onCancel }: any) {
  const [config, setConfig] = useState({
    sync_enabled: existingConfig?.sync_enabled ?? true,
    auto_create_activities: existingConfig?.auto_create_activities ?? true,
    auto_link_contacts: existingConfig?.auto_link_contacts ?? true,
    sync_calendar: existingConfig?.sync_calendar ?? true,
    sync_sent_emails: existingConfig?.sync_sent_emails ?? true,
    max_results_per_sync: existingConfig?.max_results_per_sync ?? 50
  });

  const queryClient = useQueryClient();

  const saveMutation = useMutation({
    mutationFn: async () => {
      await apiClient.put('/api/v1/crm/integrations/outlook/config', config);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['crm', 'integrations'] });
      onSuccess?.();
    }
  });

  return (
    <Card className="p-6">
      <div className="flex items-center gap-3 mb-6">
        <Mail className="w-6 h-6 text-blue-600" />
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
          Outlook Configuration
        </h2>
      </div>

      <div className="space-y-6">
        <div>
          <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
            Sync Settings
          </h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <Label>Enable Email Sync</Label>
                <p className="text-xs text-gray-500">Sync emails from Outlook/Exchange</p>
              </div>
              <Switch
                checked={config.sync_enabled}
                onCheckedChange={(checked) => setConfig({ ...config, sync_enabled: checked })}
              />
            </div>

            <div className="flex items-center justify-between">
              <div>
                <Label>Sync Calendar</Label>
                <p className="text-xs text-gray-500">Include calendar meetings</p>
              </div>
              <Switch
                checked={config.sync_calendar}
                onCheckedChange={(checked) => setConfig({ ...config, sync_calendar: checked })}
              />
            </div>

            <div className="flex items-center justify-between">
              <div>
                <Label>Auto-Create Activities</Label>
                <p className="text-xs text-gray-500">Automatically log activities in CRM</p>
              </div>
              <Switch
                checked={config.auto_create_activities}
                onCheckedChange={(checked) => setConfig({ ...config, auto_create_activities: checked })}
              />
            </div>

            <div className="flex items-center justify-between">
              <div>
                <Label>Auto-Link Contacts</Label>
                <p className="text-xs text-gray-500">Match emails to CRM contacts</p>
              </div>
              <Switch
                checked={config.auto_link_contacts}
                onCheckedChange={(checked) => setConfig({ ...config, auto_link_contacts: checked })}
              />
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3 pt-4 border-t border-gray-200 dark:border-gray-700">
          {onCancel && (
            <Button variant="outline" onClick={onCancel}>
              Cancel
            </Button>
          )}
          <Button
            onClick={() => saveMutation.mutate()}
            disabled={saveMutation.isPending}
            className="bg-brand-primary hover:bg-brand-primary/90"
          >
            <Save className="w-4 h-4 mr-2" />
            Save Configuration
          </Button>
        </div>

        {saveMutation.isSuccess && (
          <Alert>
            <CheckCircle className="h-4 w-4" />
            <AlertDescription>Configuration saved successfully!</AlertDescription>
          </Alert>
        )}
      </div>
    </Card>
  );
}

// ============================================================
// TWILIO CONFIG FORM
// ============================================================

function TwilioConfigForm({ existingConfig, onSuccess, onCancel }: any) {
  const [config, setConfig] = useState({
    account_sid: existingConfig?.account_sid ?? '',
    auth_token: existingConfig?.auth_token ?? '',
    phone_number: existingConfig?.phone_number ?? '',
    auto_create_activities: existingConfig?.auto_create_activities ?? true,
    auto_transcribe: existingConfig?.auto_transcribe ?? true,
    auto_analyze_sentiment: existingConfig?.auto_analyze_sentiment ?? true
  });

  const queryClient = useQueryClient();

  const saveMutation = useMutation({
    mutationFn: async () => {
      await apiClient.put('/api/v1/crm/integrations/twilio/config', config);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['crm', 'integrations'] });
      onSuccess?.();
    }
  });

  return (
    <Card className="p-6">
      <div className="flex items-center gap-3 mb-6">
        <Phone className="w-6 h-6 text-purple-600" />
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
          Twilio Configuration
        </h2>
      </div>

      <div className="space-y-6">
        <div>
          <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
            API Credentials
          </h3>
          <div className="space-y-4">
            <div>
              <Label>Account SID</Label>
              <Input
                type="text"
                value={config.account_sid}
                onChange={(e) => setConfig({ ...config, account_sid: e.target.value })}
                placeholder="ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                className="mt-2"
              />
            </div>

            <div>
              <Label>Auth Token</Label>
              <Input
                type="password"
                value={config.auth_token}
                onChange={(e) => setConfig({ ...config, auth_token: e.target.value })}
                placeholder="••••••••••••••••••••••••••••••••"
                className="mt-2"
              />
            </div>

            <div>
              <Label>Phone Number</Label>
              <Input
                type="tel"
                value={config.phone_number}
                onChange={(e) => setConfig({ ...config, phone_number: e.target.value })}
                placeholder="+1234567890"
                className="mt-2"
              />
            </div>
          </div>
        </div>

        <div>
          <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
            Call Features
          </h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <Label>Auto-Create Activities</Label>
                <p className="text-xs text-gray-500">Log all calls in CRM</p>
              </div>
              <Switch
                checked={config.auto_create_activities}
                onCheckedChange={(checked) => setConfig({ ...config, auto_create_activities: checked })}
              />
            </div>

            <div className="flex items-center justify-between">
              <div>
                <Label>Auto-Transcribe</Label>
                <p className="text-xs text-gray-500">Generate call transcriptions</p>
              </div>
              <Switch
                checked={config.auto_transcribe}
                onCheckedChange={(checked) => setConfig({ ...config, auto_transcribe: checked })}
              />
            </div>

            <div className="flex items-center justify-between">
              <div>
                <Label>Sentiment Analysis</Label>
                <p className="text-xs text-gray-500">Analyze call sentiment with AI</p>
              </div>
              <Switch
                checked={config.auto_analyze_sentiment}
                onCheckedChange={(checked) => setConfig({ ...config, auto_analyze_sentiment: checked })}
              />
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3 pt-4 border-t border-gray-200 dark:border-gray-700">
          {onCancel && (
            <Button variant="outline" onClick={onCancel}>
              Cancel
            </Button>
          )}
          <Button
            onClick={() => saveMutation.mutate()}
            disabled={saveMutation.isPending}
            className="bg-brand-primary hover:bg-brand-primary/90"
          >
            <Save className="w-4 h-4 mr-2" />
            Save Configuration
          </Button>
        </div>

        {saveMutation.isSuccess && (
          <Alert>
            <CheckCircle className="h-4 w-4" />
            <AlertDescription>Configuration saved! Webhook URLs can be found in the dashboard.</AlertDescription>
          </Alert>
        )}
      </div>
    </Card>
  );
}

// ============================================================
// SLACK CONFIG FORM
// ============================================================

function SlackConfigForm({ existingConfig, onSuccess, onCancel }: any) {
  const [config, setConfig] = useState({
    workspace_name: existingConfig?.workspace_name ?? '',
    monitored_channels: existingConfig?.monitored_channels ?? [],
    capture_threads: existingConfig?.capture_threads ?? true,
    capture_mentions: existingConfig?.capture_mentions ?? true,
    capture_direct_messages: existingConfig?.capture_direct_messages ?? false,
    auto_link_customers: existingConfig?.auto_link_customers ?? true
  });

  const queryClient = useQueryClient();

  const saveMutation = useMutation({
    mutationFn: async () => {
      await apiClient.put('/api/v1/crm/integrations/slack/config', config);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['crm', 'integrations'] });
      onSuccess?.();
    }
  });

  return (
    <Card className="p-6">
      <div className="flex items-center gap-3 mb-6">
        <MessageSquare className="w-6 h-6 text-yellow-600" />
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
          Slack Configuration
        </h2>
      </div>

      <div className="space-y-6">
        <div>
          <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
            Capture Settings
          </h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <Label>Capture Threads</Label>
                <p className="text-xs text-gray-500">Include thread replies</p>
              </div>
              <Switch
                checked={config.capture_threads}
                onCheckedChange={(checked) => setConfig({ ...config, capture_threads: checked })}
              />
            </div>

            <div className="flex items-center justify-between">
              <div>
                <Label>Capture Mentions</Label>
                <p className="text-xs text-gray-500">Track when users are mentioned</p>
              </div>
              <Switch
                checked={config.capture_mentions}
                onCheckedChange={(checked) => setConfig({ ...config, capture_mentions: checked })}
              />
            </div>

            <div className="flex items-center justify-between">
              <div>
                <Label>Capture DMs</Label>
                <p className="text-xs text-gray-500">Include direct messages</p>
              </div>
              <Switch
                checked={config.capture_direct_messages}
                onCheckedChange={(checked) => setConfig({ ...config, capture_direct_messages: checked })}
              />
            </div>

            <div className="flex items-center justify-between">
              <div>
                <Label>Auto-Link Customers</Label>
                <p className="text-xs text-gray-500">Match to CRM contacts</p>
              </div>
              <Switch
                checked={config.auto_link_customers}
                onCheckedChange={(checked) => setConfig({ ...config, auto_link_customers: checked })}
              />
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3 pt-4 border-t border-gray-200 dark:border-gray-700">
          {onCancel && (
            <Button variant="outline" onClick={onCancel}>
              Cancel
            </Button>
          )}
          <Button
            onClick={() => saveMutation.mutate()}
            disabled={saveMutation.isPending}
            className="bg-brand-primary hover:bg-brand-primary/90"
          >
            <Save className="w-4 h-4 mr-2" />
            Save Configuration
          </Button>
        </div>
      </div>
    </Card>
  );
}

// ============================================================
// TEAMS CONFIG FORM
// ============================================================

function TeamsConfigForm({ existingConfig, onSuccess, onCancel }: any) {
  const [config, setConfig] = useState({
    tenant_name: existingConfig?.tenant_name ?? '',
    capture_messages: existingConfig?.capture_messages ?? true,
    capture_meetings: existingConfig?.capture_meetings ?? true,
    capture_calls: existingConfig?.capture_calls ?? true,
    auto_link_customers: existingConfig?.auto_link_customers ?? true
  });

  const queryClient = useQueryClient();

  const saveMutation = useMutation({
    mutationFn: async () => {
      await apiClient.put('/api/v1/crm/integrations/teams/config', config);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['crm', 'integrations'] });
      onSuccess?.();
    }
  });

  return (
    <Card className="p-6">
      <div className="flex items-center gap-3 mb-6">
        <MessageSquare className="w-6 h-6 text-indigo-600" />
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
          Microsoft Teams Configuration
        </h2>
      </div>

      <div className="space-y-6">
        <div>
          <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
            Capture Settings
          </h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <Label>Capture Messages</Label>
                <p className="text-xs text-gray-500">Include channel messages</p>
              </div>
              <Switch
                checked={config.capture_messages}
                onCheckedChange={(checked) => setConfig({ ...config, capture_messages: checked })}
              />
            </div>

            <div className="flex items-center justify-between">
              <div>
                <Label>Capture Meetings</Label>
                <p className="text-xs text-gray-500">Include online meetings</p>
              </div>
              <Switch
                checked={config.capture_meetings}
                onCheckedChange={(checked) => setConfig({ ...config, capture_meetings: checked })}
              />
            </div>

            <div className="flex items-center justify-between">
              <div>
                <Label>Capture Calls</Label>
                <p className="text-xs text-gray-500">Include Teams calls</p>
              </div>
              <Switch
                checked={config.capture_calls}
                onCheckedChange={(checked) => setConfig({ ...config, capture_calls: checked })}
              />
            </div>

            <div className="flex items-center justify-between">
              <div>
                <Label>Auto-Link Customers</Label>
                <p className="text-xs text-gray-500">Match to CRM contacts</p>
              </div>
              <Switch
                checked={config.auto_link_customers}
                onCheckedChange={(checked) => setConfig({ ...config, auto_link_customers: checked })}
              />
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3 pt-4 border-t border-gray-200 dark:border-gray-700">
          {onCancel && (
            <Button variant="outline" onClick={onCancel}>
              Cancel
            </Button>
          )}
          <Button
            onClick={() => saveMutation.mutate()}
            disabled={saveMutation.isPending}
            className="bg-brand-primary hover:bg-brand-primary/90"
          >
            <Save className="w-4 h-4 mr-2" />
            Save Configuration
          </Button>
        </div>
      </div>
    </Card>
  );
}

export default IntegrationConfigForm;
