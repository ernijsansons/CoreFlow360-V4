/**
 * Integration Testing UI
 * Test connection, sync, and validate integration setup
 */

import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import {
  CheckCircle, XCircle, Loader2, Play, RefreshCw, Settings,
  Mail, Phone, MessageSquare, AlertTriangle, Clock
} from 'lucide-react';
import apiClient from '@/lib/api/client';

interface IntegrationTestUIProps {
  provider: 'gmail' | 'outlook' | 'twilio' | 'slack' | 'teams';
  integrationId?: string;
}

interface TestResult {
  test_name: string;
  status: 'passed' | 'failed' | 'warning';
  message: string;
  details?: any;
  duration_ms?: number;
}

interface TestSuite {
  overall_status: 'passed' | 'failed' | 'partial';
  tests: TestResult[];
  total_duration_ms: number;
}

const PROVIDER_ICONS = {
  gmail: Mail,
  outlook: Mail,
  twilio: Phone,
  slack: MessageSquare,
  teams: MessageSquare
};

const PROVIDER_NAMES = {
  gmail: 'Gmail',
  outlook: 'Outlook',
  twilio: 'Twilio',
  slack: 'Slack',
  teams: 'Microsoft Teams'
};

export function IntegrationTestUI({ provider, integrationId }: IntegrationTestUIProps) {
  const [testResults, setTestResults] = useState<TestSuite | null>(null);
  const ProviderIcon = PROVIDER_ICONS[provider];
  const providerName = PROVIDER_NAMES[provider];

  // Connection Test
  const connectionTest = useMutation({
    mutationFn: async () => {
      const response = await apiClient.post(`/api/v1/crm/integrations/${provider}/test`, {
        integration_id: integrationId
      });
      return response.data.data as TestSuite;
    },
    onSuccess: (data) => {
      setTestResults(data);
    }
  });

  // Sync Test
  const syncTest = useMutation({
    mutationFn: async () => {
      const response = await apiClient.post(`/api/v1/crm/integrations/${provider}/test-sync`, {
        integration_id: integrationId,
        limit: 5 // Test with 5 items only
      });
      return response.data.data;
    }
  });

  // Webhook Test (for Twilio, Slack, Teams)
  const webhookTest = useMutation({
    mutationFn: async () => {
      const response = await apiClient.post(`/api/v1/crm/integrations/${provider}/test-webhook`, {
        integration_id: integrationId
      });
      return response.data.data;
    }
  });

  const runAllTests = async () => {
    await connectionTest.mutateAsync();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card className="p-6 bg-gradient-to-br from-brand-primary/10 to-brand-accent/10 border-brand-primary/20">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <ProviderIcon className="w-8 h-8 text-brand-primary" />
            <div>
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
                Test {providerName} Integration
              </h2>
              <p className="text-gray-600 dark:text-gray-400 mt-1">
                Verify connection, sync, and configuration
              </p>
            </div>
          </div>
        </div>
      </Card>

      {/* Test Actions */}
      <Card className="p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Test Suite
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <Button
            onClick={() => connectionTest.mutate()}
            disabled={connectionTest.isPending}
            className="w-full"
          >
            {connectionTest.isPending ? (
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <Play className="w-4 h-4 mr-2" />
            )}
            Connection Test
          </Button>

          <Button
            onClick={() => syncTest.mutate()}
            disabled={syncTest.isPending}
            className="w-full"
            variant="outline"
          >
            {syncTest.isPending ? (
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <RefreshCw className="w-4 h-4 mr-2" />
            )}
            Test Sync (5 items)
          </Button>

          {['twilio', 'slack', 'teams'].includes(provider) && (
            <Button
              onClick={() => webhookTest.mutate()}
              disabled={webhookTest.isPending}
              className="w-full"
              variant="outline"
            >
              {webhookTest.isPending ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <Settings className="w-4 h-4 mr-2" />
              )}
              Test Webhook
            </Button>
          )}
        </div>

        <div className="mt-4">
          <Button
            onClick={runAllTests}
            disabled={connectionTest.isPending}
            className="w-full bg-brand-primary hover:bg-brand-primary/90"
          >
            {connectionTest.isPending ? (
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <Play className="w-4 h-4 mr-2" />
            )}
            Run All Tests
          </Button>
        </div>
      </Card>

      {/* Test Results */}
      {testResults && (
        <Card className="p-6">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Test Results
            </h3>
            <div className="flex items-center gap-3">
              <Badge
                className={
                  testResults.overall_status === 'passed'
                    ? 'bg-green-100 text-green-800 border-green-200'
                    : testResults.overall_status === 'partial'
                    ? 'bg-yellow-100 text-yellow-800 border-yellow-200'
                    : 'bg-red-100 text-red-800 border-red-200'
                }
              >
                {testResults.overall_status === 'passed' && <CheckCircle className="w-3 h-3 mr-1" />}
                {testResults.overall_status === 'failed' && <XCircle className="w-3 h-3 mr-1" />}
                {testResults.overall_status === 'partial' && <AlertTriangle className="w-3 h-3 mr-1" />}
                {testResults.overall_status.toUpperCase()}
              </Badge>
              <div className="flex items-center gap-1 text-sm text-gray-600 dark:text-gray-400">
                <Clock className="w-4 h-4" />
                {testResults.total_duration_ms}ms
              </div>
            </div>
          </div>

          <div className="space-y-3">
            {testResults.tests.map((test, index) => (
              <TestResultCard key={index} result={test} />
            ))}
          </div>
        </Card>
      )}

      {/* Sync Test Results */}
      {syncTest.isSuccess && syncTest.data && (
        <Card className="p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Sync Test Results
          </h3>
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-4">
              <div>
                <p className="text-sm text-gray-500 mb-1">Items Processed</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {syncTest.data.items_processed || 0}
                </p>
              </div>
              <div>
                <p className="text-sm text-gray-500 mb-1">Items Captured</p>
                <p className="text-2xl font-bold text-green-600">
                  {syncTest.data.items_captured || 0}
                </p>
              </div>
              <div>
                <p className="text-sm text-gray-500 mb-1">Errors</p>
                <p className="text-2xl font-bold text-red-600">
                  {syncTest.data.errors?.length || 0}
                </p>
              </div>
            </div>

            {syncTest.data.errors && syncTest.data.errors.length > 0 && (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  <div className="font-semibold mb-2">Sync Errors:</div>
                  <ul className="space-y-1 text-sm">
                    {syncTest.data.errors.map((error: string, index: number) => (
                      <li key={index}>• {error}</li>
                    ))}
                  </ul>
                </AlertDescription>
              </Alert>
            )}
          </div>
        </Card>
      )}

      {/* Webhook Test Results */}
      {webhookTest.isSuccess && webhookTest.data && (
        <Card className="p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Webhook Test Results
          </h3>
          {webhookTest.data.success ? (
            <Alert>
              <CheckCircle className="h-4 w-4" />
              <AlertDescription>
                Webhook is correctly configured and responding
              </AlertDescription>
            </Alert>
          ) : (
            <Alert variant="destructive">
              <XCircle className="h-4 w-4" />
              <AlertDescription>
                {webhookTest.data.message || 'Webhook test failed'}
              </AlertDescription>
            </Alert>
          )}
        </Card>
      )}

      {/* Error Display */}
      {connectionTest.isError && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            Failed to run tests. Please check your integration configuration.
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
}

function TestResultCard({ result }: { result: TestResult }) {
  const statusIcons = {
    passed: CheckCircle,
    failed: XCircle,
    warning: AlertTriangle
  };

  const statusColors = {
    passed: 'text-green-600',
    failed: 'text-red-600',
    warning: 'text-yellow-600'
  };

  const StatusIcon = statusIcons[result.status];
  const statusColor = statusColors[result.status];

  return (
    <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-3 flex-1">
          <StatusIcon className={`w-5 h-5 mt-0.5 ${statusColor}`} />
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-1">
              <h4 className="font-semibold text-gray-900 dark:text-white">
                {result.test_name}
              </h4>
              {result.duration_ms && (
                <span className="text-xs text-gray-500">
                  ({result.duration_ms}ms)
                </span>
              )}
            </div>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              {result.message}
            </p>

            {result.details && (
              <div className="mt-2 p-2 bg-gray-50 dark:bg-gray-800 rounded text-xs">
                <pre className="whitespace-pre-wrap text-gray-700 dark:text-gray-300">
                  {typeof result.details === 'string'
                    ? result.details
                    : JSON.stringify(result.details, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default IntegrationTestUI;
