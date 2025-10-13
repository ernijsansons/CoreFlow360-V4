/**
 * OAuth Callback Success/Error Pages
 * Handles OAuth redirects for Gmail, Outlook, and Teams integrations
 */

import { useEffect, useState } from 'react';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { CheckCircle, XCircle, AlertTriangle, ArrowRight, RefreshCw } from 'lucide-react';
import { createFileRoute } from '@tanstack/react-router';

export const Route = createFileRoute('/crm/integrations/oauth-callback')({
  component: OAuthCallback
});

function OAuthCallback() {
  const searchParams = useSearch({ from: '/crm/integrations/oauth-callback' });
  const navigate = useNavigate();
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [provider, setProvider] = useState<string>('');
  const [errorMessage, setErrorMessage] = useState<string>('');

  useEffect(() => {
    // Extract provider from pathname
    const path = window.location.pathname;
    const providerMatch = path.match(/\/(gmail|outlook|teams)\//);

    if (providerMatch) {
      const detectedProvider = providerMatch[1];
      setProvider(detectedProvider);

      // Check for success or error
      if (path.includes('/success')) {
        setStatus('success');
      } else if (path.includes('/error')) {
        setStatus('error');
        const message = (searchParams as any).message || 'Unknown error occurred';
        setErrorMessage(decodeURIComponent(message));
      }
    }
  }, [searchParams]);

  const handleReturnToDashboard = () => {
    navigate({ to: '/crm/integrations' });
  };

  const handleRetry = () => {
    // Redirect back to authorization URL
    navigate({ to: '/crm/integrations/setup' });
  };

  if (status === 'loading') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
        <Card className="p-12 max-w-md w-full text-center">
          <div className="animate-spin rounded-full h-16 w-16 border-b-4 border-brand-primary mx-auto mb-6"></div>
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
            Processing...
          </h2>
          <p className="text-gray-600 dark:text-gray-400">
            Please wait while we complete your integration setup
          </p>
        </Card>
      </div>
    );
  }

  if (status === 'success') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 p-4">
        <Card className="p-12 max-w-md w-full">
          <div className="text-center">
            <div className="inline-flex items-center justify-center w-20 h-20 rounded-full bg-green-100 mb-6">
              <CheckCircle className="w-12 h-12 text-green-600" />
            </div>

            <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-3">
              Integration Successful!
            </h1>

            <p className="text-lg text-gray-600 dark:text-gray-400 mb-2">
              Your {getProviderName(provider)} account has been connected
            </p>

            <p className="text-sm text-gray-500 dark:text-gray-500 mb-8">
              We'll start capturing your {getDataType(provider)} automatically
            </p>

            <div className="space-y-3">
              <Button
                onClick={handleReturnToDashboard}
                className="w-full bg-brand-primary hover:bg-brand-primary/90"
              >
                Go to Integrations Dashboard
                <ArrowRight className="w-4 h-4 ml-2" />
              </Button>

              <Button
                variant="outline"
                onClick={() => navigate({ to: '/crm/integrations/setup' })}
                className="w-full"
              >
                Add Another Integration
              </Button>
            </div>

            <div className="mt-8 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
              <h3 className="font-semibold text-gray-900 dark:text-white mb-2">
                What happens next?
              </h3>
              <ul className="text-sm text-gray-600 dark:text-gray-400 space-y-1 text-left">
                <li>• Your {getDataType(provider)} will be synced automatically</li>
                <li>• Contacts and companies will be linked automatically</li>
                <li>• All interactions will appear in your CRM timeline</li>
                <li>• You can view sync status in the integrations dashboard</li>
              </ul>
            </div>
          </div>
        </Card>
      </div>
    );
  }

  if (status === 'error') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 p-4">
        <Card className="p-12 max-w-md w-full">
          <div className="text-center">
            <div className="inline-flex items-center justify-center w-20 h-20 rounded-full bg-red-100 mb-6">
              <XCircle className="w-12 h-12 text-red-600" />
            </div>

            <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-3">
              Integration Failed
            </h1>

            <p className="text-lg text-gray-600 dark:text-gray-400 mb-6">
              We couldn't connect your {getProviderName(provider)} account
            </p>

            <Alert variant="destructive" className="mb-8 text-left">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                {errorMessage}
              </AlertDescription>
            </Alert>

            <div className="space-y-3">
              <Button
                onClick={handleRetry}
                className="w-full bg-brand-primary hover:bg-brand-primary/90"
              >
                <RefreshCw className="w-4 h-4 mr-2" />
                Try Again
              </Button>

              <Button
                variant="outline"
                onClick={handleReturnToDashboard}
                className="w-full"
              >
                Return to Dashboard
              </Button>
            </div>

            <div className="mt-8 p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
              <h3 className="font-semibold text-gray-900 dark:text-white mb-2">
                Common Issues:
              </h3>
              <ul className="text-sm text-gray-600 dark:text-gray-400 space-y-1 text-left">
                <li>• Make sure you granted all required permissions</li>
                <li>• Check your internet connection</li>
                <li>• Try using a different browser</li>
                <li>• Contact support if the issue persists</li>
              </ul>
            </div>
          </div>
        </Card>
      </div>
    );
  }

  return null;
}

function getProviderName(provider: string): string {
  const names: Record<string, string> = {
    gmail: 'Gmail',
    outlook: 'Outlook',
    teams: 'Microsoft Teams'
  };
  return names[provider] || provider;
}

function getDataType(provider: string): string {
  const types: Record<string, string> = {
    gmail: 'emails',
    outlook: 'emails and calendar events',
    teams: 'messages and meetings'
  };
  return types[provider] || 'data';
}

export default OAuthCallback;
