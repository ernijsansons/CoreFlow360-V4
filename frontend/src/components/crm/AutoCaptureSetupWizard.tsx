/**
 * Auto-Capture Setup Wizard
 * Multi-step wizard for setting up email, call, and chat integrations
 */

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Progress } from '@/components/ui/progress';
import {
  Mail, Phone, MessageCircle, Check, ChevronRight, ChevronLeft,
  AlertCircle, ExternalLink, Settings, Zap
} from 'lucide-react';
import apiClient from '@/lib/api/client';

type IntegrationType = 'email' | 'call' | 'chat';
type EmailProvider = 'gmail' | 'outlook' | 'exchange' | 'imap';
type CallProvider = 'twilio' | 'aircall' | 'dialpad' | 'ringcentral';

interface Integration {
  id: string;
  type: IntegrationType;
  provider: string;
  status: 'connected' | 'disconnected' | 'error';
  last_sync?: string;
  items_synced?: number;
}

const INTEGRATION_OPTIONS = {
  email: [
    {
      provider: 'gmail' as EmailProvider,
      name: 'Gmail',
      description: 'Connect your Gmail account for automatic email tracking',
      icon: '📧',
      features: ['Auto-sync emails', 'Contact linking', 'Sentiment analysis'],
      setup_url: '/integrations/gmail'
    },
    {
      provider: 'outlook' as EmailProvider,
      name: 'Outlook',
      description: 'Microsoft Outlook/Office 365 integration',
      icon: '📨',
      features: ['Auto-sync emails', 'Calendar sync', 'Contact linking'],
      setup_url: '/integrations/outlook'
    },
    {
      provider: 'exchange' as EmailProvider,
      name: 'Exchange',
      description: 'On-premise Exchange server integration',
      icon: '✉️',
      features: ['Enterprise email sync', 'Advanced security'],
      setup_url: '/integrations/exchange'
    },
    {
      provider: 'imap' as EmailProvider,
      name: 'IMAP/SMTP',
      description: 'Generic IMAP/SMTP email integration',
      icon: '📮',
      features: ['Any email provider', 'Custom configuration'],
      setup_url: '/integrations/imap'
    }
  ],
  call: [
    {
      provider: 'twilio' as CallProvider,
      name: 'Twilio',
      description: 'Twilio voice and SMS integration',
      icon: '☎️',
      features: ['Call recording', 'Auto-transcription', 'SMS tracking'],
      setup_url: '/integrations/twilio'
    },
    {
      provider: 'aircall' as CallProvider,
      name: 'Aircall',
      description: 'Cloud-based call center software',
      icon: '📞',
      features: ['Call tracking', 'Analytics', 'Team collaboration'],
      setup_url: '/integrations/aircall'
    },
    {
      provider: 'dialpad' as CallProvider,
      name: 'Dialpad',
      description: 'AI-powered business communications',
      icon: '📱',
      features: ['Real-time transcription', 'Voice intelligence', 'Call routing'],
      setup_url: '/integrations/dialpad'
    },
    {
      provider: 'ringcentral' as CallProvider,
      name: 'RingCentral',
      description: 'Complete business communications platform',
      icon: '🔔',
      features: ['Voice, video, messaging', 'Analytics', 'Team collaboration'],
      setup_url: '/integrations/ringcentral'
    }
  ],
  chat: [
    {
      provider: 'slack',
      name: 'Slack',
      description: 'Capture conversations from Slack channels',
      icon: '💬',
      features: ['Channel monitoring', 'DM tracking', 'Customer engagement'],
      setup_url: '/integrations/slack'
    },
    {
      provider: 'teams',
      name: 'Microsoft Teams',
      description: 'Track Teams conversations and meetings',
      icon: '👥',
      features: ['Chat capture', 'Meeting transcripts', 'Team collaboration'],
      setup_url: '/integrations/teams'
    },
    {
      provider: 'intercom',
      name: 'Intercom',
      description: 'Customer messaging and support platform',
      icon: '💭',
      features: ['Live chat', 'Customer support', 'Automated responses'],
      setup_url: '/integrations/intercom'
    }
  ]
};

export function AutoCaptureSetupWizard() {
  const [currentStep, setCurrentStep] = useState(0);
  const [selectedType, setSelectedType] = useState<IntegrationType | null>(null);
  const [selectedProvider, setSelectedProvider] = useState<string | null>(null);
  const queryClient = useQueryClient();

  // Fetch existing integrations
  const { data: integrations } = useQuery({
    queryKey: ['integrations', 'auto-capture'],
    queryFn: async () => {
      // In production, this would fetch from API
      return [] as Integration[];
    }
  });

  const steps = [
    { title: 'Choose Type', description: 'Select integration type' },
    { title: 'Select Provider', description: 'Choose your provider' },
    { title: 'Configure', description: 'Set up connection' },
    { title: 'Test & Activate', description: 'Verify and enable' }
  ];

  const progress = ((currentStep + 1) / steps.length) * 100;

  const handleNext = () => {
    if (currentStep < steps.length - 1) {
      setCurrentStep(currentStep + 1);
    }
  };

  const handleBack = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleReset = () => {
    setCurrentStep(0);
    setSelectedType(null);
    setSelectedProvider(null);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Auto-Capture Setup</h1>
        <p className="text-gray-600 dark:text-gray-400 mt-1">
          Automatically capture and analyze all customer interactions
        </p>
      </div>

      {/* Existing Integrations */}
      {integrations && integrations.length > 0 && (
        <Card className="p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Active Integrations
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {integrations.map((integration) => (
              <IntegrationCard key={integration.id} integration={integration} />
            ))}
          </div>
        </Card>
      )}

      {/* Setup Wizard */}
      <Card className="p-6">
        {/* Progress Bar */}
        <div className="mb-8">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
              Step {currentStep + 1} of {steps.length}
            </span>
            <span className="text-sm text-gray-600 dark:text-gray-400">
              {Math.round(progress)}% Complete
            </span>
          </div>
          <Progress value={progress} className="h-2" />

          {/* Step Indicators */}
          <div className="grid grid-cols-4 gap-2 mt-4">
            {steps.map((step, idx) => (
              <div
                key={idx}
                className={`text-center p-3 rounded-lg transition-all ${
                  idx === currentStep
                    ? 'bg-brand-primary text-white'
                    : idx < currentStep
                    ? 'bg-green-100 text-green-800 dark:bg-green-900/20'
                    : 'bg-gray-100 text-gray-600 dark:bg-gray-800'
                }`}
              >
                <div className="font-medium text-sm">{step.title}</div>
                <div className="text-xs mt-1 opacity-75">{step.description}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Step Content */}
        <div className="min-h-[400px]">
          {currentStep === 0 && (
            <Step1SelectType
              selectedType={selectedType}
              onSelectType={(type) => {
                setSelectedType(type);
                setSelectedProvider(null);
              }}
            />
          )}

          {currentStep === 1 && selectedType && (
            <Step2SelectProvider
              integrationType={selectedType}
              selectedProvider={selectedProvider}
              onSelectProvider={setSelectedProvider}
            />
          )}

          {currentStep === 2 && selectedType && selectedProvider && (
            <Step3Configure
              integrationType={selectedType}
              provider={selectedProvider}
            />
          )}

          {currentStep === 3 && (
            <Step4TestActivate
              integrationType={selectedType!}
              provider={selectedProvider!}
              onComplete={handleReset}
            />
          )}
        </div>

        {/* Navigation */}
        <div className="flex items-center justify-between mt-8 pt-6 border-t">
          <Button
            variant="outline"
            onClick={handleBack}
            disabled={currentStep === 0}
          >
            <ChevronLeft className="w-4 h-4 mr-2" />
            Back
          </Button>

          <Button
            onClick={handleNext}
            disabled={
              (currentStep === 0 && !selectedType) ||
              (currentStep === 1 && !selectedProvider) ||
              currentStep === steps.length - 1
            }
            className="bg-brand-primary hover:bg-brand-primary/90"
          >
            {currentStep === steps.length - 1 ? 'Complete' : 'Next'}
            <ChevronRight className="w-4 h-4 ml-2" />
          </Button>
        </div>
      </Card>
    </div>
  );
}

// Step 1: Select Integration Type
function Step1SelectType({
  selectedType,
  onSelectType
}: {
  selectedType: IntegrationType | null;
  onSelectType: (type: IntegrationType) => void;
}) {
  const types = [
    {
      type: 'email' as IntegrationType,
      icon: Mail,
      title: 'Email Integration',
      description: 'Automatically capture and analyze email conversations',
      benefits: ['Auto-sync emails', 'Sentiment analysis', 'Contact linking', 'Activity tracking'],
      color: 'from-blue-500 to-blue-600'
    },
    {
      type: 'call' as IntegrationType,
      icon: Phone,
      title: 'Call Integration',
      description: 'Track and transcribe phone calls automatically',
      benefits: ['Call recording', 'Auto-transcription', 'Sentiment analysis', 'Action items'],
      color: 'from-green-500 to-green-600'
    },
    {
      type: 'chat' as IntegrationType,
      icon: MessageCircle,
      title: 'Chat Integration',
      description: 'Capture conversations from chat platforms',
      benefits: ['Live chat tracking', 'Multi-channel support', 'Real-time insights'],
      color: 'from-purple-500 to-purple-600'
    }
  ];

  return (
    <div>
      <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
        Choose Integration Type
      </h2>
      <p className="text-gray-600 dark:text-gray-400 mb-6">
        Select the type of integration you want to set up
      </p>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {types.map((item) => {
          const Icon = item.icon;
          const isSelected = selectedType === item.type;

          return (
            <Card
              key={item.type}
              className={`p-6 cursor-pointer transition-all hover:shadow-lg ${
                isSelected ? 'ring-2 ring-brand-primary border-brand-primary' : ''
              }`}
              onClick={() => onSelectType(item.type)}
            >
              <div className={`w-12 h-12 rounded-lg bg-gradient-to-br ${item.color} flex items-center justify-center mb-4`}>
                <Icon className="w-6 h-6 text-white" />
              </div>

              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                {item.title}
              </h3>
              <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                {item.description}
              </p>

              <div className="space-y-2">
                {item.benefits.map((benefit, idx) => (
                  <div key={idx} className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                    <Check className="w-4 h-4 text-green-500" />
                    <span>{benefit}</span>
                  </div>
                ))}
              </div>

              {isSelected && (
                <Badge className="mt-4 bg-brand-primary text-white">
                  <Check className="w-3 h-3 mr-1" />
                  Selected
                </Badge>
              )}
            </Card>
          );
        })}
      </div>
    </div>
  );
}

// Step 2: Select Provider
function Step2SelectProvider({
  integrationType,
  selectedProvider,
  onSelectProvider
}: {
  integrationType: IntegrationType;
  selectedProvider: string | null;
  onSelectProvider: (provider: string) => void;
}) {
  const providers = INTEGRATION_OPTIONS[integrationType];

  return (
    <div>
      <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
        Select Provider
      </h2>
      <p className="text-gray-600 dark:text-gray-400 mb-6">
        Choose your {integrationType} provider
      </p>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {providers.map((provider) => {
          const isSelected = selectedProvider === provider.provider;

          return (
            <Card
              key={provider.provider}
              className={`p-6 cursor-pointer transition-all hover:shadow-lg ${
                isSelected ? 'ring-2 ring-brand-primary border-brand-primary' : ''
              }`}
              onClick={() => onSelectProvider(provider.provider)}
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="text-3xl">{provider.icon}</div>
                  <div>
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                      {provider.name}
                    </h3>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                      {provider.description}
                    </p>
                  </div>
                </div>
                {isSelected && (
                  <Check className="w-5 h-5 text-brand-primary" />
                )}
              </div>

              <div className="space-y-2">
                {provider.features.map((feature, idx) => (
                  <div key={idx} className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                    <Zap className="w-4 h-4 text-brand-accent" />
                    <span>{feature}</span>
                  </div>
                ))}
              </div>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

// Step 3: Configure
function Step3Configure({
  integrationType,
  provider
}: {
  integrationType: IntegrationType;
  provider: string;
}) {
  return (
    <div>
      <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
        Configure Integration
      </h2>
      <p className="text-gray-600 dark:text-gray-400 mb-6">
        Set up your {provider} integration
      </p>

      <Alert className="mb-6">
        <Settings className="h-4 w-4" />
        <AlertDescription>
          You'll be redirected to {provider} to authorize CoreFlow360 to access your account.
          This is secure and you can revoke access at any time.
        </AlertDescription>
      </Alert>

      <Card className="p-6 bg-gray-50 dark:bg-gray-800">
        <h3 className="font-medium text-gray-900 dark:text-white mb-4">
          What we'll access:
        </h3>
        <ul className="space-y-2 text-sm text-gray-700 dark:text-gray-300">
          <li className="flex items-center gap-2">
            <Check className="w-4 h-4 text-green-500" />
            Read {integrationType} messages and metadata
          </li>
          <li className="flex items-center gap-2">
            <Check className="w-4 h-4 text-green-500" />
            Access contact information for auto-linking
          </li>
          <li className="flex items-center gap-2">
            <Check className="w-4 h-4 text-green-500" />
            Create activities in your CRM
          </li>
        </ul>

        <Button className="mt-6 w-full bg-brand-primary hover:bg-brand-primary/90">
          <ExternalLink className="w-4 h-4 mr-2" />
          Connect {provider} Account
        </Button>
      </Card>
    </div>
  );
}

// Step 4: Test & Activate
function Step4TestActivate({
  integrationType,
  provider,
  onComplete
}: {
  integrationType: IntegrationType;
  provider: string;
  onComplete: () => void;
}) {
  return (
    <div className="text-center py-8">
      <div className="w-20 h-20 bg-green-100 dark:bg-green-900/20 rounded-full flex items-center justify-center mx-auto mb-6">
        <Check className="w-10 h-10 text-green-600 dark:text-green-400" />
      </div>

      <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
        Integration Active!
      </h2>
      <p className="text-gray-600 dark:text-gray-400 mb-8">
        Your {provider} {integrationType} integration is now capturing interactions
      </p>

      <Card className="p-6 bg-gradient-to-br from-brand-primary/10 to-brand-accent/10 border-brand-primary/20 mb-6">
        <div className="grid grid-cols-3 gap-4 text-center">
          <div>
            <div className="text-3xl font-bold text-brand-primary">0</div>
            <div className="text-sm text-gray-600 dark:text-gray-400 mt-1">Captured Today</div>
          </div>
          <div>
            <div className="text-3xl font-bold text-brand-primary">0</div>
            <div className="text-sm text-gray-600 dark:text-gray-400 mt-1">Auto-Linked</div>
          </div>
          <div>
            <div className="text-3xl font-bold text-brand-primary">100%</div>
            <div className="text-sm text-gray-600 dark:text-gray-400 mt-1">Success Rate</div>
          </div>
        </div>
      </Card>

      <div className="flex gap-3 justify-center">
        <Button variant="outline">
          View Captured Interactions
        </Button>
        <Button onClick={onComplete} className="bg-brand-primary hover:bg-brand-primary/90">
          Set Up Another Integration
        </Button>
      </div>
    </div>
  );
}

// Integration Card Component
function IntegrationCard({ integration }: { integration: Integration }) {
  const statusConfig = {
    connected: { color: 'bg-green-100 text-green-800', icon: Check },
    disconnected: { color: 'bg-gray-100 text-gray-800', icon: AlertCircle },
    error: { color: 'bg-red-100 text-red-800', icon: AlertCircle }
  };

  const config = statusConfig[integration.status];
  const Icon = config.icon;

  return (
    <Card className="p-4">
      <div className="flex items-start justify-between mb-3">
        <div>
          <h3 className="font-medium text-gray-900 dark:text-white capitalize">
            {integration.provider}
          </h3>
          <p className="text-sm text-gray-600 dark:text-gray-400 capitalize">
            {integration.type}
          </p>
        </div>
        <Badge className={config.color}>
          <Icon className="w-3 h-3 mr-1" />
          {integration.status}
        </Badge>
      </div>

      {integration.last_sync && (
        <div className="text-xs text-gray-500">
          Last synced: {new Date(integration.last_sync).toLocaleString()}
        </div>
      )}

      {integration.items_synced !== undefined && (
        <div className="text-xs text-gray-500">
          {integration.items_synced.toLocaleString()} items captured
        </div>
      )}

      <Button size="sm" variant="outline" className="w-full mt-3">
        <Settings className="w-4 h-4 mr-2" />
        Configure
      </Button>
    </Card>
  );
}

export default AutoCaptureSetupWizard;
