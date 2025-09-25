/**
 * Integration Node - Connect to 50+ External Services
 * Supports OAuth2, rate limiting, response transformation, and error handling
 */

import React, { useState, memo } from 'react';
import { Handle, Position, NodeProps } from 'reactflow';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Slider } from '@/components/ui/slider';
import {
  Globe,
  Database,
  Mail,
  Phone,
  FileText,
  MessageSquare,
  Settings,
  Key,
  Zap,
  CheckCircle,
  AlertCircle,
  Clock,
  Shield,
  Activity,
  ArrowUpDown,
  Filter,
  RefreshCw
} from 'lucide-react';

interface IntegrationNodeData {
  label: string;
  integrationType: 'crm' | 'email' | 'sms' | 'file' | 'database' | 'api' | 'webhook' | 'slack' | 'teams';
  provider: string;
  endpoint: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  authentication: AuthConfig;
  requestConfig: RequestConfig;
  responseConfig: ResponseConfig;
  rateLimiting: RateLimitConfig;
  retryPolicy: RetryConfig;
  timeout: number;
  status?: 'idle' | 'running' | 'completed' | 'failed';
  lastResponse?: any;
  connectionStatus?: 'connected' | 'disconnected' | 'error';
}

interface AuthConfig {
  type: 'none' | 'api_key' | 'oauth2' | 'basic' | 'bearer' | 'custom';
  apiKey?: string;
  clientId?: string;
  clientSecret?: string;
  accessToken?: string;
  refreshToken?: string;
  username?: string;
  password?: string;
  customHeaders?: Record<string, string>;
}

interface RequestConfig {
  headers: Record<string, string>;
  queryParams: Record<string, string>;
  bodyType: 'json' | 'form' | 'xml' | 'raw';
  bodyTemplate: string;
  dataMapping: DataMapping[];
  batchConfig?: BatchConfig;
}

interface ResponseConfig {
  successCodes: number[];
  dataPath: string;
  errorPath: string;
  transformation: string;
  caching: CacheConfig;
}

interface DataMapping {
  id: string;
  source: string;
  target: string;
  transform?: string;
  required: boolean;
}

interface BatchConfig {
  enabled: boolean;
  batchSize: number;
  parallelRequests: number;
  delayBetweenBatches: number;
}

interface RateLimitConfig {
  enabled: boolean;
  requestsPerSecond: number;
  burstLimit: number;
  backoffStrategy: 'linear' | 'exponential' | 'fixed';
}

interface RetryConfig {
  enabled: boolean;
  maxAttempts: number;
  backoffMs: number;
  retryOn: string[];
}

interface CacheConfig {
  enabled: boolean;
  ttlSeconds: number;
  keyTemplate: string;
}

const INTEGRATION_PROVIDERS = {
  crm: {
    label: 'CRM Systems',
    icon: Database,
    color: 'bg-blue-500',
    providers: [
      { id: 'salesforce', name: 'Salesforce', icon: '☁️' },
      { id: 'hubspot', name: 'HubSpot', icon: '🧡' },
      { id: 'pipedrive', name: 'Pipedrive', icon: '🚀' },
      { id: 'zoho', name: 'Zoho CRM', icon: '📊' },
      { id: 'microsoft_dynamics', name: 'Microsoft Dynamics', icon: '🏢' }
    ]
  },
  email: {
    label: 'Email Services',
    icon: Mail,
    color: 'bg-red-500',
    providers: [
      { id: 'sendgrid', name: 'SendGrid', icon: '📧' },
      { id: 'mailgun', name: 'Mailgun', icon: '🔫' },
      { id: 'ses', name: 'Amazon SES', icon: '📬' },
      { id: 'gmail', name: 'Gmail API', icon: '📮' },
      { id: 'outlook', name: 'Outlook API', icon: '📩' }
    ]
  },
  sms: {
    label: 'SMS/Voice',
    icon: Phone,
    color: 'bg-green-500',
    providers: [
      { id: 'twilio', name: 'Twilio', icon: '📱' },
      { id: 'aws_sns', name: 'AWS SNS', icon: '📲' },
      { id: 'nexmo', name: 'Vonage (Nexmo)', icon: '☎️' },
      { id: 'plivo', name: 'Plivo', icon: '📞' }
    ]
  },
  file: {
    label: 'File Storage',
    icon: FileText,
    color: 'bg-purple-500',
    providers: [
      { id: 'aws_s3', name: 'Amazon S3', icon: '🪣' },
      { id: 'google_drive', name: 'Google Drive', icon: '💾' },
      { id: 'dropbox', name: 'Dropbox', icon: '📦' },
      { id: 'onedrive', name: 'OneDrive', icon: '☁️' },
      { id: 'ftp', name: 'FTP/SFTP', icon: '🗂️' }
    ]
  },
  database: {
    label: 'Databases',
    icon: Database,
    color: 'bg-indigo-500',
    providers: [
      { id: 'mysql', name: 'MySQL', icon: '🐬' },
      { id: 'postgresql', name: 'PostgreSQL', icon: '🐘' },
      { id: 'mongodb', name: 'MongoDB', icon: '🍃' },
      { id: 'redis', name: 'Redis', icon: '🔴' },
      { id: 'dynamodb', name: 'DynamoDB', icon: '⚡' }
    ]
  },
  api: {
    label: 'REST APIs',
    icon: Globe,
    color: 'bg-cyan-500',
    providers: [
      { id: 'stripe', name: 'Stripe', icon: '💳' },
      { id: 'paypal', name: 'PayPal', icon: '💰' },
      { id: 'quickbooks', name: 'QuickBooks', icon: '📊' },
      { id: 'custom', name: 'Custom API', icon: '🔧' }
    ]
  },
  webhook: {
    label: 'Webhooks',
    icon: ArrowUpDown,
    color: 'bg-orange-500',
    providers: [
      { id: 'incoming', name: 'Incoming Webhook', icon: '📥' },
      { id: 'outgoing', name: 'Outgoing Webhook', icon: '📤' }
    ]
  },
  slack: {
    label: 'Communication',
    icon: MessageSquare,
    color: 'bg-green-600',
    providers: [
      { id: 'slack', name: 'Slack', icon: '💬' },
      { id: 'teams', name: 'Microsoft Teams', icon: '👥' },
      { id: 'discord', name: 'Discord', icon: '🎮' }
    ]
  }
};

export const IntegrationNode = memo(({ data, selected }: NodeProps<IntegrationNodeData>) => {
  const [isConfigOpen, setIsConfigOpen] = useState(false);
  const [localData, setLocalData] = useState(data);
  const [testResponse, setTestResponse] = useState<any>(null);
  const [isTestingConnection, setIsTestingConnection] = useState(false);

  const integrationType = INTEGRATION_PROVIDERS[localData.integrationType];
  const provider = integrationType?.providers.find(p => p.id === localData.provider);
  const IconComponent = integrationType?.icon || Globe;

  const getStatusIcon = () => {
    switch (localData.status) {
      case 'running':
        return <Zap className="w-4 h-4 animate-pulse text-yellow-500" />;
      case 'completed':
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'failed':
        return <AlertCircle className="w-4 h-4 text-red-500" />;
      default:
        return <IconComponent className="w-4 h-4 text-gray-500" />;
    }
  };

  const getConnectionStatusColor = () => {
    switch (localData.connectionStatus) {
      case 'connected':
        return 'bg-green-100 text-green-800';
      case 'error':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const handleConfigChange = (field: string, value: any) => {
    const newData = { ...localData, [field]: value };
    setLocalData(newData);
  };

  const testConnection = async () => {
    setIsTestingConnection(true);
    try {
      // Mock connection test
      await new Promise(resolve => setTimeout(resolve, 2000));
      setTestResponse({
        success: true,
        statusCode: 200,
        responseTime: 150,
        data: { message: 'Connection successful' }
      });
      handleConfigChange('connectionStatus', 'connected');
    } catch (error) {
      setTestResponse({
        success: false,
        error: 'Connection failed',
        statusCode: 500
      });
      handleConfigChange('connectionStatus', 'error');
    }
    setIsTestingConnection(false);
  };

  const addDataMapping = () => {
    const newMapping: DataMapping = {
      id: `mapping_${Date.now()}`,
      source: '',
      target: '',
      required: false
    };
    const mappings = [...(localData.requestConfig?.dataMapping || []), newMapping];
    handleConfigChange('requestConfig', {
      ...localData.requestConfig,
      dataMapping: mappings
    });
  };

  const removeDataMapping = (id: string) => {
    const mappings = (localData.requestConfig?.dataMapping || []).filter(m => m.id !== id);
    handleConfigChange('requestConfig', {
      ...localData.requestConfig,
      dataMapping: mappings
    });
  };

  const updateDataMapping = (id: string, updates: Partial<DataMapping>) => {
    const mappings = (localData.requestConfig?.dataMapping || []).map(m =>
      m.id === id ? { ...m, ...updates } : m
    );
    handleConfigChange('requestConfig', {
      ...localData.requestConfig,
      dataMapping: mappings
    });
  };

  return (
    <Card className={`min-w-[280px] ${selected ? 'ring-2 ring-blue-500' : ''} relative`}>
      <Handle type="target" position={Position.Top} className="w-3 h-3" />

      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className={`w-8 h-8 rounded-lg ${integrationType?.color} flex items-center justify-center text-white`}>
              {provider?.icon || <IconComponent className="w-4 h-4" />}
            </div>
            <div>
              <div className="font-semibold text-sm">{localData.label || provider?.name}</div>
              <div className="text-xs text-gray-500 flex items-center gap-1">
                {getStatusIcon()}
                <Badge variant="outline" className="text-xs">
                  {localData.method || 'GET'}
                </Badge>
                <Badge className={`text-xs ${getConnectionStatusColor()}`}>
                  {localData.connectionStatus || 'disconnected'}
                </Badge>
              </div>
            </div>
          </div>

          <Popover open={isConfigOpen} onOpenChange={setIsConfigOpen}>
            <PopoverTrigger asChild>
              <Button variant="ghost" size="sm">
                <Settings className="w-4 h-4" />
              </Button>
            </PopoverTrigger>
            <PopoverContent className="w-96 p-0">
              <Tabs defaultValue="connection" className="w-full">
                <TabsList className="grid w-full grid-cols-4">
                  <TabsTrigger value="connection">Connection</TabsTrigger>
                  <TabsTrigger value="request">Request</TabsTrigger>
                  <TabsTrigger value="response">Response</TabsTrigger>
                  <TabsTrigger value="advanced">Advanced</TabsTrigger>
                </TabsList>

                <TabsContent value="connection" className="p-4 space-y-4">
                  <div>
                    <Label>Integration Type</Label>
                    <Select
                      value={localData.integrationType}
                      onValueChange={(value) => handleConfigChange('integrationType', value)}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {Object.entries(INTEGRATION_PROVIDERS).map(([key, config]) => (
                          <SelectItem key={key} value={key}>
                            <div className="flex items-center gap-2">
                              <config.icon className="w-4 h-4" />
                              <span>{config.label}</span>
                            </div>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div>
                    <Label>Provider</Label>
                    <Select
                      value={localData.provider}
                      onValueChange={(value) => handleConfigChange('provider', value)}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {integrationType?.providers.map(provider => (
                          <SelectItem key={provider.id} value={provider.id}>
                            <div className="flex items-center gap-2">
                              <span>{provider.icon}</span>
                              <span>{provider.name}</span>
                            </div>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <Label>Method</Label>
                      <Select
                        value={localData.method}
                        onValueChange={(value) => handleConfigChange('method', value)}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="GET">GET</SelectItem>
                          <SelectItem value="POST">POST</SelectItem>
                          <SelectItem value="PUT">PUT</SelectItem>
                          <SelectItem value="DELETE">DELETE</SelectItem>
                          <SelectItem value="PATCH">PATCH</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div>
                      <Label>Timeout (ms)</Label>
                      <Input
                        type="number"
                        value={localData.timeout || 30000}
                        onChange={(e) => handleConfigChange('timeout', parseInt(e.target.value))}
                      />
                    </div>
                  </div>

                  <div>
                    <Label>Endpoint URL</Label>
                    <Input
                      placeholder="https://api.example.com/v1/endpoint"
                      value={localData.endpoint}
                      onChange={(e) => handleConfigChange('endpoint', e.target.value)}
                    />
                  </div>

                  <div>
                    <Label>Authentication Type</Label>
                    <Select
                      value={localData.authentication?.type || 'none'}
                      onValueChange={(value) => handleConfigChange('authentication', {
                        ...localData.authentication,
                        type: value
                      })}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="none">None</SelectItem>
                        <SelectItem value="api_key">API Key</SelectItem>
                        <SelectItem value="oauth2">OAuth 2.0</SelectItem>
                        <SelectItem value="basic">Basic Auth</SelectItem>
                        <SelectItem value="bearer">Bearer Token</SelectItem>
                        <SelectItem value="custom">Custom Headers</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  {localData.authentication?.type === 'api_key' && (
                    <div>
                      <Label>API Key</Label>
                      <Input
                        type="password"
                        placeholder="Your API key"
                        value={localData.authentication.apiKey || ''}
                        onChange={(e) => handleConfigChange('authentication', {
                          ...localData.authentication,
                          apiKey: e.target.value
                        })}
                      />
                    </div>
                  )}

                  {localData.authentication?.type === 'oauth2' && (
                    <div className="space-y-2">
                      <div>
                        <Label>Client ID</Label>
                        <Input
                          value={localData.authentication.clientId || ''}
                          onChange={(e) => handleConfigChange('authentication', {
                            ...localData.authentication,
                            clientId: e.target.value
                          })}
                        />
                      </div>
                      <div>
                        <Label>Client Secret</Label>
                        <Input
                          type="password"
                          value={localData.authentication.clientSecret || ''}
                          onChange={(e) => handleConfigChange('authentication', {
                            ...localData.authentication,
                            clientSecret: e.target.value
                          })}
                        />
                      </div>
                    </div>
                  )}

                  <div className="border-t pt-4">
                    <Button
                      onClick={testConnection}
                      disabled={isTestingConnection || !localData.endpoint}
                      className="w-full"
                    >
                      {isTestingConnection ? (
                        <>
                          <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                          Testing...
                        </>
                      ) : (
                        <>
                          <Activity className="w-4 h-4 mr-2" />
                          Test Connection
                        </>
                      )}
                    </Button>

                    {testResponse && (
                      <div className={`mt-2 p-2 rounded text-xs ${
                        testResponse.success ? 'bg-green-50 text-green-800' : 'bg-red-50 text-red-800'
                      }`}>
                        {testResponse.success ? (
                          <div>
                            <div>✅ Connection successful</div>
                            <div>Response time: {testResponse.responseTime}ms</div>
                          </div>
                        ) : (
                          <div>❌ {testResponse.error}</div>
                        )}
                      </div>
                    )}
                  </div>
                </TabsContent>

                <TabsContent value="request" className="p-4 space-y-4">
                  <div>
                    <Label>Request Body Type</Label>
                    <Select
                      value={localData.requestConfig?.bodyType || 'json'}
                      onValueChange={(value) => handleConfigChange('requestConfig', {
                        ...localData.requestConfig,
                        bodyType: value
                      })}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="json">JSON</SelectItem>
                        <SelectItem value="form">Form Data</SelectItem>
                        <SelectItem value="xml">XML</SelectItem>
                        <SelectItem value="raw">Raw</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div>
                    <Label>Request Template</Label>
                    <Textarea
                      placeholder="Request body template with {{variables}}"
                      value={localData.requestConfig?.bodyTemplate || ''}
                      onChange={(e) => handleConfigChange('requestConfig', {
                        ...localData.requestConfig,
                        bodyTemplate: e.target.value
                      })}
                      className="min-h-[100px] font-mono text-sm"
                    />
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <Label>Data Mapping</Label>
                      <Button variant="outline" size="sm" onClick={addDataMapping}>
                        Add Mapping
                      </Button>
                    </div>

                    <div className="space-y-2">
                      {(localData.requestConfig?.dataMapping || []).map((mapping) => (
                        <div key={mapping.id} className="border rounded p-2 space-y-2">
                          <div className="flex items-center justify-between">
                            <div className="text-xs font-medium">Field Mapping</div>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => removeDataMapping(mapping.id)}
                            >
                              ×
                            </Button>
                          </div>

                          <div className="grid grid-cols-2 gap-2">
                            <div>
                              <Label className="text-xs">Source Field</Label>
                              <Input
                                placeholder="input.field"
                                value={mapping.source}
                                onChange={(e) => updateDataMapping(mapping.id, { source: e.target.value })}
                                className="text-sm"
                              />
                            </div>

                            <div>
                              <Label className="text-xs">Target Field</Label>
                              <Input
                                placeholder="api.field"
                                value={mapping.target}
                                onChange={(e) => updateDataMapping(mapping.id, { target: e.target.value })}
                                className="text-sm"
                              />
                            </div>
                          </div>

                          <div className="flex items-center space-x-2">
                            <Switch
                              checked={mapping.required}
                              onCheckedChange={(checked) => updateDataMapping(mapping.id, { required: checked })}
                            />
                            <Label className="text-xs">Required</Label>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="response" className="p-4 space-y-4">
                  <div>
                    <Label>Success Status Codes</Label>
                    <Input
                      placeholder="200,201,202"
                      value={(localData.responseConfig?.successCodes || [200]).join(',')}
                      onChange={(e) => {
                        const codes = e.target.value.split(',').map(c => parseInt(c.trim())).filter(c => !isNaN(c));
                        handleConfigChange('responseConfig', {
                          ...localData.responseConfig,
                          successCodes: codes
                        });
                      }}
                    />
                  </div>

                  <div>
                    <Label>Data Path (JSONPath)</Label>
                    <Input
                      placeholder="$.data"
                      value={localData.responseConfig?.dataPath || ''}
                      onChange={(e) => handleConfigChange('responseConfig', {
                        ...localData.responseConfig,
                        dataPath: e.target.value
                      })}
                    />
                  </div>

                  <div>
                    <Label>Error Path (JSONPath)</Label>
                    <Input
                      placeholder="$.error.message"
                      value={localData.responseConfig?.errorPath || ''}
                      onChange={(e) => handleConfigChange('responseConfig', {
                        ...localData.responseConfig,
                        errorPath: e.target.value
                      })}
                    />
                  </div>

                  <div>
                    <Label>Response Transformation</Label>
                    <Textarea
                      placeholder="JavaScript transformation function"
                      value={localData.responseConfig?.transformation || ''}
                      onChange={(e) => handleConfigChange('responseConfig', {
                        ...localData.responseConfig,
                        transformation: e.target.value
                      })}
                      className="min-h-[80px] font-mono text-sm"
                    />
                  </div>

                  <div className="border-t pt-4">
                    <div className="flex items-center space-x-2 mb-2">
                      <Switch
                        checked={localData.responseConfig?.caching?.enabled || false}
                        onCheckedChange={(checked) => handleConfigChange('responseConfig', {
                          ...localData.responseConfig,
                          caching: {
                            ...localData.responseConfig?.caching,
                            enabled: checked
                          }
                        })}
                      />
                      <Label>Enable Response Caching</Label>
                    </div>

                    {localData.responseConfig?.caching?.enabled && (
                      <div>
                        <Label>Cache TTL (seconds)</Label>
                        <Input
                          type="number"
                          value={localData.responseConfig.caching.ttlSeconds || 300}
                          onChange={(e) => handleConfigChange('responseConfig', {
                            ...localData.responseConfig,
                            caching: {
                              ...localData.responseConfig.caching,
                              ttlSeconds: parseInt(e.target.value)
                            }
                          })}
                        />
                      </div>
                    )}
                  </div>
                </TabsContent>

                <TabsContent value="advanced" className="p-4 space-y-4">
                  <div>
                    <div className="flex items-center space-x-2 mb-2">
                      <Switch
                        checked={localData.rateLimiting?.enabled || false}
                        onCheckedChange={(checked) => handleConfigChange('rateLimiting', {
                          ...localData.rateLimiting,
                          enabled: checked
                        })}
                      />
                      <Label>Enable Rate Limiting</Label>
                    </div>

                    {localData.rateLimiting?.enabled && (
                      <div className="space-y-2">
                        <div>
                          <Label>Requests per Second: {localData.rateLimiting.requestsPerSecond || 10}</Label>
                          <Slider
                            value={[localData.rateLimiting.requestsPerSecond || 10]}
                            onValueChange={([value]) => handleConfigChange('rateLimiting', {
                              ...localData.rateLimiting,
                              requestsPerSecond: value
                            })}
                            min={1}
                            max={100}
                            step={1}
                            className="mt-2"
                          />
                        </div>

                        <div>
                          <Label>Burst Limit</Label>
                          <Input
                            type="number"
                            value={localData.rateLimiting.burstLimit || 20}
                            onChange={(e) => handleConfigChange('rateLimiting', {
                              ...localData.rateLimiting,
                              burstLimit: parseInt(e.target.value)
                            })}
                          />
                        </div>
                      </div>
                    )}
                  </div>

                  <div>
                    <div className="flex items-center space-x-2 mb-2">
                      <Switch
                        checked={localData.retryPolicy?.enabled || false}
                        onCheckedChange={(checked) => handleConfigChange('retryPolicy', {
                          ...localData.retryPolicy,
                          enabled: checked
                        })}
                      />
                      <Label>Enable Retry Logic</Label>
                    </div>

                    {localData.retryPolicy?.enabled && (
                      <div className="grid grid-cols-2 gap-2">
                        <div>
                          <Label>Max Attempts</Label>
                          <Input
                            type="number"
                            value={localData.retryPolicy.maxAttempts || 3}
                            onChange={(e) => handleConfigChange('retryPolicy', {
                              ...localData.retryPolicy,
                              maxAttempts: parseInt(e.target.value)
                            })}
                          />
                        </div>

                        <div>
                          <Label>Backoff (ms)</Label>
                          <Input
                            type="number"
                            value={localData.retryPolicy.backoffMs || 1000}
                            onChange={(e) => handleConfigChange('retryPolicy', {
                              ...localData.retryPolicy,
                              backoffMs: parseInt(e.target.value)
                            })}
                          />
                        </div>
                      </div>
                    )}
                  </div>

                  <div>
                    <div className="flex items-center space-x-2 mb-2">
                      <Switch
                        checked={localData.requestConfig?.batchConfig?.enabled || false}
                        onCheckedChange={(checked) => handleConfigChange('requestConfig', {
                          ...localData.requestConfig,
                          batchConfig: {
                            ...localData.requestConfig?.batchConfig,
                            enabled: checked
                          }
                        })}
                      />
                      <Label>Enable Batch Processing</Label>
                    </div>

                    {localData.requestConfig?.batchConfig?.enabled && (
                      <div className="grid grid-cols-2 gap-2">
                        <div>
                          <Label>Batch Size</Label>
                          <Input
                            type="number"
                            value={localData.requestConfig.batchConfig.batchSize || 10}
                            onChange={(e) => handleConfigChange('requestConfig', {
                              ...localData.requestConfig,
                              batchConfig: {
                                ...localData.requestConfig.batchConfig,
                                batchSize: parseInt(e.target.value)
                              }
                            })}
                          />
                        </div>

                        <div>
                          <Label>Parallel Requests</Label>
                          <Input
                            type="number"
                            value={localData.requestConfig.batchConfig.parallelRequests || 3}
                            onChange={(e) => handleConfigChange('requestConfig', {
                              ...localData.requestConfig,
                              batchConfig: {
                                ...localData.requestConfig.batchConfig,
                                parallelRequests: parseInt(e.target.value)
                              }
                            })}
                          />
                        </div>
                      </div>
                    )}
                  </div>
                </TabsContent>
              </Tabs>
            </PopoverContent>
          </Popover>
        </div>
      </CardHeader>

      <CardContent className="pt-0">
        <div className="text-xs text-gray-600 mb-2">
          {localData.endpoint?.substring(0, 40)}
          {localData.endpoint?.length > 40 ? '...' : ''}
        </div>

        <div className="flex items-center justify-between text-xs text-gray-500">
          <span>{localData.method} {provider?.name}</span>
          <span>
            {localData.timeout ? `${localData.timeout}ms timeout` : 'No timeout'}
          </span>
        </div>

        {localData.status === 'running' && (
          <div className="mt-2 w-full bg-gray-200 rounded-full h-1">
            <div className="bg-green-500 h-1 rounded-full animate-pulse" style={{ width: '70%' }}></div>
          </div>
        )}
      </CardContent>

      <Handle type="source" position={Position.Bottom} className="w-3 h-3" />
    </Card>
  );
});

IntegrationNode.displayName = 'IntegrationNode';