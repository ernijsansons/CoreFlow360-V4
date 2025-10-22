import { useState } from 'react'
import {
  useTestConnection,
  useDiscoverSchema,
  useCreateMigration,
  useStartMigration,
  usePauseMigration,
  useResumeMigration,
  useMigration,
} from '@/hooks/api'
import { Card } from '@/components/ui/card-refactored'
import { Button } from '@/components/ui/button-refactored'
import { Badge } from '@/components/ui/badge-refactored'
import { Input } from '@/components/ui/input-refactored'
import {
  Loader2,
  CheckCircle2,
  XCircle,
  ArrowRight,
  Database,
  Play,
  Pause,
  RotateCcw,
} from 'lucide-react'

type Platform = 'salesforce' | 'hubspot' | 'pipedrive' | 'zoho' | 'csv'
type Step = 'platform' | 'credentials' | 'test' | 'schema' | 'mapping' | 'migration' | 'progress'

export function MigrationWizard() {
  const [currentStep, setCurrentStep] = useState<Step>('platform')
  const [selectedPlatform, setSelectedPlatform] = useState<Platform | null>(null)
  const [credentials, setCredentials] = useState<Record<string, string>>({})
  const [migrationId, setMigrationId] = useState<string | null>(null)

  const testConnection = useTestConnection()
  const discoverSchema = useDiscoverSchema()
  const createMigration = useCreateMigration()
  const startMigration = useStartMigration()
  const pauseMigration = usePauseMigration()
  const resumeMigration = useResumeMigration()
  const { data: migration } = useMigration(migrationId || '', !!migrationId)

  const platforms: Array<{ value: Platform; label: string; description: string }> = [
    { value: 'salesforce', label: 'Salesforce', description: 'Import from Salesforce CRM' },
    { value: 'hubspot', label: 'HubSpot', description: 'Import from HubSpot CRM' },
    { value: 'pipedrive', label: 'Pipedrive', description: 'Import from Pipedrive' },
    { value: 'zoho', label: 'Zoho CRM', description: 'Import from Zoho CRM' },
    { value: 'csv', label: 'CSV File', description: 'Import from CSV files' },
  ]

  const handleTestConnection = () => {
    if (!selectedPlatform) return

    testConnection.mutate(
      {
        platform: selectedPlatform,
        credentials,
      },
      {
        onSuccess: (data) => {
          if (data.data.success) {
            setCurrentStep('schema')
          }
        },
      }
    )
  }

  const handleDiscoverSchema = () => {
    if (!selectedPlatform) return

    discoverSchema.mutate(
      {
        platform: selectedPlatform,
        credentials,
      },
      {
        onSuccess: () => {
          setCurrentStep('mapping')
        },
      }
    )
  }

  const handleCreateMigration = () => {
    if (!selectedPlatform) return

    createMigration.mutate(
      {
        platform: selectedPlatform,
        credentials,
        mapping: {}, // Simplified for demo
        options: {
          batch_size: 100,
          skip_duplicates: true,
          update_existing: false,
        },
      },
      {
        onSuccess: (data) => {
          setMigrationId(data.data.id)
          setCurrentStep('progress')
        },
      }
    )
  }

  const steps = [
    { id: 'platform', label: 'Platform' },
    { id: 'credentials', label: 'Credentials' },
    { id: 'test', label: 'Test' },
    { id: 'schema', label: 'Schema' },
    { id: 'mapping', label: 'Mapping' },
    { id: 'migration', label: 'Migration' },
    { id: 'progress', label: 'Progress' },
  ]

  const currentStepIndex = steps.findIndex((s) => s.id === currentStep)

  return (
    <div className="container mx-auto py-8 space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Data Migration</h1>
        <p className="text-gray-600 dark:text-gray-400 mt-2">
          Import your data from other CRM platforms
        </p>
      </div>

      {/* Progress Steps */}
      <Card className="p-6">
        <div className="flex items-center justify-between">
          {steps.map((step, index) => (
            <div key={step.id} className="flex items-center">
              <div
                className={`flex items-center justify-center w-10 h-10 rounded-full border-2 ${
                  index <= currentStepIndex
                    ? 'border-brand-primary bg-brand-primary text-white'
                    : 'border-gray-300 bg-white dark:bg-gray-800 text-gray-500'
                }`}
              >
                {index < currentStepIndex ? (
                  <CheckCircle2 className="h-5 w-5" />
                ) : (
                  <span className="text-sm font-medium">{index + 1}</span>
                )}
              </div>
              <span
                className={`ml-2 text-sm font-medium ${
                  index <= currentStepIndex ? 'text-gray-900 dark:text-white' : 'text-gray-500'
                }`}
              >
                {step.label}
              </span>
              {index < steps.length - 1 && (
                <ArrowRight className="h-5 w-5 text-gray-300 mx-4" />
              )}
            </div>
          ))}
        </div>
      </Card>

      {/* Step Content */}
      <Card className="p-6">
        {/* Platform Selection */}
        {currentStep === 'platform' && (
          <div className="space-y-6">
            <h2 className="text-2xl font-bold">Select Platform</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {platforms.map((platform) => (
                <button
                  key={platform.value}
                  onClick={() => {
                    setSelectedPlatform(platform.value)
                    setCurrentStep('credentials')
                  }}
                  className={`p-6 border-2 rounded-lg transition-all text-left ${
                    selectedPlatform === platform.value
                      ? 'border-brand-primary bg-brand-primary/5'
                      : 'border-gray-200 dark:border-gray-700 hover:border-brand-primary/50'
                  }`}
                >
                  <Database className="h-8 w-8 mb-3" />
                  <h3 className="font-semibold text-lg mb-1">{platform.label}</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    {platform.description}
                  </p>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Credentials */}
        {currentStep === 'credentials' && selectedPlatform && (
          <div className="space-y-6">
            <div>
              <h2 className="text-2xl font-bold">Enter Credentials</h2>
              <p className="text-gray-600 dark:text-gray-400 mt-1">
                Platform: <Badge>{selectedPlatform}</Badge>
              </p>
            </div>

            <div className="space-y-4">
              {selectedPlatform === 'salesforce' && (
                <>
                  <div>
                    <label className="block text-sm font-medium mb-2">Instance URL</label>
                    <Input
                      placeholder="https://your-instance.salesforce.com"
                      value={credentials.instance_url || ''}
                      onChange={(e) =>
                        setCredentials({ ...credentials, instance_url: e.target.value })
                      }
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-2">Access Token</label>
                    <Input
                      type="password"
                      placeholder="Enter access token"
                      value={credentials.access_token || ''}
                      onChange={(e) =>
                        setCredentials({ ...credentials, access_token: e.target.value })
                      }
                    />
                  </div>
                </>
              )}

              {(selectedPlatform === 'hubspot' ||
                selectedPlatform === 'pipedrive' ||
                selectedPlatform === 'zoho') && (
                <div>
                  <label className="block text-sm font-medium mb-2">API Key</label>
                  <Input
                    type="password"
                    placeholder="Enter API key"
                    value={credentials.api_key || ''}
                    onChange={(e) =>
                      setCredentials({ ...credentials, api_key: e.target.value })
                    }
                  />
                </div>
              )}

              {selectedPlatform === 'csv' && (
                <div>
                  <label className="block text-sm font-medium mb-2">File Path</label>
                  <Input
                    placeholder="/path/to/file.csv"
                    value={credentials.file_path || ''}
                    onChange={(e) =>
                      setCredentials({ ...credentials, file_path: e.target.value })
                    }
                  />
                </div>
              )}
            </div>

            <div className="flex space-x-3">
              <Button variant="outline" onClick={() => setCurrentStep('platform')}>
                Back
              </Button>
              <Button onClick={() => setCurrentStep('test')}>Next</Button>
            </div>
          </div>
        )}

        {/* Test Connection */}
        {currentStep === 'test' && (
          <div className="space-y-6">
            <h2 className="text-2xl font-bold">Test Connection</h2>

            {testConnection.data?.data ? (
              <div
                className={`p-4 rounded-lg border ${
                  testConnection.data.data.success
                    ? 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800'
                    : 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800'
                }`}
              >
                <div className="flex items-start space-x-3">
                  {testConnection.data.data.success ? (
                    <CheckCircle2 className="h-5 w-5 text-green-600 mt-0.5" />
                  ) : (
                    <XCircle className="h-5 w-5 text-red-600 mt-0.5" />
                  )}
                  <div>
                    <p
                      className={`font-medium ${
                        testConnection.data.data.success
                          ? 'text-green-900 dark:text-green-300'
                          : 'text-red-900 dark:text-red-300'
                      }`}
                    >
                      {testConnection.data.data.success
                        ? 'Connection Successful'
                        : 'Connection Failed'}
                    </p>
                    {testConnection.data.data.error && (
                      <p className="text-sm text-red-700 dark:text-red-400 mt-1">
                        {testConnection.data.data.error}
                      </p>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <Button onClick={handleTestConnection} disabled={testConnection.isPending}>
                {testConnection.isPending ? (
                  <Loader2 className="h-5 w-5 mr-2 animate-spin" />
                ) : (
                  <CheckCircle2 className="h-5 w-5 mr-2" />
                )}
                Test Connection
              </Button>
            )}
          </div>
        )}

        {/* Migration Progress */}
        {currentStep === 'progress' && migration?.data && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <h2 className="text-2xl font-bold">Migration in Progress</h2>
              <Badge
                variant={
                  migration.data.status === 'completed'
                    ? 'default'
                    : migration.data.status === 'failed'
                    ? 'destructive'
                    : 'secondary'
                }
              >
                {migration.data.status}
              </Badge>
            </div>

            {/* Progress Bar */}
            {migration.data.status === 'in_progress' && (
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium">Progress</span>
                  <span className="text-sm text-gray-500">{migration.data.progress}%</span>
                </div>
                <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3">
                  <div
                    className="bg-brand-primary h-3 rounded-full transition-all"
                    style={{ width: `${migration.data.progress}%` }}
                  />
                </div>
              </div>
            )}

            {/* Stats */}
            <div className="grid grid-cols-3 gap-4">
              <Card className="p-4">
                <p className="text-sm text-gray-600 dark:text-gray-400">Total Records</p>
                <p className="text-2xl font-bold mt-1">
                  {migration.data.total_records?.toLocaleString() || 0}
                </p>
              </Card>
              <Card className="p-4">
                <p className="text-sm text-gray-600 dark:text-gray-400">Migrated</p>
                <p className="text-2xl font-bold mt-1 text-green-600">
                  {migration.data.migrated_records?.toLocaleString() || 0}
                </p>
              </Card>
              <Card className="p-4">
                <p className="text-sm text-gray-600 dark:text-gray-400">Failed</p>
                <p className="text-2xl font-bold mt-1 text-red-600">
                  {migration.data.failed_records?.toLocaleString() || 0}
                </p>
              </Card>
            </div>

            {/* Controls */}
            <div className="flex space-x-3">
              {migration.data.status === 'in_progress' ? (
                <Button
                  onClick={() => migrationId && pauseMigration.mutate(migrationId)}
                  disabled={pauseMigration.isPending}
                >
                  <Pause className="h-4 w-4 mr-2" />
                  Pause
                </Button>
              ) : migration.data.status === 'paused' ? (
                <Button
                  onClick={() => migrationId && resumeMigration.mutate(migrationId)}
                  disabled={resumeMigration.isPending}
                >
                  <Play className="h-4 w-4 mr-2" />
                  Resume
                </Button>
              ) : migration.data.status === 'pending' ? (
                <Button
                  onClick={() => migrationId && startMigration.mutate(migrationId)}
                  disabled={startMigration.isPending}
                >
                  <Play className="h-4 w-4 mr-2" />
                  Start Migration
                </Button>
              ) : null}

              {migration.data.status === 'completed' && (
                <Button onClick={() => setCurrentStep('platform')}>
                  <RotateCcw className="h-4 w-4 mr-2" />
                  Start New Migration
                </Button>
              )}
            </div>
          </div>
        )}

        {/* Simplified Schema & Mapping Steps */}
        {currentStep === 'schema' && (
          <div className="space-y-6">
            <h2 className="text-2xl font-bold">Discover Schema</h2>
            <Button onClick={handleDiscoverSchema} disabled={discoverSchema.isPending}>
              {discoverSchema.isPending ? (
                <Loader2 className="h-5 w-5 mr-2 animate-spin" />
              ) : (
                <Database className="h-5 w-5 mr-2" />
              )}
              Discover Schema
            </Button>
          </div>
        )}

        {currentStep === 'mapping' && (
          <div className="space-y-6">
            <h2 className="text-2xl font-bold">Field Mapping</h2>
            <p className="text-gray-600 dark:text-gray-400">
              Automatic field mapping configured. Review and adjust if needed.
            </p>
            <Button onClick={() => setCurrentStep('migration')}>Continue to Migration</Button>
          </div>
        )}

        {currentStep === 'migration' && (
          <div className="space-y-6">
            <h2 className="text-2xl font-bold">Start Migration</h2>
            <p className="text-gray-600 dark:text-gray-400">
              Ready to start migrating your data. This process may take some time.
            </p>
            <Button onClick={handleCreateMigration} disabled={createMigration.isPending}>
              {createMigration.isPending ? (
                <Loader2 className="h-5 w-5 mr-2 animate-spin" />
              ) : (
                <Play className="h-5 w-5 mr-2" />
              )}
              Create & Start Migration
            </Button>
          </div>
        )}
      </Card>
    </div>
  )
}
