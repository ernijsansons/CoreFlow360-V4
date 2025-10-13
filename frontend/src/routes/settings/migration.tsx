/**
 * Migration Tools & Data Import Wizard
 * Import data from external CRM systems with intelligent mapping
 */

import { createFileRoute } from '@tanstack/react-router';
import { useState, useEffect } from 'react';
import { MainLayout } from '@/layouts/main-layout';
import { migrationService, type Migration, type MigrationSchema, type MigrationMapping } from '@/lib/api/services/migration.service';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import {
  Database,
  Upload,
  FileText,
  Table,
  ArrowRight,
  CheckCircle,
  XCircle,
  AlertCircle,
  Loader2,
  Play,
  Pause,
  RefreshCw,
  Download,
  Settings,
  Link as LinkIcon,
  FileSpreadsheet,
  Globe,
  Zap,
  MapPin,
  AlertTriangle
} from 'lucide-react';

export const Route = createFileRoute('/settings/migration')({
  component: MigrationPage,
});

type SourceType = 'salesforce' | 'hubspot' | 'pipedrive' | 'zoho' | 'csv' | 'excel';
type WizardStep = 'source' | 'schema' | 'mapping' | 'preview' | 'import';

function MigrationPage() {
  const [currentStep, setCurrentStep] = useState<WizardStep>('source');
  const [sourceType, setSourceType] = useState<SourceType | null>(null);
  const [credentials, setCredentials] = useState<Record<string, string>>({});
  const [isTestingConnection, setIsTestingConnection] = useState(false);
  const [connectionValid, setConnectionValid] = useState(false);
  const [schema, setSchema] = useState<MigrationSchema | null>(null);
  const [mappings, setMappings] = useState<MigrationMapping[]>([]);
  const [activeMigrations, setActiveMigrations] = useState<Migration[]>([]);
  const [isLoadingSchema, setIsLoadingSchema] = useState(false);
  const [currentMigration, setCurrentMigration] = useState<Migration | null>(null);

  useEffect(() => {
    loadActiveMigrations();
    const interval = setInterval(loadActiveMigrations, 5000);
    return () => clearInterval(interval);
  }, []);

  const loadActiveMigrations = async () => {
    try {
      const response = await migrationService.listMigrations({ limit: 10 });
      setActiveMigrations(response.data);
    } catch (error) {
      console.error('Failed to load migrations:', error);
    }
  };

  const sources = [
    {
      type: 'salesforce' as SourceType,
      name: 'Salesforce',
      icon: Globe,
      description: 'Import from Salesforce CRM',
      fields: ['api_key', 'instance_url', 'username'],
    },
    {
      type: 'hubspot' as SourceType,
      name: 'HubSpot',
      icon: Zap,
      description: 'Import from HubSpot CRM',
      fields: ['api_key'],
    },
    {
      type: 'pipedrive' as SourceType,
      name: 'Pipedrive',
      icon: Database,
      description: 'Import from Pipedrive CRM',
      fields: ['api_token', 'company_domain'],
    },
    {
      type: 'zoho' as SourceType,
      name: 'Zoho CRM',
      icon: Database,
      description: 'Import from Zoho CRM',
      fields: ['client_id', 'client_secret', 'refresh_token'],
    },
    {
      type: 'csv' as SourceType,
      name: 'CSV File',
      icon: FileText,
      description: 'Import from CSV file',
      fields: ['file_upload'],
    },
    {
      type: 'excel' as SourceType,
      name: 'Excel',
      icon: FileSpreadsheet,
      description: 'Import from Excel file',
      fields: ['file_upload'],
    },
  ];

  const entityTypes = [
    { value: 'contact', label: 'Contact', icon: '👤' },
    { value: 'company', label: 'Company', icon: '🏢' },
    { value: 'lead', label: 'Lead', icon: '🎯' },
    { value: 'deal', label: 'Deal', icon: '💼' },
  ];

  const handleTestConnection = async () => {
    if (!sourceType) return;

    setIsTestingConnection(true);
    try {
      const response = await migrationService.testConnection({
        source_type: sourceType,
        credentials,
        test_mode: true,
      });

      if (response.data.success) {
        setConnectionValid(true);
        const event = new CustomEvent('show-toast', {
          detail: { message: 'Connection successful!', type: 'success' }
        });
        window.dispatchEvent(event);
      }
    } catch (error) {
      setConnectionValid(false);
      const event = new CustomEvent('show-toast', {
        detail: { message: 'Connection failed', type: 'error' }
      });
      window.dispatchEvent(event);
    } finally {
      setIsTestingConnection(false);
    }
  };

  const handleDiscoverSchema = async () => {
    if (!sourceType) return;

    setIsLoadingSchema(true);
    try {
      const response = await migrationService.discoverSchema({
        source_type: sourceType,
        credentials,
      });

      setSchema(response.data);
      setCurrentStep('schema');
    } catch (error) {
      const event = new CustomEvent('show-toast', {
        detail: { message: 'Failed to discover schema', type: 'error' }
      });
      window.dispatchEvent(event);
    } finally {
      setIsLoadingSchema(false);
    }
  };

  const handleCreateMapping = (sourceTable: string, targetEntity: string) => {
    const newMapping: MigrationMapping = {
      source_table: sourceTable,
      target_entity: targetEntity as any,
      field_mappings: {},
    };

    setMappings([...mappings, newMapping]);
  };

  const handleStartMigration = async () => {
    if (!sourceType) return;

    try {
      // First create mapping
      const mappingResponse = await migrationService.createMapping({
        source_type: sourceType,
        mappings,
      });

      // Then create migration
      const migrationResponse = await migrationService.createMigration({
        source_connection: {
          source_type: sourceType,
          credentials,
        },
        mapping_id: mappingResponse.data.mapping_id,
        options: {
          batch_size: 100,
          skip_duplicates: true,
          update_existing: false,
        },
      });

      const migration = migrationResponse.data;
      setCurrentMigration(migration);

      // Start the migration
      await migrationService.startMigration(migration.id);

      setCurrentStep('import');
      loadActiveMigrations();

      const event = new CustomEvent('show-toast', {
        detail: { message: 'Migration started successfully', type: 'success' }
      });
      window.dispatchEvent(event);
    } catch (error) {
      const event = new CustomEvent('show-toast', {
        detail: { message: 'Failed to start migration', type: 'error' }
      });
      window.dispatchEvent(event);
    }
  };

  const handlePauseMigration = async (id: string) => {
    try {
      await migrationService.pauseMigration(id);
      loadActiveMigrations();
    } catch (error) {
      console.error('Failed to pause migration:', error);
    }
  };

  const handleResumeMigration = async (id: string) => {
    try {
      await migrationService.resumeMigration(id);
      loadActiveMigrations();
    } catch (error) {
      console.error('Failed to resume migration:', error);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400';
      case 'running':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400';
      case 'paused':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400';
      case 'failed':
        return 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300';
    }
  };

  const selectedSource = sources.find((s) => s.type === sourceType);

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
              <Database className="w-6 h-6 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight">Data Migration</h1>
              <p className="text-muted-foreground mt-1">
                Import data from external CRM systems with intelligent mapping
              </p>
            </div>
          </div>
        </div>

        {/* Progress Steps */}
        <Card className="p-6">
          <div className="flex items-center justify-between">
            {[
              { id: 'source', label: 'Source', icon: Database },
              { id: 'schema', label: 'Schema', icon: Table },
              { id: 'mapping', label: 'Mapping', icon: MapPin },
              { id: 'preview', label: 'Preview', icon: Settings },
              { id: 'import', label: 'Import', icon: Upload },
            ].map((step, idx, arr) => (
              <div key={step.id} className="flex items-center">
                <div
                  className={`flex items-center gap-3 ${
                    currentStep === step.id ? 'text-primary' : 'text-muted-foreground'
                  }`}
                >
                  <div
                    className={`w-10 h-10 rounded-full flex items-center justify-center ${
                      currentStep === step.id
                        ? 'bg-primary text-primary-foreground'
                        : 'bg-muted'
                    }`}
                  >
                    <step.icon className="w-5 h-5" />
                  </div>
                  <span className="font-medium">{step.label}</span>
                </div>
                {idx < arr.length - 1 && (
                  <ArrowRight className="w-5 h-5 mx-4 text-muted-foreground" />
                )}
              </div>
            ))}
          </div>
        </Card>

        {/* Step: Source Selection */}
        {currentStep === 'source' && (
          <>
            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4">Select Data Source</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {sources.map((source) => (
                  <button
                    key={source.type}
                    onClick={() => setSourceType(source.type)}
                    className={`p-6 border-2 rounded-lg text-left transition-all ${
                      sourceType === source.type
                        ? 'border-primary bg-primary/5'
                        : 'border-border hover:border-primary/50'
                    }`}
                  >
                    <source.icon className="w-8 h-8 text-primary mb-3" />
                    <h4 className="font-semibold mb-1">{source.name}</h4>
                    <p className="text-sm text-muted-foreground">{source.description}</p>
                  </button>
                ))}
              </div>
            </Card>

            {selectedSource && (
              <Card className="p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <LinkIcon className="w-5 h-5 text-primary" />
                  Connect to {selectedSource.name}
                </h3>
                <div className="space-y-4 max-w-2xl">
                  {selectedSource.fields.map((field) => (
                    <div key={field}>
                      <label className="block text-sm font-medium mb-2 capitalize">
                        {field.replace('_', ' ')}
                      </label>
                      {field === 'file_upload' ? (
                        <Input type="file" accept=".csv,.xlsx,.xls" />
                      ) : (
                        <Input
                          type={field.includes('secret') || field.includes('token') ? 'password' : 'text'}
                          placeholder={`Enter ${field.replace('_', ' ')}`}
                          value={credentials[field] || ''}
                          onChange={(e) =>
                            setCredentials({ ...credentials, [field]: e.target.value })
                          }
                        />
                      )}
                    </div>
                  ))}

                  <div className="flex gap-3 pt-4">
                    <Button
                      onClick={handleTestConnection}
                      disabled={isTestingConnection}
                      variant="outline"
                    >
                      {isTestingConnection ? (
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      ) : connectionValid ? (
                        <CheckCircle className="w-4 h-4 mr-2 text-green-500" />
                      ) : (
                        <AlertCircle className="w-4 h-4 mr-2" />
                      )}
                      Test Connection
                    </Button>
                    <Button
                      onClick={handleDiscoverSchema}
                      disabled={!connectionValid || isLoadingSchema}
                    >
                      {isLoadingSchema ? (
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      ) : (
                        <ArrowRight className="w-4 h-4 mr-2" />
                      )}
                      Discover Schema
                    </Button>
                  </div>
                </div>
              </Card>
            )}
          </>
        )}

        {/* Step: Schema Discovery */}
        {currentStep === 'schema' && schema && (
          <Card className="p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">Available Tables</h3>
              <Button variant="outline" size="sm" onClick={() => setCurrentStep('source')}>
                Back
              </Button>
            </div>
            <div className="space-y-3">
              {schema.tables.map((table) => (
                <div key={table.name} className="p-4 border border-border rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <Table className="w-5 h-5 text-primary" />
                      <h4 className="font-semibold">{table.name}</h4>
                      <span className="text-sm text-muted-foreground">
                        ({table.record_count.toLocaleString()} records)
                      </span>
                    </div>
                    <select
                      className="h-9 px-3 rounded-md border border-input bg-background"
                      onChange={(e) => {
                        if (e.target.value) {
                          handleCreateMapping(table.name, e.target.value);
                        }
                      }}
                    >
                      <option value="">Map to...</option>
                      {entityTypes.map((entity) => (
                        <option key={entity.value} value={entity.value}>
                          {entity.icon} {entity.label}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="flex flex-wrap gap-2 mt-2">
                    {table.columns.slice(0, 10).map((col) => (
                      <span
                        key={col.name}
                        className="px-2 py-1 rounded text-xs bg-muted"
                      >
                        {col.name}
                        {col.required && <span className="text-red-500 ml-1">*</span>}
                      </span>
                    ))}
                    {table.columns.length > 10 && (
                      <span className="px-2 py-1 rounded text-xs text-muted-foreground">
                        +{table.columns.length - 10} more
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
            {mappings.length > 0 && (
              <div className="flex justify-end mt-6">
                <Button onClick={() => setCurrentStep('mapping')}>
                  Continue to Mapping
                  <ArrowRight className="w-4 h-4 ml-2" />
                </Button>
              </div>
            )}
          </Card>
        )}

        {/* Step: Field Mapping */}
        {currentStep === 'mapping' && (
          <Card className="p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">Field Mapping</h3>
              <Button variant="outline" size="sm" onClick={() => setCurrentStep('schema')}>
                Back
              </Button>
            </div>
            <div className="space-y-6">
              {mappings.map((mapping, idx) => (
                <div key={idx} className="p-4 border border-border rounded-lg">
                  <h4 className="font-semibold mb-3">
                    {mapping.source_table} → {mapping.target_entity}
                  </h4>
                  <p className="text-sm text-muted-foreground mb-4">
                    Map fields from source to target entity
                  </p>
                  {/* Field mapping UI would go here - simplified for now */}
                  <div className="text-sm text-muted-foreground">
                    Auto-mapping based on field names will be applied
                  </div>
                </div>
              ))}
            </div>
            <div className="flex justify-end gap-3 mt-6">
              <Button variant="outline" onClick={() => setCurrentStep('preview')}>
                Preview Migration
              </Button>
              <Button onClick={handleStartMigration}>
                Start Migration
                <Play className="w-4 h-4 ml-2" />
              </Button>
            </div>
          </Card>
        )}

        {/* Active Migrations */}
        {activeMigrations.length > 0 && (
          <Card className="p-6">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <RefreshCw className="w-5 h-5 text-primary" />
              Active Migrations
            </h3>
            <div className="space-y-3">
              {activeMigrations.map((migration) => (
                <div key={migration.id} className="p-4 border border-border rounded-lg">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <Database className="w-5 h-5 text-primary" />
                      <div>
                        <h4 className="font-semibold capitalize">{migration.source_type}</h4>
                        <p className="text-sm text-muted-foreground">
                          ID: {migration.id.slice(0, 8)}
                        </p>
                      </div>
                    </div>
                    <span className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(migration.status)}`}>
                      {migration.status}
                    </span>
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">Progress</span>
                      <span className="font-medium">
                        {migration.progress.processed_records} / {migration.progress.total_records}
                      </span>
                    </div>
                    <div className="w-full h-2 bg-muted rounded-full overflow-hidden">
                      <div
                        className="h-full bg-primary transition-all duration-300"
                        style={{
                          width: `${(migration.progress.processed_records / migration.progress.total_records) * 100}%`,
                        }}
                      />
                    </div>
                    <div className="flex items-center gap-4 text-xs text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <CheckCircle className="w-3 h-3 text-green-500" />
                        {migration.progress.imported_records} imported
                      </span>
                      {migration.progress.failed_records > 0 && (
                        <span className="flex items-center gap-1">
                          <XCircle className="w-3 h-3 text-red-500" />
                          {migration.progress.failed_records} failed
                        </span>
                      )}
                      {migration.progress.skipped_records > 0 && (
                        <span className="flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3 text-yellow-500" />
                          {migration.progress.skipped_records} skipped
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="flex gap-2 mt-4">
                    {migration.status === 'running' && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => handlePauseMigration(migration.id)}
                      >
                        <Pause className="w-4 h-4 mr-2" />
                        Pause
                      </Button>
                    )}
                    {migration.status === 'paused' && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => handleResumeMigration(migration.id)}
                      >
                        <Play className="w-4 h-4 mr-2" />
                        Resume
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </Card>
        )}
      </div>
    </MainLayout>
  );
}
