import React, { useState } from 'react';

interface ConnectionConfig {
  id: string;
  type: string;
  name: string;
  parameters: Record<string, any>;
}

interface MigrationWizardProps {
  onComplete: (migrationId: string) => void;
  onCancel: () => void;
}

interface WizardStep {
  id: string;
  title: string;
  description: string;
}

const steps: WizardStep[] = [
  { id: 'source', title: 'Source Connection', description: 'Configure the source data connection' },
  { id: 'target', title: 'Target Connection', description: 'Configure the target data connection' },
  { id: 'mapping', title: 'Schema Mapping', description: 'Map fields between source and target' },
  { id: 'options', title: 'Migration Options', description: 'Configure migration settings' },
  { id: 'review', title: 'Review & Start', description: 'Review settings and start migration' }
];

export const MigrationWizard: React.FC<MigrationWizardProps> = ({ onComplete, onCancel }) => {
  const [currentStep, setCurrentStep] = useState(0);
  const [sourceConfig, setSourceConfig] = useState<ConnectionConfig | null>(null);
  const [targetConfig, setTargetConfig] = useState<ConnectionConfig | null>(null);
  const [schemaMapping, setSchemaMapping] = useState<any>(null);
  const [migrationOptions, setMigrationOptions] = useState({
    name: '',
    batchSize: 1000,
    parallelism: 1,
    mode: 'full',
    schedule: null,
    validateData: true,
    createSnapshots: true
  });

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

  const handleSubmit = async () => {
    try {
      const migrationRequest = {
        name: migrationOptions.name,
        source: sourceConfig,
        target: targetConfig,
        mapping: schemaMapping,
        options: migrationOptions
      };

      const response = await fetch('/api/migration/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(migrationRequest)
      });

      const result = await response.json();

      if (result.success) {
        onComplete(result.migrationId);
      } else {
        throw new Error(result.error || 'Failed to create migration');
      }
    } catch (error) {
      console.error('Failed to create migration:', error);
      alert('Failed to create migration: ' + (error as Error).message);
    }
  };

  const canProceed = () => {
    switch (currentStep) {
      case 0: return sourceConfig !== null;
      case 1: return targetConfig !== null;
      case 2: return schemaMapping !== null;
      case 3: return migrationOptions.name.trim() !== '';
      case 4: return true;
      default: return false;
    }
  };

  return (
    <div className="max-w-4xl mx-auto">
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-xl font-semibold text-gray-900">Create New Migration</h2>
          <p className="mt-1 text-sm text-gray-600">
            Step {currentStep + 1} of {steps.length}: {steps[currentStep].description}
          </p>
        </div>

        <div className="px-6 py-4">
          <nav aria-label="Progress">
            <ol className="flex items-center">
              {steps.map((step, index) => (
                <li key={step.id} className={`${index !== steps.length - 1 ? 'pr-8 sm:pr-20' : ''} relative`}>
                  <div className="flex items-center">
                    <div className={`flex h-8 w-8 items-center justify-center rounded-full ${
                      index < currentStep ? 'bg-blue-600' :
                      index === currentStep ? 'bg-blue-100 border-2 border-blue-600' :
                      'bg-gray-200'
                    }`}>
                      {index < currentStep ? (
                        <svg className="h-5 w-5 text-white" fill="currentColor" viewBox="0 0 20 20">
                          <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                        </svg>
                      ) : (
                        <span className={`text-sm font-medium ${
                          index === currentStep ? 'text-blue-600' : 'text-gray-500'
                        }`}>
                          {index + 1}
                        </span>
                      )}
                    </div>
                    <span className={`ml-3 text-sm font-medium ${
                      index <= currentStep ? 'text-gray-900' : 'text-gray-500'
                    }`}>
                      {step.title}
                    </span>
                  </div>
                  {index !== steps.length - 1 && (
                    <div className={`absolute top-4 left-4 -ml-px mt-0.5 h-full w-0.5 ${
                      index < currentStep ? 'bg-blue-600' : 'bg-gray-300'
                    }`} />
                  )}
                </li>
              ))}
            </ol>
          </nav>
        </div>

        <div className="px-6 py-6 min-h-96">
          {currentStep === 0 && (
            <SourceConnectionStep
              config={sourceConfig}
              onChange={setSourceConfig}
            />
          )}

          {currentStep === 1 && (
            <TargetConnectionStep
              config={targetConfig}
              onChange={setTargetConfig}
            />
          )}

          {currentStep === 2 && (
            <SchemaMappingStep
              sourceConfig={sourceConfig}
              targetConfig={targetConfig}
              mapping={schemaMapping}
              onChange={setSchemaMapping}
            />
          )}

          {currentStep === 3 && (
            <MigrationOptionsStep
              options={migrationOptions}
              onChange={setMigrationOptions}
            />
          )}

          {currentStep === 4 && (
            <ReviewStep
              sourceConfig={sourceConfig}
              targetConfig={targetConfig}
              schemaMapping={schemaMapping}
              options={migrationOptions}
            />
          )}
        </div>

        <div className="px-6 py-4 border-t border-gray-200 flex justify-between">
          <div>
            <button
              onClick={onCancel}
              className="text-gray-600 hover:text-gray-800 transition-colors"
            >
              Cancel
            </button>
          </div>

          <div className="flex space-x-3">
            {currentStep > 0 && (
              <button
                onClick={handleBack}
                className="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50 transition-colors"
              >
                Back
              </button>
            )}

            {currentStep < steps.length - 1 ? (
              <button
                onClick={handleNext}
                disabled={!canProceed()}
                className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors"
              >
                Next
              </button>
            ) : (
              <button
                onClick={handleSubmit}
                disabled={!canProceed()}
                className="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors"
              >
                Create Migration
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

const SourceConnectionStep: React.FC<{
  config: ConnectionConfig | null;
  onChange: (config: ConnectionConfig | null) => void;
}> = ({ config, onChange }) => {
  const [connectionType, setConnectionType] = useState('database');
  const [connectionParams, setConnectionParams] = useState({
    name: '',
    host: '',
    port: '',
    database: '',
    username: '',
    password: '',
    connectionString: ''
  });

  const handleTest = async () => {
    try {
      const testConfig = {
        id: crypto.randomUUID(),
        type: connectionType,
        name: connectionParams.name,
        parameters: connectionParams
      };

      const response = await fetch('/api/connections/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(testConfig)
      });

      const result = await response.json();

      if (result.success) {
        alert('Connection test successful!');
        onChange(testConfig);
      } else {
        alert('Connection test failed: ' + result.message);
      }
    } catch (error) {
      alert('Connection test failed: ' + (error as Error).message);
    }
  };

  return (
    <div className="space-y-6">
      <h3 className="text-lg font-medium text-gray-900">Source Connection</h3>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-2">
          Connection Type
        </label>
        <select
          value={connectionType}
          onChange={(e) => setConnectionType(e.target.value)}
          className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="database">Database</option>
          <option value="file">File</option>
          <option value="api">API</option>
        </select>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Connection Name
          </label>
          <input
            type="text"
            value={connectionParams.name}
            onChange={(e) => setConnectionParams(prev => ({ ...prev, name: e.target.value }))}
            className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="My Source Connection"
          />
        </div>

        {connectionType === 'database' && (
          <>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Host
              </label>
              <input
                type="text"
                value={connectionParams.host}
                onChange={(e) => setConnectionParams(prev => ({ ...prev, host: e.target.value }))}
                className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="localhost"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Port
              </label>
              <input
                type="text"
                value={connectionParams.port}
                onChange={(e) => setConnectionParams(prev => ({ ...prev, port: e.target.value }))}
                className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="5432"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Database
              </label>
              <input
                type="text"
                value={connectionParams.database}
                onChange={(e) => setConnectionParams(prev => ({ ...prev, database: e.target.value }))}
                className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="mydb"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Username
              </label>
              <input
                type="text"
                value={connectionParams.username}
                onChange={(e) => setConnectionParams(prev => ({ ...prev, username: e.target.value }))}
                className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="username"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Password
              </label>
              <input
                type="password"
                value={connectionParams.password}
                onChange={(e) => setConnectionParams(prev => ({ ...prev, password: e.target.value }))}
                className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="password"
              />
            </div>
          </>
        )}
      </div>

      <div className="flex justify-end">
        <button
          onClick={handleTest}
          className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
        >
          Test Connection
        </button>
      </div>

      {config && (
        <div className="bg-green-50 border border-green-200 rounded-md p-4">
          <div className="flex">
            <svg className="h-5 w-5 text-green-400" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
            <div className="ml-3">
              <p className="text-sm text-green-700">
                Connection test successful! Configuration saved.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Similar components for TargetConnectionStep, SchemaMappingStep, MigrationOptionsStep, and ReviewStep
// would be implemented here with similar patterns

const TargetConnectionStep: React.FC<{
  config: ConnectionConfig | null;
  onChange: (config: ConnectionConfig | null) => void;
}> = ({ config, onChange }) => {
  // Similar implementation to SourceConnectionStep
  return <div>Target Connection Step - Implementation similar to Source</div>;
};

const SchemaMappingStep: React.FC<{
  sourceConfig: ConnectionConfig | null;
  targetConfig: ConnectionConfig | null;
  mapping: any;
  onChange: (mapping: any) => void;
}> = ({ sourceConfig, targetConfig, mapping, onChange }) => {
  // Implementation for schema mapping
  return <div>Schema Mapping Step - AI-powered field mapping interface</div>;
};

const MigrationOptionsStep: React.FC<{
  options: any;
  onChange: (options: any) => void;
}> = ({ options, onChange }) => {
  return (
    <div className="space-y-6">
      <h3 className="text-lg font-medium text-gray-900">Migration Options</h3>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Migration Name
          </label>
          <input
            type="text"
            value={options.name}
            onChange={(e) => onChange({ ...options, name: e.target.value })}
            className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="My Migration"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Batch Size
          </label>
          <input
            type="number"
            value={options.batchSize}
            onChange={(e) => onChange({ ...options, batchSize: parseInt(e.target.value) })}
            className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
            min="1"
            max="10000"
          />
        </div>
      </div>

      <div className="space-y-4">
        <div className="flex items-center">
          <input
            type="checkbox"
            id="validateData"
            checked={options.validateData}
            onChange={(e) => onChange({ ...options, validateData: e.target.checked })}
            className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
          />
          <label htmlFor="validateData" className="ml-2 block text-sm text-gray-900">
            Validate data during migration
          </label>
        </div>

        <div className="flex items-center">
          <input
            type="checkbox"
            id="createSnapshots"
            checked={options.createSnapshots}
            onChange={(e) => onChange({ ...options, createSnapshots: e.target.checked })}
            className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
          />
          <label htmlFor="createSnapshots" className="ml-2 block text-sm text-gray-900">
            Create snapshots for rollback
          </label>
        </div>
      </div>
    </div>
  );
};

const ReviewStep: React.FC<{
  sourceConfig: ConnectionConfig | null;
  targetConfig: ConnectionConfig | null;
  schemaMapping: any;
  options: any;
}> = ({ sourceConfig, targetConfig, schemaMapping, options }) => {
  return (
    <div className="space-y-6">
      <h3 className="text-lg font-medium text-gray-900">Review Migration</h3>

      <div className="bg-gray-50 rounded-lg p-4 space-y-4">
        <div>
          <h4 className="font-medium text-gray-900">Migration Name</h4>
          <p className="text-gray-600">{options.name}</p>
        </div>

        <div>
          <h4 className="font-medium text-gray-900">Source</h4>
          <p className="text-gray-600">{sourceConfig?.name} ({sourceConfig?.type})</p>
        </div>

        <div>
          <h4 className="font-medium text-gray-900">Target</h4>
          <p className="text-gray-600">{targetConfig?.name} ({targetConfig?.type})</p>
        </div>

        <div>
          <h4 className="font-medium text-gray-900">Options</h4>
          <ul className="text-gray-600 space-y-1">
            <li>Batch Size: {options.batchSize}</li>
            <li>Data Validation: {options.validateData ? 'Enabled' : 'Disabled'}</li>
            <li>Snapshots: {options.createSnapshots ? 'Enabled' : 'Disabled'}</li>
          </ul>
        </div>
      </div>
    </div>
  );
};