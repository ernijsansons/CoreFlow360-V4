import React, { useState } from 'react';

interface ConnectionTest {
  type: string;
  name: string;
  parameters: Record<string, any>;
}

export const ConnectionTester: React.FC = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [connectionType, setConnectionType] = useState('database');
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<{ success: boolean; message: string } | null>(null);
  const [connectionParams, setConnectionParams] = useState({
    name: '',
    host: '',
    port: '',
    database: '',
    username: '',
    password: '',
    connectionString: '',
    filePath: '',
    apiUrl: '',
    apiKey: ''
  });

  const resetForm = () => {
    setConnectionParams({
      name: '',
      host: '',
      port: '',
      database: '',
      username: '',
      password: '',
      connectionString: '',
      filePath: '',
      apiUrl: '',
      apiKey: ''
    });
    setResult(null);
  };

  const handleTest = async () => {
    setTesting(true);
    setResult(null);

    try {
      const testConfig: ConnectionTest = {
        type: connectionType,
        name: connectionParams.name || 'Test Connection',
        parameters: getParametersForType()
      };

      const response = await fetch('/api/connections/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(testConfig)
      });

      const data = await response.json();
      setResult({
        success: data.success,
        message: data.message || (data.success ? 'Connection successful' : 'Connection failed')
      });
    } catch (error) {
      setResult({
        success: false,
        message: `Test failed: ${(error as Error).message}`
      });
    } finally {
      setTesting(false);
    }
  };

  const getParametersForType = () => {
    switch (connectionType) {
      case 'database':
        return {
          host: connectionParams.host,
          port: connectionParams.port,
          database: connectionParams.database,
          username: connectionParams.username,
          password: connectionParams.password,
          connectionString: connectionParams.connectionString
        };
      case 'file':
        return {
          filePath: connectionParams.filePath
        };
      case 'api':
        return {
          apiUrl: connectionParams.apiUrl,
          apiKey: connectionParams.apiKey
        };
      default:
        return {};
    }
  };

  const canTest = () => {
    switch (connectionType) {
      case 'database':
        return connectionParams.host && connectionParams.database;
      case 'file':
        return connectionParams.filePath;
      case 'api':
        return connectionParams.apiUrl;
      default:
        return false;
    }
  };

  if (!isOpen) {
    return (
      <button
        onClick={() => setIsOpen(true)}
        className="w-full bg-gray-100 text-gray-700 px-4 py-2 rounded-md hover:bg-gray-200 transition-colors text-left"
      >
        Test Connection
      </button>
    );
  }

  return (
    <div className="border border-gray-300 rounded-lg p-4 space-y-4">
      <div className="flex justify-between items-center">
        <h4 className="font-medium text-gray-900">Test Connection</h4>
        <button
          onClick={() => setIsOpen(false)}
          className="text-gray-400 hover:text-gray-600"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-2">
          Connection Type
        </label>
        <select
          value={connectionType}
          onChange={(e) => {
            setConnectionType(e.target.value);
            resetForm();
          }}
          className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="database">Database</option>
          <option value="file">File</option>
          <option value="api">API</option>
        </select>
      </div>

      {connectionType === 'database' && (
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">
                Host
              </label>
              <input
                type="text"
                value={connectionParams.host}
                onChange={(e) => setConnectionParams(prev => ({ ...prev, host: e.target.value }))}
                className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="localhost"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">
                Port
              </label>
              <input
                type="text"
                value={connectionParams.port}
                onChange={(e) => setConnectionParams(prev => ({ ...prev, port: e.target.value }))}
                className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="5432"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">
              Database
            </label>
            <input
              type="text"
              value={connectionParams.database}
              onChange={(e) => setConnectionParams(prev => ({ ...prev, database: e.target.value }))}
              className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="mydb"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">
                Username
              </label>
              <input
                type="text"
                value={connectionParams.username}
                onChange={(e) => setConnectionParams(prev => ({ ...prev, username: e.target.value }))}
                className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="username"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">
                Password
              </label>
              <input
                type="password"
                value={connectionParams.password}
                onChange={(e) => setConnectionParams(prev => ({ ...prev, password: e.target.value }))}
                className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="password"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">
              Connection String (Optional)
            </label>
            <input
              type="text"
              value={connectionParams.connectionString}
              onChange={(e) => setConnectionParams(prev => ({ ...prev, connectionString: e.target.value }))}
              className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="postgresql://user:pass@host:port/db"
            />
          </div>
        </div>
      )}

      {connectionType === 'file' && (
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">
            File Path
          </label>
          <input
            type="text"
            value={connectionParams.filePath}
            onChange={(e) => setConnectionParams(prev => ({ ...prev, filePath: e.target.value }))}
            className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="/path/to/file.csv"
          />
        </div>
      )}

      {connectionType === 'api' && (
        <div className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">
              API URL
            </label>
            <input
              type="text"
              value={connectionParams.apiUrl}
              onChange={(e) => setConnectionParams(prev => ({ ...prev, apiUrl: e.target.value }))}
              className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="https://api.example.com"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">
              API Key (Optional)
            </label>
            <input
              type="password"
              value={connectionParams.apiKey}
              onChange={(e) => setConnectionParams(prev => ({ ...prev, apiKey: e.target.value }))}
              className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="API Key"
            />
          </div>
        </div>
      )}

      {result && (
        <div className={`rounded-md p-3 ${
          result.success ? 'bg-green-50 border border-green-200' : 'bg-red-50 border border-red-200'
        }`}>
          <div className="flex">
            <svg className={`h-5 w-5 ${result.success ? 'text-green-400' : 'text-red-400'}`} fill="currentColor" viewBox="0 0 20 20">
              {result.success ? (
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              ) : (
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              )}
            </svg>
            <div className="ml-3">
              <p className={`text-sm ${result.success ? 'text-green-700' : 'text-red-700'}`}>
                {result.message}
              </p>
            </div>
          </div>
        </div>
      )}

      <div className="flex space-x-3">
        <button
          onClick={handleTest}
          disabled={!canTest() || testing}
          className="flex-1 bg-blue-600 text-white px-3 py-2 rounded-md hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors text-sm"
        >
          {testing ? (
            <div className="flex items-center justify-center">
              <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="m4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              Testing...
            </div>
          ) : (
            'Test Connection'
          )}
        </button>
        <button
          onClick={resetForm}
          className="px-3 py-2 border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50 transition-colors text-sm"
        >
          Clear
        </button>
      </div>
    </div>
  );
};