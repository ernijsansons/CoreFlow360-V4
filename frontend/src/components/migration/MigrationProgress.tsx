import React, { useState, useEffect } from 'react';

interface MigrationMetrics {
  recordsProcessed: number;
  recordsTotal: number;
  recordsSuccess: number;
  recordsError: number;
  bytesProcessed: number;
  bytesTotal: number;
  throughputRecordsPerSecond: number;
  throughputBytesPerSecond: number;
  estimatedTimeRemaining: number;
  errorRate: number;
}

interface MigrationState {
  id: string;
  status: string;
  progress: number;
  phase: string;
  startTime?: Date;
  endTime?: Date;
  lastUpdate?: Date;
  metrics: MigrationMetrics;
}

interface AuditEntry {
  id: string;
  timestamp: Date;
  action: string;
  actor: string;
  details: any;
}

interface MigrationProgressProps {
  migrationId: string;
}

export const MigrationProgress: React.FC<MigrationProgressProps> = ({ migrationId }) => {
  const [state, setState] = useState<MigrationState | null>(null);
  const [auditLog, setAuditLog] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'overview' | 'metrics' | 'logs'>('overview');

  useEffect(() => {
    if (!migrationId) return;

    loadMigrationData();

    // Set up real-time updates via Server-Sent Events
    const eventSource = new EventSource(`/api/migration/${migrationId}/stream`);

    eventSource.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'state') {
        setState(data.data);
      } else {
        // Handle progress events
        setState(prev => prev ? { ...prev, ...data } : null);
      }
    };

    eventSource.onerror = (error) => {
      console.error('SSE error:', error);
      eventSource.close();
    };

    return () => {
      eventSource.close();
    };
  }, [migrationId]);

  const loadMigrationData = async () => {
    try {
      setLoading(true);
      const [progressResponse, auditResponse] = await Promise.all([
        fetch(`/api/migration/${migrationId}/progress`),
        fetch(`/api/migration/${migrationId}/audit?limit=20`)
      ]);

      const progressData = await progressResponse.json();
      const auditData = await auditResponse.json();

      if (progressData.migration) {
        setState({
          ...progressData.migration,
          metrics: progressData.metrics
        });
      }

      setAuditLog(auditData.auditLog || []);
    } catch (error) {
      console.error('Failed to load migration data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handlePause = async () => {
    try {
      await fetch(`/api/migration/${migrationId}/pause`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'User requested pause' })
      });
    } catch (error) {
      console.error('Failed to pause migration:', error);
    }
  };

  const handleResume = async () => {
    try {
      await fetch(`/api/migration/${migrationId}/resume`, {
        method: 'POST'
      });
    } catch (error) {
      console.error('Failed to resume migration:', error);
    }
  };

  const handleCancel = async () => {
    if (!confirm('Are you sure you want to cancel this migration?')) return;

    try {
      await fetch(`/api/migration/${migrationId}/cancel`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'User cancelled' })
      });
    } catch (error) {
      console.error('Failed to cancel migration:', error);
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatDuration = (seconds: number) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);

    if (hours > 0) {
      return `${hours}h ${minutes}m ${secs}s`;
    } else if (minutes > 0) {
      return `${minutes}m ${secs}s`;
    } else {
      return `${secs}s`;
    }
  };

  if (loading) {
    return (
      <div className="bg-white rounded-lg shadow p-6">
        <div className="animate-pulse">
          <div className="h-4 bg-gray-200 rounded w-3/4 mb-4"></div>
          <div className="h-4 bg-gray-200 rounded w-1/2 mb-2"></div>
          <div className="h-4 bg-gray-200 rounded w-2/3"></div>
        </div>
      </div>
    );
  }

  if (!state) {
    return (
      <div className="bg-white rounded-lg shadow p-6">
        <div className="text-center text-gray-500">
          Migration not found
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow">
      <div className="px-6 py-4 border-b border-gray-200">
        <h3 className="text-lg font-medium text-gray-900">Migration Progress</h3>
        <div className="mt-2 flex items-center space-x-4">
          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
            state.status === 'running' ? 'bg-blue-100 text-blue-800' :
            state.status === 'completed' ? 'bg-green-100 text-green-800' :
            state.status === 'failed' ? 'bg-red-100 text-red-800' :
            state.status === 'paused' ? 'bg-yellow-100 text-yellow-800' :
            'bg-gray-100 text-gray-800'
          }`}>
            {state.status.charAt(0).toUpperCase() + state.status.slice(1)}
          </span>
          <span className="text-sm text-gray-500">{state.phase}</span>
        </div>
      </div>

      <div className="px-6 py-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm text-gray-600">Overall Progress</span>
          <span className="text-sm font-medium">{Math.round(state.progress)}%</span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-2 mb-4">
          <div
            className="bg-blue-600 h-2 rounded-full transition-all duration-300"
            style={{ width: `${Math.min(state.progress, 100)}%` }}
          ></div>
        </div>

        {state.status === 'running' && (
          <div className="flex space-x-2 mb-4">
            <button
              onClick={handlePause}
              className="bg-yellow-600 text-white px-3 py-1 rounded text-sm hover:bg-yellow-700 transition-colors"
            >
              Pause
            </button>
            <button
              onClick={handleCancel}
              className="bg-red-600 text-white px-3 py-1 rounded text-sm hover:bg-red-700 transition-colors"
            >
              Cancel
            </button>
          </div>
        )}

        {state.status === 'paused' && (
          <div className="flex space-x-2 mb-4">
            <button
              onClick={handleResume}
              className="bg-green-600 text-white px-3 py-1 rounded text-sm hover:bg-green-700 transition-colors"
            >
              Resume
            </button>
            <button
              onClick={handleCancel}
              className="bg-red-600 text-white px-3 py-1 rounded text-sm hover:bg-red-700 transition-colors"
            >
              Cancel
            </button>
          </div>
        )}
      </div>

      <div className="border-b border-gray-200">
        <nav className="flex space-x-8 px-6">
          {(['overview', 'metrics', 'logs'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </nav>
      </div>

      <div className="px-6 py-4">
        {activeTab === 'overview' && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <div className="text-sm text-gray-600">Records Processed</div>
                <div className="text-lg font-semibold">
                  {state.metrics.recordsProcessed.toLocaleString()} / {state.metrics.recordsTotal.toLocaleString()}
                </div>
              </div>
              <div>
                <div className="text-sm text-gray-600">Data Processed</div>
                <div className="text-lg font-semibold">
                  {formatBytes(state.metrics.bytesProcessed)} / {formatBytes(state.metrics.bytesTotal)}
                </div>
              </div>
              <div>
                <div className="text-sm text-gray-600">Success Rate</div>
                <div className="text-lg font-semibold text-green-600">
                  {((state.metrics.recordsSuccess / Math.max(state.metrics.recordsProcessed, 1)) * 100).toFixed(1)}%
                </div>
              </div>
              <div>
                <div className="text-sm text-gray-600">Errors</div>
                <div className="text-lg font-semibold text-red-600">
                  {state.metrics.recordsError.toLocaleString()}
                </div>
              </div>
            </div>

            {state.metrics.estimatedTimeRemaining > 0 && (
              <div>
                <div className="text-sm text-gray-600">Estimated Time Remaining</div>
                <div className="text-lg font-semibold">
                  {formatDuration(state.metrics.estimatedTimeRemaining)}
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'metrics' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 gap-4">
              <div className="flex justify-between">
                <span className="text-sm text-gray-600">Throughput (Records/sec)</span>
                <span className="font-medium">{state.metrics.throughputRecordsPerSecond.toFixed(2)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-600">Throughput (Bytes/sec)</span>
                <span className="font-medium">{formatBytes(state.metrics.throughputBytesPerSecond)}/s</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-600">Error Rate</span>
                <span className="font-medium text-red-600">{state.metrics.errorRate.toFixed(2)}%</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-600">Start Time</span>
                <span className="font-medium">{state.startTime ? new Date(state.startTime).toLocaleString() : 'N/A'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-600">Last Update</span>
                <span className="font-medium">{state.lastUpdate ? new Date(state.lastUpdate).toLocaleString() : 'N/A'}</span>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'logs' && (
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {auditLog.length === 0 ? (
              <div className="text-center text-gray-500 py-4">No logs available</div>
            ) : (
              auditLog.map((entry) => (
                <div key={entry.id} className="border-l-4 border-gray-200 pl-3 py-2">
                  <div className="flex justify-between items-start">
                    <span className="text-sm font-medium">{entry.action}</span>
                    <span className="text-xs text-gray-500">
                      {new Date(entry.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  {entry.details && (
                    <div className="text-xs text-gray-600 mt-1">
                      {typeof entry.details === 'string' ? entry.details : JSON.stringify(entry.details)}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
};