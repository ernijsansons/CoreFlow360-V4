import React from 'react';
import { Migration } from './MigrationDashboard';

interface MigrationListProps {
  migrations: Migration[];
  selectedMigration: string | null;
  onMigrationSelect: (id: string) => void;
  onCreateMigration: () => void;
  onRefresh: () => void;
}

const StatusBadge: React.FC<{ status: Migration['status'] }> = ({ status }) => {
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running':
        return 'bg-blue-100 text-blue-800';
      case 'completed':
        return 'bg-green-100 text-green-800';
      case 'failed':
        return 'bg-red-100 text-red-800';
      case 'paused':
        return 'bg-yellow-100 text-yellow-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(status)}`}>
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
};

const ProgressBar: React.FC<{ progress: number; status: Migration['status'] }> = ({ progress, status }) => {
  const getProgressColor = (status: string) => {
    switch (status) {
      case 'running':
        return 'bg-blue-600';
      case 'completed':
        return 'bg-green-600';
      case 'failed':
        return 'bg-red-600';
      case 'paused':
        return 'bg-yellow-600';
      default:
        return 'bg-gray-600';
    }
  };

  return (
    <div className="w-full bg-gray-200 rounded-full h-2">
      <div
        className={`h-2 rounded-full transition-all duration-300 ${getProgressColor(status)}`}
        style={{ width: `${Math.min(progress, 100)}%` }}
      ></div>
    </div>
  );
};

export const MigrationList: React.FC<MigrationListProps> = ({
  migrations,
  selectedMigration,
  onMigrationSelect,
  onCreateMigration,
  onRefresh
}) => {
  const formatDate = (date?: Date) => {
    if (!date) return 'N/A';
    return new Intl.DateTimeFormat('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    }).format(new Date(date));
  };

  const formatDuration = (start?: Date, end?: Date) => {
    if (!start) return 'N/A';
    const endTime = end || new Date();
    const diff = endTime.getTime() - new Date(start).getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);

    if (hours > 0) {
      return `${hours}h ${minutes % 60}m`;
    }
    return `${minutes}m`;
  };

  return (
    <div className="bg-white rounded-lg shadow">
      <div className="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
        <h2 className="text-lg font-medium text-gray-900">Migrations</h2>
        <div className="flex space-x-3">
          <button
            onClick={onRefresh}
            className="text-gray-400 hover:text-gray-600 transition-colors"
            title="Refresh"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
          </button>
          <button
            onClick={onCreateMigration}
            className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors text-sm"
          >
            New Migration
          </button>
        </div>
      </div>

      <div className="divide-y divide-gray-200">
        {migrations.length === 0 ? (
          <div className="px-6 py-12 text-center">
            <svg className="mx-auto h-12 w-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M9 19l3 3m0 0l3-3m-3 3V10" />
            </svg>
            <h3 className="mt-2 text-sm font-medium text-gray-900">No migrations</h3>
            <p className="mt-1 text-sm text-gray-500">Get started by creating your first migration.</p>
            <div className="mt-6">
              <button
                onClick={onCreateMigration}
                className="inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                <svg className="-ml-1 mr-2 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                </svg>
                New Migration
              </button>
            </div>
          </div>
        ) : (
          migrations.map((migration) => (
            <div
              key={migration.id}
              className={`px-6 py-4 cursor-pointer hover:bg-gray-50 transition-colors ${
                selectedMigration === migration.id ? 'bg-blue-50 border-l-4 border-blue-600' : ''
              }`}
              onClick={() => onMigrationSelect(migration.id)}
            >
              <div className="flex items-center justify-between">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center space-x-3">
                    <h3 className="text-sm font-medium text-gray-900 truncate">
                      {migration.name}
                    </h3>
                    <StatusBadge status={migration.status} />
                  </div>

                  <div className="mt-2 flex items-center space-x-4 text-sm text-gray-500">
                    <span>{migration.sourceType} → {migration.targetType}</span>
                    <span>•</span>
                    <span>{migration.phase}</span>
                  </div>

                  <div className="mt-3">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-gray-500">
                        {migration.recordsProcessed.toLocaleString()} / {migration.recordsTotal.toLocaleString()} records
                      </span>
                      <span className="text-xs text-gray-500">
                        {Math.round(migration.progress)}%
                      </span>
                    </div>
                    <ProgressBar progress={migration.progress} status={migration.status} />
                  </div>

                  <div className="mt-2 flex items-center justify-between text-xs text-gray-500">
                    <span>
                      Started: {formatDate(migration.startTime)}
                    </span>
                    <span>
                      Duration: {formatDuration(migration.startTime, migration.endTime)}
                    </span>
                    {migration.errorCount > 0 && (
                      <span className="text-red-600">
                        {migration.errorCount} errors
                      </span>
                    )}
                  </div>
                </div>

                <div className="ml-4 flex-shrink-0">
                  <svg className="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};