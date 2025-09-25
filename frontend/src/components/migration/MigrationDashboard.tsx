import React, { useState, useEffect } from 'react';
import { MigrationList } from './MigrationList';
import { MigrationWizard } from './MigrationWizard';
import { MigrationProgress } from './MigrationProgress';
import { ConnectionTester } from './ConnectionTester';

export interface Migration {
  id: string;
  name: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'paused';
  progress: number;
  phase: string;
  startTime?: Date;
  endTime?: Date;
  sourceType: string;
  targetType: string;
  recordsProcessed: number;
  recordsTotal: number;
  errorCount: number;
}

export const MigrationDashboard: React.FC = () => {
  const [migrations, setMigrations] = useState<Migration[]>([]);
  const [selectedMigration, setSelectedMigration] = useState<string | null>(null);
  const [showWizard, setShowWizard] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadMigrations();
  }, []);

  const loadMigrations = async () => {
    try {
      const response = await fetch('/api/migrations');
      const data = await response.json();
      setMigrations(data.migrations || []);
    } catch (error) {
      console.error('Failed to load migrations:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateMigration = () => {
    setShowWizard(true);
  };

  const handleMigrationCreated = (migrationId: string) => {
    setShowWizard(false);
    setSelectedMigration(migrationId);
    loadMigrations();
  };

  const handleMigrationSelect = (migrationId: string) => {
    setSelectedMigration(migrationId);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">Migration Center</h1>
        <p className="mt-2 text-gray-600">
          Manage and monitor your data migrations
        </p>
      </div>

      {showWizard ? (
        <MigrationWizard
          onComplete={handleMigrationCreated}
          onCancel={() => setShowWizard(false)}
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="lg:col-span-2">
            <MigrationList
              migrations={migrations}
              selectedMigration={selectedMigration}
              onMigrationSelect={handleMigrationSelect}
              onCreateMigration={handleCreateMigration}
              onRefresh={loadMigrations}
            />
          </div>

          <div className="lg:col-span-1">
            {selectedMigration ? (
              <MigrationProgress migrationId={selectedMigration} />
            ) : (
              <div className="space-y-6">
                <div className="bg-white rounded-lg shadow p-6">
                  <h3 className="text-lg font-medium text-gray-900 mb-4">
                    Quick Actions
                  </h3>
                  <div className="space-y-3">
                    <button
                      onClick={handleCreateMigration}
                      className="w-full bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors"
                    >
                      New Migration
                    </button>
                    <ConnectionTester />
                  </div>
                </div>

                <div className="bg-white rounded-lg shadow p-6">
                  <h3 className="text-lg font-medium text-gray-900 mb-4">
                    Migration Stats
                  </h3>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-gray-600">Total Migrations</span>
                      <span className="font-medium">{migrations.length}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">Running</span>
                      <span className="font-medium text-blue-600">
                        {migrations.filter(m => m.status === 'running').length}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">Completed</span>
                      <span className="font-medium text-green-600">
                        {migrations.filter(m => m.status === 'completed').length}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">Failed</span>
                      <span className="font-medium text-red-600">
                        {migrations.filter(m => m.status === 'failed').length}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};