/**
 * Advanced Export System
 * Multi-format data export with scheduling and automation
 */

import { createFileRoute } from '@tanstack/react-router';
import { useState, useEffect, useCallback } from 'react';
import { MainLayout } from '@/layouts/main-layout';
import { exportService, ExportRequest } from '@/lib/api/services/export.service';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import {
  Download,
  FileText,
  Table,
  FileSpreadsheet,
  FileJson,
  Plus,
  RefreshCw,
  Trash2,
  X,
  Clock,
  CheckCircle,
  AlertCircle,
  Loader2,
  Filter,
  Calendar,
  Settings,
  Play,
  Pause
} from 'lucide-react';

export const Route = createFileRoute('/export')({
  component: ExportPage,
});

type ExportType = 'contacts' | 'leads' | 'invoices' | 'transactions' | 'financial_report';
type ExportFormat = 'csv' | 'excel' | 'pdf' | 'json';

interface ExportConfig {
  exportType: ExportType;
  format: ExportFormat;
  filters: Record<string, any>;
  columns: string[];
  schedule?: {
    enabled: boolean;
    frequency: 'daily' | 'weekly' | 'monthly';
    time: string;
    nextRun?: string;
  };
}

function ExportPage() {
  const [exports, setExports] = useState<ExportRequest[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [showNewExport, setShowNewExport] = useState(false);
  const [selectedStatus, setSelectedStatus] = useState<string>('all');

  const [newExport, setNewExport] = useState<ExportConfig>({
    exportType: 'contacts',
    format: 'csv',
    filters: {},
    columns: [],
    schedule: {
      enabled: false,
      frequency: 'weekly',
      time: '09:00',
    },
  });

  const loadExports = useCallback(async () => {
    try {
      const params = selectedStatus !== 'all' ? { status: selectedStatus as any } : undefined;
      const response = await exportService.listExports(params);
      setExports(response.data);
    } catch (error) {
      console.error('Failed to load exports:', error);
    } finally {
      setIsLoading(false);
    }
  }, [selectedStatus]);

  useEffect(() => {
    void loadExports();
    const interval = setInterval(() => {
      void loadExports();
    }, 5000); // Poll every 5 seconds
    return () => clearInterval(interval);
  }, [loadExports]);

  const handleCreateExport = async () => {
    try {
      await exportService.createExport({
        export_type: newExport.exportType,
        format: newExport.format,
        filters: newExport.filters,
        columns: newExport.columns.length > 0 ? newExport.columns : undefined,
      });

      setShowNewExport(false);
      setNewExport({
        exportType: 'contacts',
        format: 'csv',
        filters: {},
        columns: [],
        schedule: { enabled: false, frequency: 'weekly', time: '09:00' },
      });

      loadExports();

      const event = new CustomEvent('show-toast', {
        detail: { message: 'Export created successfully', type: 'success' }
      });
      window.dispatchEvent(event);
    } catch (error) {
      const event = new CustomEvent('show-toast', {
        detail: { message: 'Failed to create export', type: 'error' }
      });
      window.dispatchEvent(event);
    }
  };

  const handleDownload = async (exportReq: ExportRequest) => {
    try {
      const blob = await exportService.downloadExport(exportReq.id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${exportReq.export_type}-${exportReq.format}-${new Date().toISOString().split('T')[0]}.${exportReq.format}`;
      a.click();
      URL.revokeObjectURL(url);

      const event = new CustomEvent('show-toast', {
        detail: { message: 'Download started', type: 'success' }
      });
      window.dispatchEvent(event);
    } catch (error) {
      const event = new CustomEvent('show-toast', {
        detail: { message: 'Failed to download export', type: 'error' }
      });
      window.dispatchEvent(event);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await exportService.deleteExport(id);
      loadExports();
      const event = new CustomEvent('show-toast', {
        detail: { message: 'Export deleted', type: 'success' }
      });
      window.dispatchEvent(event);
    } catch (error) {
      const event = new CustomEvent('show-toast', {
        detail: { message: 'Failed to delete export', type: 'error' }
      });
      window.dispatchEvent(event);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'processing':
        return <Loader2 className="w-5 h-5 text-blue-500 animate-spin" />;
      case 'pending':
        return <Clock className="w-5 h-5 text-yellow-500" />;
      case 'failed':
        return <AlertCircle className="w-5 h-5 text-red-500" />;
      default:
        return null;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400';
      case 'processing':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400';
      case 'pending':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400';
      case 'failed':
        return 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300';
    }
  };

  const getFormatIcon = (format: string) => {
    switch (format) {
      case 'csv':
        return <FileText className="w-4 h-4" />;
      case 'excel':
        return <FileSpreadsheet className="w-4 h-4" />;
      case 'pdf':
        return <FileText className="w-4 h-4" />;
      case 'json':
        return <FileJson className="w-4 h-4" />;
      default:
        return <FileText className="w-4 h-4" />;
    }
  };

  const exportTypes = [
    { value: 'contacts', label: 'Contacts', icon: '👤' },
    { value: 'leads', label: 'Leads', icon: '🎯' },
    { value: 'invoices', label: 'Invoices', icon: '📄' },
    { value: 'transactions', label: 'Transactions', icon: '💰' },
    { value: 'financial_report', label: 'Financial Report', icon: '📊' },
  ];

  const formats = [
    { value: 'csv', label: 'CSV', icon: FileText, description: 'Comma-separated values' },
    { value: 'excel', label: 'Excel', icon: FileSpreadsheet, description: 'Microsoft Excel format' },
    { value: 'pdf', label: 'PDF', icon: FileText, description: 'Portable document format' },
    { value: 'json', label: 'JSON', icon: FileJson, description: 'JavaScript object notation' },
  ];

  const filteredExports = exports.filter((exp) =>
    selectedStatus === 'all' || exp.status === selectedStatus
  );

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Data Export</h1>
            <p className="text-muted-foreground mt-1">
              Export your data in multiple formats with scheduling and automation
            </p>
          </div>
          <div className="flex items-center gap-3">
            <Button variant="outline" size="sm" onClick={loadExports}>
              <RefreshCw className="w-4 h-4 mr-2" />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setShowNewExport(true)}>
              <Plus className="w-4 h-4 mr-2" />
              New Export
            </Button>
          </div>
        </div>

        {/* Filters */}
        <Card className="p-4">
          <div className="flex items-center gap-4">
            <Filter className="w-4 h-4 text-muted-foreground" />
            <div className="flex items-center gap-2">
              <Button
                variant={selectedStatus === 'all' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSelectedStatus('all')}
              >
                All
              </Button>
              <Button
                variant={selectedStatus === 'completed' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSelectedStatus('completed')}
              >
                Completed
              </Button>
              <Button
                variant={selectedStatus === 'processing' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSelectedStatus('processing')}
              >
                Processing
              </Button>
              <Button
                variant={selectedStatus === 'pending' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSelectedStatus('pending')}
              >
                Pending
              </Button>
              <Button
                variant={selectedStatus === 'failed' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSelectedStatus('failed')}
              >
                Failed
              </Button>
            </div>
          </div>
        </Card>

        {/* New Export Modal */}
        {showNewExport && (
          <Card className="p-6 border-2 border-primary">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold">Create New Export</h2>
              <Button variant="ghost" size="sm" onClick={() => setShowNewExport(false)}>
                <X className="w-4 h-4" />
              </Button>
            </div>

            <div className="space-y-6">
              {/* Export Type */}
              <div>
                <label className="block text-sm font-medium mb-3">Data Type</label>
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
                  {exportTypes.map((type) => (
                    <button
                      key={type.value}
                      onClick={() => setNewExport({ ...newExport, exportType: type.value as ExportType })}
                      className={`p-4 border-2 rounded-lg text-center transition-all hover:border-primary ${
                        newExport.exportType === type.value
                          ? 'border-primary bg-primary/5'
                          : 'border-border'
                      }`}
                    >
                      <div className="text-2xl mb-2">{type.icon}</div>
                      <div className="text-sm font-medium">{type.label}</div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Format */}
              <div>
                <label className="block text-sm font-medium mb-3">Export Format</label>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {formats.map((format) => (
                    <button
                      key={format.value}
                      onClick={() => setNewExport({ ...newExport, format: format.value as ExportFormat })}
                      className={`p-4 border-2 rounded-lg text-left transition-all hover:border-primary ${
                        newExport.format === format.value
                          ? 'border-primary bg-primary/5'
                          : 'border-border'
                      }`}
                    >
                      <format.icon className="w-6 h-6 mb-2 text-primary" />
                      <div className="font-medium">{format.label}</div>
                      <div className="text-xs text-muted-foreground">{format.description}</div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Schedule (Optional) */}
              <div>
                <div className="flex items-center justify-between mb-3">
                  <label className="text-sm font-medium">Schedule Export</label>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setNewExport({
                      ...newExport,
                      schedule: { ...newExport.schedule!, enabled: !newExport.schedule!.enabled }
                    })}
                  >
                    {newExport.schedule?.enabled ? 'Disable' : 'Enable'}
                  </Button>
                </div>
                {newExport.schedule?.enabled && (
                  <Card className="p-4 space-y-3">
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="block text-xs font-medium mb-2">Frequency</label>
                        <select
                          value={newExport.schedule.frequency}
                          onChange={(e) => setNewExport({
                            ...newExport,
                            schedule: { ...newExport.schedule!, frequency: e.target.value as any }
                          })}
                          className="w-full h-9 px-3 rounded-md border border-input bg-background"
                        >
                          <option value="daily">Daily</option>
                          <option value="weekly">Weekly</option>
                          <option value="monthly">Monthly</option>
                        </select>
                      </div>
                      <div>
                        <label className="block text-xs font-medium mb-2">Time</label>
                        <Input
                          type="time"
                          value={newExport.schedule.time}
                          onChange={(e) => setNewExport({
                            ...newExport,
                            schedule: { ...newExport.schedule!, time: e.target.value }
                          })}
                        />
                      </div>
                    </div>
                  </Card>
                )}
              </div>

              {/* Actions */}
              <div className="flex justify-end gap-3 pt-4 border-t">
                <Button variant="outline" onClick={() => setShowNewExport(false)}>
                  Cancel
                </Button>
                <Button onClick={handleCreateExport}>
                  <Download className="w-4 h-4 mr-2" />
                  Create Export
                </Button>
              </div>
            </div>
          </Card>
        )}

        {/* Exports List */}
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-8 h-8 animate-spin text-primary" />
          </div>
        ) : filteredExports.length > 0 ? (
          <div className="grid grid-cols-1 gap-4">
            {filteredExports.map((exportReq) => (
              <Card key={exportReq.id} className="p-6 hover:shadow-lg transition-shadow">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4 flex-1">
                    {/* Status Icon */}
                    <div className="flex-shrink-0">
                      {getStatusIcon(exportReq.status)}
                    </div>

                    {/* Info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="font-semibold capitalize">
                          {exportReq.export_type.replace('_', ' ')}
                        </h3>
                        <div className="flex items-center gap-2 text-muted-foreground">
                          {getFormatIcon(exportReq.format)}
                          <span className="text-sm uppercase">{exportReq.format}</span>
                        </div>
                        <span className={`px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(exportReq.status)}`}>
                          {exportReq.status}
                        </span>
                      </div>

                      {/* Progress Bar */}
                      {exportReq.status === 'processing' && (
                        <div className="mb-2">
                          <div className="flex items-center justify-between text-xs text-muted-foreground mb-1">
                            <span>Processing...</span>
                            <span>{exportReq.progress_percent}%</span>
                          </div>
                          <div className="w-full h-2 bg-muted rounded-full overflow-hidden">
                            <div
                              className="h-full bg-primary transition-all duration-300"
                              style={{ width: `${exportReq.progress_percent}%` }}
                            />
                          </div>
                        </div>
                      )}

                      {/* Meta Info */}
                      <div className="flex items-center gap-4 text-sm text-muted-foreground">
                        <span>Created {new Date(exportReq.created_at).toLocaleString()}</span>
                        {exportReq.total_records && (
                          <span>{exportReq.total_records.toLocaleString()} records</span>
                        )}
                        {exportReq.file_size && (
                          <span>{(exportReq.file_size / 1024 / 1024).toFixed(2)} MB</span>
                        )}
                        {exportReq.expires_at && exportReq.status === 'completed' && (
                          <span className="text-yellow-600">
                            Expires {new Date(exportReq.expires_at).toLocaleDateString()}
                          </span>
                        )}
                      </div>

                      {exportReq.error_message && (
                        <p className="text-sm text-red-600 mt-2">{exportReq.error_message}</p>
                      )}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2 ml-4">
                    {exportReq.status === 'completed' && (
                      <Button size="sm" onClick={() => handleDownload(exportReq)}>
                        <Download className="w-4 h-4 mr-2" />
                        Download
                      </Button>
                    )}
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleDelete(exportReq.id)}
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        ) : (
          /* Empty State */
          <Card className="p-12">
            <div className="text-center">
              <Download className="mx-auto h-12 w-12 text-muted-foreground mb-4" />
              <h3 className="text-lg font-semibold mb-2">No exports found</h3>
              <p className="text-sm text-muted-foreground mb-6">
                {selectedStatus === 'all'
                  ? 'Create your first export to get started'
                  : `No ${selectedStatus} exports found`}
              </p>
              {selectedStatus === 'all' && (
                <Button onClick={() => setShowNewExport(true)}>
                  <Plus className="w-4 h-4 mr-2" />
                  Create Export
                </Button>
              )}
            </div>
          </Card>
        )}
      </div>
    </MainLayout>
  );
}
