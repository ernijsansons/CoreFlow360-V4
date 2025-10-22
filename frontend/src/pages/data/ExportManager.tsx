import { useState } from 'react'
import {
  useCreateExport,
  useExportProgress,
  useDownloadExport,
} from '@/hooks/api'
import { Card } from '@/components/ui/card-refactored'
import { Button } from '@/components/ui/button-refactored'
import { Badge } from '@/components/ui/badge-refactored'
import {
  Loader2,
  Download,
  FileText,
  Database,
  CheckCircle2,
  XCircle,
  Clock,
} from 'lucide-react'

type EntityType = 'leads' | 'contacts' | 'companies' | 'invoices' | 'transactions' | 'journal_entries'
type ExportFormat = 'csv' | 'excel' | 'json' | 'pdf'

export function ExportManager() {
  const [selectedEntity, setSelectedEntity] = useState<EntityType>('leads')
  const [selectedFormat, setSelectedFormat] = useState<ExportFormat>('csv')
  const [activeJobId, setActiveJobId] = useState<string | null>(null)

  const createExport = useCreateExport()
  const { data: exportProgress } = useExportProgress(activeJobId || '', !!activeJobId)
  const downloadExport = useDownloadExport()

  const entities: Array<{ value: EntityType; label: string; icon: typeof FileText }> = [
    { value: 'leads', label: 'Leads', icon: FileText },
    { value: 'contacts', label: 'Contacts', icon: FileText },
    { value: 'companies', label: 'Companies', icon: FileText },
    { value: 'invoices', label: 'Invoices', icon: FileText },
    { value: 'transactions', label: 'Transactions', icon: Database },
    { value: 'journal_entries', label: 'Journal Entries', icon: Database },
  ]

  const formats: Array<{ value: ExportFormat; label: string; description: string }> = [
    { value: 'csv', label: 'CSV', description: 'Comma-separated values' },
    { value: 'excel', label: 'Excel', description: 'Microsoft Excel spreadsheet' },
    { value: 'json', label: 'JSON', description: 'JavaScript Object Notation' },
    { value: 'pdf', label: 'PDF', description: 'Portable Document Format' },
  ]

  const handleStartExport = () => {
    createExport.mutate(
      {
        entity_type: selectedEntity,
        format: selectedFormat,
      },
      {
        onSuccess: (data) => {
          setActiveJobId(data.data.job_id)
        },
      }
    )
  }

  const handleDownload = () => {
    if (activeJobId) {
      downloadExport.mutate(activeJobId, {
        onSuccess: () => {
          setActiveJobId(null)
        },
      })
    }
  }

  const getStatusIcon = (status?: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle2 className="h-5 w-5 text-green-500" />
      case 'failed':
        return <XCircle className="h-5 w-5 text-red-500" />
      case 'in_progress':
        return <Loader2 className="h-5 w-5 text-blue-500 animate-spin" />
      default:
        return <Clock className="h-5 w-5 text-gray-500" />
    }
  }

  return (
    <div className="container mx-auto py-8 space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Data Export</h1>
        <p className="text-gray-600 dark:text-gray-400 mt-2">
          Export your data in multiple formats for analysis or backup
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Export Configuration */}
        <Card className="p-6">
          <h2 className="text-2xl font-bold mb-6">Configure Export</h2>

          <div className="space-y-6">
            {/* Entity Selection */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
                Select Data Type
              </label>
              <div className="grid grid-cols-2 gap-3">
                {entities.map((entity) => {
                  const Icon = entity.icon
                  return (
                    <button
                      key={entity.value}
                      onClick={() => setSelectedEntity(entity.value)}
                      className={`p-4 border-2 rounded-lg transition-all text-left ${
                        selectedEntity === entity.value
                          ? 'border-brand-primary bg-brand-primary/5'
                          : 'border-gray-200 dark:border-gray-700 hover:border-brand-primary/50'
                      }`}
                    >
                      <Icon className="h-5 w-5 mb-2" />
                      <p className="font-medium">{entity.label}</p>
                    </button>
                  )
                })}
              </div>
            </div>

            {/* Format Selection */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
                Export Format
              </label>
              <div className="space-y-2">
                {formats.map((format) => (
                  <button
                    key={format.value}
                    onClick={() => setSelectedFormat(format.value)}
                    className={`w-full p-4 border-2 rounded-lg transition-all text-left ${
                      selectedFormat === format.value
                        ? 'border-brand-primary bg-brand-primary/5'
                        : 'border-gray-200 dark:border-gray-700 hover:border-brand-primary/50'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="font-medium">{format.label}</p>
                        <p className="text-sm text-gray-500">{format.description}</p>
                      </div>
                      {selectedFormat === format.value && (
                        <CheckCircle2 className="h-5 w-5 text-brand-primary" />
                      )}
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Start Export Button */}
            <Button
              className="w-full"
              size="lg"
              onClick={handleStartExport}
              disabled={createExport.isPending || !!activeJobId}
            >
              {createExport.isPending ? (
                <Loader2 className="h-5 w-5 mr-2 animate-spin" />
              ) : (
                <Download className="h-5 w-5 mr-2" />
              )}
              Start Export
            </Button>
          </div>
        </Card>

        {/* Export Progress */}
        <Card className="p-6">
          <h2 className="text-2xl font-bold mb-6">Export Status</h2>

          {activeJobId && exportProgress?.data ? (
            <div className="space-y-6">
              {/* Status Header */}
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  {getStatusIcon(exportProgress.data.status)}
                  <div>
                    <p className="font-medium capitalize">{exportProgress.data.status}</p>
                    <p className="text-sm text-gray-500">
                      {exportProgress.data.entity_type} → {exportProgress.data.format.toUpperCase()}
                    </p>
                  </div>
                </div>
                <Badge
                  variant={
                    exportProgress.data.status === 'completed'
                      ? 'default'
                      : exportProgress.data.status === 'failed'
                      ? 'destructive'
                      : 'secondary'
                  }
                >
                  {exportProgress.data.status}
                </Badge>
              </div>

              {/* Progress Bar */}
              {exportProgress.data.status === 'in_progress' && (
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium">Progress</span>
                    <span className="text-sm text-gray-500">
                      {exportProgress.data.progress}%
                    </span>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div
                      className="bg-brand-primary h-2 rounded-full transition-all"
                      style={{ width: `${exportProgress.data.progress}%` }}
                    />
                  </div>
                  {exportProgress.data.current_step && (
                    <p className="text-sm text-gray-500 mt-2">
                      {exportProgress.data.current_step}
                    </p>
                  )}
                </div>
              )}

              {/* Export Details */}
              <div className="space-y-3 text-sm">
                {exportProgress.data.total_records !== undefined && (
                  <div className="flex items-center justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Total Records</span>
                    <span className="font-medium">
                      {exportProgress.data.total_records.toLocaleString()}
                    </span>
                  </div>
                )}

                {exportProgress.data.processed_records !== undefined && (
                  <div className="flex items-center justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Processed</span>
                    <span className="font-medium">
                      {exportProgress.data.processed_records.toLocaleString()}
                    </span>
                  </div>
                )}

                {exportProgress.data.file_size && (
                  <div className="flex items-center justify-between">
                    <span className="text-gray-600 dark:text-gray-400">File Size</span>
                    <span className="font-medium">
                      {(exportProgress.data.file_size / 1024 / 1024).toFixed(2)} MB
                    </span>
                  </div>
                )}

                {exportProgress.data.estimated_completion && (
                  <div className="flex items-center justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Estimated Completion</span>
                    <span className="font-medium">
                      {new Date(exportProgress.data.estimated_completion).toLocaleTimeString()}
                    </span>
                  </div>
                )}
              </div>

              {/* Download/Error Actions */}
              {exportProgress.data.status === 'completed' && (
                <div className="pt-4 border-t">
                  <Button
                    className="w-full"
                    onClick={handleDownload}
                    disabled={downloadExport.isPending}
                  >
                    {downloadExport.isPending ? (
                      <Loader2 className="h-5 w-5 mr-2 animate-spin" />
                    ) : (
                      <Download className="h-5 w-5 mr-2" />
                    )}
                    Download File
                  </Button>
                </div>
              )}

              {exportProgress.data.status === 'failed' && (
                <div className="pt-4 border-t">
                  <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
                    <div className="flex items-start space-x-3">
                      <XCircle className="h-5 w-5 text-red-600 mt-0.5" />
                      <div>
                        <p className="font-medium text-red-900 dark:text-red-300">Export Failed</p>
                        <p className="text-sm text-red-700 dark:text-red-400 mt-1">
                          {exportProgress.data.error || 'An error occurred during export'}
                        </p>
                      </div>
                    </div>
                  </div>
                  <Button
                    className="w-full mt-4"
                    variant="outline"
                    onClick={() => setActiveJobId(null)}
                  >
                    Start New Export
                  </Button>
                </div>
              )}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-64 text-gray-500">
              <Database className="h-16 w-16 mb-4" />
              <p className="text-lg font-medium mb-2">No Active Export</p>
              <p className="text-sm">Configure and start an export to see progress here</p>
            </div>
          )}
        </Card>
      </div>
    </div>
  )
}
