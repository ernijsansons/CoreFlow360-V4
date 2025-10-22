import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { exportService } from '@/lib/api/services/export.service'
import { toast } from '@/components/ui/toast'

// Query Keys
export const exportKeys = {
  all: ['export'] as const,
  progress: (jobId: string) => [...exportKeys.all, 'progress', jobId] as const,
}

// Hooks

export function useCreateExport() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (params: {
      entity_type: 'leads' | 'contacts' | 'companies' | 'invoices' | 'transactions' | 'journal_entries'
      format: 'csv' | 'excel' | 'json' | 'pdf'
      filters?: Record<string, unknown>
      columns?: string[]
    }) => exportService.createExport(params),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: exportKeys.progress(data.data.job_id) })
      toast({
        title: 'Export started',
        description: 'Your export is being generated',
      })
    },
  })
}

export function useExportProgress(jobId: string, enabled = true) {
  return useQuery({
    queryKey: exportKeys.progress(jobId),
    queryFn: () => exportService.getExportProgress(jobId),
    enabled: enabled && !!jobId,
    refetchInterval: (data) => {
      // Stop polling if export is complete or failed
      if (data?.data?.status === 'completed' || data?.data?.status === 'failed') {
        return false
      }
      return 2000 // Poll every 2 seconds while in progress
    },
    staleTime: 0, // Always fetch fresh data
  })
}

export function useDownloadExport() {
  return useMutation({
    mutationFn: async (jobId: string) => {
      const response = await exportService.downloadExport(jobId)

      // Create blob and download
      const blob = new Blob([response.data as Blob], {
        type: response.data.type || 'application/octet-stream'
      })
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `export-${jobId}.${getFileExtension(response.data.type)}`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)

      return response
    },
    onSuccess: () => {
      toast({
        title: 'Download started',
        description: 'Your export file is downloading',
      })
    },
    onError: () => {
      toast({
        title: 'Download failed',
        description: 'Failed to download export file',
        variant: 'destructive',
      })
    },
  })
}

function getFileExtension(contentType?: string): string {
  if (!contentType) return 'bin'

  const extensions: Record<string, string> = {
    'text/csv': 'csv',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
    'application/json': 'json',
    'application/pdf': 'pdf',
  }

  return extensions[contentType] || 'bin'
}
