/**
 * Export Hook
 * Client-side export functionality with progress tracking
 */

import { useState, useCallback, useRef, useEffect } from 'react'
import { toast } from 'sonner'

export interface ExportRequest {
  type: 'single-widget' | 'dashboard' | 'report' | 'batch'
  format: 'pdf' | 'excel' | 'powerpoint' | 'csv' | 'png' | 'svg'
  widgets: any[]
  options?: ExportOptions
  metadata?: any
}

export interface ExportOptions {
  pageSize?: 'A4' | 'A3' | 'Letter' | 'Legal'
  orientation?: 'portrait' | 'landscape'
  includeTitle?: boolean
  includeDescription?: boolean
  includeTimestamp?: boolean
  includeBranding?: boolean
  includeFilters?: boolean
  dpi?: 150 | 300 | 600
  theme?: 'light' | 'dark' | 'auto'
  watermark?: string
  password?: string
  template?: string
}

export interface ExportProgress {
  stage: 'preparing' | 'rendering' | 'compiling' | 'uploading' | 'completed' | 'failed'
  progress: number
  message: string
  estimatedCompletion?: Date
  downloadUrl?: string
  error?: string
}

export interface ExportResult {
  success: boolean
  exportId: string
  downloadUrl?: string
  progressUrl?: string
  error?: string
}

export const useExport = () => {
  const [isExporting, setIsExporting] = useState(false)
  const [progress, setProgress] = useState<ExportProgress | null>(null)
  const [history, setHistory] = useState<any[]>([])
  const [templates, setTemplates] = useState<any[]>([])

  const wsRef = useRef<WebSocket | null>(null)
  const currentExportId = useRef<string | null>(null)

  // Start export process
  const startExport = useCallback(async (request: ExportRequest): Promise<ExportResult> => {
    setIsExporting(true)
    setProgress({
      stage: 'preparing',
      progress: 0,
      message: 'Preparing export...'
    })

    try {
      const response = await fetch('/api/export', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        },
        body: JSON.stringify(request)
      })

      const result = await response.json()

      if (!result.success) {
        throw new Error(result.error || 'Export failed')
      }

      currentExportId.current = result.exportId

      // Start progress tracking
      startProgressTracking(result.exportId)

      toast.success('Export started successfully')

      return {
        success: true,
        exportId: result.exportId,
        downloadUrl: result.downloadUrl,
        progressUrl: result.progressUrl
      }

    } catch (error) {
      setIsExporting(false)
      setProgress({
        stage: 'failed',
        progress: 0,
        message: 'Export failed',
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      toast.error('Failed to start export')

      return {
        success: false,
        exportId: '',
        error: error instanceof Error ? error.message : 'Unknown error'
      }
    }
  }, [])

  // Start progress tracking via WebSocket
  const startProgressTracking = useCallback((exportId: string) => {
    const wsUrl = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/api/export/${exportId}/progress/ws`

    wsRef.current = new WebSocket(wsUrl)

    wsRef.current.onopen = () => {
      wsRef.current?.send(JSON.stringify({
        type: 'subscribe',
        exportId
      }))
    }

    wsRef.current.onmessage = (event) => {
      const data = JSON.parse(event.data)

      if (data.type === 'progress') {
        setProgress(data)

        // Handle completion
        if (data.stage === 'completed') {
          setIsExporting(false)
          toast.success('Export completed successfully')

          // Auto-download if requested
          if (data.downloadUrl) {
            window.open(data.downloadUrl, '_blank')
          }
        } else if (data.stage === 'failed') {
          setIsExporting(false)
          toast.error('Export failed: ' + (data.error || 'Unknown error'))
        }
      }
    }

    wsRef.current.onerror = () => {
      // Fallback to polling
      startPollingProgress(exportId)
    }

    wsRef.current.onclose = () => {
      wsRef.current = null
    }
  }, [])

  // Fallback progress tracking via polling
  const startPollingProgress = useCallback((exportId: string) => {
    const pollProgress = async () => {
      try {
        const response = await fetch(`/api/export/${exportId}/progress`, {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('authToken')}`
          }
        })

        const data = await response.json()

        if (data.success) {
          setProgress(data)

          if (data.stage === 'completed' || data.stage === 'failed') {
            setIsExporting(false)
            return
          }

          // Continue polling
          setTimeout(pollProgress, 2000)
        }
      } catch (error) {
        console.error('Failed to poll progress:', error)
        setTimeout(pollProgress, 5000) // Retry after 5 seconds
      }
    }

    pollProgress()
  }, [])

  // Cancel export
  const cancelExport = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close()
    }

    if (currentExportId.current) {
      // Send cancel request to server
      fetch(`/api/export/${currentExportId.current}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        }
      }).catch(console.error)
    }

    setIsExporting(false)
    setProgress(null)
    currentExportId.current = null

    toast.info('Export cancelled')
  }, [])

  // Load export history
  const loadHistory = useCallback(async (page = 1, limit = 20, format?: string) => {
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        limit: limit.toString()
      })

      if (format) {
        params.append('format', format)
      }

      const response = await fetch(`/api/export/history?${params}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        }
      })

      const data = await response.json()

      if (data.success) {
        setHistory(data.exports)
        return data
      }
    } catch (error) {
      console.error('Failed to load export history:', error)
      toast.error('Failed to load export history')
    }

    return null
  }, [])

  // Load export templates
  const loadTemplates = useCallback(async () => {
    try {
      const response = await fetch('/api/export/templates', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        }
      })

      const data = await response.json()

      if (data.success) {
        setTemplates(data.templates)
        return data.templates
      }
    } catch (error) {
      console.error('Failed to load export templates:', error)
      toast.error('Failed to load export templates')
    }

    return []
  }, [])

  // Download export file
  const downloadExport = useCallback(async (exportId: string) => {
    try {
      const response = await fetch(`/api/export/${exportId}/download`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        }
      })

      if (response.ok) {
        const blob = await response.blob()
        const url = URL.createObjectURL(blob)

        // Get filename from Content-Disposition header
        const contentDisposition = response.headers.get('Content-Disposition')
        const filename = contentDisposition
          ? contentDisposition.split('filename=')[1]?.replace(/"/g, '')
          : `export-${exportId}`

        const a = document.createElement('a')
        a.href = url
        a.download = filename
        a.click()

        URL.revokeObjectURL(url)
        toast.success('Download started')
      } else {
        throw new Error('Download failed')
      }
    } catch (error) {
      console.error('Download failed:', error)
      toast.error('Download failed')
    }
  }, [])

  // Delete export
  const deleteExport = useCallback(async (exportId: string) => {
    try {
      const response = await fetch(`/api/export/${exportId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        }
      })

      const data = await response.json()

      if (data.success) {
        setHistory(prev => prev.filter(item => item.id !== exportId))
        toast.success('Export deleted')
      } else {
        throw new Error(data.error || 'Delete failed')
      }
    } catch (error) {
      console.error('Failed to delete export:', error)
      toast.error('Failed to delete export')
    }
  }, [])

  // Batch export
  const batchExport = useCallback(async (exports: ExportRequest[], options?: any) => {
    try {
      const response = await fetch('/api/export/batch', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        },
        body: JSON.stringify({ exports, options })
      })

      const result = await response.json()

      if (result.success) {
        toast.success(`Batch export started: ${result.successfulExports}/${result.totalExports} successful`)
        return result
      } else {
        throw new Error(result.error || 'Batch export failed')
      }
    } catch (error) {
      console.error('Batch export failed:', error)
      toast.error('Batch export failed')
      return null
    }
  }, [])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (wsRef.current) {
        wsRef.current.close()
      }
    }
  }, [])

  // Convenience methods for common export types
  const exportWidget = useCallback((widget: any, format: string, options?: ExportOptions) => {
    return startExport({
      type: 'single-widget',
      format: format as any,
      widgets: [widget],
      options,
      metadata: {
        dashboardTitle: `${widget.title} Export`,
        dashboardId: widget.dashboardId
      }
    })
  }, [startExport])

  const exportDashboard = useCallback((widgets: any[], dashboardTitle: string, format: string, options?: ExportOptions) => {
    return startExport({
      type: 'dashboard',
      format: format as any,
      widgets,
      options,
      metadata: {
        dashboardTitle,
        dashboardId: widgets[0]?.dashboardId
      }
    })
  }, [startExport])

  return {
    // State
    isExporting,
    progress,
    history,
    templates,

    // Actions
    startExport,
    cancelExport,
    loadHistory,
    loadTemplates,
    downloadExport,
    deleteExport,
    batchExport,

    // Convenience methods
    exportWidget,
    exportDashboard,

    // Utils
    getProgressPercentage: () => progress?.progress || 0,
    getProgressMessage: () => progress?.message || '',
    isCompleted: () => progress?.stage === 'completed',
    isFailed: () => progress?.stage === 'failed',
    canCancel: () => isExporting && progress?.stage !== 'completed' && progress?.stage !== 'failed'
  }
}