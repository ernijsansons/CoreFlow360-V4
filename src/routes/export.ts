/**
 * Export API Routes
 * REST endpoints for managing export requests and downloads
 */

import { Router } from 'express'
import { z } from 'zod'
import { nanoid } from 'nanoid'
import { ExportEngine, ExportRequest } from '../services/export-engine'

const router = Router()

// Request validation schemas
const ExportRequestSchema = z.object({
  type: z.enum(['single-widget', 'dashboard', 'report', 'batch']),
  format: z.enum(['pdf', 'excel', 'powerpoint', 'csv', 'png', 'svg']),
  widgets: z.array(z.object({
    id: z.string(),
    title: z.string(),
    description: z.string().optional(),
    type: z.enum(['chart', 'table', 'kpi', 'text', 'image']),
    data: z.any(),
    config: z.any(),
    position: z.object({
      x: z.number(),
      y: z.number(),
      width: z.number(),
      height: z.number()
    }).optional()
  })),
  options: z.object({
    pageSize: z.enum(['A4', 'A3', 'Letter', 'Legal']).default('A4'),
    orientation: z.enum(['portrait', 'landscape']).default('portrait'),
    margins: z.object({
      top: z.number().default(20),
      right: z.number().default(20),
      bottom: z.number().default(20),
      left: z.number().default(20)
    }).default({}),
    includeTitle: z.boolean().default(true),
    includeDescription: z.boolean().default(true),
    includeTimestamp: z.boolean().default(true),
    includeBranding: z.boolean().default(true),
    includeFilters: z.boolean().default(true),
    dpi: z.enum([150, 300, 600]).default(300),
    compression: z.enum(['none', 'low', 'medium', 'high']).default('medium'),
    theme: z.enum(['light', 'dark', 'auto']).default('light'),
    colorScheme: z.enum(['default', 'monochrome', 'colorblind-friendly']).default('default'),
    fontSize: z.enum(['small', 'medium', 'large']).default('medium'),
    watermark: z.string().optional(),
    password: z.string().optional(),
    template: z.string().optional()
  }).default({}),
  metadata: z.object({
    dashboardId: z.string().optional(),
    dashboardTitle: z.string().optional(),
    filters: z.record(z.any()).optional(),
    dateRange: z.object({
      from: z.string().transform(str => new Date(str)),
      to: z.string().transform(str => new Date(str))
    }).optional()
  }).default({})
})

// POST /api/export - Create export request
router.post('/', async (req, res) => {
  try {
    const validatedData = ExportRequestSchema.parse(req.body)

    const exportRequest: ExportRequest = {
      id: nanoid(),
      ...validatedData,
      metadata: {
        ...validatedData.metadata,
        requestedBy: req.user?.id || 'anonymous',
        requestedAt: new Date(),
        userRole: req.user?.role || 'user',
        organizationId: req.user?.organizationId || 'default'
      }
    }

    // Get Durable Object instance
    const exportEngineId = req.env.EXPORT_ENGINE.idFromName('export-engine')
    const exportEngine = req.env.EXPORT_ENGINE.get(exportEngineId)

    // Start export process
    const downloadUrl = await exportEngine.processExportRequest(exportRequest)

    res.json({
      success: true,
      exportId: exportRequest.id,
      downloadUrl,
      estimatedCompletion: new Date(Date.now() + 30000), // 30 seconds estimate
      progressUrl: `/api/export/${exportRequest.id}/progress`
    })

  } catch (error: any) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        success: false,
        error: 'Validation error',
        details: error.errors
      })
    }

    res.status(500).json({
      success: false,
      error: 'Export request failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    })
  }
})

// GET /api/export/:id/progress - Get export progress
router.get('/:id/progress', async (req, res) => {
  try {
    const { id } = req.params

    // Get Durable Object instance
    const exportEngineId = req.env.EXPORT_ENGINE.idFromName('export-engine')
    const exportEngine = req.env.EXPORT_ENGINE.get(exportEngineId)

    // Get progress from storage
    const progressKey = `export:${id}`
    const progress = await exportEngine.storage.get(progressKey)

    if (!progress) {
      return res.status(404).json({
        success: false,
        error: 'Export not found'
      })
    }

    res.json({
      success: true,
      ...progress
    })

  } catch (error: any) {
    res.status(500).json({
      success: false,
      error: 'Failed to get export progress'
    })
  }
})

// WebSocket endpoint for real-time progress updates
router.get('/:id/progress/ws', async (req, res) => {
  try {
    const { id } = req.params

    // Upgrade to WebSocket
    const upgradeHeader = req.headers.upgrade
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
      return res.status(426).json({
        success: false,
        error: 'Expected WebSocket upgrade'
      })
    }

    // Get Durable Object instance
    const exportEngineId = req.env.EXPORT_ENGINE.idFromName('export-engine')
    const exportEngine = req.env.EXPORT_ENGINE.get(exportEngineId)

    // Forward to Durable Object WebSocket handler
    const response = await exportEngine.websocket(req)
    return response

  } catch (error: any) {
    res.status(500).json({
      success: false,
      error: 'WebSocket upgrade failed'
    })
  }
})

// GET /api/export/:id/download - Download completed export
router.get('/:id/download', async (req, res) => {
  try {
    const { id } = req.params

    // Get export metadata from R2
    const exportFile = await req.env.EXPORTS_BUCKET.get(`exports/${id}`)

    if (!exportFile) {
      return res.status(404).json({
        success: false,
        error: 'Export file not found'
      })
    }

    const metadata = exportFile.customMetadata
    const httpMetadata = exportFile.httpMetadata

    // Set appropriate headers
    res.set({
      'Content-Type': httpMetadata?.contentType || 'application/octet-stream',
      'Content-Disposition': httpMetadata?.contentDisposition || `attachment; filename="export-${id}"`,
      'Content-Length': exportFile.size.toString(),
      'Cache-Control': 'private, max-age=3600'
    })

    // Stream the file
    const arrayBuffer = await exportFile.arrayBuffer()
    const buffer = Buffer.from(arrayBuffer)

    res.send(buffer)

  } catch (error: any) {
    res.status(500).json({
      success: false,
      error: 'Download failed'
    })
  }
})

// DELETE /api/export/:id - Delete export file
router.delete('/:id', async (req, res) => {
  try {
    const { id } = req.params

    // Verify user has permission to delete
    const exportFile = await req.env.EXPORTS_BUCKET.get(`exports/${id}`)
    if (!exportFile) {
      return res.status(404).json({
        success: false,
        error: 'Export not found'
      })
    }

    const metadata = exportFile.customMetadata
    if (metadata?.requestedBy !== req.user?.id && req.user?.role !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Permission denied'
      })
    }

    // Delete from R2
    await req.env.EXPORTS_BUCKET.delete(`exports/${id}`)

    // Clean up progress tracking
    const exportEngineId = req.env.EXPORT_ENGINE.idFromName('export-engine')
    const exportEngine = req.env.EXPORT_ENGINE.get(exportEngineId)
    await exportEngine.storage.delete(`export:${id}`)

    res.json({
      success: true,
      message: 'Export deleted successfully'
    })

  } catch (error: any) {
    res.status(500).json({
      success: false,
      error: 'Failed to delete export'
    })
  }
})

// GET /api/export/history - Get user's export history
router.get('/history', async (req, res) => {
  try {
    const userId = req.user?.id
    const page = parseInt(req.query.page as string) || 1
    const limit = parseInt(req.query.limit as string) || 20
    const format = req.query.format as string

    // List exports from R2 with pagination
    const listOptions: any = {
      prefix: 'exports/',
      maxKeys: limit
    }

    if (req.query.cursor) {
      listOptions.cursor = req.query.cursor
    }

    const result = await req.env.EXPORTS_BUCKET.list(listOptions)

    // Filter by user and format
    const exports = result.objects
      .filter((obj: any) => {
        if (!obj.customMetadata?.requestedBy) return false
        if (userId && obj.customMetadata.requestedBy !== userId) return false
        if (format && !obj.key.endsWith(`.${format}`)) return false
        return true
      })
      .map((obj: any) => ({
        id: obj.key.replace('exports/', '').split('.')[0],
        filename: obj.key,
        size: obj.size,
        uploaded: obj.uploaded,
        format: obj.key.split('.').pop(),
        requestedBy: obj.customMetadata?.requestedBy,
        exportType: obj.customMetadata?.exportType,
        downloadUrl: `/api/export/${obj.key.replace('exports/', '').split('.')[0]}/download`
      }))

    res.json({
      success: true,
      exports,
      pagination: {
        page,
        limit,
        hasMore: result.truncated,
        nextCursor: result.cursor
      }
    })

  } catch (error: any) {
    res.status(500).json({
      success: false,
      error: 'Failed to get export history'
    })
  }
})

// POST /api/export/batch - Batch export multiple dashboards/widgets
router.post('/batch', async (req, res) => {
  try {
    const { exports, options = {} } = req.body

    if (!Array.isArray(exports) || exports.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid batch export request'
      })
    }

    const batchId = nanoid()
    const results = []

    // Process each export request
    for (let i = 0; i < exports.length; i++) {
      const exportData = exports[i]
      const validatedData = ExportRequestSchema.parse(exportData)

      const exportRequest: ExportRequest = {
        id: `${batchId}-${i + 1}`,
        ...validatedData,
        metadata: {
          ...validatedData.metadata,
          requestedBy: req.user?.id || 'anonymous',
          requestedAt: new Date(),
          userRole: req.user?.role || 'user',
          organizationId: req.user?.organizationId || 'default'
        }
      }

      // Get Durable Object instance
      const exportEngineId = req.env.EXPORT_ENGINE.idFromName('export-engine')
      const exportEngine = req.env.EXPORT_ENGINE.get(exportEngineId)

      try {
        const downloadUrl = await exportEngine.processExportRequest(exportRequest)
        results.push({
          success: true,
          exportId: exportRequest.id,
          downloadUrl,
          progressUrl: `/api/export/${exportRequest.id}/progress`
        })
      } catch (error: any) {
        results.push({
          success: false,
          exportId: exportRequest.id,
          error: error instanceof Error ? error.message : 'Export failed'
        })
      }
    }

    res.json({
      success: true,
      batchId,
      results,
      totalExports: exports.length,
      successfulExports: results.filter((r: any) => r.success).length
    })

  } catch (error: any) {
    res.status(500).json({
      success: false,
      error: 'Batch export failed'
    })
  }
})

// GET /api/export/templates - Get available export templates
router.get('/templates', async (req, res) => {
  try {
    const templates = [
      {
        id: 'executive-summary',
        name: 'Executive Summary',
        description: 'High-level overview with key metrics and trends',
        formats: ['pdf', 'powerpoint'],
        layout: 'portrait',
        sections: ['kpis', 'charts', 'summary']
      },
      {
        id: 'detailed-report',
        name: 'Detailed Report',
        description: 'Comprehensive report with all data and insights',
        formats: ['pdf', 'excel'],
        layout: 'portrait',
        sections: ['title', 'toc', 'summary', 'details', 'appendix']
      },
      {
        id: 'dashboard-snapshot',
        name: 'Dashboard Snapshot',
        description: 'Visual snapshot of the entire dashboard',
        formats: ['png', 'pdf'],
        layout: 'landscape',
        sections: ['dashboard']
      },
      {
        id: 'data-export',
        name: 'Data Export',
        description: 'Raw data export for analysis',
        formats: ['excel', 'csv'],
        layout: 'landscape',
        sections: ['data']
      }
    ]

    res.json({
      success: true,
      templates
    })

  } catch (error: any) {
    res.status(500).json({
      success: false,
      error: 'Failed to get templates'
    })
  }
})

export default router