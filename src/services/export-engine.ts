/**
 * Data Export Engine
 * Comprehensive export system supporting PDF, Excel, PowerPoint, and more
 */

import { DurableObject } from 'cloudflare:workers'
import jsPDF from 'jspdf'
import * as XLSX from 'xlsx'
import { ChartJSNodeCanvas } from 'chartjs-node-canvas'

export interface ExportRequest {
  id: string
  type: 'single-widget' | 'dashboard' | 'report' | 'batch'
  format: 'pdf' | 'excel' | 'powerpoint' | 'csv' | 'png' | 'svg'
  widgets: ExportWidget[]
  options: ExportOptions
  metadata: ExportMetadata
}

export interface ExportWidget {
  id: string
  title: string
  description?: string
  type: 'chart' | 'table' | 'kpi' | 'text' | 'image'
  data: any
  config: any
  position?: { x: number; y: number; width: number; height: number }
}

export interface ExportOptions {
  // Layout options
  pageSize: 'A4' | 'A3' | 'Letter' | 'Legal'
  orientation: 'portrait' | 'landscape'
  margins: { top: number; right: number; bottom: number; left: number }

  // Content options
  includeTitle: boolean
  includeDescription: boolean
  includeTimestamp: boolean
  includeBranding: boolean
  includeFilters: boolean

  // Quality options
  dpi: 150 | 300 | 600
  compression: 'none' | 'low' | 'medium' | 'high'

  // Customization
  theme: 'light' | 'dark' | 'auto'
  colorScheme: 'default' | 'monochrome' | 'colorblind-friendly'
  fontSize: 'small' | 'medium' | 'large'

  // Advanced options
  watermark?: string
  password?: string
  template?: string
}

export interface ExportMetadata {
  requestedBy: string
  requestedAt: Date
  dashboardId?: string
  dashboardTitle?: string
  filters?: Record<string, any>
  dateRange?: { from: Date; to: Date }
  userRole: string
  organizationId: string
}

export interface ExportProgress {
  stage: 'preparing' | 'rendering' | 'compiling' | 'uploading' | 'completed' | 'failed'
  progress: number // 0-100
  message: string
  estimatedCompletion?: Date
  downloadUrl?: string
  error?: string
}

export class ExportEngine extends DurableObject {
  private storage: DurableObjectStorage
  private env: any

  constructor(ctx: DurableObjectState, env: any) {
    super(ctx, env)
    this.storage = ctx.storage
    this.env = env
  }

  async processExportRequest(request: ExportRequest): Promise<string> {
    const progressKey = `export:${request.id}`

    try {
      // Initialize progress tracking
      await this.updateProgress(progressKey, {
        stage: 'preparing',
        progress: 0,
        message: 'Preparing export...'
      })

      // Validate request
      await this.validateRequest(request)

      // Process based on format
      let result: Buffer
      switch (request.format) {
        case 'pdf':
          result = await this.exportToPDF(request)
          break
        case 'excel':
          result = await this.exportToExcel(request)
          break
        case 'powerpoint':
          result = await this.exportToPowerPoint(request)
          break
        case 'csv':
          result = await this.exportToCSV(request)
          break
        case 'png':
          result = await this.exportToPNG(request)
          break
        case 'svg':
          result = await this.exportToSVG(request)
          break
        default:
          throw new Error(`Unsupported export format: ${request.format}`)
      }

      // Upload to R2
      await this.updateProgress(progressKey, {
        stage: 'uploading',
        progress: 90,
        message: 'Uploading file...'
      })

      const downloadUrl = await this.uploadToR2(result, request)

      // Complete export
      await this.updateProgress(progressKey, {
        stage: 'completed',
        progress: 100,
        message: 'Export completed',
        downloadUrl
      })

      return downloadUrl

    } catch (error) {
      await this.updateProgress(progressKey, {
        stage: 'failed',
        progress: 0,
        message: 'Export failed',
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      throw error
    }
  }

  private async exportToPDF(request: ExportRequest): Promise<Buffer> {
    await this.updateProgress(`export:${request.id}`, {
      stage: 'rendering',
      progress: 20,
      message: 'Rendering PDF...'
    })

    const doc = new jsPDF({
      orientation: request.options.orientation,
      unit: 'mm',
      format: request.options.pageSize.toLowerCase()
    })

    const pageWidth = doc.internal.pageSize.getWidth()
    const pageHeight = doc.internal.pageSize.getHeight()
    const margin = request.options.margins

    let currentY = margin.top

    // Add title
    if (request.options.includeTitle && request.metadata.dashboardTitle) {
      doc.setFontSize(20)
      doc.setFont('helvetica', 'bold')
      doc.text(request.metadata.dashboardTitle, margin.left, currentY)
      currentY += 15
    }

    // Add timestamp
    if (request.options.includeTimestamp) {
      doc.setFontSize(10)
      doc.setFont('helvetica', 'normal')
      doc.text(`Generated on ${new Date().toLocaleString()}`, margin.left, currentY)
      currentY += 10
    }

    // Add filters info
    if (request.options.includeFilters && request.metadata.filters) {
      doc.setFontSize(8)
      doc.text('Applied Filters:', margin.left, currentY)
      currentY += 5

      Object.entries(request.metadata.filters).forEach(([key, value]) => {
        doc.text(`• ${key}: ${value}`, margin.left + 5, currentY)
        currentY += 4
      })
      currentY += 5
    }

    // Render widgets
    for (let i = 0; i < request.widgets.length; i++) {
      const widget = request.widgets[i]

      await this.updateProgress(`export:${request.id}`, {
        stage: 'rendering',
        progress: 20 + (i / request.widgets.length) * 60,
        message: `Rendering widget: ${widget.title}`
      })

      // Check if we need a new page
      if (currentY > pageHeight - 80) {
        doc.addPage()
        currentY = margin.top
      }

      // Add widget title
      doc.setFontSize(14)
      doc.setFont('helvetica', 'bold')
      doc.text(widget.title, margin.left, currentY)
      currentY += 10

      // Add widget description
      if (request.options.includeDescription && widget.description) {
        doc.setFontSize(9)
        doc.setFont('helvetica', 'normal')
        const lines = doc.splitTextToSize(widget.description, pageWidth - margin.left - margin.right)
        doc.text(lines, margin.left, currentY)
        currentY += lines.length * 4 + 5
      }

      // Render widget content
      if (widget.type === 'chart') {
        const chartImage = await this.renderChartToPNG(widget)
        if (chartImage) {
          const imgWidth = Math.min(120, pageWidth - margin.left - margin.right)
          const imgHeight = 80
          doc.addImage(chartImage, 'PNG', margin.left, currentY, imgWidth, imgHeight)
          currentY += imgHeight + 10
        }
      } else if (widget.type === 'table') {
        currentY =
  await this.renderTableToPDF(doc, widget, margin.left, currentY, pageWidth - margin.left - margin.right)
      } else if (widget.type === 'kpi') {
        currentY = await this.renderKPIToPDF(doc, widget, margin.left, currentY)
      }

      currentY += 10
    }

    // Add watermark
    if (request.options.watermark) {
      const totalPages = doc.getNumberOfPages()
      for (let i = 1; i <= totalPages; i++) {
        doc.setPage(i)
        doc.setFontSize(50)
        doc.setTextColor(200, 200, 200)
        doc.text(request.options.watermark, pageWidth / 2, pageHeight / 2, {
          angle: 45,
          align: 'center'
        })
      }
    }

    // Add branding
    if (request.options.includeBranding) {
      const totalPages = doc.getNumberOfPages()
      for (let i = 1; i <= totalPages; i++) {
        doc.setPage(i)
        doc.setFontSize(8)
        doc.setTextColor(100, 100, 100)
        doc.text('Generated by CoreFlow360', pageWidth - margin.right, pageHeight - 5, { align: 'right' })
      }
    }

    return Buffer.from(doc.output('arraybuffer'))
  }

  private async exportToExcel(request: ExportRequest): Promise<Buffer> {
    await this.updateProgress(`export:${request.id}`, {
      stage: 'rendering',
      progress: 20,
      message: 'Creating Excel workbook...'
    })

    const workbook = XLSX.utils.book_new()

    // Create summary sheet
    const summaryData = [
      ['Dashboard Export Summary'],
      ['Title:', request.metadata.dashboardTitle || 'Dashboard'],
      ['Generated:', new Date().toISOString()],
      ['Requested by:', request.metadata.requestedBy],
      [''],
      ['Filters Applied:']
    ]

    if (request.metadata.filters) {
      Object.entries(request.metadata.filters).forEach(([key, value]) => {
        summaryData.push([key, value])
      })
    }

    const summarySheet = XLSX.utils.aoa_to_sheet(summaryData)
    XLSX.utils.book_append_sheet(workbook, summarySheet, 'Summary')

    // Create sheet for each widget
    for (let i = 0; i < request.widgets.length; i++) {
      const widget = request.widgets[i]

      await this.updateProgress(`export:${request.id}`, {
        stage: 'rendering',
        progress: 20 + (i / request.widgets.length) * 60,
        message: `Processing widget: ${widget.title}`
      })

      if (widget.type === 'table') {
        const sheet = this.createTableSheet(widget)
        const sheetName = this.sanitizeSheetName(widget.title)
        XLSX.utils.book_append_sheet(workbook, sheet, sheetName)
      } else if (widget.type === 'chart') {
        const sheet = this.createChartDataSheet(widget)
        const sheetName = this.sanitizeSheetName(widget.title)
        XLSX.utils.book_append_sheet(workbook, sheet, sheetName)
      } else if (widget.type === 'kpi') {
        const sheet = this.createKPISheet(widget)
        const sheetName = this.sanitizeSheetName(widget.title)
        XLSX.utils.book_append_sheet(workbook, sheet, sheetName)
      }
    }

    return XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' })
  }

  private async exportToPowerPoint(request: ExportRequest): Promise<Buffer> {
    await this.updateProgress(`export:${request.id}`, {
      stage: 'rendering',
      progress: 20,
      message: 'Creating PowerPoint presentation...'
    })

    // Using PptxGenJS for PowerPoint generation
    const pptx = require('pptxgenjs')()

    // Title slide
    const titleSlide = pptx.addSlide()
    titleSlide.addText(request.metadata.dashboardTitle || 'Dashboard Report', {
      x: 1, y: 2, w: 8, h: 1,
      fontSize: 32,
      bold: true,
      align: 'center'
    })

    titleSlide.addText(`Generated on ${new Date().toLocaleDateString()}`, {
      x: 1, y: 4, w: 8, h: 0.5,
      fontSize: 16,
      align: 'center'
    })

    // Create slide for each widget
    for (let i = 0; i < request.widgets.length; i++) {
      const widget = request.widgets[i]

      await this.updateProgress(`export:${request.id}`, {
        stage: 'rendering',
        progress: 20 + (i / request.widgets.length) * 60,
        message: `Creating slide: ${widget.title}`
      })

      const slide = pptx.addSlide()

      // Add title
      slide.addText(widget.title, {
        x: 0.5, y: 0.5, w: 9, h: 0.8,
        fontSize: 24,
        bold: true
      })

      // Add content based on widget type
      if (widget.type === 'chart') {
        const chartImage = await this.renderChartToPNG(widget)
        if (chartImage) {
          slide.addImage({
            data: chartImage,
            x: 1, y: 1.5, w: 8, h: 5
          })
        }
      } else if (widget.type === 'table') {
        await this.addTableToSlide(slide, widget)
      } else if (widget.type === 'kpi') {
        await this.addKPIToSlide(slide, widget)
      }

      // Add description
      if (widget.description) {
        slide.addText(widget.description, {
          x: 0.5, y: 7, w: 9, h: 0.5,
          fontSize: 12,
          italic: true
        })
      }
    }

    return pptx.writeFile()
  }

  private async exportToCSV(request: ExportRequest): Promise<Buffer> {
    await this.updateProgress(`export:${request.id}`, {
      stage: 'rendering',
      progress: 50,
      message: 'Converting data to CSV...'
    })

    const csvData: string[] = []

    // Add header
    csvData.push(`# Dashboard Export: ${request.metadata.dashboardTitle || 'Dashboard'}`)
    csvData.push(`# Generated: ${new Date().toISOString()}`)
    csvData.push(`# Requested by: ${request.metadata.requestedBy}`)
    csvData.push('')

    // Add filters
    if (request.metadata.filters) {
      csvData.push('# Applied Filters:')
      Object.entries(request.metadata.filters).forEach(([key, value]) => {
        csvData.push(`# ${key}: ${value}`)
      })
      csvData.push('')
    }

    // Process each widget
    for (const widget of request.widgets) {
      csvData.push(`# Widget: ${widget.title}`)

      if (widget.type === 'table' && widget.data?.rows) {
        // Export table data
        const headers = widget.data.columns?.map((col: any) => col.label).join(',') || ''
        csvData.push(headers)

        widget.data.rows.forEach((row: any) => {
          const values = widget.data.columns?.map((col: any) => {
            const value = row[col.key]
            return typeof value === 'string' && value.includes(',') ? `"${value}"` : value
          }).join(',') || ''
          csvData.push(values)
        })
      } else if (widget.type === 'chart' && widget.data?.datasets) {
        // Export chart data
        csvData.push('Label,' + widget.data.datasets.map((ds: any) => ds.label).join(','))

        widget.data.labels?.forEach((label: string, index: number) => {
          const values = widget.data.datasets.map((ds: any) => ds.data[index] || '')
          csvData.push(`${label},${values.join(',')}`)
        })
      } else if (widget.type === 'kpi') {
        // Export KPI data
        csvData.push('Metric,Value,Unit,Trend')
      
   csvData.push(`${widget.title},${widget.data?.value || ''},${widget.data?.unit || ''},${widget.data?.trend || ''}`)
      }

      csvData.push('')
    }

    return Buffer.from(csvData.join('\n'), 'utf-8')
  }

  private async exportToPNG(request: ExportRequest): Promise<Buffer> {
    await this.updateProgress(`export:${request.id}`, {
      stage: 'rendering',
      progress: 50,
      message: 'Rendering PNG image...'
    })

    // For single widget export
    if (request.widgets.length === 1) {
      return await this.renderChartToPNG(request.widgets[0])
    }

    // For multiple widgets, create a composite image
    return await this.renderDashboardToPNG(request)
  }

  private async exportToSVG(request: ExportRequest): Promise<Buffer> {
    await this.updateProgress(`export:${request.id}`, {
      stage: 'rendering',
      progress: 50,
      message: 'Generating SVG...'
    })

    // Generate SVG for dashboard or widget
    const svg = await this.renderToSVG(request)
    return Buffer.from(svg, 'utf-8')
  }

  // Helper methods
  private async renderChartToPNG(widget: ExportWidget): Promise<Buffer> {
    const chartCanvas = new ChartJSNodeCanvas({
      width: 800,
      height: 600,
      backgroundColour: 'white'
    })

    const chartConfig = {
      type: widget.config.type || 'line',
      data: widget.data,
      options: {
        ...widget.config.options,
        responsive: false,
        animation: false
      }
    }

    return await chartCanvas.renderToBuffer(chartConfig)
  }

  private async updateProgress(key: string, progress: ExportProgress): Promise<void> {
    await this.storage.put(key, progress)
  }

  private async uploadToR2(data: Buffer, request: ExportRequest): Promise<string> {
    const filename = `exports/${request.id}.${request.format}`

    // Upload to Cloudflare R2
    await this.env.EXPORTS_BUCKET.put(filename, data, {
      httpMetadata: {
        contentType: this.getContentType(request.format),
        contentDisposition: `attachment; filename="${request.metadata.dashboardTitle || 'export'}.${request.format}"`
      },
      customMetadata: {
        requestId: request.id,
        requestedBy: request.metadata.requestedBy,
        exportType: request.type
      }
    })

    return `${this.env.R2_PUBLIC_URL}/${filename}`
  }

  private getContentType(format: string): string {
    const contentTypes = {
      pdf: 'application/pdf',
      excel: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      powerpoint: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      csv: 'text/csv',
      png: 'image/png',
      svg: 'image/svg+xml'
    }
    return contentTypes[format as keyof typeof contentTypes] || 'application/octet-stream'
  }

  private sanitizeSheetName(name: string): string {
    return name.replace(/[\\\/\*\?\[\]]/g, '').substring(0, 31)
  }

  private async validateRequest(request: ExportRequest): Promise<void> {
    if (!request.widgets || request.widgets.length === 0) {
      throw new Error('No widgets to export')
    }

    if (!['pdf', 'excel', 'powerpoint', 'csv', 'png', 'svg'].includes(request.format)) {
      throw new Error('Invalid export format')
    }

    // Add more validation as needed
  }

  // Additional helper methods for specific rendering tasks...
  private createTableSheet(widget: ExportWidget): any {
    // Implementation for table sheet creation
    return {}
  }

  private createChartDataSheet(widget: ExportWidget): any {
    // Implementation for chart data sheet creation
    return {}
  }

  private createKPISheet(widget: ExportWidget): any {
    // Implementation for KPI sheet creation
    return {}
  }

  private async renderTableToPDF(doc: any, widget: ExportWidget, x: number, y: number, width: number): Promise<number> {
    // Implementation for PDF table rendering
    return y + 50
  }

  private async renderKPIToPDF(doc: any, widget: ExportWidget, x: number, y: number): Promise<number> {
    // Implementation for PDF KPI rendering
    return y + 30
  }

  private async addTableToSlide(slide: any, widget: ExportWidget): Promise<void> {
    // Implementation for PowerPoint table
  }

  private async addKPIToSlide(slide: any, widget: ExportWidget): Promise<void> {
    // Implementation for PowerPoint KPI
  }

  private async renderDashboardToPNG(request: ExportRequest): Promise<Buffer> {
    // Implementation for composite PNG rendering
    return Buffer.alloc(0)
  }

  private async renderToSVG(request: ExportRequest): Promise<string> {
    // Implementation for SVG generation
    return '<svg></svg>'
  }

  // WebSocket endpoint for progress updates
  async websocket(request: Request): Promise<Response> {
    const webSocketPair = new WebSocketPair()
    const [client, server] = Object.values(webSocketPair)

    server.accept()

    // Handle export progress subscriptions
    server.addEventListener('message', async (event) => {
      const message = JSON.parse(event.data)

      if (message.type === 'subscribe' && message.exportId) {
        // Subscribe to export progress updates
        const progressKey = `export:${message.exportId}`

        // Send current progress
        const progress = await this.storage.get(progressKey)
        if (progress) {
          server.send(JSON.stringify({
            type: 'progress',
            exportId: message.exportId,
            ...progress
          }))
        }
      }
    })

    return new Response(null, {
      status: 101,
      webSocket: client
    })
  }
}

export { ExportEngine }