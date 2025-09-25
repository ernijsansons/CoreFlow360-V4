/**
 * Action Dispatcher Service
 * Coordinates and executes dashboard actions with context awareness
 */

import { toast } from 'sonner'
import type { Widget } from '@/types/dashboard'
import type { QuickAction } from '@/components/dashboard/QuickActions'

export interface ActionContext {
  widgetId: string
  dashboardId: string
  userId: string
  userRole: string
  currentFilters?: Record<string, any>
  drillDownPath?: any[]
  selectedData?: any
}

export interface ActionResult {
  success: boolean
  message?: string
  data?: any
  redirectTo?: string
}

export interface ExportOptions {
  format: 'png' | 'pdf' | 'svg' | 'excel' | 'csv' | 'pptx'
  includeTitle?: boolean
  includeDescription?: boolean
  highResolution?: boolean
  backgroundColor?: string
  dateRange?: { from: Date; to: Date }
  filters?: Record<string, any>
}

export interface ShareOptions {
  type: 'link' | 'email' | 'slack' | 'teams'
  recipients?: string[]
  message?: string
  permissions?: 'view' | 'edit'
  expiresAt?: Date
}

class ActionDispatcherService {
  private baseURL: string
  private authToken: string | null = null

  constructor() {
    this.baseURL = process.env.NEXT_PUBLIC_API_URL || '/api'
  }

  setAuthToken(token: string) {
    this.authToken = token
  }

  private async apiCall(endpoint: string, options: RequestInit = {}) {
    const response = await fetch(`${this.baseURL}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(this.authToken && { 'Authorization': `Bearer ${this.authToken}` }),
        ...options.headers
      }
    })

    if (!response.ok) {
      throw new Error(`API call failed: ${response.statusText}`)
    }

    return response.json()
  }

  async executeAction(
    action: QuickAction,
    widget: Widget,
    context: ActionContext,
    options?: any
  ): Promise<ActionResult> {
    try {
      switch (action.id) {
        case 'refresh':
          return await this.refreshWidget(widget, context)

        case 'maximize':
          return await this.maximizeWidget(widget, context)

        case 'filter':
          return await this.applyFilter(widget, context, options)

        case 'export-png':
        case 'export-pdf':
        case 'export-svg':
        case 'export-excel':
        case 'export-csv':
          return await this.exportWidget(widget, context, options)

        case 'share':
          return await this.shareWidget(widget, context, options)

        case 'duplicate':
          return await this.duplicateWidget(widget, context)

        case 'configure':
          return await this.configureWidget(widget, context)

        case 'delete':
          return await this.deleteWidget(widget, context)

        case 'drill-time':
        case 'drill-category':
        case 'drill-geography':
          return await this.drillDown(widget, context, action.id, options)

        default:
          return await this.executeCustomAction(action, widget, context, options)
      }
    } catch (error) {
      console.error('Action execution failed:', error)
      return {
        success: false,
        message: error instanceof Error ? error.message : 'Action failed'
      }
    }
  }

  private async refreshWidget(widget: Widget, context: ActionContext): Promise<ActionResult> {
    toast.loading('Refreshing widget data...', { id: `refresh-${widget.id}` })

    try {
      const response = await this.apiCall(`/widgets/${widget.id}/refresh`, {
        method: 'POST',
        body: JSON.stringify({
          filters: context.currentFilters,
          drillDownPath: context.drillDownPath
        })
      })

      toast.success('Widget refreshed successfully', { id: `refresh-${widget.id}` })

      return {
        success: true,
        data: response.data,
        message: 'Widget data refreshed'
      }
    } catch (error) {
      toast.error('Failed to refresh widget', { id: `refresh-${widget.id}` })
      throw error
    }
  }

  private async maximizeWidget(widget: Widget, context: ActionContext): Promise<ActionResult> {
    return {
      success: true,
      redirectTo: `/dashboard/${context.dashboardId}/widget/${widget.id}/expanded`
    }
  }

  private async applyFilter(
    widget: Widget,
    context: ActionContext,
    filters: Record<string, any>
  ): Promise<ActionResult> {
    toast.loading('Applying filters...', { id: `filter-${widget.id}` })

    try {
      const response = await this.apiCall(`/widgets/${widget.id}/filter`, {
        method: 'POST',
        body: JSON.stringify({
          filters,
          mergeWithExisting: true
        })
      })

      toast.success('Filters applied successfully', { id: `filter-${widget.id}` })

      return {
        success: true,
        data: response.data,
        message: `Applied ${Object.keys(filters).length} filter(s)`
      }
    } catch (error) {
      toast.error('Failed to apply filters', { id: `filter-${widget.id}` })
      throw error
    }
  }

  private async exportWidget(
    widget: Widget,
    context: ActionContext,
    options: ExportOptions
  ): Promise<ActionResult> {
    const format = options.format
    toast.loading(`Exporting as ${format.toUpperCase()}...`, { id: `export-${widget.id}` })

    try {
      const response = await this.apiCall(`/widgets/${widget.id}/export`, {
        method: 'POST',
        body: JSON.stringify({
          format,
          options: {
            includeTitle: options.includeTitle ?? true,
            includeDescription: options.includeDescription ?? true,
            highResolution: options.highResolution ?? false,
            backgroundColor: options.backgroundColor ?? 'white',
            filters: context.currentFilters,
            drillDownPath: context.drillDownPath,
            dateRange: options.dateRange
          }
        })
      })

      // Handle different export types
      if (format === 'png' || format === 'pdf' || format === 'svg') {
        // Direct download
        const blob = await fetch(response.downloadUrl).then(r => r.blob())
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `${widget.title.replace(/\s+/g, '_').toLowerCase()}.${format}`
        a.click()
        URL.revokeObjectURL(url)
      } else {
        // Server-side processing (Excel, PowerPoint, etc.)
        window.open(response.downloadUrl, '_blank')
      }

      toast.success(`${format.toUpperCase()} export completed`, { id: `export-${widget.id}` })

      return {
        success: true,
        data: response,
        message: `Widget exported as ${format.toUpperCase()}`
      }
    } catch (error) {
      toast.error(`Export failed`, { id: `export-${widget.id}` })
      throw error
    }
  }

  private async shareWidget(
    widget: Widget,
    context: ActionContext,
    options: ShareOptions
  ): Promise<ActionResult> {
    toast.loading('Creating shareable link...', { id: `share-${widget.id}` })

    try {
      const response = await this.apiCall(`/widgets/${widget.id}/share`, {
        method: 'POST',
        body: JSON.stringify({
          type: options.type,
          recipients: options.recipients,
          message: options.message,
          permissions: options.permissions ?? 'view',
          expiresAt: options.expiresAt,
          includeFilters: true,
          filters: context.currentFilters,
          drillDownPath: context.drillDownPath
        })
      })

      // Copy to clipboard
      if (options.type === 'link') {
        await navigator.clipboard.writeText(response.shareUrl)
        toast.success('Share link copied to clipboard', { id: `share-${widget.id}` })
      } else {
        toast.success('Share invitation sent', { id: `share-${widget.id}` })
      }

      return {
        success: true,
        data: response,
        message: 'Widget shared successfully'
      }
    } catch (error) {
      toast.error('Failed to share widget', { id: `share-${widget.id}` })
      throw error
    }
  }

  private async duplicateWidget(widget: Widget, context: ActionContext): Promise<ActionResult> {
    toast.loading('Duplicating widget...', { id: `duplicate-${widget.id}` })

    try {
      const response = await this.apiCall(`/widgets/${widget.id}/duplicate`, {
        method: 'POST',
        body: JSON.stringify({
          dashboardId: context.dashboardId,
          position: { x: 0, y: 0 }, // Will be auto-positioned
          copyFilters: true,
          copyConfig: true
        })
      })

      toast.success('Widget duplicated successfully', { id: `duplicate-${widget.id}` })

      return {
        success: true,
        data: response.widget,
        message: 'Widget duplicated'
      }
    } catch (error) {
      toast.error('Failed to duplicate widget', { id: `duplicate-${widget.id}` })
      throw error
    }
  }

  private async configureWidget(widget: Widget, context: ActionContext): Promise<ActionResult> {
    return {
      success: true,
      redirectTo: `/dashboard/${context.dashboardId}/widget/${widget.id}/configure`
    }
  }

  private async deleteWidget(widget: Widget, context: ActionContext): Promise<ActionResult> {
    // Show confirmation dialog first
    const confirmed = confirm(`Are you sure you want to delete "${widget.title}"? This action cannot be undone.`)

    if (!confirmed) {
      return {
        success: false,
        message: 'Deletion cancelled'
      }
    }

    toast.loading('Deleting widget...', { id: `delete-${widget.id}` })

    try {
      await this.apiCall(`/widgets/${widget.id}`, {
        method: 'DELETE'
      })

      toast.success('Widget deleted successfully', { id: `delete-${widget.id}` })

      return {
        success: true,
        message: 'Widget deleted'
      }
    } catch (error) {
      toast.error('Failed to delete widget', { id: `delete-${widget.id}` })
      throw error
    }
  }

  private async drillDown(
    widget: Widget,
    context: ActionContext,
    drillType: string,
    options?: any
  ): Promise<ActionResult> {
    toast.loading('Loading drill-down data...', { id: `drill-${widget.id}` })

    try {
      const response = await this.apiCall(`/widgets/${widget.id}/drill-down`, {
        method: 'POST',
        body: JSON.stringify({
          type: drillType,
          currentPath: context.drillDownPath || [],
          filters: context.currentFilters,
          selectedData: options?.selectedData
        })
      })

      toast.success('Drill-down data loaded', { id: `drill-${widget.id}` })

      return {
        success: true,
        data: response,
        message: 'Drill-down completed'
      }
    } catch (error) {
      toast.error('Failed to load drill-down data', { id: `drill-${widget.id}` })
      throw error
    }
  }

  private async executeCustomAction(
    action: QuickAction,
    widget: Widget,
    context: ActionContext,
    options?: any
  ): Promise<ActionResult> {
    // Handle custom actions defined by plugins or extensions
    toast.loading(`Executing ${action.label}...`, { id: `custom-${widget.id}` })

    try {
      const response = await this.apiCall(`/widgets/${widget.id}/custom-action`, {
        method: 'POST',
        body: JSON.stringify({
          actionId: action.id,
          options,
          context
        })
      })

      toast.success(`${action.label} completed`, { id: `custom-${widget.id}` })

      return {
        success: true,
        data: response,
        message: `${action.label} executed successfully`
      }
    } catch (error) {
      toast.error(`${action.label} failed`, { id: `custom-${widget.id}` })
      throw error
    }
  }

  // Batch actions for multiple widgets
  async executeBatchAction(
    action: QuickAction,
    widgets: Widget[],
    context: ActionContext,
    options?: any
  ): Promise<ActionResult[]> {
    toast.loading(`Executing ${action.label} on ${widgets.length} widgets...`)

    const results = await Promise.allSettled(
      widgets.map(widget => this.executeAction(action, widget, context, options))
    )

    const successCount = results.filter(r => r.status === 'fulfilled').length
    const failureCount = results.length - successCount

    if (failureCount === 0) {
      toast.success(`${action.label} completed on all ${widgets.length} widgets`)
    } else {
      toast.warning(`${action.label} completed on ${successCount}/${widgets.length} widgets`)
    }

    return results.map(result =>
      result.status === 'fulfilled'
        ? result.value
        : { success: false, message: result.reason?.message || 'Action failed' }
    )
  }

  // Get available actions for a widget based on context
  getAvailableActions(widget: Widget, context: ActionContext): QuickAction[] {
    const actions: QuickAction[] = []

    // Always available actions
    actions.push(
      { id: 'refresh', label: 'Refresh', icon: 'RefreshCw', category: 'view', handler: () => {} },
      { id: 'maximize', label: 'Expand', icon: 'Maximize2', category: 'view', handler: () => {} }
    )

    // Role-based actions
    if (context.userRole === 'admin' || context.userRole === 'editor') {
      actions.push(
        { id: 'configure', label: 'Configure', icon: 'Settings', category: 'edit', handler: () => {} },
        { id: 'duplicate', label: 'Duplicate', icon: 'Copy', category: 'edit', handler: () => {} }
      )
    }

    if (context.userRole === 'admin') {
      actions.push(
        { id: 'delete', label: 'Delete', icon: 'Trash2', category: 'edit', destructive: true, handler: () => {} }
      )
    }

    // Widget-type specific actions
    if (widget.type === 'data_table') {
      actions.push(
        { id: 'export-excel', label: 'Export Excel', icon: 'Download', category: 'export', handler: () => {} },
        { id: 'export-csv', label: 'Export CSV', icon: 'Download', category: 'export', handler: () => {} }
      )
    }

    if (['line_chart', 'bar_chart', 'pie_chart'].includes(widget.type)) {
      actions.push(
        { id: 'export-png', label: 'Export PNG', icon: 'Download', category: 'export', handler: () => {} },
        { id: 'export-pdf', label: 'Export PDF', icon: 'Download', category: 'export', handler: () => {} }
      )
    }

    // Drill-down actions based on data type
    if (widget.config?.supportsDrillDown) {
      actions.push(
        { id: 'drill-time', label: 'Drill by Time', icon: 'Clock', category: 'drill-down', handler: () => {} },
        { id: 'drill-category', label: 'Drill by Category', icon: 'BarChart3', category: 'drill-down', handler: () => {} }
      )
    }

    return actions
  }
}

export const actionDispatcher = new ActionDispatcherService()