/**
 * Quick Actions Framework
 * Contextual actions and drill-down capabilities for dashboard widgets
 */

import React, { useState, useRef, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Filter,
  Download,
  Share2,
  Settings,
  Maximize2,
  BarChart3,
  PieChart,
  TrendingUp,
  Users,
  Calendar,
  Globe,
  RefreshCw,
  Eye,
  Edit,
  Copy,
  Trash2,
  AlertCircle,
  CheckCircle,
  Clock,
  Target,
  Zap,
  ArrowRight,
  ExternalLink,
  MoreVertical
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Calendar as CalendarComponent } from '@/components/ui/calendar'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { Separator } from '@/components/ui/separator'
import { Switch } from '@/components/ui/switch'
import type { Widget } from '@/types/dashboard'

export interface QuickAction {
  id: string
  label: string
  icon: React.ComponentType<{ className?: string }>
  category: 'filter' | 'export' | 'view' | 'edit' | 'share' | 'drill-down'
  shortcut?: string
  description?: string
  handler: (widget: Widget, context?: any) => void | Promise<void>
  condition?: (widget: Widget) => boolean
  destructive?: boolean
}

export interface DrillDownPath {
  level: string
  label: string
  filters: Record<string, any>
  breadcrumb: string[]
}

export interface QuickActionsProps {
  widget: Widget
  position: { x: number; y: number }
  isVisible: boolean
  onClose: () => void
  onAction: (action: QuickAction, widget: Widget) => void
  customActions?: QuickAction[]
  drillDownPath?: DrillDownPath[]
  className?: string
}

export interface FilterPanelProps {
  widget: Widget
  onApplyFilter: (filters: Record<string, any>) => void
  onClose: () => void
}

export interface ExportOptionsProps {
  widget: Widget
  onExport: (format: string, options: any) => void
  onClose: () => void
}

// Default quick actions available for all widgets
const DEFAULT_ACTIONS: QuickAction[] = [
  {
    id: 'refresh',
    label: 'Refresh Data',
    icon: RefreshCw,
    category: 'view',
    shortcut: 'R',
    description: 'Refresh widget data',
    handler: (widget) => {
      // Trigger data refresh
      console.log('Refreshing widget:', widget.id)
    }
  },
  {
    id: 'maximize',
    label: 'Expand View',
    icon: Maximize2,
    category: 'view',
    shortcut: 'F',
    description: 'Open in expanded view',
    handler: (widget) => {
      console.log('Expanding widget:', widget.id)
    }
  },
  {
    id: 'filter',
    label: 'Add Filter',
    icon: Filter,
    category: 'filter',
    shortcut: 'Ctrl+F',
    description: 'Add custom filters',
    handler: (widget) => {
      console.log('Opening filter panel for:', widget.id)
    }
  },
  {
    id: 'export-png',
    label: 'Export as PNG',
    icon: Download,
    category: 'export',
    description: 'Export widget as PNG image',
    handler: (widget) => {
      console.log('Exporting PNG for:', widget.id)
    }
  },
  {
    id: 'export-pdf',
    label: 'Export as PDF',
    icon: Download,
    category: 'export',
    description: 'Export widget as PDF',
    handler: (widget) => {
      console.log('Exporting PDF for:', widget.id)
    }
  },
  {
    id: 'share',
    label: 'Share Widget',
    icon: Share2,
    category: 'share',
    shortcut: 'Ctrl+S',
    description: 'Share widget link',
    handler: (widget) => {
      console.log('Sharing widget:', widget.id)
    }
  },
  {
    id: 'duplicate',
    label: 'Duplicate',
    icon: Copy,
    category: 'edit',
    description: 'Create a copy of this widget',
    handler: (widget) => {
      console.log('Duplicating widget:', widget.id)
    }
  },
  {
    id: 'configure',
    label: 'Configure',
    icon: Settings,
    category: 'edit',
    shortcut: 'Ctrl+,',
    description: 'Configure widget settings',
    handler: (widget) => {
      console.log('Configuring widget:', widget.id)
    }
  },
  {
    id: 'delete',
    label: 'Delete Widget',
    icon: Trash2,
    category: 'edit',
    destructive: true,
    description: 'Remove widget from dashboard',
    handler: (widget) => {
      console.log('Deleting widget:', widget.id)
    }
  }
]

// Chart-specific drill-down actions
const CHART_DRILL_ACTIONS: QuickAction[] = [
  {
    id: 'drill-time',
    label: 'Drill Down by Time',
    icon: Clock,
    category: 'drill-down',
    description: 'Break down data by time periods',
    handler: (widget, context) => {
      console.log('Drilling down by time:', widget.id, context)
    },
    condition: (widget) => ['line_chart', 'bar_chart', 'area_chart'].includes(widget.type)
  },
  {
    id: 'drill-category',
    label: 'Drill Down by Category',
    icon: BarChart3,
    category: 'drill-down',
    description: 'Break down data by categories',
    handler: (widget, context) => {
      console.log('Drilling down by category:', widget.id, context)
    },
    condition: (widget) => ['pie_chart', 'doughnut_chart', 'bar_chart'].includes(widget.type)
  },
  {
    id: 'drill-geography',
    label: 'Drill Down by Region',
    icon: Globe,
    category: 'drill-down',
    description: 'Break down data by geographic regions',
    handler: (widget, context) => {
      console.log('Drilling down by geography:', widget.id, context)
    },
    condition: (widget) => widget.config?.hasGeographicData
  }
]

// Table-specific actions
const TABLE_ACTIONS: QuickAction[] = [
  {
    id: 'export-excel',
    label: 'Export to Excel',
    icon: Download,
    category: 'export',
    description: 'Export table data to Excel',
    handler: (widget) => {
      console.log('Exporting Excel for:', widget.id)
    },
    condition: (widget) => widget.type === 'data_table'
  },
  {
    id: 'export-csv',
    label: 'Export to CSV',
    icon: Download,
    category: 'export',
    description: 'Export table data to CSV',
    handler: (widget) => {
      console.log('Exporting CSV for:', widget.id)
    },
    condition: (widget) => widget.type === 'data_table'
  }
]

const FilterPanel: React.FC<FilterPanelProps> = ({ widget, onApplyFilter, onClose }) => {
  const [filters, setFilters] = useState<Record<string, any>>({})
  const [dateRange, setDateRange] = useState<{ from?: Date; to?: Date }>({})

  const handleApplyFilters = () => {
    const combinedFilters = {
      ...filters,
      dateRange: dateRange.from && dateRange.to ? dateRange : undefined
    }
    onApplyFilter(combinedFilters)
    onClose()
  }

  return (
    <motion.div
      className="absolute top-full left-0 mt-2 w-80 bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 z-50"
      initial={{ opacity: 0, y: -10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
    >
      <div className="p-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
            Filter Options
          </h3>
          <Button variant="ghost" size="sm" onClick={onClose}>
            ×
          </Button>
        </div>

        <div className="space-y-4">
          {/* Date Range Filter */}
          <div>
            <Label className="text-xs text-gray-600 dark:text-gray-400 mb-2 block">
              Date Range
            </Label>
            <Popover>
              <PopoverTrigger asChild>
                <Button variant="outline" size="sm" className="w-full justify-start">
                  <Calendar className="w-4 h-4 mr-2" />
                  {dateRange.from && dateRange.to
                    ? `${dateRange.from.toLocaleDateString()} - ${dateRange.to.toLocaleDateString()}`
                    : 'Select date range'
                  }
                </Button>
              </PopoverTrigger>
              <PopoverContent className="w-auto p-0">
                <CalendarComponent
                  mode="range"
                  selected={{ from: dateRange.from, to: dateRange.to }}
                  onSelect={(range) => setDateRange(range || {})}
                />
              </PopoverContent>
            </Popover>
          </div>

          {/* Category Filter */}
          <div>
            <Label className="text-xs text-gray-600 dark:text-gray-400 mb-2 block">
              Category
            </Label>
            <Select onValueChange={(value) => setFilters({ ...filters, category: value })}>
              <SelectTrigger>
                <SelectValue placeholder="All categories" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Categories</SelectItem>
                <SelectItem value="sales">Sales</SelectItem>
                <SelectItem value="marketing">Marketing</SelectItem>
                <SelectItem value="support">Support</SelectItem>
                <SelectItem value="finance">Finance</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Value Range Filter */}
          <div>
            <Label className="text-xs text-gray-600 dark:text-gray-400 mb-2 block">
              Value Range
            </Label>
            <div className="flex space-x-2">
              <Input
                placeholder="Min"
                type="number"
                onChange={(e) => setFilters({ ...filters, minValue: e.target.value })}
              />
              <Input
                placeholder="Max"
                type="number"
                onChange={(e) => setFilters({ ...filters, maxValue: e.target.value })}
              />
            </div>
          </div>

          {/* Boolean Filters */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Label className="text-xs text-gray-600 dark:text-gray-400">
                Show only active items
              </Label>
              <Switch
                checked={filters.activeOnly || false}
                onCheckedChange={(checked) => setFilters({ ...filters, activeOnly: checked })}
              />
            </div>
            <div className="flex items-center justify-between">
              <Label className="text-xs text-gray-600 dark:text-gray-400">
                Include archived data
              </Label>
              <Switch
                checked={filters.includeArchived || false}
                onCheckedChange={(checked) => setFilters({ ...filters, includeArchived: checked })}
              />
            </div>
          </div>
        </div>

        <Separator className="my-4" />

        <div className="flex justify-end space-x-2">
          <Button variant="outline" size="sm" onClick={onClose}>
            Cancel
          </Button>
          <Button size="sm" onClick={handleApplyFilters}>
            Apply Filters
          </Button>
        </div>
      </div>
    </motion.div>
  )
}

const ExportOptions: React.FC<ExportOptionsProps> = ({ widget, onExport, onClose }) => {
  const [format, setFormat] = useState('png')
  const [options, setOptions] = useState({
    includeTitle: true,
    includeDescription: true,
    highResolution: false,
    backgroundColor: 'white'
  })

  const handleExport = () => {
    onExport(format, options)
    onClose()
  }

  return (
    <motion.div
      className="absolute top-full left-0 mt-2 w-72 bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 z-50"
      initial={{ opacity: 0, y: -10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
    >
      <div className="p-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
            Export Options
          </h3>
          <Button variant="ghost" size="sm" onClick={onClose}>
            ×
          </Button>
        </div>

        <div className="space-y-4">
          {/* Format Selection */}
          <div>
            <Label className="text-xs text-gray-600 dark:text-gray-400 mb-2 block">
              Export Format
            </Label>
            <Select value={format} onValueChange={setFormat}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="png">PNG Image</SelectItem>
                <SelectItem value="pdf">PDF Document</SelectItem>
                <SelectItem value="svg">SVG Vector</SelectItem>
                {widget.type === 'data_table' && (
                  <>
                    <SelectItem value="excel">Excel Spreadsheet</SelectItem>
                    <SelectItem value="csv">CSV File</SelectItem>
                  </>
                )}
              </SelectContent>
            </Select>
          </div>

          {/* Export Options */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Label className="text-xs text-gray-600 dark:text-gray-400">
                Include title
              </Label>
              <Switch
                checked={options.includeTitle}
                onCheckedChange={(checked) => setOptions({ ...options, includeTitle: checked })}
              />
            </div>
            <div className="flex items-center justify-between">
              <Label className="text-xs text-gray-600 dark:text-gray-400">
                Include description
              </Label>
              <Switch
                checked={options.includeDescription}
                onCheckedChange={(checked) => setOptions({ ...options, includeDescription: checked })}
              />
            </div>
            <div className="flex items-center justify-between">
              <Label className="text-xs text-gray-600 dark:text-gray-400">
                High resolution
              </Label>
              <Switch
                checked={options.highResolution}
                onCheckedChange={(checked) => setOptions({ ...options, highResolution: checked })}
              />
            </div>
          </div>

          {/* Background Color */}
          <div>
            <Label className="text-xs text-gray-600 dark:text-gray-400 mb-2 block">
              Background
            </Label>
            <Select
              value={options.backgroundColor}
              onValueChange={(value) => setOptions({ ...options, backgroundColor: value })}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="white">White</SelectItem>
                <SelectItem value="transparent">Transparent</SelectItem>
                <SelectItem value="dark">Dark</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        <Separator className="my-4" />

        <div className="flex justify-end space-x-2">
          <Button variant="outline" size="sm" onClick={onClose}>
            Cancel
          </Button>
          <Button size="sm" onClick={handleExport}>
            <Download className="w-4 h-4 mr-2" />
            Export
          </Button>
        </div>
      </div>
    </motion.div>
  )
}

export const QuickActions: React.FC<QuickActionsProps> = ({
  widget,
  position,
  isVisible,
  onClose,
  onAction,
  customActions = [],
  drillDownPath = [],
  className
}) => {
  const [showFilterPanel, setShowFilterPanel] = useState(false)
  const [showExportOptions, setShowExportOptions] = useState(false)
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null)
  const menuRef = useRef<HTMLDivElement>(null)

  // Combine all available actions
  const allActions = [
    ...DEFAULT_ACTIONS,
    ...CHART_DRILL_ACTIONS,
    ...TABLE_ACTIONS,
    ...customActions
  ].filter(action => !action.condition || action.condition(widget))

  // Group actions by category
  const actionsByCategory = allActions.reduce((acc, action) => {
    if (!acc[action.category]) {
      acc[action.category] = []
    }
    acc[action.category].push(action)
    return acc
  }, {} as Record<string, QuickAction[]>)

  // Handle click outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        onClose()
      }
    }

    if (isVisible) {
      document.addEventListener('mousedown', handleClickOutside)
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
    }
  }, [isVisible, onClose])

  // Handle keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (!isVisible) return

      const shortcutAction = allActions.find(action => {
        if (!action.shortcut) return false

        const keys = action.shortcut.split('+')
        const isCtrl = keys.includes('Ctrl') && event.ctrlKey
        const isShift = keys.includes('Shift') && event.shiftKey
        const key = keys[keys.length - 1].toLowerCase()

        return event.key.toLowerCase() === key &&
               (!keys.includes('Ctrl') || isCtrl) &&
               (!keys.includes('Shift') || isShift)
      })

      if (shortcutAction) {
        event.preventDefault()
        onAction(shortcutAction, widget)
        onClose()
      }

      if (event.key === 'Escape') {
        onClose()
      }
    }

    if (isVisible) {
      document.addEventListener('keydown', handleKeyDown)
    }

    return () => {
      document.removeEventListener('keydown', handleKeyDown)
    }
  }, [isVisible, allActions, widget, onAction, onClose])

  const handleActionClick = (action: QuickAction) => {
    if (action.id === 'filter') {
      setShowFilterPanel(true)
      return
    }

    if (action.id.startsWith('export-')) {
      setShowExportOptions(true)
      return
    }

    onAction(action, widget)
    onClose()
  }

  const categoryIcons = {
    filter: Filter,
    export: Download,
    view: Eye,
    edit: Edit,
    share: Share2,
    'drill-down': TrendingUp
  }

  if (!isVisible) return null

  return (
    <AnimatePresence>
      <motion.div
        ref={menuRef}
        className={cn(
          "fixed bg-white dark:bg-gray-800 rounded-lg shadow-xl border border-gray-200 dark:border-gray-700 z-50 min-w-64",
          className
        )}
        style={{
          left: position.x,
          top: position.y
        }}
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        transition={{ duration: 0.1 }}
      >
        {/* Breadcrumb for drill-down path */}
        {drillDownPath.length > 0 && (
          <div className="px-3 py-2 border-b border-gray-200 dark:border-gray-700">
            <div className="flex items-center text-xs text-gray-500 dark:text-gray-400">
              {drillDownPath.map((level, index) => (
                <React.Fragment key={level.level}>
                  {index > 0 && <ArrowRight className="w-3 h-3 mx-1" />}
                  <span className="truncate">{level.label}</span>
                </React.Fragment>
              ))}
            </div>
          </div>
        )}

        {/* Widget info */}
        <div className="px-3 py-2 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-gray-900 dark:text-white truncate">
              {widget.title}
            </span>
            <Badge variant="outline" className="text-xs">
              {widget.type.replace('_', ' ')}
            </Badge>
          </div>
        </div>

        {/* Category tabs */}
        <div className="flex border-b border-gray-200 dark:border-gray-700">
          {Object.keys(actionsByCategory).map((category) => {
            const IconComponent = categoryIcons[category as keyof typeof categoryIcons] || MoreVertical
            const isActive = selectedCategory === category || (!selectedCategory && category === 'view')

            return (
              <button
                key={category}
                onClick={() => setSelectedCategory(category)}
                className={cn(
                  "flex items-center px-3 py-2 text-xs font-medium border-b-2 transition-colors",
                  isActive
                    ? "border-blue-500 text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20"
                    : "border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
                )}
              >
                <IconComponent className="w-3 h-3 mr-1" />
                {category.replace('-', ' ')}
              </button>
            )
          })}
        </div>

        {/* Actions list */}
        <div className="py-1 max-h-80 overflow-y-auto">
          {actionsByCategory[selectedCategory || 'view']?.map((action) => (
            <button
              key={action.id}
              onClick={() => handleActionClick(action)}
              className={cn(
                "w-full flex items-center px-3 py-2 text-sm text-left hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors",
                action.destructive && "text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20"
              )}
            >
              <action.icon className="w-4 h-4 mr-3 flex-shrink-0" />
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <span>{action.label}</span>
                  {action.shortcut && (
                    <Badge variant="outline" className="text-xs ml-2">
                      {action.shortcut}
                    </Badge>
                  )}
                </div>
                {action.description && (
                  <div className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                    {action.description}
                  </div>
                )}
              </div>
            </button>
          ))}
        </div>

        {/* Filter Panel */}
        <AnimatePresence>
          {showFilterPanel && (
            <FilterPanel
              widget={widget}
              onApplyFilter={(filters) => {
                console.log('Applied filters:', filters)
                setShowFilterPanel(false)
              }}
              onClose={() => setShowFilterPanel(false)}
            />
          )}
        </AnimatePresence>

        {/* Export Options */}
        <AnimatePresence>
          {showExportOptions && (
            <ExportOptions
              widget={widget}
              onExport={(format, options) => {
                console.log('Export:', format, options)
                setShowExportOptions(false)
              }}
              onClose={() => setShowExportOptions(false)}
            />
          )}
        </AnimatePresence>
      </motion.div>
    </AnimatePresence>
  )
}

export default QuickActions