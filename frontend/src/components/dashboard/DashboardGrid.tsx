/**
 * Dashboard Grid Layout Engine
 * Advanced drag-and-drop grid system with 24-column layout
 */

import React, { useState, useEffect, useCallback, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import RGL, { WidthProvider, Layout, Layouts } from 'react-grid-layout'
import {
  Maximize2,
  Minimize2,
  Move,
  Lock,
  Unlock,
  Settings,
  X,
  RotateCcw,
  Save,
  Grid3X3,
  Eye,
  EyeOff
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { useDashboardStore } from '@/stores/dashboardStore'
import { useGridLayout } from '@/hooks/useGridLayout'
import { DashboardWidget } from './DashboardWidget'
import { WidgetConfigModal } from './WidgetConfigModal'
import type { Widget, GridBreakpoint } from '@/types/dashboard'

const ReactGridLayout = WidthProvider(RGL)

export interface DashboardGridProps {
  dashboardId: string
  widgets: Widget[]
  isEditable?: boolean
  className?: string
}

const GRID_CONFIG = {
  cols: { lg: 24, md: 20, sm: 16, xs: 12, xxs: 8 },
  breakpoints: { lg: 1200, md: 996, sm: 768, xs: 480, xxs: 0 },
  rowHeight: 40,
  margin: [16, 16],
  containerPadding: [20, 20],
  compactType: 'vertical' as const,
  preventCollision: false,
  useCSSTransforms: true,
  verticalCompact: true
}

const SNAP_THRESHOLD = 10

export const DashboardGrid: React.FC<DashboardGridProps> = ({
  dashboardId,
  widgets,
  isEditable = false,
  className
}) => {
  const [currentBreakpoint, setCurrentBreakpoint] = useState<GridBreakpoint>('lg')
  const [isLayoutLocked, setIsLayoutLocked] = useState(false)
  const [selectedWidgetId, setSelectedWidgetId] = useState<string | null>(null)
  const [expandedWidgetId, setExpandedWidgetId] = useState<string | null>(null)
  const [showGrid, setShowGrid] = useState(false)
  const [configModalOpen, setConfigModalOpen] = useState(false)

  const gridRef = useRef<HTMLDivElement>(null)

  const {
    layouts,
    updateLayout,
    updateLayouts,
    saveLayout,
    resetLayout,
    canUndo,
    canRedo,
    undo,
    redo,
    isLoading
  } = useGridLayout(dashboardId)

  const {
    updateWidget,
    removeWidget,
    isEditMode,
    setEditMode
  } = useDashboardStore()

  // Handle layout changes
  const handleLayoutChange = useCallback((layout: Layout[], layouts: Layouts) => {
    if (!isEditable || isLayoutLocked) return

    updateLayouts(layouts)
  }, [isEditable, isLayoutLocked, updateLayouts])

  // Handle breakpoint changes
  const handleBreakpointChange = useCallback((breakpoint: string) => {
    setCurrentBreakpoint(breakpoint as GridBreakpoint)
  }, [])

  // Handle widget drag start
  const handleDragStart = useCallback((layout: Layout[], oldItem: Layout, newItem: Layout) => {
    if (!isEditable || isLayoutLocked) return

    setSelectedWidgetId(newItem.i)
    setShowGrid(true)
  }, [isEditable, isLayoutLocked])

  // Handle widget drag stop
  const handleDragStop = useCallback((layout: Layout[], oldItem: Layout, newItem: Layout) => {
    setShowGrid(false)
    setSelectedWidgetId(null)

    // Apply magnetic snapping
    const snappedItem = applyMagneticSnapping(newItem, layout)
    if (snappedItem !== newItem) {
      updateLayout(currentBreakpoint, snappedItem)
    }
  }, [currentBreakpoint, updateLayout])

  // Handle widget resize
  const handleResizeStop = useCallback((layout: Layout[], oldItem: Layout, newItem: Layout) => {
    // Apply size constraints
    const constrainedItem = applyWidgetConstraints(newItem, getWidgetById(newItem.i))
    if (constrainedItem !== newItem) {
      updateLayout(currentBreakpoint, constrainedItem)
    }
  }, [currentBreakpoint, updateLayout])

  // Magnetic snapping logic
  const applyMagneticSnapping = (item: Layout, layout: Layout[]): Layout => {
    const otherItems = layout.filter(i => i.i !== item.i)
    let snappedItem = { ...item }

    // Snap to grid lines
    const gridX = Math.round(item.x / 2) * 2
    const gridY = Math.round(item.y / 2) * 2

    if (Math.abs(item.x - gridX) < SNAP_THRESHOLD / GRID_CONFIG.cols[currentBreakpoint]) {
      snappedItem.x = gridX
    }

    if (Math.abs(item.y - gridY) < SNAP_THRESHOLD / GRID_CONFIG.rowHeight) {
      snappedItem.y = gridY
    }

    // Snap to other widgets
    for (const otherItem of otherItems) {
      // Snap to right edge
      const rightEdge = otherItem.x + otherItem.w
      if (Math.abs(item.x - rightEdge) < SNAP_THRESHOLD / GRID_CONFIG.cols[currentBreakpoint]) {
        snappedItem.x = rightEdge
      }

      // Snap to left edge
      if (Math.abs(item.x - otherItem.x) < SNAP_THRESHOLD / GRID_CONFIG.cols[currentBreakpoint]) {
        snappedItem.x = otherItem.x
      }

      // Snap to bottom edge
      const bottomEdge = otherItem.y + otherItem.h
      if (Math.abs(item.y - bottomEdge) < SNAP_THRESHOLD / GRID_CONFIG.rowHeight) {
        snappedItem.y = bottomEdge
      }

      // Snap to top edge
      if (Math.abs(item.y - otherItem.y) < SNAP_THRESHOLD / GRID_CONFIG.rowHeight) {
        snappedItem.y = otherItem.y
      }
    }

    return snappedItem
  }

  // Apply widget size constraints
  const applyWidgetConstraints = (item: Layout, widget?: Widget): Layout => {
    if (!widget) return item

    const constraints = widget.constraints || {}
    let constrainedItem = { ...item }

    if (constraints.minW && item.w < constraints.minW) {
      constrainedItem.w = constraints.minW
    }

    if (constraints.maxW && item.w > constraints.maxW) {
      constrainedItem.w = constraints.maxW
    }

    if (constraints.minH && item.h < constraints.minH) {
      constrainedItem.h = constraints.minH
    }

    if (constraints.maxH && item.h > constraints.maxH) {
      constrainedItem.h = constraints.maxH
    }

    return constrainedItem
  }

  // Get widget by ID
  const getWidgetById = (id: string): Widget | undefined => {
    return widgets.find(w => w.id === id)
  }

  // Handle widget expansion
  const handleExpandWidget = useCallback((widgetId: string) => {
    if (expandedWidgetId === widgetId) {
      setExpandedWidgetId(null)
    } else {
      setExpandedWidgetId(widgetId)
    }
  }, [expandedWidgetId])

  // Handle widget configuration
  const handleConfigureWidget = useCallback((widgetId: string) => {
    setSelectedWidgetId(widgetId)
    setConfigModalOpen(true)
  }, [])

  // Handle widget removal
  const handleRemoveWidget = useCallback((widgetId: string) => {
    removeWidget(widgetId)
  }, [removeWidget])

  // Widget toolbar component
  const WidgetToolbar: React.FC<{ widget: Widget }> = ({ widget }) => {
    if (!isEditable || !isEditMode) return null

    return (
      <div className="absolute top-2 right-2 z-10 opacity-0 group-hover:opacity-100 transition-opacity">
        <div className="flex items-center space-x-1 bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 p-1">
          <Button
            variant="ghost"
            size="sm"
            className="w-6 h-6 p-0"
            onClick={() => handleExpandWidget(widget.id)}
            title={expandedWidgetId === widget.id ? "Collapse" : "Expand"}
          >
            {expandedWidgetId === widget.id ? (
              <Minimize2 className="w-3 h-3" />
            ) : (
              <Maximize2 className="w-3 h-3" />
            )}
          </Button>

          <Button
            variant="ghost"
            size="sm"
            className="w-6 h-6 p-0"
            onClick={() => handleConfigureWidget(widget.id)}
            title="Configure widget"
          >
            <Settings className="w-3 h-3" />
          </Button>

          <Button
            variant="ghost"
            size="sm"
            className="w-6 h-6 p-0 hover:bg-red-100 dark:hover:bg-red-900/30"
            onClick={() => handleRemoveWidget(widget.id)}
            title="Remove widget"
          >
            <X className="w-3 h-3" />
          </Button>
        </div>
      </div>
    )
  }

  // Grid overlay for visual guidance
  const GridOverlay: React.FC = () => {
    if (!showGrid || !isEditable) return null

    return (
      <div className="absolute inset-0 pointer-events-none z-0">
        <svg width="100%" height="100%" className="opacity-20">
          <defs>
            <pattern
              id="grid"
              width={`${100 / GRID_CONFIG.cols[currentBreakpoint]}%`}
              height={GRID_CONFIG.rowHeight + GRID_CONFIG.margin[1]}
              patternUnits="userSpaceOnUse"
            >
              <path
                d={`M 0 0 L 0 ${GRID_CONFIG.rowHeight + GRID_CONFIG.margin[1]} M 0 0 L ${100 / GRID_CONFIG.cols[currentBreakpoint]} 0`}
                fill="none"
                stroke="currentColor"
                strokeWidth="1"
              />
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#grid)" />
        </svg>
      </div>
    )
  }

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (!isEditable) return

      if (e.ctrlKey || e.metaKey) {
        switch (e.key) {
          case 'z':
            e.preventDefault()
            if (e.shiftKey) {
              redo()
            } else {
              undo()
            }
            break
          case 's':
            e.preventDefault()
            saveLayout()
            break
          case 'r':
            e.preventDefault()
            resetLayout()
            break
          case 'l':
            e.preventDefault()
            setIsLayoutLocked(!isLayoutLocked)
            break
          case 'g':
            e.preventDefault()
            setShowGrid(!showGrid)
            break
        }
      }

      if (e.key === 'Escape') {
        setSelectedWidgetId(null)
        setExpandedWidgetId(null)
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isEditable, isLayoutLocked, showGrid, undo, redo, saveLayout, resetLayout])

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin w-8 h-8 border-2 border-blue-600 border-t-transparent rounded-full" />
      </div>
    )
  }

  return (
    <div className={cn("relative w-full", className)} ref={gridRef}>
      {/* Toolbar */}
      {isEditable && (
        <div className="flex items-center justify-between mb-4 p-3 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-2">
            <Badge variant={isEditMode ? "default" : "secondary"}>
              {isEditMode ? "Edit Mode" : "View Mode"}
            </Badge>

            <Badge variant="outline" className="text-xs">
              {currentBreakpoint.toUpperCase()} • {GRID_CONFIG.cols[currentBreakpoint]} cols
            </Badge>

            {isLayoutLocked && (
              <Badge variant="destructive" className="text-xs">
                <Lock className="w-3 h-3 mr-1" />
                Locked
              </Badge>
            )}
          </div>

          <div className="flex items-center space-x-1">
            <Button
              variant="outline"
              size="sm"
              onClick={undo}
              disabled={!canUndo}
              title="Undo (Ctrl+Z)"
            >
              <RotateCcw className="w-4 h-4" />
            </Button>

            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowGrid(!showGrid)}
              title="Toggle grid (Ctrl+G)"
            >
              {showGrid ? (
                <EyeOff className="w-4 h-4" />
              ) : (
                <Eye className="w-4 h-4" />
              )}
            </Button>

            <Button
              variant="outline"
              size="sm"
              onClick={() => setIsLayoutLocked(!isLayoutLocked)}
              title="Lock layout (Ctrl+L)"
            >
              {isLayoutLocked ? (
                <Lock className="w-4 h-4" />
              ) : (
                <Unlock className="w-4 h-4" />
              )}
            </Button>

            <Button
              variant="outline"
              size="sm"
              onClick={saveLayout}
              title="Save layout (Ctrl+S)"
            >
              <Save className="w-4 h-4" />
            </Button>
          </div>
        </div>
      )}

      {/* Grid Overlay */}
      <GridOverlay />

      {/* Grid Layout */}
      <div className="relative">
        <ReactGridLayout
          {...GRID_CONFIG}
          layouts={layouts}
          onLayoutChange={handleLayoutChange}
          onBreakpointChange={handleBreakpointChange}
          onDragStart={handleDragStart}
          onDragStop={handleDragStop}
          onResizeStop={handleResizeStop}
          isDraggable={isEditable && !isLayoutLocked}
          isResizable={isEditable && !isLayoutLocked}
          className="dashboard-grid"
        >
          {widgets.map((widget) => (
            <div
              key={widget.id}
              className={cn(
                "group relative bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700",
                "shadow-sm hover:shadow-md transition-shadow",
                selectedWidgetId === widget.id && "ring-2 ring-blue-500",
                expandedWidgetId === widget.id && "z-50 shadow-2xl",
                widget.isHidden && "opacity-50"
              )}
              style={{
                cursor: isEditable && !isLayoutLocked ? 'move' : 'default'
              }}
            >
              {/* Widget Toolbar */}
              <WidgetToolbar widget={widget} />

              {/* Widget Content */}
              <div className="h-full p-4">
                <DashboardWidget
                  widget={widget}
                  isExpanded={expandedWidgetId === widget.id}
                  isSelected={selectedWidgetId === widget.id}
                  isEditable={isEditable}
                />
              </div>

              {/* Resize Handle */}
              {isEditable && !isLayoutLocked && (
                <div className="absolute bottom-1 right-1 opacity-0 group-hover:opacity-100 transition-opacity">
                  <div className="w-3 h-3 bg-gray-400 rounded-sm transform rotate-45" />
                </div>
              )}
            </div>
          ))}
        </ReactGridLayout>
      </div>

      {/* Expanded Widget Modal */}
      <AnimatePresence>
        {expandedWidgetId && (
          <motion.div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setExpandedWidgetId(null)}
          >
            <motion.div
              className="bg-white dark:bg-gray-900 rounded-xl shadow-2xl w-full max-w-6xl h-[80vh] overflow-hidden"
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.9 }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
                <h2 className="text-lg font-semibold">
                  {getWidgetById(expandedWidgetId)?.title || 'Widget'}
                </h2>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setExpandedWidgetId(null)}
                >
                  <X className="w-4 h-4" />
                </Button>
              </div>

              <div className="p-6 h-full">
                {getWidgetById(expandedWidgetId) && (
                  <DashboardWidget
                    widget={getWidgetById(expandedWidgetId)!}
                    isExpanded={true}
                    isSelected={false}
                    isEditable={isEditable}
                  />
                )}
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Widget Configuration Modal */}
      <WidgetConfigModal
        isOpen={configModalOpen}
        onClose={() => setConfigModalOpen(false)}
        widget={selectedWidgetId ? getWidgetById(selectedWidgetId) : undefined}
        onSave={(config) => {
          if (selectedWidgetId) {
            updateWidget(selectedWidgetId, config)
          }
          setConfigModalOpen(false)
        }}
      />
    </div>
  )
}

export default DashboardGrid