/**
 * Mobile Dashboard Component
 * Optimized dashboard experience for mobile devices
 */

import React, { useState, useEffect, useMemo, useCallback } from 'react'
import { motion, AnimatePresence, PanInfo } from 'framer-motion'
import {
  Menu,
  Search,
  Filter,
  Settings,
  MoreVertical,
  ChevronDown,
  ChevronRight,
  Grid,
  List,
  Maximize2,
  Share2,
  RefreshCw,
  Home,
  BarChart3,
  Users,
  Settings as SettingsIcon,
  Bell
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Drawer, DrawerContent, DrawerTrigger } from '@/components/ui/drawer'
import { Sheet, SheetContent, SheetTrigger } from '@/components/ui/sheet'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { KPICard } from './widgets/KPICard'
import { ChartContainer } from './widgets/charts/ChartContainer'
import { DataTable } from './widgets/DataTable'
import { QuickActions } from './QuickActions'
import { useDrillDown } from '@/hooks/useDrillDown'
import { useCache } from '@/services/cache-client'
import type { Widget, Dashboard } from '@/types/dashboard'

export interface MobileDashboardProps {
  dashboard: Dashboard
  widgets: Widget[]
  onWidgetUpdate?: (widget: Widget) => void
  onLayoutChange?: (layout: any) => void
  onFilterChange?: (filters: Record<string, any>) => void
  className?: string
}

type ViewMode = 'cards' | 'list' | 'carousel'
type LayoutMode = 'stack' | 'grid' | 'tabs'

export const MobileDashboard: React.FC<MobileDashboardProps> = ({
  dashboard,
  widgets,
  onWidgetUpdate,
  onLayoutChange,
  onFilterChange,
  className
}) => {
  const [viewMode, setViewMode] = useState<ViewMode>('cards')
  const [layoutMode, setLayoutMode] = useState<LayoutMode>('stack')
  const [selectedWidget, setSelectedWidget] = useState<Widget | null>(null)
  const [showFilters, setShowFilters] = useState(false)
  const [showSearch, setShowSearch] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [filters, setFilters] = useState<Record<string, any>>({})
  const [refreshing, setRefreshing] = useState(false)
  const [currentIndex, setCurrentIndex] = useState(0)

  // Mobile navigation state
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [quickActionsOpen, setQuickActionsOpen] = useState(false)
  const [quickActionsPosition, setQuickActionsPosition] = useState({ x: 0, y: 0 })

  // Responsive breakpoints
  const [screenSize, setScreenSize] = useState<'xs' | 'sm' | 'md'>('md')

  // Detect screen size
  useEffect(() => {
    const handleResize = () => {
      const width = window.innerWidth
      if (width < 480) {
        setScreenSize('xs')
        setLayoutMode('stack')
      } else if (width < 768) {
        setScreenSize('sm')
      } else {
        setScreenSize('md')
      }
    }

    handleResize()
    window.addEventListener('resize', handleResize)
    return () => window.removeEventListener('resize', handleResize)
  }, [])

  // Filter widgets based on search and filters
  const filteredWidgets = useMemo(() => {
    let filtered = widgets

    // Search filter
    if (searchQuery) {
      filtered = filtered.filter(widget =>
        widget.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        widget.description?.toLowerCase().includes(searchQuery.toLowerCase())
      )
    }

    // Category/type filters
    if (filters.category) {
      filtered = filtered.filter(widget => widget.category === filters.category)
    }

    if (filters.type) {
      filtered = filtered.filter(widget => widget.type === filters.type)
    }

    return filtered
  }, [widgets, searchQuery, filters])

  // Group widgets by priority for mobile display
  const groupedWidgets = useMemo(() => {
    const groups = {
      critical: filteredWidgets.filter(w => w.priority === 'critical'),
      high: filteredWidgets.filter(w => w.priority === 'high'),
      medium: filteredWidgets.filter(w => w.priority === 'medium'),
      low: filteredWidgets.filter(w => w.priority === 'low' || !w.priority)
    }

    return groups
  }, [filteredWidgets])

  // Handle pull-to-refresh
  const handleRefresh = useCallback(async () => {
    setRefreshing(true)
    try {
      // Trigger data refresh for all widgets
      await Promise.all(
        widgets.map(widget =>
          fetch(`/api/widgets/${widget.id}/refresh`, { method: 'POST' })
        )
      )
    } catch (error) {
      console.error('Refresh failed:', error)
    } finally {
      setRefreshing(false)
    }
  }, [widgets])

  // Handle swipe gestures for carousel mode
  const handleSwipe = useCallback((event: any, info: PanInfo) => {
    if (viewMode !== 'carousel') return

    const threshold = 50
    if (info.offset.x > threshold && currentIndex > 0) {
      setCurrentIndex(currentIndex - 1)
    } else if (info.offset.x < -threshold && currentIndex < filteredWidgets.length - 1) {
      setCurrentIndex(currentIndex + 1)
    }
  }, [viewMode, currentIndex, filteredWidgets.length])

  // Handle long press for quick actions
  const handleLongPress = useCallback((widget: Widget, event: React.TouchEvent) => {
    const touch = event.touches[0]
    setQuickActionsPosition({ x: touch.clientX, y: touch.clientY })
    setSelectedWidget(widget)
    setQuickActionsOpen(true)
  }, [])

  // Render widget based on type and screen size
  const renderWidget = useCallback((widget: Widget, index: number, compact = false) => {
    const commonProps = {
      widget,
      isExpanded: !compact && selectedWidget?.id === widget.id,
      className: cn(
        'touch-manipulation',
        compact && 'h-32',
        !compact && 'min-h-48'
      )
    }

    const handleTouch = (event: React.TouchEvent) => {
      // Handle long press
      const timer = setTimeout(() => {
        handleLongPress(widget, event)
      }, 500)

      const handleTouchEnd = () => {
        clearTimeout(timer)
        document.removeEventListener('touchend', handleTouchEnd)
      }

      document.addEventListener('touchend', handleTouchEnd)
    }

    const widgetElement = (
      <motion.div
        key={widget.id}
        className={cn(
          "bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700",
          compact ? "p-3" : "p-4",
          "cursor-pointer"
        )}
        onTouchStart={handleTouch}
        onClick={() => setSelectedWidget(selectedWidget?.id === widget.id ? null : widget)}
        layout
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.9 }}
        transition={{ delay: index * 0.05 }}
      >
        {widget.type === 'kpi' && <KPICard {...commonProps} />}
        {widget.type.includes('chart') && <ChartContainer {...commonProps} />}
        {widget.type === 'data_table' && <DataTable {...commonProps} />}
      </motion.div>
    )

    return widgetElement
  }, [selectedWidget, handleLongPress])

  // Render mobile navigation
  const renderMobileNav = () => (
    <div className="fixed bottom-0 left-0 right-0 bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 z-40">
      <div className="flex items-center justify-around py-2">
        <Button variant="ghost" size="sm" className="flex flex-col gap-1">
          <Home className="w-4 h-4" />
          <span className="text-xs">Home</span>
        </Button>
        <Button variant="ghost" size="sm" className="flex flex-col gap-1">
          <BarChart3 className="w-4 h-4" />
          <span className="text-xs">Analytics</span>
        </Button>
        <Button variant="ghost" size="sm" className="flex flex-col gap-1">
          <Users className="w-4 h-4" />
          <span className="text-xs">Team</span>
        </Button>
        <Button variant="ghost" size="sm" className="flex flex-col gap-1">
          <Bell className="w-4 h-4" />
          <span className="text-xs">Alerts</span>
        </Button>
        <Button variant="ghost" size="sm" className="flex flex-col gap-1">
          <SettingsIcon className="w-4 h-4" />
          <span className="text-xs">Settings</span>
        </Button>
      </div>
    </div>
  )

  // Render header with mobile controls
  const renderHeader = () => (
    <div className="sticky top-0 z-30 bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
      <div className="flex items-center justify-between p-3">
        <div className="flex items-center space-x-3">
          <Sheet open={sidebarOpen} onOpenChange={setSidebarOpen}>
            <SheetTrigger asChild>
              <Button variant="ghost" size="sm">
                <Menu className="w-5 h-5" />
              </Button>
            </SheetTrigger>
            <SheetContent side="left" className="w-80">
              {renderSidebar()}
            </SheetContent>
          </Sheet>

          <div>
            <h1 className="text-lg font-semibold text-gray-900 dark:text-white truncate">
              {dashboard.title}
            </h1>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              {filteredWidgets.length} widgets
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setShowSearch(!showSearch)}
          >
            <Search className="w-4 h-4" />
          </Button>

          <Button
            variant="ghost"
            size="sm"
            onClick={() => setShowFilters(!showFilters)}
          >
            <Filter className="w-4 h-4" />
            {Object.keys(filters).length > 0 && (
              <Badge className="ml-1 h-4 w-4 p-0 text-xs">
                {Object.keys(filters).length}
              </Badge>
            )}
          </Button>

          <Button
            variant="ghost"
            size="sm"
            onClick={handleRefresh}
            disabled={refreshing}
          >
            <RefreshCw className={cn("w-4 h-4", refreshing && "animate-spin")} />
          </Button>

          <Drawer>
            <DrawerTrigger asChild>
              <Button variant="ghost" size="sm">
                <MoreVertical className="w-4 h-4" />
              </Button>
            </DrawerTrigger>
            <DrawerContent>
              {renderMobileSettings()}
            </DrawerContent>
          </Drawer>
        </div>
      </div>

      {/* Search bar */}
      <AnimatePresence>
        {showSearch && (
          <motion.div
            className="px-3 pb-3"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
          >
            <Input
              placeholder="Search widgets..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full"
              autoFocus
            />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Filters */}
      <AnimatePresence>
        {showFilters && (
          <motion.div
            className="px-3 pb-3 space-y-2"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
          >
            <div className="flex flex-wrap gap-2">
              {['kpi', 'chart', 'table', 'text'].map(type => (
                <Button
                  key={type}
                  variant={filters.type === type ? "default" : "outline"}
                  size="sm"
                  onClick={() => setFilters(prev => ({
                    ...prev,
                    type: prev.type === type ? undefined : type
                  }))}
                >
                  {type.toUpperCase()}
                </Button>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )

  // Render sidebar for mobile navigation
  const renderSidebar = () => (
    <div className="h-full flex flex-col">
      <div className="p-4 border-b border-gray-200 dark:border-gray-700">
        <h2 className="text-lg font-semibold">CoreFlow360</h2>
        <p className="text-sm text-gray-500">Dashboard System</p>
      </div>

      <ScrollArea className="flex-1 p-4">
        <div className="space-y-4">
          <div>
            <h3 className="text-sm font-medium mb-2">Dashboards</h3>
            <div className="space-y-1">
              {/* Dashboard list would go here */}
              <Button variant="ghost" className="w-full justify-start">
                Executive Overview
              </Button>
              <Button variant="ghost" className="w-full justify-start">
                Sales Analytics
              </Button>
              <Button variant="ghost" className="w-full justify-start">
                Marketing Metrics
              </Button>
            </div>
          </div>

          <div>
            <h3 className="text-sm font-medium mb-2">View Options</h3>
            <div className="space-y-2">
              <Button
                variant={viewMode === 'cards' ? 'default' : 'ghost'}
                className="w-full justify-start"
                onClick={() => setViewMode('cards')}
              >
                <Grid className="w-4 h-4 mr-2" />
                Card View
              </Button>
              <Button
                variant={viewMode === 'list' ? 'default' : 'ghost'}
                className="w-full justify-start"
                onClick={() => setViewMode('list')}
              >
                <List className="w-4 h-4 mr-2" />
                List View
              </Button>
              <Button
                variant={viewMode === 'carousel' ? 'default' : 'ghost'}
                className="w-full justify-start"
                onClick={() => setViewMode('carousel')}
              >
                <Maximize2 className="w-4 h-4 mr-2" />
                Carousel
              </Button>
            </div>
          </div>
        </div>
      </ScrollArea>
    </div>
  )

  // Render mobile settings drawer
  const renderMobileSettings = () => (
    <div className="p-4 space-y-4">
      <h3 className="text-lg font-semibold">Dashboard Options</h3>

      <div className="space-y-2">
        <Button variant="outline" className="w-full justify-start">
          <Share2 className="w-4 h-4 mr-2" />
          Share Dashboard
        </Button>
        <Button variant="outline" className="w-full justify-start">
          <Settings className="w-4 h-4 mr-2" />
          Configure Layout
        </Button>
        <Button variant="outline" className="w-full justify-start">
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh All Data
        </Button>
      </div>
    </div>
  )

  // Render widgets based on view mode
  const renderWidgets = () => {
    if (viewMode === 'carousel') {
      return (
        <div className="relative h-full">
          <motion.div
            className="flex h-full"
            drag="x"
            dragConstraints={{ left: -(filteredWidgets.length - 1) * window.innerWidth, right: 0 }}
            onDragEnd={handleSwipe}
            animate={{ x: -currentIndex * window.innerWidth }}
            transition={{ type: "spring", stiffness: 300, damping: 30 }}
          >
            {filteredWidgets.map((widget, index) => (
              <div key={widget.id} className="w-full flex-shrink-0 p-4">
                {renderWidget(widget, index)}
              </div>
            ))}
          </motion.div>

          {/* Carousel indicators */}
          <div className="absolute bottom-4 left-1/2 transform -translate-x-1/2 flex space-x-2">
            {filteredWidgets.map((_, index) => (
              <button
                key={index}
                className={cn(
                  "w-2 h-2 rounded-full transition-colors",
                  index === currentIndex ? "bg-blue-500" : "bg-gray-300"
                )}
                onClick={() => setCurrentIndex(index)}
              />
            ))}
          </div>
        </div>
      )
    }

    if (viewMode === 'list') {
      return (
        <ScrollArea className="h-full">
          <div className="p-4 space-y-3">
            {filteredWidgets.map((widget, index) => (
              <div key={widget.id} className="h-32">
                {renderWidget(widget, index, true)}
              </div>
            ))}
          </div>
        </ScrollArea>
      )
    }

    // Card view with priority grouping
    return (
      <ScrollArea className="h-full">
        <div className="p-4 space-y-6">
          {Object.entries(groupedWidgets).map(([priority, widgets]) => {
            if (widgets.length === 0) return null

            return (
              <div key={priority}>
                <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wider mb-3">
                  {priority} Priority
                </h3>
                <div className={cn(
                  "grid gap-4",
                  screenSize === 'xs' ? "grid-cols-1" : "grid-cols-2"
                )}>
                  {widgets.map((widget, index) => renderWidget(widget, index))}
                </div>
              </div>
            )
          })}
        </div>
      </ScrollArea>
    )
  }

  return (
    <div className={cn("h-screen flex flex-col bg-gray-50 dark:bg-gray-900", className)}>
      {renderHeader()}

      <div className="flex-1 overflow-hidden pb-16">
        {renderWidgets()}
      </div>

      {renderMobileNav()}

      {/* Quick Actions */}
      <QuickActions
        widget={selectedWidget!}
        position={quickActionsPosition}
        isVisible={quickActionsOpen && !!selectedWidget}
        onClose={() => setQuickActionsOpen(false)}
        onAction={(action, widget) => {
          console.log('Mobile action:', action, widget)
          setQuickActionsOpen(false)
        }}
      />
    </div>
  )
}

export default MobileDashboard