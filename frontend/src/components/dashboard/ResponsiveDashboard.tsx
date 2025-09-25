/**
 * Responsive Dashboard Component
 * Adaptive dashboard that switches between desktop and mobile layouts
 */

import React, { useState, useEffect, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useResponsive } from '@/hooks/useResponsive'
import { DashboardGrid } from './DashboardGrid'
import { MobileDashboard } from './MobileDashboard'
import type { Widget, Dashboard } from '@/types/dashboard'

export interface ResponsiveDashboardProps {
  dashboard: Dashboard
  widgets: Widget[]
  onWidgetUpdate?: (widget: Widget) => void
  onLayoutChange?: (layout: any) => void
  onFilterChange?: (filters: Record<string, any>) => void
  className?: string
}

export const ResponsiveDashboard: React.FC<ResponsiveDashboardProps> = ({
  dashboard,
  widgets,
  onWidgetUpdate,
  onLayoutChange,
  onFilterChange,
  className
}) => {
  const {
    viewport,
    isMobile,
    isTablet,
    isDesktop,
    getAdaptiveLayout,
    getOptimalWidgetSize,
    touchHelpers
  } = useResponsive()

  const [currentLayout, setCurrentLayout] = useState<any[]>([])
  const [forceDesktopMode, setForceDesktopMode] = useState(false)

  // Determine which layout to use
  const shouldUseMobileLayout = useMemo(() => {
    if (forceDesktopMode) return false
    return isMobile || (isTablet && viewport.orientation === 'portrait')
  }, [isMobile, isTablet, viewport.orientation, forceDesktopMode])

  // Generate responsive layout for grid
  const responsiveLayout = useMemo(() => {
    if (shouldUseMobileLayout) return []

    const adaptiveConfig = getAdaptiveLayout()

    return widgets.map((widget, index) => {
      const { width, height } = getOptimalWidgetSize(
        widget.aspectRatio || 16/9,
        widget.priority || 'medium'
      )

      // Calculate position using simple flow layout
      const cols = adaptiveConfig.columns
      const row = Math.floor(index / cols)
      const col = index % cols

      return {
        i: widget.id,
        x: col * Math.floor(width),
        y: row * height,
        w: Math.min(width, cols - (col * Math.floor(width))),
        h: height,
        minW: 1,
        minH: Math.ceil(200 / adaptiveConfig.rowHeight),
        maxW: cols,
        isDraggable: !widget.locked,
        isResizable: !widget.locked && isDesktop,
        static: widget.locked
      }
    })
  }, [widgets, shouldUseMobileLayout, getAdaptiveLayout, getOptimalWidgetSize, isDesktop])

  // Handle layout changes
  const handleLayoutChange = (layout: any[]) => {
    setCurrentLayout(layout)
    onLayoutChange?.(layout)
  }

  // Render mobile layout
  if (shouldUseMobileLayout) {
    return (
      <AnimatePresence mode="wait">
        <motion.div
          key="mobile"
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 1.05 }}
          transition={{ duration: 0.2 }}
          className={className}
        >
          <MobileDashboard
            dashboard={dashboard}
            widgets={widgets}
            onWidgetUpdate={onWidgetUpdate}
            onLayoutChange={onLayoutChange}
            onFilterChange={onFilterChange}
          />
        </motion.div>
      </AnimatePresence>
    )
  }

  // Render desktop/tablet layout
  return (
    <AnimatePresence mode="wait">
      <motion.div
        key="desktop"
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 1.05 }}
        transition={{ duration: 0.2 }}
        className={className}
      >
        <DashboardGrid
          dashboard={dashboard}
          widgets={widgets}
          layout={responsiveLayout}
          onLayoutChange={handleLayoutChange}
          onWidgetUpdate={onWidgetUpdate}
          breakpoints={{
            lg: 1200,
            md: 996,
            sm: 768,
            xs: 480,
            xxs: 0
          }}
          cols={{
            lg: viewport.deviceType === 'desktop' ? 12 : 8,
            md: viewport.deviceType === 'desktop' ? 10 : 6,
            sm: 6,
            xs: 4,
            xxs: 2
          }}
          rowHeight={getAdaptiveLayout().rowHeight}
          margin={getAdaptiveLayout().margin}
          containerPadding={getAdaptiveLayout().containerPadding}
          isResizable={isDesktop}
          isDraggable={true}
          compactType={getAdaptiveLayout().compactType}
          useCSSTransforms={true}
          preventCollision={false}
        />

        {/* Mobile mode toggle for tablets */}
        {isTablet && (
          <motion.button
            className="fixed bottom-4 right-4 z-50 bg-blue-600 text-white p-3 rounded-full shadow-lg"
            onClick={() => setForceDesktopMode(!forceDesktopMode)}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            {forceDesktopMode ? '📱' : '🖥️'}
          </motion.button>
        )}
      </motion.div>
    </AnimatePresence>
  )
}

export default ResponsiveDashboard