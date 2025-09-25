/**
 * Responsive Hook
 * Handles responsive behavior and adaptive layouts for dashboard components
 */

import { useState, useEffect, useCallback, useMemo } from 'react'

export type Breakpoint = 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl'
export type Orientation = 'portrait' | 'landscape'
export type DeviceType = 'mobile' | 'tablet' | 'desktop'

export interface ResponsiveConfig {
  breakpoints: Record<Breakpoint, number>
  containerPadding: Record<Breakpoint, number>
  gridColumns: Record<Breakpoint, number>
  widgetMinHeight: Record<Breakpoint, number>
}

export interface ViewportInfo {
  width: number
  height: number
  breakpoint: Breakpoint
  orientation: Orientation
  deviceType: DeviceType
  pixelRatio: number
  isTouch: boolean
  isMobile: boolean
  isTablet: boolean
  isDesktop: boolean
}

export interface AdaptiveLayout {
  columns: number
  rowHeight: number
  margin: [number, number]
  containerPadding: [number, number]
  compactType: 'vertical' | 'horizontal' | null
}

const DEFAULT_CONFIG: ResponsiveConfig = {
  breakpoints: {
    xs: 0,
    sm: 640,
    md: 768,
    lg: 1024,
    xl: 1280,
    '2xl': 1536
  },
  containerPadding: {
    xs: 8,
    sm: 12,
    md: 16,
    lg: 20,
    xl: 24,
    '2xl': 32
  },
  gridColumns: {
    xs: 1,
    sm: 2,
    md: 3,
    lg: 4,
    xl: 6,
    '2xl': 8
  },
  widgetMinHeight: {
    xs: 200,
    sm: 250,
    md: 300,
    lg: 350,
    xl: 400,
    '2xl': 450
  }
}

export const useResponsive = (config: Partial<ResponsiveConfig> = {}) => {
  const mergedConfig = { ...DEFAULT_CONFIG, ...config }

  const [viewport, setViewport] = useState<ViewportInfo>(() => {
    if (typeof window === 'undefined') {
      return {
        width: 1024,
        height: 768,
        breakpoint: 'lg' as Breakpoint,
        orientation: 'landscape' as Orientation,
        deviceType: 'desktop' as DeviceType,
        pixelRatio: 1,
        isTouch: false,
        isMobile: false,
        isTablet: false,
        isDesktop: true
      }
    }

    return getViewportInfo(mergedConfig.breakpoints)
  })

  const updateViewport = useCallback(() => {
    if (typeof window === 'undefined') return
    setViewport(getViewportInfo(mergedConfig.breakpoints))
  }, [mergedConfig.breakpoints])

  useEffect(() => {
    if (typeof window === 'undefined') return

    // Initial check
    updateViewport()

    // Set up resize listener with debouncing
    let timeoutId: NodeJS.Timeout
    const handleResize = () => {
      clearTimeout(timeoutId)
      timeoutId = setTimeout(updateViewport, 150)
    }

    // Set up orientation change listener
    const handleOrientationChange = () => {
      // Delay to ensure dimensions are updated
      setTimeout(updateViewport, 100)
    }

    window.addEventListener('resize', handleResize)
    window.addEventListener('orientationchange', handleOrientationChange)

    return () => {
      clearTimeout(timeoutId)
      window.removeEventListener('resize', handleResize)
      window.removeEventListener('orientationchange', handleOrientationChange)
    }
  }, [updateViewport])

  // Get adaptive layout configuration
  const getAdaptiveLayout = useCallback((
    baseColumns = 12,
    baseRowHeight = 60
  ): AdaptiveLayout => {
    const { breakpoint, deviceType, orientation } = viewport

    // Responsive columns
    let columns = mergedConfig.gridColumns[breakpoint]

    // Adjust for device type and orientation
    if (deviceType === 'mobile') {
      columns = orientation === 'portrait' ? 1 : 2
    } else if (deviceType === 'tablet') {
      columns = orientation === 'portrait' ? 2 : 3
    }

    // Responsive row height
    let rowHeight = baseRowHeight
    if (deviceType === 'mobile') {
      rowHeight = Math.max(40, baseRowHeight * 0.7)
    } else if (deviceType === 'tablet') {
      rowHeight = Math.max(50, baseRowHeight * 0.85)
    }

    // Responsive margins
    const basePadding = mergedConfig.containerPadding[breakpoint]
    const margin: [number, number] = [basePadding / 2, basePadding / 2]

    // Container padding
    const containerPadding: [number, number] = [basePadding, basePadding]

    // Compact type based on device
    let compactType: 'vertical' | 'horizontal' | null = null
    if (deviceType === 'mobile' && orientation === 'portrait') {
      compactType = 'vertical'
    }

    return {
      columns,
      rowHeight,
      margin,
      containerPadding,
      compactType
    }
  }, [viewport, mergedConfig])

  // Get responsive value based on current breakpoint
  const getResponsiveValue = useCallback(<T>(
    values: Partial<Record<Breakpoint, T>> | T
  ): T => {
    if (typeof values !== 'object' || values === null) {
      return values as T
    }

    const breakpoints = Object.keys(mergedConfig.breakpoints) as Breakpoint[]
    const currentBreakpointIndex = breakpoints.indexOf(viewport.breakpoint)

    // Find the value for current or closest smaller breakpoint
    for (let i = currentBreakpointIndex; i >= 0; i--) {
      const breakpoint = breakpoints[i]
      if ((values as Record<Breakpoint, T>)[breakpoint] !== undefined) {
        return (values as Record<Breakpoint, T>)[breakpoint]
      }
    }

    // Fallback to the smallest breakpoint
    const firstBreakpoint = breakpoints.find(bp =>
      (values as Record<Breakpoint, T>)[bp] !== undefined
    )

    return firstBreakpoint
      ? (values as Record<Breakpoint, T>)[firstBreakpoint]
      : (values as any)
  }, [viewport.breakpoint, mergedConfig.breakpoints])

  // Check if current breakpoint matches query
  const matches = useCallback((query: Breakpoint | `${Breakpoint}+` | `${Breakpoint}-`): boolean => {
    const breakpoints = Object.keys(mergedConfig.breakpoints) as Breakpoint[]
    const currentIndex = breakpoints.indexOf(viewport.breakpoint)

    if (query.endsWith('+')) {
      const targetBreakpoint = query.slice(0, -1) as Breakpoint
      const targetIndex = breakpoints.indexOf(targetBreakpoint)
      return currentIndex >= targetIndex
    }

    if (query.endsWith('-')) {
      const targetBreakpoint = query.slice(0, -1) as Breakpoint
      const targetIndex = breakpoints.indexOf(targetBreakpoint)
      return currentIndex <= targetIndex
    }

    return viewport.breakpoint === query
  }, [viewport.breakpoint, mergedConfig.breakpoints])

  // Get optimal widget size for current viewport
  const getOptimalWidgetSize = useCallback((
    aspectRatio = 16/9,
    priority: 'low' | 'medium' | 'high' | 'critical' = 'medium'
  ) => {
    const layout = getAdaptiveLayout()
    const availableWidth = viewport.width - (layout.containerPadding[0] * 2)
    const columnWidth = (availableWidth - (layout.margin[0] * (layout.columns - 1))) / layout.columns

    let width = 1 // Default width in grid units
    let height = 1 // Default height in grid units

    // Adjust based on device type and priority
    if (viewport.deviceType === 'mobile') {
      width = layout.columns // Full width on mobile
      height = Math.ceil((columnWidth / aspectRatio) / layout.rowHeight)
    } else if (viewport.deviceType === 'tablet') {
      if (priority === 'critical') {
        width = layout.columns
        height = Math.ceil((availableWidth / aspectRatio) / layout.rowHeight)
      } else if (priority === 'high') {
        width = Math.ceil(layout.columns / 2)
        height = Math.ceil((columnWidth * 2 / aspectRatio) / layout.rowHeight)
      } else {
        width = Math.ceil(layout.columns / 3)
        height = Math.ceil((columnWidth / aspectRatio) / layout.rowHeight)
      }
    } else {
      // Desktop
      if (priority === 'critical') {
        width = Math.ceil(layout.columns / 2)
        height = Math.ceil((columnWidth * 2 / aspectRatio) / layout.rowHeight)
      } else if (priority === 'high') {
        width = Math.ceil(layout.columns / 3)
        height = Math.ceil((columnWidth / aspectRatio) / layout.rowHeight)
      } else {
        width = Math.ceil(layout.columns / 4)
        height = Math.ceil((columnWidth / aspectRatio) / layout.rowHeight)
      }
    }

    // Ensure minimum height
    const minHeight = mergedConfig.widgetMinHeight[viewport.breakpoint]
    const minHeightUnits = Math.ceil(minHeight / layout.rowHeight)
    height = Math.max(height, minHeightUnits)

    return { width, height }
  }, [viewport, getAdaptiveLayout, mergedConfig.widgetMinHeight])

  // Touch and gesture helpers
  const touchHelpers = useMemo(() => ({
    isTouchDevice: viewport.isTouch,
    getSafeAreaInsets: () => {
      if (typeof window === 'undefined') return { top: 0, right: 0, bottom: 0, left: 0 }

      const safeAreaInsets = {
        top: parseInt(getComputedStyle(document.documentElement).getPropertyValue('--sat') || '0'),
        right: parseInt(getComputedStyle(document.documentElement).getPropertyValue('--sar') || '0'),
        bottom: parseInt(getComputedStyle(document.documentElement).getPropertyValue('--sab') || '0'),
        left: parseInt(getComputedStyle(document.documentElement).getPropertyValue('--sal') || '0')
      }

      return safeAreaInsets
    },
    getOptimalTouchTarget: () => {
      // Minimum 44px for touch targets (iOS HIG)
      return viewport.isMobile ? 44 : 32
    }
  }), [viewport])

  return {
    viewport,
    getAdaptiveLayout,
    getResponsiveValue,
    getOptimalWidgetSize,
    matches,
    touchHelpers,

    // Convenience properties
    isMobile: viewport.isMobile,
    isTablet: viewport.isTablet,
    isDesktop: viewport.isDesktop,
    isTouch: viewport.isTouch,
    breakpoint: viewport.breakpoint,
    orientation: viewport.orientation,
    deviceType: viewport.deviceType
  }
}

// Helper function to get viewport information
function getViewportInfo(breakpoints: Record<Breakpoint, number>): ViewportInfo {
  const width = window.innerWidth
  const height = window.innerHeight
  const pixelRatio = window.devicePixelRatio || 1

  // Determine breakpoint
  const breakpoint = Object.entries(breakpoints)
    .reverse()
    .find(([_, minWidth]) => width >= minWidth)?.[0] as Breakpoint || 'xs'

  // Determine orientation
  const orientation: Orientation = width > height ? 'landscape' : 'portrait'

  // Determine device type
  let deviceType: DeviceType = 'desktop'
  const isTouch = 'ontouchstart' in window || navigator.maxTouchPoints > 0

  if (isTouch && width < 768) {
    deviceType = 'mobile'
  } else if (isTouch && width < 1024) {
    deviceType = 'tablet'
  }

  // Additional checks for device type
  if (navigator.userAgent.includes('Mobile') || navigator.userAgent.includes('Android')) {
    deviceType = 'mobile'
  } else if (navigator.userAgent.includes('Tablet') || navigator.userAgent.includes('iPad')) {
    deviceType = 'tablet'
  }

  return {
    width,
    height,
    breakpoint,
    orientation,
    deviceType,
    pixelRatio,
    isTouch,
    isMobile: deviceType === 'mobile',
    isTablet: deviceType === 'tablet',
    isDesktop: deviceType === 'desktop'
  }
}

// Hook for media queries
export const useMediaQuery = (query: string): boolean => {
  const [matches, setMatches] = useState(false)

  useEffect(() => {
    if (typeof window === 'undefined') return

    const mediaQuery = window.matchMedia(query)
    setMatches(mediaQuery.matches)

    const handleChange = (event: MediaQueryListEvent) => {
      setMatches(event.matches)
    }

    mediaQuery.addEventListener('change', handleChange)
    return () => mediaQuery.removeEventListener('change', handleChange)
  }, [query])

  return matches
}

// Hook for device orientation
export const useOrientation = () => {
  const [orientation, setOrientation] = useState<{
    angle: number
    type: OrientationType
  }>(() => {
    if (typeof window === 'undefined') {
      return { angle: 0, type: 'landscape-primary' as OrientationType }
    }

    return {
      angle: screen.orientation?.angle || 0,
      type: screen.orientation?.type || 'landscape-primary' as OrientationType
    }
  })

  useEffect(() => {
    if (typeof window === 'undefined' || !screen.orientation) return

    const handleOrientationChange = () => {
      setOrientation({
        angle: screen.orientation.angle,
        type: screen.orientation.type
      })
    }

    screen.orientation.addEventListener('change', handleOrientationChange)
    return () => screen.orientation.removeEventListener('change', handleOrientationChange)
  }, [])

  return orientation
}

// Hook for safe area insets (mobile notches, etc.)
export const useSafeArea = () => {
  const [safeAreaInsets, setSafeAreaInsets] = useState({
    top: 0,
    right: 0,
    bottom: 0,
    left: 0
  })

  useEffect(() => {
    if (typeof window === 'undefined') return

    const updateSafeArea = () => {
      const computedStyle = getComputedStyle(document.documentElement)
      setSafeAreaInsets({
        top: parseInt(computedStyle.getPropertyValue('--sat') || '0'),
        right: parseInt(computedStyle.getPropertyValue('--sar') || '0'),
        bottom: parseInt(computedStyle.getPropertyValue('--sab') || '0'),
        left: parseInt(computedStyle.getPropertyValue('--sal') || '0')
      })
    }

    updateSafeArea()

    // Listen for orientation changes that might affect safe areas
    window.addEventListener('orientationchange', updateSafeArea)
    return () => window.removeEventListener('orientationchange', updateSafeArea)
  }, [])

  return safeAreaInsets
}

export default useResponsive