import * as React from 'react'
import { cn } from '@/lib/utils'

export interface ResponsiveGridProps {
  children: React.ReactNode
  className?: string
  cols?: {
    xs?: number
    sm?: number
    md?: number
    lg?: number
    xl?: number
    '2xl'?: number
  }
  gap?: string | number
  rowGap?: string | number
  colGap?: string | number
}

export function ResponsiveGrid({
  children,
  className,
  cols = { xs: 1, sm: 2, md: 3, lg: 4, xl: 5, '2xl': 6 },
  gap,
  rowGap,
  colGap
}: ResponsiveGridProps) {
  const gridClasses = React.useMemo(() => {
    const classes = []

    // Base grid class
    classes.push('grid')

    // Responsive column classes
    if (cols.xs) classes.push(`grid-cols-${cols.xs}`)
    if (cols.sm) classes.push(`sm:grid-cols-${cols.sm}`)
    if (cols.md) classes.push(`md:grid-cols-${cols.md}`)
    if (cols.lg) classes.push(`lg:grid-cols-${cols.lg}`)
    if (cols.xl) classes.push(`xl:grid-cols-${cols.xl}`)
    if (cols['2xl']) classes.push(`2xl:grid-cols-${cols['2xl']}`)

    // Gap classes
    if (gap) classes.push(typeof gap === 'number' ? `gap-${gap}` : gap)
    if (rowGap) classes.push(typeof rowGap === 'number' ? `gap-y-${rowGap}` : rowGap)
    if (colGap) classes.push(typeof colGap === 'number' ? `gap-x-${colGap}` : colGap)

    return classes.join(' ')
  }, [cols, gap, rowGap, colGap])

  return (
    <div className={cn(gridClasses, className)}>
      {children}
    </div>
  )
}

export interface ResponsiveStackProps {
  children: React.ReactNode
  className?: string
  direction?: {
    xs?: 'row' | 'col'
    sm?: 'row' | 'col'
    md?: 'row' | 'col'
    lg?: 'row' | 'col'
    xl?: 'row' | 'col'
  }
  gap?: string | number
  align?: 'start' | 'center' | 'end' | 'stretch'
  justify?: 'start' | 'center' | 'end' | 'between' | 'around' | 'evenly'
}

export function ResponsiveStack({
  children,
  className,
  direction = { xs: 'col', md: 'row' },
  gap = 4,
  align = 'start',
  justify = 'start'
}: ResponsiveStackProps) {
  const stackClasses = React.useMemo(() => {
    const classes = ['flex']

    // Direction classes
    if (direction.xs) classes.push(`flex-${direction.xs}`)
    if (direction.sm) classes.push(`sm:flex-${direction.sm}`)
    if (direction.md) classes.push(`md:flex-${direction.md}`)
    if (direction.lg) classes.push(`lg:flex-${direction.lg}`)
    if (direction.xl) classes.push(`xl:flex-${direction.xl}`)

    // Gap
    if (gap) classes.push(typeof gap === 'number' ? `gap-${gap}` : gap)

    // Alignment
    const alignMap = {
      start: 'items-start',
      center: 'items-center',
      end: 'items-end',
      stretch: 'items-stretch'
    }
    classes.push(alignMap[align])

    // Justification
    const justifyMap = {
      start: 'justify-start',
      center: 'justify-center',
      end: 'justify-end',
      between: 'justify-between',
      around: 'justify-around',
      evenly: 'justify-evenly'
    }
    classes.push(justifyMap[justify])

    return classes.join(' ')
  }, [direction, gap, align, justify])

  return (
    <div className={cn(stackClasses, className)}>
      {children}
    </div>
  )
}

export interface ResponsiveContainerProps {
  children: React.ReactNode
  className?: string
  maxWidth?: 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl' | 'full'
  padding?: {
    xs?: string | number
    sm?: string | number
    md?: string | number
    lg?: string | number
    xl?: string | number
  }
  centerContent?: boolean
}

export function ResponsiveContainer({
  children,
  className,
  maxWidth = 'xl',
  padding = { xs: 4, sm: 6, md: 8, lg: 12 },
  centerContent = true
}: ResponsiveContainerProps) {
  const containerClasses = React.useMemo(() => {
    const classes = ['w-full']

    // Max width
    if (maxWidth !== 'full') {
      classes.push(`max-w-${maxWidth}`)
    }

    // Center content
    if (centerContent) {
      classes.push('mx-auto')
    }

    // Responsive padding
    if (padding.xs) classes.push(typeof padding.xs === 'number' ? `px-${padding.xs}` : padding.xs)
    if (padding.sm) classes.push(typeof padding.sm === 'number' ? `sm:px-${padding.sm}` : `sm:${padding.sm}`)
    if (padding.md) classes.push(typeof padding.md === 'number' ? `md:px-${padding.md}` : `md:${padding.md}`)
    if (padding.lg) classes.push(typeof padding.lg === 'number' ? `lg:px-${padding.lg}` : `lg:${padding.lg}`)
    if (padding.xl) classes.push(typeof padding.xl === 'number' ? `xl:px-${padding.xl}` : `xl:${padding.xl}`)

    return classes.join(' ')
  }, [maxWidth, padding, centerContent])

  return (
    <div className={cn(containerClasses, className)}>
      {children}
    </div>
  )
}

export interface ResponsiveColumnsProps {
  children: React.ReactNode
  className?: string
  columns?: {
    xs?: number
    sm?: number
    md?: number
    lg?: number
    xl?: number
  }
  gap?: string | number
}

export function ResponsiveColumns({
  children,
  className,
  columns = { xs: 1, md: 2, lg: 3 },
  gap = 6
}: ResponsiveColumnsProps) {
  const columnClasses = React.useMemo(() => {
    const classes = []

    // Column classes
    if (columns.xs) classes.push(`columns-${columns.xs}`)
    if (columns.sm) classes.push(`sm:columns-${columns.sm}`)
    if (columns.md) classes.push(`md:columns-${columns.md}`)
    if (columns.lg) classes.push(`lg:columns-${columns.lg}`)
    if (columns.xl) classes.push(`xl:columns-${columns.xl}`)

    // Gap
    if (gap) classes.push(typeof gap === 'number' ? `gap-${gap}` : gap)

    return classes.join(' ')
  }, [columns, gap])

  return (
    <div className={cn(columnClasses, className)}>
      {children}
    </div>
  )
}

export interface MobileDrawerProps {
  children: React.ReactNode
  isOpen: boolean
  onClose: () => void
  title?: string
  position?: 'bottom' | 'top' | 'left' | 'right'
  className?: string
  showOnDesktop?: boolean
}

export function MobileDrawer({
  children,
  isOpen,
  onClose,
  title,
  position = 'bottom',
  className,
  showOnDesktop = false
}: MobileDrawerProps) {
  React.useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = 'unset'
    }

    return () => {
      document.body.style.overflow = 'unset'
    }
  }, [isOpen])

  if (!isOpen) return null

  const positionClasses = {
    bottom: 'inset-x-0 bottom-0 rounded-t-[var(--radius-2xl)]',
    top: 'inset-x-0 top-0 rounded-b-[var(--radius-2xl)]',
    left: 'inset-y-0 left-0 rounded-r-[var(--radius-2xl)]',
    right: 'inset-y-0 right-0 rounded-l-[var(--radius-2xl)]'
  }

  const slideClasses = {
    bottom: 'animate-in slide-in-from-bottom duration-300',
    top: 'animate-in slide-in-from-top duration-300',
    left: 'animate-in slide-in-from-left duration-300',
    right: 'animate-in slide-in-from-right duration-300'
  }

  return (
    <div
      className={cn(
        'fixed inset-0 z-[var(--z-index-modal)] md:hidden',
        !showOnDesktop && 'md:hidden'
      )}
    >
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm animate-in fade-in-0 duration-200"
        onClick={onClose}
      />

      {/* Drawer */}
      <div
        className={cn(
          'absolute bg-[var(--color-bg-surface)] border-[var(--color-border-subtle)] shadow-[var(--shadow-2xl)]',
          'max-h-[90vh] overflow-y-auto',
          positionClasses[position],
          slideClasses[position],
          className
        )}
      >
        {title && (
          <div className="flex items-center justify-between p-4 border-b border-[var(--color-border-subtle)]">
            <h3 className="text-[var(--font-size-lg)] font-semibold text-[var(--color-text-primary)]">
              {title}
            </h3>
            <button
              onClick={onClose}
              className="p-2 rounded-[var(--radius-md)] hover:bg-[var(--color-bg-hover)] transition-colors"
            >
              <span className="sr-only">Close</span>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        )}

        <div className="p-4">
          {children}
        </div>
      </div>
    </div>
  )
}

// Hook for responsive breakpoints
export function useResponsive() {
  const [breakpoint, setBreakpoint] = React.useState<'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl'>('xs')

  React.useEffect(() => {
    const updateBreakpoint = () => {
      const width = window.innerWidth
      if (width >= 1536) setBreakpoint('2xl')
      else if (width >= 1280) setBreakpoint('xl')
      else if (width >= 1024) setBreakpoint('lg')
      else if (width >= 768) setBreakpoint('md')
      else if (width >= 480) setBreakpoint('sm')
      else setBreakpoint('xs')
    }

    updateBreakpoint()
    window.addEventListener('resize', updateBreakpoint)

    return () => window.removeEventListener('resize', updateBreakpoint)
  }, [])

  return {
    breakpoint,
    isXs: breakpoint === 'xs',
    isSm: breakpoint === 'sm',
    isMd: breakpoint === 'md',
    isLg: breakpoint === 'lg',
    isXl: breakpoint === 'xl',
    is2xl: breakpoint === '2xl',
    isMobile: ['xs', 'sm'].includes(breakpoint),
    isTablet: breakpoint === 'md',
    isDesktop: ['lg', 'xl', '2xl'].includes(breakpoint)
  }
}