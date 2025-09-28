/**
 * Advanced lazy loading utilities for CoreFlow360 V4
 * Optimized component loading with suspense and error boundaries
 */

import React, { Suspense, ComponentType, LazyExoticComponent, ReactNode } from 'react'
import { cn } from '@/lib/utils'

// Enhanced loading fallback component
export interface LoadingFallbackProps {
  className?: string
  size?: 'sm' | 'md' | 'lg'
  variant?: 'spinner' | 'skeleton' | 'minimal'
  message?: string
}

export function LoadingFallback({
  className,
  size = 'md',
  variant = 'spinner',
  message
}: LoadingFallbackProps) {
  const sizeClasses = {
    sm: 'h-8 w-8',
    md: 'h-12 w-12',
    lg: 'h-16 w-16'
  }

  if (variant === 'skeleton') {
    return (
      <div className={cn('animate-pulse space-y-4 p-4', className)}>
        <div className="h-4 bg-[var(--color-bg-component)] rounded w-3/4"></div>
        <div className="space-y-2">
          <div className="h-4 bg-[var(--color-bg-component)] rounded"></div>
          <div className="h-4 bg-[var(--color-bg-component)] rounded w-5/6"></div>
        </div>
      </div>
    )
  }

  if (variant === 'minimal') {
    return (
      <div className={cn('flex items-center justify-center p-8', className)}>
        <div className="text-[var(--color-text-tertiary)] text-sm">
          {message || 'Loading...'}
        </div>
      </div>
    )
  }

  return (
    <div className={cn('flex flex-col items-center justify-center p-8 gap-2', className)}>
      <div className={cn(
        'animate-spin rounded-full border-2 border-[var(--color-border-subtle)] border-t-[var(--brand-8)]',
        sizeClasses[size]
      )} />
      {message && (
        <div className="text-[var(--color-text-tertiary)] text-sm text-center">
          {message}
        </div>
      )}
    </div>
  )
}

// Error boundary for lazy loaded components
interface ErrorBoundaryState {
  hasError: boolean
  error?: Error
}

interface ErrorBoundaryProps {
  children: ReactNode
  fallback?: ComponentType<{ error?: Error; retry?: () => void }>
  onError?: (error: Error, errorInfo: React.ErrorInfo) => void
}

class LazyErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('Lazy loading error:', error, errorInfo)
    this.props.onError?.(error, errorInfo)
  }

  retry = () => {
    this.setState({ hasError: false, error: undefined })
  }

  render() {
    if (this.state.hasError) {
      const FallbackComponent = this.props.fallback || DefaultErrorFallback
      return <FallbackComponent error={this.state.error} retry={this.retry} />
    }

    return this.props.children
  }
}

// Default error fallback component
function DefaultErrorFallback({ error, retry }: { error?: Error; retry?: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center p-8 text-center">
      <div className="mb-4 text-[var(--error-8)]">
        <svg className="w-12 h-12 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      </div>
      <h3 className="text-lg font-medium text-[var(--color-text-primary)] mb-2">
        Failed to load component
      </h3>
      <p className="text-[var(--color-text-tertiary)] mb-4 max-w-md">
        {error?.message || 'Something went wrong while loading this part of the application.'}
      </p>
      {retry && (
        <button
          onClick={retry}
          className="px-4 py-2 bg-[var(--brand-8)] text-white rounded-[var(--radius-md)] hover:bg-[var(--brand-9)] transition-colors"
        >
          Try again
        </button>
      )}
    </div>
  )
}

// Lazy loading options
export interface LazyLoadOptions {
  fallback?: ComponentType<LoadingFallbackProps>
  errorFallback?: ComponentType<{ error?: Error; retry?: () => void }>
  preload?: boolean
  retryAttempts?: number
  retryDelay?: number
  onError?: (error: Error) => void
}

// Enhanced lazy component creator with retry and error handling
export function createLazyComponent<T = {}>(
  importFn: () => Promise<{ default: ComponentType<T> }>,
  options: LazyLoadOptions = {}
): LazyExoticComponent<ComponentType<T>> {
  const {
    retryAttempts = 3,
    retryDelay = 1000,
    preload = false,
    onError
  } = options

  // Create retry wrapper for import function
  const retryImport = async (): Promise<{ default: ComponentType<T> }> => {
    let lastError: Error

    for (let attempt = 0; attempt < retryAttempts; attempt++) {
      try {
        return await importFn()
      } catch (error) {
        lastError = error as Error
        onError?.(lastError)

        if (attempt < retryAttempts - 1) {
          await new Promise(resolve =>
            setTimeout(resolve, retryDelay * Math.pow(2, attempt))
          )
        }
      }
    }

    throw lastError!
  }

  const LazyComponent = React.lazy(retryImport)

  // Preload component if requested
  if (preload) {
    // Delay preloading to avoid blocking initial render
    setTimeout(() => {
      retryImport().catch(console.error)
    }, 100)
  }

  return LazyComponent
}

// Wrapper component for lazy loaded components
interface LazyWrapperProps {
  children: ReactNode
  fallback?: ComponentType<LoadingFallbackProps>
  errorFallback?: ComponentType<{ error?: Error; retry?: () => void }>
  loadingProps?: LoadingFallbackProps
  onError?: (error: Error, errorInfo: React.ErrorInfo) => void
}

export function LazyWrapper({
  children,
  fallback: FallbackComponent = LoadingFallback,
  errorFallback,
  loadingProps,
  onError
}: LazyWrapperProps) {
  return (
    <LazyErrorBoundary fallback={errorFallback} onError={onError}>
      <Suspense fallback={<FallbackComponent {...loadingProps} />}>
        {children}
      </Suspense>
    </LazyErrorBoundary>
  )
}

// Hook for intersection observer based lazy loading
export function useIntersectionObserver(
  elementRef: React.RefObject<Element>,
  options: IntersectionObserverInit = {}
) {
  const [isIntersecting, setIsIntersecting] = React.useState(false)
  const [hasIntersected, setHasIntersected] = React.useState(false)

  React.useEffect(() => {
    const element = elementRef.current
    if (!element) return

    const observer = new IntersectionObserver(
      ([entry]) => {
        const isIntersecting = entry.isIntersecting
        setIsIntersecting(isIntersecting)

        if (isIntersecting && !hasIntersected) {
          setHasIntersected(true)
        }
      },
      {
        threshold: 0.1,
        rootMargin: '50px',
        ...options
      }
    )

    observer.observe(element)

    return () => {
      observer.disconnect()
    }
  }, [elementRef, hasIntersected, options])

  return { isIntersecting, hasIntersected }
}

// Lazy image component with intersection observer
interface LazyImageProps extends React.ImgHTMLAttributes<HTMLImageElement> {
  src: string
  alt: string
  placeholder?: string
  blurDataURL?: string
  onLoad?: () => void
  onError?: () => void
}

export function LazyImage({
  src,
  alt,
  placeholder,
  blurDataURL,
  className,
  onLoad,
  onError,
  ...props
}: LazyImageProps) {
  const imgRef = React.useRef<HTMLImageElement>(null)
  const [isLoaded, setIsLoaded] = React.useState(false)
  const [hasError, setHasError] = React.useState(false)
  const { hasIntersected } = useIntersectionObserver(imgRef)

  const handleLoad = () => {
    setIsLoaded(true)
    onLoad?.()
  }

  const handleError = () => {
    setHasError(true)
    onError?.()
  }

  return (
    <div className={cn('relative overflow-hidden', className)}>
      {/* Placeholder/blur background */}
      {(blurDataURL || placeholder) && !isLoaded && (
        <div
          className="absolute inset-0 bg-cover bg-center filter blur-sm scale-110"
          style={{
            backgroundImage: `url(${blurDataURL || placeholder})`
          }}
        />
      )}

      {/* Main image */}
      <img
        ref={imgRef}
        src={hasIntersected ? src : undefined}
        alt={alt}
        className={cn(
          'transition-opacity duration-300',
          isLoaded ? 'opacity-100' : 'opacity-0',
          hasError && 'hidden'
        )}
        onLoad={handleLoad}
        onError={handleError}
        {...props}
      />

      {/* Error fallback */}
      {hasError && (
        <div className="absolute inset-0 flex items-center justify-center bg-[var(--color-bg-component)]">
          <div className="text-[var(--color-text-tertiary)] text-center">
            <div className="w-8 h-8 mx-auto mb-2 opacity-50">
              <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
              </svg>
            </div>
            <div className="text-xs">Failed to load</div>
          </div>
        </div>
      )}

      {/* Loading indicator */}
      {!hasIntersected && (
        <div className="absolute inset-0 flex items-center justify-center bg-[var(--color-bg-component)]">
          <div className="w-8 h-8 animate-pulse bg-[var(--color-bg-hover)] rounded"></div>
        </div>
      )}
    </div>
  )
}

// Component for lazy loading sections/features
interface LazySectionProps {
  children: ReactNode
  threshold?: number
  rootMargin?: string
  fallback?: ReactNode
  className?: string
}

export function LazySection({
  children,
  threshold = 0.1,
  rootMargin = '100px',
  fallback,
  className
}: LazySectionProps) {
  const sectionRef = React.useRef<HTMLDivElement>(null)
  const { hasIntersected } = useIntersectionObserver(sectionRef, {
    threshold,
    rootMargin
  })

  return (
    <div ref={sectionRef} className={className}>
      {hasIntersected ? children : fallback}
    </div>
  )
}

// Preloader utility for critical resources
export class ResourcePreloader {
  private static preloadedResources = new Set<string>()

  static preloadComponent(importFn: () => Promise<any>): void {
    const moduleId = importFn.toString()
    if (this.preloadedResources.has(moduleId)) return

    importFn().catch(console.error)
    this.preloadedResources.add(moduleId)
  }

  static preloadRoute(path: string): void {
    if (this.preloadedResources.has(path)) return

    const link = document.createElement('link')
    link.rel = 'prefetch'
    link.href = path
    document.head.appendChild(link)
    this.preloadedResources.add(path)
  }

  static preloadCSS(href: string): void {
    if (this.preloadedResources.has(href)) return

    const link = document.createElement('link')
    link.rel = 'preload'
    link.as = 'style'
    link.href = href
    document.head.appendChild(link)
    this.preloadedResources.add(href)
  }

  static preloadFont(href: string): void {
    if (this.preloadedResources.has(href)) return

    const link = document.createElement('link')
    link.rel = 'preload'
    link.as = 'font'
    link.type = 'font/woff2'
    link.crossOrigin = 'anonymous'
    link.href = href
    document.head.appendChild(link)
    this.preloadedResources.add(href)
  }
}

// Export commonly used lazy loaded components
export const LazyCharts = createLazyComponent(
  () => import('@/components/charts'),
  {
    fallback: LoadingFallback,
    preload: false,
    retryAttempts: 3
  }
)

export const LazyReports = createLazyComponent(
  () => import('@/components/reports'),
  {
    fallback: LoadingFallback,
    preload: false,
    retryAttempts: 3
  }
)

export const LazyIntegrations = createLazyComponent(
  () => import('@/components/integrations'),
  {
    fallback: LoadingFallback,
    preload: false,
    retryAttempts: 3
  }
)