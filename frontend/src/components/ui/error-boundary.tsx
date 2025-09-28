import * as React from 'react'
import { motion } from 'framer-motion'
import { AlertTriangle, RefreshCw, Home, Bug } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from './button'
import { Card, CardContent, CardHeader, CardTitle } from './card'

export interface ErrorBoundaryState {
  hasError: boolean
  error: Error | null
  errorInfo: React.ErrorInfo | null
  errorId: string
}

export interface ErrorBoundaryProps {
  children: React.ReactNode
  fallback?: React.ComponentType<ErrorFallbackProps>
  onError?: (error: Error, errorInfo: React.ErrorInfo) => void
  resetOnLocationChange?: boolean
  resetKeys?: Array<string | number>
  level?: 'page' | 'component' | 'critical'
}

export interface ErrorFallbackProps {
  error: Error
  errorInfo: React.ErrorInfo
  resetError: () => void
  errorId: string
  level: 'page' | 'component' | 'critical'
}

export class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  private resetTimeoutId: number | null = null

  constructor(props: ErrorBoundaryProps) {
    super(props)
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: ''
    }
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return {
      hasError: true,
      error,
      errorId: `error-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`
    }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    this.setState({
      error,
      errorInfo
    })

    // Call optional error handler
    this.props.onError?.(error, errorInfo)

    // Log error for monitoring
    console.error('ErrorBoundary caught an error:', error, errorInfo)

    // Report to error tracking service in production
    if (process.env.NODE_ENV === 'production') {
      this.reportError(error, errorInfo)
    }
  }

  componentDidUpdate(prevProps: ErrorBoundaryProps) {
    const { resetKeys } = this.props
    const { hasError } = this.state

    // Reset error state if resetKeys change
    if (hasError && resetKeys !== prevProps.resetKeys) {
      if (resetKeys && prevProps.resetKeys) {
        const hasResetKeyChanged = resetKeys.some(
          (key, index) => key !== prevProps.resetKeys![index]
        )
        if (hasResetKeyChanged) {
          this.resetError()
        }
      }
    }
  }

  private reportError = (error: Error, errorInfo: React.ErrorInfo) => {
    // Integrate with error reporting service (Sentry, LogRocket, etc.)
    try {
      // Example: Send to monitoring service
      const errorReport = {
        message: error.message,
        stack: error.stack,
        componentStack: errorInfo.componentStack,
        errorId: this.state.errorId,
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent,
        url: window.location.href,
        userId: localStorage.getItem('userId') || 'anonymous',
        level: this.props.level || 'component'
      }

      // Send error report
      fetch('/api/errors', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(errorReport)
      }).catch(() => {
        // Silently fail if error reporting fails
      })
    } catch (reportingError) {
      console.error('Failed to report error:', reportingError)
    }
  }

  private resetError = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: ''
    })
  }

  private handleRetry = () => {
    this.resetError()
  }

  private handleReload = () => {
    window.location.reload()
  }

  private handleGoHome = () => {
    window.location.href = '/'
  }

  render() {
    const { hasError, error, errorInfo, errorId } = this.state
    const { children, fallback: Fallback, level = 'component' } = this.props

    if (hasError && error) {
      if (Fallback) {
        return (
          <Fallback
            error={error}
            errorInfo={errorInfo!}
            resetError={this.resetError}
            errorId={errorId}
            level={level}
          />
        )
      }

      return <DefaultErrorFallback
        error={error}
        errorInfo={errorInfo!}
        resetError={this.resetError}
        errorId={errorId}
        level={level}
      />
    }

    return children
  }
}

// Default error fallback component
const DefaultErrorFallback: React.FC<ErrorFallbackProps> = ({
  error,
  errorInfo,
  resetError,
  errorId,
  level
}) => {
  const [showDetails, setShowDetails] = React.useState(false)

  const getErrorIcon = () => {
    switch (level) {
      case 'critical':
        return <AlertTriangle className="h-8 w-8 text-destructive" />
      case 'page':
        return <AlertTriangle className="h-6 w-6 text-destructive" />
      default:
        return <Bug className="h-5 w-5 text-destructive" />
    }
  }

  const getErrorTitle = () => {
    switch (level) {
      case 'critical':
        return 'Application Error'
      case 'page':
        return 'Page Error'
      default:
        return 'Component Error'
    }
  }

  const getErrorDescription = () => {
    switch (level) {
      case 'critical':
        return 'A critical error occurred that prevents the application from running properly.'
      case 'page':
        return 'An error occurred while loading this page.'
      default:
        return 'A component failed to render properly.'
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className={cn(
        "flex items-center justify-center p-4",
        level === 'critical' && "min-h-screen",
        level === 'page' && "min-h-[400px]"
      )}
    >
      <Card className={cn(
        "w-full max-w-md",
        level === 'component' && "border-destructive/20"
      )}>
        <CardHeader className="text-center">
          <div className="mx-auto mb-4">
            {getErrorIcon()}
          </div>
          <CardTitle className="text-destructive">
            {getErrorTitle()}
          </CardTitle>
          <p className="text-muted-foreground text-sm">
            {getErrorDescription()}
          </p>
        </CardHeader>

        <CardContent className="space-y-4">
          {/* Error message */}
          <div className="text-center">
            <p className="text-sm text-muted-foreground mb-2">
              Error ID: <code className="bg-muted px-1 rounded text-xs">{errorId}</code>
            </p>
            {error.message && (
              <p className="text-sm font-mono bg-muted p-2 rounded border-l-2 border-destructive">
                {error.message}
              </p>
            )}
          </div>

          {/* Action buttons */}
          <div className="flex flex-col gap-2">
            <Button onClick={resetError} className="w-full">
              <RefreshCw className="h-4 w-4 mr-2" />
              Try Again
            </Button>

            {level === 'page' && (
              <Button variant="outline" onClick={() => window.location.reload()} className="w-full">
                <RefreshCw className="h-4 w-4 mr-2" />
                Reload Page
              </Button>
            )}

            {level === 'critical' && (
              <Button variant="outline" onClick={() => window.location.href = '/'} className="w-full">
                <Home className="h-4 w-4 mr-2" />
                Go Home
              </Button>
            )}

            {/* Show details toggle */}
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setShowDetails(!showDetails)}
              className="w-full text-xs"
            >
              {showDetails ? 'Hide' : 'Show'} Technical Details
            </Button>
          </div>

          {/* Error details */}
          {showDetails && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="mt-4 p-3 bg-muted rounded border text-xs font-mono overflow-auto max-h-48"
            >
              <div className="mb-2">
                <strong>Error Stack:</strong>
                <pre className="mt-1 whitespace-pre-wrap">{error.stack}</pre>
              </div>
              {errorInfo?.componentStack && (
                <div>
                  <strong>Component Stack:</strong>
                  <pre className="mt-1 whitespace-pre-wrap">{errorInfo.componentStack}</pre>
                </div>
              )}
            </motion.div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  )
}

// HOC for wrapping components with error boundary
export function withErrorBoundary<P extends object>(
  Component: React.ComponentType<P>,
  errorBoundaryProps?: Partial<ErrorBoundaryProps>
) {
  const WrappedComponent = (props: P) => (
    <ErrorBoundary {...errorBoundaryProps}>
      <Component {...props} />
    </ErrorBoundary>
  )

  WrappedComponent.displayName = `withErrorBoundary(${Component.displayName || Component.name})`

  return WrappedComponent
}

// Hook for error boundary context
export function useErrorHandler() {
  return (error: Error, errorInfo?: React.ErrorInfo) => {
    // This can be enhanced to integrate with error boundary
    console.error('Error caught by useErrorHandler:', error, errorInfo)

    // Throw error to be caught by nearest error boundary
    throw error
  }
}

// Async error boundary for handling async errors
export const AsyncErrorBoundary: React.FC<{
  children: React.ReactNode
  fallback?: React.ComponentType<ErrorFallbackProps>
}> = ({ children, fallback }) => {
  const [asyncError, setAsyncError] = React.useState<Error | null>(null)

  React.useEffect(() => {
    const handleUnhandledRejection = (event: PromiseRejectionEvent) => {
      setAsyncError(new Error(event.reason))
    }

    window.addEventListener('unhandledrejection', handleUnhandledRejection)

    return () => {
      window.removeEventListener('unhandledrejection', handleUnhandledRejection)
    }
  }, [])

  if (asyncError) {
    throw asyncError
  }

  return (
    <ErrorBoundary fallback={fallback} level="component">
      {children}
    </ErrorBoundary>
  )
}

export { DefaultErrorFallback }