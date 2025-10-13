/* eslint-disable react-refresh/only-export-components */
import React, { Component, ReactNode } from 'react'
import { AlertTriangle, RefreshCw, Home, Palette } from 'lucide-react'
import { Button } from '@/components/ui'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui'
import { validateCSSVariables, logCSSValidation } from '@/lib/css-validation'

interface Props {
  children: ReactNode
  fallback?: ReactNode
  onReset?: () => void
}

interface State {
  hasError: boolean
  error: Error | null
  errorInfo: React.ErrorInfo | null
  cssValidationResult: ReturnType<typeof validateCSSVariables> | null
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, error: null, errorInfo: null, cssValidationResult: null }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null, cssValidationResult: null }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('ErrorBoundary caught an error:', error, errorInfo)

    // Validate CSS variables to check if this might be a CSS-related error
    const cssValidationResult = validateCSSVariables()
    logCSSValidation(cssValidationResult)

    if (typeof window !== 'undefined' && window.Sentry) {
      window.Sentry.captureException(error, {
        contexts: { 
          react: { componentStack: errorInfo.componentStack },
          css: { validationResult: cssValidationResult }
        }
      })
    }

    this.setState({
      error,
      errorInfo,
      cssValidationResult
    })
  }

  handleReset = () => {
    const { onReset } = this.props

    this.setState({ hasError: false, error: null, errorInfo: null, cssValidationResult: null })

    if (onReset) {
      onReset()
    } else {
      window.location.reload()
    }
  }

  handleGoHome = () => {
    window.location.href = '/'
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback
      }

      const isDevelopment = import.meta.env.DEV
      const { error, errorInfo, cssValidationResult } = this.state

      // Check if this might be a CSS-related error
      const isCSSError = cssValidationResult && !cssValidationResult.valid

      return (
        <div className="min-h-screen flex items-center justify-center p-4">
          <div className="max-w-2xl w-full space-y-4">
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertTitle>
                {isCSSError ? 'Design System Error' : 'Something went wrong'}
              </AlertTitle>
              <AlertDescription>
                {isCSSError ? (
                  <>
                    The application failed to load because critical design tokens are missing. 
                    This usually indicates a build configuration issue.
                  </>
                ) : (
                  <>
                    An unexpected error occurred. The error has been logged and our team has been notified.
                  </>
                )}
              </AlertDescription>
            </Alert>

            {isCSSError && cssValidationResult && (
              <Alert>
                <Palette className="h-4 w-4" />
                <AlertTitle>CSS Design Tokens Issue</AlertTitle>
                <AlertDescription>
                  <div className="space-y-2">
                    <p>Missing critical CSS variables:</p>
                    <ul className="list-disc list-inside text-sm space-y-1">
                      {cssValidationResult.missing.slice(0, 5).map(variable => (
                        <li key={variable} className="font-mono">{variable}</li>
                      ))}
                      {cssValidationResult.missing.length > 5 && (
                        <li className="text-muted-foreground">
                          ... and {cssValidationResult.missing.length - 5} more
                        </li>
                      )}
                    </ul>
                    <div className="mt-3 p-3 bg-muted rounded-md">
                      <p className="text-sm font-medium mb-2">Troubleshooting steps:</p>
                      <ol className="text-sm space-y-1 list-decimal list-inside">
                        <li>Check browser console for detailed error messages</li>
                        <li>Verify design-tokens.css is loaded in Network tab</li>
                        <li>Try refreshing the page</li>
                        <li>Contact support if the issue persists</li>
                      </ol>
                    </div>
                  </div>
                </AlertDescription>
              </Alert>
            )}

            {isDevelopment && error && (
              <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4">
                <h3 className="font-semibold text-sm mb-2">Error Details (Development Only)</h3>
                <pre className="text-xs overflow-auto">
                  <code>{error.toString()}</code>
                </pre>
                {errorInfo && (
                  <details className="mt-4">
                    <summary className="cursor-pointer text-sm font-medium">Component Stack</summary>
                    <pre className="text-xs overflow-auto mt-2">
                      <code>{errorInfo.componentStack}</code>
                    </pre>
                  </details>
                )}
                {cssValidationResult && (
                  <details className="mt-4">
                    <summary className="cursor-pointer text-sm font-medium">CSS Validation Result</summary>
                    <pre className="text-xs overflow-auto mt-2">
                      <code>{JSON.stringify(cssValidationResult, null, 2)}</code>
                    </pre>
                  </details>
                )}
              </div>
            )}

            <div className="flex gap-2">
              <Button onClick={this.handleReset} variant="default">
                <RefreshCw className="mr-2 h-4 w-4" />
                Try Again
              </Button>
              <Button onClick={this.handleGoHome} variant="outline">
                <Home className="mr-2 h-4 w-4" />
                Go Home
              </Button>
            </div>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}

interface AsyncErrorBoundaryProps {
  children: ReactNode
  fallback?: (error: Error, retry: () => void) => ReactNode
}

export function AsyncErrorBoundary({ children, fallback }: AsyncErrorBoundaryProps) {
  const [error, setError] = React.useState<Error | null>(null)

  React.useEffect(() => {
    const handleError = (event: ErrorEvent) => {
      setError(new Error(event.message))
    }

    const handleRejection = (event: PromiseRejectionEvent) => {
      setError(new Error(event.reason))
    }

    window.addEventListener('error', handleError)
    window.addEventListener('unhandledrejection', handleRejection)

    return () => {
      window.removeEventListener('error', handleError)
      window.removeEventListener('unhandledrejection', handleRejection)
    }
  }, [])

  const retry = () => {
    setError(null)
  }

  if (error) {
    if (fallback) {
      return <>{fallback(error, retry)}</>
    }

    return (
      <div className="p-4 rounded-lg border border-destructive/50 bg-destructive/10">
        <h3 className="font-semibold text-sm mb-2">Async Error</h3>
        <p className="text-sm text-muted-foreground mb-4">{error.message}</p>
        <Button onClick={retry} size="sm" variant="outline">
          Retry
        </Button>
      </div>
    )
  }

  return <>{children}</>
}

export function withErrorBoundary<P extends object>(
  Component: React.ComponentType<P>,
  fallback?: ReactNode
): React.ComponentType<P> {
  const WrappedComponent = (props: P) => (
    <ErrorBoundary fallback={fallback}>
      <Component {...props} />
    </ErrorBoundary>
  )

  WrappedComponent.displayName = `withErrorBoundary(${Component.displayName || Component.name})`

  return WrappedComponent
}