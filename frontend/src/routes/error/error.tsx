import * as React from 'react'
import { createFileRoute, Link, useRouter } from '@tanstack/react-router'
import { AlertTriangle, RefreshCw, Home, Copy, CheckCircle2, FileText } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@/components/ui/alert'
import { cn } from '@/lib/utils'

interface ErrorPageProps {
  error?: Error | string
  statusCode?: number
  reset?: () => void
}

export const Route = createFileRoute('/error/error')({
  component: ErrorPage,
})

function ErrorPage({ error, statusCode = 500, reset }: ErrorPageProps) {
  const router = useRouter()
  const [copied, setCopied] = React.useState(false)
  const [reportSent, setReportSent] = React.useState(false)
  const [isReporting, setIsReporting] = React.useState(false)

  // Generate error ID for tracking
  const errorId = React.useMemo(() => {
    return `ERR-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`
  }, [])

  const errorMessage = error instanceof Error ? error.message : error || 'An unexpected error occurred'
  const errorStack = error instanceof Error ? error.stack : undefined

  const handleCopyError = async () => {
    const errorDetails = `
Error ID: ${errorId}
Status Code: ${statusCode}
Timestamp: ${new Date().toISOString()}
Message: ${errorMessage}
${errorStack ? `Stack: ${errorStack}` : ''}
URL: ${window.location.href}
User Agent: ${navigator.userAgent}
    `.trim()

    try {
      await navigator.clipboard.writeText(errorDetails)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      console.error('Failed to copy error details:', err)
    }
  }

  const handleReportError = async () => {
    setIsReporting(true)
    try {
      // Mock API call to report error
      await new Promise(resolve => setTimeout(resolve, 1500))
      setReportSent(true)
    } catch (err) {
      console.error('Failed to report error:', err)
    } finally {
      setIsReporting(false)
    }
  }

  const handleRetry = () => {
    if (reset) {
      reset()
    } else {
      window.location.reload()
    }
  }

  const getStatusMessage = () => {
    switch (statusCode) {
      case 400:
        return { title: 'Bad Request', description: 'The request could not be understood by the server.' }
      case 401:
        return { title: 'Unauthorized', description: 'You need to be authenticated to access this resource.' }
      case 403:
        return { title: 'Forbidden', description: 'You don\'t have permission to access this resource.' }
      case 404:
        return { title: 'Not Found', description: 'The requested resource could not be found.' }
      case 429:
        return { title: 'Too Many Requests', description: 'You\'ve made too many requests. Please try again later.' }
      case 500:
        return { title: 'Internal Server Error', description: 'Something went wrong on our end. We\'re working to fix it.' }
      case 502:
        return { title: 'Bad Gateway', description: 'We\'re having trouble connecting to our servers.' }
      case 503:
        return { title: 'Service Unavailable', description: 'Our service is temporarily unavailable. Please try again later.' }
      default:
        return { title: 'Something went wrong', description: 'An unexpected error occurred. Please try again.' }
    }
  }

  const { title, description } = getStatusMessage()

  return (
    <div className="min-h-screen flex items-center justify-center px-8 py-16 bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-950">
      <div className="max-w-2xl w-full space-y-8">
        {/* Error Header */}
        <div className="text-center space-y-4">
          <div className="inline-flex">
            <div className={cn(
              "h-20 w-20 rounded-full flex items-center justify-center",
              statusCode >= 500 ? "bg-red-100 dark:bg-red-900/20" : "bg-yellow-100 dark:bg-yellow-900/20"
            )}>
              <AlertTriangle className={cn(
                "h-10 w-10",
                statusCode >= 500 ? "text-red-600 dark:text-red-400" : "text-yellow-600 dark:text-yellow-400"
              )} />
            </div>
          </div>

          <div>
            <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-2">
              {statusCode} - {title}
            </h1>
            <p className="text-lg text-gray-600 dark:text-gray-400">
              {description}
            </p>
          </div>
        </div>

        {/* Error Details Alert */}
        <Alert variant={statusCode >= 500 ? "destructive" : "default"}>
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Error Details</AlertTitle>
          <AlertDescription className="space-y-2">
            <p className="break-words">{errorMessage}</p>
            <p className="text-xs text-muted-foreground">
              Error ID: <code className="font-mono">{errorId}</code>
            </p>
          </AlertDescription>
        </Alert>

        {/* Action Buttons */}
        <div className="flex flex-col sm:flex-row gap-3 justify-center">
          <Button onClick={handleRetry} size="lg" className="gap-2">
            <RefreshCw className="h-4 w-4" />
            Try again
          </Button>
          <Button variant="outline" size="lg" asChild>
            <Link to="/">
              <Home className="h-4 w-4 mr-2" />
              Go to dashboard
            </Link>
          </Button>
        </div>

        {/* Report Section */}
        {!reportSent ? (
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 space-y-4">
            <h2 className="font-semibold text-gray-900 dark:text-white">
              Help us improve
            </h2>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              This error has been logged automatically. You can help us fix it faster by reporting additional details.
            </p>
            <div className="flex gap-3">
              <Button
                variant="secondary"
                size="sm"
                onClick={handleCopyError}
                disabled={copied}
                className="gap-2"
              >
                {copied ? (
                  <>
                    <CheckCircle2 className="h-4 w-4" />
                    Copied!
                  </>
                ) : (
                  <>
                    <Copy className="h-4 w-4" />
                    Copy error details
                  </>
                )}
              </Button>
              <Button
                variant="secondary"
                size="sm"
                onClick={handleReportError}
                disabled={isReporting}
                className="gap-2"
              >
                {isReporting ? (
                  <>
                    <RefreshCw className="h-4 w-4 animate-spin" />
                    Reporting...
                  </>
                ) : (
                  <>
                    <FileText className="h-4 w-4" />
                    Report this error
                  </>
                )}
              </Button>
            </div>
          </div>
        ) : (
          <Alert className="bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800">
            <CheckCircle2 className="h-4 w-4 text-green-600 dark:text-green-400" />
            <AlertTitle className="text-green-900 dark:text-green-100">
              Thank you for your report
            </AlertTitle>
            <AlertDescription className="text-green-700 dark:text-green-300">
              We've received your error report and our team will investigate it shortly.
            </AlertDescription>
          </Alert>
        )}

        {/* Developer Details (only in development) */}
        {import.meta.env.DEV && errorStack && (
          <details className="bg-gray-900 text-gray-100 rounded-lg p-4">
            <summary className="cursor-pointer font-medium mb-2">
              Stack Trace (Development Only)
            </summary>
            <pre className="text-xs overflow-auto whitespace-pre-wrap break-words">
              {errorStack}
            </pre>
          </details>
        )}

        {/* Support Link */}
        <div className="text-center text-sm text-gray-600 dark:text-gray-400">
          <p>
            If this problem persists, please{' '}
            <Link
              to="/help/contact"
              className="font-medium text-brand-600 hover:underline"
            >
              contact support
            </Link>{' '}
            with error ID: <code className="font-mono text-xs">{errorId}</code>
          </p>
        </div>
      </div>
    </div>
  )
}

export { ErrorPage }