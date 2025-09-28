import React from 'react'
import { QueryProvider } from './query-provider'
import { ToastProvider } from '@/hooks/use-toast'
import { ToastContainer } from '@/components/ui/toast-container'
import { ErrorBoundary } from '@/components/error-boundary'
import { SSEProvider } from './sse-provider'
import { AuthProvider } from './auth-provider'
import { ThemeProvider } from './theme-provider'

interface AppProvidersProps {
  children: React.ReactNode
}

/**
 * AppProviders wraps the entire application with all necessary context providers
 * The order matters - more fundamental providers should wrap others
 */
export function AppProviders({ children }: AppProvidersProps) {
  return (
    <ErrorBoundary>
      <ThemeProvider>
        <AuthProvider>
          <QueryProvider>
            <SSEProvider>
              <ToastProvider>
                {children}
                <ToastContainer />
              </ToastProvider>
            </SSEProvider>
          </QueryProvider>
        </AuthProvider>
      </ThemeProvider>
    </ErrorBoundary>
  )
}

// Export individual providers for testing
export { QueryProvider } from './query-provider'
export { ToastProvider } from '@/hooks/use-toast'
export { SSEProvider } from './sse-provider'
export { AuthProvider } from './auth-provider'
export { ThemeProvider } from './theme-provider'