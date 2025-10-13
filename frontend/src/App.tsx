import { Suspense, useEffect } from 'react'
import { RouterProvider } from '@tanstack/react-router'
import { router } from './router'
import { Toaster } from 'sonner'
import { ErrorBoundary } from '@/components/error-boundary'
import { ToastListener } from '@/components/toast-listener'
import { QueryProvider } from '@/providers/query-provider'

function LoadingFallback() {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
        minHeight: '100vh',
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        color: 'white',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
      }}
    >
      <div style={{ fontSize: '24px', fontWeight: 600, marginBottom: '10px' }}>
        Loading CoreFlow360...
      </div>
      <div style={{ fontSize: '14px', opacity: 0.8 }}>
        Preparing your AI-First Platform
      </div>
    </div>
  )
}

export default function App() {
  useEffect(() => {
    console.log('[CoreFlow360] App component mounted')

    // Hide loading screen when React is ready
    const loadingScreen = document.getElementById('loading-screen')
    if (loadingScreen) {
      console.log('[CoreFlow360] Removing loading screen')
      loadingScreen.style.display = 'none'
    }

    return () => {
      console.log('[CoreFlow360] App component unmounting')
    }
  }, [])

  return (
    <ErrorBoundary>
      <QueryProvider>
        <Suspense fallback={<LoadingFallback />}>
          <RouterProvider router={router} />
        </Suspense>
      </QueryProvider>
      <ToastListener />
      <Toaster
        position="top-right"
        richColors
        closeButton
        duration={4000}
        aria-label="Notifications"
      />
    </ErrorBoundary>
  )
}
