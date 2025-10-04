import { RouterProvider } from '@tanstack/react-router'
import { router } from './router'
import { Toaster } from 'sonner'
import { ErrorBoundary } from '@/components/error-boundary'

export default function App() {
  return (
    <ErrorBoundary>
      <RouterProvider router={router} />
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
