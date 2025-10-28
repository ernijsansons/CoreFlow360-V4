import { AppRouter } from './router'
import { Toaster } from 'sonner'
import { ErrorBoundary } from '@/components/error-boundary'

export default function App() {
  return (
    <ErrorBoundary>
      <AppRouter />
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
