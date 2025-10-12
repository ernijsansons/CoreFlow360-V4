import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import './styles/globals.css'
import { validateEnvironment } from './lib/env-validation'

console.log('[CoreFlow360] main.tsx: Starting application initialization')

// Validate environment variables before initialization
try {
  validateEnvironment()
} catch (error) {
  console.error('[CoreFlow360] Environment validation failed:', error)
  const rootElement = document.getElementById('root')
  if (rootElement) {
    rootElement.innerHTML = `
      <div style="padding: 40px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto;">
        <h1 style="color: #dc2626; margin-bottom: 16px;">⚠️ Configuration Error</h1>
        <p style="color: #374151; margin-bottom: 24px;">The application cannot start due to missing environment variables.</p>
        <div style="background: #fef2f2; border-left: 4px solid #dc2626; padding: 16px; margin-bottom: 24px; border-radius: 4px;">
          <pre style="margin: 0; font-size: 14px; overflow-x: auto;">${error instanceof Error ? error.message : String(error)}</pre>
        </div>
        <p style="color: #6b7280; font-size: 14px;">
          Please contact your system administrator or check the deployment configuration.
        </p>
      </div>
    `
  }
  throw error // Prevent app from loading
}

const rootElement = document.getElementById('root')

if (!rootElement) {
  console.error('[CoreFlow360] CRITICAL: Root element not found!')
  document.body.innerHTML = '<div style="padding: 20px; font-family: Arial;"><h1 style="color: red;">Error: Root element not found</h1><p>Please check console for details</p></div>'
} else {
  console.log('[CoreFlow360] Root element found:', rootElement)

  if (!rootElement.innerHTML) {
    console.log('[CoreFlow360] Mounting React application...')
    try {
      const root = createRoot(rootElement)
      root.render(
        <StrictMode>
          <App />
        </StrictMode>,
      )
      console.log('[CoreFlow360] React application mounted successfully')
    } catch (error) {
      console.error('[CoreFlow360] Error mounting React app:', error)
      rootElement.innerHTML = '<div style="padding: 20px; font-family: Arial;"><h1 style="color: red;">Error mounting application</h1><p>Check console for details</p><pre>' + String(error) + '</pre></div>'
    }
  } else {
    console.warn('[CoreFlow360] Root element already has content, skipping mount')
  }
}