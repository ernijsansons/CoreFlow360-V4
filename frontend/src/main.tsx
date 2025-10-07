import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import './styles/globals.css'

console.log('[CoreFlow360] main.tsx: Starting application initialization')
console.log('[CoreFlow360] Environment:', import.meta.env.MODE)
console.log('[CoreFlow360] API URL:', import.meta.env.VITE_API_URL)

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