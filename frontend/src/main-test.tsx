import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './styles/globals.css'
import { validateCSSVariables, logCSSValidation } from '@/lib/css-validation'
import { validateEnvironment } from '@/lib/env-validation'
import { useAuthStore, useUIStore, useEntityStore, useCacheStore, useSyncStore } from '@/stores'
import { router } from './router'

console.log('[TEST-ROUTER] Starting TanStack Router test')

// Test CSS validation
try {
  const cssResult = validateCSSVariables()
  logCSSValidation(cssResult)
  console.log('[TEST-ROUTER] CSS validation result:', cssResult)
} catch (error) {
  console.error('[TEST-ROUTER] CSS validation threw error:', error)
}

// Test environment validation
try {
  const envResult = validateEnvironment()
  console.log('[TEST-ROUTER] Environment validation result:', envResult)
} catch (error) {
  console.error('[TEST-ROUTER] Environment validation threw error:', error)
}

// Test Zustand stores
try {
  const authStore = useAuthStore.getState()
  const uiStore = useUIStore.getState()
  const entityStore = useEntityStore.getState()
  const cacheStore = useCacheStore.getState()
  const syncStore = useSyncStore.getState()
  console.log('[TEST-ROUTER] ✅ All stores loaded successfully!')
} catch (error) {
  console.error('[TEST-ROUTER] ❌ Store initialization threw error:', error)
}

// Test TanStack Router
try {
  console.log('[TEST-ROUTER] Testing router import...')
  console.log('[TEST-ROUTER] Router object:', router)
  console.log('[TEST-ROUTER] Router state:', router.state)
  console.log('[TEST-ROUTER] ✅ Router loaded successfully!')
} catch (error) {
  console.error('[TEST-ROUTER] ❌ Router threw error:', error)
}

const rootElement = document.getElementById('root')

if (!rootElement) {
  console.error('[TEST] No root element found')
  document.body.innerHTML = '<h1 style="color: red; padding: 40px;">ERROR: No root element</h1>'
} else {
  console.log('[TEST] Root element found, mounting React')

  try {
    const root = createRoot(rootElement)
    root.render(
      <StrictMode>
        <div style={{
          padding: '40px',
          fontFamily: 'Arial, sans-serif',
          maxWidth: '800px',
          margin: '0 auto'
        }}>
          <h1 style={{ color: '#2563eb', marginBottom: '20px' }}>
            ✅ ROUTER TEST SUCCESSFUL
          </h1>
          <p style={{ fontSize: '18px', marginBottom: '10px' }}>
            React + CSS + Env + Stores + Router working!
          </p>
          <p style={{ color: '#6b7280' }}>
            If you see this, the issue is with one of the imports in the main App.
          </p>
          <div style={{
            marginTop: '30px',
            padding: '20px',
            background: '#f3f4f6',
            borderRadius: '8px'
          }}>
            <h2 style={{ marginBottom: '10px' }}>Test Details:</h2>
            <ul style={{ lineHeight: '1.8' }}>
              <li>✅ React 19 loaded</li>
              <li>✅ ReactDOM.createRoot() working</li>
              <li>✅ CSS imports working</li>
              <li>✅ TypeScript compilation successful</li>
            </ul>
          </div>
        </div>
      </StrictMode>
    )

    console.log('[TEST] React mounted successfully')

    // Hide loading screen
    const loadingScreen = document.getElementById('loading-screen')
    if (loadingScreen) {
      loadingScreen.style.display = 'none'
      console.log('[TEST] Loading screen hidden')
    }
  } catch (error) {
    console.error('[TEST] Error mounting React:', error)
    rootElement.innerHTML = `
      <div style="padding: 40px; font-family: Arial;">
        <h1 style="color: red;">Error mounting React</h1>
        <pre style="background: #f3f4f6; padding: 20px; border-radius: 8px; overflow: auto;">
          ${error instanceof Error ? error.stack : String(error)}
        </pre>
      </div>
    `
  }
}
