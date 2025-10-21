// ============================================================================
// CRITICAL: Import and validate React FIRST
// ============================================================================
import * as React from 'react'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

// Validate React module loaded correctly
console.log('[CoreFlow360] React validation:', {
  React: !!React,
  useEffect: typeof React.useEffect,
  keys: React ? Object.keys(React).slice(0, 10) : []
});

if (!React || typeof React.useEffect !== 'function') {
  console.error('[CoreFlow360] FATAL: React.useEffect is ' + typeof React?.useEffect);
  throw new Error('React module validation failed');
}

import App from './App'
import './styles/globals.css'
import { validateEnvironment } from './lib/env-validation'

// Reuse the global fatal handler registered in index.html (before module evaluation)
declare global {
  interface Window {
    __CF360_FATAL__?: (label: string, detail: unknown) => void
  }
}

const surfaceFatal =
  window.__CF360_FATAL__ ??
  ((label: string, detail: unknown) => console.error(`[CoreFlow360] ${label}:`, detail))

console.log('[CoreFlow360] main.tsx: Starting application initialization')

// Web Vitals monitoring - lazy load to avoid blocking
if (typeof window !== 'undefined' && import.meta.env.PROD) {
  import('web-vitals').then(({ onCLS, onFID, onLCP, onINP, onFCP, onTTFB }) => {
    const sendToAnalytics = (metric: any) => {
      // Send to Cloudflare Workers KV or Analytics Engine
      const body = JSON.stringify({
        name: metric.name,
        value: metric.value,
        rating: metric.rating,
        delta: metric.delta,
        id: metric.id,
        navigationType: metric.navigationType,
      });

      // Use navigator.sendBeacon for reliability
      // Note: Web vitals endpoint doesn't require auth in production, but can be gated by Cloudflare Access
      const apiUrl = `${import.meta.env.VITE_API_URL || 'https://coreflow360-v4-prod.ernijs-ansons.workers.dev'}/api/v1/telemetry/web-vitals`;

      // Use fetch since sendBeacon doesn't support custom headers for auth
      fetch(apiUrl, {
        method: 'POST',
        body,
        headers: {
          'Content-Type': 'application/json',
          // In production, this endpoint should be behind Cloudflare Access instead of API key auth
          // to avoid exposing keys in frontend code
        },
        keepalive: true,
      }).catch(err => console.warn('[CoreFlow360] Failed to send web vitals:', err));
    };

    onCLS(sendToAnalytics);
    onFID(sendToAnalytics);
    onLCP(sendToAnalytics);
    onINP(sendToAnalytics);
    onFCP(sendToAnalytics);
    onTTFB(sendToAnalytics);

    console.log('[CoreFlow360] Web Vitals monitoring initialized');
  }).catch(err => {
    console.warn('[CoreFlow360] Failed to load web-vitals:', err);
  });
}

// Validate environment variables before initialization
let envValidationPassed = false
try {
  const validationResult = validateEnvironment()
  envValidationPassed = validationResult.valid
  
  if (!validationResult.valid) {
    console.error('[CoreFlow360] Environment validation failed:', validationResult.missing)
    // Show error but don't prevent app from loading - use fallbacks
    const rootElement = document.getElementById('root')
    if (rootElement) {
      rootElement.innerHTML = `
        <div style="padding: 40px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto;">
          <h1 style="color: #dc2626; margin-bottom: 16px;">⚠️ Configuration Warning</h1>
          <p style="color: #374151; margin-bottom: 24px;">Some environment variables are missing, but the app will continue with fallback values.</p>
          <div style="background: #fef2f2; border-left: 4px solid #dc2626; padding: 16px; margin-bottom: 24px; border-radius: 4px;">
            <pre style="margin: 0; font-size: 14px; overflow-x: auto;">Missing: ${validationResult.missing.join(', ')}</pre>
          </div>
          <p style="color: #6b7280; font-size: 14px;">
            The application will use default configuration values.
          </p>
        </div>
      `
    }
    // Don't throw - let the app continue with fallbacks
  } else {
    console.log('[CoreFlow360] Environment validation passed')
  }
} catch (error) {
  console.error('[CoreFlow360] Environment validation error:', error)
  // Don't throw - let the app continue with fallbacks
  envValidationPassed = false
}

const rootElement = document.getElementById('root')

if (!rootElement) {
  console.error('[CoreFlow360] CRITICAL: Root element not found!')
  document.body.innerHTML = '<div style="padding: 20px; font-family: Arial;"><h1 style="color: red;">Error: Root element not found</h1><p>Please check console for details</p></div>'
} else {
  console.log('[CoreFlow360] Root element found:', rootElement)

  // Only mount React if environment validation passed or if we're using fallbacks
  if (!rootElement.innerHTML || !envValidationPassed) {
    console.log('[CoreFlow360] Mounting React application...')
    try {
      // Clear any existing content from environment validation errors
      if (!envValidationPassed) {
        rootElement.innerHTML = ''
      }
      
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
