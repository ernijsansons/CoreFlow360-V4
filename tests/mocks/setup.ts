/**
 * MSW Test Setup
 * Initializes Mock Service Worker for all tests with comprehensive handlers
 */

import { beforeAll, afterEach, afterAll, vi } from 'vitest'
import { server } from './server'

// Re-export server from our comprehensive setup
export { server }

// Setup and teardown
beforeAll(() => {
  server.listen({
    onUnhandledRequest: 'warn'
  })
})

afterEach(() => {
  server.resetHandlers()
})

afterAll(() => {
  server.close()
})

// Enhanced fetch mock to prevent ECONNREFUSED errors
const originalFetch = globalThis.fetch

// Mock fetch for better error handling
globalThis.fetch = vi.fn(async (url, options) => {
  try {
    // Let MSW handle the request first
    return await originalFetch(url, options)
  } catch (error) {
    // If network error (ECONNREFUSED), return mock response
    if (error instanceof TypeError && error.message.includes('fetch')) {
      console.warn(`MSW: Network error for ${url}, returning mock response`)
      return new Response(JSON.stringify({
        error: 'Network error - mocked response',
        url: url.toString(),
        mocked: true
      }), {
        status: 503,
        headers: { 'Content-Type': 'application/json' }
      })
    }
    throw error
  }
}) as any

// Store original fetch for cleanup
;(globalThis.fetch as any).original = originalFetch