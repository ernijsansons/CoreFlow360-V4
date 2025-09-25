/**
 * Test Setup Configuration
 * Jest and testing library setup for CoreFlow360
 */

import '@testing-library/jest-dom'
import { beforeAll, afterEach, afterAll, vi } from 'vitest'
import { cleanup } from '@testing-library/react'

// Basic test environment setup
beforeAll(() => {
  // Setup test environment
})

// Reset any request handlers that we may add during the tests
afterEach(() => {
  cleanup()
})

// Clean up after the tests are finished
afterAll(() => {
  // Cleanup test environment
})

// Mock window methods (only if window exists)
if (typeof window !== 'undefined') {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: vi.fn().mockImplementation(query => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  })
}

// Mock ResizeObserver
global.ResizeObserver = vi.fn().mockImplementation(() => ({
  observe: vi.fn(),
  unobserve: vi.fn(),
  disconnect: vi.fn(),
}))

// Mock IntersectionObserver
global.IntersectionObserver = vi.fn().mockImplementation(() => ({
  observe: vi.fn(),
  unobserve: vi.fn(),
  disconnect: vi.fn(),
}))

// Mock fetch if not available
if (!global.fetch) {
  global.fetch = vi.fn()
}

// Mock console methods in test environment
if (process.env.NODE_ENV === 'test') {
  global.console = {
    ...console,
    // Uncomment to ignore specific console outputs
    // log: vi.fn(),
    // debug: vi.fn(),
    // info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }
}