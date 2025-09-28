/**
 * Enhanced Test Setup Configuration
 * Comprehensive test environment setup with MSW mocking
 */

import '@testing-library/jest-dom'
import { beforeAll, afterEach, afterAll, vi } from 'vitest'
import { cleanup } from '@testing-library/react'
import { setupMockServer, resetMockServer, closeMockServer } from './mocks/server'
import { setupSDKMocks } from './mocks/sdk-mocks'

// Setup MSW mock server and test environment
beforeAll(() => {
  // Setup SDK mocks first
  setupSDKMocks()

  // Setup MSW mock server
  setupMockServer()

  // Set test environment variables
  process.env.NODE_ENV = 'test'
  process.env.COREFLOW_URL = 'http://localhost:8787'
  process.env.AGENT_SYSTEM_URL = 'http://localhost:3000'

  // Mock Cloudflare-specific environments
  process.env.CLOUDFLARE_ACCOUNT_ID = 'test-account-id'
  process.env.CLOUDFLARE_API_TOKEN = 'test-api-token'

  // Mock database URLs
  process.env.DATABASE_URL = 'test://test.db'
  process.env.KV_NAMESPACE = 'test-kv'
  process.env.R2_BUCKET = 'test-r2'
})

// Reset any request handlers that we may add during the tests
afterEach(() => {
  cleanup()
  resetMockServer()
})

// Clean up after the tests are finished
afterAll(() => {
  // Close MSW server
  closeMockServer()
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

// Mock fetch if not available (MSW will override this)
if (!global.fetch) {
  global.fetch = vi.fn()
}

// Mock console methods in test environment
if (process.env.NODE_ENV === 'test') {
  global.console = {
    ...console,
    // Suppress noise in tests but keep errors visible
    warn: vi.fn(),
    error: vi.fn(),
  }
}

// Mock performance API
global.performance = global.performance || {
  mark: vi.fn(),
  measure: vi.fn(),
  getEntriesByName: vi.fn(() => []),
  getEntriesByType: vi.fn(() => []),
  clearMarks: vi.fn(),
  clearMeasures: vi.fn(),
  now: vi.fn(() => Date.now())
} as any

// Mock crypto API for Node.js environment
if (!global.crypto) {
  global.crypto = {
    randomUUID: vi.fn(() => '00000000-0000-0000-0000-000000000000'),
    getRandomValues: vi.fn((array) => {
      for (let i = 0; i < array.length; i++) {
        array[i] = Math.floor(Math.random() * 256)
      }
      return array
    })
  } as any
}

// Mock TextEncoder/TextDecoder if not available
if (!global.TextEncoder) {
  global.TextEncoder = class {
    encode(text: string) {
      return new Uint8Array(Buffer.from(text, 'utf-8'))
    }
  } as any
}

if (!global.TextDecoder) {
  global.TextDecoder = class {
    decode(bytes: Uint8Array) {
      return Buffer.from(bytes).toString('utf-8')
    }
  } as any
}

// Mock ReadableStream for SSE testing
if (!global.ReadableStream) {
  global.ReadableStream = class {
    constructor(source: any) {
      this._source = source
    }
    getReader() {
      return {
        read: vi.fn().mockResolvedValue({ done: true, value: undefined }),
        cancel: vi.fn()
      }
    }
  } as any
}