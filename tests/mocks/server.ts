/**
 * MSW Mock Server Setup
 * Comprehensive API mocking for all external services
 */

import { setupServer } from 'msw/node'
import { handlers } from './handlers'

// Setup MSW server with all handlers
export const server = setupServer(...handlers)

// Configure server for test environment
export function setupMockServer() {
  // Start server before all tests
  server.listen({
    onUnhandledRequest: 'warn'
  })
}

export function resetMockServer() {
  // Reset handlers between tests
  server.resetHandlers()
}

export function closeMockServer() {
  // Close server after all tests
  server.close()
}

// Export additional utilities
export { handlers } from './handlers'