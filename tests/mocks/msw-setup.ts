import { setupServer } from 'msw/node';
import { handlers } from './msw-handlers';

// Create MSW server with default handlers
export const server = setupServer(...handlers);

// Start server before all tests
export const setupMSW = () => {
  beforeAll(() => {
    server.listen({
      onUnhandledRequest: 'warn',
    });
  });

  // Reset handlers after each test
  afterEach(() => {
    server.resetHandlers();
  });

  // Close server after all tests
  afterAll(() => {
    server.close();
  });
};

// Helper to add runtime handlers
export const addMockHandler = (...newHandlers: any[]) => {
  server.use(...newHandlers);
};

// Helper to reset specific handlers
export const resetMockHandlers = (...newHandlers: any[]) => {
  server.resetHandlers(...newHandlers);
};

export default server;