/**
 * Error Handler - Centralized error handling
 */

// Re-export ErrorHandler class from middleware
export { ErrorHandler } from '../middleware/error-handler';

// Also export the simple error handler function from shared
export { errorHandler } from '../shared/error-handler';