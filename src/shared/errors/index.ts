/**
 * Error handling utilities and classes
 * Centralized error management for CoreFlow360
 */

export {
  AppError,
  ErrorCategory,
  ErrorSeverity,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ConflictError,
  SecurityError,
  RateLimitError,
  InternalError,
  isAppError,
  formatErrorResponse
} from './app-error';
export type { ErrorDetails, ErrorContext } from './app-error';