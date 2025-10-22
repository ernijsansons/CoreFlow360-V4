/**
 * Authentication Middleware - Bridge to AuthMiddleware
 */



export { AuthMiddleware as AuthenticationMiddleware } from './auth';

// Export helper functions
export { authenticate, requireMFA } from './auth';