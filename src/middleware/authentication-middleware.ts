/**
 * Authentication Middleware - Bridge to AuthMiddleware
 */

import { AuthMiddleware } from './auth';

export { AuthMiddleware as AuthenticationMiddleware } from './auth';

// Export helper functions
export { authenticate, requireMFA } from './auth';