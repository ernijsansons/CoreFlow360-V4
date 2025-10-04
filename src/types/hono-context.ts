/**
 * Hono Context Type Definitions
 * Provides type-safe context variable access throughout the application
 */

import { Context } from 'hono';
import type { Env } from './environment';

/**
 * Application Context Variables
 * All variables that can be set/get on Hono context
 */
export type AppVariables = {
  // Request tracking
  correlationId?: string;
  requestId?: string;

  // Environment bindings
  env?: Env;

  // Authentication & Authorization
  userId?: string;
  businessId?: string;
  sessionId?: string;
  roles?: string[];
  tokenVersion?: string | number;

  // Request data
  sanitizedBody?: any;

  // Performance tracking
  startTime?: number;
  dbQueryCount?: number;
  cacheHitCount?: number;
  cacheMissCount?: number;
};

/**
 * Typed Hono Context
 * Use this type for all middleware and route handlers
 */
export type AppContext = Context<{
  Bindings: Env;
  Variables: AppVariables;
}>;

/**
 * Helper type for Next function
 */
export type Next = () => Promise<void>;

/**
 * Middleware handler type
 */
export type MiddlewareHandler = (c: AppContext, next: Next) => Promise<void | Response>;

/**
 * Route handler type
 */
export type RouteHandler = (c: AppContext) => Promise<Response> | Response;
