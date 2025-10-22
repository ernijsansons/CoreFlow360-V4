// Development-only auth routes without rate limiting
import { Hono } from 'hono';
import type { StatusCode } from 'hono/utils/http-status';
import type { Env } from '../types/env';
import { AuthService } from '../modules/auth/service';
import { errorHandler, asyncHandler } from '../shared/error-handler';
import {
  RegisterRequestSchema,
  LoginRequestSchema,
  RefreshTokenRequestSchema,
} from '../modules/auth/types';

const auth = new Hono<{ Bindings: Env }>();

// Apply error handler
auth.onError(errorHandler);

/**
 * Register new user and business
 * POST /auth/register
 * DEV: No rate limiting
 */
auth.post('/register', asyncHandler(async (c: any) => {
  const body = await c.req.json();

  // Validate input
  const validation = RegisterRequestSchema.safeParse(body);
  if (!validation.success) {
    return c.json({
      success: false,
      error: 'Validation failed',
      details: validation.error.flatten().fieldErrors
    }, 400);
  }

  // SECURITY FIX: Validate JWT_SECRET environment variable
  if (!c.env.JWT_SECRET) {
    return c.json({
      success: false,
      error: 'Server configuration error',
      code: 'MISSING_JWT_SECRET'
    }, 500);
  }

  // Create auth service
  const authService = new AuthService(c.env);

  // Get IP address and user agent
  const ipAddress = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown';
  const userAgent = c.req.header('User-Agent') || 'unknown';

  const result = await authService.register(validation.data, ipAddress, userAgent);

  if (result.success) {
    return c.json(result, 201);
  } else {
    return c.json(result, 400);
  }
}));

/**
 * Login user
 * POST /auth/login
 * DEV: No rate limiting
 */
auth.post('/login', asyncHandler(async (c: any) => {
  const body = await c.req.json();

  // Validate input
  const validation = LoginRequestSchema.safeParse(body);
  if (!validation.success) {
    return c.json({
      success: false,
      error: 'Invalid login credentials'
    }, 400);
  }

  // SECURITY FIX: Validate JWT_SECRET environment variable
  if (!c.env.JWT_SECRET) {
    return c.json({
      success: false,
      error: 'Server configuration error',
      code: 'MISSING_JWT_SECRET'
    }, 500);
  }

  // Create auth service
  const authService = new AuthService(c.env);

  // Get IP address and user agent
  const ipAddress = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown';
  const userAgent = c.req.header('User-Agent') || 'unknown';

  const result = await authService.login(validation.data, ipAddress, userAgent);

  if (result.success) {
    // Set session cookie if successful
    if (result.accessToken) {
      c.header('Set-Cookie', `session=${result.accessToken}; HttpOnly; Secure; SameSite=Strict; Path=/`);
    }

    // IMPORTANT: Transform response to match frontend expectations
    // Frontend expects: { success: true, data: { token, refreshToken, user } }
    return c.json({
      success: true,
      data: {
        token: result.accessToken,
        refreshToken: result.refreshToken,
        user: result.user,
        expiresIn: 86400 // 24 hours in seconds
      }
    });
  } else {
    const statusCode = (result.mfaRequired ? 202 : 401) as StatusCode;
    return c.json(result, statusCode);
  }
}));

/**
 * Refresh access token
 * POST /auth/refresh
 * DEV: No rate limiting
 */
auth.post('/refresh', asyncHandler(async (c: any) => {
  const authService = new AuthService(c.env);
  const body = await c.req.json();

  const validation = RefreshTokenRequestSchema.safeParse(body);
  if (!validation.success) {
    return c.json({ success: false, error: 'Invalid refresh token' }, 400);
  }

  const result = await authService.refreshToken(validation.data.refreshToken);

  return c.json({ success: true, ...result });
}));

export default auth;
