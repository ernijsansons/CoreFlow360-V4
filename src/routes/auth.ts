import { Hono } from 'hono';
import type { Env } from '../types/env';
import { createAuthService } from '../modules/user-management/auth-service';
import { extractTenantContext } from '../database/tenant-isolated-db';
import { rateLimiters } from '../middleware/rate-limit';
import { authenticate, requireMFA } from '../middleware/auth';
import { errorHandler, asyncHandler } from '../shared/error-handler';
import {
  registerSchema,
  loginSchema,
  changePasswordSchema,
  passwordResetRequestSchema,
  validateSchema,
  type RegisterInput,
  type LoginInput,
  type ChangePasswordInput
} from '../database/schemas';

const auth = new Hono<{ Bindings: Env }>();

// Apply error handler
auth.onError(errorHandler);

/**
 * Register new user and business
 * POST /auth/register
 */
auth.post('/register', rateLimiters.register, asyncHandler(async (c) => {
  const body = await c.req.json();

  // Validate input
  const validation = validateSchema(registerSchema, body);
  if (!validation.success) {
    return c.json({
      success: false,
      error: 'Validation failed',
      details: validation.errors?.flatten().fieldErrors
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

  // Create auth service with system context (no tenant yet)
  const authService = createAuthService(
    c.env.DB,
    { businessId: 'system' }, // Will be overridden during registration
    c.req.raw,
    {
      jwtSecret: c.env.JWT_SECRET
    }
  );

  const result = await authService.register(validation.data!);

  if (result.success) {
    return c.json(result, 201);
  } else {
    return c.json(result, 400);
  }
}));

/**
 * Login user
 * POST /auth/login
 */
auth.post('/login', rateLimiters.login, asyncHandler(async (c) => {
  const body = await c.req.json();

  // Validate input
  const validation = validateSchema(loginSchema, body);
  if (!validation.success) {
    return c.json({
      success: false,
      error: 'Invalid login credentials'
    }, 400);
  }

  // First, get user to determine business context
  const userLookup = await c.env.DB
    .prepare('SELECT business_id FROM users WHERE email = ? AND deleted_at IS NULL')
    .bind(validation.data!.email)
    .first();

  if (!userLookup) {
    return c.json({
      success: false,
      error: 'Invalid login credentials'
    }, 401);
  }

  // SECURITY FIX: Validate JWT_SECRET environment variable
  if (!c.env.JWT_SECRET) {
    return c.json({
      success: false,
      error: 'Server configuration error',
      code: 'MISSING_JWT_SECRET'
    }, 500);
  }

  // Create auth service with user's business context
  const authService = createAuthService(
    c.env.DB,
    { businessId: userLookup.business_id },
    c.req.raw,
    {
      jwtSecret: c.env.JWT_SECRET
    }
  );

  const result = await authService.login(validation.data!);

  if (result.success) {
    // Set session cookie if successful
    if (result.sessionToken) {
      c.header('Set-Cookie', `session=${result.sessionToken}; HttpOnly; Secure; SameSite=Strict; Path=/`);
    }
    return c.json(result);
  } else {
    const statusCode = result.requiresMFA ? 202 : 401;
    return c.json(result, statusCode);
  }
}));

/**
 * Logout user
 * POST /auth/logout
 */
auth.post('/logout', authenticate(), asyncHandler(async (c) => {
  const authService = new AuthService(c.env);
  const sessionId = c.get('sessionId');

  await authService.logout(sessionId);

  return c.json({ success: true, message: 'Logged out successfully' });
}));

/**
 * Refresh access token
 * POST /auth/refresh
 */
auth.post('/refresh', asyncHandler(async (c) => {
  const authService = new AuthService(c.env);
  const body = await c.req.json();
  const validated = RefreshTokenRequestSchema.parse(body);

  const result = await authService.refreshToken(validated.refreshToken);

  return c.json(result);
}));

/**
 * Get current user info
 * GET /auth/me
 */
auth.get('/me', authenticate(), asyncHandler(async (c) => {
  const userId = c.get('userId');
  const businessId = c.get('businessId');

  const user = await c.env.DB_MAIN
    .prepare(`
      SELECT u.id, u.email, u.first_name, u.last_name, u.avatar_url,
             u.language, u.timezone, u.date_format, u.two_factor_enabled,
             bm.role, bm.job_title, bm.department,
             b.name as business_name, b.subscription_tier
      FROM users u
      JOIN business_memberships bm ON bm.user_id = u.id
      JOIN businesses b ON b.id = bm.business_id
      WHERE u.id = ? AND bm.business_id = ? AND bm.status = 'active'
    `)
    .bind(userId, businessId)
    .first();

  if (!user) {
    return c.json({ error: 'User not found' }, 404);
  }

  return c.json({
    success: true,
    user,
  });
}));

/**
 * Update current user profile
 * PUT /auth/me
 */
auth.put('/me', authenticate(), asyncHandler(async (c) => {
  const userId = c.get('userId');
  const body = await c.req.json();

  // Only allow updating certain fields
  const allowedFields = ['first_name', 'last_name', 'language', 'timezone', 'date_format'];
  const updates: string[] = [];
  const values: any[] = [];

  for (const field of allowedFields) {
    if (body[field] !== undefined) {
      updates.push(`${field} = ?`);
      values.push(body[field]);
    }
  }

  if (updates.length === 0) {
    return c.json({ error: 'No valid fields to update' }, 400);
  }

  values.push(userId);

  await c.env.DB_MAIN
    .prepare(`
      UPDATE users
      SET ${updates.join(', ')}, updated_at = datetime('now')
      WHERE id = ?
    `)
    .bind(...values)
    .run();

  return c.json({ success: true, message: 'Profile updated successfully' });
}));

/**
 * Change password
 * POST /auth/change-password
 */
auth.post('/change-password', authenticate(), requireMFA(), asyncHandler(async (c) => {
  const userId = c.get('userId');
  const body = await c.req.json();
  const { currentPassword, newPassword } = body;

  if (!currentPassword || !newPassword) {
    return c.json({ error: 'Current and new passwords are required' }, 400);
  }

  // Verify current password
  const user = await c.env.DB_MAIN
    .prepare('SELECT password_hash FROM users WHERE id = ?')
    .bind(userId)
    .first<any>();

  const [salt, hash] = user.password_hash.split(':');
  const { verifyPassword, hashPassword } = await import('../modules/auth/crypto');

  const isValid = await verifyPassword(currentPassword, hash, salt);
  if (!isValid) {
    return c.json({ error: 'Current password is incorrect' }, 401);
  }

  // Hash new password
  const newHash = await hashPassword(newPassword);

  // Update password
  await c.env.DB_MAIN
    .prepare(`
      UPDATE users
      SET password_hash = ?, updated_at = datetime('now')
      WHERE id = ?
    `)
    .bind(`${newHash.salt}:${newHash.hash}`, userId)
    .run();

  // Invalidate all sessions
  const { SessionManager } = await import('../modules/auth/session');
  const { JWTService } = await import('../modules/auth/jwt');

  if (!c.env.JWT_SECRET) {
    throw new Error('JWT_SECRET environment variable is required');
  }

  const sessionManager = new SessionManager(
    c.env.KV_SESSION,
    new JWTService(c.env.JWT_SECRET)
  );
  await sessionManager.deleteUserSessions(userId);

  return c.json({ success: true, message: 'Password changed successfully' });
}));

/**
 * Request password reset
 * POST /auth/forgot-password
 */
auth.post('/forgot-password', rateLimiters.passwordReset, asyncHandler(async (c) => {
  const authService = new AuthService(c.env);
  const body = await c.req.json();
  const validated = PasswordResetRequestSchema.parse(body);

  await authService.requestPasswordReset(validated.email);

  // Always return success to prevent email enumeration
  return c.json({
    success: true,
    message: 'If an account exists with this email, you will receive a password reset link.',
  });
}));

/**
 * Confirm password reset
 * POST /auth/reset-password
 */
auth.post('/reset-password', rateLimiters.passwordReset, asyncHandler(async (c) => {
  const authService = new AuthService(c.env);
  const body = await c.req.json();
  const validated = PasswordResetConfirmSchema.parse(body);

  await authService.confirmPasswordReset(validated.token, validated.newPassword);

  return c.json({
    success: true,
    message: 'Password reset successfully. You can now login with your new password.',
  });
}));

/**
 * Setup MFA
 * POST /auth/mfa/setup
 */
auth.post('/mfa/setup', authenticate(), requireMFA(), asyncHandler(async (c) => {
  const userId = c.get('userId');
  const authService = new AuthService(c.env);
  const body = await c.req.json();
  const validated = MFASetupRequestSchema.parse(body);

  const result = await authService.setupMFA(userId, validated.type);

  return c.json({
    success: true,
    ...result,
  });
}));

/**
 * Verify MFA setup
 * POST /auth/mfa/verify
 */
auth.post('/mfa/verify', authenticate(), asyncHandler(async (c) => {
  const userId = c.get('userId');
  const sessionId = c.get('sessionId');
  const body = await c.req.json();
  const validated = MFAVerifyRequestSchema.parse(body);

  // Verify the MFA code
  // This would verify TOTP/SMS/Email code
  // For now, simple validation
  if (validated.code !== '123456') {
    return c.json({ error: 'Invalid verification code' }, 400);
  }

  // Enable MFA for user
  await c.env.DB_MAIN
    .prepare(`
      UPDATE users
      SET two_factor_enabled = 1, updated_at = datetime('now')
      WHERE id = ?
    `)
    .bind(userId)
    .run();

  // Update session MFA status
  const { SessionManager } = await import('../modules/auth/session');
  const { JWTService } = await import('../modules/auth/jwt');

  if (!c.env.JWT_SECRET) {
    throw new Error('JWT_SECRET environment variable is required');
  }

  const sessionManager = new SessionManager(
    c.env.KV_SESSION,
    new JWTService(c.env.JWT_SECRET)
  );
  await sessionManager.updateMFAStatus(sessionId, true);

  return c.json({
    success: true,
    message: 'MFA has been successfully enabled',
  });
}));

/**
 * Disable MFA
 * POST /auth/mfa/disable
 */
auth.post('/mfa/disable', authenticate(), requireMFA(), asyncHandler(async (c) => {
  const userId = c.get('userId');
  const body = await c.req.json();

  // Verify password before disabling MFA
  const user = await c.env.DB_MAIN
    .prepare('SELECT password_hash FROM users WHERE id = ?')
    .bind(userId)
    .first<any>();

  const [salt, hash] = user.password_hash.split(':');
  const { verifyPassword } = await import('../modules/auth/crypto');

  const isValid = await verifyPassword(body.password, hash, salt);
  if (!isValid) {
    return c.json({ error: 'Invalid password' }, 401);
  }

  // Disable MFA
  await c.env.DB_MAIN
    .prepare(`
      UPDATE users
      SET two_factor_enabled = 0, two_factor_secret = NULL, updated_at = datetime('now')
      WHERE id = ?
    `)
    .bind(userId)
    .run();

  // Clear MFA config from KV
  await c.env.KV_SESSION.delete(`mfa:${userId}`);

  return c.json({
    success: true,
    message: 'MFA has been disabled',
  });
}));

/**
 * Get active sessions
 * GET /auth/sessions
 */
auth.get('/sessions', authenticate(), asyncHandler(async (c) => {
  const userId = c.get('userId');
  const currentSessionId = c.get('sessionId');

  const sessions = await c.env.DB_MAIN
    .prepare(`
      SELECT id, ip_address, user_agent, created_at, last_activity_at, expires_at
      FROM user_sessions
      WHERE user_id = ? AND revoked_at IS NULL
      ORDER BY last_activity_at DESC
    `)
    .bind(userId)
    .all();

  return c.json({
    success: true,
    sessions: sessions.results?.map((s: any) => ({
      ...s,
      isCurrent: s.id === currentSessionId,
    })) || [],
  });
}));

/**
 * Revoke session
 * DELETE /auth/sessions/:sessionId
 */
auth.delete('/sessions/:sessionId', authenticate(), asyncHandler(async (c) => {
  const userId = c.get('userId');
  const sessionId = c.req.param('sessionId');

  // Verify session belongs to user
  const session = await c.env.DB_MAIN
    .prepare('SELECT id FROM user_sessions WHERE id = ? AND user_id = ?')
    .bind(sessionId, userId)
    .first();

  if (!session) {
    return c.json({ error: 'Session not found' }, 404);
  }

  // Revoke session
  const { SessionManager } = await import('../modules/auth/session');
  const { JWTService } = await import('../modules/auth/jwt');

  if (!c.env.JWT_SECRET) {
    throw new Error('JWT_SECRET environment variable is required');
  }

  const sessionManager = new SessionManager(
    c.env.KV_SESSION,
    new JWTService(c.env.JWT_SECRET)
  );
  await sessionManager.deleteSession(sessionId);

  return c.json({
    success: true,
    message: 'Session revoked successfully',
  });
}));

/**
 * Check password strength
 * POST /auth/password-strength
 */
auth.post('/password-strength', asyncHandler(async (c) => {
  const body = await c.req.json();
  const { password } = body;

  if (!password) {
    return c.json({ error: 'Password is required' }, 400);
  }

  const strength = calculatePasswordStrength(password);

  return c.json({
    success: true,
    strength,
  });
}));

export default auth;