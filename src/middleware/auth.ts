import { Context, Next } from 'hono';
import { JWTService } from '../modules/auth/jwt';
import { SessionManager } from '../modules/auth/session';
import { AuthenticationError, AuthorizationError } from '../shared/error-handler';
import type { AuthContext } from '../modules/auth/types';

/**
 * Authentication middleware - verifies JWT and session
 */
export function authenticate(options?: { optional?: boolean }) {
  return async (c: Context, next: Next) => {
    const authHeader = c.req.header('Authorization');
    const token = JWTService.extractBearerToken(authHeader);

    if (!token) {
      if (options?.optional) {
        c.set('isAuthenticated', false);
        return next();
      }
      throw new AuthenticationError('Authentication required');
    }

    try {
      // Initialize services
      const jwtService = new JWTService(c.env.JWT_SECRET || 'dev-secret');
      const sessionManager = new SessionManager(c.env.KV_SESSION, jwtService);

      // Verify token
      const claims = await jwtService.verifyToken(token);

      // Verify session
      const authContext = await sessionManager.verifySession(claims.sessionId, token);

      if (!authContext) {
        throw new AuthenticationError('Invalid or expired session');
      }

      // Set auth context for downstream handlers
      c.set('authContext', authContext);
      c.set('isAuthenticated', true);
      c.set('userId', authContext.userId);
      c.set('businessId', authContext.businessId);
      c.set('role', authContext.role);
      c.set('sessionId', authContext.sessionId);

      await next();
    } catch (error) {
      if (options?.optional) {
        c.set('isAuthenticated', false);
        return next();
      }

      if (error instanceof Error) {
        if (error.message.includes('expired')) {
          throw new AuthenticationError('Token has expired');
        }
        if (error.message.includes('signature')) {
          throw new AuthenticationError('Invalid token');
        }
      }

      throw new AuthenticationError('Authentication failed');
    }
  };
}

/**
 * Authorization middleware - checks user permissions
 */
export function authorize(
  requiredPermission?: string | string[],
  options?: {
    requireBusinessId?: boolean;
    requireRole?: string[];
    checkOwnership?: (c: Context) => Promise<boolean>;
  }
) {
  return async (c: Context, next: Next) => {
    const authContext = c.get('authContext') as AuthContext;

    if (!authContext || !authContext.isAuthenticated) {
      throw new AuthenticationError('Authentication required');
    }

    // Check MFA requirement
    if (authContext.mfaRequired && !authContext.mfaVerified) {
      throw new AuthenticationError('MFA verification required');
    }

    // Check business context
    if (options?.requireBusinessId && !authContext.businessId) {
      throw new AuthorizationError('Business context required');
    }

    // Check role requirement
    if (options?.requireRole) {
      if (!options.requireRole.includes(authContext.role)) {
        throw new AuthorizationError(`Required role: ${options.requireRole.join(' or ')}`);
      }
    }

    // Check specific permissions
    if (requiredPermission) {
      const permissions = Array.isArray(requiredPermission)
        ? requiredPermission
        : [requiredPermission];

      const hasPermission = permissions.some(perm =>
        authContext.permissions.includes(perm) ||
        authContext.permissions.includes('*')
      );

      if (!hasPermission) {
        throw new AuthorizationError('Insufficient permissions');
      }
    }

    // Check ownership if provided
    if (options?.checkOwnership) {
      const isOwner = await options.checkOwnership(c);
      if (!isOwner) {
        throw new AuthorizationError('You do not have access to this resource');
      }
    }

    await next();
  };
}

/**
 * Role-based authorization shortcuts
 */
export const requireRole = {
  owner: authorize(undefined, { requireRole: ['owner'] }),
  director: authorize(undefined, { requireRole: ['owner', 'director'] }),
  manager: authorize(undefined, { requireRole: ['owner', 'director', 'manager'] }),
  employee: authorize(undefined, { requireRole: ['owner', 'director', 'manager', 'employee'] }),
  viewer: authorize(undefined, {
    requireRole: ['owner', 'director', 'manager', 'employee', 'viewer']
  }),
};

/**
 * Business context middleware - ensures valid business membership
 */
export function requireBusiness() {
  return async (c: Context, next: Next) => {
    const authContext = c.get('authContext') as AuthContext;
    const businessId = c.req.param('businessId') || authContext?.businessId;

    if (!businessId) {
      throw new AuthorizationError('Business context required');
    }

    if (!authContext || !authContext.isAuthenticated) {
      throw new AuthenticationError('Authentication required');
    }

    // Verify user has access to this business
    const membership = await c.env.DB_MAIN
      .prepare(`
        SELECT role, status
        FROM business_memberships
        WHERE user_id = ? AND business_id = ? AND status = 'active'
      `)
      .bind(authContext.userId, businessId)
      .first<any>();

    if (!membership) {
      throw new AuthorizationError('You do not have access to this business');
    }

    // Update context with business info
    c.set('businessId', businessId);
    c.set('businessRole', membership.role);

    await next();
  };
}

/**
 * API key authentication middleware
 */
export function authenticateApiKey() {
  return async (c: Context, next: Next) => {
    const apiKey = c.req.header('X-API-Key');

    if (!apiKey) {
      throw new AuthenticationError('API key required');
    }

    // Hash the provided key for comparison
    const encoder = new TextEncoder();
    const keyBuffer = encoder.encode(apiKey);
    const hashBuffer = await crypto.subtle.digest('SHA-256', keyBuffer);
    const keyHash = btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));

    // Look up API key
    const apiKeyRecord = await c.env.DB_MAIN
      .prepare(`
        SELECT ak.*, b.subscription_tier, b.status as business_status
        FROM api_keys ak
        JOIN businesses b ON b.id = ak.business_id
        WHERE ak.key_hash = ? AND ak.status = 'active'
      `)
      .bind(keyHash)
      .first<any>();

    if (!apiKeyRecord) {
      throw new AuthenticationError('Invalid API key');
    }

    // Check expiration
    if (apiKeyRecord.expires_at && new Date(apiKeyRecord.expires_at) < new Date()) {
      throw new AuthenticationError('API key has expired');
    }

    // Check business status
    if (apiKeyRecord.business_status !== 'active') {
      throw new AuthorizationError('Business account is not active');
    }

    // Update usage stats
    await c.env.DB_MAIN
      .prepare(`
        UPDATE api_keys
        SET last_used_at = datetime('now'),
            last_used_ip = ?,
            usage_count = usage_count + 1
        WHERE id = ?
      `)
      .bind(c.req.header('CF-Connecting-IP') || 'unknown', apiKeyRecord.id)
      .run();

    // Set context
    c.set('authType', 'apiKey');
    c.set('apiKeyId', apiKeyRecord.id);
    c.set('businessId', apiKeyRecord.business_id);
    c.set('permissions', JSON.parse(apiKeyRecord.permissions || '[]'));
    c.set('rateLimit', apiKeyRecord.rate_limit);

    await next();
  };
}

/**
 * Multi-factor authentication check
 */
export function requireMFA() {
  return async (c: Context, next: Next) => {
    const authContext = c.get('authContext') as AuthContext;

    if (!authContext || !authContext.isAuthenticated) {
      throw new AuthenticationError('Authentication required');
    }

    if (authContext.mfaRequired && !authContext.mfaVerified) {
      throw new AuthenticationError('MFA verification required');
    }

    await next();
  };
}

/**
 * Check resource ownership
 */
export function checkOwnership(
  resourceType: string,
  getResourceId: (c: Context) => string
) {
  return authorize(undefined, {
    checkOwnership: async (c: Context) => {
      const authContext = c.get('authContext') as AuthContext;
      const resourceId = getResourceId(c);

      // Check if user owns or has access to the resource
      const query = {
        user: 'SELECT id FROM users WHERE id = ? AND id = ?',
        business: 'SELECT id FROM businesses WHERE id = ? AND id IN (SELECT business_id FROM business_memberships WHERE user_id = ?)',
        document: 'SELECT id FROM documents WHERE id = ? AND (created_by = ? OR business_id IN (SELECT business_id FROM business_memberships WHERE user_id = ?))',
      }[resourceType];

      if (!query) {
        return false;
      }

      const result = await c.env.DB_MAIN
        .prepare(query)
        .bind(resourceId, authContext.userId, authContext.userId)
        .first();

      return result !== null;
    }
  });
}

/**
 * Audit trail middleware
 */
export function auditLog(action: string, resourceType: string) {
  return async (c: Context, next: Next) => {
    const authContext = c.get('authContext') as AuthContext;
    const startTime = Date.now();

    try {
      await next();

      // Log successful action
      await c.env.DB_MAIN
        .prepare(`
          INSERT INTO audit_logs (
            id, business_id, user_id, event_type, event_name,
            resource_type, resource_id, ip_address, user_agent,
            request_method, request_path, status, compute_time_ms,
            created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        `)
        .bind(
          crypto.randomUUID(),
          authContext?.businessId || 'SYSTEM',
          authContext?.userId || null,
          'api_call',
          action,
          resourceType,
          c.req.param('id') || null,
          c.req.header('CF-Connecting-IP') || 'unknown',
          c.req.header('User-Agent') || 'unknown',
          c.req.method,
          c.req.path,
          'success',
          Date.now() - startTime
        )
        .run();
    } catch (error) {
      // Log failed action
      await c.env.DB_MAIN
        .prepare(`
          INSERT INTO audit_logs (
            id, business_id, user_id, event_type, event_name,
            resource_type, resource_id, ip_address, user_agent,
            request_method, request_path, status, error_message,
            compute_time_ms, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        `)
        .bind(
          crypto.randomUUID(),
          authContext?.businessId || 'SYSTEM',
          authContext?.userId || null,
          'api_call',
          action,
          resourceType,
          c.req.param('id') || null,
          c.req.header('CF-Connecting-IP') || 'unknown',
          c.req.header('User-Agent') || 'unknown',
          c.req.method,
          c.req.path,
          'failure',
          error instanceof Error ? error.message : 'Unknown error',
          Date.now() - startTime
        )
        .run();

      throw error;
    }
  };
}