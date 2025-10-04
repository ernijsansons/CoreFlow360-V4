/**
 * Tenant Isolation Middleware
 *
 * Enforces multi-tenant security at the middleware level by:
 * - Extracting business_id from JWT token
 * - Injecting security context into all database operations
 * - Preventing cross-tenant data access
 * - Validating tenant permissions
 *
 * OWASP 2025 Compliance:
 * - A01: Broken Access Control (CVSS 8.6)
 * - A04: Insecure Design (Multi-Tenant Architecture)
 * - A07: Identification and Authentication Failures
 */

import { Context, Next } from 'hono';
import { verify } from 'hono/jwt';
import { z } from 'zod';
import { createSecureDatabase, type SecurityConfig } from '../database/secure-database';
import { AppError } from '../shared/errors/app-error';
import { logger } from '../shared/logger';

// JWT Payload schema
const JWTPayloadSchema = z.object({
  sub: z.string(), // User ID
  businessId: z.string(),
  tenantId: z.string().optional(),
  role: z.enum(['owner', 'admin', 'user', 'viewer']),
  permissions: z.array(z.string()).optional(),
  iat: z.number(),
  exp: z.number(),
  jti: z.string().optional() // JWT ID for revocation
});

type JWTPayload = z.infer<typeof JWTPayloadSchema>;

// Security headers that should be set
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
};

// Cache for tenant validation (5 minute TTL)
const tenantCache = new Map<string, { valid: boolean; expires: number }>();

/**
 * Validates if a tenant/business exists and is active
 */
async function validateTenant(businessId: string, db: any): Promise<boolean> {
  // Check cache first
  const cached = tenantCache.get(businessId);
  if (cached && cached.expires > Date.now()) {
    return cached.valid;
  }

  try {
    const result = await db
      .prepare('SELECT id, status FROM businesses WHERE id = ? AND status = ?')
      .bind(businessId, 'active')
      .first();

    const valid = Boolean(result);

    // Cache the result
    tenantCache.set(businessId, {
      valid,
      expires: Date.now() + 5 * 60 * 1000 // 5 minutes
    });

    return valid;
  } catch (error) {
    logger.error('Tenant validation failed', { businessId, error });
    return false;
  }
}

/**
 * Extracts and validates JWT from Authorization header
 */
async function extractJWT(c: Context): Promise<JWTPayload | null> {
  const authHeader = c.req.header('Authorization');

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }

  const token = authHeader.substring(7);

  try {
    // Get JWT secret from environment
    const jwtSecret = c.env.JWT_SECRET;
    if (!jwtSecret) {
      throw new Error('JWT_SECRET not configured');
    }

    // Verify and decode token
    const payload = await verify(token, jwtSecret);

    // Validate payload structure
    const validated = JWTPayloadSchema.parse(payload);

    // Check token expiration
    if (validated.exp < Math.floor(Date.now() / 1000)) {
      throw new AppError('Token expired', 401, 'TOKEN_EXPIRED');
    }

    // Check if token is blacklisted (if using token revocation)
    if (validated.jti) {
      const blacklisted = await c.env.KV_SESSION?.get(`blacklist:${validated.jti}`);
      if (blacklisted) {
        throw new AppError('Token revoked', 401, 'TOKEN_REVOKED');
      }
    }

    return validated;
  } catch (error: any) {
    logger.warn('JWT validation failed', {
      error: error.message,
      ip: c.req.header('CF-Connecting-IP')
    });
    return null;
  }
}

/**
 * Main tenant isolation middleware
 */
export async function tenantIsolationMiddleware(c: Context, next: Next) {
  const startTime = Date.now();

  try {
    // Set security headers
    Object.entries(SECURITY_HEADERS).forEach(([key, value]) => {
      c.header(key, value);
    });

    // Extract JWT payload
    const jwtPayload = await extractJWT(c);

    // Check if authentication is required for this route
    const publicRoutes = ['/health', '/api/auth/login', '/api/auth/register', '/api/auth/refresh'];
    const isPublicRoute = publicRoutes.some(route => c.req.path.startsWith(route));

    if (!isPublicRoute && !jwtPayload) {
      throw new AppError('Authentication required', 401, 'AUTH_REQUIRED');
    }

    // If authenticated, set up secure database context
    if (jwtPayload) {
      // Validate tenant exists and is active
      const tenantValid = await validateTenant(jwtPayload.businessId, c.env.DB_MAIN);

      if (!tenantValid) {
        throw new AppError('Invalid or inactive tenant', 403, 'INVALID_TENANT');
      }

      // Create security config
      const securityConfig: SecurityConfig = {
        businessId: jwtPayload.businessId,
        userId: jwtPayload.sub,
        role: jwtPayload.role,
        tenantId: jwtPayload.tenantId,
        enforceRLS: true,
        auditLog: true,
        preventCrossTenant: true
      };

      // Create secure database instance
      const secureDb = createSecureDatabase(c.env.DB_MAIN, securityConfig);

      // Attach to context for use in routes
      c.set('secureDb', secureDb);
      c.set('userId', jwtPayload.sub);
      c.set('businessId', jwtPayload.businessId);
      c.set('userRole', jwtPayload.role);
      c.set('permissions', jwtPayload.permissions || []);

      // Log successful authentication
      logger.info('Request authenticated', {
        userId: jwtPayload.sub,
        businessId: jwtPayload.businessId,
        role: jwtPayload.role,
        path: c.req.path,
        method: c.req.method,
        ip: c.req.header('CF-Connecting-IP')
      });
    }

    // Validate request body for dangerous payloads
    if (c.req.method === 'POST' || c.req.method === 'PUT' || c.req.method === 'PATCH') {
      try {
        const body = await c.req.json();
        validateRequestBody(body);
      } catch (error) {
        // Body parsing failed or validation failed
        if (error instanceof AppError) {
          throw error;
        }
        // Continue without body validation for non-JSON requests
      }
    }

    // Add request ID for tracing
    const requestId = c.req.header('X-Request-ID') || crypto.randomUUID();
    c.header('X-Request-ID', requestId);
    c.set('requestId', requestId);

    // Continue to next middleware/handler
    await next();

    // Log request completion
    const duration = Date.now() - startTime;
    if (duration > 1000) {
      logger.warn('Slow request detected', {
        path: c.req.path,
        method: c.req.method,
        duration,
        userId: c.get('userId'),
        businessId: c.get('businessId')
      });
    }

  } catch (error: any) {
    // Log security errors
    logger.error('Tenant isolation middleware error', {
      error: error.message,
      path: c.req.path,
      method: c.req.method,
      ip: c.req.header('CF-Connecting-IP')
    });

    // Return appropriate error response
    if (error instanceof AppError) {
      return c.json(
        {
          error: error.message,
          code: error.code,
          requestId: c.get('requestId')
        },
        error.statusCode as any
      );
    }

    // Generic error for security
    return c.json(
      {
        error: 'Internal server error',
        requestId: c.get('requestId')
      },
      500
    );
  }
}

/**
 * Validates request body for dangerous payloads
 */
function validateRequestBody(body: any): void {
  if (!body || typeof body !== 'object') {
    return;
  }

  // Check for prototype pollution attempts
  const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
  const checkObject = (obj: any, path: string = ''): void => {
    for (const key in obj) {
      const fullPath = path ? `${path}.${key}` : key;

      if (dangerousKeys.includes(key)) {
        throw new AppError(`Dangerous key detected: ${fullPath}`, 400, 'DANGEROUS_PAYLOAD');
      }

      if (obj[key] && typeof obj[key] === 'object') {
        checkObject(obj[key], fullPath);
      }
    }
  };

  checkObject(body);

  // Check for excessively large payloads
  const jsonSize = JSON.stringify(body).length;
  if (jsonSize > 1024 * 1024) { // 1MB limit
    throw new AppError('Request body too large', 413, 'PAYLOAD_TOO_LARGE');
  }
}

/**
 * Permission checking middleware
 */
export function requirePermission(permission: string) {
  return async (c: Context, next: Next) => {
    const permissions = c.get('permissions') as string[] || [];
    const userRole = c.get('userRole') as string;

    // Owners have all permissions
    if (userRole === 'owner') {
      return next();
    }

    // Check specific permission
    if (!permissions.includes(permission) && !permissions.includes('*')) {
      logger.warn('Permission denied', {
        userId: c.get('userId'),
        businessId: c.get('businessId'),
        requiredPermission: permission,
        userPermissions: permissions
      });

      return c.json(
        {
          error: 'Insufficient permissions',
          requiredPermission: permission
        },
        403
      );
    }

    return next();
  };
}

/**
 * Role checking middleware
 */
export function requireRole(minRole: 'viewer' | 'user' | 'admin' | 'owner') {
  return async (c: Context, next: Next) => {
    const userRole = c.get('userRole') as string;

    const roleHierarchy: Record<string, number> = {
      viewer: 1,
      user: 2,
      admin: 3,
      owner: 4
    };

    const userLevel = roleHierarchy[userRole] || 0;
    const requiredLevel = roleHierarchy[minRole];

    if (userLevel < requiredLevel) {
      logger.warn('Role check failed', {
        userId: c.get('userId'),
        businessId: c.get('businessId'),
        userRole,
        requiredRole: minRole
      });

      return c.json(
        {
          error: 'Insufficient role',
          requiredRole: minRole,
          userRole
        },
        403
      );
    }

    return next();
  };
}

/**
 * Rate limiting per tenant
 */
export function tenantRateLimit(limit: number, window: number = 60) {
  return async (c: Context, next: Next) => {
    const businessId = c.get('businessId') as string;
    const userId = c.get('userId') as string;

    if (!businessId || !userId) {
      return next(); // Skip for unauthenticated requests
    }

    const key = `rate:${businessId}:${userId}:${c.req.path}`;
    const now = Date.now();
    const windowStart = now - (window * 1000);

    try {
      // Get rate limit data from KV
      const data = await c.env.KV_SESSION?.get(key);
      let requests: number[] = data ? JSON.parse(data) : [];

      // Filter out old requests
      requests = requests.filter((timestamp: number) => timestamp > windowStart);

      // Check if limit exceeded
      if (requests.length >= limit) {
        const resetTime = Math.min(...requests) + (window * 1000);
        const retryAfter = Math.ceil((resetTime - now) / 1000);

        logger.warn('Rate limit exceeded', {
          businessId,
          userId,
          path: c.req.path,
          limit,
          window
        });

        c.header('X-RateLimit-Limit', limit.toString());
        c.header('X-RateLimit-Remaining', '0');
        c.header('X-RateLimit-Reset', resetTime.toString());
        c.header('Retry-After', retryAfter.toString());

        return c.json(
          {
            error: 'Rate limit exceeded',
            retryAfter
          },
          429
        );
      }

      // Add current request
      requests.push(now);

      // Store updated data
      await c.env.KV_SESSION?.put(key, JSON.stringify(requests), {
        expirationTtl: window + 60 // Expire after window + buffer
      });

      // Set rate limit headers
      c.header('X-RateLimit-Limit', limit.toString());
      c.header('X-RateLimit-Remaining', (limit - requests.length).toString());
      c.header('X-RateLimit-Reset', (now + (window * 1000)).toString());

    } catch (error) {
      logger.error('Rate limiting error', { error, businessId, userId });
      // Continue on error to not block requests
    }

    return next();
  };
}

// Export middleware and helpers
export {
  validateTenant,
  extractJWT,
  validateRequestBody,
  type JWTPayload
};