/**
 * Secure CORS Configuration for CoreFlow360 V4
 * Implements strict CORS policy following OWASP recommendations
 */

export interface CORSConfig {
  allowedOrigins: string[];
  allowedMethods: string[];
  allowedHeaders: string[];
  exposedHeaders: string[];
  maxAge: number;
  credentials: boolean;
}

/**
 * Production CORS configuration
 */
export const PRODUCTION_CORS_CONFIG: CORSConfig = {
  // Strict list of allowed origins - NEVER use '*' in production
  allowedOrigins: [
    'https://app.coreflow360.com',
    'https://dashboard.coreflow360.com',
    'https://api.coreflow360.com',
    'https://admin.coreflow360.com'
  ],

  // Allowed HTTP methods
  allowedMethods: [
    'GET',
    'POST',
    'PUT',
    'DELETE',
    'OPTIONS'
  ],

  // Allowed request headers
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-API-Key',
    'X-Request-ID',
    'X-Business-ID',
    'X-Session-ID',
    'X-CSRF-Token'
  ],

  // Headers exposed to the client
  exposedHeaders: [
    'X-Request-ID',
    'X-RateLimit-Limit',
    'X-RateLimit-Remaining',
    'X-RateLimit-Reset',
    'X-Response-Time'
  ],

  // Preflight cache duration (24 hours)
  maxAge: 86400,

  // Allow credentials (cookies, auth headers)
  credentials: true
};

/**
 * Staging CORS configuration
 */
export const STAGING_CORS_CONFIG: CORSConfig = {
  allowedOrigins: [
    'https://staging-app.coreflow360.com',
    'https://staging-dashboard.coreflow360.com',
    'https://staging-api.coreflow360.com'
  ],
  allowedMethods: PRODUCTION_CORS_CONFIG.allowedMethods,
  allowedHeaders: PRODUCTION_CORS_CONFIG.allowedHeaders,
  exposedHeaders: PRODUCTION_CORS_CONFIG.exposedHeaders,
  maxAge: 3600, // 1 hour for staging
  credentials: true
};

/**
 * Development CORS configuration
 */
export const DEVELOPMENT_CORS_CONFIG: CORSConfig = {
  allowedOrigins: [
    'http://localhost:3000',
    'http://localhost:5173',
    'http://localhost:8787',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5173',
    'http://127.0.0.1:8787'
  ],
  allowedMethods: PRODUCTION_CORS_CONFIG.allowedMethods,
  allowedHeaders: [...PRODUCTION_CORS_CONFIG.allowedHeaders, 'X-Debug-Mode'],
  exposedHeaders: [...PRODUCTION_CORS_CONFIG.exposedHeaders, 'X-Debug-Info'],
  maxAge: 300, // 5 minutes for development
  credentials: true
};

/**
 * CORS Manager class for handling CORS headers
 */
export class CORSManager {
  private config: CORSConfig;
  private environment: string;

  constructor(environment: string = 'production') {
    this.environment = environment;
    this.config = this.getConfigForEnvironment(environment);
  }

  /**
   * Get CORS configuration based on environment
   */
  private getConfigForEnvironment(env: string): CORSConfig {
    switch (env.toLowerCase()) {
      case 'development':
      case 'dev':
        return DEVELOPMENT_CORS_CONFIG;
      case 'staging':
      case 'stage':
        return STAGING_CORS_CONFIG;
      case 'production':
      case 'prod':
      default:
        return PRODUCTION_CORS_CONFIG;
    }
  }

  /**
   * Check if origin is allowed
   */
  isOriginAllowed(origin: string | null): boolean {
    if (!origin) return false;

    // Exact match
    if (this.config.allowedOrigins.includes(origin)) {
      return true;
    }

    // Check for subdomain wildcards (if configured)
    // For example: *.coreflow360.com
    for (const allowedOrigin of this.config.allowedOrigins) {
      if (allowedOrigin.startsWith('*.')) {
        const domain = allowedOrigin.substring(2);
        if (origin.endsWith(domain)) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Handle preflight OPTIONS request
   */
  handlePreflight(request: Request): Response {
    const origin = request.headers.get('Origin');
    const requestedMethod = request.headers.get('Access-Control-Request-Method');
    const requestedHeaders = request.headers.get('Access-Control-Request-Headers');

    // Check if origin is allowed
    if (!this.isOriginAllowed(origin)) {
      return new Response('CORS policy: Origin not allowed', { status: 403 });
    }

    // Check if method is allowed
    if (requestedMethod && !this.config.allowedMethods.includes(requestedMethod)) {
      return new Response('CORS policy: Method not allowed', { status: 403 });
    }

    // Check if headers are allowed
    if (requestedHeaders) {
      const headers = requestedHeaders.split(',').map(h => h.trim());
      const invalidHeaders = headers.filter(h =>
        !this.config.allowedHeaders.some(allowed =>
          allowed.toLowerCase() === h.toLowerCase()
        )
      );

      if (invalidHeaders.length > 0) {
        return new Response(`CORS policy: Headers not allowed: ${invalidHeaders.join(', ')}`, {
          status: 403
        });
      }
    }

    // Return successful preflight response
    return new Response(null, {
      status: 204,
      headers: this.getCORSHeaders(origin!)
    });
  }

  /**
   * Get CORS headers for a request
   */
  getCORSHeaders(origin: string): Record<string, string> {
    const headers: Record<string, string> = {};

    // Only set origin if it's allowed
    if (this.isOriginAllowed(origin)) {
      headers['Access-Control-Allow-Origin'] = origin;
    } else {
      // For security, don't reveal allowed origins in error
      return {};
    }

    // Set other CORS headers
    headers['Access-Control-Allow-Methods'] = this.config.allowedMethods.join(', ');
    headers['Access-Control-Allow-Headers'] = this.config.allowedHeaders.join(', ');
    headers['Access-Control-Expose-Headers'] = this.config.exposedHeaders.join(', ');
    headers['Access-Control-Max-Age'] = this.config.maxAge.toString();

    if (this.config.credentials) {
      headers['Access-Control-Allow-Credentials'] = 'true';
    }

    // Add Vary header to prevent cache poisoning
    headers['Vary'] = 'Origin';

    return headers;
  }

  /**
   * Apply CORS headers to a response
   */
  applyCORSHeaders(response: Response, request: Request): Response {
    const origin = request.headers.get('Origin');

    if (!origin) {
      return response;
    }

    const corsHeaders = this.getCORSHeaders(origin);

    // If no CORS headers (origin not allowed), return original response
    if (Object.keys(corsHeaders).length === 0) {
      return response;
    }

    // Clone response and add CORS headers
    const newHeaders = new Headers(response.headers);
    Object.entries(corsHeaders).forEach(([key, value]) => {
      newHeaders.set(key, value);
    });

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders
    });
  }

  /**
   * Validate CORS for WebSocket upgrade
   */
  validateWebSocketOrigin(origin: string | null): boolean {
    // WebSocket connections must have a valid origin
    if (!origin) return false;

    // Use same origin validation as HTTP
    return this.isOriginAllowed(origin);
  }

  /**
   * Get security headers (beyond CORS)
   */
  getSecurityHeaders(): Record<string, string> {
    return {
      // Prevent clickjacking
      'X-Frame-Options': 'DENY',

      // Prevent MIME type sniffing
      'X-Content-Type-Options': 'nosniff',

      // Enable XSS protection
      'X-XSS-Protection': '1; mode=block',

      // Referrer policy
      'Referrer-Policy': 'strict-origin-when-cross-origin',

      // Content Security Policy
      'Content-Security-Policy': this.getCSPHeader(),

      // Strict Transport Security (HSTS)
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',

      // Permissions Policy (formerly Feature Policy)
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), interest-cohort=()'
    };
  }

  /**
   * Generate Content Security Policy header
   */
  private getCSPHeader(): string {
    const policies = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "font-src 'self' data:",
      "connect-src 'self' https://api.coreflow360.com wss://ws.coreflow360.com",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "upgrade-insecure-requests"
    ];

    // Add reporting in production
    if (this.environment === 'production') {
      policies.push("report-uri https://api.coreflow360.com/csp-report");
    }

    return policies.join('; ');
  }

  /**
   * Check if request has valid CSRF token
   */
  validateCSRFToken(request: Request, sessionToken: string): boolean {
    const csrfToken = request.headers.get('X-CSRF-Token');

    if (!csrfToken) {
      return false;
    }

    // Validate CSRF token against session
    // In production, implement proper CSRF token validation
    return this.validateToken(csrfToken, sessionToken);
  }

  /**
   * Validate a CSRF token
   */
  private validateToken(token: string, sessionToken: string): boolean {
    // Simple validation for now - implement proper CSRF in production
    return token === sessionToken;
  }
}

/**
 * Middleware function for Express/Hono/etc
 */
export function corsMiddleware(env: string = 'production') {
  const corsManager = new CORSManager(env);

  return async (request: Request): Promise<Response | null> => {
    // Handle preflight
    if (request.method === 'OPTIONS') {
      return corsManager.handlePreflight(request);
    }

    return null;
  };
}

/**
 * Export configurations and manager
 */
export default {
  CORSManager,
  corsMiddleware,
  PRODUCTION_CORS_CONFIG,
  STAGING_CORS_CONFIG,
  DEVELOPMENT_CORS_CONFIG
};