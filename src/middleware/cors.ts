/**
 * Secure CORS Middleware for CoreFlow360 V4
 *
 * SECURITY FIXES:
 * - NO wildcard origins in production (CVSS 6.1)
 * - Environment-specific allowed origins
 * - Preflight request validation
 * - Credentials security with origin binding
 * - Methods and headers whitelisting
 *
 * @security-level HIGH
 * @compliance SOC2, OWASP
 */

export interface CORSConfig {
  allowedOrigins: string[];
  allowedMethods?: string[];
  allowedHeaders?: string[];
  exposedHeaders?: string[];
  maxAge?: number;
  credentials?: boolean;
  environment?: 'development' | 'staging' | 'production';
  preflightContinue?: boolean;
  optionsSuccessStatus?: number;
}

export interface CORSValidationResult {
  allowed: boolean;
  origin?: string;
  reason?: string;
  riskScore?: number;
}

/**
 * Default secure CORS configuration
 */
const DEFAULT_CORS_CONFIG: Required<CORSConfig> = {
  allowedOrigins: [],
  allowedMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'X-Business-ID',
    'X-User-ID',
    'X-Request-ID',
    'X-CSRF-Token',
    'Cache-Control'
  ],
  exposedHeaders: [
    'X-Request-ID',
    'X-Rate-Limit-Remaining',
    'X-Rate-Limit-Reset'
  ],
  maxAge: 86400, // 24 hours
  credentials: true,
  environment: 'production',
  preflightContinue: false,
  optionsSuccessStatus: 204
};

/**
 * Production-safe origin validation
 * SECURITY: Absolutely NO wildcards in production
 */
function validateOrigin(
  origin: string | null,
  allowedOrigins: string[],
  environment: string
): CORSValidationResult {
  // No origin header (same-origin request)
  if (!origin) {
    return { allowed: true, riskScore: 0 };
  }

  // SECURITY: Never allow wildcard in production
  if (environment === 'production' && allowedOrigins.includes('*')) {
    console.error('SECURITY VIOLATION: Wildcard origin detected in production');
    return {
      allowed: false,
      reason: 'Wildcard origins not allowed in production',
      riskScore: 90
    };
  }

  // Exact origin match
  if (allowedOrigins.includes(origin)) {
    return { allowed: true, origin, riskScore: 0 };
  }

  // Development environment localhost allowance
  if (environment === 'development') {
    const localhostPatterns = [
      /^https?:\/\/localhost(:\d+)?$/,
      /^https?:\/\/127\.0\.0\.1(:\d+)?$/,
      /^https?:\/\/\[::1\](:\d+)?$/
    ];

    if (localhostPatterns.some(pattern => pattern.test(origin))) {
      return {
        allowed: true,
        origin,
        reason: 'Development localhost',
        riskScore: 10
      };
    }
  }

  // Check for potential subdomain matching (if configured)
  const domainMatches = allowedOrigins.filter(allowed => {
    if (allowed.startsWith('*.')) {
      const domain = allowed.slice(2);
      return origin.endsWith(`.${domain}`) || origin === `https://${domain}`;
    }
    return false;
  });

  if (domainMatches.length > 0) {
    return {
      allowed: true,
      origin,
      reason: 'Subdomain match',
      riskScore: 5
    };
  }

  // Origin not allowed
  return {
    allowed: false,
    origin,
    reason: `Origin '${origin}' not in allowed list`,
    riskScore: 70
  };
}

/**
 * Validate CORS preflight request
 */
function validatePreflightRequest(
  request: Request,
  config: Required<CORSConfig>
): { valid: boolean; error?: string } {
  const method = request.headers.get('Access-Control-Request-Method');
  const headers = request.headers.get('Access-Control-Request-Headers');

  // Validate requested method
  if (method && !config.allowedMethods.includes(method.toUpperCase())) {
    return {
      valid: false,
      error: `Method '${method}' not allowed`
    };
  }

  // Validate requested headers
  if (headers) {
    const requestedHeaders = headers
      .split(',')
      .map(h => h.trim().toLowerCase());

    const allowedHeadersLower = config.allowedHeaders.map(h => h.toLowerCase());

    for (const header of requestedHeaders) {
      if (!allowedHeadersLower.includes(header)) {
        return {
          valid: false,
          error: `Header '${header}' not allowed`
        };
      }
    }
  }

  return { valid: true };
}

/**
 * Generate CORS headers based on validation result
 */
function generateCORSHeaders(
  validationResult: CORSValidationResult,
  config: Required<CORSConfig>,
  request: Request
): Record<string, string> {
  const headers: Record<string, string> = {};

  if (!validationResult.allowed) {
    // Return minimal headers for rejected requests
    headers['Access-Control-Allow-Origin'] = 'null';
    return headers;
  }

  // Set allowed origin
  headers['Access-Control-Allow-Origin'] = validationResult.origin || 'null';

  // Set allowed methods
  headers['Access-Control-Allow-Methods'] = config.allowedMethods.join(', ');

  // Set allowed headers
  headers['Access-Control-Allow-Headers'] = config.allowedHeaders.join(', ');

  // Set exposed headers
  if (config.exposedHeaders.length > 0) {
    headers['Access-Control-Expose-Headers'] = config.exposedHeaders.join(', ');
  }

  // Set max age for preflight caching
  headers['Access-Control-Max-Age'] = config.maxAge.toString();

  // Set credentials (only with specific origins, never with wildcard)
  if (config.credentials && validationResult.origin && validationResult.origin !== 'null') {
    headers['Access-Control-Allow-Credentials'] = 'true';
  }

  // Add Vary header for proper caching
  headers['Vary'] = 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers';

  return headers;
}

/**
 * Main CORS middleware function
 */
export async function handleCORS(
  request: Request,
  config: Partial<CORSConfig> = {}
): Promise<{
  headers: Record<string, string>;
  shouldContinue: boolean;
  response?: Response;
}> {
  const fullConfig = { ...DEFAULT_CORS_CONFIG, ...config };
  const origin = request.headers.get('Origin');
  const method = request.method.toUpperCase();

  // Validate origin
  const validationResult = validateOrigin(
    origin,
    fullConfig.allowedOrigins,
    fullConfig.environment
  );

  // Generate base CORS headers
  const corsHeaders = generateCORSHeaders(validationResult, fullConfig, request);

  // Handle preflight requests (OPTIONS)
  if (method === 'OPTIONS') {
    const preflightValidation = validatePreflightRequest(request, fullConfig);

    if (!preflightValidation.valid) {
      return {
        headers: { 'Access-Control-Allow-Origin': 'null' },
        shouldContinue: false,
        response: new Response(preflightValidation.error, {
          status: 400,
          headers: {
            'Content-Type': 'text/plain',
            'Access-Control-Allow-Origin': 'null'
          }
        })
      };
    }

    // Return successful preflight response
    return {
      headers: corsHeaders,
      shouldContinue: !fullConfig.preflightContinue,
      response: new Response(null, {
        status: fullConfig.optionsSuccessStatus,
        headers: corsHeaders
      })
    };
  }

  // For actual requests, check if origin is allowed
  if (!validationResult.allowed) {
    return {
      headers: { 'Access-Control-Allow-Origin': 'null' },
      shouldContinue: false,
      response: new Response('CORS policy violation', {
        status: 403,
        headers: {
          'Content-Type': 'text/plain',
          'Access-Control-Allow-Origin': 'null'
        }
      })
    };
  }

  // Origin is allowed, continue with request
  return {
    headers: corsHeaders,
    shouldContinue: true
  };
}

/**
 * CORS middleware factory
 */
export function createCORSMiddleware(config: Partial<CORSConfig> = {}) {
  return async (request: Request): Promise<{
    headers: Record<string, string>;
    response?: Response;
  }> => {
    const result = await handleCORS(request, config);

    if (result.response) {
      return {
        headers: result.headers,
        response: result.response
      };
    }

    return {
      headers: result.headers
    };
  };
}

/**
 * Validate CORS configuration for security issues
 */
export function validateCORSConfig(
  config: Partial<CORSConfig>
): { valid: boolean; errors: string[]; warnings: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Check for wildcard in production
  if (config.environment === 'production' && config.allowedOrigins?.includes('*')) {
    errors.push('Wildcard origins not allowed in production environment');
  }

  // Check for credentials with wildcard
  if (config.credentials && config.allowedOrigins?.includes('*')) {
    errors.push('Credentials cannot be used with wildcard origins');
  }

  // Check for insecure origins in production
  if (config.environment === 'production') {
    const insecureOrigins = config.allowedOrigins?.filter(origin =>
      origin.startsWith('http://') && !origin.includes('localhost')
    ) || [];

    if (insecureOrigins.length > 0) {
      warnings.push(
        `Insecure HTTP origins in production: ${insecureOrigins.join(', ')}`
      );
    }
  }

  // Check for overly permissive methods
  const dangerousMethods = ['TRACE', 'TRACK'];
  const hasDangerousMethods = config.allowedMethods?.some(method =>
    dangerousMethods.includes(method.toUpperCase())
  );

  if (hasDangerousMethods) {
    warnings.push('Potentially dangerous HTTP methods detected (TRACE, TRACK)');
  }

  // Check max age
  if (config.maxAge && config.maxAge > 86400) {
    warnings.push('Max age greater than 24 hours may cause caching issues');
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings
  };
}

/**
 * Environment-specific CORS configurations
 */
export const CORS_CONFIGURATIONS = {
  development: {
    allowedOrigins: [
      'http://localhost:3000',
      'http://localhost:3001',
      'http://127.0.0.1:3000',
      'https://localhost:3000'
    ],
    credentials: true,
    environment: 'development' as const
  },

  staging: {
    allowedOrigins: [
      'https://staging-app.coreflow360.com',
      'https://staging-admin.coreflow360.com'
    ],
    credentials: true,
    environment: 'staging' as const
  },

  production: {
    allowedOrigins: [
      'https://app.coreflow360.com',
      'https://admin.coreflow360.com',
      'https://dashboard.coreflow360.com'
    ],
    credentials: true,
    environment: 'production' as const,
    maxAge: 86400
  }
};

/**
 * Export all CORS utilities
 */
export {
  validateOrigin,
  validatePreflightRequest,
  generateCORSHeaders,
  DEFAULT_CORS_CONFIG
};