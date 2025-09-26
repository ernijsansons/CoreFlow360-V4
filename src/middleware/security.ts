// src/middleware/security.ts
import type { ExecutionContext } from '../cloudflare/types/cloudflare';
import { jwtVerify, createRemoteJWKSet, type JWTPayload } from 'jose';
import { authenticator, totp } from 'otplib';

export interface SecurityConfig {
  enableHSTS?: boolean;
  hstsMaxAge?: number;
  allowedOrigins?: string[];
  allowedFrameAncestors?: string[];
  customCSP?: string;
  reportUri?: string;
  environment?: string;
}

export async function addSecurityHeaders(
  response: Response,
  config: SecurityConfig = {}
): Promise<Response> {
  const headers = new Headers(response.headers);

  // Core security headers
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', (config.allowedFrameAncestors?.length || config.allowedOrigins?.length) ? 'SAMEORIGIN' : 'DENY');
  headers.set('X-XSS-Protection', '1; mode=block');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Permissions Policy - Restrictive by default
  headers.set('Permissions-Policy', [
    'camera=()',
    'microphone=()',
    'geolocation=()',
    'payment=()',
    'usb=()',
    'magnetometer=()',
    'gyroscope=()',
    'accelerometer=()',
    'ambient-light-sensor=()',
    'autoplay=()',
    'encrypted-media=()',
    'fullscreen=()',
    'picture-in-picture=()'
  ].join(', '));

  // HSTS - Only for HTTPS
  if (config.enableHSTS !== false) {
    const maxAge = config.hstsMaxAge || 31536000; // 1 year
    headers.set('Strict-Transport-Security',
      `max-age=${maxAge}; includeSubDomains; preload`);
  }

  // Content Security Policy
  const csp = config.customCSP || buildCSP(config);
  headers.set('Content-Security-Policy', csp);

  // Report-Only CSP for testing in development
  if (config.environment === 'development' && config.reportUri) {
    headers.set('Content-Security-Policy-Report-Only', csp);
  }

  // Additional security headers
  headers.set('Cross-Origin-Embedder-Policy', 'require-corp');
  headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  headers.set('Cross-Origin-Resource-Policy', 'same-origin');

  // Remove potentially sensitive headers
  headers.delete('Server');
  headers.delete('X-Powered-By');

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

export function buildCSP(config: SecurityConfig): string {
  const policy = {
    'default-src': ["'self'"],
    'script-src': [
      "'self'",
      "'unsafe-inline'", // Required for some functionality
      'https://cdn.cloudflare.com',
      'https://challenges.cloudflare.com'
    ],
    'style-src': [
      "'self'",
      "'unsafe-inline'", // Required for dynamic styles
      'https://fonts.googleapis.com'
    ],
    'img-src': [
      "'self'",
      'data:',
      'https:',
      'blob:'
    ],
    'font-src': [
      "'self'",
      'https://fonts.gstatic.com'
    ],
    'connect-src': [
      "'self'",
      'https://api.anthropic.com',
      'https://api.openai.com',
      'https://api.cloudflare.com',
      'wss:', // For WebSocket connections
      'https:'
    ],
    'media-src': ["'self'", 'https:'],
    'object-src': ["'none'"],
    'base-uri': ["'self'"],
    'form-action': ["'self'"],
    'frame-ancestors': config.allowedFrameAncestors || ["'none'"],
    'upgrade-insecure-requests': [],
    'block-all-mixed-content': []
  };

  // Add report URI if configured
  if (config.reportUri) {
    (policy as any)['report-uri'] = [config.reportUri];
  }

  // Convert policy object to CSP string
  return Object.entries(policy)
    .map(([directive, sources]) =>
      sources.length ? `${directive} ${sources.join(' ')}` : directive
    )
    .join('; ');
}

export async function validateCSP(
  request: Request,
  reportUri: string
): Promise<void> {
  // Process CSP violation reports
  if (request.method === 'POST' && request.url.includes('/csp-report')) {
    try {
      const report = await request.json();

      // Send to monitoring service
      await fetch(reportUri, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'csp-violation',
          report,
          timestamp: new Date().toISOString(),
          userAgent: request.headers.get('User-Agent')
        })
      });
    } catch (error) {
    }
  }
}

export function getCorsHeaders(
  request: Request,
  allowedOrigins: string[] = [],
  allowCredentials = true,
  environment = 'production'
): Record<string, string> {
  const origin = request.headers.get('Origin') || '';

  // Validate origin
  let allowedOrigin = 'null';

  if (allowedOrigins.length > 0) {
    // Check if origin is in allowed list
    if (allowedOrigins.includes(origin)) {
      allowedOrigin = origin;
    } else if (environment === 'development') {
      // More permissive in development for localhost
      if (origin.startsWith('http://localhost:') || origin.startsWith('https://localhost:')) {
        allowedOrigin = origin;
      }
    }
  }

  const headers: Record<string, string> = {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'X-Business-ID',
      'X-User-ID',
      'X-Request-ID',
      'X-API-Key'
    ].join(', '),
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };

  if (allowCredentials && allowedOrigin !== 'null') {
    headers['Access-Control-Allow-Credentials'] = 'true';
  }

  return headers;
}

// SECURITY FIX: Secure CORS headers helper (fixes wildcard vulnerability)
export function corsHeaders(origin?: string, allowedOrigins: string[] = []): HeadersInit {
  // SECURITY: Never use wildcard (*) in production
  let allowedOrigin = 'null';
  
  if (origin && allowedOrigins.includes(origin)) {
    allowedOrigin = origin;
  } else if (origin && origin.startsWith('https://') && 
             (origin.includes('coreflow360.com') || origin.includes('localhost'))) {
    // Only allow known secure origins
    allowedOrigin = origin;
  }
  
  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Business-ID, X-User-ID, X-Request-ID',
    'Access-Control-Max-Age': '86400',
    'Access-Control-Allow-Credentials': allowedOrigin !== 'null' ? 'true' : 'false'
  };
}

// Validate CORS request
export function validateCorsRequest(
  request: Request,
  allowedOrigins: string[],
  environment = 'production'
): { allowed: boolean; reason?: string } {
  const origin = request.headers.get('Origin') || '';

  // Allow same-origin requests (no Origin header)
  if (!origin) {
    return { allowed: true };
  }

  // Check against allowed origins
  if (allowedOrigins.includes(origin)) {
    return { allowed: true };
  }

  // Development mode is more permissive
  if (environment === 'development') {
    if (origin.startsWith('http://localhost:') || origin.startsWith('https://localhost:')) {
      return { allowed: true };
    }
  }

  return {
    allowed: false,
    reason: `Origin ${origin} not allowed`
  };
}

export interface RateLimitConfig {
  requests: number;
  window: number; // seconds
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
  keyGenerator?: (request: Request) => string;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetTime: number;
  totalHits: number;
}

export async function advancedRateLimit(
  request: Request,
  kv: KVNamespace,
  config: RateLimitConfig
): Promise<RateLimitResult> {
  const { requests, window, keyGenerator } = config;

  // Generate key - can be IP, user ID, API key, etc.
  const key = keyGenerator
    ? keyGenerator(request)
    : `rate_limit:${request.headers.get('CF-Connecting-IP') || 'unknown'}`;

  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - window;

  try {
    // Get current window data
    const windowKey = `${key}:${Math.floor(now / window)}`;
    const currentData = await kv.get(windowKey);
    const currentCount = currentData ? parseInt(currentData) : 0;

    if (currentCount >= requests) {
      return {
        allowed: false,
        remaining: 0,
        resetTime: (Math.floor(now / window) + 1) * window,
        totalHits: currentCount
      };
    }

    // Increment counter
    await kv.put(windowKey, (currentCount + 1).toString(), {
      expirationTtl: window * 2 // Extra buffer for cleanup
    });

    return {
      allowed: true,
      remaining: requests - currentCount - 1,
      resetTime: (Math.floor(now / window) + 1) * window,
      totalHits: currentCount + 1
    };
  } catch (error) {
    // SECURITY FIX: Fail closed - deny request if rate limiting fails (fixes fail-open vulnerability)
    console.error('Rate limiting error - failing closed:', error);
    return {
      allowed: false,
      remaining: 0,
      resetTime: now + window,
      totalHits: requests // Assume limit exceeded on error
    };
  }
}

export async function rateLimitByIP(
  request: Request,
  kv: KVNamespace,
  limit = 100,
  window = 60
): Promise<RateLimitResult> {
  return advancedRateLimit(request, kv, {
    requests: limit,
    window,
    keyGenerator: (req) => `ip:${req.headers.get('CF-Connecting-IP') || 'unknown'}`
  });
}

export async function rateLimitByUser(
  request: Request,
  kv: KVNamespace,
  userId: string,
  limit = 1000,
  window = 3600 // 1 hour
): Promise<RateLimitResult> {
  return advancedRateLimit(request, kv, {
    requests: limit,
    window,
    keyGenerator: () => `user:${userId}`
  });
}

export async function rateLimitByAPIKey(
  request: Request,
  kv: KVNamespace,
  apiKey: string,
  limit = 10000,
  window = 3600 // 1 hour
): Promise<RateLimitResult> {
  return advancedRateLimit(request, kv, {
    requests: limit,
    window,
    keyGenerator: () => `api_key:${apiKey}`
  });
}

// Exponential backoff for repeated violations
export async function getBackoffDelay(
  violationKey: string,
  kv: KVNamespace
): Promise<number> {
  const key = `backoff:${violationKey}`;
  const violations = await kv.get(key);
  const count = violations ? parseInt(violations) : 0;

  // Exponential backoff: 1, 2, 4, 8, 16, 32, 60 (max 1 minute)
  const delaySeconds = Math.min(Math.pow(2, count), 60);

  // Record this violation
  await kv.put(key, (count + 1).toString(), {
    expirationTtl: 3600 // Reset after 1 hour
  });

  return delaySeconds;
}

export function addRateLimitHeaders(
  response: Response,
  rateLimit: RateLimitResult,
  limit?: number
): Response {
  const headers = new Headers(response.headers);

  headers.set('X-RateLimit-Limit', limit?.toString() || '100');
  headers.set('X-RateLimit-Remaining', rateLimit.remaining.toString());
  headers.set('X-RateLimit-Reset', rateLimit.resetTime.toString());
  headers.set('X-RateLimit-Used', rateLimit.totalHits.toString());

  if (!rateLimit.allowed) {
    const retryAfter = rateLimit.resetTime - Math.floor(Date.now() / 1000);
    headers.set('Retry-After', Math.max(retryAfter, 1).toString());
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

export async function validateJWT(
  token: string,
  secret: string | Uint8Array,
  algorithm = 'HS256'
): Promise<{ valid: boolean; payload?: JWTPayload; error?: string }> {
  try {
    // Convert string secret to Uint8Array for HMAC algorithms
    const secretKey = typeof secret === 'string'
      ? new TextEncoder().encode(secret)
      : secret;

    // Verify JWT with proper cryptographic signature verification
    const { payload } = await jwtVerify(token, secretKey, {
      algorithms: [algorithm],
      clockTolerance: 5, // Allow 5 seconds clock skew
    });

    // Additional payload validation
    if (!payload.sub) {
      return { valid: false, error: 'Missing subject claim' };
    }

    if (!payload.iat) {
      return { valid: false, error: 'Missing issued at claim' };
    }

    // Check for suspicious token age (over 24 hours)
    const tokenAge = Date.now() / 1000 - (payload.iat as number);
    if (tokenAge > 86400) { // 24 hours
      return { valid: false, error: 'Token too old' };
    }

    return {
      valid: true,
      payload
    };
  } catch (error) {
    // Handle specific JWT errors
    if (error instanceof Error) {
      if (error.message.includes('signature')) {
        return { valid: false, error: 'Invalid signature' };
      }
      if (error.message.includes('expired')) {
        return { valid: false, error: 'Token expired' };
      }
      if (error.message.includes('before')) {
        return { valid: false, error: 'Token not yet valid' };
      }
    }

    return {
      valid: false,
      error: 'Token validation failed'
    };
  }
}

// JWT blacklist for revoked tokens
const JWT_BLACKLIST_KEY_PREFIX = 'jwt_blacklist:';

export async function revokeJWT(
  jti: string,
  kv: KVNamespace,
  expirationTtl = 86400 // 24 hours
): Promise<void> {
  const key = `${JWT_BLACKLIST_KEY_PREFIX}${jti}`;
  await kv.put(key, 'revoked', { expirationTtl });
}

export async function isJWTRevoked(
  jti: string,
  kv: KVNamespace
): Promise<boolean> {
  const key = `${JWT_BLACKLIST_KEY_PREFIX}${jti}`;
  const value = await kv.get(key);
  return value === 'revoked';
}

// Enhanced JWT validation with blacklist check
export async function validateJWTWithBlacklist(
  token: string,
  secret: string | Uint8Array,
  kv: KVNamespace,
  algorithm = 'HS256'
): Promise<{ valid: boolean; payload?: JWTPayload; error?: string }> {
  const result = await validateJWT(token, secret, algorithm);

  if (!result.valid || !result.payload) {
    return result;
  }

  // Check if token is revoked
  const jti = result.payload.jti as string;
  if (jti && await isJWTRevoked(jti, kv)) {
    return { valid: false, error: 'Token revoked' };
  }

  return result;
}

export interface SanitizationOptions {
  maxLength?: number;
  allowHtml?: boolean;
  stripTags?: boolean;
  allowedTags?: string[];
  removeNullBytes?: boolean;
  normalizeWhitespace?: boolean;
}

export function sanitizeInput(
  input: string,
  options: SanitizationOptions = {}
): string {
  if (typeof input !== 'string') {
    return '';
  }

  const {
    maxLength = 1000,
    allowHtml = false,
    stripTags = true,
    allowedTags = [],
    removeNullBytes = true,
    normalizeWhitespace = true
  } = options;

  let sanitized = input;

  // Remove null bytes and other control characters
  if (removeNullBytes) {
    sanitized = sanitized.replace(/[\x00-\x1F\x7F-\x9F]/g, '');
  }

  // Normalize whitespace
  if (normalizeWhitespace) {
    sanitized = sanitized.replace(/\s+/g, ' ').trim();
  }

  // Handle HTML
  if (!allowHtml) {
    // If HTML is not allowed, strip all tags regardless of stripTags setting
    sanitized = sanitized.replace(/<[^>]*>/g, '');

    // HTML entity encoding for remaining special characters
    sanitized = sanitized.replace(/[<>\"'&]/g, (char) => {
      const entities: Record<string, string> = {
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '&': '&amp;'
      };
      return entities[char] || char;
    });
  } else if (stripTags) {
    if (allowedTags.length > 0) {
      // Strip all tags except allowed ones
      const regex = new RegExp(`<(?!/?(?:${allowedTags.join('|')})\\b)[^>]*>`, 'gi');
      sanitized = sanitized.replace(regex, '');
    } else {
      // Strip all HTML tags
      sanitized = sanitized.replace(/<[^>]*>/g, '');
    }
  }

  // SECURITY FIX: Enhanced XSS pattern detection (fixes CVSS 7.5 vulnerability)
  // Remove JavaScript event handlers and dangerous patterns
  const xssPatterns = [
    // JavaScript protocols
    /javascript\s*:/gi,
    /vbscript\s*:/gi,
    /data\s*:\s*text\/html/gi,
    
    // Event handlers (comprehensive list)
    /on\w+\s*=/gi,
    /on(click|load|error|focus|blur|change|submit|reset|select|scroll|resize|mouseover|mouseout|mousedown|mouseup|mousemove|keydown|keyup|keypress|abort|beforeunload|unload)\s*=/gi,
    
    // Script-related patterns
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript\s*:/gi,
    /expression\s*\(/gi,
    /eval\s*\(/gi,
    /setTimeout\s*\(/gi,
    /setInterval\s*\(/gi,
    /Function\s*\(/gi,
    
    // CSS expressions
    /expression\s*\(/gi,
    /-moz-binding\s*:/gi,
    /behaviour\s*:/gi,
    
    // Data URIs that could contain scripts
    /data\s*:\s*text\/javascript/gi,
    /data\s*:\s*application\/javascript/gi,
    
    // Base64 encoded patterns that might hide scripts
    /data\s*:\s*.*base64.*script/gi,
    
    // Common XSS vectors
    /alert\s*\(/gi,
    /confirm\s*\(/gi,
    /prompt\s*\(/gi,
    /document\.(write|writeln|cookie|domain)/gi,
    /window\.(open|location|alert)/gi,
    
    // HTML5 event attributes
    /on(canplay|canplaythrough|durationchange|emptied|ended|loadeddata|loadedmetadata|pause|play|playing|progress|ratechange|seeked|seeking|stalled|suspend|timeupdate|volumechange|waiting|animationend|animationiteration|animationstart|transitionend)\s*=/gi,
    
    // Form-related events
    /on(autocomplete|input|invalid|search|formchange|forminput|formdata|reset|submit)\s*=/gi,
    
    // Drag and drop events
    /on(drag|dragend|dragenter|dragexit|dragleave|dragover|dragstart|drop)\s*=/gi,
    
    // Touch events
    /on(touchstart|touchend|touchmove|touchcancel)\s*=/gi,
    
    // Pointer events
    /on(pointerdown|pointerup|pointermove|pointerover|pointerout|pointerenter|pointerleave|pointercancel|gotpointercapture|lostpointercapture)\s*=/gi
  ];

  for (const pattern of xssPatterns) {
    sanitized = sanitized.replace(pattern, '');
  }

  // Limit length
  if (maxLength > 0) {
    sanitized = sanitized.slice(0, maxLength);
  }

  return sanitized;
}

// Specific sanitizers for different data types
export function sanitizeEmail(email: string): string {
  // Check for malicious patterns before sanitization
  if (email.includes('<script') || email.includes('javascript:') ||
      email.includes('onclick') || email.includes('onerror') ||
      email.includes('onload') || email.includes('alert(')) {
    return '';
  }

  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  const sanitized = sanitizeInput(email, { maxLength: 254, stripTags: true });

  return emailRegex.test(sanitized) ? sanitized : '';
}

export function sanitizePhoneNumber(phone: string): string {
  // Remove all non-numeric characters except +, spaces, hyphens, parentheses
  const sanitized = phone.replace(/[^\d\s\-\+\(\)]/g, '');
  return sanitized.slice(0, 20); // Max reasonable phone length
}

export function sanitizeUrl(url: string): string {
  try {
    const parsed = new URL(url);

    // Only allow http and https protocols
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return '';
    }

    // Basic domain validation
    if (!parsed.hostname || parsed.hostname.length > 253) {
      return '';
    }

    return parsed.toString();
  } catch {
    return '';
  }
}

export function sanitizeFilename(filename: string): string {
  return filename
    .replace(/[<>:"/\\|?*\x00-\x1f]/g, '') // Remove invalid file characters
    .replace(/^\.+/, '') // Remove leading dots
    .slice(0, 255); // Limit filename length
}

// SQL injection prevention
export function escapeSqlString(input: string): string {
  return input.replace(/'/g, "''").replace(/\\/g, '\\\\');
}

// Comprehensive XSS prevention
export function preventXSS(input: string): string {
  return sanitizeInput(input, {
    allowHtml: false,
    stripTags: true,
    removeNullBytes: true,
    normalizeWhitespace: true,
    maxLength: 10000
  });
}

// Content-Type validation
export function validateContentType(
  request: Request,
  allowedTypes: string[] = ['application/json']
): boolean {
  const contentType = request.headers.get('Content-Type');

  if (!contentType) {
    return false;
  }

  return allowedTypes.some(type =>
    contentType.toLowerCase().includes(type.toLowerCase())
  );
}

// Request body size validation
export function validateRequestSize(
  request: Request,
  maxSize = 1024 * 1024 // 1MB default
): boolean {
  const contentLength = request.headers.get('Content-Length');

  if (!contentLength) {
    return true; // Let the runtime handle it
  }

  const size = parseInt(contentLength, 10);
  return !isNaN(size) && size <= maxSize;
}

// Request validation middleware
export async function validateRequest(
  request: Request,
  options: {
    maxSize?: number;
    allowedContentTypes?: string[];
    requireAuth?: boolean;
    validateOrigin?: boolean;
  } = {}
): Promise<{ valid: boolean; error?: string }> {
  const {
    maxSize = 1024 * 1024,
    allowedContentTypes = ['application/json'],
    requireAuth = false,
    validateOrigin = true
  } = options;

  // Check request size
  if (!validateRequestSize(request, maxSize)) {
    return { valid: false, error: 'Request body too large' };
  }

  // Check content type for POST/PUT requests
  if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
    if (!validateContentType(request, allowedContentTypes)) {
      return { valid: false, error: 'Invalid content type' };
    }
  }

  // Check for suspicious activity
  const suspiciousCheck = detectSuspiciousActivity(request);
  if (suspiciousCheck.suspicious) {
    return { valid: false, error: `Suspicious activity: ${suspiciousCheck.reasons.join(', ')}` };
  }

  // Check authorization if required
  if (requireAuth) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return { valid: false, error: 'Missing or invalid authorization' };
    }
  }

  return { valid: true };
}

export function validateBusinessId(businessId: string): boolean {
  // Business ID validation
  const pattern = /^[a-zA-Z0-9_-]{3,50}$/;
  return pattern.test(businessId);
}

export function detectSuspiciousActivity(
  request: Request
): { suspicious: boolean; reasons: string[] } {
  const reasons: string[] = [];
  const userAgent = request.headers.get('User-Agent') || '';
  const url = new URL(request.url);

  // Check for suspicious patterns
  if (userAgent.length < 10 || userAgent.includes('bot') || userAgent.includes('curl')) {
    reasons.push('Suspicious user agent');
  }

  // Check for path traversal in the raw URL before normalization
  if (request.url.includes('../') || request.url.includes('..%2F') || 
      request.url.includes('%2E%2E%2F') || url.pathname.includes('..') || 
      url.pathname.includes('%')) {
    reasons.push('Path traversal attempt');
  }

  if (request.method === 'POST' && !request.headers.get('Content-Type')) {
    reasons.push('Missing content type');
  }

  // Check for SQL injection patterns in query parameters
  const queryString = url.search.toLowerCase();
  const sqlPatterns = ['union', 'select', 'drop', 'insert', 'delete', 'update'];
  if (sqlPatterns.some(pattern => queryString.includes(pattern))) {
    reasons.push('Potential SQL injection');
  }

  return {
    suspicious: reasons.length > 0,
    reasons
  };
}

// =====================================================
// COMPREHENSIVE AUDIT LOGGING
// =====================================================

export enum AuditEventType {
  LOGIN = 'user.login',
  LOGOUT = 'user.logout',
  LOGIN_FAILED = 'user.login_failed',
  PASSWORD_CHANGED = 'user.password_changed',
  MFA_ENABLED = 'user.mfa_enabled',
  MFA_DISABLED = 'user.mfa_disabled',
  MFA_VERIFIED = 'user.mfa_verified',
  MFA_FAILED = 'user.mfa_failed',
  SESSION_CREATED = 'session.created',
  SESSION_REVOKED = 'session.revoked',
  API_KEY_CREATED = 'api.key_created',
  API_KEY_REVOKED = 'api.key_revoked',
  API_KEY_USED = 'api.key_used',
  RATE_LIMIT_EXCEEDED = 'security.rate_limit_exceeded',
  SUSPICIOUS_ACTIVITY = 'security.suspicious_activity',
  PERMISSION_DENIED = 'security.permission_denied',
  DATA_ACCESS = 'data.access',
  DATA_CREATED = 'data.created',
  DATA_UPDATED = 'data.updated',
  DATA_DELETED = 'data.deleted',
  ADMIN_ACTION = 'admin.action',
  COMPLIANCE_VIOLATION = 'compliance.violation'
}

export enum AuditSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  eventType: AuditEventType;
  severity: AuditSeverity;
  userId?: string;
  businessId?: string;
  sessionId?: string;
  ipAddress?: string;
  userAgent?: string;
  resource?: string;
  action?: string;
  details: Record<string, any>;
  success: boolean;
  riskScore?: number;
  complianceFlags?: string[];
}

// Enhanced security event logging
export async function logSecurityEvent(
  event: string,
  details: any,
  analytics: AnalyticsEngineDataset
): Promise<void> {
  try {
    await analytics.writeDataPoint({
      indexes: ['security', event, details.severity || 'medium'],
      blobs: [
        JSON.stringify(details),
        details.ip || 'unknown',
        details.userAgent || 'unknown'
      ],
      doubles: [Date.now(), 1]
    });
  } catch (error) {
    // Silent fail for analytics
  }
}

// Comprehensive audit logging
export async function logAuditEvent(
  entry: Partial<AuditLogEntry>,
  kv: KVNamespace,
  analytics?: AnalyticsEngineDataset
): Promise<void> {
  const auditEntry: AuditLogEntry = {
    id: generateSessionId(), // Reuse session ID generation for unique IDs
    timestamp: new Date().toISOString(),
    eventType: entry.eventType || AuditEventType.DATA_ACCESS,
    severity: entry.severity || AuditSeverity.LOW,
    success: entry.success ?? true,
    details: entry.details || {},
    ...entry
  };

  try {
    // Store in KV for long-term retention
    const auditKey = `audit:${auditEntry.timestamp.slice(0, 10)}:${auditEntry.id}`;
    await kv.put(auditKey, JSON.stringify(auditEntry), {
      expirationTtl: 86400 * 365 * 7 // 7 years retention for compliance
    });

    // Also log to analytics for real-time monitoring
    if (analytics) {
      await analytics.writeDataPoint({
        indexes: [
          'audit',
          auditEntry.eventType,
          auditEntry.severity,
          auditEntry.businessId || 'system',
          auditEntry.success ? 'success' : 'failure'
        ],
        blobs: [
          JSON.stringify(auditEntry.details),
          auditEntry.ipAddress || 'unknown',
          auditEntry.userAgent || 'unknown',
          auditEntry.resource || 'unknown'
        ],
        doubles: [
          Date.now(),
          auditEntry.riskScore || 0,
          1 // count
        ]
      });
    }
  } catch (error) {
    // Critical: Audit logging should never fail silently in production
    console.error('Audit logging failed:', error);
  }
}

// Helper functions for common audit events
export async function logLoginAttempt(
  userId: string,
  businessId: string,
  success: boolean,
  ipAddress: string,
  userAgent: string,
  kv: KVNamespace,
  analytics?: AnalyticsEngineDataset,
  details: Record<string, any> = {}
): Promise<void> {
  await logAuditEvent({
    eventType: success ? AuditEventType.LOGIN : AuditEventType.LOGIN_FAILED,
    severity: success ? AuditSeverity.LOW : AuditSeverity.MEDIUM,
    userId,
    businessId,
    ipAddress,
    userAgent,
    success,
    riskScore: success ? 0 : 0.5,
    details: {
      loginMethod: details.loginMethod || 'password',
      mfaRequired: details.mfaRequired || false,
      ...details
    }
  }, kv, analytics);
}

export async function logDataAccess(
  userId: string,
  businessId: string,
  resource: string,
  action: string,
  success: boolean,
  kv: KVNamespace,
  analytics?: AnalyticsEngineDataset,
  details: Record<string, any> = {}
): Promise<void> {
  await logAuditEvent({
    eventType: AuditEventType.DATA_ACCESS,
    severity: AuditSeverity.LOW,
    userId,
    businessId,
    resource,
    action,
    success,
    riskScore: success ? 0 : 0.3,
    details
  }, kv, analytics);
}

export async function logSecurityViolation(
  eventType: AuditEventType,
  userId: string | undefined,
  businessId: string | undefined,
  ipAddress: string,
  userAgent: string,
  details: Record<string, any>,
  kv: KVNamespace,
  analytics?: AnalyticsEngineDataset
): Promise<void> {
  await logAuditEvent({
    eventType,
    severity: AuditSeverity.HIGH,
    userId,
    businessId,
    ipAddress,
    userAgent,
    success: false,
    riskScore: 0.8,
    complianceFlags: ['security_incident'],
    details
  }, kv, analytics);
}

export async function logAdminAction(
  adminUserId: string,
  businessId: string,
  action: string,
  targetUserId: string | undefined,
  success: boolean,
  kv: KVNamespace,
  analytics?: AnalyticsEngineDataset,
  details: Record<string, any> = {}
): Promise<void> {
  await logAuditEvent({
    eventType: AuditEventType.ADMIN_ACTION,
    severity: AuditSeverity.HIGH,
    userId: adminUserId,
    businessId,
    action,
    success,
    riskScore: 0.1,
    complianceFlags: ['admin_action'],
    details: {
      targetUserId,
      ...details
    }
  }, kv, analytics);
}

// Query audit logs (for compliance and investigation)
export async function queryAuditLogs(
  kv: KVNamespace,
  filters: {
    businessId?: string;
    userId?: string;
    eventType?: AuditEventType;
    startDate?: string;
    endDate?: string;
    severity?: AuditSeverity;
  },
  limit = 100
): Promise<AuditLogEntry[]> {
  const results: AuditLogEntry[] = [];

  // This is a simplified implementation
  // In production, you'd use a proper database with indexing
  const { keys } = await kv.list({
    prefix: 'audit:',
    limit: limit * 2 // Get more than needed for filtering
  });

  for (const key of keys) {
    try {
      const entryJson = await kv.get(key.name);
      if (entryJson) {
        const entry: AuditLogEntry = JSON.parse(entryJson);

        // Apply filters
        if (filters.businessId && entry.businessId !== filters.businessId) continue;
        if (filters.userId && entry.userId !== filters.userId) continue;
        if (filters.eventType && entry.eventType !== filters.eventType) continue;
        if (filters.severity && entry.severity !== filters.severity) continue;
        if (filters.startDate && entry.timestamp < filters.startDate) continue;
        if (filters.endDate && entry.timestamp > filters.endDate) continue;

        results.push(entry);

        if (results.length >= limit) break;
      }
    } catch {
      // Skip invalid entries
    }
  }

  return results.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
}

// Generate compliance report
export async function generateComplianceReport(
  kv: KVNamespace,
  businessId: string,
  startDate: string,
  endDate: string
): Promise<{
  totalEvents: number;
  securityIncidents: number;
  failedLogins: number;
  adminActions: number;
  dataAccess: number;
  riskScore: number;
  complianceIssues: string[];
}> {
  const logs = await queryAuditLogs(kv, {
    businessId,
    startDate,
    endDate
  }, 10000);

  const totalEvents = logs.length;
  const securityIncidents = logs.filter(log =>
    log.severity === AuditSeverity.HIGH || log.severity === AuditSeverity.CRITICAL
  ).length;
  const failedLogins = logs.filter(log => log.eventType === AuditEventType.LOGIN_FAILED).length;
  const adminActions = logs.filter(log => log.eventType === AuditEventType.ADMIN_ACTION).length;
  const dataAccess = logs.filter(log => log.eventType === AuditEventType.DATA_ACCESS).length;

  const averageRiskScore = logs.reduce((acc, log) => acc + (log.riskScore || 0), 0) / totalEvents;

  const complianceIssues: string[] = [];
  if (securityIncidents > totalEvents * 0.05) {
    complianceIssues.push('High security incident rate');
  }
  if (failedLogins > totalEvents * 0.1) {
    complianceIssues.push('High failed login rate');
  }
  if (averageRiskScore > 0.3) {
    complianceIssues.push('High average risk score');
  }

  return {
    totalEvents,
    securityIncidents,
    failedLogins,
    adminActions,
    dataAccess,
    riskScore: averageRiskScore,
    complianceIssues
  };
}

// =====================================================
// MFA (TOTP) IMPLEMENTATION
// =====================================================

export interface MFAConfig {
  issuer: string;
  serviceName: string;
  window?: number; // Number of time steps to allow
}

export interface MFASecret {
  secret: string;
  backupCodes: string[];
  qrCodeUrl: string;
}

export interface MFAVerification {
  valid: boolean;
  remainingAttempts?: number;
  error?: string;
}

// Generate MFA secret and backup codes
export function generateMFASecret(
  userEmail: string,
  config: MFAConfig
): MFASecret {
  const secret = authenticator.generateSecret();

  // Generate 10 backup codes
  const backupCodes = Array.from({ length: 10 }, () =>
    Math.random().toString(36).substr(2, 8).toUpperCase()
  );

  // Create QR code URL for authenticator apps
  const qrCodeUrl = authenticator.keyuri(
    userEmail,
    config.serviceName,
    secret
  );

  return {
    secret,
    backupCodes,
    qrCodeUrl
  };
}

// Verify TOTP code
export function verifyTOTP(
  token: string,
  secret: string,
  window = 1
): boolean {
  try {
    return authenticator.verify({
      token: token.replace(/\s/g, ''), // Remove spaces
      secret,
      // window // Allow 1 step before/after for clock skew
    });
  } catch {
    return false;
  }
}

// Verify backup code
export async function verifyBackupCode(
  code: string,
  userId: string,
  kv: KVNamespace
): Promise<{ valid: boolean; remainingCodes?: number }> {
  const key = `mfa_backup:${userId}`;

  try {
    const codesJson = await kv.get(key);
    if (!codesJson) {
      return { valid: false };
    }

    const codes: string[] = JSON.parse(codesJson);
    const normalizedCode = code.replace(/\s/g, '').toUpperCase();

    const codeIndex = codes.indexOf(normalizedCode);
    if (codeIndex === -1) {
      return { valid: false };
    }

    // Remove used code
    codes.splice(codeIndex, 1);

    // Save remaining codes
    await kv.put(key, JSON.stringify(codes));

    return {
      valid: true,
      remainingCodes: codes.length
    };
  } catch {
    return { valid: false };
  }
}

// Store backup codes
export async function storeBackupCodes(
  userId: string,
  codes: string[],
  kv: KVNamespace
): Promise<void> {
  const key = `mfa_backup:${userId}`;
  await kv.put(key, JSON.stringify(codes));
}

// Comprehensive MFA verification
export async function verifyMFA(
  token: string,
  secret: string,
  userId: string,
  kv: KVNamespace,
  window = 1
): Promise<MFAVerification> {
  const normalizedToken = token.replace(/\s/g, '');

  // Check if it's a 6-digit TOTP code
  if (/^\d{6}$/.test(normalizedToken)) {
    // Check for rate limiting
    const attemptKey = `mfa_attempts:${userId}`;
    const attempts = await kv.get(attemptKey);
    const attemptCount = attempts ? parseInt(attempts) : 0;

    if (attemptCount >= 5) {
      return {
        valid: false,
        error: 'Too many failed attempts. Try again later.'
      };
    }

    // Verify TOTP
    const isValid = verifyTOTP(normalizedToken, secret, window);

    if (!isValid) {
      // Increment failed attempts
      await kv.put(attemptKey, (attemptCount + 1).toString(), {
        expirationTtl: 300 // 5 minutes
      });

      return {
        valid: false,
        remainingAttempts: 5 - attemptCount - 1,
        error: 'Invalid verification code'
      };
    }

    // Clear failed attempts on success
    await kv.delete(attemptKey);

    return { valid: true };
  }

  // Check if it's a backup code (8 characters)
  if (/^[A-Z0-9]{8}$/.test(normalizedToken)) {
    const backupResult = await verifyBackupCode(normalizedToken, userId, kv);

    if (!backupResult.valid) {
      return {
        valid: false,
        error: 'Invalid backup code'
      };
    }

    return {
      valid: true,
      remainingAttempts: backupResult.remainingCodes
    };
  }

  return {
    valid: false,
    error: 'Invalid code format'
  };
}

// Check if user has MFA enabled
export async function isMFAEnabled(userId: string, kv: KVNamespace): Promise<boolean> {
  const key = `mfa_secret:${userId}`;
  const secret = await kv.get(key);
  return !!secret;
}

// Enable MFA for user
export async function enableMFA(
  userId: string,
  secret: string,
  backupCodes: string[],
  kv: KVNamespace
): Promise<void> {
  const secretKey = `mfa_secret:${userId}`;
  await kv.put(secretKey, secret);
  await storeBackupCodes(userId, backupCodes, kv);
}

// Disable MFA for user
export async function disableMFA(userId: string, kv: KVNamespace): Promise<void> {
  const secretKey = `mfa_secret:${userId}`;
  const backupKey = `mfa_backup:${userId}`;

  await kv.delete(secretKey);
  await kv.delete(backupKey);
}

// Get user's MFA secret
export async function getMFASecret(userId: string, kv: KVNamespace): Promise<string | null> {
  const key = `mfa_secret:${userId}`;
  return await kv.get(key);
}

// =====================================================
// API KEY SYSTEM
// =====================================================

export interface APIKey {
  id: string;
  name: string;
  keyHash: string;
  permissions: string[];
  rateLimit: {
    requests: number;
    window: number;
  };
  createdAt: string;
  lastUsed?: string;
  expiresAt?: string;
}

// Generate API key
export async function generateAPIKey(): Promise<{ key: string; hash: string }> {
  // Generate a proper 32-character random string
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let randomStr = '';
  for (let i = 0; i < 32; i++) {
    randomStr += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  const key = `cfk_${randomStr}`;

  // Create hash for storage (don't store plain key)
  const encoder = new TextEncoder();
  const data = encoder.encode(key);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

  return { key, hash };
}

// Validate API key
export async function validateAPIKey(
  apiKey: string,
  kv: KVNamespace
): Promise<{ valid: boolean; keyData?: APIKey; error?: string }> {
  try {
    // Hash the provided key
    const encoder = new TextEncoder();
    const data = encoder.encode(apiKey);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    // Look up key data
    const keyData = await kv.get(`api_key:${hash}`);
    if (!keyData) {
      return { valid: false, error: 'Invalid API key' };
    }

    const parsedKeyData: APIKey = JSON.parse(keyData);

    // Check expiration
    if (parsedKeyData.expiresAt && new Date(parsedKeyData.expiresAt) < new Date()) {
      return { valid: false, error: 'API key expired' };
    }

    // Update last used
    parsedKeyData.lastUsed = new Date().toISOString();
    await kv.put(`api_key:${hash}`, JSON.stringify(parsedKeyData));

    return { valid: true, keyData: parsedKeyData };
  } catch {
    return { valid: false, error: 'Key validation failed' };
  }
}

// =====================================================
// SECURE SESSION MANAGEMENT
// =====================================================

export interface SessionData {
  userId: string;
  businessId: string;
  email: string;
  role: string;
  permissions: string[];
  mfaVerified: boolean;
  createdAt: string;
  lastActivity: string;
  ipAddress: string;
  userAgent: string;
}

export interface SessionConfig {
  maxAge: number; // seconds
  secure: boolean;
  httpOnly: boolean;
  sameSite: 'strict' | 'lax' | 'none';
  domain?: string;
}

// Generate secure session ID
export function generateSessionId(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// Create session
export async function createSession(
  sessionData: SessionData,
  kv: KVNamespace,
  config: SessionConfig = {
    maxAge: 86400, // 24 hours
    secure: true,
    httpOnly: true,
    sameSite: 'strict'
  }
): Promise<string> {
  const sessionId = generateSessionId();
  const sessionKey = `session:${sessionId}`;

  const sessionWithMetadata = {
    ...sessionData,
    sessionId,
    createdAt: new Date().toISOString(),
    lastActivity: new Date().toISOString()
  };

  await kv.put(sessionKey, JSON.stringify(sessionWithMetadata), {
    expirationTtl: config.maxAge
  });

  return sessionId;
}

// Validate session
export async function validateSession(
  sessionId: string,
  kv: KVNamespace,
  request?: Request
): Promise<{ valid: boolean; sessionData?: SessionData; error?: string }> {
  if (!sessionId) {
    return { valid: false, error: 'Session ID missing' };
  }

  const sessionKey = `session:${sessionId}`;

  try {
    const sessionJson = await kv.get(sessionKey);
    if (!sessionJson) {
      return { valid: false, error: 'Session not found' };
    }

    const sessionData: SessionData = JSON.parse(sessionJson);

    // Check for session hijacking
    if (request) {
      const currentIP = request.headers.get('CF-Connecting-IP');
      const currentUA = request.headers.get('User-Agent');

      if (currentIP && sessionData.ipAddress !== currentIP) {
        await revokeSession(sessionId, kv);
        return { valid: false, error: 'Session security violation' };
      }

      if (currentUA && sessionData.userAgent !== currentUA) {
        await revokeSession(sessionId, kv);
        return { valid: false, error: 'Session security violation' };
      }
    }

    // Update last activity
    sessionData.lastActivity = new Date().toISOString();
    await kv.put(sessionKey, JSON.stringify(sessionData), {
      expirationTtl: 86400 // Reset expiration
    });

    return { valid: true, sessionData };
  } catch {
    return { valid: false, error: 'Session validation failed' };
  }
}

// Revoke session
export async function revokeSession(sessionId: string, kv: KVNamespace): Promise<void> {
  const sessionKey = `session:${sessionId}`;
  await kv.delete(sessionKey);
}

// Revoke all user sessions
export async function revokeAllUserSessions(userId: string, kv: KVNamespace): Promise<void> {
  // Note: In a real implementation, you'd maintain a user->sessions mapping
  // For now, we'll use a simple approach
  const userSessionsKey = `user_sessions:${userId}`;
  const sessionsJson = await kv.get(userSessionsKey);

  if (sessionsJson) {
    const sessionIds: string[] = JSON.parse(sessionsJson);
    for (const sessionId of sessionIds) {
      await revokeSession(sessionId, kv);
    }
    await kv.delete(userSessionsKey);
  }
}

// Track user sessions
export async function trackUserSession(
  userId: string,
  sessionId: string,
  kv: KVNamespace
): Promise<void> {
  const userSessionsKey = `user_sessions:${userId}`;
  const sessionsJson = await kv.get(userSessionsKey);
  const sessions = sessionsJson ? JSON.parse(sessionsJson) : [];

  if (!sessions.includes(sessionId)) {
    sessions.push(sessionId);

    // Limit to 10 concurrent sessions per user
    if (sessions.length > 10) {
      const oldestSession = sessions.shift();
      await revokeSession(oldestSession, kv);
    }

    await kv.put(userSessionsKey, JSON.stringify(sessions), {
      expirationTtl: 86400 * 7 // 7 days
    });
  }
}

// Create secure cookie header
export function createSecureCookie(
  name: string,
  value: string,
  config: SessionConfig
): string {
  const parts = [`${name}=${value}`];

  if (config.maxAge) {
    parts.push(`Max-Age=${config.maxAge}`);
  }

  if (config.secure) {
    parts.push('Secure');
  }

  if (config.httpOnly) {
    parts.push('HttpOnly');
  }

  if (config.sameSite) {
    parts.push(`SameSite=${config.sameSite}`);
  }

  if (config.domain) {
    parts.push(`Domain=${config.domain}`);
  }

  parts.push('Path=/');

  return parts.join('; ');
}

// HTTPS enforcement middleware
export function enforceHTTPS(request: Request): { valid: boolean; redirectUrl?: string } {
  const url = new URL(request.url);
  
  // Check if request is using HTTPS
  if (url.protocol !== 'https:') {
    // Create HTTPS redirect URL
    const httpsUrl = new URL(request.url);
    httpsUrl.protocol = 'https:';
    
    return {
      valid: false,
      redirectUrl: httpsUrl.toString()
    };
  }
  
  return { valid: true };
}

// Security middleware factory
export function createSecurityMiddleware(config: SecurityConfig) {
  return async (
    request: Request,
    response: Response,
    ctx: ExecutionContext
  ): Promise<Response> => {
    // Enforce HTTPS in production
    if (config.environment === 'production') {
      const httpsCheck = enforceHTTPS(request);
      if (!httpsCheck.valid && httpsCheck.redirectUrl) {
        return new Response(null, {
          status: 301,
          headers: {
            'Location': httpsCheck.redirectUrl,
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload'
          }
        });
      }
    }
    
    // Add security headers to response
    return addSecurityHeaders(response, config);
  };
}