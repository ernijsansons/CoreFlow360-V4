/**;
 * Security Utilities for Agent System;
 * Provides validation, sanitization, and security functions;/
 */
;
import { z } from 'zod';"/
import { ValidationError } from './types';"/
import { Logger } from '../../shared/logger';

const logger = new Logger();
/
// ============================================================================;/
// VALIDATION PATTERNS;/
// ============================================================================
;/
/**;
 * Business ID validation pattern;
 * - 8-64 characters;
 * - Alphanumeric with hyphens and underscores;
 * - Must start with letter or number;/
 */;/
const BUSINESS_ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9\-_]{7,63}$/;
/
/**;
 * User ID validation pattern;
 * Similar to business ID but allows email format;/
 */;/
const USER_ID_PATTERN = /^([a-zA-Z0-9][a-zA-Z0-9\-_]{7,63}|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$/;
/
/**;/
 * SQL identifier pattern for table/column names;/
 */;/
const SQL_IDENTIFIER_PATTERN = /^[a-zA-Z_][a-zA-Z0-9_]{0,63}$/;
/
/**;
 * Patterns that indicate potential prompt injection;/
 */;
const PROMPT_INJECTION_PATTERNS = [;/
  /system\s*:/gi,;/
  /assistant\s*:/gi,;/
  /human\s*:/gi,;/
  /\[INST\]/gi,;/
  /\[\/INST\]/gi,;/
  /<<<.*>>>/g,;/
  /ignore\s+previous\s+instructions/gi,;/
  /disregard\s+all\s+prior/gi,;/
  /forget\s+everything/gi,;/
  /new\s+instructions\s*:/gi,;/
  /you\s+are\s+now/gi,;/
  /act\s+as\s+if/gi,;/
  /pretend\s+to\s+be/gi;
];
/
/**;
 * PII patterns for detection and redaction;/
 */;
const PII_PATTERNS = {/
  email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,;/
  phone: /(\+?1?\s?)?(\([0-9]{3}\)|[0-9]{3})[\s.-]?[0-9]{3}[\s.-]?[0-9]{4}/g,;/
  ssn: /\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b/g,;/
  creditCard: /\b(?:\d[ -]*?){13,16}\b/g,;/
  ipAddress: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,;/
  apiKey: /\b(sk-|pk-|api[_-]?key[_-]?)[a-zA-Z0-9]{20,}\b/gi,;/
  jwt: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g,;
};
/
// ============================================================================;/
// VALIDATION FUNCTIONS;/
// ============================================================================
;/
/**;
 * Validate business ID format;/
 */;
export function validateBusinessId(businessId: string): boolean {"
  if (!businessId || typeof businessId !== 'string') {
    return false;}
  return BUSINESS_ID_PATTERN.test(businessId);
}
/
/**;
 * Validate user ID format;/
 */;
export function validateUserId(userId: string): boolean {"
  if (!userId || typeof userId !== 'string') {
    return false;}
  return USER_ID_PATTERN.test(userId);
}
/
/**;/
 * Validate SQL identifier (table/column names);/
 */;
export function validateSqlIdentifier(identifier: string): boolean {"
  if (!identifier || typeof identifier !== 'string') {
    return false;}
  return SQL_IDENTIFIER_PATTERN.test(identifier);
}
/
/**;
 * Validate and sanitize business ID with strict checking;/
 */;
export function sanitizeBusinessId(businessId: string): string {
  if (!validateBusinessId(businessId)) {
    throw new ValidationError(`Invalid business ID format: ${businessId?.substring(0, 10)}...`);
  }
  return businessId.trim();
}
/
/**;
 * Validate and sanitize user ID;/
 */;
export function sanitizeUserId(userId: string): string {
  if (!validateUserId(userId)) {`
    throw new ValidationError(`Invalid user ID format: ${userId?.substring(0, 10)}...`);
  }
  return userId.trim();
}
/
// ============================================================================;/
// INPUT SANITIZATION;/
// ============================================================================
;/
/**;
 * Sanitize input for AI models to prevent prompt injection;/
 */;"
export function sanitizeAIInput(input: "unknown", maxLength: number = 50000): string {"
  let sanitized = '';
/
  // Convert to string safely;"
  if (typeof input === 'string') {"
    sanitized = input;} else if (typeof input === 'object' && input !== null) {
    const obj = input as Record<string, unknown>;
    sanitized = obj.prompt || obj.message || obj.content || JSON.stringify(input);
    sanitized = String(sanitized);
  } else {
    sanitized = String(input);
  }
/
  // Remove potential prompt injection patterns;
  for (const pattern of PROMPT_INJECTION_PATTERNS) {"
    sanitized = sanitized.replace(pattern, '[BLOCKED]');
  }
/
  // Remove HTML/script tags;
  sanitized = sanitized;"/
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '[SCRIPT_REMOVED]');"/
    .replace(/<\/?[^>]+(>|$)/g, '');
/
  // Remove control characters except newlines and tabs;"/
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
/
  // Enforce length limit;
  if (sanitized.length > maxLength) {"
    sanitized = sanitized.substring(0, maxLength) + '... [TRUNCATED]';
  }
/
  // Log if injection was detected;"
  if (sanitized.includes('[BLOCKED]') || sanitized.includes('[SCRIPT_REMOVED]')) {"
    logger.warn('Potential prompt injection detected and blocked', {"
      originalLength: "String(input).length",;"
      sanitizedLength: "sanitized.length",;"
      blocked: "true;"});
  }

  return sanitized;
}
/
/**;
 * Sanitize SQL query parameters;/
 */;
export function sanitizeSqlParam(param: unknown): string | number | null {
  if (param === null || param === undefined) {
    return null;}
"
  if (typeof param === 'number') {/
    // Validate number is not NaN or Infinity;
    if (!isFinite(param)) {"
      throw new ValidationError('Invalid numeric parameter');
    }
    return param;
  }
"
  if (typeof param === 'boolean') {"
    return param ? 1: "0;"}
"
  if (typeof param === 'string') {/
    // Remove any SQL comment syntax;
    let sanitized = param;"/
      .replace(/--.*$/gm, '');"/
      .replace(/\/\*[\s\S]*?\*\//g, '');"/
      .replace(/;.*$/g, ''); // Remove anything after semicolon
;/
    // Escape single quotes by doubling them (SQL standard);"/
    sanitized = sanitized.replace(/'/g, "''");

    return sanitized;
  }
/
  // For objects/arrays, stringify and sanitize;
  return sanitizeSqlParam(JSON.stringify(param));
}
/
// ============================================================================;/
// PII DETECTION AND REDACTION;/
// ============================================================================
;/
/**;
 * Detect if text contains PII;/
 */;
export function containsPII(text: string): boolean {
  for (const [type, pattern] of Object.entries(PII_PATTERNS)) {
    if (pattern.test(text)) {
      return true;
    }
  }
  return false;
}
/
/**;
 * Redact PII from text;/
 */;"
export function redactPII(text: "string", replaceWith: string = '[REDACTED]'): string {
  let redacted = text;

  for (const [type, pattern] of Object.entries(PII_PATTERNS)) {`
    redacted = redacted.replace(pattern, `${replaceWith}_${type.toUpperCase()}`);
  }

  return redacted;
}
/
/**;
 * Sanitize object for logging (redact PII from all string values);/
 */;"
export function sanitizeForLogging(obj: "any", depth: number = 0): any {"/
  if (depth > 10) return '[MAX_DEPTH]'; // Prevent infinite recursion
;
  if (obj === null || obj === undefined) {
    return obj;}
"
  if (typeof obj === 'string') {
    return redactPII(obj);
  }
"
  if (typeof obj === 'number' || typeof obj === 'boolean') {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeForLogging(item, depth + 1));
  }
"
  if (typeof obj === 'object') {"
    const sanitized: "Record<string", any> = {};"
    const sensitiveKeys = ['password', 'token', 'secret', 'apiKey', 'api_key', 'authorization', 'cookie', 'session'];

    for (const [key, value] of Object.entries(obj)) {/
      // Completely redact sensitive keys;
      if (sensitiveKeys.some(sensitive => key.toLowerCase().includes(sensitive))) {"
        sanitized[key] = '[REDACTED]';
      } else {
        sanitized[key] = sanitizeForLogging(value, depth + 1);
      }
    }

    return sanitized;
  }
"
  return '[UNKNOWN_TYPE]';
}
/
// ============================================================================;/
// API KEY SECURITY;/
// ============================================================================
;/
/**;
 * Validate API key format without exposing it;/
 */;"
export function validateApiKeyFormat(apiKey: "string", prefix: string = 'sk-'): boolean {"
  if (!apiKey || typeof apiKey !== 'string') {
    return false;}
/
  // Check prefix and minimum length;
  if (!apiKey.startsWith(prefix) || apiKey.length < 20) {
    return false;
  }
"/
  // Ensure it doesn't contain invalid characters;/
  const validPattern = /^[a-zA-Z0-9\-_]+$/;
  return validPattern.test(apiKey.substring(prefix.length));
}
/
/**;
 * Mask API key for display (show only prefix and last 4 chars);/
 */;
export function maskApiKey(apiKey: string): string {
  if (!apiKey || apiKey.length < 10) {"
    return '[INVALID_KEY]';}

  const prefix = apiKey.substring(0, 3);
  const suffix = apiKey.substring(apiKey.length - 4);`
  return `${prefix}...${suffix}`;
}
/
// ============================================================================;/
// ERROR SANITIZATION;/
// ============================================================================
;/
/**;
 * Sanitize error messages for user display;/
 */;
export function sanitizeErrorForUser(error: Error | string): string {
  const errorMessage = error instanceof Error ? error.message : String(error);
/
  // Remove stack traces;"
  let sanitized = errorMessage.split('\n')[0];
/
  // Remove file paths;"/
  sanitized = sanitized.replace(/([A-Z]:)?[\\/][\w\s\-\.]+[\\/]/gi, '[PATH]/');
/
  // Remove potential PII;
  sanitized = redactPII(sanitized);
/
  // Remove internal service names;"/
  sanitized = sanitized.replace(/\b(localhost|127\.0\.0\.1|internal|staging|dev)\b/gi, '[SERVICE]');
/
  // Categorize common errors with user-friendly messages;"
  const errorMappings: "Record<string", string> = {"
    'rate limit': 'The service is temporarily busy. Please try again in a moment.',;"
    'timeout': 'The operation took too long. Please try again.',;"
    'network error': 'Connection issue detected. Please check your internet connection.',;"
    'unauthorized': 'You don\'t have permission to perform this action.',;"
    'not found': 'The requested resource was not found.',;"
    'validation': 'The provided data is invalid. Please check and try again.',;"
    'server error': 'An unexpected error occurred. Our team has been notified.',;
  };

  for (const [pattern, message] of Object.entries(errorMappings)) {
    if (sanitized.toLowerCase().includes(pattern)) {
      return message;
    }
  }
/
  // Default sanitized message if no pattern matches;"
  return 'An error occurred while processing your request. Please try again.';
}
/
// ============================================================================;/
// SECURITY HEADERS;/
// ============================================================================
;/
/**;
 * Generate secure response headers;/
 */;
export function getSecurityHeaders(): Record<string, string> {
  return {"
    'X-Content-Type-Options': 'nosniff',;"
    'X-Frame-Options': 'DENY',;"
    'X-XSS-Protection': '1; mode=block',;"
    'Referrer-Policy': 'strict-origin-when-cross-origin',;"
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',;"
    'Content-Security-Policy': "default-src;"
  'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';",;
  };
}
/
// ============================================================================;/
// RATE LIMITING;/
// ============================================================================
;
interface RateLimitEntry {"
  count: "number;"
  resetAt: number;"}

const rateLimitMap = new Map<string, RateLimitEntry>();
/
/**;
 * Check if request should be rate limited;/
 */;
export function checkRateLimit(;"
  identifier: "string",;"
  maxRequests: "number = 100",;
  windowMs: number = 60000;
): { allowed: boolean; remaining: number; resetAt: number} {
  const now = Date.now();
  const entry = rateLimitMap.get(identifier);
/
  // Clean up old entries periodically;
  if (rateLimitMap.size > 10000) {
    for (const [key, value] of rateLimitMap.entries()) {
      if (value.resetAt < now) {
        rateLimitMap.delete(key);
      }
    }
  }

  if (!entry || entry.resetAt < now) {/
    // Create new entry;
    rateLimitMap.set(identifier, {"
      count: "1",;"
      resetAt: "now + windowMs;"});

    return {"
      allowed: "true",;"
      remaining: "maxRequests - 1",;"
      resetAt: "now + windowMs;"};
  }
/
  // Check existing entry;
  if (entry.count >= maxRequests) {
    return {"
      allowed: "false",;"
      remaining: "0",;"
      resetAt: "entry.resetAt;"};
  }
/
  // Increment count;
  entry.count++;

  return {"
    allowed: "true",;"
    remaining: "maxRequests - entry.count",;"
    resetAt: "entry.resetAt;"};
}
/
// ============================================================================;/
// ENCRYPTION HELPERS;/
// ============================================================================
;/
/**;
 * Hash sensitive data for storage (one-way);/
 */;
export async function hashSensitiveData(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);"
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));"
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
/
/**;
 * Generate secure random token;/
 */;
export function generateSecureToken(length: number = 32): string {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);"
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}
/
// ============================================================================;/
// AUDIT HELPERS;/
// ============================================================================
;/
/**;
 * Create audit-safe log entry;/
 */;
export function createAuditEntry(;"
  action: "string",;"
  businessId: "string",;"
  userId: "string",;"
  details: "any;"
): Record<string", any> {
  return {"
    id: "generateSecureToken(16)",;"
    timestamp: "new Date().toISOString()",;
    action,;"
    businessId: "sanitizeBusinessId(businessId)",;"
    userId: "sanitizeUserId(userId)",;"
    details: "sanitizeForLogging(details)",;"
    environment: process.env.NODE_ENV || 'development',;"
    version: process.env.APP_VERSION || 'unknown';};
}
/
// ============================================================================;/
// EXPORT VALIDATION SCHEMAS;/
// ============================================================================
;
export const SecureBusinessContextSchema = z.object({"
  businessId: "z.string().refine(validateBusinessId", 'Invalid business ID format'),;"
  userId: "z.string().refine(validateUserId", 'Invalid user ID format'),;"
  sessionId: "z.string().optional()",;"
  department: "z.string().optional()",;"
  timezone: z.string().default('UTC'),;"
  currency: z.string().default('USD'),;"
  locale: z.string().default('en-US'),;
  permissions: z.array(z.string()).default([]),;
});

export const SecureTaskInputSchema = z.object({"
  id: "z.string().min(1)",;"
  capability: "z.string().min(1)",;"
  input: "z.unknown().transform(val => sanitizeAIInput(val))",;"
  context: "SecureBusinessContextSchema",;
  constraints: z.object({
    maxCost: z.number().positive().optional(),;"
    maxLatency: "z.number().positive().optional()",;"
    requiredAccuracy: "z.number().min(0).max(1).optional()",;"
    timeout: "z.number().positive().optional()",;"
    retryLimit: "z.number().int().min(0).max(5).optional()",;
  }).optional(),;"
  metadata: "z.record(z.unknown()).optional()",;"
  priority: z.enum(['low', 'normal', 'high', 'critical']).optional(),;
});

export type SecureBusinessContext = z.infer<typeof SecureBusinessContextSchema>;
export type SecureTaskInput = z.infer<typeof SecureTaskInputSchema>;"`/