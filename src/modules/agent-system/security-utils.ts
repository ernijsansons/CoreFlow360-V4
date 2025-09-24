/**
 * Security Utilities for Agent System
 * Provides validation, sanitization, and security functions
 */
import { z } from 'zod';
import { ValidationError } from './types';
import { Logger } from '../../shared/logger';

const logger = new Logger();

// ============================================================================
// VALIDATION PATTERNS
// ============================================================================

/**
 * Business ID validation pattern
 * - 8-64 characters
 * - Alphanumeric with hyphens and underscores
 * - Must start with letter or number
 */
const BUSINESS_ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9\-_]{7,63}$/;

/**
 * User ID validation pattern
 * Similar to business ID but allows email format
 */
const USER_ID_PATTERN = /^([a-zA-Z0-9][a-zA-Z0-9\-_]{7,63}|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$/;

/**
 * SQL identifier pattern for table/column names
 */
const SQL_IDENTIFIER_PATTERN = /^[a-zA-Z_][a-zA-Z0-9_]{0,63}$/;

/**
 * Patterns that indicate potential prompt injection
 */
const PROMPT_INJECTION_PATTERNS = [
  /system\s*:/gi,
  /assistant\s*:/gi,
  /human\s*:/gi,
  /\[INST\]/gi,
  /\[\/INST\]/gi,
  /<<<.*>>>/g,
  /ignore\s+previous\s+instructions/gi,
  /disregard\s+all\s+prior/gi,
  /forget\s+everything/gi,
  /new\s+instructions\s*:/gi,
  /you\s+are\s+now/gi,
  /act\s+as\s+if/gi,
  /pretend\s+to\s+be/gi,
  /roleplay\s+as/gi,
  /jailbreak/gi,
  /DAN\s+mode/gi,
  /developer\s+mode/gi,
  /admin\s+override/gi,
  /bypass\s+security/gi,
  /ignore\s+safety/gi,
  /unrestricted\s+mode/gi
];

/**
 * Patterns that indicate potential SQL injection
 */
const SQL_INJECTION_PATTERNS = [
  /union\s+select/gi,
  /drop\s+table/gi,
  /delete\s+from/gi,
  /insert\s+into/gi,
  /update\s+set/gi,
  /alter\s+table/gi,
  /create\s+table/gi,
  /exec\s*\(/gi,
  /execute\s*\(/gi,
  /sp_executesql/gi,
  /xp_cmdshell/gi,
  /--/g,
  /\/\*/g,
  /\*\//g,
  /'/g,
  /"/g,
  /;/g
];

/**
 * Patterns that indicate potential XSS
 */
const XSS_PATTERNS = [
  /<script[^>]*>.*?<\/script>/gi,
  /<iframe[^>]*>.*?<\/iframe>/gi,
  /<object[^>]*>.*?<\/object>/gi,
  /<embed[^>]*>.*?<\/embed>/gi,
  /<link[^>]*>.*?<\/link>/gi,
  /<meta[^>]*>.*?<\/meta>/gi,
  /javascript:/gi,
  /vbscript:/gi,
  /onload\s*=/gi,
  /onerror\s*=/gi,
  /onclick\s*=/gi,
  /onmouseover\s*=/gi,
  /onfocus\s*=/gi,
  /onblur\s*=/gi,
  /onchange\s*=/gi,
  /onsubmit\s*=/gi,
  /onreset\s*=/gi,
  /onselect\s*=/gi,
  /onkeydown\s*=/gi,
  /onkeyup\s*=/gi,
  /onkeypress\s*=/gi
];

// ============================================================================
// VALIDATION SCHEMAS
// ============================================================================

const BusinessIdSchema = z.string()
  .min(8, 'Business ID must be at least 8 characters')
  .max(64, 'Business ID must be at most 64 characters')
  .regex(BUSINESS_ID_PATTERN, 'Business ID must be alphanumeric with hyphens and underscores');

const UserIdSchema = z.string()
  .min(1, 'User ID is required')
  .max(255, 'User ID must be at most 255 characters')
  .regex(USER_ID_PATTERN, 'User ID must be valid format');

const SqlIdentifierSchema = z.string()
  .min(1, 'SQL identifier is required')
  .max(64, 'SQL identifier must be at most 64 characters')
  .regex(SQL_IDENTIFIER_PATTERN, 'SQL identifier must be valid');

const SessionIdSchema = z.string()
  .min(1, 'Session ID is required')
  .max(255, 'Session ID must be at most 255 characters')
  .regex(/^[a-zA-Z0-9\-_]+$/, 'Session ID must be alphanumeric with hyphens and underscores');

// ============================================================================
// VALIDATION FUNCTIONS
// ============================================================================

/**
 * Validate business ID
 */
export function validateBusinessId(businessId: unknown): string {
  try {
    return BusinessIdSchema.parse(businessId);
  } catch (error) {
    logger.error('Business ID validation failed', {
      businessId: sanitizeForLogging(businessId),
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    throw new ValidationError('Invalid business ID format');
  }
}

/**
 * Validate user ID
 */
export function validateUserId(userId: unknown): string {
  try {
    return UserIdSchema.parse(userId);
  } catch (error) {
    logger.error('User ID validation failed', {
      userId: sanitizeForLogging(userId),
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    throw new ValidationError('Invalid user ID format');
  }
}

/**
 * Validate SQL identifier
 */
export function validateSqlIdentifier(identifier: unknown): string {
  try {
    return SqlIdentifierSchema.parse(identifier);
  } catch (error) {
    logger.error('SQL identifier validation failed', {
      identifier: sanitizeForLogging(identifier),
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    throw new ValidationError('Invalid SQL identifier format');
  }
}

/**
 * Validate session ID
 */
export function validateSessionId(sessionId: unknown): string {
  try {
    return SessionIdSchema.parse(sessionId);
  } catch (error) {
    logger.error('Session ID validation failed', {
      sessionId: sanitizeForLogging(sessionId),
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    throw new ValidationError('Invalid session ID format');
  }
}

// ============================================================================
// SANITIZATION FUNCTIONS
// ============================================================================

/**
 * Sanitize business ID
 */
export function sanitizeBusinessId(businessId: unknown): string {
  if (typeof businessId !== 'string') {
    throw new ValidationError('Business ID must be a string');
  }
  
  const sanitized = businessId.trim().toLowerCase();
  return validateBusinessId(sanitized);
}

/**
 * Sanitize user ID
 */
export function sanitizeUserId(userId: unknown): string {
  if (typeof userId !== 'string') {
    throw new ValidationError('User ID must be a string');
  }
  
  const sanitized = userId.trim().toLowerCase();
  return validateUserId(sanitized);
}

/**
 * Sanitize SQL parameter
 */
export function sanitizeSqlParam(param: unknown): string {
  if (typeof param !== 'string') {
    throw new ValidationError('SQL parameter must be a string');
  }
  
  // Remove potential SQL injection characters
  let sanitized = param.trim();
  
  // Remove null bytes
  sanitized = sanitized.replace(/\0/g, '');
  
  // Remove control characters except newlines and tabs
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  
  // Limit length
  if (sanitized.length > 1000) {
    sanitized = sanitized.substring(0, 1000);
  }

  return sanitized;
}

/**
 * Sanitize SQL identifier
 */
export function sanitizeSqlIdentifier(identifier: unknown): string {
  if (typeof identifier !== 'string') {
    throw new ValidationError('SQL identifier must be a string');
  }
  
  const sanitized = identifier.trim();
  return validateSqlIdentifier(sanitized);
}

/**
 * Sanitize text for logging (remove sensitive data)
 */
export function sanitizeForLogging(data: unknown): unknown {
  if (data === null || data === undefined) {
    return data;
  }
  
  if (typeof data === 'string') {
    // Remove potential sensitive patterns
    return data
      .replace(/password["\s]*[:=]["\s]*[^"'\s,}]+/gi, 'password: [REDACTED]')
      .replace(/token["\s]*[:=]["\s]*[^"'\s,}]+/gi, 'token: [REDACTED]')
      .replace(/key["\s]*[:=]["\s]*[^"'\s,}]+/gi, 'key: [REDACTED]')
      .replace(/secret["\s]*[:=]["\s]*[^"'\s,}]+/gi, 'secret: [REDACTED]')
      .replace(/api[_-]?key["\s]*[:=]["\s]*[^"'\s,}]+/gi, 'api_key: [REDACTED]')
      .replace(/access[_-]?token["\s]*[:=]["\s]*[^"'\s,}]+/gi, 'access_token: [REDACTED]')
      .replace(/refresh[_-]?token["\s]*[:=]["\s]*[^"'\s,}]+/gi, 'refresh_token: [REDACTED]')
      .substring(0, 1000); // Limit length
  }
  
  if (Array.isArray(data)) {
    return data.map(item => sanitizeForLogging(item));
  }
  
  if (typeof data === 'object') {
    const sanitized: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data)) {
      const sanitizedKey = sanitizeForLogging(key) as string;
      const sanitizedValue = sanitizeForLogging(value);
      sanitized[sanitizedKey] = sanitizedValue;
    }
    return sanitized;
  }
  
  return data;
}

// ============================================================================
// SECURITY DETECTION FUNCTIONS
// ============================================================================

/**
 * Detect prompt injection attempts
 */
export function detectPromptInjection(text: string): {
  detected: boolean;
  patterns: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
} {
  const detectedPatterns: string[] = [];
  
  for (const pattern of PROMPT_INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      detectedPatterns.push(pattern.source);
    }
  }
  
  const detected = detectedPatterns.length > 0;
  let severity: 'low' | 'medium' | 'high' | 'critical' = 'low';
  
  if (detected) {
    if (detectedPatterns.length >= 5) {
      severity = 'critical';
    } else if (detectedPatterns.length >= 3) {
      severity = 'high';
    } else if (detectedPatterns.length >= 2) {
      severity = 'medium';
    }
  }
  
  return {
    detected,
    patterns: detectedPatterns,
    severity
  };
}

/**
 * Detect SQL injection attempts
 */
export function detectSqlInjection(text: string): {
  detected: boolean;
  patterns: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
} {
  const detectedPatterns: string[] = [];
  
  for (const pattern of SQL_INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      detectedPatterns.push(pattern.source);
    }
  }
  
  const detected = detectedPatterns.length > 0;
  let severity: 'low' | 'medium' | 'high' | 'critical' = 'low';
  
  if (detected) {
    if (detectedPatterns.length >= 5) {
      severity = 'critical';
    } else if (detectedPatterns.length >= 3) {
      severity = 'high';
    } else if (detectedPatterns.length >= 2) {
      severity = 'medium';
    }
  }
  
  return {
    detected,
    patterns: detectedPatterns,
    severity
  };
}

/**
 * Detect XSS attempts
 */
export function detectXss(text: string): {
  detected: boolean;
  patterns: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
} {
  const detectedPatterns: string[] = [];
  
  for (const pattern of XSS_PATTERNS) {
    if (pattern.test(text)) {
      detectedPatterns.push(pattern.source);
    }
  }
  
  const detected = detectedPatterns.length > 0;
  let severity: 'low' | 'medium' | 'high' | 'critical' = 'low';
  
  if (detected) {
    if (detectedPatterns.length >= 5) {
      severity = 'critical';
    } else if (detectedPatterns.length >= 3) {
      severity = 'high';
    } else if (detectedPatterns.length >= 2) {
      severity = 'medium';
    }
  }
  
  return {
    detected,
    patterns: detectedPatterns,
    severity
  };
}

/**
 * Comprehensive security scan
 */
export function securityScan(text: string): {
  promptInjection: ReturnType<typeof detectPromptInjection>;
  sqlInjection: ReturnType<typeof detectSqlInjection>;
  xss: ReturnType<typeof detectXss>;
  overallRisk: 'low' | 'medium' | 'high' | 'critical';
} {
  const promptInjection = detectPromptInjection(text);
  const sqlInjection = detectSqlInjection(text);
  const xss = detectXss(text);
  
  const risks = [promptInjection.severity, sqlInjection.severity, xss.severity];
  const riskLevels = { low: 1, medium: 2, high: 3, critical: 4 };
  const maxRisk = Math.max(...risks.map(risk => riskLevels[risk]));
  
  let overallRisk: 'low' | 'medium' | 'high' | 'critical' = 'low';
  if (maxRisk >= 4) overallRisk = 'critical';
  else if (maxRisk >= 3) overallRisk = 'high';
  else if (maxRisk >= 2) overallRisk = 'medium';
  
  return {
    promptInjection,
    sqlInjection,
    xss,
    overallRisk
  };
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Generate secure random string
 */
export function generateSecureRandom(length: number = 32): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  
  return result;
}

/**
 * Hash string for consistent comparison
 */
export function hashString(input: string): string {
  let hash = 0;
  if (input.length === 0) return hash.toString();
  
  for (let i = 0; i < input.length; i++) {
    const char = input.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32-bit integer
  }
  
  return Math.abs(hash).toString(36);
}

/**
 * Check if string contains only safe characters
 */
export function isSafeString(input: string): boolean {
  // Allow alphanumeric, spaces, and common punctuation
  const safePattern = /^[a-zA-Z0-9\s.,!?;:()\-_@#$%&*+=<>[\]{}|\\\/~`"']+$/;
  return safePattern.test(input);
}

/**
 * Escape HTML entities
 */
export function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Unescape HTML entities
 */
export function unescapeHtml(input: string): string {
  return input
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}

