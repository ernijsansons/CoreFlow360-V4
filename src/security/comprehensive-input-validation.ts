/**
 * Comprehensive Input Validation System - Fortune 50 Level Security
 * 
 * SECURITY FIXES IMPLEMENTED:
 * - CVSS 7.5 Insufficient Input Validation Prevention
 * - Comprehensive Zod schemas for all endpoints
 * - Input sanitization and validation
 * - XSS and injection attack prevention
 * - Data type and range validation
 * - Business logic validation
 */

import { z } from 'zod';


export interface ValidationResult<T = any> {
  success: boolean;
  data?: T;
  errors: ValidationError[];
  sanitizedData?: any;
}

export interface ValidationError {
  field: string;
  message: string;
  code: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  value?: any;
}

export interface ValidationConfig {
  enableXSSProtection: boolean;
  enableSQLInjectionProtection: boolean;
  enablePathTraversalProtection: boolean;
  enableCommandInjectionProtection: boolean;
  maxStringLength: number;
  maxArrayLength: number;
  maxObjectDepth: number;
  allowHtml: boolean;
  sanitizeInput: boolean;
}

/**
 * Comprehensive Input Validation Schemas
 */
export class InputValidationSchemas {
  private static readonly DEFAULT_CONFIG: ValidationConfig = {
    enableXSSProtection: true,
    enableSQLInjectionProtection: true,
    enablePathTraversalProtection: true,
    enableCommandInjectionProtection: true,
    maxStringLength: 10000,
    maxArrayLength: 1000,
    maxObjectDepth: 10,
    allowHtml: false,
    sanitizeInput: true
  };

  /**
   * Base string validator with security enhancements
   */
  static secureString(minLength: number = 1, maxLength: number = 255) {
    return z.string()
      .min(minLength, `Must be at least ${minLength} characters`)
      .max(maxLength, `Must be no more than ${maxLength} characters`)
      .transform((str) => this.sanitizeString(str))
      .refine((str) => !this.containsXSS(str), 'Contains potentially dangerous content')
      .refine((str) => !this.containsSQLInjection(str), 'Contains potentially dangerous SQL content')
      .refine((str) => !this.containsPathTraversal(str), 'Contains potentially dangerous path content');
  }

  /**
   * Email validator with comprehensive security checks
   */
  static secureEmail() {
    return z.string()
      .email('Invalid email format')
      .max(254, 'Email too long')
      .transform((email) => email.toLowerCase().trim())
      .refine((email) => !this.containsXSS(email), 'Email contains potentially dangerous content')
      .refine((email) => this.isValidEmailFormat(email), 'Invalid email format');
  }

  /**
   * Password validator with strength requirements
   */
  static securePassword() {
    return z.string()
      .min(8, 'Password must be at least 8 characters')
      .max(128, 'Password too long')
      .refine((password) => /[a-z]/.test(password), 'Password must contain lowercase letter')
      .refine((password) => /[A-Z]/.test(password), 'Password must contain uppercase letter')
      .refine((password) => /[0-9]/.test(password), 'Password must contain number')
      .refine((password) => /[^a-zA-Z0-9]/.test(password), 'Password must contain special character')
      .refine((password) => !this.isCommonPassword(password), 'Password is too common')
      .refine((password) => !this.containsPersonalInfo(password), 'Password contains personal information');
  }

  /**
   * Business ID validator with format validation
   */
  static businessId() {
    return z.string()
      .regex(/^biz_[a-zA-Z0-9_-]{8,32}$/, 'Invalid business ID format')
      .refine((id) => !this.containsInjectionPatterns(id), 'Business ID contains dangerous patterns');
  }

  /**
   * User ID validator with format validation
   */
  static userId() {
    return z.string()
      .regex(/^usr_[a-zA-Z0-9_-]{8,32}$/, 'Invalid user ID format')
      .refine((id) => !this.containsInjectionPatterns(id), 'User ID contains dangerous patterns');
  }

  /**
   * Phone number validator
   */
  static phoneNumber() {
    return z.string()
      .regex(/^\+?[1-9]\d{1,14}$/, 'Invalid phone number format')
      .max(15, 'Phone number too long')
      .transform((phone) => phone.replace(/\D/g, ''));
  }

  /**
   * URL validator with security checks
   */
  static secureUrl() {
    return z.string()
      .url('Invalid URL format')
      .refine((url) => this.isAllowedUrl(url), 'URL not allowed')
      .refine((url) => !this.containsXSS(url), 'URL contains potentially dangerous content');
  }

  /**
   * Date validator with range checks
   */
  static secureDate() {
    return z.string()
      .datetime('Invalid date format')
      .refine((date) => {
        const d = new Date(date);
        const now = new Date();
        const minDate = new Date('1900-01-01');
        return d >= minDate && d <= now;
      }, 'Date out of valid range');
  }

  /**
   * JSON validator with depth and size limits
   */
  static secureJson(maxDepth: number = 5, maxSize: number = 10000) {
    return z.string()
      .max(maxSize, 'JSON too large')
      .transform((jsonStr) => {
        try {
          const parsed = JSON.parse(jsonStr);
          if (this.getObjectDepth(parsed) > maxDepth) {
            throw new Error('JSON depth exceeds limit');
          }
          return parsed;
        } catch (error) {
          throw new Error('Invalid JSON format');
        }
      });
  }

  /**
   * File upload validator
   */
  static secureFileUpload() {
    return z.object({
      name: z.string()
        .min(1, 'File name required')
        .max(255, 'File name too long')
        .refine((name) => this.isValidFileName(name), 'Invalid file name'),
      size: z.number()
        .min(1, 'File size must be positive')
        .max(10 * 1024 * 1024, 'File too large (max 10MB)'),
      type: z.string()
        .refine((type) => this.isAllowedFileType(type), 'File type not allowed'),
      content: z.string()
        .optional()
        .refine((content) => !content || this.isValidFileContent(content), 'Invalid file content')
    });
  }

  /**
   * API request validator
   */
  static apiRequest() {
    return z.object({
      method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']),
      path: z.string()
        .min(1, 'Path required')
        .max(500, 'Path too long')
        .refine((path) => this.isValidApiPath(path), 'Invalid API path'),
      headers: z.record(z.string())
        .optional()
        .refine((headers) => !headers || this.areValidHeaders(headers), 'Invalid headers'),
      body: z.any()
        .optional()
        .refine((body) => !body || this.isValidRequestBody(body), 'Invalid request body')
    });
  }

  /**
   * Search query validator
   */
  static searchQuery() {
    return z.string()
      .min(1, 'Search query required')
      .max(500, 'Search query too long')
      .transform((query) => this.sanitizeSearchQuery(query))
      .refine((query) => !this.containsXSS(query), 'Search query contains dangerous content')
      .refine((query) => !this.containsSQLInjection(query), 'Search query contains SQL injection attempt');
  }

  /**
   * Pagination validator
   */
  static pagination() {
    return z.object({
      page: z.number()
        .int('Page must be integer')
        .min(1, 'Page must be positive')
        .max(10000, 'Page too large'),
      limit: z.number()
        .int('Limit must be integer')
        .min(1, 'Limit must be positive')
        .max(100, 'Limit too large'),
      sort: z.string()
        .optional()
        .refine((sort) => !sort || this.isValidSortField(sort), 'Invalid sort field'),
      order: z.enum(['asc', 'desc'])
        .optional()
    });
  }

  /**
   * Validate input with comprehensive security checks
   */
  static async validateInput<T>(
    schema: z.ZodSchema<T>,
    data: unknown,
    config: Partial<ValidationConfig> = {}
  ): Promise<ValidationResult<T>> {
    const fullConfig = { ...this.DEFAULT_CONFIG, ...config };
    const result: ValidationResult<T> = {
      success: false,
      errors: []
    };

    try {
      // Pre-validation security checks
      const securityValidation = this.performSecurityChecks(data, fullConfig);
      if (!securityValidation.isValid) {
        result.errors.push(...securityValidation.errors);
        return result;
      }

      // Schema validation
      const validatedData = await schema.parseAsync(data);
      result.data = validatedData;
      result.success = true;

      // Post-validation sanitization
      if (fullConfig.sanitizeInput) {
        result.sanitizedData = this.sanitizeData(validatedData, fullConfig);
      }

      return result;

    } catch (error) {
      if (error instanceof z.ZodError) {
        result.errors = error.errors.map(err => ({
          field: err.path.join('.'),
          message: err.message,
          code: err.code,
          severity: this.getSeverityFromError(err),
          value: data
        }));
      } else {
        result.errors.push({
          field: 'unknown',
          message: error instanceof Error ? error.message : 'Unknown validation error',
          code: 'UNKNOWN_ERROR',
          severity: 'high'
        });
      }

      return result;
    }
  }

  /**
   * Perform comprehensive security checks
   */
  private static performSecurityChecks(
    data: unknown,
    config: ValidationConfig
  ): { isValid: boolean; errors: ValidationError[] } {
    const errors: ValidationError[] = [];

    // Check data size
    const dataSize = JSON.stringify(data).length;
    if (dataSize > config.maxStringLength) {
      errors.push({
        field: 'data',
        message: 'Data size exceeds maximum allowed',
        code: 'DATA_TOO_LARGE',
        severity: 'high',
        value: dataSize
      });
    }

    // Check object depth
    if (typeof data === 'object' && data !== null) {
      const depth = this.getObjectDepth(data);
      if (depth > config.maxObjectDepth) {
        errors.push({
          field: 'data',
          message: 'Object depth exceeds maximum allowed',
          code: 'OBJECT_TOO_DEEP',
          severity: 'medium',
          value: depth
        });
      }
    }

    // Check for dangerous patterns
    if (typeof data === 'string') {
      if (config.enableXSSProtection && this.containsXSS(data)) {
        errors.push({
          field: 'data',
          message: 'Contains XSS patterns',
          code: 'XSS_DETECTED',
          severity: 'critical',
          value: data.substring(0, 100)
        });
      }

      if (config.enableSQLInjectionProtection && this.containsSQLInjection(data)) {
        errors.push({
          field: 'data',
          message: 'Contains SQL injection patterns',
          code: 'SQL_INJECTION_DETECTED',
          severity: 'critical',
          value: data.substring(0, 100)
        });
      }

      if (config.enablePathTraversalProtection && this.containsPathTraversal(data)) {
        errors.push({
          field: 'data',
          message: 'Contains path traversal patterns',
          code: 'PATH_TRAVERSAL_DETECTED',
          severity: 'high',
          value: data.substring(0, 100)
        });
      }

      if (config.enableCommandInjectionProtection && this.containsCommandInjection(data)) {
        errors.push({
          field: 'data',
          message: 'Contains command injection patterns',
          code: 'COMMAND_INJECTION_DETECTED',
          severity: 'critical',
          value: data.substring(0, 100)
        });
      }
    }

    return { isValid: errors.length === 0, errors };
  }

  /**
   * Sanitize string input
   */
  private static sanitizeString(input: string): string {
    return input
      .replace(/[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F-\x9F]/g, '') // Remove control characters
      .replace(/\s+/g, ' ') // Normalize whitespace
      .trim();
  }

  /**
   * Check for XSS patterns
   */
  private static containsXSS(input: string): boolean {
    const xssPatterns = [
      /<script[^>]*>.*?<\/script>/gi,
      /<iframe[^>]*>.*?<\/iframe>/gi,
      /<object[^>]*>.*?<\/object>/gi,
      /<embed[^>]*>.*?<\/embed>/gi,
      /javascript:/gi,
      /vbscript:/gi,
      /onload\s*=/gi,
      /onerror\s*=/gi,
      /onclick\s*=/gi,
      /onmouseover\s*=/gi
    ];

    return xssPatterns.some(pattern => pattern.test(input));
  }

  /**
   * Check for SQL injection patterns
   */
  private static containsSQLInjection(input: string): boolean {
    const sqlPatterns = [
      /('|(\\')|(;)|(\-\-)|(\/\*)|(\*\/))/i,
      /(union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from)/i,
      /(or\s+1\s*=\s*1|and\s+1\s*=\s*1|or\s+true|and\s+true)/i,
      /(exec\s*\(|execute\s*\(|sp_|xp_)/i
    ];

    return sqlPatterns.some(pattern => pattern.test(input));
  }

  /**
   * Check for path traversal patterns
   */
  private static containsPathTraversal(input: string): boolean {
    const pathPatterns = [
      /\.\.\//g,
      /\.\.\\/g,
      /\.\.%2f/gi,
      /\.\.%5c/gi,
      /\.\.%252f/gi,
      /\.\.%255c/gi
    ];

    return pathPatterns.some(pattern => pattern.test(input));
  }

  /**
   * Check for command injection patterns
   */
  private static containsCommandInjection(input: string): boolean {
    const commandPatterns = [
      /[;&|`$()]/,
      /(rm\s+-rf|del\s+\/s|format\s+c:)/i,
      /(wget|curl|nc|netcat)/i,
      /(cat\s+\/etc\/passwd|type\s+c:\\windows\\system32\\drivers\\etc\\hosts)/i
    ];

    return commandPatterns.some(pattern => pattern.test(input));
  }

  /**
   * Check for injection patterns in IDs
   */
  private static containsInjectionPatterns(input: string): boolean {
    return this.containsXSS(input) || 
           this.containsSQLInjection(input) || 
           this.containsPathTraversal(input) ||
           this.containsCommandInjection(input);
  }

  /**
   * Validate email format
   */
  private static isValidEmailFormat(email: string): boolean {
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    return emailRegex.test(email);
  }

  /**
   * Check if password is common
   */
  private static isCommonPassword(password: string): boolean {
    const commonPasswords = [
      'password', '123456', '123456789', 'qwerty', 'abc123',
      'password123', 'admin', 'letmein', 'welcome', 'monkey',
      '1234567890', 'password1', 'qwerty123', 'dragon', 'master'
    ];

    return commonPasswords.includes(password.toLowerCase());
  }

  /**
   * Check if password contains personal information
   */
  private static containsPersonalInfo(password: string): boolean {
    // This would check against user profile data in a real implementation
    // For now, we'll check for common patterns
    const personalPatterns = [
      /(january|february|march|april|may|june|july|august|september|october|november|december)/i,
      /(monday|tuesday|wednesday|thursday|friday|saturday|sunday)/i,
      /(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)/i,
      /(mon|tue|wed|thu|fri|sat|sun)/i
    ];

    return personalPatterns.some(pattern => pattern.test(password));
  }

  /**
   * Validate URL is allowed
   */
  private static isAllowedUrl(url: string): boolean {
    try {
      const urlObj = new URL(url);
      const allowedProtocols = ['http:', 'https:'];
      const blockedDomains = ['localhost', '127.0.0.1', '0.0.0.0'];
      
      if (!allowedProtocols.includes(urlObj.protocol)) {
        return false;
      }

      if (blockedDomains.includes(urlObj.hostname)) {
        return false;
      }

      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get object depth
   */
  private static getObjectDepth(obj: any, depth: number = 0): number {
    if (typeof obj !== 'object' || obj === null) {
      return depth;
    }

    let maxDepth = depth;
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        const currentDepth = this.getObjectDepth(obj[key], depth + 1);
        maxDepth = Math.max(maxDepth, currentDepth);
      }
    }

    return maxDepth;
  }

  /**
   * Validate file name
   */
  private static isValidFileName(name: string): boolean {
    const invalidChars = /[<>:"/\\|?*\x00-\x1f]/;
    const reservedNames = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'];
    
    if (invalidChars.test(name)) {
      return false;
    }

    if (reservedNames.includes(name.toUpperCase())) {
      return false;
    }

    if (name.endsWith('.') || name.endsWith(' ')) {
      return false;
    }

    return true;
  }

  /**
   * Check if file type is allowed
   */
  private static isAllowedFileType(type: string): boolean {
    const allowedTypes = [
      'image/jpeg', 'image/png', 'image/gif', 'image/webp',
      'application/pdf', 'text/plain', 'text/csv',
      'application/json', 'application/xml'
    ];

    return allowedTypes.includes(type);
  }

  /**
   * Validate file content
   */
  private static isValidFileContent(content: string): boolean {
    // Basic content validation - in production, this would be more comprehensive
    return content.length > 0 && content.length < 10 * 1024 * 1024; // 10MB max
  }

  /**
   * Validate API path
   */
  private static isValidApiPath(path: string): boolean {
    const pathRegex = /^\/[a-zA-Z0-9\/\-_\.]*$/;
    return pathRegex.test(path) && !this.containsPathTraversal(path);
  }

  /**
   * Validate headers
   */
  private static areValidHeaders(headers: Record<string, string>): boolean {
    for (const [key, value] of Object.entries(headers)) {
      if (this.containsXSS(key) || this.containsXSS(value)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Validate request body
   */
  private static isValidRequestBody(body: any): boolean {
    if (typeof body === 'string') {
      return !this.containsXSS(body) && !this.containsSQLInjection(body);
    }
    return true;
  }

  /**
   * Sanitize search query
   */
  private static sanitizeSearchQuery(query: string): string {
    return query
      .replace(/[<>]/g, '') // Remove angle brackets
      .replace(/['"]/g, '') // Remove quotes
      .replace(/[;\\]/g, '') // Remove semicolons and backslashes
      .trim();
  }

  /**
   * Validate sort field
   */
  private static isValidSortField(field: string): boolean {
    const allowedFields = ['id', 'name', 'email', 'created_at', 'updated_at'];
    return allowedFields.includes(field);
  }

  /**
   * Sanitize data recursively
   */
  private static sanitizeData(data: any, config: ValidationConfig): any {
    if (typeof data === 'string') {
      return this.sanitizeString(data);
    }

    if (Array.isArray(data)) {
      return data.map(item => this.sanitizeData(item, config));
    }

    if (typeof data === 'object' && data !== null) {
      const sanitized: any = {};
      for (const [key, value] of Object.entries(data)) {
        sanitized[key] = this.sanitizeData(value, config);
      }
      return sanitized;
    }

    return data;
  }

  /**
   * Get severity from Zod error
   */
  private static getSeverityFromError(error: z.ZodIssue): 'low' | 'medium' | 'high' | 'critical' {
    switch (error.code) {
      case 'too_small':
      case 'too_big':
        return 'medium';
      case 'invalid_type':
        return 'high';
      case 'custom':
        return 'critical';
      default:
        return 'medium';
    }
  }
}

/**
 * Input Validation Middleware
 */
export function createInputValidationMiddleware<T>(
  schema: z.ZodSchema<T>,
  config?: Partial<ValidationConfig>
) {
  return async (c: any, next: () => Promise<void>) => {
    try {
      const body = await c.req.json();
      const validation = await InputValidationSchemas.validateInput(schema, body, config);

      if (!validation.success) {
        return c.json({
          error: 'Validation failed',
          details: validation.errors
        }, 400);
      }

      c.set('validatedData', validation.data);
      c.set('sanitizedData', validation.sanitizedData);
      await next();

    } catch (error) {
      return c.json({
        error: 'Invalid request format',
        details: 'Request body must be valid JSON'
      }, 400);
    }
  };
}
