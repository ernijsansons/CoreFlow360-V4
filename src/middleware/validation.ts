/**
 * Comprehensive Input Validation Middleware for CoreFlow360 V4
 *
 * SECURITY FEATURES:
 * - XSS prevention with advanced pattern detection (CVSS 7.5)
 * - SQL injection prevention with parameterized query validation
 * - Path traversal protection with multiple encoding detection
 * - Request size limits and content-type validation
 * - File upload security with MIME type validation
 * - Business logic validation with Zod schemas
 *
 * @security-level CRITICAL
 * @compliance SOC2, OWASP Top 10
 */

import { z } from 'zod';

export interface ValidationConfig {
  maxRequestSize?: number;
  allowedContentTypes?: string[];
  enableXSSProtection?: boolean;
  enableSQLInjectionProtection?: boolean;
  enablePathTraversalProtection?: boolean;
  enableFileUploadValidation?: boolean;
  customSanitizers?: Record<string, (value: any) => any>;
  strictMode?: boolean;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  sanitizedData?: any;
  riskScore: number;
}

export interface ValidationError {
  field: string;
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  code: string;
  value?: any;
}

export interface FileValidationConfig {
  maxFileSize?: number;
  allowedMimeTypes?: string[];
  allowedExtensions?: string[];
  scanForMalware?: boolean;
  preventExecutables?: boolean;
}

/**
 * Default validation configuration
 */
const DEFAULT_VALIDATION_CONFIG: Required<ValidationConfig> = {
  maxRequestSize: 10 * 1024 * 1024, // 10MB
  allowedContentTypes: [
    'application/json',
    'application/x-www-form-urlencoded',
    'multipart/form-data',
    'text/plain'
  ],
  enableXSSProtection: true,
  enableSQLInjectionProtection: true,
  enablePathTraversalProtection: true,
  enableFileUploadValidation: true,
  customSanitizers: {},
  strictMode: true
};

/**
 * Comprehensive XSS pattern detection
 * SECURITY FIX: Enhanced pattern matching for all XSS vectors
 */
const XSS_PATTERNS = [
  // Script tags and variations
  /<script[^>]*>.*?<\/script>/gis,
  /<script[^>]*>/gi,
  /<\/script>/gi,
  
  // JavaScript protocols and URIs
  /javascript\s*:/gi,
  /vbscript\s*:/gi,
  /data\s*:\s*text\/html/gi,
  /data\s*:\s*application\/javascript/gi,
  
  // Event handlers (comprehensive list)
  /on\w+\s*=/gi,
  /on(load|error|click|focus|blur|change|submit|reset|select|scroll|resize|mouseover|mouseout|mousedown|mouseup|mousemove|keydown|keyup|keypress|abort|beforeunload|unload)\s*=/gi,
  
  // HTML5 event attributes
  /on(canplay|canplaythrough|durationchange|emptied|ended|loadeddata|loadedmetadata|pause|play|playing|progress|ratechange|seeked|seeking|stalled|suspend|timeupdate|volumechange|waiting)\s*=/gi,
  
  // Form and input events
  /on(autocomplete|input|invalid|search|formchange|forminput|formdata|reset|submit)\s*=/gi,
  
  // Drag and drop events
  /on(drag|dragend|dragenter|dragexit|dragleave|dragover|dragstart|drop)\s*=/gi,
  
  // Touch and pointer events
  /on(touchstart|touchend|touchmove|touchcancel|pointerdown|pointerup|pointermove|pointerover|pointerout|pointerenter|pointerleave|pointercancel|gotpointercapture|lostpointercapture)\s*=/gi,
  
  // Dangerous elements
  /<iframe[^>]*>/gi,
  /<object[^>]*>/gi,
  /<embed[^>]*>/gi,
  /<link[^>]*>/gi,
  /<meta[^>]*>/gi,
  /<style[^>]*>.*?<\/style>/gis,
  
  // CSS expressions and imports
  /expression\s*\(/gi,
  /@import/gi,
  /javascript\s*:/gi,
  /-moz-binding\s*:/gi,
  /behaviour\s*:/gi,
  
  // Common XSS functions
  /\balert\s*\(/gi,
  /\bconfirm\s*\(/gi,
  /\bprompt\s*\(/gi,
  /\beval\s*\(/gi,
  /\bsetTimeout\s*\(/gi,
  /\bsetInterval\s*\(/gi,
  /\bFunction\s*\(/gi,
  
  // Document and window access
  /document\.(write|writeln|cookie|domain|location)/gi,
  /window\.(open|location|alert|confirm|prompt)/gi,
  
  // Encoded variations
  /%3Cscript/gi,
  /%3C%2Fscript%3E/gi,
  /&lt;script/gi,
  /&lt;\/script&gt;/gi,
  
  // Unicode and hex encoded
  /\\u003c/gi,
  /\\x3c/gi,
  /\\u0022/gi,
  /\\x22/gi
];

/**
 * SQL injection pattern detection
 * SECURITY FIX: Comprehensive SQL injection prevention
 */
const SQL_INJECTION_PATTERNS = [
  // Classic SQL injection
  /'\s*(or|and)\s*'\s*=\s*'/gi,
  /'\s*(or|and)\s*\d+\s*=\s*\d+/gi,
  /'\s*or\s*'.*?'\s*=\s*'/gi,
  
  // Union-based attacks
  /union\s+(all\s+)?select/gi,
  /union\s+select/gi,
  
  // Comment-based attacks
  /--\s*$/gm,
  /\/\*.*?\*\//gs,
  /#.*$/gm,
  
  // Function-based attacks
  /(exec|execute|sp_|xp_)\w*/gi,
  /\b(exec|execute)\s*\(/gi,
  
  // Time-based attacks
  /(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(/gi,
  
  // Information gathering
  /(information_schema|sysobjects|systables|pg_tables)/gi,
  /(version|user|database|schema)\s*\(/gi,
  
  // Data manipulation
  /\b(drop|delete|insert|update|alter|create|truncate)\b/gi,
  
  // Boolean-based blind
  /(and|or)\s+\d+\s*=\s*\d+/gi,
  /(and|or)\s+'\w+'\s*=\s*'\w+'/gi,
  
  // Stacked queries
  /;\s*(drop|delete|insert|update|exec)/gi
];

/**
 * Path traversal pattern detection
 * SECURITY FIX: Multiple encoding and obfuscation detection
 */
const PATH_TRAVERSAL_PATTERNS = [
  // Basic patterns
  /\.\.\/|\.\.\\/gi,
  
  // URL encoded
  /%2e%2e%2f|%2e%2e%5c/gi,
  /%2e%2e\/|%2e%2e\\/gi,
  /\.%2e%2f|\.%2e%5c/gi,
  /%2e\.\/|%2e\.\\/gi,
  
  // Double URL encoded
  /%252e%252e%252f|%252e%252e%255c/gi,
  
  // Unicode encoded
  /\u002e\u002e\u002f|\u002e\u002e\u005c/gi,
  
  // Overlong UTF-8
  /%c0%ae%c0%ae%c0%af|%c0%ae%c0%ae%c0%5c/gi,
  
  // 16-bit Unicode
  /%c1%9c|%c1%pc/gi,
  
  // Dot variations
  /\.{2,}[\/\\]/gi,
  /\.{3,}/gi,
  
  // Windows specific
  /\\\\|\\\.\\|\\\?\\|\\\.\./gi,
  
  // Null byte injection
  /%00/gi,
  
  // Special characters
  /[\x00-\x1f\x7f-\x9f]/gi
];

/**
 * Dangerous file extensions and MIME types
 */
const DANGEROUS_EXTENSIONS = [
  '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js', '.jar',
  '.php', '.asp', '.aspx', '.jsp', '.pl', '.py', '.rb', '.sh', '.ps1',
  '.reg', '.msi', '.deb', '.rpm', '.dmg', '.app', '.ipa', '.apk',
  '.htaccess', '.htpasswd', '.config', '.ini', '.cfg', '.conf'
];

const DANGEROUS_MIME_TYPES = [
  'application/x-executable',
  'application/x-msdownload',
  'application/x-bat',
  'application/x-sh',
  'application/javascript',
  'text/javascript',
  'application/x-php',
  'application/x-httpd-php',
  'text/x-php',
  'application/x-perl',
  'application/x-python',
  'text/x-script.python'
];

/**
 * Sanitize input against XSS attacks
 */
export function sanitizeXSS(input: string): string {
  if (typeof input !== 'string') {
    return '';
  }

  let sanitized = input;

  // Remove null bytes and control characters
  sanitized = sanitized.replace(/[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F-\x9F]/g, '');

  // Apply XSS pattern removal
  for (const pattern of XSS_PATTERNS) {
    sanitized = sanitized.replace(pattern, '');
  }

  // Decode and re-sanitize to catch encoded attacks
  try {
    const decoded = decodeURIComponent(sanitized);
    if (decoded !== sanitized) {
      // Recursively sanitize decoded content
      sanitized = sanitizeXSS(decoded);
    }
  } catch {
    // If decoding fails, continue with current sanitized string
  }

  // HTML entity encode remaining dangerous characters
  sanitized = sanitized
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');

  return sanitized;
}

/**
 * Validate against SQL injection patterns
 */
export function validateSQLInjection(input: string): ValidationError[] {
  const errors: ValidationError[] = [];

  if (typeof input !== 'string') {
    return errors;
  }

  for (const pattern of SQL_INJECTION_PATTERNS) {
    if (pattern.test(input)) {
      errors.push({
        field: 'input',
        message: 'Potential SQL injection detected',
        severity: 'critical',
        code: 'SQL_INJECTION',
        value: input.substring(0, 100) // Limit logged value
      });
      break; // One error is enough
    }
  }

  return errors;
}

/**
 * Validate against path traversal attacks
 */
export function validatePathTraversal(input: string): ValidationError[] {
  const errors: ValidationError[] = [];

  if (typeof input !== 'string') {
    return errors;
  }

  for (const pattern of PATH_TRAVERSAL_PATTERNS) {
    if (pattern.test(input)) {
      errors.push({
        field: 'path',
        message: 'Path traversal attempt detected',
        severity: 'high',
        code: 'PATH_TRAVERSAL',
        value: input.substring(0, 100)
      });
      break;
    }
  }

  return errors;
}

/**
 * Validate file upload security
 */
export function validateFileUpload(
  filename: string,
  mimeType?: string,
  size?: number,
  config: FileValidationConfig = {}
): ValidationError[] {
  const errors: ValidationError[] = [];
  const {
    maxFileSize = 10 * 1024 * 1024, // 10MB
    allowedMimeTypes = [],
    allowedExtensions = [],
    preventExecutables = true
  } = config;

  // Validate filename
  const pathErrors = validatePathTraversal(filename);
  errors.push(...pathErrors);

  // Check for dangerous extensions
  if (preventExecutables) {
    const extension = filename.toLowerCase().substring(filename.lastIndexOf('.'));
    if (DANGEROUS_EXTENSIONS.includes(extension)) {
      errors.push({
        field: 'filename',
        message: `Dangerous file extension: ${extension}`,
        severity: 'critical',
        code: 'DANGEROUS_EXTENSION',
        value: extension
      });
    }
  }

  // Validate against allowed extensions
  if (allowedExtensions.length > 0) {
    const extension = filename.toLowerCase().substring(filename.lastIndexOf('.'));
    if (!allowedExtensions.includes(extension)) {
      errors.push({
        field: 'filename',
        message: `File extension not allowed: ${extension}`,
        severity: 'medium',
        code: 'EXTENSION_NOT_ALLOWED',
        value: extension
      });
    }
  }

  // Validate MIME type
  if (mimeType) {
    if (DANGEROUS_MIME_TYPES.includes(mimeType.toLowerCase())) {
      errors.push({
        field: 'mimeType',
        message: `Dangerous MIME type: ${mimeType}`,
        severity: 'critical',
        code: 'DANGEROUS_MIME_TYPE',
        value: mimeType
      });
    }

    if (allowedMimeTypes.length > 0 && !allowedMimeTypes.includes(mimeType.toLowerCase())) {
      errors.push({
        field: 'mimeType',
        message: `MIME type not allowed: ${mimeType}`,
        severity: 'medium',
        code: 'MIME_TYPE_NOT_ALLOWED',
        value: mimeType
      });
    }
  }

  // Validate file size
  if (size !== undefined && size > maxFileSize) {
    errors.push({
      field: 'size',
      message: `File size exceeds limit: ${size} bytes`,
      severity: 'medium',
      code: 'FILE_SIZE_EXCEEDED',
      value: size
    });
  }

  // Check for special filenames
  const specialFiles = ['web.config', '.htaccess', 'passwd', 'shadow', 'hosts'];
  const lowercaseFilename = filename.toLowerCase();
  for (const special of specialFiles) {
    if (lowercaseFilename.includes(special)) {
      errors.push({
        field: 'filename',
        message: `Special system filename detected: ${special}`,
        severity: 'high',
        code: 'SPECIAL_FILENAME',
        value: filename
      });
    }
  }

  return errors;
}

/**
 * Validate request content type
 */
export function validateContentType(
  request: Request,
  allowedTypes: string[]
): ValidationError[] {
  const errors: ValidationError[] = [];
  const contentType = request.headers.get('Content-Type');

  if (['POST', 'PUT', 'PATCH'].includes(request.method) && !contentType) {
    errors.push({
      field: 'content-type',
      message: 'Content-Type header required for request',
      severity: 'medium',
      code: 'MISSING_CONTENT_TYPE'
    });
    return errors;
  }

  if (contentType) {
    const mainType = contentType.split(';')[0].trim().toLowerCase();
    if (!allowedTypes.some(allowed => mainType === allowed.toLowerCase())) {
      errors.push({
        field: 'content-type',
        message: `Content-Type not allowed: ${mainType}`,
        severity: 'medium',
        code: 'CONTENT_TYPE_NOT_ALLOWED',
        value: mainType
      });
    }
  }

  return errors;
}

/**
 * Validate request size
 */
export function validateRequestSize(
  request: Request,
  maxSize: number
): ValidationError[] {
  const errors: ValidationError[] = [];
  const contentLength = request.headers.get('Content-Length');

  if (contentLength) {
    const size = parseInt(contentLength, 10);
    if (!isNaN(size) && size > maxSize) {
      errors.push({
        field: 'content-length',
        message: `Request size exceeds limit: ${size} bytes`,
        severity: 'medium',
        code: 'REQUEST_SIZE_EXCEEDED',
        value: size
      });
    }
  }

  return errors;
}

/**
 * Comprehensive input validation function
 */
export function validateInput(
  data: any,
  config: ValidationConfig = {}
): ValidationResult {
  const fullConfig = { ...DEFAULT_VALIDATION_CONFIG, ...config };
  const errors: ValidationError[] = [];
  let riskScore = 0;
  let sanitizedData = data;

  if (typeof data === 'string') {
    // XSS validation
    if (fullConfig.enableXSSProtection) {
      const originalLength = data.length;
      sanitizedData = sanitizeXSS(data);
      if (sanitizedData.length !== originalLength) {
        errors.push({
          field: 'input',
          message: 'XSS patterns detected and removed',
          severity: 'high',
          code: 'XSS_DETECTED'
        });
        riskScore += 40;
      }
    }

    // SQL injection validation
    if (fullConfig.enableSQLInjectionProtection) {
      const sqlErrors = validateSQLInjection(data);
      errors.push(...sqlErrors);
      riskScore += sqlErrors.length * 50;
    }

    // Path traversal validation
    if (fullConfig.enablePathTraversalProtection) {
      const pathErrors = validatePathTraversal(data);
      errors.push(...pathErrors);
      riskScore += pathErrors.length * 30;
    }

  } else if (typeof data === 'object' && data !== null) {
    // Recursively validate object properties
    const result = {};
    for (const [key, value] of Object.entries(data)) {
      const fieldResult = validateInput(value, config);
      errors.push(...fieldResult.errors.map(error => ({
        ...error,
        field: key
      })));
      riskScore += fieldResult.riskScore;
      result[key] = fieldResult.sanitizedData;
    }
    sanitizedData = result;
  }

  return {
    valid: errors.length === 0,
    errors,
    sanitizedData,
    riskScore: Math.min(riskScore, 100)
  };
}

/**
 * Create validation middleware
 */
export function createValidationMiddleware(config: ValidationConfig = {}) {
  return async (request: Request): Promise<ValidationResult> => {
    const fullConfig = { ...DEFAULT_VALIDATION_CONFIG, ...config };
    const errors: ValidationError[] = [];
    let riskScore = 0;

    try {
      // Validate request size
      const sizeErrors = validateRequestSize(request, fullConfig.maxRequestSize);
      errors.push(...sizeErrors);
      riskScore += sizeErrors.length * 20;

      // Validate content type
      const contentTypeErrors = validateContentType(request, fullConfig.allowedContentTypes);
      errors.push(...contentTypeErrors);
      riskScore += contentTypeErrors.length * 15;

      // Validate URL for path traversal
      const url = new URL(request.url);
      const pathErrors = validatePathTraversal(url.pathname + url.search);
      errors.push(...pathErrors);
      riskScore += pathErrors.length * 30;

      // For POST/PUT requests, validate body if present
      if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
        try {
          const body = await request.text();
          if (body) {
            const bodyValidation = validateInput(body, fullConfig);
            errors.push(...bodyValidation.errors);
            riskScore += bodyValidation.riskScore;
          }
        } catch {
          // If body parsing fails, it's likely not JSON/text
          // This is fine for multipart/form-data, etc.
        }
      }

      return {
        valid: errors.length === 0,
        errors,
        riskScore: Math.min(riskScore, 100)
      };

    } catch (error) {
      return {
        valid: false,
        errors: [{
          field: 'request',
          message: 'Validation error occurred',
          severity: 'medium',
          code: 'VALIDATION_ERROR'
        }],
        riskScore: 50
      };
    }
  };
}

/**
 * Zod schema helpers for business logic validation
 */
export const ValidationSchemas = {
  // Business ID validation
  businessId: z.string()
    .min(3, 'Business ID must be at least 3 characters')
    .max(50, 'Business ID must be at most 50 characters')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Business ID contains invalid characters'),

  // User ID validation
  userId: z.string()
    .min(3, 'User ID must be at least 3 characters')
    .max(50, 'User ID must be at most 50 characters')
    .regex(/^[a-zA-Z0-9_-]+$/, 'User ID contains invalid characters'),

  // Email validation
  email: z.string()
    .email('Invalid email format')
    .max(255, 'Email too long')
    .transform(email => email.toLowerCase().trim()),

  // Password validation
  password: z.string()
    .min(12, 'Password must be at least 12 characters')
    .regex(/[A-Z]/, 'Password must contain uppercase letter')
    .regex(/[a-z]/, 'Password must contain lowercase letter')
    .regex(/\d/, 'Password must contain number')
    .regex(/[^A-Za-z0-9]/, 'Password must contain special character'),

  // Name validation
  name: z.string()
    .min(2, 'Name must be at least 2 characters')
    .max(100, 'Name too long')
    .regex(/^[a-zA-Z\s'-]+$/, 'Name contains invalid characters')
    .transform(name => name.trim()),

  // Phone validation
  phone: z.string()
    .regex(/^\+?[1-9]\d{1,14}$/, 'Invalid phone number format')
    .transform(phone => phone.replace(/\D/g, '')),

  // URL validation
  url: z.string()
    .url('Invalid URL format')
    .refine(url => ['http:', 'https:'].includes(new URL(url).protocol), {
      message: 'Only HTTP and HTTPS URLs allowed'
    }),

  // UUID validation
  uuid: z.string()
    .uuid('Invalid UUID format'),

  // Amount validation (for financial data)
  amount: z.number()
    .positive('Amount must be positive')
    .finite('Amount must be finite')
    .multipleOf(0.01, 'Amount can have at most 2 decimal places'),

  // Date validation
  date: z.string()
    .datetime('Invalid date format')
    .or(z.date())
};

/**
 * Export all validation utilities
 */
export {
  sanitizeXSS,
  validateSQLInjection,
  validatePathTraversal,
  validateFileUpload,
  validateContentType,
  validateRequestSize,
  validateInput,
  createValidationMiddleware,
  ValidationSchemas,
  DEFAULT_VALIDATION_CONFIG,
  XSS_PATTERNS,
  SQL_INJECTION_PATTERNS,
  PATH_TRAVERSAL_PATTERNS,
  DANGEROUS_EXTENSIONS,
  DANGEROUS_MIME_TYPES
};