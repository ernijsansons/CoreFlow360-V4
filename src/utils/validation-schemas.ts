/**
 * Comprehensive Input Validation Schemas - Enhanced Security
 * Prevents injection attacks and ensures data integrity
 * Updated with enterprise-grade security validation
 */

import { z } from 'zod';
import { preventXSS, sanitizeInput } from '../middleware/security';

// =====================================================
// ENHANCED SECURITY VALIDATION PATTERNS
// =====================================================

// Security-enhanced string validators with XSS and SQL injection prevention
const secureString = (minLength = 1, maxLength = 255) =>
  z.string()
    .min(minLength, `Must be at least ${minLength} characters`)
    .max(maxLength, `Must be at most ${maxLength} characters`)
    .transform((str) => preventXSS(str))
    .refine((str) => !str.includes('<script'), 'Contains potentially dangerous content')
    .refine((str) => !str.includes('javascript:'), 'Contains potentially dangerous content');

const secureId = z.string()
  .min(1)
  .max(100)
  .regex(/^[a-zA-Z0-9_-]+$/, 'Invalid ID format')
  .transform((str) => preventXSS(str));

const secureBusinessId = z.string()
  .min(1)
  .max(100)
  .regex(/^biz_[a-zA-Z0-9_-]+$/, 'Invalid business ID format')
  .transform((str) => preventXSS(str));

const secureEmail = z.string()
  .email('Invalid email format')
  .max(254, 'Email too long')
  .toLowerCase()
  .transform((email) => preventXSS(email.trim()))
  .refine((email) => {
    // Additional email security checks
    const dangerousPatterns = ['<script', 'javascript:', 'onclick', 'onerror', 'onload'];
    return !dangerousPatterns.some(pattern => email.includes(pattern));
  }, 'Email contains potentially dangerous content');

const securePhone = z.string()
  .regex(/^\+?[1-9]\d{1,14}$/, 'Invalid phone number format')
  .optional()
  .transform((phone) => phone ? preventXSS(phone) : phone);

const secureName = z.string()
  .min(1)
  .max(100)
  .regex(/^[a-zA-Z\s'-]+$/, 'Name contains invalid characters')
  .transform((name) => preventXSS(name));

const secureText = z.string()
  .max(10000)
  .transform((text) => preventXSS(text.trim()))
  .refine((text) => {
    // Check for potential SQL injection patterns
    const sqlPatterns = ['union select', 'drop table', 'insert into', 'delete from', '--', ';'];
    const lowerText = text.toLowerCase();
    return !sqlPatterns.some(pattern => lowerText.includes(pattern));
  }, 'Contains potentially dangerous content');

const secureUrl = z.string()
  .url('Invalid URL format')
  .max(2048)
  .refine((url) => {
    try {
      const parsed = new URL(url);
      // Only allow http and https protocols
      return ['http:', 'https:'].includes(parsed.protocol);
    } catch {
      return false;
    }
  }, 'Invalid or unsafe URL protocol');

// Strong password validation
const strongPassword = z.string()
  .min(12, 'Password must be at least 12 characters')
  .max(128, 'Password too long')
  .refine((password) => /[A-Z]/.test(password), 'Password must contain at least one uppercase letter')
  .refine((password) => /[a-z]/.test(password), 'Password must contain at least one lowercase letter')
  .refine((password) => /\d/.test(password), 'Password must contain at least one number')
  .refine((password) => /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password), 'Password must contain at least one special character')
  .refine((password) => {
    // Check against common passwords
    const commonPasswords = ['password123', 'admin123', 'welcome123', 'qwerty123'];
    return !commonPasswords.includes(password.toLowerCase());
  }, 'Password is too common')
  .refine((password) => !/(.)\1{2,}/.test(password), 'Password cannot have more than 2 consecutive identical characters');

// Backwards compatibility aliases
const safeId = secureId;
const safeBusinessId = secureBusinessId;
const safeEmail = secureEmail;
const safePhone = securePhone;
const safeName = secureName;
const safeText = secureText;
const safeUrl = secureUrl;

const _pagination = z.object({
  page: z.number().int().min(1).default(1),
  limit: z.number().int().min(1).max(100).default(20),
  sortBy: z.string().regex(/^[a-zA-Z_]+$/).optional(),
  sortOrder: z.enum(['asc', 'desc']).default('asc')
});

// =====================================================
// CRM SCHEMAS
// =====================================================

export const leadSchema = z.object({
  businessId: safeBusinessId,
  firstName: safeName,
  lastName: safeName,
  email: safeEmail,
  phone: safePhone,
  company: z.string().max(255).optional(),
  title: z.string().max(100).optional(),
  source: z.enum(['website', 'email', 'phone', 'social', 'referral', 'paid_ad', 'organic', 'direct']),
  status: z.enum(['new', 'contacted', 'qualified', 'unqualified', 'converted', 'lost']),
  score: z.number().min(0).max(100).optional(),
  tags: z.array(z.string().max(50)).max(20).optional(),
  customFields: z.record(z.unknown()).optional(),
  assignedTo: safeId.optional()
}).strict();

export const opportunitySchema = z.object({
  businessId: safeBusinessId,
  leadId: safeId,
  name: z.string().min(1).max(255),
  value: z.number().min(0).max(1000000000), // Max $1B
  stage: z.enum(['prospecting', 'qualification', 'proposal', 'negotiation', 'closing', 'closed_won', 'closed_lost']),
  probability: z.number().min(0).max(100),
  closeDate: z.string().datetime(),
  ownerId: safeId,
  description: safeText.optional(),
  competitors: z.array(z.string().max(100)).max(10).optional(),
  nextSteps: safeText.optional()
}).strict();

export const interactionSchema = z.object({
  businessId: safeBusinessId,
  leadId: safeId,
  type: z.enum(['email', 'call', 'meeting', 'chat', 'social', 'demo', 'proposal']),
  channel: z.enum(['email', 'phone', 'linkedin', 'website', 'whatsapp', 'slack', 'other']),
  direction: z.enum(['inbound', 'outbound']),
  subject: z.string().max(255).optional(),
  content: safeText,
  duration: z.number().min(0).max(86400).optional(), // Max 24 hours in seconds
  outcome: z.enum(['positive', 'neutral', 'negative']).optional(),
  nextAction: safeText.optional(),
  scheduledAt: z.string().datetime().optional()
}).strict();

// =====================================================
// LEARNING SYSTEM SCHEMAS
// =====================================================

export const recordOutcomeSchema = z.object({
  businessId: safeBusinessId,
  interactionId: safeId,
  leadId: safeId,
  type: z.enum(['email', 'call', 'meeting', 'chat', 'demo']),
  channel: z.enum(['email', 'phone', 'linkedin', 'website', 'whatsapp']),
  strategy: z.string().max(100),
  variant: safeId.optional(),
  content: safeText,
  context: z.record(z.unknown()).optional(),
  timing: z.enum(['immediate', 'morning', 'afternoon', 'evening', 'weekend']).optional(),
  outcome: z.object({
    success: z.boolean(),
    result: z.enum(['responded', 'meeting_booked', 'rejected', 'no_response', 'unsubscribed']),
    responseTime: z.number().min(0).max(10080).optional(), // Max 1 week in minutes
    sentiment: z.enum(['positive', 'neutral', 'negative']).optional(),
    qualityScore: z.number().min(0).max(1).optional(),
    notes: z.string().max(1000).optional()
  }).strict()
}).strict();

export const patternAnalysisSchema = z.object({
  businessId: safeBusinessId,
  type: z.enum(['all', 'winning', 'channel', 'timing', 'content', 'objection', 'sequence', 'closing']),
  timeframe: z.enum(['7d', '30d', '90d', '180d', '365d']).default('30d'),
  segmentId: safeId.optional(),
  minConfidence: z.number().min(0).max(1).default(0.5)
}).strict();

export const playbookGenerationSchema = z.object({
  businessId: safeBusinessId,
  segmentId: safeId,
  segmentName: z.string().min(1).max(100),
  criteria: z.object({
    industry: z.array(z.string().max(50)).optional(),
    companySize: z.enum(['1-10', '11-50', '51-200', '201-500', '500+']).optional(),
    region: z.array(z.string().max(50)).optional(),
    technology: z.array(z.string().max(50)).optional(),
    budget: z.object({
      min: z.number().min(0).optional(),
      max: z.number().min(0).optional()
    }).optional()
  }),
  characteristics: z.object({
    typicalChallenges: z.array(z.string().max(255)).max(10),
    decisionMakers: z.array(z.string().max(100)).max(10),
    preferredChannels: z.array(z.enum(['email', 'phone', 'linkedin', 'in-person'])),
    communicationStyle: z.enum(['formal', 'casual', 'technical', 'executive']),
    buyingCycle: z.enum(['immediate', 'short', 'medium', 'long']).optional()
  })
}).strict();

// =====================================================
// INTEGRATION SCHEMAS
// =====================================================

export const integrationConfigSchema = z.object({
  businessId: safeBusinessId,
  name: z.string().min(1).max(100),
  type: z.enum(['marketing', 'sales', 'communication', 'enrichment', 'analytics', 'accounting']),
  provider: z.enum(['meta', 'google', 'hubspot', 'salesforce', 'twilio', 'sendgrid', 'clearbit', 'segment']),
  credentials: z.object({
    apiKey: z.string().max(500).optional(),
    apiSecret: z.string().max(500).optional(),
    accessToken: z.string().max(2000).optional(),
    refreshToken: z.string().max(2000).optional()
  }).strict(),
  config: z.object({
    webhookUrl: safeUrl.optional(),
    syncInterval: z.number().min(1).max(1440).optional(), // Max 24 hours in minutes
    syncDirection: z.enum(['inbound', 'outbound', 'bidirectional']),
    options: z.record(z.unknown()).optional()
  }).strict()
}).strict();

export const syncRequestSchema = z.object({
  businessId: safeBusinessId,
  integrationId: safeId,
  direction: z.enum(['inbound', 'outbound', 'bidirectional']).optional(),
  force: z.boolean().default(false)
}).strict();

// =====================================================
// WORKFLOW SCHEMAS
// =====================================================

export const workflowSchema = z.object({
  businessId: safeBusinessId,
  name: z.string().min(1).max(255),
  description: safeText.optional(),
  trigger: z.object({
    type: z.enum(['webhook', 'schedule', 'event', 'manual', 'condition']),
    config: z.record(z.unknown())
  }),
  actions: z.array(z.object({
    type: z.enum([
      'send_email', 'send_sms', 'make_call', 'create_task',
      'update_field', 'assign_lead', 'score_lead', 'enrich_data',
      'create_invoice', 'send_notification', 'http_request',
      'custom_code', 'ai_action'
    ]),
    name: z.string().max(100),
    config: z.record(z.unknown()),
    conditions: z.array(z.object({
      field: z.string().max(100),
      operator: z.enum(['equals', 'not_equals', 'contains', 'greater_than', 'less_than']),
      value: z.unknown()
    })).optional()
  })).max(50), // Max 50 actions per workflow
  enabled: z.boolean().default(false)
}).strict();

export const workflowExecutionSchema = z.object({
  businessId: safeBusinessId,
  workflowId: safeId,
  context: z.record(z.unknown()).optional(),
  triggeredBy: z.string().max(100).default('manual')
}).strict();

// =====================================================
// ANALYTICS SCHEMAS
// =====================================================

export const dashboardRequestSchema = z.object({
  businessId: safeBusinessId,
  userId: safeId.optional(),
  role: z.enum(['sales_rep', 'sales_manager', 'executive', 'ops', 'customer_success', 'marketing']),
  timeframe: z.enum(['today', 'yesterday',
  'this_week', 'last_week', 'this_month', 'last_month', 'this_quarter', 'this_year']).optional(),
  filters: z.record(z.unknown()).optional()
}).strict();

export const reportRequestSchema = z.object({
  businessId: safeBusinessId,
  type: z.enum(['sales', 'marketing', 'customer', 'financial', 'operational']),
  format: z.enum(['pdf', 'excel', 'csv', 'json']),
  timeframe: z.object({
    start: z.string().datetime(),
    end: z.string().datetime()
  }),
  filters: z.array(z.object({
    field: z.string().max(100),
    operator: z.string().max(20),
    value: z.unknown()
  })).optional(),
  groupBy: z.array(z.string().max(100)).optional(),
  includeCharts: z.boolean().default(true)
}).strict();

export const metricQuerySchema = z.object({
  businessId: safeBusinessId,
  metric: z.string().max(100),
  timeframe: z.string().max(20),
  groupBy: z.string().max(100).optional(),
  filters: z.record(z.unknown()).optional()
}).strict();

// =====================================================
// VALIDATION HELPERS
// =====================================================

/**
 * Validate and sanitize input data
 */
export function validateInput<T>(schema: z.ZodSchema<T>, data: unknown): T {
  try {
    return schema.parse(data);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const issues = error.issues.map(issue => ({
        field: issue.path.join('.'),
        message: issue.message
      }));
      throw new ValidationError('Validation failed', issues);
    }
    throw error;
  }
}

/**
 * Custom validation error class
 */
export class ValidationError extends Error {
  constructor(
    message: string,
    public issues: Array<{ field: string; message: string }>
  ) {
    super(message);
    this.name = 'ValidationError';
  }
}

/**
 * Sanitize SQL identifiers (table/column names)
 */
export function sanitizeSQLIdentifier(identifier: string): string {
  // Only allow alphanumeric and underscore
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(identifier)) {
    throw new Error('Invalid SQL identifier');
  }
  return identifier;
}

/**
 * Sanitize search queries
 */
export function sanitizeSearchQuery(query: string): string {
  // Remove SQL keywords and special characters
  const sqlKeywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER', 'UNION', 'OR', '--', ';'];
  let sanitized = query;

  for (const keyword of sqlKeywords) {
    const regex = new RegExp(keyword, 'gi');
    sanitized = sanitized.replace(regex, '');
  }

  // Remove special characters except spaces and basic punctuation
  sanitized = sanitized.replace(/[^\w\s.,!?-]/g, '');

  return sanitized.trim();
}

/**
 * Validate business context
 */
export function validateBusinessContext(
  businessId: string,
  userId: string,
  _requiredRole?: string
): void {
  if (!businessId || !safeBusinessId.safeParse(businessId).success) {
    throw new Error('Invalid business context');
  }

  if (!userId || !safeId.safeParse(userId).success) {
    throw new Error('Invalid user context');
  }

  // Additional role-based validation would go here
}

/**
 * Create paginated response
 */
export function createPaginatedResponse<T>(
  data: T[],
  page: number,
  limit: number,
  total: number
) {
  return {
    data,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      hasNext: page * limit < total,
      hasPrev: page > 1
    }
  };
}

// =====================================================
// ENHANCED AUTHENTICATION SCHEMAS
// =====================================================

export const secureLoginSchema = z.object({
  email: secureEmail,
  password: z.string().min(1, 'Password is required').max(128, 'Password too long'),
  remember_me: z.boolean().optional().default(false),
  mfa_token: z.string().optional().regex(/^[0-9]{6}$|^[A-Z0-9]{8}$/, 'Invalid MFA token format'),
  device_fingerprint: secureString(0, 500).optional()
}).strict();

export const secureRegisterSchema = z.object({
  business_name: secureString(2, 100),
  business_slug: z.string()
    .min(2, 'Slug too short')
    .max(50, 'Slug too long')
    .regex(/^[a-z0-9-]+$/, 'Slug must contain only lowercase letters, numbers, and hyphens')
    .transform((slug) => preventXSS(slug)),
  email: secureEmail,
  password: strongPassword,
  first_name: secureName,
  last_name: secureName,
  terms_accepted: z.boolean().refine(val => val === true, 'Terms must be accepted'),
  privacy_accepted: z.boolean().refine(val => val === true, 'Privacy policy must be accepted'),
  marketing_accepted: z.boolean().optional().default(false),
  company_size: z.enum(['1-10', '11-50', '51-200', '201-1000', '1000+']).optional(),
  industry: secureString(0, 100).optional()
}).strict();

export const securePasswordResetRequestSchema = z.object({
  email: secureEmail,
  captcha_token: secureString(0, 1000).optional()
}).strict();

export const securePasswordResetConfirmSchema = z.object({
  token: z.string()
    .min(1, 'Reset token is required')
    .max(500, 'Reset token too long')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Invalid reset token format'),
  password: strongPassword,
  confirm_password: z.string()
}).refine((data) => data.password === data.confirm_password, {
  message: "Passwords don't match",
  path: ["confirm_password"]
}).strict();

export const secureChangePasswordSchema = z.object({
  current_password: z.string().min(1, 'Current password is required').max(128),
  new_password: strongPassword,
  confirm_password: z.string()
}).refine((data) => data.new_password === data.confirm_password, {
  message: "Passwords don't match",
  path: ["confirm_password"]
}).refine((data) => data.current_password !== data.new_password, {
  message: "New password must be different from current password",
  path: ["new_password"]
}).strict();

// =====================================================
// SECURITY VALIDATION HELPERS
// =====================================================

/**
 * Enhanced validation with comprehensive security checks
 */
export function validateWithSecurity<T>(
  schema: z.ZodSchema<T>, 
  data: unknown,
  options: {
    sanitize?: boolean;
    checkBusinessId?: string;
    requireAuth?: boolean;
  } = {}
): {
  success: boolean;
  data?: T;
  errors?: z.ZodError;
  securityIssues?: string[];
} {
  const securityIssues: string[] = [];

  try {
    // Pre-validation security checks
    if (typeof data === 'object' && data !== null) {
      const dataStr = JSON.stringify(data);
      
      // Check for potential XSS
      if (dataStr.includes('<script') || dataStr.includes('javascript:')) {
        securityIssues.push('Potential XSS content detected');
      }
      
      // Check for potential SQL injection
      const sqlPatterns = ['union select', 'drop table', 'insert into', 'delete from'];
      if (sqlPatterns.some(pattern => dataStr.toLowerCase().includes(pattern))) {
        securityIssues.push('Potential SQL injection detected');
      }
      
      // Check for oversized payloads
      if (dataStr.length > 1000000) { // 1MB limit
        securityIssues.push('Payload too large');
      }
    }

    if (securityIssues.length > 0) {
      return {
        success: false,
        securityIssues
      };
    }

    // Perform schema validation
    const result = schema.safeParse(data);
    
    if (!result.success) {
      return {
        success: false,
        errors: result.error
      };
    }

    return {
      success: true,
      data: result.data
    };
  } catch (error) {
    securityIssues.push('Validation error occurred');
    return {
      success: false,
      securityIssues
    };
  }
}

// Export enhanced types
export type SecureLoginInput = z.infer<typeof secureLoginSchema>;
export type SecureRegisterInput = z.infer<typeof secureRegisterSchema>;
export type SecurePasswordResetRequestInput = z.infer<typeof securePasswordResetRequestSchema>;
export type SecurePasswordResetConfirmInput = z.infer<typeof securePasswordResetConfirmSchema>;
export type SecureChangePasswordInput = z.infer<typeof secureChangePasswordSchema>;