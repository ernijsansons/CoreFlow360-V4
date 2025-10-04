/**
 * Comprehensive Input Validation Schemas for CoreFlow360 V4
 * Implements OWASP-compliant validation for all API endpoints
 */

import { z } from 'zod';

/**
 * Common validation patterns
 */
const patterns = {
  // Strong password: 12+ chars, uppercase, lowercase, number, special char
  strongPassword: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,128}$/,

  // Name: Letters, spaces, hyphens, apostrophes
  name: /^[a-zA-Z\s'-]{2,100}$/,

  // Company name: Letters, numbers, spaces, common business chars
  companyName: /^[a-zA-Z0-9\s&.,'-]{2,100}$/,

  // UUID v4
  uuid: /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,

  // Safe string (no HTML/script tags)
  safeString: /^[^<>]*$/,

  // Phone number (international format)
  phone: /^\+?[1-9]\d{1,14}$/,

  // URL slug
  slug: /^[a-z0-9-]+$/,

  // API key format
  apiKey: /^cf_(live|test)_[A-Za-z0-9_-]{40,}$/
};

/**
 * Custom error messages
 */
const errorMessages = {
  email: 'Please provide a valid email address',
  password: 'Password must be at least 12 characters with uppercase, lowercase, numbers, and special characters',
  name: 'Name can only contain letters, spaces, hyphens, and apostrophes',
  required: 'This field is required',
  uuid: 'Invalid ID format',
  phone: 'Please provide a valid phone number',
  url: 'Please provide a valid URL',
  date: 'Please provide a valid date'
};

/**
 * Base schemas for common fields
 */
export const BaseSchemas = {
  email: z.string()
    .email(errorMessages.email)
    .max(255, 'Email must be less than 255 characters')
    .toLowerCase()
    .transform(val => val.trim()),

  password: z.string()
    .min(12, 'Password must be at least 12 characters')
    .max(128, 'Password must be less than 128 characters')
    .regex(patterns.strongPassword, errorMessages.password),

  name: z.string()
    .min(2, 'Name must be at least 2 characters')
    .max(100, 'Name must be less than 100 characters')
    .regex(patterns.name, errorMessages.name)
    .transform(val => val.trim()),

  uuid: z.string()
    .regex(patterns.uuid, errorMessages.uuid),

  businessId: z.string()
    .regex(patterns.uuid, 'Invalid business ID'),

  companyName: z.string()
    .min(2, 'Company name must be at least 2 characters')
    .max(100, 'Company name must be less than 100 characters')
    .regex(patterns.companyName, 'Invalid company name format')
    .transform(val => val.trim()),

  phone: z.string()
    .regex(patterns.phone, errorMessages.phone)
    .optional(),

  url: z.string()
    .url(errorMessages.url)
    .max(2048, 'URL must be less than 2048 characters')
    .optional(),

  date: z.string()
    .datetime()
    .or(z.number()),

  pagination: z.object({
    page: z.number().int().min(1).default(1),
    limit: z.number().int().min(1).max(100).default(20),
    sortBy: z.string().optional(),
    sortOrder: z.enum(['asc', 'desc']).default('desc')
  })
};

/**
 * Authentication schemas
 */
export const AuthSchemas = {
  // User registration
  register: z.object({
    email: BaseSchemas.email,
    password: BaseSchemas.password,
    name: BaseSchemas.name,
    businessId: BaseSchemas.businessId.optional(),
    companyName: BaseSchemas.companyName.optional(),
    phone: BaseSchemas.phone,
    acceptTerms: z.boolean().refine(val => val === true, {
      message: 'You must accept the terms and conditions'
    })
  }),

  // User login
  login: z.object({
    email: BaseSchemas.email,
    password: z.string().min(1, 'Password is required'),
    businessId: BaseSchemas.businessId.optional(),
    rememberMe: z.boolean().optional()
  }),

  // Password reset request
  passwordResetRequest: z.object({
    email: BaseSchemas.email
  }),

  // Password reset
  passwordReset: z.object({
    token: z.string().min(1, 'Reset token is required'),
    newPassword: BaseSchemas.password,
    confirmPassword: z.string()
  }).refine(data => data.newPassword === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword']
  }),

  // Change password
  changePassword: z.object({
    currentPassword: z.string().min(1, 'Current password is required'),
    newPassword: BaseSchemas.password,
    confirmPassword: z.string()
  }).refine(data => data.newPassword === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword']
  }).refine(data => data.currentPassword !== data.newPassword, {
    message: 'New password must be different from current password',
    path: ['newPassword']
  }),

  // Two-factor authentication
  twoFactorSetup: z.object({
    password: z.string().min(1, 'Password is required for 2FA setup')
  }),

  twoFactorVerify: z.object({
    code: z.string().length(6, 'Code must be 6 digits').regex(/^\d{6}$/, 'Code must be numeric')
  }),

  // API key generation
  apiKeyCreate: z.object({
    name: z.string()
      .min(3, 'API key name must be at least 3 characters')
      .max(50, 'API key name must be less than 50 characters')
      .regex(patterns.safeString, 'Invalid characters in name'),
    permissions: z.array(z.string()).min(1, 'At least one permission is required'),
    expiresAt: BaseSchemas.date.optional()
  })
};

/**
 * Business/Organization schemas
 */
export const BusinessSchemas = {
  // Create business
  create: z.object({
    name: BaseSchemas.companyName,
    domain: z.string().optional(),
    industry: z.string().max(50).optional(),
    size: z.enum(['1-10', '11-50', '51-200', '201-500', '500+']).optional(),
    timezone: z.string().max(50).optional(),
    currency: z.string().length(3, 'Currency must be 3-letter code').optional()
  }),

  // Update business
  update: z.object({
    name: BaseSchemas.companyName.optional(),
    domain: z.string().optional(),
    industry: z.string().max(50).optional(),
    size: z.enum(['1-10', '11-50', '51-200', '201-500', '500+']).optional(),
    timezone: z.string().max(50).optional(),
    currency: z.string().length(3).optional(),
    settings: z.record(z.any()).optional()
  }),

  // Invite team member
  inviteTeamMember: z.object({
    email: BaseSchemas.email,
    name: BaseSchemas.name,
    role: z.enum(['owner', 'admin', 'manager', 'member', 'viewer']),
    permissions: z.array(z.string()).optional(),
    message: z.string().max(500).optional()
  })
};

/**
 * CRM/Lead schemas
 */
export const CRMSchemas = {
  // Create lead
  createLead: z.object({
    name: BaseSchemas.name,
    email: BaseSchemas.email,
    phone: BaseSchemas.phone,
    company: BaseSchemas.companyName.optional(),
    title: z.string().max(100).optional(),
    source: z.enum(['website', 'referral', 'social', 'email', 'phone', 'event', 'other']),
    status: z.enum(['new', 'contacted', 'qualified', 'proposal', 'negotiation', 'won', 'lost']),
    value: z.number().min(0).optional(),
    notes: z.string().max(5000).regex(patterns.safeString).optional(),
    customFields: z.record(z.any()).optional()
  }),

  // Update lead
  updateLead: z.object({
    name: BaseSchemas.name.optional(),
    email: BaseSchemas.email.optional(),
    phone: BaseSchemas.phone,
    company: BaseSchemas.companyName.optional(),
    title: z.string().max(100).optional(),
    source: z.enum(['website', 'referral', 'social', 'email', 'phone', 'event', 'other']).optional(),
    status: z.enum(['new', 'contacted', 'qualified', 'proposal', 'negotiation', 'won', 'lost']).optional(),
    value: z.number().min(0).optional(),
    notes: z.string().max(5000).regex(patterns.safeString).optional(),
    customFields: z.record(z.any()).optional()
  }),

  // Create contact
  createContact: z.object({
    firstName: BaseSchemas.name,
    lastName: BaseSchemas.name,
    email: BaseSchemas.email,
    phone: BaseSchemas.phone,
    company: BaseSchemas.companyName.optional(),
    title: z.string().max(100).optional(),
    address: z.object({
      street: z.string().max(200).optional(),
      city: z.string().max(100).optional(),
      state: z.string().max(100).optional(),
      country: z.string().max(100).optional(),
      postalCode: z.string().max(20).optional()
    }).optional(),
    tags: z.array(z.string().max(50)).max(20).optional()
  }),

  // Create deal
  createDeal: z.object({
    name: z.string().min(1).max(200),
    value: z.number().min(0),
    stage: z.string().max(50),
    probability: z.number().min(0).max(100).optional(),
    expectedCloseDate: BaseSchemas.date.optional(),
    contactId: BaseSchemas.uuid.optional(),
    companyId: BaseSchemas.uuid.optional(),
    assignedTo: BaseSchemas.uuid.optional(),
    description: z.string().max(5000).regex(patterns.safeString).optional()
  })
};

/**
 * Finance/Invoice schemas
 */
export const FinanceSchemas = {
  // Create invoice
  createInvoice: z.object({
    invoiceNumber: z.string().max(50),
    customerId: BaseSchemas.uuid,
    issueDate: BaseSchemas.date,
    dueDate: BaseSchemas.date,
    items: z.array(z.object({
      description: z.string().max(500),
      quantity: z.number().positive(),
      unitPrice: z.number().min(0),
      tax: z.number().min(0).max(100).optional(),
      discount: z.number().min(0).max(100).optional()
    })).min(1, 'At least one item is required'),
    currency: z.string().length(3),
    notes: z.string().max(2000).regex(patterns.safeString).optional(),
    terms: z.string().max(2000).regex(patterns.safeString).optional()
  }),

  // Create payment
  createPayment: z.object({
    invoiceId: BaseSchemas.uuid,
    amount: z.number().positive(),
    paymentDate: BaseSchemas.date,
    paymentMethod: z.enum(['cash', 'check', 'credit_card', 'debit_card', 'bank_transfer', 'paypal', 'stripe', 'other']),
    reference: z.string().max(100).optional(),
    notes: z.string().max(500).regex(patterns.safeString).optional()
  }),

  // Create expense
  createExpense: z.object({
    amount: z.number().positive(),
    category: z.string().max(50),
    date: BaseSchemas.date,
    vendor: z.string().max(100),
    description: z.string().max(500).regex(patterns.safeString),
    receiptUrl: BaseSchemas.url,
    taxDeductible: z.boolean().optional(),
    projectId: BaseSchemas.uuid.optional()
  })
};

/**
 * Inventory schemas
 */
export const InventorySchemas = {
  // Create product
  createProduct: z.object({
    sku: z.string().max(100),
    name: z.string().min(1).max(200),
    description: z.string().max(5000).regex(patterns.safeString).optional(),
    category: z.string().max(100),
    price: z.number().min(0),
    cost: z.number().min(0).optional(),
    quantity: z.number().int().min(0),
    reorderPoint: z.number().int().min(0).optional(),
    unit: z.string().max(20).optional(),
    barcode: z.string().max(100).optional(),
    images: z.array(BaseSchemas.url).max(10).optional(),
    variants: z.array(z.object({
      name: z.string().max(100),
      sku: z.string().max(100),
      price: z.number().min(0).optional(),
      quantity: z.number().int().min(0)
    })).optional()
  }),

  // Stock adjustment
  stockAdjustment: z.object({
    productId: BaseSchemas.uuid,
    quantity: z.number().int(),
    type: z.enum(['add', 'remove', 'set']),
    reason: z.enum(['sale', 'purchase', 'return', 'damage', 'theft', 'correction', 'other']),
    notes: z.string().max(500).regex(patterns.safeString).optional()
  })
};

/**
 * Query parameter schemas
 */
export const QuerySchemas = {
  // List/search parameters
  list: z.object({
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
    search: z.string().max(100).optional(),
    sortBy: z.string().max(50).optional(),
    sortOrder: z.enum(['asc', 'desc']).default('desc'),
    filters: z.record(z.string()).optional()
  }),

  // Date range
  dateRange: z.object({
    startDate: BaseSchemas.date,
    endDate: BaseSchemas.date
  }).refine(data => new Date(data.startDate) <= new Date(data.endDate), {
    message: 'Start date must be before or equal to end date',
    path: ['startDate']
  })
};

/**
 * Sanitization helpers
 */
export class InputSanitizer {
  /**
   * Sanitize and validate input against schema
   */
  static async validate<T>(schema: z.ZodSchema<T>, data: unknown): Promise<T> {
    try {
      // Parse and validate
      const validated = await schema.parseAsync(data);
      return validated;
    } catch (error) {
      if (error instanceof z.ZodError) {
        // Format validation errors
        const formattedErrors = error.errors.map(err => ({
          field: err.path.join('.'),
          message: err.message
        }));

        throw new ValidationError('Validation failed', formattedErrors);
      }
      throw error;
    }
  }

  /**
   * Sanitize HTML content
   */
  static sanitizeHtml(input: string): string {
    return input
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }

  /**
   * Strip HTML tags
   */
  static stripHtml(input: string): string {
    return input.replace(/<[^>]*>/g, '');
  }

  /**
   * Sanitize filename
   */
  static sanitizeFilename(filename: string): string {
    return filename
      .replace(/[^a-zA-Z0-9.-]/g, '_')
      .replace(/\.{2,}/g, '.')
      .substring(0, 255);
  }
}

/**
 * Custom validation error class
 */
export class ValidationError extends Error {
  constructor(
    message: string,
    public errors: Array<{ field: string; message: string }>
  ) {
    super(message);
    this.name = 'ValidationError';
  }
}

/**
 * Export all schemas
 */
export const Schemas = {
  Base: BaseSchemas,
  Auth: AuthSchemas,
  Business: BusinessSchemas,
  CRM: CRMSchemas,
  Finance: FinanceSchemas,
  Inventory: InventorySchemas,
  Query: QuerySchemas
};