/**
 * Finance Module Validation Schemas
 * Comprehensive input validation using Zod for all financial operations
 */

import { z } from 'zod';
import {
  AccountType,
  AccountCategory,
  JournalEntryType,
  JournalEntryStatus,
  ReportType,
  ReportDataSource,
  FilterOperator,
  FilterDataType,
  AggregationType,
  InvoiceStatus,
  PaymentMethod
} from './types';

// Enhanced security validation patterns
const businessIdSchema = z.string()
  .min(4, 'Business ID must be at least 4 characters')
  .max(50, 'Business ID must be at most 50 characters')
  .regex(/^[a-zA-Z][a-zA-Z0-9_-]*[a-zA-Z0-9]$/, 'Business ID must start with letter, end with letter/number, and contain only letters, numbers, underscore, hyphen')
  .refine((val) => {
    // Reject pure numbers or single characters
    return !/^[0-9]+$/.test(val) && !/^[a-zA-Z]$/.test(val);
  }, 'Business ID cannot be pure numbers or single character')
  .refine((val) => {
    // Reject patterns with consecutive special characters
    return !val.includes('..') && !val.includes('__') && !val.includes('--');
  }, 'Business ID cannot contain consecutive special characters')
  .refine((val) => {
    // Reject SQL injection patterns
    const sqlPatterns = [/';/gi, /\bDROP\b/gi, /\bSELECT\b/gi, /\bINSERT\b/gi, /\bUPDATE\b/gi, /\bDELETE\b/gi, /\bOR\s+1\s*=\s*1/gi, /--/gi, /union/gi, /exec/gi];
    return !sqlPatterns.some(pattern => pattern.test(val));
  }, 'Business ID contains prohibited patterns')
  .refine((val) => {
    // Reject XSS patterns
    const xssPatterns = [/<script/gi, /<\/script>/gi, /javascript:/gi, /on\w+\s*=/gi, /alert\s*\(/gi, /<.*>/gi];
    return !xssPatterns.some(pattern => pattern.test(val));
  }, 'Business ID contains prohibited patterns')
  .refine((val) => {
    // Reject path traversal patterns
    return !val.includes('../') && !val.includes('..\\') && !val.includes('/etc/') && !val.includes('\\windows\\');
  }, 'Business ID contains prohibited patterns')
  .refine((val) => {
    // Reject null bytes and control characters
    return !/[\x00-\x1f\x7f-\x9f]/.test(val);
  }, 'Business ID contains invalid characters')
  .refine((val) => {
    // Reject common invalid patterns
    const invalidPatterns = [/\s/g, /[%$#@!+=:;,<>?|{}[\]\\\/]/g, /['"`;]/g];
    return !invalidPatterns.some(pattern => pattern.test(val));
  }, 'Business ID contains prohibited characters');

const userIdSchema = z.string()
  .min(3, 'User ID must be at least 3 characters')
  .max(50, 'User ID must be at most 50 characters')
  .regex(/^[a-zA-Z0-9_\.-]+$/, 'User ID contains invalid characters');

const currencySchema = z.string()
  .length(3, 'Currency must be ISO 4217 code')
  .regex(/^[A-Z]{3}$/, 'Currency must be uppercase ISO 4217 code')
  .refine((val) => {
    // Allow only valid ISO currency codes
    const validCurrencies = ['USD', 'EUR', 'GBP', 'JPY', 'CAD', 'AUD', 'CHF', 'CNY', 'SEK', 'NZD', 'MXN', 'SGD', 'HKD', 'NOK', 'TRY', 'ZAR', 'BRL', 'INR', 'RUB', 'KRW', 'PLN', 'THB', 'ILS', 'DKK', 'CZK', 'HUF', 'CLP', 'PHP', 'AED', 'COP', 'SAR', 'MYR', 'RON'];
    return validCurrencies.includes(val);
  }, 'Invalid currency code');

const amountSchema = z.number()
  .min(0, 'Amount must be non-negative')
  .max(999999999.99, 'Amount exceeds maximum allowed value')
  .refine((val) => Number.isFinite(val), 'Amount must be a finite number')
  .refine((val) => !Number.isNaN(val), 'Amount cannot be NaN');

const dateSchema = z.number()
  .int('Date must be an integer timestamp')
  .min(946684800000, 'Date must be after year 2000') // Jan 1, 2000
  .max(4102444800000, 'Date must be before year 2100') // Jan 1, 2100
  .refine((val) => Number.isFinite(val), 'Date must be a finite number')
  .refine((val) => !Number.isNaN(val), 'Date cannot be NaN');

// Chart of Accounts validation
export const chartAccountCreateSchema = z.object({
  code: z.string()
    .min(1, 'Account code is required')
    .max(20, 'Account code too long')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Account code contains invalid characters')
    .refine((val) => {
      // Reject SQL injection patterns
      const sqlPatterns = [/';/gi, /\bDROP\b/gi, /\bSELECT\b/gi, /--/gi];
      return !sqlPatterns.some(pattern => pattern.test(val));
    }, 'Account code contains prohibited patterns'),
  name: z.string()
    .min(1, 'Account name is required')
    .max(100, 'Account name too long')
    .refine((val) => {
      // Reject XSS patterns
      const xssPatterns = [/<script/gi, /<\/script>/gi, /javascript:/gi, /on\w+\s*=/gi];
      return !xssPatterns.some(pattern => pattern.test(val));
    }, 'Account name contains prohibited patterns')
    .refine((val) => {
      // Reject null bytes and control characters
      return !/[\x00-\x1f\x7f-\x9f]/.test(val);
    }, 'Account name contains invalid characters'),
  type: z.nativeEnum(AccountType),
  category: z.nativeEnum(AccountCategory),
  parentId: z.string().optional(),
  description: z.string().max(500, 'Description too long').optional(),
  isActive: z.boolean().default(true),
  businessId: businessIdSchema
});

export const chartAccountUpdateSchema = chartAccountCreateSchema.partial().extend({
  id: z.string().min(1, 'Account ID is required')
});

// Journal Entry validation
export const journalEntryCreateSchema = z.object({
  entryNumber: z.string()
    .min(1, 'Entry number is required')
    .max(20, 'Entry number too long')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Entry number contains invalid characters')
    .refine((val) => {
      // Reject SQL injection patterns
      const sqlPatterns = [/';/gi, /\bDROP\b/gi, /\bSELECT\b/gi, /--/gi];
      return !sqlPatterns.some(pattern => pattern.test(val));
    }, 'Entry number contains prohibited patterns'),
  date: dateSchema,
  description: z.string()
    .min(1, 'Description is required')
    .max(500, 'Description too long')
    .refine((val) => {
      // Reject XSS patterns
      const xssPatterns = [/<script/gi, /<\/script>/gi, /javascript:/gi, /on\w+\s*=/gi];
      return !xssPatterns.some(pattern => pattern.test(val));
    }, 'Description contains prohibited patterns'),
  reference: z.string().max(100).optional(),
  type: z.nativeEnum(JournalEntryType),
  periodId: z.string().min(1, 'Period ID is required').max(20),
  businessId: businessIdSchema
});

export const journalLineCreateSchema = z.object({
  accountId: z.string().min(1, 'Account ID is required'),
  debit: amountSchema.optional(),
  credit: amountSchema.optional(),
  currency: currencySchema,
  exchangeRate: z.number().positive('Exchange rate must be positive').default(1),
  description: z.string().max(500).optional()
}).refine(
  (data) => (data.debit || 0) > 0 || (data.credit || 0) > 0,
  { message: 'Either debit or credit must be greater than 0' }
).refine(
  (data) => !data.debit || !data.credit || data.debit === 0 || data.credit === 0,
  { message: 'Cannot have both debit and credit amounts' }
);

export const journalEntryWithLinesSchema = journalEntryCreateSchema.extend({
  lines: z.array(journalLineCreateSchema).min(2, 'Minimum 2 journal lines required')
}).refine(
  (data) => {
    const totalDebits = data.lines.reduce((sum, line) => sum + (line.debit || 0), 0);
    const totalCredits = data.lines.reduce((sum, line) => sum + (line.credit || 0), 0);
    return Math.abs(totalDebits - totalCredits) < 0.01; // Allow for rounding errors
  },
  { message: 'Total debits must equal total credits' }
);

// Invoice validation
export const invoiceCreateSchema = z.object({
  invoiceNumber: z.string()
    .min(1, 'Invoice number is required')
    .max(50, 'Invoice number too long')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Invoice number contains invalid characters')
    .refine((val) => {
      // Reject SQL injection patterns
      const sqlPatterns = [/';/gi, /\bDROP\b/gi, /\bSELECT\b/gi, /--/gi];
      return !sqlPatterns.some(pattern => pattern.test(val));
    }, 'Invoice number contains prohibited patterns'),
  customerId: z.string().min(1, 'Customer ID is required'),
  customerName: z.string()
    .min(1, 'Customer name is required')
    .max(100, 'Customer name too long')
    .refine((val) => {
      // Reject XSS patterns
      const xssPatterns = [/<script/gi, /<\/script>/gi, /javascript:/gi, /on\w+\s*=/gi];
      return !xssPatterns.some(pattern => pattern.test(val));
    }, 'Customer name contains prohibited patterns'),
  customerEmail: z.string().email('Invalid email format').optional(),
  issueDate: dateSchema,
  dueDate: dateSchema,
  terms: z.string().max(100).optional(),
  subtotal: amountSchema.refine((val) => val > 0, 'Subtotal must be greater than 0'),
  taxAmount: amountSchema.default(0),
  discountAmount: amountSchema.default(0),
  total: amountSchema.refine((val) => val > 0, 'Total must be greater than 0'),
  currency: currencySchema,
  notes: z.string().max(1000).optional(),
  businessId: businessIdSchema
}).refine(
  (data) => data.dueDate >= data.issueDate,
  { message: 'Due date must be on or after issue date' }
).refine(
  (data) => Math.abs(data.total - (data.subtotal + data.taxAmount - data.discountAmount)) < 0.01,
  { message: 'Total must equal subtotal + tax - discount' }
);

export const invoiceUpdateSchema = z.object({
  id: z.string().min(1, 'Invoice ID is required'),
  invoiceNumber: z.string().min(1).max(50).optional(),
  customerId: z.string().min(1).optional(),
  customerName: z.string().min(1).max(100).optional(),
  customerEmail: z.string().email('Invalid email format').optional(),
  issueDate: dateSchema.optional(),
  dueDate: dateSchema.optional(),
  terms: z.string().max(100).optional(),
  subtotal: amountSchema.optional(),
  taxAmount: amountSchema.optional(),
  discountAmount: amountSchema.optional(),
  total: amountSchema.optional(),
  currency: currencySchema.optional(),
  notes: z.string().max(1000).optional(),
  businessId: businessIdSchema.optional(),
  status: z.nativeEnum(InvoiceStatus).optional()
});

// Payment validation
export const paymentCreateSchema = z.object({
  invoiceId: z.string()
    .min(1, 'Invoice ID is required')
    .refine((val) => {
      // Reject SQL injection patterns
      const sqlPatterns = [/';/gi, /\bDROP\b/gi, /\bSELECT\b/gi, /--/gi];
      return !sqlPatterns.some(pattern => pattern.test(val));
    }, 'Invoice ID contains prohibited patterns'),
  amount: amountSchema.refine((val) => val >= 0.01, 'Payment amount must be greater than 0'),
  paymentDate: dateSchema,
  paymentMethod: z.nativeEnum(PaymentMethod),
  reference: z.string().max(100).optional(),
  notes: z.string().max(500).optional(),
  currency: currencySchema,
  businessId: businessIdSchema
});

// Report Parameters validation
export const reportParametersSchema = z.object({
  startDate: dateSchema,
  endDate: dateSchema,
  comparisonStartDate: dateSchema.optional(),
  comparisonEndDate: dateSchema.optional(),
  currency: currencySchema.optional(),
  includeInactive: z.boolean().default(false),
  consolidateSubsidiaries: z.boolean().default(false),
  customerIds: z.array(z.string()).optional(),
  vendorIds: z.array(z.string()).optional(),
  accountIds: z.array(z.string()).optional(),
  customFilters: z.array(z.object({
    field: z.string()
      .min(1, 'Field name is required')
      .max(100, 'Field name too long')
      .regex(/^[a-zA-Z0-9_]+$/, 'Field name contains invalid characters')
      .refine((val) => {
        // Reject SQL injection patterns
        const sqlPatterns = [/';/gi, /\bDROP\b/gi, /\bSELECT\b/gi, /--/gi];
        return !sqlPatterns.some(pattern => pattern.test(val));
      }, 'Field name contains prohibited patterns'),
    operator: z.nativeEnum(FilterOperator),
    value: z.union([z.string(), z.number(), z.boolean(), z.array(z.string())]),
    dataType: z.nativeEnum(FilterDataType)
  })).optional()
}).refine(
  (data) => data.endDate >= data.startDate,
  { message: 'End date must be on or after start date' }
).refine(
  (data) => !data.comparisonStartDate || !data.comparisonEndDate || data.comparisonEndDate >= data.comparisonStartDate,
  { message: 'Comparison end date must be on or after comparison start date' }
);

// Custom Report Definition validation
export const reportColumnSchema = z.object({
  id: z.string().min(1),
  field: z.string().min(1),
  name: z.string().min(1).max(100),
  dataType: z.nativeEnum(FilterDataType),
  isVisible: z.boolean().default(true),
  width: z.number().positive().optional(),
  aggregationType: z.nativeEnum(AggregationType).optional(),
  formatting: z.object({
    decimalPlaces: z.number().int().min(0).max(10).optional(),
    showCurrency: z.boolean().optional(),
    dateFormat: z.string().optional()
  }).optional()
});

export const reportFilterSchema = z.object({
  field: z.string().min(1),
  operator: z.nativeEnum(FilterOperator),
  value: z.union([z.string(), z.number(), z.boolean(), z.array(z.string())]),
  dataType: z.nativeEnum(FilterDataType)
});

export const reportSortSchema = z.object({
  field: z.string().min(1),
  direction: z.enum(['ASC', 'DESC']),
  priority: z.number().int().min(1)
});

export const reportGroupingSchema = z.object({
  field: z.string().min(1),
  level: z.number().int().min(1).max(5),
  showSubtotals: z.boolean().default(false)
});

export const reportAggregationSchema = z.object({
  field: z.string().min(1),
  type: z.nativeEnum(AggregationType)
});

export const customReportDefinitionSchema = z.object({
  name: z.string()
    .min(1, 'Report name is required')
    .max(100, 'Report name too long')
    .refine((val) => {
      // Reject SQL injection patterns
      const sqlPatterns = [/';/gi, /\bDROP\b/gi, /\bSELECT\b/gi, /--/gi];
      return !sqlPatterns.some(pattern => pattern.test(val));
    }, 'Report name contains prohibited patterns'),
  description: z.string().max(500).optional(),
  dataSource: z.nativeEnum(ReportDataSource),
  columns: z.array(reportColumnSchema).min(1, 'At least one column is required'),
  filters: z.array(reportFilterSchema).default([]),
  sorting: z.array(reportSortSchema).default([]),
  grouping: z.array(reportGroupingSchema).default([]),
  aggregations: z.array(reportAggregationSchema).default([]),
  formatting: z.object({
    showRowNumbers: z.boolean().default(false),
    alternateRowColors: z.boolean().default(true),
    pageSize: z.number().int().min(10).max(1000).default(100)
  }).optional(),
  isTemplate: z.boolean().default(false),
  isPublic: z.boolean().default(false),
  createdBy: userIdSchema,
  businessId: businessIdSchema
});

// Export Request validation
export const exportRequestSchema = z.object({
  reportId: z.string()
    .min(1, 'Report ID is required')
    .refine((val) => {
      // Reject SQL injection patterns
      const sqlPatterns = [/';/gi, /\bDROP\b/gi, /\bSELECT\b/gi, /--/gi];
      return !sqlPatterns.some(pattern => pattern.test(val));
    }, 'Report ID contains prohibited patterns'),
  format: z.enum(['EXCEL', 'CSV', 'PDF']),
  filename: z.string()
    .min(1, 'Filename is required')
    .max(100, 'Filename too long')
    .regex(/^[a-zA-Z0-9_.-]+$/, 'Filename contains invalid characters')
    .refine((val) => {
      // Reject path traversal patterns
      return !val.includes('../') && !val.includes('..\\') && !val.includes('/') && !val.includes('\\');
    }, 'Filename contains prohibited patterns')
    .optional(),
  includeCharts: z.boolean().default(false),
  includeRawData: z.boolean().default(true),
  businessId: businessIdSchema
});

// Generate Report Request validation
export const generateReportRequestSchema = z.object({
  type: z.nativeEnum(ReportType),
  parameters: reportParametersSchema,
  customReportId: z.string().optional(),
  format: z.enum(['JSON', 'EXCEL', 'CSV', 'PDF']).default('JSON'),
  businessId: businessIdSchema
}).refine(
  (data) => data.type !== ReportType.CUSTOM || data.customReportId,
  { message: 'Custom report ID is required for custom reports' }
);

// Business ID validation function
export const validateBusinessIdInput = (businessId: unknown): string => {
  const result = businessIdSchema.safeParse(businessId);
  if (!result.success) {
    throw new Error(`Invalid business ID: ${result.error.message}`);
  }
  return result.data;
};

// User ID validation function
export const validateUserIdInput = (userId: unknown): string => {
  const result = userIdSchema.safeParse(userId);
  if (!result.success) {
    throw new Error(`Invalid user ID: ${result.error.message}`);
  }
  return result.data;
};

// Currency validation function
export const validateCurrencyInput = (currency: unknown): string => {
  const result = currencySchema.safeParse(currency);
  if (!result.success) {
    throw new Error(`Invalid currency: ${result.error.message}`);
  }
  return result.data;
};

// Amount validation function
export const validateAmountInput = (amount: unknown): number => {
  const result = amountSchema.safeParse(amount);
  if (!result.success) {
    throw new Error(`Invalid amount: ${result.error.message}`);
  }
  return result.data;
};

// Date validation function
export const validateDateInput = (date: unknown): number => {
  const result = dateSchema.safeParse(date);
  if (!result.success) {
    throw new Error(`Invalid date: ${result.error.message}`);
  }
  return result.data;
};

// Generic validation function
export const validateInput = <T>(schema: z.ZodSchema<T>, input: unknown): T => {
  const result = schema.safeParse(input);
  if (!result.success) {
    throw new Error(`Validation failed: ${result.error.message}`);
  }
  return result.data;
};

// Validation error class
export class ValidationError extends Error {
  constructor(message: string, public details?: any) {
    super(message);
    this.name = 'ValidationError';
  }
}

// Safe validation function that returns ValidationError
export const safeValidateInput = <T>(schema: z.ZodSchema<T>, input: unknown): { success: true;
  data: T } | { success: false; error: ValidationError } => {
  const result = schema.safeParse(input);
  if (result.success) {
    return { success: true, data: result.data };
  } else {
    return {
      success: false,
      error: new ValidationError('Validation failed', result.error.format())
    };
  }
};