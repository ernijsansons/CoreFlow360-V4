/**
 * Capability Contract System Types
 * Defines safe AI tool use with validation, cost estimation, and audit
 */

import { z } from 'zod';

/**
 * Parameter types for capability inputs
 */
export type ParameterType =
  | 'string'
  | 'number'
  | 'boolean'
  | 'date'
  | 'email'
  | 'currency'
  | 'percentage'
  | 'enum'
  | 'array'
  | 'object'
  | 'file'
  | 'json';

/**
 * Parameter validation rules
 */
export interface ParameterValidation {
  required: boolean;
  minLength?: number;
  maxLength?: number;
  min?: number;
  max?: number;
  pattern?: string; // Regex pattern
  enum?: string[]; // Allowed values
  format?: 'email' | 'url' | 'uuid' | 'iso8601' | 'currency' | 'percentage';
  customValidator?: string; // Reference to custom validation function
}

/**
 * Parameter specification
 */
export interface ParameterSpec {
  name: string;
  type: ParameterType;
  description: string;
  validation: ParameterValidation;
  examples?: unknown[];
  sensitive?: boolean; // Mark as PII/sensitive data
  aiUsage?: {
    includeInPrompt: boolean;
    sanitize: boolean;
    maxTokens?: number;
  };
}

/**
 * SQL operation specification (safe, parameterized queries only)
 */
export interface SqlOperationSpec {
  type: 'select' | 'insert' | 'update' | 'delete' | 'procedure';
  table?: string;
  procedure?: string;
  allowedColumns?: string[]; // Whitelist of allowed columns
  whereClause?: {
    allowedColumns: string[];
    operators: ('=' | '!=' | '>' | '<' | '>=' | '<=' | 'LIKE' | 'IN' | 'BETWEEN')[];
  };
  maxRows?: number; // Limit result set size
  timeout?: number; // Query timeout in ms
  readOnly?: boolean; // Enforce read-only operations
}

/**
 * API operation specification
 */
export interface ApiOperationSpec {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  endpoint: string;
  baseUrl?: string;
  headers?: Record<string, string>;
  timeout?: number;
  retries?: number;
  rateLimitPerMinute?: number;
}

/**
 * File operation specification
 */
export interface FileOperationSpec {
  operation: 'read' | 'write' | 'delete' | 'upload' | 'download';
  allowedExtensions?: string[];
  maxFileSize?: number; // In bytes
  allowedMimeTypes?: string[];
  virusScan?: boolean;
  encryption?: boolean;
}

/**
 * Cost estimation specification
 */
export interface CostSpec {
  baseComputeUnits: number;
  perParameterUnits?: number;
  perRowUnits?: number; // For database operations
  perByteUnits?: number; // For file operations
  perRequestUnits?: number; // For API operations
  aiTokenMultiplier?: number;
  customCostFactors?: Record<string, number>;
  maxCostUSD?: number; // Maximum allowed cost
}

/**
 * Permission requirements for capability
 */
export interface PermissionSpec {
  requiredCapabilities: string[]; // ABAC capabilities required
  resourceTypes?: string[]; // Resource types this operates on
  businessContextRequired: boolean;
  userContextRequired: boolean;
  elevatedPrivileges?: boolean; // Requires admin/elevated access
  approvalRequired?: {
    minApprovers: number;
    approverRoles: string[];
    timeoutMinutes: number;
  };
}

/**
 * Audit specification
 */
export interface AuditSpec {
  severity: 'low' | 'medium' | 'high' | 'critical';
  eventType: string;
  sensitiveDataHandling: {
    redactParameters: string[]; // Parameter names to redact
    redactResults: boolean;
    retentionDays: number;
  };
  complianceFlags?: string[]; // GDPR, SOX, HIPAA, etc.
  customMetadata?: Record<string, unknown>;
}

/**
 * Main capability specification
 */
export interface CapabilitySpec {
  // Identity
  id: string;
  name: string;
  description: string;
  version: string;
  category: 'database' | 'api' | 'file' | 'computation' | 'notification' | 'integration';

  // Parameters
  parameters: ParameterSpec[];

  // Operations (exactly one must be specified)
  sqlOperation?: SqlOperationSpec;
  apiOperation?: ApiOperationSpec;
  fileOperation?: FileOperationSpec;
  customHandler?: string; // Reference to custom handler function

  // Return type specification
  returnType: {
    type: ParameterType;
    schema?: Record<string, unknown>; // JSON Schema for complex returns
    examples?: unknown[];
  };

  // Safety and validation
  validation: {
    preExecution: string[]; // List of validation functions to run
    postExecution: string[]; // List of post-execution validations
    crossParameterValidation?: string; // Complex validation across parameters
  };

  // Security and cost
  costEstimation: CostSpec;
  permissions: PermissionSpec;
  audit: AuditSpec;

  // Metadata
  tags?: string[];
  deprecated?: boolean;
  replacedBy?: string; // ID of replacement capability
  owner: string;
  createdAt: number;
  updatedAt: number;

  // AI-specific configuration
  aiConfiguration?: {
    promptTemplate?: string;
    responseProcessing?: string; // How to process AI responses
    fallbackBehavior?: 'error' | 'default' | 'manual';
    confidenceThreshold?: number;
  };
}

/**
 * Capability execution context
 */
export interface CapabilityExecutionContext {
  capabilityId: string;
  executionId: string;
  correlationId: string;

  // User context
  userId: string;
  businessId: string;
  sessionId?: string;

  // AI context
  aiRequestId?: string;
  aiModel?: string;
  aiConfidence?: number;

  // Execution metadata
  startTime: number;
  timeout: number;
  dryRun?: boolean; // Preview mode without actual execution

  // Audit trail
  parentExecutionId?: string; // For nested capability calls
  callStack?: string[]; // Track capability call chain
}

/**
 * Capability execution result
 */
export interface CapabilityExecutionResult {
  success: boolean;
  result?: unknown;
  error?: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    retryable: boolean;
  };

  // Execution metrics
  executionTime: number;
  actualCost: {
    computeUnits: number;
    totalUSD: number;
    breakdown: Record<string, number>;
  };

  // Validation results
  validationErrors?: Array<{
    parameter: string;
    code: string;
    message: string;
  }>;

  // Audit information
  auditEvent: {
    eventId: string;
    timestamp: number;
    outcome: 'success' | 'failure' | 'partial';
    sensitiveDataRedacted: boolean;
  };

  // Metadata
  metadata?: Record<string, unknown>;
}

/**
 * Capability validation error
 */
export class CapabilityValidationError extends Error {
  constructor(
    message: string,
    public parameter: string,
    public code: string,
    public value?: unknown
  ) {
    super(message);
    this.name = 'CapabilityValidationError';
  }
}

/**
 * Capability permission error
 */
export class CapabilityPermissionError extends Error {
  constructor(
    message: string,
    public requiredCapability: string,
    public userCapabilities: string[]
  ) {
    super(message);
    this.name = 'CapabilityPermissionError';
  }
}

/**
 * Capability cost limit error
 */
export class CapabilityCostLimitError extends Error {
  constructor(
    message: string,
    public estimatedCost: number,
    public maxAllowedCost: number
  ) {
    super(message);
    this.name = 'CapabilityCostLimitError';
  }
}

/**
 * Validation schemas using Zod
 */
export const ParameterValidationSchema = z.object({
  required: z.boolean(),
  minLength: z.number().min(0).optional(),
  maxLength: z.number().min(0).optional(),
  min: z.number().optional(),
  max: z.number().optional(),
  pattern: z.string().optional(),
  enum: z.array(z.string()).optional(),
  format: z.enum(['email', 'url', 'uuid', 'iso8601', 'currency', 'percentage']).optional(),
  customValidator: z.string().optional(),
});

export const ParameterSpecSchema = z.object({
  name: z.string().min(1).max(128),
  type: z.enum(['string', 'number', 'boolean', 'date',
  'email', 'currency', 'percentage', 'enum', 'array', 'object', 'file', 'json']),
  description: z.string().min(1).max(1000),
  validation: ParameterValidationSchema,
  examples: z.array(z.unknown()).optional(),
  sensitive: z.boolean().optional(),
  aiUsage: z.object({
    includeInPrompt: z.boolean(),
    sanitize: z.boolean(),
    maxTokens: z.number().min(1).optional(),
  }).optional(),
});

export const SqlOperationSpecSchema = z.object({
  type: z.enum(['select', 'insert', 'update', 'delete', 'procedure']),
  table: z.string().optional(),
  procedure: z.string().optional(),
  allowedColumns: z.array(z.string()).optional(),
  whereClause: z.object({
    allowedColumns: z.array(z.string()),
    operators: z.array(z.enum(['=', '!=', '>', '<', '>=', '<=', 'LIKE', 'IN', 'BETWEEN'])),
  }).optional(),
  maxRows: z.number().min(1).max(10000).optional(),
  timeout: z.number().min(1000).max(300000).optional(),
  readOnly: z.boolean().optional(),
});

export const ApiOperationSpecSchema = z.object({
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']),
  endpoint: z.string().min(1),
  baseUrl: z.string().url().optional(),
  headers: z.record(z.string()).optional(),
  timeout: z.number().min(1000).max(300000).optional(),
  retries: z.number().min(0).max(5).optional(),
  rateLimitPerMinute: z.number().min(1).max(1000).optional(),
});

export const FileOperationSpecSchema = z.object({
  operation: z.enum(['read', 'write', 'delete', 'upload', 'download']),
  allowedExtensions: z.array(z.string()).optional(),
  maxFileSize: z.number().min(1).optional(),
  allowedMimeTypes: z.array(z.string()).optional(),
  virusScan: z.boolean().optional(),
  encryption: z.boolean().optional(),
});

export const CostSpecSchema = z.object({
  baseComputeUnits: z.number().min(0),
  perParameterUnits: z.number().min(0).optional(),
  perRowUnits: z.number().min(0).optional(),
  perByteUnits: z.number().min(0).optional(),
  perRequestUnits: z.number().min(0).optional(),
  aiTokenMultiplier: z.number().min(0).optional(),
  customCostFactors: z.record(z.number()).optional(),
  maxCostUSD: z.number().min(0).optional(),
});

export const PermissionSpecSchema = z.object({
  requiredCapabilities: z.array(z.string()).min(1),
  resourceTypes: z.array(z.string()).optional(),
  businessContextRequired: z.boolean(),
  userContextRequired: z.boolean(),
  elevatedPrivileges: z.boolean().optional(),
  approvalRequired: z.object({
    minApprovers: z.number().min(1),
    approverRoles: z.array(z.string()),
    timeoutMinutes: z.number().min(1),
  }).optional(),
});

export const AuditSpecSchema = z.object({
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  eventType: z.string().min(1),
  sensitiveDataHandling: z.object({
    redactParameters: z.array(z.string()),
    redactResults: z.boolean(),
    retentionDays: z.number().min(1),
  }),
  complianceFlags: z.array(z.string()).optional(),
  customMetadata: z.record(z.unknown()).optional(),
});

export const CapabilitySpecSchema = z.object({
  id: z.string().min(1).max(128),
  name: z.string().min(1).max(256),
  description: z.string().min(1).max(2000),
  version: z.string().min(1).max(32),
  category: z.enum(['database', 'api', 'file', 'computation', 'notification', 'integration']),
  parameters: z.array(ParameterSpecSchema),
  sqlOperation: SqlOperationSpecSchema.optional(),
  apiOperation: ApiOperationSpecSchema.optional(),
  fileOperation: FileOperationSpecSchema.optional(),
  customHandler: z.string().optional(),
  returnType: z.object({
    type: z.enum(['string', 'number', 'boolean',
  'date', 'email', 'currency', 'percentage', 'enum', 'array', 'object', 'file', 'json']),
    schema: z.record(z.unknown()).optional(),
    examples: z.array(z.unknown()).optional(),
  }),
  validation: z.object({
    preExecution: z.array(z.string()),
    postExecution: z.array(z.string()),
    crossParameterValidation: z.string().optional(),
  }),
  costEstimation: CostSpecSchema,
  permissions: PermissionSpecSchema,
  audit: AuditSpecSchema,
  tags: z.array(z.string()).optional(),
  deprecated: z.boolean().optional(),
  replacedBy: z.string().optional(),
  owner: z.string().min(1),
  createdAt: z.number(),
  updatedAt: z.number(),
  aiConfiguration: z.object({
    promptTemplate: z.string().optional(),
    responseProcessing: z.string().optional(),
    fallbackBehavior: z.enum(['error', 'default', 'manual']).optional(),
    confidenceThreshold: z.number().min(0).max(1).optional(),
  }).optional(),
});

/**
 * Built-in validation functions
 */
export const BuiltInValidators = {
  /**
   * Validate email address
   */
  validateEmail: (value: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(value);
  },

  /**
   * Validate currency amount
   */
  validateCurrency: (value: number): boolean => {
    return Number.isFinite(value) && value >= 0 && value <= 999999999.99;
  },

  /**
   * Validate percentage
   */
  validatePercentage: (value: number): boolean => {
    return Number.isFinite(value) && value >= 0 && value <= 100;
  },

  /**
   * Validate UUID
   */
  validateUUID: (value: string): boolean => {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(value);
  },

  /**
   * Validate ISO 8601 date
   */
  validateISO8601: (value: string): boolean => {
    const date = new Date(value);
    return !isNaN(date.getTime()) && value === date.toISOString();
  },

  /**
   * Validate URL
   */
  validateURL: (value: string): boolean => {
    try {
      new URL(value);
      return true;
    } catch {
      return false;
    }
  },

  /**
   * Validate SQL identifier (prevent injection)
   */
  validateSQLIdentifier: (value: string): boolean => {
    // Only allow alphanumeric characters, underscores, and dots
    const sqlIdentifierRegex = /^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)*$/;
    return sqlIdentifierRegex.test(value) && value.length <= 128;
  },

  /**
   * Validate that value doesn't contain SQL injection patterns
   */
  validateNoSQLInjection: (value: string): boolean => {
    const sqlInjectionPatterns = [
      /(\s*(union|select|insert|update|delete|drop|create|alter|exec|execute)\s+)/i,
      /(--|\/\*|\*\/|xp_|sp_)/i,
      /(\s*(or|and)\s+\d+\s*=\s*\d+)/i,
      /('\s*(or|and)\s+')/i,
    ];

    return !sqlInjectionPatterns.some(pattern => pattern.test(value));
  },
};

/**
 * Default cost calculation
 */
export const DEFAULT_COST_MULTIPLIERS = {
  COMPUTE_UNIT_USD: 0.0001, // $0.0001 per compute unit
  STORAGE_BYTE_USD: 0.000000001, // $0.000000001 per byte
  NETWORK_REQUEST_USD: 0.001, // $0.001 per API request
  AI_TOKEN_USD: 0.00001, // $0.00001 per AI token
};

/**
 * Capability execution limits
 */
export const EXECUTION_LIMITS = {
  MAX_EXECUTION_TIME_MS: 300000, // 5 minutes
  MAX_PARAMETERS: 50,
  MAX_PARAMETER_SIZE_BYTES: 1048576, // 1MB
  MAX_RESULT_SIZE_BYTES: 10485760, // 10MB
  MAX_SQL_ROWS: 10000,
  MAX_FILE_SIZE_BYTES: 104857600, // 100MB
  MAX_CONCURRENT_EXECUTIONS: 100,
};