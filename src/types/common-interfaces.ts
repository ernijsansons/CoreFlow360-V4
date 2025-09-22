/**
 * Common Interface Definitions
 * Centralized type definitions to prevent 'any' usage throughout the codebase
 */

// =====================================================
// DATABASE RESULT TYPES
// =====================================================

export interface DatabaseRow {
  [key: string]: string | number | boolean | Date | null;
}

export interface PaginatedResult<T = DatabaseRow> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    hasMore: boolean;
  };
}

export interface QueryResult<T = DatabaseRow> {
  success: boolean;
  data?: T[];
  error?: string;
  rowsAffected?: number;
  executionTimeMs?: number;
}

// =====================================================
// API RESPONSE TYPES
// =====================================================

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: Record<string, string | number | boolean>;
  };
  metadata?: {
    timestamp: string;
    correlationId?: string;
    executionTimeMs?: number;
    version?: string;
  };
}

export interface ErrorDetails {
  code: string;
  message: string;
  field?: string;
  value?: string | number | boolean;
  context?: Record<string, string | number | boolean>;
}

// =====================================================
// FINANCIAL DATA TYPES
// =====================================================

export interface MonetaryAmount {
  amount: number;
  currency: string;
  precision?: number;
}

export interface Transaction {
  id: string;
  businessId: string;
  date: string;
  amount: MonetaryAmount;
  description: string;
  type: 'credit' | 'debit';
  category?: string;
  status: 'pending' | 'completed' | 'failed' | 'cancelled';
  metadata?: Record<string, string | number | boolean>;
}

export interface AccountBalance {
  accountId: string;
  balance: MonetaryAmount;
  availableBalance?: MonetaryAmount;
  lastUpdated: string;
}

// =====================================================
// AUDIT AND LOGGING TYPES
// =====================================================

export interface AuditLogEntry {
  id: string;
  businessId: string;
  userId?: string;
  action: string;
  entityType: string;
  entityId: string;
  oldValues?: Record<string, any>;
  newValues?: Record<string, any>;
  timestamp: string;
  ipAddress?: string;
  userAgent?: string;
  correlationId?: string;
}

export interface LogContext {
  businessId?: string;
  userId?: string;
  correlationId?: string;
  operation?: string;
  [key: string]: string | number | boolean | undefined;
}

// =====================================================
// BUSINESS ENTITY TYPES
// =====================================================

export interface BusinessEntity {
  id: string;
  businessId: string;
  createdAt: string;
  updatedAt: string;
  createdBy?: string;
  updatedBy?: string;
  status: 'active' | 'inactive' | 'deleted';
}

export interface Contact extends BusinessEntity {
  firstName?: string;
  lastName?: string;
  email: string;
  phone?: string;
  title?: string;
  companyId?: string;
}

export interface Company extends BusinessEntity {
  name: string;
  domain?: string;
  industry?: string;
  size?: string;
  revenue?: MonetaryAmount;
}

// =====================================================
// WORKFLOW AND AUTOMATION TYPES
// =====================================================

export interface WorkflowVariable {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'object' | 'array';
  value: string | number | boolean | object | any[];
  encrypted?: boolean;
}

export interface WorkflowContext {
  variables: WorkflowVariable[];
  executionId: string;
  businessId: string;
  userId?: string;
  metadata: Record<string, string | number | boolean>;
}

export interface ExecutionMetrics {
  startTime: number;
  endTime?: number;
  duration?: number;
  cost?: MonetaryAmount;
  tokensUsed?: number;
  memoryUsed?: number;
  errors?: ErrorDetails[];
}

// =====================================================
// NOTIFICATION AND ALERT TYPES
// =====================================================

export interface NotificationPayload {
  type: 'email' | 'sms' | 'push' | 'webhook';
  recipient: string;
  subject?: string;
  content: string;
  priority: 'low' | 'normal' | 'high' | 'urgent';
  metadata?: Record<string, string | number | boolean>;
}

export interface Alert {
  id: string;
  businessId: string;
  name: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  status: 'active' | 'acknowledged' | 'resolved';
  triggeredAt: string;
  acknowledgedAt?: string;
  resolvedAt?: string;
  assignedTo?: string;
  metadata?: Record<string, string | number | boolean>;
}

// =====================================================
// FILE AND IMPORT/EXPORT TYPES
// =====================================================

export interface FileMetadata {
  name: string;
  size: number;
  type: string;
  lastModified?: number;
  encoding?: string;
  checksum?: string;
}

export interface ImportResult {
  success: boolean;
  totalRecords: number;
  processedRecords: number;
  successfulRecords: number;
  failedRecords: number;
  errors: Array<{
    row: number;
    field?: string;
    message: string;
    value?: string;
  }>;
  warnings: Array<{
    row: number;
    field?: string;
    message: string;
    value?: string;
  }>;
}

export interface ExportConfig {
  format: 'csv' | 'xlsx' | 'json' | 'pdf';
  includeHeaders: boolean;
  dateFormat?: string;
  timezone?: string;
  filters?: Record<string, any>;
  columns?: string[];
}

// =====================================================
// INTEGRATION AND API TYPES
// =====================================================

export interface ApiCredentials {
  type: 'bearer' | 'basic' | 'apikey' | 'oauth2';
  token?: string;
  username?: string;
  password?: string;
  apiKey?: string;
  apiSecret?: string;
  refreshToken?: string;
  expiresAt?: string;
}

export interface WebhookPayload {
  event: string;
  businessId: string;
  timestamp: string;
  data: Record<string, any>;
  signature?: string;
  version: string;
}

export interface IntegrationConfig {
  id: string;
  name: string;
  provider: string;
  enabled: boolean;
  credentials: ApiCredentials;
  settings: Record<string, string | number | boolean>;
  endpoints: Record<string, string>;
  lastSyncAt?: string;
  errorCount?: number;
}

// =====================================================
// PERFORMANCE AND MONITORING TYPES
// =====================================================

export interface PerformanceMetric {
  name: string;
  value: number;
  unit: string;
  timestamp: string;
  tags: Record<string, string>;
}

export interface HealthCheckResult {
  service: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  latency?: number;
  error?: string;
  timestamp: string;
  details?: Record<string, string | number | boolean>;
}

export interface ServiceLimits {
  requestsPerMinute: number;
  requestsPerHour: number;
  concurrentRequests: number;
  dataRetentionDays: number;
  storageQuotaBytes: number;
}

// =====================================================
// SECURITY AND AUTHENTICATION TYPES
// =====================================================

export interface SecurityContext {
  userId: string;
  businessId: string;
  roles: string[];
  permissions: string[];
  sessionId?: string;
  ipAddress?: string;
  userAgent?: string;
  mfaVerified?: boolean;
}

export interface AccessAttempt {
  userId?: string;
  ipAddress: string;
  userAgent: string;
  success: boolean;
  timestamp: string;
  reason?: string;
  location?: {
    country?: string;
    region?: string;
    city?: string;
  };
}

// =====================================================
// UTILITY TYPES
// =====================================================

export type Primitive = string | number | boolean | null | undefined;

export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

export type RequiredFields<T, K extends keyof T> = T & Required<Pick<T, K>>;

export type OptionalFields<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;

export type StringKeys<T> = {
  [K in keyof T]: T[K] extends string ? K : never;
}[keyof T];

export type NumberKeys<T> = {
  [K in keyof T]: T[K] extends number ? K : never;
}[keyof T];

// =====================================================
// VALIDATION HELPERS
// =====================================================

export interface ValidationRule {
  field: string;
  required?: boolean;
  type?: 'string' | 'number' | 'boolean' | 'email' | 'url' | 'date';
  minLength?: number;
  maxLength?: number;
  min?: number;
  max?: number;
  pattern?: string;
  custom?: (value: any) => boolean | string;
}

export interface ValidationResult {
  valid: boolean;
  errors: Array<{
    field: string;
    message: string;
    value?: any;
  }>;
}

// =====================================================
// CONFIGURATION TYPES
// =====================================================

export interface ModuleConfig {
  enabled: boolean;
  settings: Record<string, string | number | boolean>;
  dependencies?: string[];
  version?: string;
}

export interface FeatureFlag {
  name: string;
  enabled: boolean;
  rolloutPercentage?: number;
  conditions?: Record<string, any>;
  metadata?: Record<string, string | number | boolean>;
}

export interface SystemConfiguration {
  modules: Record<string, ModuleConfig>;
  features: Record<string, FeatureFlag>;
  limits: ServiceLimits;
  maintenance?: {
    enabled: boolean;
    message?: string;
    startTime?: string;
    endTime?: string;
  };
}