import { z } from 'zod';

// User types
export const UserSchema = z.object({
  id: z.string().uuid(),
  email: z.string().email(),
  username: z.string().optional(),
  firstName: z.string(),
  lastName: z.string(),
  displayName: z.string().optional(),
  avatarUrl: z.string().url().optional(),
  phone: z.string().optional(),
  emailVerified: z.boolean().default(false),
  twoFactorEnabled: z.boolean().default(false),
  language: z.string().default('en'),
  timezone: z.string().default('UTC'),
  dateFormat: z.string().default('YYYY-MM-DD'),
  status: z.enum(['active', 'inactive', 'suspended', 'deleted']),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
  deletedAt: z.string().datetime().optional(),
});

export type User = z.infer<typeof UserSchema>;

// Business types
export const BusinessSchema = z.object({
  id: z.string().uuid(),
  name: z.string(),
  legalName: z.string().optional(),
  registrationNumber: z.string().optional(),
  taxId: z.string().optional(),
  industry: z.string().optional(),
  size: z.enum(['micro', 'small', 'medium', 'large', 'enterprise']).optional(),
  email: z.string().email(),
  phone: z.string().optional(),
  website: z.string().url().optional(),
  addressLine1: z.string().optional(),
  addressLine2: z.string().optional(),
  city: z.string().optional(),
  stateProvince: z.string().optional(),
  postalCode: z.string().optional(),
  country: z.string().default('US'),
  timezone: z.string().default('UTC'),
  currency: z.string().default('USD'),
  fiscalYearStart: z.number().min(1).max(12).default(1),
  dateFormat: z.string().default('YYYY-MM-DD'),
  subscriptionTier: z.enum(['trial', 'starter', 'professional', 'enterprise']),
  subscriptionStatus: z.enum(['active', 'suspended', 'cancelled', 'expired']),
  subscriptionExpiresAt: z.string().datetime().optional(),
  status: z.enum(['active', 'inactive', 'suspended', 'deleted']),
  settings: z.record(z.unknown()).default({}),
  metadata: z.record(z.unknown()).default({}),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
  deletedAt: z.string().datetime().optional(),
});

export type Business = z.infer<typeof BusinessSchema>;

// Membership types
export const MembershipSchema = z.object({
  id: z.string().uuid(),
  businessId: z.string().uuid(),
  userId: z.string().uuid(),
  role: z.enum(['owner', 'director', 'manager', 'employee', 'viewer']),
  employeeId: z.string().optional(),
  jobTitle: z.string().optional(),
  department: z.string().optional(),
  reportsToUserId: z.string().uuid().optional(),
  isPrimary: z.boolean().default(false),
  canApproveTransactions: z.boolean().default(false),
  spendingLimit: z.number().min(0).default(0),
  status: z.enum(['active', 'inactive', 'suspended', 'pending']),
  invitedByUserId: z.string().uuid().optional(),
  invitationToken: z.string().optional(),
  invitationExpiresAt: z.string().datetime().optional(),
  joinedAt: z.string().datetime().optional(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
  deletedAt: z.string().datetime().optional(),
});

export type Membership = z.infer<typeof MembershipSchema>;

// Session types
export const SessionSchema = z.object({
  id: z.string().uuid(),
  userId: z.string().uuid(),
  businessId: z.string().uuid().optional(),
  token: z.string(),
  refreshToken: z.string().optional(),
  ipAddress: z.string().optional(),
  userAgent: z.string().optional(),
  deviceType: z.string().optional(),
  deviceName: z.string().optional(),
  lastActivityAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  revokedAt: z.string().datetime().optional(),
  revokedReason: z.string().optional(),
  createdAt: z.string().datetime(),
});

export type Session = z.infer<typeof SessionSchema>;

// Department types
export const DepartmentSchema = z.object({
  id: z.string().uuid(),
  businessId: z.string().uuid(),
  code: z.string(),
  name: z.string(),
  description: z.string().optional(),
  parentDepartmentId: z.string().uuid().optional(),
  departmentHeadUserId: z.string().uuid().optional(),
  type: z.enum([
    'executive', 'finance', 'accounting', 'hr', 'operations',
    'sales', 'marketing', 'procurement', 'it', 'legal',
    'compliance', 'customer_service', 'warehouse', 'production',
    'quality', 'research', 'other'
  ]),
  costCenterCode: z.string().optional(),
  annualBudget: z.number().min(0).default(0),
  budgetUsed: z.number().min(0).default(0),
  budgetYear: z.number().optional(),
  status: z.enum(['active', 'inactive', 'deleted']),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
  deletedAt: z.string().datetime().optional(),
});

export type Department = z.infer<typeof DepartmentSchema>;

// Account types (Chart of Accounts)
export const AccountSchema = z.object({
  id: z.string().uuid(),
  businessId: z.string().uuid(),
  accountNumber: z.string(),
  accountName: z.string(),
  description: z.string().optional(),
  accountType: z.enum([
    'asset', 'liability', 'equity', 'revenue', 'expense',
    'contra_asset', 'contra_liability', 'contra_equity',
    'contra_revenue', 'contra_expense'
  ]),
  category: z.string(),
  normalBalance: z.enum(['debit', 'credit']),
  isControlAccount: z.boolean().default(false),
  parentAccountId: z.string().uuid().optional(),
  accountLevel: z.number().min(0).default(0),
  currency: z.string().default('USD'),
  taxRate: z.number().min(0).max(100).default(0),
  taxCode: z.string().optional(),
  openingBalance: z.number().default(0),
  openingBalanceDate: z.string().datetime().optional(),
  currentBalance: z.number().default(0),
  ytdDebit: z.number().default(0),
  ytdCredit: z.number().default(0),
  isBankAccount: z.boolean().default(false),
  bankAccountNumber: z.string().optional(),
  bankName: z.string().optional(),
  status: z.enum(['active', 'inactive', 'closed', 'deleted']),
  isSystemAccount: z.boolean().default(false),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
  closedAt: z.string().datetime().optional(),
  deletedAt: z.string().datetime().optional(),
});

export type Account = z.infer<typeof AccountSchema>;

// Workflow types
export const WorkflowInstanceSchema = z.object({
  id: z.string().uuid(),
  businessId: z.string().uuid(),
  workflowDefinitionId: z.string().uuid(),
  instanceKey: z.string(),
  instanceName: z.string().optional(),
  contextType: z.string().optional(),
  contextId: z.string().optional(),
  currentState: z.string(),
  currentStepNumber: z.number().min(0),
  totalSteps: z.number().min(1),
  status: z.enum(['draft', 'active', 'paused', 'waiting', 'completed', 'cancelled', 'failed', 'expired']),
  progressPercentage: z.number().min(0).max(100),
  completedSteps: z.number().min(0),
  skippedSteps: z.number().min(0),
  startedAt: z.string().datetime().optional(),
  pausedAt: z.string().datetime().optional(),
  resumedAt: z.string().datetime().optional(),
  completedAt: z.string().datetime().optional(),
  cancelledAt: z.string().datetime().optional(),
  expiresAt: z.string().datetime().optional(),
  initiatorUserId: z.string().uuid(),
  currentAssigneeUserId: z.string().uuid().optional(),
  currentAssigneeGroup: z.string().optional(),
  workflowData: z.record(z.unknown()).optional(),
  variables: z.record(z.unknown()).optional(),
  errorCount: z.number().min(0).default(0),
  lastError: z.string().optional(),
  priority: z.enum(['low', 'normal', 'high', 'urgent', 'critical']),
  slaDeadline: z.string().datetime().optional(),
  isOverdue: z.boolean().default(false),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});

export type WorkflowInstance = z.infer<typeof WorkflowInstanceSchema>;

// Audit Log types
export const AuditLogSchema = z.object({
  id: z.string().uuid(),
  businessId: z.string().uuid(),
  eventType: z.string(),
  eventName: z.string(),
  eventDescription: z.string().optional(),
  resourceType: z.string(),
  resourceId: z.string().optional(),
  resourceName: z.string().optional(),
  userId: z.string().uuid().optional(),
  sessionId: z.string().optional(),
  impersonatedByUserId: z.string().uuid().optional(),
  ipAddress: z.string().optional(),
  userAgent: z.string().optional(),
  requestMethod: z.string().optional(),
  requestPath: z.string().optional(),
  requestQuery: z.record(z.unknown()).optional(),
  requestBody: z.record(z.unknown()).optional(),
  responseStatus: z.number().optional(),
  oldValues: z.record(z.unknown()).optional(),
  newValues: z.record(z.unknown()).optional(),
  changedFields: z.array(z.string()).optional(),
  operationCost: z.number().min(0).default(0),
  computeTimeMs: z.number().min(0).default(0),
  storageBytes: z.number().min(0).default(0),
  networkBytes: z.number().min(0).default(0),
  apiCallsCount: z.number().min(0).default(0),
  databaseReads: z.number().min(0).default(0),
  databaseWrites: z.number().min(0).default(0),
  aiModelUsed: z.string().optional(),
  aiTokensUsed: z.number().min(0).default(0),
  aiCost: z.number().min(0).default(0),
  status: z.enum(['success', 'failure', 'partial', 'warning']),
  errorCode: z.string().optional(),
  errorMessage: z.string().optional(),
  isSensitive: z.boolean().default(false),
  complianceFlags: z.array(z.string()).optional(),
  riskScore: z.number().min(0).max(100).default(0),
  createdAt: z.string().datetime(),
  eventTimestamp: z.string().datetime(),
});

export type AuditLog = z.infer<typeof AuditLogSchema>;