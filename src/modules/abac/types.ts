import { z } from 'zod';

// ============= Core Types =============

/**
 * Subject represents the user/entity trying to access a resource
 */
export interface Subject {
  userId: string;
  businessId: string;

  // Roles
  orgRole: OrgRole;
  deptRoles: DepartmentRole[];

  // Attributes
  attributes: {
    email: string;
    employeeId?: string;
    jobTitle?: string;
    department?: string;
    reportsTo?: string;
    canApproveTransactions: boolean;
    spendingLimit: number;
    joinedAt: string;
    isVerified: boolean;
    mfaEnabled: boolean;
  };

  // Context
  context: {
    ipAddress: string;
    userAgent: string;
    sessionId: string;
    requestTime: number;
    location?: string;
  };
}

/**
 * Resource represents what is being accessed
 */
export interface Resource {
  type: string; // 'invoice', 'employee', 'report', etc.
  id?: string;
  businessId: string;

  attributes: {
    ownerId?: string;
    departmentId?: string;
    status?: string;
    amount?: number;
    createdAt?: string;
    tags?: string[];
    confidential?: boolean;
    [key: string]: any;
  };
}

/**
 * Action represents what operation is being performed
 */
export type Action =
  | 'create'
  | 'read'
  | 'update'
  | 'delete'
  | 'approve'
  | 'reject'
  | 'export'
  | 'share'
  | 'archive'
  | 'restore';

/**
 * Organization-wide roles
 */
export type OrgRole = 'owner' | 'director' | 'manager' | 'employee' | 'viewer';

/**
 * Department-specific role
 */
export interface DepartmentRole {
  departmentId: string;
  departmentType: DepartmentType;
  role: 'head' | 'manager' | 'supervisor' | 'lead' | 'member';
  permissions?: string[];
}

export type DepartmentType =
  | 'executive'
  | 'finance'
  | 'hr'
  | 'operations'
  | 'sales'
  | 'procurement'
  | 'it'
  | 'legal'
  | 'marketing';

/**
 * Capability represents a specific permission
 * Format: "module.resource.action"
 */
export type Capability = string;

/**
 * Policy rule for ABAC evaluation
 */
export interface PolicyRule {
  id: string;
  name: string;
  description?: string;
  priority: number; // Lower number = higher priority

  // Conditions
  conditions: {
    subject?: SubjectCondition;
    resource?: ResourceCondition;
    context?: ContextCondition;
  };

  // Effect
  effect: 'allow' | 'deny';
  capabilities: Capability[];

  // Optional constraints
  constraints?: {
    maxAmount?: number;
    timeWindow?: {
      start: string; // Time in HH:MM format
      end: string;
    };
    requireMFA?: boolean;
    requireApproval?: boolean;
  };
}

export interface SubjectCondition {
  orgRole?: OrgRole | OrgRole[];
  deptRole?: string | string[];
  attributes?: Record<string, any>;
}

export interface ResourceCondition {
  type?: string | string[];
  attributes?: Record<string, any>;
}

export interface ContextCondition {
  ipRange?: string[];
  timeRange?: {
    start: string;
    end: string;
  };
  location?: string[];
}

/**
 * Permission bundle for caching
 */
export interface PermissionBundle {
  userId: string;
  businessId: string;
  capabilities: Set<Capability>;
  constraints: Map<Capability, any>;
  evaluatedAt: number;
  expiresAt: number;
  version: number;
}

/**
 * Policy evaluation result
 */
export interface EvaluationResult {
  allowed: boolean;
  matched: PolicyRule[];
  denied: PolicyRule[];
  reason?: string;
  constraints?: any;
  evaluationTimeMs: number;
  cacheHit: boolean;
  fastPath: 'owner' | 'dept' | 'org' | 'policy' | null;
}

/**
 * Capability definition
 */
export interface CapabilityDefinition {
  capability: Capability;
  module: string;
  resource: string;
  action: string;
  description: string;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  requiresMFA?: boolean;
  requiresApproval?: boolean;
  defaultRoles?: OrgRole[];
  departmentTypes?: DepartmentType[];
}

// ============= Validation Schemas =============

export const CapabilitySchema = z.string().regex(
  /^[a-z]+\.[a-z_]+\.(create|read|update|delete|approve|reject|export|share|archive|restore)$/,
  'Invalid capability format. Expected: module.resource.action'
);

export const PolicyRuleSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string().optional(),
  priority: z.number().min(0).max(1000),
  conditions: z.object({
    subject: z.object({
      orgRole: z.union([
        z.enum(['owner', 'director', 'manager', 'employee', 'viewer']),
        z.array(z.enum(['owner', 'director', 'manager', 'employee', 'viewer']))
      ]).optional(),
      deptRole: z.union([z.string(), z.array(z.string())]).optional(),
      attributes: z.record(z.any()).optional(),
    }).optional(),
    resource: z.object({
      type: z.union([z.string(), z.array(z.string())]).optional(),
      attributes: z.record(z.any()).optional(),
    }).optional(),
    context: z.object({
      ipRange: z.array(z.string()).optional(),
      timeRange: z.object({
        start: z.string(),
        end: z.string(),
      }).optional(),
      location: z.array(z.string()).optional(),
    }).optional(),
  }),
  effect: z.enum(['allow', 'deny']),
  capabilities: z.array(CapabilitySchema),
  constraints: z.object({
    maxAmount: z.number().optional(),
    timeWindow: z.object({
      start: z.string(),
      end: z.string(),
    }).optional(),
    requireMFA: z.boolean().optional(),
    requireApproval: z.boolean().optional(),
  }).optional(),
});

export const CheckPermissionRequestSchema = z.object({
  capability: CapabilitySchema,
  resource: z.object({
    type: z.string(),
    id: z.string().optional(),
    attributes: z.record(z.any()).optional(),
  }).optional(),
});

// ============= Constants =============

/**
 * Role hierarchy for fast-path evaluation
 */
export const ROLE_HIERARCHY: Record<OrgRole, number> = {
  owner: 100,
  director: 80,
  manager: 60,
  employee: 40,
  viewer: 20,
};

/**
 * Default capabilities by role
 */
export const DEFAULT_CAPABILITIES: Record<OrgRole, Capability[]> = {
  owner: ['*.*.*'], // All capabilities
  director: [
    '*.*.read',
    '*.*.create',
    '*.*.update',
    '*.*.approve',
    'finance.*.delete',
    'hr.*.delete',
  ],
  manager: [
    '*.*.read',
    '*.*.create',
    '*.*.update',
    'finance.invoice.approve',
    'hr.employee.approve',
  ],
  employee: [
    '*.*.read',
    'finance.invoice.create',
    'finance.expense.create',
    'hr.leave.create',
  ],
  viewer: [
    '*.*.read',
  ],
};

/**
 * Department-specific capabilities
 */
export const DEPARTMENT_CAPABILITIES: Record<DepartmentType, Capability[]> = {
  executive: ['*.*.*'],
  finance: [
    'finance.*.*',
    'accounting.*.*',
    'reports.financial.*',
  ],
  hr: [
    'hr.*.*',
    'employees.*.*',
    'payroll.*.*',
  ],
  operations: [
    'operations.*.*',
    'inventory.*.*',
    'warehouse.*.*',
  ],
  sales: [
    'sales.*.*',
    'customers.*.*',
    'quotes.*.*',
  ],
  procurement: [
    'procurement.*.*',
    'vendors.*.*',
    'purchases.*.*',
  ],
  it: [
    'system.*.*',
    'users.*.*',
    'security.*.*',
  ],
  legal: [
    'legal.*.*',
    'contracts.*.*',
    'compliance.*.*',
  ],
  marketing: [
    'marketing.*.*',
    'campaigns.*.*',
    'content.*.*',
  ],
};