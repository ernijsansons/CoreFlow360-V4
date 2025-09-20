import { z } from 'zod';

// Business switching request/response schemas
export const SwitchBusinessRequestSchema = z.object({
  targetBusinessId: z.string().uuid(),
  prefetchContext: z.boolean().default(true),
});

export const BusinessListRequestSchema = z.object({
  includeInactive: z.boolean().default(false),
  forceRefresh: z.boolean().default(false),
});

// Types
export type SwitchBusinessRequest = z.infer<typeof SwitchBusinessRequestSchema>;
export type BusinessListRequest = z.infer<typeof BusinessListRequestSchema>;

export interface BusinessMembership {
  businessId: string;
  businessName: string;
  businessLogo?: string;
  role: 'owner' | 'director' | 'manager' | 'employee' | 'viewer';
  permissions: string[];
  isPrimary: boolean;
  isActive: boolean;
  joinedAt: string;
  lastAccessedAt?: string;

  // Business metadata
  subscription: {
    tier: 'trial' | 'starter' | 'professional' | 'enterprise';
    status: 'active' | 'suspended' | 'cancelled' | 'expired';
    expiresAt?: string;
  };

  // Quick stats for UI
  stats?: {
    userCount: number;
    activeModules: string[];
    storageUsed: number;
  };
}

export interface BusinessContext {
  businessId: string;
  businessName: string;
  role: string;
  permissions: string[];

  // Prefetched data for fast UI rendering
  settings: Record<string, any>;
  theme?: Record<string, any>;
  modules: string[];
  departments: Array<{
    id: string;
    name: string;
    code: string;
  }>;

  // User's context within this business
  userProfile: {
    employeeId?: string;
    jobTitle?: string;
    department?: string;
    reportsTo?: string;
    canApproveTransactions: boolean;
    spendingLimit: number;
  };
}

export interface SwitchResult {
  success: boolean;
  accessToken: string;
  refreshToken: string;
  businessContext: BusinessContext;
  switchTimeMs: number;
  cacheHit: boolean;

  // Performance metrics
  metrics: {
    dbQueryMs: number;
    cacheReadMs: number;
    cacheWriteMs: number;
    tokenGenerationMs: number;
    prefetchMs: number;
    totalMs: number;
  };
}

export interface CachedMembership {
  data: BusinessMembership;
  context?: Partial<BusinessContext>;
  cachedAt: number;
  expiresAt: number;
  version: number;
}

export interface PerformanceMetrics {
  operation: string;
  startTime: number;
  endTime?: number;
  duration?: number;
  metadata?: Record<string, any>;
}

export interface BusinessSwitchAudit {
  userId: string;
  fromBusinessId: string;
  toBusinessId: string;
  switchTimeMs: number;
  cacheHit: boolean;
  timestamp: number;
  ipAddress: string;
  userAgent: string;
}