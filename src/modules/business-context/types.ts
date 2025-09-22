/**
 * Business Context Type Definitions
 * Comprehensive types for business intelligence and contextual AI interactions
 */

import { z } from 'zod';

/**
 * Core business context data structure
 */
export interface BusinessContextData {
  businessId: string;
  companyProfile: CompanyProfile;
  departmentProfile?: DepartmentProfile;
  userProfile: UserProfile;
  businessIntelligence: BusinessIntelligence;
  departmentCapabilities: DepartmentCapabilities;
  contextualPrompts?: ContextualPrompts;
  realTimeMetrics?: RealTimeMetrics;
  metadata: {
    lastUpdated: number;
    version: string;
    fromCache?: boolean;
    confidenceScore: number;
  };
}

/**
 * Company profile for AI context
 */
export interface CompanyProfile {
  basic: {
    id: string;
    name: string;
    legalName: string;
    email: string;
    website?: string;
    phone?: string;
    industry: string;
    subIndustry?: string;
    size: 'startup' | 'small' | 'medium' | 'large' | 'enterprise';
    foundedYear?: number;
    headquarters: {
      country: string;
      region: string;
      city: string;
      timezone: string;
    };
  };

  business: {
    model: 'b2b' | 'b2c' | 'b2b2c' | 'marketplace' | 'saas' | 'ecommerce' | 'other';
    revenue: {
      annual?: number;
      currency: string;
      growthRate?: number;
      stage: 'pre-revenue' | 'early-revenue' | 'growth' | 'mature' | 'decline';
    };
    customers: {
      count?: number;
      segments: string[];
      avgLifetimeValue?: number;
      churnRate?: number;
    };
    marketPosition: 'leader' | 'challenger' | 'follower' | 'niche' | 'startup';
  };

  structure: {
    employeeCount: number;
    departments: string[];
    locations: Array<{
      type: 'headquarters' | 'office' | 'warehouse' | 'retail' | 'remote';
      country: string;
      city: string;
      employeeCount?: number;
    }>;
    hierarchy: 'flat' | 'traditional' | 'matrix' | 'network';
  };

  technology: {
    primarySystems: string[];
    integrations: string[];
    maturityLevel: 'basic' | 'intermediate' | 'advanced' | 'cutting-edge';
    digitalTransformation: 'planning' | 'in-progress' | 'mature' | 'leading';
  };

  culture: {
    values: string[];
    workStyle: 'traditional' | 'flexible' | 'remote-first' | 'hybrid';
    decisionMaking: 'centralized' | 'decentralized' | 'collaborative';
    communicationStyle: 'formal' | 'informal' | 'mixed';
  };
}

/**
 * Department-specific profile and capabilities
 */
export interface DepartmentProfile {
  basic: {
    code: string;
    name: string;
    description: string;
    type: 'revenue' | 'cost' | 'support' | 'strategic';
    headUserId?: string;
    parentDepartment?: string;
  };

  team: {
    size: number;
    roles: Array<{
      title: string;
      level: 'junior' | 'mid' | 'senior' | 'lead' | 'manager' | 'director';
      count: number;
    }>;
    skills: string[];
    averageExperience: number;
  };

  operations: {
    primaryFunctions: string[];
    keyProcesses: string[];
    tools: string[];
    kpis: Array<{
      name: string;
      target?: number;
      current?: number;
      unit: string;
    }>;
    budget: {
      annual?: number;
      currency: string;
      allocation: Record<string, number>; // category -> percentage
    };
  };

  workflows: {
    approvalLevels: number;
    automationLevel: 'low' | 'medium' | 'high';
    commonTasks: string[];
    painPoints: string[];
    efficiency: {
      score: number; // 0-100
      bottlenecks: string[];
      improvements: string[];
    };
  };

  relationships: {
    upstreamDepartments: string[];
    downstreamDepartments: string[];
    externalPartners: string[];
    conflictAreas?: string[];
    collaborationStrength: Record<string, number>; // dept -> score 0-100
  };
}

/**
 * User profile within business context
 */
export interface UserProfile {
  basic: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    jobTitle: string;
    department: string;
    role: 'owner' | 'director' | 'manager' | 'employee' | 'viewer';
    startDate: number;
    directReports?: number;
  };

  permissions: {
    capabilities: string[];
    dataAccess: string[];
    approvalLimits: Record<string, number>;
    systemAccess: string[];
  };

  preferences: {
    communicationStyle: 'direct' | 'detailed' | 'summary' | 'visual';
    workingHours: {
      timezone: string;
      start: string; // HH:MM
      end: string;   // HH:MM
      daysOfWeek: number[]; // 0-6, 0=Sunday
    };
    assistantStyle: 'formal' | 'friendly' | 'concise' | 'detailed';
    priorities: string[];
  };

  context: {
    currentProjects: string[];
    recentTasks: string[];
    expertise: string[];
    interests: string[];
    goals: {
      short: string[];
      long: string[];
    };
  };
}

/**
 * Business intelligence for informed AI decisions
 */
export interface BusinessIntelligence {
  financial: {
    performance: {
      profitability: 'high' | 'medium' | 'low' | 'negative';
      cashFlow: 'positive' | 'neutral' | 'negative';
      growth: 'accelerating' | 'steady' | 'slowing' | 'declining';
      seasonality?: string[];
    };
    constraints: {
      budgetTight: boolean;
      cashFlowConcerns: boolean;
      investmentFocus: string[];
    };
  };

  market: {
    position: 'growing' | 'stable' | 'declining';
    competition: 'intense' | 'moderate' | 'low';
    opportunities: string[];
    threats: string[];
    trends: string[];
  };

  operational: {
    efficiency: number; // 0-100
    scalability: 'excellent' | 'good' | 'limited' | 'poor';
    riskLevel: 'low' | 'medium' | 'high';
    priorities: Array<{
      area: string;
      urgency: 'low' | 'medium' | 'high' | 'critical';
      impact: 'low' | 'medium' | 'high';
    }>;
  };

  strategic: {
    phase: 'startup' | 'growth' | 'expansion' | 'maturity' | 'transformation';
    focus: string[];
    timeHorizon: 'immediate' | 'short' | 'medium' | 'long';
    riskTolerance: 'conservative' | 'moderate' | 'aggressive';
  };
}

/**
 * Department-specific capabilities and restrictions
 */
export interface DepartmentCapabilities {
  allowedOperations: string[];
  restrictedOperations: string[];
  dataAccess: {
    read: string[];
    write: string[];
    delete: string[];
  };
  approvalRequired: string[];
  costLimits: Record<string, number>;
  escalationRules: Array<{
    condition: string;
    action: string;
    recipient: string;
  }>;
}

/**
 * AI prompt templates customized for business context
 */
export interface ContextualPrompts {
  systemPrompt: string;
  departmentContext: string;
  roleContext: string;
  businessRules: string[];
  communicationGuidelines: string;
  escalationInstructions: string;
  complianceRequirements: string[];
  exampleInteractions: Array<{
    scenario: string;
    expectedResponse: string;
  }>;
}

/**
 * Real-time business metrics
 */
export interface RealTimeMetrics {
  timestamp: number;
  financial: {
    dailyRevenue?: number;
    monthlyRevenue?: number;
    cashPosition?: number;
    expenses?: number;
  };
  operational: {
    activeUsers?: number;
    systemLoad?: number;
    errorRates?: Record<string, number>;
    performanceMetrics?: Record<string, number>;
  };
  departmental?: Record<string, {
    productivity: number;
    workload: number;
    satisfaction: number;
    efficiency: number;
  }>;
}

/**
 * Business context request
 */
export interface BusinessContextRequest {
  businessId: string;
  userId: string;
  department?: string;
  capability?: string;
  taskType?: 'analysis' | 'generation' | 'processing' | 'reporting' | 'automation';
  enrichmentLevel?: 'minimal' | 'standard' | 'comprehensive' | 'complete';
  includeRealTimeData?: boolean;
  correlationId?: string;
}

/**
 * Business context response
 */
export interface BusinessContextResponse {
  success: boolean;
  businessId: string;
  contextData?: BusinessContextData;
  contextualPrompts?: ContextualPrompts;
  error?: {
    code: string;
    message: string;
    retryable: boolean;
  };
  metadata: {
    generatedAt: number;
    processingTimeMs: number;
    cacheHit: boolean;
    enrichmentLevel: string;
  };
}

/**
 * Context enrichment configuration
 */
export interface ContextEnrichmentConfig {
  enabled: boolean;
  level: 'minimal' | 'standard' | 'comprehensive' | 'complete';
  realTimeData: {
    enabled: boolean;
    refreshIntervalMs: number;
    sources: string[];
  };
  cache: {
    enabled: boolean;
    ttlSeconds: number;
    maxSize: number;
    compressionEnabled: boolean;
  };
  intelligence: {
    analysisEnabled: boolean;
    predictionEnabled: boolean;
    recommendationsEnabled: boolean;
    confidenceThreshold: number;
  };
  privacy: {
    dataAnonymization: boolean;
    sensitiveFieldRedaction: string[];
    auditTrail: boolean;
    retentionDays: number;
  };
}

/**
 * Context cache entry
 */
export interface ContextCacheEntry {
  key: string;
  data: BusinessContextData;
  metadata: {
    createdAt: number;
    expiresAt: number;
    accessCount: number;
    lastAccessed: number;
    version: string;
  };
}

/**
 * Context refresh trigger
 */
export interface ContextRefreshTrigger {
  businessId: string;
  reason: 'scheduled' | 'manual' | 'event' | 'stale_data' | 'error';
  triggeredBy: string;
  metadata?: Record<string, unknown>;
}

/**
 * Company metrics for analysis
 */
export interface CompanyMetrics {
  financial: {
    revenue: number;
    expenses: number;
    profit: number;
    cashFlow: number;
    growth: number;
  };
  operational: {
    efficiency: number;
    productivity: number;
    customerSatisfaction: number;
    employeeSatisfaction: number;
  };
  strategic: {
    marketShare: number;
    competitivePosition: number;
    innovationIndex: number;
    sustainabilityScore: number;
  };
}

/**
 * Validation schemas
 */
export const BusinessContextRequestSchema = z.object({
  businessId: z.string().min(1),
  userId: z.string().min(1),
  department: z.string().optional(),
  capability: z.string().optional(),
  taskType: z.enum(['analysis', 'generation', 'processing', 'reporting', 'automation']).optional(),
  enrichmentLevel: z.enum(['minimal', 'standard', 'comprehensive', 'complete']).optional(),
  includeRealTimeData: z.boolean().optional(),
  correlationId: z.string().optional(),
});

export const ContextEnrichmentConfigSchema = z.object({
  enabled: z.boolean(),
  level: z.enum(['minimal', 'standard', 'comprehensive', 'complete']),
  realTimeData: z.object({
    enabled: z.boolean(),
    refreshIntervalMs: z.number().min(1000),
    sources: z.array(z.string()),
  }),
  cache: z.object({
    enabled: z.boolean(),
    ttlSeconds: z.number().min(60),
    maxSize: z.number().min(1),
    compressionEnabled: z.boolean(),
  }),
  intelligence: z.object({
    analysisEnabled: z.boolean(),
    predictionEnabled: z.boolean(),
    recommendationsEnabled: z.boolean(),
    confidenceThreshold: z.number().min(0).max(1),
  }),
  privacy: z.object({
    dataAnonymization: z.boolean(),
    sensitiveFieldRedaction: z.array(z.string()),
    auditTrail: z.boolean(),
    retentionDays: z.number().min(1),
  }),
});

/**
 * Error types for business context
 */
export class BusinessContextError extends Error {
  constructor(
    message: string,
    public code: string,
    public retryable: boolean = false
  ) {
    super(message);
    this.name = 'BusinessContextError';
  }
}

export class BusinessAccessError extends BusinessContextError {
  constructor(businessId: string, userId: string) {
    super(
      `User ${userId} does not have access to business ${businessId}`,
      'BUSINESS_ACCESS_DENIED',
      false
    );
  }
}

export class ContextNotFoundError extends BusinessContextError {
  constructor(businessId: string, contextType: string) {
    super(
      `${contextType} context not found for business ${businessId}`,
      'CONTEXT_NOT_FOUND',
      true
    );
  }
}

export class ContextStaleError extends BusinessContextError {
  constructor(businessId: string, age: number) {
    super(
      `Context for business ${businessId} is stale (${age}ms old)`,
      'CONTEXT_STALE',
      true
    );
  }
}

/**
 * Default configuration values
 */
export const DEFAULT_CONTEXT_CONFIG: ContextEnrichmentConfig = {
  enabled: true,
  level: 'standard',
  realTimeData: {
    enabled: true,
    refreshIntervalMs: 300000, // 5 minutes
    sources: ['financial', 'operational', 'departmental'],
  },
  cache: {
    enabled: true,
    ttlSeconds: 3600, // 1 hour
    maxSize: 1000,
    compressionEnabled: true,
  },
  intelligence: {
    analysisEnabled: true,
    predictionEnabled: false,
    recommendationsEnabled: true,
    confidenceThreshold: 0.7,
  },
  privacy: {
    dataAnonymization: false,
    sensitiveFieldRedaction: ['salary', 'ssn', 'personal_notes'],
    auditTrail: true,
    retentionDays: 365,
  },
};

/**
 * Context constants
 */
export const CONTEXT_CONSTANTS = {
  MAX_CACHE_SIZE: 10000,
  MIN_CONFIDENCE_SCORE: 0.5,
  STALE_THRESHOLD_MS: 3600000, // 1 hour
  REAL_TIME_REFRESH_MS: 300000, // 5 minutes
  MAX_PROMPT_LENGTH: 32000,
  MAX_CONTEXT_AGE_MS: 86400000, // 24 hours
} as const;