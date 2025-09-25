/**
 * Business Context Provider
 * Central provider for gathering and enriching business context for AI agents
 */

import type { D1Database } from '@cloudflare/workers-types';
import {
  BusinessContextData,
  CompanyProfile,
  DepartmentProfile,
  UserProfile,
  BusinessIntelligence,
  DepartmentCapabilities,
  ContextualPrompts,
  RealTimeMetrics,
  ContextEnrichmentConfig,
  BusinessContextError,
  BusinessAccessError,
  ContextNotFoundError,
  DEFAULT_CONTEXT_CONFIG,
  CONTEXT_CONSTANTS
} from './types';
import { ContextCache } from './cache';
import { CompanyAnalyzer } from './company-analyzer';
import { DepartmentProfiler } from './department-profiler';
import { ContextEnricher } from './context-enricher';
import { Logger } from '../../shared/logger';
import { CorrelationId } from '../../shared/security-utils';

export class BusinessContextProvider {
  private logger: Logger;
  private db: D1Database;
  private cache: ContextCache;
  private companyAnalyzer: CompanyAnalyzer;
  private departmentProfiler: DepartmentProfiler;
  private contextEnricher: ContextEnricher;
  private config: ContextEnrichmentConfig;

  constructor(
    db: D1Database,
    cache: ContextCache,
    config?: Partial<ContextEnrichmentConfig>
  ) {
    this.logger = new Logger();
    this.db = db;
    this.cache = cache;
    this.config = { ...DEFAULT_CONTEXT_CONFIG, ...config };

    this.companyAnalyzer = new CompanyAnalyzer(db);
    this.departmentProfiler = new DepartmentProfiler(db);
    this.contextEnricher = new ContextEnricher(this.config);
  }

  /**
   * Get comprehensive business context
   */
  async getBusinessContext(
    businessId: string,
    userId: string,
    department?: string,
    capability?: string
  ): Promise<BusinessContextData> {
    const startTime = Date.now();

    try {
      // Check cache first
      if (this.config.cache.enabled) {
        const cacheKey = this.generateCacheKey(businessId, userId, department, capability);
        const cached = await this.cache.get(cacheKey);
        if (cached && !this.isContextStale(cached)) {
          cached.metadata.fromCache = true;
          return cached;
        }
      }

      // Validate access
      const hasAccess = await this.validateAccess(userId, businessId);
      if (!hasAccess) {
        throw new BusinessAccessError(businessId, userId);
      }

      // Get core context components in parallel
      const [
        companyProfile,
        userProfile,
        departmentProfile,
        businessIntelligence,
        departmentCapabilities
      ] = await Promise.all([
        this.getCompanyProfile(businessId),
        this.getUserProfile(userId, businessId),
        department ? this.getDepartmentProfile(businessId, department) : null,
        this.getBusinessIntelligence(businessId),
        department ? this.getDepartmentCapabilities(businessId, department) : this.getDefaultCapabilities()
      ]);

      if (!companyProfile) {
        throw new ContextNotFoundError(businessId, 'company');
      }

      if (!userProfile) {
        throw new ContextNotFoundError(businessId, 'user');
      }

      // Build context data
      const contextData: BusinessContextData = {
        businessId,
        companyProfile,
        userProfile,
        businessIntelligence,
        departmentCapabilities,
        departmentProfile: departmentProfile || undefined,
        metadata: {
          lastUpdated: Date.now(),
          version: '1.0.0',
          fromCache: false,
          confidenceScore: this.calculateConfidenceScore(companyProfile, userProfile, departmentProfile),
        },
      };

      // Enrich context based on configuration
      if (this.config.intelligence.analysisEnabled) {
        await this.contextEnricher.enrichWithAnalysis(contextData);
      }

      // Generate contextual prompts if capability specified
      if (capability) {
        contextData.contextualPrompts = await this.generateContextualPrompts(
          contextData,
          capability
        );
      }

      // Cache the result
      if (this.config.cache.enabled) {
        const cacheKey = this.generateCacheKey(businessId, userId, department, capability);
        await this.cache.set(cacheKey, contextData, this.config.cache.ttlSeconds);
      }

      const processingTime = Date.now() - startTime;
      this.logger.info('Business context generated successfully', {
        businessId,
        userId,
        department,
        capability,
        processingTime,
        confidenceScore: contextData.metadata.confidenceScore,
      });

      return contextData;

    } catch (error) {
      const processingTime = Date.now() - startTime;
      this.logger.error('Failed to get business context', error, {
        businessId,
        userId,
        department,
        capability,
        processingTime,
      });
      throw error;
    }
  }

  /**
   * Get company profile with business intelligence
   */
  async getCompanyProfile(businessId: string): Promise<CompanyProfile | null> {
    try {
      // Get basic company data
      const companyData = await this.db.prepare(`
        SELECT
          b.id,
          b.name,
          b.legal_name,
          b.email,
          b.website,
          b.phone,
          b.industry,
          b.sub_industry,
          b.size,
          b.founded_year,
          b.headquarters_country,
          b.headquarters_region,
          b.headquarters_city,
          b.timezone,
          b.business_model,
          b.settings,
          b.created_at
        FROM businesses b
        WHERE b.id = ? AND b.status = 'active'
      `).bind(businessId).first();

      if (!companyData) {
        return null;
      }

      // Get additional company analysis
      const analysis = await this.companyAnalyzer.analyzeCompany(businessId);

      // Build comprehensive company profile
      const companyProfile: CompanyProfile = {
        basic: {
          id: companyData.id,
          name: companyData.name,
          legalName: companyData.legal_name || companyData.name,
          email: companyData.email,
          website: companyData.website,
          phone: companyData.phone,
          industry: companyData.industry || 'Unknown',
          subIndustry: companyData.sub_industry,
          size: companyData.size || 'small',
          foundedYear: companyData.founded_year,
          headquarters: {
            country: companyData.headquarters_country || 'US',
            region: companyData.headquarters_region || 'Unknown',
            city: companyData.headquarters_city || 'Unknown',
            timezone: companyData.timezone || 'UTC',
          },
        },
        business: analysis.businessModel,
        structure: analysis.organizationalStructure,
        technology: analysis.technologyProfile,
        culture: analysis.culturalProfile,
      };

      return companyProfile;

    } catch (error) {
      this.logger.error('Failed to get company profile', error, { businessId });
      return null;
    }
  }

  /**
   * Get department profile with operational context
   */
  async getDepartmentProfile(businessId: string, department: string): Promise<DepartmentProfile | null> {
    try {
      return await this.departmentProfiler.getDepartmentProfile(businessId, department);
    } catch (error) {
      this.logger.error('Failed to get department profile', error, { businessId, department });
      return null;
    }
  }

  /**
   * Get user profile within business context
   */
  async getUserProfile(userId: string, businessId: string): Promise<UserProfile | null> {
    try {
      const userData = await this.db.prepare(`
        SELECT
          u.id,
          u.email,
          u.first_name,
          u.last_name,
          bm.role,
          bm.job_title,
          bm.department,
          bm.joined_at,
          bm.settings,
          (SELECT COUNT(*) FROM business_memberships WHERE manager_user_id = u.id AND business_id = ?) as direct_reports
        FROM users u
        JOIN business_memberships bm ON bm.user_id = u.id
        WHERE u.id = ? AND bm.business_id = ? AND bm.status = 'active'
      `).bind(businessId, userId, businessId).first();

      if (!userData) {
        return null;
      }

      const settings = JSON.parse(userData.settings || '{}');

      // Get user permissions and capabilities
      const permissions = await this.getUserPermissions(userId, businessId);

      const userProfile: UserProfile = {
        basic: {
          id: userData.id,
          email: userData.email,
          firstName: userData.first_name,
          lastName: userData.last_name,
          jobTitle: userData.job_title || 'Employee',
          department: userData.department || 'General',
          role: userData.role || 'employee',
          startDate: new Date(userData.joined_at).getTime(),
          directReports: userData.direct_reports || 0,
        },
        permissions,
        preferences: {
          communicationStyle: settings.communicationStyle || 'friendly',
          workingHours: settings.workingHours || {
            timezone: 'UTC',
            start: '09:00',
            end: '17:00',
            daysOfWeek: [1, 2, 3, 4, 5],
          },
          assistantStyle: settings.assistantStyle || 'friendly',
          priorities: settings.priorities || [],
        },
        context: {
          currentProjects: await this.getUserProjects(userId, businessId),
          recentTasks: await this.getUserRecentTasks(userId, businessId),
          expertise: settings.expertise || [],
          interests: settings.interests || [],
          goals: settings.goals || { short: [], long: [] },
        },
      };

      return userProfile;

    } catch (error) {
      this.logger.error('Failed to get user profile', error, { userId, businessId });
      return null;
    }
  }

  /**
   * Get business intelligence for strategic context
   */
  async getBusinessIntelligence(businessId: string): Promise<BusinessIntelligence> {
    try {
      return await this.companyAnalyzer.getBusinessIntelligence(businessId);
    } catch (error) {
      this.logger.error('Failed to get business intelligence', error, { businessId });

      // Return default intelligence with low confidence
      return {
        financial: {
          performance: {
            profitability: 'medium',
            cashFlow: 'neutral',
            growth: 'steady',
          },
          constraints: {
            budgetTight: false,
            cashFlowConcerns: false,
            investmentFocus: [],
          },
        },
        market: {
          position: 'stable',
          competition: 'moderate',
          opportunities: [],
          threats: [],
          trends: [],
        },
        operational: {
          efficiency: 70,
          scalability: 'good',
          riskLevel: 'medium',
          priorities: [],
        },
        strategic: {
          phase: 'growth',
          focus: [],
          timeHorizon: 'medium',
          riskTolerance: 'moderate',
        },
      };
    }
  }

  /**
   * Get department capabilities and restrictions
   */
  async getDepartmentCapabilities(businessId: string, department: string): Promise<DepartmentCapabilities> {
    try {
      return await this.departmentProfiler.getDepartmentCapabilities(businessId, department);
    } catch (error) {
      this.logger.error('Failed to get department capabilities', error, { businessId, department });
      return this.getDefaultCapabilities();
    }
  }

  /**
   * Generate contextual prompts for AI agents
   */
  async generateContextualPrompts(
    contextData: BusinessContextData,
    capability: string,
    taskType?: string
  ): Promise<ContextualPrompts> {
    return this.contextEnricher.generateContextualPrompts(contextData, capability, taskType);
  }

  /**
   * Get real-time metrics for dynamic context
   */
  async getRealTimeMetrics(businessId: string, department?: string): Promise<RealTimeMetrics> {
    try {
      const timestamp = Date.now();

      // Get real-time financial metrics
      const financial = await this.getRealTimeFinancialMetrics(businessId);

      // Get operational metrics
      const operational = await this.getRealTimeOperationalMetrics(businessId);

      // Get departmental metrics if specified
      const departmental = department
        ? await this.getRealTimeDepartmentalMetrics(businessId, department)
        : undefined;

      return {
        timestamp,
        financial,
        operational,
        departmental: departmental ? { [department]: departmental } : undefined,
      };

    } catch (error) {
      this.logger.error('Failed to get real-time metrics', error, { businessId, department });
      return { timestamp: Date.now() };
    }
  }

  /**
   * Refresh business context cache
   */
  async refreshBusinessContext(businessId: string): Promise<void> {
    try {
      // Clear all cached data for this business
      await this.cache.invalidateByPattern(`context:${businessId}:*`);

      this.logger.info('Business context cache refreshed', { businessId });

    } catch (error) {
      this.logger.error('Failed to refresh business context', error, { businessId });
      throw error;
    }
  }

  /**
   * Validate user access to business context
   */
  async validateAccess(userId: string, businessId: string, requiredRole?: string): Promise<boolean> {
    try {
      const membership = await this.db.prepare(`
        SELECT role, status
        FROM business_memberships
        WHERE user_id = ? AND business_id = ?
      `).bind(userId, businessId).first();

      if (!membership || membership.status !== 'active') {
        return false;
      }

      if (requiredRole) {
        const roleHierarchy = ['viewer', 'employee', 'manager', 'director', 'owner'];
        const userRoleIndex = roleHierarchy.indexOf(membership.role);
        const requiredRoleIndex = roleHierarchy.indexOf(requiredRole);

        return userRoleIndex >= requiredRoleIndex;
      }

      return true;

    } catch (error) {
      this.logger.error('Failed to validate context access', error, { userId, businessId, requiredRole });
      return false;
    }
  }

  /**
   * Private helper methods
   */

  private generateCacheKey(businessId: string, userId: string, department?: string, capability?: string): string {
    const parts = ['context', businessId, userId];
    if (department) parts.push(department);
    if (capability) parts.push(capability);
    return parts.join(':');
  }

  private isContextStale(contextData: BusinessContextData): boolean {
    const age = Date.now() - contextData.metadata.lastUpdated;
    return age > CONTEXT_CONSTANTS.STALE_THRESHOLD_MS;
  }

  private calculateConfidenceScore(
    companyProfile: CompanyProfile,
    userProfile: UserProfile,
    departmentProfile?: DepartmentProfile | null
  ): number {
    let score = 0.5; // Base score

    // Company profile completeness
    if (companyProfile.basic.industry && companyProfile.basic.industry !== 'Unknown') score += 0.1;
    if (companyProfile.basic.size) score += 0.05;
    if (companyProfile.business.model) score += 0.1;
    if (companyProfile.structure.employeeCount > 0) score += 0.05;

    // User profile completeness
    if (userProfile.basic.jobTitle && userProfile.basic.jobTitle !== 'Employee') score += 0.05;
    if (userProfile.basic.department && userProfile.basic.department !== 'General') score += 0.05;
    if (userProfile.permissions.capabilities.length > 0) score += 0.05;

    // Department profile bonus
    if (departmentProfile) score += 0.1;

    return Math.min(1.0, score);
  }

  private async getUserPermissions(userId: string, businessId: string): Promise<UserProfile['permissions']> {
    // Get user permissions from database or capability system
    // This is a simplified implementation
    return {
      capabilities: [], // Will be populated by capability system
      dataAccess: ['read_own', 'read_department'],
      approvalLimits: {},
      systemAccess: ['basic'],
    };
  }

  private async getUserProjects(userId: string, businessId: string): Promise<string[]> {
    // Get user's current projects
    return [];
  }

  private async getUserRecentTasks(userId: string, businessId: string): Promise<string[]> {
    // Get user's recent tasks
    return [];
  }

  private async getRealTimeFinancialMetrics(businessId: string): Promise<RealTimeMetrics['financial']> {
    // Get real-time financial data
    return {};
  }

  private async getRealTimeOperationalMetrics(businessId: string): Promise<RealTimeMetrics['operational']> {
    // Get real-time operational data
    return {};
  }

  private async getRealTimeDepartmentalMetrics(businessId: string, department: string): Promise<any> {
    // Get real-time departmental data
    return {
      productivity: 75,
      workload: 80,
      satisfaction: 85,
      efficiency: 70,
    };
  }

  private getDefaultCapabilities(): DepartmentCapabilities {
    return {
      allowedOperations: ['read', 'create', 'update'],
      restrictedOperations: ['delete', 'admin'],
      dataAccess: {
        read: ['own', 'department'],
        write: ['own'],
        delete: [],
      },
      approvalRequired: ['high_cost', 'external_communication'],
      costLimits: {
        daily: 100,
        monthly: 2000,
      },
      escalationRules: [],
    };
  }
}