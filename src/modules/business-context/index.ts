/**
 * Business Context System
 * Provides rich contextual information for AI agents to make intelligent decisions
 */

// Core business context services
export { BusinessContextProvider } from './provider';
export { DepartmentProfiler } from './department-profiler';
export { CompanyAnalyzer } from './company-analyzer';
export { ContextEnricher } from './context-enricher';

// Type definitions
export type {
  BusinessContextData,
  DepartmentProfile,
  CompanyProfile,
  UserProfile,
  ContextEnrichmentConfig,
  BusinessIntelligence,
  DepartmentCapabilities,
  CompanyMetrics,
  ContextualPrompts,
  BusinessContextRequest,
  BusinessContextResponse,
  ContextCacheEntry,
  ContextRefreshTrigger
} from './types';

// Context-specific services
export { FinanceContextService } from './services/finance-context';
export { HRContextService } from './services/hr-context';
export { SalesContextService } from './services/sales-context';
export { OperationsContextService } from './services/operations-context';
export { MarketingContextService } from './services/marketing-context';

// Context retrieval and caching
export { ContextCache } from './cache';
export { ContextAggregator } from './aggregator';

// Utilities
export {
  ContextUtils,
  DepartmentMatcher,
  CompanyClassifier,
  ContextValidator,
  PromptEnhancer
} from './utils';

import type { KVNamespace, D1Database } from '@cloudflare/workers-types';
import {
  BusinessContextData,
  BusinessContextRequest,
  BusinessContextResponse,
  ContextEnrichmentConfig,
  DepartmentProfile,
  CompanyProfile
} from './types';
import { BusinessContextProvider } from './provider';
import { ContextCache } from './cache';
import { Logger } from '../../shared/logger';
import { AuditService } from '../audit/audit-service';

/**
 * Business Context Manager
 * Central interface for managing business context for AI agents
 */
export // TODO: Consider splitting BusinessContextManager into smaller, focused classes
class BusinessContextManager {
  private logger: Logger;
  private provider: BusinessContextProvider;
  private cache: ContextCache;
  private auditService: AuditService;

  constructor(
    kv: KVNamespace,
    db: D1Database,
    auditService: AuditService,
    config?: Partial<ContextEnrichmentConfig>
  ) {
    this.logger = new Logger();
    this.cache = new ContextCache(kv);
    this.provider = new BusinessContextProvider(db, this.cache, config);
    this.auditService = auditService;
  }

  /**
   * Get comprehensive business context for AI agents
   */
  async getBusinessContext(request: BusinessContextRequest): Promise<BusinessContextResponse> {
    const startTime = Date.now();

    try {
      // Get business context from provider
      const contextData = await this.provider.getBusinessContext(
        request.businessId,
        request.userId,
        request.department,
        request.capability
      );

      // Enrich with real-time data if requested
      if (request.includeRealTimeData) {
        contextData.realTimeMetrics = await this.provider.getRealTimeMetrics(
          request.businessId,
          request.department
        );
      }

      // Generate contextual prompts for the requested capability
      const contextualPrompts = await this.provider.generateContextualPrompts(
        contextData,
        request.capability,
        request.taskType
      );

      // Create response
      const response: BusinessContextResponse = {
        success: true,
        businessId: request.businessId,
        contextData,
        contextualPrompts,
        metadata: {
          generatedAt: Date.now(),
          processingTimeMs: Date.now() - startTime,
          cacheHit: contextData.metadata?.fromCache || false,
          enrichmentLevel: request.enrichmentLevel || 'standard',
        },
      };

      // Log context access for audit
      await this.auditService.logEvent({
        eventType: 'business_context_accessed',
        severity: 'low',
        operation: `context:${request.capability}`,
        result: 'success',
        details: {
          businessId: request.businessId,
          userId: request.userId,
          department: request.department,
          capability: request.capability,
          enrichmentLevel: request.enrichmentLevel,
          processingTime: response.metadata.processingTimeMs,
        },
        securityContext: {
          correlationId: request.correlationId || 'unknown',
          userId: request.userId,
          businessId: request.businessId,
          operation: 'business_context_access',
        },
      });

      this.logger.info('Business context retrieved successfully', {
        businessId: request.businessId,
        userId: request.userId,
        department: request.department,
        capability: request.capability,
        processingTime: response.metadata.processingTimeMs,
        cacheHit: response.metadata.cacheHit,
      });

      return response;

    } catch (error) {
      const errorTime = Date.now() - startTime;

      // Log error
      await this.auditService.logEvent({
        eventType: 'business_context_error',
        severity: 'medium',
        operation: `context:${request.capability}`,
        result: 'failure',
        details: {
          businessId: request.businessId,
          userId: request.userId,
          error: error instanceof Error ? error.message : 'Unknown error',
          processingTime: errorTime,
        },
        securityContext: {
          correlationId: request.correlationId || 'unknown',
          userId: request.userId,
          businessId: request.businessId,
          operation: 'business_context_access',
        },
      });

      this.logger.error('Failed to retrieve business context', error, {
        businessId: request.businessId,
        userId: request.userId,
        department: request.department,
        capability: request.capability,
        processingTime: errorTime,
      });

      // Return error response
      return {
        success: false,
        businessId: request.businessId,
        error: {
          code: 'CONTEXT_RETRIEVAL_FAILED',
          message: error instanceof Error ? error.message : 'Unknown error',
          retryable: true,
        },
        metadata: {
          generatedAt: Date.now(),
          processingTimeMs: errorTime,
          cacheHit: false,
          enrichmentLevel: request.enrichmentLevel || 'standard',
        },
      };
    }
  }

  /**
   * Get department profile for contextual AI interactions
   */
  async getDepartmentProfile(
    businessId: string,
    department: string
  ): Promise<DepartmentProfile | null> {
    try {
      return await this.provider.getDepartmentProfile(businessId, department);
    } catch (error) {
      this.logger.error('Failed to get department profile', error, {
        businessId,
        department,
      });
      return null;
    }
  }

  /**
   * Get company profile for business intelligence
   */
  async getCompanyProfile(businessId: string): Promise<CompanyProfile | null> {
    try {
      return await this.provider.getCompanyProfile(businessId);
    } catch (error) {
      this.logger.error('Failed to get company profile', error, {
        businessId,
      });
      return null;
    }
  }

  /**
   * Refresh context cache for a business
   */
  async refreshBusinessContext(
    businessId: string,
    userId: string,
    reason: string = 'manual_refresh'
  ): Promise<void> {
    try {
      await this.provider.refreshBusinessContext(businessId);

      this.logger.info('Business context refreshed', {
        businessId,
        userId,
        reason,
      });

      // Audit the refresh
      await this.auditService.logEvent({
        eventType: 'business_context_refreshed',
        severity: 'low',
        operation: 'context:refresh',
        result: 'success',
        details: {
          businessId,
          reason,
          triggeredBy: userId,
        },
        securityContext: {
          correlationId: 'context_refresh',
          userId,
          businessId,
          operation: 'business_context_refresh',
        },
      });

    } catch (error) {
      this.logger.error('Failed to refresh business context', error, {
        businessId,
        userId,
        reason,
      });
      throw error;
    }
  }

  /**
   * Validate that user has access to business context
   */
  async validateContextAccess(
    userId: string,
    businessId: string,
    requiredRole?: string
  ): Promise<boolean> {
    try {
      return await this.provider.validateAccess(userId, businessId, requiredRole);
    } catch (error) {
      this.logger.error('Failed to validate context access', error, {
        userId,
        businessId,
        requiredRole,
      });
      return false;
    }
  }

  /**
   * Get context cache statistics
   */
  async getCacheStatistics(): Promise<any> {
    return this.cache.getStatistics();
  }

  /**
   * Clean up expired context cache entries
   */
  async cleanupCache(): Promise<void> {
    await this.cache.cleanup();
  }
}

/**
 * Factory function to create business context manager
 */
export async function createBusinessContextManager(
  kv: KVNamespace,
  db: D1Database,
  auditService: AuditService,
  config?: Partial<ContextEnrichmentConfig>
): Promise<BusinessContextManager> {
  const manager = new BusinessContextManager(kv, db, auditService, config);

  // Perform any initialization
  await manager.cleanupCache();

  return manager;
}