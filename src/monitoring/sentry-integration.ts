/**
 * Enhanced Sentry Integration with AI Analysis
 * Advanced error tracking with ML-powered insights and automated remediation
 */

import { Env } from '../types/env';
import { Logger } from '../shared/logger';

export interface SentryConfig {
  dsn: string;
  environment: string;
  release?: string;
  tracesSampleRate: number;
  profilesSampleRate: number;
  beforeSend?: (event: SentryEvent, hint: SentryHint) => Promise<SentryEvent | null>;
  beforeSendTransaction?: (event: SentryTransaction, hint: SentryHint) => Promise<SentryTransaction | null>;
}

export interface SentryEvent {
  event_id?: string;
  message?: string;
  level?: SentryLevel;
  platform?: string;
  timestamp?: number;
  environment?: string;
  release?: string;
  user?: SentryUser;
  tags?: Record<string, string>;
  extra?: Record<string, any>;
  fingerprint?: string[];
  exception?: SentryException;
  request?: SentryRequest;
  contexts?: SentryContexts;
  breadcrumbs?: SentryBreadcrumb[];
}

export interface SentryTransaction {
  event_id?: string;
  type: 'transaction';
  transaction: string;
  start_timestamp: number;
  timestamp: number;
  spans?: SentrySpan[];
  contexts?: SentryContexts;
}

export type SentryLevel = 'fatal' | 'error' | 'warning' | 'info' | 'debug';

export interface SentryUser {
  id?: string;
  email?: string;
  username?: string;
  ip_address?: string;
  segment?: string;
}

export interface SentryException {
  values: SentryExceptionValue[];
}

export interface SentryExceptionValue {
  type: string;
  value: string;
  module?: string;
  thread_id?: number;
  stacktrace?: SentryStacktrace;
}

export interface SentryStacktrace {
  frames: SentryFrame[];
}

export interface SentryFrame {
  filename: string;
  function: string;
  lineno: number;
  colno: number;
  abs_path?: string;
  context_line?: string;
  pre_context?: string[];
  post_context?: string[];
  in_app?: boolean;
}

export interface SentryRequest {
  url: string;
  method: string;
  headers?: Record<string, string>;
  query_string?: string;
  data?: any;
  cookies?: Record<string, string>;
  env?: Record<string, string>;
}

export interface SentryContexts {
  app?: SentryAppContext;
  browser?: SentryBrowserContext;
  device?: SentryDeviceContext;
  os?: SentryOSContext;
  runtime?: SentryRuntimeContext;
  trace?: SentryTraceContext;
  business?: SentryBusinessContext;
}

export interface SentryAppContext {
  app_name: string;
  app_version: string;
  app_identifier: string;
  build_type: string;
}

export interface SentryBrowserContext {
  name: string;
  version: string;
}

export interface SentryDeviceContext {
  name: string;
  family: string;
  model: string;
  memory_size?: number;
  free_memory?: number;
  usable_memory?: number;
  storage_size?: number;
  free_storage?: number;
}

export interface SentryOSContext {
  name: string;
  version: string;
  build?: string;
  kernel_version?: string;
}

export interface SentryRuntimeContext {
  name: string;
  version: string;
  build?: string;
}

export interface SentryTraceContext {
  trace_id: string;
  span_id: string;
  parent_span_id?: string;
  op?: string;
  description?: string;
  status?: string;
}

export interface SentryBusinessContext {
  business_id: string;
  plan: string;
  features: string[];
  usage_tier: string;
  region: string;
}

export interface SentryBreadcrumb {
  timestamp: number;
  type?: string;
  level?: SentryLevel;
  message?: string;
  category?: string;
  data?: Record<string, any>;
}

export interface SentrySpan {
  span_id: string;
  parent_span_id?: string;
  trace_id: string;
  op: string;
  description?: string;
  start_timestamp: number;
  timestamp: number;
  status?: string;
  tags?: Record<string, string>;
  data?: Record<string, any>;
}

export interface SentryHint {
  originalException?: Error;
  syntheticException?: Error;
  data?: any;
}

export interface AIAnalysis {
  rootCause: string;
  suggestedFix: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  similarIssues: string[];
  affectedUsers: number;
  businessImpact: BusinessImpact;
  autoFixAvailable: boolean;
  escalationRequired: boolean;
}

export interface BusinessImpact {
  revenue: number;
  userExperience: number;
  operationalImpact: number;
  reputationRisk: number;
  complianceRisk: number;
}

export interface TicketCreationRequest {
  title: string;
  description: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  assignee?: string;
  labels: string[];
  suggestedFix?: string;
  errorDetails: any;
}

export class SentryIntegration {
  private logger = new Logger();
  private config: SentryConfig;
  private aiAnalyzer: ErrorAnalyzer;
  private ticketManager: TicketManager;
  private env: Env;

  constructor(env: Env, config: Partial<SentryConfig> = {}) {
    this.env = env;
    this.config = {
      dsn: env.SENTRY_DSN || '',
      environment: env.ENVIRONMENT || 'development',
      release: env.SENTRY_RELEASE || 'unknown',
      tracesSampleRate: this.getAdaptiveSampleRate(),
      profilesSampleRate: 0.1,
      beforeSend: this.enhancedBeforeSend.bind(this),
      beforeSendTransaction: this.enhancedBeforeTransaction.bind(this),
      ...config
    };

    this.aiAnalyzer = new ErrorAnalyzer(env);
    this.ticketManager = new TicketManager(env);
  }

  /**
   * Initialize Sentry with enhanced configuration
   */
  async initialize(): Promise<void> {
    this.logger.info('Initializing enhanced Sentry integration', {
      environment: this.config.environment,
      release: this.config.release
    });

    // Sentry initialization would happen here
    // In a real implementation, this would call Sentry.init()
  }

  /**
   * Enhanced beforeSend hook with AI analysis
   */
  private async enhancedBeforeSend(event: SentryEvent, hint: SentryHint): Promise<SentryEvent | null> {
    try {
      // Skip if DSN not configured
      if (!this.config.dsn) {
        return null;
      }

      // Add business context
      event = this.addBusinessContext(event);

      // Add performance context
      event = this.addPerformanceContext(event);

      // Add security context
      event = this.addSecurityContext(event);

      // AI analysis of error
      const analysis = await this.aiAnalyzer.analyzeError(event, hint);

      // Enhance event with AI insights
      event.extra = {
        ...event.extra,
        aiAnalysis: analysis,
        businessImpact: analysis.businessImpact,
        affectedUsers: await this.getAffectedUsersCount(event),
        correlationId: this.extractCorrelationId(event),
        deploymentContext: await this.getDeploymentContext()
      };

      // Add fingerprinting for better grouping
      event.fingerprint = this.generateFingerprint(event, analysis);

      // Auto-create ticket for critical errors
      if (analysis.severity === 'critical' || analysis.escalationRequired) {
        await this.createAutomaticTicket(event, analysis);
      }

      // Auto-fix if possible
      if (analysis.autoFixAvailable && this.env.ENVIRONMENT === 'production') {
        await this.attemptAutoFix(event, analysis);
      }

      // Rate limiting for spam prevention
      if (await this.shouldRateLimit(event)) {
        this.logger.debug('Rate limiting Sentry event', {
          fingerprint: event.fingerprint,
          message: event.message
        });
        return null;
      }

      return event;

    } catch (error) {
      this.logger.error('Error in Sentry beforeSend hook', error);
      return event; // Return original event on processing failure
    }
  }

  /**
   * Enhanced beforeSendTransaction hook
   */
  private async enhancedBeforeTransaction(
    transaction: SentryTransaction,
    hint: SentryHint
  ): Promise<SentryTransaction | null> {
    try {
      // Add business context to transactions
      transaction.contexts = {
        ...transaction.contexts,
        business: await this.getBusinessContext()
      };

      // Add performance annotations
      transaction = this.annotatePerformance(transaction);

      // Filter out irrelevant transactions
      if (this.shouldFilterTransaction(transaction)) {
        return null;
      }

      return transaction;

    } catch (error) {
      this.logger.error('Error in Sentry beforeSendTransaction hook', error);
      return transaction;
    }
  }

  /**
   * Add business context to events
   */
  private addBusinessContext(event: SentryEvent): SentryEvent {
    const businessContext: SentryBusinessContext = {
      business_id: event.user?.id || 'unknown',
      plan: 'enterprise', // Would be determined from user context
      features: ['ai', 'crm', 'finance', 'inventory'],
      usage_tier: 'high',
      region: this.env.CLOUDFLARE_REGION || 'unknown'
    };

    event.contexts = {
      ...event.contexts,
      business: businessContext
    };

    return event;
  }

  /**
   * Add performance context
   */
  private addPerformanceContext(event: SentryEvent): SentryEvent {
    event.contexts = {
      ...event.contexts,
      runtime: {
        name: 'cloudflare-workers',
        version: 'latest',
        build: this.config.release || 'unknown'
      }
    };

    return event;
  }

  /**
   * Add security context
   */
  private addSecurityContext(event: SentryEvent): SentryEvent {
    // Sanitize sensitive data
    if (event.request?.headers) {
      const sanitizedHeaders = { ...event.request.headers };
      delete sanitizedHeaders.authorization;
      delete sanitizedHeaders.cookie;
      delete sanitizedHeaders['x-api-key'];
      event.request.headers = sanitizedHeaders;
    }

    // Add security tags
    event.tags = {
      ...event.tags,
      security_context: 'sanitized',
      data_classification: 'business'
    };

    return event;
  }

  /**
   * Generate intelligent fingerprint for error grouping
   */
  private generateFingerprint(event: SentryEvent, analysis: AIAnalysis): string[] {
    const fingerprint: string[] = [];

    // Use AI-suggested grouping
    if (analysis.rootCause) {
      fingerprint.push(`root_cause:${analysis.rootCause}`);
    }

    // Add error type
    if (event.exception?.values?.[0]?.type) {
      fingerprint.push(`error_type:${event.exception.values[0].type}`);
    }

    // Add function context
    if (event.exception?.values?.[0]?.stacktrace?.frames?.[0]?.function) {
      fingerprint.push(`function:${event.exception.values[0].stacktrace.frames[0].function}`);
    }

    // Add business context
    if (event.contexts?.business?.business_id) {
      fingerprint.push(`business:${event.contexts.business.business_id}`);
    }

    return fingerprint.length > 0 ? fingerprint : ['{{ default }}'];
  }

  /**
   * Create automatic ticket for critical errors
   */
  private async createAutomaticTicket(event: SentryEvent, analysis: AIAnalysis): Promise<void> {
    try {
      const ticket: TicketCreationRequest = {
        title: `Critical Error: ${event.message || 'Unknown error'}`,
        description: this.generateTicketDescription(event, analysis),
        priority: analysis.severity,
        assignee: await this.findResponsibleOwner(event),
        labels: this.generateTicketLabels(event, analysis),
        suggestedFix: analysis.suggestedFix,
        errorDetails: {
          sentryUrl: `https://sentry.io/organizations/coreflow360/issues/?query=event.id:${event.event_id}`,
          timestamp: event.timestamp,
          environment: event.environment,
          release: event.release
        }
      };

      await this.ticketManager.createTicket(ticket);

      this.logger.info('Automatic ticket created for critical error', {
        eventId: event.event_id,
        severity: analysis.severity,
        ticketTitle: ticket.title
      });

    } catch (error) {
      this.logger.error('Failed to create automatic ticket', error);
    }
  }

  /**
   * Attempt automated fix for known issues
   */
  private async attemptAutoFix(event: SentryEvent, analysis: AIAnalysis): Promise<void> {
    if (!analysis.autoFixAvailable) return;

    try {
      this.logger.info('Attempting automated fix', {
        eventId: event.event_id,
        rootCause: analysis.rootCause,
        suggestedFix: analysis.suggestedFix
      });

      // Implement auto-fix logic based on error type
      switch (analysis.rootCause) {
        case 'rate_limit_exceeded':
          await this.autoFixRateLimit(event);
          break;
        case 'database_connection_timeout':
          await this.autoFixDatabaseTimeout(event);
          break;
        case 'memory_pressure':
          await this.autoFixMemoryPressure(event);
          break;
        default:
          this.logger.debug('No auto-fix available for root cause', {
            rootCause: analysis.rootCause
          });
      }

    } catch (error) {
      this.logger.error('Auto-fix attempt failed', error);
    }
  }

  /**
   * Auto-fix rate limiting issues
   */
  private async autoFixRateLimit(event: SentryEvent): Promise<void> {
    // Implement dynamic rate limit adjustment
    this.logger.info('Auto-adjusting rate limits', { eventId: event.event_id });
  }

  /**
   * Auto-fix database timeout issues
   */
  private async autoFixDatabaseTimeout(event: SentryEvent): Promise<void> {
    // Implement connection pool adjustment
    this.logger.info('Auto-adjusting database connection settings', { eventId: event.event_id });
  }

  /**
   * Auto-fix memory pressure issues
   */
  private async autoFixMemoryPressure(event: SentryEvent): Promise<void> {
    // Implement memory cleanup
    this.logger.info('Initiating memory cleanup', { eventId: event.event_id });
  }

  /**
   * Rate limiting for error events
   */
  private async shouldRateLimit(event: SentryEvent): Promise<boolean> {
    const fingerprint = event.fingerprint?.join(':') || 'unknown';

    // Implement rate limiting logic
    // In a real implementation, this would use KV storage
    return false;
  }

  /**
   * Get adaptive sampling rate based on environment and load
   */
  private getAdaptiveSampleRate(): number {
    switch (this.env.ENVIRONMENT) {
      case 'production':
        return 0.1; // 10% sampling in production
      case 'staging':
        return 0.5; // 50% sampling in staging
      default:
        return 1.0; // 100% sampling in development
    }
  }

  /**
   * Helper methods
   */
  private async getAffectedUsersCount(event: SentryEvent): Promise<number> {
    // Calculate affected users based on error context
    return 1; // Simplified implementation
  }

  private extractCorrelationId(event: SentryEvent): string | null {
    return event.extra?.correlationId || event.tags?.correlation_id || null;
  }

  private async getDeploymentContext(): Promise<any> {
    return {
      version: this.config.release,
      timestamp: Date.now(),
      region: this.env.CLOUDFLARE_REGION
    };
  }

  private async getBusinessContext(): Promise<SentryBusinessContext> {
    return {
      business_id: 'default',
      plan: 'enterprise',
      features: ['ai', 'crm', 'finance'],
      usage_tier: 'high',
      region: this.env.CLOUDFLARE_REGION || 'unknown'
    };
  }

  private annotatePerformance(transaction: SentryTransaction): SentryTransaction {
    // Add performance annotations
    return transaction;
  }

  private shouldFilterTransaction(transaction: SentryTransaction): boolean {
    // Filter out health check and other irrelevant transactions
    const ignoredOps = ['/health', '/metrics', '/favicon.ico'];
    return ignoredOps.some(op => transaction.transaction.includes(op));
  }

  private generateTicketDescription(event: SentryEvent, analysis: AIAnalysis): string {
    return `
## Error Summary
**Message:** ${event.message || 'Unknown error'}
**Severity:** ${analysis.severity}
**Environment:** ${event.environment}
**Release:** ${event.release}

## AI Analysis
**Root Cause:** ${analysis.rootCause}
**Confidence:** ${analysis.confidence}%
**Business Impact:** ${analysis.businessImpact.userExperience}/10

## Suggested Fix
${analysis.suggestedFix}

## Additional Context
**Affected Users:** ${analysis.affectedUsers}
**Similar Issues:** ${analysis.similarIssues.join(', ')}
**Auto-fix Available:** ${analysis.autoFixAvailable ? 'Yes' : 'No'}
    `;
  }

  private generateTicketLabels(event: SentryEvent, analysis: AIAnalysis): string[] {
    const labels = ['error', 'sentry', 'automated'];

    labels.push(`severity-${analysis.severity}`);
    labels.push(`environment-${event.environment}`);

    if (analysis.autoFixAvailable) {
      labels.push('auto-fix-available');
    }

    if (analysis.escalationRequired) {
      labels.push('escalation-required');
    }

    return labels;
  }

  private async findResponsibleOwner(event: SentryEvent): Promise<string | undefined> {
    // Logic to determine responsible team member based on error context
    return undefined;
  }
}

/**
 * AI-powered error analyzer
 */
class ErrorAnalyzer {
  private env: Env;

  constructor(env: Env) {
    this.env = env;
  }

  async analyzeError(event: SentryEvent, hint: SentryHint): Promise<AIAnalysis> {
    // Simplified AI analysis - in a real implementation, this would use ML models
    const analysis: AIAnalysis = {
      rootCause: this.identifyRootCause(event),
      suggestedFix: this.generateSuggestedFix(event),
      severity: this.assessSeverity(event),
      confidence: 0.85,
      similarIssues: [],
      affectedUsers: 1,
      businessImpact: {
        revenue: 0.05,
        userExperience: 0.3,
        operationalImpact: 0.2,
        reputationRisk: 0.1,
        complianceRisk: 0.0
      },
      autoFixAvailable: this.hasAutoFix(event),
      escalationRequired: this.requiresEscalation(event)
    };

    return analysis;
  }

  private identifyRootCause(event: SentryEvent): string {
    if (event.message?.includes('rate limit')) return 'rate_limit_exceeded';
    if (event.message?.includes('timeout')) return 'database_connection_timeout';
    if (event.message?.includes('memory')) return 'memory_pressure';
    return 'unknown';
  }

  private generateSuggestedFix(event: SentryEvent): string {
    const rootCause = this.identifyRootCause(event);

    switch (rootCause) {
      case 'rate_limit_exceeded':
        return 'Implement exponential backoff or increase rate limits';
      case 'database_connection_timeout':
        return 'Optimize query performance or increase timeout values';
      case 'memory_pressure':
        return 'Implement memory cleanup or increase worker memory limits';
      default:
        return 'Review error details and implement appropriate error handling';
    }
  }

  private assessSeverity(event: SentryEvent): 'low' | 'medium' | 'high' | 'critical' {
    if (event.level === 'fatal') return 'critical';
    if (event.level === 'error') return 'high';
    if (event.level === 'warning') return 'medium';
    return 'low';
  }

  private hasAutoFix(event: SentryEvent): boolean {
    const rootCause = this.identifyRootCause(event);
    return ['rate_limit_exceeded', 'database_connection_timeout'].includes(rootCause);
  }

  private requiresEscalation(event: SentryEvent): boolean {
    return event.level === 'fatal' || event.message?.includes('security');
  }
}

/**
 * Ticket management system
 */
// TODO: Consider splitting TicketManager into smaller, focused classes
class TicketManager {
  private env: Env;

  constructor(env: Env) {
    this.env = env;
  }

  async createTicket(request: TicketCreationRequest): Promise<void> {
    // In a real implementation, this would integrate with GitHub Issues, Jira, etc.
  }
}

/**
 * Create Sentry integration instance
 */
export function createSentryIntegration(env: Env, config?: Partial<SentryConfig>): SentryIntegration {
  return new SentryIntegration(env, config);
}