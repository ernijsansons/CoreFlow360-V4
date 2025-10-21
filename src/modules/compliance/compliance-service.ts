/**
 * Compliance Service
 * Enforces company guidelines and agent policies across all AI agents
 * Target Quality Score: 95/100
 */

import type { D1Database } from '@cloudflare/workers-types';
import type { BusinessContext, AgentTask, AgentResult } from '../agents/types';
import { Logger } from '../../shared/logger';
import { CorrelationId } from '../../shared/security-utils';

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

export interface CompanyGuideline {
  id: string;
  businessId: string;
  name: string;
  description: string;
  category: GuidelineCategory;
  severity: 'low' | 'medium' | 'high' | 'critical';
  rules: GuidelineRules;
  enforcementMode: 'monitor' | 'warn' | 'enforce';
  autoRemediation: boolean;
  appliesToAgents: string[];
  appliesToDepartments: string[];
  status: 'active' | 'inactive' | 'archived';
  priority: number;
}

export type GuidelineCategory =
  | 'tone_and_style'
  | 'content_restrictions'
  | 'data_boundaries'
  | 'privacy_and_security'
  | 'brand_voice'
  | 'compliance_rules'
  | 'escalation_triggers'
  | 'response_limits';

export interface GuidelineRules {
  prohibitedTopics?: string[];
  prohibitedCompetitors?: string[];
  requiredTone?: 'formal' | 'casual' | 'professional' | 'friendly' | 'technical';
  maxResponseLength?: number;
  minResponseLength?: number;
  requireDisclaimer?: boolean;
  disclaimerText?: string;
  allowedLanguages?: string[];
  prohibitedPhrases?: string[];
  requiredPhrases?: string[];
  dataAccessRules?: {
    allowedTables?: string[];
    prohibitedTables?: string[];
    rowLevelFilters?: string[];
  };
  escalationTriggers?: {
    keywords?: string[];
    sentiments?: string[];
    customerTiers?: string[];
  };
}

export interface AgentPolicy {
  id: string;
  businessId: string;
  agentId: string;
  policyName: string;
  policyType: PolicyType;
  policyConfig: Record<string, any>;
  enabled: boolean;
  enforcementLevel: 'lenient' | 'moderate' | 'strict';
  status: 'active' | 'inactive' | 'testing';
}

export type PolicyType =
  | 'capability_restriction'
  | 'data_access_control'
  | 'rate_limiting'
  | 'response_filtering'
  | 'escalation_rules'
  | 'quality_requirements'
  | 'cost_limits';

export interface ComplianceCheckResult {
  compliant: boolean;
  violations: ComplianceViolation[];
  warnings: ComplianceWarning[];
  remediatedContent?: string;
  action: 'allow' | 'block' | 'modify' | 'escalate';
}

export interface ComplianceViolation {
  guidelineId?: string;
  policyId?: string;
  violationType: ViolationType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  details: Record<string, any>;
  suggestedFix?: string;
}

export type ViolationType =
  | 'prohibited_content'
  | 'tone_violation'
  | 'data_boundary_breach'
  | 'unauthorized_capability'
  | 'rate_limit_exceeded'
  | 'quality_below_threshold'
  | 'escalation_required'
  | 'pii_exposure'
  | 'cost_limit_exceeded';

export interface ComplianceWarning {
  type: string;
  message: string;
  severity: 'info' | 'warning';
}

// ============================================================================
// COMPLIANCE SERVICE
// ============================================================================

export class ComplianceService {
  private logger: Logger;
  private db: D1Database;

  // In-memory cache for guidelines and policies (refreshed periodically)
  private guidelinesCache = new Map<string, CompanyGuideline[]>();
  private policiesCache = new Map<string, AgentPolicy[]>();
  private cacheExpiry = new Map<string, number>();
  private readonly CACHE_TTL = 300000; // 5 minutes

  constructor(db: D1Database) {
    this.logger = new Logger();
    this.db = db;
  }

  // ============================================================================
  // PRE-EXECUTION VALIDATION
  // ============================================================================

  /**
   * Validate task before agent execution
   * Checks if agent is allowed to perform the capability
   */
  async validateTaskExecution(
    task: AgentTask,
    agentId: string,
    context: BusinessContext
  ): Promise<ComplianceCheckResult> {
    const correlationId = context.correlationId;
    const businessId = context.businessId;

    try {
      // Load guidelines and policies
      const guidelines = await this.getBusinessGuidelines(businessId);
      const agentPolicies = await this.getAgentPolicies(businessId, agentId);

      const violations: ComplianceViolation[] = [];
      const warnings: ComplianceWarning[] = [];

      // Check capability restrictions
      const capabilityViolations = this.checkCapabilityRestrictions(
        task,
        agentId,
        agentPolicies
      );
      violations.push(...capabilityViolations);

      // Check data access boundaries
      if (task.input.data) {
        const dataViolations = this.checkDataAccessBoundaries(
          task,
          guidelines,
          agentPolicies
        );
        violations.push(...dataViolations);
      }

      // Check rate limits
      const rateLimitViolation = await this.checkRateLimits(
        businessId,
        agentId,
        agentPolicies
      );
      if (rateLimitViolation) {
        violations.push(rateLimitViolation);
      }

      // Check cost limits
      const costViolation = await this.checkCostLimits(businessId, agentId, agentPolicies);
      if (costViolation) {
        violations.push(costViolation);
      }

      // Determine action based on violations
      const action = this.determineAction(violations, guidelines, agentPolicies);

      this.logger.info('Pre-execution validation completed', {
        correlationId,
        agentId,
        taskId: task.id,
        violationCount: violations.length,
        action
      });

      return {
        compliant: violations.length === 0,
        violations,
        warnings,
        action
      };
    } catch (error) {
      this.logger.error('Pre-execution validation failed', error, { correlationId });
      throw error;
    }
  }

  // ============================================================================
  // POST-EXECUTION VALIDATION
  // ============================================================================

  /**
   * Validate agent response before sending to user
   * Checks content, tone, and compliance with guidelines
   */
  async validateAgentResponse(
    response: AgentResult,
    task: AgentTask,
    agentId: string,
    context: BusinessContext
  ): Promise<ComplianceCheckResult> {
    const correlationId = context.correlationId;
    const businessId = context.businessId;

    try {
      const guidelines = await this.getBusinessGuidelines(businessId);
      const agentPolicies = await this.getAgentPolicies(businessId, agentId);

      const violations: ComplianceViolation[] = [];
      const warnings: ComplianceWarning[] = [];

      // Get response text
      const responseText = this.extractResponseText(response);

      if (!responseText) {
        return {
          compliant: true,
          violations: [],
          warnings: [],
          action: 'allow'
        };
      }

      // Check prohibited content
      const contentViolations = this.checkProhibitedContent(responseText, guidelines);
      violations.push(...contentViolations);

      // Check tone and style
      const toneViolations = this.checkToneCompliance(responseText, guidelines);
      violations.push(...toneViolations);

      // Check response length
      const lengthViolations = this.checkResponseLength(responseText, guidelines);
      violations.push(...lengthViolations);

      // Check for PII exposure
      const piiViolations = this.checkPIIExposure(responseText, guidelines);
      violations.push(...piiViolations);

      // Check escalation triggers
      const escalationNeeded = this.checkEscalationTriggers(
        responseText,
        task,
        guidelines
      );
      if (escalationNeeded) {
        violations.push({
          violationType: 'escalation_required',
          severity: 'high',
          message: 'Response requires human review',
          details: { reason: 'Escalation trigger detected' }
        });
      }

      // Check quality requirements
      const qualityViolations = this.checkQualityRequirements(
        response,
        agentPolicies
      );
      violations.push(...qualityViolations);

      // Attempt auto-remediation if enabled
      let remediatedContent: string | undefined;
      if (violations.length > 0) {
        remediatedContent = await this.attemptAutoRemediation(
          responseText,
          violations,
          guidelines
        );
      }

      // Determine action
      const action = this.determineAction(violations, guidelines, agentPolicies);

      // Log violations to database
      if (violations.length > 0) {
        await this.logViolations(
          businessId,
          agentId,
          task.id,
          violations,
          responseText,
          remediatedContent,
          action,
          context
        );
      }

      this.logger.info('Post-execution validation completed', {
        correlationId,
        agentId,
        taskId: task.id,
        violationCount: violations.length,
        remediationAttempted: !!remediatedContent,
        action
      });

      return {
        compliant: violations.length === 0 || !!remediatedContent,
        violations,
        warnings,
        remediatedContent,
        action: remediatedContent && action === 'block' ? 'modify' : action
      };
    } catch (error) {
      this.logger.error('Post-execution validation failed', error, { correlationId });
      throw error;
    }
  }

  // ============================================================================
  // VALIDATION CHECKS
  // ============================================================================

  private checkCapabilityRestrictions(
    task: AgentTask,
    agentId: string,
    policies: AgentPolicy[]
  ): ComplianceViolation[] {
    const violations: ComplianceViolation[] = [];

    for (const policy of policies) {
      if (policy.policyType === 'capability_restriction' && policy.enabled) {
        const restrictedCapabilities = policy.policyConfig.restrictedCapabilities || [];

        if (restrictedCapabilities.includes(task.capability)) {
          violations.push({
            policyId: policy.id,
            violationType: 'unauthorized_capability',
            severity: 'high',
            message: `Agent ${agentId} is not authorized to use capability: ${task.capability}`,
            details: {
              capability: task.capability,
              policyName: policy.policyName
            }
          });
        }
      }
    }

    return violations;
  }

  private checkDataAccessBoundaries(
    task: AgentTask,
    guidelines: CompanyGuideline[],
    policies: AgentPolicy[]
  ): ComplianceViolation[] {
    const violations: ComplianceViolation[] = [];

    // Check guidelines
    for (const guideline of guidelines) {
      if (guideline.category === 'data_boundaries' && guideline.status === 'active') {
        const rules = guideline.rules.dataAccessRules;
        if (!rules) continue;

        // Check if data access is within allowed boundaries
        // This is simplified - in production, you'd analyze the actual SQL queries
        const taskData = JSON.stringify(task.input.data || {});

        if (rules.prohibitedTables) {
          for (const table of rules.prohibitedTables) {
            if (taskData.toLowerCase().includes(table.toLowerCase())) {
              violations.push({
                guidelineId: guideline.id,
                violationType: 'data_boundary_breach',
                severity: guideline.severity,
                message: `Attempted to access prohibited table: ${table}`,
                details: {
                  prohibitedTable: table,
                  guidelineName: guideline.name
                }
              });
            }
          }
        }
      }
    }

    // Check policies
    for (const policy of policies) {
      if (policy.policyType === 'data_access_control' && policy.enabled) {
        const allowedScopes = policy.policyConfig.allowedDataScopes || [];
        const requestedScope = task.input.parameters?.dataScope || 'all';

        if (allowedScopes.length > 0 && !allowedScopes.includes(requestedScope)) {
          violations.push({
            policyId: policy.id,
            violationType: 'data_boundary_breach',
            severity: 'high',
            message: `Data scope '${requestedScope}' not allowed by policy`,
            details: {
              requestedScope,
              allowedScopes,
              policyName: policy.policyName
            }
          });
        }
      }
    }

    return violations;
  }

  private async checkRateLimits(
    businessId: string,
    agentId: string,
    policies: AgentPolicy[]
  ): Promise<ComplianceViolation | null> {
    for (const policy of policies) {
      if (policy.policyType === 'rate_limiting' && policy.enabled) {
        const rateLimit = policy.policyConfig.requestsPerMinute || 60;

        // Query recent requests from agent
        const recentRequests = await this.db
          .prepare(`
            SELECT COUNT(*) as count
            FROM compliance_violations
            WHERE business_id = ?
              AND agent_id = ?
              AND occurred_at > datetime('now', '-1 minute')
          `)
          .bind(businessId, agentId)
          .first();

        const count = (recentRequests?.count as number) || 0;

        if (count >= rateLimit) {
          return {
            policyId: policy.id,
            violationType: 'rate_limit_exceeded',
            severity: 'medium',
            message: `Rate limit exceeded: ${count}/${rateLimit} requests per minute`,
            details: {
              currentRate: count,
              limit: rateLimit,
              policyName: policy.policyName
            }
          };
        }
      }
    }

    return null;
  }

  private async checkCostLimits(
    businessId: string,
    agentId: string,
    policies: AgentPolicy[]
  ): Promise<ComplianceViolation | null> {
    for (const policy of policies) {
      if (policy.policyType === 'cost_limits' && policy.enabled) {
        const dailyLimit = policy.policyConfig.dailyLimitUSD || 100;

        // This would query actual cost tracking - simplified for now
        const estimatedCost = 0.05; // Placeholder

        if (estimatedCost > dailyLimit) {
          return {
            policyId: policy.id,
            violationType: 'cost_limit_exceeded',
            severity: 'high',
            message: `Daily cost limit exceeded: $${estimatedCost}/$${dailyLimit}`,
            details: {
              currentCost: estimatedCost,
              limit: dailyLimit
            }
          };
        }
      }
    }

    return null;
  }

  private checkProhibitedContent(
    text: string,
    guidelines: CompanyGuideline[]
  ): ComplianceViolation[] {
    const violations: ComplianceViolation[] = [];
    const lowerText = text.toLowerCase();

    for (const guideline of guidelines) {
      if (guideline.category === 'content_restrictions' && guideline.status === 'active') {
        // Check prohibited topics
        const prohibitedTopics = guideline.rules.prohibitedTopics || [];
        for (const topic of prohibitedTopics) {
          if (lowerText.includes(topic.toLowerCase())) {
            violations.push({
              guidelineId: guideline.id,
              violationType: 'prohibited_content',
              severity: guideline.severity,
              message: `Response contains prohibited topic: ${topic}`,
              details: {
                prohibitedTopic: topic,
                guidelineName: guideline.name
              },
              suggestedFix: 'Remove or rephrase content related to this topic'
            });
          }
        }

        // Check prohibited phrases
        const prohibitedPhrases = guideline.rules.prohibitedPhrases || [];
        for (const phrase of prohibitedPhrases) {
          if (lowerText.includes(phrase.toLowerCase())) {
            violations.push({
              guidelineId: guideline.id,
              violationType: 'prohibited_content',
              severity: guideline.severity,
              message: `Response contains prohibited phrase: "${phrase}"`,
              details: {
                prohibitedPhrase: phrase,
                guidelineName: guideline.name
              },
              suggestedFix: `Remove or replace the phrase: "${phrase}"`
            });
          }
        }

        // Check competitors
        const prohibitedCompetitors = guideline.rules.prohibitedCompetitors || [];
        for (const competitor of prohibitedCompetitors) {
          if (lowerText.includes(competitor.toLowerCase())) {
            violations.push({
              guidelineId: guideline.id,
              violationType: 'prohibited_content',
              severity: 'high',
              message: `Response mentions competitor: ${competitor}`,
              details: {
                competitor,
                guidelineName: guideline.name
              },
              suggestedFix: 'Remove competitor references and focus on our products'
            });
          }
        }
      }
    }

    return violations;
  }

  private checkToneCompliance(
    text: string,
    guidelines: CompanyGuideline[]
  ): ComplianceViolation[] {
    const violations: ComplianceViolation[] = [];

    for (const guideline of guidelines) {
      if (guideline.category === 'tone_and_style' && guideline.status === 'active') {
        const requiredTone = guideline.rules.requiredTone;
        if (!requiredTone) continue;

        // Detect actual tone (simplified - use NLP in production)
        const detectedTone = this.detectTone(text);

        if (detectedTone !== requiredTone) {
          violations.push({
            guidelineId: guideline.id,
            violationType: 'tone_violation',
            severity: guideline.severity,
            message: `Response tone is ${detectedTone}, but ${requiredTone} is required`,
            details: {
              requiredTone,
              detectedTone,
              guidelineName: guideline.name
            },
            suggestedFix: `Adjust language to match ${requiredTone} tone`
          });
        }
      }
    }

    return violations;
  }

  private checkResponseLength(
    text: string,
    guidelines: CompanyGuideline[]
  ): ComplianceViolation[] {
    const violations: ComplianceViolation[] = [];
    const wordCount = text.split(/\s+/).length;

    for (const guideline of guidelines) {
      if (guideline.category === 'response_limits' && guideline.status === 'active') {
        const maxLength = guideline.rules.maxResponseLength;
        const minLength = guideline.rules.minResponseLength;

        if (maxLength && wordCount > maxLength) {
          violations.push({
            guidelineId: guideline.id,
            violationType: 'prohibited_content',
            severity: guideline.severity,
            message: `Response exceeds maximum length: ${wordCount}/${maxLength} words`,
            details: {
              wordCount,
              maxLength,
              guidelineName: guideline.name
            },
            suggestedFix: 'Shorten response to be more concise'
          });
        }

        if (minLength && wordCount < minLength) {
          violations.push({
            guidelineId: guideline.id,
            violationType: 'quality_below_threshold',
            severity: 'low',
            message: `Response below minimum length: ${wordCount}/${minLength} words`,
            details: {
              wordCount,
              minLength,
              guidelineName: guideline.name
            },
            suggestedFix: 'Expand response with more detail'
          });
        }
      }
    }

    return violations;
  }

  private checkPIIExposure(
    text: string,
    guidelines: CompanyGuideline[]
  ): ComplianceViolation[] {
    const violations: ComplianceViolation[] = [];

    // Detect PII patterns (simplified - use proper PII detection in production)
    const piiPatterns = {
      email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
      ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
      creditCard: /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g,
      phone: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g
    };

    for (const [type, pattern] of Object.entries(piiPatterns)) {
      const matches = text.match(pattern);
      if (matches) {
        violations.push({
          violationType: 'pii_exposure',
          severity: 'critical',
          message: `Response may contain ${type} PII`,
          details: {
            piiType: type,
            matchCount: matches.length
          },
          suggestedFix: `Redact or remove ${type} from response`
        });
      }
    }

    return violations;
  }

  private checkEscalationTriggers(
    text: string,
    task: AgentTask,
    guidelines: CompanyGuideline[]
  ): boolean {
    const lowerText = text.toLowerCase();

    for (const guideline of guidelines) {
      if (guideline.category === 'escalation_triggers' && guideline.status === 'active') {
        const triggers = guideline.rules.escalationTriggers;
        if (!triggers) continue;

        // Check keyword triggers
        if (triggers.keywords) {
          for (const keyword of triggers.keywords) {
            if (lowerText.includes(keyword.toLowerCase())) {
              return true;
            }
          }
        }

        // Check sentiment triggers (simplified)
        if (triggers.sentiments) {
          const detectedSentiment = this.detectSentiment(text);
          if (triggers.sentiments.includes(detectedSentiment)) {
            return true;
          }
        }
      }
    }

    return false;
  }

  private checkQualityRequirements(
    response: AgentResult,
    policies: AgentPolicy[]
  ): ComplianceViolation[] {
    const violations: ComplianceViolation[] = [];

    for (const policy of policies) {
      if (policy.policyType === 'quality_requirements' && policy.enabled) {
        const minConfidence = policy.policyConfig.minimumConfidence || 0.8;

        if (response.result?.confidence && response.result.confidence < minConfidence) {
          violations.push({
            policyId: policy.id,
            violationType: 'quality_below_threshold',
            severity: 'medium',
            message: `Response confidence below threshold: ${response.result.confidence}/${minConfidence}`,
            details: {
              confidence: response.result.confidence,
              threshold: minConfidence,
              policyName: policy.policyName
            },
            suggestedFix: 'Consider regenerating response or escalating to human'
          });
        }
      }
    }

    return violations;
  }

  // ============================================================================
  // AUTO-REMEDIATION
  // ============================================================================

  private async attemptAutoRemediation(
    originalText: string,
    violations: ComplianceViolation[],
    guidelines: CompanyGuideline[]
  ): Promise<string | undefined> {
    // Check if any guideline has auto-remediation enabled
    const autoRemediationEnabled = guidelines.some(
      g => g.autoRemediation && g.status === 'active'
    );

    if (!autoRemediationEnabled) {
      return undefined;
    }

    let remediatedText = originalText;

    // Attempt to fix violations
    for (const violation of violations) {
      if (violation.violationType === 'prohibited_content') {
        // Remove prohibited content
        const phrase = violation.details.prohibitedPhrase || violation.details.prohibitedTopic;
        if (phrase) {
          const regex = new RegExp(phrase, 'gi');
          remediatedText = remediatedText.replace(regex, '[CONTENT REMOVED]');
        }
      }

      if (violation.violationType === 'pii_exposure') {
        // Redact PII
        const piiType = violation.details.piiType;
        if (piiType === 'email') {
          remediatedText = remediatedText.replace(
            /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
            '[EMAIL REDACTED]'
          );
        } else if (piiType === 'phone') {
          remediatedText = remediatedText.replace(
            /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,
            '[PHONE REDACTED]'
          );
        }
      }
    }

    // Only return if we actually modified something
    return remediatedText !== originalText ? remediatedText : undefined;
  }

  // ============================================================================
  // HELPER METHODS
  // ============================================================================

  private determineAction(
    violations: ComplianceViolation[],
    guidelines: CompanyGuideline[],
    policies: AgentPolicy[]
  ): 'allow' | 'block' | 'modify' | 'escalate' {
    if (violations.length === 0) {
      return 'allow';
    }

    // Check for critical violations
    const hasCriticalViolation = violations.some(v => v.severity === 'critical');
    if (hasCriticalViolation) {
      return 'block';
    }

    // Check escalation requirements
    const needsEscalation = violations.some(v => v.violationType === 'escalation_required');
    if (needsEscalation) {
      return 'escalate';
    }

    // Check enforcement mode
    const enforceMode = guidelines.find(g => g.enforcementMode === 'enforce');
    if (enforceMode) {
      return 'block';
    }

    // Default to block for high severity
    const hasHighViolation = violations.some(v => v.severity === 'high');
    return hasHighViolation ? 'block' : 'allow';
  }

  private extractResponseText(response: AgentResult): string | null {
    if (!response.result) return null;

    // Handle different response formats
    if (typeof response.result.data === 'string') {
      return response.result.data;
    }

    if (response.result.data && typeof response.result.data === 'object') {
      const data = response.result.data as any;
      return data.message || data.response || data.text || JSON.stringify(data);
    }

    return null;
  }

  private detectTone(text: string): 'formal' | 'casual' | 'professional' | 'friendly' | 'technical' {
    // Simplified tone detection (use NLP in production)
    const lowerText = text.toLowerCase();

    if (lowerText.includes('please') && lowerText.includes('kindly')) {
      return 'formal';
    }
    if (lowerText.includes('hey') || lowerText.includes('cool')) {
      return 'casual';
    }
    if (lowerText.includes('api') || lowerText.includes('implementation')) {
      return 'technical';
    }
    if (lowerText.includes('happy') || lowerText.includes('glad')) {
      return 'friendly';
    }

    return 'professional';
  }

  private detectSentiment(text: string): string {
    // Simplified sentiment detection (use NLP in production)
    const lowerText = text.toLowerCase();

    const negativeWords = ['angry', 'frustrated', 'upset', 'complaint', 'terrible', 'horrible'];
    const positiveWords = ['great', 'excellent', 'happy', 'satisfied', 'wonderful'];

    const negativeCount = negativeWords.filter(w => lowerText.includes(w)).length;
    const positiveCount = positiveWords.filter(w => lowerText.includes(w)).length;

    if (negativeCount > positiveCount) return 'negative';
    if (positiveCount > negativeCount) return 'positive';
    return 'neutral';
  }

  private async logViolations(
    businessId: string,
    agentId: string,
    taskId: string,
    violations: ComplianceViolation[],
    originalResponse: string,
    remediatedResponse: string | undefined,
    action: string,
    context: BusinessContext
  ): Promise<void> {
    try {
      for (const violation of violations) {
        await this.db
          .prepare(`
            INSERT INTO compliance_violations (
              id, business_id, agent_id, guideline_id, policy_id,
              violation_type, task_id, capability, user_id, department,
              original_response, violation_details, severity,
              action_taken, remediated_response, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
          `)
          .bind(
            CorrelationId.generate(),
            businessId,
            agentId,
            violation.guidelineId || null,
            violation.policyId || null,
            violation.violationType,
            taskId,
            context.userContext!.department || null,
            context.userId,
            context.userContext!.department || null,
            originalResponse.slice(0, 5000), // Limit length
            JSON.stringify(violation.details),
            violation.severity,
            action,
            remediatedResponse || null
          )
          .run();
      }
    } catch (error) {
      this.logger.error('Failed to log violations', error);
    }
  }

  // ============================================================================
  // DATA ACCESS
  // ============================================================================

  private async getBusinessGuidelines(businessId: string): Promise<CompanyGuideline[]> {
    // Check cache first
    const cacheKey = `guidelines:${businessId}`;
    const cached = this.guidelinesCache.get(cacheKey);
    const expiry = this.cacheExpiry.get(cacheKey);

    if (cached && expiry && expiry > Date.now()) {
      return cached;
    }

    // Fetch from database
    const result = await this.db
      .prepare(`
        SELECT *
        FROM company_guidelines
        WHERE business_id = ?
          AND status = 'active'
          AND (effective_until IS NULL OR effective_until > datetime('now'))
        ORDER BY priority DESC
      `)
      .bind(businessId)
      .all();

    const guidelines = (result.results || []).map(row => this.parseGuideline(row as any));

    // Update cache
    this.guidelinesCache.set(cacheKey, guidelines);
    this.cacheExpiry.set(cacheKey, Date.now() + this.CACHE_TTL);

    return guidelines;
  }

  private async getAgentPolicies(
    businessId: string,
    agentId: string
  ): Promise<AgentPolicy[]> {
    // Check cache first
    const cacheKey = `policies:${businessId}:${agentId}`;
    const cached = this.policiesCache.get(cacheKey);
    const expiry = this.cacheExpiry.get(cacheKey);

    if (cached && expiry && expiry > Date.now()) {
      return cached;
    }

    // Fetch from database
    const result = await this.db
      .prepare(`
        SELECT *
        FROM agent_policies
        WHERE business_id = ?
          AND agent_id = ?
          AND status = 'active'
          AND enabled = 1
      `)
      .bind(businessId, agentId)
      .all();

    const policies = (result.results || []).map(row => this.parsePolicy(row as any));

    // Update cache
    this.policiesCache.set(cacheKey, policies);
    this.cacheExpiry.set(cacheKey, Date.now() + this.CACHE_TTL);

    return policies;
  }

  private parseGuideline(row: any): CompanyGuideline {
    return {
      id: row.id,
      businessId: row.business_id,
      name: row.name,
      description: row.description,
      category: row.category,
      severity: row.severity,
      rules: JSON.parse(row.rules || '{}'),
      enforcementMode: row.enforcement_mode,
      autoRemediation: Boolean(row.auto_remediation),
      appliesToAgents: JSON.parse(row.applies_to_agents || '[]'),
      appliesToDepartments: JSON.parse(row.applies_to_departments || '[]'),
      status: row.status,
      priority: row.priority
    };
  }

  private parsePolicy(row: any): AgentPolicy {
    return {
      id: row.id,
      businessId: row.business_id,
      agentId: row.agent_id,
      policyName: row.policy_name,
      policyType: row.policy_type,
      policyConfig: JSON.parse(row.policy_config || '{}'),
      enabled: Boolean(row.enabled),
      enforcementLevel: row.enforcement_level,
      status: row.status
    };
  }

  /**
   * Clear cached guidelines and policies
   */
  public clearCache(): void {
    this.guidelinesCache.clear();
    this.policiesCache.clear();
    this.cacheExpiry.clear();
  }
}
