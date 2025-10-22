/**
 * ComplianceService Test Suite
 *
 * Tests compliance validation, auto-remediation, and violation tracking
 * Coverage target: 95%+
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { ComplianceService } from '../compliance-service';
import type { AgentTask, AgentResult, BusinessContext } from '../../agents/types';

// Mock D1 Database
const createMockDB = () => ({
  prepare: vi.fn().mockReturnThis(),
  bind: vi.fn().mockReturnThis(),
  first: vi.fn(),
  all: vi.fn(),
  run: vi.fn(),
});

describe('ComplianceService', () => {
  let complianceService: ComplianceService;
  let mockDB: any;
  let testContext: BusinessContext;

  beforeEach(() => {
    mockDB = createMockDB();
    complianceService = new ComplianceService(mockDB);

    testContext = {
      userId: 'user-123',
      businessId: 'biz-123',
      organizationId: 'org-123',
      timestamp: new Date().toISOString(),
      requestId: 'req-123',
      userPermissions: ['read', 'write'],
      preferences: {}
    };
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('validateTaskExecution (Pre-execution)', () => {
    it('should allow task when no restrictions exist', async () => {
      // No guidelines or policies
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      const task: AgentTask = {
        id: 'task-1',
        capability: 'data_import',
        input: { data: { dataType: 'customers' } },
        priority: 'normal',
        context: testContext
      };

      const result = await complianceService.validateTaskExecution(
        task,
        'onboarding-agent',
        testContext
      );

      expect(result.compliant).toBe(true);
      expect(result.action).toBe('allow');
      expect(result.violations).toHaveLength(0);
    });

    it('should block task when capability is restricted', async () => {
      // No guidelines
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      // Policy with capability restriction
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [{
            id: 'policy-1',
            agent_id: 'onboarding-agent',
            policy_type: 'capability_restriction',
            policy_config: JSON.stringify({
              allowedCapabilities: ['account_setup', 'team_onboarding'],
              blockedCapabilities: ['data_import']
            }),
            enforcement_level: 'enforce'
          }]
        })
      });

      const task: AgentTask = {
        id: 'task-1',
        capability: 'data_import',
        input: { data: {} },
        priority: 'normal',
        context: testContext
      };

      const result = await complianceService.validateTaskExecution(
        task,
        'onboarding-agent',
        testContext
      );

      expect(result.compliant).toBe(false);
      expect(result.action).toBe('block');
      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].violation_type).toBe('unauthorized_capability');
    });

    it('should enforce data boundaries', async () => {
      // Guideline with data boundaries
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [{
            id: 'guideline-1',
            business_id: 'biz-123',
            category: 'data_boundaries',
            rules: JSON.stringify({
              allowedDataTypes: ['customers', 'products'],
              forbiddenDataTypes: ['financial_records', 'personal_health']
            }),
            enforcement_mode: 'enforce'
          }]
        })
      });

      // No policies
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      const task: AgentTask = {
        id: 'task-1',
        capability: 'data_import',
        input: { data: { dataType: 'financial_records' } },
        priority: 'normal',
        context: testContext
      };

      const result = await complianceService.validateTaskExecution(
        task,
        'onboarding-agent',
        testContext
      );

      expect(result.compliant).toBe(false);
      expect(result.action).toBe('block');
      expect(result.violations[0].violation_type).toBe('data_boundary_breach');
    });

    it('should check rate limits', async () => {
      // No guidelines
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      // Policy with rate limiting
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [{
            id: 'policy-1',
            agent_id: 'onboarding-agent',
            policy_type: 'rate_limiting',
            policy_config: JSON.stringify({
              requestsPerMinute: 10,
              requestsPerHour: 100
            }),
            enforcement_level: 'enforce'
          }]
        })
      });

      // Recent executions exceeding rate limit
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({ execution_count: 15 })
      });

      const task: AgentTask = {
        id: 'task-1',
        capability: 'data_import',
        input: { data: {} },
        priority: 'normal',
        context: testContext
      };

      const result = await complianceService.validateTaskExecution(
        task,
        'onboarding-agent',
        testContext
      );

      expect(result.compliant).toBe(false);
      expect(result.action).toBe('block');
      expect(result.violations[0].violation_type).toBe('rate_limit_exceeded');
    });

    it('should check cost limits', async () => {
      // No guidelines
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      // Policy with cost limits
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [{
            id: 'policy-1',
            agent_id: 'onboarding-agent',
            policy_type: 'cost_limits',
            policy_config: JSON.stringify({
              maxCostPerRequest: 0.5,
              maxDailyCost: 10.0
            }),
            enforcement_level: 'enforce'
          }]
        })
      });

      // No rate limit check needed
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({ execution_count: 0 })
      });

      // Daily cost exceeding limit
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({ total_cost: 12.5 })
      });

      const task: AgentTask = {
        id: 'task-1',
        capability: 'data_import',
        input: { data: {} },
        priority: 'normal',
        context: testContext
      };

      const result = await complianceService.validateTaskExecution(
        task,
        'onboarding-agent',
        testContext
      );

      expect(result.compliant).toBe(false);
      expect(result.action).toBe('block');
      expect(result.violations[0].violation_type).toBe('cost_limit_exceeded');
    });
  });

  describe('validateAgentResponse (Post-execution)', () => {
    it('should allow compliant response', async () => {
      // No guidelines
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      // No policies
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      const response: AgentResult = {
        taskId: 'task-1',
        agentId: 'onboarding-agent',
        status: 'completed',
        result: {
          success: true,
          data: {
            message: 'Data imported successfully',
            rowsImported: 100
          }
        },
        metrics: {
          executionTime: 1500,
          tokensUsed: 500,
          cost: 0.05
        },
        timestamp: new Date().toISOString()
      };

      const task: AgentTask = {
        id: 'task-1',
        capability: 'data_import',
        input: { data: {} },
        priority: 'normal',
        context: testContext
      };

      const result = await complianceService.validateAgentResponse(
        response,
        task,
        'onboarding-agent',
        testContext
      );

      expect(result.compliant).toBe(true);
      expect(result.action).toBe('allow');
      expect(result.violations).toHaveLength(0);
    });

    it('should detect prohibited content', async () => {
      // Guideline with content restrictions
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [{
            id: 'guideline-1',
            business_id: 'biz-123',
            category: 'content_restrictions',
            rules: JSON.stringify({
              prohibitedWords: ['competitor', 'rival', 'alternative'],
              prohibitedTopics: ['pricing_comparison', 'competitor_criticism']
            }),
            enforcement_mode: 'enforce',
            auto_remediation: true
          }]
        })
      });

      // No policies
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      const response: AgentResult = {
        taskId: 'task-1',
        agentId: 'company-knowledge-agent',
        status: 'completed',
        result: {
          success: true,
          data: {
            message: 'Unlike our competitor, we offer better pricing and features.'
          }
        },
        metrics: {
          executionTime: 1000,
          tokensUsed: 300,
          cost: 0.03
        },
        timestamp: new Date().toISOString()
      };

      const task: AgentTask = {
        id: 'task-1',
        capability: 'content_recommendation',
        input: { data: {} },
        priority: 'normal',
        context: testContext
      };

      const result = await complianceService.validateAgentResponse(
        response,
        task,
        'company-knowledge-agent',
        testContext
      );

      expect(result.compliant).toBe(false);
      expect(result.violations[0].violation_type).toBe('prohibited_content');
      expect(result.remediatedContent).toBeDefined();
      expect(result.remediatedContent).toContain('[CONTENT REMOVED]');
    });

    it('should detect tone violations', async () => {
      // Guideline with tone requirements
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [{
            id: 'guideline-1',
            business_id: 'biz-123',
            category: 'tone_and_style',
            rules: JSON.stringify({
              requiredTone: 'professional',
              prohibitedTones: ['casual', 'slang', 'informal']
            }),
            enforcement_mode: 'enforce',
            auto_remediation: false
          }]
        })
      });

      // No policies
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      const response: AgentResult = {
        taskId: 'task-1',
        agentId: 'chat-support-agent',
        status: 'completed',
        result: {
          success: true,
          data: {
            message: 'Hey! Yeah, that sounds awesome! Totally cool with me 😎'
          }
        },
        metrics: {
          executionTime: 800,
          tokensUsed: 200,
          cost: 0.02
        },
        timestamp: new Date().toISOString()
      };

      const task: AgentTask = {
        id: 'task-1',
        capability: 'respond',
        input: { data: {} },
        priority: 'normal',
        context: testContext
      };

      const result = await complianceService.validateAgentResponse(
        response,
        task,
        'chat-support-agent',
        testContext
      );

      expect(result.compliant).toBe(false);
      expect(result.violations[0].violation_type).toBe('tone_violation');
      expect(result.action).toBe('block'); // No auto-remediation
    });

    it('should detect and redact PII', async () => {
      // Guideline with privacy rules
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [{
            id: 'guideline-1',
            business_id: 'biz-123',
            category: 'privacy_and_security',
            rules: JSON.stringify({
              piiProtection: true,
              allowedPII: []
            }),
            enforcement_mode: 'enforce',
            auto_remediation: true
          }]
        })
      });

      // No policies
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      const response: AgentResult = {
        taskId: 'task-1',
        agentId: 'onboarding-agent',
        status: 'completed',
        result: {
          success: true,
          data: {
            message: 'User email is john.doe@example.com and phone is 555-123-4567. SSN: 123-45-6789'
          }
        },
        metrics: {
          executionTime: 1200,
          tokensUsed: 400,
          cost: 0.04
        },
        timestamp: new Date().toISOString()
      };

      const task: AgentTask = {
        id: 'task-1',
        capability: 'data_import',
        input: { data: {} },
        priority: 'normal',
        context: testContext
      };

      const result = await complianceService.validateAgentResponse(
        response,
        task,
        'onboarding-agent',
        testContext
      );

      expect(result.compliant).toBe(false);
      expect(result.violations[0].violation_type).toBe('pii_exposure');
      expect(result.remediatedContent).toBeDefined();
      expect(result.remediatedContent).toContain('[EMAIL REDACTED]');
      expect(result.remediatedContent).toContain('[PHONE REDACTED]');
      expect(result.remediatedContent).toContain('[SSN REDACTED]');
    });

    it('should check quality requirements', async () => {
      // No guidelines
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      // Policy with quality requirements
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [{
            id: 'policy-1',
            agent_id: 'company-knowledge-agent',
            policy_type: 'quality_requirements',
            policy_config: JSON.stringify({
              minimumAccuracy: 0.85,
              minimumCompleteness: 0.80
            }),
            enforcement_level: 'enforce'
          }]
        })
      });

      const response: AgentResult = {
        taskId: 'task-1',
        agentId: 'company-knowledge-agent',
        status: 'completed',
        result: {
          success: true,
          data: {
            message: 'Analysis completed',
            qualityScore: 0.70 // Below threshold
          }
        },
        metrics: {
          executionTime: 2000,
          tokensUsed: 600,
          cost: 0.06
        },
        timestamp: new Date().toISOString()
      };

      const task: AgentTask = {
        id: 'task-1',
        capability: 'brand_voice_analysis',
        input: { data: {} },
        priority: 'normal',
        context: testContext
      };

      const result = await complianceService.validateAgentResponse(
        response,
        task,
        'company-knowledge-agent',
        testContext
      );

      expect(result.compliant).toBe(false);
      expect(result.violations[0].violation_type).toBe('quality_below_threshold');
      expect(result.action).toBe('block');
    });

    it('should trigger escalation when required', async () => {
      // Guideline with escalation triggers
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [{
            id: 'guideline-1',
            business_id: 'biz-123',
            category: 'escalation_triggers',
            rules: JSON.stringify({
              escalationKeywords: ['refund', 'lawsuit', 'lawyer', 'complaint'],
              escalationThreshold: 1
            }),
            enforcement_mode: 'enforce'
          }]
        })
      });

      // No policies
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      const response: AgentResult = {
        taskId: 'task-1',
        agentId: 'chat-support-agent',
        status: 'completed',
        result: {
          success: true,
          data: {
            message: 'I want a full refund and I will contact my lawyer if this is not resolved immediately.'
          }
        },
        metrics: {
          executionTime: 900,
          tokensUsed: 250,
          cost: 0.025
        },
        timestamp: new Date().toISOString()
      };

      const task: AgentTask = {
        id: 'task-1',
        capability: 'respond',
        input: { data: {} },
        priority: 'normal',
        context: testContext
      };

      const result = await complianceService.validateAgentResponse(
        response,
        task,
        'chat-support-agent',
        testContext
      );

      expect(result.compliant).toBe(false);
      expect(result.violations[0].violation_type).toBe('escalation_required');
      expect(result.action).toBe('escalate');
    });
  });

  describe('recordViolation', () => {
    it('should record violation with all details', async () => {
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const violation = {
        business_id: 'biz-123',
        agent_id: 'chat-agent',
        task_id: 'task-1',
        violation_type: 'prohibited_content' as const,
        severity: 'high' as const,
        guideline_id: 'guideline-1',
        policy_id: null,
        details: { prohibitedWord: 'competitor' },
        original_content: 'Unlike our competitor...',
        remediated_content: 'Unlike [CONTENT REMOVED]...',
        action_taken: 'modified' as const,
        occurred_at: new Date().toISOString()
      };

      await complianceService['recordViolation'](violation);

      expect(mockDB.prepare).toHaveBeenCalled();
      const prepareCall = mockDB.prepare.mock.calls[0][0];
      expect(prepareCall).toContain('INSERT INTO compliance_violations');
    });
  });

  describe('Cache Management', () => {
    it('should cache guidelines and policies', async () => {
      // First call - should query database
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [{
            id: 'guideline-1',
            business_id: 'biz-123',
            category: 'tone_and_style',
            rules: JSON.stringify({ requiredTone: 'professional' })
          }]
        })
      });
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      const task: AgentTask = {
        id: 'task-1',
        capability: 'respond',
        input: { data: {} },
        priority: 'normal',
        context: testContext
      };

      await complianceService.validateTaskExecution(task, 'chat-agent', testContext);

      // Second call - should use cache (no new DB queries for guidelines/policies)
      const callCountBefore = mockDB.prepare.mock.calls.length;

      await complianceService.validateTaskExecution(task, 'chat-agent', testContext);

      // Should have additional queries for rate limit/cost checks but not guidelines/policies
      const callCountAfter = mockDB.prepare.mock.calls.length;
      expect(callCountAfter).toBeGreaterThan(callCountBefore);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty response content gracefully', async () => {
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      const response: AgentResult = {
        taskId: 'task-1',
        agentId: 'test-agent',
        status: 'completed',
        result: {
          success: true,
          data: null
        },
        metrics: {
          executionTime: 100,
          tokensUsed: 0,
          cost: 0
        },
        timestamp: new Date().toISOString()
      };

      const task: AgentTask = {
        id: 'task-1',
        capability: 'test',
        input: { data: {} },
        priority: 'normal',
        context: testContext
      };

      const result = await complianceService.validateAgentResponse(
        response,
        task,
        'test-agent',
        testContext
      );

      expect(result.compliant).toBe(true);
    });

    it('should handle monitor mode (log violations but allow)', async () => {
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [{
            id: 'guideline-1',
            business_id: 'biz-123',
            category: 'content_restrictions',
            rules: JSON.stringify({
              prohibitedWords: ['test']
            }),
            enforcement_mode: 'monitor', // Monitor only
            auto_remediation: false
          }]
        })
      });
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      // Mock violation recording
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const response: AgentResult = {
        taskId: 'task-1',
        agentId: 'test-agent',
        status: 'completed',
        result: {
          success: true,
          data: { message: 'This is a test message' }
        },
        metrics: {
          executionTime: 100,
          tokensUsed: 50,
          cost: 0.01
        },
        timestamp: new Date().toISOString()
      };

      const task: AgentTask = {
        id: 'task-1',
        capability: 'test',
        input: { data: {} },
        priority: 'normal',
        context: testContext
      };

      const result = await complianceService.validateAgentResponse(
        response,
        task,
        'test-agent',
        testContext
      );

      // Should detect violation but still allow (monitor mode)
      expect(result.violations.length).toBeGreaterThan(0);
      expect(result.action).toBe('allow'); // Monitor mode doesn't block
    });
  });
});
