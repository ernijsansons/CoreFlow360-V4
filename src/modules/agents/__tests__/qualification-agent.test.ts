/**
 * Qualification Agent Test Suite
 *
 * Comprehensive tests for BANT qualification capabilities
 * Coverage target: 95%+
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { QualificationAgent } from '../qualification-agent';
import type { AgentTask, BusinessContext } from '../types';

describe('QualificationAgent', () => {
  let agent: QualificationAgent;
  let mockEnv: any;
  let testContext: BusinessContext;

  beforeEach(() => {
    mockEnv = {
      ANTHROPIC_API_KEY: 'test-key-12345'
    };
    agent = new QualificationAgent(mockEnv);

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

  describe('Agent Configuration', () => {
    it('should have correct agent metadata', () => {
      expect(agent.id).toBe('qualification-agent');
      expect(agent.name).toBe('BANT Qualification Agent');
      expect(agent.version).toBe('1.0.0');
      expect(agent.type).toBe('specialized');
    });

    it('should declare all 3 capabilities', () => {
      expect(agent.capabilities).toHaveLength(3);
      expect(agent.capabilities).toContain('lead_qualification');
      expect(agent.capabilities).toContain('bant_analysis');
      expect(agent.capabilities).toContain('conversation_analysis');
    });

    it('should have correct cost and performance characteristics', () => {
      expect(agent.costPerCall).toBe(0.15);
      expect(agent.maxConcurrency).toBe(10);
      expect(agent.averageLatency).toBe(5000);
    });

    it('should support English language', () => {
      expect(agent.supportedLanguages).toContain('en');
    });

    it('should support text and JSON formats', () => {
      expect(agent.supportedFormats).toContain('text');
      expect(agent.supportedFormats).toContain('json');
    });
  });

  describe('lead_qualification capability', () => {
    it('should qualify a lead with complete BANT information', async () => {
      const task: AgentTask = {
        id: 'task-qual-001',
        capability: 'lead_qualification',
        input: {
          data: {
            lead_id: 'lead-123',
            conversation_context: {
              messages: [
                { role: 'user', content: 'We have a budget of $50,000 for this project' },
                { role: 'user', content: 'I am the VP of Sales and can make this decision' },
                { role: 'user', content: 'We need to solve our CRM integration issues' },
                { role: 'user', content: 'We want this implemented within 3 months' }
              ]
            }
          }
        },
        priority: 'high'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data).toBeDefined();
      expect(result.result.data.leadId).toBe('lead-123');
      expect(result.result.data.overall_score).toBeGreaterThan(0);
      expect(result.result.data.bant_data).toBeDefined();
      expect(result.result.data.qualification_status).toBeDefined();
    });

    it('should handle lead with missing budget information', async () => {
      const task: AgentTask = {
        id: 'task-qual-002',
        capability: 'lead_qualification',
        input: {
          data: {
            lead_id: 'lead-124',
            conversation_context: {
              messages: [
                { role: 'user', content: 'I am the decision maker' },
                { role: 'user', content: 'We need better reporting tools' },
                { role: 'user', content: 'We want this soon' }
              ]
            }
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.bant_data.budget).toBeDefined();
      expect(result.result.data.next_questions).toBeDefined();
      expect(result.result.data.next_questions.length).toBeGreaterThan(0);
    });

    it('should handle lead with no authority indicated', async () => {
      const task: AgentTask = {
        id: 'task-qual-003',
        capability: 'lead_qualification',
        input: {
          data: {
            lead_id: 'lead-125',
            conversation_context: {
              messages: [
                { role: 'user', content: 'Our budget is around $30k' },
                { role: 'user', content: 'We have performance issues' },
                { role: 'user', content: 'Timeline is flexible' }
              ]
            }
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.bant_data.authority).toBeDefined();
      expect(result.result.data.overall_score).toBeLessThan(100);
    });

    it('should identify high-priority need indicators', async () => {
      const task: AgentTask = {
        id: 'task-qual-004',
        capability: 'lead_qualification',
        input: {
          data: {
            lead_id: 'lead-126',
            conversation_context: {
              messages: [
                { role: 'user', content: 'We are losing $10k per day due to system downtime' },
                { role: 'user', content: 'This is a critical blocker for our business' },
                { role: 'user', content: 'We need a solution immediately' }
              ]
            }
          }
        },
        priority: 'urgent'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.bant_data.need.urgency).toBeDefined();
      expect(result.result.data.qualification_status).toBe('qualified');
    });

    it('should handle force requalification flag', async () => {
      const task: AgentTask = {
        id: 'task-qual-005',
        capability: 'lead_qualification',
        input: {
          data: {
            lead_id: 'lead-127',
            force_requalification: true,
            conversation_context: {
              messages: [
                { role: 'user', content: 'Budget approved at $75k' },
                { role: 'user', content: 'I have final approval' }
              ]
            }
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.leadId).toBe('lead-127');
    });

    it('should generate appropriate next questions', async () => {
      const task: AgentTask = {
        id: 'task-qual-006',
        capability: 'lead_qualification',
        input: {
          data: {
            lead_id: 'lead-128',
            conversation_context: {
              messages: [
                { role: 'user', content: 'Looking for a CRM solution' }
              ]
            }
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.next_questions).toBeDefined();
      expect(result.result.data.next_questions.length).toBeGreaterThan(0);
      expect(result.result.data.next_questions[0]).toHaveProperty('category');
      expect(result.result.data.next_questions[0]).toHaveProperty('question');
    });

    it('should provide AI insights', async () => {
      const task: AgentTask = {
        id: 'task-qual-007',
        capability: 'lead_qualification',
        input: {
          data: {
            lead_id: 'lead-129',
            conversation_context: {
              messages: [
                { role: 'user', content: 'We spent $100k last year on a failed implementation' },
                { role: 'user', content: 'Looking for better ROI this time' }
              ]
            }
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.ai_insights).toBeDefined();
      expect(result.result.data.confidence_level).toBeGreaterThan(0);
    });

    it('should calculate overall qualification score', async () => {
      const task: AgentTask = {
        id: 'task-qual-008',
        capability: 'lead_qualification',
        input: {
          data: {
            lead_id: 'lead-130',
            conversation_context: {
              messages: [
                { role: 'user', content: 'Budget: $50k, I am CEO, need ASAP, critical issue' }
              ]
            }
          }
        },
        priority: 'high'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.overall_score).toBeGreaterThanOrEqual(0);
      expect(result.result.data.overall_score).toBeLessThanOrEqual(100);
    });

    it('should fail when conversation context is missing', async () => {
      const task: AgentTask = {
        id: 'task-qual-009',
        capability: 'lead_qualification',
        input: {
          data: {
            lead_id: 'lead-131'
            // Missing conversation_context
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('failed');
      expect(result.error).toBeDefined();
    });

    it('should classify lead as qualified when score is high', async () => {
      const task: AgentTask = {
        id: 'task-qual-010',
        capability: 'lead_qualification',
        input: {
          data: {
            lead_id: 'lead-132',
            conversation_context: {
              messages: [
                { role: 'user', content: 'I am the CEO with full budget authority' },
                { role: 'user', content: 'We have $200k allocated for this project' },
                { role: 'user', content: 'System crashes are costing us revenue daily' },
                { role: 'user', content: 'Need solution deployed within 30 days' }
              ]
            }
          }
        },
        priority: 'urgent'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.overall_score).toBeGreaterThan(70);
      expect(result.result.data.qualification_status).toMatch(/qualified|highly_qualified/);
    });
  });

  describe('bant_analysis capability', () => {
    it('should analyze conversation for BANT factors', async () => {
      const task: AgentTask = {
        id: 'task-bant-001',
        capability: 'bant_analysis',
        input: {
          data: {
            messages: [
              { role: 'user', content: 'We have $40k budget' },
              { role: 'user', content: 'I can approve this purchase' },
              { role: 'user', content: 'We need better analytics' },
              { role: 'user', content: 'Timeline is Q2 next year' }
            ]
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data).toBeDefined();
      expect(result.result.data.budget).toBeDefined();
      expect(result.result.data.authority).toBeDefined();
      expect(result.result.data.need).toBeDefined();
      expect(result.result.data.timeline).toBeDefined();
    });

    it('should extract budget range from conversation', async () => {
      const task: AgentTask = {
        id: 'task-bant-002',
        capability: 'bant_analysis',
        input: {
          data: {
            messages: [
              { role: 'user', content: 'Our budget is between $25,000 and $50,000' }
            ]
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.budget).toBeDefined();
      expect(result.result.data.budget.detected).toBe(true);
    });

    it('should identify authority level from role mentions', async () => {
      const task: AgentTask = {
        id: 'task-bant-003',
        capability: 'bant_analysis',
        input: {
          data: {
            messages: [
              { role: 'user', content: 'I am the Director of IT and have purchasing authority' }
            ]
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.authority).toBeDefined();
      expect(result.result.data.authority.level).toMatch(/decision_maker|influencer/);
    });

    it('should detect pain points and needs', async () => {
      const task: AgentTask = {
        id: 'task-bant-004',
        capability: 'bant_analysis',
        input: {
          data: {
            messages: [
              { role: 'user', content: 'Our current system is slow and unreliable' },
              { role: 'user', content: 'We lose data frequently and it costs us money' }
            ]
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.need).toBeDefined();
      expect(result.result.data.need.pain_points).toBeDefined();
      expect(result.result.data.need.pain_points.length).toBeGreaterThan(0);
    });

    it('should identify timeline urgency', async () => {
      const task: AgentTask = {
        id: 'task-bant-005',
        capability: 'bant_analysis',
        input: {
          data: {
            messages: [
              { role: 'user', content: 'We need this implemented immediately' },
              { role: 'user', content: 'This is blocking our product launch' }
            ]
          }
        },
        priority: 'urgent'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.timeline).toBeDefined();
      expect(result.result.data.timeline.urgency).toMatch(/immediate|urgent/);
    });

    it('should handle conversation with minimal BANT information', async () => {
      const task: AgentTask = {
        id: 'task-bant-006',
        capability: 'bant_analysis',
        input: {
          data: {
            messages: [
              { role: 'user', content: 'Tell me about your product' }
            ]
          }
        },
        priority: 'low'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data).toBeDefined();
    });

    it('should calculate completeness score', async () => {
      const task: AgentTask = {
        id: 'task-bant-007',
        capability: 'bant_analysis',
        input: {
          data: {
            messages: [
              { role: 'user', content: 'Budget $50k, CEO approval, urgent need' }
            ]
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.completeness_score).toBeGreaterThanOrEqual(0);
      expect(result.result.data.completeness_score).toBeLessThanOrEqual(100);
    });
  });

  describe('conversation_analysis capability', () => {
    it('should analyze conversation for qualification signals', async () => {
      const task: AgentTask = {
        id: 'task-conv-001',
        capability: 'conversation_analysis',
        input: {
          data: {
            messages: [
              { role: 'user', content: 'We are evaluating solutions' },
              { role: 'assistant', content: 'What is your timeline?' },
              { role: 'user', content: 'We want to decide within 2 weeks' }
            ]
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data).toBeDefined();
    });

    it('should identify buying signals', async () => {
      const task: AgentTask = {
        id: 'task-conv-002',
        capability: 'conversation_analysis',
        input: {
          data: {
            messages: [
              { role: 'user', content: 'How soon can you get started?' },
              { role: 'user', content: 'What are the payment terms?' },
              { role: 'user', content: 'Can we sign the contract today?' }
            ]
          }
        },
        priority: 'high'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.buying_signals).toBeDefined();
      expect(result.result.data.buying_signals.length).toBeGreaterThan(0);
    });

    it('should detect risk indicators', async () => {
      const task: AgentTask = {
        id: 'task-conv-003',
        capability: 'conversation_analysis',
        input: {
          data: {
            messages: [
              { role: 'user', content: 'We are also looking at your competitors' },
              { role: 'user', content: 'Not sure if we have budget approved yet' },
              { role: 'user', content: 'Timeline is unclear' }
            ]
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.risk_indicators).toBeDefined();
    });

    it('should calculate engagement level', async () => {
      const task: AgentTask = {
        id: 'task-conv-004',
        capability: 'conversation_analysis',
        input: {
          data: {
            messages: [
              { role: 'user', content: 'This looks interesting' },
              { role: 'assistant', content: 'Would you like a demo?' },
              { role: 'user', content: 'Yes, and can we also discuss pricing?' }
            ]
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.engagement_level).toBeDefined();
    });

    it('should identify objections raised', async () => {
      const task: AgentTask = {
        id: 'task-conv-005',
        capability: 'conversation_analysis',
        input: {
          data: {
            messages: [
              { role: 'user', content: 'This seems expensive' },
              { role: 'user', content: 'We had a bad experience with similar tools before' }
            ]
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.objections).toBeDefined();
      expect(result.result.data.objections.length).toBeGreaterThan(0);
    });

    it('should recommend next actions', async () => {
      const task: AgentTask = {
        id: 'task-conv-006',
        capability: 'conversation_analysis',
        input: {
          data: {
            messages: [
              { role: 'user', content: 'Sounds good, send me more information' }
            ]
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.recommended_actions).toBeDefined();
    });
  });

  describe('Validation', () => {
    it('should validate input for lead_qualification', async () => {
      const task: AgentTask = {
        id: 'task-val-001',
        capability: 'lead_qualification',
        input: {
          data: {} // Empty data
        },
        priority: 'normal'
      };

      const validation = await agent.validateInput(task.input, 'lead_qualification');

      expect(validation.valid).toBe(false);
      expect(validation.errors).toBeDefined();
    });

    it('should accept valid lead_qualification input', async () => {
      const input = {
        data: {
          lead_id: 'lead-123',
          conversation_context: {
            messages: [{ role: 'user', content: 'Test' }]
          }
        }
      };

      const validation = await agent.validateInput(input, 'lead_qualification');

      expect(validation.valid).toBe(true);
    });
  });

  describe('Cost Estimation', () => {
    it('should estimate cost for qualification task', async () => {
      const task: AgentTask = {
        id: 'task-cost-001',
        capability: 'lead_qualification',
        input: {
          data: {
            lead_id: 'lead-123',
            conversation_context: {
              messages: Array(10).fill({ role: 'user', content: 'Test message' })
            }
          }
        },
        priority: 'normal'
      };

      const cost = await agent.estimateCost(task);

      expect(cost).toBeGreaterThan(0);
      expect(cost).toBeLessThanOrEqual(1); // Max $1 for qualification
    });
  });

  describe('Health Check', () => {
    it('should return healthy status', async () => {
      const health = await agent.healthCheck();

      expect(health.status).toBe('healthy');
      expect(health.capabilities).toBeDefined();
    });
  });

  describe('Error Handling', () => {
    it('should handle unsupported capability', async () => {
      const task: AgentTask = {
        id: 'task-err-001',
        capability: 'unsupported_capability',
        input: { data: {} },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('failed');
      expect(result.error).toBeDefined();
      expect(result.error.code).toBe('UNSUPPORTED_CAPABILITY');
    });

    it('should include execution metrics in error response', async () => {
      const task: AgentTask = {
        id: 'task-err-002',
        capability: 'lead_qualification',
        input: {
          data: {
            lead_id: 'lead-error'
            // Missing required conversation_context
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('failed');
      expect(result.metrics).toBeDefined();
      expect(result.metrics.executionTime).toBeGreaterThan(0);
    });
  });

  describe('Performance', () => {
    it('should complete qualification within expected latency', async () => {
      const task: AgentTask = {
        id: 'task-perf-001',
        capability: 'lead_qualification',
        input: {
          data: {
            lead_id: 'lead-perf',
            conversation_context: {
              messages: [
                { role: 'user', content: 'Performance test message' }
              ]
            }
          }
        },
        priority: 'normal'
      };

      const startTime = Date.now();
      const result = await agent.execute(task, testContext);
      const duration = Date.now() - startTime;

      expect(result.status).toBe('completed');
      expect(duration).toBeLessThan(10000); // Should complete within 10 seconds
    });
  });

  describe('Metrics', () => {
    it('should include execution metrics in result', async () => {
      const task: AgentTask = {
        id: 'task-met-001',
        capability: 'lead_qualification',
        input: {
          data: {
            lead_id: 'lead-metrics',
            conversation_context: {
              messages: [{ role: 'user', content: 'Test' }]
            }
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.metrics).toBeDefined();
      expect(result.metrics.executionTime).toBeGreaterThan(0);
      expect(result.metrics.tokensUsed).toBeGreaterThan(0);
      expect(result.metrics.costUSD).toBe(agent.costPerCall);
      expect(result.metrics.retryCount).toBe(0);
    });

    it('should track model used in metrics', async () => {
      const task: AgentTask = {
        id: 'task-met-002',
        capability: 'bant_analysis',
        input: {
          data: {
            messages: [{ role: 'user', content: 'Test' }]
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.metrics.modelUsed).toBeDefined();
    });
  });
});
