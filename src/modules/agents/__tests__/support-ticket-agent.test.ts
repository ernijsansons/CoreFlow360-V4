/**
 * Support Ticket Agent Test Suite
 *
 * Comprehensive tests for all 10 ticket management capabilities
 * Coverage target: 95%+
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SupportTicketAgent } from '../support-ticket-agent';
import type { AgentTask, BusinessContext } from '../types';

describe('SupportTicketAgent', () => {
  let agent: SupportTicketAgent;
  let mockEnv: any;
  let testContext: BusinessContext;

  beforeEach(() => {
    mockEnv = {
      DB_MAIN: {
        prepare: vi.fn().mockReturnThis(),
        bind: vi.fn().mockReturnThis(),
        first: vi.fn(),
        all: vi.fn(),
        run: vi.fn()
      },
      ANTHROPIC_API_KEY: 'test-key-support'
    };
    agent = new SupportTicketAgent(mockEnv);

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
      expect(agent.id).toBe('support-ticket-agent');
      expect(agent.name).toBe('Support Ticket Agent');
    });

    it('should declare all 10 capabilities', () => {
      expect(agent.capabilities).toHaveLength(10);
      expect(agent.capabilities).toContain('ticket_creation');
      expect(agent.capabilities).toContain('ticket_analysis');
      expect(agent.capabilities).toContain('ticket_routing');
      expect(agent.capabilities).toContain('ticket_prioritization');
      expect(agent.capabilities).toContain('auto_response');
      expect(agent.capabilities).toContain('sla_management');
      expect(agent.capabilities).toContain('sentiment_analysis');
      expect(agent.capabilities).toContain('ticket_resolution');
      expect(agent.capabilities).toContain('escalation_management');
      expect(agent.capabilities).toContain('customer_satisfaction');
    });

    it('should support correct departments', () => {
      expect(agent.departments).toContain('support');
      expect(agent.departments).toContain('customer_success');
      expect(agent.departments).toContain('operations');
    });

    it('should have high concurrency for support operations', () => {
      expect(agent.maxConcurrency).toBe(50);
    });

    it('should have low cost per call', () => {
      expect(agent.costPerCall).toBe(0.003);
    });
  });

  describe('ticket_creation capability', () => {
    it('should create a new support ticket', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({ ticket_number: 'TKT-1000' })
      });
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-create-001',
        capability: 'ticket_creation',
        input: {
          data: {
            customerId: 'cust-123',
            customerName: 'John Doe',
            customerEmail: 'john@example.com',
            subject: 'Unable to login',
            description: 'I cannot access my account',
            category: 'technical'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data).toBeDefined();
      expect(result.result.data.ticketNumber).toBeDefined();
    });

    it('should auto-generate ticket number', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({ ticket_number: 'TKT-1001' })
      });
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-create-002',
        capability: 'ticket_creation',
        input: {
          data: {
            customerId: 'cust-124',
            customerEmail: 'jane@example.com',
            subject: 'Billing question',
            description: 'Question about recent invoice'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.ticketNumber).toMatch(/TKT-\d+/);
    });

    it('should set SLA due date based on priority', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({ ticket_number: 'TKT-1002' }),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-create-003',
        capability: 'ticket_creation',
        input: {
          data: {
            customerId: 'cust-125',
            customerEmail: 'urgent@example.com',
            subject: 'System down',
            description: 'Critical system failure',
            priority: 'critical'
          }
        },
        priority: 'urgent'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.slaDueDate).toBeDefined();
    });

    it('should validate required fields', async () => {
      const task: AgentTask = {
        id: 'task-create-004',
        capability: 'ticket_creation',
        input: {
          data: {
            // Missing required fields
            subject: 'Test'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('failed');
    });
  });

  describe('ticket_analysis capability', () => {
    it('should analyze ticket content', async () => {
      const task: AgentTask = {
        id: 'task-analyze-001',
        capability: 'ticket_analysis',
        input: {
          data: {
            ticketId: 'ticket-123',
            subject: 'Application crashes on startup',
            description: 'The app crashes immediately when I try to open it. Very frustrating!'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.category).toBeDefined();
      expect(result.result.data.priority).toBeDefined();
      expect(result.result.data.sentiment).toBeDefined();
    });

    it('should suggest relevant knowledge base articles', async () => {
      const task: AgentTask = {
        id: 'task-analyze-002',
        capability: 'ticket_analysis',
        input: {
          data: {
            ticketId: 'ticket-124',
            subject: 'Password reset not working',
            description: 'I clicked forgot password but never received the email'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.relatedKnowledgeBase).toBeDefined();
      expect(Array.isArray(result.result.data.relatedKnowledgeBase)).toBe(true);
    });

    it('should estimate resolution time', async () => {
      const task: AgentTask = {
        id: 'task-analyze-003',
        capability: 'ticket_analysis',
        input: {
          data: {
            ticketId: 'ticket-125',
            subject: 'Feature request',
            description: 'Would be nice to have dark mode'
          }
        },
        priority: 'low'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.estimatedResolutionTime).toBeDefined();
      expect(result.result.data.estimatedResolutionTime).toBeGreaterThan(0);
    });

    it('should identify required expertise', async () => {
      const task: AgentTask = {
        id: 'task-analyze-004',
        capability: 'ticket_analysis',
        input: {
          data: {
            ticketId: 'ticket-126',
            subject: 'Database migration failed',
            description: 'Error during PostgreSQL migration to version 14'
          }
        },
        priority: 'high'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.requiredExpertise).toBeDefined();
      expect(result.result.data.requiredExpertise).toContain('database');
    });
  });

  describe('ticket_routing capability', () => {
    it('should route ticket to appropriate team', async () => {
      const task: AgentTask = {
        id: 'task-route-001',
        capability: 'ticket_routing',
        input: {
          data: {
            ticketId: 'ticket-200',
            category: 'billing',
            priority: 'medium'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.assignedTeam).toBeDefined();
    });

    it('should assign to specific agent based on expertise', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [
            { id: 'agent-1', name: 'Tech Expert', availability: 'available' }
          ]
        }),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-route-002',
        capability: 'ticket_routing',
        input: {
          data: {
            ticketId: 'ticket-201',
            category: 'technical',
            requiredExpertise: ['api', 'backend']
          }
        },
        priority: 'high'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.assignedTo).toBeDefined();
    });

    it('should handle no available agents gracefully', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] }),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-route-003',
        capability: 'ticket_routing',
        input: {
          data: {
            ticketId: 'ticket-202',
            category: 'technical'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.assignedTeam).toBeDefined();
    });

    it('should consider agent workload in routing', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [
            { id: 'agent-1', name: 'Agent 1', ticket_count: 5 },
            { id: 'agent-2', name: 'Agent 2', ticket_count: 2 }
          ]
        }),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-route-004',
        capability: 'ticket_routing',
        input: {
          data: {
            ticketId: 'ticket-203',
            category: 'general'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      // Should route to agent with lower workload
      expect(result.result.data.assignedTo).toBe('agent-2');
    });
  });

  describe('ticket_prioritization capability', () => {
    it('should calculate urgency score', async () => {
      const task: AgentTask = {
        id: 'task-priority-001',
        capability: 'ticket_prioritization',
        input: {
          data: {
            ticketId: 'ticket-300',
            subject: 'Payment processing down',
            description: 'Customers cannot complete purchases. Losing revenue!',
            sentiment: 'angry'
          }
        },
        priority: 'urgent'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.urgencyScore).toBeGreaterThan(80);
      expect(result.result.data.priority).toBe('critical');
    });

    it('should consider SLA in prioritization', async () => {
      const task: AgentTask = {
        id: 'task-priority-002',
        capability: 'ticket_prioritization',
        input: {
          data: {
            ticketId: 'ticket-301',
            slaDueDate: new Date(Date.now() + 1000 * 60 * 30).toISOString() // 30 min
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.priority).toMatch(/high|critical/);
    });

    it('should detect VIP customers', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({ is_vip: true, tier: 'enterprise' })
      });

      const task: AgentTask = {
        id: 'task-priority-003',
        capability: 'ticket_prioritization',
        input: {
          data: {
            ticketId: 'ticket-302',
            customerId: 'vip-customer-1'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.priorityAdjustment).toBeDefined();
    });

    it('should analyze sentiment impact on priority', async () => {
      const task: AgentTask = {
        id: 'task-priority-004',
        capability: 'ticket_prioritization',
        input: {
          data: {
            ticketId: 'ticket-303',
            sentiment: 'angry',
            description: 'This is completely unacceptable! Third time reporting this!'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.urgencyScore).toBeGreaterThan(60);
    });
  });

  describe('auto_response capability', () => {
    it('should generate appropriate auto-response', async () => {
      const task: AgentTask = {
        id: 'task-auto-001',
        capability: 'auto_response',
        input: {
          data: {
            ticketId: 'ticket-400',
            category: 'password_reset',
            customerName: 'John Doe'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.response).toBeDefined();
      expect(result.result.data.response).toContain('John');
    });

    it('should include knowledge base links', async () => {
      const task: AgentTask = {
        id: 'task-auto-002',
        capability: 'auto_response',
        input: {
          data: {
            ticketId: 'ticket-401',
            category: 'how_to',
            relatedArticles: ['kb-123', 'kb-456']
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.response).toContain('kb-');
    });

    it('should personalize response based on customer data', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({
          name: 'Jane Smith',
          tier: 'premium',
          language: 'en'
        })
      });

      const task: AgentTask = {
        id: 'task-auto-003',
        capability: 'auto_response',
        input: {
          data: {
            ticketId: 'ticket-402',
            customerId: 'cust-premium-1'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.response).toContain('Jane');
    });
  });

  describe('sla_management capability', () => {
    it('should calculate SLA due dates', async () => {
      const task: AgentTask = {
        id: 'task-sla-001',
        capability: 'sla_management',
        input: {
          data: {
            ticketId: 'ticket-500',
            priority: 'high',
            createdAt: new Date().toISOString()
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.firstResponseDue).toBeDefined();
      expect(result.result.data.resolutionDue).toBeDefined();
    });

    it('should detect SLA breaches', async () => {
      const past = new Date(Date.now() - 1000 * 60 * 60 * 5).toISOString(); // 5 hours ago

      const task: AgentTask = {
        id: 'task-sla-002',
        capability: 'sla_management',
        input: {
          data: {
            ticketId: 'ticket-501',
            priority: 'critical',
            createdAt: past,
            firstResponseAt: null
          }
        },
        priority: 'urgent'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.slaBreached).toBe(true);
      expect(result.result.data.breachType).toContain('first_response');
    });

    it('should calculate time remaining', async () => {
      const task: AgentTask = {
        id: 'task-sla-003',
        capability: 'sla_management',
        input: {
          data: {
            ticketId: 'ticket-502',
            priority: 'medium',
            slaDueDate: new Date(Date.now() + 1000 * 60 * 60 * 4).toISOString()
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.timeRemaining).toBeDefined();
      expect(result.result.data.timeRemaining).toBeGreaterThan(0);
    });
  });

  describe('sentiment_analysis capability', () => {
    it('should detect angry customer sentiment', async () => {
      const task: AgentTask = {
        id: 'task-sentiment-001',
        capability: 'sentiment_analysis',
        input: {
          data: {
            ticketId: 'ticket-600',
            text: 'This is absolutely terrible! Worst service ever! I want a refund NOW!'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.sentiment).toBe('angry');
      expect(result.result.data.score).toBeLessThan(0);
    });

    it('should detect positive sentiment', async () => {
      const task: AgentTask = {
        id: 'task-sentiment-002',
        capability: 'sentiment_analysis',
        input: {
          data: {
            ticketId: 'ticket-601',
            text: 'Thank you so much for your help! The issue is resolved and I am very happy!'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.sentiment).toBe('positive');
      expect(result.result.data.score).toBeGreaterThan(0);
    });

    it('should analyze conversation history sentiment trend', async () => {
      const task: AgentTask = {
        id: 'task-sentiment-003',
        capability: 'sentiment_analysis',
        input: {
          data: {
            ticketId: 'ticket-602',
            conversationHistory: [
              { text: 'I have a problem', timestamp: '2025-01-01T10:00:00Z' },
              { text: 'Still waiting for response...', timestamp: '2025-01-01T11:00:00Z' },
              { text: 'This is taking too long!', timestamp: '2025-01-01T12:00:00Z' }
            ]
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.sentimentTrend).toBeDefined();
      expect(result.result.data.sentimentTrend).toBe('declining');
    });
  });

  describe('ticket_resolution capability', () => {
    it('should mark ticket as resolved', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-resolve-001',
        capability: 'ticket_resolution',
        input: {
          data: {
            ticketId: 'ticket-700',
            resolution: 'Password reset link sent successfully',
            resolutionType: 'solved'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.status).toBe('resolved');
      expect(result.result.data.resolvedAt).toBeDefined();
    });

    it('should calculate resolution time', async () => {
      const createdAt = new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString();

      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({ created_at: createdAt }),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-resolve-002',
        capability: 'ticket_resolution',
        input: {
          data: {
            ticketId: 'ticket-701',
            resolution: 'Issue fixed'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.resolutionTime).toBeGreaterThan(0);
    });

    it('should send resolution notification to customer', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({
          customer_email: 'customer@example.com',
          customer_name: 'John Doe'
        }),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-resolve-003',
        capability: 'ticket_resolution',
        input: {
          data: {
            ticketId: 'ticket-702',
            resolution: 'All fixed now',
            sendNotification: true
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.notificationSent).toBe(true);
    });
  });

  describe('escalation_management capability', () => {
    it('should escalate overdue ticket', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-escalate-001',
        capability: 'escalation_management',
        input: {
          data: {
            ticketId: 'ticket-800',
            reason: 'SLA breach',
            escalateTo: 'senior_support'
          }
        },
        priority: 'high'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.escalated).toBe(true);
      expect(result.result.data.escalationLevel).toBeDefined();
    });

    it('should notify management of critical escalations', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-escalate-002',
        capability: 'escalation_management',
        input: {
          data: {
            ticketId: 'ticket-801',
            priority: 'critical',
            sentiment: 'angry',
            escalateTo: 'management'
          }
        },
        priority: 'urgent'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.managementNotified).toBe(true);
    });

    it('should track escalation history', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [
            { escalated_at: '2025-01-01T10:00:00Z', level: 'tier_2' },
            { escalated_at: '2025-01-01T11:00:00Z', level: 'management' }
          ]
        }),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-escalate-003',
        capability: 'escalation_management',
        input: {
          data: {
            ticketId: 'ticket-802',
            getHistory: true
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.escalationHistory).toBeDefined();
      expect(result.result.data.escalationHistory.length).toBe(2);
    });
  });

  describe('customer_satisfaction capability', () => {
    it('should record customer satisfaction rating', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-csat-001',
        capability: 'customer_satisfaction',
        input: {
          data: {
            ticketId: 'ticket-900',
            rating: 5,
            feedback: 'Excellent service, very helpful!'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.csatRecorded).toBe(true);
    });

    it('should calculate team CSAT average', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({ avg_rating: 4.3, count: 50 })
      });

      const task: AgentTask = {
        id: 'task-csat-002',
        capability: 'customer_satisfaction',
        input: {
          data: {
            teamId: 'support-team-1',
            period: 'last_30_days'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.averageRating).toBeDefined();
      expect(result.result.data.totalResponses).toBe(50);
    });

    it('should flag low satisfaction scores', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-csat-003',
        capability: 'customer_satisfaction',
        input: {
          data: {
            ticketId: 'ticket-901',
            rating: 1,
            feedback: 'Terrible experience, not helpful at all'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.flaggedForReview).toBe(true);
      expect(result.result.data.escalationTriggered).toBe(true);
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
    });

    it('should handle missing ticket ID gracefully', async () => {
      const task: AgentTask = {
        id: 'task-err-002',
        capability: 'ticket_analysis',
        input: {
          data: {
            // Missing ticketId
            subject: 'Test'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('failed');
      expect(result.error.message).toContain('ticketId');
    });

    it('should include metrics in error response', async () => {
      const task: AgentTask = {
        id: 'task-err-003',
        capability: 'ticket_routing',
        input: {
          data: {
            ticketId: 'invalid-ticket'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.metrics).toBeDefined();
      expect(result.metrics.executionTime).toBeGreaterThan(0);
    });
  });

  describe('Performance', () => {
    it('should complete ticket creation quickly', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({ ticket_number: 'TKT-PERF' }),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-perf-001',
        capability: 'ticket_creation',
        input: {
          data: {
            customerId: 'perf-test',
            customerEmail: 'perf@test.com',
            subject: 'Performance test',
            description: 'Testing response time'
          }
        },
        priority: 'normal'
      };

      const startTime = Date.now();
      const result = await agent.execute(task, testContext);
      const duration = Date.now() - startTime;

      expect(result.status).toBe('completed');
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
    });
  });
});
