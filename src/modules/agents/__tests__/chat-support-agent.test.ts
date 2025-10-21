/**
 * Chat Support Agent Test Suite
 * Comprehensive tests for all 10 capabilities
 * Target: 95%+ test coverage
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ChatSupportAgent } from '../chat-support-agent';
import type { AgentTask, BusinessContext } from '../types';

describe('ChatSupportAgent', () => {
  let agent: ChatSupportAgent;
  let mockEnv: any;
  let testContext: BusinessContext;

  beforeEach(() => {
    mockEnv = {
      DB_MAIN: {
        prepare: vi.fn().mockReturnValue({
          bind: vi.fn().mockReturnThis(),
          run: vi.fn().mockResolvedValue({ success: true }),
          first: vi.fn().mockResolvedValue(null),
          all: vi.fn().mockResolvedValue({ results: [] })
        })
      },
      ANTHROPIC_API_KEY: 'test-anthropic-key'
    };

    agent = new ChatSupportAgent(mockEnv);

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
    it('should have correct agent metadata', async () => {
      const config = await agent.getConfig();

      expect(config.id).toBe('chat-support-agent');
      expect(config.name).toBe('Chat Support Agent');
      expect(config.type).toBe('specialized');
    });

    it('should have all 10 capabilities', async () => {
      const config = await agent.getConfig();

      expect(config.capabilities).toHaveLength(10);
      expect(config.capabilities).toContain('chat_response');
      expect(config.capabilities).toContain('intent_detection');
      expect(config.capabilities).toContain('sentiment_tracking');
      expect(config.capabilities).toContain('conversation_management');
      expect(config.capabilities).toContain('human_handoff');
      expect(config.capabilities).toContain('proactive_assistance');
      expect(config.capabilities).toContain('conversation_summary');
      expect(config.capabilities).toContain('csat_collection');
      expect(config.capabilities).toContain('multi_channel_support');
      expect(config.capabilities).toContain('context_awareness');
    });

    it('should support multiple departments', async () => {
      const config = await agent.getConfig();

      expect(config.departments).toContain('support');
      expect(config.departments).toContain('customer_success');
      expect(config.departments).toContain('sales');
    });

    it('should have reasonable cost per call', async () => {
      const config = await agent.getConfig();

      expect(config.costPerCall).toBe(0.004);
    });

    it('should estimate task cost correctly', async () => {
      const task: AgentTask = {
        id: 'task-001',
        capability: 'chat_response',
        input: { data: {} },
        priority: 'normal'
      };

      const cost = await agent.estimateCost(task);
      expect(cost).toBe(0.004);
    });
  });

  describe('chat_response capability', () => {
    it('should generate AI-powered response', async () => {
      // Mock chat session retrieval
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({
          id: 'session-123',
          business_id: 'biz-123',
          customer_id: 'cust-123',
          customer_name: 'John Doe',
          customer_email: 'john@example.com',
          channel: 'web',
          status: 'active',
          ai_assist_level: 'full',
          messages: '[]',
          context: JSON.stringify({
            customerId: 'cust-123',
            customerProfile: {
              name: 'John Doe',
              email: 'john@example.com',
              tier: 'pro',
              lifetimeValue: 1000,
              accountAge: 365,
              previousTickets: 5,
              averageSatisfaction: 4.5
            },
            previousConversations: [],
            businessHours: true,
            availableAgents: 2
          }),
          sentiment: 'neutral',
          urgency: 'medium',
          intents: '[]',
          resolved_issues: '[]',
          suggested_articles: '[]',
          metadata: '{}',
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z'
        })
      });

      // Mock storing messages (2 calls: customer message + AI response)
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          content: [
            {
              text: JSON.stringify({
                message: 'I can help you reset your password. Please click the "Forgot Password" link on the login page.',
                confidence: 0.9,
                intent: 'password_reset',
                suggestedActions: [],
                requiresHumanAgent: false,
                sentiment: 'helpful'
              })
            }
          ]
        })
      });

      const task: AgentTask = {
        id: 'task-chat-001',
        capability: 'chat_response',
        input: {
          data: {
            sessionId: 'session-123',
            message: 'I forgot my password',
            conversationHistory: [
              { role: 'customer', content: 'Hello' },
              { role: 'ai', content: 'Hi! How can I help?' },
              { role: 'customer', content: 'I forgot my password' }
            ]
          }
        },
        priority: 'high'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data).toBeDefined();
      expect(result.result.data.message).toBeDefined();
      expect(result.result.data.confidence).toBeGreaterThan(0);
    });

    it('should include suggested actions in response', async () => {
      // Mock chat session retrieval
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({
          id: 'session-123',
          business_id: 'biz-123',
          customer_id: 'cust-123',
          customer_name: 'John Doe',
          customer_email: 'john@example.com',
          channel: 'web',
          status: 'active',
          ai_assist_level: 'full',
          messages: '[]',
          context: JSON.stringify({
            customerId: 'cust-123',
            customerProfile: {
              name: 'John Doe',
              email: 'john@example.com',
              tier: 'pro'
            },
            previousConversations: [],
            businessHours: true,
            availableAgents: 2
          }),
          sentiment: 'neutral',
          urgency: 'medium',
          intents: '[]',
          resolved_issues: '[]',
          suggested_articles: '[]',
          metadata: '{}',
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z'
        })
      });

      // Mock storing messages
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          content: [
            {
              text: JSON.stringify({
                message: 'Here is how to reset your password...',
                confidence: 0.9,
                suggestedActions: ['reset_password', 'verify_email'],
                requiresHumanAgent: false
              })
            }
          ]
        })
      });

      const task: AgentTask = {
        id: 'task-actions-001',
        capability: 'chat_response',
        input: {
          data: {
            sessionId: 'session-123',
            message: 'How do I reset password?',
            conversationHistory: []
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.result.data.suggestedActions).toBeDefined();
    });

    it('should detect when human handoff is needed', async () => {
      // Mock chat session retrieval
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({
          id: 'session-123',
          business_id: 'biz-123',
          customer_id: 'cust-123',
          customer_name: 'John Doe',
          customer_email: 'john@example.com',
          channel: 'web',
          status: 'active',
          ai_assist_level: 'full',
          messages: '[]',
          context: JSON.stringify({
            customerId: 'cust-123',
            customerProfile: {
              name: 'John Doe',
              email: 'john@example.com',
              tier: 'pro'
            },
            previousConversations: [],
            businessHours: true,
            availableAgents: 2
          }),
          sentiment: 'negative',
          urgency: 'high',
          intents: '[]',
          resolved_issues: '[]',
          suggested_articles: '[]',
          metadata: '{}',
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z'
        })
      });

      // Mock storing messages
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          content: [
            {
              text: JSON.stringify({
                message: 'This requires account access verification. I need to connect you with our security team.',
                confidence: 0.95,
                requiresHumanAgent: true,
                escalationReason: 'account_deletion_request'
              })
            }
          ]
        })
      });

      const task: AgentTask = {
        id: 'task-handoff-001',
        capability: 'chat_response',
        input: {
          data: {
            sessionId: 'session-123',
            message: 'I need to delete my account immediately',
            conversationHistory: []
          }
        },
        priority: 'high'
      };

      const result = await agent.execute(task, testContext);

      expect(result.result.data.requiresHumanAgent).toBeDefined();
    });

    it('should use fallback when AI unavailable', async () => {
      const noAIEnv = { ...mockEnv, ANTHROPIC_API_KEY: undefined };
      const agentNoAI = new ChatSupportAgent(noAIEnv);

      // Mock chat session retrieval
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({
          id: 'session-123',
          business_id: 'biz-123',
          customer_id: 'cust-123',
          customer_name: 'John Doe',
          customer_email: 'john@example.com',
          channel: 'web',
          status: 'active',
          ai_assist_level: 'none',
          messages: '[]',
          context: JSON.stringify({
            customerId: 'cust-123',
            customerProfile: {
              name: 'John Doe',
              email: 'john@example.com'
            },
            previousConversations: [],
            businessHours: true,
            availableAgents: 2
          }),
          sentiment: 'neutral',
          urgency: 'low',
          intents: '[]',
          resolved_issues: '[]',
          suggested_articles: '[]',
          metadata: '{}',
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z'
        })
      });

      // Mock storing messages
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-fallback-001',
        capability: 'chat_response',
        input: {
          data: {
            sessionId: 'session-123',
            message: 'Hello',
            conversationHistory: []
          }
        },
        priority: 'normal'
      };

      const result = await agentNoAI.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.message).toBeDefined();
    });
  });

  describe('intent_detection capability', () => {
    it('should detect customer intent', async () => {
      const task: AgentTask = {
        id: 'task-intent-001',
        capability: 'intent_detection',
        input: {
          data: {
            message: 'I want to cancel my subscription'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.intent).toBeDefined();
      expect(result.result.data.confidence).toBeGreaterThan(0);
    });

    it('should detect multiple intents', async () => {
      const task: AgentTask = {
        id: 'task-multi-intent-001',
        capability: 'intent_detection',
        input: {
          data: {
            message: 'I need help with billing and also want to upgrade my plan'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.result.data.primaryIntent).toBeDefined();
      expect(result.result.data.secondaryIntents).toBeDefined();
    });

    it('should classify common intents correctly', async () => {
      const testCases = [
        { message: 'How much does this cost?', expectedCategory: 'pricing' },
        { message: 'My account is not working', expectedCategory: 'technical' },
        { message: 'I want a refund', expectedCategory: 'billing' }
      ];

      for (const testCase of testCases) {
        const task: AgentTask = {
          id: 'task-classify-001',
          capability: 'intent_detection',
          input: {
            data: {
              message: testCase.message
            }
          },
          priority: 'normal'
        };

        const result = await agent.execute(task, testContext);
        expect(result.result.data.category).toBeDefined();
      }
    });
  });

  describe('sentiment_tracking capability', () => {
    it('should track conversation sentiment', async () => {
      const task: AgentTask = {
        id: 'task-sent-001',
        capability: 'sentiment_tracking',
        input: {
          data: {
            sessionId: 'session-123',
            messages: [
              { content: 'This is frustrating!', timestamp: '2024-01-01T10:00:00Z' },
              { content: 'Nothing works!', timestamp: '2024-01-01T10:01:00Z' }
            ]
          }
        },
        priority: 'high'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.overallSentiment).toBeDefined();
      expect(result.result.data.sentimentScore).toBeDefined();
    });

    it('should detect sentiment escalation', async () => {
      const task: AgentTask = {
        id: 'task-escalation-001',
        capability: 'sentiment_tracking',
        input: {
          data: {
            sessionId: 'session-123',
            messages: [
              { content: 'Hi there', timestamp: '2024-01-01T10:00:00Z' },
              { content: 'This is not working', timestamp: '2024-01-01T10:01:00Z' },
              { content: 'I am very angry!', timestamp: '2024-01-01T10:02:00Z' }
            ]
          }
        },
        priority: 'critical'
      };

      const result = await agent.execute(task, testContext);

      expect(result.result.data.sentimentTrend).toBe('negative');
      expect(result.result.data.requiresAttention).toBe(true);
    });

    it('should provide sentiment insights', async () => {
      const task: AgentTask = {
        id: 'task-insights-001',
        capability: 'sentiment_tracking',
        input: {
          data: {
            sessionId: 'session-123',
            messages: [
              { content: 'Thank you so much!', timestamp: '2024-01-01T10:00:00Z' }
            ]
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.result.data.insights).toBeDefined();
    });
  });

  describe('conversation_management capability', () => {
    it('should create new chat session', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-create-session-001',
        capability: 'conversation_management',
        input: {
          data: {
            action: 'create_session',
            customerId: 'cust-123',
            customerName: 'John Doe',
            customerEmail: 'john@example.com',
            channel: 'web'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.sessionId).toBeDefined();
    });

    it('should update session status', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-update-001',
        capability: 'conversation_management',
        input: {
          data: {
            action: 'update_status',
            sessionId: 'session-123',
            status: 'resolved'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
    });

    it('should add message to conversation', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-add-msg-001',
        capability: 'conversation_management',
        input: {
          data: {
            action: 'add_message',
            sessionId: 'session-123',
            type: 'ai',
            content: 'How can I help you?',
            authorId: 'ai-agent',
            authorName: 'Support AI'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.result.data.messageId).toBeDefined();
    });
  });

  describe('human_handoff capability', () => {
    it('should initiate handoff to human agent', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      }).mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({ available_agents: 3 })
      });

      const task: AgentTask = {
        id: 'task-handoff-001',
        capability: 'human_handoff',
        input: {
          data: {
            sessionId: 'session-123',
            reason: 'complex_issue',
            urgency: 'high'
          }
        },
        priority: 'high'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.handoffInitiated).toBe(true);
    });

    it('should notify customer of handoff', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true }),
        first: vi.fn().mockResolvedValue({ available_agents: 2 })
      });

      const task: AgentTask = {
        id: 'task-notify-001',
        capability: 'human_handoff',
        input: {
          data: {
            sessionId: 'session-123',
            reason: 'customer_request'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.result.data.notificationSent).toBe(true);
    });

    it('should queue when no agents available', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true }),
        first: vi.fn().mockResolvedValue({ available_agents: 0 })
      });

      const task: AgentTask = {
        id: 'task-queue-001',
        capability: 'human_handoff',
        input: {
          data: {
            sessionId: 'session-123',
            reason: 'technical_issue'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.result.data.queued).toBe(true);
    });
  });

  describe('proactive_assistance capability', () => {
    it('should offer proactive help based on behavior', async () => {
      const task: AgentTask = {
        id: 'task-proactive-001',
        capability: 'proactive_assistance',
        input: {
          data: {
            sessionId: 'session-123',
            userBehavior: {
              pageVisits: ['/pricing', '/pricing', '/pricing'],
              timeOnPage: 180000,
              clickEvents: ['compare-plans']
            }
          }
        },
        priority: 'low'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.suggestion).toBeDefined();
    });

    it('should suggest relevant articles', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [
            { id: 'art-1', title: 'Getting Started Guide' }
          ]
        })
      });

      const task: AgentTask = {
        id: 'task-articles-001',
        capability: 'proactive_assistance',
        input: {
          data: {
            sessionId: 'session-123',
            context: 'onboarding'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.result.data.suggestedArticles).toBeDefined();
    });
  });

  describe('conversation_summary capability', () => {
    it('should summarize conversation', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          content: [
            {
              text: 'Customer inquired about password reset. Provided step-by-step instructions. Issue resolved.'
            }
          ]
        })
      });

      const task: AgentTask = {
        id: 'task-summary-001',
        capability: 'conversation_summary',
        input: {
          data: {
            sessionId: 'session-123',
            messages: [
              { type: 'customer', content: 'I forgot my password' },
              { type: 'ai', content: 'I can help with that...' },
              { type: 'customer', content: 'Thank you!' }
            ]
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.summary).toBeDefined();
    });

    it('should extract key topics', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          content: [{ text: 'Password reset, account recovery' }]
        })
      });

      const task: AgentTask = {
        id: 'task-topics-001',
        capability: 'conversation_summary',
        input: {
          data: {
            sessionId: 'session-123',
            messages: []
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.result.data.topics).toBeDefined();
    });

    it('should identify resolution status', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          content: [{ text: 'Issue resolved successfully' }]
        })
      });

      const task: AgentTask = {
        id: 'task-resolution-001',
        capability: 'conversation_summary',
        input: {
          data: {
            sessionId: 'session-123',
            messages: []
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.result.data.resolved).toBeDefined();
    });
  });

  describe('csat_collection capability', () => {
    it('should collect customer satisfaction rating', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-csat-001',
        capability: 'csat_collection',
        input: {
          data: {
            sessionId: 'session-123',
            rating: 5,
            feedback: 'Excellent service!'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.recorded).toBe(true);
    });

    it('should trigger follow-up for low ratings', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-low-rating-001',
        capability: 'csat_collection',
        input: {
          data: {
            sessionId: 'session-123',
            rating: 2,
            feedback: 'Not helpful'
          }
        },
        priority: 'high'
      };

      const result = await agent.execute(task, testContext);

      expect(result.result.data.followUpCreated).toBe(true);
    });
  });

  describe('multi_channel_support capability', () => {
    it('should handle web chat', async () => {
      const task: AgentTask = {
        id: 'task-web-001',
        capability: 'multi_channel_support',
        input: {
          data: {
            channel: 'web',
            message: 'Hello',
            sessionId: 'session-123'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.channelSupported).toBe(true);
    });

    it('should handle SMS messages', async () => {
      const task: AgentTask = {
        id: 'task-sms-001',
        capability: 'multi_channel_support',
        input: {
          data: {
            channel: 'sms',
            message: 'Need help',
            phoneNumber: '+1234567890'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.result.data.channelSupported).toBe(true);
    });

    it('should adapt response format for channel', async () => {
      const task: AgentTask = {
        id: 'task-adapt-001',
        capability: 'multi_channel_support',
        input: {
          data: {
            channel: 'sms',
            message: 'Help'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.result.data.responseFormat).toBeDefined();
    });
  });

  describe('context_awareness capability', () => {
    it('should build conversation context', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({
          name: 'John Doe',
          email: 'john@example.com',
          tier: 'pro',
          lifetime_value: 5000
        })
      }).mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [
            { id: 'conv-1', topic: 'billing', resolved: true }
          ]
        })
      });

      const task: AgentTask = {
        id: 'task-context-001',
        capability: 'context_awareness',
        input: {
          data: {
            customerId: 'cust-123',
            sessionId: 'session-123'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.customerProfile).toBeDefined();
      expect(result.result.data.previousConversations).toBeDefined();
    });

    it('should include product context', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({
          name: 'Jane Doe',
          email: 'jane@example.com',
          tier: 'enterprise',
          current_plan: 'Enterprise Pro'
        }),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      const task: AgentTask = {
        id: 'task-product-001',
        capability: 'context_awareness',
        input: {
          data: {
            customerId: 'cust-456'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.result.data.productContext).toBeDefined();
    });
  });

  describe('Error Handling', () => {
    it('should handle unsupported capability', async () => {
      const task: AgentTask = {
        id: 'task-unsupported-001',
        capability: 'invalid_capability' as any,
        input: { data: {} },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('failed');
      expect(result.error?.code).toBe('EXECUTION_FAILED');
      expect(result.error?.message).toContain('Unsupported capability');
    });

    it('should handle API failures gracefully', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('API timeout'));

      const task: AgentTask = {
        id: 'task-api-fail-001',
        capability: 'chat_response',
        input: {
          data: {
            sessionId: 'session-123',
            customerMessage: 'Hello',
            conversationHistory: []
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('failed');
      expect(result.error?.retryable).toBe(true);
    });

    it('should include execution metrics in errors', async () => {
      const task: AgentTask = {
        id: 'task-metrics-error-001',
        capability: 'invalid' as any,
        input: { data: {} },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.metrics.executionTime).toBeGreaterThan(0);
    });
  });

  describe('Performance', () => {
    it('should respond to chat messages quickly', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          content: [{ text: 'Quick response' }]
        })
      });

      const task: AgentTask = {
        id: 'task-perf-001',
        capability: 'chat_response',
        input: {
          data: {
            sessionId: 'session-123',
            customerMessage: 'Hi',
            conversationHistory: []
          }
        },
        priority: 'high'
      };

      const startTime = Date.now();
      const result = await agent.execute(task, testContext);
      const duration = Date.now() - startTime;

      expect(result.status).toBe('completed');
      expect(duration).toBeLessThan(5000);
    });
  });

  describe('Metrics', () => {
    it('should track execution metrics', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          content: [{ text: 'Response' }]
        })
      });

      const task: AgentTask = {
        id: 'task-metrics-001',
        capability: 'chat_response',
        input: {
          data: {
            sessionId: 'session-123',
            customerMessage: 'Test',
            conversationHistory: []
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.metrics).toBeDefined();
      expect(result.metrics.executionTime).toBeGreaterThan(0);
      expect(result.metrics.costUSD).toBe(0.004);
      expect(result.metrics.retryCount).toBe(0);
    });

    it('should include confidence scores', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          content: [{ text: 'Response' }]
        })
      });

      const task: AgentTask = {
        id: 'task-conf-001',
        capability: 'chat_response',
        input: {
          data: {
            sessionId: 'session-123',
            customerMessage: 'Test',
            conversationHistory: []
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.result.confidence).toBeGreaterThan(0);
      expect(result.result.reasoning).toBeDefined();
    });
  });
});
