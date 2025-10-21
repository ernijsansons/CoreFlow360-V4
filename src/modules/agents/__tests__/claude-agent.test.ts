/**
 * Claude Agent Test Suite
 * Comprehensive tests for Anthropic Claude integration
 * Target: 95%+ test coverage
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { ClaudeAgent } from '../claude-agent';
import type { AgentTask, BusinessContext } from '../types';

describe('ClaudeAgent', () => {
  let agent: ClaudeAgent;
  let mockEnv: any;
  let testContext: BusinessContext;

  beforeEach(() => {
    mockEnv = {
      ANTHROPIC_API_KEY: 'test-api-key-12345'
    };

    agent = new ClaudeAgent(mockEnv);

    testContext = {
      userId: 'user-123',
      businessId: 'biz-123',
      organizationId: 'org-123',
      timestamp: new Date().toISOString(),
      requestId: 'req-123',
      userPermissions: ['read', 'write'],
      preferences: {},
      businessData: {
        companyName: 'Test Company',
        industry: 'Technology',
        companySize: 'medium'
      }
    };

    // Reset fetch mock
    global.fetch = vi.fn();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('Agent Configuration', () => {
    it('should initialize with default configuration', () => {
      expect(agent.id).toBeDefined();
      expect(agent.name).toBeDefined();
      expect(agent.type).toBe('external');
      expect(agent.version).toBe('3.5.0');
    });

    it('should have required capabilities', async () => {
      const config = await agent.getConfig();

      expect(config.capabilities).toContain('analysis');
      expect(config.capabilities).toContain('generation');
      expect(config.capabilities).toContain('reasoning');
      expect(config.capabilities).toContain('planning');
    });

    it('should support multiple departments', async () => {
      const config = await agent.getConfig();

      expect(config.departments).toBeDefined();
      expect(Array.isArray(config.departments)).toBe(true);
    });

    it('should have production tags', () => {
      expect(agent.tags).toContain('llm');
      expect(agent.tags).toContain('anthropic');
      expect(agent.tags).toContain('production');
      expect(agent.tags).toContain('multi-modal');
    });

    it('should support multiple languages', () => {
      expect(agent.supportedLanguages).toContain('en');
      expect(agent.supportedLanguages).toContain('es');
      expect(agent.supportedLanguages).toContain('fr');
      expect(agent.supportedLanguages).toContain('de');
    });

    it('should support multiple output formats', () => {
      expect(agent.supportedFormats).toContain('text');
      expect(agent.supportedFormats).toContain('json');
      expect(agent.supportedFormats).toContain('markdown');
      expect(agent.supportedFormats).toContain('csv');
      expect(agent.supportedFormats).toContain('xml');
    });

    it('should have reasonable cost per call', async () => {
      const config = await agent.getConfig();

      expect(config.costPerCall).toBeGreaterThan(0);
      expect(config.costPerCall).toBeLessThan(1); // Should be under $1
    });

    it('should estimate task cost', async () => {
      const task: AgentTask = {
        id: 'task-001',
        capability: 'analysis',
        input: { data: { query: 'Test query' } },
        priority: 'normal'
      };

      const cost = await agent.estimateCost(task);

      expect(cost).toBeGreaterThan(0);
    });
  });

  describe('analysis capability', () => {
    it('should perform financial analysis', async () => {
      const mockResponse: any = {
        id: 'msg-123',
        type: 'message',
        role: 'assistant',
        content: [
          {
            type: 'text',
            text: 'Financial analysis shows revenue trending upward with 15% growth.'
          }
        ],
        model: 'claude-3-5-sonnet-20241022',
        stop_reason: 'end_turn',
        usage: {
          input_tokens: 150,
          output_tokens: 200
        }
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockResponse
      });

      const task: AgentTask = {
        id: 'task-fin-001',
        capability: 'analysis',
        input: {
          data: {
            analysisType: 'financial',
            data: {
              revenue: [100000, 110000, 115000],
              expenses: [80000, 85000, 87000]
            }
          }
        },
        priority: 'high'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data).toBeDefined();
      expect(result.metrics.tokensUsed).toBe(350);
      expect(result.metrics.costUSD).toBeGreaterThan(0);
    });

    it('should analyze customer sentiment', async () => {
      const mockResponse: any = {
        id: 'msg-456',
        type: 'message',
        role: 'assistant',
        content: [
          {
            type: 'text',
            text: 'Sentiment: Negative. Customer expresses frustration with service delays.'
          }
        ],
        model: 'claude-3-5-sonnet-20241022',
        stop_reason: 'end_turn',
        usage: {
          input_tokens: 100,
          output_tokens: 150
        }
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockResponse
      });

      const task: AgentTask = {
        id: 'task-sent-001',
        capability: 'analysis',
        input: {
          data: {
            analysisType: 'sentiment',
            text: 'This service is terrible! I have been waiting for 2 weeks!'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data).toContain('Negative');
    });

    it('should perform market analysis', async () => {
      const mockResponse: any = {
        id: 'msg-789',
        type: 'message',
        role: 'assistant',
        content: [
          {
            type: 'text',
            text: 'Market analysis indicates strong demand in the enterprise segment.'
          }
        ],
        model: 'claude-3-5-sonnet-20241022',
        stop_reason: 'end_turn',
        usage: {
          input_tokens: 200,
          output_tokens: 300
        }
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockResponse
      });

      const task: AgentTask = {
        id: 'task-market-001',
        capability: 'analysis',
        input: {
          data: {
            analysisType: 'market',
            market: 'SaaS',
            competitors: ['Competitor A', 'Competitor B']
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data).toBeDefined();
    });

    it('should handle API errors gracefully', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 429,
        statusText: 'Too Many Requests',
        json: async () => ({
          error: {
            type: 'rate_limit_error',
            message: 'Rate limit exceeded'
          }
        })
      });

      const task: AgentTask = {
        id: 'task-error-001',
        capability: 'analysis',
        input: {
          data: {
            analysisType: 'financial',
            data: {}
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('failed');
      expect(result.error).toBeDefined();
      expect(result.error?.code).toBe('RATE_LIMIT_EXCEEDED');
    });

    it('should retry on transient failures', async () => {
      global.fetch = vi.fn()
        .mockResolvedValueOnce({
          ok: false,
          status: 500,
          statusText: 'Internal Server Error'
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            id: 'msg-retry',
            type: 'message',
            role: 'assistant',
            content: [{ type: 'text', text: 'Success after retry' }],
            model: 'claude-3-5-sonnet-20241022',
            stop_reason: 'end_turn',
            usage: { input_tokens: 50, output_tokens: 100 }
          })
        });

      const task: AgentTask = {
        id: 'task-retry-001',
        capability: 'analysis',
        input: {
          data: {
            analysisType: 'simple',
            query: 'test'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.metrics.retryCount).toBeGreaterThan(0);
    });
  });

  describe('generation capability', () => {
    it('should generate content', async () => {
      const mockResponse: any = {
        id: 'msg-gen-001',
        type: 'message',
        role: 'assistant',
        content: [
          {
            type: 'text',
            text: '# Welcome to Our Platform\n\nThis comprehensive guide will help you get started...'
          }
        ],
        model: 'claude-3-5-sonnet-20241022',
        stop_reason: 'end_turn',
        usage: {
          input_tokens: 100,
          output_tokens: 500
        }
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockResponse
      });

      const task: AgentTask = {
        id: 'task-gen-001',
        capability: 'generation',
        input: {
          data: {
            contentType: 'documentation',
            topic: 'Getting Started Guide',
            format: 'markdown'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data).toContain('Welcome');
    });

    it('should generate JSON output', async () => {
      const mockResponse: any = {
        id: 'msg-json-001',
        type: 'message',
        role: 'assistant',
        content: [
          {
            type: 'text',
            text: '{"name":"John Doe","email":"john@example.com","role":"developer"}'
          }
        ],
        model: 'claude-3-5-sonnet-20241022',
        stop_reason: 'end_turn',
        usage: {
          input_tokens: 80,
          output_tokens: 120
        }
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockResponse
      });

      const task: AgentTask = {
        id: 'task-json-001',
        capability: 'generation',
        input: {
          data: {
            contentType: 'structured',
            format: 'json',
            schema: {
              name: 'string',
              email: 'string',
              role: 'string'
            }
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(() => JSON.parse(result.result.data)).not.toThrow();
    });

    it('should generate code', async () => {
      const mockResponse: any = {
        id: 'msg-code-001',
        type: 'message',
        role: 'assistant',
        content: [
          {
            type: 'text',
            text: 'function calculateTotal(items) {\n  return items.reduce((sum, item) => sum + item.price, 0);\n}'
          }
        ],
        model: 'claude-3-5-sonnet-20241022',
        stop_reason: 'end_turn',
        usage: {
          input_tokens: 120,
          output_tokens: 200
        }
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockResponse
      });

      const task: AgentTask = {
        id: 'task-code-001',
        capability: 'generation',
        input: {
          data: {
            contentType: 'code',
            language: 'javascript',
            description: 'Function to calculate total from array of items'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data).toContain('function');
    });

    it('should respect temperature setting', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          id: 'msg-temp-001',
          type: 'message',
          role: 'assistant',
          content: [{ type: 'text', text: 'Creative response' }],
          model: 'claude-3-5-sonnet-20241022',
          stop_reason: 'end_turn',
          usage: { input_tokens: 50, output_tokens: 100 }
        })
      });

      const task: AgentTask = {
        id: 'task-temp-001',
        capability: 'generation',
        input: {
          data: {
            contentType: 'creative',
            temperature: 0.8
          }
        },
        priority: 'normal'
      };

      await agent.execute(task, testContext);

      expect(global.fetch).toHaveBeenCalled();
      const fetchCall = (global.fetch as any).mock.calls[0];
      const requestBody = JSON.parse(fetchCall[1].body);
      expect(requestBody.temperature).toBeGreaterThan(0.1);
    });
  });

  describe('reasoning capability', () => {
    it('should perform logical reasoning', async () => {
      const mockResponse: any = {
        id: 'msg-reason-001',
        type: 'message',
        role: 'assistant',
        content: [
          {
            type: 'text',
            text: 'Based on the premises: 1) All employees must complete training, 2) John is an employee. Therefore: John must complete training.'
          }
        ],
        model: 'claude-3-5-sonnet-20241022',
        stop_reason: 'end_turn',
        usage: {
          input_tokens: 150,
          output_tokens: 250
        }
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockResponse
      });

      const task: AgentTask = {
        id: 'task-reason-001',
        capability: 'reasoning',
        input: {
          data: {
            problem: 'If all employees must complete training, and John is an employee, what must John do?',
            context: ['All employees must complete training', 'John is an employee']
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data).toContain('training');
    });

    it('should solve business problems', async () => {
      const mockResponse: any = {
        id: 'msg-problem-001',
        type: 'message',
        role: 'assistant',
        content: [
          {
            type: 'text',
            text: 'To reduce customer churn: 1) Improve onboarding, 2) Increase engagement, 3) Proactive support.'
          }
        ],
        model: 'claude-3-5-sonnet-20241022',
        stop_reason: 'end_turn',
        usage: {
          input_tokens: 200,
          output_tokens: 300
        }
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockResponse
      });

      const task: AgentTask = {
        id: 'task-problem-001',
        capability: 'reasoning',
        input: {
          data: {
            problem: 'How can we reduce customer churn?',
            constraints: ['Limited budget', '3-month timeline']
          }
        },
        priority: 'high'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data).toContain('churn');
    });

    it('should provide step-by-step reasoning', async () => {
      const mockResponse: any = {
        id: 'msg-steps-001',
        type: 'message',
        role: 'assistant',
        content: [
          {
            type: 'text',
            text: 'Step 1: Identify problem\nStep 2: Analyze root cause\nStep 3: Propose solutions\nStep 4: Evaluate options'
          }
        ],
        model: 'claude-3-5-sonnet-20241022',
        stop_reason: 'end_turn',
        usage: {
          input_tokens: 100,
          output_tokens: 200
        }
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockResponse
      });

      const task: AgentTask = {
        id: 'task-steps-001',
        capability: 'reasoning',
        input: {
          data: {
            problem: 'Sales are declining',
            requireSteps: true
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data).toContain('Step');
    });
  });

  describe('planning capability', () => {
    it('should create project plans', async () => {
      const mockResponse: any = {
        id: 'msg-plan-001',
        type: 'message',
        role: 'assistant',
        content: [
          {
            type: 'text',
            text: 'Project Plan:\n1. Requirements Gathering (Week 1-2)\n2. Design (Week 3-4)\n3. Development (Week 5-8)\n4. Testing (Week 9-10)'
          }
        ],
        model: 'claude-3-5-sonnet-20241022',
        stop_reason: 'end_turn',
        usage: {
          input_tokens: 180,
          output_tokens: 320
        }
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockResponse
      });

      const task: AgentTask = {
        id: 'task-plan-001',
        capability: 'planning',
        input: {
          data: {
            projectType: 'software',
            goals: ['Build user authentication', 'Create dashboard'],
            timeline: '10 weeks',
            resources: 3
          }
        },
        priority: 'high'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data).toContain('Week');
    });

    it('should create budget plans', async () => {
      const mockResponse: any = {
        id: 'msg-budget-001',
        type: 'message',
        role: 'assistant',
        content: [
          {
            type: 'text',
            text: 'Budget Allocation:\n- Personnel: 60%\n- Technology: 25%\n- Marketing: 10%\n- Contingency: 5%'
          }
        ],
        model: 'claude-3-5-sonnet-20241022',
        stop_reason: 'end_turn',
        usage: {
          input_tokens: 150,
          output_tokens: 250
        }
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockResponse
      });

      const task: AgentTask = {
        id: 'task-budget-001',
        capability: 'planning',
        input: {
          data: {
            planType: 'budget',
            totalBudget: 500000,
            categories: ['Personnel', 'Technology', 'Marketing']
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data).toContain('Budget');
    });

    it('should create growth strategies', async () => {
      const mockResponse: any = {
        id: 'msg-growth-001',
        type: 'message',
        role: 'assistant',
        content: [
          {
            type: 'text',
            text: 'Growth Strategy:\n1. Expand to new markets\n2. Improve customer retention\n3. Launch new product lines'
          }
        ],
        model: 'claude-3-5-sonnet-20241022',
        stop_reason: 'end_turn',
        usage: {
          input_tokens: 200,
          output_tokens: 300
        }
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockResponse
      });

      const task: AgentTask = {
        id: 'task-growth-001',
        capability: 'planning',
        input: {
          data: {
            planType: 'growth',
            currentRevenue: 1000000,
            targetRevenue: 2000000,
            timeframe: '12 months'
          }
        },
        priority: 'high'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data).toContain('Growth');
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid API key', async () => {
      const invalidEnv = { ANTHROPIC_API_KEY: 'invalid-key' };
      const invalidAgent = new ClaudeAgent(invalidEnv);

      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        json: async () => ({
          error: {
            type: 'authentication_error',
            message: 'Invalid API key'
          }
        })
      });

      const task: AgentTask = {
        id: 'task-auth-001',
        capability: 'analysis',
        input: { data: { query: 'test' } },
        priority: 'normal'
      };

      const result = await invalidAgent.execute(task, testContext);

      expect(result.status).toBe('failed');
      expect(result.error?.code).toBe('AUTHENTICATION_ERROR');
    });

    it('should handle network errors', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('Network timeout'));

      const task: AgentTask = {
        id: 'task-network-001',
        capability: 'analysis',
        input: { data: { query: 'test' } },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('failed');
      expect(result.error?.retryable).toBe(true);
    });

    it('should handle unsupported capability', async () => {
      const task: AgentTask = {
        id: 'task-unsupported-001',
        capability: 'invalid_capability' as any,
        input: { data: {} },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('failed');
      expect(result.error?.message).toContain('Unsupported');
    });

    it('should handle malformed responses', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          // Missing required fields
          id: 'msg-malformed',
          type: 'message'
        })
      });

      const task: AgentTask = {
        id: 'task-malformed-001',
        capability: 'analysis',
        input: { data: { query: 'test' } },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('failed');
    });

    it('should include execution time in error response', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('Test error'));

      const task: AgentTask = {
        id: 'task-timing-001',
        capability: 'analysis',
        input: { data: { query: 'test' } },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.metrics.executionTime).toBeGreaterThan(0);
    });
  });

  describe('Validation', () => {
    it('should validate input data', async () => {
      const validationResult = await agent.validateInput({
        capability: 'analysis',
        input: { data: { query: 'test' } }
      } as AgentTask);

      expect(validationResult.isValid).toBe(true);
    });

    it('should detect missing required fields', async () => {
      const validationResult = await agent.validateInput({
        capability: 'analysis',
        input: { data: {} }
      } as AgentTask);

      expect(validationResult.isValid).toBe(false);
      expect(validationResult.errors).toBeDefined();
    });

    it('should validate data types', async () => {
      const validationResult = await agent.validateInput({
        capability: 'planning',
        input: {
          data: {
            budget: 'not-a-number' // Should be number
          }
        }
      } as AgentTask);

      expect(validationResult.isValid).toBe(false);
    });
  });

  describe('Health Check', () => {
    it('should return healthy status', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          id: 'msg-health',
          type: 'message',
          role: 'assistant',
          content: [{ type: 'text', text: 'OK' }],
          model: 'claude-3-5-sonnet-20241022',
          stop_reason: 'end_turn',
          usage: { input_tokens: 10, output_tokens: 20 }
        })
      });

      const health = await agent.healthCheck();

      expect(health.status).toBe('healthy');
      expect(health.latency).toBeGreaterThan(0);
    });

    it('should detect unhealthy state', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('Service unavailable'));

      const health = await agent.healthCheck();

      expect(health.status).toBe('unhealthy');
      expect(health.message).toBeDefined();
    });
  });

  describe('Performance', () => {
    it('should complete tasks within timeout', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          id: 'msg-perf',
          type: 'message',
          role: 'assistant',
          content: [{ type: 'text', text: 'Quick response' }],
          model: 'claude-3-5-sonnet-20241022',
          stop_reason: 'end_turn',
          usage: { input_tokens: 50, output_tokens: 100 }
        })
      });

      const task: AgentTask = {
        id: 'task-perf-001',
        capability: 'analysis',
        input: { data: { query: 'test' } },
        priority: 'high'
      };

      const startTime = Date.now();
      const result = await agent.execute(task, testContext);
      const duration = Date.now() - startTime;

      expect(result.status).toBe('completed');
      expect(duration).toBeLessThan(10000); // Should complete in under 10s
    });

    it('should track token usage', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          id: 'msg-tokens',
          type: 'message',
          role: 'assistant',
          content: [{ type: 'text', text: 'Response' }],
          model: 'claude-3-5-sonnet-20241022',
          stop_reason: 'end_turn',
          usage: {
            input_tokens: 150,
            output_tokens: 300
          }
        })
      });

      const task: AgentTask = {
        id: 'task-tokens-001',
        capability: 'generation',
        input: { data: { contentType: 'text' } },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.metrics.tokensUsed).toBe(450);
    });

    it('should calculate cost correctly', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          id: 'msg-cost',
          type: 'message',
          role: 'assistant',
          content: [{ type: 'text', text: 'Response' }],
          model: 'claude-3-5-sonnet-20241022',
          stop_reason: 'end_turn',
          usage: {
            input_tokens: 1000,
            output_tokens: 2000
          }
        })
      });

      const task: AgentTask = {
        id: 'task-cost-001',
        capability: 'generation',
        input: { data: { contentType: 'text' } },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.metrics.costUSD).toBeGreaterThan(0);
      expect(result.metrics.tokensUsed).toBe(3000);
    });
  });

  describe('Metrics', () => {
    it('should track execution metrics', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          id: 'msg-metrics',
          type: 'message',
          role: 'assistant',
          content: [{ type: 'text', text: 'Response' }],
          model: 'claude-3-5-sonnet-20241022',
          stop_reason: 'end_turn',
          usage: { input_tokens: 100, output_tokens: 200 }
        })
      });

      const task: AgentTask = {
        id: 'task-metrics-001',
        capability: 'analysis',
        input: { data: { query: 'test' } },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.metrics).toBeDefined();
      expect(result.metrics.executionTime).toBeGreaterThan(0);
      expect(result.metrics.tokensUsed).toBe(300);
      expect(result.metrics.costUSD).toBeGreaterThan(0);
      expect(result.metrics.retryCount).toBeDefined();
    });

    it('should include timestamps', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          id: 'msg-time',
          type: 'message',
          role: 'assistant',
          content: [{ type: 'text', text: 'Response' }],
          model: 'claude-3-5-sonnet-20241022',
          stop_reason: 'end_turn',
          usage: { input_tokens: 50, output_tokens: 100 }
        })
      });

      const task: AgentTask = {
        id: 'task-time-001',
        capability: 'analysis',
        input: { data: { query: 'test' } },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.startedAt).toBeDefined();
      expect(result.completedAt).toBeDefined();
      expect(result.completedAt).toBeGreaterThan(result.startedAt);
    });
  });
});
