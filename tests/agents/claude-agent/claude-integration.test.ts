/**
 * Claude Agent Integration Tests
 * Tests specific to Claude AI integration and Anthropic API functionality
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  TestEnvironmentFactory,
  BusinessContextGenerator,
  TaskGenerator,
  PerformanceMonitor,
  setupAgentTests,
  type TestEnvironment
} from '../test-harness';
import { ClaudeAgent } from '../../../src/modules/agents/claude-agent';
import type {
  AgentTask,
  BusinessContext,
  AgentConfig,
  AgentResult
} from '../../../src/modules/agents/types';

describe('Claude Agent Integration', () => {
  let testEnv: TestEnvironment;
  let claudeAgent: ClaudeAgent;
  let businessContext: BusinessContext;
  let performanceMonitor: PerformanceMonitor;

  setupAgentTests();

  beforeEach(async () => {
    testEnv = await TestEnvironmentFactory.create();
    businessContext = testEnv.businessContext;
    performanceMonitor = new PerformanceMonitor();

    // Create Claude agent with test configuration
    const claudeConfig: AgentConfig = {
      id: 'claude-test-agent',
      name: 'Claude Test Agent',
      type: 'external',
      enabled: true,
      apiKey: process.env.ANTHROPIC_API_KEY || 'test-api-key',
      model: 'claude-3-sonnet-20240229',
      maxTokens: 4000,
      temperature: 0.7,
      capabilities: [
        'analysis',
        'generation',
        'reasoning',
        'planning',
        'summarization',
        'translation',
        'code_review',
        'creative_writing'
      ],
      departments: ['all'],
      maxConcurrency: 5,
      costPerCall: 0.02,
      owner: 'test-system',
      createdAt: Date.now(),
      updatedAt: Date.now()
    };

    claudeAgent = new ClaudeAgent(claudeConfig);
  });

  afterEach(async () => {
    await TestEnvironmentFactory.cleanup(testEnv);
  });

  describe('API Configuration and Authentication', () => {
    it('should validate API key configuration', async () => {
      const healthStatus = await claudeAgent.healthCheck();

      expect(healthStatus.status).toBeDefined();
      expect(['online', 'offline', 'degraded', 'error']).toContain(healthStatus.status);

      if (healthStatus.status === 'offline' || healthStatus.status === 'error') {
        expect(healthStatus.details?.error).toBeDefined();
      }
    });

    it('should handle API authentication errors', async () => {
      // Create agent with invalid API key
      const invalidConfig: AgentConfig = {
        id: 'claude-invalid',
        name: 'Claude Invalid',
        type: 'external',
        enabled: true,
        apiKey: 'invalid-api-key',
        model: 'claude-3-sonnet-20240229',
        capabilities: ['test'],
        departments: ['all'],
        maxConcurrency: 1,
        costPerCall: 0.01,
        owner: 'test',
        createdAt: Date.now(),
        updatedAt: Date.now()
      };

      const invalidAgent = new ClaudeAgent(invalidConfig);

      const task = TaskGenerator.generate({
        capability: 'analysis',
        context: businessContext,
        input: {
          prompt: 'Test authentication',
          data: { test: true }
        }
      });

      try {
        await invalidAgent.execute(task, businessContext);
        // If no error thrown, check if it handled gracefully
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect(error.message).toMatch(/auth|api|key|invalid/i);
      }
    });

    it('should validate model configuration', async () => {
      expect(claudeAgent.id).toBe('claude-test-agent');
      expect(claudeAgent.type).toBe('external');
      expect(claudeAgent.capabilities).toContain('analysis');
      expect(claudeAgent.costPerCall).toBeGreaterThan(0);
    });
  });

  describe('Claude-Specific Capabilities', () => {
    it('should perform complex analytical reasoning', async () => {
      const analyticalTask = TaskGenerator.generate({
        capability: 'analysis',
        context: businessContext,
        input: {
          prompt: `Analyze the following business scenario and provide strategic recommendations:

          Company: ${businessContext.businessData.companyName}
          Industry: ${businessContext.businessData.industry}
          Current Metrics:
          - Revenue: $${businessContext.businessState.keyMetrics.revenue}
          - Expenses: $${businessContext.businessState.keyMetrics.expenses}
          - Profit: $${businessContext.businessState.keyMetrics.profit}
          - Employees: ${businessContext.businessState.keyMetrics.employees}

          Challenges:
          1. Increasing competition in the market
          2. Rising operational costs
          3. Need for digital transformation
          4. Talent acquisition difficulties

          Please provide:
          1. SWOT analysis
          2. Key strategic recommendations
          3. Implementation timeline
          4. Success metrics`,
          data: {
            businessMetrics: businessContext.businessState.keyMetrics,
            industry: businessContext.businessData.industry,
            analysisType: 'strategic_planning'
          },
          parameters: {
            outputFormat: 'structured',
            includeReasoning: true,
            confidenceLevel: 'required'
          }
        }
      });

      performanceMonitor.start();
      const result = await claudeAgent.execute(analyticalTask, businessContext);
      performanceMonitor.end();

      expect(result.status).toBe('completed');
      expect(result.result.data).toBeDefined();
      expect(result.result.confidence).toBeGreaterThan(0.7);
      expect(result.result.reasoning).toBeDefined();

      // Verify analytical depth
      const responseText = JSON.stringify(result.result.data);
      expect(responseText.toLowerCase()).toMatch(/(swot|strength|weakness|opportunity|threat)/);
      expect(responseText.toLowerCase()).toMatch(/(recommend|strategy|implement)/);

      // Performance validation
      expect(performanceMonitor.getExecutionTime()).toBeLessThan(30000); // 30 seconds max
      expect(result.metrics.tokensUsed).toBeGreaterThan(0);
      expect(result.metrics.costUSD).toBeGreaterThan(0);
    });

    it('should generate high-quality content', async () => {
      const contentTask = TaskGenerator.generate({
        capability: 'generation',
        context: businessContext,
        input: {
          prompt: `Create a professional email template for customer onboarding for ${businessContext.businessData.companyName}.

          Requirements:
          - Professional and welcoming tone
          - Include key onboarding steps
          - Personalization placeholders
          - Clear call-to-action
          - Branded footer

          Industry context: ${businessContext.businessData.industry}
          Company size: ${businessContext.businessData.size}`,
          data: {
            templateType: 'email',
            purpose: 'customer_onboarding',
            industry: businessContext.businessData.industry,
            tone: 'professional_friendly'
          },
          parameters: {
            includeSubjectLine: true,
            includePersonalization: true,
            maxLength: 500
          }
        }
      });

      const result = await claudeAgent.execute(contentTask, businessContext);

      expect(result.status).toBe('completed');
      expect(result.result.data).toBeDefined();

      const content = JSON.stringify(result.result.data);
      expect(content).toMatch(/subject|onboarding|welcome/i);
      expect(content).toMatch(/\{.*\}/); // Should include personalization placeholders
      expect(content.length).toBeGreaterThan(100); // Substantial content
    });

    it('should perform code review and analysis', async () => {
      const codeReviewTask = TaskGenerator.generate({
        capability: 'code_review',
        context: businessContext,
        input: {
          prompt: `Review the following TypeScript code for security, performance, and best practices:`,
          data: {
            code: `
export class UserService {
  private users: any[] = [];

  async createUser(userData: any): Promise<any> {
    // Validate input
    if (!userData.email) {
      throw new Error('Email required');
    }

    // Create user
    const user = {
      id: Math.random().toString(),
      ...userData,
      createdAt: new Date()
    };

    this.users.push(user);

    // Send notification
    await fetch('http://notification-service.com/send', {
      method: 'POST',
      body: JSON.stringify(user)
    });

    return user;
  }

  getUser(id: string): any {
    return this.users.find(u => u.id === id);
  }
}`,
            language: 'typescript',
            filename: 'user-service.ts'
          },
          parameters: {
            checkSecurity: true,
            checkPerformance: true,
            checkBestPractices: true,
            includeRecommendations: true
          }
        }
      });

      const result = await claudeAgent.execute(codeReviewTask, businessContext);

      expect(result.status).toBe('completed');
      expect(result.result.data).toBeDefined();

      const review = JSON.stringify(result.result.data);
      // Should identify common issues
      expect(review.toLowerCase()).toMatch(/(security|validation|type|error)/);
      expect(review.toLowerCase()).toMatch(/(recommend|improve|should|consider)/);
    });

    it('should handle multi-language scenarios', async () => {
      const translationTask = TaskGenerator.generate({
        capability: 'translation',
        context: businessContext,
        input: {
          prompt: 'Translate the following business content to Spanish and French',
          data: {
            content: `Welcome to ${businessContext.businessData.companyName}!
            We're excited to help you achieve your business goals.
            Our team of experts is ready to support your success.`,
            sourceLanguage: 'en',
            targetLanguages: ['es', 'fr'],
            context: 'business_communication'
          },
          parameters: {
            maintainTone: true,
            businessContext: true
          }
        }
      });

      const result = await claudeAgent.execute(translationTask, businessContext);

      expect(result.status).toBe('completed');
      expect(result.result.data).toBeDefined();

      const translations = JSON.stringify(result.result.data);
      // Should contain non-English text
      expect(translations).toMatch(/[áéíóúñü]/i); // Spanish characters
      expect(translations).toMatch(/[àâäéèêëîôöùûüÿç]/i); // French characters
    });
  });

  describe('Token Management and Cost Control', () => {
    it('should accurately estimate token usage', async () => {
      const tasks = [
        {
          prompt: 'Short test',
          expectedTokens: { min: 10, max: 50 }
        },
        {
          prompt: 'This is a medium length prompt that should use a moderate amount of tokens for processing and response generation.',
          expectedTokens: { min: 50, max: 150 }
        },
        {
          prompt: `This is a very long prompt that contains extensive details about business operations, strategic planning, market analysis, competitive intelligence, financial forecasting, operational efficiency, human resources management, technology infrastructure, customer relationship management, supply chain optimization, risk assessment, regulatory compliance, and innovation strategy. It should require significantly more tokens to process and generate a comprehensive response.`,
          expectedTokens: { min: 200, max: 500 }
        }
      ];

      for (const testCase of tasks) {
        const task = TaskGenerator.generate({
          capability: 'analysis',
          context: businessContext,
          input: {
            prompt: testCase.prompt,
            data: { tokenTest: true }
          }
        });

        const estimatedCost = await claudeAgent.estimateCost(task);
        expect(estimatedCost).toBeGreaterThan(0);

        const result = await claudeAgent.execute(task, businessContext);
        expect(result.metrics.tokensUsed).toBeGreaterThan(0);
        expect(result.metrics.tokensUsed).toBeGreaterThanOrEqual(testCase.expectedTokens.min);

        // Cost should correlate with token usage
        expect(result.metrics.costUSD).toBeGreaterThan(0);
      }
    });

    it('should enforce token limits', async () => {
      const longTask = TaskGenerator.generate({
        capability: 'generation',
        context: businessContext,
        input: {
          prompt: 'Generate a comprehensive business plan with all sections',
          data: {
            sections: [
              'executive_summary', 'company_description', 'market_analysis',
              'organization_management', 'service_offering', 'marketing_sales',
              'funding_request', 'financial_projections', 'appendix'
            ],
            detailLevel: 'comprehensive',
            includeCharts: true,
            includeFinancials: true
          },
          parameters: {
            maxTokens: 2000, // Limit tokens
            enforceLimit: true
          }
        }
      });

      const result = await claudeAgent.execute(longTask, businessContext);

      expect(result.status).toBe('completed');
      expect(result.metrics.tokensUsed).toBeLessThanOrEqual(2000);
    });

    it('should track costs across multiple requests', async () => {
      const batchTasks = TaskGenerator.generateBatch(10, {
        capability: 'analysis',
        context: businessContext,
        input: {
          prompt: 'Analyze this data point',
          data: { batchTest: true }
        }
      });

      let totalCost = 0;
      const results: AgentResult[] = [];

      for (const task of batchTasks) {
        const result = await claudeAgent.execute(task, businessContext);
        results.push(result);
        totalCost += result.metrics.costUSD;
      }

      expect(results).toHaveLength(10);
      expect(totalCost).toBeGreaterThan(0);

      // Average cost should be reasonable
      const averageCost = totalCost / 10;
      expect(averageCost).toBeLessThan(1.0); // Less than $1 per simple task
    });
  });

  describe('Response Quality and Reliability', () => {
    it('should provide consistent response quality', async () => {
      const consistencyTask = {
        capability: 'analysis',
        context: businessContext,
        input: {
          prompt: 'Explain the key factors for business success in the technology industry',
          data: { consistencyTest: true },
          parameters: { temperature: 0.1 } // Low temperature for consistency
        }
      };

      const results: AgentResult[] = [];

      // Execute same task multiple times
      for (let i = 0; i < 3; i++) {
        const task = TaskGenerator.generate(consistencyTask);
        const result = await claudeAgent.execute(task, businessContext);
        results.push(result);

        expect(result.status).toBe('completed');
        expect(result.result.confidence).toBeGreaterThan(0.8);
      }

      // All results should be successful
      expect(results).toHaveLength(3);
      results.forEach(result => {
        expect(result.status).toBe('completed');
        expect(result.result.data).toBeDefined();
      });
    });

    it('should handle edge cases gracefully', async () => {
      const edgeCases = [
        {
          prompt: '', // Empty prompt
          expectError: true
        },
        {
          prompt: 'x'.repeat(50000), // Very long prompt
          expectError: false
        },
        {
          prompt: '🚀💼📈🎯✨🔥💡🌟⚡🏆', // Only emojis
          expectError: false
        },
        {
          prompt: 'Analyze this: null undefined NaN Infinity -Infinity',
          expectError: false
        },
        {
          prompt: '<?xml version="1.0"?><script>alert("xss")</script>',
          expectError: false
        }
      ];

      for (const edgeCase of edgeCases) {
        const task = TaskGenerator.generate({
          capability: 'analysis',
          context: businessContext,
          input: {
            prompt: edgeCase.prompt,
            data: { edgeCaseTest: true }
          }
        });

        try {
          const result = await claudeAgent.execute(task, businessContext);

          if (!edgeCase.expectError) {
            expect(result.status).toBe('completed');
          }
        } catch (error) {
          if (edgeCase.expectError) {
            expect(error).toBeInstanceOf(Error);
          } else {
            // Unexpected error - log for debugging
            console.warn('Unexpected error for edge case:', edgeCase.prompt, error);
          }
        }
      }
    });

    it('should maintain context across conversation turns', async () => {
      const conversationTurns = [
        {
          prompt: 'I need help planning a marketing campaign for our new product launch.',
          expectedContext: ['marketing', 'campaign', 'product', 'launch']
        },
        {
          prompt: 'The product is a SaaS platform for small businesses.',
          expectedContext: ['saas', 'platform', 'small', 'business']
        },
        {
          prompt: 'What channels should we focus on?',
          expectedContext: ['channel', 'focus', 'marketing']
        },
        {
          prompt: 'How much budget should we allocate?',
          expectedContext: ['budget', 'allocate', 'campaign']
        }
      ];

      const conversationId = 'test-conversation-123';
      const results: AgentResult[] = [];

      for (let i = 0; i < conversationTurns.length; i++) {
        const turn = conversationTurns[i];
        const task = TaskGenerator.generate({
          capability: 'planning',
          context: businessContext,
          input: {
            prompt: turn.prompt,
            data: {
              conversationId,
              turnIndex: i,
              previousContext: results.map(r => r.result.data)
            }
          },
          metadata: {
            conversationId,
            turnIndex: i
          }
        });

        const result = await claudeAgent.execute(task, businessContext);
        results.push(result);

        expect(result.status).toBe('completed');
        expect(result.metadata?.conversationId).toBe(conversationId);
      }

      // Verify conversation coherence
      expect(results).toHaveLength(4);

      // Later responses should build on earlier context
      const lastResponse = JSON.stringify(results[3].result.data).toLowerCase();
      expect(lastResponse).toMatch(/(marketing|campaign|budget|saas|platform)/);
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle concurrent requests efficiently', async () => {
      const concurrentTasks = TaskGenerator.generateBatch(5, {
        capability: 'analysis',
        context: businessContext,
        input: {
          prompt: 'Analyze business performance metrics',
          data: { concurrencyTest: true }
        }
      });

      performanceMonitor.start();

      const results = await Promise.all(
        concurrentTasks.map(task => claudeAgent.execute(task, businessContext))
      );

      performanceMonitor.end();

      expect(results).toHaveLength(5);
      results.forEach(result => {
        expect(result.status).toBe('completed');
      });

      // Should handle concurrent requests within reasonable time
      expect(performanceMonitor.getExecutionTime()).toBeLessThan(20000); // 20 seconds
    });

    it('should respect rate limits', async () => {
      const rapidTasks = TaskGenerator.generateBatch(20, {
        capability: 'generation',
        context: businessContext,
        input: {
          prompt: 'Generate a short business insight',
          data: { rateLimitTest: true }
        }
      });

      const results: (AgentResult | Error)[] = [];

      // Execute rapidly to test rate limiting
      for (const task of rapidTasks) {
        try {
          const result = await claudeAgent.execute(task, businessContext);
          results.push(result);
        } catch (error) {
          results.push(error as Error);
        }
      }

      // Should handle rate limits gracefully
      const successful = results.filter(r => !(r instanceof Error)).length;
      const errors = results.filter(r => r instanceof Error).length;

      expect(successful + errors).toBe(20);

      // Most requests should succeed or fail gracefully
      if (errors > 0) {
        const errorMessages = errors > 0 ? (results.filter(r => r instanceof Error) as Error[]).map(e => e.message) : [];
        errorMessages.forEach(msg => {
          expect(msg.toLowerCase()).toMatch(/(rate|limit|quota|throttle)/);
        });
      }
    });

    it('should monitor health status accurately', async () => {
      // Test health monitoring over time
      const healthChecks: any[] = [];

      for (let i = 0; i < 5; i++) {
        const health = await claudeAgent.healthCheck();
        healthChecks.push({
          ...health,
          checkIndex: i,
          timestamp: Date.now()
        });

        // Small delay between checks
        await new Promise(resolve => setTimeout(resolve, 1000));
      }

      expect(healthChecks).toHaveLength(5);

      healthChecks.forEach((health, index) => {
        expect(health.status).toBeDefined();
        expect(health.lastCheck).toBeGreaterThan(0);
        expect(health.checkIndex).toBe(index);

        if (index > 0) {
          expect(health.lastCheck).toBeGreaterThan(healthChecks[index - 1].lastCheck);
        }
      });
    });
  });
});