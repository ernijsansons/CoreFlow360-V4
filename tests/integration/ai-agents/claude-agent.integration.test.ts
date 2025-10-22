/**
 * Claude Agent Integration Tests
 *
 * IMPORTANT: These tests make REAL API calls and will incur costs!
 * - Requires ANTHROPIC_API_KEY or DEEPSEEK_API_KEY environment variable
 * - Tests are skipped automatically if no API key is provided
 * - Set MAX_COST_PER_TEST to limit spending (default: $0.50 per test)
 *
 * Run with: npm run test:integration:ai
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { ClaudeAgent } from '../../../src/modules/agents/claude-agent';
import type { AgentTask, BusinessContext } from '../../../src/modules/agents/types';

// Cost tracking
let totalCost = 0;
const MAX_COST_PER_TEST = parseFloat(process.env.MAX_COST_PER_TEST || '0.50');
const MAX_COST_PER_SUITE = parseFloat(process.env.MAX_COST_PER_SUITE || '5.00');

// Helper to conditionally run tests
const testIfKey = (condition: boolean) => condition ? it : it.skip;
const hasAnthropicKey = !!process.env.ANTHROPIC_API_KEY;
const hasDeepSeekKey = !!process.env.DEEPSEEK_API_KEY;
const hasAnyKey = hasAnthropicKey || hasDeepSeekKey;

describe('ClaudeAgent - Real API Integration', () => {
  let anthropicAgent: ClaudeAgent | null = null;
  let deepseekAgent: ClaudeAgent | null = null;

  const testContext: BusinessContext = {
    userId: 'integration-test-user',
    businessId: 'integration-test-business',
    timestamp: new Date().toISOString(),
    requestId: 'integration-test-request'
  };

  beforeAll(() => {
    if (!hasAnyKey) {
      console.warn('\n⚠️  Skipping AI Agent Integration Tests');
      console.warn('   Reason: No API keys configured');
      console.warn('   Required: ANTHROPIC_API_KEY or DEEPSEEK_API_KEY\n');
      console.warn('   To run these tests:');
      console.warn('   1. Get API key from https://console.anthropic.com or https://platform.deepseek.com');
      console.warn('   2. export ANTHROPIC_API_KEY="sk-ant-..."');
      console.warn('   3. npm run test:integration:ai\n');
      return;
    }

    console.log('\n🧪 Running Real API Integration Tests');
    console.log('   Cost Limits:');
    console.log(`   - Max per test: $${MAX_COST_PER_TEST.toFixed(2)}`);
    console.log(`   - Max per suite: $${MAX_COST_PER_SUITE.toFixed(2)}\n`);

    if (hasAnthropicKey) {
      console.log('   ✅ Anthropic Claude API key found');
      anthropicAgent = new ClaudeAgent({
        apiKey: process.env.ANTHROPIC_API_KEY!
      });
    }

    if (hasDeepSeekKey) {
      console.log('   ✅ DeepSeek API key found');
      deepseekAgent = new ClaudeAgent({
        deepseekApiKey: process.env.DEEPSEEK_API_KEY!
      });
    }

    console.log('');
  });

  afterAll(() => {
    if (totalCost > 0) {
      console.log('\n💰 Total Integration Test Costs:');
      console.log(`   Total Spent: $${totalCost.toFixed(4)}`);
      console.log(`   Budget Used: ${(totalCost / MAX_COST_PER_SUITE * 100).toFixed(1)}%`);

      if (totalCost > MAX_COST_PER_SUITE) {
        console.warn(`   ⚠️  WARNING: Exceeded suite budget by $${(totalCost - MAX_COST_PER_SUITE).toFixed(4)}`);
      }
      console.log('');
    }
  });

  describe('Basic API Connectivity', () => {
    testIfKey(hasAnthropicKey)(
      'should connect to Anthropic Claude API',
      async () => {
        const task: AgentTask = {
          id: 'connectivity-test-anthropic',
          capability: 'analysis',
          input: {
            data: {
              query: 'What is 2 + 2? Answer with only the number, nothing else.'
            }
          },
          priority: 'normal'
        };

        const result = await anthropicAgent!.executeTask(task, testContext);

        // Validate response structure
        expect(result).toBeDefined();
        expect(result.success).toBe(true);
        expect(result.output).toBeDefined();
        expect(result.output.data).toBeDefined();

        // Response should contain "4"
        const response = JSON.stringify(result.output);
        expect(response).toContain('4');

        // Validate metrics
        expect(result.metrics).toBeDefined();
        expect(result.metrics!.tokensUsed).toBeGreaterThan(0);
        expect(result.metrics!.latency).toBeGreaterThan(0);
        expect(result.metrics!.cost).toBeGreaterThan(0);

        // Track cost
        totalCost += result.metrics!.cost || 0;

        // Log results
        console.log('   ✅ Anthropic API connected successfully');
        console.log(`      Tokens: ${result.metrics!.tokensUsed}`);
        console.log(`      Latency: ${result.metrics!.latency}ms`);
        console.log(`      Cost: $${result.metrics!.cost?.toFixed(4)}`);

        // Verify cost limit
        expect(result.metrics!.cost).toBeLessThan(MAX_COST_PER_TEST);
      },
      30000 // 30 second timeout
    );

    testIfKey(hasDeepSeekKey)(
      'should connect to DeepSeek API',
      async () => {
        const task: AgentTask = {
          id: 'connectivity-test-deepseek',
          capability: 'analysis',
          input: {
            data: {
              query: 'What is 2 + 2? Answer with only the number, nothing else.'
            }
          },
          priority: 'normal'
        };

        const result = await deepseekAgent!.executeTask(task, testContext);

        expect(result.success).toBe(true);
        expect(result.output).toBeDefined();

        const response = JSON.stringify(result.output);
        expect(response).toContain('4');

        totalCost += result.metrics!.cost || 0;

        console.log('   ✅ DeepSeek API connected successfully');
        console.log(`      Tokens: ${result.metrics!.tokensUsed}`);
        console.log(`      Latency: ${result.metrics!.latency}ms`);
        console.log(`      Cost: $${result.metrics!.cost?.toFixed(4)}`);

        expect(result.metrics!.cost).toBeLessThan(MAX_COST_PER_TEST);
      },
      30000
    );
  });

  describe('Analysis Capability', () => {
    testIfKey(hasAnyKey)(
      'should perform real financial analysis',
      async () => {
        const agent = anthropicAgent || deepseekAgent!;

        const task: AgentTask = {
          id: 'analysis-financial',
          capability: 'analysis',
          input: {
            data: {
              analysisType: 'financial',
              data: {
                revenue: [100000, 110000, 125000, 135000],
                expenses: [80000, 85000, 90000, 92000],
                months: ['Jan', 'Feb', 'Mar', 'Apr']
              },
              query: 'Analyze the revenue and expense trend. Calculate profit margin for each month.'
            }
          },
          priority: 'normal'
        };

        const result = await agent.executeTask(task, testContext);

        expect(result.success).toBe(true);
        expect(result.output).toBeDefined();

        // Should mention profit or margin
        const response = JSON.stringify(result.output).toLowerCase();
        expect(
          response.includes('profit') ||
          response.includes('margin') ||
          response.includes('growth')
        ).toBe(true);

        totalCost += result.metrics!.cost || 0;

        console.log('   ✅ Financial analysis completed');
        console.log(`      Cost: $${result.metrics!.cost?.toFixed(4)}`);
      },
      45000
    );
  });

  describe('Generation Capability', () => {
    testIfKey(hasAnyKey)(
      'should generate real email content',
      async () => {
        const agent = anthropicAgent || deepseekAgent!;

        const task: AgentTask = {
          id: 'generation-email',
          capability: 'generation',
          input: {
            data: {
              type: 'email',
              context: {
                purpose: 'follow-up',
                tone: 'professional',
                recipient: 'potential customer',
                details: 'They requested a demo of our AI-powered platform'
              }
            }
          },
          priority: 'normal'
        };

        const result = await agent.executeTask(task, testContext);

        expect(result.success).toBe(true);
        expect(result.output).toBeDefined();

        // Should contain email-like content
        const response = JSON.stringify(result.output).toLowerCase();
        expect(
          response.includes('demo') ||
          response.includes('platform') ||
          response.includes('thank') ||
          response.includes('follow')
        ).toBe(true);

        totalCost += result.metrics!.cost || 0;

        console.log('   ✅ Email generation completed');
        console.log(`      Cost: $${result.metrics!.cost?.toFixed(4)}`);
      },
      45000
    );
  });

  describe('Error Handling', () => {
    testIfKey(hasAnyKey)(
      'should handle invalid input gracefully',
      async () => {
        const agent = anthropicAgent || deepseekAgent!;

        const task: AgentTask = {
          id: 'error-invalid-input',
          capability: 'analysis',
          input: {
            data: null as any // Invalid input
          },
          priority: 'normal'
        };

        // Should not throw, but return error result
        const result = await agent.executeTask(task, testContext);

        // Agent should handle this gracefully
        expect(result).toBeDefined();

        // Either succeeds with empty analysis or fails gracefully
        if (!result.success) {
          expect(result.error).toBeDefined();
        }

        console.log('   ✅ Invalid input handled gracefully');
      },
      30000
    );
  });

  describe('Performance Validation', () => {
    testIfKey(hasAnyKey)(
      'should respond within acceptable time',
      async () => {
        const agent = anthropicAgent || deepseekAgent!;

        const task: AgentTask = {
          id: 'performance-test',
          capability: 'analysis',
          input: {
            data: {
              query: 'List 3 benefits of AI in business operations.'
            }
          },
          priority: 'normal'
        };

        const startTime = Date.now();
        const result = await agent.executeTask(task, testContext);
        const endTime = Date.now();

        const actualLatency = endTime - startTime;

        expect(result.success).toBe(true);
        expect(actualLatency).toBeLessThan(10000); // Should respond in < 10 seconds

        totalCost += result.metrics!.cost || 0;

        console.log('   ✅ Performance within acceptable range');
        console.log(`      Latency: ${actualLatency}ms`);
        console.log(`      Cost: $${result.metrics!.cost?.toFixed(4)}`);
      },
      15000
    );
  });

  describe('Cost Comparison', () => {
    testIfKey(hasAnthropicKey && hasDeepSeekKey)(
      'should compare costs between Claude and DeepSeek',
      async () => {
        const task: AgentTask = {
          id: 'cost-comparison',
          capability: 'analysis',
          input: {
            data: {
              query: 'Summarize the key trends in Q1 2024 business performance: Revenue up 15%, costs up 8%, profit margin improved to 22%.'
            }
          },
          priority: 'normal'
        };

        // Test with Claude
        const claudeResult = await anthropicAgent!.executeTask(task, testContext);
        const claudeCost = claudeResult.metrics!.cost || 0;

        // Test with DeepSeek
        const deepseekResult = await deepseekAgent!.executeTask(task, testContext);
        const deepseekCost = deepseekResult.metrics!.cost || 0;

        totalCost += claudeCost + deepseekCost;

        // Compare
        const savings = ((1 - deepseekCost / claudeCost) * 100);

        console.log('\n   📊 Cost Comparison Results:');
        console.log(`      Claude Cost: $${claudeCost.toFixed(4)}`);
        console.log(`      DeepSeek Cost: $${deepseekCost.toFixed(4)}`);
        console.log(`      Savings with DeepSeek: ${savings.toFixed(1)}%`);
        console.log(`      Cost Ratio: ${(claudeCost / deepseekCost).toFixed(1)}x\n`);

        expect(claudeResult.success).toBe(true);
        expect(deepseekResult.success).toBe(true);

        // DeepSeek should be significantly cheaper
        expect(deepseekCost).toBeLessThan(claudeCost);
      },
      60000
    );
  });

  describe('Health Status', () => {
    testIfKey(hasAnyKey)(
      'should report healthy status after successful call',
      async () => {
        const agent = anthropicAgent || deepseekAgent!;

        // Make a successful call first
        const task: AgentTask = {
          id: 'health-check-task',
          capability: 'analysis',
          input: { data: { query: 'Test health' } },
          priority: 'normal'
        };

        await agent.executeTask(task, testContext);

        // Check health status
        const health = await agent.getHealthStatus();

        expect(health).toBeDefined();
        expect(health.status).toBe('healthy');
        expect(health.uptime).toBeGreaterThan(0);
        expect(health.successRate).toBeGreaterThan(0);

        console.log('   ✅ Agent health status: healthy');
        console.log(`      Success rate: ${(health.successRate * 100).toFixed(1)}%`);
      },
      30000
    );
  });
});
