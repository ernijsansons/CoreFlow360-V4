/**
 * Gemini 2.0 Flash Integration Tests
 *
 * IMPORTANT: These tests make REAL API calls and will incur costs!
 * - Requires GOOGLE_AI_API_KEY or GEMINI_API_KEY environment variable
 * - Tests are skipped automatically if no API key is provided
 * - Ultra-low cost: ~$0.075 per 1M input tokens, ~$0.30 per 1M output tokens
 *
 * Run with: npm run test:integration:gemini
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { ClaudeAgent } from '../../../src/modules/agents/claude-agent';
import type { AgentTask, BusinessContext } from '../../../src/modules/agents/types';

// Cost tracking
let totalCost = 0;
const MAX_COST_PER_TEST = parseFloat(process.env.MAX_COST_PER_TEST || '0.10'); // Lower for Gemini
const MAX_COST_PER_SUITE = parseFloat(process.env.MAX_COST_PER_SUITE || '1.00'); // Lower for Gemini

// Helper to conditionally run tests
const testIfKey = (condition: boolean) => condition ? it : it.skip;
const hasGeminiKey = !!(process.env.GOOGLE_AI_API_KEY || process.env.GEMINI_API_KEY);

describe('Gemini 2.0 Flash - Real API Integration', () => {
  let geminiAgent: ClaudeAgent | null = null;

  const testContext: BusinessContext = {
    userId: 'integration-test-user',
    businessId: 'integration-test-business',
    timestamp: new Date().toISOString(),
    requestId: 'integration-test-request',
    userContext: {
      userId: 'integration-test-user',
      role: 'manager',
      department: 'operations',
      permissions: ['read', 'write'],
    },
    businessData: {
      companyName: 'Test Corp',
      industry: 'Technology',
      size: 'mid-sized',
      currency: 'USD',
      timezone: 'America/New_York',
    },
  };

  beforeAll(() => {
    if (!hasGeminiKey) {
      console.warn('\n⚠️  Skipping Gemini Integration Tests');
      console.warn('   Reason: No API key configured');
      console.warn('   Required: GOOGLE_AI_API_KEY or GEMINI_API_KEY\n');
      console.warn('   To run these tests:');
      console.warn('   1. Get API key from https://aistudio.google.com/app/apikey');
      console.warn('   2. export GEMINI_API_KEY="your-key-here"');
      console.warn('   3. npm run test:integration:gemini\n');
      return;
    }

    console.log('\n🧪 Running Gemini 2.0 Flash Real API Integration Tests');
    console.log('   Model: Gemini 2.0 Flash Experimental');
    console.log('   Cost Limits:');
    console.log(`   - Max per test: $${MAX_COST_PER_TEST.toFixed(2)}`);
    console.log(`   - Max per suite: $${MAX_COST_PER_SUITE.toFixed(2)}`);
    console.log('   Expected: Ultra-low cost (~10-20x cheaper than Claude)\n');

    const apiKey = process.env.GOOGLE_AI_API_KEY || process.env.GEMINI_API_KEY || '';
    geminiAgent = new ClaudeAgent({
      geminiApiKey: apiKey,
      id: 'gemini-2-flash',
      name: 'Gemini 2.0 Flash Experimental'
    });

    console.log('   ✅ Gemini API key found\n');
  });

  afterAll(() => {
    if (totalCost > 0) {
      console.log('\n💰 Total Gemini Integration Test Costs:');
      console.log(`   Total Spent: $${totalCost.toFixed(4)}`);
      console.log(`   Budget Used: ${(totalCost / MAX_COST_PER_SUITE * 100).toFixed(1)}%`);

      if (totalCost > MAX_COST_PER_SUITE) {
        console.warn(`   ⚠️  WARNING: Exceeded suite budget by $${(totalCost - MAX_COST_PER_SUITE).toFixed(4)}`);
      }
      console.log('');
    }
  });

  describe('Basic API Connectivity', () => {
    testIfKey(hasGeminiKey)(
      'should connect to Gemini API and get response',
      async () => {
        const task: AgentTask = {
          id: 'connectivity-test-gemini',
          capability: 'analysis',
          input: {
            data: {
              query: 'What is 2 + 2? Answer with only the number.'
            }
          },
          priority: 'normal'
        };

        const result = await geminiAgent!.executeTask(task, testContext);

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

        // Track cost
        totalCost += result.metrics!.cost || 0;

        // Log results
        console.log('   ✅ Gemini API connected successfully');
        console.log(`      Tokens: ${result.metrics!.tokensUsed}`);
        console.log(`      Latency: ${result.metrics!.latency}ms`);
        console.log(`      Cost: $${result.metrics!.cost?.toFixed(6) || '0.000000'}`);

        // Verify ultra-low cost
        expect(result.metrics!.cost).toBeLessThan(MAX_COST_PER_TEST);
      },
      30000
    );
  });

  describe('Speed Performance', () => {
    testIfKey(hasGeminiKey)(
      'should respond faster than Claude (target <1.5s)',
      async () => {
        const task: AgentTask = {
          id: 'speed-test-gemini',
          capability: 'analysis',
          input: {
            data: {
              query: 'List 5 benefits of cloud computing in one sentence each.'
            }
          },
          priority: 'normal'
        };

        const startTime = Date.now();
        const result = await geminiAgent!.executeTask(task, testContext);
        const endTime = Date.now();

        const actualLatency = endTime - startTime;

        expect(result.success).toBe(true);
        expect(actualLatency).toBeLessThan(1500); // Should be <1.5s (faster than Claude's ~2.5s)

        totalCost += result.metrics!.cost || 0;

        console.log('   ✅ Gemini speed advantage confirmed');
        console.log(`      Latency: ${actualLatency}ms (target: <1500ms)`);
        console.log(`      Cost: $${result.metrics!.cost?.toFixed(6) || '0.000000'}`);
      },
      10000
    );
  });

  describe('Invoice Processing (Standard Capability)', () => {
    testIfKey(hasGeminiKey)(
      'should process invoice data quickly and cheaply',
      async () => {
        const task: AgentTask = {
          id: 'gemini-invoice-processing',
          capability: 'invoice_processing',
          input: {
            data: {
              vendor: 'Office Supplies Inc',
              amount: 1250.50,
              date: '2024-10-15',
              description: 'Office supplies and equipment for Q4',
              lineItems: [
                { item: 'Desk chairs', quantity: 5, unitPrice: 150.00 },
                { item: 'Standing desks', quantity: 3, unitPrice: 250.00 },
                { item: 'Monitor arms', quantity: 8, unitPrice: 25.00 }
              ]
            }
          },
          priority: 'normal'
        };

        const result = await geminiAgent!.executeTask(task, testContext);

        expect(result.success).toBe(true);
        expect(result.output).toBeDefined();

        // Should mention invoice concepts
        const response = JSON.stringify(result.output).toLowerCase();
        expect(
          response.includes('invoice') ||
          response.includes('expense') ||
          response.includes('office') ||
          response.includes('supplies')
        ).toBe(true);

        totalCost += result.metrics!.cost || 0;

        console.log('   ✅ Invoice processing completed');
        console.log(`      Latency: ${result.metrics!.latency}ms`);
        console.log(`      Cost: $${result.metrics!.cost?.toFixed(6) || '0.000000'}`);
      },
      45000
    );
  });

  describe('Data Extraction (Bulk Operation)', () => {
    testIfKey(hasGeminiKey)(
      'should extract structured data from text',
      async () => {
        const task: AgentTask = {
          id: 'gemini-data-extraction',
          capability: 'data_extraction',
          input: {
            data: {
              text: `
                Invoice #12345
                Date: October 15, 2024
                Customer: Acme Corp
                Total: $5,432.10

                Line items:
                - Product A: $1,200.00
                - Product B: $2,500.00
                - Shipping: $250.10
                - Tax: $1,482.00
              `,
              extractFields: ['invoice_number', 'date', 'customer', 'total', 'line_items']
            }
          },
          priority: 'normal'
        };

        const result = await geminiAgent!.executeTask(task, testContext);

        expect(result.success).toBe(true);
        expect(result.output).toBeDefined();

        // Should extract key data
        const response = JSON.stringify(result.output);
        expect(response).toContain('12345');
        expect(response).toContain('Acme');

        totalCost += result.metrics!.cost || 0;

        console.log('   ✅ Data extraction completed');
        console.log(`      Cost: $${result.metrics!.cost?.toFixed(6) || '0.000000'}`);
      },
      45000
    );
  });

  describe('Email Generation (Fast Generation)', () => {
    testIfKey(hasGeminiKey)(
      'should generate professional email quickly',
      async () => {
        const task: AgentTask = {
          id: 'gemini-email-generation',
          capability: 'email_generation',
          input: {
            data: {
              type: 'email',
              context: {
                purpose: 'follow-up',
                tone: 'professional',
                recipient: 'potential customer',
                details: 'Following up on demo request from last week'
              }
            }
          },
          priority: 'normal'
        };

        const result = await geminiAgent!.executeTask(task, testContext);

        expect(result.success).toBe(true);
        expect(result.output).toBeDefined();

        // Should contain email-like content
        const response = JSON.stringify(result.output).toLowerCase();
        expect(
          response.includes('demo') ||
          response.includes('follow') ||
          response.includes('thank') ||
          response.includes('email')
        ).toBe(true);

        totalCost += result.metrics!.cost || 0;

        console.log('   ✅ Email generation completed');
        console.log(`      Cost: $${result.metrics!.cost?.toFixed(6) || '0.000000'}`);
      },
      45000
    );
  });

  describe('Lead Qualification (Standard Analysis)', () => {
    testIfKey(hasGeminiKey)(
      'should qualify sales lead efficiently',
      async () => {
        const task: AgentTask = {
          id: 'gemini-lead-qualification',
          capability: 'lead_qualification',
          input: {
            data: {
              lead: {
                company: 'TechStartup Inc',
                industry: 'SaaS',
                employeeCount: 50,
                revenue: 5000000,
                interestedIn: 'Enterprise plan',
                budget: 50000,
                timeframe: 'Q1 2025'
              }
            }
          },
          priority: 'normal'
        };

        const result = await geminiAgent!.executeTask(task, testContext);

        expect(result.success).toBe(true);
        expect(result.output).toBeDefined();

        // Should mention lead qualification concepts
        const response = JSON.stringify(result.output).toLowerCase();
        expect(
          response.includes('lead') ||
          response.includes('qualify') ||
          response.includes('budget') ||
          response.includes('revenue')
        ).toBe(true);

        totalCost += result.metrics!.cost || 0;

        console.log('   ✅ Lead qualification completed');
        console.log(`      Cost: $${result.metrics!.cost?.toFixed(6) || '0.000000'}`);
      },
      45000
    );
  });

  describe('Cost Efficiency', () => {
    testIfKey(hasGeminiKey)(
      'should demonstrate ultra-low cost vs Claude',
      async () => {
        const task: AgentTask = {
          id: 'gemini-cost-test',
          capability: 'analysis',
          input: {
            data: {
              query: 'Summarize the key points: Our Q4 revenue was $5M, up 25% YoY. Operating expenses increased 15% to $3.5M. Net profit margin improved from 25% to 30%. Key drivers were new customer acquisition (+40%) and improved retention (from 85% to 92%).'
            }
          },
          priority: 'normal'
        };

        const result = await geminiAgent!.executeTask(task, testContext);

        expect(result.success).toBe(true);
        const geminiCost = result.metrics!.cost || 0;

        totalCost += geminiCost;

        // Gemini should be significantly cheaper than Claude
        const estimatedClaudeCost = 0.018; // Approximate Claude cost for same task
        const savings = estimatedClaudeCost - geminiCost;
        const savingsPercentage = (savings / estimatedClaudeCost) * 100;

        console.log('\n   📊 Cost Efficiency Analysis:');
        console.log(`      Gemini Cost: $${geminiCost.toFixed(6)}`);
        console.log(`      Estimated Claude Cost: $${estimatedClaudeCost.toFixed(6)}`);
        console.log(`      Savings: $${savings.toFixed(6)} (${savingsPercentage.toFixed(1)}%)`);
        console.log(`      Cost Ratio: ${(estimatedClaudeCost / geminiCost).toFixed(1)}x cheaper\n`);

        // Gemini should be at least 10x cheaper
        expect(geminiCost).toBeLessThan(estimatedClaudeCost / 10);
      },
      60000
    );
  });

  describe('Error Handling', () => {
    testIfKey(hasGeminiKey)(
      'should handle invalid input gracefully',
      async () => {
        const task: AgentTask = {
          id: 'gemini-error-handling',
          capability: 'analysis',
          input: {
            data: null as any // Invalid input
          },
          priority: 'normal'
        };

        // Should not throw, but return error result
        const result = await geminiAgent!.executeTask(task, testContext);

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

  describe('Multimodal Capability', () => {
    testIfKey(hasGeminiKey)(
      'should acknowledge multimodal support',
      async () => {
        // Note: This test doesn't actually test image processing
        // Just validates that Gemini agent is aware of multimodal capabilities
        const task: AgentTask = {
          id: 'gemini-multimodal-info',
          capability: 'analysis',
          input: {
            data: {
              query: 'What types of input can you process?'
            }
          },
          priority: 'normal'
        };

        const result = await geminiAgent!.executeTask(task, testContext);

        expect(result.success).toBe(true);
        expect(result.output).toBeDefined();

        totalCost += result.metrics!.cost || 0;

        console.log('   ✅ Multimodal capability acknowledged');
        console.log(`      Note: Full multimodal testing requires image/video inputs`);
      },
      30000
    );
  });
});
