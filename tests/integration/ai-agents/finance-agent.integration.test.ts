/**
 * Finance Agent Integration Tests
 *
 * IMPORTANT: These tests make REAL API calls and will incur costs!
 * - Requires ANTHROPIC_API_KEY or DEEPSEEK_API_KEY environment variable
 * - Tests are skipped automatically if no API key is provided
 * - Set MAX_COST_PER_TEST to limit spending (default: $0.50 per test)
 *
 * Run with: npm run test:integration:finance-agent
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FinanceAgent as FinanceAgentType } from '../../../src/modules/agents/finance-agent';
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

describe('FinanceAgent - Real API Integration', () => {
  let financeAgent: FinanceAgentType | null = null;

  const testContext: BusinessContext = {
    userId: 'integration-test-user',
    businessId: 'integration-test-business',
    timestamp: new Date().toISOString(),
    requestId: 'integration-test-request',
    userContext: {
      userId: 'integration-test-user',
      role: 'finance_manager',
      department: 'finance',
      permissions: ['finance.read', 'finance.write', 'finance.analyze'],
    },
    businessData: {
      companyName: 'Test Corp',
      industry: 'Technology',
      size: 'mid-sized',
      currency: 'USD',
      timezone: 'America/New_York',
    },
    businessState: {
      currentFiscalPeriod: '2024-Q4',
      keyMetrics: {
        revenue: 5000000,
        expenses: 3500000,
        profitMargin: 0.30,
      },
    },
  };

  beforeAll(async () => {
    if (!hasAnyKey) {
      console.warn('\n⚠️  Skipping Finance Agent Integration Tests');
      console.warn('   Reason: No API keys configured');
      console.warn('   Required: ANTHROPIC_API_KEY or DEEPSEEK_API_KEY\n');
      console.warn('   To run these tests:');
      console.warn('   1. Get API key from https://console.anthropic.com or https://platform.deepseek.com');
      console.warn('   2. export ANTHROPIC_API_KEY="sk-ant-..."');
      console.warn('   3. npm run test:integration:finance-agent\n');
      return;
    }

    console.log('\n🧪 Running Finance Agent Real API Integration Tests');
    console.log('   Cost Limits:');
    console.log(`   - Max per test: $${MAX_COST_PER_TEST.toFixed(2)}`);
    console.log(`   - Max per suite: $${MAX_COST_PER_SUITE.toFixed(2)}\n`);

    // Dynamically import FinanceAgent to avoid loading if no API key
    const { FinanceAgent } = await import('../../../src/modules/agents/finance-agent');

    // Create Finance Agent with appropriate API key
    const apiKey = process.env.ANTHROPIC_API_KEY || '';
    const deepseekApiKey = process.env.DEEPSEEK_API_KEY || '';

    if (hasAnthropicKey) {
      console.log('   ✅ Anthropic Claude API key found - using Claude');
      financeAgent = new FinanceAgent(apiKey);
    } else if (hasDeepSeekKey) {
      console.log('   ✅ DeepSeek API key found - using DeepSeek');
      financeAgent = new FinanceAgent('', deepseekApiKey);
    }

    console.log('');
  });

  afterAll(() => {
    if (totalCost > 0) {
      console.log('\n💰 Total Finance Agent Integration Test Costs:');
      console.log(`   Total Spent: $${totalCost.toFixed(4)}`);
      console.log(`   Budget Used: ${(totalCost / MAX_COST_PER_SUITE * 100).toFixed(1)}%`);

      if (totalCost > MAX_COST_PER_SUITE) {
        console.warn(`   ⚠️  WARNING: Exceeded suite budget by $${(totalCost - MAX_COST_PER_SUITE).toFixed(4)}`);
      }
      console.log('');
    }
  });

  describe('Financial Statement Analysis', () => {
    testIfKey(hasAnyKey)(
      'should analyze income statement with real data',
      async () => {
        const task: AgentTask = {
          id: 'finance-income-statement',
          capability: 'financial_analysis',
          input: {
            data: {
              analysisType: 'income_statement',
              statement: {
                revenue: 5000000,
                costOfGoodsSold: 2000000,
                grossProfit: 3000000,
                operatingExpenses: 1500000,
                operatingIncome: 1500000,
                interestExpense: 50000,
                taxExpense: 435000,
                netIncome: 1015000,
              },
              period: '2024-Q4',
              previousPeriod: {
                revenue: 4500000,
                netIncome: 900000,
              },
            },
          },
          priority: 'normal',
        };

        const result = await financeAgent!.executeTask(task, testContext);

        expect(result.success).toBe(true);
        expect(result.output).toBeDefined();
        expect(result.output.data).toBeDefined();

        // Should mention key financial metrics
        const response = JSON.stringify(result.output).toLowerCase();
        expect(
          response.includes('revenue') ||
          response.includes('profit') ||
          response.includes('margin') ||
          response.includes('growth')
        ).toBe(true);

        // Track cost
        if (result.metrics?.cost) {
          totalCost += result.metrics.cost;
        }

        console.log('   ✅ Income statement analysis completed');
        console.log(`      Tokens: ${result.metrics?.tokensUsed || 'N/A'}`);
        console.log(`      Latency: ${result.metrics?.latency || 'N/A'}ms`);
        console.log(`      Cost: $${result.metrics?.cost?.toFixed(4) || '0.0000'}`);
      },
      60000
    );

    testIfKey(hasAnyKey)(
      'should analyze balance sheet and provide insights',
      async () => {
        const task: AgentTask = {
          id: 'finance-balance-sheet',
          capability: 'financial_analysis',
          input: {
            data: {
              analysisType: 'balance_sheet',
              statement: {
                assets: {
                  current: {
                    cash: 1500000,
                    accountsReceivable: 800000,
                    inventory: 500000,
                  },
                  nonCurrent: {
                    propertyPlantEquipment: 3000000,
                    intangibleAssets: 500000,
                  },
                },
                liabilities: {
                  current: {
                    accountsPayable: 400000,
                    shortTermDebt: 200000,
                  },
                  nonCurrent: {
                    longTermDebt: 1500000,
                  },
                },
                equity: {
                  commonStock: 2000000,
                  retainedEarnings: 2200000,
                },
              },
              period: '2024-Q4',
            },
          },
          priority: 'normal',
        };

        const result = await financeAgent!.executeTask(task, testContext);

        expect(result.success).toBe(true);
        expect(result.output).toBeDefined();

        // Should mention balance sheet concepts
        const response = JSON.stringify(result.output).toLowerCase();
        expect(
          response.includes('asset') ||
          response.includes('liability') ||
          response.includes('equity') ||
          response.includes('balance')
        ).toBe(true);

        if (result.metrics?.cost) {
          totalCost += result.metrics.cost;
        }

        console.log('   ✅ Balance sheet analysis completed');
        console.log(`      Cost: $${result.metrics?.cost?.toFixed(4) || '0.0000'}`);
      },
      60000
    );
  });

  describe('Cash Flow Analysis', () => {
    testIfKey(hasAnyKey)(
      'should analyze cash flow and predict future trends',
      async () => {
        const task: AgentTask = {
          id: 'finance-cash-flow',
          capability: 'cash_flow_analysis',
          input: {
            data: {
              historicalCashFlow: [
                { month: 'Jan', inflow: 500000, outflow: 350000, net: 150000 },
                { month: 'Feb', inflow: 550000, outflow: 380000, net: 170000 },
                { month: 'Mar', inflow: 520000, outflow: 390000, net: 130000 },
                { month: 'Apr', inflow: 580000, outflow: 400000, net: 180000 },
              ],
              currentCash: 2500000,
              upcomingExpenses: [
                { description: 'Payroll', amount: 300000, date: '2024-11-15' },
                { description: 'Rent', amount: 50000, date: '2024-11-01' },
                { description: 'Equipment', amount: 150000, date: '2024-11-20' },
              ],
            },
          },
          priority: 'high',
        };

        const result = await financeAgent!.executeTask(task, testContext);

        expect(result.success).toBe(true);
        expect(result.output).toBeDefined();

        // Should mention cash flow concepts
        const response = JSON.stringify(result.output).toLowerCase();
        expect(
          response.includes('cash') ||
          response.includes('flow') ||
          response.includes('liquidity') ||
          response.includes('forecast')
        ).toBe(true);

        if (result.metrics?.cost) {
          totalCost += result.metrics.cost;
        }

        console.log('   ✅ Cash flow analysis completed');
        console.log(`      Cost: $${result.metrics?.cost?.toFixed(4) || '0.0000'}`);
      },
      60000
    );
  });

  describe('Budget Planning', () => {
    testIfKey(hasAnyKey)(
      'should create budget recommendations',
      async () => {
        const task: AgentTask = {
          id: 'finance-budget-planning',
          capability: 'budget_planning',
          input: {
            data: {
              department: 'Marketing',
              currentBudget: 100000,
              spent: 65000,
              remainingPeriod: 90, // days
              plannedInitiatives: [
                { name: 'Q4 Campaign', estimatedCost: 25000 },
                { name: 'Trade Show', estimatedCost: 15000 },
                { name: 'Content Production', estimatedCost: 8000 },
              ],
              historicalPerformance: {
                averageMonthlySpend: 22000,
                variance: 0.15,
              },
            },
          },
          priority: 'normal',
        };

        const result = await financeAgent!.executeTask(task, testContext);

        expect(result.success).toBe(true);
        expect(result.output).toBeDefined();

        // Should mention budget concepts
        const response = JSON.stringify(result.output).toLowerCase();
        expect(
          response.includes('budget') ||
          response.includes('spend') ||
          response.includes('allocat') ||
          response.includes('recommend')
        ).toBe(true);

        if (result.metrics?.cost) {
          totalCost += result.metrics.cost;
        }

        console.log('   ✅ Budget planning completed');
        console.log(`      Cost: $${result.metrics?.cost?.toFixed(4) || '0.0000'}`);
      },
      60000
    );
  });

  describe('Invoice Processing', () => {
    testIfKey(hasAnyKey)(
      'should analyze and categorize invoices',
      async () => {
        const task: AgentTask = {
          id: 'finance-invoice-processing',
          capability: 'invoice_processing',
          input: {
            data: {
              invoices: [
                {
                  vendor: 'AWS',
                  amount: 12500,
                  date: '2024-10-31',
                  description: 'Cloud infrastructure services - October 2024',
                  items: [
                    { service: 'EC2', cost: 8000 },
                    { service: 'S3', cost: 3000 },
                    { service: 'RDS', cost: 1500 },
                  ],
                },
                {
                  vendor: 'Office Supplies Co',
                  amount: 850,
                  date: '2024-10-28',
                  description: 'Office supplies and equipment',
                },
              ],
            },
          },
          priority: 'normal',
        };

        const result = await financeAgent!.executeTask(task, testContext);

        expect(result.success).toBe(true);
        expect(result.output).toBeDefined();

        // Should mention invoice concepts
        const response = JSON.stringify(result.output).toLowerCase();
        expect(
          response.includes('invoice') ||
          response.includes('expense') ||
          response.includes('categor') ||
          response.includes('vendor')
        ).toBe(true);

        if (result.metrics?.cost) {
          totalCost += result.metrics.cost;
        }

        console.log('   ✅ Invoice processing completed');
        console.log(`      Cost: $${result.metrics?.cost?.toFixed(4) || '0.0000'}`);
      },
      60000
    );
  });

  describe('Financial Ratio Analysis', () => {
    testIfKey(hasAnyKey)(
      'should calculate and interpret financial ratios',
      async () => {
        const task: AgentTask = {
          id: 'finance-ratio-analysis',
          capability: 'financial_analysis',
          input: {
            data: {
              analysisType: 'ratio_analysis',
              financials: {
                currentAssets: 2800000,
                currentLiabilities: 600000,
                totalAssets: 6300000,
                totalLiabilities: 2100000,
                revenue: 5000000,
                netIncome: 1015000,
                operatingIncome: 1500000,
                equity: 4200000,
              },
              period: '2024-Q4',
            },
          },
          priority: 'normal',
        };

        const result = await financeAgent!.executeTask(task, testContext);

        expect(result.success).toBe(true);
        expect(result.output).toBeDefined();

        // Should mention ratio concepts
        const response = JSON.stringify(result.output).toLowerCase();
        expect(
          response.includes('ratio') ||
          response.includes('liquidity') ||
          response.includes('profitability') ||
          response.includes('leverage')
        ).toBe(true);

        if (result.metrics?.cost) {
          totalCost += result.metrics.cost;
        }

        console.log('   ✅ Financial ratio analysis completed');
        console.log(`      Cost: $${result.metrics?.cost?.toFixed(4) || '0.0000'}`);
      },
      60000
    );
  });

  describe('Tax Analysis', () => {
    testIfKey(hasAnyKey)(
      'should provide tax planning insights',
      async () => {
        const task: AgentTask = {
          id: 'finance-tax-analysis',
          capability: 'financial_analysis',
          input: {
            data: {
              analysisType: 'tax_planning',
              taxableIncome: 1450000,
              jurisdiction: 'United States',
              entityType: 'C-Corporation',
              deductions: [
                { type: 'Business Expenses', amount: 1500000 },
                { type: 'Depreciation', amount: 200000 },
                { type: 'R&D Credits', amount: 50000 },
              ],
              period: '2024',
            },
          },
          priority: 'high',
        };

        const result = await financeAgent!.executeTask(task, testContext);

        expect(result.success).toBe(true);
        expect(result.output).toBeDefined();

        // Should mention tax concepts
        const response = JSON.stringify(result.output).toLowerCase();
        expect(
          response.includes('tax') ||
          response.includes('deduct') ||
          response.includes('credit') ||
          response.includes('compliance')
        ).toBe(true);

        if (result.metrics?.cost) {
          totalCost += result.metrics.cost;
        }

        console.log('   ✅ Tax analysis completed');
        console.log(`      Cost: $${result.metrics?.cost?.toFixed(4) || '0.0000'}`);
      },
      60000
    );
  });

  describe('Anomaly Detection', () => {
    testIfKey(hasAnyKey)(
      'should detect anomalies in financial data',
      async () => {
        const task: AgentTask = {
          id: 'finance-anomaly-detection',
          capability: 'expense_analysis',
          input: {
            data: {
              transactions: [
                { date: '2024-10-01', category: 'Office Supplies', amount: 250 },
                { date: '2024-10-05', category: 'Software', amount: 5000 },
                { date: '2024-10-10', category: 'Office Supplies', amount: 180 },
                { date: '2024-10-15', category: 'Office Supplies', amount: 15000 }, // Anomaly
                { date: '2024-10-20', category: 'Travel', amount: 1200 },
                { date: '2024-10-25', category: 'Software', amount: 4800 },
                { date: '2024-10-28', category: 'Office Supplies', amount: 220 },
              ],
              historicalAverages: {
                'Office Supplies': 250,
                'Software': 5000,
                'Travel': 1500,
              },
            },
          },
          priority: 'normal',
        };

        const result = await financeAgent!.executeTask(task, testContext);

        expect(result.success).toBe(true);
        expect(result.output).toBeDefined();

        // Should mention anomaly concepts
        const response = JSON.stringify(result.output).toLowerCase();
        expect(
          response.includes('anomal') ||
          response.includes('unusual') ||
          response.includes('outlier') ||
          response.includes('flag')
        ).toBe(true);

        if (result.metrics?.cost) {
          totalCost += result.metrics.cost;
        }

        console.log('   ✅ Anomaly detection completed');
        console.log(`      Cost: $${result.metrics?.cost?.toFixed(4) || '0.0000'}`);
      },
      60000
    );
  });

  describe('Performance Validation', () => {
    testIfKey(hasAnyKey)(
      'should respond within acceptable time for financial analysis',
      async () => {
        const task: AgentTask = {
          id: 'finance-performance-test',
          capability: 'financial_analysis',
          input: {
            data: {
              analysisType: 'quick_summary',
              revenue: 5000000,
              expenses: 3500000,
              period: '2024-Q4',
            },
          },
          priority: 'normal',
        };

        const startTime = Date.now();
        const result = await financeAgent!.executeTask(task, testContext);
        const endTime = Date.now();

        const actualLatency = endTime - startTime;

        expect(result.success).toBe(true);
        expect(actualLatency).toBeLessThan(15000); // Should respond in < 15 seconds

        if (result.metrics?.cost) {
          totalCost += result.metrics.cost;
        }

        console.log('   ✅ Performance within acceptable range');
        console.log(`      Latency: ${actualLatency}ms`);
        console.log(`      Cost: $${result.metrics?.cost?.toFixed(4) || '0.0000'}`);
      },
      20000
    );
  });

  describe('Error Handling', () => {
    testIfKey(hasAnyKey)(
      'should handle invalid financial data gracefully',
      async () => {
        const task: AgentTask = {
          id: 'finance-error-handling',
          capability: 'financial_analysis',
          input: {
            data: {
              // Missing required fields
              analysisType: 'income_statement',
              // No statement data
            },
          },
          priority: 'normal',
        };

        // Should not throw, but handle gracefully
        const result = await financeAgent!.executeTask(task, testContext);

        expect(result).toBeDefined();

        // Either succeeds with limited analysis or fails gracefully
        if (!result.success) {
          expect(result.error).toBeDefined();
        }

        console.log('   ✅ Invalid data handled gracefully');
        console.log(`      Result: ${result.success ? 'Success' : 'Failed gracefully'}`);
      },
      30000
    );
  });

  describe('Multi-Currency Support', () => {
    testIfKey(hasAnyKey)(
      'should handle multi-currency financial analysis',
      async () => {
        const task: AgentTask = {
          id: 'finance-multi-currency',
          capability: 'financial_analysis',
          input: {
            data: {
              analysisType: 'multi_currency',
              transactions: [
                { amount: 100000, currency: 'USD', description: 'US Sales' },
                { amount: 80000, currency: 'EUR', description: 'EU Sales' },
                { amount: 12000000, currency: 'JPY', description: 'Japan Sales' },
              ],
              baseCurrency: 'USD',
              exchangeRates: {
                EUR: 1.1,
                JPY: 0.0067,
              },
            },
          },
          priority: 'normal',
        };

        const result = await financeAgent!.executeTask(task, testContext);

        expect(result.success).toBe(true);
        expect(result.output).toBeDefined();

        // Should mention currency concepts
        const response = JSON.stringify(result.output).toLowerCase();
        expect(
          response.includes('currency') ||
          response.includes('exchange') ||
          response.includes('conversion') ||
          response.includes('usd')
        ).toBe(true);

        if (result.metrics?.cost) {
          totalCost += result.metrics.cost;
        }

        console.log('   ✅ Multi-currency analysis completed');
        console.log(`      Cost: $${result.metrics?.cost?.toFixed(4) || '0.0000'}`);
      },
      60000
    );
  });
});
