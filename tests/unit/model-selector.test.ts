/**
 * Model Selection Discipline Tests
 * Validates that the correct model is chosen for each task type
 * to ensure cost optimization and quality balance
 */

import { describe, it, expect } from 'vitest';
import { ModelSelector } from '../../src/modules/agents/model-selector';
import type { AgentTask } from '../../src/modules/agents/types';

describe('ModelSelector - Cost Discipline', () => {
  describe('Primary Tasks → Gemini (Fast + Cheap)', () => {
    it('should route invoice_processing to Gemini', () => {
      const task: AgentTask = {
        id: 'test-1',
        capability: 'invoice_processing',
        priority: 'normal',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('gemini');
      expect(result.model).toBe('gemini-2.0-flash-exp');
      expect(result.reasoning).toContain('Gemini');
      expect(result.estimatedLatency).toBeLessThan(1500);
    });

    it('should route expense_analysis to Gemini', () => {
      const task: AgentTask = {
        id: 'test-2',
        capability: 'expense_analysis',
        priority: 'normal',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('gemini');
      expect(result.reasoning).toContain('Gemini');
    });

    it('should route lead_qualification to Gemini', () => {
      const task: AgentTask = {
        id: 'test-3',
        capability: 'lead_qualification',
        priority: 'normal',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('gemini');
      expect(result.reasoning).toContain('Gemini');
    });

    it('should route email_generation to Gemini', () => {
      const task: AgentTask = {
        id: 'test-4',
        capability: 'email_generation',
        priority: 'normal',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('gemini');
      expect(result.reasoning).toContain('Gemini');
    });

    it('should route customer_insights to Gemini', () => {
      const task: AgentTask = {
        id: 'test-5',
        capability: 'customer_insights',
        priority: 'normal',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('gemini');
      expect(result.reasoning).toContain('Gemini');
    });

    it('should route report_generation to Gemini', () => {
      const task: AgentTask = {
        id: 'test-6',
        capability: 'report_generation',
        priority: 'normal',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('gemini');
      expect(result.reasoning).toContain('Gemini');
    });

    it('should route analysis (generic) to Gemini', () => {
      const task: AgentTask = {
        id: 'test-7',
        capability: 'analysis',
        priority: 'normal',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('gemini');
      expect(result.reasoning).toContain('Gemini');
    });

    it('should route generation (generic) to Gemini', () => {
      const task: AgentTask = {
        id: 'test-8',
        capability: 'generation',
        priority: 'normal',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('gemini');
      expect(result.reasoning).toContain('Gemini');
    });
  });

  describe('Complex Tasks → Claude (Deep Reasoning)', () => {
    it('should route financial_analysis to Claude', () => {
      const task: AgentTask = {
        id: 'test-9',
        capability: 'financial_analysis',
        priority: 'normal',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('anthropic');
      expect(result.model).toBe('claude-3-5-sonnet-20241022');
      expect(result.reasoning).toContain('Claude');
      expect(result.reasoning).toContain('reasoning');
    });

    it('should route budget_planning to Claude', () => {
      const task: AgentTask = {
        id: 'test-10',
        capability: 'budget_planning',
        priority: 'normal',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('anthropic');
      expect(result.reasoning).toContain('Claude');
    });

    it('should route cash_flow_analysis to Claude', () => {
      const task: AgentTask = {
        id: 'test-11',
        capability: 'cash_flow_analysis',
        priority: 'normal',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('anthropic');
      expect(result.reasoning).toContain('Claude');
    });

    it('should route contract_review to Claude', () => {
      const task: AgentTask = {
        id: 'test-12',
        capability: 'contract_review',
        priority: 'normal',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('anthropic');
      expect(result.reasoning).toContain('Claude');
    });

    it('should route market_analysis to Claude', () => {
      const task: AgentTask = {
        id: 'test-13',
        capability: 'market_analysis',
        priority: 'normal',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('anthropic');
      expect(result.reasoning).toContain('Claude');
    });

    it('should route strategic_planning to Claude', () => {
      const task: AgentTask = {
        id: 'test-14',
        capability: 'strategic_planning',
        priority: 'normal',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('anthropic');
      expect(result.reasoning).toContain('Claude');
    });
  });

  describe('Bulk Tasks → DeepSeek (Cost Efficient)', () => {
    it('should route data_extraction to DeepSeek', () => {
      const task: AgentTask = {
        id: 'test-15',
        capability: 'data_extraction',
        priority: 'normal',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('deepseek');
      expect(result.model).toBe('deepseek-chat');
      expect(result.reasoning).toContain('DeepSeek');
    });

    it('should route classification to DeepSeek', () => {
      const task: AgentTask = {
        id: 'test-16',
        capability: 'classification',
        priority: 'normal',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('deepseek');
      expect(result.reasoning).toContain('DeepSeek');
    });

    it('should route summarization to DeepSeek', () => {
      const task: AgentTask = {
        id: 'test-17',
        capability: 'summarization',
        priority: 'normal',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('deepseek');
      expect(result.reasoning).toContain('DeepSeek');
    });

    it('should route translation to DeepSeek', () => {
      const task: AgentTask = {
        id: 'test-18',
        capability: 'translation',
        priority: 'normal',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('deepseek');
      expect(result.reasoning).toContain('DeepSeek');
    });

    it('should route code generation to DeepSeek', () => {
      const task: AgentTask = {
        id: 'test-19',
        capability: 'code_generation',
        priority: 'normal',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('deepseek');
      expect(result.reasoning).toContain('DeepSeek');
    });
  });

  describe('Priority-Based Overrides', () => {
    it('should route high-priority financial_analysis to Claude', () => {
      const task: AgentTask = {
        id: 'test-20',
        capability: 'financial_analysis',
        priority: 'high',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('anthropic');
      expect(result.reasoning).toContain('reasoning');
    });

    it('should route critical contract_review to Claude', () => {
      const task: AgentTask = {
        id: 'test-21',
        capability: 'contract_review',
        priority: 'critical',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('anthropic');
    });

    it('should respect latency constraints by choosing Gemini', () => {
      const task: AgentTask = {
        id: 'test-22',
        capability: 'financial_analysis',
        priority: 'high',
        input: {},
        constraints: {
          maxLatency: 1500 // <2s requirement
        }
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('gemini');
      expect(result.reasoning).toContain('Latency constraint');
    });

    it('should allow priority override to force Claude', () => {
      const task: AgentTask = {
        id: 'test-23',
        capability: 'invoice_processing', // Normally Gemini
        priority: 'normal',
        input: {}
      };

      const result = ModelSelector.selectModel({
        task,
        priorityOverride: 'anthropic'
      });

      expect(result.provider).toBe('anthropic');
      expect(result.reasoning).toContain('User priority override');
    });

    it('should allow priority override to force DeepSeek', () => {
      const task: AgentTask = {
        id: 'test-24',
        capability: 'financial_analysis', // Normally Claude
        priority: 'normal',
        input: {}
      };

      const result = ModelSelector.selectModel({
        task,
        priorityOverride: 'deepseek'
      });

      expect(result.provider).toBe('deepseek');
      expect(result.reasoning).toContain('User priority override');
    });
  });

  describe('Cost Estimation Accuracy', () => {
    it('should estimate Gemini as cheapest for standard task', () => {
      const task: AgentTask = {
        id: 'test-25',
        capability: 'invoice_processing',
        priority: 'normal',
        input: {}
      };

      const geminiResult = ModelSelector.selectModel({ task });
      const claudeResult = ModelSelector.selectModel({ task, priorityOverride: 'anthropic' });

      expect(geminiResult.estimatedCost).toBeLessThan(claudeResult.estimatedCost);
      expect(geminiResult.estimatedCost).toBeLessThan(0.001); // Very cheap
    });

    it('should estimate Claude as most expensive', () => {
      const task: AgentTask = {
        id: 'test-26',
        capability: 'analysis',
        priority: 'normal',
        input: {}
      };

      const geminiResult = ModelSelector.selectModel({ task, priorityOverride: 'gemini' });
      const claudeResult = ModelSelector.selectModel({ task, priorityOverride: 'anthropic' });
      const deepseekResult = ModelSelector.selectModel({ task, priorityOverride: 'deepseek' });

      expect(claudeResult.estimatedCost).toBeGreaterThan(geminiResult.estimatedCost);
      expect(claudeResult.estimatedCost).toBeGreaterThan(deepseekResult.estimatedCost);
    });

    it('should estimate DeepSeek as budget-friendly', () => {
      const task: AgentTask = {
        id: 'test-27',
        capability: 'analysis',
        priority: 'normal',
        input: {}
      };

      const geminiResult = ModelSelector.selectModel({ task, priorityOverride: 'gemini' });
      const deepseekResult = ModelSelector.selectModel({ task, priorityOverride: 'deepseek' });
      const claudeResult = ModelSelector.selectModel({ task, priorityOverride: 'anthropic' });

      // DeepSeek should be between Gemini and Claude in cost
      expect(deepseekResult.estimatedCost).toBeGreaterThan(geminiResult.estimatedCost);
      expect(deepseekResult.estimatedCost).toBeLessThan(claudeResult.estimatedCost);
    });
  });

  describe('Latency Estimation Accuracy', () => {
    it('should estimate Gemini as fastest', () => {
      const task: AgentTask = {
        id: 'test-28',
        capability: 'analysis',
        priority: 'normal',
        input: {}
      };

      const geminiResult = ModelSelector.selectModel({ task, priorityOverride: 'gemini' });
      const claudeResult = ModelSelector.selectModel({ task, priorityOverride: 'anthropic' });
      const deepseekResult = ModelSelector.selectModel({ task, priorityOverride: 'deepseek' });

      expect(geminiResult.estimatedLatency).toBeLessThan(claudeResult.estimatedLatency);
      expect(geminiResult.estimatedLatency).toBeLessThan(deepseekResult.estimatedLatency);
      expect(geminiResult.estimatedLatency).toBeLessThan(1000); // Should be <1s
    });

    it('should estimate Claude as slowest', () => {
      const task: AgentTask = {
        id: 'test-29',
        capability: 'analysis',
        priority: 'normal',
        input: {}
      };

      const claudeResult = ModelSelector.selectModel({ task, priorityOverride: 'anthropic' });

      expect(claudeResult.estimatedLatency).toBeGreaterThan(2000); // ~2.5s
    });

    it('should estimate DeepSeek as medium speed', () => {
      const task: AgentTask = {
        id: 'test-30',
        capability: 'analysis',
        priority: 'normal',
        input: {}
      };

      const geminiResult = ModelSelector.selectModel({ task, priorityOverride: 'gemini' });
      const deepseekResult = ModelSelector.selectModel({ task, priorityOverride: 'deepseek' });
      const claudeResult = ModelSelector.selectModel({ task, priorityOverride: 'anthropic' });

      expect(deepseekResult.estimatedLatency).toBeGreaterThan(geminiResult.estimatedLatency);
      expect(deepseekResult.estimatedLatency).toBeLessThan(claudeResult.estimatedLatency);
    });
  });

  describe('Tier-Based Recommendations', () => {
    it('should recommend Gemini primary for free tier', () => {
      const recommendation = ModelSelector.getProviderRecommendation('free');

      expect(recommendation.primary).toBe('gemini');
      expect(recommendation.secondary).toBe('deepseek');
      expect(recommendation.bulk).toBe('deepseek');
      expect(recommendation.reasoning).toContain('Free tier');
    });

    it('should recommend multi-model for pro tier', () => {
      const recommendation = ModelSelector.getProviderRecommendation('pro');

      expect(recommendation.primary).toBe('gemini');
      expect(recommendation.secondary).toBe('anthropic');
      expect(recommendation.bulk).toBe('deepseek');
      expect(recommendation.reasoning).toContain('Pro tier');
    });

    it('should recommend premium quality for enterprise tier', () => {
      const recommendation = ModelSelector.getProviderRecommendation('enterprise');

      expect(recommendation.primary).toBe('gemini');
      expect(recommendation.secondary).toBe('anthropic');
      expect(recommendation.bulk).toBe('anthropic'); // Quality-first
      expect(recommendation.reasoning).toContain('Enterprise');
    });
  });

  describe('Cost Savings Calculator', () => {
    it('should calculate significant savings with multi-model vs all-Claude', () => {
      const tasks: AgentTask[] = [
        // 80 standard tasks (should use Gemini)
        ...Array.from({ length: 80 }, (_, i) => ({
          id: `standard-${i}`,
          capability: 'invoice_processing',
          priority: 'normal' as const,
          input: {}
        })),
        // 15 complex tasks (should use Claude)
        ...Array.from({ length: 15 }, (_, i) => ({
          id: `complex-${i}`,
          capability: 'financial_analysis',
          priority: 'high' as const,
          input: {}
        })),
        // 5 bulk tasks (should use DeepSeek)
        ...Array.from({ length: 5 }, (_, i) => ({
          id: `bulk-${i}`,
          capability: 'data_extraction',
          priority: 'normal' as const,
          input: {}
        }))
      ];

      const savings = ModelSelector.calculateSavings(tasks, 'pro');

      expect(savings.withSelection).toBeLessThan(savings.alwaysClaude);
      expect(savings.savings).toBeGreaterThan(0);
      expect(savings.savingsPercentage).toBeGreaterThan(50); // At least 50% savings

      console.log('\n💰 Cost Savings Analysis:');
      console.log(`   Multi-model strategy: $${savings.withSelection}`);
      console.log(`   All-Claude approach: $${savings.alwaysClaude}`);
      console.log(`   Savings: $${savings.savings} (${savings.savingsPercentage}%)`);
    });

    it('should show ~80% savings for typical workload', () => {
      // Typical workload: 80% standard, 15% complex, 5% bulk
      const tasks: AgentTask[] = [
        ...Array.from({ length: 800 }, () => ({
          id: 'standard',
          capability: 'invoice_processing',
          priority: 'normal' as const,
          input: {}
        })),
        ...Array.from({ length: 150 }, () => ({
          id: 'complex',
          capability: 'financial_analysis',
          priority: 'high' as const,
          input: {}
        })),
        ...Array.from({ length: 50 }, () => ({
          id: 'bulk',
          capability: 'data_extraction',
          priority: 'normal' as const,
          input: {}
        }))
      ];

      const savings = ModelSelector.calculateSavings(tasks, 'pro');

      expect(savings.savingsPercentage).toBeGreaterThan(70); // Should be ~80%
      expect(savings.savingsPercentage).toBeLessThan(90);

      console.log('\n📊 Large-Scale Cost Analysis (1000 tasks):');
      console.log(`   Savings percentage: ${savings.savingsPercentage}%`);
    });
  });

  describe('Edge Cases', () => {
    it('should default to Gemini for unknown capability', () => {
      const task: AgentTask = {
        id: 'test-31',
        capability: 'unknown_capability',
        priority: 'normal',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('gemini');
      expect(result.reasoning).toContain('Default to Gemini');
    });

    it('should handle low priority tasks efficiently', () => {
      const task: AgentTask = {
        id: 'test-32',
        capability: 'analysis',
        priority: 'low',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('gemini'); // Should use cheapest
    });

    it('should handle tasks with no priority specified', () => {
      const task: AgentTask = {
        id: 'test-33',
        capability: 'invoice_processing',
        input: {}
      };

      const result = ModelSelector.selectModel({ task });

      expect(result.provider).toBe('gemini');
    });
  });

  describe('Real-World Scenarios', () => {
    it('should optimize costs for invoice processing batch', () => {
      const tasks: AgentTask[] = Array.from({ length: 100 }, (_, i) => ({
        id: `invoice-${i}`,
        capability: 'invoice_processing',
        priority: 'normal' as const,
        input: {}
      }));

      const selections = tasks.map(task => ModelSelector.selectModel({ task }));
      const allGemini = selections.every(s => s.provider === 'gemini');

      expect(allGemini).toBe(true);

      const totalCost = selections.reduce((sum, s) => sum + s.estimatedCost, 0);
      console.log('\n📋 Invoice Processing Batch (100 tasks):');
      console.log(`   All routed to: Gemini`);
      console.log(`   Total estimated cost: $${totalCost.toFixed(4)}`);
    });

    it('should route complex financial analysis to Claude', () => {
      const tasks: AgentTask[] = [
        {
          id: 'fin-1',
          capability: 'financial_analysis',
          priority: 'high',
          input: {}
        },
        {
          id: 'fin-2',
          capability: 'cash_flow_analysis',
          priority: 'high',
          input: {}
        },
        {
          id: 'fin-3',
          capability: 'budget_planning',
          priority: 'high',
          input: {}
        }
      ];

      const selections = tasks.map(task => ModelSelector.selectModel({ task }));
      const allClaude = selections.every(s => s.provider === 'anthropic');

      expect(allClaude).toBe(true);
      console.log('\n🧠 Complex Financial Tasks (3 tasks):');
      console.log(`   All routed to: Claude (deep reasoning)`);
    });

    it('should handle mixed workload optimally', () => {
      const tasks: AgentTask[] = [
        // Standard tasks
        { id: '1', capability: 'invoice_processing', priority: 'normal' as const, input: {} },
        { id: '2', capability: 'email_generation', priority: 'normal' as const, input: {} },
        { id: '3', capability: 'lead_qualification', priority: 'normal' as const, input: {} },
        // Complex task
        { id: '4', capability: 'financial_analysis', priority: 'high' as const, input: {} },
        // Bulk task
        { id: '5', capability: 'data_extraction', priority: 'normal' as const, input: {} },
      ];

      const selections = tasks.map(task => ModelSelector.selectModel({ task }));

      const geminiCount = selections.filter(s => s.provider === 'gemini').length;
      const claudeCount = selections.filter(s => s.provider === 'anthropic').length;
      const deepseekCount = selections.filter(s => s.provider === 'deepseek').length;

      expect(geminiCount).toBe(3); // Standard tasks
      expect(claudeCount).toBe(1); // Complex task
      expect(deepseekCount).toBe(1); // Bulk task

      console.log('\n🎯 Mixed Workload Distribution:');
      console.log(`   Gemini: ${geminiCount} tasks (standard)`);
      console.log(`   Claude: ${claudeCount} task (complex)`);
      console.log(`   DeepSeek: ${deepseekCount} task (bulk)`);
    });
  });

  describe('Cost Discipline Validation', () => {
    it('should never waste money on Claude for simple tasks', () => {
      const simpleTasks: AgentTask[] = [
        { id: '1', capability: 'invoice_processing', priority: 'normal' as const, input: {} },
        { id: '2', capability: 'email_generation', priority: 'normal' as const, input: {} },
        { id: '3', capability: 'expense_analysis', priority: 'normal' as const, input: {} },
        { id: '4', capability: 'lead_qualification', priority: 'normal' as const, input: {} },
      ];

      const selections = simpleTasks.map(task => ModelSelector.selectModel({ task }));
      const noClaude = selections.every(s => s.provider !== 'anthropic');

      expect(noClaude).toBe(true);
      console.log('\n✅ Cost Discipline: No Claude for simple tasks');
    });

    it('should always use Claude for critical reasoning', () => {
      const criticalTasks: AgentTask[] = [
        { id: '1', capability: 'financial_analysis', priority: 'high' as const, input: {} },
        { id: '2', capability: 'contract_review', priority: 'critical' as const, input: {} },
        { id: '3', capability: 'strategic_planning', priority: 'high' as const, input: {} },
      ];

      const selections = criticalTasks.map(task => ModelSelector.selectModel({ task }));
      const allClaude = selections.every(s => s.provider === 'anthropic');

      expect(allClaude).toBe(true);
      console.log('\n✅ Quality Discipline: Claude for critical reasoning');
    });

    it('should optimize bulk operations with DeepSeek', () => {
      const bulkTasks: AgentTask[] = [
        { id: '1', capability: 'data_extraction', priority: 'normal' as const, input: {} },
        { id: '2', capability: 'classification', priority: 'normal' as const, input: {} },
        { id: '3', capability: 'summarization', priority: 'normal' as const, input: {} },
      ];

      const selections = bulkTasks.map(task => ModelSelector.selectModel({ task }));
      const allDeepSeek = selections.every(s => s.provider === 'deepseek');

      expect(allDeepSeek).toBe(true);
      console.log('\n✅ Bulk Discipline: DeepSeek for high-volume operations');
    });
  });
});
