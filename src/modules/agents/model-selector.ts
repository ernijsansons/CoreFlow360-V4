// @ts-nocheck
/**
 * Model Selection Strategy
 * Intelligently routes tasks to optimal AI model based on requirements
 *
 * Strategy:
 * - Gemini 2.0 Flash: Primary for fast, edge-speed tasks (low cost)
 * - Claude 3.5 Sonnet: Deep reasoning, complex analysis (premium)
 * - DeepSeek V3.2: Bulk operations, high-volume (budget)
 */

import type { AgentTask } from './types';

export type ModelProvider = 'gemini' | 'anthropic' | 'deepseek';

export interface ModelSelectionCriteria {
  task: AgentTask;
  userTier?: 'free' | 'pro' | 'enterprise';
  priorityOverride?: ModelProvider;
}

export interface ModelSelectionResult {
  provider: ModelProvider;
  model: string;
  reasoning: string;
  estimatedCost: number;
  estimatedLatency: number;
}

/**
 * Model Selection Strategy Engine
 */
export class ModelSelector {
  // Model characteristics
  private static readonly MODEL_PROFILES = {
    gemini: {
      name: 'Gemini 2.0 Flash Experimental',
      costPerMTokenInput: 0.075,  // $0.075 per 1M input tokens
      costPerMTokenOutput: 0.30,  // $0.30 per 1M output tokens
      averageLatency: 800,        // ~800ms average
      maxTokens: 1000000,         // 1M context window
      strengths: ['speed', 'cost-efficiency', 'multimodal', 'edge-deployment'],
      weaknesses: ['complex-reasoning', 'long-form-content'],
      useCase: 'Primary for fast, edge-speed tasks with low cost'
    },
    anthropic: {
      name: 'Claude 3.5 Sonnet',
      costPerMTokenInput: 3.00,   // $3 per 1M input tokens
      costPerMTokenOutput: 15.00, // $15 per 1M output tokens
      averageLatency: 2500,       // ~2.5s average
      maxTokens: 200000,          // 200k context window
      strengths: ['deep-reasoning', 'complex-analysis', 'code-generation', 'safety'],
      weaknesses: ['cost', 'latency'],
      useCase: 'Deep reasoning, complex financial/legal analysis'
    },
    deepseek: {
      name: 'DeepSeek V3.2',
      costPerMTokenInput: 0.14,   // $0.14 per 1M input tokens
      costPerMTokenOutput: 0.28,  // $0.28 per 1M output tokens
      averageLatency: 1800,       // ~1.8s average
      maxTokens: 64000,           // 64k context window
      strengths: ['cost', 'code-generation', 'bulk-operations'],
      weaknesses: ['reasoning-depth', 'safety-alignment'],
      useCase: 'Bulk operations, high-volume tasks, budget-conscious'
    }
  };

  /**
   * Select optimal model for a given task
   */
  static selectModel(criteria: ModelSelectionCriteria): ModelSelectionResult {
    const { task, userTier = 'pro', priorityOverride } = criteria;

    // Priority override (user explicitly chose a model)
    if (priorityOverride) {
      return this.buildResult(priorityOverride, 'User priority override');
    }

    // Task priority-based selection
    if (task.priority === 'critical' || task.priority === 'high') {
      return this.selectForHighPriority(task, userTier);
    }

    // Capability-based selection
    return this.selectByCapability(task, userTier);
  }

  /**
   * Select model for high-priority tasks
   */
  private static selectForHighPriority(
    task: AgentTask,
    _userTier: string
  ): ModelSelectionResult {
    const capability = task.capability;

    // Fast response needed → Gemini (check FIRST, before capability)
    if (task.constraints?.maxLatency && task.constraints.maxLatency < 2000) {
      return this.buildResult(
        'gemini',
        `Latency constraint <2s requires Gemini 2.0 Flash (800ms avg)`
      );
    }

    // Deep reasoning capabilities → Claude
    const reasoningCapabilities = [
      'financial_analysis',
      'contract_review',
      'legal_analysis',
      'strategic_planning',
      'risk_assessment',
      'compliance_review'
    ];

    if (reasoningCapabilities.includes(capability)) {
      return this.buildResult(
        'anthropic',
        `High-priority ${capability} requires deep reasoning (Claude 3.5 Sonnet)`
      );
    }

    // Default high-priority → Claude for quality
    return this.buildResult(
      'anthropic',
      'High priority task defaults to Claude for maximum quality'
    );
  }

  /**
   * Select model by capability
   */
  private static selectByCapability(
    task: AgentTask,
    _userTier: string
  ): ModelSelectionResult {
    const capability = task.capability;

    // Bulk/simple operations → DeepSeek
    const bulkCapabilities = [
      'data_extraction',
      'classification',
      'summarization',
      'translation',
      'simple_generation'
    ];

    if (bulkCapabilities.includes(capability)) {
      return this.buildResult(
        'deepseek',
        `Bulk operation ${capability} uses DeepSeek for cost efficiency`
      );
    }

    // Complex analysis → Claude
    const complexCapabilities = [
      'financial_analysis',
      'budget_planning',
      'cash_flow_analysis',
      'contract_review',
      'market_analysis',
      'strategic_planning'
    ];

    if (complexCapabilities.includes(capability)) {
      return this.buildResult(
        'anthropic',
        `Complex ${capability} requires Claude's deep reasoning`
      );
    }

    // Fast/standard operations → Gemini (PRIMARY)
    const standardCapabilities = [
      'analysis',
      'generation',
      'invoice_processing',
      'expense_analysis',
      'lead_qualification',
      'customer_insights',
      'email_generation',
      'report_generation'
    ];

    if (standardCapabilities.includes(capability)) {
      return this.buildResult(
        'gemini',
        `Standard ${capability} uses Gemini 2.0 Flash for speed + low cost (PRIMARY)`
      );
    }

    // Code generation → DeepSeek (specialized)
    if (capability.includes('code') || capability === 'automation') {
      return this.buildResult(
        'deepseek',
        'Code generation optimized for DeepSeek'
      );
    }

    // Default fallback → Gemini (PRIMARY)
    return this.buildResult(
      'gemini',
      'Default to Gemini 2.0 Flash for speed and cost efficiency'
    );
  }

  /**
   * Build selection result
   */
  private static buildResult(
    provider: ModelProvider,
    reasoning: string
  ): ModelSelectionResult {
    const profile = this.MODEL_PROFILES[provider];

    return {
      provider,
      model: this.getModelName(provider),
      reasoning,
      estimatedCost: this.estimateCost(provider, 1000, 500), // Estimate for 1k input, 500 output
      estimatedLatency: profile.averageLatency
    };
  }

  /**
   * Get model name for provider
   */
  private static getModelName(provider: ModelProvider): string {
    const models = {
      gemini: 'gemini-2.0-flash-exp',
      anthropic: 'claude-3-5-sonnet-20241022',
      deepseek: 'deepseek-chat'
    };
    return models[provider];
  }

  /**
   * Estimate cost for a task
   */
  private static estimateCost(
    provider: ModelProvider,
    inputTokens: number,
    outputTokens: number
  ): number {
    const profile = this.MODEL_PROFILES[provider];
    const inputCost = (inputTokens / 1_000_000) * profile.costPerMTokenInput;
    const outputCost = (outputTokens / 1_000_000) * profile.costPerMTokenOutput;
    return Math.round((inputCost + outputCost) * 10000) / 10000; // Round to 4 decimals
  }

  /**
   * Get provider recommendation based on user tier and budget
   */
  static getProviderRecommendation(
    userTier: 'free' | 'pro' | 'enterprise',
    _monthlyBudget?: number
  ): {
    primary: ModelProvider;
    secondary: ModelProvider;
    bulk: ModelProvider;
    reasoning: string;
  } {
    if (userTier === 'free') {
      return {
        primary: 'gemini',
        secondary: 'deepseek',
        bulk: 'deepseek',
        reasoning: 'Free tier: Gemini primary (ultra-low cost), DeepSeek for bulk'
      };
    }

    if (userTier === 'pro') {
      return {
        primary: 'gemini',
        secondary: 'anthropic',
        bulk: 'deepseek',
        reasoning: 'Pro tier: Gemini primary for speed, Claude for complex analysis, DeepSeek for bulk'
      };
    }

    // Enterprise
    return {
      primary: 'gemini',
      secondary: 'anthropic',
      bulk: 'anthropic',
      reasoning: 'Enterprise: Gemini primary, Claude for all complex/bulk operations (quality-first)'
    };
  }

  /**
   * Calculate cost savings by using model selection vs. always using Claude
   */
  static calculateSavings(
    tasks: AgentTask[],
    userTier: 'free' | 'pro' | 'enterprise' = 'pro'
  ): {
    withSelection: number;
    alwaysClaude: number;
    savings: number;
    savingsPercentage: number;
  } {
    let costWithSelection = 0;
    let costAlwaysClaude = 0;

    for (const task of tasks) {
      const selection = this.selectModel({ task, userTier });
      costWithSelection += selection.estimatedCost;
      costAlwaysClaude += this.estimateCost('anthropic', 1000, 500);
    }

    const savings = costAlwaysClaude - costWithSelection;
    const savingsPercentage = (savings / costAlwaysClaude) * 100;

    return {
      withSelection: Math.round(costWithSelection * 100) / 100,
      alwaysClaude: Math.round(costAlwaysClaude * 100) / 100,
      savings: Math.round(savings * 100) / 100,
      savingsPercentage: Math.round(savingsPercentage * 10) / 10
    };
  }
}

/**
 * Usage Example:
 *
 * const task: AgentTask = {
 *   id: 'task-1',
 *   capability: 'invoice_processing',
 *   priority: 'normal'
 * };
 *
 * const selection = ModelSelector.selectModel({ task, userTier: 'pro' });
 * // Result: Gemini 2.0 Flash (fast, low cost)
 *
 * const analysisTask: AgentTask = {
 *   id: 'task-2',
 *   capability: 'financial_analysis',
 *   priority: 'high'
 * };
 *
 * const analysisSelection = ModelSelector.selectModel({ task: analysisTask });
 * // Result: Claude 3.5 Sonnet (deep reasoning)
 */
