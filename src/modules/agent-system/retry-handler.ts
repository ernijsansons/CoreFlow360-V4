/**
 * Fallback & Retry Logic System
 * Intelligent retry with model downgrade and agent fallback
 */

import {
  IAgent,
  AgentTask,
  BusinessContext,
  AgentResult,
  TaskConstraints
} from './types';
import { AgentRegistry } from './registry';
import { Logger } from '../../shared/logger';

export interface RetryConfig {
  maxRetries: number;
  baseDelayMs: number;
  exponentialBackoff: boolean;
  jitterMs: number;
  retryableErrors: string[];
  nonRetryableErrors: string[];
  timeoutMs: number;
  enableModelDowngrade: boolean;
  enableAgentFallback: boolean;
}

export class RetryHandler {
  private logger: Logger;
  private registry: AgentRegistry;
  private defaultConfig: RetryConfig;

  constructor(registry: AgentRegistry, config?: Partial<RetryConfig>) {
    this.logger = new Logger();
    this.registry = registry;
    this.defaultConfig = {
      maxRetries: 3,
      baseDelayMs: 1000,
      exponentialBackoff: true,
      jitterMs: 500,
      retryableErrors: [
        'RATE_LIMIT_EXCEEDED',
        'SERVER_ERROR',
        'TIMEOUT',
        'NETWORK_ERROR',
        'OVERLOADED',
        'TEMPORARY_FAILURE'
      ],
      nonRetryableErrors: [
        'VALIDATION_FAILED',
        'PERMISSION_DENIED',
        'COST_LIMIT_EXCEEDED',
        'CAPABILITY_NOT_SUPPORTED',
        'AGENT_NOT_FOUND'
      ],
      timeoutMs: 30000,
      enableModelDowngrade: true,
      enableAgentFallback: true,
      ...config,
    };
  }

  /**
   * Execute task with intelligent retry and fallback logic
   */
  async executeWithRetry(
    agent: IAgent,
    task: AgentTask,
    context: BusinessContext,
    maxAttempts?: number
  ): Promise<AgentResult> {
    const config = this.defaultConfig;
    const attempts = maxAttempts || config.maxRetries + 1;
    let lastError: Error | undefined;
    let currentTask = { ...task };
    let currentAgent = agent;

    for (let attempt = 0; attempt < attempts; attempt++) {
      try {
        this.logger.debug('Executing task attempt', {
          taskId: task.id,
          attempt: attempt + 1,
          maxAttempts: attempts,
          agentId: currentAgent.id,
        });

        // Execute with timeout
        const result = await this.executeWithTimeout(
          currentAgent,
          currentTask,
          context,
          config.timeoutMs
        );

        // Update retry count in result
        result.metrics.retryCount = attempt;

        if (result.success) {
          this.logger.info('Task executed successfully', {
            taskId: task.id,
            agentId: currentAgent.id,
            attempts: attempt + 1,
            cost: result.metrics.cost,
            latency: result.metrics.latency,
          });

          return result;
        }

        // Task failed, check if retryable
        const error = new Error(result.error || 'Unknown error');
        if (!this.isRetryableError(error, config) || attempt === attempts - 1) {
          this.logger.warn('Task failed with non-retryable error or max attempts reached', {
            taskId: task.id,
            agentId: currentAgent.id,
            attempt: attempt + 1,
            error: result.error,
            retryable: this.isRetryableError(error, config),
          });

          return result;
        }

        lastError = error;

        // Try fallback strategies before retrying
        const fallbackResult = await this.tryFallbackStrategies(
          currentAgent,
          currentTask,
          error,
          attempt,
          config
        );

        if (fallbackResult.agent) {
          currentAgent = fallbackResult.agent;
          this.logger.info('Switched to fallback agent', {
            taskId: task.id,
            originalAgent: agent.id,
            fallbackAgent: currentAgent.id,
            reason: fallbackResult.reason,
          });
        }

        if (fallbackResult.task) {
          currentTask = fallbackResult.task;
          this.logger.info('Downgraded task configuration', {
            taskId: task.id,
            agentId: currentAgent.id,
            reason: fallbackResult.reason,
          });
        }

      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));

        this.logger.warn('Task execution threw exception', lastError, {
          taskId: task.id,
          agentId: currentAgent.id,
          attempt: attempt + 1,
        });

        // Check if error is retryable
        if (!this.isRetryableError(lastError, config) || attempt === attempts - 1) {
          this.logger.error('Task failed with non-retryable exception or max attempts reached', lastError, {
            taskId: task.id,
            agentId: currentAgent.id,
            totalAttempts: attempt + 1,
          });

          return this.createErrorResult(task.id, currentAgent.id, lastError, attempt);
        }
      }

      // Wait before next retry (if not the last attempt)
      if (attempt < attempts - 1) {
        const delay = this.calculateDelay(attempt, config);

        this.logger.debug('Waiting before retry', {
          taskId: task.id,
          attempt: attempt + 1,
          delay,
          nextAttempt: attempt + 2,
        });

        await this.sleep(delay);
      }
    }

    // If we get here, all attempts failed
    const finalError = lastError || new Error('Max retries exceeded');

    this.logger.error('Task failed after all retry attempts', finalError, {
      taskId: task.id,
      agentId: currentAgent.id,
      totalAttempts: attempts,
    });

    return this.createErrorResult(task.id, currentAgent.id, finalError, attempts - 1);
  }

  /**
   * Try various fallback strategies
   */
  private async tryFallbackStrategies(
    agent: IAgent,
    task: AgentTask,
    error: Error,
    attempt: number,
    config: RetryConfig
  ): Promise<{
    agent?: IAgent;
    task?: AgentTask;
    reason?: string;
  }> {
    const errorMessage = error.message.toLowerCase();

    // Strategy 1: Model downgrade for cost/performance issues
    if (config.enableModelDowngrade && this.shouldDowngradeModel(errorMessage)) {
      const downgradedTask = this.downgradeTask(task);
      if (downgradedTask) {
        return {
          task: downgradedTask,
          reason: 'Model downgraded due to cost/performance constraints',
        };
      }
    }

    // Strategy 2: Agent fallback for availability issues
    if (config.enableAgentFallback && this.shouldSwitchAgent(errorMessage)) {
      const fallbackAgent = await this.selectFallbackAgent(agent, task);
      if (fallbackAgent) {
        return {
          agent: fallbackAgent,
          reason: `Agent unavailable, switched to ${fallbackAgent.id}`,
        };
      }
    }

    // Strategy 3: Constraint relaxation for strict requirements
    if (this.shouldRelaxConstraints(errorMessage)) {
      const relaxedTask = this.relaxTaskConstraints(task);
      if (relaxedTask) {
        return {
          task: relaxedTask,
          reason: 'Task constraints relaxed to improve success probability',
        };
      }
    }

    return {};
  }

  /**
   * Execute task with timeout
   */
  private async executeWithTimeout(
    agent: IAgent,
    task: AgentTask,
    context: BusinessContext,
    timeoutMs: number
  ): Promise<AgentResult> {
    return Promise.race([
      agent.execute(task, context),
      new Promise<AgentResult>((_, reject) =>
        setTimeout(() => reject(new Error('Task timeout')), timeoutMs)
      ),
    ]);
  }

  /**
   * Check if error is retryable
   */
  private isRetryableError(error: Error, config: RetryConfig): boolean {
    const errorMessage = error.message.toLowerCase();

    // Check non-retryable patterns first
    for (const pattern of config.nonRetryableErrors) {
      if (errorMessage.includes(pattern.toLowerCase())) {
        return false;
      }
    }

    // Check retryable patterns
    for (const pattern of config.retryableErrors) {
      if (errorMessage.includes(pattern.toLowerCase())) {
        return true;
      }
    }

    // Default patterns for common retryable errors
    const retryablePatterns = [
      'timeout',
      'rate limit',
      'server error',
      'network error',
      'connection',
      'overloaded',
      'busy',
      'unavailable',
      'temporary'
    ];

    return retryablePatterns.some(pattern => errorMessage.includes(pattern));
  }

  /**
   * Calculate delay for next retry
   */
  private calculateDelay(attempt: number, config: RetryConfig): number {
    let delay = config.baseDelayMs;

    if (config.exponentialBackoff) {
      delay *= Math.pow(2, attempt);
    }

    // Add jitter to prevent thundering herd
    if (config.jitterMs > 0) {
      delay += Math.random() * config.jitterMs;
    }

    return Math.min(delay, 30000); // Cap at 30 seconds
  }

  /**
   * Sleep for specified milliseconds
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Check if should downgrade model
   */
  private shouldDowngradeModel(errorMessage: string): boolean {
    const downgradeIndicators = [
      'cost limit',
      'too expensive',
      'quota exceeded',
      'budget',
      'latency',
      'timeout',
      'slow'
    ];

    return downgradeIndicators.some(indicator => errorMessage.includes(indicator));
  }

  /**
   * Check if should switch agent
   */
  private shouldSwitchAgent(errorMessage: string): boolean {
    const switchIndicators = [
      'agent unavailable',
      'agent offline',
      'agent overloaded',
      'capacity exceeded',
      'service unavailable',
      'connection refused'
    ];

    return switchIndicators.some(indicator => errorMessage.includes(indicator));
  }

  /**
   * Check if should relax constraints
   */
  private shouldRelaxConstraints(errorMessage: string): boolean {
    const relaxIndicators = [
      'constraint',
      'requirement not met',
      'accuracy too high',
      'impossible',
      'unrealistic'
    ];

    return relaxIndicators.some(indicator => errorMessage.includes(indicator));
  }

  /**
   * Downgrade task to use cheaper/faster model
   */
  private downgradeTask(task: AgentTask): AgentTask | null {
    const downgradedTask = { ...task };

    // Increase cost tolerance
    if (downgradedTask.constraints?.maxCost) {
      downgradedTask.constraints.maxCost *= 0.5; // Reduce by half
    } else {
      downgradedTask.constraints = {
        ...downgradedTask.constraints,
        maxCost: 0.001, // Very low cost
      };
    }

    // Reduce accuracy requirements
    if (downgradedTask.constraints?.requiredAccuracy && downgradedTask.constraints.requiredAccuracy > 0.5) {
      downgradedTask.constraints.requiredAccuracy *= 0.8;
    }

    // Increase latency tolerance
    if (downgradedTask.constraints?.maxLatency) {
      downgradedTask.constraints.maxLatency *= 2;
    }

    // Add metadata to indicate downgrade
    downgradedTask.metadata = {
      ...downgradedTask.metadata,
      downgraded: true,
      originalConstraints: task.constraints,
    };

    return downgradedTask;
  }

  /**
   * Select fallback agent for task
   */
  private async selectFallbackAgent(currentAgent: IAgent, task: AgentTask): Promise<IAgent | null> {
    try {
      // Get agents that support this capability
      const candidateAgents = this.registry.getAgentsForCapability(task.capability);

      // Filter out current agent and find best alternative
      const alternatives = candidateAgents.filter(agent => agent.id !== currentAgent.id);

      if (alternatives.length === 0) {
        return null;
      }

      // Prefer agents with lower cost and higher availability
      const scoredAgents = alternatives.map(agent => {
        const agentEntry = this.registry.getAgentEntry(agent.id);
        let score = 0;

        // Health score
        if (agentEntry?.health.healthy) score += 10;

        // Availability score
        const utilization = agentEntry?.loadBalancing.utilization || 0;
        score += (1 - utilization) * 5;

        // Cost score (lower cost = higher score)
        const costScore = Math.max(0, 5 - agent.costPerCall * 1000);
        score += costScore;

        return { agent, score };
      });

      // Sort by score and return best agent
      scoredAgents.sort((a, b) => b.score - a.score);
      return scoredAgents[0]?.agent || null;

    } catch (error) {
      this.logger.error('Failed to select fallback agent', error, {
        currentAgent: currentAgent.id,
        capability: task.capability,
      });
      return null;
    }
  }

  /**
   * Relax task constraints to improve success probability
   */
  private relaxTaskConstraints(task: AgentTask): AgentTask | null {
    const relaxedTask = { ...task };

    if (!relaxedTask.constraints) {
      return null; // No constraints to relax
    }

    // Increase cost limit by 50%
    if (relaxedTask.constraints.maxCost) {
      relaxedTask.constraints.maxCost *= 1.5;
    }

    // Increase latency tolerance by 100%
    if (relaxedTask.constraints.maxLatency) {
      relaxedTask.constraints.maxLatency *= 2;
    }

    // Reduce accuracy requirement by 10%
    if (relaxedTask.constraints.requiredAccuracy && relaxedTask.constraints.requiredAccuracy > 0.6) {
      relaxedTask.constraints.requiredAccuracy *= 0.9;
    }

    // Increase timeout by 50%
    if (relaxedTask.constraints.timeout) {
      relaxedTask.constraints.timeout *= 1.5;
    }

    // Add metadata to indicate relaxation
    relaxedTask.metadata = {
      ...relaxedTask.metadata,
      constraintsRelaxed: true,
      originalConstraints: task.constraints,
    };

    return relaxedTask;
  }

  /**
   * Create error result for failed execution
   */
  private createErrorResult(
    taskId: string,
    agentId: string,
    error: Error,
    retryCount: number
  ): AgentResult {
    return {
      taskId,
      agentId,
      success: false,
      error: error.message,
      metrics: {
        startTime: Date.now(),
        endTime: Date.now(),
        latency: 0,
        cost: 0,
        retryCount,
        memoryHits: 0,
      },
      retry: false, // Don't retry at this level, already exhausted retries
    };
  }

  /**
   * Update retry configuration
   */
  updateConfig(newConfig: Partial<RetryConfig>): void {
    this.defaultConfig = { ...this.defaultConfig, ...newConfig };

    this.logger.info('Retry handler configuration updated', {
      maxRetries: this.defaultConfig.maxRetries,
      baseDelayMs: this.defaultConfig.baseDelayMs,
      enableModelDowngrade: this.defaultConfig.enableModelDowngrade,
      enableAgentFallback: this.defaultConfig.enableAgentFallback,
    });
  }

  /**
   * Get current configuration
   */
  getConfig(): RetryConfig {
    return { ...this.defaultConfig };
  }

  /**
   * Get retry statistics
   */
  getStatistics(): {
    totalRetries: number;
    successAfterRetry: number;
    avgRetriesPerTask: number;
    fallbacksUsed: number;
    modelDowngrades: number;
  } {
    // In a real implementation, these would be tracked
    return {
      totalRetries: 0,
      successAfterRetry: 0,
      avgRetriesPerTask: 0,
      fallbacksUsed: 0,
      modelDowngrades: 0,
    };
  }
}