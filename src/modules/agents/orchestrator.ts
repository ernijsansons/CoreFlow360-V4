/**
 * Agent Orchestrator
 * Routes tasks to appropriate agents with fallback, cost optimization, and monitoring
 */

import type { KVNamespace, D1Database } from '@cloudflare/workers-types';
import {
  AgentTask,
  BusinessContext,
  AgentResult,
  TaskRoutingRequest,
  TaskRoutingResult,
  IAgent,
  AgentConfig,
  OrchestratorConfig,
  MemoryRecord,
  CostRecord,
  RetryConfig,
  FallbackConfig,
  AgentError,
  AgentNotFoundError,
  CapabilityNotSupportedError,
  CostLimitExceededError,
  AgentTaskSchema,
  BusinessContextSchema,
  AGENT_LIMITS,
  COST_LIMITS
} from './types';
import { AgentRegistry } from './registry';
import { ClaudeAgent } from './claude-agent';
import { Logger } from '../../shared/logger';
import { SecurityError, CorrelationId } from '../../shared/security-utils';
import { CapabilityManager } from '../capabilities';
import { AuditService } from '../audit/audit-service';

export class AgentOrchestrator {
  private logger: Logger;
  private registry: AgentRegistry;
  private config: OrchestratorConfig;
  private capabilityManager: CapabilityManager;
  private auditService: AuditService;
  private kv: KVNamespace;
  private db: D1Database;

  // Active task tracking
  private activeTasks = new Map<string, {
    task: AgentTask;
    startTime: number;
    agentId: string;
    abortController: AbortController;
  }>();

  // Cost tracking
  private dailyCosts = new Map<string, number>(); // businessId -> cost
  private monthlyCosts = new Map<string, number>(); // businessId -> cost

  // Memory management
  private shortTermMemory = new Map<string, MemoryRecord[]>(); // userId -> records
  private memoryCleanupInterval?: number;

  // Performance metrics
  private metrics = {
    totalTasks: 0,
    completedTasks: 0,
    failedTasks: 0,
    totalCost: 0,
    averageLatency: 0,
    routingDecisions: new Map<string, number>(), // agentId -> count
  };

  constructor(
    kv: KVNamespace,
    db: D1Database,
    capabilityManager: CapabilityManager,
    auditService: AuditService,
    config?: Partial<OrchestratorConfig>
  ) {
    this.kv = kv;
    this.db = db;
    this.capabilityManager = capabilityManager;
    this.auditService = auditService;
    this.logger = new Logger();
    this.registry = new AgentRegistry(kv);

    // Default configuration
    this.config = {
      routing: {
        strategy: 'capability_based',
        fallbackEnabled: true,
        loadBalancingEnabled: true,
      },
      memory: {
        shortTermEnabled: true,
        longTermEnabled: true,
        contextWindowSize: 10,
        retentionPolicy: {
          conversationDays: 7,
          factsDays: 30,
          preferencesDays: 90,
        },
      },
      costManagement: {
        enabled: true,
        dailyLimitUSD: COST_LIMITS.DEFAULT_DAILY_LIMIT_USD,
        monthlyLimitUSD: COST_LIMITS.DEFAULT_MONTHLY_LIMIT_USD,
        alertThresholds: COST_LIMITS.ALERT_THRESHOLDS,
        costOptimizationEnabled: true,
      },
      performance: {
        caching: {
          enabled: true,
          ttlSeconds: 3600,
          maxCacheSize: 1000,
        },
        concurrent: {
          maxPerUser: 5,
          maxGlobal: 100,
          queueSize: 1000,
        },
        timeouts: {
          defaultTaskTimeout: AGENT_LIMITS.DEFAULT_TIMEOUT_MS,
          healthCheckTimeout: 10000,
          streamingTimeout: AGENT_LIMITS.MAX_STREAMING_DURATION_MS,
        },
      },
      monitoring: {
        metricsEnabled: true,
        healthCheckInterval: 30000,
        alertingEnabled: true,
        logLevel: 'info',
      },
      ...config,
    };

    this.initializeOrchestrator();
  }

  /**
   * Execute a task with automatic agent selection and routing
   */
  async executeTask(
    task: AgentTask,
    context: BusinessContext,
    preferences?: TaskRoutingRequest['preferences']
  ): Promise<AgentResult> {
    const startTime = Date.now();
    const abortController = new AbortController();

    try {
      // Validate inputs
      AgentTaskSchema.parse(task);
      BusinessContextSchema.parse(context);

      // Check concurrency limits
      await this.checkConcurrencyLimits(context.userId);

      // Check cost limits
      if (this.config.costManagement.enabled) {
        await this.checkCostLimits(context.businessId, task);
      }

      // Route task to appropriate agent
      const routingResult = await this.routeTask({
        task,
        preferences,
        fallbackEnabled: this.config.routing.fallbackEnabled,
      });

      // Get agent instance
      const agent = this.registry.getAgent(routingResult.selectedAgent);
      if (!agent) {
        throw new AgentNotFoundError(routingResult.selectedAgent);
      }

      // Track active task
      this.activeTasks.set(task.id, {
        task,
        startTime,
        agentId: routingResult.selectedAgent,
        abortController,
      });

      // Inject business context and memory
      const enhancedTask = await this.enhanceTaskWithContext(task, context);

      // Execute with retry logic
      const result = await this.executeWithRetry(
        agent,
        enhancedTask,
        context,
        abortController.signal
      );

      // Update metrics and costs
      await this.updateMetrics(result, routingResult.selectedAgent);
      await this.trackCost(result, context);

      // Store memory if enabled
      if (this.config.memory.shortTermEnabled || this.config.memory.longTermEnabled) {
        await this.storeMemory(task, result, context);
      }

      // Emit audit event
      await this.auditService.logEvent({
        eventType: 'agent_task_completed',
        severity: 'low',
        operation: `agent_task:${task.capability}`,
        result: 'success',
        details: {
          taskId: task.id,
          agentId: routingResult.selectedAgent,
          capability: task.capability,
          executionTime: result.metrics.executionTime,
          cost: result.metrics.costUSD,
          tokensUsed: result.metrics.tokensUsed,
        },
        securityContext: {
          correlationId: context.correlationId,
          userId: context.userId,
          businessId: context.businessId,
          operation: `agent_orchestration:${task.capability}`,
        },
      });

      this.logger.info('Task executed successfully', {
        taskId: task.id,
        capability: task.capability,
        agentId: routingResult.selectedAgent,
        executionTime: result.metrics.executionTime,
        cost: result.metrics.costUSD,
        correlationId: context.correlationId,
      });

      return result;

    } catch (error: any) {
      const executionTime = Date.now() - startTime;

      // Create error result
      const errorResult: AgentResult = {
        taskId: task.id,
        agentId: 'orchestrator',
        status: 'failed',
        error: {
          code: this.getErrorCode(error),
          message: error instanceof Error ? error.message : 'Unknown error',
          retryable: this.isRetryableError(error),
          category: this.getErrorCategory(error),
        },
        metrics: {
          executionTime,
          costUSD: 0,
          retryCount: 0,
        },
        startedAt: startTime,
        completedAt: Date.now(),
      };

      // Update failure metrics
      this.metrics.failedTasks++;

      // Emit audit event for failure
      await this.auditService.logEvent({
        eventType: 'agent_task_failed',
        severity: 'medium',
        operation: `agent_task:${task.capability}`,
        result: 'failure',
        details: {
          taskId: task.id,
          capability: task.capability,
          error: errorResult.error,
          executionTime,
        },
        securityContext: {
          correlationId: context.correlationId,
          userId: context.userId,
          businessId: context.businessId,
          operation: `agent_orchestration:${task.capability}`,
        },
      });

      this.logger.error('Task execution failed', error, {
        taskId: task.id,
        capability: task.capability,
        executionTime,
        correlationId: context.correlationId,
      });

      return errorResult;

    } finally {
      this.activeTasks.delete(task.id);
    }
  }

  /**
   * Route task to best available agent
   */
  async routeTask(request: TaskRoutingRequest): Promise<TaskRoutingResult> {
    const { task, preferences } = request;

    try {
      // Find agents that support the required capability
      const candidates = this.registry.findAgentsByCapability(
        task.capability,
        true // require online
      );

      if (candidates.length === 0) {
        throw new CapabilityNotSupportedError(task.capability, 'any');
      }

      // Filter by preferences
      let filtered = candidates;
      if (preferences?.excludedAgents) {
        filtered = candidates.filter((entry: any) =>
          !preferences.excludedAgents!.includes(entry.config.id)
        );
      }

      if (preferences?.preferredAgents) {
        const preferred = filtered.filter((entry: any) =>
          preferences.preferredAgents!.includes(entry.config.id)
        );
        if (preferred.length > 0) {
          filtered = preferred;
        }
      }

      if (filtered.length === 0) {
        throw new AgentError(
          'No suitable agents available after applying preferences',
          'NO_SUITABLE_AGENTS',
          'routing'
        );
      }

      // Score and rank agents
      const scoredAgents = await Promise.all(
        filtered.map(async entry => {
          const score = await this.scoreAgent(entry, task, preferences);
          return { entry, score };
        })
      );

      // Sort by score (higher is better)
      scoredAgents.sort((a, b) => b.score.total - a.score.total);

      const selectedAgent = scoredAgents[0].entry;
      const alternatives = scoredAgents.slice(1, 3).map(({ entry, score }) => ({
        agentId: entry.config.id,
        score: score.total,
        reason: score.reasoning,
      }));

      // Estimate cost and latency
      const estimatedCost = await this.estimateTaskCost(task, selectedAgent.config.id);
      const estimatedLatency = selectedAgent.metrics.averageLatency || selectedAgent.config.costPerCall * 1000;

      return {
        selectedAgent: selectedAgent.config.id,
        reasoning: scoredAgents[0].score.reasoning,
        alternatives,
        estimatedCost,
        estimatedLatency,
      };

    } catch (error: any) {
      this.logger.error('Task routing failed', error, {
        taskId: task.id,
        capability: task.capability,
      });
      throw error;
    }
  }

  /**
   * Get memory context for a user
   */
  async getMemoryContext(
    userId: string,
    businessId: string,
    capability?: string
  ): Promise<MemoryRecord[]> {
    try {
      let records: MemoryRecord[] = [];

      // Get short-term memory
      if (this.config.memory.shortTermEnabled) {
        const shortTerm = this.shortTermMemory.get(userId) || [];
        records.push(...shortTerm);
      }

      // Get long-term memory from D1
      if (this.config.memory.longTermEnabled) {
        const longTerm = await this.getLongTermMemory(userId, businessId, capability);
        records.push(...longTerm);
      }

      // Filter by relevance and recency
      records = records
        .filter((record: any) => {
          const ageMs = Date.now() - record.lifecycle.createdAt;
          const ageDays = ageMs / (24 * 60 * 60 * 1000);

          switch (record.type) {
            case 'conversation':
              return ageDays <= this.config.memory.retentionPolicy.conversationDays;
            case 'fact':
              return ageDays <= this.config.memory.retentionPolicy.factsDays;
            case 'preference':
              return ageDays <= this.config.memory.retentionPolicy.preferencesDays;
            default:
              return ageDays <= 7; // Default 7 days
          }
        })
        .sort((a, b) => b.relevance.importance - a.relevance.importance)
        .slice(0, this.config.memory.contextWindowSize);

      return records;

    } catch (error: any) {
      this.logger.error('Failed to get memory context', error, {
        userId,
        businessId,
        capability,
      });
      return [];
    }
  }

  /**
   * Register a new agent
   */
  async registerAgent(config: AgentConfig, instance?: IAgent): Promise<void> {
    await this.registry.registerAgent(config, instance);

    this.logger.info('Agent registered with orchestrator', {
      agentId: config.id,
      name: config.name,
      capabilities: config.capabilities,
    });
  }

  /**
   * Get orchestrator metrics
   */
  getMetrics(): typeof this.metrics & {
    activeTaskCount: number;
    registeredAgents: number;
    systemHealth: any;
  } {
    return {
      ...this.metrics,
      activeTaskCount: this.activeTasks.size,
      registeredAgents: this.registry.listAgents().length,
      systemHealth: this.registry.getSystemMetrics(),
    };
  }

  /**
   * Cancel a running task
   */
  async cancelTask(taskId: string, reason: string = 'User cancelled'): Promise<boolean> {
    const activeTask = this.activeTasks.get(taskId);
    if (!activeTask) {
      return false;
    }

    try {
      activeTask.abortController.abort();
      this.activeTasks.delete(taskId);

      this.logger.info('Task cancelled', {
        taskId,
        reason,
        agentId: activeTask.agentId,
        executionTime: Date.now() - activeTask.startTime,
      });

      return true;

    } catch (error: any) {
      this.logger.error('Failed to cancel task', error, { taskId, reason });
      return false;
    }
  }

  /**
   * Shutdown orchestrator
   */
  async shutdown(): Promise<void> {
    try {
      // Cancel all active tasks
      const taskIds = Array.from(this.activeTasks.keys());
      await Promise.allSettled(
        taskIds.map((taskId: any) => this.cancelTask(taskId, 'System shutdown'))
      );

      // Stop periodic tasks
      if (this.memoryCleanupInterval) {
        clearInterval(this.memoryCleanupInterval);
      }

      // Shutdown registry
      await this.registry.shutdown();

      this.logger.info('Agent orchestrator shutdown completed');

    } catch (error: any) {
      this.logger.error('Failed to shutdown orchestrator', error);
      throw error;
    }
  }

  /**
   * Private methods
   */

  private async initializeOrchestrator(): Promise<void> {
    try {
      // Load agents from storage
      await this.registry.loadAgentsFromStorage();

      // Register default Claude agent if API key is available
      const claudeApiKey = process.env.ANTHROPIC_API_KEY;
      if (claudeApiKey) {
        const claudeAgent = new ClaudeAgent(claudeApiKey, this.capabilityManager);

        const claudeConfig: AgentConfig = {
          id: 'claude-3-5-sonnet',
          name: 'Claude 3.5 Sonnet',
          type: 'external',
          enabled: true,
          apiEndpoint: 'https://api.anthropic.com/v1',
          model: 'claude-3-5-sonnet-20241022',
          fallbackModels: ['claude-3-haiku-20240307'],
          maxTokens: 8192,
          temperature: 0.1,
          capabilities: claudeAgent.capabilities,
          departments: claudeAgent.departments,
          maxConcurrency: claudeAgent.maxConcurrency,
          costPerCall: claudeAgent.costPerCall,
          streamingEnabled: true,
          fallbackEnabled: true,
          cachingEnabled: true,
          loggingEnabled: true,
          owner: 'system',
          description: 'Anthropic Claude 3.5 Sonnet for general business tasks',
          tags: ['llm', 'anthropic', 'production'],
          createdAt: Date.now(),
          updatedAt: Date.now(),
        };

        await this.registry.registerAgent(claudeConfig, claudeAgent);
      }

      // Register QualificationAgent for BANT lead qualification
      try {
        const { QualificationAgent } = await import('./qualification-agent');
        const qualificationAgent = new QualificationAgent({
          DB_MAIN: this.db,
          ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY
        });

        const qualificationConfig: AgentConfig = {
          id: 'qualification-agent',
          name: 'BANT Qualification Agent',
          type: 'specialized',
          enabled: true,
          capabilities: qualificationAgent.capabilities,
          departments: qualificationAgent.departments,
          maxConcurrency: qualificationAgent.maxConcurrency,
          costPerCall: qualificationAgent.costPerCall,
          streamingEnabled: false,
          fallbackEnabled: true,
          cachingEnabled: true,
          loggingEnabled: true,
          owner: 'system',
          description: 'AI agent specialized in BANT lead qualification methodology',
          tags: qualificationAgent.tags,
          createdAt: Date.now(),
          updatedAt: Date.now(),
        };

        await this.registry.registerAgent(qualificationConfig, qualificationAgent);

        this.logger.info('QualificationAgent registered successfully', {
          agentId: qualificationConfig.id,
          capabilities: qualificationConfig.capabilities
        });
      } catch (error: any) {
        this.logger.error('Failed to register QualificationAgent', error);
        // Continue initialization even if qualification agent fails
      }

      // Start periodic tasks
      this.startPeriodicTasks();

      this.logger.info('Agent orchestrator initialized', {
        registeredAgents: this.registry.listAgents().length,
        configuredCapabilities: this.config,
      });

    } catch (error: any) {
      this.logger.error('Failed to initialize orchestrator', error);
      throw error;
    }
  }

  private async checkConcurrencyLimits(userId: string): Promise<void> {
    // Check user-specific limit
    const userTasks = Array.from(this.activeTasks.values())
      .filter((task: any) => task.task.context.userId === userId);

    if (userTasks.length >= this.config.performance.concurrent.maxPerUser) {
      throw new AgentError(
        `User has reached maximum concurrent tasks limit (${this.config.performance.concurrent.maxPerUser})`,
        'USER_CONCURRENCY_LIMIT',
        'system'
      );
    }

    // Check global limit
    if (this.activeTasks.size >= this.config.performance.concurrent.maxGlobal) {
      throw new AgentError(
        `System has reached maximum concurrent tasks limit (${this.config.performance.concurrent.maxGlobal})`,
        'GLOBAL_CONCURRENCY_LIMIT',
        'system'
      );
    }
  }

  private async checkCostLimits(businessId: string, task: AgentTask): Promise<void> {
    const today = new Date().toISOString().split('T')[0];
    const currentMonth = new Date().toISOString().slice(0, 7);

    // Get current costs
    const dailyCost = this.dailyCosts.get(`${businessId}:${today}`) || 0;
    const monthlyCost = this.monthlyCosts.get(`${businessId}:${currentMonth}`) || 0;

    // Estimate task cost
    const estimatedCost = task.constraints?.maxCost || 1.0;

    // Check daily limit
    if (this.config.costManagement.dailyLimitUSD) {
      if (dailyCost + estimatedCost > this.config.costManagement.dailyLimitUSD) {
        throw new CostLimitExceededError(
          dailyCost + estimatedCost,
          this.config.costManagement.dailyLimitUSD
        );
      }
    }

    // Check monthly limit
    if (this.config.costManagement.monthlyLimitUSD) {
      if (monthlyCost + estimatedCost > this.config.costManagement.monthlyLimitUSD) {
        throw new CostLimitExceededError(
          monthlyCost + estimatedCost,
          this.config.costManagement.monthlyLimitUSD
        );
      }
    }
  }

  private async enhanceTaskWithContext(
    task: AgentTask,
    context: BusinessContext
  ): Promise<AgentTask> {
    // Get relevant memory context
    const memoryContext = await this.getMemoryContext(
      context.userId,
      context.businessId,
      task.capability
    );

    // Enhance task with memory and business context
    const enhancedTask: AgentTask = {
      ...task,
      input: {
        ...task.input,
        memoryContext: memoryContext.length > 0 ? memoryContext : undefined,
        businessContext: context.businessData,
        userContext: context.userContext,
      },
    };

    return enhancedTask;
  }

  private async executeWithRetry(
    agent: IAgent,
    task: AgentTask,
    context: BusinessContext,
    signal: AbortSignal
  ): Promise<AgentResult> {
    const retryConfig: RetryConfig = {
      maxRetries: 3,
      baseDelayMs: 1000,
      exponentialBackoff: true,
      jitterMs: 500,
      retryableErrors: ['RATE_LIMIT_EXCEEDED', 'SERVER_ERROR', 'TIMEOUT'],
      nonRetryableErrors: ['VALIDATION_FAILED', 'PERMISSION_DENIED', 'COST_LIMIT_EXCEEDED'],
      timeoutMs: this.config.performance.timeouts.defaultTaskTimeout,
    };

    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= retryConfig.maxRetries; attempt++) {
      try {
        // Check if request was aborted
        if (signal.aborted) {
          throw new AgentError('Task was cancelled', 'TASK_CANCELLED', 'system');
        }

        // Execute task
        const result = await Promise.race([
          agent.execute(task, context),
          new Promise<never>((_, reject) => {
            setTimeout(() => reject(new Error('Task timeout')), retryConfig.timeoutMs);
          }),
        ]);

        // Update retry count in result
        result.metrics.retryCount = attempt;

        return result;

      } catch (error: any) {
        lastError = error instanceof Error ? error : new Error(String(error));

        // Check if error is retryable
        const errorCode = this.getErrorCode(error);
        if (retryConfig.nonRetryableErrors.includes(errorCode) || attempt === retryConfig.maxRetries) {
          throw lastError;
        }

        if (!retryConfig.retryableErrors.includes(errorCode)) {
          throw lastError;
        }

        // Calculate delay with exponential backoff and jitter
        let delay = retryConfig.baseDelayMs;
        if (retryConfig.exponentialBackoff) {
          delay *= Math.pow(2, attempt);
        }
        delay += Math.random() * retryConfig.jitterMs;

        this.logger.warn('Retrying task execution', {
          taskId: task.id,
          attempt: attempt + 1,
          maxRetries: retryConfig.maxRetries,
          delay,
          error: lastError.message,
        });

        // Wait before retry
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }

    throw lastError || new Error('Unknown retry error');
  }

  private async scoreAgent(
    entry: any,
    task: AgentTask,
    preferences?: TaskRoutingRequest['preferences']
  ): Promise<{ total: number; reasoning: string }> {
    let score = 0;
    const reasons: string[] = [];

    // Base capability score
    if (entry.config.capabilities.includes(task.capability)) {
      score += 10;
      reasons.push('supports capability');
    }

    // Department matching
    const taskDepartment = task.metadata?.department || task.context.userContext.department;
    if (taskDepartment && entry.config.departments?.includes(taskDepartment)) {
      score += 5;
      reasons.push('department match');
    }

    // Cost optimization
    if (preferences?.costOptimized) {
      const costScore = Math.max(0, 10 - entry.config.costPerCall * 100);
      score += costScore;
      reasons.push(`low cost (${entry.config.costPerCall})`);
    }

    // Latency optimization
    if (preferences?.latencyOptimized) {
      const latencyScore = Math.max(0, 10 - entry.metrics.averageLatency / 1000);
      score += latencyScore;
      reasons.push(`low latency (${entry.metrics.averageLatency}ms)`);
    }

    // Success rate
    const successRate = entry.metrics.totalTasks > 0
      ? entry.metrics.successfulTasks / entry.metrics.totalTasks
      : 0.5;
    score += successRate * 10;
    reasons.push(`success rate (${Math.round(successRate * 100)}%)`);

    // Load balancing
    const loadScore = Math.max(0, 10 - entry.loadBalancing.activeConnections);
    score += loadScore;
    reasons.push(`load (${entry.loadBalancing.activeConnections} active)`);

    // Health status
    if (entry.health.status === 'online') {
      score += 5;
      reasons.push('healthy');
    } else if (entry.health.status === 'degraded') {
      score += 2;
      reasons.push('degraded');
    }

    return {
      total: score,
      reasoning: reasons.join(', '),
    };
  }

  private async estimateTaskCost(task: AgentTask, agentId: string): Promise<number> {
    const agent = this.registry.getAgent(agentId);
    if (!agent) {
      return 0;
    }

    try {
      return await agent.estimateCost(task);
    } catch (error: any) {
      this.logger.warn('Failed to estimate task cost', error, { taskId: task.id, agentId });
      return 0;
    }
  }

  private async updateMetrics(result: AgentResult, agentId: string): Promise<void> {
    this.metrics.totalTasks++;

    if (result.status === 'completed') {
      this.metrics.completedTasks++;
    } else {
      this.metrics.failedTasks++;
    }

    this.metrics.totalCost += result.metrics.costUSD;

    // Update average latency
    const totalTasks = this.metrics.totalTasks;
    if (totalTasks > 0) {
      this.metrics.averageLatency =
        (this.metrics.averageLatency * (totalTasks - 1) + result.metrics.executionTime) / totalTasks;
    }

    // Update routing decisions
    const routingCount = this.metrics.routingDecisions.get(agentId) || 0;
    this.metrics.routingDecisions.set(agentId, routingCount + 1);

    // Update agent metrics in registry
    this.registry.updateAgentMetrics(agentId, {
      taskCompleted: true,
      success: result.status === 'completed',
      latency: result.metrics.executionTime,
      cost: result.metrics.costUSD,
    });
  }

  private async trackCost(result: AgentResult, context: BusinessContext): Promise<void> {
    const cost = result.metrics.costUSD;
    const today = new Date().toISOString().split('T')[0];
    const currentMonth = new Date().toISOString().slice(0, 7);

    // Update daily costs
    const dailyKey = `${context.businessId}:${today}`;
    const currentDaily = this.dailyCosts.get(dailyKey) || 0;
    this.dailyCosts.set(dailyKey, currentDaily + cost);

    // Update monthly costs
    const monthlyKey = `${context.businessId}:${currentMonth}`;
    const currentMonthly = this.monthlyCosts.get(monthlyKey) || 0;
    this.monthlyCosts.set(monthlyKey, currentMonthly + cost);

    // Store cost record in database
    if (this.db) {
      try {
        const costRecord: CostRecord = {
          id: CorrelationId.generate(),
          taskId: result.taskId,
          agentId: result.agentId,
          userId: context.userId,
          businessId: context.businessId,
          costs: {
            inputTokens: Math.floor((result.metrics.tokensUsed || 0) * 0.6),
            outputTokens: Math.floor((result.metrics.tokensUsed || 0) * 0.4),
            totalTokens: result.metrics.tokensUsed || 0,
            modelCost: cost * 0.9, // Approximate model cost
            processingCost: cost * 0.1, // Approximate processing cost
            storageCost: 0,
            totalCostUSD: cost,
          },
          billing: {
            model: result.metrics.modelUsed || 'unknown',
            provider: 'anthropic',
            tier: 'standard',
          },
          timestamp: Date.now(),
        };

        // Use INSERT OR REPLACE with task_id as unique key for idempotency
        await this.db.prepare(`
          INSERT OR REPLACE INTO agent_costs (
            id, task_id, agent_id, user_id, business_id,
            input_tokens, output_tokens, total_tokens,
            model_cost, processing_cost, storage_cost, total_cost_usd,
            model, provider, tier, timestamp
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          costRecord.id,
          costRecord.taskId,
          costRecord.agentId,
          costRecord.userId,
          costRecord.businessId,
          costRecord.costs.inputTokens,
          costRecord.costs.outputTokens,
          costRecord.costs.totalTokens,
          costRecord.costs.modelCost,
          costRecord.costs.processingCost,
          costRecord.costs.storageCost,
          costRecord.costs.totalCostUSD,
          costRecord.billing.model,
          costRecord.billing.provider,
          costRecord.billing.tier,
          costRecord.timestamp
        ).run();

      } catch (error: any) {
        this.logger.error('Failed to store cost record', error, {
          taskId: result.taskId,
          cost,
        });
      }
    }
  }

  private async storeMemory(
    task: AgentTask,
    result: AgentResult,
    context: BusinessContext
  ): Promise<void> {
    try {
      const memoryRecord: MemoryRecord = {
        id: CorrelationId.generate(),
        type: 'conversation',
        userId: context.userId,
        businessId: context.businessId,
        agentId: result.agentId,
        content: {
          summary: `${task.capability}: ${task.input.prompt?.substring(0, 100)}...`,
          details: {
            task: {
              capability: task.capability,
              input: task.input,
              type: task.type,
            },
            result: {
              data: result.result?.data,
              confidence: result.result?.confidence,
            },
          },
          context: {
            department: context.userContext.department,
            businessContext: context.businessData,
          },
        },
        relevance: {
          department: context.userContext.department,
          capability: task.capability,
          keywords: this.extractKeywords(task.input.prompt || ''),
          importance: result.result?.confidence || 0.5,
        },
        lifecycle: {
          createdAt: Date.now(),
          updatedAt: Date.now(),
          accessedAt: Date.now(),
          version: 1,
        },
      };

      // Store in short-term memory
      if (this.config.memory.shortTermEnabled) {
        const userMemory = this.shortTermMemory.get(context.userId) || [];
        userMemory.push(memoryRecord);

        // Keep only most recent records
        if (userMemory.length > this.config.memory.contextWindowSize) {
          userMemory.splice(0, userMemory.length - this.config.memory.contextWindowSize);
        }

        this.shortTermMemory.set(context.userId, userMemory);
      }

      // Store in long-term memory (D1)
      if (this.config.memory.longTermEnabled && this.db) {
        await this.db.prepare(`
          INSERT INTO agent_memory (
            id, type, user_id, business_id, agent_id,
            summary, details, context, department, capability,
            keywords, importance, created_at, updated_at, accessed_at, version
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          memoryRecord.id,
          memoryRecord.type,
          memoryRecord.userId,
          memoryRecord.businessId,
          memoryRecord.agentId,
          memoryRecord.content.summary,
          JSON.stringify(memoryRecord.content.details),
          JSON.stringify(memoryRecord.content.context),
          memoryRecord.relevance.department,
          memoryRecord.relevance.capability,
          JSON.stringify(memoryRecord.relevance.keywords),
          memoryRecord.relevance.importance,
          memoryRecord.lifecycle.createdAt,
          memoryRecord.lifecycle.updatedAt,
          memoryRecord.lifecycle.accessedAt,
          memoryRecord.lifecycle.version
        ).run();
      }

    } catch (error: any) {
      this.logger.error('Failed to store memory', error, {
        taskId: task.id,
        userId: context.userId,
      });
    }
  }

  private async getLongTermMemory(
    userId: string,
    businessId: string,
    capability?: string
  ): Promise<MemoryRecord[]> {
    if (!this.db) return [];

    try {
      let query = `
        SELECT * FROM agent_memory
        WHERE user_id = ? AND business_id = ?
      `;
      const params = [userId, businessId];

      if (capability) {
        query += ` AND capability = ?`;
        params.push(capability);
      }

      query += ` ORDER BY importance DESC, accessed_at DESC LIMIT ?`;
      params.push(this.config.memory.contextWindowSize.toString());

      const result = await this.db.prepare(query).bind(...params).all();

      return result.results.map((row: any) => ({
        id: row.id,
        type: row.type,
        userId: row.user_id,
        businessId: row.business_id,
        agentId: row.agent_id,
        content: {
          summary: row.summary,
          details: JSON.parse(row.details),
          context: JSON.parse(row.context),
        },
        relevance: {
          department: row.department,
          capability: row.capability,
          keywords: JSON.parse(row.keywords),
          importance: row.importance,
        },
        lifecycle: {
          createdAt: row.created_at,
          updatedAt: row.updated_at,
          accessedAt: row.accessed_at,
          version: row.version,
        },
      }));

    } catch (error: any) {
      this.logger.error('Failed to get long-term memory', error, {
        userId,
        businessId,
        capability,
      });
      return [];
    }
  }

  private extractKeywords(text: string): string[] {
    // Simple keyword extraction - in production, use more sophisticated NLP
    const words = text.toLowerCase()
      .replace(/[^\w\s]/g, '')
      .split(/\s+/)
      .filter((word: any) => word.length > 3);

    // Remove common stop words
    const stopWords = new Set(['this', 'that', 'with', 'have', 'will', 'from', 'they', 'been', 'said', 'each', 'which', 'their', 'time', 'would', 'there', 'about', 'could', 'other', 'after', 'first', 'more', 'very', 'what', 'know', 'just', 'also', 'into', 'over', 'think', 'only', 'new', 'good', 'much', 'work', 'life', 'way', 'well', 'year', 'come', 'make', 'take', 'see', 'how', 'people', 'day', 'man', 'get', 'old', 'want', 'here', 'say', 'right', 'look', 'still', 'back',
  'call', 'give', 'hand', 'last', 'long', 'place', 'great', 'small', 'every', 'own', 'under', 'might', 'never', 'house', 'head', 'high', 'same', 'both', 'those', 'does', 'part', 'while', 'where', 'turn', 'again', 'keep', 'though', 'little', 'world', 'seem', 'many', 'different', 'between', 'important', 'being', 'system', 'group', 'number', 'against', 'should', 'without', 'another', 'large', 'company', 'business', 'financial', 'invoice', 'analysis', 'report', 'data', 'information', 'process', 'management', 'service', 'customer', 'market', 'sales', 'product', 'project', 'team', 'employee', 'department', 'organization']);

    return words
      .filter((word: any) => !stopWords.has(word))
      .slice(0, 10); // Keep top 10 keywords
  }

  private startPeriodicTasks(): void {
    // Memory cleanup every 5 minutes
    this.memoryCleanupInterval = setInterval(() => {
      this.cleanupMemory().catch((error: any) => {
        this.logger.error('Memory cleanup failed', error);
      });
    }, 300000) as any;
  }

  private async cleanupMemory(): Promise<void> {
    const now = Date.now();

    // Cleanup short-term memory
    for (const [userId, records] of this.shortTermMemory.entries()) {
      const filtered = records.filter((record: any) => {
        const ageMs = now - record.lifecycle.createdAt;
        const ageDays = ageMs / (24 * 60 * 60 * 1000);
        return ageDays <= this.config.memory.retentionPolicy.conversationDays;
      });

      if (filtered.length !== records.length) {
        this.shortTermMemory.set(userId, filtered);
      }
    }

    // Cleanup long-term memory in D1
    if (this.db) {
      try {
        const cutoffTime = now - (this.config.memory.retentionPolicy.conversationDays * 24 * 60 * 60 * 1000);
        await this.db.prepare(`
          DELETE FROM agent_memory
          WHERE type = 'conversation' AND created_at < ?
        `).bind(cutoffTime).run();

        const factsCutoff = now - (this.config.memory.retentionPolicy.factsDays * 24 * 60 * 60 * 1000);
        await this.db.prepare(`
          DELETE FROM agent_memory
          WHERE type = 'fact' AND created_at < ?
        `).bind(factsCutoff).run();

        const preferencesCutoff = now - (this.config.memory.retentionPolicy.preferencesDays * 24 * 60 * 60 * 1000);
        await this.db.prepare(`
          DELETE FROM agent_memory
          WHERE type = 'preference' AND created_at < ?
        `).bind(preferencesCutoff).run();

      } catch (error: any) {
        this.logger.error('Failed to cleanup long-term memory', error);
      }
    }
  }

  private getErrorCode(error: unknown): string {
    if (error instanceof AgentError) return error.code;
    if (error instanceof Error) {
      if (error.message.includes('timeout')) return 'TIMEOUT';
      if (error.message.includes('network')) return 'NETWORK_ERROR';
      if (error.message.includes('rate limit')) return 'RATE_LIMIT_EXCEEDED';
    }
    return 'UNKNOWN_ERROR';
  }

  private getErrorCategory(error: unknown): string {
    if (error instanceof AgentError) return error.category;
    if (error instanceof CostLimitExceededError) return 'cost';
    return 'system';
  }

  private isRetryableError(error: unknown): boolean {
    if (error instanceof AgentError) return error.retryable;
    const code = this.getErrorCode(error);
    return ['TIMEOUT', 'NETWORK_ERROR', 'RATE_LIMIT_EXCEEDED', 'SERVER_ERROR'].includes(code);
  }
}