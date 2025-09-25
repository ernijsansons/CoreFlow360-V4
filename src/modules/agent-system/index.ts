/**
 * Modular Agent Integration System for CoreFlow360 V4
 * Complete agent system with Claude integration and architecture for hundreds of specialized agents
 */

// ============================================================================
// CORE EXPORTS
// ============================================================================

// Core interfaces and types
export * from './types';

// Agent registry and management
export { AgentRegistry } from './registry';

// Native Claude agent implementation
export { ClaudeNativeAgent } from './claude-native-agent';

// Orchestration and routing
export { AgentOrchestrator } from './orchestrator';

// Memory management
export { AgentMemory } from './memory';

// Cost tracking and governance
export { CostTracker } from './cost-tracker';

// Retry and fallback logic
export { RetryHandler } from './retry-handler';

// Streaming responses
export { StreamingHandler } from './streaming-handler';

// Capability contracts
export { CapabilityRegistry } from './capability-registry';

// Integration tests
export { runIntegrationTests } from './integration-tests';

// ============================================================================
// FACTORY FUNCTIONS
// ============================================================================

import type { KVNamespace, D1Database } from '@cloudflare/workers-types';
import {
  AgentTask,
  BusinessContext,
  OrchestratorResult,
  WorkflowResult,
  Workflow,
  CapabilityContract,
  CostLimits
} from './types';
import { AgentRegistry } from './registry';
import { ClaudeNativeAgent } from './claude-native-agent';
import { AgentOrchestrator } from './orchestrator';
import { AgentMemory } from './memory';
import { CostTracker } from './cost-tracker';
import { RetryHandler } from './retry-handler';
import { StreamingHandler } from './streaming-handler';
import { CapabilityRegistry } from './capability-registry';
import { Logger } from '../../shared/logger';

/**
 * Configuration for the agent system
 */
export interface AgentSystemConfig {
  // Environment bindings
  kv: KVNamespace;
  db: D1Database;

  // API keys
  anthropicApiKey?: string;

  // Cost limits
  defaultCostLimits?: Partial<CostLimits>;

  // Feature flags
  enableStreaming?: boolean;
  enableRetries?: boolean;
  enableMemory?: boolean;
  enableCostTracking?: boolean;

  // Performance settings
  maxConcurrentTasks?: number;
  defaultTimeout?: number;
  retryAttempts?: number;

  // Logging
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
}

/**
 * Complete Agent System Factory
 * Creates and configures the entire agent system
 */
export class AgentSystemFactory {
  private logger: Logger;
  private config: AgentSystemConfig;

  private registry?: AgentRegistry;
  private orchestrator?: AgentOrchestrator;
  private capabilityRegistry?: CapabilityRegistry;
  private memory?: AgentMemory;
  private costTracker?: CostTracker;
  private retryHandler?: RetryHandler;
  private streamingHandler?: StreamingHandler;

  constructor(config: AgentSystemConfig) {
    this.config = config;
    this.logger = new Logger();
  }

  /**
   * Initialize the complete agent system
   */
  async initialize(): Promise<AgentSystem> {
    const startTime = Date.now();

    try {
      this.logger.info('Initializing Agent System...', {
        enableStreaming: this.config.enableStreaming ?? true,
        enableRetries: this.config.enableRetries ?? true,
        enableMemory: this.config.enableMemory ?? true,
        enableCostTracking: this.config.enableCostTracking ?? true,
      });

      // Initialize core components
      this.registry = new AgentRegistry(this.config.kv);
      this.capabilityRegistry = new CapabilityRegistry();

      if (this.config.enableMemory !== false) {
        this.memory = new AgentMemory(this.config.kv, this.config.db);
      }

      if (this.config.enableCostTracking !== false) {
        this.costTracker = new CostTracker(
          this.config.kv,
          this.config.db,
          this.config.defaultCostLimits
        );
      }

      if (this.config.enableRetries !== false) {
        this.retryHandler = new RetryHandler(this.registry);
      }

      if (this.config.enableStreaming !== false) {
        this.streamingHandler = new StreamingHandler();
      }

      // Initialize orchestrator
      this.orchestrator = new AgentOrchestrator(
        this.registry,
        this.memory!,
        this.costTracker!,
        this.retryHandler!
      );

      // Register Claude agent if API key is provided
      if (this.config.anthropicApiKey) {
        await this.registerClaudeAgent();
      }

      // Load any existing agents from storage
      await this.registry.loadAgentsFromStorage();

      const initTime = Date.now() - startTime;

      this.logger.info('Agent System initialized successfully', {
        initializationTime: initTime,
        registeredAgents: this.registry.getStatistics().totalAgents,
        capabilitiesRegistered: this.capabilityRegistry.getAllContracts().length,
      });

      return new AgentSystem(
        this.registry,
        this.orchestrator,
        this.capabilityRegistry,
        this.memory,
        this.costTracker,
        this.retryHandler,
        this.streamingHandler
      );

    } catch (error) {
      this.logger.error('Failed to initialize Agent System', error);
      throw error;
    }
  }

  /**
   * Register Claude agent with the system
   */
  private async registerClaudeAgent(): Promise<void> {
    try {
      const claudeAgent = new ClaudeNativeAgent(this.config.anthropicApiKey!);
      await this.registry!.registerAgent(claudeAgent);

      this.logger.info('Claude Native Agent registered successfully', {
        agentId: claudeAgent.id,
        capabilities: claudeAgent.capabilities.length,
        departments: claudeAgent.department?.length || 0,
      });

    } catch (error) {
      this.logger.error('Failed to register Claude agent', error);
      throw error;
    }
  }
}

/**
 * Main Agent System Interface
 * Provides high-level API for agent operations
 */
export class AgentSystem {
  private logger: Logger;

  constructor(
    private registry: AgentRegistry,
    private orchestrator: AgentOrchestrator,
    private capabilityRegistry: CapabilityRegistry,
    private memory?: AgentMemory,
    private costTracker?: CostTracker,
    private retryHandler?: RetryHandler,
    private streamingHandler?: StreamingHandler
  ) {
    this.logger = new Logger();
  }

  /**
   * Execute a single task
   */
  async executeTask(task: AgentTask): Promise<OrchestratorResult> {
    const startTime = Date.now();

    try {
      // Validate task against capability contracts
      if (task.capability !== '*') {
        const validation = this.capabilityRegistry.validateTaskInput(task);
        if (!validation.valid) {
          throw new Error(`Task validation failed: ${validation.errors?.join(', ')}`);
        }
      }

      // Execute through orchestrator
      const result = await this.orchestrator.executeTask(task);

      this.logger.info('Task executed', {
        taskId: task.id,
        success: result.success,
        agentId: result.selectedAgent,
        cost: result.totalCost,
        latency: result.totalLatency,
        executionTime: Date.now() - startTime,
      });

      return result;

    } catch (error) {
      this.logger.error('Task execution failed', error, {
        taskId: task.id,
        capability: task.capability,
      });
      throw error;
    }
  }

  /**
   * Execute a workflow
   */
  async executeWorkflow(workflow: Workflow): Promise<WorkflowResult> {
    const startTime = Date.now();

    try {
      const result = await this.orchestrator.executeWorkflow(workflow);

      this.logger.info('Workflow executed', {
        workflowId: workflow.id,
        success: result.success,
        totalSteps: workflow.steps.length,
        successfulSteps: result.steps.filter(s => s.success).length,
        totalCost: result.totalCost,
        totalLatency: result.totalLatency,
        executionTime: Date.now() - startTime,
      });

      return result;

    } catch (error) {
      this.logger.error('Workflow execution failed', error, {
        workflowId: workflow.id,
      });
      throw error;
    }
  }

  /**
   * Stream task execution
   */
  streamTask(task: AgentTask): Response {
    if (!this.streamingHandler) {
      throw new Error('Streaming is not enabled in this system configuration');
    }

    const agent = this.registry.selectAgent(task);
    return StreamingHandler.createStreamingResponse(this.streamingHandler, agent, task);
  }

  /**
   * Register a new capability contract
   */
  registerCapability(contract: CapabilityContract): void {
    this.capabilityRegistry.register(contract);

    this.logger.info('Capability registered', {
      capability: contract.name,
      version: contract.version,
      category: contract.category,
      supportedAgents: contract.supportedAgents.length,
    });
  }

  /**
   * Register a new agent
   */
  async registerAgent(agent: any, config?: any): Promise<void> {
    await this.registry.registerAgent(agent, config);

    this.logger.info('Agent registered', {
      agentId: agent.id,
      type: agent.type,
      capabilities: agent.capabilities.length,
    });
  }

  /**
   * Get system statistics
   */
  getSystemStatistics(): {
    registry: any;
    orchestrator: any;
    costTracker?: any;
    memoryStats?: any;
  } {
    return {
      registry: this.registry.getStatistics(),
      orchestrator: this.orchestrator.getStatistics(),
      costTracker: this.costTracker?.getStatistics(),
      memoryStats: this.memory ? {} : undefined, // Memory stats would be async
    };
  }

  /**
   * Get available capabilities
   */
  getCapabilities(category?: string): CapabilityContract[] {
    return category
      ? this.capabilityRegistry.getCapabilitiesByCategory(category)
      : this.capabilityRegistry.getAllContracts();
  }

  /**
   * Search capabilities
   */
  searchCapabilities(query: string): CapabilityContract[] {
    return this.capabilityRegistry.searchCapabilities(query);
  }

  /**
   * Suggest capabilities for input
   */
  suggestCapabilities(input: unknown, limit?: number): Array<{
    capability: string;
    confidence: number;
    reason: string;
  }> {
    return this.capabilityRegistry.suggestCapabilities(input, limit);
  }

  /**
   * Set cost limits for a business
   */
  async setCostLimits(businessId: string, limits: Partial<CostLimits>): Promise<void> {
    if (!this.costTracker) {
      throw new Error('Cost tracking is not enabled in this system configuration');
    }

    await this.costTracker.setBusinessLimits(businessId, limits);

    this.logger.info('Cost limits updated', {
      businessId,
      limits,
    });
  }

  /**
   * Get cost analytics for a business
   */
  async getCostAnalytics(businessId: string, days?: number): Promise<any> {
    if (!this.costTracker) {
      throw new Error('Cost tracking is not enabled in this system configuration');
    }

    return this.costTracker.getCostAnalytics(businessId, days);
  }

  /**
   * Clear memory for a session
   */
  async clearMemory(businessId: string, sessionId: string): Promise<void> {
    if (!this.memory) {
      throw new Error('Memory management is not enabled in this system configuration');
    }

    await this.memory.clearSession(businessId, sessionId);

    this.logger.info('Memory cleared', {
      businessId,
      sessionId,
    });
  }

  /**
   * Cancel an active execution
   */
  async cancelExecution(executionId: string, reason?: string): Promise<boolean> {
    return this.orchestrator.cancelExecution(executionId, reason);
  }

  /**
   * Get active executions
   */
  getActiveExecutions(): any[] {
    return this.orchestrator.getActiveExecutions();
  }

  /**
   * Perform system health check
   */
  async healthCheck(): Promise<{
    status: 'healthy' | 'degraded' | 'unhealthy';
    components: Record<string, any>;
    timestamp: number;
  }> {
    const checks = [];

    // Check registry health
    checks.push(this.checkRegistryHealth());

    // Check database connectivity
    checks.push(this.checkDatabaseHealth());

    // Check individual agent health
    const agents = this.registry.listAgents();
    for (const agent of agents.slice(0, 3)) { // Check first 3 agents
      checks.push(this.registry.updateAgentHealth(agent.agent.id));
    }

    const results = await Promise.allSettled(checks);
    const healthyComponents = results.filter(r => r.status === 'fulfilled').length;
    const totalComponents = results.length;

    let systemStatus: 'healthy' | 'degraded' | 'unhealthy';
    if (healthyComponents === totalComponents) {
      systemStatus = 'healthy';
    } else if (healthyComponents > totalComponents / 2) {
      systemStatus = 'degraded';
    } else {
      systemStatus = 'unhealthy';
    }

    return {
      status: systemStatus,
      components: {
        registry: results[0]?.status === 'fulfilled' ? 'healthy' : 'unhealthy',
        database: results[1]?.status === 'fulfilled' ? 'healthy' : 'unhealthy',
        agents: agents.length > 0 ? 'healthy' : 'unhealthy',
        totalAgents: agents.length,
        healthyAgents: healthyComponents - 2, // Subtract registry and db checks
      },
      timestamp: Date.now(),
    };
  }

  /**
   * Shutdown the system gracefully
   */
  async shutdown(): Promise<void> {
    this.logger.info('Shutting down Agent System...');

    const shutdownTasks = [];

    if (this.orchestrator) {
      shutdownTasks.push(
        this.orchestrator.getActiveExecutions().map(exec =>
          this.orchestrator.cancelExecution(exec.executionId, 'System shutdown')
        )
      );
    }

    if (this.registry) {
      shutdownTasks.push(this.registry.shutdown());
    }

    if (this.memory) {
      shutdownTasks.push(this.memory.cleanup());
    }

    if (this.costTracker) {
      shutdownTasks.push(this.costTracker.cleanup());
    }

    await Promise.allSettled(shutdownTasks.flat());

    this.logger.info('Agent System shutdown completed');
  }

  /**
   * Private helper methods
   */

  private async checkRegistryHealth(): Promise<boolean> {
    const stats = this.registry.getStatistics();
    return stats.activeAgents > 0;
  }

  private async checkDatabaseHealth(): Promise<boolean> {
    try {
      // Simple database connectivity check
      await this.orchestrator['db']?.prepare('SELECT 1').first();
      return true;
    } catch {
      return false;
    }
  }
}

/**
 * Convenience function to create and initialize the agent system
 */
export async function createAgentSystem(config: AgentSystemConfig): Promise<AgentSystem> {
  const factory = new AgentSystemFactory(config);
  return factory.initialize();
}

/**
 * Example of how to add a new specialized agent
 */
export class ExampleSpecializedAgent {
  readonly id = 'sales-prospector-v1';
  readonly name = 'Sales Prospecting Specialist';
  readonly type = 'specialized' as const;
  readonly capabilities = ['prospect.research', 'outreach.generate', 'lead.score'];
  readonly department = ['sales'];
  readonly costPerCall = 0.001;
  readonly maxConcurrency = 100;

  async execute(task: AgentTask, context: BusinessContext): Promise<any> {
    // Your future implementation here
    throw new Error('Not implemented yet - placeholder for future specialized agent');
  }

  validateInput(input: unknown): any {
    return { valid: true };
  }

  estimateCost(task: AgentTask): number {
    return this.costPerCall;
  }

  async healthCheck(): Promise<any> {
    return { healthy: true, status: 'online', latency: 0, lastCheck: Date.now() };
  }
}

/**
 * Example usage and registration
 */
export async function registerSpecializedAgent(agentSystem: AgentSystem): Promise<void> {
  const specializedAgent = new ExampleSpecializedAgent();
  await agentSystem.registerAgent(specializedAgent);

  // Register capabilities for this agent
  const prospectingCapability: CapabilityContract = {
    name: 'prospect.research',
    description: 'Research and qualify sales prospects',
    version: '1.0.0',
    category: 'sales',
    inputSchema: {
      type: 'object',
      properties: {
        company: { type: 'string' },
        industry: { type: 'string' },
        contact: { type: 'object' },
      },
      required: ['company'],
    },
    outputSchema: {
      type: 'object',
      properties: {
        score: { type: 'number' },
        insights: { type: 'array' },
        recommendations: { type: 'array' },
      },
    },
    requiredPermissions: ['sales:prospect'],
    supportedAgents: ['sales-prospector-v1'],
    estimatedLatency: 5000,
    estimatedCost: 0.01,
    examples: [],
    documentation: 'Research prospects and provide qualification scores',
  };

  agentSystem.registerCapability(prospectingCapability);
}

// ============================================================================
// DEPARTMENT-SPECIFIC SYSTEM PROMPTS (For Easy Access)
// ============================================================================

export const DEPARTMENT_PROMPTS = {
  finance: `You are CoreFlow360's financial operations controller.
            Enforce double-entry bookkeeping rules.
            Ensure GAAP compliance.
            Track every transaction in the audit log.`,

  sales: `You are CoreFlow360's sales automation specialist.
          Focus on pipeline velocity and conversion.
          Personalize outreach while maintaining efficiency.
          Track all activities in CRM.`,

  hr: `You are CoreFlow360's people operations manager.
       Ensure compliance with labor laws.
       Maintain confidentiality of employee data.
       Focus on employee experience and retention.`,

  operations: `You are CoreFlow360's operations optimizer.
               Focus on efficiency and cost reduction.
               Maintain quality standards.
               Track KPIs and suggest improvements.`,

  marketing: `You are CoreFlow360's marketing strategist.
              Focus on brand consistency and ROI.
              Ensure compliance with marketing regulations.
              Track campaign performance and attribution.`,

  it: `You are CoreFlow360's IT specialist.
       Prioritize security and system reliability.
       Follow IT governance and compliance.
       Support digital transformation initiatives.`,

  legal: `You are CoreFlow360's legal advisor.
          Ensure strict compliance with laws and regulations.
          Maintain attorney-client privilege.
          Provide conservative legal advice to minimize risk.`,
} as const;

// ============================================================================
// EXPORT EVERYTHING FOR EASY IMPORT
// ============================================================================

export default {
  // Main system
  AgentSystem,
  createAgentSystem,
  AgentSystemFactory,

  // Core components
  AgentRegistry,
  ClaudeNativeAgent,
  AgentOrchestrator,
  AgentMemory,
  CostTracker,
  RetryHandler,
  StreamingHandler,
  CapabilityRegistry,

  // Examples and utilities
  ExampleSpecializedAgent,
  registerSpecializedAgent,
  DEPARTMENT_PROMPTS,
  runIntegrationTests,
};