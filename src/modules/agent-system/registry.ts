/**
 * Agent Registry with Plug-in Architecture
 * Manages agent lifecycle, routing, and load balancing
 */

import type { KVNamespace } from '@cloudflare/workers-types';
import {
  IAgent,
  AgentConfig,
  AgentRegistryEntry,
  AgentStatus,
  AgentMetrics,
  LoadBalancingData,
  HealthStatus,
  AgentTask,
  AgentError,
  AgentNotFoundError,
  AgentUnavailableError,
  AgentConfigSchema,
  AGENT_CONSTANTS
} from './types';
import { Logger } from '../../shared/logger';
import { CorrelationId } from '../../shared/security-utils';

export class AgentRegistry {
  private logger: Logger;
  private agents = new Map<string, AgentRegistryEntry>();
  private capabilityIndex = new Map<string, string[]>(); // capability -> [agentIds]
  private departmentIndex = new Map<string, string[]>(); // department -> [agentIds]
  private defaultAgent: string = 'claude-native';
  private healthCheckInterval?: number;
  private metricsUpdateInterval?: number;
  private kv?: KVNamespace;

  constructor(kv?: KVNamespace) {
    this.logger = new Logger();
    this.kv = kv;
    this.startPeriodicTasks();
  }

  /**
   * Register agent at runtime (supports hot-loading)
   */
  async registerAgent(agent: IAgent, config?: Partial<AgentConfig>): Promise<void> {
    try {
      // Validate agent implementation
      this.validateAgent(agent);

      // Create or update configuration
      const agentConfig = await this.createAgentConfig(agent, config);

      // Validate configuration
      AgentConfigSchema.parse(agentConfig);

      // Check for duplicate IDs
      if (this.agents.has(agent.id) && !config) {
        throw new AgentError(
          `Agent with ID '${agent.id}' already registered`,
          'DUPLICATE_AGENT_ID',
          agent.id
        );
      }

      // Initial health check
      const health = await this.performHealthCheck(agent);

      // Create registry entry
      const entry: AgentRegistryEntry = {
        agent,
        config: agentConfig,
        status: health.healthy ? 'active' : 'inactive',
        health,
        metrics: this.initializeMetrics(),
        loadBalancing: this.initializeLoadBalancing(agentConfig),
        registeredAt: Date.now(),
        lastHealthCheck: Date.now(),
      };

      // Store in registry
      this.agents.set(agent.id, entry);

      // Update indexes
      this.updateCapabilityIndex(agent);
      this.updateDepartmentIndex(agent);

      // Persist configuration if KV available
      if (this.kv && agentConfig.enabled) {
        await this.saveAgentConfig(agentConfig);
      }

      this.logger.info('Agent registered successfully', {
        agentId: agent.id,
        name: agent.name,
        type: agent.type,
        capabilities: agent.capabilities.length,
        departments: agent.department?.length || 0,
        healthy: health.healthy,
      });

    } catch (error: any) {
      this.logger.error('Failed to register agent', error, {
        agentId: agent.id,
        name: agent.name,
      });
      throw error;
    }
  }

  /**
   * Find best agent for a task
   */
  selectAgent(task: AgentTask): IAgent {
    try {
      const capability = task.capability;
      const department = task.context.department;
      const constraints = task.constraints;

      // Get candidate agents
      let candidates = this.findCandidateAgents(capability, department);

      if (candidates.length === 0) {
        // Fallback to default agent if available
        const defaultEntry = this.agents.get(this.defaultAgent);
        if (defaultEntry && defaultEntry.status === 'active') {
          this.logger.warn('No suitable agents found, using default', {
            capability,
            department,
            defaultAgent: this.defaultAgent,
          });
          return defaultEntry.agent;
        }

        throw new AgentNotFoundError(`No agents available for capability '${capability}'`);
      }

      // Filter by constraints
      candidates = this.filterByConstraints(candidates, constraints);

      if (candidates.length === 0) {
        throw new AgentUnavailableError(
          'constraints',
          'No agents meet the specified constraints'
        );
      }

      // Score and select best agent
      const bestAgent = this.scoreAndSelectAgent(candidates, task);

      this.logger.debug('Agent selected', {
        taskId: task.id,
        capability,
        selectedAgent: bestAgent.id,
        candidateCount: candidates.length,
      });

      return bestAgent;

    } catch (error: any) {
      this.logger.error('Failed to select agent', error, {
        taskId: task.id,
        capability: task.capability,
      });
      throw error;
    }
  }

  /**
   * Get agents that support a specific capability
   */
  getAgentsForCapability(capability: string): IAgent[] {
    const agentIds = this.capabilityIndex.get(capability) || [];
    return agentIds
      .map((id: any) => this.agents.get(id))
      .filter((entry): entry is AgentRegistryEntry =>
        entry !== undefined && entry.status === 'active'
      )
      .map((entry: any) => entry.agent);
  }

  /**
   * Get agents for a specific department
   */
  getAgentsForDepartment(department: string): IAgent[] {
    const agentIds = this.departmentIndex.get(department) || [];
    return agentIds
      .map((id: any) => this.agents.get(id))
      .filter((entry): entry is AgentRegistryEntry =>
        entry !== undefined && entry.status === 'active'
      )
      .map((entry: any) => entry.agent);
  }

  /**
   * Update agent health status
   */
  async updateAgentHealth(agentId: string): Promise<HealthStatus> {
    const entry = this.agents.get(agentId);
    if (!entry) {
      throw new AgentNotFoundError(agentId);
    }

    try {
      const health = await this.performHealthCheck(entry.agent);
      entry.health = health;
      entry.lastHealthCheck = Date.now();

      // Update status based on health
      if (health.healthy && health.status === 'online') {
        entry.status = 'active';
      } else if (health.status === 'degraded') {
        entry.status = 'degraded';
      } else {
        entry.status = 'inactive';
      }

      this.logger.debug('Agent health updated', {
        agentId,
        status: health.status,
        latency: health.latency,
        healthy: health.healthy,
      });

      return health;

    } catch (error: any) {
      const errorHealth: HealthStatus = {
        healthy: false,
        status: 'offline',
        latency: -1,
        lastCheck: Date.now(),
        errors: [error instanceof Error ? error.message : 'Unknown error'],
      };

      entry.health = errorHealth;
      entry.status = 'error';

      this.logger.error('Agent health check failed', error, { agentId });
      return errorHealth;
    }
  }

  /**
   * Update agent performance metrics
   */
  updateAgentMetrics(agentId: string, update: {
    taskCompleted: boolean;
    success: boolean;
    latency: number;
    cost: number;
  }): void {
    const entry = this.agents.get(agentId);
    if (!entry) {
      this.logger.warn('Attempted to update metrics for unknown agent', { agentId });
      return;
    }

    const metrics = entry.metrics;
    const loadBalancing = entry.loadBalancing;

    if (update.taskCompleted) {
      metrics.totalTasks++;
      metrics.totalCost += update.cost;
      metrics.lastTaskAt = Date.now();

      if (update.success) {
        metrics.successfulTasks++;
      } else {
        metrics.failedTasks++;
      }

      // Update averages
      const totalCompleted = metrics.successfulTasks + metrics.failedTasks;
      if (totalCompleted > 0) {
        metrics.averageLatency = (metrics.averageLatency * (totalCompleted - 1) + update.latency) / totalCompleted;
        metrics.averageCost = metrics.totalCost / totalCompleted;
        metrics.successRate = metrics.successfulTasks / totalCompleted;
        metrics.errorRate = metrics.failedTasks / totalCompleted;
      }

      // Update load balancing data
      loadBalancing.lastRequestAt = Date.now();
      if (loadBalancing.activeConnections > 0) {
        loadBalancing.activeConnections--;
      }

      // Calculate throughput (tasks per minute)
      const timeWindow = 60000; // 1 minute
      const recentTasks = this.getRecentTaskCount(entry, timeWindow);
      metrics.throughput = recentTasks;
    }

    this.logger.debug('Agent metrics updated', {
      agentId,
      totalTasks: metrics.totalTasks,
      successRate: Math.round(metrics.successRate * 100),
      averageLatency: Math.round(metrics.averageLatency),
      throughput: metrics.throughput,
    });
  }

  /**
   * Update load balancing data for an agent
   */
  updateLoadBalancing(agentId: string, update: {
    activeConnections?: number;
    queuedTasks?: number;
  }): void {
    const entry = this.agents.get(agentId);
    if (!entry) return;

    const lb = entry.loadBalancing;

    if (update.activeConnections !== undefined) {
      lb.activeConnections = Math.max(0, Math.min(update.activeConnections, lb.capacity));
    }

    if (update.queuedTasks !== undefined) {
      lb.queuedTasks = Math.max(0, update.queuedTasks);
    }

    // Update utilization
    lb.utilization = lb.capacity > 0 ? lb.activeConnections / lb.capacity : 0;

    // Adjust priority based on utilization
    if (lb.utilization < 0.5) {
      lb.priority = 100; // High priority
    } else if (lb.utilization < 0.8) {
      lb.priority = 75;  // Medium priority
    } else {
      lb.priority = 25;  // Low priority
    }
  }

  /**
   * Deactivate an agent
   */
  async deactivateAgent(agentId: string, reason: string = 'Manual deactivation'): Promise<void> {
    const entry = this.agents.get(agentId);
    if (!entry) {
      throw new AgentNotFoundError(agentId);
    }

    entry.status = 'inactive';
    entry.config.enabled = false;

    // Update configuration in storage
    if (this.kv) {
      await this.saveAgentConfig(entry.config);
    }

    this.logger.info('Agent deactivated', { agentId, reason });
  }

  /**
   * Remove an agent from registry
   */
  async removeAgent(agentId: string): Promise<void> {
    const entry = this.agents.get(agentId);
    if (!entry) {
      throw new AgentNotFoundError(agentId);
    }

    // Remove from indexes
    this.removeFromCapabilityIndex(entry.agent);
    this.removeFromDepartmentIndex(entry.agent);

    // Remove from registry
    this.agents.delete(agentId);

    // Remove from storage
    if (this.kv) {
      await this.kv.delete(`agent_config:${agentId}`);
    }

    this.logger.info('Agent removed', { agentId });
  }

  /**
   * Get all registered agents
   */
  listAgents(includeInactive: boolean = false): AgentRegistryEntry[] {
    const agents = Array.from(this.agents.values());
    return includeInactive
      ? agents
      : agents.filter((entry: any) => entry.status === 'active');
  }

  /**
   * Get agent by ID
   */
  getAgent(agentId: string): IAgent | undefined {
    const entry = this.agents.get(agentId);
    return entry?.agent;
  }

  /**
   * Get agent registry entry
   */
  getAgentEntry(agentId: string): AgentRegistryEntry | undefined {
    return this.agents.get(agentId);
  }

  /**
   * Get registry statistics
   */
  getStatistics(): {
    totalAgents: number;
    activeAgents: number;
    capabilitiesSupported: number;
    departmentsSupported: number;
    totalTasks: number;
    averageSuccessRate: number;
    averageLatency: number;
    totalCost: number;
  } {
    const entries = Array.from(this.agents.values());
    const activeEntries = entries.filter((e: any) => e.status === 'active');

    const totalTasks = entries.reduce((sum, e) => sum + e.metrics.totalTasks, 0);
    const totalSuccessful = entries.reduce((sum, e) => sum + e.metrics.successfulTasks, 0);
    const totalLatency = entries.reduce((sum, e) => sum + e.metrics.averageLatency * e.metrics.totalTasks, 0);
    const totalCost = entries.reduce((sum, e) => sum + e.metrics.totalCost, 0);

    return {
      totalAgents: entries.length,
      activeAgents: activeEntries.length,
      capabilitiesSupported: this.capabilityIndex.size,
      departmentsSupported: this.departmentIndex.size,
      totalTasks,
      averageSuccessRate: totalTasks > 0 ? totalSuccessful / totalTasks : 0,
      averageLatency: totalTasks > 0 ? totalLatency / totalTasks : 0,
      totalCost,
    };
  }

  /**
   * Load agents from storage
   */
  async loadAgentsFromStorage(): Promise<void> {
    if (!this.kv) return;

    try {
      // List all agent configurations
      const { keys } = await this.kv.list({ prefix: 'agent_config:' });

      for (const key of keys) {
        try {
          const configData = await this.kv.get(key.name, 'json');
          if (configData) {
            const config = configData as AgentConfig;

            // Only load if enabled
            if (config.enabled) {
              // Create placeholder agent - actual implementation would load from factory
              this.logger.info('Loading agent from storage', {
                agentId: config.id,
                type: config.type,
              });
            }
          }
        } catch (error: any) {
          this.logger.error('Failed to load agent config', error, { key: key.name });
        }
      }

    } catch (error: any) {
      this.logger.error('Failed to load agents from storage', error);
    }
  }

  /**
   * Shutdown registry
   */
  async shutdown(): Promise<void> {
    // Stop periodic tasks
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }
    if (this.metricsUpdateInterval) {
      clearInterval(this.metricsUpdateInterval);
    }

    this.logger.info('Agent registry shutdown completed');
  }

  /**
   * Private helper methods
   */

  private validateAgent(agent: IAgent): void {
    if (!agent.id || typeof agent.id !== 'string') {
      throw new AgentError('Agent must have a valid ID', 'INVALID_AGENT_ID');
    }

    if (!agent.name || typeof agent.name !== 'string') {
      throw new AgentError('Agent must have a valid name', 'INVALID_AGENT_NAME');
    }

    if (!Array.isArray(agent.capabilities) || agent.capabilities.length === 0) {
      throw new AgentError('Agent must have at least one capability', 'INVALID_CAPABILITIES');
    }

    if (typeof agent.costPerCall !== 'number' || agent.costPerCall < 0) {
      throw new AgentError('Agent must have a valid cost per call', 'INVALID_COST');
    }

    if (typeof agent.maxConcurrency !== 'number' || agent.maxConcurrency < 1) {
      throw new AgentError('Agent must have a valid max concurrency', 'INVALID_CONCURRENCY');
    }

    // Validate required methods
    const requiredMethods = ['execute', 'validateInput', 'estimateCost', 'healthCheck'];
    for (const method of requiredMethods) {
      if (typeof (agent as any)[method] !== 'function') {
        throw new AgentError(`Agent must implement ${method} method`, 'MISSING_METHOD');
      }
    }
  }

  private async createAgentConfig(agent: IAgent, partial?: Partial<AgentConfig>): Promise<AgentConfig> {
    const now = Date.now();

    return {
      id: agent.id,
      name: agent.name,
      type: agent.type,
      version: '1.0.0',
      description: `${agent.name} - ${agent.type} agent`,
      capabilities: [...agent.capabilities],
      department: agent.department ? [...agent.department] : undefined,
      costPerCall: agent.costPerCall,
      maxConcurrency: agent.maxConcurrency,
      enabled: true,
      streamingEnabled: true,
      cachingEnabled: true,
      retryEnabled: true,
      fallbackEnabled: true,
      owner: 'system',
      tags: [agent.type],
      createdAt: now,
      updatedAt: now,
      ...partial,
    };
  }

  private async performHealthCheck(agent: IAgent): Promise<HealthStatus> {
    const startTime = Date.now();

    try {
      const health = await Promise.race([
        agent.healthCheck(),
        new Promise<HealthStatus>((_, reject) =>
          setTimeout(() => reject(new Error('Health check timeout')), 10000)
        )
      ]);

      const latency = Date.now() - startTime;

      return {
        ...health,
        latency,
        lastCheck: Date.now(),
      };

    } catch (error: any) {
      return {
        healthy: false,
        status: 'offline',
        latency: Date.now() - startTime,
        lastCheck: Date.now(),
        errors: [error instanceof Error ? error.message : 'Unknown error'],
      };
    }
  }

  private initializeMetrics(): AgentMetrics {
    return {
      totalTasks: 0,
      successfulTasks: 0,
      failedTasks: 0,
      averageLatency: 0,
      averageCost: 0,
      totalCost: 0,
      successRate: 0,
      errorRate: 0,
      throughput: 0,
    };
  }

  private initializeLoadBalancing(config: AgentConfig): LoadBalancingData {
    return {
      activeConnections: 0,
      queuedTasks: 0,
      capacity: config.maxConcurrency,
      utilization: 0,
      priority: 100,
    };
  }

  private updateCapabilityIndex(agent: IAgent): void {
    for (const capability of agent.capabilities) {
      const agentIds = this.capabilityIndex.get(capability) || [];
      if (!agentIds.includes(agent.id)) {
        agentIds.push(agent.id);
        this.capabilityIndex.set(capability, agentIds);
      }
    }
  }

  private updateDepartmentIndex(agent: IAgent): void {
    if (agent.department) {
      for (const dept of agent.department) {
        const agentIds = this.departmentIndex.get(dept) || [];
        if (!agentIds.includes(agent.id)) {
          agentIds.push(agent.id);
          this.departmentIndex.set(dept, agentIds);
        }
      }
    }
  }

  private removeFromCapabilityIndex(agent: IAgent): void {
    for (const capability of agent.capabilities) {
      const agentIds = this.capabilityIndex.get(capability) || [];
      const index = agentIds.indexOf(agent.id);
      if (index > -1) {
        agentIds.splice(index, 1);
        if (agentIds.length === 0) {
          this.capabilityIndex.delete(capability);
        } else {
          this.capabilityIndex.set(capability, agentIds);
        }
      }
    }
  }

  private removeFromDepartmentIndex(agent: IAgent): void {
    if (agent.department) {
      for (const dept of agent.department) {
        const agentIds = this.departmentIndex.get(dept) || [];
        const index = agentIds.indexOf(agent.id);
        if (index > -1) {
          agentIds.splice(index, 1);
          if (agentIds.length === 0) {
            this.departmentIndex.delete(dept);
          } else {
            this.departmentIndex.set(dept, agentIds);
          }
        }
      }
    }
  }

  private findCandidateAgents(capability: string, department?: string): AgentRegistryEntry[] {
    // Get agents by capability
    let candidateIds = this.capabilityIndex.get(capability) || [];

    // If no exact match, check for wildcard capability
    if (candidateIds.length === 0) {
      candidateIds = this.capabilityIndex.get('*') || [];
    }

    // Filter by department if specified
    if (department && candidateIds.length > 0) {
      const departmentAgentIds = this.departmentIndex.get(department) || [];
      candidateIds = candidateIds.filter((id: any) => departmentAgentIds.includes(id));
    }

    // Get registry entries for active agents
    return candidateIds
      .map((id: any) => this.agents.get(id))
      .filter((entry): entry is AgentRegistryEntry =>
        entry !== undefined &&
        entry.status === 'active' &&
        entry.health.healthy
      );
  }

  private filterByConstraints(
    candidates: AgentRegistryEntry[],
    constraints?: AgentTask['constraints']
  ): AgentRegistryEntry[] {
    if (!constraints) return candidates;

    return candidates.filter((entry: any) => {
      // Check cost constraint
      if (constraints.maxCost !== undefined && entry.agent.costPerCall > constraints.maxCost) {
        return false;
      }

      // Check latency constraint
      if (constraints.maxLatency !== undefined && entry.metrics.averageLatency > constraints.maxLatency) {
        return false;
      }

      // Check if agent has available capacity
      if (entry.loadBalancing.utilization >= 1.0) {
        return false;
      }

      return true;
    });
  }

  private scoreAndSelectAgent(candidates: AgentRegistryEntry[], task: AgentTask): IAgent {
    // Score each candidate
    const scoredCandidates = candidates.map((entry: any) => ({
      entry,
      score: this.calculateAgentScore(entry, task),
    }));

    // Sort by score (highest first)
    scoredCandidates.sort((a, b) => b.score - a.score);

    // Select the highest scoring agent
    const selected = scoredCandidates[0];
    if (!selected) {
      throw new AgentUnavailableError('scoring', 'No suitable agents found after scoring');
    }

    // Update load balancing
    this.updateLoadBalancing(selected.entry.agent.id, {
      activeConnections: selected.entry.loadBalancing.activeConnections + 1,
    });

    return selected.entry.agent;
  }

  private calculateAgentScore(entry: AgentRegistryEntry, task: AgentTask): number {
    let score = 0;

    // Success rate (0-40 points)
    score += entry.metrics.successRate * 40;

    // Latency (0-20 points, lower is better)
    const latencyScore = Math.max(0, 20 - (entry.metrics.averageLatency / 1000));
    score += latencyScore;

    // Cost efficiency (0-20 points, lower cost is better)
    const maxCost = task.constraints?.maxCost || 1.0;
    const costScore = Math.max(0, 20 * (1 - entry.agent.costPerCall / maxCost));
    score += costScore;

    // Load balancing (0-10 points, lower utilization is better)
    const loadScore = (1 - entry.loadBalancing.utilization) * 10;
    score += loadScore;

    // Priority boost (0-10 points)
    score += (entry.loadBalancing.priority / 100) * 10;

    return score;
  }

  private getRecentTaskCount(entry: AgentRegistryEntry, timeWindow: number): number {
    // This would typically query a task history store
    // For now, use a simple approximation based on throughput
    return entry.metrics.throughput || 0;
  }

  private async saveAgentConfig(config: AgentConfig): Promise<void> {
    if (!this.kv) return;

    try {
      await this.kv.put(
        `agent_config:${config.id}`,
        JSON.stringify(config),
        { metadata: { version: config.version, updatedAt: config.updatedAt } }
      );
    } catch (error: any) {
      this.logger.error('Failed to save agent config', error, { agentId: config.id });
    }
  }

  private startPeriodicTasks(): void {
    // Health check every 30 seconds
    this.healthCheckInterval = setInterval(() => {
      this.performPeriodicHealthChecks().catch((error: any) => {
        this.logger.error('Periodic health check failed', error);
      });
    }, AGENT_CONSTANTS.HEALTH_CHECK_INTERVAL) as any;

    // Metrics update every minute
    this.metricsUpdateInterval = setInterval(() => {
      this.updatePeriodicMetrics();
    }, AGENT_CONSTANTS.METRICS_UPDATE_INTERVAL) as any;
  }

  private async performPeriodicHealthChecks(): Promise<void> {
    const agents = Array.from(this.agents.values());
    const batchSize = 10; // Process in batches to avoid overwhelming the system

    // Process agents in batches to avoid N+1 and thundering herd
    for (let i = 0; i < agents.length; i += batchSize) {
      const batch = agents.slice(i, i + batchSize);

      const healthCheckPromises = batch.map(async entry => {
        try {
          await this.updateAgentHealth(entry.agent.id);
        } catch (error: any) {
          this.logger.error('Health check failed for agent', error, {
            agentId: entry.agent.id,
          });
        }
      });

      // Wait for current batch to complete
      await Promise.allSettled(healthCheckPromises);

      // Small delay between batches to prevent system overload
      if (i + batchSize < agents.length) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }
  }

  private updatePeriodicMetrics(): void {
    // Update throughput calculations and other time-based metrics
    const now = Date.now();

    for (const entry of this.agents.values()) {
      // Reset throughput calculation window
      if (entry.metrics.lastTaskAt && now - entry.metrics.lastTaskAt > 300000) {
        // No tasks in last 5 minutes, reset throughput
        entry.metrics.throughput = 0;
      }
    }
  }
}