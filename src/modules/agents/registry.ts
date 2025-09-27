/**
 * Agent Registry System
 * Manages agent lifecycle, routing, and load balancing
 */

import type { KVNamespace } from '@cloudflare/workers-types';
import {
  IAgent,
  AgentConfig,
  AgentRegistryEntry,
  AgentError,
  AgentNotFoundError,
  AgentUnavailableError,
  HealthStatus,
  AgentStatus,
  AgentConfigSchema,
  AGENT_LIMITS
} from './types';
import { Logger } from '../../shared/logger';
import { SecurityError, CorrelationId } from '../../shared/security-utils';

export class AgentRegistry {
  private logger: Logger;
  private agents = new Map<string, AgentRegistryEntry>();
  private healthCheckInterval?: number;
  private metricsUpdateInterval?: number;
  private kv?: KVNamespace;

  constructor(kv?: KVNamespace) {
    this.logger = new Logger();
    this.kv = kv;
    this.startPeriodicTasks();
  }

  /**
   * Register a new agent
   */
  async registerAgent(config: AgentConfig, agentInstance?: IAgent): Promise<void> {
    try {
      // Validate configuration
      AgentConfigSchema.parse(config);

      // Check for duplicate IDs
      if (this.agents.has(config.id)) {
        throw new AgentError(
          `Agent with ID '${config.id}' already registered`,
          'DUPLICATE_AGENT_ID',
          'validation'
        );
      }

      // Validate agent instance if provided
      if (agentInstance) {
        await this.validateAgentInstance(agentInstance, config);
      }

      // Create registry entry
      const entry: AgentRegistryEntry = {
        config,
        instance: agentInstance,
        metrics: {
          totalTasks: 0,
          successfulTasks: 0,
          failedTasks: 0,
          averageLatency: 0,
          totalCost: 0,
        },
        health: {
          status: 'offline',
          lastCheck: Date.now(),
        },
        loadBalancing: {
          weight: 1.0,
          activeConnections: 0,
          queueSize: 0,
        },
      };

      // Store in memory
      this.agents.set(config.id, entry);

      // Persist to KV if available
      if (this.kv) {
        await this.persistAgentConfig(config);
      }

      // Perform initial health check
      if (agentInstance) {
        await this.updateAgentHealth(config.id);
      }

      this.logger.info('Agent registered', {
        agentId: config.id,
        name: config.name,
        type: config.type,
        capabilities: config.capabilities,
        hasInstance: !!agentInstance,
      });

    } catch (error: any) {
      this.logger.error('Failed to register agent', error, {
        agentId: config.id,
      });
      throw error;
    }
  }

  /**
   * Unregister an agent
   */
  async unregisterAgent(agentId: string): Promise<void> {
    const entry = this.agents.get(agentId);
    if (!entry) {
      throw new AgentNotFoundError(agentId);
    }

    try {
      // Cleanup agent instance
      if (entry.instance?.cleanup) {
        await entry.instance.cleanup();
      }

      // Remove from memory
      this.agents.delete(agentId);

      // Remove from KV if available
      if (this.kv) {
        await this.kv.delete(`agent_config:${agentId}`);
      }

      this.logger.info('Agent unregistered', {
        agentId,
        name: entry.config.name,
      });

    } catch (error: any) {
      this.logger.error('Failed to unregister agent', error, {
        agentId,
      });
      throw error;
    }
  }

  /**
   * Get agent by ID
   */
  getAgent(agentId: string): IAgent | undefined {
    const entry = this.agents.get(agentId);
    return entry?.instance;
  }

  /**
   * Get agent configuration
   */
  getAgentConfig(agentId: string): AgentConfig | undefined {
    const entry = this.agents.get(agentId);
    return entry?.config;
  }

  /**
   * Get agent registry entry
   */
  getAgentEntry(agentId: string): AgentRegistryEntry | undefined {
    return this.agents.get(agentId);
  }

  /**
   * List all registered agents
   */
  listAgents(filters?: {
    type?: string;
    capability?: string;
    department?: string;
    status?: AgentStatus;
    enabled?: boolean;
  }): AgentRegistryEntry[] {
    let agents = Array.from(this.agents.values());

    if (filters) {
      agents = agents.filter((entry: any) => {
        if (filters.type && entry.config.type !== filters.type) return false;
        if (filters.capability && !entry.config.capabilities.includes(filters.capability)) return false;
        if (filters.department && !entry.config.departments?.includes(filters.department)) return false;
        if (filters.status && entry.health.status !== filters.status) return false;
        if (filters.enabled !== undefined && entry.config.enabled !== filters.enabled) return false;
        return true;
      });
    }

    return agents;
  }

  /**
   * Find agents by capability
   */
  findAgentsByCapability(capability: string, requireOnline = true): AgentRegistryEntry[] {
    return Array.from(this.agents.values()).filter((entry: any) => {
      if (!entry.config.enabled) return false;
      if (!entry.config.capabilities.includes(capability)) return false;
      if (requireOnline && entry.health.status !== 'online') return false;
      return true;
    });
  }

  /**
   * Get best agent for capability using load balancing
   */
  getBestAgentForCapability(
    capability: string,
    preferences?: {
      costOptimized?: boolean;
      latencyOptimized?: boolean;
      excludeAgents?: string[];
    }
  ): AgentRegistryEntry | undefined {
    const candidates = this.findAgentsByCapability(capability, true);

    if (candidates.length === 0) {
      return undefined;
    }

    // Filter excluded agents
    let filtered = candidates;
    if (preferences?.excludeAgents) {
      filtered = candidates.filter((entry: any) =>
        !preferences.excludeAgents!.includes(entry.config.id)
      );
    }

    if (filtered.length === 0) {
      return undefined;
    }

    // Sort by optimization preference
    if (preferences?.costOptimized) {
      filtered.sort((a, b) => a.config.costPerCall - b.config.costPerCall);
    } else if (preferences?.latencyOptimized) {
      filtered.sort((a, b) => a.metrics.averageLatency - b.metrics.averageLatency);
    } else {
      // Default: load balancing by active connections
      filtered.sort((a, b) => {
        const scoreA = this.calculateLoadScore(a);
        const scoreB = this.calculateLoadScore(b);
        return scoreA - scoreB;
      });
    }

    return filtered[0];
  }

  /**
   * Update agent configuration
   */
  async updateAgentConfig(agentId: string, updates: Partial<AgentConfig>): Promise<void> {
    const entry = this.agents.get(agentId);
    if (!entry) {
      throw new AgentNotFoundError(agentId);
    }

    try {
      // Merge updates with existing config
      const updatedConfig = {
        ...entry.config,
        ...updates,
        updatedAt: Date.now(),
      };

      // Validate updated configuration
      AgentConfigSchema.parse(updatedConfig);

      // Update agent instance if it supports config updates
      if (entry.instance?.updateConfig) {
        await entry.instance.updateConfig(updates);
      }

      // Update registry entry
      entry.config = updatedConfig;

      // Persist to KV
      if (this.kv) {
        await this.persistAgentConfig(updatedConfig);
      }

      this.logger.info('Agent configuration updated', {
        agentId,
        updates: Object.keys(updates),
      });

    } catch (error: any) {
      this.logger.error('Failed to update agent configuration', error, {
        agentId,
      });
      throw error;
    }
  }

  /**
   * Set agent instance for an existing configuration
   */
  async setAgentInstance(agentId: string, instance: IAgent): Promise<void> {
    const entry = this.agents.get(agentId);
    if (!entry) {
      throw new AgentNotFoundError(agentId);
    }

    try {
      // Validate agent instance
      await this.validateAgentInstance(instance, entry.config);

      // Cleanup previous instance if exists
      if (entry.instance?.cleanup) {
        await entry.instance.cleanup();
      }

      // Set new instance
      entry.instance = instance;

      // Initialize if supported
      if (instance.initialize) {
        await instance.initialize(entry.config.customConfig || {});
      }

      // Update health status
      await this.updateAgentHealth(agentId);

      this.logger.info('Agent instance updated', {
        agentId,
        agentName: instance.name,
      });

    } catch (error: any) {
      this.logger.error('Failed to set agent instance', error, {
        agentId,
      });
      throw error;
    }
  }

  /**
   * Update agent metrics
   */
  updateAgentMetrics(
    agentId: string,
    metrics: {
      taskCompleted?: boolean;
      success?: boolean;
      latency?: number;
      cost?: number;
    }
  ): void {
    const entry = this.agents.get(agentId);
    if (!entry) return;

    if (metrics.taskCompleted) {
      entry.metrics.totalTasks++;

      if (metrics.success) {
        entry.metrics.successfulTasks++;
      } else {
        entry.metrics.failedTasks++;
      }
    }

    if (metrics.latency !== undefined) {
      // Calculate running average
      const totalTasks = entry.metrics.totalTasks;
      if (totalTasks > 0) {
        entry.metrics.averageLatency =
          (entry.metrics.averageLatency * (totalTasks - 1) + metrics.latency) / totalTasks;
      }
    }

    if (metrics.cost !== undefined) {
      entry.metrics.totalCost += metrics.cost;
    }

    entry.metrics.lastUsed = Date.now();
  }

  /**
   * Update agent health status
   */
  async updateAgentHealth(agentId: string): Promise<HealthStatus> {
    const entry = this.agents.get(agentId);
    if (!entry || !entry.instance) {
      throw new AgentNotFoundError(agentId);
    }

    try {
      const health = await entry.instance.healthCheck();
      entry.health = health;

      this.logger.debug('Agent health updated', {
        agentId,
        status: health.status,
        latency: health.latency,
      });

      return health;

    } catch (error: any) {
      // Mark agent as error status
      entry.health = {
        status: 'error',
        lastCheck: Date.now(),
        details: {
          recentErrors: [error instanceof Error ? error.message : String(error)],
        },
      };

      this.logger.error('Agent health check failed', error, {
        agentId,
      });

      return entry.health;
    }
  }

  /**
   * Get system-wide metrics
   */
  getSystemMetrics(): {
    totalAgents: number;
    onlineAgents: number;
    offlineAgents: number;
    errorAgents: number;
    totalTasks: number;
    successRate: number;
    averageLatency: number;
    totalCost: number;
  } {
    const entries = Array.from(this.agents.values());

    const statusCounts = entries.reduce((acc, entry) => {
      acc[entry.health.status] = (acc[entry.health.status] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const totalTasks = entries.reduce((sum, entry) => sum + entry.metrics.totalTasks, 0);
    const successfulTasks = entries.reduce((sum, entry) => sum + entry.metrics.successfulTasks, 0);
    const totalLatency = entries.reduce((sum, entry) =>
      sum + (entry.metrics.averageLatency * entry.metrics.totalTasks), 0);
    const totalCost = entries.reduce((sum, entry) => sum + entry.metrics.totalCost, 0);

    return {
      totalAgents: entries.length,
      onlineAgents: statusCounts.online || 0,
      offlineAgents: statusCounts.offline || 0,
      errorAgents: statusCounts.error || 0,
      totalTasks,
      successRate: totalTasks > 0 ? successfulTasks / totalTasks : 0,
      averageLatency: totalTasks > 0 ? totalLatency / totalTasks : 0,
      totalCost,
    };
  }

  /**
   * Load agents from persistent storage
   */
  async loadAgentsFromStorage(): Promise<void> {
    if (!this.kv) return;

    try {
      const { keys } = await this.kv.list({ prefix: 'agent_config:' });

      for (const key of keys) {
        try {
          const configData = await this.kv.get(key.name);
          if (configData) {
            const config = JSON.parse(configData) as AgentConfig;

            // Register agent without instance (will be set later)
            await this.registerAgent(config);
          }
        } catch (error: any) {
          this.logger.error('Failed to load agent config from storage', error, {
            key: key.name,
          });
        }
      }

      this.logger.info('Agents loaded from storage', {
        count: keys.length,
      });

    } catch (error: any) {
      this.logger.error('Failed to load agents from storage', error);
    }
  }

  /**
   * Cleanup and shutdown
   */
  async shutdown(): Promise<void> {
    try {
      // Stop periodic tasks
      if (this.healthCheckInterval) {
        clearInterval(this.healthCheckInterval);
      }
      if (this.metricsUpdateInterval) {
        clearInterval(this.metricsUpdateInterval);
      }

      // Cleanup all agent instances
      const cleanupPromises = Array.from(this.agents.values())
        .filter((entry: any) => entry.instance?.cleanup)
        .map(async entry => {
          try {
            await entry.instance!.cleanup!();
          } catch (error: any) {
            this.logger.error('Failed to cleanup agent', error, {
              agentId: entry.config.id,
            });
          }
        });

      await Promise.allSettled(cleanupPromises);

      this.logger.info('Agent registry shutdown completed');

    } catch (error: any) {
      this.logger.error('Failed to shutdown agent registry', error);
      throw error;
    }
  }

  /**
   * Private methods
   */

  private async validateAgentInstance(instance: IAgent, config: AgentConfig): Promise<void> {
    // Validate agent implements required interface
    if (!instance.id || !instance.name || !instance.execute || !instance.healthCheck) {
      throw new AgentError(
        'Agent instance must implement IAgent interface',
        'INVALID_AGENT_INSTANCE',
        'validation'
      );
    }

    // Validate agent ID matches config
    if (instance.id !== config.id) {
      throw new AgentError(
        `Agent instance ID '${instance.id}' does not match config ID '${config.id}'`,
        'AGENT_ID_MISMATCH',
        'validation'
      );
    }

    // Validate capabilities
    for (const capability of config.capabilities) {
      if (!instance.capabilities.includes(capability)) {
        throw new AgentError(
          `Agent instance does not support required capability '${capability}'`,
          'CAPABILITY_MISMATCH',
          'validation'
        );
      }
    }

    // Test basic functionality
    try {
      const health = await instance.healthCheck();
      if (!health || typeof health.status !== 'string') {
        throw new AgentError(
          'Agent health check returned invalid response',
          'INVALID_HEALTH_CHECK',
          'validation'
        );
      }
    } catch (error: any) {
      throw new AgentError(
        `Agent health check failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'HEALTH_CHECK_FAILED',
        'validation'
      );
    }
  }

  private calculateLoadScore(entry: AgentRegistryEntry): number {
    const { activeConnections, weight, queueSize } = entry.loadBalancing;
    const maxConcurrency = entry.config.maxConcurrency;

    // Calculate load as percentage of max capacity
    const loadPercentage = activeConnections / maxConcurrency;

    // Add queue size penalty
    const queuePenalty = queueSize * 0.1;

    // Apply weight (lower weight = higher priority)
    const weightedScore = (loadPercentage + queuePenalty) / weight;

    return weightedScore;
  }

  private async persistAgentConfig(config: AgentConfig): Promise<void> {
    if (!this.kv) return;

    try {
      await this.kv.put(
        `agent_config:${config.id}`,
        JSON.stringify(config),
        {
          metadata: {
            type: config.type,
            enabled: config.enabled,
            updatedAt: config.updatedAt,
          },
        }
      );
    } catch (error: any) {
      this.logger.error('Failed to persist agent config', error, {
        agentId: config.id,
      });
    }
  }

  private startPeriodicTasks(): void {
    // Health checks every 30 seconds
    this.healthCheckInterval = setInterval(() => {
      this.performHealthChecks().catch((error: any) => {
        this.logger.error('Health check task failed', error);
      });
    }, 30000) as any;

    // Metrics cleanup every 5 minutes
    this.metricsUpdateInterval = setInterval(() => {
      this.cleanupMetrics();
    }, 300000) as any;
  }

  private async performHealthChecks(): Promise<void> {
    const agents = Array.from(this.agents.values())
      .filter((entry: any) => entry.instance && entry.config.enabled);

    const healthCheckPromises = agents.map(async entry => {
      try {
        await this.updateAgentHealth(entry.config.id);
      } catch (error: any) {
        // Health check failures are logged in updateAgentHealth
      }
    });

    await Promise.allSettled(healthCheckPromises);
  }

  private cleanupMetrics(): void {
    // Reset load balancing queues for agents with no active connections
    for (const entry of this.agents.values()) {
      if (entry.loadBalancing.activeConnections === 0) {
        entry.loadBalancing.queueSize = 0;
      }
    }

    this.logger.debug('Metrics cleanup completed');
  }
}