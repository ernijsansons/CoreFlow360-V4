import { EventEmitter } from 'events';

export interface SyncConfiguration {
  syncInterval: number;
  batchSize: number;
  retryAttempts: number;
  conflictResolution: 'agent-priority' | 'coreflow-priority' | 'newest' | 'manual';
  enableBidirectional: boolean;
  dataTypes: string[];
}

export interface SyncJob {
  id: string;
  type: 'full' | 'incremental' | 'delta';
  source: 'agents' | 'coreflow';
  target: 'agents' | 'coreflow';
  status: 'pending' | 'running' | 'completed' | 'failed';
  startTime: Date;
  endTime?: Date;
  recordsProcessed: number;
  recordsFailed: number;
  errors: SyncError[];
}

export interface SyncError {
  timestamp: Date;
  recordId: string;
  error: string;
  retryCount: number;
}

export interface DataMapping {
  sourceField: string;
  targetField: string;
  transformation?: (value: any) => any;
  required: boolean;
}

export class DataSynchronizationService extends EventEmitter {
  private config: SyncConfiguration;
  private syncJobs: Map<string, SyncJob> = new Map();
  private dataMappings: Map<string, DataMapping[]> = new Map();
  private syncTimer?: NodeJS.Timer;
  private isRunning: boolean = false;
  private lastSyncTimestamp: Map<string, Date> = new Map();
  private conflictQueue: Map<string, any> = new Map();
  private env: any;

  constructor(config: Partial<SyncConfiguration> = {}, env?: any) {
    super();
    this.config = {
      syncInterval: config.syncInterval || 60000, // 1 minute default
      batchSize: config.batchSize || 100,
      retryAttempts: config.retryAttempts || 3,
      conflictResolution: config.conflictResolution || 'newest',
      enableBidirectional: config.enableBidirectional !== false,
      dataTypes: config.dataTypes || [
        'decisions',
        'workflows',
        'metrics',
        'agents',
        'business_data'
      ]
    };
    this.env = env;
    this.initializeDataMappings();
  }

  // Initialize data field mappings
  private initializeDataMappings(): void {
    // Agent decision to workflow mapping
    this.dataMappings.set('agent_decision_to_workflow', [
      { sourceField: 'decision.id', targetField: 'decisionId', required: true },
      { sourceField: 'decision.agentId', targetField: 'agentSource', required: true },
      { sourceField: 'decision.result', targetField: 'actionToTake', required: true },
      { sourceField: 'decision.confidence', targetField: 'confidenceScore', required: false },
      { sourceField: 'decision.reasoning', targetField: 'decisionReasoning', required: false },
      {
        sourceField: 'decision.timestamp',
        targetField: 'decisionTimestamp',
        transformation: (v) => new Date(v).toISOString(),
        required: true
      }
    ]);

    // CoreFlow business data to agent context mapping
    this.dataMappings.set('business_data_to_agent', [
      { sourceField: 'revenue', targetField: 'financialMetrics.revenue', required: false },
      { sourceField: 'expenses', targetField: 'financialMetrics.expenses', required: false },
      { sourceField: 'customerCount', targetField: 'businessMetrics.customers', required: false },
      { sourceField: 'employeeCount', targetField: 'organizationMetrics.employees', required: false },
      { sourceField: 'marketShare', targetField: 'marketMetrics.share', required: false },
      {
        sourceField: 'timestamp',
        targetField: 'dataTimestamp',
        transformation: (v) => new Date(v).toISOString(),
        required: true
      }
    ]);

    // Workflow status to agent feedback mapping
    this.dataMappings.set('workflow_status_to_agent', [
      { sourceField: 'workflowId', targetField: 'contextId', required: true },
      { sourceField: 'status', targetField: 'executionStatus', required: true },
      { sourceField: 'result', targetField: 'executionResult', required: false },
      { sourceField: 'errors', targetField: 'executionErrors', required: false },
      { sourceField: 'metrics', targetField: 'performanceMetrics', required: false }
    ]);
  }

  // Start automatic synchronization
  async startSync(): Promise<void> {
    if (this.isRunning) {
      return;
    }

    this.isRunning = true;
    this.emit('syncStarted', { timestamp: new Date() });

    // Run initial sync
    await this.performFullSync();

    // Set up periodic sync
    this.syncTimer = setInterval(async () => {
      try {
        await this.performIncrementalSync();
      } catch (error) {
        this.emit('syncError', error);
      }
    }, this.config.syncInterval);
  }

  // Stop synchronization
  stopSync(): void {
    if (this.syncTimer) {
      clearInterval(this.syncTimer);
      this.syncTimer = undefined;
    }
    this.isRunning = false;
    this.emit('syncStopped', { timestamp: new Date() });
  }

  // Perform full synchronization
  async performFullSync(): Promise<SyncJob> {
    const job = this.createSyncJob('full');
    this.emit('syncJobStarted', job);

    try {
      // Sync each data type
      for (const dataType of this.config.dataTypes) {
        await this.syncDataType(dataType, job, 'full');
      }

      job.status = 'completed';
      job.endTime = new Date();
      this.emit('syncJobCompleted', job);
    } catch (error) {
      job.status = 'failed';
      job.endTime = new Date();
      job.errors.push({
        timestamp: new Date(),
        recordId: 'full-sync',
        error: error instanceof Error ? error.message : 'Unknown error',
        retryCount: 0
      });
      this.emit('syncJobFailed', job);
      throw error;
    }

    return job;
  }

  // Perform incremental synchronization
  async performIncrementalSync(): Promise<SyncJob> {
    const job = this.createSyncJob('incremental');
    this.emit('syncJobStarted', job);

    try {
      for (const dataType of this.config.dataTypes) {
        const lastSync = this.lastSyncTimestamp.get(dataType) || new Date(0);
        await this.syncDataType(dataType, job, 'incremental', lastSync);
        this.lastSyncTimestamp.set(dataType, new Date());
      }

      // Process conflict queue
      if (this.conflictQueue.size > 0) {
        await this.resolveConflicts();
      }

      job.status = 'completed';
      job.endTime = new Date();
      this.emit('syncJobCompleted', job);
    } catch (error) {
      job.status = 'failed';
      job.endTime = new Date();
      job.errors.push({
        timestamp: new Date(),
        recordId: 'incremental-sync',
        error: error instanceof Error ? error.message : 'Unknown error',
        retryCount: 0
      });
      this.emit('syncJobFailed', job);
    }

    return job;
  }

  // Sync specific data type
  private async syncDataType(
    dataType: string,
    job: SyncJob,
    syncType: 'full' | 'incremental',
    since?: Date
  ): Promise<void> {
    switch (dataType) {
      case 'decisions':
        await this.syncDecisions(job, syncType, since);
        break;
      case 'workflows':
        await this.syncWorkflows(job, syncType, since);
        break;
      case 'metrics':
        await this.syncMetrics(job, syncType, since);
        break;
      case 'agents':
        await this.syncAgentStatus(job, syncType);
        break;
      case 'business_data':
        await this.syncBusinessData(job, syncType, since);
        break;
    }
  }

  // Sync agent decisions
  private async syncDecisions(job: SyncJob, syncType: string, since?: Date): Promise<void> {
    try {
      // Fetch decisions from agent system
      const decisions = await this.fetchAgentDecisions(since);
      const mapping = this.dataMappings.get('agent_decision_to_workflow');

      for (const decision of decisions) {
        try {
          const mappedData = this.applyMapping(decision, mapping!);
          await this.pushToCoreFlow('workflow_decisions', mappedData);
          job.recordsProcessed++;
        } catch (error) {
          job.recordsFailed++;
          job.errors.push({
            timestamp: new Date(),
            recordId: decision.id,
            error: error instanceof Error ? error.message : 'Mapping error',
            retryCount: 0
          });
        }
      }
    } catch (error) {
      throw error;
    }
  }

  // Sync workflow data
  private async syncWorkflows(job: SyncJob, syncType: string, since?: Date): Promise<void> {
    if (!this.config.enableBidirectional) return;

    try {
      // Fetch workflow updates from CoreFlow360
      const workflows = await this.fetchCoreFlowWorkflows(since);
      const mapping = this.dataMappings.get('workflow_status_to_agent');

      for (const workflow of workflows) {
        try {
          const mappedData = this.applyMapping(workflow, mapping!);
          await this.pushToAgentSystem('workflow_feedback', mappedData);
          job.recordsProcessed++;
        } catch (error) {
          job.recordsFailed++;
          job.errors.push({
            timestamp: new Date(),
            recordId: workflow.id,
            error: error instanceof Error ? error.message : 'Mapping error',
            retryCount: 0
          });
        }
      }
    } catch (error) {
      throw error;
    }
  }

  // Sync business metrics
  private async syncMetrics(job: SyncJob, syncType: string, since?: Date): Promise<void> {
    try {
      const metrics = await this.fetchBusinessMetrics(since);
      const aggregated = this.aggregateMetrics(metrics);

      // Send aggregated metrics to agent system for learning
      await this.pushToAgentSystem('business_metrics', aggregated);
      job.recordsProcessed += metrics.length;
    } catch (error) {
      throw error;
    }
  }

  // Sync agent status
  private async syncAgentStatus(job: SyncJob, syncType: string): Promise<void> {
    try {
      const agentStatus = await this.fetchAgentStatus();

      // Store agent status in CoreFlow360
      await this.pushToCoreFlow('agent_status', {
        timestamp: new Date(),
        agents: Array.from(agentStatus.entries())
      });

      job.recordsProcessed += agentStatus.size;
    } catch (error) {
      throw error;
    }
  }

  // Sync business data to agents
  private async syncBusinessData(job: SyncJob, syncType: string, since?: Date): Promise<void> {
    try {
      const businessData = await this.fetchBusinessData(since);
      const mapping = this.dataMappings.get('business_data_to_agent');

      const batchedData = this.batchData(businessData, this.config.batchSize);

      for (const batch of batchedData) {
        try {
          const mappedBatch = batch.map(data => this.applyMapping(data, mapping!));
          await this.pushToAgentSystem('business_context', mappedBatch);
          job.recordsProcessed += batch.length;
        } catch (error) {
          job.recordsFailed += batch.length;
        }
      }
    } catch (error) {
      throw error;
    }
  }

  // Apply data mapping transformation
  private applyMapping(sourceData: any, mappings: DataMapping[]): any {
    const result: any = {};

    for (const mapping of mappings) {
      const value = this.getNestedValue(sourceData, mapping.sourceField);

      if (value === undefined && mapping.required) {
        throw new Error(`Required field missing: ${mapping.sourceField}`);
      }

      if (value !== undefined) {
        const transformedValue = mapping.transformation
          ? mapping.transformation(value)
          : value;

        this.setNestedValue(result, mapping.targetField, transformedValue);
      }
    }

    return result;
  }

  // Handle data conflicts
  private async resolveConflicts(): Promise<void> {
    const conflicts = Array.from(this.conflictQueue.entries());

    for (const [id, conflict] of conflicts) {
      try {
        const resolution = await this.resolveConflict(conflict);
        if (resolution.resolved) {
          this.conflictQueue.delete(id);
          this.emit('conflictResolved', { id, resolution });
        }
      } catch (error) {
      }
    }
  }

  // Resolve individual conflict
  private async resolveConflict(conflict: any): Promise<any> {
    switch (this.config.conflictResolution) {
      case 'agent-priority':
        return { resolved: true, action: 'use-agent-data', data: conflict.agentData };

      case 'coreflow-priority':
        return { resolved: true, action: 'use-coreflow-data', data: conflict.coreflowData };

      case 'newest':
        const agentTime = new Date(conflict.agentData.timestamp).getTime();
        const coreflowTime = new Date(conflict.coreflowData.timestamp).getTime();
        return {
          resolved: true,
          action: agentTime > coreflowTime ? 'use-agent-data' : 'use-coreflow-data',
          data: agentTime > coreflowTime ? conflict.agentData : conflict.coreflowData
        };

      case 'manual':
        // Queue for manual resolution
        this.emit('manualResolutionRequired', conflict);
        return { resolved: false, action: 'queued-for-manual' };

      default:
        return { resolved: false, action: 'unknown-strategy' };
    }
  }

  // Helper methods for data fetching
  private async fetchAgentDecisions(since?: Date): Promise<any[]> {
    const url = `${process.env.AGENT_SYSTEM_URL || 'http://localhost:3000'}/api/decisions`;
    const params = since ? `?since=${since.toISOString()}` : '';

    const response = await fetch(url + params);
    if (!response.ok) throw new Error('Failed to fetch agent decisions');

    return await response.json();
  }

  private async fetchCoreFlowWorkflows(since?: Date): Promise<any[]> {
    const url = `${process.env.COREFLOW_API_URL || 'http://localhost:8787'}/api/workflows`;
    const params = since ? `?updatedSince=${since.toISOString()}` : '';

    const response = await fetch(url + params);
    if (!response.ok) throw new Error('Failed to fetch workflows');

    return await response.json();
  }

  private async fetchBusinessMetrics(since?: Date): Promise<any[]> {
    const url = `${process.env.COREFLOW_API_URL || 'http://localhost:8787'}/api/metrics`;
    const params = since ? `?since=${since.toISOString()}` : '';

    const response = await fetch(url + params);
    if (!response.ok) return [];

    return await response.json();
  }

  private async fetchAgentStatus(): Promise<Map<string, any>> {
    const url = `${process.env.AGENT_SYSTEM_URL || 'http://localhost:3000'}/api/agents/status`;

    const response = await fetch(url);
    if (!response.ok) throw new Error('Failed to fetch agent status');

    const data = await response.json();
    return new Map(Object.entries(data));
  }

  private async fetchBusinessData(since?: Date): Promise<any[]> {
    const url = `${process.env.COREFLOW_API_URL || 'http://localhost:8787'}/api/business/data`;
    const params = since ? `?since=${since.toISOString()}` : '';

    const response = await fetch(url + params);
    if (!response.ok) return [];

    return await response.json();
  }

  // Helper methods for data pushing
  private async pushToCoreFlow(dataType: string, data: any): Promise<void> {
    const url = `${process.env.COREFLOW_API_URL || 'http://localhost:8787'}/api/sync/${dataType}`;

    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });

    if (!response.ok) {
      throw new Error(`Failed to push to CoreFlow360: ${response.statusText}`);
    }
  }

  private async pushToAgentSystem(dataType: string, data: any): Promise<void> {
    const url = `${process.env.AGENT_SYSTEM_URL || 'http://localhost:3000'}/api/sync/${dataType}`;

    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });

    if (!response.ok) {
      throw new Error(`Failed to push to Agent System: ${response.statusText}`);
    }
  }

  // Utility methods
  private createSyncJob(type: 'full' | 'incremental' | 'delta'): SyncJob {
    const job: SyncJob = {
      id: `sync-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type,
      source: 'agents',
      target: 'coreflow',
      status: 'running',
      startTime: new Date(),
      recordsProcessed: 0,
      recordsFailed: 0,
      errors: []
    };

    this.syncJobs.set(job.id, job);
    return job;
  }

  private batchData<T>(data: T[], batchSize: number): T[][] {
    const batches: T[][] = [];
    for (let i = 0; i < data.length; i += batchSize) {
      batches.push(data.slice(i, i + batchSize));
    }
    return batches;
  }

  private aggregateMetrics(metrics: any[]): any {
    // Aggregate metrics for efficient transmission
    return {
      timestamp: new Date(),
      count: metrics.length,
      aggregates: {
        revenue: metrics.reduce((sum, m) => sum + (m.revenue || 0), 0),
        expenses: metrics.reduce((sum, m) => sum + (m.expenses || 0), 0),
        profit: metrics.reduce((sum, m) => sum + ((m.revenue || 0) - (m.expenses || 0)), 0)
      },
      averages: {
        customerSatisfaction: metrics.reduce((sum, m) => sum + (m.customerSatisfaction || 0), 0) / metrics.length,
        employeeProductivity: metrics.reduce((sum, m) => sum + (m.employeeProductivity || 0), 0) / metrics.length
      }
    };
  }

  private getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((current, key) => current?.[key], obj);
  }

  private setNestedValue(obj: any, path: string, value: any): void {
    const keys = path.split('.');
    const lastKey = keys.pop()!;

    const target = keys.reduce((current, key) => {
      if (!current[key]) current[key] = {};
      return current[key];
    }, obj);

    target[lastKey] = value;
  }

  // Get sync statistics
  getSyncStatistics(): any {
    const jobs = Array.from(this.syncJobs.values());
    const completed = jobs.filter(j => j.status === 'completed');
    const failed = jobs.filter(j => j.status === 'failed');

    return {
      totalJobs: jobs.length,
      completedJobs: completed.length,
      failedJobs: failed.length,
      totalRecordsProcessed: jobs.reduce((sum, j) => sum + j.recordsProcessed, 0),
      totalRecordsFailed: jobs.reduce((sum, j) => sum + j.recordsFailed, 0),
      lastSyncTimestamps: Object.fromEntries(this.lastSyncTimestamp),
      conflictsQueued: this.conflictQueue.size,
      isRunning: this.isRunning
    };
  }

  // Cleanup
  cleanup(): void {
    this.stopSync();
    this.syncJobs.clear();
    this.conflictQueue.clear();
    this.lastSyncTimestamp.clear();
  }
}