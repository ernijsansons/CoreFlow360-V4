import { MigrationState, MigrationMetrics, AuditLog, ProgressUpdate } from '../../types/migration';

export interface ProgressEvent {
  migrationId: string;
  timestamp: Date;
  phase: string;
  status: 'started' | 'progress' | 'completed' | 'failed' | 'paused';
  progress: number;
  message?: string;
  details?: any;
  metrics?: Partial<MigrationMetrics>;
}

export interface AuditEntry {
  id: string;
  migrationId: string;
  timestamp: Date;
  action: string;
  actor: string;
  details: any;
  before?: any;
  after?: any;
  metadata?: Record<string, any>;
}

export class ProgressTracker {
  private progressCallbacks: Map<string, ((event: ProgressEvent) => void)[]> = new Map();
  private auditLog: AuditEntry[] = [];
  private migrationStates: Map<string, MigrationState> = new Map();
  private env: any;

  constructor(env: any) {
    this.env = env;
  }

  subscribeTo(migrationId: string, callback: (event: ProgressEvent) => void): void {
    if (!this.progressCallbacks.has(migrationId)) {
      this.progressCallbacks.set(migrationId, []);
    }
    this.progressCallbacks.get(migrationId)!.push(callback);
  }

  unsubscribeFrom(migrationId: string, callback: (event: ProgressEvent) => void): void {
    const callbacks = this.progressCallbacks.get(migrationId);
    if (callbacks) {
      const index = callbacks.indexOf(callback);
      if (index > -1) {
        callbacks.splice(index, 1);
      }
    }
  }

  async updateProgress(migrationId: string, update: Partial<ProgressEvent>): Promise<void> {
    const event: ProgressEvent = {
      migrationId,
      timestamp: new Date(),
      phase: update.phase || 'unknown',
      status: update.status || 'progress',
      progress: update.progress || 0,
      message: update.message,
      details: update.details,
      metrics: update.metrics
    };

    // Update migration state
    const currentState = this.migrationStates.get(migrationId) || {
      id: migrationId,
      status: 'pending',
      progress: 0,
      phase: 'initialization',
      startTime: new Date(),
      metrics: {
        recordsProcessed: 0,
        recordsTotal: 0,
        recordsSuccess: 0,
        recordsError: 0,
        bytesProcessed: 0,
        bytesTotal: 0,
        throughputRecordsPerSecond: 0,
        throughputBytesPerSecond: 0,
        estimatedTimeRemaining: 0,
        errorRate: 0
      },
      logs: []
    };

    const updatedState: MigrationState = {
      ...currentState,
      status: this.mapEventStatusToMigrationStatus(event.status),
      progress: event.progress,
      phase: event.phase,
      lastUpdate: event.timestamp,
      ...(event.status === 'completed' && { endTime: event.timestamp }),
      ...(event.metrics && {
        metrics: {
          ...currentState.metrics,
          ...event.metrics
        }
      })
    };

    this.migrationStates.set(migrationId, updatedState);

    // Store progress in Durable Object if available
    await this.persistProgress(migrationId, event);

    // Notify subscribers
    const callbacks = this.progressCallbacks.get(migrationId) || [];
    callbacks.forEach(callback => {
      try {
        callback(event);
      } catch (error) {
      }
    });

    // Log audit entry for significant events
    if (['started', 'completed', 'failed', 'paused'].includes(event.status)) {
      await this.logAudit(migrationId, `migration_${event.status}`, 'system', {
        phase: event.phase,
        progress: event.progress,
        message: event.message,
        details: event.details
      });
    }
  }

  async logAudit(
    migrationId: string,
    action: string,
    actor: string,
    details: any,
    before?: any,
    after?: any
  ): Promise<void> {
    const entry: AuditEntry = {
      id: crypto.randomUUID(),
      migrationId,
      timestamp: new Date(),
      action,
      actor,
      details,
      before,
      after,
      metadata: {
        userAgent: 'CoreFlow360-Migration-Engine',
        sessionId: this.generateSessionId()
      }
    };

    this.auditLog.push(entry);

    // Persist audit entry
    await this.persistAuditEntry(entry);
  }

  async getMigrationState(migrationId: string): Promise<MigrationState | null> {
    let state = this.migrationStates.get(migrationId);

    if (!state) {
      // Try to load from persistent storage
      state = await this.loadMigrationState(migrationId);
      if (state) {
        this.migrationStates.set(migrationId, state);
      }
    }

    return state || null;
  }

  async getAuditLog(migrationId: string, limit?: number): Promise<AuditEntry[]> {
    const entries = this.auditLog
      .filter(entry => entry.migrationId === migrationId)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    if (limit) {
      return entries.slice(0, limit);
    }

    return entries;
  }

  async getAllMigrationStates(): Promise<MigrationState[]> {
    const states = Array.from(this.migrationStates.values());

    // Also load any persisted states not in memory
    const persistedStates = await this.loadAllMigrationStates();

    // Merge and deduplicate
    const stateMap = new Map<string, MigrationState>();
    [...states, ...persistedStates].forEach(state => {
      stateMap.set(state.id, state);
    });

    return Array.from(stateMap.values());
  }

  async calculateMetrics(migrationId: string): Promise<MigrationMetrics> {
    const state = await this.getMigrationState(migrationId);
    if (!state) {
      throw new Error(`Migration state not found: ${migrationId}`);
    }

    const now = new Date();
    const elapsed = state.startTime ? (now.getTime() - state.startTime.getTime()) / 1000 : 0;
    const remainingProgress = Math.max(0, 100 - state.progress);
    const estimatedTimeRemaining = state.progress > 0 && remainingProgress > 0
      ? (elapsed / state.progress) * remainingProgress
      : 0;

    const throughputRecordsPerSecond = elapsed > 0
      ? state.metrics.recordsProcessed / elapsed
      : 0;

    const throughputBytesPerSecond = elapsed > 0
      ? state.metrics.bytesProcessed / elapsed
      : 0;

    const errorRate = state.metrics.recordsProcessed > 0
      ? (state.metrics.recordsError / state.metrics.recordsProcessed) * 100
      : 0;

    return {
      ...state.metrics,
      throughputRecordsPerSecond,
      throughputBytesPerSecond,
      estimatedTimeRemaining,
      errorRate
    };
  }

  async generateProgressReport(migrationId: string): Promise<any> {
    const state = await this.getMigrationState(migrationId);
    const metrics = await this.calculateMetrics(migrationId);
    const auditEntries = await this.getAuditLog(migrationId, 10);

    return {
      migration: {
        id: migrationId,
        status: state?.status,
        progress: state?.progress,
        phase: state?.phase,
        startTime: state?.startTime,
        endTime: state?.endTime,
        lastUpdate: state?.lastUpdate
      },
      metrics,
      recentActivity: auditEntries,
      summary: {
        duration: state?.startTime ?
          ((state?.endTime || new Date()).getTime() - state.startTime.getTime()) / 1000 : 0,
        successRate: metrics.recordsProcessed > 0
          ? ((metrics.recordsProcessed - metrics.recordsError) / metrics.recordsProcessed) * 100
          : 0,
        avgThroughput: metrics.throughputRecordsPerSecond,
        totalErrors: metrics.recordsError
      }
    };
  }

  async pauseMigration(migrationId: string, reason: string): Promise<void> {
    await this.updateProgress(migrationId, {
      status: 'paused',
      message: `Migration paused: ${reason}`
    });

    await this.logAudit(migrationId, 'migration_paused', 'user', { reason });
  }

  async resumeMigration(migrationId: string): Promise<void> {
    await this.updateProgress(migrationId, {
      status: 'progress',
      message: 'Migration resumed'
    });

    await this.logAudit(migrationId, 'migration_resumed', 'user', {});
  }

  async cancelMigration(migrationId: string, reason: string): Promise<void> {
    await this.updateProgress(migrationId, {
      status: 'failed',
      message: `Migration cancelled: ${reason}`
    });

    await this.logAudit(migrationId, 'migration_cancelled', 'user', { reason });
  }

  private mapEventStatusToMigrationStatus(eventStatus: string): string {
    switch (eventStatus) {
      case 'started': return 'running';
      case 'progress': return 'running';
      case 'completed': return 'completed';
      case 'failed': return 'failed';
      case 'paused': return 'paused';
      default: return 'unknown';
    }
  }

  private async persistProgress(migrationId: string, event: ProgressEvent): Promise<void> {
    try {
      // Store in KV or database
      const key = `migration:progress:${migrationId}`;
      const value = JSON.stringify({
        ...event,
        timestamp: event.timestamp.toISOString()
      });

      if (this.env.MIGRATION_KV) {
        await this.env.MIGRATION_KV.put(key, value);
      }
    } catch (error) {
    }
  }

  private async persistAuditEntry(entry: AuditEntry): Promise<void> {
    try {
      const key = `migration:audit:${entry.migrationId}:${entry.id}`;
      const value = JSON.stringify({
        ...entry,
        timestamp: entry.timestamp.toISOString()
      });

      if (this.env.MIGRATION_KV) {
        await this.env.MIGRATION_KV.put(key, value);
      }
    } catch (error) {
    }
  }

  private async loadMigrationState(migrationId: string): Promise<MigrationState | null> {
    try {
      const key = `migration:state:${migrationId}`;

      if (this.env.MIGRATION_KV) {
        const value = await this.env.MIGRATION_KV.get(key);
        if (value) {
          const parsed = JSON.parse(value);
          return {
            ...parsed,
            startTime: new Date(parsed.startTime),
            endTime: parsed.endTime ? new Date(parsed.endTime) : undefined,
            lastUpdate: parsed.lastUpdate ? new Date(parsed.lastUpdate) : undefined
          };
        }
      }
    } catch (error) {
    }

    return null;
  }

  private async loadAllMigrationStates(): Promise<MigrationState[]> {
    try {
      if (this.env.MIGRATION_KV) {
        const list = await this.env.MIGRATION_KV.list({ prefix: 'migration:state:' });
        const states: MigrationState[] = [];

        for (const key of list.keys) {
          const value = await this.env.MIGRATION_KV.get(key.name);
          if (value) {
            const parsed = JSON.parse(value);
            states.push({
              ...parsed,
              startTime: new Date(parsed.startTime),
              endTime: parsed.endTime ? new Date(parsed.endTime) : undefined,
              lastUpdate: parsed.lastUpdate ? new Date(parsed.lastUpdate) : undefined
            });
          }
        }

        return states;
      }
    } catch (error) {
    }

    return [];
  }

  private generateSessionId(): string {
    return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

export class MetricsCollector {
  private metrics: Map<string, MigrationMetrics> = new Map();
  private startTimes: Map<string, number> = new Map();

  startCollection(migrationId: string): void {
    this.startTimes.set(migrationId, Date.now());
    this.metrics.set(migrationId, {
      recordsProcessed: 0,
      recordsTotal: 0,
      recordsSuccess: 0,
      recordsError: 0,
      bytesProcessed: 0,
      bytesTotal: 0,
      throughputRecordsPerSecond: 0,
      throughputBytesPerSecond: 0,
      estimatedTimeRemaining: 0,
      errorRate: 0
    });
  }

  incrementRecords(migrationId: string, processed: number, success: number, errors: number): void {
    const metrics = this.metrics.get(migrationId);
    if (metrics) {
      metrics.recordsProcessed += processed;
      metrics.recordsSuccess += success;
      metrics.recordsError += errors;
      this.updateThroughput(migrationId, metrics);
    }
  }

  incrementBytes(migrationId: string, bytes: number): void {
    const metrics = this.metrics.get(migrationId);
    if (metrics) {
      metrics.bytesProcessed += bytes;
      this.updateThroughput(migrationId, metrics);
    }
  }

  setTotals(migrationId: string, totalRecords: number, totalBytes: number): void {
    const metrics = this.metrics.get(migrationId);
    if (metrics) {
      metrics.recordsTotal = totalRecords;
      metrics.bytesTotal = totalBytes;
    }
  }

  getMetrics(migrationId: string): MigrationMetrics | null {
    return this.metrics.get(migrationId) || null;
  }

  private updateThroughput(migrationId: string, metrics: MigrationMetrics): void {
    const startTime = this.startTimes.get(migrationId);
    if (startTime) {
      const elapsed = (Date.now() - startTime) / 1000;
      if (elapsed > 0) {
        metrics.throughputRecordsPerSecond = metrics.recordsProcessed / elapsed;
        metrics.throughputBytesPerSecond = metrics.bytesProcessed / elapsed;

        if (metrics.recordsTotal > 0) {
          const remainingRecords = metrics.recordsTotal - metrics.recordsProcessed;
          if (metrics.throughputRecordsPerSecond > 0) {
            metrics.estimatedTimeRemaining = remainingRecords / metrics.throughputRecordsPerSecond;
          }
        }

        if (metrics.recordsProcessed > 0) {
          metrics.errorRate = (metrics.recordsError / metrics.recordsProcessed) * 100;
        }
      }
    }
  }
}