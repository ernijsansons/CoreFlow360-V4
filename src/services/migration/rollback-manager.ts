import { MigrationConfig, RollbackConfig, Checkpoint } from '../../types/migration';

interface Snapshot {
  id: string;
  migrationId: string;
  timestamp: Date;
  type: 'PRE_MIGRATION' | 'CHECKPOINT' | 'POST_MIGRATION';
  tables: string[];
  dataLocation: string; // R2 or D1 location
  metadata: SnapshotMetadata;
  compression: 'none' | 'gzip' | 'brotli';
  encrypted: boolean;
  status: 'CREATING' | 'READY' | 'RESTORING' | 'EXPIRED';
}

interface SnapshotMetadata {
  recordCount: number;
  sizeBytes: number;
  schemaVersion: string;
  checksum: string;
  dependencies: string[];
  retentionPolicy: RetentionPolicy;
}

interface RetentionPolicy {
  retentionDays: number;
  autoCleanup: boolean;
  archiveAfterDays?: number;
  compressionLevel: number;
}

interface RollbackPlan {
  id: string;
  migrationId: string;
  targetSnapshot: string;
  rollbackSteps: RollbackStep[];
  estimatedDuration: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  prerequisites: string[];
  warnings: string[];
}

interface RollbackStep {
  id: string;
  order: number;
  type: 'RESTORE_DATA' | 'RESTORE_SCHEMA' | 'REPLAY_TRANSACTIONS' | 'VALIDATE' | 'NOTIFY';
  description: string;
  command: string;
  estimatedDuration: number;
  rollbackable: boolean;
  dependencies: string[];
}

interface Transaction {
  id: string;
  timestamp: Date;
  table: string;
  operation: 'INSERT' | 'UPDATE' | 'DELETE';
  oldData?: Record<string, any>;
  newData?: Record<string, any>;
  migrationId: string;
  batchId: string;
  checkpoint: string;
}

interface RollbackExecution {
  id: string;
  planId: string;
  status: 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
  startTime: Date;
  endTime?: Date;
  currentStep: number;
  totalSteps: number;
  progress: number;
  errors: RollbackError[];
  logs: RollbackLog[];
}

interface RollbackError {
  id: string;
  stepId: string;
  timestamp: Date;
  message: string;
  details: string;
  severity: 'WARNING' | 'ERROR' | 'CRITICAL';
  recoverable: boolean;
}

interface RollbackLog {
  id: string;
  timestamp: Date;
  level: 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';
  message: string;
  stepId?: string;
  metadata: Record<string, any>;
}

export // TODO: Consider splitting RollbackManager into smaller, focused classes
class RollbackManager {
  private env: any;
  private snapshots: Map<string, Snapshot> = new Map();
  private transactions: Map<string, Transaction[]> = new Map();
  private rollbackExecutions: Map<string, RollbackExecution> = new Map();

  constructor(env: any) {
    this.env = env;
    this.startCleanupScheduler();
  }

  async createSnapshot(migrationId: string, type: Snapshot['type'], tables?: string[]): Promise<string> {
    const snapshotId = crypto.randomUUID();
    const timestamp = new Date();

    const snapshot: Snapshot = {
      id: snapshotId,
      migrationId,
      timestamp,
      type,
      tables: tables || await this.getAllTables(migrationId),
      dataLocation: `snapshots/${migrationId}/${snapshotId}`,
      metadata: {
        recordCount: 0,
        sizeBytes: 0,
        schemaVersion: '1.0',
        checksum: '',
        dependencies: [],
        retentionPolicy: {
          retentionDays: 30,
          autoCleanup: true,
          compressionLevel: 6
        }
      },
      compression: 'gzip',
      encrypted: true,
      status: 'CREATING'
    };

    this.snapshots.set(snapshotId, snapshot);

    // Create snapshot asynchronously
    this.env.ctx.waitUntil(this.performSnapshotCreation(snapshot));

    return snapshotId;
  }

  private async performSnapshotCreation(snapshot: Snapshot): Promise<void> {
    try {
      let totalRecords = 0;
      let totalSize = 0;
      const snapshotData: Record<string, any[]> = {};

      // Snapshot each table
      for (const table of snapshot.tables) {
        const tableData = await this.snapshotTable(table, snapshot.migrationId);
        snapshotData[table] = tableData;
        totalRecords += tableData.length;
      }

      // Compress and encrypt data
      const serializedData = JSON.stringify(snapshotData);
      const compressedData = await this.compressData(serializedData, snapshot.compression);
      const encryptedData = snapshot.encrypted
        ? await this.encryptData(compressedData)
        : compressedData;

      totalSize = encryptedData.byteLength;

      // Store in R2
      await this.storeSnapshotData(snapshot.dataLocation, encryptedData);

      // Calculate checksum
      const checksum = await this.calculateChecksum(encryptedData);

      // Update snapshot metadata
      snapshot.metadata.recordCount = totalRecords;
      snapshot.metadata.sizeBytes = totalSize;
      snapshot.metadata.checksum = checksum;
      snapshot.status = 'READY';

      // Store metadata in D1
      await this.storeSnapshotMetadata(snapshot);

    } catch (error) {
      snapshot.status = 'EXPIRED';
    }
  }

  private async snapshotTable(table: string, migrationId: string): Promise<any[]> {
    // This would query the actual database to get table data
    // Implementation depends on the database type

    if (this.env.DB) {
      // D1 example
      const result = await this.env.DB.prepare(`SELECT * FROM ${table}`).all();
      return result.results || [];
    }

    return [];
  }

  private async compressData(data: string, compression: string): Promise<Uint8Array> {
    switch (compression) {
      case 'gzip':
        // Use CompressionStream if available
        const stream = new CompressionStream('gzip');
        const writer = stream.writable.getWriter();
        const reader = stream.readable.getReader();

        writer.write(new TextEncoder().encode(data));
        writer.close();

        const chunks: Uint8Array[] = [];
        let done = false;

        while (!done) {
          const { value, done: readerDone } = await reader.read();
          done = readerDone;
          if (value) chunks.push(value);
        }

        const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
        const result = new Uint8Array(totalLength);
        let offset = 0;

        for (const chunk of chunks) {
          result.set(chunk, offset);
          offset += chunk.length;
        }

        return result;

      case 'none':
      default:
        return new TextEncoder().encode(data);
    }
  }

  private async encryptData(data: Uint8Array): Promise<Uint8Array> {
    if (!this.env.ENCRYPTION_KEY) {
      return data; // No encryption if key not available
    }

    // Use Web Crypto API for encryption
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(this.env.ENCRYPTION_KEY),
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      data
    );

    // Combine IV and encrypted data
    const result = new Uint8Array(iv.length + encrypted.byteLength);
    result.set(iv);
    result.set(new Uint8Array(encrypted), iv.length);

    return result;
  }

  private async storeSnapshotData(location: string, data: Uint8Array): Promise<void> {
    if (this.env.R2_BUCKET) {
      await this.env.R2_BUCKET.put(location, data);
    } else {
      throw new Error('R2 bucket not configured for snapshot storage');
    }
  }

  private async calculateChecksum(data: Uint8Array): Promise<string> {
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  private async storeSnapshotMetadata(snapshot: Snapshot): Promise<void> {
    if (this.env.DB) {
      await this.env.DB.prepare(`
        INSERT INTO snapshots (
          id, migration_id, timestamp, type, tables, data_location,
          record_count, size_bytes, checksum, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        snapshot.id,
        snapshot.migrationId,
        snapshot.timestamp.toISOString(),
        snapshot.type,
        JSON.stringify(snapshot.tables),
        snapshot.dataLocation,
        snapshot.metadata.recordCount,
        snapshot.metadata.sizeBytes,
        snapshot.metadata.checksum,
        snapshot.status
      ).run();
    }
  }

  async rollback(migrationId: string, targetSnapshot?: string): Promise<string> {
    // Find the appropriate snapshot to rollback to
    const snapshot = targetSnapshot
      ? this.snapshots.get(targetSnapshot)
      : await this.findBestRollbackSnapshot(migrationId);

    if (!snapshot) {
      throw new Error('No suitable snapshot found for rollback');
    }

    // Create rollback plan
    const plan = await this.createRollbackPlan(migrationId, snapshot);

    // Execute rollback
    const executionId = await this.executeRollbackPlan(plan);

    return executionId;
  }

  private async findBestRollbackSnapshot(migrationId: string): Promise<Snapshot | null> {
    const migrationSnapshots = Array.from(this.snapshots.values())
      .filter(s => s.migrationId === migrationId && s.status === 'READY')
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    // Prefer PRE_MIGRATION snapshots, then most recent checkpoint
    return migrationSnapshots.find(s => s.type === 'PRE_MIGRATION') ||
           migrationSnapshots.find(s => s.type === 'CHECKPOINT') ||
           null;
  }

  private async createRollbackPlan(migrationId: string, snapshot: Snapshot): Promise<RollbackPlan> {
    const steps: RollbackStep[] = [];
    let order = 1;

    // Step 1: Validate prerequisites
    steps.push({
      id: crypto.randomUUID(),
      order: order++,
      type: 'VALIDATE',
      description: 'Validate rollback prerequisites',
      command: 'validate_prerequisites',
      estimatedDuration: 30000, // 30 seconds
      rollbackable: false,
      dependencies: []
    });

    // Step 2: Create current state backup
    steps.push({
      id: crypto.randomUUID(),
      order: order++,
      type: 'RESTORE_DATA',
      description: 'Create backup of current state',
      command: 'backup_current_state',
      estimatedDuration: 300000, // 5 minutes
      rollbackable: false,
      dependencies: []
    });

    // Step 3: Restore schema if needed
    if (snapshot.type === 'PRE_MIGRATION') {
      steps.push({
        id: crypto.randomUUID(),
        order: order++,
        type: 'RESTORE_SCHEMA',
        description: 'Restore database schema',
        command: `restore_schema:${snapshot.id}`,
        estimatedDuration: 120000, // 2 minutes
        rollbackable: true,
        dependencies: []
      });
    }

    // Step 4: Restore data
    steps.push({
      id: crypto.randomUUID(),
      order: order++,
      type: 'RESTORE_DATA',
      description: 'Restore snapshot data',
      command: `restore_data:${snapshot.id}`,
      estimatedDuration: this.estimateRestoreTime(snapshot),
      rollbackable: true,
      dependencies: []
    });

    // Step 5: Replay transactions if checkpoint rollback
    if (snapshot.type === 'CHECKPOINT') {
      const transactionsToReplay = await this.getTransactionsSinceCheckpoint(migrationId, snapshot.id);
      if (transactionsToReplay.length > 0) {
        steps.push({
          id: crypto.randomUUID(),
          order: order++,
          type: 'REPLAY_TRANSACTIONS',
          description: `Replay ${transactionsToReplay.length} transactions`,
          command: `replay_transactions:${snapshot.id}`,
          estimatedDuration: transactionsToReplay.length * 100, // 100ms per transaction
          rollbackable: true,
          dependencies: []
        });
      }
    }

    // Step 6: Validate restored data
    steps.push({
      id: crypto.randomUUID(),
      order: order++,
      type: 'VALIDATE',
      description: 'Validate restored data integrity',
      command: 'validate_data_integrity',
      estimatedDuration: 180000, // 3 minutes
      rollbackable: false,
      dependencies: []
    });

    // Step 7: Notify affected systems
    steps.push({
      id: crypto.randomUUID(),
      order: order++,
      type: 'NOTIFY',
      description: 'Notify affected systems of rollback',
      command: 'notify_rollback_completion',
      estimatedDuration: 30000, // 30 seconds
      rollbackable: false,
      dependencies: []
    });

    const totalDuration = steps.reduce((sum, step) => sum + step.estimatedDuration, 0);
    const riskLevel = this.assessRollbackRisk(migrationId, snapshot);

    return {
      id: crypto.randomUUID(),
      migrationId,
      targetSnapshot: snapshot.id,
      rollbackSteps: steps,
      estimatedDuration: totalDuration,
      riskLevel,
      prerequisites: [
        'Database connection established',
        'Sufficient storage space available',
        'Migration not currently running'
      ],
      warnings: [
        'This operation will overwrite current data',
        'Some recent changes may be lost',
        'Affected systems will experience downtime'
      ]
    };
  }

  private estimateRestoreTime(snapshot: Snapshot): number {
    // Estimate based on data size (rough calculation)
    const bytesPerSecond = 10 * 1024 * 1024; // 10MB/s
    return (snapshot.metadata.sizeBytes / bytesPerSecond) * 1000;
  }

  private assessRollbackRisk(migrationId: string, snapshot: Snapshot): 'LOW' | 'MEDIUM' | 'HIGH' {
    const age = Date.now() - snapshot.timestamp.getTime();
    const ageHours = age / (1000 * 60 * 60);

    // Risk increases with snapshot age and data size
    if (ageHours > 168 || snapshot.metadata.sizeBytes > 1024 * 1024 * 1024) { // > 1 week or > 1GB
      return 'HIGH';
    } else if (ageHours > 24 || snapshot.metadata.sizeBytes > 100 * 1024 * 1024) { // > 1 day or > 100MB
      return 'MEDIUM';
    } else {
      return 'LOW';
    }
  }

  private async executeRollbackPlan(plan: RollbackPlan): Promise<string> {
    const executionId = crypto.randomUUID();

    const execution: RollbackExecution = {
      id: executionId,
      planId: plan.id,
      status: 'RUNNING',
      startTime: new Date(),
      currentStep: 0,
      totalSteps: plan.rollbackSteps.length,
      progress: 0,
      errors: [],
      logs: []
    };

    this.rollbackExecutions.set(executionId, execution);

    // Execute rollback asynchronously
    this.env.ctx.waitUntil(this.performRollback(execution, plan));

    return executionId;
  }

  private async performRollback(execution: RollbackExecution, plan: RollbackPlan): Promise<void> {
    try {
      for (let i = 0; i < plan.rollbackSteps.length; i++) {
        const step = plan.rollbackSteps[i];
        execution.currentStep = i + 1;
        execution.progress = ((i + 1) / plan.rollbackSteps.length) * 100;

        this.addLog(execution, 'INFO', `Starting step ${step.order}: ${step.description}`);

        try {
          await this.executeRollbackStep(step, execution);
          this.addLog(execution, 'INFO', `Completed step ${step.order}`);
        } catch (error) {
          const rollbackError: RollbackError = {
            id: crypto.randomUUID(),
            stepId: step.id,
            timestamp: new Date(),
            message: (error as Error).message,
            details: (error as Error).stack || '',
            severity: 'ERROR',
            recoverable: step.rollbackable
          };

          execution.errors.push(rollbackError);
          this.addLog(execution, 'ERROR', `Step ${step.order} failed: ${(error as Error).message}`);

          if (!step.rollbackable) {
            throw error; // Abort rollback
          }
        }
      }

      execution.status = 'COMPLETED';
      execution.endTime = new Date();
      this.addLog(execution, 'INFO', 'Rollback completed successfully');

    } catch (error) {
      execution.status = 'FAILED';
      execution.endTime = new Date();
      this.addLog(execution, 'ERROR', `Rollback failed: ${(error as Error).message}`);

      // Send failure notification
      await this.notifyRollbackFailure(execution, plan);
    }
  }

  private async executeRollbackStep(step: RollbackStep, execution: RollbackExecution): Promise<void> {
    const [command, parameter] = step.command.split(':');

    switch (command) {
      case 'validate_prerequisites':
        await this.validatePrerequisites();
        break;
      case 'backup_current_state':
        await this.backupCurrentState(execution.planId);
        break;
      case 'restore_schema':
        await this.restoreSchema(parameter);
        break;
      case 'restore_data':
        await this.restoreData(parameter);
        break;
      case 'replay_transactions':
        await this.replayTransactions(parameter);
        break;
      case 'validate_data_integrity':
        await this.validateDataIntegrity();
        break;
      case 'notify_rollback_completion':
        await this.notifyRollbackCompletion(execution);
        break;
      default:
        throw new Error(`Unknown rollback command: ${command}`);
    }
  }

  private async validatePrerequisites(): Promise<void> {
    // Check database connectivity
    if (this.env.DB) {
      await this.env.DB.prepare('SELECT 1').first();
    }

    // Check R2 connectivity
    if (this.env.R2_BUCKET) {
      await this.env.R2_BUCKET.head('test-connectivity');
    }
  }

  private async backupCurrentState(planId: string): Promise<void> {
    // Create a snapshot of current state before rollback
    await this.createSnapshot(planId, 'PRE_MIGRATION');
  }

  private async restoreSchema(snapshotId: string): Promise<void> {
    // Restore database schema from snapshot
    // This would involve dropping and recreating tables
  }

  private async restoreData(snapshotId: string): Promise<void> {
    const snapshot = this.snapshots.get(snapshotId);
    if (!snapshot) {
      throw new Error(`Snapshot ${snapshotId} not found`);
    }

    // Retrieve snapshot data from R2
    const encryptedData = await this.retrieveSnapshotData(snapshot.dataLocation);

    // Decrypt and decompress
    const compressedData = snapshot.encrypted
      ? await this.decryptData(encryptedData)
      : encryptedData;

    const rawData = await this.decompressData(compressedData, snapshot.compression);
    const snapshotData = JSON.parse(rawData);

    // Restore each table
    for (const [table, data] of Object.entries(snapshotData)) {
      await this.restoreTableData(table, data as any[]);
    }
  }

  private async retrieveSnapshotData(location: string): Promise<Uint8Array> {
    if (!this.env.R2_BUCKET) {
      throw new Error('R2 bucket not configured');
    }

    const object = await this.env.R2_BUCKET.get(location);
    if (!object) {
      throw new Error(`Snapshot data not found at ${location}`);
    }

    return new Uint8Array(await object.arrayBuffer());
  }

  private async decryptData(encryptedData: Uint8Array): Promise<Uint8Array> {
    if (!this.env.ENCRYPTION_KEY) {
      return encryptedData;
    }

    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(this.env.ENCRYPTION_KEY),
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const iv = encryptedData.slice(0, 12);
    const data = encryptedData.slice(12);

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      data
    );

    return new Uint8Array(decrypted);
  }

  private async decompressData(compressedData: Uint8Array, compression: string): Promise<string> {
    switch (compression) {
      case 'gzip':
        const stream = new DecompressionStream('gzip');
        const writer = stream.writable.getWriter();
        const reader = stream.readable.getReader();

        writer.write(compressedData);
        writer.close();

        const chunks: Uint8Array[] = [];
        let done = false;

        while (!done) {
          const { value, done: readerDone } = await reader.read();
          done = readerDone;
          if (value) chunks.push(value);
        }

        const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
        const result = new Uint8Array(totalLength);
        let offset = 0;

        for (const chunk of chunks) {
          result.set(chunk, offset);
          offset += chunk.length;
        }

        return new TextDecoder().decode(result);

      case 'none':
      default:
        return new TextDecoder().decode(compressedData);
    }
  }

  private async restoreTableData(table: string, data: any[]): Promise<void> {
    if (!this.env.DB) return;

    // Clear existing data
    await this.env.DB.prepare(`DELETE FROM ${table}`).run();

    // Insert restored data in batches
    const batchSize = 100;
    for (let i = 0; i < data.length; i += batchSize) {
      const batch = data.slice(i, i + batchSize);

      for (const record of batch) {
        const columns = Object.keys(record);
        const values = Object.values(record);
        const placeholders = columns.map(() => '?').join(', ');

        await this.env.DB.prepare(`
          INSERT INTO ${table} (${columns.join(', ')})
          VALUES (${placeholders})
        `).bind(...values).run();
      }
    }
  }

  private async replayTransactions(checkpointId: string): Promise<void> {
    const transactions = await this.getTransactionsSinceCheckpoint('', checkpointId);

    for (const transaction of transactions) {
      await this.applyTransaction(transaction);
    }
  }

  private async getTransactionsSinceCheckpoint(migrationId: string, checkpointId: string): Promise<Transaction[]> {
    // This would query the transaction log for transactions after the checkpoint
    return this.transactions.get(migrationId) || [];
  }

  private async applyTransaction(transaction: Transaction): Promise<void> {
    if (!this.env.DB) return;

    switch (transaction.operation) {
      case 'INSERT':
        if (transaction.newData) {
          const columns = Object.keys(transaction.newData);
          const values = Object.values(transaction.newData);
          const placeholders = columns.map(() => '?').join(', ');

          await this.env.DB.prepare(`
            INSERT INTO ${transaction.table} (${columns.join(', ')})
            VALUES (${placeholders})
          `).bind(...values).run();
        }
        break;

      case 'UPDATE':
        if (transaction.newData) {
          const sets = Object.keys(transaction.newData)
            .map(key => `${key} = ?`)
            .join(', ');
          const values = Object.values(transaction.newData);

          await this.env.DB.prepare(`
            UPDATE ${transaction.table}
            SET ${sets}
            WHERE id = ?
          `).bind(...values, transaction.id).run();
        }
        break;

      case 'DELETE':
        await this.env.DB.prepare(`
          DELETE FROM ${transaction.table} WHERE id = ?
        `).bind(transaction.id).run();
        break;
    }
  }

  private async validateDataIntegrity(): Promise<void> {
    // Perform data integrity checks
    // This would verify foreign key constraints, data consistency, etc.
  }

  private async notifyRollbackCompletion(execution: RollbackExecution): Promise<void> {
    if (this.env.ROLLBACK_WEBHOOK) {
      await fetch(this.env.ROLLBACK_WEBHOOK, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'rollback_completed',
          executionId: execution.id,
          status: execution.status
        })
      });
    }
  }

  private async notifyRollbackFailure(execution: RollbackExecution, plan: RollbackPlan): Promise<void> {
    if (this.env.ROLLBACK_WEBHOOK) {
      await fetch(this.env.ROLLBACK_WEBHOOK, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'rollback_failed',
          executionId: execution.id,
          errors: execution.errors,
          plan
        })
      });
    }
  }

  private addLog(execution: RollbackExecution, level: RollbackLog['level'], message: string, stepId?: string): void {
    execution.logs.push({
      id: crypto.randomUUID(),
      timestamp: new Date(),
      level,
      message,
      stepId,
      metadata: {}
    });
  }

  private async getAllTables(migrationId: string): Promise<string[]> {
    // This would query the database schema to get all table names
    if (this.env.DB) {
      const result = await this.env.DB.prepare(`
        SELECT name FROM sqlite_master WHERE type='table'
      `).all();

      return result.results?.map((row: any) => row.name) || [];
    }

    return [];
  }

  private startCleanupScheduler(): void {
    // Clean up expired snapshots periodically
    setInterval(async () => {
      await this.cleanupExpiredSnapshots();
    }, 24 * 60 * 60 * 1000); // Daily cleanup
  }

  private async cleanupExpiredSnapshots(): Promise<void> {
    const now = Date.now();

    for (const [id, snapshot] of this.snapshots) {
      const age = now - snapshot.timestamp.getTime();
      const retentionPeriod = snapshot.metadata.retentionPolicy.retentionDays * 24 * 60 * 60 * 1000;

      if (age > retentionPeriod && snapshot.metadata.retentionPolicy.autoCleanup) {
        await this.deleteSnapshot(id);
      }
    }
  }

  private async deleteSnapshot(snapshotId: string): Promise<void> {
    const snapshot = this.snapshots.get(snapshotId);
    if (!snapshot) return;

    // Delete from R2
    if (this.env.R2_BUCKET) {
      await this.env.R2_BUCKET.delete(snapshot.dataLocation);
    }

    // Delete from D1
    if (this.env.DB) {
      await this.env.DB.prepare('DELETE FROM snapshots WHERE id = ?').bind(snapshotId).run();
    }

    // Remove from memory
    this.snapshots.delete(snapshotId);
  }

  async getSnapshots(migrationId?: string): Promise<Snapshot[]> {
    let snapshots = Array.from(this.snapshots.values());

    if (migrationId) {
      snapshots = snapshots.filter(s => s.migrationId === migrationId);
    }

    return snapshots.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  async getRollbackExecution(executionId: string): Promise<RollbackExecution | null> {
    return this.rollbackExecutions.get(executionId) || null;
  }

  async cancelRollback(executionId: string): Promise<void> {
    const execution = this.rollbackExecutions.get(executionId);
    if (execution && execution.status === 'RUNNING') {
      execution.status = 'CANCELLED';
      execution.endTime = new Date();
      this.addLog(execution, 'WARN', 'Rollback cancelled by user');
    }
  }
}