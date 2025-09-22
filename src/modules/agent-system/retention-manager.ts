/**
 * Data Retention Manager
 * Automatic data cleanup and archival with configurable policies
 */

import { Logger } from '../../shared/logger';
import type { D1Database, KVNamespace, R2Bucket } from '@cloudflare/workers-types';
import { sanitizeBusinessId } from './security-utils';

export interface RetentionPolicy {
  id: string;
  name: string;
  tableName: string;
  retentionDays: number;
  archiveEnabled: boolean;
  archiveAfterDays?: number;
  deleteStrategy: 'hard' | 'soft';
  batchSize: number;
  enabled: boolean;
  lastRun?: number;
  nextRun?: number;
  filters?: PolicyFilter[];
  schedule?: string; // cron expression
}

export interface PolicyFilter {
  column: string;
  operator: '=' | '!=' | '>' | '<' | 'IN' | 'NOT IN';
  value: any;
}

export interface ArchiveConfig {
  bucket?: R2Bucket;
  format: 'json' | 'csv' | 'parquet';
  compression: 'none' | 'gzip' | 'brotli';
  encryption?: boolean;
  partitionBy?: string; // column name
}

export interface RetentionStats {
  totalRecordsProcessed: number;
  recordsDeleted: number;
  recordsArchived: number;
  spaceReclaimed: number;
  lastRunTime: number;
  errors: number;
}

export interface DataLifecycle {
  hot: number;  // days in hot storage
  warm: number; // days in warm storage
  cold: number; // days in cold storage (archive)
  delete: number; // days until deletion
}

export // TODO: Consider splitting RetentionManager into smaller, focused classes
class RetentionManager {
  private logger: Logger;
  private db: D1Database;
  private kv: KVNamespace;
  private archiveBucket?: R2Bucket;

  private policies = new Map<string, RetentionPolicy>();
  private runningPolicies = new Set<string>();
  private stats = new Map<string, RetentionStats>();

  private cleanupInterval?: NodeJS.Timeout;
  private archiveConfig: ArchiveConfig;

  constructor(
    db: D1Database,
    kv: KVNamespace,
    archiveConfig?: Partial<ArchiveConfig>
  ) {
    this.logger = new Logger();
    this.db = db;
    this.kv = kv;
    this.archiveConfig = {
      format: 'json',
      compression: 'gzip',
      encryption: true,
      ...archiveConfig
    };

    this.loadPolicies();
    this.startScheduler();
  }

  /**
   * Create or update retention policy
   */
  async createPolicy(
    policy: Omit<RetentionPolicy, 'id' | 'lastRun' | 'nextRun'>
  ): Promise<string> {
    const policyId = `policy_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;

    const retentionPolicy: RetentionPolicy = {
      ...policy,
      id: policyId,
      nextRun: this.calculateNextRun(policy.schedule)
    };

    // Validate policy
    this.validatePolicy(retentionPolicy);

    // Save to database
    await this.db.prepare(`
      INSERT INTO retention_policies (
        id, name, table_name, retention_days,
        archive_enabled, archive_after_days,
        delete_strategy, batch_size, enabled,
        filters, schedule
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      policyId,
      policy.name,
      policy.tableName,
      policy.retentionDays,
      policy.archiveEnabled ? 1 : 0,
      policy.archiveAfterDays || null,
      policy.deleteStrategy,
      policy.batchSize,
      policy.enabled ? 1 : 0,
      JSON.stringify(policy.filters || []),
      policy.schedule || null
    ).run();

    // Update cache
    this.policies.set(policyId, retentionPolicy);

    this.logger.info('Retention policy created', {
      policyId,
      name: policy.name,
      table: policy.tableName,
      retentionDays: policy.retentionDays
    });

    return policyId;
  }

  /**
   * Execute retention policy
   */
  async executePolicy(policyId: string): Promise<RetentionStats> {
    const policy = this.policies.get(policyId);
    if (!policy) {
      throw new Error(`Policy not found: ${policyId}`);
    }

    if (!policy.enabled) {
      throw new Error(`Policy is disabled: ${policyId}`);
    }

    if (this.runningPolicies.has(policyId)) {
      throw new Error(`Policy is already running: ${policyId}`);
    }

    this.runningPolicies.add(policyId);

    const stats: RetentionStats = {
      totalRecordsProcessed: 0,
      recordsDeleted: 0,
      recordsArchived: 0,
      spaceReclaimed: 0,
      lastRunTime: Date.now(),
      errors: 0
    };

    try {
      this.logger.info('Executing retention policy', {
        policyId,
        name: policy.name,
        table: policy.tableName
      });

      // Archive records if enabled
      if (policy.archiveEnabled && policy.archiveAfterDays) {
        const archiveStats = await this.archiveRecords(policy);
        stats.recordsArchived = archiveStats.recordsArchived;
        stats.totalRecordsProcessed += archiveStats.recordsProcessed;
      }

      // Delete expired records
      const deleteStats = await this.deleteExpiredRecords(policy);
      stats.recordsDeleted = deleteStats.recordsDeleted;
      stats.totalRecordsProcessed += deleteStats.recordsProcessed;
      stats.spaceReclaimed = deleteStats.spaceReclaimed;

      // Update policy last run
      policy.lastRun = Date.now();
      policy.nextRun = this.calculateNextRun(policy.schedule);

      await this.updatePolicyStatus(policyId, policy);

      // Save stats
      await this.saveStats(policyId, stats);

      this.logger.info('Retention policy completed', {
        policyId,
        stats
      });

    } catch (error) {
      stats.errors++;
      this.logger.error('Retention policy failed', error, { policyId });
      throw error;

    } finally {
      this.runningPolicies.delete(policyId);
    }

    return stats;
  }

  /**
   * Archive records
   */
  private async archiveRecords(
    policy: RetentionPolicy
  ): Promise<{ recordsArchived: number; recordsProcessed: number }> {
    if (!policy.archiveAfterDays) {
      return { recordsArchived: 0, recordsProcessed: 0 };
    }

    const archiveCutoff = Date.now() - (policy.archiveAfterDays * 86400000);
    const deleteCutoff = Date.now() - (policy.retentionDays * 86400000);

    let recordsArchived = 0;
    let recordsProcessed = 0;
    let offset = 0;

    while (true) {
      // Get batch of records to archive
      const whereClause = this.buildWhereClause(policy.filters);
      const query = `
        SELECT * FROM ${policy.tableName}
        WHERE timestamp >= ? AND timestamp < ?
        ${whereClause ? `AND ${whereClause}` : ''}
        ORDER BY timestamp ASC
        LIMIT ? OFFSET ?
      `;

      const result = await this.db.prepare(query)
        .bind(deleteCutoff, archiveCutoff, policy.batchSize, offset)
        .all();

      const records = result.results || [];
      if (records.length === 0) break;

      recordsProcessed += records.length;

      // Archive batch
      const archived = await this.archiveBatch(policy, records);
      recordsArchived += archived;

      // Mark records as archived (soft delete)
      if (archived > 0 && policy.deleteStrategy === 'soft') {
        await this.markAsArchived(policy.tableName, records);
      }

      offset += policy.batchSize;

      // Add delay to prevent overload
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    return { recordsArchived, recordsProcessed };
  }

  /**
   * Archive batch of records
   */
  private async archiveBatch(
    policy: RetentionPolicy,
    records: any[]
  ): Promise<number> {
    if (records.length === 0) return 0;

    try {
      const timestamp = Date.now();
    
   const fileName = `${policy.tableName}/${new Date().toISOString().split('T')[0]}/${timestamp}.${this.archiveConfig.format}`;

      let data: string | Uint8Array;

      // Format data
      switch (this.archiveConfig.format) {
        case 'json':
          data = JSON.stringify(records);
          break;
        case 'csv':
          data = this.convertToCSV(records);
          break;
        case 'parquet':
          // Would need parquet library
          data = JSON.stringify(records);
          break;
        default:
          data = JSON.stringify(records);
      }

      // Compress if enabled
      if (this.archiveConfig.compression !== 'none') {
        data = await this.compress(data, this.archiveConfig.compression);
      }

      // Encrypt if enabled
      if (this.archiveConfig.encryption) {
        data = await this.encrypt(data);
      }

      // Save to archive storage
      if (this.archiveConfig.bucket) {
        await this.archiveConfig.bucket.put(fileName, data);
      } else {
        // Fallback to KV for small archives
        await this.kv.put(`archive:${fileName}`, data, {
          expirationTtl: 7776000 // 90 days
        });
      }

      this.logger.debug('Records archived', {
        policy: policy.name,
        count: records.length,
        file: fileName
      });

      return records.length;

    } catch (error) {
      this.logger.error('Archive failed', error, {
        policy: policy.name,
        count: records.length
      });
      return 0;
    }
  }

  /**
   * Delete expired records
   */
  private async deleteExpiredRecords(
    policy: RetentionPolicy
  ): Promise<{
    recordsDeleted: number;
    recordsProcessed: number;
    spaceReclaimed: number;
  }> {
    const cutoff = Date.now() - (policy.retentionDays * 86400000);

    let recordsDeleted = 0;
    let recordsProcessed = 0;
    let spaceReclaimed = 0;

    while (true) {
      const whereClause = this.buildWhereClause(policy.filters);

      // Count records to delete
      const countQuery = `
        SELECT COUNT(*) as count
        FROM ${policy.tableName}
        WHERE timestamp < ?
        ${whereClause ? `AND ${whereClause}` : ''}
        ${policy.deleteStrategy === 'soft' ? 'AND archived = 1' : ''}
      `;

      const countResult = await this.db.prepare(countQuery)
        .bind(cutoff)
        .first();

      const totalToDelete = (countResult?.count as number) || 0;
      if (totalToDelete === 0) break;

      recordsProcessed += totalToDelete;

      // Estimate space (rough calculation)
      spaceReclaimed = totalToDelete * 1024; // 1KB per record estimate

      // Delete in batches
      let deleted = 0;
      while (deleted < totalToDelete) {
        const deleteQuery = policy.deleteStrategy === 'hard'
          ? `
            DELETE FROM ${policy.tableName}
            WHERE timestamp < ?
            ${whereClause ? `AND ${whereClause}` : ''}
            LIMIT ?
          `
          : `
            UPDATE ${policy.tableName}
            SET deleted = 1, deleted_at = ?
            WHERE timestamp < ?
            ${whereClause ? `AND ${whereClause}` : ''}
            AND deleted = 0
            LIMIT ?
          `;

        const bindings = policy.deleteStrategy === 'hard'
          ? [cutoff, policy.batchSize]
          : [Date.now(), cutoff, policy.batchSize];

        const result = await this.db.prepare(deleteQuery)
          .bind(...bindings)
          .run();

        const affected = result.meta.changes || 0;
        deleted += affected;
        recordsDeleted += affected;

        if (affected === 0) break;

        // Add delay between batches
        await new Promise(resolve => setTimeout(resolve, 100));
      }

      break; // Single pass for now
    }

    return { recordsDeleted, recordsProcessed, spaceReclaimed };
  }

  /**
   * Mark records as archived
   */
  private async markAsArchived(
    tableName: string,
    records: any[]
  ): Promise<void> {
    if (records.length === 0) return;

    const ids = records.map(r => r.id).filter(Boolean);
    if (ids.length === 0) return;

    await this.db.prepare(`
      UPDATE ${tableName}
      SET archived = 1, archived_at = ?
      WHERE id IN (${ids.map(() => '?').join(',')})
    `).bind(Date.now(), ...ids).run();
  }

  /**
   * Build WHERE clause from filters
   */
  private buildWhereClause(filters?: PolicyFilter[]): string {
    if (!filters || filters.length === 0) return '';

    const conditions = filters.map(filter => {
      switch (filter.operator) {
        case 'IN':
        case 'NOT IN':
          const values = Array.isArray(filter.value) ? filter.value : [filter.value];
          const placeholders = values.map(() => '?').join(',');
          return `${filter.column} ${filter.operator} (${placeholders})`;
        default:
          return `${filter.column} ${filter.operator} ?`;
      }
    });

    return conditions.join(' AND ');
  }

  /**
   * Convert records to CSV
   */
  private convertToCSV(records: any[]): string {
    if (records.length === 0) return '';

    const headers = Object.keys(records[0]);
    const csvHeaders = headers.join(',');

    const csvRows = records.map(record => {
      return headers.map(header => {
        const value = record[header];
        if (value === null || value === undefined) return '';
        if (typeof value === 'string' && value.includes(',')) {
          return `"${value.replace(/"/g, '""')}"`;
        }
        return value;
      }).join(',');
    });

    return `${csvHeaders}\n${csvRows.join('\n')}`;
  }

  /**
   * Compress data
   */
  private async compress(
    data: string | Uint8Array,
    compression: 'gzip' | 'brotli'
  ): Promise<Uint8Array> {
    const encoder = new TextEncoder();
    const input = typeof data === 'string' ? encoder.encode(data) : data;

    // Use CompressionStream if available
    if (typeof CompressionStream !== 'undefined') {
      const format = compression === 'brotli' ? 'deflate' : 'gzip';
      const cs = new CompressionStream(format);
      const writer = cs.writable.getWriter();
      writer.write(input);
      writer.close();

      const chunks: Uint8Array[] = [];
      const reader = cs.readable.getReader();
      let result;
      while (!(result = await reader.read()).done) {
        chunks.push(result.value);
      }

      // Combine chunks
      const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
      const compressed = new Uint8Array(totalLength);
      let offset = 0;
      for (const chunk of chunks) {
        compressed.set(chunk, offset);
        offset += chunk.length;
      }

      return compressed;
    }

    // Fallback - no compression
    return input;
  }

  /**
   * Encrypt data
   */
  private async encrypt(data: string | Uint8Array): Promise<Uint8Array> {
    // Simple encryption using Web Crypto API
    const encoder = new TextEncoder();
    const input = typeof data === 'string' ? encoder.encode(data) : data;

    // Generate key (in production, use proper key management)
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      input
    );

    // Combine IV and encrypted data
    const result = new Uint8Array(iv.length + encrypted.byteLength);
    result.set(iv);
    result.set(new Uint8Array(encrypted), iv.length);

    return result;
  }

  /**
   * Calculate next run time
   */
  private calculateNextRun(schedule?: string): number {
    if (!schedule) {
      // Default to daily at 2 AM
      const tomorrow = new Date();
      tomorrow.setDate(tomorrow.getDate() + 1);
      tomorrow.setHours(2, 0, 0, 0);
      return tomorrow.getTime();
    }

    // Parse cron expression (simplified)
    // Format: "0 2 * * *" (minute hour day month weekday)
    const parts = schedule.split(' ');
    if (parts.length !== 5) {
      return Date.now() + 86400000; // Default to 24 hours
    }

    const [minute, hour] = parts.map(p => parseInt(p) || 0);
    const next = new Date();
    next.setHours(hour, minute, 0, 0);

    if (next.getTime() <= Date.now()) {
      next.setDate(next.getDate() + 1);
    }

    return next.getTime();
  }

  /**
   * Validate retention policy
   */
  private validatePolicy(policy: RetentionPolicy): void {
    if (policy.retentionDays < 1) {
      throw new Error('Retention days must be at least 1');
    }

    if (policy.archiveAfterDays && policy.archiveAfterDays >= policy.retentionDays) {
      throw new Error('Archive days must be less than retention days');
    }

    if (policy.batchSize < 1 || policy.batchSize > 10000) {
      throw new Error('Batch size must be between 1 and 10000');
    }

    // Validate table exists
    // In production, query database schema
  }

  /**
   * Load policies from database
   */
  private async loadPolicies(): Promise<void> {
    try {
      const result = await this.db.prepare(`
        SELECT * FROM retention_policies
        WHERE enabled = 1
      `).all();

      for (const row of result.results || []) {
        const policy: RetentionPolicy = {
          id: row.id as string,
          name: row.name as string,
          tableName: row.table_name as string,
          retentionDays: row.retention_days as number,
          archiveEnabled: (row.archive_enabled as number) === 1,
          archiveAfterDays: row.archive_after_days as number | undefined,
          deleteStrategy: row.delete_strategy as 'hard' | 'soft',
          batchSize: row.batch_size as number,
          enabled: (row.enabled as number) === 1,
          lastRun: row.last_run as number | undefined,
          nextRun: row.next_run as number | undefined,
          filters: row.filters ? JSON.parse(row.filters as string) : [],
          schedule: row.schedule as string | undefined
        };

        this.policies.set(policy.id, policy);
      }

      this.logger.info('Retention policies loaded', {
        count: this.policies.size
      });

    } catch (error) {
      this.logger.error('Failed to load retention policies', error);
    }
  }

  /**
   * Update policy status
   */
  private async updatePolicyStatus(
    policyId: string,
    policy: RetentionPolicy
  ): Promise<void> {
    await this.db.prepare(`
      UPDATE retention_policies
      SET last_run = ?, next_run = ?
      WHERE id = ?
    `).bind(policy.lastRun, policy.nextRun, policyId).run();
  }

  /**
   * Save retention statistics
   */
  private async saveStats(policyId: string, stats: RetentionStats): Promise<void> {
    await this.db.prepare(`
      INSERT INTO retention_stats (
        policy_id, total_processed, records_deleted,
        records_archived, space_reclaimed, errors,
        run_time
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      policyId,
      stats.totalRecordsProcessed,
      stats.recordsDeleted,
      stats.recordsArchived,
      stats.spaceReclaimed,
      stats.errors,
      stats.lastRunTime
    ).run();

    this.stats.set(policyId, stats);
  }

  /**
   * Start retention scheduler
   */
  private startScheduler(): void {
    // Check every hour for policies to run
    this.cleanupInterval = setInterval(async () => {
      await this.runScheduledPolicies();
    }, 3600000) as any; // 1 hour

    // Run initial check
    this.runScheduledPolicies().catch(error => {
      this.logger.error('Initial policy run failed', error);
    });
  }

  /**
   * Run scheduled policies
   */
  private async runScheduledPolicies(): Promise<void> {
    const now = Date.now();

    for (const [policyId, policy] of this.policies) {
      if (!policy.enabled) continue;
      if (this.runningPolicies.has(policyId)) continue;

      if (policy.nextRun && policy.nextRun <= now) {
        try {
          await this.executePolicy(policyId);
        } catch (error) {
          this.logger.error('Scheduled policy execution failed', error, {
            policyId,
            name: policy.name
          });
        }
      }
    }
  }

  /**
   * Get retention statistics
   */
  getStats(policyId?: string): Map<string, RetentionStats> | RetentionStats | null {
    if (policyId) {
      return this.stats.get(policyId) || null;
    }
    return new Map(this.stats);
  }

  /**
   * Get data lifecycle recommendations
   */
  async getLifecycleRecommendations(
    tableName: string
  ): Promise<DataLifecycle> {
    // Analyze data access patterns
    const result = await this.db.prepare(`
      SELECT
        AVG(CASE WHEN timestamp > ? THEN 1 ELSE 0 END) as hot_ratio,
        AVG(CASE WHEN timestamp BETWEEN ? AND ? THEN 1 ELSE 0 END) as warm_ratio,
        COUNT(*) as total_records
      FROM ${tableName}
    `).bind(
      Date.now() - 7 * 86400000,  // 7 days
      Date.now() - 30 * 86400000, // 30 days
      Date.now() - 7 * 86400000   // 7 days
    ).first();

    const hotRatio = (result?.hot_ratio as number) || 0;
    const warmRatio = (result?.warm_ratio as number) || 0;

    // Recommend lifecycle based on access patterns
    return {
      hot: hotRatio > 0.5 ? 7 : 3,      // High access: 7 days, Low: 3 days
      warm: warmRatio > 0.3 ? 30 : 14,  // Moderate access: 30 days, Low: 14 days
      cold: 90,                          // Archive after 90 days
      delete: 365                        // Delete after 1 year
    };
  }

  /**
   * Shutdown retention manager
   */
  async shutdown(): Promise<void> {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }

    // Wait for running policies to complete
    const timeout = Date.now() + 30000; // 30 second timeout
    while (this.runningPolicies.size > 0 && Date.now() < timeout) {
      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    this.logger.info('Retention manager shutdown', {
      runningPolicies: this.runningPolicies.size
    });
  }
}

/**
 * Database schema for retention
 */
export const RETENTION_SCHEMA = `
CREATE TABLE IF NOT EXISTS retention_policies (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  table_name TEXT NOT NULL,
  retention_days INTEGER NOT NULL,
  archive_enabled INTEGER DEFAULT 0,
  archive_after_days INTEGER,
  delete_strategy TEXT DEFAULT 'hard',
  batch_size INTEGER DEFAULT 1000,
  enabled INTEGER DEFAULT 1,
  filters TEXT,
  schedule TEXT,
  last_run INTEGER,
  next_run INTEGER,
  created_at INTEGER DEFAULT (strftime('%s', 'now') * 1000),

  INDEX idx_retention_enabled_next (enabled, next_run)
);

CREATE TABLE IF NOT EXISTS retention_stats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  policy_id TEXT NOT NULL,
  total_processed INTEGER,
  records_deleted INTEGER,
  records_archived INTEGER,
  space_reclaimed INTEGER,
  errors INTEGER,
  run_time INTEGER,

  INDEX idx_retention_stats_policy (policy_id, run_time DESC)
);
`;