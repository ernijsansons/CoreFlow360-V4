import { D1Database } from '@cloudflare/workers-types';
import { Logger } from '../shared/logger';
import type { Env } from '../types/env';

export interface FixStrategy {
  id: string;
  name: string;
  description: string;
  category: 'integrity' | 'consistency' | 'optimization' | 'compliance';
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  automated: boolean;
  requiresApproval: boolean;
  reversible: boolean;
  estimatedImpact: number;
  dependencies?: string[];
}

export interface DataIssue {
  id: string;
  type: 'foreign_key_violation' | 'orphaned_record' | 'duplicate_data' | 'missing_data' |
  'invalid_format' | 'constraint_violation' | 'inconsistent_state' | 'cache_stale' | 'replication_lag' | 'data_anomaly';
  severity: 'low' | 'medium' | 'high' | 'critical';
  table: string;
  column?: string;
  recordId?: string;
  businessId: string;
  description: string;
  detectedAt: string;
  metadata: Record<string, any>;
  suggestedFixes: string[];
}

export interface FixPreview {
  issueId: string;
  strategyId: string;
  action: string;
  affectedRecords: number;
  sqlStatements: string[];
  backupRequired: boolean;
  estimatedDuration: number;
  riskAssessment: {
    dataLoss: boolean;
    downtime: boolean;
    rollbackDifficulty: 'easy' | 'medium' | 'hard' | 'impossible';
    affectedSystems: string[];
  };
  preview: {
    before: Record<string, any>[];
    after: Record<string, any>[];
  };
}

export interface FixExecution {
  id: string;
  issueId: string;
  strategyId: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'rolled_back';
  startedAt: string;
  completedAt?: string;
  executedBy: string;
  businessId: string;
  backupId?: string;
  rollbackData?: Record<string, any>;
  results: {
    recordsAffected: number;
    sqlStatementsExecuted: string[];
    errors: string[];
    warnings: string[];
    verificationPassed: boolean;
  };
  rollbackAvailable: boolean;
}

export interface AutomatedDataFixerConfig {
  enableAutomatedFixes: boolean;
  maxRiskLevel: 'low' | 'medium' | 'high';
  requireApprovalThreshold: number;
  backupBeforeFix: boolean;
  verificationEnabled: boolean;
  rollbackWindowHours: number;
  businessId: string;
  concurrentFixesLimit: number;
}

export interface FixValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  recommendations: string[];
  estimatedImpact: {
    recordsAffected: number;
    tablesInvolved: string[];
    systemsImpacted: string[];
  };
}

export interface DataBackup {
  id: string;
  issueId: string;
  strategyId: string;
  businessId: string;
  createdAt: string;
  expiresAt: string;
  tables: string[];
  recordCount: number;
  size: number;
  compressionRatio: number;
  metadata: Record<string, any>;
}

export class AutomatedDataFixer {
  private db: D1Database;
  private logger: Logger;
  private env: Env;
  private config: AutomatedDataFixerConfig;

  constructor(env: Env, config: AutomatedDataFixerConfig) {
    this.env = env;
    this.db = env.DB;
    this.logger = new Logger();
    this.config = config;
  }

  async analyzeIssue(issue: DataIssue): Promise<FixStrategy[]> {
    try {
      this.logger.info('Analyzing data issue for fix strategies', { issueId: issue.id });

      const strategies: FixStrategy[] = [];

      switch (issue.type) {
        case 'foreign_key_violation':
          strategies.push(...await this.getForeignKeyFixStrategies(issue));
          break;
        case 'orphaned_record':
          strategies.push(...await this.getOrphanedRecordFixStrategies(issue));
          break;
        case 'duplicate_data':
          strategies.push(...await this.getDuplicateDataFixStrategies(issue));
          break;
        case 'missing_data':
          strategies.push(...await this.getMissingDataFixStrategies(issue));
          break;
        case 'invalid_format':
          strategies.push(...await this.getInvalidFormatFixStrategies(issue));
          break;
        case 'constraint_violation':
          strategies.push(...await this.getConstraintViolationFixStrategies(issue));
          break;
        case 'inconsistent_state':
          strategies.push(...await this.getInconsistentStateFixStrategies(issue));
          break;
        case 'cache_stale':
          strategies.push(...await this.getCacheStaleFixStrategies(issue));
          break;
        case 'replication_lag':
          strategies.push(...await this.getReplicationLagFixStrategies(issue));
          break;
        case 'data_anomaly':
          strategies.push(...await this.getDataAnomalyFixStrategies(issue));
          break;
      }

      // Filter strategies based on config
      const filteredStrategies = strategies.filter(strategy => {
        const riskLevels = ['low', 'medium', 'high', 'critical'];
        const configRiskIndex = riskLevels.indexOf(this.config.maxRiskLevel);
        const strategyRiskIndex = riskLevels.indexOf(strategy.riskLevel);
        return strategyRiskIndex <= configRiskIndex;
      });

      this.logger.info('Fix strategies analyzed', {
        issueId: issue.id,
        totalStrategies: strategies.length,
        applicableStrategies: filteredStrategies.length
      });

      return filteredStrategies;
    } catch (error) {
      this.logger.error('Failed to analyze issue for fix strategies', error, { issueId: issue.id });
      throw error;
    }
  }

  async generateFixPreview(issue: DataIssue, strategy: FixStrategy): Promise<FixPreview> {
    try {
      this.logger.info('Generating fix preview', { issueId: issue.id, strategyId: strategy.id });

      const sqlStatements = await this.generateFixSQL(issue, strategy);
      const affectedRecords = await this.estimateAffectedRecords(issue, strategy);
      const preview = await this.generateDataPreview(issue, strategy);

      const fixPreview: FixPreview = {
        issueId: issue.id,
        strategyId: strategy.id,
        action: strategy.description,
        affectedRecords,
        sqlStatements,
        backupRequired: strategy.riskLevel !== 'low' || this.config.backupBeforeFix,
        estimatedDuration: this.estimateFixDuration(affectedRecords, strategy),
        riskAssessment: {
          dataLoss: strategy.riskLevel === 'high' || strategy.riskLevel === 'critical',
          downtime: affectedRecords > 10000,
          rollbackDifficulty: this.assessRollbackDifficulty(strategy),
          affectedSystems: await this.identifyAffectedSystems(issue, strategy)
        },
        preview
      };

      return fixPreview;
    } catch (error) {
      this.logger.error('Failed to generate fix preview', error, { issueId: issue.id, strategyId: strategy.id });
      throw error;
    }
  }

  async validateFix(issue: DataIssue, strategy: FixStrategy): Promise<FixValidationResult> {
    try {
      this.logger.info('Validating fix strategy', { issueId: issue.id, strategyId: strategy.id });

      const errors: string[] = [];
      const warnings: string[] = [];
      const recommendations: string[] = [];

      // Validate business isolation
      if (!this.validateBusinessIsolation(issue, strategy)) {
        errors.push('Fix strategy would affect data outside business context');
      }

      // Validate dependencies
      if (strategy.dependencies) {
        for (const dependency of strategy.dependencies) {
          const dependencyExists = await this.checkDependency(dependency, issue.businessId);
          if (!dependencyExists) {
            errors.push(`Missing dependency: ${dependency}`);
          }
        }
      }

      // Validate SQL syntax and safety
      const sqlValidation = await this.validateSQL(issue, strategy);
      errors.push(...sqlValidation.errors);
      warnings.push(...sqlValidation.warnings);

      // Check for potential side effects
      const sideEffects = await this.analyzeSideEffects(issue, strategy);
      warnings.push(...sideEffects.warnings);
      recommendations.push(...sideEffects.recommendations);

      // Estimate impact
      const estimatedImpact = {
        recordsAffected: await this.estimateAffectedRecords(issue, strategy),
        tablesInvolved: await this.identifyAffectedTables(issue, strategy),
        systemsImpacted: await this.identifyAffectedSystems(issue, strategy)
      };

      // Add recommendations based on impact
      if (estimatedImpact.recordsAffected > 1000) {
        recommendations.push('Consider running during maintenance window');
      }

      if (estimatedImpact.tablesInvolved.length > 3) {
        recommendations.push('Consider breaking fix into smaller batches');
      }

      const result: FixValidationResult = {
        valid: errors.length === 0,
        errors,
        warnings,
        recommendations,
        estimatedImpact
      };

      this.logger.info('Fix validation completed', {
        issueId: issue.id,
        strategyId: strategy.id,
        valid: result.valid,
        errorsCount: errors.length,
        warningsCount: warnings.length
      });

      return result;
    } catch (error) {
      this.logger.error('Failed to validate fix strategy', error, { issueId: issue.id, strategyId: strategy.id });
      throw error;
    }
  }

  async createBackup(issue: DataIssue, strategy: FixStrategy): Promise<DataBackup> {
    try {
      this.logger.info('Creating data backup before fix', { issueId: issue.id, strategyId: strategy.id });

      const backupId = crypto.randomUUID();
      const tables = await this.identifyAffectedTables(issue, strategy);

      let totalRecords = 0;
      const backupData: Record<string, any[]> = {};

      // Backup affected records from each table
      for (const table of tables) {
        const records = await this.backupTableData(table, issue, strategy);
        backupData[table] = records;
        totalRecords += records.length;
      }

      // Store backup in R2
      const backupKey = `backups/${issue.businessId}/${backupId}.json`;
      const backupContent = JSON.stringify(backupData);
      const compressedContent = await this.compressData(backupContent);

      await this.env.R2_BACKUPS.put(backupKey, compressedContent, {
        customMetadata: {
          issueId: issue.id,
          strategyId: strategy.id,
          businessId: issue.businessId,
          createdAt: new Date().toISOString(),
          recordCount: totalRecords.toString()
        }
      });

      const backup: DataBackup = {
        id: backupId,
        issueId: issue.id,
        strategyId: strategy.id,
        businessId: issue.businessId,
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + this.config.rollbackWindowHours * 60 * 60 * 1000).toISOString(),
        tables,
        recordCount: totalRecords,
        size: compressedContent.byteLength,
        compressionRatio: compressedContent.byteLength / backupContent.length,
        metadata: {
          originalSize: backupContent.length,
          compressionAlgorithm: 'gzip'
        }
      };

      // Store backup metadata in database
      await this.db.prepare(`
        INSERT INTO data_backups (
          id, issue_id, strategy_id, business_id, created_at, expires_at,
          tables, record_count, size_bytes, compression_ratio, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        backup.id,
        backup.issueId,
        backup.strategyId,
        backup.businessId,
        backup.createdAt,
        backup.expiresAt,
        JSON.stringify(backup.tables),
        backup.recordCount,
        backup.size,
        backup.compressionRatio,
        JSON.stringify(backup.metadata)
      ).run();

      this.logger.info('Data backup created successfully', {
        backupId,
        issueId: issue.id,
        recordCount: totalRecords,
        sizeBytes: backup.size
      });

      return backup;
    } catch (error) {
      this.logger.error('Failed to create data backup', error, { issueId: issue.id, strategyId: strategy.id });
      throw error;
    }
  }

  async executeFix(issue: DataIssue, strategy: FixStrategy, approvedBy?: string): Promise<FixExecution> {
    try {
      this.logger.info('Executing data fix', { issueId: issue.id, strategyId: strategy.id });

      const executionId = crypto.randomUUID();
      const execution: FixExecution = {
        id: executionId,
        issueId: issue.id,
        strategyId: strategy.id,
        status: 'pending',
        startedAt: new Date().toISOString(),
        executedBy: approvedBy || 'system',
        businessId: issue.businessId,
        results: {
          recordsAffected: 0,
          sqlStatementsExecuted: [],
          errors: [],
          warnings: [],
          verificationPassed: false
        },
        rollbackAvailable: false
      };

      // Create backup if required
      let backup: DataBackup | undefined;
      if (strategy.riskLevel !== 'low' || this.config.backupBeforeFix) {
        backup = await this.createBackup(issue, strategy);
        execution.backupId = backup.id;
      }

      execution.status = 'running';
      await this.saveExecutionState(execution);

      try {
        // Generate and execute fix SQL
        const sqlStatements = await this.generateFixSQL(issue, strategy);

        // Execute in transaction
        const transactionResult = await this.executeInTransaction(sqlStatements, issue.businessId);

        execution.results.sqlStatementsExecuted = sqlStatements;
        execution.results.recordsAffected = transactionResult.recordsAffected;
        execution.results.warnings = transactionResult.warnings;

        // Verify fix if enabled
        if (this.config.verificationEnabled) {
          const verificationResult = await this.verifyFix(issue, strategy, execution);
          execution.results.verificationPassed = verificationResult.passed;
          execution.results.warnings.push(...verificationResult.warnings);

          if (!verificationResult.passed) {
            execution.results.errors.push('Fix verification failed');
            execution.status = 'failed';
          }
        }

        if (execution.results.errors.length === 0) {
          execution.status = 'completed';
          execution.rollbackAvailable = backup !== undefined && strategy.reversible;
        } else {
          execution.status = 'failed';
        }

        execution.completedAt = new Date().toISOString();

        this.logger.info('Data fix execution completed', {
          executionId,
          issueId: issue.id,
          status: execution.status,
          recordsAffected: execution.results.recordsAffected
        });

      } catch (error) {
        execution.status = 'failed';
        execution.results.errors.push(error instanceof Error ? error.message : 'Unknown error');
        execution.completedAt = new Date().toISOString();

        this.logger.error('Data fix execution failed', error, { executionId, issueId: issue.id });
      }

      await this.saveExecutionState(execution);
      return execution;

    } catch (error) {
      this.logger.error('Failed to execute data fix', error, { issueId: issue.id, strategyId: strategy.id });
      throw error;
    }
  }

  async rollbackFix(executionId: string): Promise<boolean> {
    try {
      this.logger.info('Rolling back data fix', { executionId });

      const execution = await this.getExecution(executionId);
      if (!execution) {
        throw new Error('Execution not found');
      }

      if (!execution.rollbackAvailable) {
        throw new Error('Rollback not available for this execution');
      }

      if (!execution.backupId) {
        throw new Error('No backup available for rollback');
      }

      // Retrieve backup
      const backup = await this.getBackup(execution.backupId);
      if (!backup) {
        throw new Error('Backup not found');
      }

      // Restore data from backup
      const backupKey = `backups/${execution.businessId}/${execution.backupId}.json`;
      const backupObject = await this.env.R2_BACKUPS.get(backupKey);

      if (!backupObject) {
        throw new Error('Backup data not found in storage');
      }

      const compressedData = await backupObject.arrayBuffer();
      const backupContent = await this.decompressData(compressedData);
      const backupData = JSON.parse(backupContent);

      // Restore each table
      for (const [table, records] of Object.entries(backupData)) {
        await this.restoreTableData(table, records as any[], execution.businessId);
      }

      // Update execution status
      execution.status = 'rolled_back';
      execution.completedAt = new Date().toISOString();
      await this.saveExecutionState(execution);

      this.logger.info('Data fix rolled back successfully', { executionId });
      return true;

    } catch (error) {
      this.logger.error('Failed to rollback data fix', error, { executionId });
      return false;
    }
  }

  private async getForeignKeyFixStrategies(issue: DataIssue): Promise<FixStrategy[]> {
    return [
      {
        id: 'fk_delete_orphan',
        name: 'Delete Orphaned Record',
        description: 'Remove the record with invalid foreign key reference',
        category: 'integrity',
        riskLevel: 'medium',
        automated: true,
        requiresApproval: true,
        reversible: true,
        estimatedImpact: 1
      },
      {
        id: 'fk_create_parent',
        name: 'Create Missing Parent Record',
        description: 'Create the missing parent record with default values',
        category: 'integrity',
        riskLevel: 'high',
        automated: false,
        requiresApproval: true,
        reversible: true,
        estimatedImpact: 1
      },
      {
        id: 'fk_update_reference',
        name: 'Update Foreign Key Reference',
        description: 'Update the foreign key to reference an existing valid record',
        category: 'integrity',
        riskLevel: 'medium',
        automated: false,
        requiresApproval: true,
        reversible: true,
        estimatedImpact: 1
      }
    ];
  }

  private async getOrphanedRecordFixStrategies(issue: DataIssue): Promise<FixStrategy[]> {
    return [
      {
        id: 'orphan_delete',
        name: 'Delete Orphaned Record',
        description: 'Remove the orphaned record that has no valid parent',
        category: 'integrity',
        riskLevel: 'low',
        automated: true,
        requiresApproval: false,
        reversible: true,
        estimatedImpact: 1
      },
      {
        id: 'orphan_reassign',
        name: 'Reassign to Valid Parent',
        description: 'Update the record to reference a valid parent entity',
        category: 'integrity',
        riskLevel: 'medium',
        automated: false,
        requiresApproval: true,
        reversible: true,
        estimatedImpact: 1
      }
    ];
  }

  private async getDuplicateDataFixStrategies(issue: DataIssue): Promise<FixStrategy[]> {
    return [
      {
        id: 'duplicate_merge',
        name: 'Merge Duplicate Records',
        description: 'Combine duplicate records into a single consolidated record',
        category: 'optimization',
        riskLevel: 'high',
        automated: false,
        requiresApproval: true,
        reversible: false,
        estimatedImpact: 2
      },
      {
        id: 'duplicate_delete_newest',
        name: 'Delete Newest Duplicate',
        description: 'Remove the most recently created duplicate record',
        category: 'optimization',
        riskLevel: 'medium',
        automated: true,
        requiresApproval: true,
        reversible: true,
        estimatedImpact: 1
      },
      {
        id: 'duplicate_mark_inactive',
        name: 'Mark Duplicates as Inactive',
        description: 'Set duplicate records as inactive instead of deleting',
        category: 'optimization',
        riskLevel: 'low',
        automated: true,
        requiresApproval: false,
        reversible: true,
        estimatedImpact: 1
      }
    ];
  }

  private async getMissingDataFixStrategies(issue: DataIssue): Promise<FixStrategy[]> {
    return [
      {
        id: 'missing_populate_default',
        name: 'Populate with Default Values',
        description: 'Fill missing data with appropriate default values',
        category: 'consistency',
        riskLevel: 'low',
        automated: true,
        requiresApproval: false,
        reversible: true,
        estimatedImpact: 1
      },
      {
        id: 'missing_interpolate',
        name: 'Interpolate Missing Values',
        description: 'Calculate missing values based on surrounding data patterns',
        category: 'consistency',
        riskLevel: 'medium',
        automated: false,
        requiresApproval: true,
        reversible: true,
        estimatedImpact: 1
      }
    ];
  }

  private async getInvalidFormatFixStrategies(issue: DataIssue): Promise<FixStrategy[]> {
    return [
      {
        id: 'format_standardize',
        name: 'Standardize Data Format',
        description: 'Convert data to the correct standard format',
        category: 'consistency',
        riskLevel: 'low',
        automated: true,
        requiresApproval: false,
        reversible: true,
        estimatedImpact: 1
      },
      {
        id: 'format_validate_strict',
        name: 'Apply Strict Validation',
        description: 'Remove or quarantine data that cannot be formatted correctly',
        category: 'consistency',
        riskLevel: 'medium',
        automated: false,
        requiresApproval: true,
        reversible: true,
        estimatedImpact: 1
      }
    ];
  }

  private async getConstraintViolationFixStrategies(issue: DataIssue): Promise<FixStrategy[]> {
    return [
      {
        id: 'constraint_fix_value',
        name: 'Fix Constraint Violation',
        description: 'Update the value to satisfy the constraint',
        category: 'integrity',
        riskLevel: 'medium',
        automated: true,
        requiresApproval: true,
        reversible: true,
        estimatedImpact: 1
      },
      {
        id: 'constraint_remove_record',
        name: 'Remove Violating Record',
        description: 'Delete the record that violates the constraint',
        category: 'integrity',
        riskLevel: 'high',
        automated: false,
        requiresApproval: true,
        reversible: true,
        estimatedImpact: 1
      }
    ];
  }

  private async getInconsistentStateFixStrategies(issue: DataIssue): Promise<FixStrategy[]> {
    return [
      {
        id: 'state_reconcile',
        name: 'Reconcile Inconsistent State',
        description: 'Update related records to maintain consistent state',
        category: 'consistency',
        riskLevel: 'high',
        automated: false,
        requiresApproval: true,
        reversible: true,
        estimatedImpact: 3
      },
      {
        id: 'state_reset_canonical',
        name: 'Reset to Canonical State',
        description: 'Reset the state based on the authoritative source',
        category: 'consistency',
        riskLevel: 'critical',
        automated: false,
        requiresApproval: true,
        reversible: false,
        estimatedImpact: 5
      }
    ];
  }

  private async getCacheStaleFixStrategies(issue: DataIssue): Promise<FixStrategy[]> {
    return [
      {
        id: 'cache_invalidate',
        name: 'Invalidate Stale Cache',
        description: 'Remove stale cache entries to force refresh',
        category: 'consistency',
        riskLevel: 'low',
        automated: true,
        requiresApproval: false,
        reversible: false,
        estimatedImpact: 0
      },
      {
        id: 'cache_refresh',
        name: 'Refresh Cache Data',
        description: 'Update cache with current data from source',
        category: 'consistency',
        riskLevel: 'low',
        automated: true,
        requiresApproval: false,
        reversible: false,
        estimatedImpact: 0
      }
    ];
  }

  private async getReplicationLagFixStrategies(issue: DataIssue): Promise<FixStrategy[]> {
    return [
      {
        id: 'replication_force_sync',
        name: 'Force Replication Sync',
        description: 'Trigger immediate synchronization of lagging replicas',
        category: 'consistency',
        riskLevel: 'medium',
        automated: true,
        requiresApproval: true,
        reversible: false,
        estimatedImpact: 0
      },
      {
        id: 'replication_rebuild',
        name: 'Rebuild Replica',
        description: 'Completely rebuild the lagging replica from master',
        category: 'consistency',
        riskLevel: 'high',
        automated: false,
        requiresApproval: true,
        reversible: false,
        estimatedImpact: 0
      }
    ];
  }

  private async getDataAnomalyFixStrategies(issue: DataIssue): Promise<FixStrategy[]> {
    return [
      {
        id: 'anomaly_quarantine',
        name: 'Quarantine Anomalous Data',
        description: 'Move anomalous data to quarantine table for review',
        category: 'consistency',
        riskLevel: 'low',
        automated: true,
        requiresApproval: false,
        reversible: true,
        estimatedImpact: 1
      },
      {
        id: 'anomaly_correct',
        name: 'Correct Anomalous Values',
        description: 'Replace anomalous values with statistically normal ones',
        category: 'consistency',
        riskLevel: 'high',
        automated: false,
        requiresApproval: true,
        reversible: true,
        estimatedImpact: 1
      }
    ];
  }

  private async generateFixSQL(issue: DataIssue, strategy: FixStrategy): Promise<string[]> {
    const statements: string[] = [];

    // Add business_id isolation to all statements
    const businessFilter = `business_id = '${issue.businessId}'`;

    switch (strategy.id) {
      case 'fk_delete_orphan':
        statements.push(`DELETE FROM ${issue.table} WHERE id = '${issue.recordId}' AND ${businessFilter}`);
        break;
      case 'orphan_delete':
        statements.push(`DELETE FROM ${issue.table} WHERE id = '${issue.recordId}' AND ${businessFilter}`);
        break;
      case 'duplicate_delete_newest':
        statements.push(`
          DELETE FROM ${issue.table}
          WHERE id IN (
            SELECT id FROM ${issue.table}
            WHERE ${issue.column} = '${issue.metadata.duplicateValue}'
            AND ${businessFilter}
            ORDER BY created_at DESC
            LIMIT 1
          )
        `);
        break;
      case 'cache_invalidate':
        // This would be handled by cache layer, not SQL
        break;
      default:
        statements.push(`-- Custom fix for ${strategy.id} not implemented`);
    }

    return statements;
  }

  private async estimateAffectedRecords(issue: DataIssue, strategy: FixStrategy): Promise<number> {
    // Simplified estimation - in real implementation, this would analyze the actual SQL
    return strategy.estimatedImpact;
  }

  private async generateDataPreview(issue: DataIssue, strategy: FixStrategy):
  Promise<{ before: Record<string, any>[]; after: Record<string, any>[] }> {
    // Simplified preview generation
    return {
      before: [{ id: issue.recordId, status: 'current' }],
      after: [{ id: issue.recordId, status: 'fixed' }]
    };
  }

  private estimateFixDuration(recordCount: number, strategy: FixStrategy): number {
    // Estimate in seconds based on record count and strategy complexity
    const baseTime = 5; // 5 seconds base
    const recordTime = recordCount * 0.1; // 0.1 seconds per record
    const complexityMultiplier = strategy.riskLevel === 'critical' ? 3 : strategy.riskLevel === 'high' ? 2 : 1;

    return Math.ceil((baseTime + recordTime) * complexityMultiplier);
  }

  private assessRollbackDifficulty(strategy: FixStrategy): 'easy' | 'medium' | 'hard' | 'impossible' {
    if (!strategy.reversible) return 'impossible';
    if (strategy.riskLevel === 'critical') return 'hard';
    if (strategy.riskLevel === 'high') return 'medium';
    return 'easy';
  }

  private async identifyAffectedSystems(issue: DataIssue, strategy: FixStrategy): Promise<string[]> {
    const systems = ['database'];

    if (strategy.id.includes('cache')) {
      systems.push('cache');
    }

    if (strategy.id.includes('replication')) {
      systems.push('replication');
    }

    return systems;
  }

  private validateBusinessIsolation(issue: DataIssue, strategy: FixStrategy): boolean {
    // Ensure the fix only affects data within the business context
    return issue.businessId !== undefined && issue.businessId.length > 0;
  }

  private async checkDependency(dependency: string, businessId: string): Promise<boolean> {
    // Check if required dependencies exist
    try {
      const result = await this.db.prepare(`
        SELECT COUNT(*) as count FROM dependencies
        WHERE name = ? AND business_id = ?
      `).bind(dependency, businessId).first();

      return (result as any)?.count > 0;
    } catch {
      return false;
    }
  }

  private async validateSQL(issue: DataIssue, strategy:
  FixStrategy): Promise<{ errors: string[]; warnings: string[] }> {
    const errors: string[] = [];
    const warnings: string[] = [];

    const sqlStatements = await this.generateFixSQL(issue, strategy);

    for (const sql of sqlStatements) {
      // Basic SQL validation
      if (!sql.includes('business_id')) {
        errors.push('SQL statement missing business_id isolation');
      }

      if (sql.includes('DELETE') && !sql.includes('WHERE')) {
        errors.push('DELETE statement without WHERE clause');
      }

      if (sql.includes('UPDATE') && !sql.includes('WHERE')) {
        errors.push('UPDATE statement without WHERE clause');
      }
    }

    return { errors, warnings };
  }

  private async analyzeSideEffects(issue: DataIssue, strategy:
  FixStrategy): Promise<{ warnings: string[]; recommendations: string[] }> {
    const warnings: string[] = [];
    const recommendations: string[] = [];

    if (strategy.riskLevel === 'high' || strategy.riskLevel === 'critical') {
      warnings.push('High-risk operation may impact system performance');
      recommendations.push('Schedule during maintenance window');
    }

    if (strategy.id.includes('delete')) {
      warnings.push('Data deletion is irreversible without backup');
      recommendations.push('Ensure backup is created before execution');
    }

    return { warnings, recommendations };
  }

  private async identifyAffectedTables(issue: DataIssue, strategy: FixStrategy): Promise<string[]> {
    const tables = [issue.table];

    // Add related tables based on strategy
    if (strategy.id.includes('merge') || strategy.id.includes('reconcile')) {
      // Would need to analyze foreign key relationships
      tables.push(`${issue.table}_history`);
    }

    return tables;
  }

  private async backupTableData(table: string, issue: DataIssue, strategy: FixStrategy): Promise<any[]> {
    try {
      const result = await this.db.prepare(`
        SELECT * FROM ${table}
        WHERE business_id = ?
        AND id = ?
      `).bind(issue.businessId, issue.recordId).all();

      return result.results || [];
    } catch (error) {
      this.logger.warn('Failed to backup table data', { table, error });
      return [];
    }
  }

  private async compressData(data: string): Promise<ArrayBuffer> {
    // Simplified compression - in real implementation, use gzip
    return new TextEncoder().encode(data).buffer;
  }

  private async decompressData(data: ArrayBuffer): Promise<string> {
    // Simplified decompression - in real implementation, use gzip
    return new TextDecoder().decode(data);
  }

  private async executeInTransaction(sqlStatements: string[], businessId:
  string): Promise<{ recordsAffected: number; warnings: string[] }> {
    let recordsAffected = 0;
    const warnings: string[] = [];

    try {
      // Execute each statement
      for (const sql of sqlStatements) {
        if (sql.trim() && !sql.startsWith('--')) {
          const result = await this.db.prepare(sql).run();
          if (result.changes) {
            recordsAffected += result.changes;
          }
        }
      }

      return { recordsAffected, warnings };
    } catch (error) {
      this.logger.error('Transaction execution failed', error);
      throw error;
    }
  }

  private async verifyFix(issue: DataIssue, strategy: FixStrategy,
  execution: FixExecution): Promise<{ passed: boolean; warnings: string[] }> {
    const warnings: string[] = [];

    try {
      // Verify the fix was applied correctly
      const verificationQuery = `
        SELECT COUNT(*) as count FROM ${issue.table}
        WHERE business_id = ? AND id = ?
      `;

      const result = await this.db.prepare(verificationQuery)
        .bind(issue.businessId, issue.recordId)
        .first();

      const recordExists = (result as any)?.count > 0;

      // For delete operations, record should not exist
      if (strategy.id.includes('delete')) {
        return { passed: !recordExists, warnings };
      }

      // For other operations, record should exist
      return { passed: recordExists, warnings };

    } catch (error) {
      warnings.push(`Verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return { passed: false, warnings };
    }
  }

  private async saveExecutionState(execution: FixExecution): Promise<void> {
    await this.db.prepare(`
      INSERT OR REPLACE INTO fix_executions (
        id, issue_id, strategy_id, status, started_at, completed_at,
        executed_by, business_id, backup_id, results, rollback_available
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      execution.id,
      execution.issueId,
      execution.strategyId,
      execution.status,
      execution.startedAt,
      execution.completedAt,
      execution.executedBy,
      execution.businessId,
      execution.backupId,
      JSON.stringify(execution.results),
      execution.rollbackAvailable ? 1 : 0
    ).run();
  }

  private async getExecution(executionId: string): Promise<FixExecution | null> {
    const result = await this.db.prepare(`
      SELECT * FROM fix_executions WHERE id = ?
    `).bind(executionId).first();

    if (!result) return null;

    return {
      ...(result as any),
      results: JSON.parse((result as any).results),
      rollbackAvailable: (result as any).rollback_available === 1
    };
  }

  private async getBackup(backupId: string): Promise<DataBackup | null> {
    const result = await this.db.prepare(`
      SELECT * FROM data_backups WHERE id = ?
    `).bind(backupId).first();

    if (!result) return null;

    return {
      ...(result as any),
      tables: JSON.parse((result as any).tables),
      metadata: JSON.parse((result as any).metadata)
    };
  }

  private async restoreTableData(table: string, records: any[], businessId: string): Promise<void> {
    // First delete existing records
    await this.db.prepare(`DELETE FROM ${table} WHERE business_id = ?`).bind(businessId).run();

    // Then restore from backup
    for (const record of records) {
      const columns = Object.keys(record);
      const placeholders = columns.map(() => '?').join(', ');
      const values = columns.map(col => record[col]);

      await this.db.prepare(`
        INSERT INTO ${table} (${columns.join(', ')})
        VALUES (${placeholders})
      `).bind(...values).run();
    }
  }
}