/**
 * D1 Migration Manager
 * Specialized migration manager for Cloudflare D1 database with versioning
 */

import { z } from 'zod';
import { Logger } from '../shared/logger';
import { CorrelationId } from '../shared/correlation-id';

export interface D1Migration {
  version: number;
  name: string;
  filename: string;
  upSql: string;
  downSql: string;
  author: string;
  description: string;
  tags: string[];
  checksum: string;
  appliedAt?: number;
  executionTime?: number;
  status: MigrationStatus;
}

export type MigrationStatus = 'pending' | 'applied' | 'failed' | 'rolled_back';

export interface MigrationHistory {
  version: number;
  name: string;
  appliedAt: number;
  executionTime: number;
  checksum: string;
  author: string;
  rollbackSql: string;
}

export interface MigrationPlan {
  migrationsToApply: D1Migration[];
  migrationsToRollback: D1Migration[];
  estimatedDuration: number;
  riskLevel: 'low' | 'medium' | 'high';
  dependencies: string[];
  warnings: string[];
}

export // TODO: Consider splitting D1MigrationManager into smaller, focused classes
class D1MigrationManager {
  private logger = new Logger();
  private migrationsPath: string;
  private appliedMigrations = new Map<number, MigrationHistory>();

  constructor(migrationsPath: string = './migrations') {
    this.migrationsPath = migrationsPath;
  }

  /**
   * Generate new migration file
   */
  async generateMigration(name: string, options: GenerateMigrationOptions = {}): Promise<string> {
    const correlationId = CorrelationId.generate();
    const timestamp = Date.now();
    const version = options.version || timestamp;
    const filename = `${version}_${this.sanitizeName(name)}.sql`;
    const author = options.author || await this.getCurrentUser();

    this.logger.info('Generating new migration', {
      correlationId,
      name,
      version,
      filename,
      author
    });

    const template = this.generateMigrationTemplate({
      name,
      version,
      author,
      description: options.description || '',
      tags: options.tags || []
    });

    const filePath = `${this.migrationsPath}/${filename}`;
    await this.saveMigration(filePath, template);

    this.logger.info('Migration file generated', {
      correlationId,
      filename,
      path: filePath
    });

    return filePath;
  }

  /**
   * Load all migration files
   */
  async loadMigrations(): Promise<D1Migration[]> {
    const migrationFiles = await this.getMigrationFiles();
    const migrations: D1Migration[] = [];

    for (const file of migrationFiles) {
      try {
        const migration = await this.parseMigrationFile(file);
        migrations.push(migration);
      } catch (error) {
        this.logger.error('Failed to parse migration file', error, { file });
      }
    }

    // Sort by version
    return migrations.sort((a, b) => a.version - b.version);
  }

  /**
   * Get migration status and plan
   */
  async planMigrations(targetVersion?: number): Promise<MigrationPlan> {
    const allMigrations = await this.loadMigrations();
    const appliedVersions = await this.getAppliedMigrations();

    const currentVersion = appliedVersions.length > 0
      ? Math.max(...appliedVersions.map(m => m.version))
      : 0;

    const target = targetVersion || (allMigrations.length > 0
      ? Math.max(...allMigrations.map(m => m.version))
      : currentVersion);

    let migrationsToApply: D1Migration[] = [];
    let migrationsToRollback: D1Migration[] = [];

    if (target > currentVersion) {
      // Forward migration
      migrationsToApply = allMigrations.filter(m =>
        m.version > currentVersion && m.version <= target
      );
    } else if (target < currentVersion) {
      // Rollback migration
      migrationsToRollback = appliedVersions
        .filter(m => m.version > target)
        .sort((a, b) => b.version - a.version) // Reverse order for rollback
        .map(history => ({
          version: history.version,
          name: history.name,
          filename: `${history.version}_${history.name}.sql`,
          upSql: '',
          downSql: history.rollbackSql,
          author: history.author,
          description: `Rollback of ${history.name}`,
          tags: ['rollback'],
          checksum: history.checksum,
          status: 'pending' as MigrationStatus
        }));
    }

    const estimatedDuration = this.estimateMigrationDuration(migrationsToApply, migrationsToRollback);
    const riskLevel = this.assessMigrationRisk(migrationsToApply, migrationsToRollback);
    const dependencies = this.extractDependencies(migrationsToApply);
    const warnings = this.generateWarnings(migrationsToApply, migrationsToRollback);

    return {
      migrationsToApply,
      migrationsToRollback,
      estimatedDuration,
      riskLevel,
      dependencies,
      warnings
    };
  }

  /**
   * Execute migration plan
   */
  async executeMigrations(plan: MigrationPlan, options: ExecutionOptions = {}): Promise<MigrationExecutionResult> {
    const correlationId = CorrelationId.generate();
    const startTime = Date.now();

    this.logger.info('Starting migration execution', {
      correlationId,
      migrationsToApply: plan.migrationsToApply.length,
      migrationsToRollback: plan.migrationsToRollback.length,
      estimatedDuration: plan.estimatedDuration
    });

    const results: MigrationResult[] = [];
    let success = true;

    try {
      // Execute rollbacks first (if any)
      for (const migration of plan.migrationsToRollback) {
        const result = await this.executeSingleMigration(migration, 'rollback', correlationId);
        results.push(result);

        if (result.status === 'failed') {
          success = false;
          if (!options.continueOnFailure) {
            break;
          }
        }
      }

      // Execute forward migrations
      if (success || options.continueOnFailure) {
        for (const migration of plan.migrationsToApply) {
          const result = await this.executeSingleMigration(migration, 'apply', correlationId);
          results.push(result);

          if (result.status === 'failed') {
            success = false;
            if (!options.continueOnFailure) {
              // Rollback applied migrations in this execution
              await this.rollbackFailedExecution(results.filter(r => r.status === 'applied'));
              break;
            }
          }
        }
      }

      const duration = Date.now() - startTime;

      this.logger.info('Migration execution completed', {
        correlationId,
        success,
        duration,
        appliedCount: results.filter(r => r.status === 'applied').length,
        failedCount: results.filter(r => r.status === 'failed').length
      });

      return {
        success,
        duration,
        results,
        appliedMigrations: results.filter(r => r.status === 'applied').map(r => r.migration),
        failedMigrations: results.filter(r => r.status === 'failed').map(r => r.migration)
      };

    } catch (error) {
      this.logger.error('Migration execution failed', error, { correlationId });

      return {
        success: false,
        duration: Date.now() - startTime,
        results,
        appliedMigrations: [],
        failedMigrations: plan.migrationsToApply,
        error: error.message
      };
    }
  }

  /**
   * Rollback to specific version
   */
  async rollbackToVersion(targetVersion: number, options: RollbackOptions = {}): Promise<MigrationExecutionResult> {
    const correlationId = CorrelationId.generate();

    this.logger.info('Starting rollback to version', {
      correlationId,
      targetVersion,
      options
    });

    const plan = await this.planMigrations(targetVersion);

    if (plan.migrationsToRollback.length === 0) {
      this.logger.info('No migrations to rollback', { correlationId });
      return {
        success: true,
        duration: 0,
        results: [],
        appliedMigrations: [],
        failedMigrations: []
      };
    }

    return await this.executeMigrations(plan, {
      continueOnFailure: options.continueOnFailure || false,
      dryRun: options.dryRun || false
    });
  }

  /**
   * Get current database version
   */
  async getCurrentVersion(): Promise<number> {
    const appliedMigrations = await this.getAppliedMigrations();
    return appliedMigrations.length > 0
      ? Math.max(...appliedMigrations.map(m => m.version))
      : 0;
  }

  /**
   * Validate migration files
   */
  async validateMigrations(): Promise<ValidationResult> {
    const migrations = await this.loadMigrations();
    const issues: ValidationIssue[] = [];
    const warnings: string[] = [];

    // Check for duplicate versions
    const versions = migrations.map(m => m.version);
    const duplicates = versions.filter((v, i) => versions.indexOf(v) !== i);
    if (duplicates.length > 0) {
      issues.push({
        type: 'duplicate_version',
        severity: 'error',
        message: `Duplicate migration versions found: ${duplicates.join(', ')}`,
        migrations: migrations.filter(m => duplicates.includes(m.version))
      });
    }

    // Check for missing dependencies
    for (const migration of migrations) {
      const dependencies = this.extractMigrationDependencies(migration);
      for (const dep of dependencies) {
        const depExists = migrations.some(m => m.name === dep || m.version.toString() === dep);
        if (!depExists) {
          issues.push({
            type: 'missing_dependency',
            severity: 'error',
            message: `Migration ${migration.name} depends on ${dep} which doesn't exist`,
            migrations: [migration]
          });
        }
      }
    }

    // Check for circular dependencies
    const circularDeps = this.detectCircularDependencies(migrations);
    if (circularDeps.length > 0) {
      issues.push({
        type: 'circular_dependency',
        severity: 'error',
        message: `Circular dependencies detected: ${circularDeps.join(' -> ')}`,
        migrations: migrations.filter(m => circularDeps.includes(m.name))
      });
    }

    // Check SQL syntax (basic)
    for (const migration of migrations) {
      const syntaxIssues = await this.validateSqlSyntax(migration);
      issues.push(...syntaxIssues);
    }

    // Generate warnings for risky operations
    for (const migration of migrations) {
      const migrationWarnings = this.generateMigrationWarnings(migration);
      warnings.push(...migrationWarnings);
    }

    return {
      valid: issues.filter(i => i.severity === 'error').length === 0,
      issues,
      warnings
    };
  }

  /**
   * Private helper methods
   */
  private generateMigrationTemplate(options: MigrationTemplateOptions): string {
    const { name, version, author, description, tags } = options;

    return `-- Migration: ${name}
-- Version: ${version}
-- Author: ${author}
-- Date: ${new Date().toISOString()}
-- Description: ${description}
-- Tags: ${tags.join(', ')}

-- ==========================================
-- UP MIGRATION
-- ==========================================

BEGIN TRANSACTION;

-- Your schema changes here
-- Example: CREATE TABLE IF NOT EXISTS users (
--   id INTEGER PRIMARY KEY AUTOINCREMENT,
--   email TEXT NOT NULL UNIQUE,
--   name TEXT NOT NULL,
--   created_at DATETIME DEFAULT CURRENT_TIMESTAMP
-- );

-- Example: CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Update migration history
INSERT INTO migration_history (version, name, applied_at, author, checksum)
VALUES (${version}, '${name}', CURRENT_TIMESTAMP, '${author}', '${this.generateChecksum(name + version)}');

COMMIT;

-- ==========================================
-- DOWN MIGRATION (Rollback)
-- ==========================================

-- Uncomment and modify for rollback capability
-- BEGIN TRANSACTION;

-- Example rollback SQL:
-- DROP INDEX IF EXISTS idx_users_email;
-- DROP TABLE IF EXISTS users;

-- Remove from migration history
-- DELETE FROM migration_history WHERE version = ${version};

-- COMMIT;
`;
  }

  private async saveMigration(filePath: string, content: string): Promise<void> {
    // In a real implementation, this would write to the file system
    // For now, we'll simulate it
    this.logger.debug('Saving migration file', { filePath, size: content.length });
  }

  private async getCurrentUser(): Promise<string> {
    // In a real implementation, this would get the current user
    return process.env.USER || process.env.USERNAME || 'system';
  }

  private sanitizeName(name: string): string {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '_')
      .replace(/^_+|_+$/g, '');
  }

  private async getMigrationFiles(): Promise<string[]> {
    // In a real implementation, this would read the migrations directory
    // For now, return empty array
    return [];
  }

  private async parseMigrationFile(filename: string): Promise<D1Migration> {
    // Parse migration file and extract metadata
    const version = this.extractVersionFromFilename(filename);
    const name = this.extractNameFromFilename(filename);

    return {
      version,
      name,
      filename,
      upSql: '',
      downSql: '',
      author: 'unknown',
      description: '',
      tags: [],
      checksum: this.generateChecksum(filename),
      status: 'pending'
    };
  }

  private extractVersionFromFilename(filename: string): number {
    const match = filename.match(/^(\d+)_/);
    return match ? parseInt(match[1]) : 0;
  }

  private extractNameFromFilename(filename: string): string {
    const match = filename.match(/^\d+_(.+)\.sql$/);
    return match ? match[1] : filename;
  }

  private generateChecksum(content: string): string {
    // Simple checksum implementation
    let hash = 0;
    for (let i = 0; i < content.length; i++) {
      const char = content.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(16);
  }

  private async getAppliedMigrations(): Promise<MigrationHistory[]> {
    // In a real implementation, this would query the migration_history table
    return Array.from(this.appliedMigrations.values());
  }

  private estimateMigrationDuration(
    migrationsToApply: D1Migration[],
    migrationsToRollback: D1Migration[]
  ): number {
    // Estimate duration based on migration complexity
    const applyTime = migrationsToApply.length * 5000; // 5 seconds per migration
    const rollbackTime = migrationsToRollback.length * 3000; // 3 seconds per rollback
    return applyTime + rollbackTime;
  }

  private assessMigrationRisk(
    migrationsToApply: D1Migration[],
    migrationsToRollback: D1Migration[]
  ): 'low' | 'medium' | 'high' {
    const totalMigrations = migrationsToApply.length + migrationsToRollback.length;

    if (totalMigrations === 0) return 'low';
    if (totalMigrations <= 3) return 'low';
    if (totalMigrations <= 10) return 'medium';
    return 'high';
  }

  private extractDependencies(migrations: D1Migration[]): string[] {
    const dependencies: string[] = [];

    for (const migration of migrations) {
      const migrationDeps = this.extractMigrationDependencies(migration);
      dependencies.push(...migrationDeps);
    }

    return [...new Set(dependencies)];
  }

  private extractMigrationDependencies(migration: D1Migration): string[] {
    // Extract dependencies from migration metadata or SQL comments
    const dependsOnPattern = /-- Depends on: (.+)/g;
    const dependencies: string[] = [];

    let match;
    while ((match = dependsOnPattern.exec(migration.upSql)) !== null) {
      dependencies.push(match[1].trim());
    }

    return dependencies;
  }

  private generateWarnings(
    migrationsToApply: D1Migration[],
    migrationsToRollback: D1Migration[]
  ): string[] {
    const warnings: string[] = [];

    if (migrationsToRollback.length > 0) {
      warnings.push(`${migrationsToRollback.length} migration(s) will be rolled back`);
    }

    if (migrationsToApply.length > 5) {
      warnings.push(`Large number of migrations (${migrationsToApply.length}) will be applied`);
    }

    return warnings;
  }

  private async executeSingleMigration(
    migration: D1Migration,
    operation: 'apply' | 'rollback',
    correlationId: string
  ): Promise<MigrationResult> {
    const startTime = Date.now();

    this.logger.info('Executing migration', {
      correlationId,
      migration: migration.name,
      version: migration.version,
      operation
    });

    try {
      const sql = operation === 'apply' ? migration.upSql : migration.downSql;

      // Execute the migration SQL
      await this.executeSql(sql);

      // Update migration history
      if (operation === 'apply') {
        await this.recordMigrationApplied(migration);
      } else {
        await this.recordMigrationRolledBack(migration);
      }

      const duration = Date.now() - startTime;

      this.logger.info('Migration executed successfully', {
        correlationId,
        migration: migration.name,
        operation,
        duration
      });

      return {
        migration,
        status: operation === 'apply' ? 'applied' : 'rolled_back',
        duration,
        operation
      };

    } catch (error) {
      const duration = Date.now() - startTime;

      this.logger.error('Migration execution failed', error, {
        correlationId,
        migration: migration.name,
        operation,
        duration
      });

      return {
        migration,
        status: 'failed',
        duration,
        operation,
        error: error.message
      };
    }
  }

  private async executeSql(sql: string): Promise<void> {
    // In a real implementation, this would execute SQL against D1 database
    this.logger.debug('Executing SQL', { sql: sql.substring(0, 200) + '...' });
  }

  private async recordMigrationApplied(migration: D1Migration): Promise<void> {
    const history: MigrationHistory = {
      version: migration.version,
      name: migration.name,
      appliedAt: Date.now(),
      executionTime: 0,
      checksum: migration.checksum,
      author: migration.author,
      rollbackSql: migration.downSql
    };

    this.appliedMigrations.set(migration.version, history);
  }

  private async recordMigrationRolledBack(migration: D1Migration): Promise<void> {
    this.appliedMigrations.delete(migration.version);
  }

  private async rollbackFailedExecution(appliedResults: MigrationResult[]): Promise<void> {
    this.logger.warn('Rolling back failed execution', {
      migrationsToRollback: appliedResults.length
    });

    // Rollback in reverse order
    for (let i = appliedResults.length - 1; i >= 0; i--) {
      const result = appliedResults[i];
      try {
        await this.executeSql(result.migration.downSql);
        await this.recordMigrationRolledBack(result.migration);
      } catch (error) {
        this.logger.error('Rollback failed', error, {
          migration: result.migration.name
        });
      }
    }
  }

  private detectCircularDependencies(migrations: D1Migration[]): string[] {
    // Simplified circular dependency detection
    // In a real implementation, this would use graph algorithms
    return [];
  }

  private async validateSqlSyntax(migration: D1Migration): Promise<ValidationIssue[]> {
    const issues: ValidationIssue[] = [];

    // Basic SQL syntax validation
    const sql = migration.upSql;

    // Check for common issues
    if (sql.includes('DROP TABLE') && !sql.includes('IF EXISTS')) {
      issues.push({
        type: 'risky_operation',
        severity: 'warning',
        message: `Migration ${migration.name} contains DROP TABLE without IF EXISTS`,
        migrations: [migration]
      });
    }

    if (sql.includes('ALTER TABLE') && sql.includes('DROP COLUMN')) {
      issues.push({
        type: 'risky_operation',
        severity: 'warning',
        message: `Migration ${migration.name} drops a column, which may cause data loss`,
        migrations: [migration]
      });
    }

    return issues;
  }

  private generateMigrationWarnings(migration: D1Migration): string[] {
    const warnings: string[] = [];

    if (migration.upSql.includes('DROP')) {
      warnings.push(`Migration ${migration.name} contains DROP operations`);
    }

    if (migration.upSql.includes('ALTER TABLE') && migration.upSql.includes('DROP COLUMN')) {
      warnings.push(`Migration ${migration.name} may cause data loss`);
    }

    if (!migration.downSql || migration.downSql.trim() === '') {
      warnings.push(`Migration ${migration.name} has no rollback SQL`);
    }

    return warnings;
  }
}

// Supporting interfaces
interface GenerateMigrationOptions {
  author?: string;
  description?: string;
  tags?: string[];
  version?: number;
}

interface MigrationTemplateOptions {
  name: string;
  version: number;
  author: string;
  description: string;
  tags: string[];
}

interface ExecutionOptions {
  continueOnFailure?: boolean;
  dryRun?: boolean;
}

interface RollbackOptions {
  continueOnFailure?: boolean;
  dryRun?: boolean;
}

interface MigrationExecutionResult {
  success: boolean;
  duration: number;
  results: MigrationResult[];
  appliedMigrations: D1Migration[];
  failedMigrations: D1Migration[];
  error?: string;
}

interface MigrationResult {
  migration: D1Migration;
  status: MigrationStatus;
  duration: number;
  operation: 'apply' | 'rollback';
  error?: string;
}

interface ValidationResult {
  valid: boolean;
  issues: ValidationIssue[];
  warnings: string[];
}

interface ValidationIssue {
  type: 'duplicate_version' | 'missing_dependency' | 'circular_dependency' | 'risky_operation';
  severity: 'error' | 'warning';
  message: string;
  migrations: D1Migration[];
}

/**
 * Create D1 migration manager
 */
export function createD1MigrationManager(migrationsPath?: string): D1MigrationManager {
  return new D1MigrationManager(migrationsPath);
}

/**
 * CLI utilities for migration management
 */
export class MigrationCLI {
  constructor(private manager: D1MigrationManager) {}

  async generateCommand(name: string, options: any): Promise<void> {
    const filePath = await this.manager.generateMigration(name, options);
  }

  async statusCommand(): Promise<void> {
    const currentVersion = await this.manager.getCurrentVersion();
    const plan = await this.manager.planMigrations();


    if (plan.warnings.length > 0) {
      plan.warnings.forEach(warning => console.log(`  - ${warning}`));
    }
  }

  async migrateCommand(options: any): Promise<void> {
    const plan = await this.manager.planMigrations(options.version);

    if (plan.migrationsToApply.length === 0 && plan.migrationsToRollback.length === 0) {
      return;
    }


    const result = await this.manager.executeMigrations(plan, {
      continueOnFailure: options.continueOnFailure,
      dryRun: options.dryRun
    });

    if (result.success) {
    } else {
      if (result.error) {
      }
    }
  }

  async rollbackCommand(version: number, options: any): Promise<void> {
    const result = await this.manager.rollbackToVersion(version, options);

    if (result.success) {
    } else {
    }
  }

  async validateCommand(): Promise<void> {
    const validation = await this.manager.validateMigrations();

    if (validation.valid) {
    } else {
      validation.issues.forEach(issue => {
      });
    }

    if (validation.warnings.length > 0) {
      validation.warnings.forEach(warning => console.log(`  - ${warning}`));
    }
  }
}