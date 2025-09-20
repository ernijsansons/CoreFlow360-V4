import { z } from 'zod';
import type { Env } from '../../types/env';

export interface MigrationFile {
  version: string;
  name: string;
  sql: string;
  checksum: string;
}

export interface MigrationResult {
  version: string;
  name: string;
  status: 'success' | 'failed' | 'skipped';
  error?: string;
  executionTimeMs: number;
}

export class MigrationRunner {
  private db: D1Database;
  private executedBy: string;

  constructor(db: D1Database, executedBy: string = 'system') {
    this.db = db;
    this.executedBy = executedBy;
  }

  /**
   * Initialize migration tracking table
   */
  async initialize(): Promise<void> {
    const initSQL = `
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        executed_at TEXT DEFAULT (datetime('now')),
        execution_time_ms INTEGER,
        checksum TEXT,
        status TEXT DEFAULT 'completed' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'rolled_back')),
        error_message TEXT,
        executed_by TEXT
      );
    `;

    await this.db.prepare(initSQL).run();
  }

  /**
   * Check if a migration has been executed
   */
  async isMigrationExecuted(version: string): Promise<boolean> {
    const result = await this.db
      .prepare('SELECT status FROM schema_migrations WHERE version = ? AND status = ?')
      .bind(version, 'completed')
      .first();

    return result !== null;
  }

  /**
   * Execute a single migration
   */
  async executeMigration(migration: MigrationFile): Promise<MigrationResult> {
    const startTime = Date.now();

    try {
      // Check if already executed
      if (await this.isMigrationExecuted(migration.version)) {
        return {
          version: migration.version,
          name: migration.name,
          status: 'skipped',
          executionTimeMs: Date.now() - startTime,
        };
      }

      // Mark as running
      await this.db
        .prepare(
          `INSERT OR REPLACE INTO schema_migrations
           (version, name, status, checksum, executed_by)
           VALUES (?, ?, 'running', ?, ?)`
        )
        .bind(migration.version, migration.name, migration.checksum, this.executedBy)
        .run();

      // Execute migration in a transaction
      const statements = this.parseSQLStatements(migration.sql);

      for (const statement of statements) {
        if (statement.trim()) {
          await this.db.prepare(statement).run();
        }
      }

      const executionTime = Date.now() - startTime;

      // Mark as completed
      await this.db
        .prepare(
          `UPDATE schema_migrations
           SET status = 'completed',
               execution_time_ms = ?,
               executed_at = datetime('now')
           WHERE version = ?`
        )
        .bind(executionTime, migration.version)
        .run();

      return {
        version: migration.version,
        name: migration.name,
        status: 'success',
        executionTimeMs: executionTime,
      };
    } catch (error) {
      const executionTime = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : String(error);

      // Mark as failed
      await this.db
        .prepare(
          `UPDATE schema_migrations
           SET status = 'failed',
               execution_time_ms = ?,
               error_message = ?,
               executed_at = datetime('now')
           WHERE version = ?`
        )
        .bind(executionTime, errorMessage, migration.version)
        .run();

      return {
        version: migration.version,
        name: migration.name,
        status: 'failed',
        error: errorMessage,
        executionTimeMs: executionTime,
      };
    }
  }

  /**
   * Execute multiple migrations in order
   */
  async executeMigrations(migrations: MigrationFile[]): Promise<MigrationResult[]> {
    await this.initialize();

    const results: MigrationResult[] = [];

    // Sort migrations by version
    const sortedMigrations = [...migrations].sort((a, b) =>
      a.version.localeCompare(b.version, undefined, { numeric: true })
    );

    for (const migration of sortedMigrations) {
      const result = await this.executeMigration(migration);
      results.push(result);

      // Stop on failure
      if (result.status === 'failed') {
        break;
      }
    }

    return results;
  }

  /**
   * Rollback a specific migration
   */
  async rollbackMigration(version: string, rollbackSQL: string): Promise<MigrationResult> {
    const startTime = Date.now();

    try {
      // Check if migration exists and is completed
      const migration = await this.db
        .prepare('SELECT * FROM schema_migrations WHERE version = ?')
        .bind(version)
        .first();

      if (!migration) {
        return {
          version,
          name: 'rollback',
          status: 'skipped',
          error: 'Migration not found',
          executionTimeMs: Date.now() - startTime,
        };
      }

      if (migration.status !== 'completed') {
        return {
          version,
          name: 'rollback',
          status: 'skipped',
          error: 'Migration not in completed state',
          executionTimeMs: Date.now() - startTime,
        };
      }

      // Execute rollback
      const statements = this.parseSQLStatements(rollbackSQL);

      for (const statement of statements) {
        if (statement.trim()) {
          await this.db.prepare(statement).run();
        }
      }

      const executionTime = Date.now() - startTime;

      // Mark as rolled back
      await this.db
        .prepare(
          `UPDATE schema_migrations
           SET status = 'rolled_back',
               executed_at = datetime('now')
           WHERE version = ?`
        )
        .bind(version)
        .run();

      return {
        version,
        name: 'rollback',
        status: 'success',
        executionTimeMs: executionTime,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);

      return {
        version,
        name: 'rollback',
        status: 'failed',
        error: errorMessage,
        executionTimeMs: Date.now() - startTime,
      };
    }
  }

  /**
   * Get migration status
   */
  async getMigrationStatus(): Promise<any[]> {
    const results = await this.db
      .prepare(
        `SELECT version, name, status, executed_at, execution_time_ms, executed_by
         FROM schema_migrations
         ORDER BY version`
      )
      .all();

    return results.results || [];
  }

  /**
   * Parse SQL statements from a migration file
   */
  private parseSQLStatements(sql: string): string[] {
    // Remove comments and split by semicolons
    const cleaned = sql
      .split('\n')
      .map(line => {
        // Remove comments
        const commentIndex = line.indexOf('--');
        if (commentIndex >= 0) {
          return line.substring(0, commentIndex);
        }
        return line;
      })
      .join('\n');

    // Split by semicolons but handle ones inside strings
    const statements: string[] = [];
    let current = '';
    let inString = false;
    let stringChar = '';

    for (let i = 0; i < cleaned.length; i++) {
      const char = cleaned[i];
      const prevChar = i > 0 ? cleaned[i - 1] : '';

      if ((char === '"' || char === "'") && prevChar !== '\\') {
        if (!inString) {
          inString = true;
          stringChar = char;
        } else if (char === stringChar) {
          inString = false;
        }
      }

      if (char === ';' && !inString) {
        if (current.trim()) {
          statements.push(current.trim());
        }
        current = '';
      } else {
        current += char;
      }
    }

    if (current.trim()) {
      statements.push(current.trim());
    }

    return statements;
  }

  /**
   * Calculate checksum for a migration file
   */
  static async calculateChecksum(sql: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(sql);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return btoa(String.fromCharCode(...new Uint8Array(hash)));
  }
}