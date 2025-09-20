import { Hono } from 'hono';
import { z } from 'zod';
import type { Env } from '../types/env';
import { MigrationRunner, type MigrationFile } from '../modules/database/migration-runner';

// Import migration files (in production, these would be loaded from R2 or KV)
import migration001 from '../../database/migrations/001_core_tenant_users.sql?raw';
import migration002 from '../../database/migrations/002_rbac_departments.sql?raw';
import migration003 from '../../database/migrations/003_double_entry_ledger.sql?raw';
import migration004 from '../../database/migrations/004_audit_workflows.sql?raw';
import migration005 from '../../database/migrations/005_additional_indexes.sql?raw';

import rollback001 from '../../database/rollbacks/rollback_001_core_tenant_users.sql?raw';
import rollback002 from '../../database/rollbacks/rollback_002_rbac_departments.sql?raw';
import rollback003 from '../../database/rollbacks/rollback_003_double_entry_ledger.sql?raw';
import rollback004 from '../../database/rollbacks/rollback_004_audit_workflows.sql?raw';
import rollback005 from '../../database/rollbacks/rollback_005_additional_indexes.sql?raw';

const app = new Hono<{ Bindings: Env }>();

// Middleware to check admin authentication
app.use('*', async (c, next) => {
  const authHeader = c.req.header('Authorization');
  const adminKey = c.env.ADMIN_API_KEY;

  if (!adminKey || !authHeader || authHeader !== `Bearer ${adminKey}`) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  await next();
});

// Get migration status
app.get('/migrations/status', async (c) => {
  try {
    const runner = new MigrationRunner(c.env.DB_MAIN);
    const status = await runner.getMigrationStatus();

    return c.json({
      success: true,
      migrations: status,
      total: status.length,
      completed: status.filter((m: any) => m.status === 'completed').length,
      failed: status.filter((m: any) => m.status === 'failed').length,
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    }, 500);
  }
});

// Run migrations
app.post('/migrations/run', async (c) => {
  try {
    const migrations: MigrationFile[] = [
      {
        version: '001',
        name: 'core_tenant_users',
        sql: migration001,
        checksum: await MigrationRunner.calculateChecksum(migration001),
      },
      {
        version: '002',
        name: 'rbac_departments',
        sql: migration002,
        checksum: await MigrationRunner.calculateChecksum(migration002),
      },
      {
        version: '003',
        name: 'double_entry_ledger',
        sql: migration003,
        checksum: await MigrationRunner.calculateChecksum(migration003),
      },
      {
        version: '004',
        name: 'audit_workflows',
        sql: migration004,
        checksum: await MigrationRunner.calculateChecksum(migration004),
      },
      {
        version: '005',
        name: 'additional_indexes',
        sql: migration005,
        checksum: await MigrationRunner.calculateChecksum(migration005),
      },
    ];

    const runner = new MigrationRunner(c.env.DB_MAIN, 'admin');
    const results = await runner.executeMigrations(migrations);

    const hasFailures = results.some(r => r.status === 'failed');

    return c.json({
      success: !hasFailures,
      results,
      summary: {
        total: results.length,
        successful: results.filter(r => r.status === 'success').length,
        skipped: results.filter(r => r.status === 'skipped').length,
        failed: results.filter(r => r.status === 'failed').length,
      },
    }, hasFailures ? 500 : 200);
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    }, 500);
  }
});

// Rollback a specific migration
app.post('/migrations/rollback/:version', async (c) => {
  try {
    const version = c.req.param('version');

    const rollbacks: Record<string, string> = {
      '001': rollback001,
      '002': rollback002,
      '003': rollback003,
      '004': rollback004,
      '005': rollback005,
    };

    if (!rollbacks[version]) {
      return c.json({
        success: false,
        error: `Rollback script not found for version ${version}`,
      }, 404);
    }

    const runner = new MigrationRunner(c.env.DB_MAIN, 'admin');
    const result = await runner.rollbackMigration(version, rollbacks[version]);

    return c.json({
      success: result.status === 'success',
      result,
    }, result.status === 'success' ? 200 : 500);
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    }, 500);
  }
});

// Database statistics
app.get('/database/stats', async (c) => {
  try {
    const stats = await c.env.DB_MAIN.prepare(`
      SELECT
        'businesses' as table_name,
        COUNT(*) as row_count
      FROM businesses
      WHERE status != 'deleted'

      UNION ALL

      SELECT
        'users' as table_name,
        COUNT(*) as row_count
      FROM users
      WHERE status != 'deleted'

      UNION ALL

      SELECT
        'journal_entries' as table_name,
        COUNT(*) as row_count
      FROM journal_entries
      WHERE status = 'posted'

      UNION ALL

      SELECT
        'audit_logs' as table_name,
        COUNT(*) as row_count
      FROM audit_logs
      WHERE created_at > datetime('now', '-30 days')
    `).all();

    const tables = await c.env.DB_MAIN.prepare(`
      SELECT name FROM sqlite_master
      WHERE type='table'
      AND name NOT LIKE 'sqlite_%'
      AND name NOT LIKE '%_fts%'
      ORDER BY name
    `).all();

    return c.json({
      success: true,
      statistics: stats.results,
      tables: tables.results?.map((t: any) => t.name),
      tableCount: tables.results?.length || 0,
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    }, 500);
  }
});

// Health check
app.get('/health', (c) => {
  return c.json({
    status: 'healthy',
    service: 'database-admin',
    timestamp: new Date().toISOString(),
  });
});

export default app;