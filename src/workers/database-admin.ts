import { Hono } from 'hono';
import { z } from 'zod';
import type { Env } from '../types/env';
import { MigrationRunner, type MigrationFile } from '../modules/database/migration-runner';

// Import migration files (in production, these would be loaded from R2 or KV)
import { loadMigrations, loadRollbacks } from './migration-sql';


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
        sql: loadMigrations()['001'] || '-- Migration not found',
        checksum: await MigrationRunner.calculateChecksum(loadMigrations()['001'] || '-- Migration not found'),
      },
      {
        version: '002',
        name: 'rbac_departments',
        sql: loadMigrations()['002'] || '-- Migration not found',
        checksum: await MigrationRunner.calculateChecksum(loadMigrations()['002'] || '-- Migration not found'),
      },
      {
        version: '003',
        name: 'double_entry_ledger',
        sql: loadMigrations()['003'] || '-- Migration not found',
        checksum: await MigrationRunner.calculateChecksum(loadMigrations()['003'] || '-- Migration not found'),
      },
      {
        version: '004',
        name: 'audit_workflows',
        sql: loadMigrations()['004'] || '-- Migration not found',
        checksum: await MigrationRunner.calculateChecksum(loadMigrations()['004'] || '-- Migration not found'),
      },
      {
        version: '005',
        name: 'additional_indexes',
        sql: loadMigrations()['005'] || '-- Migration not found',
        checksum: await MigrationRunner.calculateChecksum(loadMigrations()['005'] || '-- Migration not found'),
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
      '001': loadRollbacks()['001'] || '-- Rollback not found',
      '002': loadRollbacks()['002'] || '-- Rollback not found',
      '003': loadRollbacks()['003'] || '-- Rollback not found',
      '004': loadRollbacks()['004'] || '-- Rollback not found',
      '005': loadRollbacks()['005'] || '-- Rollback not found',
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