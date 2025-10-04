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

  return await next();
});

// Get migration status
app.get('/migrations/status', async (c: any) => {
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
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    }, 500);
  }
});

// Run migrations
app.post('/migrations/run', async (c: any) => {
  try {
    const loadedMigrations = await loadMigrations();

    // Add checksums to migrations
    const migrations = await Promise.all(loadedMigrations.map(async (migration: any) => ({
      ...migration,
      checksum: await MigrationRunner.calculateChecksum(migration.sql)
    })));

    const runner = new MigrationRunner(c.env.DB_MAIN, 'admin');
    const results = await runner.executeMigrations(migrations);

    const hasFailures = results.some(r => r.status === 'failed');

    return c.json({
      success: !hasFailures,
      results,
      summary: {
        total: results.length,
        successful: results.filter((r: any) => r.status === 'success').length,
        skipped: results.filter((r: any) => r.status === 'skipped').length,
        failed: results.filter((r: any) => r.status === 'failed').length,
      },
    }, hasFailures ? 500 : 200);
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    }, 500);
  }
});

// Rollback a specific migration
app.post('/migrations/rollback/:version', async (c: any) => {
  try {
    const version = c.req.param('version');
    const rollbackFiles = await loadRollbacks();

    interface RollbackFile {
      version: string;
      rollbackSql?: string;
    }

    const rollback = (rollbackFiles as RollbackFile[]).find(r => r.version === version);

    if (!rollback || !rollback.rollbackSql) {
      return c.json({
        success: false,
        error: `Rollback script not found for version ${version}`,
      }, 404);
    }

    const runner = new MigrationRunner(c.env.DB_MAIN, 'admin');
    const result = await runner.rollbackMigration(version, rollback.rollbackSql);

    return c.json({
      success: result.status === 'success',
      result,
    }, result.status === 'success' ? 200 : 500);
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    }, 500);
  }
});

// Database statistics
app.get('/database/stats', async (c: any) => {
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
  } catch (error: any) {
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