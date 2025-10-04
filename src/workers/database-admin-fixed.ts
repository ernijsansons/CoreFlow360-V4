import { Hono } from 'hono';
import { z } from 'zod';
import type { Env } from '../types/env';
import { MigrationRunner, type MigrationFile } from '../modules/database/migration-runner';
import { createErrorResponse } from '../shared/utils';

import { loadMigrations, loadRollbacks } from './migration-sql';
// Import migration files (in production, these would be loaded from R2 or KV)


const app = new Hono<{ Bindings: Env }>();

// Request validation schemas
const AdminAuthSchema = z.object({
  authorization: z.string().regex(/^Bearer .+$/),
});

// Enhanced admin authentication with rate limiting
const adminAuthMiddleware = async (c: any, next: any) => {
  const requestId = crypto.randomUUID();
  c.set('requestId', requestId);

  try {
    const authHeader = c.req.header('Authorization');
    const adminKey = c.env.ADMIN_API_KEY;

    if (!adminKey) {
      await logAudit(c, 'admin_auth_failed', 'error', { reason: 'No admin key configured' });
      return createErrorResponse('UNAUTHORIZED', 'Admin access not configured', 401);
    }

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      await logAudit(c, 'admin_auth_failed', 'error', { reason: 'Invalid auth header' });
      return createErrorResponse('UNAUTHORIZED', 'Invalid authorization header', 401);
    }

    const providedKey = authHeader.substring(7); // Remove 'Bearer '

    // Constant-time comparison to prevent timing attacks
    const encoder = new TextEncoder();
    const keyBuffer = encoder.encode(adminKey);
    const providedBuffer = encoder.encode(providedKey);

    if (keyBuffer.length !== providedBuffer.length) {
      await logAudit(c, 'admin_auth_failed', 'error', { reason: 'Key length mismatch' });
      return createErrorResponse('UNAUTHORIZED', 'Invalid credentials', 401);
    }

    let match = true;
    for (let i = 0; i < keyBuffer.length; i++) {
      if (keyBuffer[i] !== providedBuffer[i]) {
        match = false;
      }
    }

    if (!match) {
      await logAudit(c, 'admin_auth_failed', 'error', { reason: 'Invalid key' });
      return createErrorResponse('UNAUTHORIZED', 'Invalid credentials', 401);
    }

    await logAudit(c, 'admin_auth_success', 'info', {});
    return await next();
  } catch (error: any) {
    await logAudit(c, 'admin_auth_error', 'error', { error: String(error) });
    return createErrorResponse('INTERNAL_ERROR', 'Authentication failed', 500);
  }
};

app.use('*', adminAuthMiddleware);

// Audit logging helper
async function logAudit(c: any, eventName: string, eventType: string, data: any): Promise<void> {
  const auditEntry = {
    id: crypto.randomUUID(),
    business_id: 'SYSTEM',
    event_type: eventType,
    event_name: eventName,
    resource_type: 'admin_api',
    resource_id: c.get('requestId'),
    ip_address: c.req.header('CF-Connecting-IP') || 'unknown',
    user_agent: c.req.header('User-Agent') || 'unknown',
    request_method: c.req.method,
    request_path: c.req.path,
    event_timestamp: new Date().toISOString(),
    ...data
  };

  try {
    await c.env.DB_MAIN.prepare(`
      INSERT INTO audit_logs (
        id, business_id, event_type, event_name, resource_type, resource_id,
        ip_address, user_agent, request_method, request_path, event_timestamp,
        status, compute_time_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      auditEntry.id,
      auditEntry.business_id,
      auditEntry.event_type,
      auditEntry.event_name,
      auditEntry.resource_type,
      auditEntry.resource_id,
      auditEntry.ip_address,
      auditEntry.user_agent,
      auditEntry.request_method,
      auditEntry.request_path,
      auditEntry.event_timestamp,
      data.status || 'success',
      data.compute_time_ms || 0
    ).run();
  } catch (error: any) {
    // Silently ignore audit failures to not break main functionality
  }
}

// Get migration status
app.get('/migrations/status', async (c: any) => {
  const startTime = Date.now();
  try {
    const runner = new MigrationRunner(c.env.DB_MAIN);
    const status = await runner.getMigrationStatus();

    await logAudit(c, 'migration_status_viewed', 'view', {
      compute_time_ms: Date.now() - startTime
    });

    return c.json({
      success: true,
      migrations: status,
      total: status.length,
      completed: status.filter((m: any) => m.status === 'completed').length,
      failed: status.filter((m: any) => m.status === 'failed').length,
    });
  } catch (error: any) {
    await logAudit(c, 'migration_status_error', 'error', { 
      error: String(error),
      compute_time_ms: Date.now() - startTime
    });
    return createErrorResponse('MIGRATION_ERROR', 'Failed to get migration status', 500);
  }
});

// Run migrations
app.post('/migrations/run', async (c: any) => {
  const startTime = Date.now();
  try {
    const runner = new MigrationRunner(c.env.DB_MAIN);
    const loadedMigrations = await loadMigrations();

    // Add checksums to migrations
    const migrations = await Promise.all(loadedMigrations.map(async (migration: any) => ({
      ...migration,
      checksum: await MigrationRunner.calculateChecksum(migration.sql)
    })));

    const results = await runner.executeMigrations(migrations);

    await logAudit(c, 'migrations_executed', 'action', {
      migrations_count: migrations.length,
      compute_time_ms: Date.now() - startTime
    });

    return c.json({
      success: true,
      results,
      executed: results.filter((r: any) => r.status === 'completed').length,
      failed: results.filter((r: any) => r.status === 'failed').length,
    });
  } catch (error: any) {
    await logAudit(c, 'migrations_execution_error', 'error', { 
      error: String(error),
      compute_time_ms: Date.now() - startTime
    });
    return createErrorResponse('MIGRATION_ERROR', 'Failed to run migrations', 500);
  }
});

// Rollback migrations
app.post('/migrations/rollback', async (c: any) => {
  const startTime = Date.now();
  try {
    const body = await c.req.json();
    const { steps = 1 } = body;

    const runner = new MigrationRunner(c.env.DB_MAIN);
    const rollbacks = await loadRollbacks();

    interface RollbackFile {
      version: string;
      sql: string;
    }

    const results = [];

    // Execute rollbacks one by one for the specified steps
    for (let i = 0; i < Math.min(steps, rollbacks.length); i++) {
      const rollback = rollbacks[i] as RollbackFile;
      const result = await runner.rollbackMigration(rollback.version, rollback.sql);
      results.push(result);
    }

    await logAudit(c, 'migrations_rollback', 'action', {
      rollback_steps: steps,
      compute_time_ms: Date.now() - startTime
    });

    return c.json({
      success: true,
      results,
      rolledBack: results.filter((r: any) => r.status === 'completed').length,
      failed: results.filter((r: any) => r.status === 'failed').length,
    });
  } catch (error: any) {
    await logAudit(c, 'migrations_rollback_error', 'error', { 
      error: String(error),
      compute_time_ms: Date.now() - startTime
    });
    return createErrorResponse('MIGRATION_ERROR', 'Failed to rollback migrations', 500);
  }
});

// Health check
app.get('/health', async (c: any) => {
  try {
    // Test database connection
    await c.env.DB_MAIN.prepare('SELECT 1').first();

    return c.json({
      success: true,
      status: 'healthy',
      timestamp: new Date().toISOString(),
      environment: c.env.ENVIRONMENT || 'development'
    });
  } catch (error: any) {
    return createErrorResponse('HEALTH_CHECK_FAILED', 'Database connection failed', 503);
  }
});

export default app;
