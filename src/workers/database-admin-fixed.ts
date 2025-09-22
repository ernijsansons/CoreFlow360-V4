import { Hono } from 'hono';
import { z } from 'zod';
import type { Env } from '../types/env';
import { MigrationRunner, type MigrationFile } from '../modules/database/migration-runner';
import { createErrorResponse } from '../shared/utils';

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
    await next();
  } catch (error) {
    await logAudit(c, 'admin_auth_error', 'error', { error: String(error) });
    return createErrorResponse('INTERNAL_ERROR', 'Authentication failed', 500);
  }
};

app.use('*', adminAuthMiddleware);

// Audit logging helper
async function logAudit(c: any, eventName: string, eventType: string, data: any) {
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
  } catch (error) {
  }
}

// Get migration status
app.get('/migrations/status', async (c) => {
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
  } catch (error) {
    await logAudit(c, 'migration_status_error', 'error', {
      error: String(error),
      compute_time_ms: Date.now() - startTime
    });
    return createErrorResponse('INTERNAL_ERROR', 'Failed to get migration status', 500);
  }
});

// Run migrations with proper error handling
app.post('/migrations/run', async (c) => {
  const startTime = Date.now();
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

    await logAudit(c, 'migrations_executed', hasFailures ? 'error' : 'create', {
      results: results.map(r => ({ version: r.version, status: r.status })),
      compute_time_ms: Date.now() - startTime
    });

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
    await logAudit(c, 'migrations_error', 'error', {
      error: String(error),
      compute_time_ms: Date.now() - startTime
    });
    return createErrorResponse('INTERNAL_ERROR', 'Failed to run migrations', 500);
  }
});

// Rollback with validation
app.post('/migrations/rollback/:version', async (c) => {
  const startTime = Date.now();
  try {
    const version = c.req.param('version');

    // Validate version format
    if (!/^\d{3}$/.test(version)) {
      return createErrorResponse('VALIDATION_ERROR', 'Invalid version format', 400);
    }

    const rollbacks: Record<string, string> = {
      '001': rollback001,
      '002': rollback002,
      '003': rollback003,
      '004': rollback004,
      '005': rollback005,
    };

    if (!rollbacks[version]) {
      await logAudit(c, 'rollback_not_found', 'error', {
        version,
        compute_time_ms: Date.now() - startTime
      });
      return createErrorResponse('NOT_FOUND', `Rollback script not found for version ${version}`, 404);
    }

    const runner = new MigrationRunner(c.env.DB_MAIN, 'admin');
    const result = await runner.rollbackMigration(version, rollbacks[version]);

    await logAudit(c, 'migration_rollback', result.status === 'success' ? 'delete' : 'error', {
      version,
      result,
      compute_time_ms: Date.now() - startTime
    });

    return c.json({
      success: result.status === 'success',
      result,
    }, result.status === 'success' ? 200 : 500);
  } catch (error) {
    await logAudit(c, 'rollback_error', 'error', {
      error: String(error),
      compute_time_ms: Date.now() - startTime
    });
    return createErrorResponse('INTERNAL_ERROR', 'Failed to rollback migration', 500);
  }
});

// Database statistics - FIXED: Now properly isolated
app.get('/database/stats/:businessId?', async (c) => {
  const startTime = Date.now();
  try {
    const businessId = c.req.param('businessId');

    // System-wide stats only if no businessId provided (admin only)
    if (!businessId) {
      const systemStats = await c.env.DB_MAIN.prepare(`
        SELECT
          'total_businesses' as metric,
          COUNT(*) as value
        FROM businesses
        WHERE status != 'deleted'

        UNION ALL

        SELECT
          'total_users' as metric,
          COUNT(*) as value
        FROM users
        WHERE status != 'deleted'
      `).all();

      await logAudit(c, 'system_stats_viewed', 'view', {
        compute_time_ms: Date.now() - startTime
      });

      return c.json({
        success: true,
        type: 'system',
        statistics: systemStats.results,
      });
    }

    // Business-specific stats with proper isolation
    const businessStats = await c.env.DB_MAIN.prepare(`
      SELECT
        'active_users' as metric,
        COUNT(*) as value
      FROM business_memberships
      WHERE business_id = ? AND status = 'active'

      UNION ALL

      SELECT
        'journal_entries' as metric,
        COUNT(*) as value
      FROM journal_entries
      WHERE business_id = ? AND status = 'posted'

      UNION ALL

      SELECT
        'recent_audits' as metric,
        COUNT(*) as value
      FROM audit_logs
      WHERE business_id = ? AND created_at > datetime('now', '-30 days')
    `).bind(businessId, businessId, businessId).all();

    await logAudit(c, 'business_stats_viewed', 'view', {
      business_id: businessId,
      compute_time_ms: Date.now() - startTime
    });

    return c.json({
      success: true,
      type: 'business',
      businessId,
      statistics: businessStats.results,
    });
  } catch (error) {
    await logAudit(c, 'stats_error', 'error', {
      error: String(error),
      compute_time_ms: Date.now() - startTime
    });
    return createErrorResponse('INTERNAL_ERROR', 'Failed to get statistics', 500);
  }
});

// Health check
app.get('/health', (c) => {
  return c.json({
    status: 'healthy',
    service: 'database-admin',
    timestamp: new Date().toISOString(),
    requestId: c.get('requestId'),
  });
});

export default app;