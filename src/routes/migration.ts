import { Hono } from 'hono';
import {
  MigrationRequest,
  ConnectionConfig,
  MigrationState,
  ValidationResult
} from '../types/migration';
import { ConnectorRegistry } from '../services/migration/connectors';
import { AISchemaMapper } from '../services/migration/ai-schema-mapper';
import { TransformationEngine } from '../services/migration/transformation-engine';
import { SyncEngine } from '../services/migration/sync-engine';
import { RollbackManager } from '../services/migration/rollback-manager';
import { MigrationTester } from '../services/migration/migration-tester';
import { ProgressTracker } from '../services/migration/progress-tracker';

const migration = new Hono();

migration.post('/connections/test', async (c) => {
  try {
    const config: ConnectionConfig = await c.req.json();
    const env = c.env;

    const registry = new ConnectorRegistry();

    // Register available connectors
    const { DatabaseConnector } = await import('../services/migration/connectors/database-connector');
    const { FileConnector } = await import('../services/migration/connectors/file-connector');
    const { APIConnector } = await import('../services/migration/connectors/api-connector');

    registry.registerConnector('database', DatabaseConnector as any);
    registry.registerConnector('file', FileConnector as any);
    registry.registerConnector('api', APIConnector as any);

    const connector = registry.createConnector(config, env);
    const isValid = await connector.testConnection();

    return c.json({
      success: isValid,
      message: isValid ? 'Connection successful' : 'Connection failed'
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 400);
  }
});

migration.post('/connections/validate', async (c) => {
  try {
    const config: ConnectionConfig = await c.req.json();
    const env = c.env;

    const registry = new ConnectorRegistry();

    const { DatabaseConnector } = await import('../services/migration/connectors/database-connector');
    const { FileConnector } = await import('../services/migration/connectors/file-connector');
    const { APIConnector } = await import('../services/migration/connectors/api-connector');

    registry.registerConnector('database', DatabaseConnector as any);
    registry.registerConnector('file', FileConnector as any);
    registry.registerConnector('api', APIConnector as any);

    const connector = registry.createConnector(config, env);
    const validation = await connector.validateConfig();

    return c.json(validation);
  } catch (error) {
    return c.json({
      valid: false,
      errors: [error instanceof Error ? error.message : 'Unknown error']
    }, 400);
  }
});

migration.post('/schema/discover', async (c) => {
  try {
    const { connectionConfig } = await c.req.json();
    const env = c.env;

    const registry = new ConnectorRegistry();

    const { DatabaseConnector } = await import('../services/migration/connectors/database-connector');
    const { FileConnector } = await import('../services/migration/connectors/file-connector');
    const { APIConnector } = await import('../services/migration/connectors/api-connector');

    registry.registerConnector('database', DatabaseConnector as any);
    registry.registerConnector('file', FileConnector as any);
    registry.registerConnector('api', APIConnector as any);

    const connector = registry.createConnector(connectionConfig, env);
    const schema = await connector.getSchema();

    return c.json({ schema });
  } catch (error) {
    return c.json({
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 400);
  }
});

migration.post('/schema/map', async (c) => {
  try {
    const { sourceSchema, targetSchema, options } = await c.req.json();
    const env = c.env;

    const mapper = new AISchemaMapper(env.AI);
    const mapping = await mapper.generateMapping(sourceSchema, targetSchema, options);

    return c.json({ mapping });
  } catch (error) {
    return c.json({
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 400);
  }
});

migration.post('/migration/create', async (c) => {
  try {
    const request: MigrationRequest = await c.req.json();
    const env = c.env;

    // Validate the migration request
    const tester = new MigrationTester(env);
    const validation = await tester.validateMigrationRequest(request);

    if (!validation.isValid) {
      return c.json({
        success: false,
        errors: validation.errors
      }, 400);
    }

    // Create migration ID
    const migrationId = crypto.randomUUID();

    // Store migration request
    const migrationData = {
      id: migrationId,
      request,
      status: 'pending',
      createdAt: new Date().toISOString(),
      createdBy: c.get('user')?.id || 'system'
    };

    if (env.MIGRATION_KV) {
      await env.MIGRATION_KV.put(
        `migration:${migrationId}`,
        JSON.stringify(migrationData)
      );
    }

    return c.json({
      success: true,
      migrationId,
      validation
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 400);
  }
});

migration.post('/migration/:id/start', async (c) => {
  try {
    const migrationId = c.req.param('id');
    const env = c.env;

    // Get migration request
    const migrationData = await env.MIGRATION_KV?.get(`migration:${migrationId}`);
    if (!migrationData) {
      return c.json({ error: 'Migration not found' }, 404);
    }

    const { request } = JSON.parse(migrationData);

    // Start migration using Durable Object
    const id = env.MIGRATION_EXECUTOR.idFromName(migrationId);
    const obj = env.MIGRATION_EXECUTOR.get(id);

    const response = await obj.fetch('http://migration/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request)
    });

    const result = await response.json();

    return c.json(result);
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 400);
  }
});

migration.post('/migration/:id/pause', async (c) => {
  try {
    const migrationId = c.req.param('id');
    const { reason } = await c.req.json();
    const env = c.env;

    const id = env.MIGRATION_EXECUTOR.idFromName(migrationId);
    const obj = env.MIGRATION_EXECUTOR.get(id);

    const response = await obj.fetch('http://migration/pause', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason })
    });

    const result = await response.json();

    return c.json(result);
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 400);
  }
});

migration.post('/migration/:id/resume', async (c) => {
  try {
    const migrationId = c.req.param('id');
    const env = c.env;

    const id = env.MIGRATION_EXECUTOR.idFromName(migrationId);
    const obj = env.MIGRATION_EXECUTOR.get(id);

    const response = await obj.fetch('http://migration/resume', {
      method: 'POST'
    });

    const result = await response.json();

    return c.json(result);
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 400);
  }
});

migration.post('/migration/:id/cancel', async (c) => {
  try {
    const migrationId = c.req.param('id');
    const { reason } = await c.req.json();
    const env = c.env;

    const id = env.MIGRATION_EXECUTOR.idFromName(migrationId);
    const obj = env.MIGRATION_EXECUTOR.get(id);

    const response = await obj.fetch('http://migration/cancel', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason })
    });

    const result = await response.json();

    return c.json(result);
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 400);
  }
});

migration.get('/migration/:id/status', async (c) => {
  try {
    const migrationId = c.req.param('id');
    const env = c.env;

    const progressTracker = new ProgressTracker(env);
    const state = await progressTracker.getMigrationState(migrationId);

    if (!state) {
      return c.json({ error: 'Migration not found' }, 404);
    }

    return c.json({ state });
  } catch (error) {
    return c.json({
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 400);
  }
});

migration.get('/migration/:id/progress', async (c) => {
  try {
    const migrationId = c.req.param('id');
    const env = c.env;

    const progressTracker = new ProgressTracker(env);
    const report = await progressTracker.generateProgressReport(migrationId);

    return c.json(report);
  } catch (error) {
    return c.json({
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 400);
  }
});

migration.get('/migration/:id/audit', async (c) => {
  try {
    const migrationId = c.req.param('id');
    const limit = parseInt(c.req.query('limit') || '50');
    const env = c.env;

    const progressTracker = new ProgressTracker(env);
    const auditLog = await progressTracker.getAuditLog(migrationId, limit);

    return c.json({ auditLog });
  } catch (error) {
    return c.json({
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 400);
  }
});

migration.get('/migrations', async (c) => {
  try {
    const env = c.env;

    const progressTracker = new ProgressTracker(env);
    const migrations = await progressTracker.getAllMigrationStates();

    return c.json({ migrations });
  } catch (error) {
    return c.json({
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 400);
  }
});

migration.post('/migration/:id/rollback', async (c) => {
  try {
    const migrationId = c.req.param('id');
    const { snapshotId, reason } = await c.req.json();
    const env = c.env;

    const rollbackManager = new RollbackManager(env);
    const result = await rollbackManager.rollback(migrationId, snapshotId, reason);

    return c.json(result);
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 400);
  }
});

migration.get('/migration/:id/snapshots', async (c) => {
  try {
    const migrationId = c.req.param('id');
    const env = c.env;

    const rollbackManager = new RollbackManager(env);
    const snapshots = await rollbackManager.listSnapshots(migrationId);

    return c.json({ snapshots });
  } catch (error) {
    return c.json({
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 400);
  }
});

migration.post('/migration/:id/test', async (c) => {
  try {
    const migrationId = c.req.param('id');
    const { testType, options } = await c.req.json();
    const env = c.env;

    // Get migration request
    const migrationData = await env.MIGRATION_KV?.get(`migration:${migrationId}`);
    if (!migrationData) {
      return c.json({ error: 'Migration not found' }, 404);
    }

    const { request } = JSON.parse(migrationData);

    const tester = new MigrationTester(env);
    let result;

    switch (testType) {
      case 'dry-run':
        result = await tester.performDryRun(request, options);
        break;
      case 'sample':
        result = await tester.runSampleTest(request, options);
        break;
      case 'performance':
        result = await tester.runPerformanceTest(request, options);
        break;
      case 'validation':
        result = await tester.validateMigrationRequest(request);
        break;
      default:
        throw new Error(`Unknown test type: ${testType}`);
    }

    return c.json(result);
  } catch (error) {
    return c.json({
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 400);
  }
});

migration.get('/migration/:id/stream', async (c) => {
  try {
    const migrationId = c.req.param('id');
    const env = c.env;

    // Set up Server-Sent Events for real-time progress updates
    const headers = new Headers({
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Cache-Control'
    });

    const progressTracker = new ProgressTracker(env);

    const stream = new ReadableStream({
      start(controller) {
        // Subscribe to progress updates
        const callback = (event: any) => {
          const data = `data: ${JSON.stringify(event)}\n\n`;
          controller.enqueue(new TextEncoder().encode(data));
        };

        progressTracker.subscribeTo(migrationId, callback);

        // Send initial state
        progressTracker.getMigrationState(migrationId).then(state => {
          if (state) {
            const data = `data: ${JSON.stringify({ type: 'state', data: state })}\n\n`;
            controller.enqueue(new TextEncoder().encode(data));
          }
        });

        // Clean up on close
        const cleanup = () => {
          progressTracker.unsubscribeFrom(migrationId, callback);
        };

        // Set up cleanup timer (close after 1 hour)
        setTimeout(() => {
          cleanup();
          controller.close();
        }, 3600000);
      },

      cancel() {
        // Cleanup will happen automatically
      }
    });

    return new Response(stream, { headers });
  } catch (error) {
    return c.json({
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 400);
  }
});

export default migration;