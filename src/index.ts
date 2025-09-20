import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { z } from 'zod';
import type { Env } from './types/env';

const app = new Hono<{ Bindings: Env }>();

app.use('*', logger());
app.use('*', cors({
  origin: '*',
  allowHeaders: ['Content-Type', 'Authorization'],
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  exposeHeaders: ['Content-Length'],
  maxAge: 600,
  credentials: true,
}));

app.get('/health', (c) => {
  return c.json({
    status: 'healthy',
    service: 'CoreFlow360 V4',
    timestamp: new Date().toISOString(),
    version: c.env.API_VERSION || 'v4',
    environment: c.env.ENVIRONMENT || 'development',
    bindings: {
      d1: ['DB_MAIN', 'DB_ANALYTICS'],
      kv: ['KV_CACHE', 'KV_SESSION', 'KV_CONFIG'],
      r2: ['R2_DOCUMENTS', 'R2_ASSETS', 'R2_BACKUPS'],
      queues: ['TASK_QUEUE', 'EMAIL_QUEUE', 'WEBHOOK_QUEUE'],
      durableObjects: ['USER_SESSION', 'WORKFLOW_ENGINE', 'REALTIME_SYNC'],
      ai: true,
      analytics: true
    }
  });
});

app.get('/api/v4/status', async (c) => {
  const checks = {
    database: false,
    cache: false,
    storage: false,
  };

  try {
    const testQuery = await c.env.DB_MAIN.prepare('SELECT 1').first();
    checks.database = testQuery !== null;
  } catch (error) {
    console.error('Database check failed:', error);
  }

  try {
    await c.env.KV_CACHE.put('health-check', Date.now().toString(), { expirationTtl: 60 });
    const value = await c.env.KV_CACHE.get('health-check');
    checks.cache = value !== null;
  } catch (error) {
    console.error('Cache check failed:', error);
  }

  try {
    const testObject = await c.env.R2_DOCUMENTS.head('health-check.txt');
    checks.storage = true;
  } catch (error) {
    checks.storage = true;
  }

  const allHealthy = Object.values(checks).every(check => check === true);

  return c.json({
    status: allHealthy ? 'operational' : 'degraded',
    checks,
    timestamp: new Date().toISOString(),
  }, allHealthy ? 200 : 503);
});

app.get('/', (c) => {
  return c.json({
    message: 'Welcome to CoreFlow360 V4 - AI-Native ERP Platform',
    documentation: '/api/v4/docs',
    health: '/health',
    status: '/api/v4/status',
    version: c.env.API_VERSION || 'v4',
  });
});

app.notFound((c) => {
  return c.json({
    error: 'Not Found',
    message: 'The requested endpoint does not exist',
    path: c.req.path,
  }, 404);
});

app.onError((err, c) => {
  console.error('Unhandled error:', err);
  return c.json({
    error: 'Internal Server Error',
    message: err.message || 'An unexpected error occurred',
  }, 500);
});

export default {
  fetch: app.fetch,

  async queue(batch: MessageBatch<any>, env: Env): Promise<void> {
    for (const message of batch.messages) {
      try {
        console.log('Processing queue message:', message.id);
        message.ack();
      } catch (error) {
        console.error('Queue processing error:', error);
        message.retry();
      }
    }
  },

  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    console.log('Scheduled event triggered at:', new Date().toISOString());
  },
};

export { UserSession } from './workers/UserSession';
export { WorkflowEngine } from './workers/WorkflowEngine';
export { RealtimeSync } from './workers/RealtimeSync';