// Comprehensive development backend with all routes imported directly
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import type { Env } from './types/env';

// Import all route modules directly
import authRoutes from './routes/auth-dev';
import dashboardRoutes from './routes/dashboard';
import crmRoutes from './routes/crm';
import financeRoutes from './routes/finance';
import agentsRoutes from './routes/agents';
import chatRoutes from './routes/chat';
import bankingRoutes from './routes/banking';
import documentsRoutes from './routes/documents';
import reconciliationRoutes from './routes/reconciliation';
import anomaliesRoutes from './routes/anomalies';
import migrationRoutes from './routes/migration';
import aiMonitoringRoutes from './routes/ai-monitoring';import { Logger } from "./shared/logger";
const logger = new Logger({ component: "indexdev-simple" });



const app = new Hono<{ Bindings: Env }>();

// CORS middleware - allow all localhost ports for development
app.use('*', cors({
  origin: (origin) => {
    // Allow all localhost and 127.0.0.1 origins in development
    if (!origin || origin.startsWith('http://localhost:') || origin.startsWith('http://127.0.0.1:')) {
      return origin || '*';
    }
    return null;
  },
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Business-ID', 'X-User-ID'],
  credentials: true
}));

// Health check
app.get('/health', (c) => {
  return c.json({
    status: 'healthy',
    service: 'CoreFlow360 V4 Dev (All Routes)',
    timestamp: new Date().toISOString(),
    environment: c.env.ENVIRONMENT || 'development'
  });
});

// API status
app.get('/api/status', (c) => {
  return c.json({
    service: 'CoreFlow360 V4 Dev',
    version: '4.0.0',
    status: 'operational',
    environment: c.env.ENVIRONMENT || 'development',
    endpoints: 'All business logic routes mounted'
  });
});

// Stub endpoints for missing routes (before main route mounting)
// Finance stubs
app.get('/api/finance/invoices', (c) => c.json({ success: true, data: [] }));
app.get('/api/finance/expenses', (c) => c.json({ success: true, data: [] }));
app.get('/api/finance/transactions', (c) => c.json({ success: true, data: [] }));
app.get('/api/finance/ledger', (c) => c.json({ success: true, data: [] }));
app.get('/api/finance/reports', (c) => c.json({ success: true, data: [] }));

// CRM stubs
app.get('/api/crm/deals', (c) => c.json({ success: true, data: [] }));
app.get('/api/crm/pipeline', (c) => c.json({ success: true, data: [] }));

// Agent stubs
app.get('/api/agents', (c) => c.json({ success: true, data: [] }));
app.get('/api/agents/status', (c) => c.json({ success: true, data: { status: 'operational', agents: [] } }));

// Chat stubs
app.get('/api/chat/messages', (c) => c.json({ success: true, data: [] }));
app.post('/api/chat/send', (c) => c.json({ success: true, data: { id: 'msg_1', sent: true } }, 201));

// Dashboard stubs
app.get('/api/dashboard/metrics', (c) => c.json({ success: true, data: {} }));

// Migration stubs
app.get('/api/migration/status', (c) => c.json({ success: true, data: { status: 'idle' } }));

// AI Monitoring stubs
app.get('/api/ai-monitoring/metrics', (c) => c.json({ success: true, data: {} }));

// Auth stubs
app.post('/api/auth/logout', (c) => c.json({ success: true }, 200));
app.post('/api/auth/refresh', (c) => c.json({ success: true, token: 'refreshed_token' }, 200));

// Reconciliation stub
app.get('/api/reconciliation', (c) => c.json({ success: true, data: { reconciliations: [] } }));

// Documents upload stub (before auth middleware)
app.post('/api/documents/upload', (c) => c.json({
  success: true,
  data: {
    document_id: 'doc_test',
    document_type: 'invoice'
  }
}, 201));

// Mount all routes directly under /api/*
// This bypasses the /v1 prefix issue
app.route('/api/auth', authRoutes);
app.route('/api/dashboard', dashboardRoutes);
app.route('/api/crm', crmRoutes);
app.route('/api/finance', financeRoutes);
app.route('/api/agents', agentsRoutes);
app.route('/api/chat', chatRoutes);
app.route('/api/banking', bankingRoutes);
app.route('/api/documents', documentsRoutes);
app.route('/api/reconciliation', reconciliationRoutes);
app.route('/api/anomalies', anomaliesRoutes);
app.route('/api/migration', migrationRoutes);
app.route('/api/ai-monitoring', aiMonitoringRoutes);

// Mock endpoints for remaining routes
app.get('/api/entities', (c) => {
  return c.json({
    success: true,
    data: []
  });
});

app.get('/api/export', (c) => {
  return c.json({
    success: true,
    data: { exports: [] }
  });
});

app.get('/api/data-quality', (c) => {
  return c.json({
    success: true,
    data: { score: 95, issues: [] }
  });
});

// 404 handler
app.notFound((c) => {
  return c.json({
    error: 'Not Found',
    path: c.req.path,
    method: c.req.method,
    message: `Endpoint ${c.req.method} ${c.req.path} not found`
  }, 404);
});

// Error handler
app.onError((err, c) => {
  logger.error('❌ Error:', err);
  return c.json({
    error: 'Internal server error',
    message: err.message,
    path: c.req.path
  }, 500);
});

export default app;
