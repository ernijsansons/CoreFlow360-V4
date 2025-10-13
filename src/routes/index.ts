// @ts-nocheck
/**
 * Central Route Aggregator
 * Combines all Hono route applications for integration with main application
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { compress } from 'hono/compress';
import { secureHeaders } from 'hono/secure-headers';

// Import all route modules
import authRoutes from './auth';
import businessRoutes from './business';
import crmRoutes from './crm';
import financeRoutes from './finance';
import invoiceRoutes from './invoices';
import paymentRoutes from './payments';
import agentRoutes from './agents';
import chatRoutes from './chat';
// import webhookRoutes from './webhooks';
// import voiceAgentRoutes from './voice-agent'; // Exports function, not Hono app
// import learningRoutes from './learning';
// import learningDashboardRoutes from './learning-dashboard';
import leadIngestionRoutes from './lead-ingestion';
import enrichmentRoutes from './enrichment';
// import exportRoutes from './export'; // Uses Express - not compatible with Workers
import migrationRoutes from './migration';
// import dataIntegrityRoutes from './data-integrity';
import abacRoutes from './abac';
import aiAuditRoutes from './ai-audit';
import aiMonitoringRoutes from './ai-monitoring';
import observabilityRoutes from './observability';
import rateLimitingRoutes from './rate-limiting';

// Priority 1 routes - High usage
import dashboardRoutes from './dashboard';
import bankingRoutes from './banking';
import documentsRoutes from './documents';
import reconciliationRoutes from './reconciliation';
import anomaliesRoutes from './anomalies';

// Priority 2 routes - Medium usage
import crmDataQualityRoutes from './crm-data-quality';
import crmIntegrationsRoutes from './crm-integrations';
import currencyRoutes from './currency';
import plaidRoutes from './plaid';
import subscriptionsRoutes from './subscriptions';

// Priority 3 routes - Low usage/Optional
import conversationLogsRoutes from './conversation-logs';
import crmV2Routes from './crm-v2';

import type { Env } from '../types/env';

// Create main API app with middleware
const api = new Hono<{ Bindings: Env }>();

// Global middleware
api.use('*', logger());
api.use('*', compress());
api.use('*', secureHeaders());

// CORS configuration
api.use('*', cors({
  origin: (origin) => {
    const allowedOrigins = [
      'https://app.coreflow360.com',
      'https://dashboard.coreflow360.com',
      'https://api.coreflow360.com',
      'https://main.coreflow360-frontend.pages.dev',
      'https://coreflow360-frontend.pages.dev',
      'http://localhost:3000',
      'http://localhost:5173'
    ];
    const wildcardOrigins = ['*.coreflow360-frontend.pages.dev'];

    const isAllowedOrigin = (value: string | undefined | null): value is string => {
      if (!value) return false;
      if (allowedOrigins.includes(value)) return true;

      try {
        const { hostname } = new URL(value);
        return wildcardOrigins.some(pattern => {
          if (!pattern.startsWith('*.')) return false;
          const domain = pattern.substring(2);
          return hostname.endsWith(domain);
        });
      } catch {
        return false;
      }
    };

    return isAllowedOrigin(origin) ? origin : allowedOrigins[0];
  },
  credentials: true,
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Business-ID', 'X-User-ID', 'X-Request-ID'],
  exposeHeaders: ['X-Request-ID', 'X-Response-Time'],
  maxAge: 86400
}));

// Health check endpoint
api.get('/health', (c) => {
  return c.json({
    success: true,
    service: 'coreflow360-api',
    status: 'operational',
    version: 'v4.0.0',
    timestamp: new Date().toISOString()
  });
});

// API version prefix
const v1 = new Hono<{ Bindings: Env }>();

// Mount all route modules under v1
v1.route('/auth', authRoutes);
v1.route('/business', businessRoutes);
v1.route('/crm', crmRoutes);
v1.route('/finance', financeRoutes);
v1.route('/invoices', invoiceRoutes);
v1.route('/payments', paymentRoutes);
v1.route('/agents', agentRoutes);
v1.route('/chat', chatRoutes);
// v1.route('/webhooks', webhookRoutes);
// v1.route('/voice-agents', voiceAgentRoutes); // Exports function, not Hono app
// v1.route('/learning', learningRoutes);
// v1.route('/learning-dashboard', learningDashboardRoutes);
v1.route('/lead-ingestion', leadIngestionRoutes);
v1.route('/enrichment', enrichmentRoutes);
// v1.route('/export', exportRoutes); // Uses Express - not compatible with Workers
v1.route('/migration', migrationRoutes);
// v1.route('/data-integrity', dataIntegrityRoutes);
v1.route('/abac', abacRoutes);
v1.route('/ai-audit', aiAuditRoutes);
v1.route('/ai-monitoring', aiMonitoringRoutes);
v1.route('/observability', observabilityRoutes);
v1.route('/rate-limiting', rateLimitingRoutes);

// Priority 1 routes - High usage
v1.route('/dashboard', dashboardRoutes);
v1.route('/banking', bankingRoutes);
v1.route('/documents', documentsRoutes);
v1.route('/reconciliation', reconciliationRoutes);
v1.route('/anomalies', anomaliesRoutes);

// Priority 2 routes - Medium usage
v1.route('/crm-data-quality', crmDataQualityRoutes);
v1.route('/crm-integrations', crmIntegrationsRoutes);
v1.route('/currency', currencyRoutes);
v1.route('/plaid', plaidRoutes);
v1.route('/subscriptions', subscriptionsRoutes);

// Priority 3 routes - Low usage/Optional
v1.route('/conversation-logs', conversationLogsRoutes);
v1.route('/crm-v2', crmV2Routes);

// Mount v1 under /api/v1
api.route('/v1', v1);

// Default 404 handler
api.all('*', (c) => {
  return c.json({
    success: false,
    error: 'Route not found',
    path: c.req.path,
    method: c.req.method
  }, 404);
});

// Error handler
api.onError((err, c) => {
  console.error('API Error:', err);

  return c.json({
    success: false,
    error: err.message || 'Internal server error',
    requestId: c.req.header('X-Request-ID'),
    timestamp: new Date().toISOString()
  }, err.status || 500);
});

export default api;

/**
 * Helper function to integrate with itty-router in main index.ts
 * Converts Hono app to a standard Request handler
 */
export async function handleAPIRequest(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  return api.fetch(request, env, ctx);
}
