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
import webhookRoutes from './webhooks';
import voiceAgentRoutes from './voice-agent';
import learningRoutes from './learning';
import learningDashboardRoutes from './learning-dashboard';
import leadIngestionRoutes from './lead-ingestion';
import enrichmentRoutes from './enrichment';
import exportRoutes from './export';
import migrationRoutes from './migration';
import dataIntegrityRoutes from './data-integrity';
import abacRoutes from './abac';
import aiAuditRoutes from './ai-audit';
import aiMonitoringRoutes from './ai-monitoring';
import observabilityRoutes from './observability';
import rateLimitingRoutes from './rate-limiting';
import usersRoutes from './users';
import inventoryRoutes from './inventory';
import dashboardRoutes from './dashboard';
import searchRoutes from './search';
import settingsRoutes from './settings';

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
      'http://localhost:3000',
      'http://localhost:5173'
    ];
    return allowedOrigins.includes(origin) ? origin : allowedOrigins[0];
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

// Mount all route modules
// These will be accessible at /api/* (without v1 prefix for simplicity)
api.route('/api/auth', authRoutes);
api.route('/api/users', usersRoutes);
api.route('/api/business', businessRoutes);
api.route('/api/crm', crmRoutes);
api.route('/api/finance', financeRoutes);
api.route('/api/invoices', invoiceRoutes);
api.route('/api/payments', paymentRoutes);
api.route('/api/inventory', inventoryRoutes);
api.route('/api/agents', agentRoutes);
api.route('/api/chat', chatRoutes);
api.route('/api/dashboard', dashboardRoutes);
api.route('/api/search', searchRoutes);
api.route('/api/settings', settingsRoutes);
api.route('/api/webhooks', webhookRoutes);
api.route('/api/voice-agents', voiceAgentRoutes);
api.route('/api/learning', learningRoutes);
api.route('/api/learning-dashboard', learningDashboardRoutes);
api.route('/api/lead-ingestion', leadIngestionRoutes);
api.route('/api/enrichment', enrichmentRoutes);
api.route('/api/export', exportRoutes);
api.route('/api/migration', migrationRoutes);
api.route('/api/data-integrity', dataIntegrityRoutes);
api.route('/api/abac', abacRoutes);
api.route('/api/ai-audit', aiAuditRoutes);
api.route('/api/ai-monitoring', aiMonitoringRoutes);
api.route('/api/observability', observabilityRoutes);
api.route('/api/rate-limiting', rateLimitingRoutes);

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