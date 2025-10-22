// Comprehensive development backend with all routes and business logic
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger as honoLogger } from 'hono/logger';
import apiRoutes from './routes/index'; // Import all routes from consolidated routes/index.ts
import type { Env } from './types/env';
import { Logger } from "./shared/logger";
const appLogger = new Logger({ component: "indexdev-full" });

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

// Logger middleware
app.use('*', honoLogger());

// Health check at root level
app.get('/health', (c) => {
  return c.json({
    status: 'healthy',
    service: 'CoreFlow360 V4 Dev (Full Routes)',
    timestamp: new Date().toISOString(),
    environment: c.env.ENVIRONMENT || 'development'
  });
});

// Root status
app.get('/api/status', (c) => {
  return c.json({
    service: 'CoreFlow360 V4 Dev',
    version: '4.0.0',
    status: 'operational',
    environment: c.env.ENVIRONMENT || 'development',
    routes: 'all routes mounted at /api/* (mapped from /v1/*)'
  });
});

// TEST HELPER: Set user role to admin (DEVELOPMENT ONLY!)
app.post('/test-set-admin', async (c) => {
  try {
    const body = await c.req.json();
    const { userId } = body;

    if (!userId) {
      return c.json({ error: 'userId required' }, 400);
    }

    await c.env.DB_MAIN.prepare(
      'UPDATE users SET role = ? WHERE id = ?'
    ).bind('admin', userId).run();

    return c.json({
      success: true,
      message: `User ${userId} role set to admin`,
      warning: 'This endpoint is for TESTING ONLY and should never exist in production!'
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

// Mount the full API routes
// The apiRoutes module mounts everything under /v1
app.route('/', apiRoutes);

// Create route aliases: /api/* → /api/v1/*
// This middleware intercepts /api/* requests and forwards them to /api/v1/*
app.all('/api/:path{.+}', async (c) => {
  const originalPath = c.req.path; // e.g., /api/auth/login

  // Skip if already a /v1 path
  if (originalPath.startsWith('/api/v1/')) {
    // This is already handled by the apiRoutes, let it pass through
    return c.notFound();
  }

  // Skip special endpoints
  if (originalPath === '/api/status' || originalPath === '/api/health') {
    return c.notFound(); // Let dedicated handlers above handle these
  }

  // Map /api/* to /api/v1/*
  const v1Path = originalPath.replace(/^\/api\//, '/api/v1/');

  appLogger.info(`🔄 Routing: ${originalPath} → ${v1Path}`);

  // Create a new URL with the v1 path
  const url = new URL(c.req.url);
  url.pathname = v1Path;

  // Forward the request to the v1 route
  const newRequest = new Request(url.toString(), {
    method: c.req.method,
    headers: c.req.raw.headers,
    body: c.req.raw.body,
    // @ts-ignore
    duplex: 'half'
  });

  return app.fetch(newRequest, c.env, c.executionCtx);
});

// 404 handler
app.notFound((c) => {
  return c.json({
    error: 'Not Found',
    path: c.req.path,
    method: c.req.method,
    message: 'Endpoint not found - check API documentation'
  }, 404);
});

// Error handler
app.onError((err, c) => {
  appLogger.error('❌ Error:', err);
  return c.json({
    error: 'Internal server error',
    message: err.message,
    path: c.req.path
  }, 500);
});

export default app;
