// CoreFlow360 V4 - Analytics Dashboard API
// Exposes Cloudflare Analytics Engine data for monitoring

import { Hono } from 'hono';
import type { HonoContext } from '../types/env';

const app = new Hono<HonoContext>();

/**
 * Get real-time analytics overview
 * Returns key metrics from Cloudflare Analytics Engine
 */
app.get('/overview', async (c: any) => {
  try {
    const analyticsEngine = c.env.ANALYTICS_ENGINE;

    if (!analyticsEngine) {
      return c.json({
        error: 'Analytics Engine not available',
        message: 'Analytics Engine binding is not configured in wrangler.toml'
      }, 503);
    }

    // Calculate time windows
    const now = Date.now();
    const last24h = now - (24 * 60 * 60 * 1000);
    const last7d = now - (7 * 24 * 60 * 60 * 1000);

    // Query analytics data (note: actual queries depend on what data was written)
    // This is a template - adjust based on actual analytics schema
    const overview = {
      timestamp: new Date().toISOString(),
      period: {
        last24h: new Date(last24h).toISOString(),
        last7d: new Date(last7d).toISOString(),
      },
      metrics: {
        // These would be populated from actual Analytics Engine queries
        totalRequests: 0,
        avgResponseTime: 0,
        errorRate: 0,
        cacheHitRate: 0,
        activeUsers: 0,
      },
      performance: {
        p50ResponseTime: 0,
        p95ResponseTime: 0,
        p99ResponseTime: 0,
      },
      topEndpoints: [],
      topErrors: [],
    };

    return c.json({
      success: true,
      data: overview,
      message: 'Analytics dashboard requires GraphQL API access to Cloudflare Analytics',
      note: 'Use Cloudflare GraphQL API for detailed analytics queries'
    });

  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * Get performance metrics
 * Returns response time, throughput, and error rate metrics
 */
app.get('/performance', async (c: any) => {
  try {
    const analyticsEngine = c.env.ANALYTICS_ENGINE;

    if (!analyticsEngine) {
      return c.json({
        error: 'Analytics Engine not available'
      }, 503);
    }

    // Performance metrics would be queried from Analytics Engine
    const performance = {
      timestamp: new Date().toISOString(),
      responseTime: {
        p50: 0,
        p95: 0,
        p99: 0,
        avg: 0,
      },
      throughput: {
        requestsPerSecond: 0,
        requestsPerMinute: 0,
        requestsPerHour: 0,
      },
      errors: {
        total: 0,
        rate: 0,
        byType: {},
      },
    };

    return c.json({
      success: true,
      data: performance,
      message: 'Use Cloudflare GraphQL API for detailed performance analytics'
    });

  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * Get geographic distribution
 * Returns request distribution by country/region
 */
app.get('/geographic', async (c: any) => {
  try {
    const analyticsEngine = c.env.ANALYTICS_ENGINE;

    if (!analyticsEngine) {
      return c.json({
        error: 'Analytics Engine not available'
      }, 503);
    }

    // Geographic data from Analytics Engine
    const geographic = {
      timestamp: new Date().toISOString(),
      byCountry: [],
      byRegion: [],
      byDatacenter: [],
    };

    return c.json({
      success: true,
      data: geographic,
      message: 'Geographic analytics available via Cloudflare Dashboard or GraphQL API'
    });

  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * Write custom analytics event
 * Allows writing custom metrics to Analytics Engine
 */
app.post('/event', async (c: any) => {
  try {
    const analyticsEngine = c.env.ANALYTICS_ENGINE;

    if (!analyticsEngine) {
      return c.json({
        error: 'Analytics Engine not available'
      }, 503);
    }

    const body = await c.req.json();
    const { eventType, value, metadata = {} } = body;

    if (!eventType || value === undefined) {
      return c.json({
        error: 'Missing required fields: eventType, value'
      }, 400);
    }

    // Write to Analytics Engine
    analyticsEngine.writeDataPoint({
      blobs: [eventType, metadata.category || 'custom', metadata.label || ''],
      doubles: [Date.now(), value],
      indexes: [metadata.index || 'events'],
    });

    return c.json({
      success: true,
      message: 'Event written to Analytics Engine',
      event: { eventType, value, timestamp: new Date().toISOString() }
    });

  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * Get Cloudflare Analytics Dashboard URL
 * Returns direct link to Cloudflare Analytics Dashboard
 */
app.get('/dashboard-url', async (c: any) => {
  const accountId = c.env.CLOUDFLARE_ACCOUNT_ID || 'd2897bdebfa128919bd89b265e6a712e';
  const workerId = c.env.CLOUDFLARE_WORKER_ID || 'coreflow360-v4-prod';

  return c.json({
    success: true,
    dashboardUrls: {
      analytics: `https://dash.cloudflare.com/${accountId}/workers/services/view/${workerId}/production/analytics`,
      logs: `https://dash.cloudflare.com/${accountId}/workers/services/view/${workerId}/production/logs`,
      performance: `https://dash.cloudflare.com/${accountId}/workers/services/view/${workerId}/production/performance`,
      health: `https://dash.cloudflare.com/${accountId}/workers/services/view/${workerId}/production/health`,
    },
    message: 'Access full analytics via Cloudflare Dashboard'
  });
});

export default app;
