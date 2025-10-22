import { Hono } from 'hono';
import type { Env } from '../types/env';
import { RateLimitConfigs } from '../security/advanced-rate-limiter';

const rateLimiting = new Hono<{ Bindings: Env }>();

rateLimiting.get('/', (c) => {
  return c.json({
    success: true,
    limits: RateLimitConfigs,
  });
});

rateLimiting.get('/status', (c) => {
  const hasKvMetrics = Boolean(c.env.KV_RATE_LIMIT_METRICS);
  const hasDurableObject = Boolean((c.env as any).RATE_LIMITER_DO);

  return c.json({
    success: true,
    kvMetricsConfigured: hasKvMetrics,
    durableObjectConfigured: hasDurableObject,
  });
});

rateLimiting.get('/metrics', async (c) => {
  if (!c.env.KV_RATE_LIMIT_METRICS) {
    return c.json({
      success: false,
      error: 'KV_RATE_LIMIT_METRICS namespace not configured',
    }, 503);
  }

  try {
    const rawStats = await c.env.KV_RATE_LIMIT_METRICS.get('global:stats', 'json') as Record<string, unknown> | null;

    return c.json({
      success: true,
      metrics: rawStats ?? {},
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error?.message || 'Unable to read rate limiting metrics',
    }, 500);
  }
});

export default rateLimiting;
