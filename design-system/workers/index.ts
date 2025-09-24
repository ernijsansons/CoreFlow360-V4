/**
 * Cloudflare Workers Edge Handler
 * Serves the design system with edge optimization
 */

import { Router } from 'itty-router';
import { createCors } from 'itty-cors';

export interface Env {
  CACHE: KVNamespace;
  ASSETS: R2Bucket;
  DB: D1Database;
  ANALYTICS: AnalyticsEngineDataset;
  ANALYTICS_QUEUE: Queue;
  FIGMA_TOKEN: string;
  API_KEY: string;
  JWT_SECRET: string;
}

// CORS configuration
const { preflight, corsify } = createCors({
  origins: ['*'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  headers: {
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  },
});

// Create router
const router = Router();

// Apply CORS preflight to all routes
router.all('*', preflight);

// Health check
router.get('/health', () => {
  return new Response(JSON.stringify({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'design-system',
  }), {
    headers: { 'Content-Type': 'application/json' },
  });
});

// Serve static assets with caching
router.get('/assets/*', async (request: Request, env: Env) => {
  const url = new URL(request.url);
  const key = url.pathname.slice(1);

  // Try cache first
  const cached = await env.CACHE.get(key, 'stream');
  if (cached) {
    return new Response(cached, {
      headers: {
        'Content-Type': getContentType(key),
        'Cache-Control': 'public, max-age=31536000, immutable',
      },
    });
  }

  // Fetch from R2
  const object = await env.ASSETS.get(key);
  if (!object) {
    return new Response('Not Found', { status: 404 });
  }

  // Cache for future requests
  await env.CACHE.put(key, await object.arrayBuffer(), {
    expirationTtl: 86400, // 24 hours
  });

  return new Response(object.body, {
    headers: {
      'Content-Type': getContentType(key),
      'Cache-Control': 'public, max-age=31536000, immutable',
      'ETag': object.etag,
    },
  });
});

// API endpoint for design tokens
router.get('/api/tokens', async (request: Request, env: Env) => {
  const cached = await env.CACHE.get('design-tokens', 'json');
  if (cached) {
    return new Response(JSON.stringify(cached), {
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=3600',
      },
    });
  }

  // Fetch latest tokens from Figma
  const tokens = await fetchFigmaTokens(env.FIGMA_TOKEN);

  // Cache for 1 hour
  await env.CACHE.put('design-tokens', JSON.stringify(tokens), {
    expirationTtl: 3600,
  });

  return new Response(JSON.stringify(tokens), {
    headers: { 'Content-Type': 'application/json' },
  });
});

// Figma webhook endpoint
router.post('/api/figma-webhook', async (request: Request, env: Env) => {
  const signature = request.headers.get('X-Figma-Signature');

  // Verify webhook signature
  if (!verifyFigmaSignature(signature, await request.text(), env.FIGMA_TOKEN)) {
    return new Response('Unauthorized', { status: 401 });
  }

  // Queue for processing
  await env.ANALYTICS_QUEUE.send({
    type: 'figma_update',
    timestamp: new Date().toISOString(),
    data: await request.json(),
  });

  // Invalidate cache
  await env.CACHE.delete('design-tokens');

  return new Response('OK', { status: 200 });
});

// Analytics endpoint
router.post('/api/analytics', async (request: Request, env: Env) => {
  const data = await request.json();

  // Write to Analytics Engine
  env.ANALYTICS.writeDataPoint({
    blobs: [data.event],
    doubles: [data.value || 1],
    indexes: [data.component || 'unknown'],
  });

  // Queue for batch processing
  await env.ANALYTICS_QUEUE.send({
    type: 'analytics',
    timestamp: new Date().toISOString(),
    data,
  });

  return new Response('OK', { status: 200 });
});

// Component usage metrics
router.get('/api/metrics/:component', async (request: Request, env: Env) => {
  const { component } = request.params;

  // Query from D1
  const { results } = await env.DB.prepare(
    'SELECT * FROM component_usage WHERE name = ? ORDER BY timestamp DESC LIMIT 100'
  ).bind(component).all();

  return new Response(JSON.stringify(results), {
    headers: { 'Content-Type': 'application/json' },
  });
});

// Playground data API
router.get('/api/playground/data', async (request: Request, env: Env) => {
  return new Response(JSON.stringify({
    deals: [
      {
        id: '1',
        company: 'Acme Corp',
        amount: 125000,
        stage: 'negotiation',
        daysInStage: 3,
        probability: 80,
      },
      {
        id: '2',
        company: 'TechStart Inc',
        amount: 85000,
        stage: 'proposal',
        daysInStage: 5,
        probability: 60,
      },
    ],
    metrics: [
      { id: 'revenue', value: 2437650, label: 'Revenue', change: 12.5 },
      { id: 'customers', value: 1284, label: 'Customers', change: 8.3 },
      { id: 'efficiency', value: 94, label: 'Efficiency %', change: 2.1 },
    ],
  }), {
    headers: { 'Content-Type': 'application/json' },
  });
});

// Server-side rendering for SEO
router.get('/*', async (request: Request, env: Env) => {
  const url = new URL(request.url);

  // Check if it's a bot/crawler
  const userAgent = request.headers.get('User-Agent') || '';
  const isBot = /bot|crawl|spider/i.test(userAgent);

  if (isBot) {
    // Return pre-rendered HTML for SEO
    const html = await env.CACHE.get(`ssr:${url.pathname}`, 'text');
    if (html) {
      return new Response(html, {
        headers: { 'Content-Type': 'text/html' },
      });
    }
  }

  // Return SPA for regular users
  const indexHtml = await env.ASSETS.get('index.html');
  if (!indexHtml) {
    return new Response('Not Found', { status: 404 });
  }

  return new Response(indexHtml.body, {
    headers: {
      'Content-Type': 'text/html',
      'Cache-Control': 'public, max-age=3600',
    },
  });
});

// Helper functions
function getContentType(key: string): string {
  const ext = key.split('.').pop()?.toLowerCase();
  const types: Record<string, string> = {
    'js': 'application/javascript',
    'css': 'text/css',
    'html': 'text/html',
    'json': 'application/json',
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'svg': 'image/svg+xml',
    'woff2': 'font/woff2',
    'woff': 'font/woff',
    'ttf': 'font/ttf',
  };
  return types[ext || ''] || 'application/octet-stream';
}

async function fetchFigmaTokens(token: string): Promise<any> {
  const response = await fetch('https://api.figma.com/v1/files/YOUR_FILE_ID/variables/local', {
    headers: {
      'X-Figma-Token': token,
    },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch Figma tokens');
  }

  return response.json();
}

function verifyFigmaSignature(signature: string | null, body: string, secret: string): boolean {
  if (!signature) return false;

  // Implement HMAC verification
  // This is a placeholder - implement actual verification
  return true;
}

// Export handlers
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Log request
    ctx.waitUntil(
      env.ANALYTICS.writeDataPoint({
        blobs: [request.url],
        doubles: [1],
        indexes: [request.method],
      })
    );

    return router
      .handle(request, env, ctx)
      .then(corsify)
      .catch((err: any) => {
        console.error(err);
        return new Response('Internal Server Error', { status: 500 });
      });
  },

  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    // Periodic cache warming
    ctx.waitUntil(warmCache(env));
  },

  async queue(batch: MessageBatch, env: Env): Promise<void> {
    // Process queued messages
    for (const message of batch.messages) {
      const data = message.body as any;

      if (data.type === 'analytics') {
        // Store in D1
        await env.DB.prepare(
          'INSERT INTO analytics (event, component, value, timestamp) VALUES (?, ?, ?, ?)'
        ).bind(data.data.event, data.data.component, data.data.value, data.timestamp).run();
      }

      message.ack();
    }
  },
};

// Cache warming function
async function warmCache(env: Env): Promise<void> {
  const criticalPaths = [
    '/',
    '/dashboard',
    '/analytics',
    '/assets/main.js',
    '/assets/main.css',
  ];

  for (const path of criticalPaths) {
    const key = `cache:${path}`;
    const cached = await env.CACHE.get(key);

    if (!cached) {
      // Pre-render and cache
      // Implementation depends on your rendering strategy
    }
  }
}

// Durable Object for session management
export class SessionManager {
  state: DurableObjectState;
  env: Env;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    switch (url.pathname) {
      case '/create':
        const sessionId = crypto.randomUUID();
        await this.state.storage.put(sessionId, {
          created: Date.now(),
          data: await request.json(),
        });
        return new Response(JSON.stringify({ sessionId }));

      case '/get':
        const id = url.searchParams.get('id');
        if (!id) return new Response('Missing ID', { status: 400 });
        const session = await this.state.storage.get(id);
        return new Response(JSON.stringify(session));

      default:
        return new Response('Not Found', { status: 404 });
    }
  }
}