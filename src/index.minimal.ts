// Minimal Cloudflare Worker Entry Point
import { Router } from 'itty-router';

export interface Env {
  DB: D1Database;
  CACHE: KVNamespace;
  R2_DOCUMENTS: R2Bucket;
  R2_ASSETS: R2Bucket;
  ANALYTICS: AnalyticsEngineDataset;
  REALTIME: DurableObjectNamespace;
  AI: Ai;
  TASK_QUEUE: Queue;
  EMAIL_QUEUE: Queue;
  WEBHOOK_QUEUE: Queue;
  JWT_SECRET: string;
  ANTHROPIC_API_KEY: string;
  EMAIL_API_KEY: string;
  API_BASE_URL: string;
  ENVIRONMENT: string;
  ALLOWED_ORIGINS: string;
}

const router = Router();

// Health check endpoint
router.get('/health', () => {
  return new Response(JSON.stringify({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    environment: 'staging'
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
});

// API status endpoint
router.get('/api/status', () => {
  return new Response(JSON.stringify({
    service: 'CoreFlow360 V4',
    version: '4.0.0',
    status: 'operational',
    features: [
      'Enterprise Docker Setup',
      'Revolutionary Design System',
      'Cloudflare Workers Integration',
      'MCP Server Support',
      'Security Hardening',
      'Performance Monitoring'
    ]
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
});

// Design system endpoint
router.get('/design-system', () => {
  return new Response(JSON.stringify({
    name: 'The Future of Enterprise Design System',
    version: '1.0.0',
    description: 'Revolutionary enterprise design system with AI-powered interfaces',
    features: [
      'Radical Reduction: 3 gray shades, 2 font weights, zero shadows',
      'Invisible Intelligence: AI that anticipates without intruding',
      'Universal Command Bar: Natural language control',
      'Hover Intelligence: Progressive disclosure',
      'Universal Undo: Every action reversible',
      'Mobile-First Enterprise: Full power in pocket'
    ],
    components: 30,
    performance: '<100KB bundle, 100/100 Lighthouse ready',
    accessibility: 'WCAG 2.2 AA compliant'
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
});

// Docker integration status
router.get('/docker/status', () => {
  return new Response(JSON.stringify({
    docker: {
      status: 'configured',
      services: [
        'app:3000',
        'frontend:3001', 
        'postgres:5432',
        'redis:6379',
        'prometheus:9090',
        'grafana:3002',
        'loki:3100',
        'nginx:80',
        'mcp-server:8080'
      ],
      networks: [
        'frontend',
        'backend', 
        'monitoring',
        'mcp'
      ],
      security: [
        'read-only containers',
        'non-root users',
        'network isolation',
        'resource limits',
        'health checks'
      ]
    }
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
});

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

// Handle CORS preflight
router.options('*', () => {
  return new Response(null, { headers: corsHeaders });
});

// 404 handler
router.all('*', () => {
  return new Response(JSON.stringify({
    error: 'Not Found',
    message: 'The requested resource was not found',
    availableEndpoints: [
      '/health',
      '/api/status', 
      '/design-system',
      '/docker/status'
    ]
  }), {
    status: 404,
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
});

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      const response = await router.handle(request, env, ctx);
      return response || new Response('Not Found', { status: 404 });
    } catch (error) {
      console.error('Worker error:', error);
      return new Response(JSON.stringify({
        error: 'Internal Server Error',
        message: 'An unexpected error occurred'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
};
