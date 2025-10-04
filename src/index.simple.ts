// Simple Cloudflare Worker without external dependencies

// Use canonical Env type
import type { Env } from './types/env';

// Re-export canonical type
export type { Env } from './types/env';

// Export Durable Object class
export class AdvancedRateLimiterDO {
  state: DurableObjectState;

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const key = request.headers.get('CF-Connecting-IP') || 'unknown';
    const now = Date.now();
    const windowMs = 60000;

    const requests = await this.state.storage.get(key) as number[] || [];
    const recentRequests = requests.filter((time: number) => now - time < windowMs);

    if (recentRequests.length >= 60) {
      return new Response(JSON.stringify({
        allowed: false,
        resetTime: Math.ceil((recentRequests[0] + windowMs - now) / 1000)
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    recentRequests.push(now);
    await this.state.storage.put(key, recentRequests);

    return new Response(JSON.stringify({ allowed: true }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// Route handlers
const routes: Record<string, (request: Request, env: Env) => Response | Promise<Response>> = {
  '/health': () => {
    return new Response(JSON.stringify({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      environment: 'development'
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  },

  '/api/status': () => {
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
  },

  '/design-system': () => {
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
  },

  '/docker/status': () => {
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
        ]
      }
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Main fetch handler
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // Simple CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    };

    // Handle OPTIONS requests
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    try {
      // Find handler
      const handler = routes[path];

      if (handler) {
        const response = await handler(request, env);

        // Add CORS headers to response
        const newHeaders = new Headers(response.headers);
        Object.entries(corsHeaders).forEach(([key, value]) => {
          newHeaders.set(key, value);
        });

        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: newHeaders
        });
      }

      // 404 Not Found
      return new Response(JSON.stringify({
        error: 'Not Found',
        message: `The endpoint ${path} does not exist`
      }), {
        status: 404,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });

    } catch (error: any) {
      console.error('Worker error:', error);
      return new Response(JSON.stringify({
        error: 'Internal Server Error',
        message: error.message || 'An unexpected error occurred',
        path
      }), {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });
    }
  }
};