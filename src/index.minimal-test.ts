// Ultra-minimal Cloudflare Worker for testing

// Export AdvancedRateLimiterDO for Durable Object compatibility
export class AdvancedRateLimiterDO {
  constructor(state: DurableObjectState, env: any) {
    // Minimal implementation for testing
  }
}

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // Basic CORS headers
    const headers = {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers });
    }

    if (url.pathname === '/health') {
      return new Response(JSON.stringify({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        path: url.pathname
      }), { headers });
    }

    if (url.pathname === '/api/status') {
      return new Response(JSON.stringify({
        service: 'CoreFlow360 V4',
        version: '4.0.0',
        status: 'operational'
      }), { headers });
    }

    if (url.pathname === '/' || url.pathname === '') {
      return new Response(JSON.stringify({
        service: 'CoreFlow360 V4 Dev API',
        status: 'online',
        endpoints: {
          health: '/health',
          apiStatus: '/api/status'
        },
        frontend: 'https://1a63671d.coreflow360-frontend.pages.dev/',
        message: 'This workers.dev instance only exposes the lightweight development API. Visit the frontend URL for the UI.'
      }), { headers });
    }

    return new Response(
      JSON.stringify({
        error: 'Not Found',
        path: url.pathname
      }),
      {
        status: 404,
        headers
      }
    );
  }
};
