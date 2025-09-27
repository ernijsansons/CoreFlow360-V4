// Ultra-minimal Cloudflare Worker for testing
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

    return new Response(JSON.stringify({
      error: 'Not Found',
      path: url.pathname
    }), {
      status: 404,
      headers
    });
  }
};