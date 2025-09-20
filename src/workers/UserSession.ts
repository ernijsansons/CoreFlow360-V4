import { DurableObject } from 'cloudflare:workers';

export class UserSession extends DurableObject {
  private sessions: Map<string, any> = new Map();

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'GET' && path === '/session') {
      const sessionId = url.searchParams.get('id');
      if (!sessionId) {
        return new Response('Session ID required', { status: 400 });
      }

      const session = this.sessions.get(sessionId);
      return new Response(JSON.stringify(session || null), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (request.method === 'POST' && path === '/session') {
      const body = await request.json() as { id: string; data: any };
      this.sessions.set(body.id, {
        ...body.data,
        lastActive: Date.now(),
      });

      return new Response(JSON.stringify({ success: true }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (request.method === 'DELETE' && path === '/session') {
      const sessionId = url.searchParams.get('id');
      if (!sessionId) {
        return new Response('Session ID required', { status: 400 });
      }

      this.sessions.delete(sessionId);
      return new Response(JSON.stringify({ success: true }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response('Method not allowed', { status: 405 });
  }
}