import { DurableObject } from 'cloudflare:workers';

interface SyncMessage {
  id: string;
  type: 'update' | 'delete' | 'create';
  entity: string;
  data: any;
  timestamp: number;
  userId?: string;
}

export class RealtimeSync extends DurableObject {
  private connections: Map<string, WebSocket> = new Map();
  private messageHistory: SyncMessage[] = [];
  private readonly MAX_HISTORY = 100;
  private readonly MAX_CONNECTIONS = 1000;
  private readonly CONNECTION_TIMEOUT = 5 * 60 * 1000; // 5 minutes
  private connectionTimestamps: Map<string, number> = new Map();
  private messageCount = 0;
  private readonly MESSAGE_RATE_LIMIT = 100; // messages per second
  private lastRateLimitReset = Date.now();

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/websocket') {
      // Check connection limit
      if (this.connections.size >= this.MAX_CONNECTIONS) {
        return new Response('Connection limit reached', { status: 503 });
      }

      const upgradeHeader = request.headers.get('Upgrade');
      if (upgradeHeader !== 'websocket') {
        return new Response('Expected websocket', { status: 400 });
      }

      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);

      const clientId = crypto.randomUUID();
      this.handleWebSocket(server, clientId);

      return new Response(null, {
        status: 101,
        webSocket: client,
      });
    }

    if (request.method === 'POST' && url.pathname === '/broadcast') {
      try {
        // Rate limiting
        const now = Date.now();
        if (now - this.lastRateLimitReset > 1000) {
          this.messageCount = 0;
          this.lastRateLimitReset = now;
        }

        if (this.messageCount >= this.MESSAGE_RATE_LIMIT) {
          return new Response('Rate limit exceeded', { status: 429 });
        }

        const message = await request.json() as SyncMessage;
        message.timestamp = Date.now();
        message.id = crypto.randomUUID();

        this.messageHistory.push(message);
        if (this.messageHistory.length > this.MAX_HISTORY) {
          this.messageHistory.shift();
        }

        this.broadcast(message);
        this.messageCount++;

        return new Response(JSON.stringify({ success: true, messageId: message.id }), {
          headers: { 'Content-Type': 'application/json' },
        });
      } catch (error: any) {
        return new Response(JSON.stringify({ error: 'Invalid message format' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }

    if (request.method === 'GET' && url.pathname === '/history') {
      const since = url.searchParams.get('since');
      const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
      const sinceTimestamp = since ? parseInt(since) : 0;

      const relevantMessages = this.messageHistory
        .filter((msg: any) => msg.timestamp > sinceTimestamp)
        .slice(-limit);

      return new Response(JSON.stringify(relevantMessages), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (request.method === 'GET' && url.pathname === '/connections') {
      // Clean up stale connections
      this.cleanupStaleConnections();

      return new Response(JSON.stringify({
        count: this.connections.size,
        maxConnections: this.MAX_CONNECTIONS,
        connectionIds: Array.from(this.connections.keys()).slice(0, 100), // Limit exposed IDs
      }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response('Not found', { status: 404 });
  }

  private handleWebSocket(ws: WebSocket, clientId: string): void {
    try {
      ws.accept();
      this.connections.set(clientId, ws);
      this.connectionTimestamps.set(clientId, Date.now());

      // Send limited history on connect
      ws.send(JSON.stringify({
        type: 'connected',
        clientId,
        history: this.messageHistory.slice(-10),
      }));

      ws.addEventListener('message', async (event: any) => {
        try {
          // Update activity timestamp
          this.connectionTimestamps.set(clientId, Date.now());

          const data = JSON.parse(event.data as string);

          if (data.type === 'ping') {
            ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
            return;
          }

          // Rate limiting per client
          if (this.messageCount >= this.MESSAGE_RATE_LIMIT) {
            ws.send(JSON.stringify({
              type: 'error',
              message: 'Rate limit exceeded',
            }));
            return;
          }

          const message: SyncMessage = {
            ...data,
            id: crypto.randomUUID(),
            timestamp: Date.now(),
          };

          this.messageHistory.push(message);
          if (this.messageHistory.length > this.MAX_HISTORY) {
            this.messageHistory.shift();
          }

          this.broadcast(message, clientId);
          this.messageCount++;
        } catch (error: any) {
          ws.send(JSON.stringify({
            type: 'error',
            message: 'Invalid message format',
          }));
        }
      });

      ws.addEventListener('close', () => {
        this.connections.delete(clientId);
        this.connectionTimestamps.delete(clientId);
        this.broadcast({
          id: crypto.randomUUID(),
          type: 'update',
          entity: 'connection',
          data: { clientId, status: 'disconnected' },
          timestamp: Date.now(),
        });
      });

      ws.addEventListener('error', (error) => {
        this.connections.delete(clientId);
        this.connectionTimestamps.delete(clientId);
      });
    } catch (error: any) {
      ws.close(1011, 'Internal server error');
    }
  }

  private broadcast(message: SyncMessage, excludeClientId?: string): void {
    const messageString = JSON.stringify(message);
    const deadConnections: string[] = [];

    this.connections.forEach((ws, clientId) => {
      if (clientId !== excludeClientId) {
        try {
          ws.send(messageString);
        } catch (error: any) {
          deadConnections.push(clientId);
        }
      }
    });

    // Clean up dead connections
    deadConnections.forEach((clientId: any) => {
      this.connections.delete(clientId);
      this.connectionTimestamps.delete(clientId);
    });
  }

  private cleanupStaleConnections(): void {
    const now = Date.now();
    const staleConnections: string[] = [];

    this.connectionTimestamps.forEach((timestamp, clientId) => {
      if (now - timestamp > this.CONNECTION_TIMEOUT) {
        staleConnections.push(clientId);
      }
    });

    staleConnections.forEach((clientId: any) => {
      const ws = this.connections.get(clientId);
      if (ws) {
        try {
          ws.close(1000, 'Connection timeout');
        } catch {}
      }
      this.connections.delete(clientId);
      this.connectionTimestamps.delete(clientId);
    });
  }
}