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

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/websocket') {
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
      const message = await request.json() as SyncMessage;
      message.timestamp = Date.now();
      message.id = crypto.randomUUID();

      this.messageHistory.push(message);
      if (this.messageHistory.length > this.MAX_HISTORY) {
        this.messageHistory.shift();
      }

      this.broadcast(message);
      return new Response(JSON.stringify({ success: true, messageId: message.id }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (request.method === 'GET' && url.pathname === '/history') {
      const since = url.searchParams.get('since');
      const sinceTimestamp = since ? parseInt(since) : 0;

      const relevantMessages = this.messageHistory.filter(
        msg => msg.timestamp > sinceTimestamp
      );

      return new Response(JSON.stringify(relevantMessages), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (request.method === 'GET' && url.pathname === '/connections') {
      return new Response(JSON.stringify({
        count: this.connections.size,
        connectionIds: Array.from(this.connections.keys()),
      }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response('Not found', { status: 404 });
  }

  private handleWebSocket(ws: WebSocket, clientId: string): void {
    ws.accept();
    this.connections.set(clientId, ws);

    ws.send(JSON.stringify({
      type: 'connected',
      clientId,
      history: this.messageHistory.slice(-10),
    }));

    ws.addEventListener('message', (event) => {
      try {
        const data = JSON.parse(event.data as string);

        if (data.type === 'ping') {
          ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
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
      } catch (error) {
        ws.send(JSON.stringify({
          type: 'error',
          message: 'Invalid message format',
        }));
      }
    });

    ws.addEventListener('close', () => {
      this.connections.delete(clientId);
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
    });
  }

  private broadcast(message: SyncMessage, excludeClientId?: string): void {
    const messageString = JSON.stringify(message);

    this.connections.forEach((ws, clientId) => {
      if (clientId !== excludeClientId) {
        try {
          ws.send(messageString);
        } catch (error) {
          this.connections.delete(clientId);
        }
      }
    });
  }
}