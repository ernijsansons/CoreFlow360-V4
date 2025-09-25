// src/realtime/coordinator.ts
import type { DurableObjectState, DurableObject } from '../cloudflare/types/cloudflare';

export interface RealtimeMessage {
  type: 'subscribe' | 'unsubscribe' | 'broadcast' | 'direct' | 'ping' | 'pong';
  channel?: string;
  target?: string;
  data?: any;
  timestamp?: number;
  sessionId?: string;
}

export interface SessionInfo {
  id: string;
  businessId: string;
  userId?: string;
  channels: Set<string>;
  lastSeen: number;
  metadata?: Record<string, any>;
}

export class RealtimeCoordinator implements DurableObject {
  private sessions: Map<string, WebSocket> = new Map();
  private sessionInfo: Map<string, SessionInfo> = new Map();
  private channels: Map<string, Set<string>> = new Map();
  private state: DurableObjectState;

  constructor(state: DurableObjectState) {
    this.state = state;
    this.initializeFromStorage();
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const upgradeHeader = request.headers.get('Upgrade');

    if (upgradeHeader === 'websocket') {
      const pair = new WebSocketPair();
      await this.handleSession(pair[1], request);
      return new Response(null, {
        status: 101,
        webSocket: pair[0]
      });
    }

    // Handle HTTP requests for coordinator management
    if (request.method === 'GET' && url.pathname === '/status') {
      return this.getStatus();
    }

    if (request.method === 'POST' && url.pathname === '/broadcast') {
      const message = await request.json();
      await this.handleBroadcast(message);
      return new Response(JSON.stringify({ success: true }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response('Expected WebSocket or valid HTTP endpoint', { status: 400 });
  }

  async handleSession(ws: WebSocket, request: Request): Promise<void> {
    const url = new URL(request.url);
    const sessionId = url.searchParams.get('session') || this.generateSessionId();
    const businessId = url.searchParams.get('business') || 'default';
    const userId = url.searchParams.get('user');

    try {
      ws.accept();

      // Initialize session
      const sessionInfo: SessionInfo = {
        id: sessionId,
        businessId,
        userId,
        channels: new Set(),
        lastSeen: Date.now(),
        metadata: {}
      };

      this.sessions.set(sessionId, ws);
      this.sessionInfo.set(sessionId, sessionInfo);

      // Send connection confirmation
      await this.sendToSession(sessionId, {
        type: 'ping',
        data: { sessionId, connected: true },
        timestamp: Date.now()
      });

      ws.addEventListener('message', async (event) => {
        try {
          const message: RealtimeMessage = JSON.parse(event.data as string);
          message.sessionId = sessionId;
          message.timestamp = Date.now();

          // Update last seen
          const info = this.sessionInfo.get(sessionId);
          if (info) {
            info.lastSeen = Date.now();
          }

          await this.handleMessage(sessionId, message);
        } catch (error) {
          await this.sendToSession(sessionId, {
            type: 'broadcast',
            data: { error: 'Invalid message format' }
          });
        }
      });

      ws.addEventListener('close', async () => {
        await this.cleanupSession(sessionId);
      });

      ws.addEventListener('error', async (event) => {
        await this.cleanupSession(sessionId);
      });

      // Persist session info
      await this.persistSessionInfo();

    } catch (error) {
      ws.close(1011, 'Session initialization failed');
    }
  }

  async handleMessage(sessionId: string, message: RealtimeMessage): Promise<void> {
    switch (message.type) {
      case 'subscribe':
        await this.handleSubscribe(sessionId, message);
        break;
      case 'unsubscribe':
        await this.handleUnsubscribe(sessionId, message);
        break;
      case 'broadcast':
        await this.handleBroadcast(message);
        break;
      case 'direct':
        await this.handleDirect(message);
        break;
      case 'ping':
        await this.handlePing(sessionId);
        break;
      default:
    }
  }

  async handleSubscribe(sessionId: string, message: RealtimeMessage): Promise<void> {
    const channel = message.channel;
    if (!channel) return;

    const sessionInfo = this.sessionInfo.get(sessionId);
    if (!sessionInfo) return;

    // Add session to channel
    sessionInfo.channels.add(channel);

    if (!this.channels.has(channel)) {
      this.channels.set(channel, new Set());
    }
    this.channels.get(channel)!.add(sessionId);

    // Confirm subscription
    await this.sendToSession(sessionId, {
      type: 'broadcast',
      data: {
        subscribed: channel,
        channels: Array.from(sessionInfo.channels)
      }
    });

    await this.persistChannelInfo();
  }

  async handleUnsubscribe(sessionId: string, message: RealtimeMessage): Promise<void> {
    const channel = message.channel;
    if (!channel) return;

    const sessionInfo = this.sessionInfo.get(sessionId);
    if (!sessionInfo) return;

    // Remove session from channel
    sessionInfo.channels.delete(channel);

    const channelSessions = this.channels.get(channel);
    if (channelSessions) {
      channelSessions.delete(sessionId);
      if (channelSessions.size === 0) {
        this.channels.delete(channel);
      }
    }

    // Confirm unsubscription
    await this.sendToSession(sessionId, {
      type: 'broadcast',
      data: {
        unsubscribed: channel,
        channels: Array.from(sessionInfo.channels)
      }
    });

    await this.persistChannelInfo();
  }

  // Efficient broadcasting to all sessions
  async handleBroadcast(message: RealtimeMessage): Promise<void> {
    const channel = message.channel;
    const data = JSON.stringify({
      ...message,
      timestamp: message.timestamp || Date.now()
    });

    if (channel) {
      // Broadcast to specific channel
      const channelSessions = this.channels.get(channel);
      if (channelSessions) {
        await Promise.allSettled(
          Array.from(channelSessions).map(sessionId => {
            const ws = this.sessions.get(sessionId);
            return ws ? this.safeWebSocketSend(ws, data) : Promise.resolve();
          })
        );
      }
    } else {
      // Broadcast to all sessions
      await Promise.allSettled(
        Array.from(this.sessions.values()).map(ws =>
          this.safeWebSocketSend(ws, data)
        )
      );
    }
  }

  async handleDirect(message: RealtimeMessage): Promise<void> {
    const targetSessionId = message.target;
    if (!targetSessionId) return;

    const data = JSON.stringify({
      ...message,
      timestamp: message.timestamp || Date.now()
    });

    const targetWs = this.sessions.get(targetSessionId);
    if (targetWs) {
      await this.safeWebSocketSend(targetWs, data);
    }
  }

  async handlePing(sessionId: string): Promise<void> {
    await this.sendToSession(sessionId, {
      type: 'pong',
      timestamp: Date.now()
    });
  }

  async sendToSession(sessionId: string, message: RealtimeMessage): Promise<void> {
    const ws = this.sessions.get(sessionId);
    if (ws) {
      const data = JSON.stringify({
        ...message,
        timestamp: message.timestamp || Date.now()
      });
      await this.safeWebSocketSend(ws, data);
    }
  }

  async safeWebSocketSend(ws: WebSocket, data: string): Promise<void> {
    try {
      if (ws.readyState === ws.OPEN) {
        ws.send(data);
      }
    } catch (error) {
    }
  }

  async cleanupSession(sessionId: string): Promise<void> {
    // Remove from all channels
    const sessionInfo = this.sessionInfo.get(sessionId);
    if (sessionInfo) {
      for (const channel of sessionInfo.channels) {
        const channelSessions = this.channels.get(channel);
        if (channelSessions) {
          channelSessions.delete(sessionId);
          if (channelSessions.size === 0) {
            this.channels.delete(channel);
          }
        }
      }
    }

    // Clean up session data
    this.sessions.delete(sessionId);
    this.sessionInfo.delete(sessionId);

    // Persist changes
    await this.persistSessionInfo();
    await this.persistChannelInfo();
  }

  // Business-specific broadcasting
  async broadcastToBusiness(businessId: string, message: RealtimeMessage): Promise<void> {
    const businessSessions = Array.from(this.sessionInfo.entries())
      .filter(([_, info]) => info.businessId === businessId)
      .map(([sessionId, _]) => sessionId);

    const data = JSON.stringify({
      ...message,
      timestamp: Date.now()
    });

    await Promise.allSettled(
      businessSessions.map(sessionId => {
        const ws = this.sessions.get(sessionId);
        return ws ? this.safeWebSocketSend(ws, data) : Promise.resolve();
      })
    );
  }

  // User-specific broadcasting
  async broadcastToUser(userId: string, message: RealtimeMessage): Promise<void> {
    const userSessions = Array.from(this.sessionInfo.entries())
      .filter(([_, info]) => info.userId === userId)
      .map(([sessionId, _]) => sessionId);

    const data = JSON.stringify({
      ...message,
      timestamp: Date.now()
    });

    await Promise.allSettled(
      userSessions.map(sessionId => {
        const ws = this.sessions.get(sessionId);
        return ws ? this.safeWebSocketSend(ws, data) : Promise.resolve();
      })
    );
  }

  // Status and metrics
  getStatus(): Response {
    const stats = {
      totalSessions: this.sessions.size,
      totalChannels: this.channels.size,
      channelDistribution: Object.fromEntries(
        Array.from(this.channels.entries()).map(([channel, sessions]) => [
          channel,
          sessions.size
        ])
      ),
      businessDistribution: this.getBusinessDistribution(),
      uptime: Date.now() - (this.state.storage?.alarm?.scheduledTime || Date.now())
    };

    return new Response(JSON.stringify(stats), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  private getBusinessDistribution(): Record<string, number> {
    const distribution: Record<string, number> = {};
    for (const info of this.sessionInfo.values()) {
      distribution[info.businessId] = (distribution[info.businessId] || 0) + 1;
    }
    return distribution;
  }

  // Persistence methods
  private async initializeFromStorage(): Promise<void> {
    try {
      const storedChannels = await this.state.storage.get('channels');
      if (storedChannels) {
        this.channels = new Map(storedChannels as any);
      }
    } catch (error) {
    }
  }

  private async persistSessionInfo(): Promise<void> {
    try {
      const sessionData = Array.from(this.sessionInfo.entries()).map(([id, info]) => [
        id,
        {
          ...info,
          channels: Array.from(info.channels)
        }
      ]);
      await this.state.storage.put('sessions', sessionData);
    } catch (error) {
    }
  }

  private async persistChannelInfo(): Promise<void> {
    try {
      const channelData = Array.from(this.channels.entries()).map(([channel, sessions]) => [
        channel,
        Array.from(sessions)
      ]);
      await this.state.storage.put('channels', channelData);
    } catch (error) {
    }
  }

  private generateSessionId(): string {
    return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Cleanup stale sessions (called periodically)
  async cleanup(): Promise<void> {
    const now = Date.now();
    const staleThreshold = 5 * 60 * 1000; // 5 minutes

    const staleSessions = Array.from(this.sessionInfo.entries())
      .filter(([_, info]) => now - info.lastSeen > staleThreshold)
      .map(([sessionId, _]) => sessionId);

    for (const sessionId of staleSessions) {
      await this.cleanupSession(sessionId);
    }
  }

  // Alarm handler for periodic cleanup
  async alarm(): Promise<void> {
    await this.cleanup();

    // Schedule next cleanup in 5 minutes
    await this.state.storage.setAlarm(Date.now() + 5 * 60 * 1000);
  }
}

// Export the Durable Object class
export { RealtimeCoordinator as default };