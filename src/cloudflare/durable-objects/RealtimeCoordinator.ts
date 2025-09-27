/**
 * REALTIME COORDINATOR - Durable Object
 * Production-ready real-time coordination using Durable Objects
 * Handles WebSocket connections, real-time updates, and state synchronization
 */

import type { DurableObject, DurableObjectState, AnalyticsEngineDataset } from '../types/cloudflare';

interface BroadcastRequest {
  roomId: string;
  message: any;
  excludeUserId?: string;
}

export class RealtimeCoordinator implements DurableObject {
  private state: DurableObjectState;
  private env: Env;
  private connections: Map<string, WebSocket>;
  private rooms: Map<string, Set<string>>;
  private userSessions: Map<string, UserSession>;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
    this.connections = new Map();
    this.rooms = new Map();
    this.userSessions = new Map();
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      switch (path) {
        case '/ws':
          return this.handleWebSocket(request);
        case '/broadcast':
          return this.handleBroadcast(request);
        case '/rooms':
          return this.handleRooms(request);
        case '/users':
          return this.handleUsers(request);
        default:
          return new Response('Not Found', { status: 404 });
      }
    } catch (error: any) {
      return new Response('Internal Server Error', { status: 500 });
    }
  }

  /**
   * Handle WebSocket connections
   */
  private async handleWebSocket(request: Request): Promise<Response> {
    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader !== 'websocket') {
      return new Response('Expected Upgrade: websocket', { status: 426 });
    }

    const url = new URL(request.url);
    const userId = url.searchParams.get('userId');
    const roomId = url.searchParams.get('roomId');

    if (!userId || !roomId) {
      return new Response('Missing userId or roomId', { status: 400 });
    }

    // Create WebSocket pair
    const [client, server] = Object.values(new WebSocketPair());

    // Accept the connection
    server.accept();

    // Store connection
    const connectionId = `${userId}_${Date.now()}`;
    this.connections.set(connectionId, server);

    // Add user to room
    if (!this.rooms.has(roomId)) {
      this.rooms.set(roomId, new Set());
    }
    this.rooms.get(roomId)!.add(connectionId);

    // Store user session
    this.userSessions.set(connectionId, {
      userId,
      roomId,
      connectedAt: new Date(),
      lastActivity: new Date()
    });

    // Set up event handlers
    server.addEventListener('message', (event) => {
      this.handleMessage(connectionId, event.data);
    });

    server.addEventListener('close', () => {
      this.handleDisconnection(connectionId);
    });

    server.addEventListener('error', (error) => {
      this.handleDisconnection(connectionId);
    });

    // Send welcome message
    server.send(JSON.stringify({
      type: 'connected',
      connectionId,
      roomId,
      timestamp: new Date().toISOString()
    }));

    // Notify others in room
    await this.broadcastToRoom(roomId, {
      type: 'user_joined',
      userId,
      timestamp: new Date().toISOString()
    }, connectionId);

    // Track analytics
    await this.trackEvent('websocket_connected', {
      userId,
      roomId,
      connectionId
    });

    return new Response(null, {
      status: 101,
      webSocket: client
    } as any);
  }

  /**
   * Handle incoming WebSocket messages
   */
  private async handleMessage(connectionId: string, message: any): Promise<void> {
    try {
      const data = typeof message === 'string' ? JSON.parse(message) : message;
      const session = this.userSessions.get(connectionId);

      if (!session) {
        return;
      }

      // Update last activity
      session.lastActivity = new Date();

      switch (data.type) {
        case 'ping':
          await this.sendToConnection(connectionId, {
            type: 'pong',
            timestamp: new Date().toISOString()
          });
          break;

        case 'room_message':
          await this.handleRoomMessage(connectionId, data);
          break;

        case 'private_message':
          await this.handlePrivateMessage(connectionId, data);
          break;

        case 'status_update':
          await this.handleStatusUpdate(connectionId, data);
          break;

        case 'typing':
          await this.handleTypingIndicator(connectionId, data);
          break;

        default:
      }

      // Track message analytics
      await this.trackEvent('websocket_message', {
        type: data.type,
        userId: session.userId,
        roomId: session.roomId
      });

    } catch (error: any) {
    }
  }

  /**
   * Handle room messages
   */
  private async handleRoomMessage(connectionId: string, data: any): Promise<void> {
    const session = this.userSessions.get(connectionId);
    if (!session) return;

    const message = {
      type: 'room_message',
      messageId: crypto.randomUUID(),
      userId: session.userId,
      roomId: session.roomId,
      content: data.content,
      timestamp: new Date().toISOString()
    };

    // Store message in state
    await this.state.storage.put(`message:${message.messageId}`, message);

    // Broadcast to room
    await this.broadcastToRoom(session.roomId, message, connectionId);
  }

  /**
   * Handle private messages
   */
  private async handlePrivateMessage(connectionId: string, data: any): Promise<void> {
    const session = this.userSessions.get(connectionId);
    if (!session) return;

    const message = {
      type: 'private_message',
      messageId: crypto.randomUUID(),
      fromUserId: session.userId,
      toUserId: data.toUserId,
      content: data.content,
      timestamp: new Date().toISOString()
    };

    // Find target user's connections
    const targetConnections = Array.from(this.userSessions.entries())
      .filter(([_, userSession]) => userSession.userId === data.toUserId)
      .map(([connId, _]) => connId);

    // Send to all target user's connections
    for (const targetConnectionId of targetConnections) {
      await this.sendToConnection(targetConnectionId, message);
    }

    // Send confirmation to sender
    await this.sendToConnection(connectionId, {
      type: 'message_sent',
      messageId: message.messageId,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Handle status updates
   */
  private async handleStatusUpdate(connectionId: string, data: any): Promise<void> {
    const session = this.userSessions.get(connectionId);
    if (!session) return;

    const statusUpdate = {
      type: 'status_update',
      userId: session.userId,
      status: data.status,
      timestamp: new Date().toISOString()
    };

    // Broadcast to room
    await this.broadcastToRoom(session.roomId, statusUpdate, connectionId);
  }

  /**
   * Handle typing indicators
   */
  private async handleTypingIndicator(connectionId: string, data: any): Promise<void> {
    const session = this.userSessions.get(connectionId);
    if (!session) return;

    const typingUpdate = {
      type: 'typing',
      userId: session.userId,
      isTyping: data.isTyping,
      timestamp: new Date().toISOString()
    };

    // Broadcast to room (excluding sender)
    await this.broadcastToRoom(session.roomId, typingUpdate, connectionId);
  }

  /**
   * Handle user disconnection
   */
  private async handleDisconnection(connectionId: string): Promise<void> {
    const session = this.userSessions.get(connectionId);

    if (session) {
      // Remove from room
      const room = this.rooms.get(session.roomId);
      if (room) {
        room.delete(connectionId);
        if (room.size === 0) {
          this.rooms.delete(session.roomId);
        }
      }

      // Notify others in room
      await this.broadcastToRoom(session.roomId, {
        type: 'user_left',
        userId: session.userId,
        timestamp: new Date().toISOString()
      });

      // Track analytics
      await this.trackEvent('websocket_disconnected', {
        userId: session.userId,
        roomId: session.roomId,
        connectionId,
        duration: Date.now() - session.connectedAt.getTime()
      });

      // Clean up
      this.userSessions.delete(connectionId);
    }

    this.connections.delete(connectionId);
  }

  /**
   * Handle broadcast requests
   */
  private async handleBroadcast(request: Request): Promise<Response> {
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    const data = await request.json<BroadcastRequest>();
    const { roomId, message, excludeUserId } = data;

    if (!roomId || !message) {
      return new Response('Missing roomId or message', { status: 400 });
    }

    const excludeConnectionId = excludeUserId ?
      Array.from(this.userSessions.entries())
        .find(([_, session]) => session.userId === excludeUserId)?.[0] :
      undefined;

    const broadcastCount = await this.broadcastToRoom(roomId, message, excludeConnectionId);

    return new Response(JSON.stringify({
      success: true,
      broadcastCount,
      timestamp: new Date().toISOString()
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  /**
   * Handle room information requests
   */
  private async handleRooms(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const roomId = url.searchParams.get('roomId');

    if (roomId) {
      // Get specific room info
      const room = this.rooms.get(roomId);
      const users = room ? Array.from(room)
        .map((connectionId: any) => this.userSessions.get(connectionId))
        .filter((session: any) => session)
        .map((session: any) => ({
          userId: session!.userId,
          connectedAt: session!.connectedAt,
          lastActivity: session!.lastActivity
        })) : [];

      return new Response(JSON.stringify({
        roomId,
        userCount: users.length,
        users
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } else {
      // Get all rooms
      const roomsInfo = Array.from(this.rooms.entries()).map(([roomId, connections]) => ({
        roomId,
        userCount: connections.size,
        users: Array.from(connections)
          .map((connectionId: any) => this.userSessions.get(connectionId)?.userId)
          .filter((userId: any) => userId)
      }));

      return new Response(JSON.stringify({
        totalRooms: roomsInfo.length,
        rooms: roomsInfo
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  /**
   * Handle user information requests
   */
  private async handleUsers(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const userId = url.searchParams.get('userId');

    if (userId) {
      // Get specific user info
      const userConnections = Array.from(this.userSessions.entries())
        .filter(([_, session]) => session.userId === userId)
        .map(([connectionId, session]) => ({
          connectionId,
          roomId: session.roomId,
          connectedAt: session.connectedAt,
          lastActivity: session.lastActivity
        }));

      return new Response(JSON.stringify({
        userId,
        connections: userConnections,
        isOnline: userConnections.length > 0
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } else {
      // Get all users
      const users = Array.from(this.userSessions.values())
        .reduce((acc, session) => {
          if (!acc[session.userId]) {
            acc[session.userId] = {
              userId: session.userId,
              rooms: new Set(),
              connections: 0,
              firstConnected: session.connectedAt,
              lastActivity: session.lastActivity
            };
          }
          acc[session.userId].rooms.add(session.roomId);
          acc[session.userId].connections++;
          if (session.lastActivity > acc[session.userId].lastActivity) {
            acc[session.userId].lastActivity = session.lastActivity;
          }
          return acc;
        }, {} as Record<string, any>);

      const usersArray = Object.values(users).map((user: any) => ({
        ...user,
        rooms: Array.from(user.rooms)
      }));

      return new Response(JSON.stringify({
        totalUsers: usersArray.length,
        users: usersArray
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  /**
   * Broadcast message to room
   */
  private async broadcastToRoom(
    roomId: string,
    message: any,
    excludeConnectionId?: string
  ): Promise<number> {
    const room = this.rooms.get(roomId);
    if (!room) return 0;

    let broadcastCount = 0;

    for (const connectionId of Array.from(room)) {
      if (connectionId !== excludeConnectionId) {
        const sent = await this.sendToConnection(connectionId, message);
        if (sent) broadcastCount++;
      }
    }

    return broadcastCount;
  }

  /**
   * Send message to specific connection
   */
  private async sendToConnection(connectionId: string, message: any): Promise<boolean> {
    const connection = this.connections.get(connectionId);
    if (!connection) return false;

    try {
      connection.send(JSON.stringify(message));
      return true;
    } catch (error: any) {
      // Clean up dead connection
      this.handleDisconnection(connectionId);
      return false;
    }
  }

  /**
   * Track analytics events
   */
  private async trackEvent(event: string, data: any): Promise<void> {
    try {
      await this.env.ANALYTICS?.writeDataPoint({
        blobs: [event, this.env.ENVIRONMENT || 'unknown'],
        doubles: [Date.now(), data.duration || 0],
        indexes: [event]
      });
    } catch (error: any) {
      // Don't let analytics failures break functionality
    }
  }

  /**
   * Cleanup old connections and messages
   */
  async alarm(): Promise<void> {

    const now = Date.now();
    const INACTIVE_THRESHOLD = 30 * 60 * 1000; // 30 minutes

    // Clean up inactive connections
    for (const [connectionId, session] of Array.from(this.userSessions.entries())) {
      if (now - session.lastActivity.getTime() > INACTIVE_THRESHOLD) {
        await this.handleDisconnection(connectionId);
      }
    }

    // Clean up old messages (keep last 1000 messages)
    const messageKeys = await this.state.storage.list({ prefix: 'message:' });
    if (messageKeys.size > 1000) {
      const keysToDelete = Array.from(messageKeys.keys()).slice(0, messageKeys.size - 1000);
      await this.state.storage.delete(keysToDelete);
    }

    // Schedule next cleanup
    await this.state.setAlarm(Date.now() + 60 * 60 * 1000); // 1 hour
  }
}

// Type definitions
interface UserSession {
  userId: string;
  roomId: string;
  connectedAt: Date;
  lastActivity: Date;
}

interface Env {
  ENVIRONMENT?: string;
  ANALYTICS?: AnalyticsEngineDataset;
}

// Type definitions
interface UserSession {
  userId: string;
  roomId: string;
  connectedAt: Date;
  lastActivity: Date;
}

interface Env {
  ENVIRONMENT?: string;
  ANALYTICS?: AnalyticsEngineDataset;
}