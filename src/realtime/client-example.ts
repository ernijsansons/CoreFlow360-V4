// src/realtime/client-example.ts
// Example WebSocket client for CoreFlow360 V4 realtime features

export class CoreFlowRealtimeClient {
  private ws: WebSocket | null = null;
  private businessId: string;
  private userId?: string;
  private sessionId: string;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;

  constructor(
    private baseUrl: string,
    businessId: string,
    userId?: string
  ) {
    this.businessId = businessId;
    this.userId = userId;
    this.sessionId = this.generateSessionId();
  }

  // Connect to realtime server
  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        const wsUrl = this.buildWebSocketUrl();
        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
          this.reconnectAttempts = 0;
          resolve();
        };

        this.ws.onmessage = (event) => {
          this.handleMessage(JSON.parse(event.data));
        };

        this.ws.onclose = () => {
          this.attemptReconnect();
        };

        this.ws.onerror = (error) => {
          reject(error);
        };

      } catch (error) {
        reject(error);
      }
    });
  }

  // Subscribe to channels
  subscribe(channel: string): void {
    this.send({
      type: 'subscribe',
      channel: `${this.businessId}:${channel}`
    });
  }

  // Unsubscribe from channels
  unsubscribe(channel: string): void {
    this.send({
      type: 'unsubscribe',
      channel: `${this.businessId}:${channel}`
    });
  }

  // Send direct message to user
  sendToUser(userId: string, message: any): void {
    this.send({
      type: 'direct',
      target: userId,
      data: message
    });
  }

  // Broadcast to all business users
  broadcast(message: any): void {
    this.send({
      type: 'broadcast',
      channel: `business:${this.businessId}`,
      data: message
    });
  }

  // Event handlers (override these)
  onDataUpdate(table: string, operation: string, data: any): void {
  }

  onUserActivity(userId: string, activity: string, metadata?: any): void {
  }

  onAIResponse(userId: string, requestId: string, response: any): void {
  }

  onWorkflowUpdate(workflowId: string, status: string, progress?: number): void {
  }

  onSystemEvent(event: string, data: any): void {
  }

  onAnalyticsUpdate(metrics: any): void {
  }

  // Private methods
  private buildWebSocketUrl(): string {
    const params = new URLSearchParams();
    params.set('business', this.businessId);
    params.set('session', this.sessionId);

    if (this.userId) {
      params.set('user', this.userId);
    }

    const protocol = this.baseUrl.startsWith('https') ? 'wss' : 'ws';
    return `${protocol}://${this.baseUrl.replace(/^https?:\/\//, '')}/realtime/connect?${params}`;
  }

  private send(message: any): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    } else {
      // In a real implementation, you might queue messages here
    }
  }

  private handleMessage(message: any): void {
    switch (message.type) {
      case 'ping':
        this.send({ type: 'pong' });
        break;

      case 'broadcast':
        this.handleBroadcast(message);
        break;

      case 'direct':
        this.handleDirect(message);
        break;

      default:
    }
  }

  private handleBroadcast(message: any): void {
    const { data } = message;

    // Handle different broadcast types
    if (data.table && data.operation) {
      this.onDataUpdate(data.table, data.operation, data.data);
    } else if (data.userId && data.activity) {
      this.onUserActivity(data.userId, data.activity, data.metadata);
    } else if (data.requestId && data.response) {
      this.onAIResponse(data.userId, data.requestId, data.response);
    } else if (data.workflowId && data.status) {
      this.onWorkflowUpdate(data.workflowId, data.status, data.progress);
    } else if (data.event) {
      this.onSystemEvent(data.event, data.data);
    } else if (data.metrics) {
      this.onAnalyticsUpdate(data.metrics);
    }
  }

  private handleDirect(message: any): void {
    // Handle direct messages
  }

  private attemptReconnect(): void {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);


      setTimeout(() => {
        this.connect().catch(console.error);
      }, delay);
    } else {
    }
  }

  private generateSessionId(): string {
    return `client_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Cleanup
  disconnect(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }
}

// Usage example:
/*
const client = new CoreFlowRealtimeClient(
  'wss://your-worker.your-subdomain.workers.dev',
  'business-123',
  'user-456'
);

// Custom event handlers
client.onDataUpdate = (table, operation, data) => {
  // Update UI accordingly
};

client.onAIResponse = (userId, requestId, response) => {
  // Update chat interface
};

// Connect and subscribe
await client.connect();
client.subscribe('data-updates');
client.subscribe('ai-responses');
client.subscribe('user-activity');

// Send messages
client.broadcast({ type: 'user-joined', userId: 'user-456' });
client.sendToUser('user-789', { type: 'private-message', content: 'Hello!' });
*/