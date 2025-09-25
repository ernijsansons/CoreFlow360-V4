// src/realtime/websocket-service.ts
import type { DurableObjectNamespace } from '../cloudflare/types/cloudflare';
import type { RealtimeMessage } from './coordinator';

export interface WebSocketConfig {
  businessId: string;
  userId?: string;
  sessionId?: string;
  channels?: string[];
}

export // TODO: Consider splitting WebSocketService into smaller, focused classes
class WebSocketService {
  public readonly businessId: string;

  constructor(
    private realtimeNamespace: DurableObjectNamespace,
    businessId: string
  ) {
    this.businessId = businessId;
  }

  // Create WebSocket connection URL
  createConnectionUrl(config: WebSocketConfig): string {
    const params = new URLSearchParams();
    params.set('business', config.businessId);

    if (config.userId) params.set('user', config.userId);
    if (config.sessionId) params.set('session', config.sessionId);

    return `/realtime/connect?${params.toString()}`;
  }

  // Get Durable Object instance for business
  private getCoordinatorId(businessId: string): DurableObjectId {
    return this.realtimeNamespace.idFromName(`business:${businessId}`);
  }

  // Broadcast message to business
  async broadcastToBusiness(businessId: string, message: RealtimeMessage): Promise<void> {
    const id = this.getCoordinatorId(businessId);
    const coordinator = this.realtimeNamespace.get(id);

    await coordinator.fetch(new Request('https://coordinator/broadcast', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...message,
        channel: `business:${businessId}`
      })
    }));
  }

  // Broadcast to specific channel
  async broadcastToChannel(businessId: string, channel: string, message: RealtimeMessage): Promise<void> {
    const id = this.getCoordinatorId(businessId);
    const coordinator = this.realtimeNamespace.get(id);

    await coordinator.fetch(new Request('https://coordinator/broadcast', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...message,
        channel: `${businessId}:${channel}`
      })
    }));
  }

  // Send direct message to user
  async sendToUser(businessId: string, userId: string, message: RealtimeMessage): Promise<void> {
    const id = this.getCoordinatorId(businessId);
    const coordinator = this.realtimeNamespace.get(id);

    await coordinator.fetch(new Request('https://coordinator/broadcast', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...message,
        channel: `user:${userId}`
      })
    }));
  }

  // Get realtime statistics
  async getStats(businessId: string): Promise<any> {
    const id = this.getCoordinatorId(businessId);
    const coordinator = this.realtimeNamespace.get(id);

    const response = await coordinator.fetch(new Request('https://coordinator/status'));
    return await response.json();
  }

  // Common realtime event helpers
  async notifyDataUpdate(businessId: string, table: string, operation: string, data: any): Promise<void> {
    await this.broadcastToChannel(businessId, 'data-updates', {
      type: 'broadcast',
      data: {
        table,
        operation,
        data,
        timestamp: Date.now()
      }
    });
  }

  async notifyUserActivity(businessId: string, userId: string, activity: string, metadata?: any): Promise<void> {
    await this.broadcastToChannel(businessId, 'user-activity', {
      type: 'broadcast',
      data: {
        userId,
        activity,
        metadata,
        timestamp: Date.now()
      }
    });
  }

  async notifySystemEvent(businessId: string, event: string, data: any): Promise<void> {
    await this.broadcastToChannel(businessId, 'system-events', {
      type: 'broadcast',
      data: {
        event,
        data,
        timestamp: Date.now()
      }
    });
  }

  async notifyAIResponse(businessId: string, userId: string, requestId: string, response: any): Promise<void> {
    await this.broadcastToChannel(businessId, 'ai-responses', {
      type: 'broadcast',
      data: {
        userId,
        requestId,
        response,
        timestamp: Date.now()
      }
    });
  }

  async notifyWorkflowUpdate(businessId: string, workflowId: string, status: string, progress?: number): Promise<void> {
    await this.broadcastToChannel(businessId, 'workflow-updates', {
      type: 'broadcast',
      data: {
        workflowId,
        status,
        progress,
        timestamp: Date.now()
      }
    });
  }

  async notifyAnalyticsUpdate(businessId: string, metrics: any): Promise<void> {
    await this.broadcastToChannel(businessId, 'analytics-updates', {
      type: 'broadcast',
      data: {
        metrics,
        timestamp: Date.now()
      }
    });
  }
}

// Factory function
export function createWebSocketService(
  realtimeNamespace: DurableObjectNamespace,
  businessId: string
): WebSocketService {
  return new WebSocketService(realtimeNamespace, businessId);
}