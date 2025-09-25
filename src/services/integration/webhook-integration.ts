import { EventEmitter } from 'events';
import crypto from 'crypto';

export interface WebhookEvent {
  id: string;
  event: string;
  source: 'agents' | 'coreflow';
  data: any;
  timestamp: Date;
  signature?: string;
  retryCount?: number;
}

export interface WebhookConfig {
  secret: string;
  maxRetries: number;
  retryDelay: number;
  timeout: number;
  endpoints: {
    agents: string;
    coreflow: string;
  };
}

export interface WebhookSubscription {
  id: string;
  event: string;
  url: string;
  active: boolean;
  createdAt: Date;
  lastTriggered?: Date;
  failureCount: number;
}

export class WebhookIntegration extends EventEmitter {
  private config: WebhookConfig;
  private subscriptions: Map<string, WebhookSubscription[]> = new Map();
  private eventQueue: WebhookEvent[] = [];
  private processing: boolean = false;
  private env: any;

  constructor(config?: Partial<WebhookConfig>, env?: any) {
    super();
    this.config = {
      secret: config?.secret || process.env.WEBHOOK_SECRET || crypto.randomBytes(32).toString('hex'),
      maxRetries: config?.maxRetries || 3,
      retryDelay: config?.retryDelay || 5000,
      timeout: config?.timeout || 30000,
      endpoints: {
        agents: config?.endpoints?.agents || `${process.env.AGENT_SYSTEM_URL}/webhooks/coreflow`,
        coreflow: config?.endpoints?.coreflow || `${process.env.COREFLOW_API_URL}/webhooks/agents`
      }
    };
    this.env = env;
  }

  // Event Management
  async emitEvent(event: string, data: any, source: 'agents' | 'coreflow' = 'coreflow'): Promise<void> {
    const webhookEvent: WebhookEvent = {
      id: crypto.randomUUID(),
      event,
      source,
      data,
      timestamp: new Date(),
      retryCount: 0
    };

    // Add signature
    webhookEvent.signature = this.generateSignature(webhookEvent);

    // Add to queue
    this.eventQueue.push(webhookEvent);

    // Process queue if not already processing
    if (!this.processing) {
      await this.processQueue();
    }

    // Emit local event
    this.emit('event', webhookEvent);
  }

  private async processQueue(): Promise<void> {
    if (this.processing || this.eventQueue.length === 0) {
      return;
    }

    this.processing = true;

    while (this.eventQueue.length > 0) {
      const event = this.eventQueue.shift();
      if (!event) continue;

      try {
        await this.deliverEvent(event);
      } catch (error) {
        console.error('Failed to deliver webhook event:', error);
        this.handleDeliveryFailure(event, error);
      }
    }

    this.processing = false;
  }

  private async deliverEvent(event: WebhookEvent): Promise<void> {
    const subscriptions = this.subscriptions.get(event.event) || [];
    const activeSubscriptions = subscriptions.filter(sub => sub.active);

    if (activeSubscriptions.length === 0) {
      console.log(`No active subscriptions for event: ${event.event}`);
      return;
    }

    // Deliver to all active subscriptions
    const deliveryPromises = activeSubscriptions.map(subscription => 
      this.deliverToSubscription(event, subscription)
    );

    await Promise.allSettled(deliveryPromises);
  }

  private async deliverToSubscription(event: WebhookEvent, subscription: WebhookSubscription): Promise<void> {
    try {
      const payload = {
        id: event.id,
        event: event.event,
        source: event.source,
        data: event.data,
        timestamp: event.timestamp.toISOString(),
        signature: event.signature
      };

      const response = await fetch(subscription.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Webhook-Signature': event.signature || '',
          'X-Webhook-Event': event.event,
          'X-Webhook-Source': event.source,
          'User-Agent': 'CoreFlow360-Webhook/1.0'
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(this.config.timeout)
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      // Update subscription stats
      subscription.lastTriggered = new Date();
      subscription.failureCount = 0;

      console.log(`Webhook delivered successfully to ${subscription.url}`);

    } catch (error) {
      console.error(`Failed to deliver webhook to ${subscription.url}:`, error);
      throw error;
    }
  }

  private handleDeliveryFailure(event: WebhookEvent, error: any): void {
    event.retryCount = (event.retryCount || 0) + 1;

    if (event.retryCount < this.config.maxRetries) {
      // Retry after delay
      setTimeout(() => {
        this.eventQueue.push(event);
        if (!this.processing) {
          this.processQueue();
        }
      }, this.config.retryDelay * event.retryCount);
    } else {
      console.error(`Webhook event ${event.id} failed after ${this.config.maxRetries} retries`);
      this.emit('delivery_failed', event, error);
    }
  }

  // Subscription Management
  async subscribe(event: string, url: string): Promise<string> {
    const subscription: WebhookSubscription = {
      id: crypto.randomUUID(),
      event,
      url,
      active: true,
      createdAt: new Date(),
      failureCount: 0
    };

    if (!this.subscriptions.has(event)) {
      this.subscriptions.set(event, []);
    }

    this.subscriptions.get(event)!.push(subscription);

    console.log(`Webhook subscription created for event: ${event} -> ${url}`);
    return subscription.id;
  }

  async unsubscribe(subscriptionId: string): Promise<boolean> {
    for (const [event, subscriptions] of this.subscriptions.entries()) {
      const index = subscriptions.findIndex(sub => sub.id === subscriptionId);
      if (index !== -1) {
        subscriptions.splice(index, 1);
        console.log(`Webhook subscription ${subscriptionId} removed for event: ${event}`);
        return true;
      }
    }
    return false;
  }

  async updateSubscription(subscriptionId: string, updates: Partial<WebhookSubscription>): Promise<boolean> {
    for (const [event, subscriptions] of this.subscriptions.entries()) {
      const subscription = subscriptions.find(sub => sub.id === subscriptionId);
      if (subscription) {
        Object.assign(subscription, updates);
        console.log(`Webhook subscription ${subscriptionId} updated for event: ${event}`);
        return true;
      }
    }
    return false;
  }

  async getSubscriptions(event?: string): Promise<WebhookSubscription[]> {
    if (event) {
      return this.subscriptions.get(event) || [];
    }

    const allSubscriptions: WebhookSubscription[] = [];
    for (const subscriptions of this.subscriptions.values()) {
      allSubscriptions.push(...subscriptions);
    }
    return allSubscriptions;
  }

  // Signature Management
  private generateSignature(event: WebhookEvent): string {
    const payload = JSON.stringify({
      id: event.id,
      event: event.event,
      source: event.source,
      data: event.data,
      timestamp: event.timestamp.toISOString()
    });

    return crypto
      .createHmac('sha256', this.config.secret)
      .update(payload)
      .digest('hex');
  }

  verifySignature(payload: string, signature: string): boolean {
    const expectedSignature = crypto
      .createHmac('sha256', this.config.secret)
      .update(payload)
      .digest('hex');

    return crypto.timingSafeEqual(
      Buffer.from(signature, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    );
  }

  // Event Handling
  async handleIncomingWebhook(payload: string, signature: string, headers: Record<string, string>): Promise<boolean> {
    try {
      // Verify signature
      if (!this.verifySignature(payload, signature)) {
        console.error('Invalid webhook signature');
        return false;
      }

      const data = JSON.parse(payload);
      const event = data.event;
      const source = headers['x-webhook-source'] || 'unknown';

      // Validate event structure
      if (!event || !data.id || !data.timestamp) {
        console.error('Invalid webhook event structure');
        return false;
      }

      // Process the event
      await this.processIncomingEvent({
        id: data.id,
        event,
        source: source as 'agents' | 'coreflow',
        data: data.data,
        timestamp: new Date(data.timestamp),
        signature
      });

      return true;

    } catch (error) {
      console.error('Failed to handle incoming webhook:', error);
      return false;
    }
  }

  private async processIncomingEvent(event: WebhookEvent): Promise<void> {
    console.log(`Processing incoming webhook event: ${event.event} from ${event.source}`);

    // Emit local event for processing
    this.emit('incoming_event', event);

    // Handle specific event types
    switch (event.event) {
      case 'agent.status_changed':
        await this.handleAgentStatusChange(event);
        break;
      case 'agent.task_completed':
        await this.handleAgentTaskCompleted(event);
        break;
      case 'coreflow.lead_created':
        await this.handleLeadCreated(event);
        break;
      case 'coreflow.lead_updated':
        await this.handleLeadUpdated(event);
        break;
      default:
        console.log(`Unhandled webhook event: ${event.event}`);
    }
  }

  private async handleAgentStatusChange(event: WebhookEvent): Promise<void> {
    console.log(`Agent status changed: ${event.data.agentId} -> ${event.data.status}`);
    // Handle agent status change logic
  }

  private async handleAgentTaskCompleted(event: WebhookEvent): Promise<void> {
    console.log(`Agent task completed: ${event.data.taskId} by ${event.data.agentId}`);
    // Handle task completion logic
  }

  private async handleLeadCreated(event: WebhookEvent): Promise<void> {
    console.log(`Lead created: ${event.data.leadId}`);
    // Handle lead creation logic
  }

  private async handleLeadUpdated(event: WebhookEvent): Promise<void> {
    console.log(`Lead updated: ${event.data.leadId}`);
    // Handle lead update logic
  }

  // Health and Monitoring
  async getHealthStatus(): Promise<{
    status: string;
    subscriptions: number;
    queuedEvents: number;
    processing: boolean;
    uptime: number;
  }> {
    const totalSubscriptions = Array.from(this.subscriptions.values())
      .reduce((total, subs) => total + subs.length, 0);

    return {
      status: 'healthy',
      subscriptions: totalSubscriptions,
      queuedEvents: this.eventQueue.length,
      processing: this.processing,
      uptime: process.uptime()
    };
  }

  async getEventStats(period: { start: Date; end: Date }): Promise<{
    totalEvents: number;
    eventsByType: Record<string, number>;
    eventsBySource: Record<string, number>;
    successRate: number;
    averageDeliveryTime: number;
  }> {
    // Mock event stats - would calculate from real data in production
    return {
      totalEvents: 1000,
      eventsByType: {
        'agent.status_changed': 200,
        'agent.task_completed': 300,
        'coreflow.lead_created': 250,
        'coreflow.lead_updated': 250
      },
      eventsBySource: {
        'agents': 500,
        'coreflow': 500
      },
      successRate: 0.95,
      averageDeliveryTime: 150
    };
  }

  // Configuration Management
  updateConfig(updates: Partial<WebhookConfig>): void {
    this.config = { ...this.config, ...updates };
    console.log('Webhook configuration updated');
  }

  getConfig(): WebhookConfig {
    return { ...this.config };
  }

  // Cleanup
  async cleanup(): Promise<void> {
    try {
      // Process remaining events in queue
      if (this.eventQueue.length > 0) {
        console.log(`Processing ${this.eventQueue.length} remaining events before cleanup`);
        await this.processQueue();
      }

      // Clear subscriptions
      this.subscriptions.clear();
      this.eventQueue = [];

      console.log('Webhook integration cleanup completed');
    } catch (error) {
      console.error('Webhook integration cleanup failed:', error);
    }
  }
}

