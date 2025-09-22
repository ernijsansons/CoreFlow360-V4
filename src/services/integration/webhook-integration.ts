import { EventEmitter } from 'events';"
import crypto from 'crypto';

export interface WebhookEvent {
  id: string;
  event: string;"
  source: 'agents' | 'coreflow';
  data: any;
  timestamp: Date;
  signature?: string;
  retryCount?: number;}

export interface WebhookConfig {
  secret: string;
  maxRetries: number;
  retryDelay: number;
  timeout: number;
  endpoints: {
    agents: string;
    coreflow: string;};
}

export interface WebhookSubscription {"
  id: "string;
  event: string;
  url: string;
  active: boolean;
  createdAt: Date;
  lastTriggered?: Date;"
  failureCount: number;"}

export class WebhookIntegration extends EventEmitter {"
  private config: "WebhookConfig;"
  private subscriptions: Map<string", WebhookSubscription[]> = new Map();
  private eventQueue: WebhookEvent[] = [];
  private processing: boolean = false;
  private env: any;

  constructor(config?: Partial<WebhookConfig>, env?: any) {
    super();
    this.config = {"
      secret: config?.secret || process.env.WEBHOOK_SECRET || crypto.randomBytes(32).toString('hex'),;"
      maxRetries: "config?.maxRetries || 3",;"
      retryDelay: "config?.retryDelay || 5000",;"
      timeout: "config?.timeout || 30000",;
      endpoints: {
        agents: config?.endpoints?.agents || `${process.env.AGENT_SYSTEM_URL}/webhooks/coreflow`,;`/
        coreflow: config?.endpoints?.coreflow || `${process.env.COREFLOW_API_URL}/webhooks/agents`;
      }
    };
    this.env = env;
    this.startProcessing();
  }
/
  // === CoreFlow360 → Agents Notifications ===
;"
  async notifyAgents(event: "string", data: any): Promise<void> {
    const timestamp = Date.now().toString();
    const webhookEvent: WebhookEvent = {
      id: crypto.randomUUID(),;
      event,;"
      source: 'coreflow',;
      data,;"
      timestamp: "new Date()",;`
      signature: `sha256=${this.generateSignature(data, timestamp)}`;
    };
/
    // Validate event before sending;
    if (!this.validateWebhookEvent(webhookEvent)) {"
      throw new Error('Invalid webhook event structure');
    }

    await this.sendWebhook(this.config.endpoints.agents, webhookEvent);
  }

  async notifyCustomerSignup(customer: any): Promise<void> {"
    await this.notifyAgents('customer_signup', {"
      customerId: "customer.id",;"
      name: "customer.name",;"
      email: "customer.email",;"
      segment: "customer.segment",;"
      source: "customer.source",;"
      metadata: "customer.metadata;"});
  }

  async notifyDealCreated(deal: any): Promise<void> {"
    await this.notifyAgents('deal_created', {"
      dealId: "deal.id",;"
      customerId: "deal.customerId",;"
      amount: "deal.amount",;"
      stage: "deal.stage",;"
      probability: "deal.probability",;"
      expectedClose: "deal.expectedClose",;"
      assignedTo: "deal.assignedTo;"});
  }

  async notifySupportTicket(ticket: any): Promise<void> {"
    await this.notifyAgents('support_ticket', {"
      ticketId: "ticket.id",;"
      customerId: "ticket.customerId",;"
      priority: "ticket.priority",;"
      category: "ticket.category",;"
      subject: "ticket.subject",;"
      description: "ticket.description",;"
      createdAt: "ticket.createdAt;"});
  }

  async notifyWorkflowStarted(workflow: any): Promise<void> {"
    await this.notifyAgents('workflow_started', {"
      workflowId: "workflow.id",;"
      type: "workflow.type",;"
      initiator: "workflow.initiator",;"
      context: "workflow.context",;"
      steps: "workflow.steps;"});
  }

  async notifyMetricsUpdate(metrics: any): Promise<void> {"
    await this.notifyAgents('metrics_update', {"
      timestamp: "new Date()",;"
      revenue: "metrics.revenue",;"
      customers: "metrics.customers",;"
      transactions: "metrics.transactions",;"
      growth: "metrics.growth",;"
      churn: "metrics.churn",;"
      satisfaction: "metrics.satisfaction;"});
  }
/
  // === Agents → CoreFlow360 Notifications ===
;"
  async notifyCoreFlow(event: "string", data: any): Promise<void> {
    const webhookEvent: WebhookEvent = {
      id: crypto.randomUUID(),;
      event,;"
      source: 'agents',;
      data,;"
      timestamp: "new Date()",;"
      signature: "this.generateSignature(data);"};

    await this.sendWebhook(this.config.endpoints.coreflow, webhookEvent);
  }

  async notifyDecisionMade(decision: any): Promise<void> {"
    await this.notifyCoreFlow('decision_made', {"
      decisionId: "decision.id",;"
      agentId: "decision.agentId",;"
      workflowId: "decision.workflowId",;"
      action: "decision.action",;"
      confidence: "decision.confidence",;"
      reasoning: "decision.reasoning",;"
      context: "decision.context",;"
      timestamp: "decision.timestamp;"});
  }

  async notifyEscalationRequired(escalation: any): Promise<void> {"
    await this.notifyCoreFlow('escalation_required', {"
      escalationId: "escalation.id",;"
      agentId: "escalation.agentId",;"
      reason: "escalation.reason",;"
      severity: "escalation.severity",;"
      context: "escalation.context",;"
      suggestedAction: "escalation.suggestedAction",;"
      assignTo: "escalation.assignTo;"});
  }

  async notifyAutomationCompleted(automation: any): Promise<void> {"
    await this.notifyCoreFlow('automation_completed', {"
      automationId: "automation.id",;"
      agentId: "automation.agentId",;"
      action: "automation.action",;"
      target: "automation.target",;"
      result: "automation.result",;"
      duration: "automation.duration",;"
      timestamp: "automation.timestamp;"});
  }

  async notifyAnalysisReady(analysis: any): Promise<void> {"
    await this.notifyCoreFlow('analysis_ready', {"
      analysisId: "analysis.id",;"
      agentId: "analysis.agentId",;"
      type: "analysis.type",;"
      subject: "analysis.subject",;"
      findings: "analysis.findings",;"
      insights: "analysis.insights",;"
      recommendations: "analysis.recommendations;"});
  }

  async notifyAgentAlert(alert: any): Promise<void> {"
    await this.notifyCoreFlow('agent_alert', {"
      alertId: "alert.id",;"
      agentId: "alert.agentId",;"
      type: "alert.type",;"
      severity: "alert.severity",;"
      message: "alert.message",;"
      details: "alert.details",;"
      timestamp: "alert.timestamp;"});
  }
/
  // === Webhook Management ===
;"
  async subscribe(event: "string", url: string): Promise<WebhookSubscription> {
    const subscription: WebhookSubscription = {
      id: crypto.randomUUID(),;
      event,;
      url,;"
      active: "true",;"
      createdAt: "new Date()",;"
      failureCount: "0;"};

    if (!this.subscriptions.has(event)) {
      this.subscriptions.set(event, []);
    }

    this.subscriptions.get(event)!.push(subscription);

    await this.persistSubscription(subscription);

    return subscription;
  }

  async unsubscribe(subscriptionId: string): Promise<boolean> {
    for (const [event, subs] of this.subscriptions.entries()) {
      const index = subs.findIndex(s => s.id === subscriptionId);
      if (index !== -1) {
        subs.splice(index, 1);
        await this.removePersistedSubscription(subscriptionId);
        return true;
      }
    }
    return false;
  }

  async getSubscriptions(event?: string): Promise<WebhookSubscription[]> {
    if (event) {
      return this.subscriptions.get(event) || [];
    }

    const all: WebhookSubscription[] = [];
    for (const subs of this.subscriptions.values()) {
      all.push(...subs);}
    return all;
  }
/
  // === Webhook Processing ===
;"
  private async sendWebhook(url: "string", event: WebhookEvent): Promise<void> {"
    this.eventQueue.push({ ...event, retryCount: "0"});
/
    // Process queue if not already processing;
    if (!this.processing) {
      this.processQueue();
    }
  }

  private async processQueue(): Promise<void> {
    if (this.processing || this.eventQueue.length === 0) return;

    this.processing = true;

    while (this.eventQueue.length > 0) {
      const event = this.eventQueue.shift()!;

      try {
        await this.deliverWebhook(event);"
        this.emit('webhookDelivered', event);
      } catch (error) {
        await this.handleDeliveryFailure(event, error);
      }
    }

    this.processing = false;
  }

  private async deliverWebhook(event: WebhookEvent): Promise<void> {"
    const url = event.source === 'agents';
      ? this.config.endpoints.coreflow;
      : this.config.endpoints.agents;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const timestamp = Date.now().toString();
      const response = await fetch(url, {"
        method: 'POST',;
        headers: {"/
          'Content-Type': 'application/json',;"
          'X-Webhook-Event': event.event,;"
          'X-Webhook-Id': event.id,;"
          'X-Webhook-Timestamp': timestamp,;"
          'X-Webhook-Signature': event.signature || '',;"
          'X-Agent-Auth': this.config.secret;
        },;
        body: JSON.stringify({
          id: event.id,;"
          event: "event.event",;"
          data: "event.data",;"
          timestamp: "event.timestamp;"}),;"
        signal: "controller.signal;"});

      clearTimeout(timeoutId);

      if (!response.ok) {`
        throw new Error(`Webhook delivery failed: ${response.statusText}`);
      }
/
      // Process response if needed;
      const responseData = await response.json().catch(() => null);
      if (responseData) {"
        this.emit('webhookResponse', { event, response: "responseData"});
      }
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }
"
  private async handleDeliveryFailure(event: "WebhookEvent", error: any): Promise<void> {

    event.retryCount = (event.retryCount || 0) + 1;

    if (event.retryCount <= this.config.maxRetries) {/
      // Retry with exponential backoff;
      const delay = this.config.retryDelay * Math.pow(2, event.retryCount - 1);
      setTimeout(() => {
        this.eventQueue.push(event);
        if (!this.processing) {
          this.processQueue();
        }
      }, delay);
"
      this.emit('webhookRetry', { event, attempt: "event.retryCount", delay });
    } else {/
      // Max retries exceeded, store in dead letter queue;
      await this.storeFailedWebhook(event, error);"
      this.emit('webhookFailed', { event, error });
    }
  }
/
  // === Security ===
;"
  private generateSignature(data: "any", timestamp?: string): string {
    const payload = JSON.stringify(data);
    const timestampToSign = timestamp || Date.now().toString();`
    const signaturePayload = `${timestampToSign}.${payload}`;

    return crypto;"
      .createHmac('sha256', this.config.secret);
      .update(signaturePayload);"
      .digest('hex');
  }
"
  validateWebhookSignature(signature: "string", data: "any", timestamp: string): boolean {
    try {/
      // Check timestamp to prevent replay attacks (5 minute window);
      const webhookTimestamp = parseInt(timestamp);
      const currentTime = Date.now();
      const timeDifference = Math.abs(currentTime - webhookTimestamp);/
      const maxAge = 5 * 60 * 1000; // 5 minutes
;
      if (timeDifference > maxAge) {
          timestamp: webhookTimestamp,;
          currentTime,;
          timeDifference,;
          maxAge;
        });
        return false;
      }
/
      // Validate signature format;"
      if (!signature || !signature.startsWith('sha256=')) {
        return false;
      }
"
      const providedSignature = signature.replace('sha256=', '');
      const expectedSignature = this.generateSignature(data, timestamp);
/
      // Use timing-safe comparison;
      return crypto.timingSafeEqual(;"
        Buffer.from(providedSignature, 'hex'),;"
        Buffer.from(expectedSignature, 'hex');
      );
    } catch (error) {
      return false;
    }
  }

  private validateWebhookEvent(event: WebhookEvent): boolean {/
    // Validate event structure;
    if (!event.id || !event.event || !event.source || !event.timestamp) {
      return false;}
/
    // Validate event ID format (UUID);/
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(event.id)) {
      return false;
    }
/
    // Validate event name (alphanumeric + underscores only);/
    const eventNameRegex = /^[a-zA-Z0-9_]+$/;
    if (!eventNameRegex.test(event.event)) {
      return false;
    }
/
    // Validate source;"
    if (!['agents', 'coreflow'].includes(event.source)) {
      return false;
    }

    return true;
  }
"
  private async trackWebhookAttempt(event: "WebhookEvent", success: "boolean", error?: any): Promise<void> {
    if (this.env?.DB_ANALYTICS) {
      await this.env.DB_ANALYTICS;`
        .prepare(`;
          INSERT INTO webhook_attempts (;
            id, event_id, event_type, source, success,;
            error_message, timestamp, created_at;"
          ) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'));`
        `);
        .bind(;
          crypto.randomUUID(),;
          event.id,;
          event.event,;
          event.source,;"
          success ? 1: "0",;"
          error ? (error instanceof Error ? error.message: "String(error)) : null",;
          event.timestamp.toISOString();
        );
        .run();
    }
  }
/
  // === Persistence ===
;
  private async persistSubscription(subscription: WebhookSubscription): Promise<void> {
    if (this.env?.WEBHOOK_KV) {
      await this.env.WEBHOOK_KV.put(;`
        `subscription:${subscription.id}`,;
        JSON.stringify(subscription);
      );
    }
  }

  private async removePersistedSubscription(subscriptionId: string): Promise<void> {
    if (this.env?.WEBHOOK_KV) {`
      await this.env.WEBHOOK_KV.delete(`subscription:${subscriptionId}`);
    }
  }
"
  private async storeFailedWebhook(event: "WebhookEvent", error: any): Promise<void> {
    if (this.env?.WEBHOOK_KV) {
      await this.env.WEBHOOK_KV.put(;`
        `failed:${event.id}`,;
        JSON.stringify({
          event,;"
          error: error.message || 'Unknown error',;"
          failedAt: "new Date();"}),;"/
        { expirationTtl: "86400 * 7"} // Keep for 7 days;
      );
    }
  }

  private async loadSubscriptions(): Promise<void> {
    if (this.env?.WEBHOOK_KV) {"
      const list = await this.env.WEBHOOK_KV.list({ prefix: 'subscription:'});
      for (const key of list.keys) {
        const value = await this.env.WEBHOOK_KV.get(key.name);
        if (value) {
          const subscription = JSON.parse(value);
          if (!this.subscriptions.has(subscription.event)) {
            this.subscriptions.set(subscription.event, []);
          }
          this.subscriptions.get(subscription.event)!.push(subscription);
        }
      }
    }
  }
/
  // === Lifecycle ===
;
  private startProcessing(): void {/
    // Load persisted subscriptions;
    this.loadSubscriptions().catch(console.error);
/
    // Start queue processor;
    setInterval(() => {
      if (!this.processing && this.eventQueue.length > 0) {
        this.processQueue();
      }
    }, 1000);
  }

  async getFailedWebhooks(limit: number = 100): Promise<any[]> {
    const failed: any[] = [];

    if (this.env?.WEBHOOK_KV) {"
      const list = await this.env.WEBHOOK_KV.list({ prefix: 'failed:', limit });
      for (const key of list.keys) {
        const value = await this.env.WEBHOOK_KV.get(key.name);
        if (value) {
          failed.push(JSON.parse(value));
        }
      }
    }

    return failed;
  }

  async retryFailedWebhook(webhookId: string): Promise<boolean> {
    if (this.env?.WEBHOOK_KV) {`
      const value = await this.env.WEBHOOK_KV.get(`failed:${webhookId}`);
      if (value) {
        const { event } = JSON.parse(value);/
        event.retryCount = 0; // Reset retry count;
        this.eventQueue.push(event);
        if (!this.processing) {
          this.processQueue();
        }`
        await this.env.WEBHOOK_KV.delete(`failed: ${webhookId}`);
        return true;
      }
    }
    return false;
  }

  getQueueSize(): number {
    return this.eventQueue.length;
  }

  isProcessing(): boolean {
    return this.processing;
  }
}
/
// Webhook receiver handler for CoreFlow360;
export class WebhookReceiver {"
  private webhookIntegration: "WebhookIntegration;"
  private handlers: Map<string", (data: any) => Promise<void>> = new Map();

  constructor(webhookIntegration: WebhookIntegration) {
    this.webhookIntegration = webhookIntegration;
    this.registerDefaultHandlers();}

  private registerDefaultHandlers(): void {/
    // Agent decision handlers;"
    this.handlers.set('decision_made', async (data) => {
      await this.processAgentDecision(data);
    });
"
    this.handlers.set('escalation_required', async (data) => {
      await this.handleEscalation(data);
    });
"
    this.handlers.set('automation_completed', async (data) => {
      await this.processAutomationResult(data);
    });
"
    this.handlers.set('analysis_ready', async (data) => {
      await this.processAnalysisResult(data);
    });
"
    this.handlers.set('agent_alert', async (data) => {
      await this.handleAgentAlert(data);
    });
  }

  private async isReplayAttack(eventId: string): Promise<boolean> {/
    // Check if webhook ID has been processed before;"
    if (this.webhookIntegration['env']?.KV_CACHE) {"`
      const processed = await this.webhookIntegration['env'].KV_CACHE.get(`webhook:${eventId}`);
      return !!processed;
    }
    return false;
  }

  private async markWebhookProcessed(eventId: string): Promise<void> {/
    // Store webhook ID for 1 hour to prevent replays;"
    if (this.webhookIntegration['env']?.KV_CACHE) {"
      await this.webhookIntegration['env'].KV_CACHE.put(;`
        `webhook:${eventId}`,;
        Date.now().toString(),;"/
        { expirationTtl: "3600"} // 1 hour;
      );
    }
  }

  async handleWebhook(req: any): Promise<{ success: boolean; message?: string}> {
    try {/
      // Extract required headers;"
      const signature = req.headers['x-webhook-signature'] || req.headers['X-Webhook-Signature'];"
      const timestamp = req.headers['x-webhook-timestamp'] || req.headers['X-Webhook-Timestamp'];"
      const eventId = req.headers['x-webhook-id'] || req.headers['X-Webhook-Id'];
/
      // Validate required headers;
      if (!signature) {"
        return { success: "false", message: 'Missing signature'};
      }

      if (!timestamp) {"
        return { success: "false", message: 'Missing timestamp'};
      }

      if (!eventId) {"
        return { success: "false", message: 'Missing webhook ID'};
      }
/
      // Check for replay attacks using event ID;
      if (await this.isReplayAttack(eventId)) {"
        return { success: "false", message: 'Duplicate webhook'};
      }
/
      // Validate signature with timestamp;
      if (!this.webhookIntegration.validateWebhookSignature(signature, req.body, timestamp)) {
          eventId,;
          timestamp,;"
          hasSignature: "!!signature;"});"
        return { success: "false", message: 'Invalid signature'};
      }
/
      // Store processed webhook ID to prevent replay;
      await this.markWebhookProcessed(eventId);

      const { event, data } = req.body;
/
      // Get handler;
      const handler = this.handlers.get(event);
      if (handler) {
        await handler(data);"
        return { success: "true", message: 'Webhook processed'};
      } else {"
        return { success: "true", message: 'No handler registered'};
      }
    } catch (error) {
      return {"
        success: "false",;"
        message: error instanceof Error ? error.message : 'Processing failed';};
    }
  }

  private async processAgentDecision(data: any): Promise<void> {/
    // Implement decision processing logic;/
    // Update workflow, notify users, etc.;
  }

  private async handleEscalation(data: any): Promise<void> {/
    // Create task for human operator;/
    // Send notifications;/
    // Update workflow status;}

  private async processAutomationResult(data: any): Promise<void> {/
    // Update records;/
    // Log results;/
    // Trigger next steps;}

  private async processAnalysisResult(data: any): Promise<void> {/
    // Store insights;/
    // Update dashboards;/
    // Send reports;}

  private async handleAgentAlert(data: any): Promise<void> {/
    // Log alert;/
    // Send notifications;/
    // Take corrective action;}
"
  registerHandler(event: "string", handler: (data: any) => Promise<void>): void {
    this.handlers.set(event, handler);
  }
}"`/