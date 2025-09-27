import { Hono } from 'hono';
import { WebhookIntegration, WebhookReceiver } from '../services/integration/webhook-integration';

const webhooks = new Hono();

// Initialize webhook services
let webhookIntegration: WebhookIntegration;
let webhookReceiver: WebhookReceiver;

webhooks.use('*', async (c, next) => {
  if (!webhookIntegration) {
    webhookIntegration = new WebhookIntegration(
      {
        secret: c.env.WEBHOOK_SECRET,
        endpoints: {
          agents: c.env.AGENT_SYSTEM_URL + '/webhooks/coreflow',
          coreflow: c.env.COREFLOW_API_URL + '/webhooks/agents'
        }
      },
      c.env
    );

    webhookReceiver = new WebhookReceiver(webhookIntegration);
  }

  c.set('webhookIntegration', webhookIntegration);
  c.set('webhookReceiver', webhookReceiver);

  await next();
});

// === Webhook Receiver - Handle incoming webhooks from Agent System ===
webhooks.post('/agents', async (c: any) => {
  try {
    const receiver = c.get('webhookReceiver');
    const body = await c.req.json();

    // Validate signature
    const signature = c.req.header('X-Webhook-Signature') || c.req.header('X-Agent-Auth');
    if (!signature) {
      return c.json({ error: 'Missing signature' }, 401);
    }

    // Process webhook
    const result = await receiver.handleWebhook({
      headers: {
        'x-webhook-signature': signature
      },
      body
    });

    return c.json(result);
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Processing failed'
    }, 500);
  }
});

// === Webhook Management ===

// Subscribe to webhook events
webhooks.post('/subscribe', async (c: any) => {
  try {
    const { event, url } = await c.req.json();
    const integration = c.get('webhookIntegration');

    const subscription = await integration.subscribe(event, url);

    return c.json({
      success: true,
      subscription
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Subscription failed'
    }, 500);
  }
});

// Unsubscribe from webhook events
webhooks.delete('/subscribe/:id', async (c: any) => {
  try {
    const subscriptionId = c.req.param('id');
    const integration = c.get('webhookIntegration');

    const success = await integration.unsubscribe(subscriptionId);

    if (!success) {
      return c.json({ error: 'Subscription not found' }, 404);
    }

    return c.json({ success: true });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unsubscribe failed'
    }, 500);
  }
});

// List webhook subscriptions
webhooks.get('/subscriptions', async (c: any) => {
  try {
    const integration = c.get('webhookIntegration');
    const event = c.req.query('event');

    const subscriptions = await integration.getSubscriptions(event);

    return c.json({ subscriptions });
  } catch (error: any) {
    return c.json({
      error: error instanceof Error ? error.message : 'Failed to get subscriptions'
    }, 500);
  }
});

// === Webhook Triggers - Send webhooks to Agent System ===

// Notify customer signup
webhooks.post('/notify/customer-signup', async (c: any) => {
  try {
    const customer = await c.req.json();
    const integration = c.get('webhookIntegration');

    await integration.notifyCustomerSignup(customer);

    return c.json({ success: true });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Notification failed'
    }, 500);
  }
});

// Notify deal created
webhooks.post('/notify/deal-created', async (c: any) => {
  try {
    const deal = await c.req.json();
    const integration = c.get('webhookIntegration');

    await integration.notifyDealCreated(deal);

    return c.json({ success: true });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Notification failed'
    }, 500);
  }
});

// Notify support ticket
webhooks.post('/notify/support-ticket', async (c: any) => {
  try {
    const ticket = await c.req.json();
    const integration = c.get('webhookIntegration');

    await integration.notifySupportTicket(ticket);

    return c.json({ success: true });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Notification failed'
    }, 500);
  }
});

// Notify workflow started
webhooks.post('/notify/workflow-started', async (c: any) => {
  try {
    const workflow = await c.req.json();
    const integration = c.get('webhookIntegration');

    await integration.notifyWorkflowStarted(workflow);

    return c.json({ success: true });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Notification failed'
    }, 500);
  }
});

// Notify metrics update
webhooks.post('/notify/metrics-update', async (c: any) => {
  try {
    const metrics = await c.req.json();
    const integration = c.get('webhookIntegration');

    await integration.notifyMetricsUpdate(metrics);

    return c.json({ success: true });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Notification failed'
    }, 500);
  }
});

// Generic webhook notification
webhooks.post('/notify/:event', async (c: any) => {
  try {
    const event = c.req.param('event');
    const data = await c.req.json();
    const integration = c.get('webhookIntegration');

    await integration.notifyAgents(event, data);

    return c.json({ success: true });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Notification failed'
    }, 500);
  }
});

// === Webhook Status and Management ===

// Get webhook queue status
webhooks.get('/status', async (c: any) => {
  try {
    const integration = c.get('webhookIntegration');

    return c.json({
      queueSize: integration.getQueueSize(),
      processing: integration.isProcessing(),
      timestamp: new Date()
    });
  } catch (error: any) {
    return c.json({
      error: error instanceof Error ? error.message : 'Status check failed'
    }, 500);
  }
});

// Get failed webhooks
webhooks.get('/failed', async (c: any) => {
  try {
    const integration = c.get('webhookIntegration');
    const limit = parseInt(c.req.query('limit') || '100');

    const failed = await integration.getFailedWebhooks(limit);

    return c.json({ failed });
  } catch (error: any) {
    return c.json({
      error: error instanceof Error ? error.message : 'Failed to get failed webhooks'
    }, 500);
  }
});

// Retry failed webhook
webhooks.post('/retry/:id', async (c: any) => {
  try {
    const webhookId = c.req.param('id');
    const integration = c.get('webhookIntegration');

    const success = await integration.retryFailedWebhook(webhookId);

    if (!success) {
      return c.json({ error: 'Webhook not found' }, 404);
    }

    return c.json({ success: true });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Retry failed'
    }, 500);
  }
});

// === Custom Webhook Handlers ===

// Register custom handler for specific events
webhooks.post('/handlers/register', async (c: any) => {
  try {
    const { event, handlerCode } = await c.req.json();
    const receiver = c.get('webhookReceiver');

    // Create handler function from code (be careful with security)
    // In production, use predefined handlers or strict validation
    const handler = new Function('data', 'return ' + handlerCode);

    receiver.registerHandler(event, handler as any);

    return c.json({ success: true });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Handler registration failed'
    }, 500);
  }
});

export default webhooks;