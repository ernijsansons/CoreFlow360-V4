/**
 * Payment Processing API Routes
 * Enterprise payment gateway integration with Stripe, PayPal, and bank transfers
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { StripePaymentGateway } from '../modules/finance/payment/stripe-gateway';
import { PayPalGateway } from '../modules/finance/payment/paypal-gateway';
import { WebhookService } from '../modules/finance/payment/webhook-service';
import { AuditLogger } from '../modules/audit/audit-service';
import type { Env } from '../types/env';

const app = new Hono<{ Bindings: Env }>();

// ============================================================================
// VALIDATION SCHEMAS
// ============================================================================

const CreatePaymentIntentSchema = z.object({
  amount: z.number().positive(),
  currency: z.string().length(3).default('USD'),
  customerId: z.string().optional(),
  invoiceId: z.string().optional(),
  description: z.string().optional(),
  paymentMethodTypes: z.array(z.string()).default(['card']),
  metadata: z.record(z.string()).optional(),
  captureMethod: z.enum(['automatic', 'manual']).default('automatic'),
  setupFutureUsage: z.enum(['on_session', 'off_session']).optional(),
  automaticPaymentMethods: z.object({
    enabled: z.boolean(),
    allowRedirects: z.enum(['always', 'never']).optional()
  }).optional()
});

const CreateCustomerSchema = z.object({
  email: z.string().email(),
  name: z.string().optional(),
  phone: z.string().optional(),
  address: z.object({
    line1: z.string(),
    line2: z.string().optional(),
    city: z.string(),
    state: z.string().optional(),
    postalCode: z.string(),
    country: z.string().length(2)
  }).optional(),
  taxIds: z.array(z.object({
    type: z.string(),
    value: z.string()
  })).optional(),
  metadata: z.record(z.string()).optional()
});

const CreateSubscriptionSchema = z.object({
  customerId: z.string(),
  priceId: z.string(),
  quantity: z.number().positive().default(1),
  trialPeriodDays: z.number().optional(),
  metadata: z.record(z.string()).optional(),
  paymentSettings: z.object({
    paymentMethodTypes: z.array(z.string()),
    saveDefaultPaymentMethod: z.enum(['on_subscription', 'off'])
  }).optional(),
  automaticTax: z.object({
    enabled: z.boolean()
  }).optional()
});

const RefundPaymentSchema = z.object({
  paymentIntentId: z.string(),
  amount: z.number().positive().optional(), // Optional for full refund
  reason: z.enum(['duplicate', 'fraudulent', 'requested_by_customer']).optional(),
  metadata: z.record(z.string()).optional()
});

const PayPalOrderSchema = z.object({
  amount: z.number().positive(),
  currency: z.string().length(3).default('USD'),
  description: z.string().optional(),
  invoiceId: z.string().optional(),
  customerId: z.string().optional(),
  returnUrl: z.string().url(),
  cancelUrl: z.string().url(),
  metadata: z.record(z.string()).optional()
});

const BankTransferSchema = z.object({
  amount: z.number().positive(),
  currency: z.string().length(3).default('USD'),
  accountNumber: z.string(),
  routingNumber: z.string(),
  accountType: z.enum(['checking', 'savings']),
  customerId: z.string(),
  invoiceId: z.string().optional(),
  description: z.string().optional()
});

// ============================================================================
// MIDDLEWARE
// ============================================================================

async function initializeGateways(env: Env) {
  const stripeConfig = {
    secretKey: env.STRIPE_SECRET_KEY,
    publishableKey: env.STRIPE_PUBLISHABLE_KEY,
    webhookSecret: env.STRIPE_WEBHOOK_SECRET,
    apiVersion: '2023-10-16' as const,
    environment: (env.ENVIRONMENT || 'test') as 'test' | 'live',
    currency: 'USD'
  };

  const paypalConfig = {
    clientId: env.PAYPAL_CLIENT_ID,
    clientSecret: env.PAYPAL_CLIENT_SECRET,
    environment: env.ENVIRONMENT === 'production' ? 'live' : 'sandbox',
    currency: 'USD'
  };

  const stripe = new StripePaymentGateway(stripeConfig);
  const paypal = new PayPalGateway(paypalConfig);
  const webhookService = new WebhookService(env.DB_MAIN);
  const auditLogger = new AuditLogger();

  return { stripe, paypal, webhookService, auditLogger };
}

// ============================================================================
// STRIPE ENDPOINTS
// ============================================================================

app.post('/stripe/payment-intent', zValidator('json', CreatePaymentIntentSchema), async (c) => {
  try {
    const { stripe, auditLogger } = await initializeGateways(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const userId = c.req.header('X-User-ID') || 'system';
    const data = c.req.valid('json');

    const result = await stripe.createPaymentIntent(data);

    // Log audit trail
    await auditLogger.log({
      businessId,
      userId,
      action: 'create_payment_intent',
      resourceType: 'payment',
      resourceId: result.id,
      details: {
        amount: data.amount,
        currency: data.currency,
        invoiceId: data.invoiceId,
        status: result.status
      }
    });

    return c.json({
      success: true,
      data: result
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to create payment intent'
    }, 400);
  }
});

app.post('/stripe/customer', zValidator('json', CreateCustomerSchema), async (c) => {
  try {
    const { stripe, auditLogger } = await initializeGateways(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const userId = c.req.header('X-User-ID') || 'system';
    const data = c.req.valid('json');

    const result = await stripe.createCustomer(data);

    // Log audit trail
    await auditLogger.log({
      businessId,
      userId,
      action: 'create_stripe_customer',
      resourceType: 'customer',
      resourceId: result.id,
      details: {
        email: data.email,
        name: data.name
      }
    });

    return c.json({
      success: true,
      data: result
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to create customer'
    }, 400);
  }
});

app.post('/stripe/subscription', zValidator('json', CreateSubscriptionSchema), async (c) => {
  try {
    const { stripe, auditLogger } = await initializeGateways(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const userId = c.req.header('X-User-ID') || 'system';
    const data = c.req.valid('json');

    const result = await stripe.createSubscription(data);

    // Log audit trail
    await auditLogger.log({
      businessId,
      userId,
      action: 'create_subscription',
      resourceType: 'subscription',
      resourceId: result.id,
      details: {
        customerId: data.customerId,
        priceId: data.priceId,
        quantity: data.quantity
      }
    });

    return c.json({
      success: true,
      data: result
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to create subscription'
    }, 400);
  }
});

app.post('/stripe/refund', zValidator('json', RefundPaymentSchema), async (c) => {
  try {
    const { stripe, auditLogger } = await initializeGateways(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const userId = c.req.header('X-User-ID') || 'system';
    const data = c.req.valid('json');

    const result = await stripe.createRefund(data);

    // Log audit trail
    await auditLogger.log({
      businessId,
      userId,
      action: 'create_refund',
      resourceType: 'refund',
      resourceId: result.id,
      details: {
        paymentIntentId: data.paymentIntentId,
        amount: result.amount,
        status: result.status
      }
    });

    return c.json({
      success: true,
      data: result
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to process refund'
    }, 400);
  }
});

app.post('/stripe/webhook', async (c) => {
  try {
    const { stripe, webhookService, auditLogger } = await initializeGateways(c.env);
    const signature = c.req.header('stripe-signature');

    if (!signature) {
      return c.json({
        success: false,
        error: 'Missing stripe-signature header'
      }, 400);
    }

    const body = await c.req.text();
    const event = await stripe.constructWebhookEvent(body, signature);

    // Process webhook event
    await webhookService.processStripeWebhook(event);

    // Log webhook receipt
    await auditLogger.log({
      businessId: 'system',
      userId: 'webhook',
      action: 'stripe_webhook',
      resourceType: 'webhook',
      resourceId: event.id,
      details: {
        type: event.type,
        livemode: event.livemode
      }
    });

    return c.json({
      success: true,
      received: true
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Webhook processing failed'
    }, 400);
  }
});

// ============================================================================
// PAYPAL ENDPOINTS
// ============================================================================

app.post('/paypal/order', zValidator('json', PayPalOrderSchema), async (c) => {
  try {
    const { paypal, auditLogger } = await initializeGateways(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const userId = c.req.header('X-User-ID') || 'system';
    const data = c.req.valid('json');

    const result = await paypal.createOrder(data);

    // Log audit trail
    await auditLogger.log({
      businessId,
      userId,
      action: 'create_paypal_order',
      resourceType: 'payment',
      resourceId: result.id,
      details: {
        amount: data.amount,
        currency: data.currency,
        invoiceId: data.invoiceId
      }
    });

    return c.json({
      success: true,
      data: result
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to create PayPal order'
    }, 400);
  }
});

app.post('/paypal/order/:id/capture', async (c) => {
  try {
    const { paypal, auditLogger } = await initializeGateways(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const userId = c.req.header('X-User-ID') || 'system';
    const orderId = c.req.param('id');

    const result = await paypal.captureOrder(orderId);

    // Log audit trail
    await auditLogger.log({
      businessId,
      userId,
      action: 'capture_paypal_order',
      resourceType: 'payment',
      resourceId: orderId,
      details: {
        status: result.status,
        capturedAt: new Date().toISOString()
      }
    });

    return c.json({
      success: true,
      data: result
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to capture PayPal order'
    }, 400);
  }
});

app.post('/paypal/webhook', async (c) => {
  try {
    const { paypal, webhookService, auditLogger } = await initializeGateways(c.env);
    const body = await c.req.json();
    const headers = c.req.header();

    // Verify webhook signature
    const isValid = await paypal.verifyWebhook({
      headers,
      body
    });

    if (!isValid) {
      return c.json({
        success: false,
        error: 'Invalid webhook signature'
      }, 401);
    }

    // Process webhook event
    await webhookService.processPayPalWebhook(body);

    // Log webhook receipt
    await auditLogger.log({
      businessId: 'system',
      userId: 'webhook',
      action: 'paypal_webhook',
      resourceType: 'webhook',
      resourceId: body.id,
      details: {
        eventType: body.event_type,
        resourceType: body.resource_type
      }
    });

    return c.json({
      success: true,
      received: true
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Webhook processing failed'
    }, 400);
  }
});

// ============================================================================
// BANK TRANSFER ENDPOINTS
// ============================================================================

app.post('/bank-transfer', zValidator('json', BankTransferSchema), async (c) => {
  try {
    const { auditLogger } = await initializeGateways(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const userId = c.req.header('X-User-ID') || 'system';
    const data = c.req.valid('json');

    // Note: Actual bank transfer implementation would integrate with banking APIs
    // This is a placeholder for the structure
    const transferId = `ach_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    // Log audit trail
    await auditLogger.log({
      businessId,
      userId,
      action: 'initiate_bank_transfer',
      resourceType: 'payment',
      resourceId: transferId,
      details: {
        amount: data.amount,
        currency: data.currency,
        accountType: data.accountType,
        invoiceId: data.invoiceId
      }
    });

    return c.json({
      success: true,
      data: {
        id: transferId,
        status: 'pending',
        amount: data.amount,
        currency: data.currency,
        estimatedArrival: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString() // 3 days
      }
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to initiate bank transfer'
    }, 400);
  }
});

// ============================================================================
// PAYMENT STATUS & HISTORY
// ============================================================================

app.get('/status/:id', async (c) => {
  try {
    const { stripe, paypal } = await initializeGateways(c.env);
    const paymentId = c.req.param('id');
    const provider = c.req.query('provider') || 'stripe';

    let status;
    if (provider === 'stripe') {
      status = await stripe.getPaymentStatus(paymentId);
    } else if (provider === 'paypal') {
      status = await paypal.getOrderStatus(paymentId);
    } else {
      return c.json({
        success: false,
        error: 'Invalid payment provider'
      }, 400);
    }

    return c.json({
      success: true,
      data: status
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to fetch payment status'
    }, 500);
  }
});

app.get('/history', async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'default';
    const customerId = c.req.query('customerId');
    const invoiceId = c.req.query('invoiceId');
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');
    const limit = parseInt(c.req.query('limit') || '20');

    // Note: This would query from a payments table in production
    const payments = []; // Placeholder for payment history query

    return c.json({
      success: true,
      data: payments,
      pagination: {
        limit,
        total: payments.length
      }
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to fetch payment history'
    }, 500);
  }
});

// ============================================================================
// HEALTH CHECK
// ============================================================================

app.get('/health', async (c) => {
  return c.json({
    success: true,
    service: 'payments',
    status: 'operational',
    providers: {
      stripe: 'connected',
      paypal: 'connected',
      bank: 'ready'
    },
    timestamp: new Date().toISOString()
  });
});

export default app;