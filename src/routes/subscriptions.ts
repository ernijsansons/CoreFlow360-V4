// @ts-nocheck
/**
 * Subscription API Routes
 * Recurring billing and subscription management
 */

import { Hono } from 'hono';
import type { Env } from '../types/env';
import { SubscriptionService } from '../services/subscription/subscription-service';
import { RecurringRevenueService } from '../services/subscription/recurring-revenue-service';

const subscriptions = new Hono<{ Bindings: Env }>();

// Middleware
subscriptions.use('*', async (c, next) => {
  const businessId = c.req.header('x-business-id') || 'default-business-id';
  c.set('businessId' as any, businessId);
  await next();
});

// ==================
// Plan Management
// ==================

/**
 * POST /subscriptions/plans
 * Create subscription plan
 */
subscriptions.post('/plans', async (c) => {
  try {
    const businessId = c.get('businessId' as any) as string;
    const body = await c.req.json();

    const service = new SubscriptionService(c.env);
    const planId = await service.createPlan({
      businessId,
      ...body,
    });

    return c.json({ success: true, data: { plan_id: planId } });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * GET /subscriptions/plans
 * List all plans
 */
subscriptions.get('/plans', async (c) => {
  try {
    const businessId = c.get('businessId' as any) as string;
    const service = new SubscriptionService(c.env);
    const plans = await service.getPlans(businessId);

    return c.json({ success: true, data: { plans } });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

// ==================
// Subscription Management
// ==================

/**
 * POST /subscriptions
 * Create subscription
 */
subscriptions.post('/', async (c) => {
  try {
    const businessId = c.get('businessId' as any) as string;
    const body = await c.req.json();

    const service = new SubscriptionService(c.env);
    const subscriptionId = await service.createSubscription({
      businessId,
      ...body,
    });

    return c.json({ success: true, data: { subscription_id: subscriptionId } });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * GET /subscriptions
 * List subscriptions
 */
subscriptions.get('/', async (c) => {
  try {
    const businessId = c.get('businessId' as any) as string;
    const { customer_id, status } = c.req.query();

    const service = new SubscriptionService(c.env);
    const subs = await service.getSubscriptions(businessId, {
      customerId: customer_id,
      status,
    });

    return c.json({ success: true, data: { subscriptions: subs } });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * POST /subscriptions/:id/cancel
 * Cancel subscription
 */
subscriptions.post('/:id/cancel', async (c) => {
  try {
    const subscriptionId = c.req.param('id');
    const { reason, immediate } = await c.req.json();

    const service = new SubscriptionService(c.env);
    await service.cancelSubscription(subscriptionId, reason, immediate);

    return c.json({ success: true, data: { message: 'Subscription cancelled' } });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * POST /subscriptions/:id/renew
 * Renew subscription
 */
subscriptions.post('/:id/renew', async (c) => {
  try {
    const subscriptionId = c.req.param('id');

    const service = new SubscriptionService(c.env);
    await service.renewSubscription(subscriptionId);

    return c.json({ success: true, data: { message: 'Subscription renewed' } });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

// ==================
// Invoice Management
// ==================

/**
 * POST /subscriptions/:id/invoice
 * Generate invoice
 */
subscriptions.post('/:id/invoice', async (c) => {
  try {
    const subscriptionId = c.req.param('id');

    const service = new SubscriptionService(c.env);
    const invoiceId = await service.generateInvoice(subscriptionId);

    return c.json({ success: true, data: { invoice_id: invoiceId } });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

// ==================
// Usage Tracking
// ==================

/**
 * POST /subscriptions/:id/usage
 * Record usage
 */
subscriptions.post('/:id/usage', async (c) => {
  try {
    const subscriptionId = c.req.param('id');
    const { feature_name, quantity, usage_date, metadata } = await c.req.json();

    const service = new SubscriptionService(c.env);
    const usageId = await service.recordUsage({
      subscriptionId,
      featureName: feature_name,
      quantity,
      usageDate: usage_date,
      metadata,
    });

    return c.json({ success: true, data: { usage_id: usageId } });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

// ==================
// Revenue Metrics
// ==================

/**
 * GET /subscriptions/metrics/mrr
 * Get current MRR
 */
subscriptions.get('/metrics/mrr', async (c) => {
  try {
    const businessId = c.get('businessId' as any) as string;

    const service = new RecurringRevenueService(c.env);
    const mrr = await service.calculateMRR(businessId);

    return c.json({ success: true, data: { mrr } });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * GET /subscriptions/metrics/arr
 * Get current ARR
 */
subscriptions.get('/metrics/arr', async (c) => {
  try {
    const businessId = c.get('businessId' as any) as string;

    const service = new RecurringRevenueService(c.env);
    const arr = await service.calculateARR(businessId);

    return c.json({ success: true, data: { arr } });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * GET /subscriptions/metrics/history
 * Get MRR history
 */
subscriptions.get('/metrics/history', async (c) => {
  try {
    const businessId = c.get('businessId' as any) as string;
    const { start_date, end_date } = c.req.query();

    if (!start_date || !end_date) {
      return c.json(
        { success: false, error: 'start_date and end_date required' },
        400
      );
    }

    const service = new RecurringRevenueService(c.env);
    const history = await service.getMRRHistory(businessId, start_date, end_date);

    return c.json({ success: true, data: { history } });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * POST /subscriptions/metrics/snapshot
 * Save MRR snapshot
 */
subscriptions.post('/metrics/snapshot', async (c) => {
  try {
    const businessId = c.get('businessId' as any) as string;
    const { date } = await c.req.json();

    const service = new RecurringRevenueService(c.env);
    await service.saveMRRSnapshot(businessId, date);

    return c.json({ success: true, data: { message: 'Snapshot saved' } });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * GET /subscriptions/metrics/churn
 * Calculate churn rate
 */
subscriptions.get('/metrics/churn', async (c) => {
  try {
    const businessId = c.get('businessId' as any) as string;
    const { start_date, end_date } = c.req.query();

    if (!start_date || !end_date) {
      return c.json(
        { success: false, error: 'start_date and end_date required' },
        400
      );
    }

    const service = new RecurringRevenueService(c.env);
    const churnRate = await service.calculateChurnRate(businessId, start_date, end_date);

    return c.json({ success: true, data: { churn_rate: churnRate } });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * GET /subscriptions/metrics/ltv/:customerId
 * Calculate customer LTV
 */
subscriptions.get('/metrics/ltv/:customerId', async (c) => {
  try {
    const businessId = c.get('businessId' as any) as string;
    const customerId = c.req.param('customerId');

    const service = new RecurringRevenueService(c.env);
    const ltv = await service.calculateLTV(businessId, customerId);

    return c.json({ success: true, data: { ltv } });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * GET /subscriptions/metrics/cohorts
 * Get cohort analysis
 */
subscriptions.get('/metrics/cohorts', async (c) => {
  try {
    const businessId = c.get('businessId' as any) as string;
    const { start_month, end_month } = c.req.query();

    if (!start_month || !end_month) {
      return c.json(
        { success: false, error: 'start_month and end_month required' },
        400
      );
    }

    const service = new RecurringRevenueService(c.env);
    const cohorts = await service.getCohortAnalysis(businessId, start_month, end_month);

    return c.json({ success: true, data: { cohorts } });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * GET /subscriptions/metrics/nrr
 * Calculate Net Revenue Retention
 */
subscriptions.get('/metrics/nrr', async (c) => {
  try {
    const businessId = c.get('businessId' as any) as string;
    const { start_date, end_date } = c.req.query();

    if (!start_date || !end_date) {
      return c.json(
        { success: false, error: 'start_date and end_date required' },
        400
      );
    }

    const service = new RecurringRevenueService(c.env);
    const nrr = await service.calculateNRR(businessId, start_date, end_date);

    return c.json({ success: true, data: { nrr } });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

export default subscriptions;
