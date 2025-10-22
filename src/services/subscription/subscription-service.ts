/**
 * Subscription Service
 * Manages recurring billing and subscription lifecycle
 */

import type { Env } from '../../types/env';

// ==================
// Types
// ==================

export interface SubscriptionPlan {
  id: string;
  business_id: string;
  name: string;
  description: string | null;
  billing_period: 'monthly' | 'quarterly' | 'annually' | 'custom';
  billing_interval: number;
  amount: number;
  currency: string;
  trial_period_days: number;
  setup_fee: number;
  is_active: boolean;
  metadata: string | null;
}

export interface Subscription {
  id: string;
  business_id: string;
  customer_id: string;
  plan_id: string;
  status: 'active' | 'paused' | 'cancelled' | 'expired' | 'trial';
  current_period_start: string;
  current_period_end: string;
  trial_start: string | null;
  trial_end: string | null;
  cancelled_at: string | null;
  amount: number;
  currency: string;
  quantity: number;
  discount_percentage: number;
  discount_amount: number;
  tax_percentage: number;
}

export interface SubscriptionInvoice {
  id: string;
  subscription_id: string;
  invoice_number: string;
  invoice_date: string;
  due_date: string;
  period_start: string;
  period_end: string;
  subtotal: number;
  tax_amount: number;
  discount_amount: number;
  total: number;
  currency: string;
  status: 'draft' | 'sent' | 'paid' | 'overdue' | 'void';
}

// ==================
// Subscription Service
// ==================

export class SubscriptionService {
  private env: Env;

  constructor(env: Env) {
    this.env = env;
  }

  /**
   * Create subscription plan
   */
  async createPlan(params: {
    businessId: string;
    name: string;
    description?: string;
    billingPeriod: 'monthly' | 'quarterly' | 'annually' | 'custom';
    billingInterval?: number;
    amount: number;
    currency?: string;
    trialPeriodDays?: number;
    setupFee?: number;
    metadata?: any;
  }): Promise<string> {
    const planId = crypto.randomUUID();

    await this.env.DB_MAIN.prepare(
      `INSERT INTO subscription_plans (
        id, business_id, name, description, billing_period, billing_interval,
        amount, currency, trial_period_days, setup_fee, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        planId,
        params.businessId,
        params.name,
        params.description || null,
        params.billingPeriod,
        params.billingInterval || 1,
        params.amount,
        params.currency || 'USD',
        params.trialPeriodDays || 0,
        params.setupFee || 0,
        params.metadata ? JSON.stringify(params.metadata) : null
      )
      .run();

    return planId;
  }

  /**
   * Get all active plans
   */
  async getPlans(businessId: string): Promise<SubscriptionPlan[]> {
    const { results } = await this.env.DB_MAIN.prepare(
      'SELECT * FROM subscription_plans WHERE business_id = ? AND is_active = 1 ORDER BY amount'
    )
      .bind(businessId)
      .all<SubscriptionPlan>();

    return results;
  }

  /**
   * Create subscription
   */
  async createSubscription(params: {
    businessId: string;
    customerId: string;
    planId: string;
    startDate?: string;
    quantity?: number;
    discountPercentage?: number;
    discountAmount?: number;
    taxPercentage?: number;
  }): Promise<string> {
    const db = this.env.DB_MAIN;

    // Get plan details
    const plan = await db
      .prepare('SELECT * FROM subscription_plans WHERE id = ?')
      .bind(params.planId)
      .first<SubscriptionPlan>();

    if (!plan) {
      throw new Error(`Plan ${params.planId} not found`);
    }

    const subscriptionId = crypto.randomUUID();
    const startDate = params.startDate || new Date().toISOString();
    const quantity = params.quantity || 1;

    // Calculate period end based on billing period
    const periodEnd = this.calculatePeriodEnd(
      startDate,
      plan.billing_period,
      plan.billing_interval
    );

    // Calculate trial period
    let trialStart = null;
    let trialEnd = null;
    let status: Subscription['status'] = 'active';

    if (plan.trial_period_days > 0) {
      trialStart = startDate;
      trialEnd = this.addDays(startDate, plan.trial_period_days);
      status = 'trial';
    }

    // Calculate amount with discounts
    let amount = plan.amount * quantity;
    if (params.discountPercentage) {
      amount -= amount * (params.discountPercentage / 100);
    }
    if (params.discountAmount) {
      amount -= params.discountAmount;
    }

    await db
      .prepare(
        `INSERT INTO subscriptions (
          id, business_id, customer_id, plan_id, status,
          current_period_start, current_period_end, trial_start, trial_end,
          amount, currency, quantity, discount_percentage, discount_amount, tax_percentage
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        subscriptionId,
        params.businessId,
        params.customerId,
        params.planId,
        status,
        startDate,
        periodEnd,
        trialStart,
        trialEnd,
        amount,
        plan.currency,
        quantity,
        params.discountPercentage || 0,
        params.discountAmount || 0,
        params.taxPercentage || 0
      )
      .run();

    // Generate first invoice if not in trial
    if (status === 'active') {
      await this.generateInvoice(subscriptionId);
    }

    return subscriptionId;
  }

  /**
   * Get subscriptions
   */
  async getSubscriptions(
    businessId: string,
    options?: {
      customerId?: string;
      status?: string;
    }
  ): Promise<Subscription[]> {
    let query = 'SELECT * FROM subscriptions WHERE business_id = ?';
    const params: any[] = [businessId];

    if (options?.customerId) {
      query += ' AND customer_id = ?';
      params.push(options.customerId);
    }

    if (options?.status) {
      query += ' AND status = ?';
      params.push(options.status);
    }

    query += ' ORDER BY created_at DESC';

    const { results } = await this.env.DB_MAIN.prepare(query)
      .bind(...params)
      .all<Subscription>();

    return results;
  }

  /**
   * Cancel subscription
   */
  async cancelSubscription(
    subscriptionId: string,
    reason?: string,
    immediate: boolean = false
  ): Promise<void> {
    const db = this.env.DB_MAIN;

    const subscription = await db
      .prepare('SELECT * FROM subscriptions WHERE id = ?')
      .bind(subscriptionId)
      .first<Subscription>();

    if (!subscription) {
      throw new Error(`Subscription ${subscriptionId} not found`);
    }

    if (immediate) {
      // Cancel immediately
      await db
        .prepare(
          `UPDATE subscriptions
           SET status = 'cancelled', cancelled_at = ?, cancellation_reason = ?, updated_at = datetime('now')
           WHERE id = ?`
        )
        .bind(new Date().toISOString(), reason || null, subscriptionId)
        .run();
    } else {
      // Cancel at period end
      await db
        .prepare(
          `UPDATE subscriptions
           SET cancelled_at = ?, cancellation_reason = ?, updated_at = datetime('now')
           WHERE id = ?`
        )
        .bind(subscription.current_period_end, reason || null, subscriptionId)
        .run();
    }
  }

  /**
   * Generate invoice for subscription
   */
  async generateInvoice(subscriptionId: string): Promise<string> {
    const db = this.env.DB_MAIN;

    // Get subscription with plan details
    const subscription = await db
      .prepare(
        `SELECT s.*, p.name as plan_name, p.description as plan_description
         FROM subscriptions s
         JOIN subscription_plans p ON s.plan_id = p.id
         WHERE s.id = ?`
      )
      .bind(subscriptionId)
      .first<Subscription & { plan_name: string; plan_description: string }>();

    if (!subscription) {
      throw new Error(`Subscription ${subscriptionId} not found`);
    }

    const invoiceId = crypto.randomUUID();

    // Generate invoice number
    const invoiceNumber = await this.generateInvoiceNumber(subscription.business_id);

    // Calculate amounts
    const subtotal = subscription.amount * subscription.quantity;
    const discountAmount = subscription.discount_amount;
    const taxAmount = subtotal * (subscription.tax_percentage / 100);
    const total = subtotal - discountAmount + taxAmount;

    // Create invoice
    await db
      .prepare(
        `INSERT INTO subscription_invoices (
          id, business_id, subscription_id, invoice_number, invoice_date, due_date,
          period_start, period_end, subtotal, tax_amount, discount_amount, total,
          currency, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        invoiceId,
        subscription.business_id,
        subscriptionId,
        invoiceNumber,
        new Date().toISOString(),
        this.addDays(new Date().toISOString(), 14), // 14 day payment terms
        subscription.current_period_start,
        subscription.current_period_end,
        subtotal,
        taxAmount,
        discountAmount,
        total,
        subscription.currency,
        'draft'
      )
      .run();

    // Add line item
    await db
      .prepare(
        `INSERT INTO subscription_invoice_items (
          invoice_id, description, quantity, unit_price, amount,
          period_start, period_end
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        invoiceId,
        subscription.plan_name,
        subscription.quantity,
        subscription.amount,
        subtotal,
        subscription.current_period_start,
        subscription.current_period_end
      )
      .run();

    // Add addons if any
    const addons = await db
      .prepare('SELECT * FROM subscription_addons WHERE subscription_id = ?')
      .bind(subscriptionId)
      .all();

    for (const addon of addons.results) {
      const addonAmount = (addon as any).amount * (addon as any).quantity;
      await db
        .prepare(
          `INSERT INTO subscription_invoice_items (
            invoice_id, description, quantity, unit_price, amount, is_addon
          ) VALUES (?, ?, ?, ?, ?, 1)`
        )
        .bind(
          invoiceId,
          (addon as any).name,
          (addon as any).quantity,
          (addon as any).amount,
          addonAmount
        )
        .run();
    }

    return invoiceId;
  }

  /**
   * Renew subscription (called by cron job)
   */
  async renewSubscription(subscriptionId: string): Promise<void> {
    const db = this.env.DB_MAIN;

    const subscription = await db
      .prepare('SELECT * FROM subscriptions WHERE id = ?')
      .bind(subscriptionId)
      .first<Subscription>();

    if (!subscription) {
      throw new Error(`Subscription ${subscriptionId} not found`);
    }

    // Check if cancelled
    if (subscription.cancelled_at) {
      await db
        .prepare(`UPDATE subscriptions SET status = 'cancelled', updated_at = datetime('now') WHERE id = ?`)
        .bind(subscriptionId)
        .run();
      return;
    }

    // Get plan
    const plan = await db
      .prepare('SELECT * FROM subscription_plans WHERE id = ?')
      .bind(subscription.plan_id)
      .first<SubscriptionPlan>();

    if (!plan) {
      throw new Error(`Plan ${subscription.plan_id} not found`);
    }

    // Calculate new period
    const newPeriodStart = subscription.current_period_end;
    const newPeriodEnd = this.calculatePeriodEnd(
      newPeriodStart,
      plan.billing_period,
      plan.billing_interval
    );

    // Update subscription
    await db
      .prepare(
        `UPDATE subscriptions
         SET current_period_start = ?, current_period_end = ?,
             status = 'active', trial_start = NULL, trial_end = NULL,
             updated_at = datetime('now')
         WHERE id = ?`
      )
      .bind(newPeriodStart, newPeriodEnd, subscriptionId)
      .run();

    // Generate invoice
    await this.generateInvoice(subscriptionId);
  }

  /**
   * Record usage for metered billing
   */
  async recordUsage(params: {
    subscriptionId: string;
    featureName: string;
    quantity: number;
    usageDate?: string;
    metadata?: any;
  }): Promise<string> {
    const usageId = crypto.randomUUID();

    await this.env.DB_MAIN.prepare(
      `INSERT INTO subscription_usage (
        id, subscription_id, feature_name, usage_quantity, usage_date, metadata
      ) VALUES (?, ?, ?, ?, ?, ?)`
    )
      .bind(
        usageId,
        params.subscriptionId,
        params.featureName,
        params.quantity,
        params.usageDate || new Date().toISOString(),
        params.metadata ? JSON.stringify(params.metadata) : null
      )
      .run();

    return usageId;
  }

  // Helper methods

  private calculatePeriodEnd(
    startDate: string,
    period: string,
    interval: number
  ): string {
    const start = new Date(startDate);

    switch (period) {
      case 'monthly':
        start.setMonth(start.getMonth() + interval);
        break;
      case 'quarterly':
        start.setMonth(start.getMonth() + 3 * interval);
        break;
      case 'annually':
        start.setFullYear(start.getFullYear() + interval);
        break;
    }

    return start.toISOString();
  }

  private addDays(dateString: string, days: number): string {
    const date = new Date(dateString);
    date.setDate(date.getDate() + days);
    return date.toISOString();
  }

  private async generateInvoiceNumber(businessId: string): Promise<string> {
    const result = await this.env.DB_MAIN.prepare(
      `SELECT COUNT(*) as count FROM subscription_invoices WHERE business_id = ?`
    )
      .bind(businessId)
      .first<{ count: number }>();

    const count = result?.count || 0;
    return `INV-${new Date().getFullYear()}-${String(count + 1).padStart(5, '0')}`;
  }
}
