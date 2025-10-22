/**
 * Recurring Revenue Service
 * MRR/ARR tracking and SaaS metrics
 */

import type { Env } from '../../types/env';

// ==================
// Types
// ==================

export interface RecurringRevenueMetrics {
  metric_date: string;
  mrr: number;
  arr: number;
  active_subscriptions: number;
  new_mrr: number;
  expansion_mrr: number;
  contraction_mrr: number;
  churned_mrr: number;
  reactivation_mrr: number;
}

export interface MRRMovement {
  type: 'new' | 'expansion' | 'contraction' | 'churn' | 'reactivation';
  amount: number;
  subscription_id: string;
  customer_id: string;
  date: string;
}

// ==================
// Recurring Revenue Service
// ==================

export class RecurringRevenueService {
  private env: Env;

  constructor(env: Env) {
    this.env = env;
  }

  /**
   * Calculate current MRR
   */
  async calculateMRR(businessId: string): Promise<number> {
    const db = this.env.DB_MAIN;

    const result = await db
      .prepare(
        `SELECT SUM(
          CASE
            WHEN p.billing_period = 'monthly' THEN s.amount
            WHEN p.billing_period = 'quarterly' THEN s.amount / 3
            WHEN p.billing_period = 'annually' THEN s.amount / 12
            ELSE s.amount
          END
        ) as mrr
        FROM subscriptions s
        JOIN subscription_plans p ON s.plan_id = p.id
        WHERE s.business_id = ? AND s.status IN ('active', 'trial')`
      )
      .bind(businessId)
      .first<{ mrr: number | null }>();

    return result?.mrr || 0;
  }

  /**
   * Calculate ARR (Annual Recurring Revenue)
   */
  async calculateARR(businessId: string): Promise<number> {
    const mrr = await this.calculateMRR(businessId);
    return mrr * 12;
  }

  /**
   * Calculate MRR movements
   */
  async calculateMRRMovements(
    businessId: string,
    startDate: string,
    endDate: string
  ): Promise<{
    new_mrr: number;
    expansion_mrr: number;
    contraction_mrr: number;
    churned_mrr: number;
    reactivation_mrr: number;
  }> {
    const db = this.env.DB_MAIN;

    // New MRR (new subscriptions)
    const newMRR = await db
      .prepare(
        `SELECT SUM(
          CASE
            WHEN p.billing_period = 'monthly' THEN s.amount
            WHEN p.billing_period = 'quarterly' THEN s.amount / 3
            WHEN p.billing_period = 'annually' THEN s.amount / 12
            ELSE s.amount
          END
        ) as total
        FROM subscriptions s
        JOIN subscription_plans p ON s.plan_id = p.id
        WHERE s.business_id = ?
          AND s.created_at >= ? AND s.created_at <= ?
          AND s.status IN ('active', 'trial')`
      )
      .bind(businessId, startDate, endDate)
      .first<{ total: number | null }>();

    // Churned MRR (cancelled subscriptions)
    const churnedMRR = await db
      .prepare(
        `SELECT SUM(
          CASE
            WHEN p.billing_period = 'monthly' THEN s.amount
            WHEN p.billing_period = 'quarterly' THEN s.amount / 3
            WHEN p.billing_period = 'annually' THEN s.amount / 12
            ELSE s.amount
          END
        ) as total
        FROM subscriptions s
        JOIN subscription_plans p ON s.plan_id = p.id
        WHERE s.business_id = ?
          AND s.cancelled_at >= ? AND s.cancelled_at <= ?
          AND s.status = 'cancelled'`
      )
      .bind(businessId, startDate, endDate)
      .first<{ total: number | null }>();

    // TODO: Implement expansion, contraction, and reactivation tracking
    // This requires tracking subscription quantity/plan changes

    return {
      new_mrr: newMRR?.total || 0,
      expansion_mrr: 0, // Placeholder
      contraction_mrr: 0, // Placeholder
      churned_mrr: churnedMRR?.total || 0,
      reactivation_mrr: 0, // Placeholder
    };
  }

  /**
   * Save daily MRR snapshot
   */
  async saveMRRSnapshot(businessId: string, date?: string): Promise<void> {
    const db = this.env.DB_MAIN;
    const metricDate = date || new Date().toISOString().split('T')[0];

    const mrr = await this.calculateMRR(businessId);
    const arr = mrr * 12;

    const activeSubscriptions = await db
      .prepare(
        `SELECT COUNT(*) as count
         FROM subscriptions
         WHERE business_id = ? AND status IN ('active', 'trial')`
      )
      .bind(businessId)
      .first<{ count: number }>();

    // Get MRR movements for the day
    const startOfDay = `${metricDate}T00:00:00Z`;
    const endOfDay = `${metricDate}T23:59:59Z`;
    const movements = await this.calculateMRRMovements(businessId, startOfDay, endOfDay);

    await db
      .prepare(
        `INSERT OR REPLACE INTO recurring_revenue_metrics (
          business_id, metric_date, mrr, arr, active_subscriptions,
          new_mrr, expansion_mrr, contraction_mrr, churned_mrr, reactivation_mrr
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        businessId,
        metricDate,
        mrr,
        arr,
        activeSubscriptions?.count || 0,
        movements.new_mrr,
        movements.expansion_mrr,
        movements.contraction_mrr,
        movements.churned_mrr,
        movements.reactivation_mrr
      )
      .run();
  }

  /**
   * Get MRR history
   */
  async getMRRHistory(
    businessId: string,
    startDate: string,
    endDate: string
  ): Promise<RecurringRevenueMetrics[]> {
    const { results } = await this.env.DB_MAIN.prepare(
      `SELECT * FROM recurring_revenue_metrics
       WHERE business_id = ? AND metric_date >= ? AND metric_date <= ?
       ORDER BY metric_date`
    )
      .bind(businessId, startDate, endDate)
      .all<RecurringRevenueMetrics>();

    return results;
  }

  /**
   * Calculate customer churn rate
   */
  async calculateChurnRate(
    businessId: string,
    startDate: string,
    endDate: string
  ): Promise<number> {
    const db = this.env.DB_MAIN;

    // Customers at start of period
    const startCustomers = await db
      .prepare(
        `SELECT COUNT(DISTINCT customer_id) as count
         FROM subscriptions
         WHERE business_id = ? AND created_at < ? AND status = 'active'`
      )
      .bind(businessId, startDate)
      .first<{ count: number }>();

    // Customers who churned during period
    const churnedCustomers = await db
      .prepare(
        `SELECT COUNT(DISTINCT customer_id) as count
         FROM subscriptions
         WHERE business_id = ?
           AND cancelled_at >= ? AND cancelled_at <= ?
           AND status = 'cancelled'`
      )
      .bind(businessId, startDate, endDate)
      .first<{ count: number }>();

    const start = startCustomers?.count || 0;
    const churned = churnedCustomers?.count || 0;

    return start > 0 ? (churned / start) * 100 : 0;
  }

  /**
   * Calculate customer lifetime value
   */
  async calculateLTV(businessId: string, customerId: string): Promise<number> {
    const db = this.env.DB_MAIN;

    // Total revenue from customer
    const totalRevenue = await db
      .prepare(
        `SELECT SUM(si.total) as total
         FROM subscription_invoices si
         JOIN subscriptions s ON si.subscription_id = s.id
         WHERE s.business_id = ? AND s.customer_id = ? AND si.status = 'paid'`
      )
      .bind(businessId, customerId)
      .first<{ total: number | null }>();

    // Number of months customer has been subscribed
    const lifetimeMonths = await db
      .prepare(
        `SELECT
          CAST((julianday('now') - julianday(MIN(created_at))) / 30 AS INTEGER) as months
         FROM subscriptions
         WHERE business_id = ? AND customer_id = ?`
      )
      .bind(businessId, customerId)
      .first<{ months: number | null }>();

    const revenue = totalRevenue?.total || 0;
    const months = lifetimeMonths?.months || 1;
    void months;

    // Simple LTV calculation: (average monthly revenue) / (monthly churn rate)
    // For now, just return total revenue
    return revenue;
  }

  /**
   * Get subscription cohort analysis
   */
  async getCohortAnalysis(
    businessId: string,
    startMonth: string,
    endMonth: string
  ): Promise<
    Array<{
      cohort_month: string;
      initial_customers: number;
      retained_customers: number;
      retention_rate: number;
    }>
  > {
    const db = this.env.DB_MAIN;

    const { results } = await db
      .prepare(
        `SELECT
          strftime('%Y-%m', created_at) as cohort_month,
          COUNT(*) as initial_customers,
          SUM(CASE WHEN status IN ('active', 'trial') THEN 1 ELSE 0 END) as retained_customers,
          CAST(SUM(CASE WHEN status IN ('active', 'trial') THEN 1 ELSE 0 END) AS REAL) / COUNT(*) * 100 as retention_rate
         FROM subscriptions
         WHERE business_id = ?
           AND strftime('%Y-%m', created_at) >= ?
           AND strftime('%Y-%m', created_at) <= ?
         GROUP BY cohort_month
         ORDER BY cohort_month`
      )
      .bind(businessId, startMonth, endMonth)
      .all();

    return results as any[];
  }

  /**
   * Calculate net revenue retention (NRR)
   */
  async calculateNRR(
    businessId: string,
    startDate: string,
    endDate: string
  ): Promise<number> {
    const movements = await this.calculateMRRMovements(businessId, startDate, endDate);

    const startingMRR = await this.calculateMRR(businessId);

    if (startingMRR === 0) return 0;

    const endingMRR =
      startingMRR +
      movements.expansion_mrr +
      movements.reactivation_mrr -
      movements.contraction_mrr -
      movements.churned_mrr;

    return (endingMRR / startingMRR) * 100;
  }
}
