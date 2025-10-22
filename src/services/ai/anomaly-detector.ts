// @ts-nocheck
/**
 * AI-Powered Anomaly Detection Service
 * Detects suspicious transactions, duplicates, and outliers
 */

import type { Env } from '../../types/env';import { Logger } from "../../shared/logger";
const logger = new Logger({ component: "services-ai-anomaly-detector" });



export interface Anomaly {
  id: string;
  transaction_type: 'bank' | 'invoice' | 'expense' | 'payment';
  transaction_id: string;
  anomaly_type: 'duplicate' | 'outlier' | 'unusual_amount' | 'suspicious_vendor' | 'timing_anomaly';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  details: any;
  confidence: number;
}

export class AnomalyDetector {
  constructor(private env: Env) {}

  /**
   * Scan for anomalies in recent transactions
   */
  async scanForAnomalies(businessId: string, daysBack: number = 30): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = [];

    const dateFrom = new Date();
    dateFrom.setDate(dateFrom.getDate() - daysBack);

    try {
      // Check for duplicate transactions
      const duplicates = await this.detectDuplicates(businessId, dateFrom);
      anomalies.push(...duplicates);

      // Check for amount outliers
      const outliers = await this.detectOutliers(businessId, dateFrom);
      anomalies.push(...outliers);

      // Check for suspicious vendors
      const suspiciousVendors = await this.detectSuspiciousVendors(businessId, dateFrom);
      anomalies.push(...suspiciousVendors);

      // Check for timing anomalies
      const timingAnomalies = await this.detectTimingAnomalies(businessId, dateFrom);
      anomalies.push(...timingAnomalies);

      // Save anomalies to database
      for (const anomaly of anomalies) {
        await this.saveAnomaly(businessId, anomaly);
      }

      return anomalies;
    } catch (error) {
      logger.error('Anomaly detection error:', error);
      return [];
    }
  }

  /**
   * Detect duplicate transactions
   */
  private async detectDuplicates(businessId: string, dateFrom: Date): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = [];

    try {
      // Check for duplicate expenses
      const expenseDuplicates = await this.env.DB.prepare(`
        SELECT
          e1.id as id1,
          e2.id as id2,
          e1.amount,
          e1.vendor_name,
          e1.expense_date,
          e1.description
        FROM expenses e1
        JOIN expenses e2 ON
          e1.business_id = e2.business_id
          AND e1.id < e2.id
          AND e1.amount = e2.amount
          AND e1.vendor_name = e2.vendor_name
          AND DATE(e1.expense_date) = DATE(e2.expense_date)
        WHERE e1.business_id = ?
          AND e1.expense_date >= ?
          AND e1.status != 'cancelled'
        LIMIT 50
      `).bind(businessId, dateFrom.toISOString().split('T')[0]).all();

      for (const dup of expenseDuplicates.results) {
        anomalies.push({
          id: crypto.randomUUID(),
          transaction_type: 'expense',
          transaction_id: dup.id2 as string,
          anomaly_type: 'duplicate',
          severity: 'high',
          description: `Possible duplicate expense: ${dup.vendor_name} for $${dup.amount} on ${dup.expense_date}`,
          details: {
            duplicate_of: dup.id1,
            amount: dup.amount,
            vendor: dup.vendor_name,
            date: dup.expense_date
          },
          confidence: 90
        });
      }

      // Check for duplicate invoices
      const invoiceDuplicates = await this.env.DB.prepare(`
        SELECT
          i1.id as id1,
          i2.id as id2,
          i1.total,
          i1.customer_name,
          i1.invoice_number
        FROM invoices i1
        JOIN invoices i2 ON
          i1.business_id = i2.business_id
          AND i1.id < i2.id
          AND i1.invoice_number = i2.invoice_number
        WHERE i1.business_id = ?
          AND i1.issue_date >= ?
          AND i1.status != 'cancelled'
        LIMIT 50
      `).bind(businessId, dateFrom.toISOString().split('T')[0]).all();

      for (const dup of invoiceDuplicates.results) {
        anomalies.push({
          id: crypto.randomUUID(),
          transaction_type: 'invoice',
          transaction_id: dup.id2 as string,
          anomaly_type: 'duplicate',
          severity: 'high',
          description: `Duplicate invoice number: ${dup.invoice_number} for ${dup.customer_name}`,
          details: {
            duplicate_of: dup.id1,
            invoice_number: dup.invoice_number,
            customer: dup.customer_name
          },
          confidence: 95
        });
      }
    } catch (error) {
      logger.error('Duplicate detection error:', error);
    }

    return anomalies;
  }

  /**
   * Detect amount outliers using statistical methods
   */
  private async detectOutliers(businessId: string, dateFrom: Date): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = [];

    try {
      // Get expense statistics
      const expenseStats = await this.env.DB.prepare(`
        SELECT
          AVG(amount) as avg_amount,
          MAX(amount) as max_amount,
          MIN(amount) as min_amount
        FROM expenses
        WHERE business_id = ?
          AND expense_date >= ?
          AND status != 'cancelled'
      `).bind(businessId, dateFrom.toISOString().split('T')[0]).first() as any;

      if (!expenseStats) return anomalies;

      const avgAmount = expenseStats.avg_amount as number;
      const threshold = avgAmount * 3; // 3x average is suspicious

      // Find outliers
      const outliers = await this.env.DB.prepare(`
        SELECT id, amount, vendor_name, expense_date, description
        FROM expenses
        WHERE business_id = ?
          AND expense_date >= ?
          AND amount > ?
          AND status != 'cancelled'
        ORDER BY amount DESC
        LIMIT 20
      `).bind(businessId, dateFrom.toISOString().split('T')[0], threshold).all();

      for (const outlier of outliers.results) {
        const timesAverage = (outlier.amount as number) / avgAmount;

        anomalies.push({
          id: crypto.randomUUID(),
          transaction_type: 'expense',
          transaction_id: outlier.id as string,
          anomaly_type: 'outlier',
          severity: timesAverage > 10 ? 'critical' : timesAverage > 5 ? 'high' : 'medium',
          description: `Unusually large expense: $${outlier.amount} (${timesAverage.toFixed(1)}x average) to ${outlier.vendor_name}`,
          details: {
            amount: outlier.amount,
            average_amount: avgAmount,
            times_average: timesAverage,
            vendor: outlier.vendor_name,
            date: outlier.expense_date
          },
          confidence: Math.min(60 + (timesAverage * 5), 95)
        });
      }
    } catch (error) {
      logger.error('Outlier detection error:', error);
    }

    return anomalies;
  }

  /**
   * Detect suspicious vendors
   */
  private async detectSuspiciousVendors(businessId: string, dateFrom: Date): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = [];

    try {
      // Check for new vendors with large amounts
      const suspiciousVendors = await this.env.DB.prepare(`
        SELECT
          vendor_name,
          SUM(amount) as total_amount,
          COUNT(*) as transaction_count,
          MIN(expense_date) as first_transaction
        FROM expenses
        WHERE business_id = ?
          AND expense_date >= ?
          AND status != 'cancelled'
        GROUP BY vendor_name
        HAVING transaction_count = 1 AND total_amount > 1000
        ORDER BY total_amount DESC
        LIMIT 20
      `).bind(businessId, dateFrom.toISOString().split('T')[0]).all();

      for (const vendor of suspiciousVendors.results) {
        // Check if this is truly a new vendor
        const firstDaysDiff = Math.floor(
          (new Date().getTime() - new Date(vendor.first_transaction as string).getTime()) / (1000 * 60 * 60 * 24)
        );

        if (firstDaysDiff <= 7) {
          anomalies.push({
            id: crypto.randomUUID(),
            transaction_type: 'expense',
            transaction_id: crypto.randomUUID(), // Group-level
            anomaly_type: 'suspicious_vendor',
            severity: (vendor.total_amount as number) > 5000 ? 'high' : 'medium',
            description: `New vendor with large transaction: ${vendor.vendor_name} ($${vendor.total_amount})`,
            details: {
              vendor: vendor.vendor_name,
              amount: vendor.total_amount,
              first_transaction: vendor.first_transaction,
              days_since_first: firstDaysDiff
            },
            confidence: 70
          });
        }
      }
    } catch (error) {
      logger.error('Suspicious vendor detection error:', error);
    }

    return anomalies;
  }

  /**
   * Detect timing anomalies (unusual transaction patterns)
   */
  private async detectTimingAnomalies(businessId: string, dateFrom: Date): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = [];

    try {
      // Check for expenses on weekends/holidays (unusual for business expenses)
      const weekendExpenses = await this.env.DB.prepare(`
        SELECT id, amount, vendor_name, expense_date, description
        FROM expenses
        WHERE business_id = ?
          AND expense_date >= ?
          AND CAST(strftime('%w', expense_date) AS INTEGER) IN (0, 6)
          AND amount > 500
          AND status != 'cancelled'
        LIMIT 20
      `).bind(businessId, dateFrom.toISOString().split('T')[0]).all();

      for (const expense of weekendExpenses.results) {
        const dayOfWeek = new Date(expense.expense_date as string).getDay();
        const dayName = dayOfWeek === 0 ? 'Sunday' : 'Saturday';

        anomalies.push({
          id: crypto.randomUUID(),
          transaction_type: 'expense',
          transaction_id: expense.id as string,
          anomaly_type: 'timing_anomaly',
          severity: 'low',
          description: `Unusual ${dayName} expense: $${expense.amount} to ${expense.vendor_name}`,
          details: {
            amount: expense.amount,
            vendor: expense.vendor_name,
            date: expense.expense_date,
            day_of_week: dayName
          },
          confidence: 60
        });
      }

      // Check for late-night transactions (potential fraud)
      // This would require timestamp data, not just dates
      // Can be added when we have full timestamp support
    } catch (error) {
      logger.error('Timing anomaly detection error:', error);
    }

    return anomalies;
  }

  /**
   * Save anomaly to database
   */
  private async saveAnomaly(businessId: string, anomaly: Anomaly): Promise<void> {
    try {
      // Check if this anomaly already exists
      const existing = await this.env.DB.prepare(`
        SELECT id FROM transaction_anomalies
        WHERE transaction_id = ?
          AND anomaly_type = ?
          AND status = 'open'
      `).bind(anomaly.transaction_id, anomaly.anomaly_type).first() as any;

      if (existing) {
        return; // Already flagged
      }

      await this.env.DB.prepare(`
        INSERT INTO transaction_anomalies (
          id, business_id, transaction_type, transaction_id,
          anomaly_type, severity, description, details, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', datetime('now'))
      `).bind(
        anomaly.id,
        businessId,
        anomaly.transaction_type,
        anomaly.transaction_id,
        anomaly.anomaly_type,
        anomaly.severity,
        anomaly.description,
        JSON.stringify(anomaly.details)
      ).run();
    } catch (error) {
      logger.error('Save anomaly error:', error);
    }
  }

  /**
   * Get open anomalies for a business
   */
  async getOpenAnomalies(businessId: string): Promise<any[]> {
    try {
      const result = await this.env.DB.prepare(`
        SELECT
          id, transaction_type, transaction_id, anomaly_type,
          severity, description, details, created_at
        FROM transaction_anomalies
        WHERE business_id = ?
          AND status = 'open'
        ORDER BY
          CASE severity
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 4
          END,
          created_at DESC
        LIMIT 100
      `).bind(businessId).all();

      return result.results.map((r: any) => ({
        ...r,
        details: JSON.parse(r.details)
      }));
    } catch (error) {
      logger.error('Get anomalies error:', error);
      return [];
    }
  }

  /**
   * Resolve an anomaly
   */
  async resolveAnomaly(
    anomalyId: string,
    businessId: string,
    userId: string,
    resolution: 'resolved' | 'false_positive'
  ): Promise<boolean> {
    try {
      await this.env.DB.prepare(`
        UPDATE transaction_anomalies
        SET
          status = ?,
          resolved_by = ?,
          resolved_at = datetime('now')
        WHERE id = ? AND business_id = ?
      `).bind(resolution, userId, anomalyId, businessId).run();

      return true;
    } catch (error) {
      logger.error('Resolve anomaly error:', error);
      return false;
    }
  }
}
