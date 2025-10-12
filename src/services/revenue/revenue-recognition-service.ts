/**
 * Revenue Recognition Service
 * ASC 606 compliant revenue recognition
 */

import type { Env } from '../../types';

// ==================
// Types
// ==================

export interface RevenueContract {
  id: string;
  business_id: string;
  customer_id: string;
  contract_number: string;
  contract_date: string;
  start_date: string;
  end_date: string | null;
  total_contract_value: number;
  currency: string;
  status: 'active' | 'completed' | 'cancelled' | 'amended';
  recognition_method: 'over_time' | 'point_in_time';
}

export interface PerformanceObligation {
  id: string;
  contract_id: string;
  obligation_number: number;
  description: string;
  standalone_selling_price: number;
  allocated_amount: number;
  status: 'unsatisfied' | 'partially_satisfied' | 'satisfied';
  satisfaction_type: 'over_time' | 'point_in_time';
  percent_complete: number;
  recognition_method: 'straight_line' | 'units_of_delivery' | 'milestones';
}

export interface RecognizedRevenue {
  id: string;
  contract_id: string;
  obligation_id: string | null;
  recognition_date: string;
  amount: number;
  recognition_basis: string;
}

// ==================
// Revenue Recognition Service
// ==================

export class RevenueRecognitionService {
  private env: Env;

  constructor(env: Env) {
    this.env = env;
  }

  /**
   * ASC 606 Step 1: Identify the contract
   */
  async createContract(params: {
    businessId: string;
    customerId: string;
    contractNumber: string;
    contractDate: string;
    startDate: string;
    endDate?: string;
    totalContractValue: number;
    currency?: string;
    recognitionMethod?: 'over_time' | 'point_in_time';
  }): Promise<string> {
    const contractId = crypto.randomUUID();

    await this.env.DB_MAIN.prepare(
      `INSERT INTO revenue_contracts (
        id, business_id, customer_id, contract_number, contract_date,
        start_date, end_date, total_contract_value, currency, recognition_method
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        contractId,
        params.businessId,
        params.customerId,
        params.contractNumber,
        params.contractDate,
        params.startDate,
        params.endDate || null,
        params.totalContractValue,
        params.currency || 'USD',
        params.recognitionMethod || 'over_time'
      )
      .run();

    return contractId;
  }

  /**
   * ASC 606 Step 2: Identify performance obligations
   */
  async createPerformanceObligation(params: {
    contractId: string;
    obligationNumber: number;
    description: string;
    standaloneSellingPrice: number;
    allocatedAmount: number;
    startDate: string;
    endDate?: string;
    satisfactionType?: 'over_time' | 'point_in_time';
    recognitionMethod?: 'straight_line' | 'units_of_delivery' | 'milestones';
  }): Promise<string> {
    const obligationId = crypto.randomUUID();

    await this.env.DB_MAIN.prepare(
      `INSERT INTO performance_obligations (
        id, contract_id, obligation_number, description,
        standalone_selling_price, allocated_amount,
        start_date, end_date, satisfaction_type, recognition_method
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        obligationId,
        params.contractId,
        params.obligationNumber,
        params.description,
        params.standaloneSellingPrice,
        params.allocatedAmount,
        params.startDate,
        params.endDate || null,
        params.satisfactionType || 'over_time',
        params.recognitionMethod || 'straight_line'
      )
      .run();

    // Generate recognition schedule
    await this.generateRecognitionSchedule(obligationId);

    return obligationId;
  }

  /**
   * ASC 606 Step 3: Allocate transaction price
   * (Relative standalone selling price method)
   */
  async allocateTransactionPrice(contractId: string): Promise<void> {
    const db = this.env.DB_MAIN;

    // Get contract
    const contract = await db
      .prepare('SELECT * FROM revenue_contracts WHERE id = ?')
      .bind(contractId)
      .first<RevenueContract>();

    if (!contract) {
      throw new Error(`Contract ${contractId} not found`);
    }

    // Get all obligations
    const { results: obligations } = await db
      .prepare('SELECT * FROM performance_obligations WHERE contract_id = ?')
      .bind(contractId)
      .all<PerformanceObligation>();

    if (obligations.length === 0) return;

    // Calculate total standalone selling price
    const totalSSP = obligations.reduce(
      (sum, o) => sum + o.standalone_selling_price,
      0
    );

    // Allocate based on relative SSP
    for (const obligation of obligations) {
      const allocationPercentage = obligation.standalone_selling_price / totalSSP;
      const allocatedAmount = contract.total_contract_value * allocationPercentage;

      await db
        .prepare(
          `UPDATE performance_obligations
           SET allocated_amount = ?, updated_at = datetime('now')
           WHERE id = ?`
        )
        .bind(allocatedAmount, obligation.id)
        .run();
    }
  }

  /**
   * Generate revenue recognition schedule
   */
  private async generateRecognitionSchedule(obligationId: string): Promise<void> {
    const db = this.env.DB_MAIN;

    const obligation = await db
      .prepare('SELECT * FROM performance_obligations WHERE id = ?')
      .bind(obligationId)
      .first<PerformanceObligation>();

    if (!obligation) return;

    if (obligation.recognition_method === 'straight_line') {
      await this.generateStraightLineSchedule(obligation);
    }
    // Other methods (units_of_delivery, milestones) require different logic
  }

  /**
   * Generate straight-line recognition schedule
   */
  private async generateStraightLineSchedule(
    obligation: PerformanceObligation
  ): Promise<void> {
    const db = this.env.DB_MAIN;

    const startDate = new Date(obligation.start_date);
    const endDate = obligation.end_date ? new Date(obligation.end_date) : null;

    if (!endDate) return; // Need end date for straight-line

    // Calculate number of periods (months)
    const months =
      (endDate.getFullYear() - startDate.getFullYear()) * 12 +
      (endDate.getMonth() - startDate.getMonth()) +
      1;

    const monthlyAmount = obligation.allocated_amount / months;

    // Generate schedule entries
    for (let i = 0; i < months; i++) {
      const periodDate = new Date(startDate);
      periodDate.setMonth(periodDate.getMonth() + i);

      await db
        .prepare(
          `INSERT INTO revenue_schedule (obligation_id, scheduled_date, scheduled_amount)
           VALUES (?, ?, ?)`
        )
        .bind(obligationId, periodDate.toISOString(), monthlyAmount)
        .run();
    }
  }

  /**
   * ASC 606 Step 5: Recognize revenue
   */
  async recognizeRevenue(obligationId: string, recognitionDate: string): Promise<string> {
    const db = this.env.DB_MAIN;

    // Get scheduled amount for this date
    const scheduled = await db
      .prepare(
        `SELECT * FROM revenue_schedule
         WHERE obligation_id = ? AND scheduled_date = ? AND is_recognized = 0`
      )
      .bind(obligationId, recognitionDate)
      .first<{ id: string; scheduled_amount: number }>();

    if (!scheduled) {
      throw new Error('No scheduled revenue for this date');
    }

    // Get obligation and contract
    const obligation = await db
      .prepare('SELECT * FROM performance_obligations WHERE id = ?')
      .bind(obligationId)
      .first<PerformanceObligation>();

    const contract = await db
      .prepare('SELECT * FROM revenue_contracts WHERE id = ?')
      .bind(obligation!.contract_id)
      .first<RevenueContract>();

    // Create recognized revenue record
    const revenueId = crypto.randomUUID();
    await db
      .prepare(
        `INSERT INTO recognized_revenue (
          id, business_id, contract_id, obligation_id, recognition_date,
          amount, currency, recognition_basis
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        revenueId,
        contract!.business_id,
        obligation!.contract_id,
        obligationId,
        recognitionDate,
        scheduled.scheduled_amount,
        contract!.currency,
        'time_elapsed'
      )
      .run();

    // Mark schedule entry as recognized
    await db
      .prepare(
        `UPDATE revenue_schedule
         SET is_recognized = 1, recognized_date = ?, recognized_revenue_id = ?
         WHERE id = ?`
      )
      .bind(recognitionDate, revenueId, scheduled.id)
      .run();

    // Update obligation percent complete
    await this.updatePercentComplete(obligationId);

    return revenueId;
  }

  /**
   * Update obligation percent complete
   */
  private async updatePercentComplete(obligationId: string): Promise<void> {
    const db = this.env.DB_MAIN;

    const result = await db
      .prepare(
        `SELECT
          COUNT(*) as total,
          SUM(CASE WHEN is_recognized = 1 THEN 1 ELSE 0 END) as recognized
         FROM revenue_schedule
         WHERE obligation_id = ?`
      )
      .bind(obligationId)
      .first<{ total: number; recognized: number }>();

    if (!result || result.total === 0) return;

    const percentComplete = (result.recognized / result.total) * 100;

    let status: PerformanceObligation['status'] = 'unsatisfied';
    if (percentComplete === 100) {
      status = 'satisfied';
    } else if (percentComplete > 0) {
      status = 'partially_satisfied';
    }

    await db
      .prepare(
        `UPDATE performance_obligations
         SET percent_complete = ?, status = ?, updated_at = datetime('now')
         WHERE id = ?`
      )
      .bind(percentComplete, status, obligationId)
      .run();
  }

  /**
   * Recognize milestone-based revenue
   */
  async recognizeMilestone(milestoneId: string, achievedDate: string): Promise<string> {
    const db = this.env.DB_MAIN;

    // Get milestone
    const milestone = await db
      .prepare('SELECT * FROM obligation_milestones WHERE id = ?')
      .bind(milestoneId)
      .first<{
        id: string;
        obligation_id: string;
        revenue_amount: number;
        is_achieved: boolean;
      }>();

    if (!milestone || milestone.is_achieved) {
      throw new Error('Milestone already achieved or not found');
    }

    // Mark milestone as achieved
    await db
      .prepare(
        `UPDATE obligation_milestones
         SET is_achieved = 1, achieved_date = ?
         WHERE id = ?`
      )
      .bind(achievedDate, milestoneId)
      .run();

    // Get obligation and contract
    const obligation = await db
      .prepare('SELECT * FROM performance_obligations WHERE id = ?')
      .bind(milestone.obligation_id)
      .first<PerformanceObligation>();

    const contract = await db
      .prepare('SELECT * FROM revenue_contracts WHERE id = ?')
      .bind(obligation!.contract_id)
      .first<RevenueContract>();

    // Recognize revenue
    const revenueId = crypto.randomUUID();
    await db
      .prepare(
        `INSERT INTO recognized_revenue (
          id, business_id, contract_id, obligation_id, recognition_date,
          amount, currency, recognition_basis
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        revenueId,
        contract!.business_id,
        obligation!.contract_id,
        milestone.obligation_id,
        achievedDate,
        milestone.revenue_amount,
        contract!.currency,
        'milestone'
      )
      .run();

    return revenueId;
  }

  /**
   * Get revenue to recognize for a period
   */
  async getRevenueToRecognize(
    businessId: string,
    periodDate: string
  ): Promise<
    Array<{
      obligation_id: string;
      contract_number: string;
      description: string;
      scheduled_amount: number;
    }>
  > {
    const { results } = await this.env.DB_MAIN.prepare(
      `SELECT
        rs.obligation_id,
        rc.contract_number,
        po.description,
        rs.scheduled_amount
       FROM revenue_schedule rs
       JOIN performance_obligations po ON rs.obligation_id = po.id
       JOIN revenue_contracts rc ON po.contract_id = rc.id
       WHERE rc.business_id = ?
         AND rs.scheduled_date = ?
         AND rs.is_recognized = 0
       ORDER BY rc.contract_number`
    )
      .bind(businessId, periodDate)
      .all();

    return results as any[];
  }

  /**
   * Get recognized revenue summary
   */
  async getRecognizedRevenueSummary(
    businessId: string,
    startDate: string,
    endDate: string
  ): Promise<{ total_recognized: number; by_contract: any[] }> {
    const db = this.env.DB_MAIN;

    // Total recognized
    const total = await db
      .prepare(
        `SELECT SUM(amount) as total
         FROM recognized_revenue
         WHERE business_id = ?
           AND recognition_date >= ?
           AND recognition_date <= ?
           AND is_reversed = 0`
      )
      .bind(businessId, startDate, endDate)
      .first<{ total: number | null }>();

    // By contract
    const { results: byContract } = await db
      .prepare(
        `SELECT
          rc.contract_number,
          rc.customer_id,
          SUM(rr.amount) as total_recognized
         FROM recognized_revenue rr
         JOIN revenue_contracts rc ON rr.contract_id = rc.id
         WHERE rr.business_id = ?
           AND rr.recognition_date >= ?
           AND rr.recognition_date <= ?
           AND rr.is_reversed = 0
         GROUP BY rc.id, rc.contract_number, rc.customer_id`
      )
      .bind(businessId, startDate, endDate)
      .all();

    return {
      total_recognized: total?.total || 0,
      by_contract: byContract,
    };
  }

  /**
   * Calculate remaining performance obligations (RPO)
   */
  async calculateRPO(businessId: string): Promise<number> {
    const result = await this.env.DB_MAIN.prepare(
      `SELECT SUM(po.allocated_amount - (po.allocated_amount * po.percent_complete / 100)) as rpo
       FROM performance_obligations po
       JOIN revenue_contracts rc ON po.contract_id = rc.id
       WHERE rc.business_id = ? AND po.status != 'satisfied'`
    )
      .bind(businessId)
      .first<{ rpo: number | null }>();

    return result?.rpo || 0;
  }
}
