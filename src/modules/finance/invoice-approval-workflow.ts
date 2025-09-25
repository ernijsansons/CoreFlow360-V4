/**
 * Invoice Approval Workflow
 * Handles multi-level approval process for invoices over threshold
 */

import type { D1Database } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import { FinanceAuditLogger } from './audit-logger';
import {
  Invoice,
  InvoiceStatus,
  ApprovalStatus,
  InvoiceApproval,
  ApproveInvoiceRequest,
  RejectInvoiceRequest
} from './types';
import { validateBusinessId } from './utils';

export interface ApprovalRule {
  id: string;
  name: string;
  description: string;
  thresholdAmount: number;
  currency: string;
  requiredApprovers: ApprovalLevel[];
  isActive: boolean;
  businessId: string;
}

export interface ApprovalLevel {
  level: number;
  name: string;
  description: string;
  approverUserIds: string[];
  approverRoles: string[];
  requiredApprovals: number; // Number of approvals needed at this level
  canSkipIfPreviousApprover?: boolean;
}

export interface ApprovalConfiguration {
  businessId: string;
  isEnabled: boolean;
  defaultThreshold: number;
  maxApprovalLevels: number;
  autoApproveSmallAmounts: boolean;
  smallAmountThreshold: number;
  requireCommentsOnRejection: boolean;
  notifyOnPendingApproval: boolean;
  escalationDays: number; // Days before escalating to next level
}

export interface ApprovalStats {
  totalPendingApprovals: number;
  pendingByLevel: Record<number, number>;
  averageApprovalTime: number; // In hours
  approvalsByUser: Record<string, {
    approved: number;
    rejected: number;
    pending: number;
  }>;
}

export class InvoiceApprovalWorkflow {
  private logger: Logger;
  private db: D1Database;
  private auditLogger: FinanceAuditLogger;

  constructor(db: D1Database, auditLogger: FinanceAuditLogger) {
    this.logger = new Logger();
    this.db = db;
    this.auditLogger = auditLogger;
  }

  /**
   * Check if invoice requires approval based on configured rules
   */
  async requiresApproval(
    invoice: Invoice,
    businessId: string
  ): Promise<{ required: boolean; rule?: ApprovalRule; levels?: ApprovalLevel[] }> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      const config = await this.getApprovalConfiguration(validBusinessId);

      if (!config.isEnabled) {
        return { required: false };
      }

      // Check for auto-approval of small amounts
      if (config.autoApproveSmallAmounts && invoice.total <= config.smallAmountThreshold) {
        return { required: false };
      }

      // Find applicable approval rule
      const rules = await this.getApprovalRules(validBusinessId);
      const applicableRule = this.findApplicableRule(invoice, rules);

      if (!applicableRule) {
        // Use default threshold
        if (invoice.total >= config.defaultThreshold) {
          return {
            required: true,
            levels: await this.getDefaultApprovalLevels(validBusinessId)
          };
        }
        return { required: false };
      }

      if (invoice.total >= applicableRule.thresholdAmount) {
        return {
          required: true,
          rule: applicableRule,
          levels: applicableRule.requiredApprovers
        };
      }

      return { required: false };

    } catch (error) {
      this.logger.error('Failed to check approval requirements', error, {
        invoiceId: invoice.id,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Initialize approval workflow for invoice
   */
  async initializeApprovalWorkflow(
    invoiceId: string,
    initiatedBy: string,
    businessId: string
  ): Promise<{ approvals: InvoiceApproval[]; nextApprovers: string[] }> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      const invoice = await this.getInvoice(invoiceId, validBusinessId);
      if (!invoice) {
        throw new Error('Invoice not found');
      }

      const approvalCheck = await this.requiresApproval(invoice, validBusinessId);
      if (!approvalCheck.required) {
        throw new Error('Invoice does not require approval');
      }

      const levels = approvalCheck.levels || [];
      if (levels.length === 0) {
        throw new Error('No approval levels configured');
      }

      // Create approval records for all levels
      const approvals: InvoiceApproval[] = [];
      let approvalIndex = 1;

      for (const level of levels) {
        for (const approverUserId of level.approverUserIds) {
          const approval: InvoiceApproval = {
            id: `appr_${invoiceId}_${approvalIndex}`,
            invoiceId,
            approverUserId,
            approverName: await this.getUserName(approverUserId),
            status: level.level === 1 ? ApprovalStatus.PENDING : ApprovalStatus.PENDING,
            level: level.level
          };

          approvals.push(approval);
          approvalIndex++;
        }
      }

      // Save approvals to database
      await this.saveApprovals(approvals);

      // Update invoice status
      await this.updateInvoiceApprovalStatus(
        invoiceId,
        InvoiceStatus.PENDING_APPROVAL,
        ApprovalStatus.PENDING,
        validBusinessId
      );

      // Get next approvers (level 1)
      const nextApprovers = levels[0].approverUserIds;

      // Log audit trail
      await this.auditLogger.logAction(
        'invoice',
        invoiceId,
        'APPROVAL_INITIATED',
        validBusinessId,
        initiatedBy,
        {
          totalLevels: levels.length,
          totalApprovers: approvals.length,
          thresholdAmount: approvalCheck.rule?.thresholdAmount
        }
      );

      this.logger.info('Approval workflow initialized', {
        invoiceId,
        totalLevels: levels.length,
        totalApprovers: approvals.length,
        nextApprovers: nextApprovers.length,
        businessId: validBusinessId
      });

      return { approvals, nextApprovers };

    } catch (error) {
      this.logger.error('Failed to initialize approval workflow', error, {
        invoiceId,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Approve invoice
   */
  async approveInvoice(
    request: ApproveInvoiceRequest,
    approvedBy: string,
    businessId: string
  ): Promise<{
    approval: InvoiceApproval;
    nextApprovers: string[];
    workflowComplete: boolean;
    invoice: Invoice;
  }> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      const invoice = await this.getInvoice(request.invoiceId, validBusinessId);
      if (!invoice) {
        throw new Error('Invoice not found');
      }

      if (invoice.status !== InvoiceStatus.PENDING_APPROVAL) {
        throw new Error('Invoice is not pending approval');
      }

      // Find the approval record for this user
      const userApproval = await this.getUserApproval(request.invoiceId, approvedBy, validBusinessId);
      if (!userApproval) {
        throw new Error('You are not authorized to approve this invoice');
      }

      if (userApproval.status !== ApprovalStatus.PENDING) {
        throw new Error('You have already processed this approval');
      }

      // Update approval record
      const updatedApproval: InvoiceApproval = {
        ...userApproval,
        status: ApprovalStatus.APPROVED,
        comments: request.comments,
        approvedAt: Date.now()
      };

      await this.updateApproval(updatedApproval);

      // Check if current level is complete
      const allApprovals = await this.getInvoiceApprovals(request.invoiceId, validBusinessId);
      const currentLevel = userApproval.level;
      const currentLevelApprovals = allApprovals.filter(a => a.level === currentLevel);
      const currentLevelApproved = currentLevelApprovals.filter(a => a.status === ApprovalStatus.APPROVED);

      // Get approval configuration to check required approvals
      const approvalRule = await this.getApprovalRuleForInvoice(invoice, validBusinessId);
      const levelConfig = approvalRule?.requiredApprovers.find(l => l.level === currentLevel);
      const requiredApprovals = levelConfig?.requiredApprovals || 1;

      let nextApprovers: string[] = [];
      let workflowComplete = false;

      if (currentLevelApproved.length >= requiredApprovals) {
        // Current level complete, check if there are more levels
        const maxLevel = Math.max(...allApprovals.map(a => a.level));

        if (currentLevel < maxLevel) {
          // Move to next level
          const nextLevel = currentLevel + 1;
          const nextLevelApprovals = allApprovals.filter(a => a.level === nextLevel);

          // Activate next level approvals
          for (const approval of nextLevelApprovals) {
            if (approval.status === ApprovalStatus.PENDING) {
              nextApprovers.push(approval.approverUserId);
            }
          }
        } else {
          // All levels complete - approve invoice
          workflowComplete = true;
          await this.updateInvoiceApprovalStatus(
            request.invoiceId,
            InvoiceStatus.SENT, // Move to sent status after approval
            ApprovalStatus.APPROVED,
            validBusinessId
          );
        }
      } else {
        // Still need more approvals at current level
        nextApprovers = currentLevelApprovals
          .filter(a => a.status === ApprovalStatus.PENDING)
          .map(a => a.approverUserId);
      }

      // Get updated invoice
      const updatedInvoice = await this.getInvoice(request.invoiceId, validBusinessId);
      if (!updatedInvoice) {
        throw new Error('Failed to retrieve updated invoice');
      }

      // Log audit trail
      await this.auditLogger.logAction(
        'invoice',
        request.invoiceId,
        'APPROVE',
        validBusinessId,
        approvedBy,
        {
          level: currentLevel,
          comments: request.comments,
          workflowComplete,
          nextApproversCount: nextApprovers.length
        }
      );

      this.logger.info('Invoice approved', {
        invoiceId: request.invoiceId,
        approvedBy,
        level: currentLevel,
        workflowComplete,
        nextApproversCount: nextApprovers.length,
        businessId: validBusinessId
      });

      return {
        approval: updatedApproval,
        nextApprovers,
        workflowComplete,
        invoice: updatedInvoice
      };

    } catch (error) {
      this.logger.error('Failed to approve invoice', error, {
        invoiceId: request.invoiceId,
        approvedBy,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Reject invoice
   */
  async rejectInvoice(
    request: RejectInvoiceRequest,
    rejectedBy: string,
    businessId: string
  ): Promise<{ approval: InvoiceApproval; invoice: Invoice }> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      const invoice = await this.getInvoice(request.invoiceId, validBusinessId);
      if (!invoice) {
        throw new Error('Invoice not found');
      }

      if (invoice.status !== InvoiceStatus.PENDING_APPROVAL) {
        throw new Error('Invoice is not pending approval');
      }

      // Find the approval record for this user
      const userApproval = await this.getUserApproval(request.invoiceId, rejectedBy, validBusinessId);
      if (!userApproval) {
        throw new Error('You are not authorized to reject this invoice');
      }

      if (userApproval.status !== ApprovalStatus.PENDING) {
        throw new Error('You have already processed this approval');
      }

      // Check if comments are required
      const config = await this.getApprovalConfiguration(validBusinessId);
      if (config.requireCommentsOnRejection && !request.comments) {
        throw new Error('Comments are required when rejecting an invoice');
      }

      // Update approval record
      const updatedApproval: InvoiceApproval = {
        ...userApproval,
        status: ApprovalStatus.REJECTED,
        comments: request.comments,
        rejectedAt: Date.now()
      };

      await this.updateApproval(updatedApproval);

      // Update invoice status back to draft
      await this.updateInvoiceApprovalStatus(
        request.invoiceId,
        InvoiceStatus.DRAFT,
        ApprovalStatus.REJECTED,
        validBusinessId
      );

      // Cancel all other pending approvals
      await this.cancelPendingApprovals(request.invoiceId, validBusinessId);

      // Get updated invoice
      const updatedInvoice = await this.getInvoice(request.invoiceId, validBusinessId);
      if (!updatedInvoice) {
        throw new Error('Failed to retrieve updated invoice');
      }

      // Log audit trail
      await this.auditLogger.logAction(
        'invoice',
        request.invoiceId,
        'REJECT',
        validBusinessId,
        rejectedBy,
        {
          level: userApproval.level,
          comments: request.comments
        }
      );

      this.logger.info('Invoice rejected', {
        invoiceId: request.invoiceId,
        rejectedBy,
        level: userApproval.level,
        businessId: validBusinessId
      });

      return {
        approval: updatedApproval,
        invoice: updatedInvoice
      };

    } catch (error) {
      this.logger.error('Failed to reject invoice', error, {
        invoiceId: request.invoiceId,
        rejectedBy,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Get approval statistics
   */
  async getApprovalStats(
    businessId: string,
    startDate?: number,
    endDate?: number
  ): Promise<ApprovalStats> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      let whereClause = 'i.business_id = ?';
      const params: any[] = [validBusinessId];

      if (startDate) {
        whereClause += ' AND i.created_at >= ?';
        params.push(startDate);
      }

      if (endDate) {
        whereClause += ' AND i.created_at <= ?';
        params.push(endDate);
      }

      // Get pending approvals
      const pendingResult = await this.db.prepare(`
        SELECT a.level, COUNT(*) as count
        FROM invoice_approvals a
        INNER JOIN invoices i ON a.invoice_id = i.id
        WHERE ${whereClause}
        AND a.status = 'PENDING'
        GROUP BY a.level
      `).bind(...params).all();

      const pendingByLevel: Record<number, number> = {};
      let totalPendingApprovals = 0;

      for (const row of pendingResult.results || []) {
        const level = row.level as number;
        const count = row.count as number;
        pendingByLevel[level] = count;
        totalPendingApprovals += count;
      }

      // Get approval statistics by user
      const userStatsResult = await this.db.prepare(`
        SELECT
          a.approver_user_id,
          a.status,
          COUNT(*) as count
        FROM invoice_approvals a
        INNER JOIN invoices i ON a.invoice_id = i.id
        WHERE ${whereClause}
        GROUP BY a.approver_user_id, a.status
      `).bind(...params).all();

      const approvalsByUser: Record<string, any> = {};

      for (const row of userStatsResult.results || []) {
        const userId = row.approver_user_id as string;
        const status = row.status as string;
        const count = row.count as number;

        if (!approvalsByUser[userId]) {
          approvalsByUser[userId] = { approved: 0, rejected: 0, pending: 0 };
        }

        switch (status) {
          case 'APPROVED':
            approvalsByUser[userId].approved = count;
            break;
          case 'REJECTED':
            approvalsByUser[userId].rejected = count;
            break;
          case 'PENDING':
            approvalsByUser[userId].pending = count;
            break;
        }
      }

      // Calculate average approval time
      const timingResult = await this.db.prepare(`
        SELECT AVG(a.approved_at - i.created_at) as avg_time
        FROM invoice_approvals a
        INNER JOIN invoices i ON a.invoice_id = i.id
        WHERE ${whereClause}
        AND a.status = 'APPROVED'
        AND a.approved_at IS NOT NULL
      `).bind(...params).first();

      const averageApprovalTime = timingResult?.avg_time
        ? Math.round((timingResult.avg_time as number) / (1000 * 60 * 60)) // Convert to hours
        : 0;

      return {
        totalPendingApprovals,
        pendingByLevel,
        averageApprovalTime,
        approvalsByUser
      };

    } catch (error) {
      this.logger.error('Failed to get approval stats', error, {
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Find applicable approval rule for invoice
   */
  private findApplicableRule(invoice: Invoice, rules: ApprovalRule[]): ApprovalRule | null {
    // Sort rules by threshold amount (descending) to find the most specific rule
    const sortedRules = rules
      .filter(rule => rule.isActive && rule.currency === invoice.currency)
      .sort((a, b) => b.thresholdAmount - a.thresholdAmount);

    return sortedRules.find(rule => invoice.total >= rule.thresholdAmount) || null;
  }

  /**
   * Get approval configuration
   */
  private async getApprovalConfiguration(businessId: string): Promise<ApprovalConfiguration> {
    const result = await this.db.prepare(`
      SELECT * FROM invoice_approval_config
      WHERE business_id = ?
    `).bind(businessId).first();

    if (!result) {
      // Return default configuration
      return {
        businessId,
        isEnabled: true,
        defaultThreshold: 1000,
        maxApprovalLevels: 3,
        autoApproveSmallAmounts: false,
        smallAmountThreshold: 100,
        requireCommentsOnRejection: true,
        notifyOnPendingApproval: true,
        escalationDays: 3
      };
    }

    return this.mapToApprovalConfiguration(result);
  }

  /**
   * Get approval rules
   */
  private async getApprovalRules(businessId: string): Promise<ApprovalRule[]> {
    const result = await this.db.prepare(`
      SELECT * FROM invoice_approval_rules
      WHERE business_id = ? AND is_active = 1
      ORDER BY threshold_amount DESC
    `).bind(businessId).all();

    return (result.results || []).map(row => this.mapToApprovalRule(row));
  }

  /**
   * Get default approval levels
   */
  private async getDefaultApprovalLevels(businessId: string): Promise<ApprovalLevel[]> {
    // Return simple default approval level
    return [{
      level: 1,
      name: 'Manager Approval',
      description: 'Requires manager approval',
      approverUserIds: [], // Would be populated from business configuration
      approverRoles: ['manager', 'finance_manager'],
      requiredApprovals: 1
    }];
  }

  /**
   * Helper methods for database operations
   */
  private async getInvoice(invoiceId: string, businessId: string): Promise<Invoice | null> {
    // Implementation would fetch invoice from database
    // This is a simplified version
    const result = await this.db.prepare(`
      SELECT * FROM invoices WHERE id = ? AND business_id = ?
    `).bind(invoiceId, businessId).first();

    return result ? this.mapToInvoice(result) : null;
  }

  private async getUserName(userId: string): Promise<string> {
    // Implementation would fetch user name from user management system
    return `User ${userId}`;
  }

  private async saveApprovals(approvals: InvoiceApproval[]): Promise<void> {
    for (const approval of approvals) {
      await this.db.prepare(`
        INSERT INTO invoice_approvals (
          id, invoice_id, approver_user_id, approver_name, status,
          level, comments, approved_at, rejected_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        approval.id,
        approval.invoiceId,
        approval.approverUserId,
        approval.approverName,
        approval.status,
        approval.level,
        approval.comments || null,
        approval.approvedAt || null,
        approval.rejectedAt || null
      ).run();
    }
  }

  private async updateInvoiceApprovalStatus(
    invoiceId: string,
    status: InvoiceStatus,
    approvalStatus: ApprovalStatus,
    businessId: string
  ): Promise<void> {
    await this.db.prepare(`
      UPDATE invoices
      SET status = ?, approval_status = ?, updated_at = ?
      WHERE id = ? AND business_id = ?
    `).bind(status, approvalStatus, Date.now(), invoiceId, businessId).run();
  }

  private async getUserApproval(
    invoiceId: string,
    userId: string,
    businessId: string
  ): Promise<InvoiceApproval | null> {
    const result = await this.db.prepare(`
      SELECT a.* FROM invoice_approvals a
      INNER JOIN invoices i ON a.invoice_id = i.id
      WHERE a.invoice_id = ? AND a.approver_user_id = ? AND i.business_id = ?
    `).bind(invoiceId, userId, businessId).first();

    return result ? this.mapToInvoiceApproval(result) : null;
  }

  private async updateApproval(approval: InvoiceApproval): Promise<void> {
    await this.db.prepare(`
      UPDATE invoice_approvals
      SET status = ?, comments = ?, approved_at = ?, rejected_at = ?
      WHERE id = ?
    `).bind(
      approval.status,
      approval.comments || null,
      approval.approvedAt || null,
      approval.rejectedAt || null,
      approval.id
    ).run();
  }

  private async getInvoiceApprovals(invoiceId: string, businessId: string): Promise<InvoiceApproval[]> {
    const result = await this.db.prepare(`
      SELECT a.* FROM invoice_approvals a
      INNER JOIN invoices i ON a.invoice_id = i.id
      WHERE a.invoice_id = ? AND i.business_id = ?
      ORDER BY a.level, a.id
    `).bind(invoiceId, businessId).all();

    return (result.results || []).map(row => this.mapToInvoiceApproval(row));
  }

  private async getApprovalRuleForInvoice(invoice: Invoice, businessId: string): Promise<ApprovalRule | null> {
    const rules = await this.getApprovalRules(businessId);
    return this.findApplicableRule(invoice, rules);
  }

  private async cancelPendingApprovals(invoiceId: string, businessId: string): Promise<void> {
    await this.db.prepare(`
      UPDATE invoice_approvals
      SET status = 'CANCELLED'
      WHERE invoice_id = ? AND status = 'PENDING'
      AND invoice_id IN (
        SELECT id FROM invoices WHERE business_id = ?
      )
    `).bind(invoiceId, businessId).run();
  }

  /**
   * Mapping functions
   */
  private mapToApprovalConfiguration(row: any): ApprovalConfiguration {
    return {
      businessId: row.business_id,
      isEnabled: Boolean(row.is_enabled),
      defaultThreshold: row.default_threshold,
      maxApprovalLevels: row.max_approval_levels,
      autoApproveSmallAmounts: Boolean(row.auto_approve_small_amounts),
      smallAmountThreshold: row.small_amount_threshold,
      requireCommentsOnRejection: Boolean(row.require_comments_on_rejection),
      notifyOnPendingApproval: Boolean(row.notify_on_pending_approval),
      escalationDays: row.escalation_days
    };
  }

  private mapToApprovalRule(row: any): ApprovalRule {
    return {
      id: row.id,
      name: row.name,
      description: row.description,
      thresholdAmount: row.threshold_amount,
      currency: row.currency,
      requiredApprovers: JSON.parse(row.required_approvers),
      isActive: Boolean(row.is_active),
      businessId: row.business_id
    };
  }

  private mapToInvoice(row: any): Invoice {
    // Simplified mapping - in real implementation would include all fields
    return {
      id: row.id,
      invoiceNumber: row.invoice_number,
      customerId: row.customer_id,
      customerName: row.customer_name,
      total: row.total,
      status: row.status as InvoiceStatus,
      approvalStatus: row.approval_status as ApprovalStatus,
      // ... other fields
    } as Invoice;
  }

  private mapToInvoiceApproval(row: any): InvoiceApproval {
    return {
      id: row.id,
      invoiceId: row.invoice_id,
      approverUserId: row.approver_user_id,
      approverName: row.approver_name,
      status: row.status as ApprovalStatus,
      level: row.level,
      comments: row.comments || undefined,
      approvedAt: row.approved_at || undefined,
      rejectedAt: row.rejected_at || undefined
    };
  }
}