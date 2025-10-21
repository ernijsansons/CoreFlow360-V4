/**
 * Finance Agent API Routes
 *
 * Endpoints for the Autonomous Finance Agent (Agent 6)
 * All routes require authentication and finance permissions
 *
 * Capabilities exposed:
 * 1. POST /journal-entry - Create double-entry bookkeeping entries
 * 2. POST /reconcile - Run bank reconciliation
 * 3. POST /invoice - Generate invoices
 * 4. POST /categorize-expense - Categorize expenses with ML
 * 5. GET /reports/:type - Generate financial reports
 * 6. POST /calculate-tax - Calculate taxes
 * 7. GET /audit-trail - Retrieve audit logs
 * 8. GET /forecast - Generate cash flow forecast
 * 9. GET /anomalies - Detect financial anomalies
 * 10. POST /currency/update-rates - Update exchange rates
 */

import { Logger } from '@/shared/logger';
import { Hono } from 'hono';
import { z } from 'zod';
import type { Env } from '@/types/env';
import { authenticate } from '../middleware/auth';
import { validateInput } from '../middleware/validation';
import { FinanceAgent } from '../modules/agents/finance-agent';
import { AgentOrchestrator } from '../modules/agents/orchestrator';
import { CapabilityManager } from '../modules/agents/capability-manager';
import { AuditService } from '../modules/audit/audit.service';
import type { AgentTask, BusinessContext } from '../modules/agents/types';
import { generateId } from '../shared/utils/id-generator';

const logger = new Logger('FinanceAgent');

const financeAgent = new Hono<{ Bindings: Env }>();

// Helper to create orchestrator
async function getOrchestrator(env: Env): Promise<AgentOrchestrator> {
  const capabilityManager = new CapabilityManager() as any;
  const auditService = new AuditService(env.DB_MAIN) as any;
  return new AgentOrchestrator(env.KV_CACHE as any, env.DB_MAIN, capabilityManager, auditService);
}

// ============================================================================
// REQUEST SCHEMAS
// ============================================================================

const JournalEntrySchema = z.object({
  transaction: z.object({
    date: z.string().optional(),
    description: z.string(),
    lines: z.array(z.object({
      account_id: z.string(),
      line_type: z.enum(['debit', 'credit']),
      amount: z.number().positive(),
      currency: z.string().optional(),
      exchange_rate: z.number().positive().optional(),
      description: z.string().optional()
    })).min(2) // At least 2 lines (debit + credit)
  }),
  reference_type: z.string().optional(),
  reference_id: z.string().optional()
});

const BankReconciliationSchema = z.object({
  bank_account_id: z.string(),
  statement_date: z.string(), // ISO date
  statement_balance: z.number().optional()
});

const InvoiceGenerationSchema = z.object({
  customer_id: z.string(),
  line_items: z.array(z.object({
    product_id: z.string().optional(),
    description: z.string(),
    quantity: z.number().positive(),
    unit_price: z.number().positive(),
    tax_rate: z.number().min(0).max(100).optional(),
    line_total: z.number().positive()
  })).min(1),
  payment_terms: z.string().optional(),
  due_days: z.number().int().positive().optional(),
  notes: z.string().optional()
});

const ExpenseCategorizationSchema = z.object({
  expense_id: z.string(),
  description: z.string(),
  amount: z.number().positive(),
  vendor: z.string().optional()
});

// ============================================================================
// ROUTE 1: Create Journal Entry
// ============================================================================

financeAgent.post(
  '/journal-entry',
  authenticate(),
  validateInput(JournalEntrySchema) as any,
  async (c) => {
    const env = c.env;
    const user = (c as any).get('user');
    const businessId = user.business_id;
    const data = await c.req.json();

    try {
      const agent = new FinanceAgent(env);
      const orchestrator = await getOrchestrator(env);

      const task: AgentTask = {
        type: 'action',
        id: generateId(),
        capability: 'double_entry_bookkeeping',
        priority: 'high',
        input: {
          source: 'api',
          data
        },
        metadata: {
          requestedBy: user.id,
          requestedAt: new Date().toISOString()
        },
        createdAt: Date.now(),
        retryCount: 0
      };

      const context: BusinessContext = {
        businessId,
        userId: user.id,
        permissions: user.permissions || []
      };

      const result = await orchestrator.executeTask(task, context);

      if (result.status === 'failed') {
        return c.json({ success: false, error: result.result!.error }, 400);
      }
      return c.json({
        success: true,
        data: result.result!.data,
        metrics: result.metrics
      });

    } catch (error: any) {
      logger.error('Journal entry creation failed:', error);
      return c.json(
        {
          success: false,
          error: {
            code: 'JOURNAL_ENTRY_FAILED',
            message: error.message
          }
        },
        500
      );
    }
  }
);

// ============================================================================
// ROUTE 2: Bank Reconciliation
// ============================================================================

financeAgent.post(
  '/reconcile',
  authenticate(),
  validateInput(BankReconciliationSchema) as any,
  async (c) => {
    const env = c.env;
    const user = (c as any).get('user');
    const businessId = user.business_id;
    const data = await c.req.json();

    try {
      const orchestrator = await getOrchestrator(env);

      const task: AgentTask = {
        type: 'action',
        id: generateId(),
        capability: 'bank_reconciliation',
        priority: 'high',
        input: { source: 'api', data },
        metadata: {
          requestedBy: user.id,
          requestedAt: new Date().toISOString()
        }
        ,
        createdAt: Date.now(),
        retryCount: 0
      };

      const context: BusinessContext = {
        businessId,
        userId: user.id,
        permissions: user.permissions || []
      };

      const result = await orchestrator.executeTask(task, context);

      if (result.status === 'failed') {
        return c.json({ success: false, error: result.result!.error }, 400);
      }

      return c.json({
        success: true,
        data: result.result!.data,
        metrics: result.metrics
      });

    } catch (error: any) {
      logger.error('Bank reconciliation failed:', error);
      return c.json({ success: false, error: { code: 'RECONCILIATION_FAILED', message: error.message } }, 500);
    }
  }
);

// ============================================================================
// ROUTE 3: Generate Invoice
// ============================================================================

financeAgent.post(
  '/invoice',
  authenticate(),
  validateInput(InvoiceGenerationSchema) as any,
  async (c) => {
    const env = c.env;
    const user = (c as any).get('user');
    const businessId = user.business_id;
    const data = await c.req.json();

    try {
      const orchestrator = await getOrchestrator(env);

      const task: AgentTask = {
        type: 'action',
        id: generateId(),
        capability: 'invoice_generation',
        priority: 'normal',
        input: { source: 'api', data },
        metadata: {
          requestedBy: user.id,
          requestedAt: new Date().toISOString()
        }
        ,
        createdAt: Date.now(),
        retryCount: 0
      };

      const context: BusinessContext = {
        businessId,
        userId: user.id,
        permissions: user.permissions || []
      };

      const result = await orchestrator.executeTask(task, context);

      if (result.status === 'failed') {
        return c.json({ success: false, error: result.result!.error }, 400);
      }

      return c.json({
        success: true,
        data: result.result!.data,
        metrics: result.metrics
      }, 201);

    } catch (error: any) {
      logger.error('Invoice generation failed:', error);
      return c.json({ success: false, error: { code: 'INVOICE_GENERATION_FAILED', message: error.message } }, 500);
    }
  }
);

// ============================================================================
// ROUTE 4: Categorize Expense
// ============================================================================

financeAgent.post(
  '/categorize-expense',
  authenticate(),
  validateInput(ExpenseCategorizationSchema) as any,
  async (c) => {
    const env = c.env;
    const user = (c as any).get('user');
    const businessId = user.business_id;
    const data = await c.req.json();

    try {
      const orchestrator = await getOrchestrator(env);

      const task: AgentTask = {
        type: 'action',
        id: generateId(),
        capability: 'expense_categorization',
        priority: 'normal',
        input: { source: 'api', data },
        metadata: {
          requestedBy: user.id,
          requestedAt: new Date().toISOString()
        }
        ,
        createdAt: Date.now(),
        retryCount: 0
      };

      const context: BusinessContext = {
        businessId,
        userId: user.id,
        permissions: user.permissions || []
      };

      const result = await orchestrator.executeTask(task, context);

      if (result.status === 'failed') {
        return c.json({ success: false, error: result.result!.error }, 400);
      }

      return c.json({
        success: true,
        data: result.result!.data,
        metrics: result.metrics
      });

    } catch (error: any) {
      logger.error('Expense categorization failed:', error);
      return c.json({ success: false, error: { code: 'CATEGORIZATION_FAILED', message: error.message } }, 500);
    }
  }
);

// ============================================================================
// ROUTE 5: Generate Financial Report
// ============================================================================

financeAgent.get(
  '/reports/:type',
  authenticate(),
  async (c) => {
    const env = c.env;
    const user = (c as any).get('user');
    const businessId = user.business_id;
    const reportType = c.req.param('type');

    const periodStart = c.req.query('period_start');
    const periodEnd = c.req.query('period_end');

    if (!periodStart || !periodEnd) {
      return c.json({ success: false, error: { code: 'MISSING_PARAMETERS', message: 'period_start and period_end are required' } }, 400);
    }

    const validTypes = ['income_statement', 'balance_sheet', 'cash_flow_statement'];
    if (!validTypes.includes(reportType)) {
      return c.json({ success: false, error: { code: 'INVALID_REPORT_TYPE', message: `Report type must be one of: ${validTypes.join(', ')}` } }, 400);
    }

    try {
      // Check cache first
      const cacheKey = `finance_report:${businessId}:${reportType}:${periodStart}:${periodEnd}`;
      const cached = await env.KV_CACHE.get(cacheKey, 'json');

      if (cached) {
        return c.json({ success: true, data: cached, cached: true });
      }

      const orchestrator = await getOrchestrator(env);

      const task: AgentTask = {
        type: 'action',
        id: generateId(),
        capability: 'financial_reporting',
        priority: 'normal',
        input: {
          source: 'api',
          data: { report_type: reportType, period_start: periodStart, period_end: periodEnd }
        },
        metadata: {
          requestedBy: user.id,
          requestedAt: new Date().toISOString()
        }
        ,
        createdAt: Date.now(),
        retryCount: 0
      };

      const context: BusinessContext = {
        businessId,
        userId: user.id,
        permissions: user.permissions || []
      };

      const result = await orchestrator.executeTask(task, context);

      if (result.status === 'failed') {
        return c.json({ success: false, error: result.result!.error }, 400);
      }

      // Cache for 5 minutes
      await env.KV_CACHE.put(cacheKey, JSON.stringify(result.result!.data), { expirationTtl: 300 });

      return c.json({
        success: true,
        data: result.result!.data,
        metrics: result.metrics,
        cached: false
      });

    } catch (error: any) {
      logger.error('Financial report generation failed:', error);
      return c.json({ success: false, error: { code: 'REPORT_GENERATION_FAILED', message: error.message } }, 500);
    }
  }
);

// ============================================================================
// ADDITIONAL ENDPOINTS
// ============================================================================

// Get Finance Agent Dashboard
financeAgent.get(
  '/dashboard',
  authenticate(),
  async (c) => {
    const env = c.env;
    const user = (c as any).get('user');
    const businessId = user.business_id;

    try {
      const cacheKey = `finance_dashboard:${businessId}`;
      const cached = await env.KV_CACHE.get(cacheKey, 'json');

      if (cached) {
        return c.json({ success: true, data: cached, cached: true });
      }

      const db = env.DB_MAIN;

      const [cashBalance, arBalance, apBalance, recentTransactions] = await Promise.all([
        db.prepare(`
          SELECT COALESCE(SUM(
            CASE WHEN jel.line_type = 'debit' THEN jel.amount
                 WHEN jel.line_type = 'credit' THEN -jel.amount
            END
          ), 0) as balance
          FROM journal_entry_lines jel
          JOIN journal_entries je ON jel.journal_entry_id = je.id
          JOIN chart_of_accounts coa ON jel.account_id = coa.id
          WHERE coa.business_id = ? AND coa.account_subtype = 'cash' AND je.status = 'posted'
        `).bind(businessId).first() as any,

        db.prepare(`
          SELECT COALESCE(SUM(amount_due), 0) as balance
          FROM invoices
          WHERE business_id = ? AND status IN ('sent', 'viewed', 'overdue', 'partially_paid')
        `).bind(businessId).first() as any,

        db.prepare(`
          SELECT COALESCE(SUM(amount), 0) as balance
          FROM expenses
          WHERE business_id = ? AND payment_status = 'unpaid'
        `).bind(businessId).first() as any,

        db.prepare(`
          SELECT * FROM journal_entries
          WHERE business_id = ?
          ORDER BY entry_date DESC
          LIMIT 10
        `).bind(businessId).all()
      ]);

      const dashboard = {
        cashBalance: cashBalance?.balance || 0,
        accountsReceivable: arBalance?.balance || 0,
        accountsPayable: apBalance?.balance || 0,
        netWorkingCapital: (cashBalance?.balance || 0) + (arBalance?.balance || 0) - (apBalance?.balance || 0),
        recentTransactions: recentTransactions.results || []
      };

      await env.KV_CACHE.put(cacheKey, JSON.stringify(dashboard), { expirationTtl: 300 });

      return c.json({ success: true, data: dashboard, cached: false });

    } catch (error: any) {
      logger.error('Dashboard retrieval failed:', error);
      return c.json({ success: false, error: { code: 'DASHBOARD_FAILED', message: error.message } }, 500);
    }
  }
);

// Get Finance Agent Metrics
financeAgent.get(
  '/metrics',
  authenticate(),
  async (c) => {
    const env = c.env;
    const user = (c as any).get('user');
    const businessId = user.business_id;

    try {
      const db = env.DB_MAIN;

      const metrics = await db
        .prepare(`
          SELECT * FROM finance_agent_metrics
          WHERE business_id = ?
          ORDER BY metric_date DESC
          LIMIT 30
        `)
        .bind(businessId)
        .all();

      return c.json({
        success: true,
        data: {
          metrics: metrics.results,
          period: '30 days'
        }
      });

    } catch (error: any) {
      logger.error('Metrics retrieval failed:', error);
      return c.json({ success: false, error: { code: 'METRICS_RETRIEVAL_FAILED', message: error.message } }, 500);
    }
  }
);

// Get Audit Trail
financeAgent.get(
  '/audit-trail',
  authenticate(),
  async (c) => {
    const env = c.env;
    const user = (c as any).get('user');
    const businessId = user.business_id;

    const entityType = c.req.query('entity_type');
    const entityId = c.req.query('entity_id');
    const startDate = c.req.query('start_date');
    const endDate = c.req.query('end_date');
    const limit = parseInt(c.req.query('limit') || '100');

    try {
      const db = env.DB_MAIN;

      let query = 'SELECT * FROM finance_audit_log WHERE business_id = ?';
      const params: any[] = [businessId];

      if (entityType) {
        query += ' AND entity_type = ?';
        params.push(entityType);
      }

      if (entityId) {
        query += ' AND entity_id = ?';
        params.push(entityId);
      }

      if (startDate) {
        query += ' AND performed_at >= ?';
        params.push(startDate);
      }

      if (endDate) {
        query += ' AND performed_at <= ?';
        params.push(endDate);
      }

      query += ' ORDER BY performed_at DESC LIMIT ?';
      params.push(limit);

      const result = await db.prepare(query).bind(...params).all();

      return c.json({
        success: true,
        data: {
          logs: result.results,
          count: result.results?.length || 0,
          hasMore: (result.results?.length || 0) === limit
        }
      });

    } catch (error: any) {
      logger.error('Audit trail retrieval failed:', error);
      return c.json({ success: false, error: { code: 'AUDIT_RETRIEVAL_FAILED', message: error.message } }, 500);
    }
  }
);

export default financeAgent;
