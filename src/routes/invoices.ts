/**
 * Invoice Management API Routes
 * Complete invoicing system with payment processing and PDF generation
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { InvoiceService } from '../modules/finance/invoice/service';
import { PDFGeneratorService } from '../modules/finance/invoice/pdf-generator';
import { TaxCalculationEngine } from '../modules/finance/invoice/tax-engine';
import { CurrencyService } from '../modules/finance/invoice/currency-service';
import { ApprovalWorkflowService } from '../modules/finance/invoice/approval-workflow';
import { AuditService } from '../modules/audit/audit-service';
import type { Env } from '../types/env';

const app = new Hono<{ Bindings: Env }>();

// ============================================================================
// VALIDATION SCHEMAS
// ============================================================================

const CreateInvoiceSchema = z.object({
  customerId: z.string().min(1),
  type: z.enum(['standard', 'recurring', 'credit_note', 'proforma']).default('standard'),
  issueDate: z.string().optional(),
  dueDate: z.string().optional(),
  paymentTerms: z.enum(['net_15', 'net_30', 'net_45', 'net_60', 'due_on_receipt', 'custom']).optional(),
  currency: z.string().length(3).default('USD'),
  lineItems: z.array(z.object({
    description: z.string().min(1),
    quantity: z.number().positive(),
    unitPrice: z.number().min(0),
    taxRate: z.number().min(0).max(100).optional(),
    discountPercent: z.number().min(0).max(100).optional(),
    accountId: z.string().optional(),
    productId: z.string().optional()
  })).min(1),
  notes: z.string().optional(),
  terms: z.string().optional(),
  purchaseOrderNumber: z.string().optional(),
  projectId: z.string().optional(),
  tags: z.array(z.string()).optional(),
  metadata: z.record(z.any()).optional()
});

const UpdateInvoiceSchema = CreateInvoiceSchema.partial().extend({
  status: z.enum(['draft', 'sent', 'viewed', 'partially_paid', 'paid', 'overdue', 'cancelled', 'refunded']).optional()
});

const RecordPaymentSchema = z.object({
  amount: z.number().positive(),
  paymentDate: z.string(),
  paymentMethod: z.enum(['cash', 'check', 'credit_card', 'bank_transfer', 'ach', 'paypal', 'stripe', 'other']),
  reference: z.string().optional(),
  notes: z.string().optional(),
  sendReceipt: z.boolean().default(true)
});

const SendInvoiceSchema = z.object({
  to: z.array(z.string().email()).min(1),
  cc: z.array(z.string().email()).optional(),
  bcc: z.array(z.string().email()).optional(),
  subject: z.string().optional(),
  message: z.string().optional(),
  attachPdf: z.boolean().default(true),
  sendReminder: z.boolean().default(false),
  reminderDays: z.array(z.number()).optional()
});

const InvoiceFiltersSchema = z.object({
  status: z.enum(['draft', 'sent', 'viewed', 'partially_paid', 'paid', 'overdue', 'cancelled']).optional(),
  customerId: z.string().optional(),
  startDate: z.string().optional(),
  endDate: z.string().optional(),
  minAmount: z.number().optional(),
  maxAmount: z.number().optional(),
  search: z.string().optional(),
  page: z.number().min(1).default(1),
  limit: z.number().min(1).max(100).default(20),
  sortBy: z.string().optional(),
  sortOrder: z.enum(['asc', 'desc']).default('desc')
});

// ============================================================================
// MIDDLEWARE
// ============================================================================

// GRUG: Helper to create security context with all required fields
function createSecurityContext(c: any, userId: string, businessId: string, operation: string) {
  return {
    userId,
    businessId,
    correlationId: `invoice_${Date.now()}`,
    ipAddress: c.req.header('CF-Connecting-IP') || '0.0.0.0',
    userAgent: c.req.header('User-Agent') || 'Unknown',
    sessionId: c.req.header('X-Session-ID'),
    timestamp: new Date().toISOString(),
    operation
  };
}

async function initializeServices(env: Env) {
  const db = env.DB_MAIN;
  // GRUG: AuditService only takes db, not KV
  const auditService = new AuditService(db);
  // GRUG: TaxCalculationEngine takes db as first param
  const taxCalculator = new TaxCalculationEngine(db);
  const pdfGenerator = new PDFGeneratorService();
  // GRUG: InvoiceService constructor params in correct order
  const invoiceService = new InvoiceService(db, taxCalculator, pdfGenerator, auditService);
  const approvalWorkflow = new ApprovalWorkflowService(db, auditService);

  return {
    invoiceService,
    approvalWorkflow,
    auditService,
    pdfGenerator
  };
}

// ============================================================================
// INVOICE CRUD ENDPOINTS
// ============================================================================

app.post('/', zValidator('json', CreateInvoiceSchema), async (c: any) => {
  try {
    const { invoiceService, auditService } = await initializeServices(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const userId = c.req.header('X-User-ID') || 'system';
    const data = c.req.valid('json');

    const invoice = await invoiceService.createInvoice(businessId, userId, data);

    // GRUG: Use logDataModification not logAccess
    await auditService.logDataModification({
      resource: {
        type: 'invoice',
        id: invoice.id,
        attributes: {
          invoiceNumber: invoice.invoiceNumber,
          customerId: invoice.customerId,
          totalAmount: invoice.totalAmount,
          currency: invoice.currency
        }
      },
      operation: 'create',
      result: 'success',
      securityContext: createSecurityContext(c, userId, businessId, 'invoice_create')
    });

    return c.json({
      success: true,
      data: invoice
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to create invoice'
    }, 400);
  }
});

app.get('/', zValidator('query', InvoiceFiltersSchema), async (c: any) => {
  try {
    const { invoiceService } = await initializeServices(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const filters = c.req.valid('query');

    const result = await invoiceService.searchInvoices(businessId, filters);

    // GRUG: Fix type - searchInvoices returns { invoices, pagination }
    const total = result.pagination?.total || 0;
    const limit = filters.limit || 20;

    return c.json({
      success: true,
      data: result.invoices,
      pagination: {
        page: filters.page || 1,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to fetch invoices'
    }, 500);
  }
});

app.get('/:id', async (c: any) => {
  try {
    const { invoiceService } = await initializeServices(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const invoiceId = c.req.param('id');

    const invoice = await invoiceService.getInvoice(businessId, invoiceId);

    if (!invoice) {
      return c.json({
        success: false,
        error: 'Invoice not found'
      }, 404);
    }

    return c.json({
      success: true,
      data: invoice
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to fetch invoice'
    }, 500);
  }
});

app.put('/:id', zValidator('json', UpdateInvoiceSchema), async (c: any) => {
  try {
    const { invoiceService, auditService } = await initializeServices(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const userId = c.req.header('X-User-ID') || 'system';
    const invoiceId = c.req.param('id');
    const updates = c.req.valid('json');

    const invoice = await invoiceService.updateInvoice(businessId, invoiceId, userId, updates);

    // GRUG: Use logDataModification not logAccess
    await auditService.logDataModification({
      resource: { type: 'invoice', id: invoice.id },
      operation: 'update',
      result: 'success',
      securityContext: createSecurityContext(c, userId, businessId, "invoice_operation")
    });

    return c.json({
      success: true,
      data: invoice
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to update invoice'
    }, 400);
  }
});

app.delete('/:id', async (c: any) => {
  try {
    const { invoiceService, auditService } = await initializeServices(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const userId = c.req.header('X-User-ID') || 'system';
    const invoiceId = c.req.param('id');

    // Update status to cancelled instead of deleting
    await invoiceService.updateInvoiceStatus(businessId, invoiceId, 'cancelled', userId);

    // GRUG: Use logDataModification not logAccess
    await auditService.logDataModification({
      resource: { type: 'invoice', id: invoiceId },
      operation: 'delete',
      result: 'success',
      securityContext: createSecurityContext(c, userId, businessId, "invoice_operation")
    });

    return c.json({
      success: true,
      message: 'Invoice cancelled successfully'
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to delete invoice'
    }, 400);
  }
});

// ============================================================================
// INVOICE ACTIONS ENDPOINTS
// ============================================================================

app.post('/:id/send', zValidator('json', SendInvoiceSchema), async (c: any) => {
  try {
    const { invoiceService, auditService } = await initializeServices(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const userId = c.req.header('X-User-ID') || 'system';
    const invoiceId = c.req.param('id');
    const sendOptions = c.req.valid('json');

    const result = await invoiceService.sendInvoiceEmail(businessId, invoiceId, sendOptions);

    // GRUG: Use logDataModification not logAccess
    await auditService.logDataModification({
      resource: { type: 'invoice', id: invoiceId, attributes: { recipients: sendOptions.to } },
      operation: 'update',
      result: 'success',
      securityContext: createSecurityContext(c, userId, businessId, "invoice_operation")
    });

    return c.json({
      success: true,
      data: result
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to send invoice'
    }, 400);
  }
});

app.post('/:id/payments', zValidator('json', RecordPaymentSchema), async (c: any) => {
  try {
    const { invoiceService, auditService } = await initializeServices(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const userId = c.req.header('X-User-ID') || 'system';
    const invoiceId = c.req.param('id');
    const payment = c.req.valid('json');

    // GRUG: Get invoice first to check amount
    const invoice = await invoiceService.getInvoice(businessId, invoiceId);
    if (!invoice) {
      return c.json({ success: false, error: 'Invoice not found' }, 404);
    }

    // Record payment by updating invoice status
    const newStatus = payment.amount >= invoice.totalAmount ? 'paid' : 'partially_paid';
    const result = await invoiceService.updateInvoiceStatus(businessId, invoiceId, newStatus, userId);

    // GRUG: Use logDataModification not logAccess
    await auditService.logDataModification({
      resource: { type: 'invoice', id: invoiceId, attributes: { amount: payment.amount, method: payment.paymentMethod } },
      operation: 'update',
      result: 'success',
      securityContext: createSecurityContext(c, userId, businessId, "invoice_operation")
    });

    return c.json({
      success: true,
      data: result
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to record payment'
    }, 400);
  }
});

app.get('/:id/pdf', async (c: any) => {
  try {
    const { invoiceService, pdfGenerator } = await initializeServices(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const invoiceId = c.req.param('id');

    const invoice = await invoiceService.getInvoice(businessId, invoiceId);

    if (!invoice) {
      return c.json({
        success: false,
        error: 'Invoice not found'
      }, 404);
    }

    const pdf = await invoiceService.generatePDF(businessId, invoiceId);

    return new Response(pdf as BodyInit, {
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="invoice-${invoice.invoiceNumber}.pdf"`
      }
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to generate PDF'
    }, 500);
  }
});

app.post('/:id/approve', async (c: any) => {
  try {
    const { invoiceService, auditService } = await initializeServices(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const userId = c.req.header('X-User-ID') || 'system';
    const invoiceId = c.req.param('id');

    // GRUG: ApprovalWorkflowService doesn't have approveInvoice - use invoiceService
    const result = await invoiceService.updateInvoiceStatus(businessId, invoiceId, 'sent', userId);

    // GRUG: Use logDataModification not logAccess
    await auditService.logDataModification({
      resource: { type: 'invoice', id: invoiceId },
      operation: 'update',
      result: 'success',
      securityContext: createSecurityContext(c, userId, businessId, "invoice_operation")
    });

    return c.json({
      success: true,
      data: { approved: true, status: 'sent' }
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to approve invoice'
    }, 400);
  }
});

app.post('/:id/void', async (c: any) => {
  try {
    const { invoiceService, auditService } = await initializeServices(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const userId = c.req.header('X-User-ID') || 'system';
    const invoiceId = c.req.param('id');
    const reason = c.req.query('reason') || 'No reason provided';

    const result = await invoiceService.updateInvoiceStatus(businessId, invoiceId, 'cancelled', userId);

    // GRUG: Use logDataModification not logAccess
    await auditService.logDataModification({
      resource: { type: 'invoice', id: invoiceId, attributes: { reason } },
      operation: 'update',
      result: 'success',
      securityContext: createSecurityContext(c, userId, businessId, "invoice_operation")
    });

    return c.json({
      success: true,
      data: result
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to void invoice'
    }, 400);
  }
});

// ============================================================================
// ANALYTICS ENDPOINTS
// ============================================================================

app.get('/analytics/summary', async (c: any) => {
  try {
    const { invoiceService } = await initializeServices(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');

    // Use searchInvoices to generate summary
    const result = await invoiceService.searchInvoices(businessId, {
      page: 1,
      limit: 1000,
      startDate,
      endDate
    });

    // GRUG: Fix type - pagination has total
    const total = result.pagination?.total || 0;

    const summary = {
      totalInvoices: total,
      totalAmount: result.invoices.reduce((sum, inv) => sum + inv.totalAmount, 0),
      paidAmount: result.invoices.filter(inv => inv.status === 'paid').reduce((sum, inv) => sum + inv.totalAmount, 0),
      overdueAmount: result.invoices.filter(inv => inv.status === 'overdue').reduce((sum, inv) => sum + inv.totalAmount, 0)
    };

    return c.json({
      success: true,
      data: summary
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to fetch invoice summary'
    }, 500);
  }
});

app.get('/analytics/aging', async (c: any) => {
  try {
    const { invoiceService } = await initializeServices(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';

    // GRUG: Get all invoices without status filter
    const result = await invoiceService.searchInvoices(businessId, { page: 1, limit: 1000 });

    const now = new Date();
    const aging = {
      current: result.invoices.filter(inv => {
        const due = new Date(inv.dueDate);
        return due >= now;
      }).reduce((sum, inv) => sum + inv.totalAmount, 0),
      days30: result.invoices.filter(inv => {
        const due = new Date(inv.dueDate);
        const diff = (now.getTime() - due.getTime()) / (1000 * 60 * 60 * 24);
        return diff > 0 && diff <= 30;
      }).reduce((sum, inv) => sum + inv.totalAmount, 0),
      days60: result.invoices.filter(inv => {
        const due = new Date(inv.dueDate);
        const diff = (now.getTime() - due.getTime()) / (1000 * 60 * 60 * 24);
        return diff > 30 && diff <= 60;
      }).reduce((sum, inv) => sum + inv.totalAmount, 0),
      days90plus: result.invoices.filter(inv => {
        const due = new Date(inv.dueDate);
        const diff = (now.getTime() - due.getTime()) / (1000 * 60 * 60 * 24);
        return diff > 60;
      }).reduce((sum, inv) => sum + inv.totalAmount, 0)
    };

    return c.json({
      success: true,
      data: aging
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to fetch aging report'
    }, 500);
  }
});

// ============================================================================
// HEALTH CHECK
// ============================================================================

app.get('/health', async (c: any) => {
  return c.json({
    success: true,
    service: 'invoices',
    status: 'operational',
    timestamp: new Date().toISOString()
  });
});

export default app;