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
import { ApprovalWorkflow } from '../modules/finance/invoice/approval-workflow';
import { AuditLogger } from '../modules/audit/audit-service';
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

async function initializeServices(env: Env) {
  const db = env.DB_MAIN;
  const auditLogger = new AuditLogger();
  const taxCalculator = new TaxCalculationEngine();
  const pdfGenerator = new PDFGeneratorService();
  const currencyService = new CurrencyService();
  const invoiceService = new InvoiceService(db, auditLogger, taxCalculator, pdfGenerator, currencyService);
  const approvalWorkflow = new ApprovalWorkflow(db);

  return {
    invoiceService,
    approvalWorkflow,
    auditLogger,
    pdfGenerator
  };
}

// ============================================================================
// INVOICE CRUD ENDPOINTS
// ============================================================================

app.post('/', zValidator('json', CreateInvoiceSchema), async (c) => {
  try {
    const { invoiceService, auditLogger } = await initializeServices(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const userId = c.req.header('X-User-ID') || 'system';
    const data = c.req.valid('json');

    const invoice = await invoiceService.createInvoice(businessId, userId, data);

    // Log audit trail
    await auditLogger.log({
      businessId,
      userId,
      action: 'create',
      resourceType: 'invoice',
      resourceId: invoice.id,
      details: {
        invoiceNumber: invoice.invoiceNumber,
        customerId: invoice.customerId,
        totalAmount: invoice.totalAmount,
        currency: invoice.currency
      }
    });

    return c.json({
      success: true,
      data: invoice
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to create invoice'
    }, 400);
  }
});

app.get('/', zValidator('query', InvoiceFiltersSchema), async (c) => {
  try {
    const { invoiceService } = await initializeServices(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const filters = c.req.valid('query');

    const result = await invoiceService.listInvoices(businessId, filters);

    return c.json({
      success: true,
      data: result.invoices,
      pagination: {
        page: filters.page,
        limit: filters.limit,
        total: result.total,
        totalPages: Math.ceil(result.total / filters.limit)
      }
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to fetch invoices'
    }, 500);
  }
});

app.get('/:id', async (c) => {
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
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to fetch invoice'
    }, 500);
  }
});

app.put('/:id', zValidator('json', UpdateInvoiceSchema), async (c) => {
  try {
    const { invoiceService, auditLogger } = await initializeServices(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const userId = c.req.header('X-User-ID') || 'system';
    const invoiceId = c.req.param('id');
    const updates = c.req.valid('json');

    const invoice = await invoiceService.updateInvoice(businessId, invoiceId, updates);

    // Log audit trail
    await auditLogger.log({
      businessId,
      userId,
      action: 'update',
      resourceType: 'invoice',
      resourceId: invoice.id,
      details: { updates }
    });

    return c.json({
      success: true,
      data: invoice
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to update invoice'
    }, 400);
  }
});

app.delete('/:id', async (c) => {
  try {
    const { invoiceService, auditLogger } = await initializeServices(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const userId = c.req.header('X-User-ID') || 'system';
    const invoiceId = c.req.param('id');

    await invoiceService.deleteInvoice(businessId, invoiceId);

    // Log audit trail
    await auditLogger.log({
      businessId,
      userId,
      action: 'delete',
      resourceType: 'invoice',
      resourceId: invoiceId,
      details: { deletedAt: new Date().toISOString() }
    });

    return c.json({
      success: true,
      message: 'Invoice deleted successfully'
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to delete invoice'
    }, 400);
  }
});

// ============================================================================
// INVOICE ACTIONS ENDPOINTS
// ============================================================================

app.post('/:id/send', zValidator('json', SendInvoiceSchema), async (c) => {
  try {
    const { invoiceService, auditLogger } = await initializeServices(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const userId = c.req.header('X-User-ID') || 'system';
    const invoiceId = c.req.param('id');
    const sendOptions = c.req.valid('json');

    const result = await invoiceService.sendInvoice(businessId, invoiceId, sendOptions);

    // Log audit trail
    await auditLogger.log({
      businessId,
      userId,
      action: 'send',
      resourceType: 'invoice',
      resourceId: invoiceId,
      details: {
        recipients: sendOptions.to,
        sentAt: new Date().toISOString()
      }
    });

    return c.json({
      success: true,
      data: result
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to send invoice'
    }, 400);
  }
});

app.post('/:id/payments', zValidator('json', RecordPaymentSchema), async (c) => {
  try {
    const { invoiceService, auditLogger } = await initializeServices(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const userId = c.req.header('X-User-ID') || 'system';
    const invoiceId = c.req.param('id');
    const payment = c.req.valid('json');

    const result = await invoiceService.recordPayment(businessId, invoiceId, payment);

    // Log audit trail
    await auditLogger.log({
      businessId,
      userId,
      action: 'payment_recorded',
      resourceType: 'invoice',
      resourceId: invoiceId,
      details: {
        amount: payment.amount,
        method: payment.paymentMethod,
        reference: payment.reference
      }
    });

    return c.json({
      success: true,
      data: result
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to record payment'
    }, 400);
  }
});

app.get('/:id/pdf', async (c) => {
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

    const pdf = await pdfGenerator.generateInvoicePDF(invoice);

    return new Response(pdf, {
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="invoice-${invoice.invoiceNumber}.pdf"`
      }
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to generate PDF'
    }, 500);
  }
});

app.post('/:id/approve', async (c) => {
  try {
    const { approvalWorkflow, auditLogger } = await initializeServices(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const userId = c.req.header('X-User-ID') || 'system';
    const invoiceId = c.req.param('id');

    const result = await approvalWorkflow.approveInvoice(businessId, invoiceId, userId);

    // Log audit trail
    await auditLogger.log({
      businessId,
      userId,
      action: 'approve',
      resourceType: 'invoice',
      resourceId: invoiceId,
      details: { approvedAt: new Date().toISOString() }
    });

    return c.json({
      success: true,
      data: result
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to approve invoice'
    }, 400);
  }
});

app.post('/:id/void', async (c) => {
  try {
    const { invoiceService, auditLogger } = await initializeServices(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const userId = c.req.header('X-User-ID') || 'system';
    const invoiceId = c.req.param('id');
    const reason = c.req.query('reason') || 'No reason provided';

    const result = await invoiceService.voidInvoice(businessId, invoiceId, reason);

    // Log audit trail
    await auditLogger.log({
      businessId,
      userId,
      action: 'void',
      resourceType: 'invoice',
      resourceId: invoiceId,
      details: { reason, voidedAt: new Date().toISOString() }
    });

    return c.json({
      success: true,
      data: result
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to void invoice'
    }, 400);
  }
});

// ============================================================================
// ANALYTICS ENDPOINTS
// ============================================================================

app.get('/analytics/summary', async (c) => {
  try {
    const { invoiceService } = await initializeServices(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');

    const summary = await invoiceService.getInvoiceSummary(businessId, {
      startDate,
      endDate
    });

    return c.json({
      success: true,
      data: summary
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to fetch invoice summary'
    }, 500);
  }
});

app.get('/analytics/aging', async (c) => {
  try {
    const { invoiceService } = await initializeServices(c.env);
    const businessId = c.req.header('X-Business-ID') || 'default';

    const aging = await invoiceService.getAgingReport(businessId);

    return c.json({
      success: true,
      data: aging
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to fetch aging report'
    }, 500);
  }
});

// ============================================================================
// HEALTH CHECK
// ============================================================================

app.get('/health', async (c) => {
  return c.json({
    success: true,
    service: 'invoices',
    status: 'operational',
    timestamp: new Date().toISOString()
  });
});

export default app;