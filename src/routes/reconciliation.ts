// @ts-nocheck
/**
 * Reconciliation API Routes
 * Endpoints for account reconciliation management
 */

import { Hono } from 'hono';
import type { Env } from '../types/env';
import { ReconciliationService } from '../services/reconciliation/reconciliation-service';
import { StatementParser } from '../services/reconciliation/statement-parser';

const reconciliation = new Hono<{ Bindings: Env }>();

// Middleware: Extract user/business from JWT (simplified - add proper auth)
reconciliation.use('*', async (c, next) => {
  const authHeader = c.req.header('Authorization');
  if (!authHeader) {
    return c.json({ success: false, error: 'Unauthorized' }, 401);
  }

  // TODO: Implement proper JWT verification
  // For now, extract from header or use test values
  c.set('userId', 'user_test_001');
  c.set('businessId', 'business_001');

  await next();
});

/**
 * GET /api/v1/reconciliation/accounts
 * List accounts available for reconciliation
 */
reconciliation.get('/accounts', async (c) => {
  try {
    const businessId = c.get('businessId');

    const accounts = await c.env.DB.prepare(`
      SELECT
        id,
        account_name,
        account_type,
        account_number,
        institution_name,
        current_balance,
        currency,
        status
      FROM accounts
      WHERE business_id = ? AND status = 'active'
      ORDER BY account_name ASC
    `)
      .bind(businessId)
      .all();

    return c.json({
      success: true,
      data: {
        accounts: accounts.results,
        count: accounts.results.length,
      },
    });
  } catch (error) {
    console.error('Error fetching accounts:', error);
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to fetch accounts',
    }, 500);
  }
});

/**
 * POST /api/v1/reconciliation
 * Create new reconciliation
 */
reconciliation.post('/', async (c) => {
  try {
    const businessId = c.get('businessId');
    const { account_id, statement_date, statement_balance } = await c.req.json();

    if (!account_id || !statement_date || statement_balance === undefined) {
      return c.json({
        success: false,
        error: 'Missing required fields: account_id, statement_date, statement_balance',
      }, 400);
    }

    const service = new ReconciliationService(c.env);
    const reconciliationId = await service.createReconciliation(
      businessId,
      account_id,
      statement_date,
      statement_balance
    );

    const reconciliation = await service.getReconciliation(reconciliationId);

    return c.json({
      success: true,
      data: {
        reconciliation_id: reconciliationId,
        reconciliation,
      },
    }, 201);
  } catch (error) {
    console.error('Error creating reconciliation:', error);
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to create reconciliation',
    }, 500);
  }
});

/**
 * POST /api/v1/reconciliation/:id/upload-statement
 * Upload and parse bank statement
 */
reconciliation.post('/:id/upload-statement', async (c) => {
  try {
    const reconciliationId = c.req.param('id');
    const formData = await c.req.formData();
    const file = formData.get('file') as File;

    if (!file) {
      return c.json({
        success: false,
        error: 'No file provided',
      }, 400);
    }

    // Read file content
    const fileContent = await file.text();
    const fileType = file.type;

    // Parse statement
    const parser = new StatementParser();
    const transactions = await parser.parseStatement(fileContent, fileType);

    // Validate transactions
    const validation = parser.validateTransactions(transactions);

    if (validation.errors.length > 0) {
      return c.json({
        success: false,
        error: 'Validation errors found',
        details: {
          valid_count: validation.valid.length,
          errors: validation.errors,
        },
      }, 400);
    }

    // Import transactions
    const service = new ReconciliationService(c.env);
    const imported = await service.importStatementTransactions(
      reconciliationId,
      validation.valid
    );

    return c.json({
      success: true,
      data: {
        imported_count: imported,
        total_transactions: validation.valid.length,
      },
    });
  } catch (error) {
    console.error('Error uploading statement:', error);
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to upload statement',
    }, 500);
  }
});

/**
 * POST /api/v1/reconciliation/:id/auto-match
 * Auto-match transactions
 */
reconciliation.post('/:id/auto-match', async (c) => {
  try {
    const businessId = c.get('businessId');
    const reconciliationId = c.req.param('id');

    const service = new ReconciliationService(c.env);
    const result = await service.autoMatchTransactions(businessId, reconciliationId);

    return c.json({
      success: true,
      data: {
        auto_matched: result.matched,
        suggestions: result.suggestions,
        suggestion_count: result.suggestions.length,
      },
    });
  } catch (error) {
    console.error('Error auto-matching:', error);
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to auto-match',
    }, 500);
  }
});

/**
 * POST /api/v1/reconciliation/:id/match
 * Manually match a transaction
 */
reconciliation.post('/:id/match', async (c) => {
  try {
    const userId = c.get('userId');
    const reconciliationId = c.req.param('id');
    const { statement_transaction_id, book_transaction_id, confidence } = await c.req.json();

    if (!statement_transaction_id || !book_transaction_id) {
      return c.json({
        success: false,
        error: 'Missing required fields: statement_transaction_id, book_transaction_id',
      }, 400);
    }

    const service = new ReconciliationService(c.env);
    await service.applyMatch(
      reconciliationId,
      statement_transaction_id,
      book_transaction_id,
      'manual',
      confidence || 100,
      userId
    );

    return c.json({
      success: true,
      message: 'Match applied successfully',
    });
  } catch (error) {
    console.error('Error applying match:', error);
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to apply match',
    }, 500);
  }
});

/**
 * GET /api/v1/reconciliation/:id
 * Get reconciliation details
 */
reconciliation.get('/:id', async (c) => {
  try {
    const reconciliationId = c.req.param('id');

    const service = new ReconciliationService(c.env);
    const reconciliation = await service.getReconciliation(reconciliationId);
    const stats = await service.getReconciliationStats(reconciliationId);

    return c.json({
      success: true,
      data: {
        reconciliation,
        stats,
      },
    });
  } catch (error) {
    console.error('Error fetching reconciliation:', error);
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to fetch reconciliation',
    }, 500);
  }
});

/**
 * GET /api/v1/reconciliation/:id/transactions
 * Get statement and matched transactions
 */
reconciliation.get('/:id/transactions', async (c) => {
  try {
    const reconciliationId = c.req.param('id');

    const statementTxns = await c.env.DB.prepare(`
      SELECT * FROM statement_transactions
      WHERE reconciliation_id = ?
      ORDER BY transaction_date DESC, amount DESC
    `)
      .bind(reconciliationId)
      .all();

    const matchedItems = await c.env.DB.prepare(`
      SELECT
        ri.*,
        le.description as book_description,
        le.amount as book_amount,
        le.entry_date as book_date
      FROM reconciliation_items ri
      LEFT JOIN ledger_entries le ON ri.transaction_id = le.id
      WHERE ri.reconciliation_id = ?
      ORDER BY ri.transaction_date DESC
    `)
      .bind(reconciliationId)
      .all();

    return c.json({
      success: true,
      data: {
        statement_transactions: statementTxns.results,
        matched_items: matchedItems.results,
      },
    });
  } catch (error) {
    console.error('Error fetching transactions:', error);
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to fetch transactions',
    }, 500);
  }
});

/**
 * POST /api/v1/reconciliation/:id/detect-discrepancies
 * Detect and create discrepancy records
 */
reconciliation.post('/:id/detect-discrepancies', async (c) => {
  try {
    const reconciliationId = c.req.param('id');

    const service = new ReconciliationService(c.env);
    await service.detectDiscrepancies(reconciliationId);

    const discrepancies = await c.env.DB.prepare(`
      SELECT * FROM reconciliation_discrepancies
      WHERE reconciliation_id = ? AND resolution = 'pending'
    `)
      .bind(reconciliationId)
      .all();

    return c.json({
      success: true,
      data: {
        discrepancies: discrepancies.results,
        count: discrepancies.results.length,
      },
    });
  } catch (error) {
    console.error('Error detecting discrepancies:', error);
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to detect discrepancies',
    }, 500);
  }
});

/**
 * POST /api/v1/reconciliation/:id/complete
 * Mark reconciliation as complete
 */
reconciliation.post('/:id/complete', async (c) => {
  try {
    const userId = c.get('userId');
    const reconciliationId = c.req.param('id');

    const service = new ReconciliationService(c.env);
    const stats = await service.getReconciliationStats(reconciliationId);

    // Check if all transactions are matched
    if (stats.unmatched_transactions > 0) {
      return c.json({
        success: false,
        error: `Cannot complete: ${stats.unmatched_transactions} transactions still unmatched`,
        data: { stats },
      }, 400);
    }

    await service.completeReconciliation(reconciliationId, userId);

    return c.json({
      success: true,
      message: 'Reconciliation completed successfully',
      data: { stats },
    });
  } catch (error) {
    console.error('Error completing reconciliation:', error);
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to complete reconciliation',
    }, 500);
  }
});

/**
 * GET /api/v1/reconciliation
 * List reconciliations
 */
reconciliation.get('/', async (c) => {
  try {
    const businessId = c.get('businessId');
    const status = c.req.query('status');
    const limit = parseInt(c.req.query('limit') || '50');

    let query = `
      SELECT
        r.*,
        a.account_name,
        a.account_type,
        u.email as reconciled_by_email
      FROM reconciliations r
      LEFT JOIN accounts a ON r.account_id = a.id
      LEFT JOIN users u ON r.reconciled_by = u.id
      WHERE r.business_id = ?
    `;

    const bindings: any[] = [businessId];

    if (status) {
      query += ` AND r.status = ?`;
      bindings.push(status);
    }

    query += ` ORDER BY r.statement_date DESC, r.created_at DESC LIMIT ?`;
    bindings.push(limit);

    const reconciliations = await c.env.DB.prepare(query).bind(...bindings).all();

    return c.json({
      success: true,
      data: {
        reconciliations: reconciliations.results,
        count: reconciliations.results.length,
      },
    });
  } catch (error) {
    console.error('Error listing reconciliations:', error);
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to list reconciliations',
    }, 500);
  }
});

export default reconciliation;
