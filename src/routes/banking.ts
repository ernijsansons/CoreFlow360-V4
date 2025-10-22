// @ts-nocheck
/**
 * Banking & Transaction Matching API Routes
 * Handles bank connections and transaction matching
 */

import { Hono } from 'hono';
import type { Env } from '../types/env';
import { TransactionMatcher } from '../services/banking/transaction-matcher';
import { authenticate } from '../middleware/auth';import { Logger } from "../shared/logger";
const logger = new Logger({ component: "routes-banking" });



const banking = new Hono<{ Bindings: Env }>();

// Apply authentication to all routes
banking.use('*', authenticate);

/**
 * GET /api/banking/transactions
 * List bank transactions
 */
banking.get('/transactions', async (c) => {
  try {
    const { businessId } = c.get('auth');
    const { status, limit = '50', offset = '0', from_date, to_date } = c.req.query();

    let query = `
      SELECT
        id, account_id, amount, currency, transaction_date,
        description, merchant_name, category, status,
        matched_invoice_id, matched_expense_id, confidence_score
      FROM bank_transactions
      WHERE business_id = ?
    `;

    const params: any[] = [businessId];

    if (status) {
      query += ` AND status = ?`;
      params.push(status);
    }

    if (from_date) {
      query += ` AND transaction_date >= ?`;
      params.push(from_date);
    }

    if (to_date) {
      query += ` AND transaction_date <= ?`;
      params.push(to_date);
    }

    query += ` ORDER BY transaction_date DESC LIMIT ? OFFSET ?`;
    params.push(parseInt(limit), parseInt(offset));

    const result = await c.env.DB.prepare(query)
      .bind(...params)
      .all();

    return c.json({
      success: true,
      data: {
        transactions: result.results,
        total: result.results.length,
        limit: parseInt(limit),
        offset: parseInt(offset)
      }
    });
  } catch (error) {
    logger.error('List transactions error:', error);
    return c.json({
      success: false,
      error: 'Failed to list transactions'
    }, 500);
  }
});

/**
 * GET /api/banking/transactions/:id
 * Get transaction details
 */
banking.get('/transactions/:id', async (c) => {
  try {
    const { businessId } = c.get('auth');
    const { id } = c.req.param();

    const transaction = await c.env.DB.prepare(`
      SELECT * FROM bank_transactions
      WHERE id = ? AND business_id = ?
    `).bind(id, businessId).first();

    if (!transaction) {
      return c.json({
        success: false,
        error: 'Transaction not found'
      }, 404);
    }

    return c.json({
      success: true,
      data: transaction
    });
  } catch (error) {
    logger.error('Get transaction error:', error);
    return c.json({
      success: false,
      error: 'Failed to get transaction'
    }, 500);
  }
});

/**
 * POST /api/banking/transactions/:id/find-matches
 * Find matching invoices/expenses for a transaction
 */
banking.post('/transactions/:id/find-matches', async (c) => {
  try {
    const { businessId } = c.get('auth');
    const { id } = c.req.param();

    const matcher = new TransactionMatcher(c.env);
    const matches = await matcher.findMatches(id, businessId);

    return c.json({
      success: true,
      data: {
        transaction_id: id,
        matches,
        count: matches.length
      }
    });
  } catch (error) {
    logger.error('Find matches error:', error);
    return c.json({
      success: false,
      error: 'Failed to find matches'
    }, 500);
  }
});

/**
 * POST /api/banking/transactions/:id/apply-match
 * Apply a match to a transaction
 */
banking.post('/transactions/:id/apply-match', async (c) => {
  try {
    const { businessId } = c.get('auth');
    const { id } = c.req.param();
    const { match_type, match_id } = await c.req.json();

    if (!match_type || !match_id) {
      return c.json({
        success: false,
        error: 'match_type and match_id are required'
      }, 400);
    }

    if (!['invoice', 'expense'].includes(match_type)) {
      return c.json({
        success: false,
        error: 'match_type must be invoice or expense'
      }, 400);
    }

    const matcher = new TransactionMatcher(c.env);
    const success = await matcher.applyMatch(id, match_type, match_id, businessId);

    if (!success) {
      return c.json({
        success: false,
        error: 'Failed to apply match'
      }, 500);
    }

    return c.json({
      success: true,
      data: {
        message: 'Match applied successfully',
        transaction_id: id,
        match_type,
        match_id
      }
    });
  } catch (error) {
    logger.error('Apply match error:', error);
    return c.json({
      success: false,
      error: 'Failed to apply match'
    }, 500);
  }
});

/**
 * POST /api/banking/transactions/:id/ignore
 * Ignore a transaction (mark as not requiring matching)
 */
banking.post('/transactions/:id/ignore', async (c) => {
  try {
    const { businessId } = c.get('auth');
    const { id } = c.req.param();

    await c.env.DB.prepare(`
      UPDATE bank_transactions
      SET status = 'ignored', updated_at = datetime('now')
      WHERE id = ? AND business_id = ?
    `).bind(id, businessId).run();

    return c.json({
      success: true,
      data: {
        message: 'Transaction ignored',
        transaction_id: id
      }
    });
  } catch (error) {
    logger.error('Ignore transaction error:', error);
    return c.json({
      success: false,
      error: 'Failed to ignore transaction'
    }, 500);
  }
});

/**
 * GET /api/banking/connections
 * List bank connections
 */
banking.get('/connections', async (c) => {
  try {
    const { businessId } = c.get('auth');

    const result = await c.env.DB.prepare(`
      SELECT
        id, institution_id, institution_name, status,
        last_synced_at, created_at
      FROM bank_connections
      WHERE business_id = ?
      ORDER BY created_at DESC
    `).bind(businessId).all();

    return c.json({
      success: true,
      data: {
        connections: result.results
      }
    });
  } catch (error) {
    logger.error('List connections error:', error);
    return c.json({
      success: false,
      error: 'Failed to list connections'
    }, 500);
  }
});

/**
 * POST /api/banking/connections
 * Create a new bank connection (Plaid integration)
 */
banking.post('/connections', async (c) => {
  try {
    const { businessId, userId } = c.get('auth');
    void userId;
    const { public_token, institution_id, institution_name, accounts } = await c.req.json();

    if (!public_token || !institution_id || !institution_name) {
      return c.json({
        success: false,
        error: 'Missing required fields'
      }, 400);
    }

    // TODO: Exchange public_token for access_token via Plaid API
    // For now, we'll store a placeholder
    const access_token = 'placeholder_' + public_token;

    const connectionId = crypto.randomUUID();

    await c.env.DB.prepare(`
      INSERT INTO bank_connections (
        id, business_id, plaid_item_id, plaid_access_token,
        institution_id, institution_name, accounts, status, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', datetime('now'))
    `).bind(
      connectionId,
      businessId,
      public_token,
      access_token,
      institution_id,
      institution_name,
      JSON.stringify(accounts || [])
    ).run();

    return c.json({
      success: true,
      data: {
        connection_id: connectionId,
        message: 'Bank connection created successfully'
      }
    });
  } catch (error) {
    logger.error('Create connection error:', error);
    return c.json({
      success: false,
      error: 'Failed to create bank connection'
    }, 500);
  }
});

/**
 * DELETE /api/banking/connections/:id
 * Remove a bank connection
 */
banking.delete('/connections/:id', async (c) => {
  try {
    const { businessId } = c.get('auth');
    const { id } = c.req.param();

    await c.env.DB.prepare(`
      UPDATE bank_connections
      SET status = 'inactive', updated_at = datetime('now')
      WHERE id = ? AND business_id = ?
    `).bind(id, businessId).run();

    return c.json({
      success: true,
      data: {
        message: 'Bank connection removed'
      }
    });
  } catch (error) {
    logger.error('Delete connection error:', error);
    return c.json({
      success: false,
      error: 'Failed to remove connection'
    }, 500);
  }
});

/**
 * GET /api/banking/stats
 * Get banking statistics
 */
banking.get('/stats', async (c) => {
  try {
    const { businessId } = c.get('auth');

    const stats = await c.env.DB.prepare(`
      SELECT
        COUNT(*) as total_transactions,
        SUM(CASE WHEN status = 'unmatched' THEN 1 ELSE 0 END) as unmatched_count,
        SUM(CASE WHEN status = 'matched' THEN 1 ELSE 0 END) as matched_count,
        SUM(CASE WHEN status = 'review' THEN 1 ELSE 0 END) as review_count,
        SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END) as total_inflows,
        SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END) as total_outflows
      FROM bank_transactions
      WHERE business_id = ?
        AND transaction_date >= date('now', '-30 days')
    `).bind(businessId).first();

    return c.json({
      success: true,
      data: stats
    });
  } catch (error) {
    logger.error('Get stats error:', error);
    return c.json({
      success: false,
      error: 'Failed to get stats'
    }, 500);
  }
});

export default banking;
