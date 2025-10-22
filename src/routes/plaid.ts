// @ts-nocheck
/**
 * Plaid API Routes
 * Handles bank connection and transaction sync endpoints
 */

import { Hono } from 'hono';
import { Logger } from '../shared/logger';
const logger = new Logger({ component: 'plaid' });
import type { Env } from '../types/env';
import { PlaidClient } from '../services/plaid/plaid-client';
import { PlaidSyncService } from '../services/plaid/plaid-sync-service';

const plaid = new Hono<{ Bindings: Env }>();

// ==================
// Middleware
// ==================

// Get business_id from auth context
plaid.use('*', async (c, next) => {
  // TODO: Get from JWT token
  const businessId = c.req.header('x-business-id') || 'default-business-id';
  c.set('businessId' as any, businessId);
  await next();
});

// ==================
// Link Token Routes
// ==================

/**
 * POST /plaid/link-token
 * Create Plaid Link token for OAuth flow
 */
plaid.post('/link-token', async (c) => {
  try {
    const businessId = c.get('businessId' as any) as string;
    const { redirect_uri } = await c.req.json();

    const plaidClient = new PlaidClient(c.env);

    // Get business name from database
    const business = await c.env.DB_MAIN.prepare(
      'SELECT name FROM businesses WHERE id = ?'
    )
      .bind(businessId)
      .first<{ name: string }>();

    if (!business) {
      return c.json({ success: false, error: 'Business not found' }, 404);
    }

    const linkToken = await plaidClient.createLinkToken({
      user_id: businessId,
      business_name: business.name,
      products: ['transactions'],
      country_codes: ['US'],
      language: 'en',
      redirect_uri,
    });

    return c.json({
      success: true,
      data: {
        link_token: linkToken.link_token,
        expiration: linkToken.expiration,
      },
    });
  } catch (error: any) {
    logger.error('Error creating link token:', error);
    return c.json(
      {
        success: false,
        error: error.message || 'Failed to create link token',
      },
      500
    );
  }
});

// ==================
// Connection Routes
// ==================

/**
 * POST /plaid/connections
 * Create new bank connection from public token
 */
plaid.post('/connections', async (c) => {
  try {
    const businessId = c.get('businessId' as any) as string;
    const { public_token } = await c.req.json();

    if (!public_token) {
      return c.json({ success: false, error: 'public_token is required' }, 400);
    }

    const service = new PlaidSyncService(c.env);
    const connectionId = await service.createConnection({
      businessId,
      publicToken: public_token,
    });

    return c.json({
      success: true,
      data: { connection_id: connectionId },
    });
  } catch (error: any) {
    logger.error('Error creating connection:', error);
    return c.json(
      {
        success: false,
        error: error.message || 'Failed to create connection',
      },
      500
    );
  }
});

/**
 * GET /plaid/connections
 * List all bank connections
 */
plaid.get('/connections', async (c) => {
  try {
    const businessId = c.get('businessId' as any) as string;

    const service = new PlaidSyncService(c.env);
    const connections = await service.getConnections(businessId);

    return c.json({
      success: true,
      data: { connections },
    });
  } catch (error: any) {
    logger.error('Error listing connections:', error);
    return c.json(
      {
        success: false,
        error: error.message || 'Failed to list connections',
      },
      500
    );
  }
});

/**
 * GET /plaid/connections/:id
 * Get connection details
 */
plaid.get('/connections/:id', async (c) => {
  try {
    const connectionId = c.req.param('id');

    const connection = await c.env.DB_MAIN.prepare(
      'SELECT * FROM plaid_connections WHERE id = ?'
    )
      .bind(connectionId)
      .first();

    if (!connection) {
      return c.json({ success: false, error: 'Connection not found' }, 404);
    }

    return c.json({
      success: true,
      data: { connection },
    });
  } catch (error: any) {
    logger.error('Error getting connection:', error);
    return c.json(
      {
        success: false,
        error: error.message || 'Failed to get connection',
      },
      500
    );
  }
});

/**
 * DELETE /plaid/connections/:id
 * Disconnect bank connection
 */
plaid.delete('/connections/:id', async (c) => {
  try {
    const connectionId = c.req.param('id');

    const service = new PlaidSyncService(c.env);
    await service.disconnectConnection(connectionId);

    return c.json({
      success: true,
      data: { message: 'Connection disconnected successfully' },
    });
  } catch (error: any) {
    logger.error('Error disconnecting connection:', error);
    return c.json(
      {
        success: false,
        error: error.message || 'Failed to disconnect connection',
      },
      500
    );
  }
});

// ==================
// Account Routes
// ==================

/**
 * GET /plaid/connections/:id/accounts
 * Get accounts for a connection
 */
plaid.get('/connections/:id/accounts', async (c) => {
  try {
    const connectionId = c.req.param('id');

    const service = new PlaidSyncService(c.env);
    const accounts = await service.getAccounts(connectionId);

    return c.json({
      success: true,
      data: { accounts },
    });
  } catch (error: any) {
    logger.error('Error getting accounts:', error);
    return c.json(
      {
        success: false,
        error: error.message || 'Failed to get accounts',
      },
      500
    );
  }
});

/**
 * PUT /plaid/accounts/:id
 * Update account settings (enable/disable sync)
 */
plaid.put('/accounts/:id', async (c) => {
  try {
    const accountId = c.req.param('id');
    const { sync_enabled } = await c.req.json();

    await c.env.DB_MAIN.prepare(
      'UPDATE plaid_accounts SET sync_enabled = ? WHERE id = ?'
    )
      .bind(sync_enabled ? 1 : 0, accountId)
      .run();

    return c.json({
      success: true,
      data: { message: 'Account updated successfully' },
    });
  } catch (error: any) {
    logger.error('Error updating account:', error);
    return c.json(
      {
        success: false,
        error: error.message || 'Failed to update account',
      },
      500
    );
  }
});

// ==================
// Sync Routes
// ==================

/**
 * POST /plaid/connections/:id/sync
 * Manually trigger sync for a connection
 */
plaid.post('/connections/:id/sync', async (c) => {
  try {
    const connectionId = c.req.param('id');

    const service = new PlaidSyncService(c.env);
    const result = await service.syncConnection(connectionId);

    return c.json({
      success: true,
      data: result,
    });
  } catch (error: any) {
    logger.error('Error syncing connection:', error);
    return c.json(
      {
        success: false,
        error: error.message || 'Failed to sync connection',
      },
      500
    );
  }
});

/**
 * GET /plaid/accounts/:id/transactions
 * Get unmatched transactions for an account
 */
plaid.get('/accounts/:id/transactions', async (c) => {
  try {
    const accountId = c.req.param('id');
    const { include_matched } = c.req.query();

    let query = 'SELECT * FROM plaid_transactions WHERE plaid_account_id = ?';
    if (!include_matched || include_matched === 'false') {
      query += ' AND matched_ledger_entry_id IS NULL';
    }
    query += ' ORDER BY transaction_date DESC';

    const { results } = await c.env.DB_MAIN.prepare(query).bind(accountId).all();

    return c.json({
      success: true,
      data: { transactions: results },
    });
  } catch (error: any) {
    logger.error('Error getting transactions:', error);
    return c.json(
      {
        success: false,
        error: error.message || 'Failed to get transactions',
      },
      500
    );
  }
});

// ==================
// Webhook Routes
// ==================

/**
 * POST /plaid/webhook
 * Handle Plaid webhooks
 */
plaid.post('/webhook', async (c) => {
  try {
    const payload = await c.req.json();

    // Store webhook for processing
    await c.env.DB_MAIN.prepare(
      `INSERT INTO plaid_webhooks (webhook_type, webhook_code, item_id, payload)
       VALUES (?, ?, ?, ?)`
    )
      .bind(
        payload.webhook_type,
        payload.webhook_code,
        payload.item_id,
        JSON.stringify(payload)
      )
      .run();

    // Process webhook based on type
    if (payload.webhook_code === 'SYNC_UPDATES_AVAILABLE') {
      // Get connection by item_id
      const connection = await c.env.DB_MAIN.prepare(
        'SELECT id FROM plaid_connections WHERE item_id = ?'
      )
        .bind(payload.item_id)
        .first<{ id: string }>();

      if (connection) {
        // Trigger sync (in production, use queue)
        const service = new PlaidSyncService(c.env);
        await service.syncConnection(connection.id);
      }
    }

    return c.json({ success: true });
  } catch (error: any) {
    logger.error('Error handling webhook:', error);
    return c.json(
      {
        success: false,
        error: error.message || 'Failed to handle webhook',
      },
      500
    );
  }
});

export default plaid;
