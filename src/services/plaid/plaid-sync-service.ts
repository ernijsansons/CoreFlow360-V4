/**
 * Plaid Sync Service
 * Manages synchronization of bank transactions with Plaid
 */

import type { Env } from '../../types/env';
import { PlaidClient, type PlaidTransaction } from './plaid-client';

// ==================
// Types
// ==================

export interface PlaidConnectionRecord {
  id: string;
  business_id: string;
  institution_id: string;
  institution_name: string;
  access_token: string;
  item_id: string;
  status: string;
  error_code: string | null;
  error_message: string | null;
  consent_expiration_time: string | null;
  created_at: string;
  last_sync_at: string | null;
  metadata: string | null;
}

export interface PlaidAccountRecord {
  id: string;
  plaid_connection_id: string;
  plaid_account_id: string;
  account_name: string;
  official_name: string | null;
  mask: string | null;
  type: string;
  subtype: string | null;
  balance_current: number | null;
  balance_available: number | null;
  balance_limit: number | null;
  currency_code: string;
  sync_enabled: boolean;
  created_at: string;
  last_synced_at: string | null;
}

export interface PlaidTransactionRecord {
  id: string;
  plaid_account_id: string;
  plaid_transaction_id: string;
  transaction_date: string;
  authorized_date: string | null;
  amount: number;
  currency_code: string;
  name: string;
  merchant_name: string | null;
  category: string | null;
  category_id: string | null;
  pending: boolean;
  payment_channel: string | null;
  payment_meta: string | null;
  location: string | null;
  matched_ledger_entry_id: string | null;
  created_at: string;
}

export interface SyncResult {
  connection_id: string;
  transactions_added: number;
  transactions_modified: number;
  transactions_removed: number;
  cursor: string;
  error?: string;
}

// ==================
// Plaid Sync Service
// ==================

export class PlaidSyncService {
  private plaidClient: PlaidClient;
  private env: Env;

  constructor(env: Env) {
    this.env = env;
    this.plaidClient = new PlaidClient(env);
  }

  /**
   * Create a new Plaid connection
   */
  async createConnection(params: {
    businessId: string;
    publicToken: string;
  }): Promise<string> {
    const db = this.env.DB_MAIN;

    // Exchange public token for access token
    const { access_token, item_id } = await this.plaidClient.exchangePublicToken(
      params.publicToken
    );

    // Get institution and account details
    const [itemResponse, accountsResponse] = await Promise.all([
      this.plaidClient.getItem(access_token),
      this.plaidClient.getAccounts(access_token),
    ]);

    const institution = await this.plaidClient.getInstitution(
      itemResponse.item.institution_id
    );

    // Store connection
    const connectionId = crypto.randomUUID();
    await db
      .prepare(
        `INSERT INTO plaid_connections (
          id, business_id, institution_id, institution_name,
          access_token, item_id, status, consent_expiration_time, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        connectionId,
        params.businessId,
        institution.institution_id,
        institution.name,
        access_token, // TODO: Encrypt in production
        item_id,
        'active',
        itemResponse.item.consent_expiration_time,
        JSON.stringify({
          logo: institution.logo,
          primary_color: institution.primary_color,
          url: institution.url,
        })
      )
      .run();

    // Store accounts
    for (const account of accountsResponse.accounts) {
      await db
        .prepare(
          `INSERT INTO plaid_accounts (
            plaid_connection_id, plaid_account_id, account_name, official_name,
            mask, type, subtype, balance_current, balance_available, balance_limit,
            currency_code, sync_enabled
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(
          connectionId,
          account.account_id,
          account.name,
          account.official_name,
          account.mask,
          account.type,
          account.subtype,
          account.balances.current,
          account.balances.available,
          account.balances.limit,
          account.balances.iso_currency_code || 'USD',
          1
        )
        .run();
    }

    // Perform initial sync
    await this.syncConnection(connectionId);

    return connectionId;
  }

  /**
   * Sync transactions for a connection
   */
  async syncConnection(connectionId: string): Promise<SyncResult> {
    const db = this.env.DB_MAIN;

    // Get connection
    const connection = await db
      .prepare('SELECT * FROM plaid_connections WHERE id = ?')
      .bind(connectionId)
      .first<PlaidConnectionRecord>();

    if (!connection) {
      throw new Error(`Connection ${connectionId} not found`);
    }

    // Get last cursor from sync log
    const lastSync = await db
      .prepare(
        'SELECT cursor FROM plaid_sync_log WHERE plaid_connection_id = ? ORDER BY sync_started_at DESC LIMIT 1'
      )
      .bind(connectionId)
      .first<{ cursor: string | null }>();

    // Create sync log entry
    const syncLogId = crypto.randomUUID();
    await db
      .prepare(
        'INSERT INTO plaid_sync_log (id, plaid_connection_id, sync_status) VALUES (?, ?, ?)'
      )
      .bind(syncLogId, connectionId, 'in_progress')
      .run();

    try {
      let hasMore = true;
      let cursor = lastSync?.cursor || undefined;
      let totalAdded = 0;
      let totalModified = 0;
      let totalRemoved = 0;

      while (hasMore) {
        const syncResponse = await this.plaidClient.syncTransactions({
          access_token: connection.access_token,
          cursor,
        });

        // Process added transactions
        for (const txn of syncResponse.added) {
          await this.storePlaidTransaction(connectionId, txn);
          totalAdded++;
        }

        // Process modified transactions
        for (const txn of syncResponse.modified) {
          await this.updatePlaidTransaction(connectionId, txn);
          totalModified++;
        }

        // Process removed transactions
        for (const removed of syncResponse.removed) {
          await this.removePlaidTransaction(connectionId, removed.transaction_id);
          totalRemoved++;
        }

        cursor = syncResponse.next_cursor;
        hasMore = syncResponse.has_more;
      }

      // Update sync log
      await db
        .prepare(
          `UPDATE plaid_sync_log
           SET sync_completed_at = datetime('now'),
               sync_status = 'success',
               transactions_added = ?,
               transactions_modified = ?,
               transactions_removed = ?,
               cursor = ?
           WHERE id = ?`
        )
        .bind(totalAdded, totalModified, totalRemoved, cursor, syncLogId)
        .run();

      // Update connection last_sync_at
      await db
        .prepare(
          `UPDATE plaid_connections SET last_sync_at = datetime('now') WHERE id = ?`
        )
        .bind(connectionId)
        .run();

      return {
        connection_id: connectionId,
        transactions_added: totalAdded,
        transactions_modified: totalModified,
        transactions_removed: totalRemoved,
        cursor: cursor!,
      };
    } catch (error: any) {
      // Update sync log with error
      await db
        .prepare(
          `UPDATE plaid_sync_log
           SET sync_completed_at = datetime('now'),
               sync_status = 'error',
               error_code = ?,
               error_message = ?
           WHERE id = ?`
        )
        .bind(error.code || 'UNKNOWN', error.message, syncLogId)
        .run();

      throw error;
    }
  }

  /**
   * Store Plaid transaction in database
   */
  private async storePlaidTransaction(
    connectionId: string,
    txn: PlaidTransaction
  ): Promise<void> {
    const db = this.env.DB_MAIN;

    // Get plaid_account_id from connection
    const account = await db
      .prepare(
        'SELECT id FROM plaid_accounts WHERE plaid_connection_id = ? AND plaid_account_id = ?'
      )
      .bind(connectionId, txn.account_id)
      .first<{ id: string }>();

    if (!account) {
      throw new Error(`Account ${txn.account_id} not found`);
    }

    await db
      .prepare(
        `INSERT OR REPLACE INTO plaid_transactions (
          plaid_account_id, plaid_transaction_id, transaction_date, authorized_date,
          amount, currency_code, name, merchant_name, category, category_id,
          pending, payment_channel, payment_meta, location
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        account.id,
        txn.transaction_id,
        txn.date,
        txn.authorized_date,
        txn.amount,
        'USD', // TODO: Get from account
        txn.name,
        txn.merchant_name,
        txn.category ? JSON.stringify(txn.category) : null,
        txn.category_id,
        txn.pending ? 1 : 0,
        txn.payment_channel,
        JSON.stringify(txn.payment_meta),
        JSON.stringify(txn.location)
      )
      .run();
  }

  /**
   * Update existing Plaid transaction
   */
  private async updatePlaidTransaction(
    connectionId: string,
    txn: PlaidTransaction
  ): Promise<void> {
    const db = this.env.DB_MAIN;

    await db
      .prepare(
        `UPDATE plaid_transactions
         SET transaction_date = ?, authorized_date = ?, amount = ?,
             name = ?, merchant_name = ?, pending = ?
         WHERE plaid_transaction_id = ?`
      )
      .bind(
        txn.date,
        txn.authorized_date,
        txn.amount,
        txn.name,
        txn.merchant_name,
        txn.pending ? 1 : 0,
        txn.transaction_id
      )
      .run();
  }

  /**
   * Remove Plaid transaction
   */
  private async removePlaidTransaction(
    connectionId: string,
    transactionId: string
  ): Promise<void> {
    const db = this.env.DB_MAIN;

    await db
      .prepare('DELETE FROM plaid_transactions WHERE plaid_transaction_id = ?')
      .bind(transactionId)
      .run();
  }

  /**
   * Get all connections for a business
   */
  async getConnections(businessId: string): Promise<PlaidConnectionRecord[]> {
    const db = this.env.DB_MAIN;

    const { results } = await db
      .prepare('SELECT * FROM plaid_connections WHERE business_id = ? ORDER BY created_at DESC')
      .bind(businessId)
      .all<PlaidConnectionRecord>();

    return results;
  }

  /**
   * Get accounts for a connection
   */
  async getAccounts(connectionId: string): Promise<PlaidAccountRecord[]> {
    const db = this.env.DB_MAIN;

    const { results } = await db
      .prepare('SELECT * FROM plaid_accounts WHERE plaid_connection_id = ? ORDER BY account_name')
      .bind(connectionId)
      .all<PlaidAccountRecord>();

    return results;
  }

  /**
   * Get unmatched transactions for an account
   */
  async getUnmatchedTransactions(accountId: string): Promise<PlaidTransactionRecord[]> {
    const db = this.env.DB_MAIN;

    const { results } = await db
      .prepare(
        `SELECT * FROM plaid_transactions
         WHERE plaid_account_id = ? AND matched_ledger_entry_id IS NULL AND pending = 0
         ORDER BY transaction_date DESC`
      )
      .bind(accountId)
      .all<PlaidTransactionRecord>();

    return results;
  }

  /**
   * Disconnect a Plaid connection
   */
  async disconnectConnection(connectionId: string): Promise<void> {
    const db = this.env.DB_MAIN;

    // Get connection
    const connection = await db
      .prepare('SELECT access_token FROM plaid_connections WHERE id = ?')
      .bind(connectionId)
      .first<{ access_token: string }>();

    if (!connection) {
      throw new Error(`Connection ${connectionId} not found`);
    }

    // Remove from Plaid
    await this.plaidClient.removeItem(connection.access_token);

    // Update status
    await db
      .prepare('UPDATE plaid_connections SET status = ? WHERE id = ?')
      .bind('disconnected', connectionId)
      .run();
  }
}
