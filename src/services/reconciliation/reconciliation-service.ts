// @ts-nocheck
/**
 * Reconciliation Service
 * Handles account reconciliation logic, auto-matching, and discrepancy detection
 */

import type { Env } from '../../types/env';

// TODO: Use Account interface when implementing reconciliation
// interface Account {
//   id: string;
//   business_id: string;
//   account_name: string;
//   account_type: string;
//   current_balance: number;
//   currency: string;
// }

interface Reconciliation {
  id: string;
  business_id: string;
  account_id: string;
  statement_date: string;
  statement_balance: number;
  book_balance: number;
  difference: number;
  status: 'in_progress' | 'completed' | 'review_required';
  statement_file_url?: string;
}

interface StatementTransaction {
  id: string;
  transaction_date: string;
  description: string;
  amount: number;
  reference_number?: string;
  check_number?: string;
}

interface BookTransaction {
  id: string;
  transaction_date: string;
  description: string;
  amount: number;
  account_id: string;
}

interface MatchSuggestion {
  statement_transaction_id: string;
  book_transaction_id: string;
  confidence: number;
  match_reasons: string[];
}

export class ReconciliationService {
  constructor(private env: Env) {}

  /**
   * Create a new reconciliation for an account
   */
  async createReconciliation(
    businessId: string,
    accountId: string,
    statementDate: string,
    statementBalance: number
  ): Promise<string> {
    const reconciliationId = crypto.randomUUID();

    // Get current book balance for the account at statement date
    const bookBalance = await this.getBookBalance(businessId, accountId, statementDate);
    const difference = statementBalance - bookBalance;

    await this.env.DB.prepare(`
      INSERT INTO reconciliations (
        id, business_id, account_id, statement_date,
        statement_balance, book_balance, difference, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `)
      .bind(
        reconciliationId,
        businessId,
        accountId,
        statementDate,
        statementBalance,
        bookBalance,
        difference,
        'in_progress'
      )
      .run();

    return reconciliationId;
  }

  /**
   * Get book balance for account at specific date
   */
  private async getBookBalance(
    businessId: string,
    accountId: string,
    asOfDate: string
  ): Promise<number> {
    const result = await this.env.DB.prepare(`
      SELECT COALESCE(SUM(amount), 0) as balance
      FROM ledger_entries
      WHERE business_id = ?
        AND account_id = ?
        AND entry_date <= ?
        AND status = 'posted'
    `)
      .bind(businessId, accountId, asOfDate)
      .first() as any;

    return (result?.balance as number) || 0;
  }

  /**
   * Import statement transactions from parsed CSV/OFX data
   */
  async importStatementTransactions(
    reconciliationId: string,
    transactions: StatementTransaction[]
  ): Promise<number> {
    let imported = 0;

    for (const txn of transactions) {
      const txnId = crypto.randomUUID();

      await this.env.DB.prepare(`
        INSERT INTO statement_transactions (
          id, reconciliation_id, transaction_date, description,
          amount, reference_number, check_number
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `)
        .bind(
          txnId,
          reconciliationId,
          txn.transaction_date,
          txn.description,
          txn.amount,
          txn.reference_number || null,
          txn.check_number || null
        )
        .run();

      imported++;
    }

    return imported;
  }

  /**
   * Auto-match transactions based on rules
   */
  async autoMatchTransactions(
    businessId: string,
    reconciliationId: string
  ): Promise<{ matched: number; suggestions: MatchSuggestion[] }> {
    // Get unmatched statement transactions
    const statementTxns = await this.env.DB.prepare(`
      SELECT * FROM statement_transactions
      WHERE reconciliation_id = ? AND matched = 0
      ORDER BY transaction_date DESC
    `)
      .bind(reconciliationId)
      .all();

    // Get unmatched book transactions (from ledger)
    const reconciliation = await this.getReconciliation(reconciliationId);
    const bookTxns = await this.env.DB.prepare(`
      SELECT
        id,
        entry_date as transaction_date,
        description,
        amount,
        account_id
      FROM ledger_entries
      WHERE business_id = ?
        AND account_id = ?
        AND entry_date <= ?
        AND status = 'posted'
        AND id NOT IN (
          SELECT transaction_id FROM reconciliation_items
          WHERE reconciliation_id = ? AND matched = 1
        )
      ORDER BY entry_date DESC
      LIMIT 500
    `)
      .bind(
        businessId,
        reconciliation.account_id,
        reconciliation.statement_date,
        reconciliationId
      )
      .all();

    let matched = 0;
    const suggestions: MatchSuggestion[] = [];

    // Apply matching algorithm
    for (const stmtTxn of statementTxns.results as StatementTransaction[]) {
      const matches = await this.findMatches(
        stmtTxn,
        bookTxns.results as BookTransaction[]
      );

      if (matches.length > 0) {
        const bestMatch = matches[0];

        if (bestMatch.confidence >= 95) {
          // Auto-match with high confidence
          await this.applyMatch(
            reconciliationId,
            stmtTxn.id,
            bestMatch.book_transaction_id,
            'auto',
            bestMatch.confidence
          );
          matched++;
        } else if (bestMatch.confidence >= 70) {
          // Suggest match for manual review
          suggestions.push({
            statement_transaction_id: stmtTxn.id,
            book_transaction_id: bestMatch.book_transaction_id,
            confidence: bestMatch.confidence,
            match_reasons: bestMatch.match_reasons,
          });
        }
      }
    }

    return { matched, suggestions };
  }

  /**
   * Find potential matches for a statement transaction
   */
  private async findMatches(
    stmtTxn: StatementTransaction,
    bookTxns: BookTransaction[]
  ): Promise<Array<{
    book_transaction_id: string;
    confidence: number;
    match_reasons: string[];
  }>> {
    const matches: Array<{
      book_transaction_id: string;
      confidence: number;
      match_reasons: string[];
    }> = [];

    for (const bookTxn of bookTxns) {
      let confidence = 0;
      const reasons: string[] = [];

      // Exact amount match (40 points)
      if (Math.abs(stmtTxn.amount - bookTxn.amount) < 0.01) {
        confidence += 40;
        reasons.push('Exact amount match');
      } else {
        // Close amount match (20 points if within 1%)
        const percentDiff = Math.abs(stmtTxn.amount - bookTxn.amount) / Math.abs(stmtTxn.amount);
        if (percentDiff < 0.01) {
          confidence += 20;
          reasons.push('Very close amount match (within 1%)');
        }
      }

      // Date proximity (30 points)
      const stmtDate = new Date(stmtTxn.transaction_date);
      const bookDate = new Date(bookTxn.transaction_date);
      const daysDiff = Math.abs((stmtDate.getTime() - bookDate.getTime()) / (1000 * 60 * 60 * 24));

      if (daysDiff === 0) {
        confidence += 30;
        reasons.push('Same day transaction');
      } else if (daysDiff <= 2) {
        confidence += 20;
        reasons.push(`${daysDiff} day${daysDiff > 1 ? 's' : ''} apart`);
      } else if (daysDiff <= 7) {
        confidence += 10;
        reasons.push('Within 1 week');
      }

      // Description similarity (30 points)
      const similarity = this.calculateStringSimilarity(
        stmtTxn.description.toLowerCase(),
        bookTxn.description.toLowerCase()
      );

      if (similarity >= 0.9) {
        confidence += 30;
        reasons.push('Strong description match');
      } else if (similarity >= 0.7) {
        confidence += 20;
        reasons.push('Good description match');
      } else if (similarity >= 0.5) {
        confidence += 10;
        reasons.push('Moderate description match');
      }

      // Check number match (bonus 10 points if present)
      if (stmtTxn.check_number && bookTxn.description.includes(stmtTxn.check_number)) {
        confidence += 10;
        reasons.push('Check number match');
      }

      if (confidence >= 50) {
        matches.push({
          book_transaction_id: bookTxn.id,
          confidence: Math.min(confidence, 100),
          match_reasons: reasons,
        });
      }
    }

    // Sort by confidence descending
    matches.sort((a, b) => b.confidence - a.confidence);

    return matches.slice(0, 5); // Return top 5 matches
  }

  /**
   * Calculate string similarity (Dice coefficient)
   */
  private calculateStringSimilarity(str1: string, str2: string): number {
    if (str1 === str2) return 1;
    if (str1.length < 2 || str2.length < 2) return 0;

    const bigrams1 = new Set<string>();
    for (let i = 0; i < str1.length - 1; i++) {
      bigrams1.add(str1.substring(i, i + 2));
    }

    const bigrams2 = new Set<string>();
    for (let i = 0; i < str2.length - 1; i++) {
      bigrams2.add(str2.substring(i, i + 2));
    }

    let intersection = 0;
    for (const bigram of bigrams1) {
      if (bigrams2.has(bigram)) intersection++;
    }

    return (2 * intersection) / (bigrams1.size + bigrams2.size);
  }

  /**
   * Apply a manual or automatic match
   */
  async applyMatch(
    reconciliationId: string,
    statementTxnId: string,
    bookTxnId: string,
    matchType: 'auto' | 'manual' | 'suggested',
    confidence: number,
    userId?: string
  ): Promise<void> {
    const itemId = crypto.randomUUID();

    // Get statement transaction details
    const stmtTxn = await this.env.DB.prepare(`
      SELECT * FROM statement_transactions WHERE id = ?
    `)
      .bind(statementTxnId)
      .first() as any;

    if (!stmtTxn) {
      throw new Error('Statement transaction not found');
    }

    // Create reconciliation item
    await this.env.DB.prepare(`
      INSERT INTO reconciliation_items (
        id, reconciliation_id, transaction_id, statement_transaction_id,
        transaction_date, description, amount, matched, match_confidence,
        match_type, matched_at, matched_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, datetime('now'), ?)
    `)
      .bind(
        itemId,
        reconciliationId,
        bookTxnId,
        statementTxnId,
        stmtTxn.transaction_date,
        stmtTxn.description,
        stmtTxn.amount,
        confidence,
        matchType,
        userId || null
      )
      .run();

    // Mark statement transaction as matched
    await this.env.DB.prepare(`
      UPDATE statement_transactions
      SET matched = 1, matched_item_id = ?
      WHERE id = ?
    `)
      .bind(itemId, statementTxnId)
      .run();
  }

  /**
   * Detect discrepancies (unmatched transactions)
   */
  async detectDiscrepancies(reconciliationId: string): Promise<void> {
    // Find unmatched statement transactions
    const unmatchedStatement = await this.env.DB.prepare(`
      SELECT * FROM statement_transactions
      WHERE reconciliation_id = ? AND matched = 0
    `)
      .bind(reconciliationId)
      .all();

    for (const txn of unmatchedStatement.results) {
      const discrepancyId = crypto.randomUUID();

      await this.env.DB.prepare(`
        INSERT INTO reconciliation_discrepancies (
          id, reconciliation_id, discrepancy_type, description,
          amount, statement_transaction_id, resolution
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `)
        .bind(
          discrepancyId,
          reconciliationId,
          'missing_transaction',
          `Unmatched statement transaction: ${txn.description}`,
          txn.amount,
          txn.id,
          'pending'
        )
        .run();
    }
  }

  /**
   * Complete reconciliation
   */
  async completeReconciliation(
    reconciliationId: string,
    userId: string
  ): Promise<void> {
    await this.env.DB.prepare(`
      UPDATE reconciliations
      SET status = 'completed',
          reconciled_by = ?,
          reconciled_at = datetime('now'),
          updated_at = datetime('now')
      WHERE id = ?
    `)
      .bind(userId, reconciliationId)
      .run();
  }

  /**
   * Get reconciliation details
   */
  async getReconciliation(reconciliationId: string): Promise<Reconciliation> {
    const result = await this.env.DB.prepare(`
      SELECT * FROM reconciliations WHERE id = ?
    `)
      .bind(reconciliationId)
      .first() as any;

    if (!result) {
      throw new Error('Reconciliation not found');
    }

    return result as Reconciliation;
  }

  /**
   * Get reconciliation statistics
   */
  async getReconciliationStats(reconciliationId: string): Promise<{
    total_statement_transactions: number;
    matched_transactions: number;
    unmatched_transactions: number;
    total_discrepancies: number;
    match_percentage: number;
  }> {
    const totalStmt = await this.env.DB.prepare(`
      SELECT COUNT(*) as count FROM statement_transactions
      WHERE reconciliation_id = ?
    `)
      .bind(reconciliationId)
      .first() as any;

    const matched = await this.env.DB.prepare(`
      SELECT COUNT(*) as count FROM statement_transactions
      WHERE reconciliation_id = ? AND matched = 1
    `)
      .bind(reconciliationId)
      .first() as any;

    const discrepancies = await this.env.DB.prepare(`
      SELECT COUNT(*) as count FROM reconciliation_discrepancies
      WHERE reconciliation_id = ? AND resolution = 'pending'
    `)
      .bind(reconciliationId)
      .first() as any;

    const total = (totalStmt?.count as number) || 0;
    const matchedCount = (matched?.count as number) || 0;
    const unmatched = total - matchedCount;
    const matchPercentage = total > 0 ? (matchedCount / total) * 100 : 0;

    return {
      total_statement_transactions: total,
      matched_transactions: matchedCount,
      unmatched_transactions: unmatched,
      total_discrepancies: (discrepancies?.count as number) || 0,
      match_percentage: Math.round(matchPercentage),
    };
  }
}
