// @ts-nocheck
/**
 * Bank Transaction Auto-Matching Service
 * Uses AI to automatically match bank transactions to invoices/expenses
 */

import type { Env } from '../../types/env';

export interface MatchSuggestion {
  transaction_id: string;
  match_type: 'invoice' | 'expense';
  match_id: string;
  confidence: number;
  reasons: string[];
  match_details: {
    amount_match: boolean;
    date_proximity: number; // days
    description_similarity: number; // 0-100
    vendor_match: boolean;
  };
}

export class TransactionMatcher {
  constructor(private env: Env) {}

  /**
   * Auto-match a bank transaction to invoices or expenses
   */
  async findMatches(
    transactionId: string,
    businessId: string
  ): Promise<MatchSuggestion[]> {
    try {
      // Get transaction details
      const transaction = await this.getTransaction(transactionId, businessId);
      if (!transaction) {
        throw new Error('Transaction not found');
      }

      const suggestions: MatchSuggestion[] = [];

      // Look for invoice matches (if transaction is incoming/positive)
      if (transaction.amount > 0) {
        const invoiceMatches = await this.matchToInvoices(transaction, businessId);
        suggestions.push(...invoiceMatches);
      }

      // Look for expense matches (if transaction is outgoing/negative)
      if (transaction.amount < 0) {
        const expenseMatches = await this.matchToExpenses(transaction, businessId);
        suggestions.push(...expenseMatches);
      }

      // Sort by confidence
      suggestions.sort((a, b) => b.confidence - a.confidence);

      // Return top 5 matches
      return suggestions.slice(0, 5);
    } catch (error) {
      console.error('Transaction matching error:', error);
      return [];
    }
  }

  /**
   * Match transaction to invoices
   */
  private async matchToInvoices(
    transaction: any,
    businessId: string
  ): Promise<MatchSuggestion[]> {
    const suggestions: MatchSuggestion[] = [];

    // Get unpaid/partially paid invoices within date range
    const dateFrom = new Date(transaction.transaction_date);
    dateFrom.setDate(dateFrom.getDate() - 30); // Look back 30 days

    const dateTo = new Date(transaction.transaction_date);
    dateTo.setDate(dateTo.getDate() + 7); // Look forward 7 days

    const invoices = await this.env.DB.prepare(`
      SELECT
        id, invoice_number, customer_name, total, issue_date, due_date,
        status
      FROM invoices
      WHERE business_id = ?
        AND status IN ('sent', 'overdue')
        AND issue_date >= ?
        AND issue_date <= ?
      ORDER BY issue_date DESC
      LIMIT 20
    `).bind(
      businessId,
      dateFrom.toISOString().split('T')[0],
      dateTo.toISOString().split('T')[0]
    ).all();

    for (const invoice of invoices.results) {
      const match = await this.calculateInvoiceMatchScore(
        transaction,
        invoice as any
      );

      if (match.confidence >= 50) { // Minimum threshold
        suggestions.push({
          transaction_id: transaction.id,
          match_type: 'invoice',
          match_id: invoice.id as string,
          confidence: match.confidence,
          reasons: match.reasons,
          match_details: match.details
        });
      }
    }

    return suggestions;
  }

  /**
   * Match transaction to expenses
   */
  private async matchToExpenses(
    transaction: any,
    businessId: string
  ): Promise<MatchSuggestion[]> {
    const suggestions: MatchSuggestion[] = [];

    // Get unmatched expenses within date range
    const dateFrom = new Date(transaction.transaction_date);
    dateFrom.setDate(dateFrom.getDate() - 7); // Look back 7 days

    const dateTo = new Date(transaction.transaction_date);
    dateTo.setDate(dateTo.getDate() + 3); // Look forward 3 days

    const expenses = await this.env.DB.prepare(`
      SELECT
        id, vendor_name, amount, expense_date, description, category,
        status
      FROM expenses
      WHERE business_id = ?
        AND matched_transaction_id IS NULL
        AND expense_date >= ?
        AND expense_date <= ?
      ORDER BY expense_date DESC
      LIMIT 20
    `).bind(
      businessId,
      dateFrom.toISOString().split('T')[0],
      dateTo.toISOString().split('T')[0]
    ).all();

    for (const expense of expenses.results) {
      const match = await this.calculateExpenseMatchScore(
        transaction,
        expense as any
      );

      if (match.confidence >= 50) { // Minimum threshold
        suggestions.push({
          transaction_id: transaction.id,
          match_type: 'expense',
          match_id: expense.id as string,
          confidence: match.confidence,
          reasons: match.reasons,
          match_details: match.details
        });
      }
    }

    return suggestions;
  }

  /**
   * Calculate match score for invoice
   */
  private async calculateInvoiceMatchScore(
    transaction: any,
    invoice: any
  ): Promise<{
    confidence: number;
    reasons: string[];
    details: any;
  }> {
    const reasons: string[] = [];
    let score = 0;

    // Amount matching (40 points max)
    const amountDiff = Math.abs(transaction.amount - invoice.total);
    const amountMatchPercent = 100 - (amountDiff / invoice.total * 100);

    if (amountMatchPercent >= 99) {
      score += 40;
      reasons.push('Exact amount match');
    } else if (amountMatchPercent >= 95) {
      score += 35;
      reasons.push('Very close amount match');
    } else if (amountMatchPercent >= 90) {
      score += 25;
      reasons.push('Close amount match');
    }

    // Date proximity (20 points max)
    const transactionDate = new Date(transaction.transaction_date);
    const dueDate = new Date(invoice.due_date);
    const daysDiff = Math.abs(Math.floor((transactionDate.getTime() - dueDate.getTime()) / (1000 * 60 * 60 * 24)));

    if (daysDiff === 0) {
      score += 20;
      reasons.push('Payment on due date');
    } else if (daysDiff <= 3) {
      score += 15;
      reasons.push('Payment within 3 days of due date');
    } else if (daysDiff <= 7) {
      score += 10;
      reasons.push('Payment within a week of due date');
    }

    // Description/customer name matching (30 points max)
    const descriptionSimilarity = await this.calculateTextSimilarity(
      transaction.description + ' ' + (transaction.merchant_name || ''),
      invoice.customer_name
    );

    if (descriptionSimilarity >= 80) {
      score += 30;
      reasons.push('Strong description match');
    } else if (descriptionSimilarity >= 60) {
      score += 20;
      reasons.push('Good description match');
    } else if (descriptionSimilarity >= 40) {
      score += 10;
      reasons.push('Partial description match');
    }

    // Invoice reference in description (10 points)
    if (transaction.description.includes(invoice.invoice_number)) {
      score += 10;
      reasons.push('Invoice number found in description');
    }

    return {
      confidence: Math.min(score, 100),
      reasons,
      details: {
        amount_match: amountMatchPercent >= 95,
        date_proximity: daysDiff,
        description_similarity: descriptionSimilarity,
        vendor_match: descriptionSimilarity >= 60
      }
    };
  }

  /**
   * Calculate match score for expense
   */
  private async calculateExpenseMatchScore(
    transaction: any,
    expense: any
  ): Promise<{
    confidence: number;
    reasons: string[];
    details: any;
  }> {
    const reasons: string[] = [];
    let score = 0;

    // Amount matching (50 points max)
    const transactionAmount = Math.abs(transaction.amount);
    const amountDiff = Math.abs(transactionAmount - expense.amount);
    const amountMatchPercent = 100 - (amountDiff / expense.amount * 100);

    if (amountMatchPercent >= 99) {
      score += 50;
      reasons.push('Exact amount match');
    } else if (amountMatchPercent >= 95) {
      score += 40;
      reasons.push('Very close amount match');
    } else if (amountMatchPercent >= 90) {
      score += 30;
      reasons.push('Close amount match');
    }

    // Date proximity (20 points max)
    const transactionDate = new Date(transaction.transaction_date);
    const expenseDate = new Date(expense.expense_date);
    const daysDiff = Math.abs(Math.floor((transactionDate.getTime() - expenseDate.getTime()) / (1000 * 60 * 60 * 24)));

    if (daysDiff === 0) {
      score += 20;
      reasons.push('Same date transaction');
    } else if (daysDiff <= 2) {
      score += 15;
      reasons.push('Within 2 days');
    } else if (daysDiff <= 5) {
      score += 10;
      reasons.push('Within 5 days');
    }

    // Vendor/merchant matching (30 points max)
    const vendorSimilarity = await this.calculateTextSimilarity(
      transaction.merchant_name || transaction.description,
      expense.vendor_name
    );

    if (vendorSimilarity >= 80) {
      score += 30;
      reasons.push('Strong vendor match');
    } else if (vendorSimilarity >= 60) {
      score += 20;
      reasons.push('Good vendor match');
    } else if (vendorSimilarity >= 40) {
      score += 10;
      reasons.push('Partial vendor match');
    }

    return {
      confidence: Math.min(score, 100),
      reasons,
      details: {
        amount_match: amountMatchPercent >= 95,
        date_proximity: daysDiff,
        description_similarity: vendorSimilarity,
        vendor_match: vendorSimilarity >= 60
      }
    };
  }

  /**
   * Calculate text similarity using AI
   */
  private async calculateTextSimilarity(text1: string, text2: string): Promise<number> {
    try {
      // Simple approach: Use Levenshtein distance
      const similarity = this.levenshteinSimilarity(
        text1.toLowerCase().trim(),
        text2.toLowerCase().trim()
      );

      return Math.round(similarity * 100);
    } catch (error) {
      console.error('Text similarity error:', error);
      return 0;
    }
  }

  /**
   * Levenshtein similarity (0-1)
   */
  private levenshteinSimilarity(str1: string, str2: string): number {
    const longer = str1.length > str2.length ? str1 : str2;
    const shorter = str1.length > str2.length ? str2 : str1;

    if (longer.length === 0) {
      return 1.0;
    }

    const distance = this.levenshteinDistance(longer, shorter);
    return (longer.length - distance) / longer.length;
  }

  /**
   * Levenshtein distance calculation
   */
  private levenshteinDistance(str1: string, str2: string): number {
    const matrix: number[][] = [];

    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }

    return matrix[str2.length][str1.length];
  }

  /**
   * Get transaction by ID
   */
  private async getTransaction(transactionId: string, businessId: string): Promise<any> {
    const result = await this.env.DB.prepare(`
      SELECT * FROM bank_transactions
      WHERE id = ? AND business_id = ?
    `).bind(transactionId, businessId).first() as any;

    return result;
  }

  /**
   * Apply match to transaction
   */
  async applyMatch(
    transactionId: string,
    matchType: 'invoice' | 'expense',
    matchId: string,
    businessId: string
  ): Promise<boolean> {
    try {
      const now = new Date().toISOString();

      // Update transaction
      await this.env.DB.prepare(`
        UPDATE bank_transactions
        SET
          ${matchType === 'invoice' ? 'matched_invoice_id' : 'matched_expense_id'} = ?,
          status = 'matched',
          matched_at = ?,
          updated_at = ?
        WHERE id = ? AND business_id = ?
      `).bind(matchId, now, now, transactionId, businessId).run();

      // Update invoice/expense status
      if (matchType === 'invoice') {
        await this.env.DB.prepare(`
          UPDATE invoices
          SET status = 'paid', paid_date = ?, updated_at = ?
          WHERE id = ?
        `).bind(now, now, matchId).run();
      } else {
        await this.env.DB.prepare(`
          UPDATE expenses
          SET status = 'approved', matched_transaction_id = ?, updated_at = ?
          WHERE id = ?
        `).bind(transactionId, now, matchId).run();
      }

      // Learn from this match (save matching rule)
      await this.learnFromMatch(transactionId, matchType, matchId, businessId);

      return true;
    } catch (error) {
      console.error('Apply match error:', error);
      return false;
    }
  }

  /**
   * Learn from successful match to improve future matching
   */
  private async learnFromMatch(
    transactionId: string,
    matchType: string,
    matchId: string,
    businessId: string
  ): Promise<void> {
    try {
      // Get transaction and matched item
      const transaction = await this.getTransaction(transactionId, businessId);

      let pattern = '';
      if (transaction.merchant_name) {
        pattern = transaction.merchant_name.toLowerCase();
      } else {
        const words = transaction.description.toLowerCase().split(' ');
        pattern = words.slice(0, 3).join(' '); // First 3 words
      }

      // Create or update matching rule
      const ruleId = crypto.randomUUID();
      await this.env.DB.prepare(`
        INSERT INTO transaction_matching_rules (
          id, business_id, rule_type, pattern, target_type, target_id,
          confidence_threshold, auto_match, match_count, last_matched_at, created_at
        ) VALUES (?, ?, 'pattern', ?, ?, ?, 90, 0, 1, datetime('now'), datetime('now'))
        ON CONFLICT(pattern, business_id) DO UPDATE SET
          match_count = match_count + 1,
          last_matched_at = datetime('now')
      `).bind(ruleId, businessId, pattern, matchType, matchId).run();
    } catch (error) {
      console.error('Learn from match error:', error);
    }
  }
}
