/**
 * Bank Reconciliation Service
 * Advanced automated bank reconciliation with ML-powered transaction matching
 */

import { z } from 'zod'
import { AppError } from '../../../shared/errors/app-error'
import { auditLogger } from '../../../shared/logging/audit-logger'

export enum ReconciliationStatus {
  PENDING = 'pending',
  IN_PROGRESS = 'in_progress',
  MATCHED = 'matched',
  UNMATCHED = 'unmatched',
  DISPUTED = 'disputed',
  REVIEWED = 'reviewed',
  APPROVED = 'approved',
  REJECTED = 'rejected'
}

export enum TransactionType {
  DEBIT = 'debit',
  CREDIT = 'credit',
  TRANSFER = 'transfer',
  FEE = 'fee',
  INTEREST = 'interest',
  ADJUSTMENT = 'adjustment'
}

export enum MatchConfidence {
  EXACT = 'exact',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  NO_MATCH = 'no_match'
}

export interface BankAccount {
  id: string
  businessId: string
  accountName: string
  accountNumber: string
  routingNumber: string
  bankName: string
  accountType: 'checking' | 'savings' | 'credit' | 'investment'
  currency: string
  currentBalance: number
  availableBalance: number
  lastReconciledDate?: string
  lastReconciledBalance?: number
  isActive: boolean
  metadata?: Record<string, unknown>
}

export interface BankTransaction {
  id: string
  accountId: string
  transactionId: string // Bank's transaction ID
  date: string
  description: string
  amount: number
  type: TransactionType
  balance: number
  category?: string
  merchantName?: string
  merchantCategory?: string
  location?: {
    city: string
    state: string
    country: string
  }
  metadata?: Record<string, unknown>
  rawData?: any // Original bank data
}

export interface BookTransaction {
  id: string
  businessId: string
  accountId: string
  date: string
  description: string
  amount: number
  type: TransactionType
  reference: string
  invoiceId?: string
  paymentId?: string
  customerId?: string
  vendorId?: string
  category: string
  reconciliationStatus: ReconciliationStatus
  matchedBankTransactionId?: string
  metadata?: Record<string, unknown>
}

export interface ReconciliationSession {
  id: string
  accountId: string
  periodStart: string
  periodEnd: string
  startingBalance: number
  endingBalance: number
  bankStatementBalance: number
  status: 'active' | 'completed' | 'cancelled'
  createdBy: string
  createdAt: string
  completedAt?: string
  summary: {
    totalBankTransactions: number
    totalBookTransactions: number
    matchedTransactions: number
    unmatchedBankTransactions: number
    unmatchedBookTransactions: number
    balanceDifference: number
  }
  metadata?: Record<string, unknown>
}

export interface TransactionMatch {
  id: string
  sessionId: string
  bankTransactionId: string
  bookTransactionId: string
  confidence: MatchConfidence
  score: number // 0-100
  matchCriteria: {
    amountMatch: boolean
    dateMatch: boolean
    descriptionMatch: boolean
    referenceMatch: boolean
    merchantMatch: boolean
  }
  differences: {
    amountDifference: number
    dateDifferenceInDays: number
    descriptionSimilarity: number
  }
  reviewRequired: boolean
  reviewedBy?: string
  reviewedAt?: string
  approvedBy?: string
  approvedAt?: string
  rejectedReason?: string
  metadata?: Record<string, unknown>
}

export interface MatchingRules {
  id: string
  name: string
  priority: number
  isActive: boolean
  conditions: {
    amountTolerance: number // Percentage
    dateTolerance: number // Days
    descriptionKeywords: string[]
    merchantNames: string[]
    referencePatterns: string[]
    minConfidenceScore: number
  }
  autoApprove: boolean
  autoApproveThreshold: number
  metadata?: Record<string, unknown>
}

const BankTransactionSchema = z.object({
  id: z.string().uuid(),
  accountId: z.string().uuid(),
  transactionId: z.string(),
  date: z.string().datetime(),
  description: z.string().min(1),
  amount: z.number(),
  type: z.nativeEnum(TransactionType),
  balance: z.number(),
  category: z.string().optional(),
  merchantName: z.string().optional(),
  merchantCategory: z.string().optional(),
  location: z.object({
    city: z.string(),
    state: z.string(),
    country: z.string()
  }).optional(),
  metadata: z.record(z.unknown()).optional(),
  rawData: z.any().optional()
})

export // TODO: Consider splitting BankReconciliationService into smaller, focused classes
class BankReconciliationService {
  private matchingRules: Map<string, MatchingRules> = new Map()
  private reconciliationSessions: Map<string, ReconciliationSession> = new Map()
  private transactionMatches: Map<string, TransactionMatch> = new Map()

  constructor(
    private readonly db: D1Database,
    private readonly mlService?: any // Machine Learning service for intelligent matching
  ) {
    this.initializeDefaultRules()
  }

  async startReconciliation(
    accountId: string,
    periodStart: string,
    periodEnd: string,
    bankStatementBalance: number,
    userId: string
  ): Promise<ReconciliationSession> {
    try {
      auditLogger.log({
        action: 'reconciliation_session_started',
        accountId,
        periodStart,
        periodEnd,
        bankStatementBalance,
        userId
      })

      // Validate inputs
      this.validateReconciliationPeriod(periodStart, periodEnd)

      // Get account information
      const account = await this.getBankAccount(accountId)
      if (!account) {
        throw new AppError('Bank account not found', 'ACCOUNT_NOT_FOUND', 404)
      }

      // Get starting balance
      const startingBalance = await this.getAccountBalanceAtDate(accountId, periodStart)

      // Create reconciliation session
      const session: ReconciliationSession = {
        id: this.generateSessionId(),
        accountId,
        periodStart,
        periodEnd,
        startingBalance,
        endingBalance: bankStatementBalance,
        bankStatementBalance,
        status: 'active',
        createdBy: userId,
        createdAt: new Date().toISOString(),
        summary: {
          totalBankTransactions: 0,
          totalBookTransactions: 0,
          matchedTransactions: 0,
          unmatchedBankTransactions: 0,
          unmatchedBookTransactions: 0,
          balanceDifference: 0
        }
      }

      // Get transactions for the period
      const [bankTransactions, bookTransactions] = await Promise.all([
        this.getBankTransactions(accountId, periodStart, periodEnd),
        this.getBookTransactions(accountId, periodStart, periodEnd)
      ])

      // Update session summary
      session.summary.totalBankTransactions = bankTransactions.length
      session.summary.totalBookTransactions = bookTransactions.length

      // Store session
      this.reconciliationSessions.set(session.id, session)

      // Start automated matching process
      await this.performAutomatedMatching(session.id, bankTransactions, bookTransactions)

      auditLogger.log({
        action: 'reconciliation_session_created',
        sessionId: session.id,
        bankTransactionCount: bankTransactions.length,
        bookTransactionCount: bookTransactions.length
      })

      return session

    } catch (error: any) {
      auditLogger.log({
        action: 'reconciliation_session_failed',
        accountId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      throw new AppError(
        'Failed to start reconciliation session',
        'RECONCILIATION_START_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  async performAutomatedMatching(
    sessionId: string,
    bankTransactions: BankTransaction[],
    bookTransactions: BookTransaction[]
  ): Promise<TransactionMatch[]> {
    try {
      auditLogger.log({
        action: 'automated_matching_started',
        sessionId,
        bankTransactionCount: bankTransactions.length,
        bookTransactionCount: bookTransactions.length
      })

      const matches: TransactionMatch[] = []
      const usedBookTransactions = new Set<string>()

      // Sort rules by priority
      const sortedRules = Array.from(this.matchingRules.values())
        .filter((rule: any) => rule.isActive)
        .sort((a, b) => b.priority - a.priority)

      // Match each bank transaction
      for (const bankTx of bankTransactions) {
        const bestMatch = await this.findBestMatch(
          bankTx,
          bookTransactions.filter((bt: any) => !usedBookTransactions.has(bt.id)),
          sortedRules
        )

        if (bestMatch) {
          matches.push(bestMatch)
          usedBookTransactions.add(bestMatch.bookTransactionId)
          this.transactionMatches.set(bestMatch.id, bestMatch)

          // Auto-approve if confidence is high enough
          if (bestMatch.confidence === MatchConfidence.EXACT ||
              (bestMatch.score >= 95 && !bestMatch.reviewRequired)) {
            await this.approveMatch(bestMatch.id, 'system')
          }
        }
      }

      // Update session summary
      const session = this.reconciliationSessions.get(sessionId)
      if (session) {
        session.summary.matchedTransactions = matches.length
        session.summary.unmatchedBankTransactions = bankTransactions.length - matches.length
        session.summary.unmatchedBookTransactions = bookTransactions.length - usedBookTransactions.size
        session.summary.balanceDifference = this.calculateBalanceDifference(session, matches)
      }

      auditLogger.log({
        action: 'automated_matching_completed',
        sessionId,
        matchCount: matches.length,
        autoApprovedCount: matches.filter((m: any) => m.approvedAt).length
      })

      return matches

    } catch (error: any) {
      auditLogger.log({
        action: 'automated_matching_failed',
        sessionId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      throw new AppError(
        'Automated matching failed',
        'MATCHING_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  private async findBestMatch(
    bankTransaction: BankTransaction,
    bookTransactions: BookTransaction[],
    rules: MatchingRules[]
  ): Promise<TransactionMatch | null> {
    let bestMatch: TransactionMatch | null = null
    let highestScore = 0

    for (const bookTx of bookTransactions) {
      const match = await this.evaluateMatch(bankTransaction, bookTx, rules)

      if (match && match.score > highestScore) {
        bestMatch = match
        highestScore = match.score
      }
    }

    return bestMatch
  }

  private async evaluateMatch(
    bankTx: BankTransaction,
    bookTx: BookTransaction,
    rules: MatchingRules[]
  ): Promise<TransactionMatch | null> {
    const matchCriteria = {
      amountMatch: false,
      dateMatch: false,
      descriptionMatch: false,
      referenceMatch: false,
      merchantMatch: false
    }

    const differences = {
      amountDifference: Math.abs(bankTx.amount - bookTx.amount),
      dateDifferenceInDays: this.calculateDateDifference(bankTx.date, bookTx.date),
      descriptionSimilarity: this.calculateStringSimilarity(bankTx.description, bookTx.description)
    }

    let totalScore = 0
    let applicableRuleCount = 0

    for (const rule of rules) {
      const ruleScore = this.evaluateRuleMatch(bankTx, bookTx, rule, matchCriteria, differences)
      if (ruleScore > 0) {
        totalScore += ruleScore
        applicableRuleCount++
      }
    }

    if (applicableRuleCount === 0) {
      return null
    }

    const averageScore = totalScore / applicableRuleCount
    const confidence = this.determineConfidence(averageScore, matchCriteria)

    // Use ML service for additional scoring if available
    if (this.mlService) {
      const mlScore = await this.mlService.predictMatch(bankTx, bookTx)
      // Blend traditional and ML scores
      const blendedScore = (averageScore * 0.7) + (mlScore * 0.3)
    }

    const match: TransactionMatch = {
      id: this.generateMatchId(),
      sessionId: '', // Will be set by caller
      bankTransactionId: bankTx.id,
      bookTransactionId: bookTx.id,
      confidence,
      score: Math.round(averageScore),
      matchCriteria,
      differences,
      reviewRequired: this.requiresReview(averageScore, confidence, differences)
    }

    return match
  }

  private evaluateRuleMatch(
    bankTx: BankTransaction,
    bookTx: BookTransaction,
    rule: MatchingRules,
    matchCriteria: TransactionMatch['matchCriteria'],
    differences: TransactionMatch['differences']
  ): number {
    let score = 0
    const { conditions } = rule

    // Amount matching
    const amountTolerancePercent = Math.abs(differences.amountDifference) / Math.abs(bankTx.amount) * 100
    if (amountTolerancePercent <= conditions.amountTolerance) {
      matchCriteria.amountMatch = true
      score += 40 // High weight for amount matching
    }

    // Date matching
    if (differences.dateDifferenceInDays <= conditions.dateTolerance) {
      matchCriteria.dateMatch = true
      score += 20
    }

    // Description matching
    if (differences.descriptionSimilarity >= 0.8) {
      matchCriteria.descriptionMatch = true
      score += 25
    }

    // Reference matching
    if (this.matchesReferencePattern(bookTx.reference, conditions.referencePatterns)) {
      matchCriteria.referenceMatch = true
      score += 10
    }

    // Merchant matching
    if (bankTx.merchantName && this.matchesMerchantName(bankTx.merchantName, conditions.merchantNames)) {
      matchCriteria.merchantMatch = true
      score += 5
    }

    return score
  }

  private determineConfidence(score: number, matchCriteria: TransactionMatch['matchCriteria']): MatchConfidence {
    if (matchCriteria.amountMatch && matchCriteria.dateMatch && matchCriteria.descriptionMatch) {
      return MatchConfidence.EXACT
    }

    if (score >= 85) {
      return MatchConfidence.HIGH
    } else if (score >= 70) {
      return MatchConfidence.MEDIUM
    } else if (score >= 50) {
      return MatchConfidence.LOW
    } else {
      return MatchConfidence.NO_MATCH
    }
  }

  private requiresReview(score: number,
  confidence: MatchConfidence, differences: TransactionMatch['differences']): boolean {
    if (confidence === MatchConfidence.EXACT && score >= 95) {
      return false
    }

    if (differences.amountDifference > 0.01) {
      return true
    }

    if (differences.dateDifferenceInDays > 2) {
      return true
    }

    if (score < 80) {
      return true
    }

    return false
  }

  async createManualMatch(
    sessionId: string,
    bankTransactionId: string,
    bookTransactionId: string,
    userId: string,
    notes?: string
  ): Promise<TransactionMatch> {
    try {
      auditLogger.log({
        action: 'manual_match_creation_started',
        sessionId,
        bankTransactionId,
        bookTransactionId,
        userId
      })

      // Validate session and transactions exist
      const session = this.reconciliationSessions.get(sessionId)
      if (!session) {
        throw new AppError('Reconciliation session not found', 'SESSION_NOT_FOUND', 404)
      }

      // Get transactions
      const [bankTx, bookTx] = await Promise.all([
        this.getBankTransaction(bankTransactionId),
        this.getBookTransaction(bookTransactionId)
      ])

      if (!bankTx || !bookTx) {
        throw new AppError('Transaction not found', 'TRANSACTION_NOT_FOUND', 404)
      }

      // Create manual match
      const match: TransactionMatch = {
        id: this.generateMatchId(),
        sessionId,
        bankTransactionId,
        bookTransactionId,
        confidence: MatchConfidence.HIGH,
        score: 100,
        matchCriteria: {
          amountMatch: bankTx.amount === bookTx.amount,
          dateMatch: true,
          descriptionMatch: true,
          referenceMatch: true,
          merchantMatch: true
        },
        differences: {
          amountDifference: Math.abs(bankTx.amount - bookTx.amount),
          dateDifferenceInDays: this.calculateDateDifference(bankTx.date, bookTx.date),
          descriptionSimilarity: 1.0
        },
        reviewRequired: false,
        reviewedBy: userId,
        reviewedAt: new Date().toISOString(),
        metadata: { notes, createdManually: true }
      }

      this.transactionMatches.set(match.id, match)

      // Auto-approve manual matches
      await this.approveMatch(match.id, userId)

      auditLogger.log({
        action: 'manual_match_created',
        matchId: match.id,
        sessionId,
        userId
      })

      return match

    } catch (error: any) {
      auditLogger.log({
        action: 'manual_match_creation_failed',
        sessionId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      throw new AppError(
        'Failed to create manual match',
        'MANUAL_MATCH_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  async approveMatch(matchId: string, userId: string): Promise<TransactionMatch> {
    const match = this.transactionMatches.get(matchId)
    if (!match) {
      throw new AppError('Match not found', 'MATCH_NOT_FOUND', 404)
    }

    match.approvedBy = userId
    match.approvedAt = new Date().toISOString()

    // Update book transaction status
    await this.updateBookTransactionStatus(
      match.bookTransactionId,
      ReconciliationStatus.MATCHED,
      match.bankTransactionId
    )

    auditLogger.log({
      action: 'match_approved',
      matchId,
      userId,
      confidence: match.confidence,
      score: match.score
    })

    return match
  }

  async rejectMatch(matchId: string, userId: string, reason: string): Promise<void> {
    const match = this.transactionMatches.get(matchId)
    if (!match) {
      throw new AppError('Match not found', 'MATCH_NOT_FOUND', 404)
    }

    match.rejectedReason = reason
    match.reviewedBy = userId
    match.reviewedAt = new Date().toISOString()

    // Remove the match
    this.transactionMatches.delete(matchId)

    auditLogger.log({
      action: 'match_rejected',
      matchId,
      userId,
      reason
    })
  }

  async completeReconciliation(sessionId: string, userId: string): Promise<ReconciliationSession> {
    try {
      const session = this.reconciliationSessions.get(sessionId)
      if (!session) {
        throw new AppError('Reconciliation session not found', 'SESSION_NOT_FOUND', 404)
      }

      // Validate all matches are reviewed
      const sessionMatches = Array.from(this.transactionMatches.values())
        .filter((m: any) => m.sessionId === sessionId)

      const pendingReviews = sessionMatches.filter((m: any) => m.reviewRequired && !m.reviewedAt)
      if (pendingReviews.length > 0) {
        throw new AppError(
          `${pendingReviews.length} matches require review before completion`,
          'PENDING_REVIEWS',
          400
        )
      }

      // Update session status
      session.status = 'completed'
      session.completedAt = new Date().toISOString()

      // Update account last reconciled date
      await this.updateAccountReconciliationDate(session.accountId, session.periodEnd)

      auditLogger.log({
        action: 'reconciliation_completed',
        sessionId,
        userId,
        matchedTransactions: session.summary.matchedTransactions,
        balanceDifference: session.summary.balanceDifference
      })

      return session

    } catch (error: any) {
      auditLogger.log({
        action: 'reconciliation_completion_failed',
        sessionId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      throw new AppError(
        'Failed to complete reconciliation',
        'RECONCILIATION_COMPLETION_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  // Utility methods
  private validateReconciliationPeriod(startDate: string, endDate: string): void {
    const start = new Date(startDate)
    const end = new Date(endDate)

    if (start >= end) {
      throw new AppError('End date must be after start date', 'INVALID_DATE_RANGE', 400)
    }

    const daysDiff = (end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24)
    if (daysDiff > 90) {
      throw new AppError('Reconciliation period cannot exceed 90 days', 'PERIOD_TOO_LONG', 400)
    }
  }

  private calculateDateDifference(date1: string, date2: string): number {
    const d1 = new Date(date1)
    const d2 = new Date(date2)
    return Math.abs((d1.getTime() - d2.getTime()) / (1000 * 60 * 60 * 24))
  }

  private calculateStringSimilarity(str1: string, str2: string): number {
    // SUPERNOVA Optimized: O(n) string similarity using optimized algorithms
    const { OptimizedStringSimilarity } = await import('../../performance/supernova-optimizations');
    return OptimizedStringSimilarity.calculateSimilarity(str1, str2);
  }

  private levenshteinDistance(str1: string, str2: string): number {
    // SUPERNOVA Optimized: Space-efficient Levenshtein distance calculation
    const longer = str1.length > str2.length ? str1 : str2;
    const shorter = str1.length > str2.length ? str2 : str1;

    if (longer.length === 0) return 0;
    if (shorter.length === 0) return longer.length;

    // Use only two rows instead of full matrix (space optimization)
    let previousRow = Array(shorter.length + 1).fill(0);
    let currentRow = Array(shorter.length + 1).fill(0);

    for (let i = 0; i <= shorter.length; i++) {
      previousRow[i] = i;
    }

    for (let i = 1; i <= longer.length; i++) {
      currentRow[0] = i;
      for (let j = 1; j <= shorter.length; j++) {
        const cost = longer[i - 1] === shorter[j - 1] ? 0 : 1;
        currentRow[j] = Math.min(
          currentRow[j - 1] + 1,
          previousRow[j] + 1,
          previousRow[j - 1] + cost
        );
      }
      [previousRow, currentRow] = [currentRow, previousRow];
    }

    return previousRow[shorter.length];
  }

  private matchesReferencePattern(reference: string, patterns: string[]): boolean {
    return patterns.some(pattern => {
      const regex = new RegExp(pattern, 'i')
      return regex.test(reference)
    })
  }

  private matchesMerchantName(merchantName: string, names: string[]): boolean {
    const normalizedMerchant = merchantName.toLowerCase()
    return names.some(name => normalizedMerchant.includes(name.toLowerCase()))
  }

  private calculateBalanceDifference(session: ReconciliationSession, matches: TransactionMatch[]): number {
    // Calculate expected balance based on starting balance and matched transactions
    let expectedBalance = session.startingBalance

    // Add/subtract matched transactions
    for (const match of matches) {
      // This would need to get the actual transaction amounts
      // For now, return the difference between statement and book balance
    }

    return session.bankStatementBalance - session.endingBalance
  }

  private generateSessionId(): string {
    return `recon_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  private generateMatchId(): string {
    return `match_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  private initializeDefaultRules(): void {
    const defaultRules: MatchingRules[] = [
      {
        id: 'exact-amount-date',
        name: 'Exact Amount and Date Match',
        priority: 100,
        isActive: true,
        conditions: {
          amountTolerance: 0,
          dateTolerance: 0,
          descriptionKeywords: [],
          merchantNames: [],
          referencePatterns: [],
          minConfidenceScore: 95
        },
        autoApprove: true,
        autoApprovalThreshold: 95
      },
      {
        id: 'close-amount-date',
        name: 'Close Amount and Date Match',
        priority: 90,
        isActive: true,
        conditions: {
          amountTolerance: 1, // 1% tolerance
          dateTolerance: 1, // 1 day tolerance
          descriptionKeywords: [],
          merchantNames: [],
          referencePatterns: [],
          minConfidenceScore: 80
        },
        autoApprove: false,
        autoApprovalThreshold: 90
      },
      {
        id: 'payment-references',
        name: 'Payment Reference Matching',
        priority: 80,
        isActive: true,
        conditions: {
          amountTolerance: 5,
          dateTolerance: 3,
          descriptionKeywords: ['payment', 'invoice', 'bill'],
          merchantNames: [],
          referencePatterns: ['^INV-\\d+$', '^PAY-\\d+$'],
          minConfidenceScore: 70
        },
        autoApprove: false,
        autoApprovalThreshold: 85
      }
    ]

    for (const rule of defaultRules) {
      this.matchingRules.set(rule.id, rule)
    }
  }

  // Placeholder methods for database operations
  private async getBankAccount(accountId: string): Promise<BankAccount | null> {
    // Database query implementation
    return null
  }

  private async getBankTransactions(accountId: string, startDate: string, endDate: string): Promise<BankTransaction[]> {
    // Database query implementation
    return []
  }

  private async getBookTransactions(accountId: string, startDate: string, endDate: string): Promise<BookTransaction[]> {
    // Database query implementation
    return []
  }

  private async getBankTransaction(transactionId: string): Promise<BankTransaction | null> {
    // Database query implementation
    return null
  }

  private async getBookTransaction(transactionId: string): Promise<BookTransaction | null> {
    // Database query implementation
    return null
  }

  private async getAccountBalanceAtDate(accountId: string, date: string): Promise<number> {
    // Database query implementation
    return 0
  }

  private async updateBookTransactionStatus(
    transactionId: string,
    status: ReconciliationStatus,
    matchedBankTransactionId?: string
  ): Promise<void> {
    // Database update implementation
  }

  private async updateAccountReconciliationDate(accountId: string, date: string): Promise<void> {
    // Database update implementation
  }

  // Public API methods
  async getReconciliationSessions(filters?: {
    accountId?: string
    status?: string
    startDate?: string
    endDate?: string
  }): Promise<ReconciliationSession[]> {
    let sessions = Array.from(this.reconciliationSessions.values())

    if (filters) {
      if (filters.accountId) {
        sessions = sessions.filter((s: any) => s.accountId === filters.accountId)
      }
      if (filters.status) {
        sessions = sessions.filter((s: any) => s.status === filters.status)
      }
      if (filters.startDate) {
        sessions = sessions.filter((s: any) => s.createdAt >= filters.startDate!)
      }
      if (filters.endDate) {
        sessions = sessions.filter((s: any) => s.createdAt <= filters.endDate!)
      }
    }

    return sessions.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
  }

  async getSessionMatches(sessionId: string): Promise<TransactionMatch[]> {
    return Array.from(this.transactionMatches.values())
      .filter((m: any) => m.sessionId === sessionId)
      .sort((a, b) => b.score - a.score)
  }

  async getUnmatchedTransactions(sessionId: string): Promise<{
    bankTransactions: BankTransaction[]
    bookTransactions: BookTransaction[]
  }> {
    const session = this.reconciliationSessions.get(sessionId)
    if (!session) {
      throw new AppError('Session not found', 'SESSION_NOT_FOUND', 404)
    }

    const sessionMatches = await this.getSessionMatches(sessionId)
    const matchedBankIds = new Set(sessionMatches.map((m: any) => m.bankTransactionId))
    const matchedBookIds = new Set(sessionMatches.map((m: any) => m.bookTransactionId))

    const [allBankTx, allBookTx] = await Promise.all([
      this.getBankTransactions(session.accountId, session.periodStart, session.periodEnd),
      this.getBookTransactions(session.accountId, session.periodStart, session.periodEnd)
    ])

    return {
      bankTransactions: allBankTx.filter((tx: any) => !matchedBankIds.has(tx.id)),
      bookTransactions: allBookTx.filter((tx: any) => !matchedBookIds.has(tx.id))
    }
  }

  async createMatchingRule(rule: Omit<MatchingRules, 'id'>): Promise<MatchingRules> {
    const newRule: MatchingRules = {
      id: `rule_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      ...rule
    }

    this.matchingRules.set(newRule.id, newRule)

    auditLogger.log({
      action: 'matching_rule_created',
      ruleId: newRule.id,
      name: newRule.name,
      priority: newRule.priority
    })

    return newRule
  }
}