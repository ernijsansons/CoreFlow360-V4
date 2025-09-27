/**
 * Finance Module Utilities
 * Common utility functions for financial operations
 */

import type { D1Database } from '@cloudflare/workers-types';

/**
 * Validate business ID format
 */
export function validateBusinessId(businessId: string): string {
  if (!businessId || typeof businessId !== 'string') {
    throw new Error('Business ID is required');
  }

  const trimmed = businessId.trim();
  if (trimmed.length < 8 || trimmed.length > 50) {
    throw new Error('Business ID must be between 8 and 50 characters');
  }

  // Basic format validation
  if (!/^[a-zA-Z0-9_-]+$/.test(trimmed)) {
    throw new Error('Business ID contains invalid characters');
  }

  return trimmed;
}

/**
 * Validate account code format
 */
export function validateAccountCode(code: string): string {
  if (!code || typeof code !== 'string') {
    throw new Error('Account code is required');
  }

  const trimmed = code.trim();
  if (trimmed.length < 3 || trimmed.length > 20) {
    throw new Error('Account code must be between 3 and 20 characters');
  }

  // Account codes should be alphanumeric
  if (!/^[a-zA-Z0-9-]+$/.test(trimmed)) {
    throw new Error('Account code contains invalid characters');
  }

  return trimmed;
}

/**
 * Generate sequential entry number
 */
export async function generateEntryNumber(
  db: D1Database,
  businessId: string,
  prefix: string = 'JE'
): Promise<string> {
  const year = new Date().getFullYear();

  // Get the current sequence number for this business and year
  const result = await db.prepare(`
    SELECT COALESCE(MAX(CAST(SUBSTR(entry_number, LENGTH(?) + LENGTH(?) + 2) AS INTEGER)), 0) as max_seq
    FROM journal_entries
    WHERE business_id = ?
    AND entry_number LIKE ?
  `).bind(
    prefix,
    year.toString(),
    businessId,
    `${prefix}-${year}-%`
  ).first();

  const nextSeq = ((result?.max_seq as number) || 0) + 1;
  const paddedSeq = nextSeq.toString().padStart(6, '0');

  return `${prefix}-${year}-${paddedSeq}`;
}

/**
 * Round amount to currency precision
 */
export function roundToCurrency(amount: number, decimalPlaces: number = 2): number {
  const factor = Math.pow(10, decimalPlaces);
  return Math.round(amount * factor) / factor;
}

/**
 * Format amount for display
 */
export function formatAmount(
  amount: number,
  currencyCode: string = 'USD',
  locale: string = 'en-US'
): string {
  try {
    return new Intl.NumberFormat(locale, {
      style: 'currency',
      currency: currencyCode
    }).format(amount);
  } catch (error: any) {
    // Fallback formatting
    return `${amount.toFixed(2)} ${currencyCode}`;
  }
}

/**
 * Parse amount from string
 */
export function parseAmount(amountStr: string): number {
  if (typeof amountStr !== 'string') {
    throw new Error('Amount must be a string');
  }

  // Remove currency symbols and formatting
  const cleaned = amountStr
    .replace(/[$€£¥₹]/g, '') // Remove currency symbols
    .replace(/,/g, '') // Remove thousand separators
    .trim();

  const amount = parseFloat(cleaned);

  if (isNaN(amount)) {
    throw new Error('Invalid amount format');
  }

  if (amount < 0) {
    throw new Error('Amount cannot be negative');
  }

  return amount;
}

/**
 * Calculate percentage
 */
export function calculatePercentage(part: number, total: number): number {
  if (total === 0) return 0;
  return (part / total) * 100;
}

/**
 * Calculate variance
 */
export function calculateVariance(actual: number, budget: number): {
  amount: number;
  percentage: number;
  favorable: boolean;
} {
  const amount = actual - budget;
  const percentage = budget !== 0 ? (amount / Math.abs(budget)) * 100 : 0;

  // For expenses, lower actual is favorable
  // For revenue, higher actual is favorable
  const favorable = amount >= 0;

  return { amount, percentage, favorable };
}

/**
 * Get fiscal year for date
 */
export function getFiscalYear(date: number, fiscalYearStart: number = 1): number {
  const d = new Date(date);
  const year = d.getFullYear();
  const month = d.getMonth() + 1; // 1-based month

  if (month >= fiscalYearStart) {
    return year;
  } else {
    return year - 1;
  }
}

/**
 * Get fiscal period for date
 */
export function getFiscalPeriod(
  date: number,
  fiscalYearStart: number = 1,
  periodType: 'monthly' | 'quarterly' = 'monthly'
): number {
  const d = new Date(date);
  let month = d.getMonth() + 1; // 1-based month

  // Adjust for fiscal year start
  month = month - fiscalYearStart + 1;
  if (month <= 0) {
    month += 12;
  }

  if (periodType === 'monthly') {
    return month;
  } else {
    // Quarterly
    return Math.ceil(month / 3);
  }
}

/**
 * Get date range for fiscal period
 */
export function getFiscalPeriodDateRange(
  fiscalYear: number,
  period: number,
  fiscalYearStart: number = 1,
  periodType: 'monthly' | 'quarterly' = 'monthly'
): { startDate: number; endDate: number } {
  let startMonth = fiscalYearStart + period - 1;
  let year = fiscalYear;

  if (startMonth > 12) {
    startMonth -= 12;
    year += 1;
  }

  const startDate = new Date(year, startMonth - 1, 1);

  let endDate: Date;
  if (periodType === 'monthly') {
    endDate = new Date(year, startMonth, 0); // Last day of month
  } else {
    // Quarterly - 3 months
    const endMonth = startMonth + 2;
    if (endMonth > 12) {
      endDate = new Date(year + 1, endMonth - 12, 0);
    } else {
      endDate = new Date(year, endMonth, 0);
    }
  }

  return {
    startDate: startDate.getTime(),
    endDate: endDate.getTime()
  };
}

/**
 * Validate date range
 */
export function validateDateRange(startDate: number, endDate: number): void {
  if (startDate >= endDate) {
    throw new Error('Start date must be before end date');
  }

  // Check if dates are reasonable (within 100 years)
  const now = Date.now();
  const hundredYears = 100 * 365 * 24 * 60 * 60 * 1000;

  if (startDate < now - hundredYears || endDate > now + hundredYears) {
    throw new Error('Date range is outside acceptable bounds');
  }
}

/**
 * Generate account hierarchy path
 */
export function generateAccountPath(
  accountCode: string,
  accountName: string,
  parentPath?: string
): string {
  const current = `${accountCode} - ${accountName}`;
  return parentPath ? `${parentPath} > ${current}` : current;
}

/**
 * Validate journal entry balance
 */
export function validateJournalBalance(
  debits: number,
  credits: number,
  tolerance: number = 0.01
): { balanced: boolean; difference: number } {
  const difference = Math.abs(debits - credits);
  const balanced = difference <= tolerance;

  return { balanced, difference };
}

/**
 * Check if amount is within tolerance
 */
export function isWithinTolerance(
  amount1: number,
  amount2: number,
  tolerance: number = 0.01
): boolean {
  return Math.abs(amount1 - amount2) <= tolerance;
}

/**
 * Format account number with standard padding
 */
export function formatAccountNumber(code: string, padding: number = 4): string {
  // Remove non-numeric characters for sorting
  const numeric = code.replace(/\D/g, '');
  if (numeric) {
    return numeric.padStart(padding, '0');
  }
  return code;
}

/**
 * Calculate compound annual growth rate (CAGR)
 */
export function calculateCAGR(
  beginningValue: number,
  endingValue: number,
  years: number
): number {
  if (beginningValue <= 0 || endingValue <= 0 || years <= 0) {
    return 0;
  }

  return Math.pow(endingValue / beginningValue, 1 / years) - 1;
}

/**
 * Calculate return on investment (ROI)
 */
export function calculateROI(gain: number, cost: number): number {
  if (cost === 0) return 0;
  return (gain / cost) * 100;
}

/**
 * Get business days between dates
 */
export function getBusinessDays(startDate: number, endDate: number): number {
  const start = new Date(startDate);
  const end = new Date(endDate);
  let businessDays = 0;

  const current = new Date(start);
  while (current <= end) {
    const dayOfWeek = current.getDay();
    if (dayOfWeek !== 0 && dayOfWeek !== 6) { // Not Sunday (0) or Saturday (6)
      businessDays++;
    }
    current.setDate(current.getDate() + 1);
  }

  return businessDays;
}

/**
 * Generate fiscal calendar for year
 */
export function generateFiscalCalendar(
  fiscalYear: number,
  fiscalYearStart: number = 1,
  periodType: 'monthly' | 'quarterly' = 'monthly'
): Array<{ period: number; startDate: number; endDate: number; name: string }> {
  const periods: Array<{ period: number; startDate: number; endDate: number; name: string }> = [];
  const periodsPerYear = periodType === 'monthly' ? 12 : 4;

  for (let period = 1; period <= periodsPerYear; period++) {
    const dateRange = getFiscalPeriodDateRange(fiscalYear, period, fiscalYearStart, periodType);
    const startDate = new Date(dateRange.startDate);

    let name: string;
    if (periodType === 'monthly') {
      name = startDate.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
    } else {
      name = `Q${period} ${fiscalYear}`;
    }

    periods.push({
      period,
      startDate: dateRange.startDate,
      endDate: dateRange.endDate,
      name
    });
  }

  return periods;
}

/**
 * Validate currency code (ISO 4217)
 */
export function validateCurrencyCode(code: string): string {
  if (!code || typeof code !== 'string') {
    throw new Error('Currency code is required');
  }

  const trimmed = code.trim().toUpperCase();

  if (trimmed.length !== 3) {
    throw new Error('Currency code must be 3 characters');
  }

  if (!/^[A-Z]{3}$/.test(trimmed)) {
    throw new Error('Currency code must contain only letters');
  }

  return trimmed;
}

/**
 * Safe division to avoid divide by zero
 */
export function safeDivide(numerator: number, denominator: number, defaultValue: number = 0): number {
  return denominator === 0 ? defaultValue : numerator / denominator;
}

/**
 * Convert to base currency amount
 */
export function convertToBase(
  amount: number,
  exchangeRate: number,
  roundTo: number = 2
): number {
  const converted = amount * exchangeRate;
  return roundToCurrency(converted, roundTo);
}

/**
 * Generate unique identifier
 */
export function generateId(prefix: string = ''): string {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 9);
  return prefix ? `${prefix}_${timestamp}_${random}` : `${timestamp}_${random}`;
}

/**
 * Sanitize description for financial records
 */
export function sanitizeDescription(description: string): string {
  if (!description || typeof description !== 'string') {
    return '';
  }

  return description
    .trim()
    .substring(0, 500) // Limit length
    .replace(/[<>]/g, '') // Remove angle brackets
    .replace(/\s+/g, ' '); // Normalize whitespace
}

/**
 * Validate positive amount
 */
export function validatePositiveAmount(amount: number, fieldName: string = 'amount'): number {
  if (typeof amount !== 'number' || isNaN(amount)) {
    throw new Error(`${fieldName} must be a valid number`);
  }

  if (amount < 0) {
    throw new Error(`${fieldName} cannot be negative`);
  }

  if (!isFinite(amount)) {
    throw new Error(`${fieldName} must be finite`);
  }

  return amount;
}

/**
 * Format date for display in reports
 */
export function formatDate(timestamp: number): string {
  if (!timestamp || typeof timestamp !== 'number') {
    return new Date().toLocaleDateString();
  }
  return new Date(timestamp).toLocaleDateString();
}