import { Logger } from "../../shared/logger";
const logger = new Logger({ component: "services-reconciliation-statement-parser" });

/**
 * Statement Parser Service
 * Parses bank statements in various formats (CSV, OFX, QFX)
 */

interface ParsedTransaction {
  transaction_date: string;
  description: string;
  amount: number;
  reference_number?: string;
  check_number?: string;
}

export class StatementParser {
  /**
   * Parse statement file based on content type
   */
  async parseStatement(
    fileContent: string,
    fileType: string
  ): Promise<ParsedTransaction[]> {
    if (fileType === 'text/csv' || fileType === 'application/vnd.ms-excel') {
      return this.parseCSV(fileContent);
    } else if (fileType === 'application/x-ofx' || fileType === 'application/vnd.intu.qfx') {
      return this.parseOFX(fileContent);
    } else {
      throw new Error(`Unsupported file type: ${fileType}`);
    }
  }

  /**
   * Parse CSV bank statement
   * Supports common formats: Chase, Bank of America, Wells Fargo, etc.
   */
  private parseCSV(content: string): ParsedTransaction[] {
    const lines = content.split('\n').filter(line => line.trim().length > 0);
    if (lines.length === 0) {
      throw new Error('Empty CSV file');
    }

    const transactions: ParsedTransaction[] = [];
    const headers = lines[0].toLowerCase().split(',').map(h => h.trim().replace(/"/g, ''));

    // Detect column indices
    const dateIdx = this.findColumnIndex(headers, ['date', 'transaction date', 'posting date', 'trans date']);
    const descIdx = this.findColumnIndex(headers, ['description', 'desc', 'memo', 'payee']);
    const amountIdx = this.findColumnIndex(headers, ['amount', 'transaction amount', 'debit/credit']);
    const checkIdx = this.findColumnIndex(headers, ['check number', 'check #', 'check', 'chk num']);
    const refIdx = this.findColumnIndex(headers, ['reference', 'ref', 'ref num', 'transaction id']);

    // Alternative amount columns (debit/credit separate)
    const debitIdx = this.findColumnIndex(headers, ['debit', 'withdrawal', 'debit amount']);
    const creditIdx = this.findColumnIndex(headers, ['credit', 'deposit', 'credit amount']);

    if (dateIdx === -1 || descIdx === -1) {
      throw new Error('Required columns not found (date, description)');
    }

    // Parse data rows
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (!line.trim()) continue;

      const values = this.parseCSVLine(line);
      if (values.length < 2) continue;

      try {
        const date = this.parseDate(values[dateIdx]);
        if (!date) continue;

        const description = values[descIdx] || 'Unknown';

        // Parse amount
        let amount = 0;
        if (amountIdx !== -1) {
          amount = this.parseAmount(values[amountIdx]);
        } else if (debitIdx !== -1 && creditIdx !== -1) {
          const debit = this.parseAmount(values[debitIdx] || '0');
          const credit = this.parseAmount(values[creditIdx] || '0');
          amount = credit - debit; // Credits positive, debits negative
        } else {
          logger.warn(`No amount column found for row ${i}`);
          continue;
        }

        const checkNumber = checkIdx !== -1 ? values[checkIdx] : undefined;
        const refNumber = refIdx !== -1 ? values[refIdx] : undefined;

        transactions.push({
          transaction_date: date,
          description: description.trim(),
          amount,
          check_number: checkNumber,
          reference_number: refNumber,
        });
      } catch (error) {
        logger.error(`Error parsing row ${i}:`, error);
        continue;
      }
    }

    return transactions;
  }

  /**
   * Parse OFX/QFX bank statement
   */
  private parseOFX(content: string): ParsedTransaction[] {
    const transactions: ParsedTransaction[] = [];

    // Extract transaction blocks (STMTTRN)
    const txnRegex = /<STMTTRN>([\s\S]*?)<\/STMTTRN>/g;
    let match;

    while ((match = txnRegex.exec(content)) !== null) {
      const txnBlock = match[1];

      try {
        const date = this.extractOFXField(txnBlock, 'DTPOSTED');
        const amount = this.extractOFXField(txnBlock, 'TRNAMT');
        const description = this.extractOFXField(txnBlock, 'NAME') || this.extractOFXField(txnBlock, 'MEMO');
        const refNumber = this.extractOFXField(txnBlock, 'FITID') || this.extractOFXField(txnBlock, 'REFNUM');
        const checkNumber = this.extractOFXField(txnBlock, 'CHECKNUM');

        if (date && amount && description) {
          transactions.push({
            transaction_date: this.parseOFXDate(date),
            description: description.trim(),
            amount: parseFloat(amount),
            reference_number: refNumber,
            check_number: checkNumber,
          });
        }
      } catch (error) {
        logger.error('Error parsing OFX transaction:', error);
        continue;
      }
    }

    return transactions;
  }

  /**
   * Find column index by possible header names
   */
  private findColumnIndex(headers: string[], possibleNames: string[]): number {
    for (const name of possibleNames) {
      const idx = headers.findIndex(h => h.includes(name));
      if (idx !== -1) return idx;
    }
    return -1;
  }

  /**
   * Parse CSV line handling quoted fields
   */
  private parseCSVLine(line: string): string[] {
    const values: string[] = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
      const char = line[i];

      if (char === '"') {
        inQuotes = !inQuotes;
      } else if (char === ',' && !inQuotes) {
        values.push(current.trim());
        current = '';
      } else {
        current += char;
      }
    }

    values.push(current.trim());
    return values;
  }

  /**
   * Parse date from various formats
   */
  private parseDate(dateStr: string): string | null {
    if (!dateStr) return null;

    // Remove quotes
    dateStr = dateStr.replace(/"/g, '').trim();

    // Try various date formats
    const formats = [
      // MM/DD/YYYY
      /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/,
      // MM-DD-YYYY
      /^(\d{1,2})-(\d{1,2})-(\d{4})$/,
      // YYYY-MM-DD (ISO)
      /^(\d{4})-(\d{1,2})-(\d{1,2})$/,
      // MM/DD/YY
      /^(\d{1,2})\/(\d{1,2})\/(\d{2})$/,
    ];

    for (const format of formats) {
      const match = dateStr.match(format);
      if (match) {
        if (match[1].length === 4) {
          // ISO format YYYY-MM-DD
          return `${match[1]}-${match[2].padStart(2, '0')}-${match[3].padStart(2, '0')}`;
        } else {
          // MM/DD/YYYY or MM/DD/YY
          let year = match[3];
          if (year.length === 2) {
            year = parseInt(year) > 50 ? `19${year}` : `20${year}`;
          }
          return `${year}-${match[1].padStart(2, '0')}-${match[2].padStart(2, '0')}`;
        }
      }
    }

    // Try parsing as Date object
    try {
      const date = new Date(dateStr);
      if (!isNaN(date.getTime())) {
        return date.toISOString().split('T')[0];
      }
    } catch {
      // Fall through
    }

    return null;
  }

  /**
   * Parse amount from string
   */
  private parseAmount(amountStr: string): number {
    if (!amountStr) return 0;

    // Remove quotes, currency symbols, commas
    amountStr = amountStr
      .replace(/"/g, '')
      .replace(/\$/g, '')
      .replace(/,/g, '')
      .trim();

    // Handle parentheses for negative numbers
    if (amountStr.startsWith('(') && amountStr.endsWith(')')) {
      amountStr = '-' + amountStr.slice(1, -1);
    }

    const amount = parseFloat(amountStr);
    return isNaN(amount) ? 0 : amount;
  }

  /**
   * Extract OFX field value
   */
  private extractOFXField(block: string, fieldName: string): string | undefined {
    const regex = new RegExp(`<${fieldName}>([^<]+)`);
    const match = block.match(regex);
    return match ? match[1].trim() : undefined;
  }

  /**
   * Parse OFX date format (YYYYMMDDHHMMSS)
   */
  private parseOFXDate(ofxDate: string): string {
    // OFX format: YYYYMMDD or YYYYMMDDHHMMSS
    const year = ofxDate.substring(0, 4);
    const month = ofxDate.substring(4, 6);
    const day = ofxDate.substring(6, 8);

    return `${year}-${month}-${day}`;
  }

  /**
   * Validate parsed transactions
   */
  validateTransactions(transactions: ParsedTransaction[]): {
    valid: ParsedTransaction[];
    errors: string[];
  } {
    const valid: ParsedTransaction[] = [];
    const errors: string[] = [];

    for (let i = 0; i < transactions.length; i++) {
      const txn = transactions[i];
      const rowErrors: string[] = [];

      if (!txn.transaction_date) {
        rowErrors.push('Missing date');
      }

      if (!txn.description || txn.description.trim().length === 0) {
        rowErrors.push('Missing description');
      }

      if (txn.amount === 0) {
        rowErrors.push('Zero amount');
      }

      if (rowErrors.length > 0) {
        errors.push(`Row ${i + 1}: ${rowErrors.join(', ')}`);
      } else {
        valid.push(txn);
      }
    }

    return { valid, errors };
  }
}
