/**
 * SQL Injection Prevention Guard
 * Multi-layer protection against SQL injection attacks
 */

import { z } from 'zod';
import { Logger } from '../shared/logger';
import { CorrelationId } from '../shared/correlation-id';

export interface QueryContext {
  query: string;
  params?: any[];
  isParameterized: boolean;
  expectedType: 'select' | 'insert' | 'update' | 'delete' | 'other';
  maxLength: number;
  allowedPattern: RegExp;
  businessId: string;
  userId?: string;
}

export interface ValidationResult {
  valid: boolean;
  reason?: string;
  evidence?: any;
  sanitized?: string;
  risk?: 'low' | 'medium' | 'high' | 'critical';
  confidence?: number;
  threats?: string[];
}

interface SemanticAnalysis {
  containsSQLLogic: boolean;
  evidence?: string[];
  suspiciousPatterns: string[];
  riskScore: number;
}

export class SQLInjectionGuard {
  private logger = new Logger();
  private patterns = new Map<string, RegExp>();
  private whitelist = new Set<string>();
  private blacklist = new Set<string>();
  private queryCache = new Map<string, ValidationResult>();

  constructor() {
    this.initializePatterns();
    this.initializeWhitelist();
  }

  /**
   * Initialize SQL injection patterns
   */
  private initializePatterns(): void {
    // Basic SQL keywords
    this.patterns.set('sql_keywords',
      /\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC|EXECUTE|UNION|FROM|WHERE|JOIN|ORDER BY|GROUP BY|HAVING)\b/gi
    );

    // SQL operators
    this.patterns.set('sql_operators',
      /\b(AND|OR|NOT|IN|EXISTS|BETWEEN|LIKE|IS NULL|IS NOT NULL)\b/gi
    );

    // Comment indicators
    this.patterns.set('comments',
      /(--|\#|\/\*|\*\/|\/\/)/g
    );

    // String concatenation
    this.patterns.set('concatenation',
      /(\|\||CONCAT|CHAR|CHR|ASCII|SUBSTRING)/gi
    );

    // Time-based attacks
    this.patterns.set('time_based',
      /\b(SLEEP|WAITFOR|DELAY|BENCHMARK|PG_SLEEP)\b/gi
    );

    // System functions
    this.patterns.set('system_functions',
      /\b(VERSION|DATABASE|USER|SYSTEM_USER|SESSION_USER|CURRENT_USER)\b/gi
    );

    // File operations
    this.patterns.set('file_operations',
      /\b(LOAD_FILE|INTO OUTFILE|INTO DUMPFILE)\b/gi
    );

    // Stacked queries
    this.patterns.set('stacked_queries',
      /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP)/gi
    );

    // Boolean-based blind
    this.patterns.set('boolean_blind',
      /(\b(AND|OR)\b\s*['"\d]+\s*=\s*['"\d]+)/gi
    );

    // Hex encoding
    this.patterns.set('hex_encoding',
      /0x[0-9a-fA-F]+/g
    );

    // Unicode encoding
    this.patterns.set('unicode_encoding',
      /\\u[0-9a-fA-F]{4}/g
    );

    // URL encoding
    this.patterns.set('url_encoding',
      /%[0-9a-fA-F]{2}/g
    );

    // Common injection payloads
    this.patterns.set('common_payloads',
      /('|(--|#)|(\*|\/\*|\*\/)|(\|\||&&)|(\'|\")(\s)*(or|and)(\s)*(\'|\"|=))/gi
    );

    // NoSQL injection patterns
    this.patterns.set('nosql_injection',
      /(\$ne|\$gt|\$lt|\$gte|\$lte|\$regex|\$where|\$exists)/gi
    );

    // LDAP injection patterns
    this.patterns.set('ldap_injection',
      /(\*|\)|\(|\\|&|\|)/g
    );

    // XPath injection patterns
    this.patterns.set('xpath_injection',
      /(\/\/|\.\.\/|@\*|node\(\)|text\(\))/g
    );
  }

  /**
   * Initialize whitelist of safe values
   */
  private initializeWhitelist(): void {
    // Common safe values
    this.whitelist.add('true');
    this.whitelist.add('false');
    this.whitelist.add('null');
    this.whitelist.add('asc');
    this.whitelist.add('desc');

    // Common field names (can be extended)
    this.whitelist.add('id');
    this.whitelist.add('name');
    this.whitelist.add('email');
    this.whitelist.add('created_at');
    this.whitelist.add('updated_at');
  }

  /**
   * Validate input for SQL injection
   */
  async validate(input: string, context: QueryContext): Promise<ValidationResult> {
    const correlationId = CorrelationId.generate();

    this.logger.debug('Validating SQL input', {
      correlationId,
      inputLength: input.length,
      context: {
        type: context.expectedType,
        parameterized: context.isParameterized
      }
    });

    // Check cache
    const cacheKey = `${input}-${JSON.stringify(context)}`;
    if (this.queryCache.has(cacheKey)) {
      return this.queryCache.get(cacheKey)!;
    }

    try {
      // Layer 1: Parameterized query enforcement
      if (!context.isParameterized && context.expectedType !== 'other') {
        return {
          valid: false,
          reason: 'SQL injection risk: Non-parameterized queries are not allowed',
          risk: 'critical',
          confidence: 0.9
        };
      }

      // Layer 2: Whitelist check for simple values
      if (this.whitelist.has(input.toLowerCase())) {
        return { valid: true, risk: 'low', confidence: 0.1 };
      }

      // Layer 3: Blacklist check
      if (this.blacklist.has(input)) {
        return {
          valid: false,
          reason: 'Input is blacklisted',
          evidence: input,
          risk: 'critical'
        };
      }

      // Layer 4: Length validation
      if (input.length > context.maxLength) {
        return {
          valid: false,
          reason: `Input exceeds maximum length of ${context.maxLength}`,
          risk: 'medium'
        };
      }

      // Layer 5: Pattern validation
      if (!context.allowedPattern.test(input)) {
        return {
          valid: false,
          reason: 'Input contains invalid characters',
          evidence: input,
          risk: 'medium'
        };
      }

      // Layer 6: Deep pattern matching
      const patternResult = await this.checkPatterns(input);
      if (!patternResult.valid) {
        return patternResult;
      }

      // Layer 7: Encoding detection
      const encodingResult = await this.checkEncodings(input);
      if (!encodingResult.valid) {
        return encodingResult;
      }

      // Layer 8: Semantic analysis
      const semanticResult = await this.analyzeSemantics(input, context);
      if (semanticResult.containsSQLLogic) {
        return {
          valid: false,
          reason: 'SQL logic detected in input',
          evidence: semanticResult.evidence,
          risk: semanticResult.riskScore > 0.7 ? 'critical' : 'high'
        };
      }

      // Layer 9: Context-specific validation
      const contextResult = await this.validateContext(input, context);
      if (!contextResult.valid) {
        return contextResult;
      }

      // Layer 10: AI-powered analysis
      const aiResult = await this.aiAnalysis(input, context);
      if (!aiResult.valid) {
        return aiResult;
      }

      // Input passed all checks
      const result: ValidationResult = {
        valid: true,
        sanitized: this.sanitize(input),
        risk: 'low'
      };

      // Cache result
      this.queryCache.set(cacheKey, result);

      return result;

    } catch (error) {
      this.logger.error('SQL validation error', error, {
        correlationId
      });

      // Fail closed - reject on error
      return {
        valid: false,
        reason: 'Validation error occurred',
        risk: 'high'
      };
    }
  }

  /**
   * Check for SQL injection patterns
   */
  private async checkPatterns(input: string): Promise<ValidationResult> {
    const detectedPatterns: string[] = [];

    for (const [name, pattern] of this.patterns) {
      if (pattern.test(input)) {
        detectedPatterns.push(name);

        // Critical patterns - immediate rejection
        if (['file_operations', 'stacked_queries', 'time_based'].includes(name)) {
          return {
            valid: false,
            reason: `Critical SQL injection pattern detected: ${name}`,
            evidence: input.match(pattern),
            risk: 'critical'
          };
        }
      }
    }

    // Multiple patterns detected - likely injection
    if (detectedPatterns.length > 2) {
      return {
        valid: false,
        reason: 'Multiple SQL injection patterns detected',
        evidence: detectedPatterns,
        risk: 'high'
      };
    }

    // Check for specific dangerous combinations
    if (detectedPatterns.includes('sql_keywords') &&
        (detectedPatterns.includes('comments') || detectedPatterns.includes('boolean_blind'))) {
      return {
        valid: false,
        reason: 'Dangerous SQL pattern combination detected',
        evidence: detectedPatterns,
        risk: 'high'
      };
    }

    return { valid: true, risk: 'low', confidence: 0.1 };
  }

  /**
   * Check for encoded payloads
   */
  private async checkEncodings(input: string): Promise<ValidationResult> {
    const encodings: string[] = [];

    // Check hex encoding
    if (this.patterns.get('hex_encoding')!.test(input)) {
      const decoded = this.decodeHex(input);
      if (await this.containsSQLPatterns(decoded)) {
        encodings.push('hex');
      }
    }

    // Check URL encoding
    if (this.patterns.get('url_encoding')!.test(input)) {
      const decoded = decodeURIComponent(input);
      if (await this.containsSQLPatterns(decoded)) {
        encodings.push('url');
      }
    }

    // Check Unicode encoding
    if (this.patterns.get('unicode_encoding')!.test(input)) {
      const decoded = this.decodeUnicode(input);
      if (await this.containsSQLPatterns(decoded)) {
        encodings.push('unicode');
      }
    }

    // Check Base64 encoding
    if (this.isBase64(input)) {
      try {
        const decoded = Buffer.from(input, 'base64').toString();
        if (await this.containsSQLPatterns(decoded)) {
          encodings.push('base64');
        }
      } catch {
        // Not valid base64
      }
    }

    if (encodings.length > 0) {
      return {
        valid: false,
        reason: 'Encoded SQL injection payload detected',
        evidence: encodings,
        risk: 'high'
      };
    }

    return { valid: true, risk: 'low', confidence: 0.1 };
  }

  /**
   * Semantic analysis of input
   */
  private async analyzeSemantics(input: string, context: QueryContext): Promise<SemanticAnalysis> {
    const analysis: SemanticAnalysis = {
      containsSQLLogic: false,
      evidence: [],
      suspiciousPatterns: [],
      riskScore: 0
    };

    // Tokenize input
    const tokens = this.tokenize(input);

    // Check for SQL structure
    if (this.hasSQLStructure(tokens)) {
      analysis.containsSQLLogic = true;
      analysis.evidence?.push('SQL-like structure detected');
      analysis.riskScore += 0.3;
    }

    // Check for logical operators in unexpected context
    if (context.expectedType === 'select' && this.hasUnexpectedOperators(tokens)) {
      analysis.suspiciousPatterns.push('Unexpected logical operators');
      analysis.riskScore += 0.2;
    }

    // Check for command chaining
    if (this.hasCommandChaining(tokens)) {
      analysis.containsSQLLogic = true;
      analysis.evidence?.push('Command chaining detected');
      analysis.riskScore += 0.4;
    }

    // Check for data exfiltration attempts
    if (this.hasExfiltrationPatterns(tokens)) {
      analysis.suspiciousPatterns.push('Data exfiltration pattern');
      analysis.riskScore += 0.3;
    }

    // Entropy analysis
    const entropy = this.calculateEntropy(input);
    if (entropy > 4.5) {
      analysis.suspiciousPatterns.push(`High entropy: ${entropy.toFixed(2)}`);
      analysis.riskScore += 0.1;
    }

    analysis.containsSQLLogic = analysis.riskScore > 0.5;

    return analysis;
  }

  /**
   * Context-specific validation
   */
  private async validateContext(input: string, context: QueryContext): Promise<ValidationResult> {
    switch (context.expectedType) {
      case 'select':
        return this.validateSelectContext(input);

      case 'insert':
        return this.validateInsertContext(input);

      case 'update':
        return this.validateUpdateContext(input);

      case 'delete':
        return this.validateDeleteContext(input);

      default:
        return { valid: true, risk: 'low', confidence: 0.1 };
    }
  }

  /**
   * Validate SELECT query context
   */
  private validateSelectContext(input: string): ValidationResult {
    // SELECT queries shouldn't modify data
    const modifyPatterns = /\b(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b/gi;
    if (modifyPatterns.test(input)) {
      return {
        valid: false,
        reason: 'Data modification attempted in SELECT context',
        risk: 'critical'
      };
    }

    return { valid: true, risk: 'low', confidence: 0.1 };
  }

  /**
   * Validate INSERT query context
   */
  private validateInsertContext(input: string): ValidationResult {
    // INSERT values should be simple
    if (input.includes('SELECT') || input.includes('(')) {
      return {
        valid: false,
        reason: 'Complex expression in INSERT context',
        risk: 'high'
      };
    }

    return { valid: true, risk: 'low', confidence: 0.1 };
  }

  /**
   * Validate UPDATE query context
   */
  private validateUpdateContext(input: string): ValidationResult {
    // UPDATE values shouldn't contain subqueries
    if (input.includes('SELECT') || input.includes('FROM')) {
      return {
        valid: false,
        reason: 'Subquery detected in UPDATE context',
        risk: 'high'
      };
    }

    return { valid: true, risk: 'low', confidence: 0.1 };
  }

  /**
   * Validate DELETE query context
   */
  private validateDeleteContext(input: string): ValidationResult {
    // DELETE shouldn't have complex conditions
    const complexPatterns = /\b(OR|UNION|SELECT|JOIN)\b/gi;
    if (complexPatterns.test(input)) {
      return {
        valid: false,
        reason: 'Complex condition in DELETE context',
        risk: 'high'
      };
    }

    return { valid: true, risk: 'low', confidence: 0.1 };
  }

  /**
   * AI-powered analysis
   */
  private async aiAnalysis(input: string, context: QueryContext): Promise<ValidationResult> {
    // This would integrate with an AI model for advanced detection
    // For now, we'll use heuristics

    const features = {
      length: input.length,
      entropy: this.calculateEntropy(input),
      specialChars: (input.match(/[^a-zA-Z0-9\s]/g) || []).length,
      keywords: (input.match(this.patterns.get('sql_keywords')!) || []).length,
      context: context.expectedType
    };

    // Simple heuristic scoring
    let riskScore = 0;

    if (features.entropy > 4) riskScore += 0.2;
    if (features.specialChars > 5) riskScore += 0.2;
    if (features.keywords > 2) riskScore += 0.3;
    if (features.length > 100) riskScore += 0.1;

    if (riskScore > 0.6) {
      return {
        valid: false,
        reason: 'AI analysis detected suspicious pattern',
        evidence: features,
        risk: riskScore > 0.8 ? 'critical' : 'high'
      };
    }

    return { valid: true, risk: 'low', confidence: 0.1 };
  }

  /**
   * Sanitize input
   */
  private sanitize(input: string): string {
    // Basic sanitization - escape special characters
    return input
      .replace(/'/g, "''")  // Escape single quotes
      .replace(/"/g, '""')  // Escape double quotes
      .replace(/\\/g, '\\\\')  // Escape backslashes
      .replace(/\n/g, '\\n')   // Escape newlines
      .replace(/\r/g, '\\r')   // Escape carriage returns
      .replace(/\t/g, '\\t')   // Escape tabs
      .replace(/\x00/g, '')    // Remove null bytes
      .replace(/\x1a/g, '');   // Remove EOF markers
  }

  /**
   * Helper methods
   */
  private containsSQLPatterns(text: string): boolean {
    for (const pattern of this.patterns.values()) {
      if (pattern.test(text)) {
        return true;
      }
    }
    return false;
  }

  private decodeHex(input: string): string {
    return input.replace(/0x([0-9a-fA-F]+)/g, (_, hex) => {
      return String.fromCharCode(parseInt(hex, 16));
    });
  }

  private decodeUnicode(input: string): string {
    return input.replace(/\\u([0-9a-fA-F]{4})/g, (_, code) => {
      return String.fromCharCode(parseInt(code, 16));
    });
  }

  private isBase64(input: string): boolean {
    const base64Regex = /^[A-Za-z0-9+/]+=*$/;
    return base64Regex.test(input) && input.length % 4 === 0;
  }

  private tokenize(input: string): string[] {
    return input.split(/\s+/).filter(t => t.length > 0);
  }

  private hasSQLStructure(tokens: string[]): boolean {
    const sqlStructure = ['SELECT', 'FROM', 'WHERE'];
    let matchCount = 0;

    for (const token of tokens) {
      if (sqlStructure.includes(token.toUpperCase())) {
        matchCount++;
      }
    }

    return matchCount >= 2;
  }

  private hasUnexpectedOperators(tokens: string[]): boolean {
    const operators = ['OR', 'AND', 'NOT'];
    return tokens.some(t => operators.includes(t.toUpperCase()));
  }

  private hasCommandChaining(tokens: string[]): boolean {
    return tokens.some(t => t.includes(';'));
  }

  private hasExfiltrationPatterns(tokens: string[]): boolean {
    const patterns = ['UNION', 'SELECT', '*', 'FROM'];
    let matchCount = 0;

    for (const token of tokens) {
      if (patterns.includes(token.toUpperCase())) {
        matchCount++;
      }
    }

    return matchCount >= 3;
  }

  private calculateEntropy(str: string): number {
    const freq: Record<string, number> = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;

    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  /**
   * Add to blacklist
   */
  addToBlacklist(input: string): void {
    this.blacklist.add(input);
    this.logger.warn('Added to SQL injection blacklist', { input });
  }

  /**
   * Clear cache
   */
  clearCache(): void {
    this.queryCache.clear();
  }
}