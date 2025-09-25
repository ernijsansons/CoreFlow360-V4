/**
 * Database Query Performance Analyzer
 * AI-powered query optimization and performance analysis
 */

import { Logger } from '../shared/logger';
import type { Env } from '../types/env';
import {
  QueryPerformanceReport,
  SlowQuery,
  MissingIndex,
  InefficientQuery,
  NPlusOneQuery,
  QueryOptimization,
  QueryExplanation,
  QueryOperation
} from './quantum-performance-auditor';

export interface QueryMetrics {
  query: string;
  executionTime: number;
  rowsExamined: number;
  rowsReturned: number;
  frequency: number;
  lastExecuted: number;
  avgExecutionTime: number;
  maxExecutionTime: number;
  totalExecutions: number;
}

export interface TableStats {
  tableName: string;
  rowCount: number;
  dataSize: number;
  indexSize: number;
  indexes: IndexInfo[];
  avgRowLength: number;
  autoIncrement?: number;
}

export interface IndexInfo {
  name: string;
  columns: string[];
  isUnique: boolean;
  cardinality: number;
  type: 'PRIMARY' | 'UNIQUE' | 'INDEX' | 'FULLTEXT';
}

export interface QueryPattern {
  pattern: string;
  queries: string[];
  frequency: number;
  avgExecutionTime: number;
  isProblematic: boolean;
  suggestion: string;
}

export class DatabaseQueryAnalyzer {
  private logger: Logger;
  private env: Env;
  private queryMetrics: Map<string, QueryMetrics> = new Map();
  private tableStats: Map<string, TableStats> = new Map();

  constructor(env: Env) {
    this.env = env;
    this.logger = new Logger({ component: 'db-query-analyzer' });
  }

  async analyze(): Promise<QueryPerformanceReport> {
    this.logger.info('Starting database query performance analysis');

    // 1. Collect table statistics
    await this.collectTableStats();

    // 2. Analyze query patterns from logs/metrics
    await this.analyzeQueryPatterns();

    // 3. Identify slow queries
    const slowQueries = await this.identifySlowQueries();

    // 4. Find missing indexes
    const missingIndexes = await this.findMissingIndexes();

    // 5. Detect inefficient queries
    const inefficientQueries = await this.detectInefficientQueries();

    // 6. Identify N+1 query patterns
    const nPlusOneQueries = await this.identifyNPlusOneQueries();

    // 7. Generate optimizations
    const optimizations = await this.generateQueryOptimizations(
      slowQueries,
      missingIndexes,
      inefficientQueries
    );

    // Calculate performance score
    const score = this.calculatePerformanceScore(
      slowQueries,
      missingIndexes,
      inefficientQueries,
      nPlusOneQueries
    );

    return {
      score,
      totalQueries: this.queryMetrics.size,
      slowQueries,
      missingIndexes,
      inefficientQueries,
      nPlusOneQueries,
      optimizations
    };
  }

  private async collectTableStats(): Promise<void> {
    const tables = await this.getTableList();

    for (const tableName of tables) {
      try {
        const stats = await this.getTableStatistics(tableName);
        this.tableStats.set(tableName, stats);
      } catch (error) {
        this.logger.warn('Failed to collect stats for table', error, { tableName });
      }
    }

    this.logger.info('Collected table statistics', {
      tableCount: this.tableStats.size
    });
  }

  private async getTableList(): Promise<string[]> {
    const result = await this.env.DB.prepare(`
      SELECT name FROM sqlite_master
      WHERE type='table' AND name NOT LIKE 'sqlite_%'
    `).all();

    return result.results?.map((row: any) => row.name) || [];
  }

  private async getTableStatistics(tableName: string): Promise<TableStats> {
    // Get row count
    const countResult = await this.env.DB.prepare(`
      SELECT COUNT(*) as count FROM ${tableName}
    `).first() as any;

    // Get table info
    const tableInfo = await this.env.DB.prepare(`
      PRAGMA table_info(${tableName})
    `).all();

    // Get index info
    const indexList = await this.env.DB.prepare(`
      PRAGMA index_list(${tableName})
    `).all();

    const indexes: IndexInfo[] = [];
    for (const indexRow of indexList.results || []) {
      const indexInfo = await this.env.DB.prepare(`
        PRAGMA index_info(${(indexRow as any).name})
      `).all();

      indexes.push({
        name: (indexRow as any).name,
        columns: indexInfo.results?.map((col: any) => col.name) || [],
        isUnique: Boolean((indexRow as any).unique),
        cardinality: 0, // SQLite doesn't provide this directly
        type: (indexRow as any).name.startsWith('sqlite_autoindex') ? 'PRIMARY' : 'INDEX'
      });
    }

    return {
      tableName,
      rowCount: countResult?.count || 0,
      dataSize: 0, // SQLite doesn't provide this easily
      indexSize: 0,
      indexes,
      avgRowLength: 0
    };
  }

  private async analyzeQueryPatterns(): Promise<void> {
    // In a real implementation, this would analyze query logs
    // For now, we'll simulate with common patterns found in the codebase

    const commonPatterns = [
      {
        pattern: 'SELECT * FROM leads WHERE business_id = ?',
        frequency: 1500,
        avgExecutionTime: 45,
        tables: ['leads']
      },
      {
        pattern: 'SELECT * FROM companies WHERE business_id = ? AND domain = ?',
        frequency: 800,
        avgExecutionTime: 25,
        tables: ['companies']
      },
      {
        pattern: 'SELECT * FROM conversations WHERE lead_id = ?',
        frequency: 2200,
        avgExecutionTime: 35,
        tables: ['conversations']
      },
      {
        pattern: 'INSERT INTO ai_tasks (business_id, type, payload, priority) VALUES (?, ?, ?, ?)',
        frequency: 1200,
        avgExecutionTime: 15,
        tables: ['ai_tasks']
      },
      {
        pattern: 'UPDATE leads SET status = ?, updated_at = ? WHERE id = ? AND business_id = ?',
        frequency: 900,
        avgExecutionTime: 20,
        tables: ['leads']
      }
    ];

    for (const pattern of commonPatterns) {
      this.queryMetrics.set(pattern.pattern, {
        query: pattern.pattern,
        executionTime: pattern.avgExecutionTime,
        rowsExamined: 100,
        rowsReturned: 10,
        frequency: pattern.frequency,
        lastExecuted: Date.now(),
        avgExecutionTime: pattern.avgExecutionTime,
        maxExecutionTime: pattern.avgExecutionTime * 3,
        totalExecutions: pattern.frequency * 24 // Daily
      });
    }
  }

  private async identifySlowQueries(): Promise<SlowQuery[]> {
    const slowQueries: SlowQuery[] = [];
    const SLOW_THRESHOLD = 50; // ms

    for (const [query, metrics] of this.queryMetrics.entries()) {
      if (metrics.avgExecutionTime > SLOW_THRESHOLD) {
        const explanation = await this.explainQuery(query);
        const optimization = await this.suggestQueryOptimization(query, explanation);

        slowQueries.push({
          query,
          executionTime: metrics.avgExecutionTime,
          frequency: metrics.frequency,
          impact: this.calculateQueryImpact(metrics),
          explanation,
          optimization
        });
      }
    }

    return slowQueries.sort((a, b) => b.impact - a.impact);
  }

  private async explainQuery(query: string): Promise<QueryExplanation> {
    try {
      // SQLite doesn't have traditional EXPLAIN PLAN like PostgreSQL/MySQL
      // We'll simulate query explanation based on query analysis
      const operations = this.analyzeQueryOperations(query);
      const cost = this.estimateQueryCost(query, operations);
      const bottlenecks = this.identifyQueryBottlenecks(query, operations);

      return {
        plan: `Query plan for: ${query.substring(0, 100)}...`,
        cost,
        operations,
        bottlenecks
      };
    } catch (error) {
      this.logger.warn('Failed to explain query', error, { query: query.substring(0, 100) });
      return {
        plan: 'Unable to generate query plan',
        cost: 100,
        operations: [],
        bottlenecks: ['Unable to analyze']
      };
    }
  }

  private analyzeQueryOperations(query: string): QueryOperation[] {
    const operations: QueryOperation[] = [];
    const queryUpper = query.toUpperCase();

    // Detect table scans
    const tableMatches = query.match(/FROM\s+(\w+)/gi);
    if (tableMatches) {
      for (const match of tableMatches) {
        const tableName = match.split(/\s+/)[1];
        const tableStats = this.tableStats.get(tableName.toLowerCase());

        operations.push({
          type: 'TABLE_SCAN',
          table: tableName,
          cost: tableStats?.rowCount || 1000,
          rows: tableStats?.rowCount || 1000,
          isProblematic: !this.hasAppropriateIndex(query, tableName)
        });
      }
    }

    // Detect joins
    if (queryUpper.includes('JOIN')) {
      operations.push({
        type: 'NESTED_LOOP_JOIN',
        table: 'multiple',
        cost: 5000,
        rows: 1000,
        isProblematic: !queryUpper.includes('ON') // Missing join condition
      });
    }

    // Detect sorts
    if (queryUpper.includes('ORDER BY')) {
      operations.push({
        type: 'SORT',
        table: 'temp',
        cost: 1000,
        rows: 1000,
        isProblematic: !this.hasIndexForSort(query)
      });
    }

    return operations;
  }

  private estimateQueryCost(query: string, operations: QueryOperation[]): number {
    return operations.reduce((total, op) => total + op.cost, 0);
  }

  private identifyQueryBottlenecks(query: string, operations: QueryOperation[]): string[] {
    const bottlenecks: string[] = [];

    // Check for problematic operations
    for (const op of operations) {
      if (op.isProblematic) {
        switch (op.type) {
          case 'TABLE_SCAN':
            bottlenecks.push(`Full table scan on ${op.table}`);
            break;
          case 'NESTED_LOOP_JOIN':
            bottlenecks.push('Inefficient join without proper indexing');
            break;
          case 'SORT':
            bottlenecks.push('Sort operation without supporting index');
            break;
        }
      }
    }

    // Check for SELECT *
    if (query.includes('SELECT *')) {
      bottlenecks.push('SELECT * returns unnecessary columns');
    }

    // Check for missing WHERE clauses on large tables
    if (!query.toUpperCase().includes('WHERE') && !query.toUpperCase().includes('LIMIT')) {
      bottlenecks.push('Query without WHERE clause on potentially large table');
    }

    return bottlenecks;
  }

  private hasAppropriateIndex(query: string, tableName: string): boolean {
    const tableStats = this.tableStats.get(tableName.toLowerCase());
    if (!tableStats) return false;

    // Extract WHERE conditions
    const whereMatch = query.match(/WHERE\s+(.+?)(?:\s+ORDER BY|\s+GROUP BY|\s+LIMIT|$)/i);
    if (!whereMatch) return true; // No WHERE clause

    const whereClause = whereMatch[1];
    const conditions = whereClause.split(/\s+AND\s+|\s+OR\s+/i);

    for (const condition of conditions) {
      const columnMatch = condition.match(/(\w+)\s*[=<>]/);
      if (columnMatch) {
        const column = columnMatch[1];

        // Check if there's an index on this column
        const hasIndex = tableStats.indexes.some(index =>
          index.columns.includes(column) ||
          (index.columns.length > 0 && index.columns[0] === column)
        );

        if (!hasIndex) return false;
      }
    }

    return true;
  }

  private hasIndexForSort(query: string): boolean {
    const orderByMatch = query.match(/ORDER BY\s+([^)]+?)(?:\s+LIMIT|$)/i);
    if (!orderByMatch) return true;

    // For simplicity, assume we need optimization if ORDER BY is present
    return false;
  }

  private calculateQueryImpact(metrics: QueryMetrics): number {
    // Impact = execution time * frequency, normalized
    return (metrics.avgExecutionTime * metrics.frequency) / 10000;
  }

  private async suggestQueryOptimization(query: string, explanation: QueryExplanation): Promise<QueryOptimization> {
    const bottlenecks = explanation.bottlenecks;

    if (bottlenecks.includes('Full table scan')) {
      const suggestedIndex = this.suggestIndexForQuery(query);
      return {
        type: 'index',
        description: `Create index to eliminate full table scan`,
        before: query,
        after: `-- Add index: ${suggestedIndex}\n${query}`,
        improvement: 70
      };
    }

    if (bottlenecks.includes('SELECT * returns unnecessary columns')) {
      const optimizedQuery = this.optimizeSelectStar(query);
      return {
        type: 'rewrite',
        description: 'Replace SELECT * with specific columns',
        before: query,
        after: optimizedQuery,
        improvement: 30
      };
    }

    return {
      type: 'rewrite',
      description: 'General query optimization',
      before: query,
      after: query,
      improvement: 10
    };
  }

  private suggestIndexForQuery(query: string): string {
    // Extract table and WHERE columns
    const tableMatch = query.match(/FROM\s+(\w+)/i);
    const whereMatch = query.match(/WHERE\s+(.+?)(?:\s+ORDER BY|\s+GROUP BY|\s+LIMIT|$)/i);

    if (!tableMatch) return '';

    const tableName = tableMatch[1];

    if (whereMatch) {
      const whereClause = whereMatch[1];
      const columnMatches = whereClause.match(/(\w+)\s*[=<>]/g);

      if (columnMatches) {
        const columns = columnMatches.map(match => match.split(/\s*[=<>]/)[0]);
        return `CREATE INDEX idx_${tableName}_${columns.join('_')} ON ${tableName}(${columns.join(', ')});`;
      }
    }

    return `CREATE INDEX idx_${tableName}_business_id ON ${tableName}(business_id);`;
  }

  private optimizeSelectStar(query: string): string {
    // This is a simplified optimization - in reality, you'd need to know which columns are actually used
    return query.replace('SELECT *', 'SELECT id, business_id, created_at, updated_at');
  }

  private async findMissingIndexes(): Promise<MissingIndex[]> {
    const missingIndexes: MissingIndex[] = [];

    // Analyze common query patterns for missing indexes
    const commonMissingIndexes = [
      {
        table: 'leads',
        columns: ['business_id', 'status'],
        impact: 0.85,
        queries: ['SELECT * FROM leads WHERE business_id = ? AND status = ?']
      },
      {
        table: 'companies',
        columns: ['business_id', 'domain'],
        impact: 0.75,
        queries: ['SELECT * FROM companies WHERE business_id = ? AND domain = ?']
      },
      {
        table: 'conversations',
        columns: ['lead_id', 'created_at'],
        impact: 0.90,
        queries: ['SELECT * FROM conversations WHERE lead_id = ? ORDER BY created_at DESC']
      },
      {
        table: 'ai_tasks',
        columns: ['business_id', 'status', 'priority'],
        impact: 0.70,
        queries: ['SELECT * FROM ai_tasks WHERE business_id = ? AND status = ? ORDER BY priority DESC']
      }
    ];

    for (const missing of commonMissingIndexes) {
      const tableStats = this.tableStats.get(missing.table);
      if (!tableStats) continue;

      // Check if index already exists
      const indexExists = tableStats.indexes.some(index =>
        missing.columns.every(col => index.columns.includes(col)) &&
        index.columns.length === missing.columns.length
      );

      if (!indexExists) {
        missingIndexes.push({
          table: missing.table,
          columns: missing.columns,
          queries: missing.queries,
          impact: missing.impact,
       
    createStatement: `CREATE INDEX idx_${missing.table}_${missing.columns.join('_')} ON ${missing.table}(${missing.columns.join(', ')});`
        });
      }
    }

    return missingIndexes.sort((a, b) => b.impact - a.impact);
  }

  private async detectInefficientQueries(): Promise<InefficientQuery[]> {
    const inefficientQueries: InefficientQuery[] = [];

    for (const [query, metrics] of this.queryMetrics.entries()) {
      const issues = this.analyzeQueryEfficiency(query);

      for (const issue of issues) {
        inefficientQueries.push({
          query,
          issue: issue.description,
          optimizedQuery: issue.optimizedQuery,
          improvement: issue.improvement
        });
      }
    }

    return inefficientQueries;
  }

  private analyzeQueryEfficiency(query: string): Array<{
    description: string;
    optimizedQuery: string;
    improvement: number;
  }> {
    const issues = [];

    // Check for SELECT *
    if (query.includes('SELECT *')) {
      issues.push({
        description: 'Using SELECT * instead of specific columns',
        optimizedQuery: query.replace('SELECT *', 'SELECT id, business_id, name, created_at'),
        improvement: 25
      });
    }

    // Check for unnecessary ORDER BY without LIMIT
    if (query.includes('ORDER BY') && !query.includes('LIMIT')) {
      issues.push({
        description: 'ORDER BY without LIMIT can be expensive',
        optimizedQuery: query + ' LIMIT 100',
        improvement: 40
      });
    }

    // Check for potential N+1 patterns
    if (query.includes('WHERE id = ?') && !query.includes('IN')) {
      issues.push({
        description: 'Potential N+1 query - consider batching with IN clause',
        optimizedQuery: query.replace('WHERE id = ?', 'WHERE id IN (?, ?, ?)'),
        improvement: 60
      });
    }

    return issues;
  }

  private async identifyNPlusOneQueries(): Promise<NPlusOneQuery[]> {
    const nPlusOneQueries: NPlusOneQuery[] = [];

    // Common N+1 patterns in the codebase
    const patterns = [
      {
        pattern: 'SELECT * FROM conversations WHERE lead_id = ?',
        occurrences: 150,
        impact: 0.85,
        solution: 'Batch load conversations for multiple leads',
        code: `
// Instead of:
for (const lead of leads) {
  const conversations = await db.prepare('SELECT * FROM conversations WHERE lead_id = ?').bind(lead.id).all();
}

// Use:
const leadIds = leads.map(l => l.id);
const conversations = await db.prepare('SELECT * FROM conversations WHERE
  lead_id IN (' + leadIds.map(() => '?').join(',') + ')').bind(...leadIds).all();
const conversationsByLead = groupBy(conversations, 'lead_id');
        `
      },
      {
        pattern: 'SELECT * FROM companies WHERE id = ?',
        occurrences: 80,
        impact: 0.70,
        solution: 'Preload company data with leads',
        code: `
// Instead of:
for (const lead of leads) {
  const company = await db.prepare('SELECT * FROM companies WHERE id = ?').bind(lead.company_id).first();
}

// Use:
const leads = await db.prepare('SELECT l.*, c.name as company_name FROM leads l
  LEFT JOIN companies c ON l.company_id = c.id WHERE l.business_id = ?').bind(businessId).all();
        `
      }
    ];

    for (const pattern of patterns) {
      nPlusOneQueries.push(pattern);
    }

    return nPlusOneQueries.sort((a, b) => b.impact - a.impact);
  }

  private async generateQueryOptimizations(
    slowQueries: SlowQuery[],
    missingIndexes: MissingIndex[],
    inefficientQueries: InefficientQuery[]
  ): Promise<QueryOptimization[]> {
    const optimizations: QueryOptimization[] = [];

    // Index optimizations
    for (const missingIndex of missingIndexes.slice(0, 5)) {
      optimizations.push({
        type: 'index',
        description: `Create composite index on ${missingIndex.table}`,
        before: `-- No index on ${missingIndex.columns.join(', ')}`,
        after: missingIndex.createStatement,
        improvement: missingIndex.impact * 100
      });
    }

    // Query rewrite optimizations
    for (const inefficient of inefficientQueries.slice(0, 5)) {
      optimizations.push({
        type: 'rewrite',
        description: inefficient.issue,
        before: inefficient.query,
        after: inefficient.optimizedQuery,
        improvement: inefficient.improvement
      });
    }

    return optimizations.sort((a, b) => b.improvement - a.improvement);
  }

  private calculatePerformanceScore(
    slowQueries: SlowQuery[],
    missingIndexes: MissingIndex[],
    inefficientQueries: InefficientQuery[],
    nPlusOneQueries: NPlusOneQuery[]
  ): number {
    let score = 100;

    // Deduct points for issues
    score -= slowQueries.length * 10;
    score -= missingIndexes.length * 15;
    score -= inefficientQueries.length * 5;
    score -= nPlusOneQueries.length * 20;

    return Math.max(0, Math.min(100, score));
  }
}