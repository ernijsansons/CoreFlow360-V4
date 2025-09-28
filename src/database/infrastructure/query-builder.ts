/**
 * Query Builder - Single Responsibility Principle Compliant
 * Focused solely on building SQL queries in a fluent, safe manner
 */

import { IQueryBuilder } from '../repositories/interfaces';
import { Logger } from '../../shared/logger';

export class QueryBuilder implements IQueryBuilder {
  private query: string = '';
  private params: any[] = [];
  private selectFields: string[] = [];
  private fromTable: string = '';
  private joinClauses: string[] = [];
  private whereClauses: string[] = [];
  private orderByClause: string = '';
  private limitCount?: number;
  private offsetCount?: number;
  private logger: Logger;

  constructor() {
    this.logger = new Logger();
  }

  select(fields: string[]): IQueryBuilder {
    // Validate and sanitize field names
    const sanitizedFields = fields.map(field => this.sanitizeFieldName(field));
    this.selectFields = sanitizedFields;
    return this;
  }

  from(table: string): IQueryBuilder {
    this.fromTable = this.sanitizeTableName(table);
    return this;
  }

  join(joinClause: string): IQueryBuilder {
    // Validate join clause for basic SQL injection protection
    if (this.isValidJoinClause(joinClause)) {
      this.joinClauses.push(joinClause);
    } else {
      this.logger.warn('Invalid join clause rejected', { joinClause });
    }
    return this;
  }

  where(condition: string, value?: any): IQueryBuilder {
    // Validate condition for basic safety
    if (this.isValidWhereCondition(condition)) {
      this.whereClauses.push(condition);
      if (value !== undefined) {
        this.params.push(value);
      }
    } else {
      this.logger.warn('Invalid where condition rejected', { condition });
    }
    return this;
  }

  orderBy(field: string, direction: 'ASC' | 'DESC' = 'ASC'): IQueryBuilder {
    const sanitizedField = this.sanitizeFieldName(field);
    const validDirection = direction === 'DESC' ? 'DESC' : 'ASC';
    this.orderByClause = `ORDER BY ${sanitizedField} ${validDirection}`;
    return this;
  }

  limit(count: number): IQueryBuilder {
    if (count > 0 && count <= 1000) { // Reasonable limit
      this.limitCount = count;
    } else {
      this.logger.warn('Invalid limit value rejected', { count });
    }
    return this;
  }

  offset(count: number): IQueryBuilder {
    if (count >= 0) {
      this.offsetCount = count;
    } else {
      this.logger.warn('Invalid offset value rejected', { count });
    }
    return this;
  }

  build(): { query: string; params: any[] } {
    try {
      this.query = this.buildSelectQuery();
      return {
        query: this.query,
        params: [...this.params] // Return copy to prevent mutation
      };
    } catch (error: any) {
      this.logger.error('Failed to build query', error);
      throw new Error(`Query build failed: ${error.message}`);
    }
  }

  reset(): IQueryBuilder {
    this.query = '';
    this.params = [];
    this.selectFields = [];
    this.fromTable = '';
    this.joinClauses = [];
    this.whereClauses = [];
    this.orderByClause = '';
    this.limitCount = undefined;
    this.offsetCount = undefined;
    return this;
  }

  // Specialized query builders for common patterns
  insertInto(table: string, data: Record<string, any>): { query: string; params: any[] } {
    const sanitizedTable = this.sanitizeTableName(table);
    const fields = Object.keys(data);
    const sanitizedFields = fields.map(field => this.sanitizeFieldName(field));
    const placeholders = fields.map(() => '?').join(', ');
    const values = Object.values(data);

    return {
      query: `INSERT INTO ${sanitizedTable} (${sanitizedFields.join(', ')}) VALUES (${placeholders})`,
      params: values
    };
  }

  updateTable(table: string, data: Record<string, any>, whereCondition: string, whereValue: any): { query: string; params: any[] } {
    const sanitizedTable = this.sanitizeTableName(table);
    const updates = Object.entries(data)
      .map(([key, _]) => `${this.sanitizeFieldName(key)} = ?`)
      .join(', ');
    const values = Object.values(data);

    return {
      query: `UPDATE ${sanitizedTable} SET ${updates} WHERE ${whereCondition}`,
      params: [...values, whereValue]
    };
  }

  deleteFrom(table: string, whereCondition: string, whereValue: any): { query: string; params: any[] } {
    const sanitizedTable = this.sanitizeTableName(table);

    return {
      query: `DELETE FROM ${sanitizedTable} WHERE ${whereCondition}`,
      params: [whereValue]
    };
  }

  // Analytics and aggregation helpers
  count(table: string, alias: string = 'count'): IQueryBuilder {
    this.selectFields = [`COUNT(*) as ${this.sanitizeFieldName(alias)}`];
    this.fromTable = this.sanitizeTableName(table);
    return this;
  }

  sum(field: string, alias: string = 'sum'): IQueryBuilder {
    const sanitizedField = this.sanitizeFieldName(field);
    const sanitizedAlias = this.sanitizeFieldName(alias);
    this.selectFields.push(`SUM(${sanitizedField}) as ${sanitizedAlias}`);
    return this;
  }

  avg(field: string, alias: string = 'avg'): IQueryBuilder {
    const sanitizedField = this.sanitizeFieldName(field);
    const sanitizedAlias = this.sanitizeFieldName(alias);
    this.selectFields.push(`AVG(${sanitizedField}) as ${sanitizedAlias}`);
    return this;
  }

  groupBy(fields: string[]): IQueryBuilder {
    const sanitizedFields = fields.map(field => this.sanitizeFieldName(field));
    this.query += ` GROUP BY ${sanitizedFields.join(', ')}`;
    return this;
  }

  having(condition: string, value?: any): IQueryBuilder {
    if (this.isValidWhereCondition(condition)) {
      this.query += ` HAVING ${condition}`;
      if (value !== undefined) {
        this.params.push(value);
      }
    }
    return this;
  }

  private buildSelectQuery(): string {
    let query = '';

    // SELECT clause
    if (this.selectFields.length === 0) {
      throw new Error('SELECT fields are required');
    }
    query += `SELECT ${this.selectFields.join(', ')}`;

    // FROM clause
    if (!this.fromTable) {
      throw new Error('FROM table is required');
    }
    query += ` FROM ${this.fromTable}`;

    // JOIN clauses
    if (this.joinClauses.length > 0) {
      query += ` ${this.joinClauses.join(' ')}`;
    }

    // WHERE clauses
    if (this.whereClauses.length > 0) {
      query += ` WHERE ${this.whereClauses.join(' AND ')}`;
    }

    // ORDER BY clause
    if (this.orderByClause) {
      query += ` ${this.orderByClause}`;
    }

    // LIMIT clause
    if (this.limitCount !== undefined) {
      query += ` LIMIT ${this.limitCount}`;
    }

    // OFFSET clause
    if (this.offsetCount !== undefined) {
      query += ` OFFSET ${this.offsetCount}`;
    }

    return query;
  }

  private sanitizeFieldName(field: string): string {
    // Allow alphanumeric, underscores, dots (for table.field), and basic SQL functions
    const allowedPattern = /^[a-zA-Z_][a-zA-Z0-9_.]*(\s+as\s+[a-zA-Z_][a-zA-Z0-9_]*)?$/i;
    const functionPattern = /^(COUNT|SUM|AVG|MAX|MIN|COALESCE)\([^)]+\)(\s+as\s+[a-zA-Z_][a-zA-Z0-9_]*)?$/i;

    if (allowedPattern.test(field) || functionPattern.test(field)) {
      return field;
    }

    this.logger.warn('Field name sanitization failed', { field });
    throw new Error(`Invalid field name: ${field}`);
  }

  private sanitizeTableName(table: string): string {
    // Allow alphanumeric, underscores, and optional alias
    const allowedPattern = /^[a-zA-Z_][a-zA-Z0-9_]*(\s+[a-zA-Z_][a-zA-Z0-9_]*)?$/;

    if (allowedPattern.test(table)) {
      return table;
    }

    this.logger.warn('Table name sanitization failed', { table });
    throw new Error(`Invalid table name: ${table}`);
  }

  private isValidJoinClause(joinClause: string): boolean {
    // Basic validation for JOIN clauses
    const joinPattern = /^(LEFT\s+JOIN|RIGHT\s+JOIN|INNER\s+JOIN|JOIN)\s+[a-zA-Z_][a-zA-Z0-9_]*(\s+[a-zA-Z_][a-zA-Z0-9_]*)?\s+ON\s+.+$/i;
    return joinPattern.test(joinClause);
  }

  private isValidWhereCondition(condition: string): boolean {
    // Basic validation to prevent obvious SQL injection
    const forbiddenPatterns = [
      /;\s*(DROP|DELETE|UPDATE|INSERT|CREATE|ALTER)/i,
      /--/,
      /\/\*/,
      /\*\//,
      /xp_cmdshell/i,
      /sp_executesql/i
    ];

    return !forbiddenPatterns.some(pattern => pattern.test(condition));
  }

  // Helper methods for complex queries
  existsSubquery(subquery: string): string {
    return `EXISTS (${subquery})`;
  }

  notExistsSubquery(subquery: string): string {
    return `NOT EXISTS (${subquery})`;
  }

  inSubquery(field: string, subquery: string): string {
    const sanitizedField = this.sanitizeFieldName(field);
    return `${sanitizedField} IN (${subquery})`;
  }

  notInSubquery(field: string, subquery: string): string {
    const sanitizedField = this.sanitizeFieldName(field);
    return `${sanitizedField} NOT IN (${subquery})`;
  }

  // Utility for building complex WHERE conditions
  or(conditions: string[]): string {
    const validConditions = conditions.filter(condition => this.isValidWhereCondition(condition));
    return `(${validConditions.join(' OR ')})`;
  }

  and(conditions: string[]): string {
    const validConditions = conditions.filter(condition => this.isValidWhereCondition(condition));
    return `(${validConditions.join(' AND ')})`;
  }

  // Date/time helpers
  dateRange(field: string, startDate: string, endDate: string): void {
    const sanitizedField = this.sanitizeFieldName(field);
    this.where(`${sanitizedField} >= ?`, startDate);
    this.where(`${sanitizedField} <= ?`, endDate);
  }

  recentRecords(field: string, days: number): void {
    const sanitizedField = this.sanitizeFieldName(field);
    const cutoffDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
    this.where(`${sanitizedField} >= ?`, cutoffDate);
  }

  // Pagination helpers
  paginate(page: number, limit: number): void {
    const offset = (page - 1) * limit;
    this.limit(limit);
    this.offset(offset);
  }

  // Debug utility
  explain(): string {
    const { query, params } = this.build();
    return `Query: ${query}\nParams: ${JSON.stringify(params)}`;
  }
}