/**
 * Secure Query Builder for Tenant Isolation
 * Replaces string manipulation with safe parameterized queries
 */

import { Logger } from '../shared/logger';
import { SecurityError } from '../shared/security-utils';

export interface QueryContext {
  businessId: string;
  userId?: string;
  tenantId?: string;
}

export interface QueryConstraints {
  maxRows?: number;
  allowCrossReference?: boolean;
  requiredColumns?: string[];
}

export class SecureQueryBuilder {
  private logger: Logger;

  // List of protected tables that require business_id
  private readonly PROTECTED_TABLES = new Set([
    'agent_decisions',
    'agent_patterns',
    'agent_memory',
    'agent_performance',
    'agent_interactions',
    'workflows',
    'customers',
    'transactions',
    'companies',
    'contacts',
    'leads',
    'conversations',
    'ai_tasks',
    'lead_activities',
    'email_sequences',
    'meetings',
    'voicemails'
  ]);

  // Allowed column names (whitelist)
  private readonly ALLOWED_COLUMNS = new Set([
    'id', 'business_id', 'created_at', 'updated_at', 'name', 'email', 'status',
    'type', 'description', 'content', 'data', 'metadata', 'priority', 'stage',
    'first_name', 'last_name', 'title', 'company_id', 'contact_id', 'lead_id',
    'workflow_id', 'agent_id', 'transaction_id', 'phone', 'address', 'notes'
  ]);

  // Safe operators for WHERE clauses
  private readonly SAFE_OPERATORS = new Set([
    '=', '!=', '<>', '<', '>', '<=', '>=', 'LIKE', 'NOT LIKE',
    'IN', 'NOT IN', 'IS NULL', 'IS NOT NULL', 'BETWEEN'
  ]);

  constructor() {
    this.logger = new Logger({ component: 'secure-query-builder' });
  }

  /**
   * Build a secure SELECT query with automatic tenant isolation
   */
  buildSelect(
    table: string,
    columns: string[] = ['*'],
    context: QueryContext,
    constraints: QueryConstraints = {}
  ): { query: string; params: any[] } {
    this.validateTable(table);
    this.validateColumns(columns);

    const params: any[] = [];
    let paramIndex = 1;

    // Build column list
    const columnList = columns.includes('*') ? '*' : columns.join(', ');

    // Start building query
    let query = `SELECT ${columnList} FROM ${table}`;

    // Add WHERE clause for tenant isolation
    const whereConditions: string[] = [];

    if (this.PROTECTED_TABLES.has(table)) {
      whereConditions.push(`business_id = ?`);
      params.push(context.businessId);
    }

    if (whereConditions.length > 0) {
      query += ` WHERE ${whereConditions.join(' AND ')}`;
    }

    // Add row limit for safety
    if (constraints.maxRows) {
      query += ` LIMIT ?`;
      params.push(constraints.maxRows);
    }

    this.logger.debug('Built secure SELECT query', {
      table,
      businessId: context.businessId,
      paramCount: params.length
    });

    return { query, params };
  }

  /**
   * Build a secure INSERT query with automatic business_id injection
   */
  buildInsert(
    table: string,
    data: Record<string, any>,
    context: QueryContext
  ): { query: string; params: any[] } {
    this.validateTable(table);

    const insertData = { ...data };

    // Automatically add business_id for protected tables
    if (this.PROTECTED_TABLES.has(table)) {
      if (insertData.business_id && insertData.business_id !== context.businessId) {
        throw new SecurityError('Cannot insert data for different business', {
          code: 'TENANT_ISOLATION_VIOLATION',
          attemptedBusinessId: insertData.business_id,
          actualBusinessId: context.businessId
        });
      }
      insertData.business_id = context.businessId;
    }

    // Validate column names
    const columns = Object.keys(insertData);
    this.validateColumns(columns);

    // Build query
    const columnList = columns.join(', ');
    const placeholders = columns.map(() => '?').join(', ');
    const params = columns.map((col: any) => insertData[col]);

    const query = `INSERT INTO ${table} (${columnList}) VALUES (${placeholders})`;

    this.logger.debug('Built secure INSERT query', {
      table,
      businessId: context.businessId,
      columnCount: columns.length
    });

    return { query, params };
  }

  /**
   * Build a secure UPDATE query with tenant isolation
   */
  buildUpdate(
    table: string,
    data: Record<string, any>,
    whereConditions: Record<string, any>,
    context: QueryContext
  ): { query: string; params: any[] } {
    this.validateTable(table);

    const updateData = { ...data };

    // Prevent business_id modification
    if ('business_id' in updateData) {
      if (updateData.business_id !== context.businessId) {
        throw new SecurityError('Cannot change business_id in update', {
          code: 'BUSINESS_ID_MODIFICATION_DENIED'
        });
      }
      delete updateData.business_id; // Remove from update since it's enforced in WHERE
    }

    const columns = Object.keys(updateData);
    this.validateColumns(columns);

    // Build SET clause
    const setClause = columns.map((col: any) => `${col} = ?`).join(', ');
    const params = columns.map((col: any) => updateData[col]);

    // Build WHERE clause
    const whereKeys = Object.keys(whereConditions);
    this.validateColumns(whereKeys);

    const whereClauseParts: string[] = [];

    // Always include business_id for protected tables
    if (this.PROTECTED_TABLES.has(table)) {
      whereClauseParts.push('business_id = ?');
      params.push(context.businessId);
    }

    // Add additional WHERE conditions
    whereKeys.forEach((key: any) => {
      whereClauseParts.push(`${key} = ?`);
      params.push(whereConditions[key]);
    });

    const query = `UPDATE ${table} SET ${setClause} WHERE ${whereClauseParts.join(' AND ')}`;

    this.logger.debug('Built secure UPDATE query', {
      table,
      businessId: context.businessId,
      updateColumns: columns.length,
      whereConditions: whereKeys.length
    });

    return { query, params };
  }

  /**
   * Build a secure DELETE query with tenant isolation
   */
  buildDelete(
    table: string,
    whereConditions: Record<string, any>,
    context: QueryContext
  ): { query: string; params: any[] } {
    this.validateTable(table);

    const whereKeys = Object.keys(whereConditions);
    this.validateColumns(whereKeys);

    const params: any[] = [];
    const whereClauseParts: string[] = [];

    // Always include business_id for protected tables
    if (this.PROTECTED_TABLES.has(table)) {
      whereClauseParts.push('business_id = ?');
      params.push(context.businessId);
    }

    // Add WHERE conditions
    whereKeys.forEach((key: any) => {
      whereClauseParts.push(`${key} = ?`);
      params.push(whereConditions[key]);
    });

    if (whereClauseParts.length === 0) {
      throw new SecurityError('DELETE queries must have WHERE conditions', {
        code: 'DELETE_WITHOUT_WHERE_DENIED'
      });
    }

    const query = `DELETE FROM ${table} WHERE ${whereClauseParts.join(' AND ')}`;

    this.logger.debug('Built secure DELETE query', {
      table,
      businessId: context.businessId,
      whereConditions: whereKeys.length
    });

    return { query, params };
  }

  /**
   * Build a secure query with complex WHERE conditions
   */
  buildComplexSelect(
    table: string,
    columns: string[],
    whereBuilder: WhereBuilder,
    context: QueryContext,
    options: {
      orderBy?: string;
      limit?: number;
      offset?: number;
    } = {}
  ): { query: string; params: any[] } {
    this.validateTable(table);
    this.validateColumns(columns);

    const params: any[] = [];
    const columnList = columns.includes('*') ? '*' : columns.join(', ');

    let query = `SELECT ${columnList} FROM ${table}`;

    // Build WHERE clause
    const whereResult = whereBuilder.build();
    const whereConditions: string[] = [];

    // Always include business_id for protected tables
    if (this.PROTECTED_TABLES.has(table)) {
      whereConditions.push('business_id = ?');
      params.push(context.businessId);
    }

    // Add complex WHERE conditions
    if (whereResult.condition) {
      whereConditions.push(whereResult.condition);
      params.push(...whereResult.params);
    }

    if (whereConditions.length > 0) {
      query += ` WHERE ${whereConditions.join(' AND ')}`;
    }

    // Add ORDER BY
    if (options.orderBy) {
      this.validateColumns([options.orderBy.split(' ')[0]]); // Validate column name
      query += ` ORDER BY ${options.orderBy}`;
    }

    // Add LIMIT and OFFSET
    if (options.limit) {
      query += ` LIMIT ?`;
      params.push(options.limit);
    }

    if (options.offset) {
      query += ` OFFSET ?`;
      params.push(options.offset);
    }

    return { query, params };
  }

  /**
   * Validate table name against allowed tables
   */
  private validateTable(table: string): void {
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(table)) {
      throw new SecurityError('Invalid table name format', {
        code: 'INVALID_TABLE_NAME',
        table
      });
    }

    // Additional validation - table should be in our known set
    const allKnownTables = new Set([
      ...this.PROTECTED_TABLES,
      'users', 'sessions', 'audit_logs', 'system_config'
    ]);

    if (!allKnownTables.has(table)) {
      throw new SecurityError('Table not allowed', {
        code: 'UNKNOWN_TABLE',
        table
      });
    }
  }

  /**
   * Validate column names against whitelist
   */
  private validateColumns(columns: string[]): void {
    for (const column of columns) {
      if (column === '*') continue;

      // Remove any alias or function calls for validation
      const baseColumn = column.split(' ')[0].split('.').pop() || column;

      if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(baseColumn)) {
        throw new SecurityError('Invalid column name format', {
          code: 'INVALID_COLUMN_NAME',
          column: baseColumn
        });
      }

      if (!this.ALLOWED_COLUMNS.has(baseColumn)) {
        throw new SecurityError('Column not allowed', {
          code: 'UNKNOWN_COLUMN',
          column: baseColumn
        });
      }
    }
  }
}

/**
 * Builder for complex WHERE conditions
 */
export class WhereBuilder {
  private conditions: string[] = [];
  private params: any[] = [];

  equals(column: string, value: any): WhereBuilder {
    this.validateColumn(column);
    this.conditions.push(`${column} = ?`);
    this.params.push(value);
    return this;
  }

  notEquals(column: string, value: any): WhereBuilder {
    this.validateColumn(column);
    this.conditions.push(`${column} != ?`);
    this.params.push(value);
    return this;
  }

  like(column: string, pattern: string): WhereBuilder {
    this.validateColumn(column);
    this.conditions.push(`${column} LIKE ?`);
    this.params.push(pattern);
    return this;
  }

  in(column: string, values: any[]): WhereBuilder {
    this.validateColumn(column);
    const placeholders = values.map(() => '?').join(', ');
    this.conditions.push(`${column} IN (${placeholders})`);
    this.params.push(...values);
    return this;
  }

  between(column: string, start: any, end: any): WhereBuilder {
    this.validateColumn(column);
    this.conditions.push(`${column} BETWEEN ? AND ?`);
    this.params.push(start, end);
    return this;
  }

  isNull(column: string): WhereBuilder {
    this.validateColumn(column);
    this.conditions.push(`${column} IS NULL`);
    return this;
  }

  isNotNull(column: string): WhereBuilder {
    this.validateColumn(column);
    this.conditions.push(`${column} IS NOT NULL`);
    return this;
  }

  and(): WhereBuilder {
    // AND is implicit in our builder
    return this;
  }

  or(): WhereBuilder {
    // For OR conditions, we need to group previous conditions
    if (this.conditions.length > 0) {
      const lastCondition = this.conditions.pop()!;
      const groupedConditions = this.conditions.join(' AND ');
      this.conditions = [`(${groupedConditions}) OR ${lastCondition}`];
    }
    return this;
  }

  build(): { condition: string; params: any[] } {
    return {
      condition: this.conditions.join(' AND '),
      params: this.params
    };
  }

  private validateColumn(column: string): void {
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(column)) {
      throw new SecurityError('Invalid column name format', {
        code: 'INVALID_COLUMN_NAME',
        column
      });
    }
  }
}

/**
 * Tenant-scoped database client using secure query builder
 */
export class SecureTenantDatabase {
  private queryBuilder: SecureQueryBuilder;
  private context: QueryContext;

  constructor(
    private db: any,
    context: QueryContext
  ) {
    this.queryBuilder = new SecureQueryBuilder();
    this.context = context;
  }

  /**
   * Execute a secure SELECT query
   */
  async select(
    table: string,
    columns: string[] = ['*'],
    constraints: QueryConstraints = {}
  ): Promise<any> {
    const { query, params } = this.queryBuilder.buildSelect(
      table,
      columns,
      this.context,
      constraints
    );

    return this.db.prepare(query).bind(...params).all();
  }

  /**
   * Execute a secure INSERT query
   */
  async insert(table: string, data: Record<string, any>): Promise<any> {
    const { query, params } = this.queryBuilder.buildInsert(
      table,
      data,
      this.context
    );

    return this.db.prepare(query).bind(...params).run();
  }

  /**
   * Execute a secure UPDATE query
   */
  async update(
    table: string,
    data: Record<string, any>,
    whereConditions: Record<string, any>
  ): Promise<any> {
    const { query, params } = this.queryBuilder.buildUpdate(
      table,
      data,
      whereConditions,
      this.context
    );

    return this.db.prepare(query).bind(...params).run();
  }

  /**
   * Execute a secure DELETE query
   */
  async delete(
    table: string,
    whereConditions: Record<string, any>
  ): Promise<any> {
    const { query, params } = this.queryBuilder.buildDelete(
      table,
      whereConditions,
      this.context
    );

    return this.db.prepare(query).bind(...params).run();
  }

  /**
   * Execute a complex SELECT with WHERE builder
   */
  async selectWhere(
    table: string,
    columns: string[],
    whereBuilder: WhereBuilder,
    options?: {
      orderBy?: string;
      limit?: number;
      offset?: number;
    }
  ): Promise<any> {
    const { query, params } = this.queryBuilder.buildComplexSelect(
      table,
      columns,
      whereBuilder,
      this.context,
      options
    );

    return this.db.prepare(query).bind(...params).all();
  }

  /**
   * Get a single record by ID
   */
  async findById(table: string, id: string): Promise<any> {
    const { query, params } = this.queryBuilder.buildSelect(
      table,
      ['*'],
      this.context,
      { maxRows: 1 }
    );

    const modifiedQuery = query.includes('WHERE')
      ? query.replace('WHERE', 'WHERE id = ? AND')
      : query + ' WHERE id = ?';

    return this.db.prepare(modifiedQuery).bind(id, ...params).first();
  }

  /**
   * Create a WHERE builder for complex queries
   */
  where(): WhereBuilder {
    return new WhereBuilder();
  }
}

// Export singleton instance
export const secureQueryBuilder = new SecureQueryBuilder();