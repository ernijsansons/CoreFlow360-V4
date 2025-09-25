/**
 * Custom Report Builder
 * Advanced report builder with filters, grouping, and custom data sources
 */

import type { D1Database } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import {
  CustomReportDefinition,
  ReportDataSource,
  ReportColumn,
  ReportFilter,
  ReportSort,
  ReportGrouping,
  ReportAggregation,
  FilterOperator,
  FilterDataType,
  AggregationType,
  ReportParameters,
  FinancialReport,
  ReportStatus
} from './types';
import { validateBusinessId, roundToCurrency } from './utils';

// Type-safe database row type
export type DatabaseRow = Record<string, string | number | boolean | null>;

// Type-safe group value union type
export type GroupValue = string | number | boolean | null;

// Type-safe query parameter type
export type QueryParameter = string | number | boolean | null;

// Type-safe SQL query interface
export interface SqlQuery {
  sql: string;
  params: QueryParameter[];
}

export interface GroupedData {
  groupValue: GroupValue;
  rows: DatabaseRow[];
  subtotals?: Record<string, number>;
}

export interface CustomReportResult {
  columns: ReportColumn[];
  rows: DatabaseRow[];
  totalRows: number;
  aggregations?: Record<string, number>;
  groupedData?: GroupedData[];
}

export class CustomReportBuilder {
  private logger: Logger;
  private db: D1Database;

  constructor(db: D1Database) {
    this.logger = new Logger();
    this.db = db;
  }

  /**
   * Create custom report definition
   */
  async createReportDefinition(
    definition: Omit<CustomReportDefinition, 'id' | 'createdAt' | 'updatedAt'>,
    businessId: string
  ): Promise<CustomReportDefinition> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      const definitionId = `rptdef_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
      const now = Date.now();

      const reportDefinition: CustomReportDefinition = {
        ...definition,
        id: definitionId,
        createdAt: now,
        updatedAt: now,
        businessId: validBusinessId
      };

      await this.saveReportDefinition(reportDefinition);

      this.logger.info('Custom report definition created', {
        definitionId,
        name: definition.name,
        dataSource: definition.dataSource,
        businessId: validBusinessId
      });

      return reportDefinition;

    } catch (error) {
      this.logger.error('Failed to create report definition', error, {
        name: definition.name,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Execute custom report
   */
  async executeCustomReport(
    definitionId: string,
    parameters: ReportParameters,
    businessId: string,
    userId: string
  ): Promise<FinancialReport> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      // Get report definition
      const definition = await this.getReportDefinition(definitionId, validBusinessId);
      if (!definition) {
        throw new Error('Report definition not found');
      }

      this.logger.info('Executing custom report', {
        definitionId,
        name: definition.name,
        dataSource: definition.dataSource,
        businessId: validBusinessId
      });

      // Generate SQL query
      const query = this.buildQuery(definition, parameters, validBusinessId);

      // Execute query
      const result = await this.executeQuery(query);

      // Process results
      const reportData = this.processQueryResults(result, definition);

      // Create financial report
      const reportId = `rpt_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;

      const report: FinancialReport = {
        id: reportId,
        type: 'CUSTOM',
        name: definition.name,
        description: definition.description,
        parameters,
        generatedAt: Date.now(),
        generatedBy: userId,
        status: ReportStatus.COMPLETED,
        data: reportData,
        businessId: validBusinessId
      };

      this.logger.info('Custom report executed successfully', {
        reportId,
        definitionId,
        rowCount: reportData.totalRows,
        businessId: validBusinessId
      });

      return report;

    } catch (error) {
      this.logger.error('Failed to execute custom report', error, {
        definitionId,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Build SQL query from report definition
   */
  private buildQuery(
    definition: CustomReportDefinition,
    parameters: ReportParameters,
    businessId: string
  ): SqlQuery {
    if (!definition.dataSource) {
      throw new Error('Report definition must specify a data source');
    }
    
    const { baseQuery, params } = this.getBaseQuery(definition.dataSource, businessId);

    // Build SELECT clause
    const selectColumns = definition.columns
      .filter(col => col.isVisible)
      .map(col => {
        if (col.aggregationType) {
          return `${this.getAggregationFunction(col.aggregationType)}(${col.field}) as ${col.id}`;
        }
        return `${col.field} as ${col.id}`;
      });

    // Build WHERE clause
    const whereConditions = [];
    const whereParams = [];

    // Add date filters
    if (parameters.startDate && parameters.endDate) {
      whereConditions.push('date BETWEEN ? AND ?');
      whereParams.push(parameters.startDate, parameters.endDate);
    }

    // Add business isolation
    whereConditions.push('business_id = ?');
    whereParams.push(businessId);

    // Add custom filters
    for (const filter of definition.filters) {
      const { condition, filterParams } = this.buildFilterCondition(filter);
      if (condition) {
        whereConditions.push(condition);
        whereParams.push(...filterParams);
      }
    }

    // Add parameter filters
    if (parameters.customFilters) {
      for (const filter of parameters.customFilters) {
        const { condition, filterParams } = this.buildFilterCondition(filter);
        if (condition) {
          whereConditions.push(condition);
          whereParams.push(...filterParams);
        }
      }
    }

    // Build GROUP BY clause
    let groupByClause = '';
    if (definition.grouping && definition.grouping.length > 0) {
      const groupFields = definition.grouping
        .sort((a, b) => a.level - b.level)
        .map(g => g.field);
      groupByClause = `GROUP BY ${groupFields.join(', ')}`;
    }

    // Build ORDER BY clause
    let orderByClause = '';
    if (definition.sorting && definition.sorting.length > 0) {
      const sortFields = definition.sorting
        .sort((a, b) => a.priority - b.priority)
        .map(s => `${s.field} ${s.direction}`);
      orderByClause = `ORDER BY ${sortFields.join(', ')}`;
    }

    // Construct final query
    const sql = `
      SELECT ${selectColumns.join(', ')}
      FROM (${baseQuery}) base
      WHERE ${whereConditions.join(' AND ')}
      ${groupByClause}
      ${orderByClause}
    `.trim();

    return {
      sql,
      params: [...params, ...whereParams]
    };
  }

  /**
   * Get base query for data source
   */
  private getBaseQuery(dataSource: ReportDataSource, businessId: string):
  { baseQuery: string; params: QueryParameter[] } {
    if (!dataSource) {
      throw new Error('Data source is required');
    }
    
    switch (dataSource) {
      case ReportDataSource.CHART_OF_ACCOUNTS:
        return {
          baseQuery: `
            SELECT
              id,
              code,
              name,
              type,
              category,
              parent_id,
              is_active,
              created_at as date,
              business_id
            FROM chart_of_accounts
          `,
          params: []
        };

      case ReportDataSource.JOURNAL_ENTRIES:
        return {
          baseQuery: `
            SELECT
              id,
              entry_number,
              date,
              description,
              reference,
              type,
              status,
              period_id,
              posted_at,
              created_at,
              business_id
            FROM journal_entries
          `,
          params: []
        };

      case ReportDataSource.JOURNAL_LINES:
        return {
          baseQuery: `
            SELECT
              jl.id,
              jl.journal_entry_id,
              jl.account_id,
              jl.account_code,
              jl.account_name,
              jl.debit,
              jl.credit,
              jl.base_debit,
              jl.base_credit,
              jl.currency,
              jl.exchange_rate,
              je.date,
              je.description as entry_description,
              je.status as entry_status,
              je.business_id
            FROM journal_lines jl
            INNER JOIN journal_entries je ON jl.journal_entry_id = je.id
          `,
          params: []
        };

      case ReportDataSource.GENERAL_LEDGER:
        return {
          baseQuery: `
            SELECT
              gl.id,
              gl.account_id,
              gl.period_id,
              gl.opening_balance,
              gl.debits,
              gl.credits,
              gl.closing_balance,
              gl.currency,
              gl.transaction_count,
              gl.last_transaction_date as date,
              coa.code as account_code,
              coa.name as account_name,
              coa.type as account_type,
              gl.business_id
            FROM general_ledger gl
            INNER JOIN chart_of_accounts coa ON gl.account_id = coa.id
          `,
          params: []
        };

      case ReportDataSource.INVOICES:
        return {
          baseQuery: `
            SELECT
              i.id,
              i.invoice_number,
              i.customer_id,
              i.customer_name,
              i.issue_date as date,
              i.due_date,
              i.total,
              i.balance_due,
              i.status,
              i.currency,
              i.sent_at,
              i.created_at,
              i.business_id
            FROM invoices i
          `,
          params: []
        };

      case ReportDataSource.PAYMENTS:
        return {
          baseQuery: `
            SELECT
              p.id,
              p.invoice_id,
              p.payment_date as date,
              p.amount,
              p.currency,
              p.payment_method,
              p.reference,
              p.created_at,
              i.customer_name,
              i.invoice_number,
              p.business_id
            FROM invoice_payments p
            INNER JOIN invoices i ON p.invoice_id = i.id
          `,
          params: []
        };

      case ReportDataSource.CUSTOMERS:
        return {
          baseQuery: `
            SELECT
              id,
              name,
              email,
              phone,
              currency,
              credit_limit,
              is_active,
              created_at as date,
              business_id
            FROM customers
          `,
          params: []
        };

      default:
        throw new Error(`Unsupported data source: ${dataSource}`);
    }
  }

  /**
   * Build filter condition
   */
  private buildFilterCondition(filter: ReportFilter): { condition: string; filterParams: QueryParameter[] } {
    const field = filter.field;
    const operator = filter.operator;
    const value = filter.value;

    switch (operator) {
      case FilterOperator.EQUALS:
        return { condition: `${field} = ?`, filterParams: [value] };

      case FilterOperator.NOT_EQUALS:
        return { condition: `${field} != ?`, filterParams: [value] };

      case FilterOperator.GREATER_THAN:
        return { condition: `${field} > ?`, filterParams: [value] };

      case FilterOperator.LESS_THAN:
        return { condition: `${field} < ?`, filterParams: [value] };

      case FilterOperator.GREATER_THAN_OR_EQUAL:
        return { condition: `${field} >= ?`, filterParams: [value] };

      case FilterOperator.LESS_THAN_OR_EQUAL:
        return { condition: `${field} <= ?`, filterParams: [value] };

      case FilterOperator.CONTAINS:
        return { condition: `${field} LIKE ?`, filterParams: [`%${value}%`] };

      case FilterOperator.NOT_CONTAINS:
        return { condition: `${field} NOT LIKE ?`, filterParams: [`%${value}%`] };

      case FilterOperator.STARTS_WITH:
        return { condition: `${field} LIKE ?`, filterParams: [`${value}%`] };

      case FilterOperator.ENDS_WITH:
        return { condition: `${field} LIKE ?`, filterParams: [`%${value}`] };

      case FilterOperator.IN:
        if (Array.isArray(value)) {
          const placeholders = value.map(() => '?').join(',');
          return { condition: `${field} IN (${placeholders})`, filterParams: value };
        }
        return { condition: '', filterParams: [] };

      case FilterOperator.NOT_IN:
        if (Array.isArray(value)) {
          const placeholders = value.map(() => '?').join(',');
          return { condition: `${field} NOT IN (${placeholders})`, filterParams: value };
        }
        return { condition: '', filterParams: [] };

      case FilterOperator.IS_NULL:
        return { condition: `${field} IS NULL`, filterParams: [] };

      case FilterOperator.IS_NOT_NULL:
        return { condition: `${field} IS NOT NULL`, filterParams: [] };

      default:
        return { condition: '', filterParams: [] };
    }
  }

  /**
   * Get aggregation function SQL
   */
  private getAggregationFunction(type: AggregationType): string {
    switch (type) {
      case AggregationType.SUM:
        return 'SUM';
      case AggregationType.AVERAGE:
        return 'AVG';
      case AggregationType.COUNT:
        return 'COUNT';
      case AggregationType.MIN:
        return 'MIN';
      case AggregationType.MAX:
        return 'MAX';
      case AggregationType.MEDIAN:
        return 'MEDIAN'; // Note: SQLite doesn't have native MEDIAN, would need custom implementation
      default:
        return 'SUM';
    }
  }

  /**
   * Execute SQL query
   */
  private async executeQuery(query: SqlQuery): Promise<DatabaseRow[]> {
    try {
      const result = await this.db.prepare(query.sql).bind(...query.params).all();
      return result.results || [];
    } catch (error) {
      this.logger.error('Query execution failed', error, {
        sql: query.sql,
        paramCount: query.params.length
      });
      throw new Error(`Query execution failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Process query results
   */
  private processQueryResults(
    rows: DatabaseRow[],
    definition: CustomReportDefinition
  ): CustomReportResult {
    const result: CustomReportResult = {
      columns: definition.columns.filter(col => col.isVisible),
      rows,
      totalRows: rows.length
    };

    // Process aggregations
    if (definition.aggregations && definition.aggregations.length > 0) {
      result.aggregations = {};
      for (const agg of definition.aggregations) {
        const values = rows.map(row => row[agg.field]).filter(val => val != null);
        result.aggregations[agg.field] = this.calculateAggregation(values, agg.type);
      }
    }

    // Process grouping
    if (definition.grouping && definition.grouping.length > 0) {
      result.groupedData = this.processGrouping(rows, definition.grouping, definition.aggregations);
    }

    return result;
  }

  /**
   * Calculate aggregation value
   */
  private calculateAggregation(values: number[], type: AggregationType): number {
    if (values.length === 0) return 0;

    switch (type) {
      case AggregationType.SUM:
        return roundToCurrency(values.reduce((sum, val) => sum + val, 0));

      case AggregationType.AVERAGE:
        return roundToCurrency(values.reduce((sum, val) => sum + val, 0) / values.length);

      case AggregationType.COUNT:
        return values.length;

      case AggregationType.MIN:
        return Math.min(...values);

      case AggregationType.MAX:
        return Math.max(...values);

      case AggregationType.MEDIAN:
        const sorted = [...values].sort((a, b) => a - b);
        const mid = Math.floor(sorted.length / 2);
        return sorted.length % 2 === 0
          ? (sorted[mid - 1] + sorted[mid]) / 2
          : sorted[mid];

      default:
        return 0;
    }
  }

  /**
   * Process grouping
   */
  private processGrouping(
    rows: DatabaseRow[],
    grouping: ReportGrouping[],
    aggregations?: ReportAggregation[]
  ): GroupedData[] {
    // Sort grouping by level
    const sortedGrouping = [...grouping].sort((a, b) => a.level - b.level);
    const primaryGroup = sortedGrouping[0];

    // Group rows by the primary grouping field
    const grouped = new Map<GroupValue, DatabaseRow[]>();

    for (const row of rows) {
      const groupValue = row[primaryGroup.field];
      if (!grouped.has(groupValue)) {
        grouped.set(groupValue, []);
      }
      grouped.get(groupValue)!.push(row);
    }

    const result = [];

    for (const [groupValue, groupRows] of grouped) {
      const groupData: GroupedData = {
        groupValue,
        rows: groupRows
      };

      // Calculate subtotals if aggregations are specified
      if (aggregations && aggregations.length > 0 && primaryGroup.showSubtotals) {
        groupData.subtotals = {};
        for (const agg of aggregations) {
          const values = groupRows.map(row => row[agg.field]).filter(val => val != null);
          groupData.subtotals[agg.field] = this.calculateAggregation(values, agg.type);
        }
      }

      result.push(groupData);
    }

    return result;
  }

  /**
   * Get report definition
   */
  async getReportDefinition(definitionId: string, businessId: string): Promise<CustomReportDefinition | null> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      const result = await this.db.prepare(`
        SELECT * FROM custom_report_definitions
        WHERE id = ? AND business_id = ?
      `).bind(definitionId, validBusinessId).first();

      if (!result) {
        return null;
      }

      return this.mapToReportDefinition(result);

    } catch (error) {
      this.logger.error('Failed to get report definition', error, {
        definitionId,
        businessId: validBusinessId
      });
      return null;
    }
  }

  /**
   * Save report definition
   */
  private async saveReportDefinition(definition: CustomReportDefinition): Promise<void> {
    await this.db.prepare(`
      INSERT OR REPLACE INTO custom_report_definitions (
        id, name, description, data_source, columns, filters,
        sorting, grouping, aggregations, formatting,
        is_template, is_public, created_by, created_at,
        updated_at, business_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      definition.id,
      definition.name,
      definition.description || null,
      definition.dataSource,
      JSON.stringify(definition.columns),
      JSON.stringify(definition.filters),
      JSON.stringify(definition.sorting),
      JSON.stringify(definition.grouping || []),
      JSON.stringify(definition.aggregations || []),
      JSON.stringify(definition.formatting || {}),
      definition.isTemplate ? 1 : 0,
      definition.isPublic ? 1 : 0,
      definition.createdBy,
      definition.createdAt,
      definition.updatedAt,
      definition.businessId
    ).run();
  }

  /**
   * Map database row to report definition
   */
  private mapToReportDefinition(row: any): CustomReportDefinition {
    return {
      id: row.id,
      name: row.name,
      description: row.description || undefined,
      dataSource: row.data_source as ReportDataSource,
      columns: JSON.parse(row.columns),
      filters: JSON.parse(row.filters),
      sorting: JSON.parse(row.sorting),
      grouping: JSON.parse(row.grouping || '[]'),
      aggregations: JSON.parse(row.aggregations || '[]'),
      formatting: JSON.parse(row.formatting || '{}'),
      isTemplate: Boolean(row.is_template),
      isPublic: Boolean(row.is_public),
      createdBy: row.created_by,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      businessId: row.business_id
    };
  }

  /**
   * List report definitions for business
   */
  async listReportDefinitions(
    businessId: string,
    includePublic: boolean = true
  ): Promise<CustomReportDefinition[]> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      let sql: string;
      let params: any[];

      if (includePublic) {
        sql = `
          SELECT * FROM custom_report_definitions
          WHERE (business_id = ? OR is_public = 1)
          ORDER BY name
        `;
        params = [validBusinessId];
      } else {
        sql = `
          SELECT * FROM custom_report_definitions
          WHERE business_id = ?
          ORDER BY name
        `;
        params = [validBusinessId];
      }

      const result = await this.db.prepare(sql).bind(...params).all();

      return (result.results || []).map(row => this.mapToReportDefinition(row));

    } catch (error) {
      this.logger.error('Failed to list report definitions', error, {
        businessId: validBusinessId
      });
      return [];
    }
  }
}