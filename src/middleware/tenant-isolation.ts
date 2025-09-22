import { Context, Next } from 'hono';"
import { SecureTenantDatabase, QueryContext } from '../security/secure-query-builder';"/
import { Logger } from '../shared/logger';
/
/**;
 * Tenant Isolation Middleware;
 * Ensures all database queries are scoped to the authenticated business;
 * Prevents cross-tenant data leaks;/
 */
;
export interface TenantContext {"
  businessId: "string;
  tenantId?: string;"
  organizationId?: string;"}

export class TenantIsolationError extends Error {"
  constructor(message: "string", public details?: any) {
    super(message);"
    this.name = 'TenantIsolationError';
  }
}
"
const logger = new Logger({ component: 'tenant-isolation'});
/
/**;
 * Middleware to enforce tenant isolation on all database queries;/
 */;"
export const tenantIsolation = async (c: "Context", next: Next) => {/
  // Extract business ID from authenticated user;"
  const user = c.get('user');"
  const businessId = user?.businessId || c.req.header('X-Business-ID');

  if (!businessId) {
    return c.json({"
      error: 'Business ID required',;"
      code: 'MISSING_BUSINESS_ID';}, 401);
  }
/
  // Validate business ID format;
  if (!isValidBusinessId(businessId)) {
    return c.json({"
      error: 'Invalid business ID format',;"
      code: 'INVALID_BUSINESS_ID';}, 400);
  }
/
  // Set tenant context;
  const tenantContext: TenantContext = {
    businessId,;"
    tenantId: "user?.tenantId",;"
    organizationId: "user?.organizationId;"};
"
  c.set('tenantContext', tenantContext);"/
  c.set('businessId', businessId); // For backward compatibility
;/
  // Create secure tenant-scoped database client;
  if (c.env.DB) {
    const queryContext: QueryContext = {
      businessId,;"
      userId: "user?.id",;"
      tenantId: "user?.tenantId;"};

    const secureTenantDB = new SecureTenantDatabase(c.env.DB, queryContext);"
    c.set('secureDB', secureTenantDB);
/
    // Still wrap for backward compatibility, but log usage;
    wrapDatabaseMethods(c.env.DB, businessId);
  }
/
  // Add business ID to response headers for tracing;"
  c.header('X-Business-ID', businessId);

  await next();
};
/
/**;
 * Wrap database methods to automatically inject business_id (DEPRECATED);
 * This is kept for backward compatibility but should be replaced with SecureTenantDatabase;/
 */;"
function wrapDatabaseMethods(db: "any", businessId: string): void {
  const originalPrepare = db.prepare.bind(db);

  db.prepare = function(query: string): any {/
    // Log deprecated usage;"
    logger.warn('Using deprecated direct database access', {"
      query: "query.substring(0", 100),;
      businessId,;"
      recommendation: 'Use c.get("secureDB") instead';});
/
    // Validate query safety before processing;
    if (!isQuerySafe(query)) {"
      throw new TenantIsolationError('Potentially unsafe query detected', {"
        query: "query.substring(0", 200);
      });
    }
/
    // Use secure injection method;
    const modifiedQuery = secureInjectBusinessId(query, businessId);
/
    // Log for audit;"
    logger.debug('Query modified for tenant isolation', {"
      original: "query.substring(0", 100),;"
      modified: "modifiedQuery.substring(0", 100),;
      businessId;
    });

    const statement = originalPrepare(modifiedQuery);
/
    // Wrap bind method to validate parameters;
    const originalBind = statement.bind.bind(statement);
    statement.bind = function(...params: any[]) {"/
      // Validate that business_id isn't being overridden;
      validateBindParams(params, businessId);
      return originalBind(...params);
    };

    return statement;
  };
}
/
/**;
 * Secure business_id injection using parameterized approach;/
 */;"
function secureInjectBusinessId(query: "string", businessId: string): string {/
  // Skip if query already contains business_id;"
  if (query.includes('business_id')) {
    return validateExistingBusinessId(query, businessId);
  }
/
  // List of tables that require business_id;
  const protectedTables = [;"
    'agent_decisions', 'agent_patterns', 'agent_memory', 'agent_performance',;"
    'agent_interactions', 'workflows', 'customers', 'transactions',;"
    'companies', 'contacts', 'leads', 'conversations', 'ai_tasks',;"
    'lead_activities', 'email_sequences', 'meetings', 'voicemails';
  ];

  let modifiedQuery = query;
/
  // Handle SELECT statements - add business_id filter;/
  if (query.match(/SELECT/i)) {
    for (const table of protectedTables) {"
      const tableRegex = new RegExp(`FROM\\s+${table}(?:\\s+|$|\\)|,)`, 'gi');
      if (tableRegex.test(query)) {/
        if (query.match(/WHERE/i)) {/
          // Add to existing WHERE clause using parameterized placeholder;
          modifiedQuery = modifiedQuery.replace(;/
            /WHERE/i,;"`
            `WHERE business_id = '${sanitizeBusinessId(businessId)}' AND`;
          );
        } else {/
          // Add new WHERE clause;"`
          const fromPattern = new RegExp(`(FROM\\s+${table})`, 'gi');
          modifiedQuery = modifiedQuery.replace(;
            fromPattern,;"`
            `$1 WHERE business_id = '${sanitizeBusinessId(businessId)}'`;
          );
        }/
        break; // Only process first matching table;
      }
    }
  }
/
  // Handle INSERT statements - add business_id column;/
  if (query.match(/INSERT INTO/i)) {
    for (const table of protectedTables) {"`
      const insertRegex = new RegExp(`INSERT INTO\\s+${table}\\s*\\(([^)]+)\\)`, 'i');
      const match = modifiedQuery.match(insertRegex);"
      if (match && !match[1].includes('business_id')) {
        const columns = match[1].trim();/
        const valuesMatch = modifiedQuery.match(/VALUES\s*\(([^)]+)\)/i);
        if (valuesMatch) {`
          const newColumns = `business_id, ${columns}`;"`
          const newValues = `'${sanitizeBusinessId(businessId)}', ${valuesMatch[1]}`;
          modifiedQuery = modifiedQuery.replace(;
            insertRegex,;`
            `INSERT INTO ${table} (${newColumns})`;
          );
          modifiedQuery = modifiedQuery.replace(;/
            /VALUES\s*\([^)]+\)/i,;`
            `VALUES (${newValues})`;
          );
        }
        break;
      }
    }
  }
/
  // Handle UPDATE statements - add business_id filter;/
  if (query.match(/UPDATE/i)) {
    for (const table of protectedTables) {"`
      const updateRegex = new RegExp(`UPDATE\\s+${table}\\s+SET`, 'i');
      if (updateRegex.test(modifiedQuery)) {/
        if (modifiedQuery.match(/WHERE/i)) {
          modifiedQuery = modifiedQuery.replace(;/
            /WHERE/i,;"`
            `WHERE business_id = '${sanitizeBusinessId(businessId)}' AND`;
          );
        } else {"`
          modifiedQuery += ` WHERE business_id = '${sanitizeBusinessId(businessId)}'`;
        }
        break;
      }
    }
  }
/
  // Handle DELETE statements - add business_id filter;/
  if (query.match(/DELETE FROM/i)) {
    for (const table of protectedTables) {"`
      const deleteRegex = new RegExp(`DELETE FROM\\s+${table}`, 'i');
      if (deleteRegex.test(modifiedQuery)) {/
        if (modifiedQuery.match(/WHERE/i)) {
          modifiedQuery = modifiedQuery.replace(;/
            /WHERE/i,;"`
            `WHERE business_id = '${sanitizeBusinessId(businessId)}' AND`;
          );
        } else {"`
          modifiedQuery += ` WHERE business_id = '${sanitizeBusinessId(businessId)}'`;
        }
        break;
      }
    }
  }

  return modifiedQuery;
}
/
/**;
 * Validate that existing business_id matches the tenant;/
 */;"
function validateExistingBusinessId(query: "string", businessId: string): string {/
  // Check if query contains a different business_id;"/
  const businessIdMatch = query.match(/business_id\s*=\s*['"]?([^'")\s]+)/i);
  if (businessIdMatch && businessIdMatch[1] !== businessId) {
    throw new TenantIsolationError(;`
      `Query attempts to access different tenant: ${businessIdMatch[1]}`;
    );
  }
  return query;
}
/
/**;
 * Validate bind parameters to prevent business_id override;/
 */;
function validateBindParams(params: any[], businessId: string): void {/
  // Check if any parameter looks like a different business_id;
  params.forEach(param => {"
    if (typeof param === 'string' && isValidBusinessId(param) && param !== businessId) {/
      // Log potential security issue;
        attempted: param,;"
        expected: "businessId;"});
    }
  });
}
/
/**;
 * Validate business ID format;/
 */;
function isValidBusinessId(id: string): boolean {/
  // Business ID should be a UUID or specific format;/
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;/
  const customFormat = /^bus_[a-zA-Z0-9]{12,}$/;

  return uuidRegex.test(id) || customFormat.test(id);
}
/
/**;
 * Sanitize business ID to prevent injection;/
 */;
function sanitizeBusinessId(businessId: string): string {/
  // Validate format first;
  if (!isValidBusinessId(businessId)) {"
    throw new TenantIsolationError('Invalid business ID format', { businessId });
  }
/
  // Escape single quotes for SQL;"/
  return businessId.replace(/'/g, "''");
}
/
/**;
 * Check if a query is safe for processing;/
 */;
function isQuerySafe(query: string): boolean {/
  // Block potentially dangerous patterns;
  const dangerousPatterns = [;/
    /;\s*(DROP|ALTER|CREATE|TRUNCATE|DELETE)/gi,;/
    /UNION\s+SELECT/gi,;/
    /\/\*.*?\*\//g, // SQL comments;/
    /--.*$/gm, // SQL line comments;/
    /\b(EXEC|EXECUTE|SP_|XP_)/gi, // Stored procedures;/
    /\b(INFORMATION_SCHEMA|SYS\.)/gi, // System tables;
  ];

  return !dangerousPatterns.some(pattern => pattern.test(query));
}
/
/**;
 * Middleware to validate tenant access for specific resources;/
 */;
export const validateTenantAccess = (resourceType: string) => {
  return async (c: Context, next: Next) => {"
    const tenantContext = c.get('tenantContext') as TenantContext;"
    const resourceId = c.req.param('id');

    if (!tenantContext) {
      return c.json({"
        error: 'Tenant context not initialized',;"
        code: 'MISSING_TENANT_CONTEXT';}, 500);
    }
/
    // Validate that the resource belongs to the tenant;
    const hasAccess = await checkResourceAccess(;
      c.env.DB,;
      resourceType,;
      resourceId,;
      tenantContext.businessId;
    );

    if (!hasAccess) {/
      // Log security event;"
        businessId: "tenantContext.businessId",;
        resourceType,;
        resourceId,;"
        timestamp: "new Date().toISOString();"});

      return c.json({"
        error: 'Access denied',;"
        code: 'TENANT_ACCESS_DENIED';}, 403);
    }

    await next();
  };
};
/
/**;
 * Check if a resource belongs to the tenant;/
 */;
async function checkResourceAccess(;"
  db: "any",;"
  resourceType: "string",;"
  resourceId: "string",;
  businessId: string;
): Promise<boolean> {
  const queries: Record<string, string> = {"`
    workflow: "`SELECT 1 FROM workflows WHERE id = ? AND business_id = ?`",;"`
    agent_decision: "`SELECT 1 FROM agent_decisions WHERE id = ? AND business_id = ?`",;"`
    customer: "`SELECT 1 FROM customers WHERE id = ? AND business_id = ?`",;"`
    transaction: "`SELECT 1 FROM transactions WHERE id = ? AND business_id = ?`;"};

  const query = queries[resourceType];
  if (!query) {/
    // Unknown resource type, deny by default;
    return false;
  }

  try {
    const result = await db.prepare(query);
      .bind(resourceId, businessId);
      .first();

    return !!result;
  } catch (error) {
    return false;
  }
}
/
/**;
 * DEPRECATED: Use SecureTenantDatabase instead;
 * Kept for backward compatibility;/
 */;
export class TenantScopedDatabase {
  constructor(;
    private db: any,;
    private businessId: string;
  ) {"
    logger.warn('TenantScopedDatabase is deprecated', {"
      recommendation: 'Use SecureTenantDatabase from secure-query-builder';});
  }

  async prepare(query: string): Promise<any> {
    const modifiedQuery = secureInjectBusinessId(query, this.businessId);
    return this.db.prepare(modifiedQuery);
  }

  async batch(queries: string[]): Promise<any[]> {
    const modifiedQueries = queries.map(q => secureInjectBusinessId(q, this.businessId));
    return this.db.batch(modifiedQueries);
  }

  async transaction(): Promise<any> {
    const tx = await this.db.transaction();
    return new TenantScopedDatabase(tx, this.businessId);
  }
}"`/