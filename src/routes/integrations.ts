/**
 * Global Integrations API Routes
 * Central hub for ALL ERP integration management
 * Used by: Finance, CRM, Inventory, HR, Payroll, E-commerce, Support, Analytics
 */

import { Hono } from 'hono';
import { Logger } from '../shared/logger';
const logger = new Logger({ component: 'integrations' });
import { z } from 'zod';
import type { Env } from '../types/env';

type HonoContext = {
  Bindings: Env;
  Variables: {
    userId: string;
    businessId: string;
  };
};

const app = new Hono<HonoContext>();

// ============================================================
// VALIDATION SCHEMAS
// ============================================================

const ConnectIntegrationSchema = z.object({
  provider_id: z.string(),
  connection_name: z.string().optional(),
  credentials: z.object({
    api_key: z.string().optional(),
    client_id: z.string().optional(),
    client_secret: z.string().optional(),
    access_token: z.string().optional(),
    refresh_token: z.string().optional(),
  }),
  settings: z.record(z.any()).optional(),
  enabled_features: z.array(z.string()).optional(),
});

const UpdateIntegrationSchema = z.object({
  connection_name: z.string().optional(),
  connection_status: z.enum(['active', 'inactive', 'suspended']).optional(),
  settings: z.record(z.any()).optional(),
  enabled_features: z.array(z.string()).optional(),
});

// ============================================================
// PROVIDER CATALOG ENDPOINTS
// ============================================================

/**
 * GET /integrations/providers
 * List all available integration providers
 */
app.get('/providers', async (c) => {
  try {
    const { type, status, category } = c.req.query();

    let query = `
      SELECT * FROM integration_providers
      WHERE 1=1
    `;
    const params: any[] = [];

    if (type) {
      query += ' AND provider_type = ?';
      params.push(type);
    }

    if (status) {
      query += ' AND status = ?';
      params.push(status);
    } else {
      query += " AND status = 'active'";
    }

    if (category) {
      query += ' AND category_tags LIKE ?';
      params.push(`%"${category}"%`);
    }

    query += ' ORDER BY is_recommended DESC, user_rating DESC, provider_name ASC';

    const result = await c.env.DB_MAIN.prepare(query).bind(...params).all();

    const providers = (result.results as any[] || []).map((row: any) => ({
      id: row.id,
      provider_key: row.provider_key,
      provider_name: row.provider_name,
      provider_logo_url: row.provider_logo_url,
      provider_website: row.provider_website,
      provider_type: row.provider_type,
      category_tags: row.category_tags ? JSON.parse(row.category_tags) : [],
      capabilities: row.capabilities ? JSON.parse(row.capabilities) : [],
      supported_entities: row.supported_entities ? JSON.parse(row.supported_entities) : [],
      pricing_model: row.pricing_model,
      base_cost_per_request: row.base_cost_per_request,
      monthly_free_quota: row.monthly_free_quota,
      user_rating: row.user_rating,
      is_recommended: Boolean(row.is_recommended),
      is_verified: Boolean(row.is_verified),
      documentation_url: row.documentation_url,
    }));

    return c.json({
      success: true,
      data: providers,
      meta: {
        total: providers.length,
      },
    });
  } catch (error: any) {
    logger.error('List providers error:', error);
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * GET /integrations/providers/:id
 * Get detailed information about a specific provider
 */
app.get('/providers/:id', async (c) => {
  try {
    const providerId = c.req.param('id');

    const provider = await c.env.DB_MAIN.prepare(
      'SELECT * FROM integration_providers WHERE id = ? OR provider_key = ?'
    )
      .bind(providerId, providerId)
      .first() as any;

    if (!provider) {
      return c.json({ success: false, error: 'Provider not found' }, 404);
    }

    return c.json({
      success: true,
      data: {
        id: provider.id,
        provider_key: provider.provider_key,
        provider_name: provider.provider_name,
        provider_logo_url: provider.provider_logo_url,
        provider_website: provider.provider_website,
        provider_type: provider.provider_type,
        category_tags: provider.category_tags ? JSON.parse(provider.category_tags) : [],
        capabilities: provider.capabilities ? JSON.parse(provider.capabilities) : [],
        supported_entities: provider.supported_entities ? JSON.parse(provider.supported_entities) : [],
        data_fields_provided: provider.data_fields_provided ? JSON.parse(provider.data_fields_provided) : [],
        auth_type: provider.auth_type,
        auth_config: provider.auth_config ? JSON.parse(provider.auth_config) : null,
        pricing_model: provider.pricing_model,
        base_cost_per_request: provider.base_cost_per_request,
        monthly_free_quota: provider.monthly_free_quota,
        rate_limit_per_minute: provider.rate_limit_per_minute,
        rate_limit_per_day: provider.rate_limit_per_day,
        avg_response_time_ms: provider.avg_response_time_ms,
        success_rate: provider.success_rate,
        data_accuracy_score: provider.data_accuracy_score,
        user_rating: provider.user_rating,
        total_reviews: provider.total_reviews,
        status: provider.status,
        is_verified: Boolean(provider.is_verified),
        is_recommended: Boolean(provider.is_recommended),
        available_regions: provider.available_regions ? JSON.parse(provider.available_regions) : [],
        documentation_url: provider.documentation_url,
        api_docs_url: provider.api_docs_url,
        support_email: provider.support_email,
        webhook_support: Boolean(provider.webhook_support),
      },
    });
  } catch (error: any) {
    logger.error('Get provider error:', error);
    return c.json({ success: false, error: error.message }, 500);
  }
});

// ============================================================
// BUSINESS INTEGRATION CONNECTION ENDPOINTS
// ============================================================

/**
 * GET /integrations/connections
 * List all integrations connected for this business
 */
app.get('/connections', async (c) => {
  try {
    const businessId = c.get('businessId');
    const { status, provider_type } = c.req.query();

    let query = `
      SELECT
        bi.*,
        ip.provider_name,
        ip.provider_logo_url,
        ip.provider_type,
        ip.pricing_model
      FROM business_integrations bi
      JOIN integration_providers ip ON bi.provider_id = ip.id
      WHERE bi.business_id = ?
    `;
    const params: any[] = [businessId];

    if (status) {
      query += ' AND bi.connection_status = ?';
      params.push(status);
    }

    if (provider_type) {
      query += ' AND ip.provider_type = ?';
      params.push(provider_type);
    }

    query += ' ORDER BY bi.created_at DESC';

    const result = await c.env.DB_MAIN.prepare(query).bind(...params).all();

    const connections = (result.results as any[] || []).map((row: any) => ({
      id: row.id,
      provider_id: row.provider_id,
      provider_name: row.provider_name,
      provider_logo_url: row.provider_logo_url,
      provider_type: row.provider_type,
      connection_name: row.connection_name,
      connection_status: row.connection_status,
      enabled_features: row.enabled_features ? JSON.parse(row.enabled_features) : [],
      total_requests: row.total_requests,
      requests_this_month: row.requests_this_month,
      monthly_quota_used: row.monthly_quota_used,
      monthly_quota_limit: row.monthly_quota_limit,
      total_cost_usd: row.total_cost_usd,
      cost_this_month: row.cost_this_month,
      success_count: row.success_count,
      error_count: row.error_count,
      last_request_at: row.last_request_at,
      last_sync_at: row.last_sync_at,
      connected_at: row.connected_at,
    }));

    return c.json({
      success: true,
      data: connections,
      meta: {
        total: connections.length,
      },
    });
  } catch (error: any) {
    logger.error('List connections error:', error);
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * POST /integrations/connections
 * Connect a new integration
 */
app.post('/connections', async (c) => {
  try {
    const businessId = c.get('businessId');
    const userId = c.get('userId');
    const body = await c.req.json();

    const validated = ConnectIntegrationSchema.parse(body);

    // Check if provider exists
    const provider = await c.env.DB_MAIN.prepare(
      'SELECT * FROM integration_providers WHERE id = ?'
    )
      .bind(validated.provider_id)
      .first() as any;

    if (!provider) {
      return c.json({ success: false, error: 'Provider not found' }, 404);
    }

    // Check if already connected
    const existing = await c.env.DB_MAIN.prepare(
      'SELECT id FROM business_integrations WHERE business_id = ? AND provider_id = ?'
    )
      .bind(businessId, validated.provider_id)
      .first();

    if (existing) {
      return c.json(
        { success: false, error: 'Integration already connected' },
        409
      );
    }

    const id = crypto.randomUUID();

    // Encrypt credentials (in production, use proper encryption)
    const credentialsEncrypted = JSON.stringify(validated.credentials);

    await c.env.DB_MAIN.prepare(
      `INSERT INTO business_integrations (
        id, business_id, provider_id, connection_name,
        connection_status, credentials_encrypted,
        settings, enabled_features,
        monthly_quota_limit, connected_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        id,
        businessId,
        validated.provider_id,
        validated.connection_name || provider.provider_name,
        'active',
        credentialsEncrypted,
        validated.settings ? JSON.stringify(validated.settings) : null,
        validated.enabled_features
          ? JSON.stringify(validated.enabled_features)
          : JSON.stringify(JSON.parse(provider.capabilities || '[]')),
        provider.monthly_free_quota || 0,
        userId
      )
      .run();

    return c.json({
      success: true,
      data: {
        id,
        message: `Successfully connected ${provider.provider_name}`,
      },
    });
  } catch (error: any) {
    logger.error('Connect integration error:', error);
    if (error instanceof z.ZodError) {
      return c.json({ success: false, error: error.errors }, 400);
    }
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * PATCH /integrations/connections/:id
 * Update an existing integration connection
 */
app.patch('/connections/:id', async (c) => {
  try {
    const businessId = c.get('businessId');
    const connectionId = c.req.param('id');
    const body = await c.req.json();

    const validated = UpdateIntegrationSchema.parse(body);

    // Verify ownership
    const connection = await c.env.DB_MAIN.prepare(
      'SELECT id FROM business_integrations WHERE id = ? AND business_id = ?'
    )
      .bind(connectionId, businessId)
      .first();

    if (!connection) {
      return c.json({ success: false, error: 'Connection not found' }, 404);
    }

    const updates: string[] = [];
    const params: any[] = [];

    if (validated.connection_name !== undefined) {
      updates.push('connection_name = ?');
      params.push(validated.connection_name);
    }

    if (validated.connection_status !== undefined) {
      updates.push('connection_status = ?');
      params.push(validated.connection_status);
    }

    if (validated.settings !== undefined) {
      updates.push('settings = ?');
      params.push(JSON.stringify(validated.settings));
    }

    if (validated.enabled_features !== undefined) {
      updates.push('enabled_features = ?');
      params.push(JSON.stringify(validated.enabled_features));
    }

    if (updates.length === 0) {
      return c.json({ success: false, error: 'No fields to update' }, 400);
    }

    updates.push('updated_at = CURRENT_TIMESTAMP');
    params.push(connectionId, businessId);

    await c.env.DB_MAIN.prepare(
      `UPDATE business_integrations
       SET ${updates.join(', ')}
       WHERE id = ? AND business_id = ?`
    )
      .bind(...params)
      .run();

    return c.json({
      success: true,
      data: { id: connectionId, message: 'Connection updated successfully' },
    });
  } catch (error: any) {
    logger.error('Update connection error:', error);
    if (error instanceof z.ZodError) {
      return c.json({ success: false, error: error.errors }, 400);
    }
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * DELETE /integrations/connections/:id
 * Disconnect an integration
 */
app.delete('/connections/:id', async (c) => {
  try {
    const businessId = c.get('businessId');
    const connectionId = c.req.param('id');

    const result = await c.env.DB_MAIN.prepare(
      'DELETE FROM business_integrations WHERE id = ? AND business_id = ?'
    )
      .bind(connectionId, businessId)
      .run();

    if (!result.success) {
      return c.json({ success: false, error: 'Connection not found' }, 404);
    }

    return c.json({
      success: true,
      data: { message: 'Integration disconnected successfully' },
    });
  } catch (error: any) {
    logger.error('Delete connection error:', error);
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * GET /integrations/connections/:id/usage
 * Get usage statistics for a specific integration
 */
app.get('/connections/:id/usage', async (c) => {
  try {
    const businessId = c.get('businessId');
    const connectionId = c.req.param('id');

    // Verify ownership
    const connection = await c.env.DB_MAIN.prepare(
      'SELECT * FROM business_integrations WHERE id = ? AND business_id = ?'
    )
      .bind(connectionId, businessId)
      .first() as any;

    if (!connection) {
      return c.json({ success: false, error: 'Connection not found' }, 404);
    }

    // Get recent usage logs
    const logsResult = await c.env.DB_MAIN.prepare(
      `SELECT * FROM integration_usage_logs
       WHERE business_integration_id = ?
       ORDER BY requested_at DESC
       LIMIT 100`
    )
      .bind(connectionId)
      .all();

    const logs = (logsResult.results as any[] || []).map((row: any) => ({
      id: row.id,
      request_type: row.request_type,
      response_status_code: row.response_status_code,
      response_time_ms: row.response_time_ms,
      response_success: Boolean(row.response_success),
      credits_used: row.credits_used,
      cost_usd: row.cost_usd,
      requested_at: row.requested_at,
    }));

    return c.json({
      success: true,
      data: {
        connection_id: connectionId,
        total_requests: connection.total_requests,
        requests_this_month: connection.requests_this_month,
        monthly_quota_used: connection.monthly_quota_used,
        monthly_quota_limit: connection.monthly_quota_limit,
        quota_remaining:
          connection.monthly_quota_limit - connection.monthly_quota_used,
        total_cost_usd: connection.total_cost_usd,
        cost_this_month: connection.cost_this_month,
        success_rate:
          connection.total_requests > 0
            ? (connection.success_count / connection.total_requests) * 100
            : 0,
        avg_response_time_ms: connection.avg_response_time_ms,
        recent_logs: logs,
      },
    });
  } catch (error: any) {
    logger.error('Get usage error:', error);
    return c.json({ success: false, error: error.message }, 500);
  }
});

export default app;
