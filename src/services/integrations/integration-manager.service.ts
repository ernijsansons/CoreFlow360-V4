/**
 * Global Integration Manager Service
 * Central orchestrator for ALL ERP integration operations
 * Used by: Finance, CRM, Inventory, HR, Payroll, E-commerce, Support, Analytics
 */

import type { Env } from '../../types/env';
import type { IntegrationProvider,
  BusinessIntegration,
  IntegrationRequest,
  IntegrationResponse,
  IntegrationCredentials,
  IntegrationErrorType } from './integration.types';
import { IntegrationError } from './integration.types';import { Logger } from "../../shared/logger";
const logger = new Logger({ component: "services-integrations-integration-managerservice" });



export class IntegrationManager {
  constructor(private env: Env) {}

  /**
   * Get integration provider details
   * Used by ANY module to discover available integrations
   */
  async getProvider(providerKey: string): Promise<IntegrationProvider | null> {
    try {
      const result = await this.env.DB_MAIN.prepare(
        'SELECT * FROM integration_providers WHERE provider_key = ? AND status = ?'
      )
        .bind(providerKey, 'active')
        .first() as any;

      if (!result) return null;

      return this.parseProvider(result);
    } catch (error) {
      logger.error('Get provider error:', error);
      return null;
    }
  }

  /**
   * List all providers by type
   * Example: Get all 'accounting' providers for Finance module
   */
  async getProvidersByType(type: string): Promise<IntegrationProvider[]> {
    try {
      const result = await this.env.DB_MAIN.prepare(
        'SELECT * FROM integration_providers WHERE provider_type = ? AND status = ? ORDER BY is_recommended DESC, user_rating DESC'
      )
        .bind(type, 'active')
        .all();

      return (result.results as any[] || []).map(row => this.parseProvider(row));
    } catch (error) {
      logger.error('Get providers by type error:', error);
      return [];
    }
  }

  /**
   * Get active integration connection for a business
   * This is the main method ALL modules use to get their integration
   */
  async getIntegration(
    businessId: string,
    providerKey: string
  ): Promise<BusinessIntegration | null> {
    try {
      const result = await this.env.DB_MAIN.prepare(
        `SELECT bi.* FROM business_integrations bi
         JOIN integration_providers ip ON bi.provider_id = ip.id
         WHERE bi.business_id = ?
         AND ip.provider_key = ?
         AND bi.connection_status = 'active'`
      )
        .bind(businessId, providerKey)
        .first() as any;

      if (!result) return null;

      return this.parseIntegration(result);
    } catch (error) {
      logger.error('Get integration error:', error);
      return null;
    }
  }

  /**
   * Get decrypted credentials for an integration
   * SECURITY: Only use this when actually making API calls
   */
  async getCredentials(
    businessId: string,
    providerKey: string
  ): Promise<IntegrationCredentials | null> {
    try {
      const integration = await this.getIntegration(businessId, providerKey);
      if (!integration) return null;

      // TODO: Implement proper decryption using Cloudflare Workers Crypto API
      // For now, just parse the JSON (assuming it's not actually encrypted in development)
      const credentials = JSON.parse(integration.credentials_encrypted) as IntegrationCredentials;
      return credentials;
    } catch (error) {
      logger.error('Get credentials error:', error);
      return null;
    }
  }

  /**
   * Execute integration request
   * This is the MAIN method ALL modules use to interact with integrations
   *
   * Usage Examples:
   * - Finance: await manager.executeIntegration({ provider_key: 'quickbooks', module: 'finance', operation: 'create_invoice', payload: {...} })
   * - CRM: await manager.executeIntegration({ provider_key: 'salesforce', module: 'crm', operation: 'create_lead', payload: {...} })
   * - HR: await manager.executeIntegration({ provider_key: 'gusto', module: 'hr', operation: 'run_payroll', payload: {...} })
   */
  async executeIntegration<T = any>(
    request: IntegrationRequest
  ): Promise<IntegrationResponse<T>> {
    const startTime = Date.now();

    try {
      // 1. Get integration connection
      const integration = await this.getIntegration(
        request.business_id,
        request.provider_key
      );

      if (!integration) {
        throw new IntegrationError(
          'NOT_FOUND' as IntegrationErrorType,
          `Integration '${request.provider_key}' not connected for this business`,
          request.provider_key,
          404,
          false
        );
      }

      // 2. Check rate limits
      await this.checkRateLimits(integration);

      // 3. Get credentials
      const credentials = await this.getCredentials(
        request.business_id,
        request.provider_key
      );

      if (!credentials) {
        throw new IntegrationError(
          'AUTH_FAILED' as IntegrationErrorType,
          'Integration credentials not found',
          request.provider_key,
          401,
          false
        );
      }

      // 4. Execute provider-specific logic
      const response = await this.executeProviderOperation(
        request.provider_key,
        request.operation,
        request.payload,
        credentials
      );

      // 5. Log usage
      const responseTime = Date.now() - startTime;
      await this.logUsage({
        business_integration_id: integration.id,
        business_id: request.business_id,
        request_type: `${request.module}:${request.operation}`,
        response_time_ms: responseTime,
        response_success: true,
        user_id: request.user_id,
      });

      return {
        success: true,
        data: response,
        response_time_ms: responseTime,
      };
    } catch (error: any) {
      const responseTime = Date.now() - startTime;

      // Log failed request
      await this.logUsage({
        business_integration_id: '', // May not have integration if error was early
        business_id: request.business_id,
        request_type: `${request.module}:${request.operation}`,
        response_time_ms: responseTime,
        response_success: false,
        response_error: error.message,
        user_id: request.user_id,
      });

      if (error instanceof IntegrationError) {
        return {
          success: false,
          error: error.message,
          provider_response_code: error.statusCode,
          response_time_ms: responseTime,
        };
      }

      return {
        success: false,
        error: error.message || 'Integration execution failed',
        response_time_ms: responseTime,
      };
    }
  }

  /**
   * Execute provider-specific operation
   * This will be extended to handle each provider's API
   */
  private async executeProviderOperation(
    providerKey: string,
    operation: string,
    payload: Record<string, any>,
    _credentials: IntegrationCredentials
  ): Promise<any> {
    // TODO: Implement provider-specific handlers
    // For now, return a placeholder
    logger.info(`Executing ${providerKey}.${operation}`, payload);

    // In future, this will delegate to provider-specific services:
    // switch (providerKey) {
    //   case 'quickbooks': return await QuickBooksProvider.execute(operation, payload, credentials);
    //   case 'salesforce': return await SalesforceProvider.execute(operation, payload, credentials);
    //   case 'stripe': return await StripeProvider.execute(operation, payload, credentials);
    //   ...
    // }

    throw new IntegrationError(
      'INVALID_REQUEST' as IntegrationErrorType,
      `Provider '${providerKey}' not yet implemented`,
      providerKey,
      501,
      false
    );
  }

  /**
   * Check rate limits for integration
   */
  private async checkRateLimits(integration: BusinessIntegration): Promise<void> {
    // Check if quota exceeded
    if (
      integration.monthly_quota_limit &&
      integration.monthly_quota_used >= integration.monthly_quota_limit
    ) {
      throw new IntegrationError(
        'QUOTA_EXCEEDED' as IntegrationErrorType,
        `Monthly quota exceeded for this integration`,
        undefined,
        429,
        false
      );
    }

    // TODO: Implement per-minute rate limiting using Durable Objects
  }

  /**
   * Log integration usage
   */
  private async logUsage(data: {
    business_integration_id: string;
    business_id: string;
    request_type: string;
    response_time_ms?: number;
    response_success: boolean;
    response_error?: string;
    user_id?: string;
  }): Promise<void> {
    try {
      await this.env.DB_MAIN.prepare(
        `INSERT INTO integration_usage_logs (
          id, business_integration_id, business_id, request_type,
          response_time_ms, response_success, response_error,
          user_id, credits_used, cost_usd
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
        .bind(
          crypto.randomUUID(),
          data.business_integration_id,
          data.business_id,
          data.request_type,
          data.response_time_ms || 0,
          data.response_success ? 1 : 0,
          data.response_error || null,
          data.user_id || null,
          1, // credits_used
          0.0 // cost_usd (calculate based on provider)
        )
        .run();

      // Update integration stats
      if (data.business_integration_id) {
        await this.env.DB_MAIN.prepare(
          `UPDATE business_integrations
           SET total_requests = total_requests + 1,
               requests_this_month = requests_this_month + 1,
               monthly_quota_used = monthly_quota_used + 1,
               success_count = success_count + ?,
               error_count = error_count + ?,
               last_request_at = CURRENT_TIMESTAMP
           WHERE id = ?`
        )
          .bind(
            data.response_success ? 1 : 0,
            data.response_success ? 0 : 1,
            data.business_integration_id
          )
          .run();
      }
    } catch (error) {
      logger.error('Log usage error:', error);
      // Don't throw - logging errors shouldn't break the request
    }
  }

  /**
   * Parse provider from database row
   */
  private parseProvider(row: any): IntegrationProvider {
    return {
      id: row.id,
      provider_key: row.provider_key,
      provider_name: row.provider_name,
      provider_logo_url: row.provider_logo_url,
      provider_website: row.provider_website,
      provider_type: row.provider_type,
      category_tags: row.category_tags ? JSON.parse(row.category_tags) : [],
      capabilities: row.capabilities ? JSON.parse(row.capabilities) : [],
      supported_entities: row.supported_entities ? JSON.parse(row.supported_entities) : [],
      data_fields_provided: row.data_fields_provided ? JSON.parse(row.data_fields_provided) : [],
      auth_type: row.auth_type,
      auth_config: row.auth_config ? JSON.parse(row.auth_config) : undefined,
      pricing_model: row.pricing_model,
      base_cost_per_request: row.base_cost_per_request,
      monthly_free_quota: row.monthly_free_quota,
      rate_limit_per_minute: row.rate_limit_per_minute,
      rate_limit_per_day: row.rate_limit_per_day,
      avg_response_time_ms: row.avg_response_time_ms,
      success_rate: row.success_rate,
      data_accuracy_score: row.data_accuracy_score,
      user_rating: row.user_rating,
      total_reviews: row.total_reviews,
      status: row.status,
      is_verified: Boolean(row.is_verified),
      is_recommended: Boolean(row.is_recommended),
      available_regions: row.available_regions ? JSON.parse(row.available_regions) : [],
      documentation_url: row.documentation_url,
      api_docs_url: row.api_docs_url,
      support_email: row.support_email,
      webhook_support: Boolean(row.webhook_support),
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  }

  /**
   * Parse integration from database row
   */
  private parseIntegration(row: any): BusinessIntegration {
    return {
      id: row.id,
      business_id: row.business_id,
      provider_id: row.provider_id,
      connection_name: row.connection_name,
      connection_status: row.connection_status,
      credentials_encrypted: row.credentials_encrypted,
      credentials_expires_at: row.credentials_expires_at,
      oauth_access_token: row.oauth_access_token,
      oauth_refresh_token: row.oauth_refresh_token,
      oauth_token_expires_at: row.oauth_token_expires_at,
      oauth_scopes: row.oauth_scopes ? JSON.parse(row.oauth_scopes) : undefined,
      settings: row.settings ? JSON.parse(row.settings) : undefined,
      enabled_features: row.enabled_features ? JSON.parse(row.enabled_features) : undefined,
      webhook_url: row.webhook_url,
      webhook_secret: row.webhook_secret,
      total_requests: row.total_requests || 0,
      requests_this_month: row.requests_this_month || 0,
      last_request_at: row.last_request_at,
      monthly_quota_used: row.monthly_quota_used || 0,
      monthly_quota_limit: row.monthly_quota_limit,
      total_cost_usd: row.total_cost_usd || 0,
      cost_this_month: row.cost_this_month || 0,
      success_count: row.success_count || 0,
      error_count: row.error_count || 0,
      avg_response_time_ms: row.avg_response_time_ms,
      last_error_message: row.last_error_message,
      last_error_at: row.last_error_at,
      last_sync_at: row.last_sync_at,
      next_sync_at: row.next_sync_at,
      sync_frequency: row.sync_frequency,
      auto_sync_enabled: Boolean(row.auto_sync_enabled),
      connected_by: row.connected_by,
      connected_at: row.connected_at,
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  }
}
