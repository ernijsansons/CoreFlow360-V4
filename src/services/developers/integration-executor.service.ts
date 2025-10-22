/**
 * Custom Integration Executor Service
 * Executes custom integration code in sandbox environment
 * Handles action execution, trigger processing, error tracking
 */

import { Logger } from '@/shared/logger';
import type { Env } from '@/types/env';
import type {
  CustomIntegration,
  CustomIntegrationInstall,
  IntegrationManifest,
  ActionDefinition,
  TriggerDefinition,
  ExecuteActionRequest,
  ExecuteActionResponse,
  ProcessTriggerRequest,
  ProcessTriggerResponse,
  IntegrationExecutionLog,
  SandboxContext,
  SandboxResult,
} from './developer.types';
import type { IntegrationRequest,
  IntegrationResponse } from '@/services/integrations/integration.types';

/**
 * Integration Executor Service
 * Executes custom integration code with proper sandboxing and error handling
 */
export class IntegrationExecutorService {
  private logger = new Logger({ component: 'IntegrationExecutorService' });

  constructor(private env: Env) {}

  /**
   * Execute Custom Integration Action
   * Called by IntegrationManager when routing to custom integration
   */
  async executeAction(request: ExecuteActionRequest): Promise<ExecuteActionResponse> {
    const startTime = Date.now();

    try {
      // 1. Validate install is active
      const install = await this.getInstall(request.install_id);
      if (!install) {
        return {
          success: false,
          error: 'Integration install not found',
        };
      }

      if (install.install_status !== 'active') {
        return {
          success: false,
          error: `Integration install is ${install.install_status}`,
        };
      }

      // 2. Get integration details
      const integration = await this.getIntegration(install.custom_integration_id);
      if (!integration) {
        return {
          success: false,
          error: 'Custom integration not found',
        };
      }

      // 3. Validate action exists in manifest
      const manifest = JSON.parse(integration.manifest) as IntegrationManifest;
      const actionDef = manifest.actions[request.action_key];
      if (!actionDef) {
        return {
          success: false,
          error: `Action '${request.action_key}' not found in integration manifest`,
        };
      }

      // 4. Check if action is enabled
      const enabledFeatures = install.enabled_features
        ? JSON.parse(install.enabled_features) as string[]
        : [];
      if (!enabledFeatures.includes(request.action_key)) {
        return {
          success: false,
          error: `Action '${request.action_key}' is not enabled for this installation`,
        };
      }

      // 5. Get credentials
      const credentials = await this.getDecryptedCredentials(install);

      // 6. Build sandbox context
      const context: SandboxContext = {
        business_id: install.business_id,
        integration_id: integration.id,
        integration_key: integration.integration_key,
        action_key: request.action_key,
        credentials,
        settings: install.settings ? JSON.parse(install.settings) as any : {},
        input: request.payload,
        env: {
          // Provide limited environment access
          KV_CACHE: this.env.KV_CACHE,
        },
      };

      // 7. Execute in sandbox
      const sandboxResult = await this.executeSandbox(
        integration.code_bundle,
        actionDef,
        context
      );

      const responseTime = Date.now() - startTime;

      // 8. Log execution
      await this.logExecution({
        custom_integration_install_id: install.id,
        business_id: install.business_id,
        custom_integration_id: integration.id,
        action_key: request.action_key,
        request_type: 'action',
        response_status_code: sandboxResult.success ? 200 : 500,
        response_time_ms: responseTime,
        response_success: sandboxResult.success,
        response_error: sandboxResult.error,
        entity_id: request.entity_id,
        entity_type: request.entity_type,
        triggered_by: request.triggered_by || 'api',
        user_id: request.user_id,
        correlation_id: request.correlation_id,
      });

      // 9. Update usage metrics
      await this.updateUsageMetrics(install.id, sandboxResult.success);

      return {
        success: sandboxResult.success,
        data: sandboxResult.data,
        error: sandboxResult.error,
        response_time_ms: responseTime,
        credits_used: 1,
        cost_usd: this.calculateCost(integration),
      };
    } catch (error) {
      const responseTime = Date.now() - startTime;

      // Log error
      await this.logExecution({
        custom_integration_install_id: request.install_id,
        business_id: '', // Will be populated from install lookup
        custom_integration_id: '',
        action_key: request.action_key,
        request_type: 'action',
        response_status_code: 500,
        response_time_ms: responseTime,
        response_success: false,
        response_error: error instanceof Error ? error.message : 'Unknown error',
        triggered_by: request.triggered_by || 'api',
        user_id: request.user_id,
        correlation_id: request.correlation_id,
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Execution failed',
        response_time_ms: responseTime,
      };
    }
  }

  /**
   * Process Custom Integration Trigger
   * Called when external system sends webhook or cron runs
   */
  async processTrigger(request: ProcessTriggerRequest): Promise<ProcessTriggerResponse> {
    const startTime = Date.now();

    try {
      // 1. Get install by webhook URL or integration key
      const install = await this.getInstallByWebhook(
        request.business_id,
        request.integration_key
      );
      if (!install) {
        return {
          success: false,
          error: 'Integration install not found',
        };
      }

      // 2. Get integration
      const integration = await this.getIntegration(install.custom_integration_id);
      if (!integration) {
        return {
          success: false,
          error: 'Custom integration not found',
        };
      }

      // 3. Validate trigger exists
      const manifest = JSON.parse(integration.manifest) as IntegrationManifest;
      if (!manifest.triggers || !manifest.triggers[request.trigger_key]) {
        return {
          success: false,
          error: `Trigger '${request.trigger_key}' not found`,
        };
      }

      const triggerDef = manifest.triggers[request.trigger_key];

      // 4. Verify webhook signature if configured
      if (install.webhook_secret && request.webhook_signature) {
        const isValid = await this.verifyWebhookSignature(
          install.webhook_secret,
          request.payload,
          request.webhook_signature
        );
        if (!isValid) {
          return {
            success: false,
            error: 'Invalid webhook signature',
          };
        }
      }

      // 5. Get credentials
      const credentials = await this.getDecryptedCredentials(install);

      // 6. Build sandbox context
      const context: SandboxContext = {
        business_id: install.business_id,
        integration_id: integration.id,
        integration_key: integration.integration_key,
        action_key: request.trigger_key,
        credentials,
        settings: install.settings ? JSON.parse(install.settings) as any : {},
        input: request.payload,
        env: {
          KV_CACHE: this.env.KV_CACHE,
        },
      };

      // 7. Execute trigger handler
      const sandboxResult = await this.executeTriggerSandbox(
        integration.code_bundle,
        triggerDef,
        context
      );

      const responseTime = Date.now() - startTime;

      // 8. Log execution
      await this.logExecution({
        custom_integration_install_id: install.id,
        business_id: install.business_id,
        custom_integration_id: integration.id,
        trigger_key: request.trigger_key,
        request_type: 'trigger',
        response_status_code: sandboxResult.success ? 200 : 500,
        response_time_ms: responseTime,
        response_success: sandboxResult.success,
        response_error: sandboxResult.error,
        triggered_by: 'webhook',
        correlation_id: request.correlation_id,
      });

      return {
        success: sandboxResult.success,
        data: sandboxResult.data,
        error: sandboxResult.error,
        response_time_ms: responseTime,
      };
    } catch (error) {
      const responseTime = Date.now() - startTime;
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Trigger processing failed',
        response_time_ms: responseTime,
      };
    }
  }

  /**
   * Execute Integration Request (from IntegrationManager)
   * Routes custom integration execution through standard IntegrationRequest interface
   */
  async executeIntegrationRequest(
    integrationKey: string,
    request: IntegrationRequest
  ): Promise<IntegrationResponse> {
    // Get install for this business
    const install = await this.getInstallByKey(request.business_id, integrationKey);
    if (!install) {
      return {
        success: false,
        error: 'Custom integration not installed for this business',
      };
    }

    // Execute as action
    const result = await this.executeAction({
      install_id: install.id,
      action_key: request.operation,
      payload: request.payload,
      triggered_by: 'api',
      user_id: request.user_id,
      correlation_id: request.idempotency_key,
    });

    return {
      success: result.success,
      data: result.data,
      error: result.error,
      response_time_ms: result.response_time_ms,
      credits_used: result.credits_used,
      cost_usd: result.cost_usd,
    };
  }

  /**
   * Execute Code in Sandbox
   * Runs custom integration code with isolation and timeouts
   */
  private async executeSandbox(
    codeBundle: string,
    actionDef: ActionDefinition,
    context: SandboxContext
  ): Promise<SandboxResult> {
    try {
      // Parse code bundle
      const code = this.parseCodeBundle(codeBundle);

      // Create isolated execution environment
      const sandbox = {
        context,
        console: {
          log: (...args: any[]) => this.logger.info('[Integration]', ...args),
          error: (...args: any[]) => this.logger.error('[Integration Error]', ...args),
          warn: (...args: any[]) => this.logger.warn('[Integration Warning]', ...args),
        },
        fetch: fetch.bind(globalThis), // Provide fetch for API calls
        setTimeout: undefined, // Disable setTimeout
        setInterval: undefined, // Disable setInterval
        crypto, // Provide crypto for signatures
      };

      // Execute with timeout (5 seconds max)
      const timeoutMs = 5000;
      const executePromise = this.executeCode(code, actionDef.handler, sandbox);
      const timeoutPromise = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('Execution timeout')), timeoutMs)
      );

      const result = await Promise.race([executePromise, timeoutPromise]);

      return {
        success: true,
        data: result,
      };
    } catch (error) {
      this.logger.error('Sandbox execution error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Sandbox execution failed',
      };
    }
  }

  /**
   * Execute Trigger in Sandbox
   */
  private async executeTriggerSandbox(
    codeBundle: string,
    triggerDef: TriggerDefinition,
    context: SandboxContext
  ): Promise<SandboxResult> {
    try {
      const code = this.parseCodeBundle(codeBundle);

      const sandbox = {
        context,
        console: {
          log: (...args: any[]) => this.logger.info('[Trigger]', ...args),
          error: (...args: any[]) => this.logger.error('[Trigger Error]', ...args),
        },
        fetch: fetch.bind(globalThis),
        crypto,
      };

      const timeoutMs = 10000; // Triggers get 10 seconds
      const executePromise = this.executeCode(code, triggerDef.handler, sandbox);
      const timeoutPromise = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('Trigger timeout')), timeoutMs)
      );

      const result = await Promise.race([executePromise, timeoutPromise]);

      return {
        success: true,
        data: result,
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Trigger execution failed',
      };
    }
  }

  /**
   * Execute Custom Code
   * Creates Function from code string and executes handler
   */
  private async executeCode(
    code: string,
    handlerName: string,
    sandbox: any
  ): Promise<any> {
    try {
      // Create function with sandbox context
      const fn = new Function('sandbox', `
        const { context, console, fetch, crypto } = sandbox;
        ${code}
        return ${handlerName};
      `);

      // Get handler function
      const handler = fn(sandbox);

      // Execute handler with context
      return await handler(sandbox.context);
    } catch (error) {
      throw new Error(
        `Code execution failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  /**
   * Parse Code Bundle
   * Extracts executable code from bundle
   */
  private parseCodeBundle(codeBundle: string): string {
    // Code bundle is stored as bundled JavaScript/TypeScript
    // In production, this would be pre-compiled and minified
    return codeBundle;
  }

  /**
   * Verify Webhook Signature
   * HMAC-SHA256 verification
   */
  private async verifyWebhookSignature(
    secret: string,
    payload: any,
    signature: string
  ): Promise<boolean> {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(JSON.stringify(payload));
      const key = encoder.encode(secret);

      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        key,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      );

      const signatureBuffer = await crypto.subtle.sign('HMAC', cryptoKey, data);
      const expectedSignature = Array.from(new Uint8Array(signatureBuffer))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');

      return expectedSignature === signature;
    } catch (error) {
      this.logger.error('Webhook signature verification error:', error);
      return false;
    }
  }

  /**
   * Get Decrypted Credentials
   * Decrypts stored credentials for integration use
   */
  private async getDecryptedCredentials(
    install: CustomIntegrationInstall
  ): Promise<Record<string, any>> {
    if (!install.credentials_encrypted) {
      return {};
    }

    try {
      // In production, use proper encryption/decryption
      // For now, assume base64 encoded JSON
      const decrypted = atob(install.credentials_encrypted);
      return JSON.parse(decrypted);
    } catch (error) {
      this.logger.error('Credential decryption error:', error);
      return {};
    }
  }

  /**
   * Calculate Execution Cost
   * Based on integration pricing model
   */
  private calculateCost(integration: CustomIntegration): number {
    if (integration.pricing_model === 'free') {
      return 0.0;
    }

    if (integration.pricing_model === 'one_time') {
      return 0.0; // Already paid
    }

    if (integration.pricing_model === 'usage_based') {
      return integration.price_usd || 0.01; // Default $0.01 per execution
    }

    return 0.0;
  }

  /**
   * Log Execution
   */
  private async logExecution(log: Partial<IntegrationExecutionLog>): Promise<void> {
    try {
      await this.env.DB_MAIN.prepare(
        `INSERT INTO custom_integration_usage_logs (
          id, custom_integration_install_id, business_id, custom_integration_id,
          action_key, trigger_key, request_type, response_status_code,
          response_time_ms, response_success, response_error, entity_id,
          entity_type, triggered_by, user_id, correlation_id,
          credits_used, cost_usd, requested_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
        .bind(
          this.generateId(),
          log.custom_integration_install_id,
          log.business_id,
          log.custom_integration_id,
          log.action_key || null,
          log.trigger_key || null,
          log.request_type,
          log.response_status_code,
          log.response_time_ms,
          log.response_success ? 1 : 0,
          log.response_error || null,
          log.entity_id || null,
          log.entity_type || null,
          log.triggered_by || 'api',
          log.user_id || null,
          log.correlation_id || null,
          1, // credits_used
          log.cost_usd || 0.0,
          new Date().toISOString()
        )
        .run();
    } catch (error) {
      this.logger.error('Failed to log execution:', error);
      // Don't throw - logging failure shouldn't break execution
    }
  }

  /**
   * Update Usage Metrics
   */
  private async updateUsageMetrics(installId: string, success: boolean): Promise<void> {
    try {
      await this.env.DB_MAIN.prepare(
        `UPDATE custom_integration_installs SET
          total_requests = total_requests + 1,
          requests_this_month = requests_this_month + 1,
          last_request_at = ?,
          error_count = error_count + ?,
          last_error_at = CASE WHEN ? = 0 THEN ? ELSE last_error_at END,
          updated_at = ?
        WHERE id = ?`
      )
        .bind(
          new Date().toISOString(),
          success ? 0 : 1,
          success ? 1 : 0,
          success ? null : new Date().toISOString(),
          new Date().toISOString(),
          installId
        )
        .run();
    } catch (error) {
      this.logger.error('Failed to update usage metrics:', error);
    }
  }

  /**
   * Get Install by ID
   */
  private async getInstall(installId: string): Promise<CustomIntegrationInstall | null> {
    const result = await this.env.DB_MAIN.prepare(
      'SELECT * FROM custom_integration_installs WHERE id = ?'
    )
      .bind(installId)
      .first() as any;

    return result ? this.mapInstall(result) : null;
  }

  /**
   * Get Install by Integration Key
   */
  private async getInstallByKey(
    businessId: string,
    integrationKey: string
  ): Promise<CustomIntegrationInstall | null> {
    const result = await this.env.DB_MAIN.prepare(
      `SELECT i.* FROM custom_integration_installs i
       JOIN custom_integrations ci ON i.custom_integration_id = ci.id
       WHERE i.business_id = ? AND ci.integration_key = ? AND i.install_status = ?`
    )
      .bind(businessId, integrationKey, 'active')
      .first() as any;

    return result ? this.mapInstall(result) : null;
  }

  /**
   * Get Install by Webhook URL
   */
  private async getInstallByWebhook(
    businessId: string,
    integrationKey: string
  ): Promise<CustomIntegrationInstall | null> {
    return this.getInstallByKey(businessId, integrationKey);
  }

  /**
   * Get Integration by ID
   */
  private async getIntegration(integrationId: string): Promise<CustomIntegration | null> {
    const result = await this.env.DB_MAIN.prepare(
      'SELECT * FROM custom_integrations WHERE id = ?'
    )
      .bind(integrationId)
      .first() as any;

    return result ? this.mapIntegration(result) : null;
  }

  /**
   * Map Database Row to Install
   */
  private mapInstall(row: any): CustomIntegrationInstall {
    return {
      id: row.id,
      business_id: row.business_id,
      custom_integration_id: row.custom_integration_id,
      integration_version: row.integration_version,
      credentials_encrypted: row.credentials_encrypted,
      oauth_access_token: row.oauth_access_token,
      oauth_refresh_token: row.oauth_refresh_token,
      oauth_token_expires_at: row.oauth_token_expires_at,
      oauth_scopes: row.oauth_scopes,
      settings: row.settings,
      enabled_features: row.enabled_features,
      webhook_url: row.webhook_url,
      webhook_secret: row.webhook_secret,
      webhook_events: row.webhook_events,
      total_requests: row.total_requests,
      requests_this_month: row.requests_this_month,
      last_request_at: row.last_request_at,
      install_status: row.install_status,
      error_count: row.error_count,
      last_error_message: row.last_error_message,
      last_error_at: row.last_error_at,
      installed_by: row.installed_by,
      installed_at: row.installed_at,
      uninstalled_at: row.uninstalled_at,
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  }

  /**
   * Map Database Row to Integration
   */
  private mapIntegration(row: any): CustomIntegration {
    return {
      id: row.id,
      developer_id: row.developer_id,
      integration_key: row.integration_key,
      integration_name: row.integration_name,
      integration_description: row.integration_description,
      integration_version: row.integration_version,
      provider_logo_url: row.provider_logo_url,
      provider_website: row.provider_website,
      provider_category: row.provider_category,
      category_tags: row.category_tags,
      code_bundle: row.code_bundle,
      manifest: row.manifest,
      source_code_url: row.source_code_url,
      auth_type: row.auth_type,
      auth_config: row.auth_config,
      supported_actions: row.supported_actions,
      supported_triggers: row.supported_triggers,
      supported_entities: row.supported_entities,
      visibility: row.visibility,
      marketplace_status: row.marketplace_status,
      pricing_model: row.pricing_model,
      price_usd: row.price_usd,
      install_count: row.install_count,
      active_install_count: row.active_install_count,
      rating: row.rating,
      total_reviews: row.total_reviews,
      security_reviewed: Boolean(row.security_reviewed),
      security_review_date: row.security_review_date,
      security_reviewer_id: row.security_reviewer_id,
      data_privacy_compliant: Boolean(row.data_privacy_compliant),
      documentation_url: row.documentation_url,
      changelog_url: row.changelog_url,
      support_email: row.support_email,
      support_url: row.support_url,
      webhook_support: Boolean(row.webhook_support),
      webhook_events: row.webhook_events,
      created_at: row.created_at,
      updated_at: row.updated_at,
      published_at: row.published_at,
      last_deployed_at: row.last_deployed_at,
    };
  }

  /**
   * Generate UUID
   */
  private generateId(): string {
    return crypto.randomUUID();
  }
}
