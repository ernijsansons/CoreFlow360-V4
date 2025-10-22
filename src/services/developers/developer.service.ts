/**
 * Developer Service
 * Manages developer accounts, registration, API keys, and quotas
 */

import { Logger } from '../../shared/logger';
import type { Env } from '../../types/env';

const logger = new Logger({ component: 'developer-service' });
import type {
  Developer,
  DeveloperTier,
  DeveloperApiKey,
  RegisterDeveloperRequest,
  RegisterDeveloperResponse,
} from './developer.types';
import { randomBytes, createHash } from 'crypto';

export class DeveloperService {
  private logger = new Logger({ component: 'DeveloperService' });

  constructor(private env: Env) {}

  /**
   * Register new developer account
   */
  async registerDeveloper(
    userId: string,
    request: RegisterDeveloperRequest
  ): Promise<RegisterDeveloperResponse> {
    try {
      // Check if user is already a developer
      const existing = await this.env.DB_MAIN.prepare(
        'SELECT id FROM developers WHERE user_id = ?'
      )
        .bind(userId)
        .first();

      if (existing) {
        return {
          success: false,
          error: 'User is already registered as a developer',
        };
      }

      // Generate API credentials
      const apiKey = this.generateApiKey();
      const apiSecret = this.generateApiSecret();
      const webhookSecret = this.generateWebhookSecret();

      // Set tier-based quotas
      const tier = request.developer_tier || 'free';
      const quotas = this.getTierQuotas(tier);

      // Insert developer record
      const developerId = this.generateId();
      await this.env.DB_MAIN.prepare(
        `INSERT INTO developers (
          id, user_id, developer_name, company_name, website_url, github_username,
          developer_tier, api_key, api_secret, webhook_secret,
          max_custom_integrations, max_installs, max_api_calls_per_day,
          status, verification_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 'unverified')`
      )
        .bind(
          developerId,
          userId,
          request.developer_name || null,
          request.company_name || null,
          request.website_url || null,
          request.github_username || null,
          tier,
          apiKey,
          apiSecret,
          webhookSecret,
          quotas.maxIntegrations,
          quotas.maxInstalls,
          quotas.maxApiCalls
        )
        .run();

      // Fetch created developer
      const developer = await this.getDeveloperById(developerId);

      return {
        success: true,
        developer: developer!,
        api_key: apiKey,
        api_secret: apiSecret,
        webhook_secret: webhookSecret,
      };
    } catch (error: any) {
      logger.error('Register developer error:', error);
      return {
        success: false,
        error: error.message || 'Failed to register developer',
      };
    }
  }

  /**
   * Get developer by ID
   */
  async getDeveloperById(developerId: string): Promise<Developer | null> {
    try {
      const result = await this.env.DB_MAIN.prepare(
        'SELECT * FROM developers WHERE id = ?'
      )
        .bind(developerId)
        .first() as any;

      if (!result) return null;

      return this.mapDeveloper(result);
    } catch (error) {
      logger.error('Get developer error:', error);
      return null;
    }
  }

  /**
   * Get developer by user ID
   */
  async getDeveloperByUserId(userId: string): Promise<Developer | null> {
    try {
      const result = await this.env.DB_MAIN.prepare(
        'SELECT * FROM developers WHERE user_id = ?'
      )
        .bind(userId)
        .first() as any;

      if (!result) return null;

      return this.mapDeveloper(result);
    } catch (error) {
      logger.error('Get developer by user error:', error);
      return null;
    }
  }

  /**
   * Get developer by API key
   */
  async getDeveloperByApiKey(apiKey: string): Promise<Developer | null> {
    try {
      const result = await this.env.DB_MAIN.prepare(
        'SELECT * FROM developers WHERE api_key = ? AND status = ?'
      )
        .bind(apiKey, 'active')
        .first() as any;

      if (!result) return null;

      return this.mapDeveloper(result);
    } catch (error) {
      logger.error('Get developer by API key error:', error);
      return null;
    }
  }

  /**
   * Update developer profile
   */
  async updateDeveloper(
    developerId: string,
    updates: Partial<Developer>
  ): Promise<{ success: boolean; developer?: Developer; error?: string }> {
    try {
      const fields: string[] = [];
      const values: any[] = [];

      if (updates.developer_name !== undefined) {
        fields.push('developer_name = ?');
        values.push(updates.developer_name);
      }
      if (updates.developer_email !== undefined) {
        fields.push('developer_email = ?');
        values.push(updates.developer_email);
      }
      if (updates.company_name !== undefined) {
        fields.push('company_name = ?');
        values.push(updates.company_name);
      }
      if (updates.website_url !== undefined) {
        fields.push('website_url = ?');
        values.push(updates.website_url);
      }
      if (updates.github_username !== undefined) {
        fields.push('github_username = ?');
        values.push(updates.github_username);
      }

      if (fields.length === 0) {
        return { success: false, error: 'No fields to update' };
      }

      fields.push('updated_at = CURRENT_TIMESTAMP');
      values.push(developerId);

      await this.env.DB_MAIN.prepare(
        `UPDATE developers SET ${fields.join(', ')} WHERE id = ?`
      )
        .bind(...values)
        .run();

      const developer = await this.getDeveloperById(developerId);
      return { success: true, developer: developer || undefined };
    } catch (error) {
      logger.error('Update developer error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to update developer',
      };
    }
  }

  /**
   * Update developer tier
   */
  async updateDeveloperTier(
    developerId: string,
    newTier: DeveloperTier
  ): Promise<boolean> {
    try {
      const quotas = this.getTierQuotas(newTier);

      await this.env.DB_MAIN.prepare(
        `UPDATE developers
         SET developer_tier = ?,
             max_custom_integrations = ?,
             max_installs = ?,
             max_api_calls_per_day = ?,
             updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`
      )
        .bind(
          newTier,
          quotas.maxIntegrations,
          quotas.maxInstalls,
          quotas.maxApiCalls,
          developerId
        )
        .run();

      return true;
    } catch (error) {
      logger.error('Update developer tier error:', error);
      return false;
    }
  }

  /**
   * Check if developer has reached quota limits
   */
  async checkQuotas(developerId: string): Promise<{
    canCreateIntegration: boolean;
    remainingIntegrations: number;
    canAcceptInstalls: boolean;
    remainingInstalls: number;
  }> {
    try {
      const developer = await this.getDeveloperById(developerId);
      if (!developer) {
        return {
          canCreateIntegration: false,
          remainingIntegrations: 0,
          canAcceptInstalls: false,
          remainingInstalls: 0,
        };
      }

      const remainingIntegrations = developer.max_custom_integrations - developer.total_integrations;
      const remainingInstalls = developer.max_installs - developer.total_installs;

      return {
        canCreateIntegration: remainingIntegrations > 0,
        remainingIntegrations: Math.max(0, remainingIntegrations),
        canAcceptInstalls: remainingInstalls > 0,
        remainingInstalls: Math.max(0, remainingInstalls),
      };
    } catch (error) {
      logger.error('Check quotas error:', error);
      return {
        canCreateIntegration: false,
        remainingIntegrations: 0,
        canAcceptInstalls: false,
        remainingInstalls: 0,
      };
    }
  }

  /**
   * Increment integration count
   */
  async incrementIntegrationCount(developerId: string): Promise<void> {
    try {
      await this.env.DB_MAIN.prepare(
        `UPDATE developers
         SET total_integrations = total_integrations + 1,
             updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`
      )
        .bind(developerId)
        .run();
    } catch (error) {
      logger.error('Increment integration count error:', error);
    }
  }

  /**
   * Increment install count
   */
  async incrementInstallCount(developerId: string): Promise<void> {
    try {
      await this.env.DB_MAIN.prepare(
        `UPDATE developers
         SET total_installs = total_installs + 1,
             updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`
      )
        .bind(developerId)
        .run();
    } catch (error) {
      logger.error('Increment install count error:', error);
    }
  }

  /**
   * Generate new API key for developer
   */
  async generateDeveloperApiKey(
    developerId: string,
    keyName: string,
    scopes?: string[]
  ): Promise<DeveloperApiKey | null> {
    try {
      const apiKey = this.generateApiKey();
      const apiKeyHash = this.hashApiKey(apiKey);
      const apiKeyPrefix = apiKey.substring(0, 8);

      const keyId = this.generateId();
      await this.env.DB_MAIN.prepare(
        `INSERT INTO developer_api_keys (
          id, developer_id, key_name, api_key, api_key_prefix, api_key_hash,
          scopes, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active')`
      )
        .bind(
          keyId,
          developerId,
          keyName,
          apiKey,
          apiKeyPrefix,
          apiKeyHash,
          scopes ? JSON.stringify(scopes) : null
        )
        .run();

      const result = await this.env.DB_MAIN.prepare(
        'SELECT * FROM developer_api_keys WHERE id = ?'
      )
        .bind(keyId)
        .first() as any;

      if (!result) return null;

      return this.mapApiKey(result);
    } catch (error) {
      logger.error('Generate API key error:', error);
      return null;
    }
  }

  /**
   * Create API Key
   */
  async createApiKey(
    developerId: string,
    request: {
      key_name: string;
      scopes?: string[];
      rate_limit_per_hour?: number;
      ip_whitelist?: string[];
      expires_at?: string;
    }
  ): Promise<{ success: boolean; api_key?: string; api_key_prefix?: string; error?: string }> {
    try {
      // Generate new API key
      const apiKey = this.generateApiKey();
      const apiKeyHash = this.hashApiKey(apiKey);
      const apiKeyPrefix = apiKey.substring(0, 12); // First 12 chars for display

      // Insert API key
      const id = this.generateId();
      await this.env.DB_MAIN.prepare(
        `INSERT INTO developer_api_keys (
          id, developer_id, key_name, api_key_hash, api_key_prefix,
          scopes, rate_limit_per_hour, ip_whitelist, expires_at,
          status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
        .bind(
          id,
          developerId,
          request.key_name,
          apiKeyHash,
          apiKeyPrefix,
          JSON.stringify(request.scopes || []),
          request.rate_limit_per_hour || 10000,
          request.ip_whitelist ? JSON.stringify(request.ip_whitelist) : null,
          request.expires_at || null,
          'active',
          new Date().toISOString(),
          new Date().toISOString()
        )
        .run();

      return {
        success: true,
        api_key: apiKey, // Return full key only once
        api_key_prefix: apiKeyPrefix,
      };
    } catch (error) {
      logger.error('Create API key error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to create API key',
      };
    }
  }

  /**
   * List API Keys
   */
  async listApiKeys(developerId: string): Promise<DeveloperApiKey[]> {
    try {
      const result = await this.env.DB_MAIN.prepare(
        `SELECT * FROM developer_api_keys
         WHERE developer_id = ?
         ORDER BY created_at DESC`
      )
        .bind(developerId)
        .all();

      return result.results.map((row) => this.mapApiKey(row));
    } catch (error) {
      logger.error('List API keys error:', error);
      return [];
    }
  }

  /**
   * Revoke API key
   */
  async revokeApiKey(keyId: string, revokedBy: string): Promise<boolean> {
    try {
      await this.env.DB_MAIN.prepare(
        `UPDATE developer_api_keys
         SET status = 'revoked',
             revoked_at = CURRENT_TIMESTAMP,
             revoked_by = ?
         WHERE id = ?`
      )
        .bind(revokedBy, keyId)
        .run();

      return true;
    } catch (error) {
      logger.error('Revoke API key error:', error);
      return false;
    }
  }

  /**
   * Validate API key
   */
  async validateApiKey(apiKey: string): Promise<DeveloperApiKey | null> {
    try {
      const apiKeyHash = this.hashApiKey(apiKey);

      const result = await this.env.DB_MAIN.prepare(
        `SELECT * FROM developer_api_keys
         WHERE api_key_hash = ? AND status = 'active'`
      )
        .bind(apiKeyHash)
        .first() as any;

      if (!result) return null;

      // Update last used timestamp
      await this.env.DB_MAIN.prepare(
        `UPDATE developer_api_keys
         SET last_used_at = CURRENT_TIMESTAMP,
             total_requests = total_requests + 1
         WHERE id = ?`
      )
        .bind(result.id)
        .run();

      return this.mapApiKey(result);
    } catch (error) {
      logger.error('Validate API key error:', error);
      return null;
    }
  }

  /**
   * Update developer activity timestamp
   */
  async updateLastActivity(developerId: string): Promise<void> {
    try {
      await this.env.DB_MAIN.prepare(
        'UPDATE developers SET last_activity_at = CURRENT_TIMESTAMP WHERE id = ?'
      )
        .bind(developerId)
        .run();
    } catch (error) {
      logger.error('Update last activity error:', error);
    }
  }

  // ============================================================
  // HELPER METHODS
  // ============================================================

  /**
   * Get tier quotas
   */
  private getTierQuotas(tier: DeveloperTier): {
    maxIntegrations: number;
    maxInstalls: number;
    maxApiCalls: number;
  } {
    switch (tier) {
      case 'free':
        return {
          maxIntegrations: 5,
          maxInstalls: 25,
          maxApiCalls: 10000,
        };
      case 'pro':
        return {
          maxIntegrations: -1, // Unlimited
          maxInstalls: 500,
          maxApiCalls: 100000,
        };
      case 'enterprise':
        return {
          maxIntegrations: -1, // Unlimited
          maxInstalls: -1, // Unlimited
          maxApiCalls: -1, // Unlimited
        };
      default:
        return {
          maxIntegrations: 5,
          maxInstalls: 25,
          maxApiCalls: 10000,
        };
    }
  }

  /**
   * Generate API key (32 chars)
   */
  private generateApiKey(): string {
    return `cf_${randomBytes(16).toString('hex')}`;
  }

  /**
   * Generate API secret (64 chars)
   */
  private generateApiSecret(): string {
    return randomBytes(32).toString('hex');
  }

  /**
   * Generate webhook secret (64 chars)
   */
  private generateWebhookSecret(): string {
    return randomBytes(32).toString('hex');
  }

  /**
   * Hash API key with SHA-256
   */
  private hashApiKey(apiKey: string): string {
    return createHash('sha256').update(apiKey).digest('hex');
  }

  /**
   * Generate UUID
   */
  private generateId(): string {
    return randomBytes(16).toString('hex');
  }

  /**
   * Map database row to Developer
   */
  private mapDeveloper(row: any): Developer {
    return {
      id: row.id,
      user_id: row.user_id,
      developer_name: row.developer_name,
      developer_email: row.developer_email,
      company_name: row.company_name,
      website_url: row.website_url,
      github_username: row.github_username,
      developer_tier: row.developer_tier,
      status: row.status,
      verification_status: row.verification_status,
      api_key: row.api_key,
      api_secret: row.api_secret,
      webhook_secret: row.webhook_secret,
      max_custom_integrations: row.max_custom_integrations,
      max_installs: row.max_installs,
      max_api_calls_per_day: row.max_api_calls_per_day,
      total_integrations: row.total_integrations,
      total_installs: row.total_installs,
      total_api_calls: row.total_api_calls,
      total_revenue_usd: row.total_revenue_usd,
      created_at: row.created_at,
      updated_at: row.updated_at,
      last_activity_at: row.last_activity_at,
    };
  }

  /**
   * Map database row to DeveloperApiKey
   */
  private mapApiKey(row: any): DeveloperApiKey {
    return {
      id: row.id,
      developer_id: row.developer_id,
      key_name: row.key_name,
      api_key: row.api_key,
      api_key_prefix: row.api_key_prefix,
      api_key_hash: row.api_key_hash,
      scopes: row.scopes ? JSON.parse(row.scopes) : undefined,
      total_requests: row.total_requests,
      last_used_at: row.last_used_at,
      ip_whitelist: row.ip_whitelist ? JSON.parse(row.ip_whitelist) : undefined,
      rate_limit_per_hour: row.rate_limit_per_hour,
      status: row.status,
      expires_at: row.expires_at,
      created_at: row.created_at,
      revoked_at: row.revoked_at,
      revoked_by: row.revoked_by,
    };
  }
}
