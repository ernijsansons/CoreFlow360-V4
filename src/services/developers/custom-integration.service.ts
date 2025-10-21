/**
 * Custom Integration Service
 * Manages custom integration lifecycle: create, update, publish, delete
 */

import { Logger } from '../../shared/logger';
import type { Env } from '../../types/env';

const logger = new Logger({ component: 'custom-integration-service' });
import type {
  CustomIntegration,
  IntegrationManifest,
  CreateCustomIntegrationRequest,
  CreateCustomIntegrationResponse,
  MarketplaceStatus,
  IntegrationVisibility,
} from './developer.types';
import { randomBytes } from 'crypto';

export class CustomIntegrationService {
  private logger = new Logger({ component: 'CustomIntegrationService' });

  constructor(private env: Env) {}

  /**
   * Create new custom integration
   */
  async createIntegration(
    developerId: string,
    request: CreateCustomIntegrationRequest
  ): Promise<CreateCustomIntegrationResponse> {
    try {
      // Validate integration key format
      if (!this.isValidIntegrationKey(request.integration_key)) {
        return {
          success: false,
          error: 'Integration key must be lowercase alphanumeric with underscores only',
        };
      }

      // Check if key already exists
      const existing = await this.env.DB_MAIN.prepare(
        'SELECT id FROM custom_integrations WHERE integration_key = ?'
      )
        .bind(request.integration_key)
        .first();

      if (existing) {
        return {
          success: false,
          error: 'Integration key already exists',
        };
      }

      // Validate manifest
      const manifestValidation = this.validateManifest(JSON.parse(request.manifest) as IntegrationManifest);
      if (!manifestValidation.valid) {
        return {
          success: false,
          error: `Invalid manifest: ${manifestValidation.error}`,
        };
      }

      // Create integration
      const integrationId = this.generateId();
      await this.env.DB_MAIN.prepare(
        `INSERT INTO custom_integrations (
          id, developer_id, integration_key, integration_name,
          integration_description, integration_version,
          code_bundle, manifest, auth_type, auth_config,
          provider_category, category_tags, visibility,
          marketplace_status, pricing_model, price_usd,
          webhook_support
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
        .bind(
          integrationId,
          developerId,
          request.integration_key,
          request.integration_name,
          request.integration_description || null,
          request.integration_version || '1.0.0',
          request.code_bundle,
          JSON.stringify(request.manifest),
          request.auth_type,
          request.auth_config ? JSON.stringify(request.auth_config) : null,
          request.provider_category || null,
          request.category_tags ? JSON.stringify(request.category_tags) : null,
          request.visibility || 'private',
          'draft',
          request.pricing_model || 'free',
          request.price_usd || 0.0,
          JSON.parse(request.manifest).triggers ? 1 : 0
        )
        .run();

      // Update developer integration count
      await this.env.DB_MAIN.prepare(
        'UPDATE developers SET total_integrations = total_integrations + 1 WHERE id = ?'
      )
        .bind(developerId)
        .run();

      // Fetch created integration
      const integration = await this.getIntegrationById(integrationId);

      return {
        success: true,
        integration: integration!,
      };
    } catch (error: any) {
      this.logger.error('Create integration error:', error);
      return {
        success: false,
        error: error.message || 'Failed to create integration',
      };
    }
  }

  /**
   * Get integration by ID
   */
  async getIntegrationById(integrationId: string): Promise<CustomIntegration | null> {
    try {
      const result = await this.env.DB_MAIN.prepare(
        'SELECT * FROM custom_integrations WHERE id = ?'
      )
        .bind(integrationId)
        .first() as any;

      if (!result) return null;

      return this.mapIntegration(result);
    } catch (error) {
      this.logger.error('Get integration error:', error);
      return null;
    }
  }

  /**
   * Get integration by key
   */
  async getIntegrationByKey(integrationKey: string): Promise<CustomIntegration | null> {
    try {
      const result = await this.env.DB_MAIN.prepare(
        'SELECT * FROM custom_integrations WHERE integration_key = ?'
      )
        .bind(integrationKey)
        .first() as any;

      if (!result) return null;

      return this.mapIntegration(result);
    } catch (error) {
      this.logger.error('Get integration by key error:', error);
      return null;
    }
  }

  /**
   * List developer's integrations
   */
  async listDeveloperIntegrations(
    developerId: string,
    filters?: {
      visibility?: IntegrationVisibility;
      status?: MarketplaceStatus;
      limit?: number;
      offset?: number;
    }
  ): Promise<CustomIntegration[]> {
    try {
      let query = 'SELECT * FROM custom_integrations WHERE developer_id = ?';
      const params: any[] = [developerId];

      if (filters?.visibility) {
        query += ' AND visibility = ?';
        params.push(filters.visibility);
      }

      if (filters?.status) {
        query += ' AND marketplace_status = ?';
        params.push(filters.status);
      }

      query += ' ORDER BY created_at DESC';

      if (filters?.limit) {
        query += ' LIMIT ?';
        params.push(filters.limit);

        if (filters?.offset) {
          query += ' OFFSET ?';
          params.push(filters.offset);
        }
      }

      const result = await this.env.DB_MAIN.prepare(query).bind(...params).all();

      return (result.results as any[] || []).map(row => this.mapIntegration(row));
    } catch (error) {
      this.logger.error('List developer integrations error:', error);
      return [];
    }
  }

  /**
   * List published marketplace integrations
   */
  async listMarketplaceIntegrations(filters?: {
    category?: string;
    search?: string;
    limit?: number;
    offset?: number;
  }): Promise<CustomIntegration[]> {
    try {
      let query = `
        SELECT * FROM custom_integrations
        WHERE marketplace_status = 'published'
        AND visibility = 'public'
      `;
      const params: any[] = [];

      if (filters?.category) {
        query += ' AND provider_category = ?';
        params.push(filters.category);
      }

      if (filters?.search) {
        query += ` AND (
          integration_name LIKE ? OR
          integration_description LIKE ? OR
          integration_key LIKE ?
        )`;
        const searchTerm = `%${filters.search}%`;
        params.push(searchTerm, searchTerm, searchTerm);
      }

      query += ' ORDER BY install_count DESC, rating DESC';

      if (filters?.limit) {
        query += ' LIMIT ?';
        params.push(filters.limit);

        if (filters?.offset) {
          query += ' OFFSET ?';
          params.push(filters.offset);
        }
      }

      const result = await this.env.DB_MAIN.prepare(query).bind(...params).all();

      return (result.results as any[] || []).map(row => this.mapIntegration(row));
    } catch (error) {
      this.logger.error('List marketplace integrations error:', error);
      return [];
    }
  }

  /**
   * Update integration
   */
  async updateIntegration(
    integrationId: string,
    developerId: string,
    updates: Partial<CustomIntegration>
  ): Promise<boolean> {
    try {
      // Verify ownership
      const integration = await this.getIntegrationById(integrationId);
      if (!integration || integration.developer_id !== developerId) {
        return false;
      }

      const fields: string[] = [];
      const values: any[] = [];

      if (updates.integration_name !== undefined) {
        fields.push('integration_name = ?');
        values.push(updates.integration_name);
      }

      if (updates.integration_description !== undefined) {
        fields.push('integration_description = ?');
        values.push(updates.integration_description);
      }

      if (updates.code_bundle !== undefined) {
        fields.push('code_bundle = ?');
        values.push(updates.code_bundle);
      }

      if (updates.manifest !== undefined) {
        const manifestValidation = this.validateManifest(JSON.parse(updates.manifest) as IntegrationManifest);
        if (!manifestValidation.valid) {
          return false;
        }
        fields.push('manifest = ?');
        values.push(JSON.stringify(updates.manifest));
      }

      if (updates.provider_category !== undefined) {
        fields.push('provider_category = ?');
        values.push(updates.provider_category);
      }

      if (updates.category_tags !== undefined) {
        fields.push('category_tags = ?');
        values.push(JSON.stringify(updates.category_tags));
      }

      if (updates.visibility !== undefined) {
        fields.push('visibility = ?');
        values.push(updates.visibility);
      }

      if (updates.pricing_model !== undefined) {
        fields.push('pricing_model = ?');
        values.push(updates.pricing_model);
      }

      if (updates.price_usd !== undefined) {
        fields.push('price_usd = ?');
        values.push(updates.price_usd);
      }

      if (fields.length === 0) return false;

      fields.push('updated_at = CURRENT_TIMESTAMP');
      values.push(integrationId);

      await this.env.DB_MAIN.prepare(
        `UPDATE custom_integrations SET ${fields.join(', ')} WHERE id = ?`
      )
        .bind(...values)
        .run();

      return true;
    } catch (error) {
      this.logger.error('Update integration error:', error);
      return false;
    }
  }

  /**
   * Submit integration for marketplace review
   */
  async submitForReview(
    integrationId: string,
    developerId: string
  ): Promise<{ success: boolean; error?: string }> {
    try {
      const integration = await this.getIntegrationById(integrationId);

      if (!integration || integration.developer_id !== developerId) {
        return { success: false, error: 'Integration not found' };
      }

      if (integration.marketplace_status !== 'draft') {
        return { success: false, error: 'Integration already submitted or published' };
      }

      if (integration.visibility !== 'public') {
        return { success: false, error: 'Integration must be public to submit to marketplace' };
      }

      // Validate completeness
      if (!integration.integration_description) {
        return { success: false, error: 'Integration description is required' };
      }

      if (!integration.provider_category) {
        return { success: false, error: 'Provider category is required' };
      }

      // Update status
      await this.env.DB_MAIN.prepare(
        `UPDATE custom_integrations
         SET marketplace_status = 'review',
             updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`
      )
        .bind(integrationId)
        .run();

      return { success: true };
    } catch (error: any) {
      this.logger.error('Submit for review error:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Publish integration (admin/review process)
   */
  async publishIntegration(
    integrationId: string,
    reviewerId: string
  ): Promise<boolean> {
    try {
      await this.env.DB_MAIN.prepare(
        `UPDATE custom_integrations
         SET marketplace_status = 'published',
             published_at = CURRENT_TIMESTAMP,
             security_reviewed = 1,
             security_review_date = CURRENT_TIMESTAMP,
             security_reviewer_id = ?,
             updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`
      )
        .bind(reviewerId, integrationId)
        .run();

      return true;
    } catch (error) {
      this.logger.error('Publish integration error:', error);
      return false;
    }
  }

  /**
   * Reject integration
   */
  async rejectIntegration(
    integrationId: string,
    reviewerId: string,
    reason: string
  ): Promise<boolean> {
    try {
      await this.env.DB_MAIN.prepare(
        `UPDATE custom_integrations
         SET marketplace_status = 'rejected',
             security_reviewer_id = ?,
             updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`
      )
        .bind(reviewerId, integrationId)
        .run();

      // TODO: Send notification to developer with rejection reason

      return true;
    } catch (error) {
      this.logger.error('Reject integration error:', error);
      return false;
    }
  }

  /**
   * Deprecate integration
   */
  async deprecateIntegration(
    integrationId: string,
    developerId: string
  ): Promise<boolean> {
    try {
      const integration = await this.getIntegrationById(integrationId);

      if (!integration || integration.developer_id !== developerId) {
        return false;
      }

      await this.env.DB_MAIN.prepare(
        `UPDATE custom_integrations
         SET marketplace_status = 'deprecated',
             updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`
      )
        .bind(integrationId)
        .run();

      return true;
    } catch (error) {
      this.logger.error('Deprecate integration error:', error);
      return false;
    }
  }

  /**
   * Delete integration
   */
  async deleteIntegration(
    integrationId: string,
    developerId: string
  ): Promise<boolean> {
    try {
      const integration = await this.getIntegrationById(integrationId);

      if (!integration || integration.developer_id !== developerId) {
        return false;
      }

      // Check if there are active installations
      const installs = await this.env.DB_MAIN.prepare(
        `SELECT COUNT(*) as count FROM custom_integration_installs
         WHERE custom_integration_id = ? AND install_status = 'active'`
      )
        .bind(integrationId)
        .first() as any;

      if (installs && installs.count > 0) {
        return false; // Cannot delete if active installs exist
      }

      // Delete integration (cascade will handle related records)
      await this.env.DB_MAIN.prepare(
        'DELETE FROM custom_integrations WHERE id = ?'
      )
        .bind(integrationId)
        .run();

      // Decrement developer integration count
      await this.env.DB_MAIN.prepare(
        'UPDATE developers SET total_integrations = total_integrations - 1 WHERE id = ?'
      )
        .bind(developerId)
        .run();

      return true;
    } catch (error) {
      this.logger.error('Delete integration error:', error);
      return false;
    }
  }

  /**
   * Increment install count
   */
  async incrementInstallCount(integrationId: string): Promise<void> {
    try {
      await this.env.DB_MAIN.prepare(
        `UPDATE custom_integrations
         SET install_count = install_count + 1,
             active_install_count = active_install_count + 1,
             updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`
      )
        .bind(integrationId)
        .run();
    } catch (error) {
      this.logger.error('Increment install count error:', error);
    }
  }

  /**
   * Decrement install count
   */
  async decrementInstallCount(integrationId: string): Promise<void> {
    try {
      await this.env.DB_MAIN.prepare(
        `UPDATE custom_integrations
         SET active_install_count = active_install_count - 1,
             updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`
      )
        .bind(integrationId)
        .run();
    } catch (error) {
      this.logger.error('Decrement install count error:', error);
    }
  }

  /**
   * Update integration rating
   */
  async updateRating(integrationId: string): Promise<void> {
    try {
      // Calculate average rating from reviews
      const result = await this.env.DB_MAIN.prepare(
        `SELECT AVG(rating) as avg_rating, COUNT(*) as total_reviews
         FROM custom_integration_reviews
         WHERE custom_integration_id = ?`
      )
        .bind(integrationId)
        .first() as any;

      if (result) {
        await this.env.DB_MAIN.prepare(
          `UPDATE custom_integrations
           SET rating = ?,
               total_reviews = ?,
               updated_at = CURRENT_TIMESTAMP
           WHERE id = ?`
        )
          .bind(result.avg_rating, result.total_reviews, integrationId)
          .run();
      }
    } catch (error) {
      this.logger.error('Update rating error:', error);
    }
  }

  // ============================================================
  // HELPER METHODS
  // ============================================================

  /**
   * Validate integration key format
   */
  private isValidIntegrationKey(key: string): boolean {
    return /^[a-z0-9_]+$/.test(key);
  }

  /**
   * Validate integration manifest
   */
  private validateManifest(manifest: IntegrationManifest): {
    valid: boolean;
    error?: string;
  } {
    if (!manifest.version) {
      return { valid: false, error: 'Manifest version is required' };
    }

    if (!manifest.actions || Object.keys(manifest.actions).length === 0) {
      return { valid: false, error: 'At least one action is required' };
    }

    if (!manifest.auth || !manifest.auth.type) {
      return { valid: false, error: 'Auth configuration is required' };
    }

    // Validate actions
    for (const [key, action] of Object.entries(manifest.actions)) {
      if (!action.key || !action.name || !action.description) {
        return {
          valid: false,
          error: `Action '${key}' is missing required fields`,
        };
      }
    }

    // Validate triggers if present
    if (manifest.triggers) {
      for (const [key, trigger] of Object.entries(manifest.triggers)) {
        if (!trigger.key || !trigger.name || !trigger.type) {
          return {
            valid: false,
            error: `Trigger '${key}' is missing required fields`,
          };
        }
      }
    }

    return { valid: true };
  }

  /**
   * Generate UUID
   */
  private generateId(): string {
    return randomBytes(16).toString('hex');
  }

  /**
   * Map database row to CustomIntegration
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
      category_tags: row.category_tags ? JSON.parse(row.category_tags) : undefined,
      code_bundle: row.code_bundle,
      manifest: JSON.parse(row.manifest),
      source_code_url: row.source_code_url,
      auth_type: row.auth_type,
      auth_config: row.auth_config ? JSON.parse(row.auth_config) : undefined,
      supported_actions: row.supported_actions ? JSON.parse(row.supported_actions) : undefined,
      supported_triggers: row.supported_triggers ? JSON.parse(row.supported_triggers) : undefined,
      supported_entities: row.supported_entities ? JSON.parse(row.supported_entities) : undefined,
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
      webhook_events: row.webhook_events ? JSON.parse(row.webhook_events) : undefined,
      created_at: row.created_at,
      updated_at: row.updated_at,
      published_at: row.published_at,
      last_deployed_at: row.last_deployed_at,
    };
  }
}
