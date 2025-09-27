import type { Env } from '../types/env';
import type {
  Integration,
  SyncResult,
  IntegrationType,
  IntegrationStatus
} from '../types/integration';

import { BaseIntegration } from './integrations/base-integration';
import {
  MetaAdsIntegration,
  GoogleAdsIntegration,
  HubSpotIntegration
} from './integrations/marketing-integrations';

export class IntegrationHub {
  private env: Env;
  private integrations = new Map<string, BaseIntegration>();
  private syncInProgress = false;
  private syncQueue: string[] = [];

  constructor(env: Env) {
    this.env = env;
  }

  async initialize(): Promise<void> {

    // Load all configured integrations
    const configuredIntegrations = await this.loadIntegrations();

    for (const integration of configuredIntegrations) {
      const instance = await this.createIntegrationInstance(integration);
      if (instance) {
        await instance.initialize();
        this.integrations.set(integration.id, instance);
      }
    }


    // Start sync scheduler
    this.startSyncScheduler();
  }

  private async loadIntegrations(): Promise<Integration[]> {
    const db = this.env.DB_MAIN;
    const result = await db.prepare(`
      SELECT * FROM integrations
      WHERE status != 'archived'
      ORDER BY created_at DESC
    `).all();

    return result.results.map((row: any) => ({
      id: row.id as string,
      name: row.name as string,
      type: row.type as IntegrationType,
      provider: row.provider as string,
      status: row.status as IntegrationStatus,
      config: JSON.parse(row.config as string),
      lastSync: row.last_sync as string,
      nextSync: row.next_sync as string,
      metadata: row.metadata ? JSON.parse(row.metadata as string) : undefined,
      createdAt: row.created_at as string,
      updatedAt: row.updated_at as string
    }));
  }

  private async createIntegrationInstance(integration: Integration): Promise<BaseIntegration | null> {
    try {
      switch (integration.provider) {
        case 'meta':
          return new MetaAdsIntegration(this.env, integration);
        case 'google':
          return new GoogleAdsIntegration(this.env, integration);
        case 'hubspot':
          return new HubSpotIntegration(this.env, integration);
        // Add more integrations here
        default:
          return null;
      }
    } catch (error: any) {
      return null;
    }
  }

  async syncAllSystems(): Promise<SyncResult[]> {
    if (this.syncInProgress) {
      return [];
    }

    this.syncInProgress = true;
    const results: SyncResult[] = [];

    try {

      // Run all syncs in parallel
      const syncPromises = Array.from(this.integrations.values())
        .filter((integration: any) => integration.isActive())
        .map((integration: any) => integration.sync());

      const syncResults = await Promise.allSettled(syncPromises);

      for (const result of syncResults) {
        if (result.status === 'fulfilled') {
          results.push(result.value);
        } else {
        }
      }

      // Process sync results
      await this.processSyncResults(results);

      return results;
    } finally {
      this.syncInProgress = false;

      // Process queued syncs
      if (this.syncQueue.length > 0) {
        const nextSync = this.syncQueue.shift();
        if (nextSync === 'all') {
          setTimeout(() => this.syncAllSystems(), 1000);
        } else if (nextSync) {
          setTimeout(() => this.syncIntegration(nextSync), 1000);
        }
      }
    }
  }

  async syncIntegration(integrationId: string): Promise<SyncResult | null> {
    const integration = this.integrations.get(integrationId);

    if (!integration) {
      return null;
    }

    if (!integration.isActive()) {
      return null;
    }

    try {
      const result = await integration.sync();
      await this.processSyncResults([result]);
      return result;
    } catch (error: any) {
      return null;
    }
  }

  async syncBidirectional(integrationId: string): Promise<{
    inbound: SyncResult | null;
    outbound: SyncResult | null;
  }> {
    const integration = this.integrations.get(integrationId);

    if (!integration) {
      return { inbound: null, outbound: null };
    }

    const results = {
      inbound: null as SyncResult | null,
      outbound: null as SyncResult | null
    };

    try {
      // Sync inbound
      results.inbound = await integration.syncInbound();

      // Sync outbound
      results.outbound = await integration.syncOutbound();

      return results;
    } catch (error: any) {
      return results;
    }
  }

  private async processSyncResults(results: SyncResult[]): Promise<void> {
    const db = this.env.DB_MAIN;

    // Aggregate statistics
    const stats = {
      totalSynced: 0,
      totalFailed: 0,
      successfulIntegrations: 0,
      partialIntegrations: 0,
      failedIntegrations: 0
    };

    for (const result of results) {
      stats.totalSynced += result.recordsSynced;
      stats.totalFailed += result.recordsFailed;

      switch (result.status) {
        case 'success':
          stats.successfulIntegrations++;
          break;
        case 'partial':
          stats.partialIntegrations++;
          break;
        case 'failed':
          stats.failedIntegrations++;
          break;
      }
    }

    // Store sync summary
    await db.prepare(`
      INSERT INTO sync_summaries (
        total_integrations, successful, partial, failed,
        records_synced, records_failed, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      results.length,
      stats.successfulIntegrations,
      stats.partialIntegrations,
      stats.failedIntegrations,
      stats.totalSynced,
      stats.totalFailed,
      new Date().toISOString()
    ).run();

    // Trigger notifications if needed
    if (stats.failedIntegrations > 0) {
      await this.notifyIntegrationFailures(results.filter((r: any) => r.status === 'failed'));
    }

    // Update AI learning based on sync results
    await this.updateAILearning(results);
  }

  private async notifyIntegrationFailures(failedResults: SyncResult[]): Promise<void> {
    // Send notifications about failed syncs
    for (const result of failedResults) {
      const integration = await this.getIntegrationDetails(result.integrationId);

      if (integration) {
        // Send notification via configured channels

        // You could send Slack notifications, emails, etc. here
      }
    }
  }

  private async updateAILearning(results: SyncResult[]): Promise<void> {
    // Feed sync results to AI learning system
    for (const result of results) {
      if (result.status === 'success' && result.recordsSynced > 0) {
        // Trigger pattern analysis on new data
        const db = this.env.DB_CRM;
        await db.prepare(`
          INSERT INTO learning_triggers (
            trigger_type, trigger_source, data, created_at
          ) VALUES (?, ?, ?, ?)
        `).bind(
          'data_sync',
          result.integrationId,
          JSON.stringify({ recordsSynced: result.recordsSynced }),
          new Date().toISOString()
        ).run();
      }
    }
  }

  private startSyncScheduler(): void {
    // Check for integrations that need syncing every minute
    setInterval(async () => {
      const now = new Date();

      for (const [id, integration] of this.integrations) {
        const config = integration.getIntegration();

        if (config.nextSync && new Date(config.nextSync) <= now) {
          this.queueSync(id);
        }
      }
    }, 60000); // Every minute
  }

  private queueSync(integrationId: string): void {
    if (!this.syncQueue.includes(integrationId)) {
      this.syncQueue.push(integrationId);

      if (!this.syncInProgress) {
        this.processQueue();
      }
    }
  }

  private async processQueue(): Promise<void> {
    if (this.syncQueue.length === 0) return;

    const nextSync = this.syncQueue.shift();
    if (nextSync) {
      await this.syncIntegration(nextSync);

      // Process next item in queue
      if (this.syncQueue.length > 0) {
        setTimeout(() => this.processQueue(), 1000);
      }
    }
  }

  // Public API

  async addIntegration(integration: Integration): Promise<void> {
    const db = this.env.DB_MAIN;

    // Store in database
    await db.prepare(`
      INSERT INTO integrations (
        id, name, type, provider, status, config,
        metadata, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      integration.id,
      integration.name,
      integration.type,
      integration.provider,
      integration.status,
      JSON.stringify(integration.config),
      integration.metadata ? JSON.stringify(integration.metadata) : null,
      integration.createdAt,
      integration.updatedAt
    ).run();

    // Create instance and initialize
    const instance = await this.createIntegrationInstance(integration);
    if (instance) {
      await instance.initialize();
      this.integrations.set(integration.id, instance);
    }
  }

  async updateIntegration(integrationId: string, updates: Partial<Integration>): Promise<void> {
    const integration = this.integrations.get(integrationId);
    if (!integration) {
      throw new Error(`Integration not found: ${integrationId}`);
    }

    const db = this.env.DB_MAIN;

    // Update database
    const fields = [];
    const values = [];

    if (updates.config) {
      fields.push('config = ?');
      values.push(JSON.stringify(updates.config));
    }
    if (updates.status) {
      fields.push('status = ?');
      values.push(updates.status);
    }
    if (updates.metadata) {
      fields.push('metadata = ?');
      values.push(JSON.stringify(updates.metadata));
    }

    fields.push('updated_at = ?');
    values.push(new Date().toISOString());
    values.push(integrationId);

    await db.prepare(`
      UPDATE integrations
      SET ${fields.join(', ')}
      WHERE id = ?
    `).bind(...values).run();

    // Reinitialize if config changed
    if (updates.config) {
      await integration.disconnect();
      await integration.initialize();
    }
  }

  async removeIntegration(integrationId: string): Promise<void> {
    const integration = this.integrations.get(integrationId);
    if (integration) {
      await integration.disconnect();
      this.integrations.delete(integrationId);
    }

    const db = this.env.DB_MAIN;
    await db.prepare(`
      UPDATE integrations
      SET status = 'archived', updated_at = ?
      WHERE id = ?
    `).bind(new Date().toISOString(), integrationId).run();
  }

  async testIntegration(integrationId: string): Promise<boolean> {
    const integration = this.integrations.get(integrationId);
    if (!integration) {
      throw new Error(`Integration not found: ${integrationId}`);
    }

    return await integration.testConnection();
  }

  getActiveIntegrations(): Integration[] {
    return Array.from(this.integrations.values())
      .filter((i: any) => i.isActive())
      .map((i: any) => i.getIntegration());
  }

  async getIntegrationDetails(integrationId: string): Promise<Integration | null> {
    const integration = this.integrations.get(integrationId);
    return integration ? integration.getIntegration() : null;
  }

  async getIntegrationsByType(type: IntegrationType): Promise<Integration[]> {
    return Array.from(this.integrations.values())
      .filter((i: any) => i.getIntegration().type === type)
      .map((i: any) => i.getIntegration());
  }

  async getSyncHistory(integrationId?: string, limit: number = 10): Promise<any[]> {
    const db = this.env.DB_MAIN;

    let query = `
      SELECT * FROM sync_logs
      ${integrationId ? 'WHERE integration_id = ?' : ''}
      ORDER BY created_at DESC
      LIMIT ?
    `;

    const params = integrationId ? [integrationId, limit] : [limit];
    const result = await db.prepare(query).bind(...params).all();

    return result.results;
  }

  async getSyncStatistics(timeframe: string = '30d'): Promise<any> {
    const db = this.env.DB_MAIN;

    // Parse timeframe
    let daysBack = 30;
    if (timeframe.endsWith('d')) {
      daysBack = parseInt(timeframe.slice(0, -1));
    }

    const stats = await db.prepare(`
      SELECT
        COUNT(DISTINCT integration_id) as total_integrations,
        COUNT(*) as total_syncs,
        SUM(records_synced) as total_records_synced,
        SUM(records_failed) as total_records_failed,
        AVG(duration) as avg_sync_duration,
        COUNT(CASE WHEN status = 'success' THEN 1 END) as successful_syncs,
        COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_syncs
      FROM sync_logs
      WHERE created_at >= datetime('now', '-${daysBack} days')
    `).first();

    return stats;
  }
}