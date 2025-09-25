import type { Env } from '../../types/env';
import type {
  Integration,
  IntegrationConfig,
  SyncResult,
  SyncError,
  IntegrationType
} from '../../types/integration';

export abstract class BaseIntegration {
  protected env: Env;
  protected integration: Integration;
  protected isConnected = false;

  constructor(env: Env, integration: Integration) {
    this.env = env;
    this.integration = integration;
  }

  // Abstract methods that must be implemented by each integration
  abstract connect(): Promise<boolean>;
  abstract disconnect(): Promise<void>;
  abstract testConnection(): Promise<boolean>;
  abstract sync(): Promise<SyncResult>;
  abstract syncInbound(): Promise<SyncResult>;
  abstract syncOutbound(): Promise<SyncResult>;
  abstract getWebhookUrl(): string | undefined;

  // Common methods
  async initialize(): Promise<void> {
    this.isConnected = await this.connect();

    if (this.isConnected) {
      await this.updateStatus('connected');
    } else {
      await this.updateStatus('error');
    }
  }

  protected async updateStatus(status: Integration['status']): Promise<void> {
    this.integration.status = status;
    this.integration.updatedAt = new Date().toISOString();

    const db = this.env.DB_MAIN;
    await db.prepare(`
      UPDATE integrations
      SET status = ?, updated_at = ?
      WHERE id = ?
    `).bind(status, this.integration.updatedAt, this.integration.id).run();
  }

  protected async updateLastSync(): Promise<void> {
    this.integration.lastSync = new Date().toISOString();

    if (this.integration.config.syncInterval) {
      const nextSync = new Date();
      nextSync.setMinutes(nextSync.getMinutes() + this.integration.config.syncInterval);
      this.integration.nextSync = nextSync.toISOString();
    }

    const db = this.env.DB_MAIN;
    await db.prepare(`
      UPDATE integrations
      SET last_sync = ?, next_sync = ?
      WHERE id = ?
    `).bind(
      this.integration.lastSync,
      this.integration.nextSync || null,
      this.integration.id
    ).run();
  }

  protected async logSyncResult(result: SyncResult): Promise<void> {
    const db = this.env.DB_MAIN;
    await db.prepare(`
      INSERT INTO sync_logs (
        integration_id, status, records_synced, records_failed,
        errors, start_time, end_time, duration, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      result.integrationId,
      result.status,
      result.recordsSynced,
      result.recordsFailed,
      JSON.stringify(result.errors || []),
      result.startTime,
      result.endTime,
      result.duration,
      new Date().toISOString()
    ).run();
  }

  protected async applyFieldMappings(data: any): Promise<any> {
    if (!this.integration.config.fieldMappings) {
      return data;
    }

    const mapped: any = {};

    for (const mapping of this.integration.config.fieldMappings) {
      const sourceValue = this.getNestedValue(data, mapping.sourceField);

      if (sourceValue !== undefined || mapping.defaultValue !== undefined) {
        let value = sourceValue !== undefined ? sourceValue : mapping.defaultValue;

        if (mapping.transform) {
          value = await this.applyTransform(value, mapping.transform);
        }

        this.setNestedValue(mapped, mapping.targetField, value);
      }
    }

    return mapped;
  }

  protected getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((current, key) => current?.[key], obj);
  }

  protected setNestedValue(obj: any, path: string, value: any): void {
    const keys = path.split('.');
    const lastKey = keys.pop()!;

    const target = keys.reduce((current, key) => {
      if (!current[key]) {
        current[key] = {};
      }
      return current[key];
    }, obj);

    target[lastKey] = value;
  }

  protected async applyTransform(value: any, transform: string): Promise<any> {
    // Simple transformations
    switch (transform) {
      case 'uppercase':
        return String(value).toUpperCase();
      case 'lowercase':
        return String(value).toLowerCase();
      case 'trim':
        return String(value).trim();
      case 'number':
        return Number(value);
      case 'string':
        return String(value);
      case 'boolean':
        return Boolean(value);
      case 'json':
        return JSON.parse(String(value));
      default:
        // Custom transform function
        if (transform.startsWith('function')) {
          try {
            const fn = new Function('value', transform);
            return fn(value);
          } catch (error) {
            return value;
          }
        }
        return value;
    }
  }

  protected async makeApiRequest(
    url: string,
    method: string = 'GET',
    data?: any,
    headers?: Record<string, string>
  ): Promise<any> {
    try {
      const response = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          ...headers
        },
        body: data ? JSON.stringify(data) : undefined
      });

      if (!response.ok) {
        throw new Error(`API request failed: ${response.status} ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      throw error;
    }
  }

  protected createSyncError(recordId: string | undefined, error: any): SyncError {
    return {
      recordId,
      error: error instanceof Error ? error.message : String(error),
      timestamp: new Date().toISOString()
    };
  }

  public getIntegration(): Integration {
    return this.integration;
  }

  public isActive(): boolean {
    return this.isConnected && this.integration.status === 'connected';
  }
}