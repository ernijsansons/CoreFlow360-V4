import { ConnectionConfig, Schema, CDCEvent } from '../../../types/migration';

export interface Connector {
  id: string;
  type: string;
  name: string;
  description: string;
  supportedOperations: ConnectorOperation[];
  configSchema: Record<string, any>;
}

export interface ConnectorOperation {
  name: string;
  type: 'READ' | 'WRITE' | 'SCHEMA' | 'CDC' | 'VALIDATE';
  description: string;
  parameters: Record<string, any>;
}

export interface DataSource {
  connector: Connector;
  connection: ConnectionConfig;
  schema?: Schema;
  capabilities: SourceCapabilities;
}

export interface SourceCapabilities {
  canRead: boolean;
  canWrite: boolean;
  canStream: boolean;
  canBatch: boolean;
  supportsCDC: boolean;
  supportsTransactions: boolean;
  supportsSchema: boolean;
  maxBatchSize: number;
  supportedFormats: string[];
}

export interface QueryOptions {
  limit?: number;
  offset?: number;
  filters?: Record<string, any>;
  orderBy?: string;
  orderDirection?: 'ASC' | 'DESC';
  timeout?: number;
}

export interface WriteOptions {
  batchSize?: number;
  upsert?: boolean;
  ignoreErrors?: boolean;
  returnResults?: boolean;
  timeout?: number;
}

export abstract class BaseConnector {
  protected config: ConnectionConfig;
  protected env: any;

  constructor(config: ConnectionConfig, env: any) {
    this.config = config;
    this.env = env;
  }

  abstract getConnectorInfo(): Connector;
  abstract testConnection(): Promise<boolean>;
  abstract getSchema(): Promise<Schema>;
  abstract read(table: string, options?: QueryOptions): Promise<any[]>;
  abstract write(table: string, data: any[], options?: WriteOptions): Promise<{ success: number; errors: number }>;
  abstract validateConfig(): Promise<{ valid: boolean; errors: string[] }>;

  // Optional methods for CDC-enabled connectors
  async startCDC?(callback: (event: CDCEvent) => Promise<void>): Promise<void> {
    throw new Error('CDC not supported by this connector');
  }

  async stopCDC?(): Promise<void> {
    throw new Error('CDC not supported by this connector');
  }

  // Optional method for streaming
  async *readStream?(table: string, options?: QueryOptions): AsyncGenerator<any[], void, unknown> {
    // Default implementation using batched reads
    let offset = 0;
    const batchSize = options?.limit || 1000;

    while (true) {
      const batch = await this.read(table, {
        ...options,
        limit: batchSize,
        offset
      });

      if (batch.length === 0) break;

      yield batch;
      offset += batch.length;

      if (batch.length < batchSize) break;
    }
  }

  protected normalizeConnectionString(connectionString: string): Record<string, string> {
    const params: Record<string, string> = {};
    const url = new URL(connectionString);

    params.protocol = url.protocol.replace(':', '');
    params.host = url.hostname;
    params.port = url.port;
    params.database = url.pathname.replace('/', '');
    params.username = url.username;
    params.password = url.password;

    // Parse query parameters
    url.searchParams.forEach((value, key) => {
      params[key] = value;
    });

    return params;
  }

  protected buildConnectionString(params: Record<string, string>): string {
    const { protocol, host, port, database, username, password, ...queryParams } = params;

    let connectionString = `${protocol}://`;

    if (username) {
      connectionString += username;
      if (password) {
        connectionString += `:${password}`;
      }
      connectionString += '@';
    }

    connectionString += host;
    if (port) {
      connectionString += `:${port}`;
    }

    if (database) {
      connectionString += `/${database}`;
    }

    const queryString = Object.entries(queryParams)
      .map(([key, value]) => `${key}=${encodeURIComponent(value)}`)
      .join('&');

    if (queryString) {
      connectionString += `?${queryString}`;
    }

    return connectionString;
  }

  protected encryptSensitiveData(data: string): string {
    // Simple encryption for sensitive data
    // In production, use proper encryption
    return btoa(data);
  }

  protected decryptSensitiveData(encryptedData: string): string {
    try {
      return atob(encryptedData);
    } catch {
      return encryptedData; // Return as-is if not encrypted
    }
  }

  protected validateRequiredFields(required: string[]): string[] {
    const errors: string[] = [];

    for (const field of required) {
      if (!this.config.parameters[field]) {
        errors.push(`Missing required field: ${field}`);
      }
    }

    return errors;
  }

  protected async withRetry<T>(
    operation: () => Promise<T>,
    maxRetries: number = 3,
    baseDelay: number = 1000
  ): Promise<T> {
    let lastError: Error;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error: any) {
        lastError = error as Error;

        if (attempt === maxRetries) {
          throw lastError;
        }

        // Exponential backoff
        const delay = baseDelay * Math.pow(2, attempt - 1);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }

    throw lastError!;
  }

  protected logOperation(operation: string, details: any): void {
  }

  protected logError(operation: string, error: Error): void {
  }
}

export class ConnectorRegistry {
  private connectors: Map<string, typeof BaseConnector> = new Map();
  private instances: Map<string, BaseConnector> = new Map();

  registerConnector(type: string, connectorClass: typeof BaseConnector): void {
    this.connectors.set(type, connectorClass);
  }

  getAvailableConnectors(): string[] {
    return Array.from(this.connectors.keys());
  }

  createConnector(config: ConnectionConfig, env: any): BaseConnector {
    const ConnectorClass = this.connectors.get(config.type);
    if (!ConnectorClass) {
      throw new Error(`Unknown connector type: ${config.type}`);
    }

    const cacheKey = `${config.type}:${config.id}`;
    let instance = this.instances.get(cacheKey);

    if (!instance) {
      instance = new ConnectorClass(config, env);
      this.instances.set(cacheKey, instance);
    }

    return instance;
  }

  async testAllConnectors(configs: ConnectionConfig[], env: any): Promise<Record<string, boolean>> {
    const results: Record<string, boolean> = {};

    await Promise.allSettled(
      configs.map(async config => {
        try {
          const connector = this.createConnector(config, env);
          results[config.id] = await connector.testConnection();
        } catch (error: any) {
          results[config.id] = false;
        }
      })
    );

    return results;
  }

  clearCache(): void {
    this.instances.clear();
  }
}