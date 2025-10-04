import { Schema, Table, Column, ConnectionConfig, CDCEvent } from '../../../types/migration';
import { BaseConnector, Connector, QueryOptions, WriteOptions } from './index';

interface APISpec {
  type: 'REST' | 'GraphQL' | 'SOAP';
  baseUrl: string;
  endpoints: Record<string, EndpointConfig>;
  authentication: AuthConfig;
  pagination?: PaginationConfig;
  rateLimit?: RateLimitConfig;
}

interface EndpointConfig {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  path: string;
  parameters?: Record<string, any>;
  headers?: Record<string, string>;
  body?: any;
  responseFormat?: 'json' | 'xml' | 'csv';
  dataPath?: string; // JSONPath to extract data from response
}

interface AuthConfig {
  type: 'none' | 'basic' | 'bearer' | 'oauth2' | 'api-key';
  username?: string;
  password?: string;
  token?: string;
  apiKey?: string;
  apiKeyHeader?: string;
  oauthUrl?: string;
  clientId?: string;
  clientSecret?: string;
}

interface PaginationConfig {
  type: 'offset' | 'cursor' | 'page';
  limitParam: string;
  offsetParam?: string;
  pageParam?: string;
  cursorParam?: string;
  pageSize: number;
  maxPages?: number;
}

interface RateLimitConfig {
  requestsPerSecond: number;
  burstLimit?: number;
  retryAfterHeader?: string;
}

interface WebhookConfig {
  url: string;
  secret?: string;
  events: string[];
  headers?: Record<string, string>;
}

export class APIConnector extends BaseConnector {
  private spec: APISpec | null = null;
  private authToken: string | null = null;
  private rateLimiter: RateLimiter;
  private webhookListeners: Map<string, (data: any) => Promise<void>> = new Map();

  constructor(config: ConnectionConfig, env: any) {
    super(config, env);
    this.rateLimiter = new RateLimiter({
      requestsPerSecond: config.parameters.rateLimit?.requestsPerSecond || 10,
      burstLimit: config.parameters.rateLimit?.burstLimit || 50
    });
  }

  getConnectorInfo(): Connector {
    return {
      id: 'api',
      type: 'API',
      name: 'API Connector',
      description: 'Connects to REST, GraphQL, and SOAP APIs',
      supportedOperations: [
        {
          name: 'read',
          type: 'READ',
          description: 'Read data from API endpoints',
          parameters: { endpoint: 'string', method: 'string' }
        },
        {
          name: 'write',
          type: 'WRITE',
          description: 'Write data to API endpoints',
          parameters: { endpoint: 'string', method: 'string', data: 'any' }
        },
        {
          name: 'schema',
          type: 'SCHEMA',
          description: 'Discover API schema',
          parameters: {}
        },
        {
          name: 'webhook',
          type: 'CDC',
          description: 'Set up webhook listeners for real-time data',
          parameters: { webhookUrl: 'string', events: 'array' }
        }
      ],
      configSchema: {
        url: { type: 'string', required: true },
        apiType: { type: 'string', enum: ['REST', 'GraphQL', 'SOAP'], required: false },
        apiKey: { type: 'string', required: false },
        apiKeyHeader: { type: 'string', required: false },
        username: { type: 'string', required: false },
        password: { type: 'string', required: false },
        token: { type: 'string', required: false },
        pagination: { type: 'object', required: false },
        rateLimit: { type: 'object', required: false },
        timeout: { type: 'number', required: false }
      }
    };
  }

  async testConnection(): Promise<boolean> {
    try {
      await this.ensureAuthentication();

      // Test with a simple GET request to the base URL or health endpoint
      const testUrl = this.getTestEndpoint();
      const response = await this.makeRequest('GET', testUrl);

      return response.status < 400;
    } catch (error: any) {
      this.logError('testConnection', error as Error);
      return false;
    }
  }

  async getSchema(): Promise<Schema> {
    await this.ensureAuthentication();

    const schema: Schema = {
      name: this.getAPIName(),
      tables: [],
      version: '1.0',
      metadata: { type: 'API', baseUrl: this.config.url }
    };

    try {
      // Try to discover schema through different methods
      if (this.config.parameters.apiType === 'GraphQL') {
        schema.tables = await this.discoverGraphQLSchema();
      } else if (this.config.parameters.apiType === 'SOAP') {
        schema.tables = await this.discoverSOAPSchema();
      } else {
        // REST API - try to discover endpoints
        schema.tables = await this.discoverRESTSchema();
      }
    } catch (error: any) {
      this.logError('getSchema', error as Error);
      // Return empty schema if discovery fails
    }

    return schema;
  }

  async read(table: string, options: QueryOptions = {}): Promise<any[]> {
    await this.ensureAuthentication();

    const endpoint = this.getEndpointConfig(table, 'GET');
    let allData: any[] = [];

    if (this.config.parameters.pagination) {
      // Handle paginated responses
      allData = await this.readPaginated(endpoint, options);
    } else {
      // Single request
      const data = await this.readSingle(endpoint, options);
      allData = Array.isArray(data) ? data : [data];
    }

    // Apply client-side filtering and sorting if needed
    return this.processData(allData, options);
  }

  async write(table: string, data: any[], options: WriteOptions = {}): Promise<{ success: number; errors: number }> {
    await this.ensureAuthentication();

    let success = 0;
    let errors = 0;

    const batchSize = options.batchSize || 1;

    for (let i = 0; i < data.length; i += batchSize) {
      const batch = data.slice(i, i + batchSize);

      try {
        if (batchSize === 1) {
          // Single record
          await this.writeSingle(table, batch[0], options);
          success++;
        } else {
          // Batch operation
          const result = await this.writeBatch(table, batch, options);
          success += result.success;
          errors += result.errors;
        }

        // Rate limiting
        await this.rateLimiter.wait();

      } catch (error: any) {
        if (options.ignoreErrors) {
          errors += batch.length;
        } else {
          throw error;
        }
      }
    }

    return { success, errors };
  }

  async validateConfig(): Promise<{ valid: boolean; errors: string[] }> {
    const errors: string[] = [];

    if (!this.config.url) {
      errors.push('API URL is required');
    } else {
      try {
        new URL(this.config.url);
      } catch {
        errors.push('Invalid API URL format');
      }
    }

    // Validate authentication config
    const authType = this.config.parameters.authType || 'none';
    switch (authType) {
      case 'basic':
        if (!this.config.username || !this.config.password) {
          errors.push('Username and password required for basic auth');
        }
        break;
      case 'bearer':
        if (!this.config.parameters.token) {
          errors.push('Token required for bearer auth');
        }
        break;
      case 'api-key':
        if (!this.config.apiKey) {
          errors.push('API key required for API key auth');
        }
        break;
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  async startCDC(callback: (event: CDCEvent) => Promise<void>): Promise<void> {
    // Set up webhook listener for real-time events
    const webhookConfig = this.config.parameters.webhook as WebhookConfig;

    if (!webhookConfig) {
      throw new Error('Webhook configuration required for CDC');
    }

    const listenerId = crypto.randomUUID();
    this.webhookListeners.set(listenerId, async (data: any) => {
      // Convert webhook data to CDCEvent format
      const event: CDCEvent = {
        id: data.id || crypto.randomUUID(),
        timestamp: new Date(data.timestamp || Date.now()),
        operation: this.mapWebhookOperation(data.action || data.operation),
        table: data.resource || data.table || 'unknown',
        oldData: data.previous || data.old,
        newData: data.current || data.new || data.data,
        primaryKey: { id: data.id },
        metadata: {
          webhook: true,
          source: data.source,
          event: data.event
        }
      };

      await callback(event);
    });
  }

  async stopCDC(): Promise<void> {
    this.webhookListeners.clear();
  }

  async handleWebhook(payload: any, headers: Record<string, string>): Promise<void> {
    // Validate webhook signature if configured
    const webhookConfig = this.config.parameters.webhook as WebhookConfig;

    if (webhookConfig?.secret) {
      const isValid = await this.validateWebhookSignature(payload, headers, webhookConfig.secret);
      if (!isValid) {
        throw new Error('Invalid webhook signature');
      }
    }

    // Notify all listeners
    for (const listener of this.webhookListeners.values()) {
      try {
        await listener(payload);
      } catch (error: any) {
        this.logError('webhook listener', error as Error);
      }
    }
  }

  private async ensureAuthentication(): Promise<void> {
    const authType = this.config.parameters.authType || 'none';

    switch (authType) {
      case 'oauth2':
        if (!this.authToken || this.isTokenExpired()) {
          await this.refreshOAuth2Token();
        }
        break;
      case 'bearer':
        this.authToken = this.config.parameters.token;
        break;
      case 'api-key':
        // No token refresh needed
        break;
    }
  }

  private async refreshOAuth2Token(): Promise<void> {
    const authConfig = this.config.parameters.auth as AuthConfig;

    if (!authConfig.oauthUrl || !authConfig.clientId || !authConfig.clientSecret) {
      throw new Error('OAuth2 configuration incomplete');
    }

    const response = await fetch(authConfig.oauthUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: authConfig.clientId,
        client_secret: authConfig.clientSecret
      })
    });

    if (!response.ok) {
      throw new Error(`OAuth2 token refresh failed: ${response.statusText}`);
    }

    const tokenData = await response.json();
    this.authToken = (tokenData as any).access_token;

    // Store token expiry time
    if ((tokenData as any).expires_in) {
      const expiryTime = Date.now() + ((tokenData as any).expires_in * 1000);
      this.config.parameters.tokenExpiry = expiryTime;
    }
  }

  private isTokenExpired(): boolean {
    const expiry = this.config.parameters.tokenExpiry;
    return expiry && Date.now() >= expiry;
  }

  private async makeRequest(method: string, url: string,
  body?: any, headers: Record<string, string> = {}): Promise<Response> {
    await this.rateLimiter.wait();

    const requestHeaders = {
      'Content-Type': 'application/json',
      ...this.getAuthHeaders(),
      ...this.config.headers,
      ...headers
    };

    const response = await this.withRetry(async () => {
      return fetch(url, {
        method,
        headers: requestHeaders,
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(this.config.parameters.timeout || 30000)
      });
    });

    if (response.status === 429) {
      // Rate limited - wait and retry
      const retryAfter = response.headers.get('Retry-After');
      const waitTime = retryAfter ? parseInt(retryAfter) * 1000 : 1000;
      await new Promise(resolve => setTimeout(resolve, waitTime));
      return this.makeRequest(method, url, body, headers);
    }

    return response;
  }

  private getAuthHeaders(): Record<string, string> {
    const authType = this.config.parameters.authType || 'none';
    const headers: Record<string, string> = {};

    switch (authType) {
      case 'basic':
        const credentials = btoa(`${this.config.username}:${this.config.password}`);
        headers.Authorization = `Basic ${credentials}`;
        break;
      case 'bearer':
        if (this.authToken) {
          headers.Authorization = `Bearer ${this.authToken}`;
        }
        break;
      case 'api-key':
        const keyHeader = this.config.parameters.apiKeyHeader || 'X-API-Key';
        headers[keyHeader] = this.config.apiKey!;
        break;
    }

    return headers;
  }

  private getTestEndpoint(): string {
    const baseUrl = this.config.url!;

    // Try common health check endpoints
    const healthEndpoints = ['/health', '/status', '/ping', '/api/health', '/'];

    for (const endpoint of healthEndpoints) {
      return `${baseUrl}${endpoint}`;
    }

    return baseUrl;
  }

  private getAPIName(): string {
    try {
      const url = new URL(this.config.url!);
      return url.hostname.replace('www.', '');
    } catch {
      return 'api';
    }
  }

  private async discoverGraphQLSchema(): Promise<Table[]> {
    const introspectionQuery = `
      query IntrospectionQuery {
        __schema {
          types {
            name
            fields {
              name
              type {
                name
                kind
              }
            }
          }
        }
      }
    `;

    const response = await this.makeRequest('POST', this.config.url!, {
      query: introspectionQuery
    });

    if (!response.ok) {
      throw new Error('GraphQL introspection failed');
    }

    const result = await response.json();
    const types = (result as any).data.__schema.types;

    return types
      .filter((type: any) => type.fields && !type.name.startsWith('__'))
      .map((type: any) => this.convertGraphQLTypeToTable(type));
  }

  private convertGraphQLTypeToTable(type: any): Table {
    const columns: Column[] = type.fields.map((field: any) => ({
      name: field.name,
      type: this.mapGraphQLType(field.type),
      nullable: field.type.kind !== 'NON_NULL',
      metadata: { graphqlType: field.type }
    }));

    return {
      name: type.name,
      columns,
      primaryKey: ['id'], // Assume 'id' is primary key
      foreignKeys: [],
      indexes: [],
      constraints: [],
      metadata: { type: 'GraphQL' }
    };
  }

  private mapGraphQLType(gqlType: any): string {
    const typeMap: Record<string, string> = {
      'String': 'varchar',
      'Int': 'integer',
      'Float': 'decimal',
      'Boolean': 'boolean',
      'ID': 'varchar'
    };

    const typeName = gqlType.name || gqlType.ofType?.name;
    return typeMap[typeName] || 'varchar';
  }

  private async discoverSOAPSchema(): Promise<Table[]> {
    // SOAP WSDL parsing would go here
    // This is a simplified implementation
    return [];
  }

  private async discoverRESTSchema(): Promise<Table[]> {
    // Try to discover REST endpoints through common patterns
    const commonEndpoints = ['users', 'items', 'products', 'orders', 'customers'];
    const tables: Table[] = [];

    for (const endpoint of commonEndpoints) {
      try {
        const url = `${this.config.url}/${endpoint}`;
        const response = await this.makeRequest('GET', url);

        if (response.ok) {
          const data = await response.json();
          const sampleData = Array.isArray(data) ? data.slice(0, 5) : [data];

          if (sampleData.length > 0) {
            const columns = this.inferColumnsFromData(sampleData);
            tables.push({
              name: endpoint,
              columns,
              primaryKey: ['id'],
              foreignKeys: [],
              indexes: [],
              constraints: [],
              metadata: { endpoint: `/${endpoint}` }
            });
          }
        }
      } catch (error: any) {
        // Ignore errors for endpoint discovery
      }
    }

    return tables;
  }

  private inferColumnsFromData(data: any[]): Column[] {
    const fieldTypes: Record<string, Set<string>> = {};

    data.forEach((item: any) => {
      if (typeof item === 'object' && item !== null) {
        Object.entries(item).forEach(([key, value]) => {
          if (!fieldTypes[key]) {
            fieldTypes[key] = new Set();
          }
          fieldTypes[key].add(typeof value);
        });
      }
    });

    return Object.entries(fieldTypes).map(([name, types]) => ({
      name,
      type: this.inferBestType(types),
      nullable: true,
      metadata: { inferred: true }
    }));
  }

  private inferBestType(types: Set<string>): string {
    if (types.has('string')) return 'varchar';
    if (types.has('number')) return 'decimal';
    if (types.has('boolean')) return 'boolean';
    if (types.has('object')) return 'json';
    return 'varchar';
  }

  private getEndpointConfig(table: string, method: string): EndpointConfig {
    // Return endpoint configuration for the table/method
    return {
      method: method as any,
      path: `/${table}`,
      headers: {},
      responseFormat: 'json'
    };
  }

  private async readPaginated(endpoint: EndpointConfig, options: QueryOptions): Promise<any[]> {
    const pagination = this.config.parameters.pagination as PaginationConfig;
    const allData: any[] = [];
    let currentPage = 0;
    let hasMore = true;

    while (hasMore && (!pagination.maxPages || currentPage < pagination.maxPages)) {
      const params = this.buildPaginationParams(pagination, currentPage, options);
      const url = this.buildURL(endpoint.path, params);

      const response = await this.makeRequest(endpoint.method, url);
      if (!response.ok) {
        throw new Error(`API request failed: ${response.statusText}`);
      }

      const responseData = await response.json();
      const data = this.extractDataFromResponse(responseData, endpoint.dataPath);

      if (Array.isArray(data)) {
        allData.push(...data);
        hasMore = data.length === pagination.pageSize;
      } else {
        allData.push(data);
        hasMore = false;
      }

      currentPage++;
    }

    return allData;
  }

  private async readSingle(endpoint: EndpointConfig, options: QueryOptions): Promise<any> {
    const params = this.buildQueryParams(options);
    const url = this.buildURL(endpoint.path, params);

    const response = await this.makeRequest(endpoint.method, url);
    if (!response.ok) {
      throw new Error(`API request failed: ${response.statusText}`);
    }

    const responseData = await response.json();
    return this.extractDataFromResponse(responseData, endpoint.dataPath);
  }

  private buildPaginationParams(pagination: PaginationConfig, page:
  number, options: QueryOptions): Record<string, any> {
    const params: Record<string, any> = {};

    switch (pagination.type) {
      case 'offset':
        params[pagination.limitParam] = pagination.pageSize;
        if (pagination.offsetParam) {
          params[pagination.offsetParam] = page * pagination.pageSize;
        }
        break;
      case 'page':
        params[pagination.limitParam] = pagination.pageSize;
        if (pagination.pageParam) {
          params[pagination.pageParam] = page + 1; // 1-based page numbers
        }
        break;
      case 'cursor':
        params[pagination.limitParam] = pagination.pageSize;
        // Cursor handling would need additional state management
        break;
    }

    return { ...params, ...this.buildQueryParams(options) };
  }

  private buildQueryParams(options: QueryOptions): Record<string, any> {
    const params: Record<string, any> = {};

    if (options.filters) {
      Object.assign(params, options.filters);
    }

    if (options.orderBy) {
      params.sort = options.orderBy;
      if (options.orderDirection) {
        params.order = options.orderDirection.toLowerCase();
      }
    }

    return params;
  }

  private buildURL(path: string, params: Record<string, any>): string {
    const url = new URL(path, this.config.url);

    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        url.searchParams.set(key, String(value));
      }
    });

    return url.toString();
  }

  private extractDataFromResponse(response: any, dataPath?: string): any {
    if (!dataPath) return response;

    // Simple JSONPath-like extraction
    const keys = dataPath.split('.');
    let current = response;

    for (const key of keys) {
      if (current && typeof current === 'object' && key in current) {
        current = current[key];
      } else {
        return response; // Fallback to full response
      }
    }

    return current;
  }

  private processData(data: any[], options: QueryOptions): any[] {
    let result = data;

    // Client-side filtering (if not handled by API)
    if (options.filters) {
      result = result.filter((item: any) => {
        return Object.entries(options.filters!).every(([key, value]) => {
          return item[key] === value;
        });
      });
    }

    // Client-side sorting (if not handled by API)
    if (options.orderBy) {
      result = result.sort((a, b) => {
        const aVal = a[options.orderBy!];
        const bVal = b[options.orderBy!];

        if (aVal < bVal) return options.orderDirection === 'DESC' ? 1 : -1;
        if (aVal > bVal) return options.orderDirection === 'DESC' ? -1 : 1;
        return 0;
      });
    }

    // Client-side pagination (if not handled by API)
    if (options.offset || options.limit) {
      const start = options.offset || 0;
      const end = options.limit ? start + options.limit : undefined;
      result = result.slice(start, end);
    }

    return result;
  }

  private async writeSingle(table: string, data: any, options: WriteOptions): Promise<void> {
    const method = options.upsert ? 'PUT' : 'POST';
    const endpoint = this.getEndpointConfig(table, method);
    const url = this.buildURL(endpoint.path, {});

    const response = await this.makeRequest(method, url, data);

    if (!response.ok) {
      throw new Error(`API write failed: ${response.statusText}`);
    }
  }

  private async writeBatch(table: string, data: any[],
  options: WriteOptions): Promise<{ success: number; errors: number }> {
    // Try batch endpoint first
    try {
      const endpoint = this.getEndpointConfig(`${table}/batch`, 'POST');
      const url = this.buildURL(endpoint.path, {});

      const response = await this.makeRequest('POST', url, data);

      if (response.ok) {
        return { success: data.length, errors: 0 };
      }
    } catch (error: any) {
      // Fall back to individual requests
    }

    // Individual requests
    let success = 0;
    let errors = 0;

    for (const item of data) {
      try {
        await this.writeSingle(table, item, options);
        success++;
      } catch (error: any) {
        if (options.ignoreErrors) {
          errors++;
        } else {
          throw error;
        }
      }
    }

    return { success, errors };
  }

  private mapWebhookOperation(action: string): 'INSERT' | 'UPDATE' | 'DELETE' {
    const actionLower = action.toLowerCase();

    if (actionLower.includes('create') || actionLower.includes('insert') || actionLower.includes('add')) {
      return 'INSERT';
    } else if (actionLower.includes('delete') || actionLower.includes('remove')) {
      return 'DELETE';
    } else {
      return 'UPDATE';
    }
  }

  private async validateWebhookSignature(payload: any,
  headers: Record<string, string>, secret: string): Promise<boolean> {
    // Simplified signature validation - implement according to your webhook provider
    const signature = headers['x-signature'] || headers['x-hub-signature-256'];

    if (!signature) return false;

    // This would implement actual HMAC signature verification
    return true;
  }
}

class RateLimiter {
  private requests: number[] = [];
  private requestsPerSecond: number;
  private burstLimit: number;

  constructor(config: { requestsPerSecond: number; burstLimit?: number }) {
    this.requestsPerSecond = config.requestsPerSecond;
    this.burstLimit = config.burstLimit || config.requestsPerSecond * 2;
  }

  async wait(): Promise<void> {
    const now = Date.now();

    // Remove requests older than 1 second
    this.requests = this.requests.filter((time: any) => now - time < 1000);

    // Check burst limit
    if (this.requests.length >= this.burstLimit) {
      const oldestRequest = this.requests[0];
      const waitTime = 1000 - (now - oldestRequest);
      await new Promise(resolve => setTimeout(resolve, waitTime));
      return this.wait();
    }

    // Check rate limit
    if (this.requests.length >= this.requestsPerSecond) {
      const waitTime = 1000 / this.requestsPerSecond;
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }

    this.requests.push(now);
  }
}