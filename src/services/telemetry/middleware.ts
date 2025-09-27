import { TelemetryCollector } from './collector';
import { MetricsCollector } from './metrics';
import { DistributedTracing } from './tracing';
import { LogEntry, Span } from '../../types/telemetry';

interface MiddlewareConfig {
  enableMetrics: boolean;
  enableTracing: boolean;
  enableLogging: boolean;
  sampleRate: number;
  excludePaths: string[];
  includeRequestBody: boolean;
  includeResponseBody: boolean;
  maxBodySize: number;
}

export class ObservabilityMiddleware {
  private collector: TelemetryCollector;
  private metrics: MetricsCollector;
  private tracing: DistributedTracing;
  private config: MiddlewareConfig;

  constructor(
    collector: TelemetryCollector,
    metrics: MetricsCollector,
    tracing: DistributedTracing,
    config: Partial<MiddlewareConfig> = {}
  ) {
    this.collector = collector;
    this.metrics = metrics;
    this.tracing = tracing;
    this.config = {
      enableMetrics: true,
      enableTracing: true,
      enableLogging: true,
      sampleRate: 1.0,
      excludePaths: ['/health', '/metrics', '/favicon.ico'],
      includeRequestBody: false,
      includeResponseBody: false,
      maxBodySize: 1024 * 1024, // 1MB
      ...config
    };
  }

  middleware() {
    return async (request: Request, env: any, ctx: any, next: () => Promise<Response>): Promise<Response> => {
      const url = new URL(request.url);

      // Skip excluded paths
      if (this.config.excludePaths.includes(url.pathname)) {
        return await next();
      }

      // Sample requests
      if (Math.random() > this.config.sampleRate) {
        return await next();
      }

      const startTime = Date.now();
      const requestId = crypto.randomUUID();
      const businessId = this.extractBusinessId(request);
      const userId = this.extractUserId(request);
      const sessionId = this.extractSessionId(request);

      let span: Span | undefined;
      let response: Response;

      try {
        // Start tracing
        if (this.config.enableTracing) {
          const context = this.tracing.extractContext(Object.fromEntries(request.headers.entries()));
          span = this.tracing.startSpan(`${request.method} ${url.pathname}`, context);

          this.tracing.setTag(span, 'http.method', request.method);
          this.tracing.setTag(span, 'http.url', request.url);
          this.tracing.setTag(span, 'http.path', url.pathname);
          this.tracing.setTag(span, 'user.id', userId);
          this.tracing.setTag(span, 'business.id', businessId);
          this.tracing.setTag(span, 'request.id', requestId);
        }

        // Process request
        response = await next();

        const latency = Date.now() - startTime;

        // Collect metrics
        if (this.config.enableMetrics) {
          this.metrics.recordRequest(latency, response.status, {
            method: request.method,
            path: url.pathname,
            status: response.status.toString(),
            business_id: businessId
          });
        }

        // Create log entry
        if (this.config.enableLogging) {
          const logEntry: LogEntry = {
            timestamp: new Date(startTime).toISOString(),
            traceId: span?.traceId || requestId,
            spanId: span?.spanId || requestId,
            parentSpanId: span?.parentSpanId,
            businessId,
            userId,
            sessionId,
            requestId,
            method: request.method,
            path: url.pathname,
            statusCode: response.status,
            latencyMs: latency,
            module: this.extractModule(url.pathname),
            capability: this.extractCapability(url.pathname),
            metadata: await this.collectMetadata(request, response)
          };

          await this.collector.collect(logEntry);
        }

        // Update span
        if (span) {
          this.tracing.setTag(span, 'http.status_code', response.status);
          this.tracing.setTag(span, 'http.response_size', response.headers.get('content-length') || '0');

          if (response.status >= 400) {
            span.status = 'error';
            this.tracing.setTag(span, 'error', true);
          }
        }

        return response;

      } catch (error: any) {
        const latency = Date.now() - startTime;

        // Record error metrics
        if (this.config.enableMetrics) {
          this.metrics.recordRequest(latency, 500, {
            method: request.method,
            path: url.pathname,
            status: '500',
            business_id: businessId
          });
        }

        // Log error
        if (this.config.enableLogging) {
          const logEntry: LogEntry = {
            timestamp: new Date(startTime).toISOString(),
            traceId: span?.traceId || requestId,
            spanId: span?.spanId || requestId,
            parentSpanId: span?.parentSpanId,
            businessId,
            userId,
            sessionId,
            requestId,
            method: request.method,
            path: url.pathname,
            statusCode: 500,
            latencyMs: latency,
            module: this.extractModule(url.pathname),
            capability: this.extractCapability(url.pathname),
            error: {
              type: error.constructor.name,
              message: (error as Error).message,
              stack: (error as Error).stack,
              userMessage: 'Internal server error'
            },
            metadata: await this.collectMetadata(request, undefined, error as Error)
          };

          await this.collector.collect(logEntry);
        }

        // Update span with error
        if (span) {
          span.status = 'error';
          this.tracing.setTag(span, 'error', true);
          this.tracing.setTag(span, 'error.message', (error as Error).message);
          this.tracing.setTag(span, 'error.type', error.constructor.name);
        }

        throw error;

      } finally {
        // Finish span
        if (span) {
          this.tracing.finishSpan(span);
        }
      }
    };
  }

  private extractBusinessId(request: Request): string {
    // Try multiple sources for business ID
    const url = new URL(request.url);

    // From query parameter
    const queryBusinessId = url.searchParams.get('businessId');
    if (queryBusinessId) return queryBusinessId;

    // From header
    const headerBusinessId = request.headers.get('X-Business-ID');
    if (headerBusinessId) return headerBusinessId;

    // From JWT token (simplified)
    const authHeader = request.headers.get('Authorization');
    if (authHeader?.startsWith('Bearer ')) {
      try {
        const token = authHeader.substring(7);
        const payload = JSON.parse(atob(token.split('.')[1]));
        if (payload.businessId) return payload.businessId;
      } catch (error: any) {
        // Ignore JWT parsing errors
      }
    }

    // From subdomain
    const host = request.headers.get('Host');
    if (host) {
      const subdomain = host.split('.')[0];
      if (subdomain !== 'www' && subdomain !== 'api') {
        return subdomain;
      }
    }

    return 'default';
  }

  private extractUserId(request: Request): string {
    // From header
    const headerUserId = request.headers.get('X-User-ID');
    if (headerUserId) return headerUserId;

    // From JWT token
    const authHeader = request.headers.get('Authorization');
    if (authHeader?.startsWith('Bearer ')) {
      try {
        const token = authHeader.substring(7);
        const payload = JSON.parse(atob(token.split('.')[1]));
        if (payload.userId) return payload.userId;
        if (payload.sub) return payload.sub;
      } catch (error: any) {
        // Ignore JWT parsing errors
      }
    }

    return 'anonymous';
  }

  private extractSessionId(request: Request): string {
    // From header
    const headerSessionId = request.headers.get('X-Session-ID');
    if (headerSessionId) return headerSessionId;

    // From cookie
    const cookieHeader = request.headers.get('Cookie');
    if (cookieHeader) {
      const sessionMatch = cookieHeader.match(/session_id=([^;]+)/);
      if (sessionMatch) return sessionMatch[1];
    }

    return crypto.randomUUID();
  }

  private extractModule(pathname: string): string {
    const parts = pathname.split('/').filter(Boolean);
    if (parts.length >= 2 && parts[0] === 'api') {
      return parts[1];
    }
    if (parts.length >= 1) {
      return parts[0];
    }
    return 'default';
  }

  private extractCapability(pathname: string): string {
    const parts = pathname.split('/').filter(Boolean);
    if (parts.length >= 3 && parts[0] === 'api') {
      return parts[2];
    }
    if (parts.length >= 2) {
      return parts[1];
    }
    return 'default';
  }

  private async collectMetadata(
    request: Request,
    response?: Response,
    error?: Error
  ): Promise<Record<string, any>> {
    const metadata: Record<string, any> = {
      userAgent: request.headers.get('User-Agent'),
      referer: request.headers.get('Referer'),
      ip: request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For'),
      country: request.headers.get('CF-IPCountry'),
      requestSize: request.headers.get('Content-Length')
    };

    // Add request body if configured
    if (this.config.includeRequestBody && request.body) {
      try {
        const contentType = request.headers.get('Content-Type');
        if (contentType?.includes('application/json')) {
          const clonedRequest = request.clone();
          const body = await clonedRequest.text();
          if (body.length <= this.config.maxBodySize) {
            metadata.requestBody = body;
          }
        }
      } catch (error: any) {
        // Ignore body reading errors
      }
    }

    // Add response metadata
    if (response) {
      metadata.responseSize = response.headers.get('Content-Length');
      metadata.responseType = response.headers.get('Content-Type');

      if (this.config.includeResponseBody && response.body) {
        try {
          const contentType = response.headers.get('Content-Type');
          if (contentType?.includes('application/json')) {
            const clonedResponse = response.clone();
            const body = await clonedResponse.text();
            if (body.length <= this.config.maxBodySize) {
              metadata.responseBody = body;
            }
          }
        } catch (error: any) {
          // Ignore body reading errors
        }
      }
    }

    // Add error metadata
    if (error) {
      metadata.errorName = error.constructor.name;
      metadata.errorMessage = error.message;
      metadata.errorStack = error.stack;
    }

    return metadata;
  }
}

// AI-specific middleware for tracking AI operations
export class AIObservabilityMiddleware {
  private collector: TelemetryCollector;
  private metrics: MetricsCollector;

  constructor(collector: TelemetryCollector, metrics: MetricsCollector) {
    this.collector = collector;
    this.metrics = metrics;
  }

  wrapAICall<T>(
    operation: string,
    model: string,
    provider: string,
    fn: () => Promise<T>
  ): Promise<T> {
    return this.instrumentAICall(operation, model, provider, fn);
  }

  private async instrumentAICall<T>(
    operation: string,
    model: string,
    provider: string,
    fn: () => Promise<T>
  ): Promise<T> {
    const startTime = Date.now();
    const requestId = crypto.randomUUID();

    try {
      const result = await fn();
      const latency = Date.now() - startTime;

      // Extract token usage and cost from result
      const { promptTokens, completionTokens, costCents } = this.extractAIMetrics(result);

      // Record AI metrics
      this.metrics.recordAIRequest(
        { prompt: promptTokens, completion: completionTokens },
        costCents,
        latency,
        model,
        provider,
        { operation }
      );

      // Create detailed log entry
      const logEntry: LogEntry = {
        timestamp: new Date(startTime).toISOString(),
        traceId: requestId,
        spanId: requestId,
        businessId: 'default', // Would be extracted from context
        userId: 'system',
        sessionId: requestId,
        requestId,
        method: 'AI_CALL',
        path: `/${provider}/${model}/${operation}`,
        statusCode: 200,
        latencyMs: latency,
        aiModel: model,
        promptTokens,
        completionTokens,
        aiCostCents: costCents,
        aiProvider: provider,
        module: 'ai',
        capability: operation,
        metadata: {
          operation,
          model,
          provider,
          totalTokens: promptTokens + completionTokens
        }
      };

      await this.collector.collect(logEntry);

      return result;

    } catch (error: any) {
      const latency = Date.now() - startTime;

      // Record AI error
      this.metrics.recordAIError((error as Error).message, model, provider);

      // Create error log entry
      const logEntry: LogEntry = {
        timestamp: new Date(startTime).toISOString(),
        traceId: requestId,
        spanId: requestId,
        businessId: 'default',
        userId: 'system',
        sessionId: requestId,
        requestId,
        method: 'AI_CALL',
        path: `/${provider}/${model}/${operation}`,
        statusCode: 500,
        latencyMs: latency,
        aiModel: model,
        aiProvider: provider,
        module: 'ai',
        capability: operation,
        error: {
          type: error.constructor.name,
          message: (error as Error).message,
          stack: (error as Error).stack,
          userMessage: 'AI service error'
        },
        metadata: {
          operation,
          model,
          provider
        }
      };

      await this.collector.collect(logEntry);

      throw error;
    }
  }

  private extractAIMetrics(result: any): { promptTokens: number; completionTokens: number; costCents: number } {
    // Extract from common AI response formats
    if (result?.usage) {
      return {
        promptTokens: result.usage.prompt_tokens || 0,
        completionTokens: result.usage.completion_tokens || 0,
        costCents: this.calculateCost(result.usage, result.model)
      };
    }

    if (result?.metadata?.usage) {
      return {
        promptTokens: result.metadata.usage.input_tokens || 0,
        completionTokens: result.metadata.usage.output_tokens || 0,
        costCents: this.calculateCost(result.metadata.usage, result.model)
      };
    }

    // Default values if no usage info
    return {
      promptTokens: 0,
      completionTokens: 0,
      costCents: 0
    };
  }

  private calculateCost(usage: any, model: string): number {
    // Simplified cost calculation - in production, use accurate pricing
    const totalTokens = (usage.prompt_tokens || usage.input_tokens || 0) +
                       (usage.completion_tokens || usage.output_tokens || 0);

    // Example pricing (cents per 1k tokens)
    const pricing: Record<string, number> = {
      'gpt-4': 3.0,
      'gpt-3.5-turbo': 0.2,
      'claude-3-sonnet': 1.5,
      'claude-3-haiku': 0.5
    };

    const pricePerK = pricing[model] || 1.0;
    return (totalTokens / 1000) * pricePerK;
  }
}

// Database query middleware
export class DatabaseObservabilityMiddleware {
  private collector: TelemetryCollector;
  private metrics: MetricsCollector;

  constructor(collector: TelemetryCollector, metrics: MetricsCollector) {
    this.collector = collector;
    this.metrics = metrics;
  }

  wrapQuery<T>(
    operation: string,
    table: string,
    fn: () => Promise<T>
  ): Promise<T> {
    return this.instrumentQuery(operation, table, fn);
  }

  private async instrumentQuery<T>(
    operation: string,
    table: string,
    fn: () => Promise<T>
  ): Promise<T> {
    const startTime = Date.now();
    const requestId = crypto.randomUUID();

    try {
      const result = await fn();
      const latency = Date.now() - startTime;

      // Record database metrics
      this.metrics.timing('database_query_duration', latency, {
        operation,
        table,
        status: 'success'
      });

      this.metrics.counter('database_queries_total', 1, {
        operation,
        table,
        status: 'success'
      });

      return result;

    } catch (error: any) {
      const latency = Date.now() - startTime;

      // Record database error metrics
      this.metrics.timing('database_query_duration', latency, {
        operation,
        table,
        status: 'error'
      });

      this.metrics.counter('database_queries_total', 1, {
        operation,
        table,
        status: 'error'
      });

      this.metrics.counter('database_errors_total', 1, {
        operation,
        table,
        error: (error as Error).message
      });

      throw error;
    }
  }
}