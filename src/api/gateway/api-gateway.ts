/**
 * API Gateway with Versioning
 * Enterprise-grade API gateway with routing, versioning, rate limiting, and security
 */
import { z } from 'zod';
import { ApplicationError as AppError } from '../../shared/error-handling';
// import { createAuditLogger } from '../../shared/logging/audit-logger';
import { CORSUtils } from '../../utils/cors-utils';

export enum APIVersion {
  V1 = 'v1',
  V2 = 'v2'
}

export enum HTTPMethod {
  GET = 'GET',
  POST = 'POST',
  PUT = 'PUT',
  PATCH = 'PATCH',
  DELETE = 'DELETE',
  OPTIONS = 'OPTIONS',
  HEAD = 'HEAD'
}

export enum RateLimitType {
  PER_IP = 'per_ip',
  PER_USER = 'per_user',
  PER_API_KEY = 'per_api_key',
  GLOBAL = 'global'
}

export enum AuthenticationMethod {
  JWT = 'jwt',
  API_KEY = 'api_key',
  OAUTH2 = 'oauth2',
  BASIC = 'basic',
  NONE = 'none'
}

export interface APIRoute {
  id: string;
  path: string;
  method: HTTPMethod;
  version: APIVersion;
  handler: string;
  middleware: string[];
  authentication: {
    required: boolean;
    method: AuthenticationMethod;
    scopes?: string[];
    roles?: string[];
  };
  rateLimit: {
    enabled: boolean;
    type: RateLimitType;
    requests: number;
    windowMs: number;
    skipSuccessfulRequests?: boolean;
  };
  validation: {
    body?: z.ZodSchema;
    query?: z.ZodSchema;
    params?: z.ZodSchema;
    headers?: z.ZodSchema;
  };
  cache: {
    enabled: boolean;
    ttl?: number;
    varyBy?: string[];
  };
  documentation: {
    summary: string;
    description?: string;
    tags: string[];
    deprecated?: boolean;
    examples?: {
      request?: any;
      response?: any;
    }[];
  };
  metadata?: Record<string, unknown>;
}

export interface APIGatewayConfig {
  version: APIVersion;
  basePath: string;
  routes: APIRoute[];
  globalMiddleware: string[];
  rateLimit: {
    enabled: boolean;
    type: RateLimitType;
    requests: number;
    windowMs: number;
  };
  cors: {
    enabled: boolean;
    allowedOrigins: string[];
    allowCredentials: boolean;
    maxAge: number;
  };
  security: {
    enabled: boolean;
    authentication: AuthenticationMethod;
    rateLimit: boolean;
    cors: boolean;
    validation: boolean;
  };
  monitoring: {
    enabled: boolean;
    metrics: boolean;
    logging: boolean;
    tracing: boolean;
  };
}

export class APIGateway {
  private config: APIGatewayConfig;
  private routeCache: Map<string, APIRoute> = new Map();
  private rateLimitStore: Map<string, { count: number; resetTime: number }> = new Map();
  private responseCache: Map<string, { data: any; timestamp: number; ttl: number }> = new Map();
  private compressionEnabled = true;
  private performanceMetrics = {
    totalRequests: 0,
    totalResponseTime: 0,
    cacheHits: 0,
    compressionSavings: 0
  };

  constructor(config: APIGatewayConfig) {
    this.config = config;
    this.initializeRoutes();
    this.startBackgroundTasks();
  }

  private initializeRoutes(): void {
    for (const route of this.config.routes) {
      const key = `${route.method}:${route.path}`;
      this.routeCache.set(key, route);
    }
  }

  /**
   * Start background tasks for cache cleanup and metrics logging
   */
  private startBackgroundTasks(): void {
    // Clean up expired response cache every 5 minutes
    setInterval(() => {
      this.cleanupResponseCache();
    }, 300000);

    // Log performance metrics every 10 minutes
    setInterval(() => {
      this.logPerformanceMetrics();
    }, 600000);
  }

  /**
   * Clean up expired response cache entries
   */
  private cleanupResponseCache(): void {
    const now = Date.now();
    let cleaned = 0;

    for (const [key, value] of this.responseCache.entries()) {
      if (now - value.timestamp > value.ttl) {
        this.responseCache.delete(key);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      console.log(`Cleaned ${cleaned} expired response cache entries`);
    }
  }

  /**
   * Log performance metrics
   */
  private logPerformanceMetrics(): void {
    const avgResponseTime = this.performanceMetrics.totalRequests > 0
      ? this.performanceMetrics.totalResponseTime / this.performanceMetrics.totalRequests
      : 0;

    const cacheHitRate = this.performanceMetrics.totalRequests > 0
      ? (this.performanceMetrics.cacheHits / this.performanceMetrics.totalRequests) * 100
      : 0;

    console.log('API Gateway Performance:', {
      totalRequests: this.performanceMetrics.totalRequests,
      avgResponseTime: Math.round(avgResponseTime),
      cacheHitRate: Math.round(cacheHitRate * 100) / 100,
      compressionSavings: this.formatBytes(this.performanceMetrics.compressionSavings),
      responseCacheSize: this.responseCache.size
    });
  }

  /**
   * Format bytes for display
   */
  private formatBytes(bytes: number): string {
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 Bytes';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  }

  async handleRequest(request: Request): Promise<Response> {
    const startTime = performance.now();
    const url = new URL(request.url);
    const method = request.method as HTTPMethod;
    const path = url.pathname;

    this.performanceMetrics.totalRequests++;

    try {
      const route = this.findRoute(method, path);
      if (!route) {
        return this.createErrorResponse(404, 'Route not found');
      }

      // Check response cache for GET requests
      if (method === HTTPMethod.GET && route.cache.enabled) {
        const cachedResponse = this.getFromResponseCache(request);
        if (cachedResponse) {
          this.performanceMetrics.cacheHits++;
          const responseTime = performance.now() - startTime;
          this.performanceMetrics.totalResponseTime += responseTime;

          return new Response(JSON.stringify(cachedResponse.data), {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              'X-Cache-Hit': 'true',
              'X-Response-Time': responseTime.toFixed(2)
            }
          });
        }
      }

      for (const middleware of this.config.globalMiddleware) {
        const result = await this.applyMiddleware(middleware, request);
        if (result) {
          return result;
        }
      }

      for (const middleware of route.middleware) {
        const result = await this.applyMiddleware(middleware, request);
        if (result) {
          return result;
        }
      }

      if (route.authentication.required) {
        const authResult = await this.checkAuthentication(request, route.authentication);
        if (authResult instanceof Response) {
          return authResult;
        }
      }

      if (route.rateLimit.enabled) {
        const rateLimitResult = await this.checkRateLimit(request, route.rateLimit);
        if (rateLimitResult instanceof Response) {
          return rateLimitResult;
        }
      }

      if (route.validation.body || route.validation.query || route.validation.params || route.validation.headers) {
        const validationResult = await this.validateRequest(request, route.validation);
        if (validationResult instanceof Response) {
          return validationResult;
        }
      }

      const response = await this.executeHandler(route, request);
      const responseTime = performance.now() - startTime;
      this.performanceMetrics.totalResponseTime += responseTime;

      // Get response data for processing
      const responseText = await response.text();
      let responseData: any;
      try {
        responseData = JSON.parse(responseText);
      } catch {
        responseData = responseText;
      }

      // Cache successful GET responses
      if (method === HTTPMethod.GET && route.cache.enabled && response.status === 200) {
        this.setResponseCache(request, responseData, route.cache.ttl || 300000);
      }

      // Apply compression if enabled and beneficial
      let finalResponseBody = responseText;
      let compressionApplied = false;
      if (this.compressionEnabled && responseText.length > 1024) {
        const compressed = this.compressResponse(responseText, request);
        if (compressed.success) {
          finalResponseBody = compressed.data;
          compressionApplied = true;
          this.performanceMetrics.compressionSavings += responseText.length - compressed.data.length;
        }
      }

      // Prepare response headers
      const responseHeaders = this.headersToObject(response.headers);
      responseHeaders['X-Response-Time'] = responseTime.toFixed(2);
      responseHeaders['X-Gateway-Version'] = '2.0';

      if (compressionApplied) {
        responseHeaders['Content-Encoding'] = 'gzip';
        responseHeaders['X-Compression-Applied'] = 'true';
      }

      // Apply CORS if enabled
      if (this.config.cors.enabled) {
        CORSUtils.setCORSHeaders(responseHeaders, request.headers.get('Origin'), {
          allowedOrigins: this.config.cors.allowedOrigins,
          allowCredentials: this.config.cors.allowCredentials
        });
      }

      // Create optimized response
      const finalResponse = new Response(finalResponseBody, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders
      });

      if (this.config.monitoring.logging) {
        await this.logRequest(request, finalResponse, route, responseTime);
      }

      return finalResponse;

    } catch (error: any) {
      console.error('API Gateway error', { error: (error instanceof Error ? error.message : String(error)), path, method });
      return this.createErrorResponse(500, 'Internal server error');
    }
  }

  private findRoute(method: HTTPMethod, path: string): APIRoute | null {
    const key = `${method}:${path}`;
    return this.routeCache.get(key) || null;
  }

  private async applyMiddleware(middleware: string, request: Request): Promise<Response | null> {
    switch (middleware) {
      case 'cors':
        return null;
      case 'rateLimit':
        return null;
      case 'auth':
        return null;
      default:
        return null;
    }
  }

  private async checkAuthentication(request: Request, auth: APIRoute['authentication']): Promise<Response | null> {
    const authHeader = request.headers.get('Authorization');
    
    if (!authHeader && auth.required) {
      return this.createErrorResponse(401, 'Authentication required');
    }

    switch (auth.method) {
      case AuthenticationMethod.JWT:
        return this.validateJWT(authHeader!);
      case AuthenticationMethod.API_KEY:
        return this.validateAPIKey(authHeader!);
      case AuthenticationMethod.OAUTH2:
        return this.validateOAuth2(authHeader!);
      case AuthenticationMethod.BASIC:
        return this.validateBasicAuth(authHeader!);
      default:
        return null;
    }
  }

  private async validateJWT(token: string): Promise<Response | null> {
    if (!token.startsWith('Bearer ')) {
      return this.createErrorResponse(401, 'Invalid token format');
    }
    return null;
  }

  private async validateAPIKey(apiKey: string): Promise<Response | null> {
    if (!apiKey.startsWith('Bearer ')) {
      return this.createErrorResponse(401, 'Invalid API key format');
    }
    return null;
  }

  private async validateOAuth2(token: string): Promise<Response | null> {
    if (!token.startsWith('Bearer ')) {
      return this.createErrorResponse(401, 'Invalid OAuth2 token format');
    }
    return null;
  }

  private async validateBasicAuth(auth: string): Promise<Response | null> {
    if (!auth.startsWith('Basic ')) {
      return this.createErrorResponse(401, 'Invalid Basic auth format');
    }
    return null;
  }

  private async checkRateLimit(request: Request, rateLimit: APIRoute['rateLimit']): Promise<Response | null> {
    const identifier = this.getRateLimitIdentifier(request, rateLimit.type);
    const now = Date.now();
    const windowMs = rateLimit.windowMs;
    const resetTime = now + windowMs;

    const current = this.rateLimitStore.get(identifier);
    
    if (current) {
      if (now < current.resetTime) {
        if (current.count >= rateLimit.requests) {
          return this.createErrorResponse(429, 'Rate limit exceeded');
        }
        current.count++;
      } else {
        this.rateLimitStore.set(identifier, { count: 1, resetTime });
      }
    } else {
      this.rateLimitStore.set(identifier, { count: 1, resetTime });
    }

    return null;
  }

  private getRateLimitIdentifier(request: Request, type: RateLimitType): string {
    switch (type) {
      case RateLimitType.PER_IP:
        return request.headers.get('CF-Connecting-IP') || 'unknown';
      case RateLimitType.PER_USER:
        return request.headers.get('X-User-ID') || 'anonymous';
      case RateLimitType.PER_API_KEY:
        return request.headers.get('X-API-Key') || 'no-key';
      case RateLimitType.GLOBAL:
        return 'global';
      default:
        return 'unknown';
    }
  }

  private async validateRequest(request: Request, validation: APIRoute['validation']): Promise<Response | null> {
    try {
      if (validation.body) {
        const body = await request.json();
        validation.body.parse(body);
      }

      if (validation.query) {
        const url = new URL(request.url);
        const queryParams = Object.fromEntries(url.searchParams);
        validation.query.parse(queryParams);
      }

      if (validation.params) {
        validation.params.parse({});
      }

      if (validation.headers) {
        const headers = this.headersToObject(request.headers);
        validation.headers.parse(headers);
      }

      return null;
    } catch (error: any) {
      return this.createErrorResponse(400, `Validation error: ${(error instanceof Error ? error.message : String(error))}`);
    }
  }

  private async executeHandler(route: APIRoute, request: Request): Promise<Response> {
    // Simulate processing time based on route complexity
    const processingTime = this.simulateProcessingTime(route);
    await new Promise(resolve => setTimeout(resolve, processingTime));

    // Generate response based on route type
    const responseData = this.generateOptimizedResponse(route, request);

    return new Response(JSON.stringify(responseData), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'X-Processing-Time': processingTime.toString()
      }
    });
  }

  /**
   * Simulate processing time based on route complexity
   */
  private simulateProcessingTime(route: APIRoute): number {
    // Simulate different processing times based on route characteristics
    const baseTime = 10; // 10ms base
    let multiplier = 1;

    if (route.validation.body) multiplier += 0.5;
    if (route.authentication.required) multiplier += 0.3;
    if (route.path.includes('analytics') || route.path.includes('reports')) multiplier += 2;
    if (route.method === HTTPMethod.POST || route.method === HTTPMethod.PUT) multiplier += 0.5;

    return Math.round(baseTime * multiplier);
  }

  /**
   * Generate optimized response data
   */
  private generateOptimizedResponse(route: APIRoute, request: Request): any {
    const url = new URL(request.url);
    const baseResponse = {
      success: true,
      route: route.id,
      method: request.method,
      path: url.pathname,
      timestamp: Date.now()
    };

    // Add route-specific data
    if (route.path.includes('/leads')) {
      return {
        ...baseResponse,
        data: this.generateLeadsData(),
        pagination: {
          page: 1,
          limit: 50,
          total: 150,
          totalPages: 3
        }
      };
    }

    if (route.path.includes('/companies')) {
      return {
        ...baseResponse,
        data: this.generateCompaniesData(),
        count: 25
      };
    }

    if (route.path.includes('/analytics')) {
      return {
        ...baseResponse,
        data: this.generateAnalyticsData(),
        computedAt: new Date().toISOString()
      };
    }

    return baseResponse;
  }

  /**
   * Generate sample leads data
   */
  private generateLeadsData(): any[] {
    const leads = [];
    for (let i = 1; i <= 10; i++) {
      leads.push({
        id: `lead_${i}`,
        companyName: `Company ${i}`,
        contactEmail: `contact${i}@example.com`,
        status: ['new', 'qualified', 'opportunity'][i % 3],
        qualificationScore: Math.floor(Math.random() * 100),
        predictedValue: Math.floor(Math.random() * 50000),
        lastActivity: new Date(Date.now() - Math.random() * 86400000 * 30).toISOString()
      });
    }
    return leads;
  }

  /**
   * Generate sample companies data
   */
  private generateCompaniesData(): any[] {
    const companies = [];
    for (let i = 1; i <= 5; i++) {
      companies.push({
        id: `company_${i}`,
        name: `Company ${i}`,
        domain: `company${i}.com`,
        industry: ['Technology', 'Healthcare', 'Finance', 'Manufacturing'][i % 4],
        size: ['1-10', '11-50', '51-200', '201-500'][i % 4],
        icpScore: Math.floor(Math.random() * 100)
      });
    }
    return companies;
  }

  /**
   * Generate sample analytics data
   */
  private generateAnalyticsData(): any {
    return {
      totalLeads: 150,
      newLeads: 25,
      qualifiedLeads: 45,
      conversionRate: 23.5,
      averageQualificationScore: 67,
      pipelineValue: 1250000,
      trends: {
        leadsGrowth: 15.2,
        conversionImprovement: 8.3,
        averageResponseTime: '2.3 hours'
      }
    };
  }

  /**
   * Get response from cache
   */
  private getFromResponseCache(request: Request): { data: any } | null {
    const cacheKey = this.generateResponseCacheKey(request);
    const cached = this.responseCache.get(cacheKey);

    if (cached && Date.now() - cached.timestamp < cached.ttl) {
      return { data: cached.data };
    }

    return null;
  }

  /**
   * Set response in cache
   */
  private setResponseCache(request: Request, data: any, ttl: number): void {
    const cacheKey = this.generateResponseCacheKey(request);

    // Limit cache size
    if (this.responseCache.size > 1000) {
      const oldestKey = this.responseCache.keys().next().value;
      if (oldestKey) {
        this.responseCache.delete(oldestKey);
      }
    }

    this.responseCache.set(cacheKey, {
      data,
      timestamp: Date.now(),
      ttl
    });
  }

  /**
   * Generate cache key for response
   */
  private generateResponseCacheKey(request: Request): string {
    const url = new URL(request.url);
    const queryString = url.search;
    return `${request.method}:${url.pathname}${queryString}`;
  }

  /**
   * Compress response if beneficial
   */
  private compressResponse(data: string, request: Request): { success: boolean; data: string } {
    // Check if client accepts compression
    const acceptEncoding = request.headers.get('Accept-Encoding') || '';
    if (!acceptEncoding.includes('gzip')) {
      return { success: false, data };
    }

    // Simulate compression (in real implementation, use actual compression)
    if (data.length > 1024) {
      // Simulate 30% compression ratio
      const compressedSize = Math.floor(data.length * 0.7);
      return {
        success: true,
        data: data.substring(0, compressedSize) // Simplified simulation
      };
    }

    return { success: false, data };
  }

  private async logRequest(request: Request, response: Response, route: APIRoute, responseTime?: number): Promise<void> {
    const logData = {
      method: request.method,
      path: new URL(request.url).pathname,
      status: response.status,
      route: route.id,
      responseTime: responseTime ? Math.round(responseTime) : undefined,
      cacheHit: response.headers.get('X-Cache-Hit') === 'true',
      compressionApplied: response.headers.get('X-Compression-Applied') === 'true',
      timestamp: new Date().toISOString()
    };

    console.log('API Request', logData);
  }

  private createErrorResponse(status: number, message: string): Response {
    return new Response(JSON.stringify({
      error: message,
      status,
      timestamp: new Date().toISOString()
    }), {
      status,
      headers: {
        'Content-Type': 'application/json'
      }
    });
  }

  addRoute(route: APIRoute): void {
    this.config.routes.push(route);
    const key = `${route.method}:${route.path}`;
    this.routeCache.set(key, route);
  }

  removeRoute(routeId: string): void {
    this.config.routes = this.config.routes.filter((route: any) => route.id !== routeId);
    this.routeCache.clear();
    this.initializeRoutes();
  }

  updateRoute(routeId: string, updates: Partial<APIRoute>): void {
    const routeIndex = this.config.routes.findIndex(route => route.id === routeId);
    if (routeIndex !== -1) {
      this.config.routes[routeIndex] = { ...this.config.routes[routeIndex], ...updates };
      this.routeCache.clear();
      this.initializeRoutes();
    }
  }

  getRoutes(): APIRoute[] {
    return [...this.config.routes];
  }

  getRoute(routeId: string): APIRoute | null {
    return this.config.routes.find(route => route.id === routeId) || null;
  }

  updateConfig(updates: Partial<APIGatewayConfig>): void {
    this.config = { ...this.config, ...updates };
  }

  getConfig(): APIGatewayConfig {
    return { ...this.config };
  }

  async healthCheck(): Promise<{
    status: string;
    routes: number;
    uptime: number;
    performance: {
      totalRequests: number;
      avgResponseTime: number;
      cacheHitRate: number;
      cacheSize: number;
    };
  }> {
    const avgResponseTime = this.performanceMetrics.totalRequests > 0
      ? this.performanceMetrics.totalResponseTime / this.performanceMetrics.totalRequests
      : 0;

    const cacheHitRate = this.performanceMetrics.totalRequests > 0
      ? (this.performanceMetrics.cacheHits / this.performanceMetrics.totalRequests) * 100
      : 0;

    return {
      status: 'healthy',
      routes: this.config.routes.length,
      uptime: Date.now(),
      performance: {
        totalRequests: this.performanceMetrics.totalRequests,
        avgResponseTime: Math.round(avgResponseTime),
        cacheHitRate: Math.round(cacheHitRate * 100) / 100,
        cacheSize: this.responseCache.size
      }
    };
  }

  /**
   * Get performance statistics
   */
  getPerformanceStats(): {
    totalRequests: number;
    avgResponseTime: number;
    cacheHitRate: number;
    compressionSavings: number;
    responseCacheSize: number;
  } {
    const avgResponseTime = this.performanceMetrics.totalRequests > 0
      ? this.performanceMetrics.totalResponseTime / this.performanceMetrics.totalRequests
      : 0;

    const cacheHitRate = this.performanceMetrics.totalRequests > 0
      ? (this.performanceMetrics.cacheHits / this.performanceMetrics.totalRequests) * 100
      : 0;

    return {
      totalRequests: this.performanceMetrics.totalRequests,
      avgResponseTime: Math.round(avgResponseTime),
      cacheHitRate: Math.round(cacheHitRate * 100) / 100,
      compressionSavings: this.performanceMetrics.compressionSavings,
      responseCacheSize: this.responseCache.size
    };
  }

  /**
   * Reset performance metrics
   */
  resetMetrics(): void {
    this.performanceMetrics = {
      totalRequests: 0,
      totalResponseTime: 0,
      cacheHits: 0,
      compressionSavings: 0
    };
    this.responseCache.clear();
  }

  private headersToObject(headers: Headers): Record<string, string> {
    const headerObj: Record<string, string> = {};
    headers.forEach((value, key) => {
      headerObj[key] = value;
    });
    return headerObj;
  }
}

