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

  constructor(config: APIGatewayConfig) {
    this.config = config;
    this.initializeRoutes();
  }

  private initializeRoutes(): void {
    for (const route of this.config.routes) {
      const key = `${route.method}:${route.path}`;
      this.routeCache.set(key, route);
    }
  }

  async handleRequest(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const method = request.method as HTTPMethod;
    const path = url.pathname;

    try {
      const route = this.findRoute(method, path);
      if (!route) {
        return this.createErrorResponse(404, 'Route not found');
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

      if (this.config.cors.enabled) {
        const responseHeaders = this.headersToObject(response.headers);
        CORSUtils.setCORSHeaders(responseHeaders, request.headers.get('Origin'), {
          allowedOrigins: this.config.cors.allowedOrigins,
          allowCredentials: this.config.cors.allowCredentials
        });
        // Apply updated headers back to response
        const newResponse = new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: responseHeaders
        });
        return newResponse;
      }

      if (this.config.monitoring.logging) {
        await this.logRequest(request, response, route);
      }

      return response;

    } catch (error) {
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
    } catch (error) {
      return this.createErrorResponse(400, `Validation error: ${(error instanceof Error ? error.message : String(error))}`);
    }
  }

  private async executeHandler(route: APIRoute, request: Request): Promise<Response> {
    const response = new Response(JSON.stringify({
      message: 'Request processed successfully',
      route: route.id,
      method: request.method,
      path: new URL(request.url).pathname
    }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json'
      }
    });

    return response;
  }

  private async logRequest(request: Request, response: Response, route: APIRoute): Promise<void> {
    const logData = {
      method: request.method,
      path: new URL(request.url).pathname,
      status: response.status,
      route: route.id,
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
    this.config.routes = this.config.routes.filter(route => route.id !== routeId);
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

  async healthCheck(): Promise<{ status: string; routes: number; uptime: number }> {
    return {
      status: 'healthy',
      routes: this.config.routes.length,
      uptime: process.uptime()
    };
  }

  private headersToObject(headers: Headers): Record<string, string> {
    const headerObj: Record<string, string> = {};
    headers.forEach((value, key) => {
      headerObj[key] = value;
    });
    return headerObj;
  }
}

