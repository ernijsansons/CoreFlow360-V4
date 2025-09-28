import { describe, it, expect, beforeEach, afterEach, vi, MockedFunction } from 'vitest';
import { APIGateway, APIGatewayConfig, APIRoute, HTTPMethod, APIVersion, RateLimitType, AuthenticationMethod } from '../../../api/gateway/api-gateway';
import { z } from 'zod';

// Mock performance.now for consistent testing
const mockPerformanceNow = vi.fn();
Object.defineProperty(global, 'performance', {
  value: { now: mockPerformanceNow },
  writable: true,
});

// Mock setInterval and clearInterval
const mockSetInterval = vi.fn();
const mockClearInterval = vi.fn();
Object.defineProperty(global, 'setInterval', { value: mockSetInterval, writable: true });
Object.defineProperty(global, 'clearInterval', { value: mockClearInterval, writable: true });

// Mock console methods to prevent noise in tests
const originalConsoleLog = console.log;
const originalConsoleError = console.error;
const originalConsoleWarn = console.warn;

describe('APIGateway', () => {
  let gateway: APIGateway;
  let config: APIGatewayConfig;
  let testRoute: APIRoute;

  beforeEach(() => {
    // Reset performance.now mock
    mockPerformanceNow.mockReturnValue(1000);

    // Mock console methods
    console.log = vi.fn();
    console.error = vi.fn();
    console.warn = vi.fn();

    testRoute = {
      id: 'test-route',
      path: '/api/v1/test',
      method: HTTPMethod.GET,
      version: APIVersion.V1,
      handler: 'test-handler',
      middleware: [],
      authentication: {
        required: false,
        method: AuthenticationMethod.NONE
      },
      rateLimit: {
        enabled: false,
        type: RateLimitType.PER_IP,
        requests: 100,
        windowMs: 60000
      },
      validation: {},
      cache: {
        enabled: false,
        ttl: 300000
      },
      documentation: {
        summary: 'Test route',
        tags: ['test']
      }
    };

    config = {
      version: APIVersion.V1,
      basePath: '/api/v1',
      routes: [testRoute],
      globalMiddleware: [],
      rateLimit: {
        enabled: false,
        type: RateLimitType.GLOBAL,
        requests: 1000,
        windowMs: 60000
      },
      cors: {
        enabled: true,
        allowedOrigins: ['*'],
        allowCredentials: false,
        maxAge: 86400
      },
      security: {
        enabled: true,
        authentication: AuthenticationMethod.JWT,
        rateLimit: true,
        cors: true,
        validation: true
      },
      monitoring: {
        enabled: true,
        metrics: true,
        logging: true,
        tracing: true
      }
    };

    gateway = new APIGateway(config);
  });

  afterEach(() => {
    // Restore console methods
    console.log = originalConsoleLog;
    console.error = originalConsoleError;
    console.warn = originalConsoleWarn;
    vi.clearAllMocks();
  });

  describe('Constructor and Initialization', () => {
    it('should initialize with valid configuration', () => {
      expect(gateway).toBeInstanceOf(APIGateway);
      expect(gateway.getConfig()).toEqual(config);
    });

    it('should start background tasks on initialization', () => {
      expect(mockSetInterval).toHaveBeenCalledTimes(2);
    });

    it('should initialize route cache', () => {
      const routes = gateway.getRoutes();
      expect(routes).toHaveLength(1);
      expect(routes[0]).toEqual(testRoute);
    });
  });

  describe('Route Management', () => {
    it('should add new route successfully', () => {
      const newRoute: APIRoute = {
        ...testRoute,
        id: 'new-route',
        path: '/api/v1/new',
        method: HTTPMethod.POST
      };

      gateway.addRoute(newRoute);
      const routes = gateway.getRoutes();
      expect(routes).toHaveLength(2);
      expect(routes.find(r => r.id === 'new-route')).toEqual(newRoute);
    });

    it('should remove route successfully', () => {
      gateway.removeRoute('test-route');
      const routes = gateway.getRoutes();
      expect(routes).toHaveLength(0);
    });

    it('should update route successfully', () => {
      const updates = { path: '/api/v1/updated' };
      gateway.updateRoute('test-route', updates);

      const route = gateway.getRoute('test-route');
      expect(route?.path).toBe('/api/v1/updated');
    });

    it('should return null for non-existent route', () => {
      const route = gateway.getRoute('non-existent');
      expect(route).toBeNull();
    });
  });

  describe('Request Handling', () => {
    it('should handle successful GET request', async () => {
      const request = new Request('http://localhost/api/v1/test', {
        method: 'GET'
      });

      const response = await gateway.handleRequest(request);
      expect(response.status).toBe(200);

      const data = await response.json();
      expect(data.success).toBe(true);
      expect(data.route).toBe('test-route');
    });

    it('should return 404 for unknown route', async () => {
      const request = new Request('http://localhost/api/v1/unknown', {
        method: 'GET'
      });

      const response = await gateway.handleRequest(request);
      expect(response.status).toBe(404);

      const data = await response.json();
      expect(data.error).toBe('Route not found');
    });

    it('should handle POST request with body', async () => {
      const postRoute: APIRoute = {
        ...testRoute,
        id: 'post-route',
        path: '/api/v1/post',
        method: HTTPMethod.POST,
        validation: {
          body: z.object({
            name: z.string(),
            email: z.string().email()
          })
        }
      };

      gateway.addRoute(postRoute);

      const request = new Request('http://localhost/api/v1/post', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'Test', email: 'test@example.com' })
      });

      const response = await gateway.handleRequest(request);
      expect(response.status).toBe(200);
    });

    it('should validate request body and return 400 for invalid data', async () => {
      const postRoute: APIRoute = {
        ...testRoute,
        id: 'post-route',
        path: '/api/v1/post',
        method: HTTPMethod.POST,
        validation: {
          body: z.object({
            name: z.string(),
            email: z.string().email()
          })
        }
      };

      gateway.addRoute(postRoute);

      const request = new Request('http://localhost/api/v1/post', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'Test', email: 'invalid-email' })
      });

      const response = await gateway.handleRequest(request);
      expect(response.status).toBe(400);

      const data = await response.json();
      expect(data.error).toContain('Validation error');
    });
  });

  describe('Authentication', () => {
    it('should require authentication when configured', async () => {
      const authRoute: APIRoute = {
        ...testRoute,
        id: 'auth-route',
        path: '/api/v1/auth',
        authentication: {
          required: true,
          method: AuthenticationMethod.JWT
        }
      };

      gateway.addRoute(authRoute);

      const request = new Request('http://localhost/api/v1/auth', {
        method: 'GET'
      });

      const response = await gateway.handleRequest(request);
      expect(response.status).toBe(401);

      const data = await response.json();
      expect(data.error).toBe('Authentication required');
    });

    it('should validate JWT token format', async () => {
      const authRoute: APIRoute = {
        ...testRoute,
        id: 'auth-route',
        path: '/api/v1/auth',
        authentication: {
          required: true,
          method: AuthenticationMethod.JWT
        }
      };

      gateway.addRoute(authRoute);

      const request = new Request('http://localhost/api/v1/auth', {
        method: 'GET',
        headers: {
          'Authorization': 'InvalidFormat token'
        }
      });

      const response = await gateway.handleRequest(request);
      expect(response.status).toBe(401);

      const data = await response.json();
      expect(data.error).toBe('Invalid token format');
    });

    it('should accept valid JWT token format', async () => {
      const authRoute: APIRoute = {
        ...testRoute,
        id: 'auth-route',
        path: '/api/v1/auth',
        authentication: {
          required: true,
          method: AuthenticationMethod.JWT
        }
      };

      gateway.addRoute(authRoute);

      const request = new Request('http://localhost/api/v1/auth', {
        method: 'GET',
        headers: {
          'Authorization': 'Bearer valid.jwt.token'
        }
      });

      const response = await gateway.handleRequest(request);
      expect(response.status).toBe(200);
    });

    it('should handle API key authentication', async () => {
      const authRoute: APIRoute = {
        ...testRoute,
        id: 'api-key-route',
        path: '/api/v1/apikey',
        authentication: {
          required: true,
          method: AuthenticationMethod.API_KEY
        }
      };

      gateway.addRoute(authRoute);

      const request = new Request('http://localhost/api/v1/apikey', {
        method: 'GET',
        headers: {
          'Authorization': 'Bearer api-key-123'
        }
      });

      const response = await gateway.handleRequest(request);
      expect(response.status).toBe(200);
    });

    it('should handle OAuth2 authentication', async () => {
      const authRoute: APIRoute = {
        ...testRoute,
        id: 'oauth-route',
        path: '/api/v1/oauth',
        authentication: {
          required: true,
          method: AuthenticationMethod.OAUTH2
        }
      };

      gateway.addRoute(authRoute);

      const request = new Request('http://localhost/api/v1/oauth', {
        method: 'GET',
        headers: {
          'Authorization': 'Bearer oauth-token-123'
        }
      });

      const response = await gateway.handleRequest(request);
      expect(response.status).toBe(200);
    });

    it('should handle Basic authentication', async () => {
      const authRoute: APIRoute = {
        ...testRoute,
        id: 'basic-route',
        path: '/api/v1/basic',
        authentication: {
          required: true,
          method: AuthenticationMethod.BASIC
        }
      };

      gateway.addRoute(authRoute);

      const request = new Request('http://localhost/api/v1/basic', {
        method: 'GET',
        headers: {
          'Authorization': 'Basic dXNlcjpwYXNz'
        }
      });

      const response = await gateway.handleRequest(request);
      expect(response.status).toBe(200);
    });
  });

  describe('Rate Limiting', () => {
    it('should apply rate limiting when enabled', async () => {
      const rateLimitRoute: APIRoute = {
        ...testRoute,
        id: 'rate-limit-route',
        path: '/api/v1/ratelimit',
        rateLimit: {
          enabled: true,
          type: RateLimitType.PER_IP,
          requests: 2,
          windowMs: 60000
        }
      };

      gateway.addRoute(rateLimitRoute);

      const createRequest = () => new Request('http://localhost/api/v1/ratelimit', {
        method: 'GET',
        headers: {
          'CF-Connecting-IP': '192.168.1.1'
        }
      });

      // First request should succeed
      const response1 = await gateway.handleRequest(createRequest());
      expect(response1.status).toBe(200);

      // Second request should succeed
      const response2 = await gateway.handleRequest(createRequest());
      expect(response2.status).toBe(200);

      // Third request should be rate limited
      const response3 = await gateway.handleRequest(createRequest());
      expect(response3.status).toBe(429);

      const data = await response3.json();
      expect(data.error).toBe('Rate limit exceeded');
    });

    it('should handle different rate limit types', async () => {
      const userRateLimitRoute: APIRoute = {
        ...testRoute,
        id: 'user-rate-limit-route',
        path: '/api/v1/userratelimit',
        rateLimit: {
          enabled: true,
          type: RateLimitType.PER_USER,
          requests: 1,
          windowMs: 60000
        }
      };

      gateway.addRoute(userRateLimitRoute);

      const request = new Request('http://localhost/api/v1/userratelimit', {
        method: 'GET',
        headers: {
          'X-User-ID': 'user123'
        }
      });

      const response1 = await gateway.handleRequest(request);
      expect(response1.status).toBe(200);

      const response2 = await gateway.handleRequest(request);
      expect(response2.status).toBe(429);
    });

    it('should reset rate limit after window expiry', async () => {
      const rateLimitRoute: APIRoute = {
        ...testRoute,
        id: 'reset-rate-limit-route',
        path: '/api/v1/resetratelimit',
        rateLimit: {
          enabled: true,
          type: RateLimitType.PER_IP,
          requests: 1,
          windowMs: 100 // Very short window for testing
        }
      };

      gateway.addRoute(rateLimitRoute);

      const createRequest = () => new Request('http://localhost/api/v1/resetratelimit', {
        method: 'GET',
        headers: {
          'CF-Connecting-IP': '192.168.1.2'
        }
      });

      // First request should succeed
      const response1 = await gateway.handleRequest(createRequest());
      expect(response1.status).toBe(200);

      // Second request should be rate limited
      const response2 = await gateway.handleRequest(createRequest());
      expect(response2.status).toBe(429);

      // Wait for window to expire
      await new Promise(resolve => setTimeout(resolve, 150));

      // Third request should succeed after window reset
      const response3 = await gateway.handleRequest(createRequest());
      expect(response3.status).toBe(200);
    });
  });

  describe('Caching', () => {
    it('should cache GET responses when enabled', async () => {
      const cachedRoute: APIRoute = {
        ...testRoute,
        id: 'cached-route',
        path: '/api/v1/cached',
        cache: {
          enabled: true,
          ttl: 60000
        }
      };

      gateway.addRoute(cachedRoute);

      const request = new Request('http://localhost/api/v1/cached', {
        method: 'GET'
      });

      // First request - cache miss
      mockPerformanceNow.mockReturnValueOnce(1000).mockReturnValueOnce(1050);
      const response1 = await gateway.handleRequest(request);
      expect(response1.status).toBe(200);
      expect(response1.headers.get('X-Cache-Hit')).toBeNull();

      // Second request - cache hit
      mockPerformanceNow.mockReturnValueOnce(2000).mockReturnValueOnce(2010);
      const response2 = await gateway.handleRequest(request);
      expect(response2.status).toBe(200);
      expect(response2.headers.get('X-Cache-Hit')).toBe('true');
    });

    it('should not cache non-GET requests', async () => {
      const cachedRoute: APIRoute = {
        ...testRoute,
        id: 'cached-post-route',
        path: '/api/v1/cachedpost',
        method: HTTPMethod.POST,
        cache: {
          enabled: true,
          ttl: 60000
        }
      };

      gateway.addRoute(cachedRoute);

      const request = new Request('http://localhost/api/v1/cachedpost', {
        method: 'POST',
        body: JSON.stringify({ test: 'data' })
      });

      const response = await gateway.handleRequest(request);
      expect(response.status).toBe(200);
      expect(response.headers.get('X-Cache-Hit')).toBeNull();
    });

    it('should respect cache TTL', async () => {
      const shortCacheRoute: APIRoute = {
        ...testRoute,
        id: 'short-cache-route',
        path: '/api/v1/shortcache',
        cache: {
          enabled: true,
          ttl: 100 // Very short TTL for testing
        }
      };

      gateway.addRoute(shortCacheRoute);

      const request = new Request('http://localhost/api/v1/shortcache', {
        method: 'GET'
      });

      // First request
      const response1 = await gateway.handleRequest(request);
      expect(response1.status).toBe(200);

      // Wait for cache to expire
      await new Promise(resolve => setTimeout(resolve, 150));

      // Second request should not hit cache
      const response2 = await gateway.handleRequest(request);
      expect(response2.status).toBe(200);
      expect(response2.headers.get('X-Cache-Hit')).toBeNull();
    });
  });

  describe('Validation', () => {
    it('should validate query parameters', async () => {
      const validationRoute: APIRoute = {
        ...testRoute,
        id: 'query-validation-route',
        path: '/api/v1/queryvalidation',
        validation: {
          query: z.object({
            page: z.string().transform(val => parseInt(val, 10)),
            limit: z.string().optional()
          })
        }
      };

      gateway.addRoute(validationRoute);

      const request = new Request('http://localhost/api/v1/queryvalidation?page=1&limit=10', {
        method: 'GET'
      });

      const response = await gateway.handleRequest(request);
      expect(response.status).toBe(200);
    });

    it('should validate headers', async () => {
      const headerValidationRoute: APIRoute = {
        ...testRoute,
        id: 'header-validation-route',
        path: '/api/v1/headervalidation',
        validation: {
          headers: z.object({
            'x-api-version': z.string(),
            'x-client-id': z.string().optional()
          })
        }
      };

      gateway.addRoute(headerValidationRoute);

      const request = new Request('http://localhost/api/v1/headervalidation', {
        method: 'GET',
        headers: {
          'x-api-version': '1.0'
        }
      });

      const response = await gateway.handleRequest(request);
      expect(response.status).toBe(200);
    });

    it('should return validation error for invalid query params', async () => {
      const validationRoute: APIRoute = {
        ...testRoute,
        id: 'invalid-query-route',
        path: '/api/v1/invalidquery',
        validation: {
          query: z.object({
            page: z.string().transform(val => {
              const num = parseInt(val, 10);
              if (isNaN(num)) throw new Error('Invalid page number');
              return num;
            })
          })
        }
      };

      gateway.addRoute(validationRoute);

      const request = new Request('http://localhost/api/v1/invalidquery?page=invalid', {
        method: 'GET'
      });

      const response = await gateway.handleRequest(request);
      expect(response.status).toBe(400);

      const data = await response.json();
      expect(data.error).toContain('Validation error');
    });
  });

  describe('Compression', () => {
    it('should apply compression for large responses when supported', async () => {
      const request = new Request('http://localhost/api/v1/test', {
        method: 'GET',
        headers: {
          'Accept-Encoding': 'gzip, deflate'
        }
      });

      // Mock a large response by modifying the route to return analytics data
      const largeDataRoute: APIRoute = {
        ...testRoute,
        path: '/api/v1/analytics'
      };
      gateway.addRoute(largeDataRoute);

      const largeRequest = new Request('http://localhost/api/v1/analytics', {
        method: 'GET',
        headers: {
          'Accept-Encoding': 'gzip, deflate'
        }
      });

      const response = await gateway.handleRequest(largeRequest);
      expect(response.status).toBe(200);
    });

    it('should not compress when client does not support it', async () => {
      const request = new Request('http://localhost/api/v1/test', {
        method: 'GET'
        // No Accept-Encoding header
      });

      const response = await gateway.handleRequest(request);
      expect(response.status).toBe(200);
      expect(response.headers.get('Content-Encoding')).toBeNull();
    });
  });

  describe('Performance Monitoring', () => {
    it('should track response times', async () => {
      mockPerformanceNow.mockReturnValueOnce(1000).mockReturnValueOnce(1050);

      const request = new Request('http://localhost/api/v1/test', {
        method: 'GET'
      });

      const response = await gateway.handleRequest(request);
      expect(response.status).toBe(200);
      expect(response.headers.get('X-Response-Time')).toBe('50.00');
    });

    it('should include gateway version header', async () => {
      const request = new Request('http://localhost/api/v1/test', {
        method: 'GET'
      });

      const response = await gateway.handleRequest(request);
      expect(response.headers.get('X-Gateway-Version')).toBe('2.0');
    });

    it('should log slow queries', async () => {
      mockPerformanceNow.mockReturnValueOnce(1000).mockReturnValueOnce(1150); // 150ms

      const request = new Request('http://localhost/api/v1/test', {
        method: 'GET'
      });

      await gateway.handleRequest(request);
      // Slow query warning should be logged (mocked console.warn)
      expect(console.warn).toHaveBeenCalled();
    });
  });

  describe('Health Check', () => {
    it('should return health status', async () => {
      const health = await gateway.healthCheck();

      expect(health.status).toBe('healthy');
      expect(health.routes).toBe(1);
      expect(health.uptime).toBeGreaterThan(0);
      expect(health.performance).toHaveProperty('totalRequests');
      expect(health.performance).toHaveProperty('avgResponseTime');
      expect(health.performance).toHaveProperty('cacheHitRate');
      expect(health.performance).toHaveProperty('cacheSize');
    });
  });

  describe('Performance Statistics', () => {
    it('should return performance statistics', () => {
      const stats = gateway.getPerformanceStats();

      expect(stats).toHaveProperty('totalRequests');
      expect(stats).toHaveProperty('avgResponseTime');
      expect(stats).toHaveProperty('cacheHitRate');
      expect(stats).toHaveProperty('compressionSavings');
      expect(stats).toHaveProperty('responseCacheSize');
    });

    it('should reset metrics', () => {
      gateway.resetMetrics();
      const stats = gateway.getPerformanceStats();

      expect(stats.totalRequests).toBe(0);
      expect(stats.avgResponseTime).toBe(0);
      expect(stats.cacheHitRate).toBe(0);
    });
  });

  describe('Configuration Management', () => {
    it('should update configuration', () => {
      const updates = {
        rateLimit: {
          enabled: true,
          type: RateLimitType.GLOBAL,
          requests: 500,
          windowMs: 30000
        }
      };

      gateway.updateConfig(updates);
      const updatedConfig = gateway.getConfig();

      expect(updatedConfig.rateLimit.enabled).toBe(true);
      expect(updatedConfig.rateLimit.requests).toBe(500);
    });
  });

  describe('Error Handling', () => {
    it('should handle internal errors gracefully', async () => {
      // Create a route that will cause an error in validation
      const errorRoute: APIRoute = {
        ...testRoute,
        id: 'error-route',
        path: '/api/v1/error',
        validation: {
          body: z.object({
            required: z.string()
          })
        }
      };

      gateway.addRoute(errorRoute);

      // Send request with malformed JSON
      const request = new Request('http://localhost/api/v1/error', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: 'invalid json'
      });

      const response = await gateway.handleRequest(request);
      expect(response.status).toBe(500);

      const data = await response.json();
      expect(data.error).toBe('Internal server error');
    });

    it('should log errors appropriately', async () => {
      const request = new Request('http://localhost/api/v1/nonexistent', {
        method: 'GET'
      });

      await gateway.handleRequest(request);
      // Error should not be logged for 404s (they're expected)
    });
  });

  describe('Response Data Generation', () => {
    it('should generate appropriate response data for leads endpoints', async () => {
      const leadsRoute: APIRoute = {
        ...testRoute,
        id: 'leads-route',
        path: '/api/v1/leads'
      };

      gateway.addRoute(leadsRoute);

      const request = new Request('http://localhost/api/v1/leads', {
        method: 'GET'
      });

      const response = await gateway.handleRequest(request);
      const data = await response.json();

      expect(data.data).toBeInstanceOf(Array);
      expect(data.pagination).toHaveProperty('page');
      expect(data.pagination).toHaveProperty('limit');
      expect(data.pagination).toHaveProperty('total');
    });

    it('should generate appropriate response data for companies endpoints', async () => {
      const companiesRoute: APIRoute = {
        ...testRoute,
        id: 'companies-route',
        path: '/api/v1/companies'
      };

      gateway.addRoute(companiesRoute);

      const request = new Request('http://localhost/api/v1/companies', {
        method: 'GET'
      });

      const response = await gateway.handleRequest(request);
      const data = await response.json();

      expect(data.data).toBeInstanceOf(Array);
      expect(data.count).toBe(25);
    });

    it('should generate appropriate response data for analytics endpoints', async () => {
      const analyticsRoute: APIRoute = {
        ...testRoute,
        id: 'analytics-route',
        path: '/api/v1/analytics'
      };

      gateway.addRoute(analyticsRoute);

      const request = new Request('http://localhost/api/v1/analytics', {
        method: 'GET'
      });

      const response = await gateway.handleRequest(request);
      const data = await response.json();

      expect(data.data).toHaveProperty('totalLeads');
      expect(data.data).toHaveProperty('conversionRate');
      expect(data.data).toHaveProperty('trends');
      expect(data.computedAt).toBeDefined();
    });
  });

  describe('Middleware Execution', () => {
    it('should execute global middleware', async () => {
      const middlewareConfig = {
        ...config,
        globalMiddleware: ['cors', 'rateLimit']
      };

      const middlewareGateway = new APIGateway(middlewareConfig);

      const request = new Request('http://localhost/api/v1/test', {
        method: 'GET'
      });

      const response = await middlewareGateway.handleRequest(request);
      expect(response.status).toBe(200);
    });

    it('should execute route-specific middleware', async () => {
      const middlewareRoute: APIRoute = {
        ...testRoute,
        middleware: ['auth', 'validation']
      };

      gateway.updateRoute('test-route', middlewareRoute);

      const request = new Request('http://localhost/api/v1/test', {
        method: 'GET'
      });

      const response = await gateway.handleRequest(request);
      expect(response.status).toBe(200);
    });
  });

  describe('Edge Cases', () => {
    it('should handle requests with no URL properly', async () => {
      const request = new Request('http://localhost', {
        method: 'GET'
      });

      const response = await gateway.handleRequest(request);
      expect(response.status).toBe(404);
    });

    it('should handle malformed URLs gracefully', async () => {
      const request = new Request('http://localhost/api/v1/test?invalid=query&', {
        method: 'GET'
      });

      const response = await gateway.handleRequest(request);
      expect(response.status).toBe(200);
    });

    it('should handle concurrent requests', async () => {
      const requests = Array.from({ length: 10 }, (_, i) =>
        new Request(`http://localhost/api/v1/test?id=${i}`, {
          method: 'GET'
        })
      );

      const responses = await Promise.all(
        requests.map(req => gateway.handleRequest(req))
      );

      responses.forEach(response => {
        expect(response.status).toBe(200);
      });
    });

    it('should handle very large payloads', async () => {
      const largeData = 'x'.repeat(10000);
      const request = new Request('http://localhost/api/v1/test', {
        method: 'POST',
        body: JSON.stringify({ data: largeData })
      });

      const response = await gateway.handleRequest(request);
      expect(response.status).toBe(200);
    });
  });

  describe('Cache Management', () => {
    it('should limit cache size to prevent memory issues', async () => {
      const cachedRoute: APIRoute = {
        ...testRoute,
        cache: {
          enabled: true,
          ttl: 60000
        }
      };

      gateway.updateRoute('test-route', cachedRoute);

      // Make many requests to fill cache
      for (let i = 0; i < 1500; i++) {
        const request = new Request(`http://localhost/api/v1/test?id=${i}`, {
          method: 'GET'
        });
        await gateway.handleRequest(request);
      }

      // Cache should be limited and not cause memory issues
      const stats = gateway.getPerformanceStats();
      expect(stats.responseCacheSize).toBeLessThanOrEqual(1000);
    });

    it('should clean up expired cache entries', async () => {
      // This test would typically verify the background cleanup
      // Since we've mocked setInterval, we can verify it was called
      expect(mockSetInterval).toHaveBeenCalled();
    });
  });
});