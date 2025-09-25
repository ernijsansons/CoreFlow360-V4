/**
 * CORS UTILITIES
 * Production-ready CORS handling for Cloudflare Workers
 */

export interface CorsOptions {
  origin?: string | string[] | ((origin: string) => boolean);
  methods?: string[];
  allowedHeaders?: string[];
  exposedHeaders?: string[];
  credentials?: boolean;
  maxAge?: number;
}

export class CorsHandler {
  private options: Required<CorsOptions>;

  constructor(options: CorsOptions = {}) {
    this.options = {
      origin: options.origin || '*',
      methods: options.methods || ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
      allowedHeaders: options.allowedHeaders || [
        'Content-Type',
        'Authorization',
        'X-Requested-With',
        'X-API-Key',
        'X-Business-ID',
        'X-CSRF-Token'
      ],
      exposedHeaders: options.exposedHeaders || [
        'X-Total-Count',
        'X-Page-Count',
        'X-Rate-Limit-Remaining',
        'X-Response-Time'
      ],
      credentials: options.credentials ?? true,
      maxAge: options.maxAge || 86400 // 24 hours
    };
  }

  /**
   * Handle CORS preflight requests
   */
  handlePreflight(request: Request): Response {
    const origin = request.headers.get('Origin');

    if (!this.isOriginAllowed(origin)) {
      return new Response(null, { status: 403 });
    }

    const headers = new Headers();

    // Set allowed origin
    if (this.options.credentials && origin) {
      headers.set('Access-Control-Allow-Origin', origin);
      headers.set('Vary', 'Origin');
    } else if (typeof this.options.origin === 'string') {
      headers.set('Access-Control-Allow-Origin', this.options.origin);
    }

    // Set allowed methods
    headers.set('Access-Control-Allow-Methods', this.options.methods.join(', '));

    // Set allowed headers
    const requestedHeaders = request.headers.get('Access-Control-Request-Headers');
    if (requestedHeaders) {
      const allowedHeaders = this.filterRequestedHeaders(requestedHeaders);
      if (allowedHeaders.length > 0) {
        headers.set('Access-Control-Allow-Headers', allowedHeaders.join(', '));
      }
    } else {
      headers.set('Access-Control-Allow-Headers', this.options.allowedHeaders.join(', '));
    }

    // Set credentials
    if (this.options.credentials) {
      headers.set('Access-Control-Allow-Credentials', 'true');
    }

    // Set max age
    headers.set('Access-Control-Max-Age', this.options.maxAge.toString());

    return new Response(null, {
      status: 204,
      headers
    });
  }

  /**
   * Add CORS headers to response
   */
  addHeaders(response: Response, request: Request): Response {
    const origin = request.headers.get('Origin');

    if (!this.isOriginAllowed(origin)) {
      return response;
    }

    const headers = new Headers(response.headers);

    // Set allowed origin
    if (this.options.credentials && origin) {
      headers.set('Access-Control-Allow-Origin', origin);
      headers.set('Vary', 'Origin');
    } else if (typeof this.options.origin === 'string') {
      headers.set('Access-Control-Allow-Origin', this.options.origin);
    }

    // Set exposed headers
    if (this.options.exposedHeaders.length > 0) {
      headers.set('Access-Control-Expose-Headers', this.options.exposedHeaders.join(', '));
    }

    // Set credentials
    if (this.options.credentials) {
      headers.set('Access-Control-Allow-Credentials', 'true');
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers
    });
  }

  /**
   * Check if origin is allowed
   */
  private isOriginAllowed(origin: string | null): boolean {
    if (!origin) {
      return true; // Allow requests without origin (same-origin)
    }

    if (this.options.origin === '*') {
      return true;
    }

    if (typeof this.options.origin === 'string') {
      return origin === this.options.origin;
    }

    if (Array.isArray(this.options.origin)) {
      return this.options.origin.includes(origin);
    }

    if (typeof this.options.origin === 'function') {
      return this.options.origin(origin);
    }

    return false;
  }

  /**
   * Filter requested headers against allowed headers
   */
  private filterRequestedHeaders(requestedHeaders: string): string[] {
    const requested = requestedHeaders
      .split(',')
      .map(header => header.trim().toLowerCase());

    const allowed = this.options.allowedHeaders.map(header => header.toLowerCase());

    return requested.filter(header => allowed.includes(header));
  }
}

/**
 * Create CORS handler from environment
 */
export function createCors(env: any): CorsHandler {
  const origins = env.CORS_ORIGINS?.split(',').map((origin: string) => origin.trim()) || ['*'];

  return new CorsHandler({
    origin: origins.length === 1 && origins[0] === '*' ? '*' : origins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'X-API-Key',
      'X-Business-ID',
      'X-CSRF-Token',
      'X-Request-ID',
      'X-Forwarded-For'
    ],
    exposedHeaders: [
      'X-Total-Count',
      'X-Page-Count',
      'X-Rate-Limit-Remaining',
      'X-Rate-Limit-Reset',
      'X-Response-Time',
      'X-Request-ID'
    ],
    maxAge: 86400 // 24 hours
  });
}

/**
 * Simple CORS middleware for quick setup
 */
export function simpleCors(request: Request, response: Response): Response {
  const corsHandler = new CorsHandler();

  if (request.method === 'OPTIONS') {
    return corsHandler.handlePreflight(request);
  }

  return corsHandler.addHeaders(response, request);
}