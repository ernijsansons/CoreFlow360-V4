export interface CORSConfig {
  allowedOrigins: string[];
  allowCredentials?: boolean;
  maxAge?: number;
  allowedMethods?: string[];
  allowedHeaders?: string[];
}

export class CORSUtils {
  private static getDefaultAllowedOrigins(environment?: string): string[] {
    const production = [
      'https://app.coreflow360.com',
      'https://dashboard.coreflow360.com',
      'https://admin.coreflow360.com',
      'https://coreflow360.com',
      'https://www.coreflow360.com'
    ];

    if (environment === 'development') {
      return [
        ...production,
        'http://localhost:3000',
        'http://localhost:3001',
        'http://localhost:5173',
        'http://127.0.0.1:3000',
        'http://127.0.0.1:3001',
        'http://127.0.0.1:5173'
      ];
    }

    return production;
  }

  static setCORSHeaders(
    headers: Record<string, string>,
    origin: string | null,
    config?: Partial<CORSConfig & { environment?: string }>
  ): void {
    const allowedOrigins = config?.allowedOrigins || this.getDefaultAllowedOrigins(config?.environment);

    if (origin && allowedOrigins.includes(origin)) {
      headers['Access-Control-Allow-Origin'] = origin;
      if (config?.allowCredentials !== false) {
        headers['Access-Control-Allow-Credentials'] = 'true';
      }
    } else if (!origin) {
      headers['Access-Control-Allow-Origin'] = '*';
    }

    headers['Access-Control-Allow-Methods'] = config?.allowedMethods?.join(', ') || 'GET, POST, PUT, PATCH, DELETE, OPTIONS';
    headers['Access-Control-Allow-Headers'] = config?.allowedHeaders?.join(', ') || 'Content-Type, Authorization, X-API-Key, X-Business-ID';
  }

  static validateCORSRequest(origin: string | null, allowedOrigins?: string[], environment?: string): boolean {
    const origins = allowedOrigins || this.getDefaultAllowedOrigins(environment);
    return !origin || origins.includes(origin);
  }
}