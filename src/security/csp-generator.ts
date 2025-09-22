/**
 * Content Security Policy Generator
 * Dynamic CSP generation based on context and requirements
 */

import { z } from 'zod';
import { Logger } from '../shared/logger';
import { CorrelationId } from '../shared/correlation-id';
import crypto from 'crypto';

export interface RequestContext {
  businessId: string;
  userId: string;
  module: string;
  role: string;
  endpoint: string;
  method: string;
  userAgent?: string;
}

export interface CSPRequirements {
  scripts: string[];
  styles: string[];
  apis: string[];
  images: string[];
  fonts: string[];
  media: string[];
  frames: string[];
  workers: string[];
}

export interface CSPDirective {
  [key: string]: string[];
}

export class CSPGenerator {
  private logger = new Logger();
  private nonceCache = new Map<string, string>();
  private requirementsCache = new Map<string, CSPRequirements>();

  /**
   * Generate dynamic CSP based on context
   */
  async generateCSP(context: RequestContext): Promise<string> {
    const correlationId = CorrelationId.generate();

    this.logger.debug('Generating CSP', {
      correlationId,
      context: {
        businessId: context.businessId,
        module: context.module,
        role: context.role
      }
    });

    // Analyze requirements based on context
    const requirements = await this.analyzeRequirements(context);

    // Generate nonce for this request
    const nonce = this.generateNonce();
    this.nonceCache.set(correlationId, nonce);

    // Build CSP directives
    const csp = await this.buildCSPDirectives(requirements, nonce, context);

    // Convert to string
    const cspString = this.directivesToString(csp);

    this.logger.info('CSP generated', {
      correlationId,
      length: cspString.length,
      directives: Object.keys(csp).length
    });

    return cspString;
  }

  /**
   * Analyze requirements for the current context
   */
  private async analyzeRequirements(context: RequestContext): Promise<CSPRequirements> {
    const cacheKey = `${context.businessId}-${context.module}-${context.role}`;

    // Check cache
    if (this.requirementsCache.has(cacheKey)) {
      return this.requirementsCache.get(cacheKey)!;
    }

    const requirements: CSPRequirements = {
      scripts: [],
      styles: [],
      apis: [],
      images: [],
      fonts: [],
      media: [],
      frames: [],
      workers: []
    };

    // Base requirements for all contexts
    requirements.scripts.push(
      'https://cdn.cloudflare.com',
      'https://cdnjs.cloudflare.com'
    );

    requirements.styles.push(
      'https://cdn.cloudflare.com',
      'https://fonts.googleapis.com'
    );

    requirements.fonts.push(
      'https://fonts.gstatic.com'
    );

    // Module-specific requirements
    switch (context.module) {
      case 'dashboard':
        requirements.scripts.push(
          'https://cdn.plot.ly',  // For charts
          'https://d3js.org'      // For visualizations
        );
        requirements.apis.push(
          'https://api.cloudflare.com/client/v4'
        );
        break;

      case 'chat':
        requirements.apis.push(
          'https://api.anthropic.com',
          'wss://*.cloudflare.com'  // WebSocket for real-time
        );
        requirements.media.push(
          'blob:',  // For file uploads
          'data:'   // For inline images
        );
        break;

      case 'finance':
        // Stricter requirements for financial module
        requirements.scripts = requirements.scripts.filter(s =>
          s.includes('cloudflare.com')
        );
        requirements.apis.push(
          'https://api.stripe.com',  // Payment processing
          'https://api.plaid.com'    // Banking
        );
        break;

      case 'agents':
        requirements.apis.push(
          'https://api.anthropic.com',
          'https://api.openai.com',
          'wss://*.cloudflare.com'
        );
        requirements.workers.push(
          'https://*.workers.dev'
        );
        break;

      default:
        // Minimal requirements for unknown modules
        break;
    }

    // Role-based adjustments
    if (context.role === 'admin' || context.role === 'owner') {
      requirements.apis.push(
        'https://api.github.com',  // For integrations
        'https://api.slack.com'    // For notifications
      );
    }

    // Cache the requirements
    this.requirementsCache.set(cacheKey, requirements);

    return requirements;
  }

  /**
   * Build CSP directives from requirements
   */
  private async buildCSPDirectives(
    requirements: CSPRequirements,
    nonce: string,
    context: RequestContext
  ): Promise<CSPDirective> {
    const csp: CSPDirective = {
      // Default source - very restrictive
      'default-src': ["'self'"],

      // Script sources with nonce
      'script-src': [
        "'self'",
        `'nonce-${nonce}'`,
        "'strict-dynamic'",  // Allow trusted scripts to load others
        ...requirements.scripts
      ],

      // Style sources
      'style-src': [
        "'self'",
        `'nonce-${nonce}'`,
        ...requirements.styles
      ],

      // API connections
      'connect-src': [
        "'self'",
        'https://*.cloudflare.com',
        ...requirements.apis
      ],

      // Images
      'img-src': [
        "'self'",
        'data:',
        'blob:',
        'https://*.cloudflare.com',
        ...requirements.images
      ],

      // Fonts
      'font-src': [
        "'self'",
        'data:',
        ...requirements.fonts
      ],

      // Media (audio/video)
      'media-src': [
        "'self'",
        ...requirements.media
      ],

      // Object/embed (plugins)
      'object-src': ["'none'"],

      // Frame ancestors (clickjacking protection)
      'frame-ancestors': ["'none'"],

      // Frame sources
      'frame-src': requirements.frames.length > 0 ? requirements.frames : ["'none'"],

      // Workers
      'worker-src': [
        "'self'",
        'blob:',
        ...requirements.workers
      ],

      // Child sources (iframes, workers)
      'child-src': [
        "'self'",
        'blob:',
        ...requirements.workers
      ],

      // Manifest
      'manifest-src': ["'self'"],

      // Form actions
      'form-action': ["'self'"],

      // Base URI
      'base-uri': ["'self'"],

      // Upgrade insecure requests
      'upgrade-insecure-requests': [],

      // Block mixed content
      'block-all-mixed-content': []
    };

    // Add report URI for CSP violations
    if (process.env.CSP_REPORT_URI) {
      csp['report-uri'] = [process.env.CSP_REPORT_URI];
      csp['report-to'] = ['csp-endpoint'];
    }

    // Adjust for development environment
    if (process.env.NODE_ENV === 'development') {
      // Allow inline scripts and styles in dev (with warning)
      csp['script-src'].push("'unsafe-inline'");
      csp['style-src'].push("'unsafe-inline'");

      this.logger.warn('CSP: Unsafe inline enabled for development', {
        context: context.module
      });
    }

    // Extra restrictions for sensitive modules
    if (context.module === 'finance' || context.module === 'admin') {
      // Remove unsafe-inline even in dev
      csp['script-src'] = csp['script-src'].filter(s => s !== "'unsafe-inline'");
      csp['style-src'] = csp['style-src'].filter(s => s !== "'unsafe-inline'");

      // Restrict to HTTPS only
      csp['connect-src'] = csp['connect-src'].map(s =>
        s.startsWith('ws://') ? s.replace('ws://', 'wss://') : s
      );
    }

    return csp;
  }

  /**
   * Generate cryptographically secure nonce
   */
  private generateNonce(): string {
    return crypto.randomBytes(16).toString('base64');
  }

  /**
   * Convert CSP directives to string
   */
  private directivesToString(directives: CSPDirective): string {
    return Object.entries(directives)
      .filter(([_, values]) => values.length > 0)
      .map(([directive, values]) => {
        if (values.length === 0 ||
            directive === 'upgrade-insecure-requests' ||
            directive === 'block-all-mixed-content') {
          return directive;
        }
        return `${directive} ${values.join(' ')}`;
      })
      .join('; ');
  }

  /**
   * Validate CSP string
   */
  validateCSP(csp: string): boolean {
    const directives = csp.split(';').map(d => d.trim());
    const validDirectives = new Set([
      'default-src', 'script-src', 'style-src', 'img-src',
      'connect-src', 'font-src', 'object-src', 'media-src',
      'frame-src', 'child-src', 'worker-src', 'frame-ancestors',
      'form-action', 'base-uri', 'manifest-src',
      'upgrade-insecure-requests', 'block-all-mixed-content',
      'report-uri', 'report-to'
    ]);

    for (const directive of directives) {
      if (!directive) continue;

      const directiveName = directive.split(' ')[0];
      if (!validDirectives.has(directiveName)) {
        this.logger.warn('Invalid CSP directive', { directive: directiveName });
        return false;
      }
    }

    return true;
  }

  /**
   * Get nonce for current request
   */
  getNonce(correlationId: string): string | undefined {
    return this.nonceCache.get(correlationId);
  }

  /**
   * Clear nonce after request
   */
  clearNonce(correlationId: string): void {
    this.nonceCache.delete(correlationId);
  }

  /**
   * Generate CSP report-to header
   */
  generateReportTo(): string {
    return JSON.stringify({
      group: 'csp-endpoint',
      max_age: 10886400,  // 126 days
      endpoints: [{
        url: process.env.CSP_REPORT_URI || 'https://csp.coreflow360.com/report'
      }]
    });
  }

  /**
   * Analyze CSP violations
   */
  async analyzeViolation(violation: any): Promise<void> {
    this.logger.warn('CSP Violation', {
      documentUri: violation['document-uri'],
      violatedDirective: violation['violated-directive'],
      blockedUri: violation['blocked-uri'],
      lineNumber: violation['line-number'],
      columnNumber: violation['column-number'],
      sourceFile: violation['source-file']
    });

    // Check if this is a known false positive
    if (this.isFalsePositive(violation)) {
      return;
    }

    // Check if this indicates an attack
    if (this.isPotentialAttack(violation)) {
      this.logger.error('Potential XSS attack detected via CSP', {
        violation,
        severity: 'HIGH'
      });

      // Alert security team
      await this.alertSecurityTeam(violation);
    }
  }

  /**
   * Check if violation is a false positive
   */
  private isFalsePositive(violation: any): boolean {
    const falsePositives = [
      'chrome-extension://',
      'moz-extension://',
      'safari-extension://',
      'about:blank',
      'data:image'
    ];

    const blockedUri = violation['blocked-uri'] || '';
    return falsePositives.some(fp => blockedUri.startsWith(fp));
  }

  /**
   * Check if violation indicates an attack
   */
  private isPotentialAttack(violation: any): boolean {
    const attackIndicators = [
      'javascript:',
      'data:text/html',
      'vbscript:',
      '<script',
      'onerror=',
      'onload=',
      'eval(',
      'alert(',
      'document.write'
    ];

    const blockedUri = violation['blocked-uri'] || '';
    const sourceFile = violation['source-file'] || '';

    return attackIndicators.some(indicator =>
      blockedUri.includes(indicator) || sourceFile.includes(indicator)
    );
  }

  /**
   * Alert security team about potential attacks
   */
  private async alertSecurityTeam(violation: any): Promise<void> {
    // Implementation would send alerts to security team
    // Via Slack, PagerDuty, email, etc.
  }
}