/**
 * Advanced XSS Protection with Context-Aware Sanitization
 * AI-powered XSS detection and prevention system
 */

import { z } from 'zod';
import { Logger } from '../shared/logger';
import { CorrelationId } from '../shared/correlation-id';

export type XSSContext =
  | 'html'
  | 'html_attribute'
  | 'css'
  | 'javascript'
  | 'url'
  | 'json'
  | 'xml'
  | 'sql'
  | 'markdown'
  | 'plain_text';

export type SanitizationLevel = 'strict' | 'moderate' | 'permissive';

export interface XSSDetectionResult {
  isXSS: boolean;
  confidence: number;
  attackType: XSSAttackType[];
  maliciousPayloads: string[];
  sanitizedContent: string;
  blocked: boolean;
  reason?: string;
  recommendations: string[];
}

export type XSSAttackType =
  | 'reflected'
  | 'stored'
  | 'dom_based'
  | 'mutation_based'
  | 'filter_evasion'
  | 'polyglot'
  | 'blind'
  | 'self_xss'
  | 'universal_xss'
  | 'scriptless';

export interface XSSProtectionConfig {
  enabled: boolean;
  level: SanitizationLevel;
  blockOnDetection: boolean;
  logViolations: boolean;
  contextualSanitization: boolean;
  aiDetection: boolean;
  mutationObserver: boolean;
  cspIntegration: boolean;
  customRules: XSSRule[];
}

export interface XSSRule {
  id: string;
  name: string;
  pattern: RegExp;
  context: XSSContext[];
  severity: 'low' | 'medium' | 'high' | 'critical';
  action: 'sanitize' | 'block' | 'warn';
  description: string;
}

export interface SanitizationContext {
  context: XSSContext;
  allowedTags?: string[];
  allowedAttributes?: string[];
  allowedProtocols?: string[];
  preserveWhitespace?: boolean;
  businessId: string;
  userId: string;
  endpoint: string;
}

export class AdvancedXSSProtection {
  private logger = new Logger();
  private xssPatterns: XSSPattern[] = [];
  private aiModel: XSSDetectionModel;
  private mutationObserver: MutationObserverProtection;

  constructor(private config: XSSProtectionConfig) {
    this.initializePatterns();
    this.aiModel = new XSSDetectionModel();
    this.mutationObserver = new MutationObserverProtection();
  }

  /**
   * Main XSS protection function
   */
  async protectContent(
    content: string,
    context: SanitizationContext,
    correlationId?: string
  ): Promise<XSSDetectionResult> {
    const requestId = correlationId || CorrelationId.generate();

    this.logger.debug('XSS protection analysis started', {
      correlationId: requestId,
      context: context.context,
      contentLength: content.length,
      businessId: context.businessId
    });

    try {
      // Step 1: Pattern-based detection
      const patternResult = await this.detectPatternBasedXSS(content, context);

      // Step 2: AI-powered detection
      const aiResult = this.config.aiDetection ?
        await this.aiModel.detectXSS(content, context) :
        { isXSS: false, confidence: 0, attackTypes: [] };

      // Step 3: Context-aware sanitization
      const sanitizedContent = this.config.contextualSanitization ?
        await this.contextualSanitize(content, context) :
        await this.basicSanitize(content);

      // Step 4: Mutation analysis
      const mutationResult = this.config.mutationObserver ?
        await this.mutationObserver.analyzeForMutation(content, context) :
        { hasMutation: false, confidence: 0 };

      // Combine results
      const finalResult = this.combineDetectionResults(
        patternResult,
        aiResult,
        mutationResult,
        sanitizedContent,
        context
      );

      // Logging and monitoring
      if (finalResult.isXSS) {
        this.logger.warn('XSS attack detected and blocked', {
          correlationId: requestId,
          confidence: finalResult.confidence,
          attackTypes: finalResult.attackType,
          businessId: context.businessId,
          userId: context.userId,
          endpoint: context.endpoint
        });

        // Record security event
        await this.recordXSSEvent(finalResult, context, requestId);
      }

      return finalResult;

    } catch (error) {
      this.logger.error('XSS protection error', error, {
        correlationId: requestId,
        context: context.context
      });

      // Fail safe - block content on error
      return {
        isXSS: true,
        confidence: 1.0,
        attackType: ['unknown'],
        maliciousPayloads: [],
        sanitizedContent: '',
        blocked: true,
        reason: 'XSS protection error - content blocked for safety',
        recommendations: ['Contact security team', 'Review content format']
      };
    }
  }

  /**
   * Pattern-based XSS detection
   */
  private async detectPatternBasedXSS(
    content: string,
    context: SanitizationContext
  ): Promise<PatternDetectionResult> {
    const detectedPatterns: DetectedPattern[] = [];
    let highestConfidence = 0;

    for (const pattern of this.xssPatterns) {
      // Skip patterns not applicable to this context
      if (pattern.contexts.length > 0 && !pattern.contexts.includes(context.context)) {
        continue;
      }

      const matches = content.match(pattern.regex);
      if (matches) {
        const confidence = this.calculatePatternConfidence(pattern, matches, content);

        detectedPatterns.push({
          pattern: pattern.name,
          matches: matches,
          confidence,
          severity: pattern.severity,
          attackType: pattern.attackType
        });

        highestConfidence = Math.max(highestConfidence, confidence);
      }
    }

    // Check for evasion techniques
    const evasionResult = this.detectEvasionTechniques(content);
    if (evasionResult.detected) {
      highestConfidence = Math.max(highestConfidence, evasionResult.confidence);
      detectedPatterns.push(...evasionResult.patterns);
    }

    return {
      isXSS: detectedPatterns.length > 0,
      confidence: highestConfidence,
      patterns: detectedPatterns,
      attackTypes: [...new Set(detectedPatterns.map(p => p.attackType))]
    };
  }

  /**
   * Context-aware sanitization
   */
  private async contextualSanitize(
    content: string,
    context: SanitizationContext
  ): Promise<string> {
    switch (context.context) {
      case 'html':
        return this.sanitizeHTML(content, context);

      case 'html_attribute':
        return this.sanitizeHTMLAttribute(content, context);

      case 'css':
        return this.sanitizeCSS(content, context);

      case 'javascript':
        return this.sanitizeJavaScript(content, context);

      case 'url':
        return this.sanitizeURL(content, context);

      case 'json':
        return this.sanitizeJSON(content, context);

      case 'xml':
        return this.sanitizeXML(content, context);

      case 'markdown':
        return this.sanitizeMarkdown(content, context);

      case 'sql':
        return this.sanitizeSQL(content, context);

      case 'plain_text':
      default:
        return this.sanitizePlainText(content, context);
    }
  }

  /**
   * HTML sanitization with allowed tags/attributes
   */
  private sanitizeHTML(content: string, context: SanitizationContext): string {
    const allowedTags = context.allowedTags || [
      'p', 'br', 'strong', 'em', 'u', 'i', 'b',
      'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
      'blockquote', 'code', 'pre'
    ];

    const allowedAttributes = context.allowedAttributes || [
      'class', 'id', 'title', 'alt'
    ];

    // Remove dangerous tags
    let sanitized = content.replace(
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, ''
    );

    sanitized = sanitized.replace(
      /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, ''
    );

    sanitized = sanitized.replace(
      /<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi, ''
    );

    sanitized = sanitized.replace(
      /<embed\b[^>]*>/gi, ''
    );

    // Remove event handlers
    sanitized = sanitized.replace(/on\w+\s*=\s*['""][^'"]*['"]/gi, '');

    // Remove javascript: urls
    sanitized = sanitized.replace(/javascript:/gi, '');

    // Allow only whitelisted tags
    sanitized = sanitized.replace(
      /<(\/?)([\w-]+)([^>]*)>/gi,
      (match, slash, tag, attributes) => {
        if (!allowedTags.includes(tag.toLowerCase())) {
          return '';
        }

        // Sanitize attributes
        const cleanAttributes = this.sanitizeAttributes(attributes, allowedAttributes);
        return `<${slash}${tag}${cleanAttributes}>`;
      }
    );

    return sanitized;
  }

  /**
   * HTML attribute sanitization
   */
  private sanitizeHTMLAttribute(content: string, context: SanitizationContext): string {
    // Remove quotes and potential script injection
    let sanitized = content.replace(/['"]/g, '');

    // Remove potentially dangerous characters
    sanitized = sanitized.replace(/[<>&]/g, (char) => {
      switch (char) {
        case '<': return '&lt;';
        case '>': return '&gt;';
        case '&': return '&amp;';
        default: return char;
      }
    });

    // Remove javascript: and data: protocols
    sanitized = sanitized.replace(/(javascript|data|vbscript):/gi, '');

    return sanitized;
  }

  /**
   * CSS sanitization
   */
  private sanitizeCSS(content: string, context: SanitizationContext): string {
    // Remove expressions and javascript
    let sanitized = content.replace(/expression\s*\(/gi, '');
    sanitized = sanitized.replace(/javascript:/gi, '');
    sanitized = sanitized.replace(/@import/gi, '');
    sanitized = sanitized.replace(/binding\s*:/gi, '');
    sanitized = sanitized.replace(/behavior\s*:/gi, '');

    // Remove url() with javascript
    sanitized = sanitized.replace(/url\s*\(\s*['"]?\s*javascript:/gi, 'url(');

    return sanitized;
  }

  /**
   * JavaScript sanitization (very restrictive)
   */
  private sanitizeJavaScript(content: string, context: SanitizationContext): string {
    // For maximum security, remove most JavaScript constructs
    if (this.config.level === 'strict') {
      return ''; // Block all JavaScript in strict mode
    }

    let sanitized = content;

    // Remove dangerous functions
    const dangerousFunctions = [
      'eval', 'setTimeout', 'setInterval', 'Function',
      'document.write', 'document.writeln', 'innerHTML',
      'outerHTML', 'insertAdjacentHTML'
    ];

    for (const func of dangerousFunctions) {
      const regex = new RegExp(`\\b${func}\\s*\\(`, 'gi');
      sanitized = sanitized.replace(regex, '');
    }

    // Remove script tags
    sanitized = sanitized.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');

    return sanitized;
  }

  /**
   * URL sanitization
   */
  private sanitizeURL(content: string, context: SanitizationContext): string {
    const allowedProtocols = context.allowedProtocols || ['http', 'https', 'mailto', 'tel'];

    try {
      const url = new URL(content);

      if (!allowedProtocols.includes(url.protocol.replace(':', ''))) {
        return '';
      }

      // Remove javascript: and data: protocols
      if (url.protocol === 'javascript:' || url.protocol === 'data:') {
        return '';
      }

      return url.toString();
    } catch {
      // Invalid URL, sanitize as plain text
      return this.sanitizePlainText(content, context);
    }
  }

  /**
   * JSON sanitization
   */
  private sanitizeJSON(content: string, context: SanitizationContext): string {
    try {
      const parsed = JSON.parse(content);

      // Recursively sanitize JSON values
      const sanitized = this.sanitizeJSONValue(parsed, context);

      return JSON.stringify(sanitized);
    } catch {
      // Invalid JSON, return empty object
      return '{}';
    }
  }

  /**
   * Basic sanitization fallback
   */
  private async basicSanitize(content: string): Promise<string> {
    // HTML encode dangerous characters
    return content
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }

  /**
   * Detect evasion techniques
   */
  private detectEvasionTechniques(content: string): EvasionDetectionResult {
    const evasionPatterns: DetectedPattern[] = [];
    let maxConfidence = 0;

    // Unicode evasion
    if (/[\u0000-\u001f\u007f-\u009f]/.test(content)) {
      evasionPatterns.push({
        pattern: 'Unicode Control Characters',
        matches: [content.match(/[\u0000-\u001f\u007f-\u009f]/g)?.join('') || ''],
        confidence: 0.7,
        severity: 'medium',
        attackType: 'filter_evasion'
      });
      maxConfidence = Math.max(maxConfidence, 0.7);
    }

    // HTML entity evasion
    if (/&#x?[0-9a-f]+;/i.test(content)) {
      const entityMatches = content.match(/&#x?[0-9a-f]+;/gi) || [];
      const decodedEntities = entityMatches.map(entity => {
        const isHex = entity.startsWith('&#x');
        const numStr = entity.slice(isHex ? 3 : 2, -1);
        const num = parseInt(numStr, isHex ? 16 : 10);
        return String.fromCharCode(num);
      }).join('');

      if (/<script|javascript:|on\w+=/i.test(decodedEntities)) {
        evasionPatterns.push({
          pattern: 'HTML Entity Evasion',
          matches: entityMatches,
          confidence: 0.9,
          severity: 'high',
          attackType: 'filter_evasion'
        });
        maxConfidence = Math.max(maxConfidence, 0.9);
      }
    }

    // Base64 evasion
    const base64Pattern = /[A-Za-z0-9+/]{4,}={0,2}/g;
    const base64Matches = content.match(base64Pattern) || [];

    for (const match of base64Matches) {
      try {
        const decoded = atob(match);
        if (/<script|javascript:|on\w+=/i.test(decoded)) {
          evasionPatterns.push({
            pattern: 'Base64 Encoded XSS',
            matches: [match],
            confidence: 0.8,
            severity: 'high',
            attackType: 'filter_evasion'
          });
          maxConfidence = Math.max(maxConfidence, 0.8);
        }
      } catch {
        // Invalid base64, ignore
      }
    }

    return {
      detected: evasionPatterns.length > 0,
      confidence: maxConfidence,
      patterns: evasionPatterns
    };
  }

  /**
   * Initialize XSS patterns
   */
  private initializePatterns(): void {
    this.xssPatterns = [
      {
        name: 'Script Tag Injection',
        regex: /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
        severity: 'critical',
        attackType: 'reflected',
        contexts: ['html']
      },
      {
        name: 'Event Handler Injection',
        regex: /on\w+\s*=\s*['""]?[^'"">\s]+/gi,
        severity: 'high',
        attackType: 'reflected',
        contexts: ['html', 'html_attribute']
      },
      {
        name: 'JavaScript URL',
        regex: /javascript:\s*[^'"">\s]+/gi,
        severity: 'high',
        attackType: 'reflected',
        contexts: ['html', 'url']
      },
      {
        name: 'Data URL with Script',
        regex: /data:text\/html[^,]*,[\s\S]*<script/gi,
        severity: 'critical',
        attackType: 'reflected',
        contexts: ['url']
      },
      {
        name: 'SVG XSS',
        regex: /<svg[\s\S]*?on\w+[\s\S]*?>/gi,
        severity: 'high',
        attackType: 'reflected',
        contexts: ['html']
      },
      {
        name: 'CSS Expression',
        regex: /expression\s*\(\s*[^)]+\)/gi,
        severity: 'medium',
        attackType: 'reflected',
        contexts: ['css']
      },
      {
        name: 'Angular Template Injection',
        regex: /\{\{[\s\S]*?\}\}/g,
        severity: 'medium',
        attackType: 'reflected',
        contexts: ['html']
      },
      {
        name: 'Vue Template Injection',
        regex: /v-[\w-]+\s*=\s*['""][^'""]*['"]/gi,
        severity: 'medium',
        attackType: 'reflected',
        contexts: ['html']
      }
    ];
  }

  /**
   * Helper methods
   */
  private combineDetectionResults(
    patternResult: PatternDetectionResult,
    aiResult: AIDetectionResult,
    mutationResult: MutationDetectionResult,
    sanitizedContent: string,
    context: SanitizationContext
  ): XSSDetectionResult {
    const isXSS = patternResult.isXSS || aiResult.isXSS || mutationResult.hasMutation;
    const confidence = Math.max(
      patternResult.confidence,
      aiResult.confidence,
      mutationResult.confidence
    );

    const attackTypes = [
      ...patternResult.attackTypes,
      ...aiResult.attackTypes,
      ...(mutationResult.hasMutation ? ['mutation_based' as XSSAttackType] : [])
    ];

    const shouldBlock = isXSS && (
      this.config.blockOnDetection ||
      confidence > 0.8 ||
      attackTypes.some(type => ['reflected', 'stored', 'dom_based'].includes(type))
    );

    return {
      isXSS,
      confidence,
      attackType: [...new Set(attackTypes)],
      maliciousPayloads: patternResult.patterns.map(p => p.matches[0]),
      sanitizedContent: shouldBlock ? '' : sanitizedContent,
      blocked: shouldBlock,
      reason: shouldBlock ? `XSS detected with ${Math.round(confidence * 100)}% confidence` : undefined,
      recommendations: this.generateRecommendations(isXSS, attackTypes, context)
    };
  }

  private calculatePatternConfidence(
    pattern: XSSPattern,
    matches: RegExpMatchArray,
    content: string
  ): number {
    let confidence = 0.5; // Base confidence

    // Increase confidence based on severity
    switch (pattern.severity) {
      case 'critical': confidence = 0.9; break;
      case 'high': confidence = 0.8; break;
      case 'medium': confidence = 0.6; break;
      case 'low': confidence = 0.4; break;
    }

    // Adjust based on context
    if (matches.length > 1) confidence += 0.1;
    if (matches[0].length > content.length * 0.1) confidence += 0.1;

    return Math.min(confidence, 1.0);
  }

  private sanitizeAttributes(attributes: string, allowed: string[]): string {
    return attributes.replace(
      /(\w+)\s*=\s*['""]([^'""]*)["'"]/g,
      (match, attr, value) => {
        if (!allowed.includes(attr.toLowerCase())) {
          return '';
        }

        // Sanitize attribute value
        const cleanValue = value.replace(/[<>&'"]/g, '');
        return ` ${attr}="${cleanValue}"`;
      }
    );
  }

  private sanitizeJSONValue(value: any, context: SanitizationContext): any {
    if (typeof value === 'string') {
      return this.sanitizePlainText(value, context);
    } else if (Array.isArray(value)) {
      return value.map(item => this.sanitizeJSONValue(item, context));
    } else if (typeof value === 'object' && value !== null) {
      const sanitized: any = {};
      for (const [key, val] of Object.entries(value)) {
        sanitized[key] = this.sanitizeJSONValue(val, context);
      }
      return sanitized;
    }
    return value;
  }

  private sanitizeXML(content: string, context: SanitizationContext): string {
    // Remove CDATA sections that might contain scripts
    let sanitized = content.replace(/<!\[CDATA\[[\s\S]*?\]\]>/gi, '');

    // Remove processing instructions
    sanitized = sanitized.replace(/<\?[\s\S]*?\?>/gi, '');

    // Apply HTML sanitization rules
    return this.sanitizeHTML(sanitized, context);
  }

  private sanitizeMarkdown(content: string, context: SanitizationContext): string {
    // Remove script tags from markdown
    let sanitized = content.replace(/```javascript[\s\S]*?```/gi, '```\n// JavaScript code removed\n```');

    // Remove HTML script tags
    sanitized = sanitized.replace(/<script[\s\S]*?<\/script>/gi, '');

    // Sanitize HTML in markdown
    sanitized = sanitized.replace(/<[^>]+>/g, (match) => {
      const tempContext: SanitizationContext = { ...context, context: 'html' };
      return this.sanitizeHTML(match, tempContext);
    });

    return sanitized;
  }

  private sanitizeSQL(content: string, context: SanitizationContext): string {
    // This is a basic implementation - would integrate with SQL injection guard
    return content
      .replace(/['"]/g, "''")
      .replace(/;/g, '')
      .replace(/--/g, '')
      .replace(/\/\*/g, '')
      .replace(/\*\//g, '');
  }

  private sanitizePlainText(content: string, context: SanitizationContext): string {
    return content
      .replace(/[<>&"']/g, (char) => {
        switch (char) {
          case '<': return '&lt;';
          case '>': return '&gt;';
          case '&': return '&amp;';
          case '"': return '&quot;';
          case "'": return '&#x27;';
          default: return char;
        }
      });
  }

  private generateRecommendations(
    isXSS: boolean,
    attackTypes: XSSAttackType[],
    context: SanitizationContext
  ): string[] {
    const recommendations: string[] = [];

    if (isXSS) {
      recommendations.push('Content contains potential XSS attack');

      if (attackTypes.includes('reflected')) {
        recommendations.push('Implement input validation and output encoding');
      }

      if (attackTypes.includes('stored')) {
        recommendations.push('Sanitize content before storing in database');
      }

      if (attackTypes.includes('dom_based')) {
        recommendations.push('Validate DOM manipulation on client-side');
      }

      if (attackTypes.includes('filter_evasion')) {
        recommendations.push('Review input filters for bypass techniques');
      }

      recommendations.push('Consider implementing Content Security Policy');
      recommendations.push('Use context-aware output encoding');
    }

    return recommendations;
  }

  private async recordXSSEvent(
    result: XSSDetectionResult,
    context: SanitizationContext,
    correlationId: string
  ): Promise<void> {
    // This would integrate with the audit system
    this.logger.warn('XSS attack recorded', {
      correlationId,
      confidence: result.confidence,
      attackTypes: result.attackType,
      context: context.context,
      businessId: context.businessId,
      userId: context.userId
    });
  }
}

/**
 * AI-powered XSS detection model
 */
class XSSDetectionModel {
  async detectXSS(content: string, context: SanitizationContext): Promise<AIDetectionResult> {
    // Simplified AI detection - would use actual ML model
    const features = this.extractFeatures(content);
    const score = this.calculateAIScore(features);

    return {
      isXSS: score > 0.7,
      confidence: score,
      attackTypes: this.predictAttackTypes(features)
    };
  }

  private extractFeatures(content: string): XSSFeatures {
    return {
      hasScriptTags: /<script/i.test(content),
      hasEventHandlers: /on\w+\s*=/i.test(content),
      hasJavaScriptURL: /javascript:/i.test(content),
      hasHTMLEntities: /&#\w+;/.test(content),
      hasSpecialChars: /[<>"']/.test(content),
      length: content.length,
      suspiciousKeywords: this.countSuspiciousKeywords(content)
    };
  }

  private calculateAIScore(features: XSSFeatures): number {
    let score = 0;

    if (features.hasScriptTags) score += 0.5;
    if (features.hasEventHandlers) score += 0.4;
    if (features.hasJavaScriptURL) score += 0.4;
    if (features.hasHTMLEntities) score += 0.2;
    if (features.suspiciousKeywords > 2) score += 0.3;

    return Math.min(score, 1.0);
  }

  private predictAttackTypes(features: XSSFeatures): XSSAttackType[] {
    const types: XSSAttackType[] = [];

    if (features.hasScriptTags) types.push('reflected');
    if (features.hasEventHandlers) types.push('reflected');
    if (features.hasJavaScriptURL) types.push('reflected');
    if (features.hasHTMLEntities) types.push('filter_evasion');

    return types;
  }

  private countSuspiciousKeywords(content: string): number {
    const keywords = ['alert', 'prompt', 'confirm', 'eval', 'document', 'window', 'location'];
    return keywords.filter(keyword => content.toLowerCase().includes(keyword)).length;
  }
}

/**
 * Mutation observer protection
 */
class MutationObserverProtection {
  async analyzeForMutation(content: string, context: SanitizationContext): Promise<MutationDetectionResult> {
    // Check for DOM mutation patterns
    const hasDOMManipulation = /innerHTML|outerHTML|insertAdjacentHTML|document\.write/i.test(content);
    const hasEventListeners = /addEventListener|attachEvent/i.test(content);

    const confidence = (hasDOMManipulation ? 0.6 : 0) + (hasEventListeners ? 0.4 : 0);

    return {
      hasMutation: confidence > 0,
      confidence,
      mutationType: hasDOMManipulation ? 'dom_manipulation' : 'event_binding'
    };
  }
}

// Interfaces
interface XSSPattern {
  name: string;
  regex: RegExp;
  severity: 'low' | 'medium' | 'high' | 'critical';
  attackType: XSSAttackType;
  contexts: XSSContext[];
}

interface PatternDetectionResult {
  isXSS: boolean;
  confidence: number;
  patterns: DetectedPattern[];
  attackTypes: XSSAttackType[];
}

interface DetectedPattern {
  pattern: string;
  matches: string[];
  confidence: number;
  severity: string;
  attackType: XSSAttackType;
}

interface AIDetectionResult {
  isXSS: boolean;
  confidence: number;
  attackTypes: XSSAttackType[];
}

interface EvasionDetectionResult {
  detected: boolean;
  confidence: number;
  patterns: DetectedPattern[];
}

interface MutationDetectionResult {
  hasMutation: boolean;
  confidence: number;
  mutationType?: string;
}

interface XSSFeatures {
  hasScriptTags: boolean;
  hasEventHandlers: boolean;
  hasJavaScriptURL: boolean;
  hasHTMLEntities: boolean;
  hasSpecialChars: boolean;
  length: number;
  suspiciousKeywords: number;
}

/**
 * Create XSS protection with default configuration
 */
export function createAdvancedXSSProtection(config?: Partial<XSSProtectionConfig>): AdvancedXSSProtection {
  const defaultConfig: XSSProtectionConfig = {
    enabled: true,
    level: 'strict',
    blockOnDetection: true,
    logViolations: true,
    contextualSanitization: true,
    aiDetection: true,
    mutationObserver: true,
    cspIntegration: true,
    customRules: []
  };

  const mergedConfig = { ...defaultConfig, ...config };
  return new AdvancedXSSProtection(mergedConfig);
}