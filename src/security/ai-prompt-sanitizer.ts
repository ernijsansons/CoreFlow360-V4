/**
 * AI Prompt Sanitization Framework
 * Comprehensive protection against prompt injection attacks
 */

import { Logger } from '../shared/logger';
import { SecurityError } from '../shared/security-utils';

export interface SanitizationOptions {
  maxLength?: number;
  allowHtml?: boolean;
  allowNewlines?: boolean;
  preserveFormatting?: boolean;
  strictMode?: boolean;
  contextType?: 'user_input' | 'system_message' | 'ai_response' | 'template';
}

export interface SanitizationResult {
  sanitized: string;
  modified: boolean;
  violations: string[];
  riskScore: number;
  blocked: boolean;
}

export interface PromptInjectionDetection {
  detected: boolean;
  confidence: number;
  patterns: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

export class AIPromptSanitizer {
  private logger: Logger;

  // Dangerous patterns that indicate prompt injection attempts
  private readonly INJECTION_PATTERNS = [
    // System prompt overrides
    /system:?\s*(?:ignore|forget|disregard|override)/gi,
    /(?:new|different|updated)\s+(?:instructions|system|prompt|role)/gi,
    /(?:you\s+are\s+now|from\s+now\s+on|instead\s+of)/gi,

    // Role manipulation
    /(?:act\s+as|pretend\s+to\s+be|role\s*[:=]\s*)/gi,
    /(?:jailbreak|break\s+character|ignore\s+previous)/gi,
    /(?:assistant|ai|chatbot)\s*[:=]\s*\{/gi,

    // Template/variable injection
    /\{\{\s*[^}]*\s*\}\}/g,
    /\$\{[^}]*\}/g,
    /%\{[^}]*\}/g,

    // Code execution attempts
    /```(?:python|javascript|bash|sh|cmd|powershell|sql)/gi,
    /(?:eval|exec|system|subprocess|shell)/gi,
    /(?:import\s+os|import\s+subprocess|import\s+sys)/gi,

    // Data extraction attempts
    /(?:show|print|display|reveal|expose)\s+(?:password|secret|key|token)/gi,
    /(?:list|enumerate|dump)\s+(?:users|files|database|schema)/gi,
    /(?:access|retrieve|fetch)\s+(?:confidential|private|internal)/gi,

    // Conversation manipulation
    /(?:end\s+conversation|stop\s+responding|shut\s+down)/gi,
    /(?:restart|reset|clear)\s+(?:conversation|memory|context)/gi,
    /(?:previous|earlier)\s+(?:message|instruction|prompt)/gi,

    // Encoding/obfuscation attempts
    /base64|hex|unicode|utf-8|url\s*encoding/gi,
    /\\x[0-9a-fA-F]{2}/g,
    /\\u[0-9a-fA-F]{4}/g,

    // Common bypass techniques
    /(?:please\s+)?(?:ignore|bypass|skip)\s+(?:safety|security|guidelines)/gi,
    /(?:this\s+is\s+)?(?:hypothetical|fictional|roleplay|game)/gi,
    /(?:legal|academic|research)\s+purposes\s+only/gi,
  ];

  // Suspicious patterns that indicate potential manipulation
  private readonly SUSPICIOUS_PATTERNS = [
    /(?:very\s+important|urgent|critical|emergency)/gi,
    /(?:ceo|admin|developer|engineer)\s+said/gi,
    /(?:secret\s+code|special\s+mode|debug\s+mode)/gi,
    /(?:only\s+this\s+time|just\s+once|exception)/gi,
    /(?:remember|note|important)\s*[:=]/gi,
  ];

  // Blocked content that should never appear in AI inputs
  private readonly BLOCKED_CONTENT = [
    // Common injection markers
    '<|im_start|>',
    '<|im_end|>',
    '<|endoftext|>',
    '### Instruction:',
    '### Response:',
    'Human:',
    'Assistant:',
    '[INST]',
    '[/INST]',

    // Template markers
    '{{system}}',
    '{{user}}',
    '{{assistant}}',
    '${prompt}',
    '{prompt}',

    // Common model identifiers
    'gpt-',
    'claude-',
    'anthropic',
    'openai',
    'chatgpt',
  ];

  // Safe content boundaries
  private readonly MAX_SAFE_LENGTH = 50000;
  private readonly MAX_NEWLINES = 100;
  private readonly MAX_SPECIAL_CHARS_RATIO = 0.1;

  constructor() {
    this.logger = new Logger({ component: 'ai-prompt-sanitizer' });
  }

  /**
   * Sanitize user input for AI consumption
   */
  sanitizeInput(
    input: string,
    options: SanitizationOptions = {}
  ): SanitizationResult {
    const startTime = Date.now();

    if (!input || typeof input !== 'string') {
      return {
        sanitized: '',
        modified: true,
        violations: ['Invalid input type'],
        riskScore: 0,
        blocked: false
      };
    }

    const violations: string[] = [];
    let sanitized = input;
    let modified = false;
    let riskScore = 0;

    // Apply length limits
    const maxLength = options.maxLength || this.MAX_SAFE_LENGTH;
    if (sanitized.length > maxLength) {
      sanitized = sanitized.substring(0, maxLength);
      violations.push(`Input truncated from ${input.length} to ${maxLength} characters`);
      modified = true;
      riskScore += 0.1;
    }

    // Detect and handle prompt injection
    const injectionResult = this.detectPromptInjection(sanitized);
    if (injectionResult.detected) {
      riskScore += injectionResult.confidence;
      violations.push(...injectionResult.patterns);

      if (injectionResult.riskLevel === 'critical' || options.strictMode) {
        return {
          sanitized: '',
          modified: true,
          violations: ['Blocked: Critical prompt injection detected', ...violations],
          riskScore: 1.0,
          blocked: true
        };
      }
    }

    // Remove blocked content
    for (const blockedItem of this.BLOCKED_CONTENT) {
      if (sanitized.toLowerCase().includes(blockedItem.toLowerCase())) {
        sanitized = sanitized.replace(new RegExp(blockedItem, 'gi'), '[REDACTED]');
        violations.push(`Blocked content removed: ${blockedItem}`);
        modified = true;
        riskScore += 0.2;
      }
    }

    // Normalize whitespace and newlines
    if (!options.preserveFormatting) {
      const originalSanitized = sanitized;

      // Limit excessive newlines
      if (!options.allowNewlines) {
        sanitized = sanitized.replace(/\n/g, ' ');
        modified = originalSanitized !== sanitized;
      } else {
        const newlineCount = (sanitized.match(/\n/g) || []).length;
        if (newlineCount > this.MAX_NEWLINES) {
          sanitized = sanitized.replace(/\n{3,}/g, '\n\n');
          violations.push('Excessive newlines normalized');
          modified = true;
          riskScore += 0.1;
        }
      }

      // Normalize other whitespace
      sanitized = sanitized.replace(/\s+/g, ' ').trim();
      if (originalSanitized !== sanitized) {
        modified = true;
      }
    }

    // Remove dangerous HTML if not allowed
    if (!options.allowHtml) {
      const htmlRemoved = this.removeHtml(sanitized);
      if (htmlRemoved !== sanitized) {
        sanitized = htmlRemoved;
        violations.push('HTML content removed');
        modified = true;
        riskScore += 0.1;
      }
    }

    // Check for excessive special characters
    const specialCharRatio = this.calculateSpecialCharRatio(sanitized);
    if (specialCharRatio > this.MAX_SPECIAL_CHARS_RATIO) {
      violations.push(`High special character ratio: ${(specialCharRatio * 100).toFixed(1)}%`);
      riskScore += 0.2;
    }

    // Unicode normalization
    try {
      const normalized = sanitized.normalize('NFKC');
      if (normalized !== sanitized) {
        sanitized = normalized;
        modified = true;
      }
    } catch (error) {
      violations.push('Unicode normalization failed');
      riskScore += 0.1;
    }

    // Final safety check
    const finalRisk = Math.min(riskScore, 1.0);
    const blocked = finalRisk >= 0.8 && options.strictMode;

    this.logger.debug('Input sanitization completed', {
      originalLength: input.length,
      sanitizedLength: sanitized.length,
      modified,
      violations: violations.length,
      riskScore: finalRisk,
      blocked,
      processingTime: Date.now() - startTime
    });

    return {
      sanitized: blocked ? '' : sanitized,
      modified,
      violations,
      riskScore: finalRisk,
      blocked
    };
  }

  /**
   * Detect potential prompt injection attacks
   */
  detectPromptInjection(input: string): PromptInjectionDetection {
    const detectedPatterns: string[] = [];
    let confidence = 0;
    let maxRiskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';

    // Check for injection patterns
    for (const pattern of this.INJECTION_PATTERNS) {
      const matches = input.match(pattern);
      if (matches) {
        detectedPatterns.push(`Injection pattern: ${pattern.source}`);
        confidence += 0.3;
        maxRiskLevel = 'high';
      }
    }

    // Check for suspicious patterns
    for (const pattern of this.SUSPICIOUS_PATTERNS) {
      const matches = input.match(pattern);
      if (matches) {
        detectedPatterns.push(`Suspicious pattern: ${pattern.source}`);
        confidence += 0.1;
        if (maxRiskLevel === 'low') maxRiskLevel = 'medium';
      }
    }

    // Check for role confusion attempts
    if (this.detectRoleConfusion(input)) {
      detectedPatterns.push('Role confusion attempt detected');
      confidence += 0.4;
      maxRiskLevel = 'critical';
    }

    // Check for template injection
    if (this.detectTemplateInjection(input)) {
      detectedPatterns.push('Template injection attempt detected');
      confidence += 0.3;
      maxRiskLevel = 'high';
    }

    // Normalize confidence
    confidence = Math.min(confidence, 1.0);

    return {
      detected: detectedPatterns.length > 0,
      confidence,
      patterns: detectedPatterns,
      riskLevel: maxRiskLevel
    };
  }

  /**
   * Sanitize AI responses before sending to users
   */
  sanitizeOutput(
    output: string,
    options: SanitizationOptions = {}
  ): SanitizationResult {
    // For outputs, we're mainly concerned with leaked system information
    const violations: string[] = [];
    let sanitized = output;
    let modified = false;

    // Remove any accidentally leaked system prompts or instructions
    const systemLeakPatterns = [
      /\[SYSTEM\].*?\[\/SYSTEM\]/gi,
      /\[INSTRUCTION\].*?\[\/INSTRUCTION\]/gi,
      /```system.*?```/gi,
      /internal_prompt.*?end_internal/gi,
    ];

    for (const pattern of systemLeakPatterns) {
      const before = sanitized;
      sanitized = sanitized.replace(pattern, '[System information redacted]');
      if (before !== sanitized) {
        violations.push('System information leak prevented');
        modified = true;
      }
    }

    return {
      sanitized,
      modified,
      violations,
      riskScore: violations.length > 0 ? 0.3 : 0,
      blocked: false
    };
  }

  /**
   * Create a secure prompt template
   */
  createSecurePrompt(
    template: string,
    userInput: string,
    variables: Record<string, string> = {}
  ): string {
    // Sanitize user input first
    const sanitizedInput = this.sanitizeInput(userInput, { strictMode: true });

    if (sanitizedInput.blocked) {
      throw new SecurityError('User input blocked due to security violation', {
        code: 'PROMPT_INJECTION_BLOCKED',
        violations: sanitizedInput.violations
      });
    }

    // Sanitize template variables
    const sanitizedVariables: Record<string, string> = {};
    for (const [key, value] of Object.entries(variables)) {
      const result = this.sanitizeInput(value, { maxLength: 1000 });
      if (result.blocked) {
        throw new SecurityError(`Template variable '${key}' blocked`, {
          code: 'TEMPLATE_VARIABLE_BLOCKED',
          violations: result.violations
        });
      }
      sanitizedVariables[key] = result.sanitized;
    }

    // Build the secure prompt
    let securePrompt = template;

    // Replace variables with sanitized versions
    for (const [key, value] of Object.entries(sanitizedVariables)) {
      securePrompt = securePrompt.replace(
        new RegExp(`\\{${key}\\}`, 'g'),
        value
      );
    }

    // Add user input in a controlled way
    securePrompt = securePrompt.replace(
      /\{USER_INPUT\}/g,
      `"""${sanitizedInput.sanitized}"""`
    );

    return securePrompt;
  }

  /**
   * Validate prompt safety before AI processing
   */
  validatePromptSafety(prompt: string): boolean {
    const result = this.detectPromptInjection(prompt);
    return !result.detected || result.riskLevel !== 'critical';
  }

  private detectRoleConfusion(input: string): boolean {
    const rolePatterns = [
      /you\s+are\s+now\s+(?:a|an|the)/gi,
      /forget\s+you\s+are/gi,
      /pretend\s+to\s+be/gi,
      /act\s+as\s+if/gi,
      /roleplay\s+as/gi,
      /imagine\s+you\s+are/gi,
    ];

    return rolePatterns.some(pattern => pattern.test(input));
  }

  private detectTemplateInjection(input: string): boolean {
    const templatePatterns = [
      /\{\{.*?\}\}/g,
      /\$\{.*?\}/g,
      /%\{.*?\}/g,
      /<%.*?%>/g,
      /\[%.*?%\]/g,
    ];

    return templatePatterns.some(pattern => pattern.test(input));
  }

  private removeHtml(input: string): string {
    return input
      .replace(/<script[^>]*>.*?<\/script>/gi, '')
      .replace(/<style[^>]*>.*?<\/style>/gi, '')
      .replace(/<[^>]*>/g, '')
      .replace(/&[a-zA-Z0-9#]+;/g, '');
  }

  private calculateSpecialCharRatio(input: string): number {
    if (input.length === 0) return 0;

    const specialChars = input.match(/[^a-zA-Z0-9\s.,!?;:'"()\-]/g) || [];
    return specialChars.length / input.length;
  }

  /**
   * Create a rate-limited sanitizer for high-volume scenarios
   */
  createRateLimitedSanitizer(maxRequestsPerMinute: number = 100) {
    const requests = new Map<string, number[]>();

    return (
      input: string,
      clientId: string,
      options?: SanitizationOptions
    ): SanitizationResult => {
      const now = Date.now();
      const windowStart = now - 60000; // 1 minute ago

      // Clean old requests
      if (requests.has(clientId)) {
        const clientRequests = requests.get(clientId)!;
        const recentRequests = clientRequests.filter(time => time > windowStart);
        requests.set(clientId, recentRequests);

        if (recentRequests.length >= maxRequestsPerMinute) {
          return {
            sanitized: '',
            modified: true,
            violations: ['Rate limit exceeded'],
            riskScore: 1.0,
            blocked: true
          };
        }

        recentRequests.push(now);
      } else {
        requests.set(clientId, [now]);
      }

      return this.sanitizeInput(input, options);
    };
  }
}

// Export singleton instance
export const promptSanitizer = new AIPromptSanitizer();

// Export utility functions
export function sanitizeUserInput(
  input: string,
  options?: SanitizationOptions
): SanitizationResult {
  return promptSanitizer.sanitizeInput(input, {
    strictMode: true,
    maxLength: 10000,
    allowHtml: false,
    ...options
  });
}

export function createSecureAIPrompt(
  template: string,
  userInput: string,
  variables?: Record<string, string>
): string {
  return promptSanitizer.createSecurePrompt(template, userInput, variables);
}

export function validateAIPrompt(prompt: string): boolean {
  return promptSanitizer.validatePromptSafety(prompt);
}