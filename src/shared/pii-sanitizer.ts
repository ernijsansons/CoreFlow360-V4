/**
 * PII Sanitization Utility
 * Removes or masks personally identifiable information for GDPR compliance
 */

export class PIISanitizer {
  private static readonly EMAIL_REGEX = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
  private static readonly PHONE_REGEX = /(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})/g;
  private static readonly SSN_REGEX = /\b\d{3}-?\d{2}-?\d{4}\b/g;
  private static readonly CREDIT_CARD_REGEX = /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g;

  // Fields that commonly contain PII
  private static readonly PII_FIELDS = [
    'email',
    'firstName',
    'lastName',
    'fullName',
    'name',
    'phone',
    'phoneNumber',
    'address',
    'ssn',
    'creditCard',
    'password',
    'token',
    'secret',
    'key',
    'ip',
    'ipAddress'
  ];

  /**
   * Sanitize a log message by removing/masking PII
   */
  static sanitizeMessage(message: string): string {
    let sanitized = message;

    // Mask emails
    sanitized = sanitized.replace(this.EMAIL_REGEX, (email) => {
      const [local, domain] = email.split('@');
      const maskedLocal = local.length > 2 ?
        local.substring(0, 2) + '*'.repeat(local.length - 2) :
        local.substring(0, 1) + '*';
      return `${maskedLocal}@${domain}`;
    });

    // Mask phone numbers
    sanitized = sanitized.replace(this.PHONE_REGEX, (phone) => {
      return phone.replace(/\d/g, '*').slice(0, -4) + phone.slice(-4);
    });

    // Mask SSNs
    sanitized = sanitized.replace(this.SSN_REGEX, () => '***-**-****');

    // Mask credit cards
    sanitized = sanitized.replace(this.CREDIT_CARD_REGEX, (card) => {
      return '*'.repeat(card.length - 4) + card.slice(-4);
    });

    return sanitized;
  }

  /**
   * Sanitize an object by removing/masking PII fields
   */
  static sanitizeObject(obj: any): any {
    if (!obj || typeof obj !== 'object') {
      return obj;
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this.sanitizeObject(item));
    }

    const sanitized: any = {};

    for (const [key, value] of Object.entries(obj)) {
      const lowerKey = key.toLowerCase();

      if (this.isPIIField(lowerKey)) {
        sanitized[key] = this.maskValue(value, key);
      } else if (typeof value === 'object' && value !== null) {
        sanitized[key] = this.sanitizeObject(value);
      } else if (typeof value === 'string') {
        sanitized[key] = this.sanitizeMessage(value);
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }

  /**
   * Check if a field is likely to contain PII
   */
  private static isPIIField(fieldName: string): boolean {
    return this.PII_FIELDS.some(piiField =>
      fieldName.includes(piiField.toLowerCase())
    );
  }

  /**
   * Mask a value based on the field type
   */
  private static maskValue(value: any, fieldName: string): any {
    if (value === null || value === undefined) {
      return value;
    }

    const stringValue = String(value);
    const lowerFieldName = fieldName.toLowerCase();

    if (lowerFieldName.includes('email')) {
      return this.maskEmail(stringValue);
    }

    if (lowerFieldName.includes('phone')) {
      return this.maskPhone(stringValue);
    }

    if (lowerFieldName.includes('password') ||
        lowerFieldName.includes('token') ||
        lowerFieldName.includes('secret') ||
        lowerFieldName.includes('key')) {
      return '[REDACTED]';
    }

    if (lowerFieldName.includes('name')) {
      return this.maskName(stringValue);
    }

    if (lowerFieldName.includes('address')) {
      return '[ADDRESS_REDACTED]';
    }

    if (lowerFieldName.includes('ip')) {
      return this.maskIP(stringValue);
    }

    // Default masking for unknown PII
    return stringValue.length > 4 ?
      stringValue.substring(0, 2) + '*'.repeat(stringValue.length - 2) :
      '*'.repeat(stringValue.length);
  }

  /**
   * Mask email address
   */
  private static maskEmail(email: string): string {
    if (!email.includes('@')) {
      return '[EMAIL_REDACTED]';
    }

    const [local, domain] = email.split('@');
    const maskedLocal = local.length > 2 ?
      local.substring(0, 2) + '*'.repeat(local.length - 2) :
      local.substring(0, 1) + '*';

    return `${maskedLocal}@${domain}`;
  }

  /**
   * Mask phone number
   */
  private static maskPhone(phone: string): string {
    const digitsOnly = phone.replace(/\D/g, '');
    if (digitsOnly.length < 4) {
      return '*'.repeat(phone.length);
    }

    return phone.replace(/\d/g, '*').slice(0, -4) + digitsOnly.slice(-4);
  }

  /**
   * Mask name
   */
  private static maskName(name: string): string {
    if (name.length <= 2) {
      return '*'.repeat(name.length);
    }

    return name.substring(0, 1) + '*'.repeat(name.length - 1);
  }

  /**
   * Mask IP address
   */
  private static maskIP(ip: string): string {
    // For IPv4, show only first octet
    if (ip.includes('.')) {
      const parts = ip.split('.');
      return parts[0] + '.***.***.***';
    }

    // For IPv6 or other formats, mask most of it
    return ip.substring(0, 4) + '*'.repeat(Math.max(0, ip.length - 4));
  }

  /**
   * Create a safe logging object from user data
   */
  static createSafeLogObject(data: any, additionalFields?: Record<string, any>): any {
    const baseLog = {
      timestamp: Date.now(),
      ...additionalFields
    };

    if (data?.id) {
      baseLog.userId = data.id;
    }

    if (data?.businessId) {
      baseLog.businessId = data.businessId;
    }

    if (data?.email) {
      baseLog.hasEmail = true;
      baseLog.emailDomain = data.email.split('@')[1];
    }

    if (data?.role) {
      baseLog.role = data.role;
    }

    return baseLog;
  }

  /**
   * Safe console.log replacement
   */
  static safeLog(message: string, data?: any): void {
    const sanitizedMessage = this.sanitizeMessage(message);
    const sanitizedData = data ? this.sanitizeObject(data) : undefined;

    if (sanitizedData) {
    } else {
    }
  }

  /**
   * Safe console.error replacement
   */
  static safeError(message: string, error?: any, data?: any): void {
    const sanitizedMessage = this.sanitizeMessage(message);
    const sanitizedData = data ? this.sanitizeObject(data) : undefined;

    if (error && sanitizedData) {
    } else if (error) {
    } else if (sanitizedData) {
    } else {
    }
  }

  /**
   * Safe console.warn replacement
   */
  static safeWarn(message: string, data?: any): void {
    const sanitizedMessage = this.sanitizeMessage(message);
    const sanitizedData = data ? this.sanitizeObject(data) : undefined;

    if (sanitizedData) {
    } else {
    }
  }
}