/**
 * Audit Logger Service
 * Provides audit logging functionality with a simplified interface
 */

import { LoggerFactory } from '../logger'

interface AuditLogEntry {
  action: string
  userId?: string
  businessId?: string
  details?: Record<string, unknown>
  [key: string]: unknown // Allow any additional properties
}

/**
 * Audit logger for compliance and security tracking
 */
export class AuditLogger {
  private logger = LoggerFactory.getLogger('audit')

  /**
   * Log audit event
   */
  log(entry: AuditLogEntry): void | Promise<void> {
    const { action, ...context } = entry
    this.logger.audit(action, undefined, context)
  }

  /**
   * Log security-related audit event
   */
  security(
    event: string,
    severity: 'low' | 'medium' | 'high' | 'critical',
    context?: Record<string, unknown>
  ): void {
    this.logger.security(event, severity, context)
  }

  /**
   * Log performance metric
   */
  performance(operation: string, duration: number, context?: Record<string, unknown>): void {
    this.logger.performance(operation, duration, context)
  }
}

export const auditLogger = new AuditLogger()
