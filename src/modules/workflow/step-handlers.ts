/**
 * Built-in Step Handlers for Workflow Orchestrator
 * Provides common step implementations with rollback support
 */

import {
  StepHandler,
  WorkflowStep,
  StepCost,
  WorkflowError
} from './types';
import { Logger } from '../../shared/logger';
import { SecurityError, InputValidator } from '../../shared/security-utils';

/**
 * HTTP Request Step Handler
 * Makes HTTP requests with configurable retry and timeout
 */
export class HttpRequestStepHandler implements StepHandler {
  private logger = new Logger();

  async execute(step: WorkflowStep, context: any): Promise<any> {
    try {
      const { url, method = 'GET', headers = {}, body, timeout = 30000 } = step.parameters;

      if (!url || typeof url !== 'string') {
        throw new WorkflowError('Missing or invalid URL parameter', 'INVALID_URL');
      }

      const validatedUrl = InputValidator.validateAndSanitize(url, 'url');
      const startTime = Date.now();

      // Create abort controller for timeout
      const abortController = new AbortController();
      const timeoutId = setTimeout(() => abortController.abort(), timeout);

      try {
        const response = await fetch(validatedUrl, {
          method,
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'CoreFlow360-Workflow/1.0',
            'X-Correlation-ID': context.correlationId,
            ...headers,
          },
          body: body ? JSON.stringify(body) : undefined,
          signal: abortController.signal,
        });

        clearTimeout(timeoutId);

        const responseData = await response.text();
        let parsedData;

        try {
          parsedData = JSON.parse(responseData);
        } catch {
          parsedData = responseData;
        }

        const endTime = Date.now();
        const duration = endTime - startTime;

        // Calculate cost based on request size and duration
        const cost: Partial<StepCost> = {
          networkCalls: 1,
          computeUnits: Math.ceil(duration / 100), // 1 unit per 100ms
          totalUSD: 0.001, // $0.001 per HTTP request
        };

        if (response.ok) {
          this.logger.info('HTTP request completed', {
            url: validatedUrl,
            method,
            status: response.status,
            duration,
            correlationId: context.correlationId,
          });

          return {
            success: true,
            output: {
              status: response.status,
              headers: Object.fromEntries(response.headers.entries()),
              data: parsedData,
              httpRequestUrl: validatedUrl,
              httpRequestMethod: method,
            },
            cost,
            metadata: {
              httpStatus: response.status,
              responseTime: duration,
              responseSize: responseData.length,
            },
          };
        } else {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

      } finally {
        clearTimeout(timeoutId);
      }

    } catch (error: any) {
      this.logger.error('HTTP request failed', error, {
        stepId: step.id,
        url: step.parameters.url,
        correlationId: context.correlationId,
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'HTTP request failed',
        cost: { networkCalls: 1, totalUSD: 0.001 },
      };
    }
  }

  async rollback(step: WorkflowStep, context: any): Promise<any> {
    // For HTTP requests, rollback might involve calling a compensating endpoint
    const { rollbackUrl, rollbackMethod = 'POST' } = step.rollbackParameters || {};

    if (!rollbackUrl) {
      this.logger.info('No rollback URL specified for HTTP step', { stepId: step.id });
      return { success: true };
    }

    try {
      const response = await fetch(rollbackUrl, {
        method: rollbackMethod,
        headers: {
          'Content-Type': 'application/json',
          'X-Correlation-ID': context.correlationId,
        },
        body: JSON.stringify({
          originalRequest: context.originalOutput,
          rollbackReason: 'workflow_rollback',
        }),
      });

      if (response.ok) {
        this.logger.info('HTTP rollback completed', {
          stepId: step.id,
          rollbackUrl,
          status: response.status,
        });
        return { success: true };
      } else {
        throw new Error(`Rollback failed: HTTP ${response.status}`);
      }

    } catch (error: any) {
      this.logger.error('HTTP rollback failed', error, { stepId: step.id });
      return {
        success: false,
        error: error instanceof Error ? error.message : 'HTTP rollback failed',
      };
    }
  }
}

/**
 * Database Operation Step Handler
 * Executes database operations with transaction support
 */
export class DatabaseStepHandler implements StepHandler {
  private logger = new Logger();

  async execute(step: WorkflowStep, context: any): Promise<any> {
    try {
      const { operation, table, data, where, transaction = false } = step.parameters;

      if (!operation || !table) {
        throw new WorkflowError('Missing operation or table parameter', 'MISSING_DB_PARAMS');
      }

      const startTime = Date.now();

      // Simulate database operation (in real implementation, use actual DB client)
      await this.simulateDbOperation(operation, table, data, where, transaction);

      const endTime = Date.now();
      const duration = endTime - startTime;

      const cost: Partial<StepCost> = {
        computeUnits: Math.ceil(duration / 50), // 1 unit per 50ms
        storageBytes: this.estimateStorageBytes(data),
        totalUSD: 0.0001 * Math.ceil(duration / 1000), // $0.0001 per second
      };

      this.logger.info('Database operation completed', {
        operation,
        table,
        duration,
        correlationId: context.correlationId,
      });

      return {
        success: true,
        output: {
          operation,
          table,
          affectedRows: 1, // Simulated
          transactionId: transaction ? this.generateTransactionId() : undefined,
        },
        cost,
        metadata: {
          executionTime: duration,
          rowsAffected: 1,
        },
      };

    } catch (error: any) {
      this.logger.error('Database operation failed', error, {
        stepId: step.id,
        correlationId: context.correlationId,
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Database operation failed',
        cost: { computeUnits: 1, totalUSD: 0.0001 },
      };
    }
  }

  async rollback(step: WorkflowStep, context: any): Promise<any> {
    try {
      const { operation, table } = step.parameters;
      const originalOutput = context.originalOutput;

      // Determine rollback operation
      let rollbackOperation: string;
      switch (operation) {
        case 'insert':
          rollbackOperation = 'delete';
          break;
        case 'update':
          rollbackOperation = 'update'; // Restore original values
          break;
        case 'delete':
          rollbackOperation = 'insert'; // Restore deleted data
          break;
        default:
          throw new Error(`Cannot rollback operation: ${operation}`);
      }

      // Simulate rollback operation
      await this.simulateDbOperation(rollbackOperation, table, originalOutput, null, true);

      this.logger.info('Database rollback completed', {
        stepId: step.id,
        originalOperation: operation,
        rollbackOperation,
        table,
      });

      return { success: true };

    } catch (error: any) {
      this.logger.error('Database rollback failed', error, { stepId: step.id });
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Database rollback failed',
      };
    }
  }

  private async simulateDbOperation(operation: string, table: string,
  data: any, where: any, transaction: boolean): Promise<void> {
    // Simulate database latency
    await new Promise(resolve => setTimeout(resolve, 10 + Math.random() * 90));

    // Validate parameters
    if (operation === 'insert' && !data) {
      throw new Error('Insert operation requires data');
    }

    if ((operation === 'update' || operation === 'delete') && !where) {
      throw new Error(`${operation} operation requires where clause`);
    }

    // Simulate potential database errors
    if (Math.random() < 0.01) { // 1% failure rate
      throw new Error('Simulated database connection error');
    }
  }

  private estimateStorageBytes(data: any): number {
    if (!data) return 0;
    return JSON.stringify(data).length * 2; // Rough estimate
  }

  private generateTransactionId(): string {
    return `txn_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

/**
 * Email Notification Step Handler
 * Sends emails with template support
 */
export class EmailStepHandler implements StepHandler {
  private logger = new Logger();

  async execute(step: WorkflowStep, context: any): Promise<any> {
    try {
      const { to, subject, template, templateData, priority = 'normal' } = step.parameters;

      if (!to || !subject) {
        throw new WorkflowError('Missing to or subject parameter', 'MISSING_EMAIL_PARAMS');
      }

      const startTime = Date.now();

      // Simulate email sending
      await this.simulateEmailSend(to, subject, template, templateData, priority);

      const endTime = Date.now();
      const duration = endTime - startTime;

      const cost: Partial<StepCost> = {
        networkCalls: 1,
        computeUnits: 1,
        totalUSD: 0.0001, // $0.0001 per email
        customCosts: { emails: 1 },
      };

      this.logger.info('Email sent', {
        to: Array.isArray(to) ? to.length : 1,
        subject,
        template,
        duration,
        correlationId: context.correlationId,
      });

      return {
        success: true,
        output: {
          messageId: this.generateMessageId(),
          recipients: Array.isArray(to) ? to.length : 1,
          subject,
          sentAt: new Date().toISOString(),
        },
        cost,
        metadata: {
          emailProvider: 'simulated',
          deliveryTime: duration,
        },
      };

    } catch (error: any) {
      this.logger.error('Email sending failed', error, {
        stepId: step.id,
        correlationId: context.correlationId,
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Email sending failed',
        cost: { customCosts: { emails: 1 }, totalUSD: 0.0001 },
      };
    }
  }

  async rollback(step: WorkflowStep, context: any): Promise<any> {
    // Email rollback might involve sending a cancellation/correction email
    const { rollbackTemplate, rollbackSubject } = step.rollbackParameters || {};

    if (!rollbackTemplate) {
      this.logger.info('No rollback template specified for email step', { stepId: step.id });
      return { success: true };
    }

    try {
      const originalOutput = context.originalOutput;
      const { to } = step.parameters;

      await this.simulateEmailSend(
        to,
        rollbackSubject || `Correction: ${originalOutput.subject}`,
        rollbackTemplate,
        { originalMessage: originalOutput },
        'high'
      );

      this.logger.info('Email rollback notification sent', {
        stepId: step.id,
        originalMessageId: originalOutput.messageId,
      });

      return { success: true };

    } catch (error: any) {
      this.logger.error('Email rollback failed', error, { stepId: step.id });
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Email rollback failed',
      };
    }
  }

  private async simulateEmailSend(to: string | string[], subject:
  string, template?: string, templateData?: any, priority?: string): Promise<void> {
    // Simulate email service latency
    const delay = priority === 'high' ? 500 : 1000 + Math.random() * 2000;
    await new Promise(resolve => setTimeout(resolve, delay));

    // Simulate potential email service errors
    if (Math.random() < 0.005) { // 0.5% failure rate
      throw new Error('Email service temporarily unavailable');
    }

    // Validate email addresses
    const recipients = Array.isArray(to) ? to : [to];
    for (const email of recipients) {
      if (!this.isValidEmail(email)) {
        throw new Error(`Invalid email address: ${email}`);
      }
    }
  }

  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  private generateMessageId(): string {
    return `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

/**
 * File Processing Step Handler
 * Processes files with various operations
 */
export class FileProcessingStepHandler implements StepHandler {
  private logger = new Logger();

  async execute(step: WorkflowStep, context: any): Promise<any> {
    try {
      const { operation, inputPath, outputPath, options = {} } = step.parameters;

      if (!operation || !inputPath) {
        throw new WorkflowError('Missing operation or inputPath parameter', 'MISSING_FILE_PARAMS');
      }

      const startTime = Date.now();

      // Simulate file processing
      const result = await this.simulateFileProcessing(operation, inputPath, outputPath, options);

      const endTime = Date.now();
      const duration = endTime - startTime;

      const cost: Partial<StepCost> = {
        computeUnits: Math.ceil(duration / 100),
        storageBytes: result.outputSize || 0,
        totalUSD: 0.001 * Math.ceil(duration / 1000),
      };

      this.logger.info('File processing completed', {
        operation,
        inputPath,
        outputPath,
        duration,
        correlationId: context.correlationId,
      });

      return {
        success: true,
        output: {
          operation,
          inputPath,
          outputPath: result.outputPath,
          inputSize: result.inputSize,
          outputSize: result.outputSize,
          processedAt: new Date().toISOString(),
        },
        cost,
        metadata: {
          processingTime: duration,
          compressionRatio: result.inputSize ? result.outputSize / result.inputSize : 1,
        },
      };

    } catch (error: any) {
      this.logger.error('File processing failed', error, {
        stepId: step.id,
        correlationId: context.correlationId,
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'File processing failed',
        cost: { computeUnits: 1, totalUSD: 0.001 },
      };
    }
  }

  async rollback(step: WorkflowStep, context: any): Promise<any> {
    try {
      const originalOutput = context.originalOutput;
      const { operation } = step.parameters;

      switch (operation) {
        case 'compress':
        case 'convert':
        case 'resize':
          // Delete the output file
          if (originalOutput.outputPath) {
            await this.simulateFileDelete(originalOutput.outputPath);
          }
          break;

        case 'delete':
          // Restore from backup (if available)
          this.logger.warn('Cannot rollback file deletion - no backup available', {
            stepId: step.id,
            inputPath: step.parameters.inputPath,
          });
          break;

        case 'move':
          // Move file back to original location
          if (originalOutput.outputPath && originalOutput.inputPath) {
            await this.simulateFileMove(originalOutput.outputPath, originalOutput.inputPath);
          }
          break;
      }

      this.logger.info('File processing rollback completed', {
        stepId: step.id,
        operation,
      });

      return { success: true };

    } catch (error: any) {
      this.logger.error('File processing rollback failed', error, { stepId: step.id });
      return {
        success: false,
        error: error instanceof Error ? error.message : 'File processing rollback failed',
      };
    }
  }

  private async simulateFileProcessing(operation: string, inputPath:
  string, outputPath?: string, options?: any): Promise<any> {
    // Simulate processing time based on operation
    const processingTime = {
      compress: 2000,
      convert: 3000,
      resize: 1500,
      delete: 100,
      move: 500,
      copy: 800,
    }[operation] || 1000;

    await new Promise(resolve => setTimeout(resolve, processingTime + Math.random() * 1000));

    // Simulate file sizes
    const inputSize = 1024 * 1024 + Math.random() * 10 * 1024 * 1024; // 1-11 MB
    let outputSize = inputSize;

    switch (operation) {
      case 'compress':
        outputSize = inputSize * (0.3 + Math.random() * 0.4); // 30-70% compression
        break;
      case 'resize':
        outputSize = inputSize * (0.5 + Math.random() * 0.3); // 50-80% of original
        break;
      case 'convert':
        outputSize = inputSize * (0.8 + Math.random() * 0.4); // 80-120% of original
        break;
    }

    return {
      inputSize: Math.round(inputSize),
      outputSize: Math.round(outputSize),
      outputPath: outputPath || `${inputPath}.processed`,
    };
  }

  private async simulateFileDelete(filePath: string): Promise<void> {
    await new Promise(resolve => setTimeout(resolve, 100));
  }

  private async simulateFileMove(fromPath: string, toPath: string): Promise<void> {
    await new Promise(resolve => setTimeout(resolve, 200));
  }
}

/**
 * Delay Step Handler
 * Introduces controlled delays in workflow execution
 */
export class DelayStepHandler implements StepHandler {
  private logger = new Logger();

  async execute(step: WorkflowStep, context: any): Promise<any> {
    try {
      const { delayMs, delayUntil } = step.parameters;

      if (!delayMs && !delayUntil) {
        throw new WorkflowError('Must specify either delayMs or delayUntil', 'MISSING_DELAY_PARAMS');
      }

      let actualDelayMs: number;

      if (delayUntil) {
        const targetTime = new Date(delayUntil).getTime();
        const now = Date.now();
        actualDelayMs = Math.max(0, targetTime - now);
      } else {
        actualDelayMs = parseInt(delayMs, 10);
      }

      const startTime = Date.now();

      this.logger.info('Starting delay step', {
        stepId: step.id,
        delayMs: actualDelayMs,
        correlationId: context.correlationId,
      });

      // Perform the delay
      await new Promise(resolve => setTimeout(resolve, actualDelayMs));

      const endTime = Date.now();
      const actualDuration = endTime - startTime;

      const cost: Partial<StepCost> = {
        computeUnits: Math.ceil(actualDelayMs / 1000), // 1 unit per second
        totalUSD: 0.00001 * Math.ceil(actualDelayMs / 1000), // Very small cost for delays
      };

      this.logger.info('Delay step completed', {
        stepId: step.id,
        plannedDelay: actualDelayMs,
        actualDelay: actualDuration,
        correlationId: context.correlationId,
      });

      return {
        success: true,
        output: {
          plannedDelayMs: actualDelayMs,
          actualDelayMs: actualDuration,
          startTime: new Date(startTime).toISOString(),
          endTime: new Date(endTime).toISOString(),
        },
        cost,
        metadata: {
          delayAccuracy: Math.abs(actualDuration - actualDelayMs),
        },
      };

    } catch (error: any) {
      this.logger.error('Delay step failed', error, {
        stepId: step.id,
        correlationId: context.correlationId,
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Delay step failed',
        cost: { computeUnits: 1, totalUSD: 0.00001 },
      };
    }
  }

  async rollback(step: WorkflowStep, context: any): Promise<any> {
    // Delay steps don't need rollback - they don't modify state
    this.logger.info('Delay step rollback - no action needed', { stepId: step.id });
    return { success: true };
  }
}

/**
 * Step Handler Registry
 * Manages registration and lookup of step handlers
 */
export class StepHandlerRegistry {
  private handlers = new Map<string, StepHandler>();
  private logger = new Logger();

  constructor() {
    this.registerBuiltInHandlers();
  }

  /**
   * Register built-in step handlers
   */
  private registerBuiltInHandlers(): void {
    this.register('http_request', new HttpRequestStepHandler());
    this.register('database', new DatabaseStepHandler());
    this.register('email', new EmailStepHandler());
    this.register('file_processing', new FileProcessingStepHandler());
    this.register('delay', new DelayStepHandler());

    this.logger.info('Built-in step handlers registered', {
      handlers: Array.from(this.handlers.keys()),
    });
  }

  /**
   * Register a step handler
   */
  register(name: string, handler: StepHandler): void {
    this.handlers.set(name, handler);
    this.logger.info('Step handler registered', { name });
  }

  /**
   * Get a step handler by name
   */
  get(name: string): StepHandler | undefined {
    return this.handlers.get(name);
  }

  /**
   * Get all registered handler names
   */
  getRegisteredHandlers(): string[] {
    return Array.from(this.handlers.keys());
  }

  /**
   * Check if a handler is registered
   */
  has(name: string): boolean {
    return this.handlers.has(name);
  }
}