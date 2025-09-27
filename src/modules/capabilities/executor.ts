/**
 * Capability Executor
 * Executes capabilities with cost estimation, permission checking, and audit
 */

import type { DurableObjectStorage } from '@cloudflare/workers-types';
import {
  CapabilitySpec,
  CapabilityExecutionContext,
  CapabilityExecutionResult,
  CapabilityValidationError,
  CapabilityPermissionError,
  CapabilityCostLimitError,
  DEFAULT_COST_MULTIPLIERS,
  EXECUTION_LIMITS
} from './types';
import { CapabilityValidator } from './validator';
import { Logger } from '../../shared/logger';
import { SecurityError, CorrelationId } from '../../shared/security-utils';
import { ABACPermissionEngine } from '../abac/permission-engine';
import { AuditService } from '../audit/audit-service';

export interface CostEstimate {
  computeUnits: number;
  totalUSD: number;
  breakdown: {
    base: number;
    parameters: number;
    operation: number;
    ai: number;
    custom: Record<string, number>;
  };
  confidence: 'low' | 'medium' | 'high';
}

export interface CapabilityExecutorConfig {
  enableCostLimits: boolean;
  enablePermissionChecking: boolean;
  enableAuditLogging: boolean;
  maxConcurrentExecutions: number;
  defaultTimeoutMs: number;
  costMultipliers: typeof DEFAULT_COST_MULTIPLIERS;
}

export class CapabilityExecutor {
  private logger: Logger;
  private validator: CapabilityValidator;
  private permissionEngine: ABACPermissionEngine;
  private auditService: AuditService;
  private config: CapabilityExecutorConfig;
  private activeExecutions = new Map<string, CapabilityExecutionContext>();
  private sqlHandlers = new Map<string, any>();
  private apiHandlers = new Map<string, any>();
  private fileHandlers = new Map<string, any>();
  private customHandlers = new Map<string, any>();

  constructor(
    permissionEngine: ABACPermissionEngine,
    auditService: AuditService,
    config: Partial<CapabilityExecutorConfig> = {}
  ) {
    this.logger = new Logger();
    this.validator = new CapabilityValidator();
    this.permissionEngine = permissionEngine;
    this.auditService = auditService;
    this.config = {
      enableCostLimits: true,
      enablePermissionChecking: true,
      enableAuditLogging: true,
      maxConcurrentExecutions: EXECUTION_LIMITS.MAX_CONCURRENT_EXECUTIONS,
      defaultTimeoutMs: EXECUTION_LIMITS.MAX_EXECUTION_TIME_MS,
      costMultipliers: DEFAULT_COST_MULTIPLIERS,
      ...config,
    };

    this.initializeBuiltInHandlers();
  }

  /**
   * Execute a capability with full validation, cost estimation, and audit
   */
  async executeCapability(
    spec: CapabilitySpec,
    parameters: Record<string, unknown>,
    context: Partial<CapabilityExecutionContext>
  ): Promise<CapabilityExecutionResult> {
    const executionId = CorrelationId.generate();
    const fullContext: CapabilityExecutionContext = {
      capabilityId: spec.id,
      executionId,
      correlationId: context.correlationId || CorrelationId.generate(),
      userId: context.userId!,
      businessId: context.businessId!,
      sessionId: context.sessionId,
      aiRequestId: context.aiRequestId,
      aiModel: context.aiModel,
      aiConfidence: context.aiConfidence,
      startTime: Date.now(),
      timeout: context.timeout || this.config.defaultTimeoutMs,
      dryRun: context.dryRun || false,
      parentExecutionId: context.parentExecutionId,
      callStack: context.callStack || [],
    };

    // Check concurrent execution limits
    if (this.activeExecutions.size >= this.config.maxConcurrentExecutions) {
      throw new CapabilityValidationError(
        'Maximum concurrent executions limit reached',
        'execution',
        'CONCURRENT_LIMIT_EXCEEDED'
      );
    }

    this.activeExecutions.set(executionId, fullContext);

    try {
      const startTime = Date.now();

      // Step 1: Validate capability specification
      this.validator.validateCapabilitySpec(spec);

      // Step 2: Validate and sanitize parameters
      const validatedParameters = await this.validator.validateExecutionParameters(
        spec,
        parameters,
        fullContext
      );

      // Step 3: Estimate execution cost
      const costEstimate = await this.estimateExecutionCost(spec, validatedParameters, fullContext);

      // Step 4: Check cost limits
      if (this.config.enableCostLimits) {
        await this.checkCostLimits(spec, costEstimate, fullContext);
      }

      // Step 5: Check permissions
      if (this.config.enablePermissionChecking) {
        await this.checkPermissions(spec, fullContext);
      }

      // Step 6: Emit audit event for execution start
      if (this.config.enableAuditLogging) {
        await this.emitAuditEvent('capability_execution_start', spec, fullContext, {
          parameters: this.redactSensitiveParameters(spec, validatedParameters),
          estimatedCost: costEstimate,
        });
      }

      // Step 7: Execute the capability (or simulate if dry run)
      const result = fullContext.dryRun
        ? await this.simulateExecution(spec, validatedParameters, fullContext)
        : await this.executeCapabilityOperation(spec, validatedParameters, fullContext);

      // Step 8: Validate result
      const validatedResult = await this.validator.validateExecutionResult(
        spec,
        result,
        fullContext
      );

      // Step 9: Calculate actual cost
      const actualCost = await this.calculateActualCost(
        spec,
        validatedParameters,
        validatedResult,
        fullContext,
        Date.now() - startTime
      );

      // Step 10: Create execution result
      const executionResult: CapabilityExecutionResult = {
        success: true,
        result: validatedResult,
        executionTime: Date.now() - startTime,
        actualCost,
        auditEvent: {
          eventId: CorrelationId.generate(),
          timestamp: Date.now(),
          outcome: 'success',
          sensitiveDataRedacted: spec.audit.sensitiveDataHandling.redactResults,
        },
      };

      // Step 11: Emit success audit event
      if (this.config.enableAuditLogging) {
        await this.emitAuditEvent('capability_execution_success', spec, fullContext, {
          result: this.redactSensitiveResult(spec, validatedResult),
          actualCost,
          executionTime: executionResult.executionTime,
        });
      }

      this.logger.info('Capability executed successfully', {
        capabilityId: spec.id,
        executionId,
        executionTime: executionResult.executionTime,
        actualCost: actualCost.totalUSD,
        correlationId: fullContext.correlationId,
      });

      return executionResult;

    } catch (error: any) {
      const executionTime = Date.now() - fullContext.startTime;
      const errorCode = this.getErrorCode(error);
      const isRetryable = this.isRetryableError(error);

      const executionResult: CapabilityExecutionResult = {
        success: false,
        error: {
          code: errorCode,
          message: error instanceof Error ? error.message : 'Unknown error',
          details: error instanceof CapabilityValidationError ? { value: error.value } : undefined,
          retryable: isRetryable,
        },
        executionTime,
        actualCost: {
          computeUnits: 1, // Minimal cost for failed execution
          totalUSD: this.config.costMultipliers.COMPUTE_UNIT_USD,
          breakdown: { base: 1, parameters: 0, operation: 0, ai: 0, custom: {} },
        },
        auditEvent: {
          eventId: CorrelationId.generate(),
          timestamp: Date.now(),
          outcome: 'failure',
          sensitiveDataRedacted: false,
        },
      };

      // Emit failure audit event
      if (this.config.enableAuditLogging) {
        await this.emitAuditEvent('capability_execution_failure', spec, fullContext, {
          error: executionResult.error,
          executionTime,
        });
      }

      this.logger.error('Capability execution failed', error, {
        capabilityId: spec.id,
        executionId,
        errorCode,
        executionTime,
        correlationId: fullContext.correlationId,
      });

      return executionResult;

    } finally {
      this.activeExecutions.delete(executionId);
    }
  }

  /**
   * Estimate execution cost before running capability
   */
  async estimateExecutionCost(
    spec: CapabilitySpec,
    parameters: Record<string, unknown>,
    context: CapabilityExecutionContext
  ): Promise<CostEstimate> {
    const costSpec = spec.costEstimation;
    let computeUnits = costSpec.baseComputeUnits;

    // Parameter-based cost
    const parameterCost = (costSpec.perParameterUnits || 0) * Object.keys(parameters).length;
    computeUnits += parameterCost;

    // Operation-specific cost estimation
    let operationCost = 0;
    let confidence: CostEstimate['confidence'] = 'high';

    if (spec.sqlOperation) {
      operationCost = await this.estimateSQLCost(spec.sqlOperation, parameters);
      confidence = 'medium'; // SQL operations can vary significantly
    } else if (spec.apiOperation) {
      operationCost = await this.estimateAPICost(spec.apiOperation, parameters);
      confidence = 'low'; // External API costs are unpredictable
    } else if (spec.fileOperation) {
      operationCost = await this.estimateFileCost(spec.fileOperation, parameters);
      confidence = 'medium';
    }

    computeUnits += operationCost;

    // AI-specific cost
    let aiCost = 0;
    if (context.aiRequestId && costSpec.aiTokenMultiplier) {
      const estimatedTokens = this.estimateAITokens(spec, parameters);
      aiCost = estimatedTokens * costSpec.aiTokenMultiplier;
      computeUnits += aiCost;
    }

    // Custom cost factors
    const customCosts: Record<string, number> = {};
    if (costSpec.customCostFactors) {
      for (const [factor, multiplier] of Object.entries(costSpec.customCostFactors)) {
        const factorCost = this.calculateCustomCostFactor(factor, parameters, multiplier);
        customCosts[factor] = factorCost;
        computeUnits += factorCost;
      }
    }

    const totalUSD = computeUnits * this.config.costMultipliers.COMPUTE_UNIT_USD;

    return {
      computeUnits,
      totalUSD,
      breakdown: {
        base: costSpec.baseComputeUnits,
        parameters: parameterCost,
        operation: operationCost,
        ai: aiCost,
        custom: customCosts,
      },
      confidence,
    };
  }

  /**
   * Register custom handlers
   */
  registerSQLHandler(name: string, handler: any): void {
    this.sqlHandlers.set(name, handler);
  }

  registerAPIHandler(name: string, handler: any): void {
    this.apiHandlers.set(name, handler);
  }

  registerFileHandler(name: string, handler: any): void {
    this.fileHandlers.set(name, handler);
  }

  registerCustomHandler(name: string, handler: any): void {
    this.customHandlers.set(name, handler);
  }

  /**
   * Private methods
   */

  private async checkCostLimits(
    spec: CapabilitySpec,
    costEstimate: CostEstimate,
    context: CapabilityExecutionContext
  ): Promise<void> {
    const maxCostUSD = spec.costEstimation.maxCostUSD;

    if (maxCostUSD && costEstimate.totalUSD > maxCostUSD) {
      throw new CapabilityCostLimitError(
        `Estimated cost $${costEstimate.totalUSD} exceeds capability limit $${maxCostUSD}`,
        costEstimate.totalUSD,
        maxCostUSD
      );
    }

    // Additional business logic for cost approval
    if (costEstimate.totalUSD > 10.0) { // $10 threshold for high-cost operations
      this.logger.warn('High-cost capability execution', {
        capabilityId: spec.id,
        estimatedCost: costEstimate.totalUSD,
        userId: context.userId,
        correlationId: context.correlationId,
      });
    }
  }

  private async checkPermissions(
    spec: CapabilitySpec,
    context: CapabilityExecutionContext
  ): Promise<void> {
    const permissionSpec = spec.permissions;

    // Check required capabilities
    for (const requiredCapability of permissionSpec.requiredCapabilities) {
      const hasPermission = await this.permissionEngine.checkPermission({
        capability: requiredCapability,
        resourceType: 'capability',
        resourceId: spec.id,
        businessId: context.businessId,
        userId: context.userId,
        correlationId: context.correlationId,
      });

      if (!hasPermission.allowed) {
        throw new CapabilityPermissionError(
          `Missing required capability: ${requiredCapability}`,
          requiredCapability,
          [] // Would get user's actual capabilities in real implementation
        );
      }
    }

    // Check elevated privileges
    if (permissionSpec.elevatedPrivileges) {
      const isAdmin = await this.permissionEngine.checkPermission({
        capability: 'admin:execute_elevated_capabilities',
        resourceType: 'system',
        resourceId: 'capabilities',
        businessId: context.businessId,
        userId: context.userId,
        correlationId: context.correlationId,
      });

      if (!isAdmin.allowed) {
        throw new CapabilityPermissionError(
          'Elevated privileges required for this capability',
          'admin:execute_elevated_capabilities',
          []
        );
      }
    }
  }

  private async executeCapabilityOperation(
    spec: CapabilitySpec,
    parameters: Record<string, unknown>,
    context: CapabilityExecutionContext
  ): Promise<unknown> {
    const timeout = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Capability execution timeout')), context.timeout);
    });

    const execution = this.performOperation(spec, parameters, context);

    return Promise.race([execution, timeout]);
  }

  private async performOperation(
    spec: CapabilitySpec,
    parameters: Record<string, unknown>,
    context: CapabilityExecutionContext
  ): Promise<unknown> {
    if (spec.sqlOperation) {
      return this.executeSQLOperation(spec.sqlOperation, parameters, context);
    } else if (spec.apiOperation) {
      return this.executeAPIOperation(spec.apiOperation, parameters, context);
    } else if (spec.fileOperation) {
      return this.executeFileOperation(spec.fileOperation, parameters, context);
    } else if (spec.customHandler) {
      return this.executeCustomHandler(spec.customHandler, parameters, context);
    } else {
      throw new CapabilityValidationError(
        'No valid operation specified',
        'operation',
        'NO_OPERATION_SPECIFIED'
      );
    }
  }

  private async executeSQLOperation(
    sqlOp: any,
    parameters: Record<string, unknown>,
    context: CapabilityExecutionContext
  ): Promise<unknown> {
    const handler = this.sqlHandlers.get('default');
    if (!handler) {
      throw new CapabilityValidationError(
        'No SQL handler registered',
        'sql',
        'NO_SQL_HANDLER'
      );
    }

    return handler.execute(sqlOp, parameters, context);
  }

  private async executeAPIOperation(
    apiOp: any,
    parameters: Record<string, unknown>,
    context: CapabilityExecutionContext
  ): Promise<unknown> {
    const handler = this.apiHandlers.get('default');
    if (!handler) {
      throw new CapabilityValidationError(
        'No API handler registered',
        'api',
        'NO_API_HANDLER'
      );
    }

    return handler.execute(apiOp, parameters, context);
  }

  private async executeFileOperation(
    fileOp: any,
    parameters: Record<string, unknown>,
    context: CapabilityExecutionContext
  ): Promise<unknown> {
    const handler = this.fileHandlers.get('default');
    if (!handler) {
      throw new CapabilityValidationError(
        'No file handler registered',
        'file',
        'NO_FILE_HANDLER'
      );
    }

    return handler.execute(fileOp, parameters, context);
  }

  private async executeCustomHandler(
    handlerName: string,
    parameters: Record<string, unknown>,
    context: CapabilityExecutionContext
  ): Promise<unknown> {
    const handler = this.customHandlers.get(handlerName);
    if (!handler) {
      throw new CapabilityValidationError(
        `Custom handler '${handlerName}' not found`,
        'custom',
        'CUSTOM_HANDLER_NOT_FOUND'
      );
    }

    return handler.execute(parameters, context);
  }

  private async simulateExecution(
    spec: CapabilitySpec,
    parameters: Record<string, unknown>,
    context: CapabilityExecutionContext
  ): Promise<unknown> {
    // Simulate execution for dry run mode
    await new Promise(resolve => setTimeout(resolve, 100)); // Simulate some processing time

    // Return mock data based on return type
    switch (spec.returnType.type) {
      case 'object':
        return { simulated: true, parameters };
      case 'array':
        return [{ simulated: true }];
      case 'string':
        return 'Simulated result';
      case 'number':
        return 42;
      case 'boolean':
        return true;
      default:
        return null;
    }
  }

  private async calculateActualCost(
    spec: CapabilitySpec,
    parameters: Record<string, unknown>,
    result: unknown,
    context: CapabilityExecutionContext,
    executionTime: number
  ): Promise<CapabilityExecutionResult['actualCost']> {
    // Base cost from execution time
    const computeUnits = Math.ceil(executionTime / 100); // 1 unit per 100ms

    // Add operation-specific costs
    let additionalCosts = 0;
    if (spec.sqlOperation && Array.isArray(result)) {
      additionalCosts += result.length * (spec.costEstimation.perRowUnits || 0);
    }

    const totalComputeUnits = computeUnits + additionalCosts;
    const totalUSD = totalComputeUnits * this.config.costMultipliers.COMPUTE_UNIT_USD;

    return {
      computeUnits: totalComputeUnits,
      totalUSD,
      breakdown: {
        execution: computeUnits * this.config.costMultipliers.COMPUTE_UNIT_USD,
        operation: additionalCosts * this.config.costMultipliers.COMPUTE_UNIT_USD,
      },
    };
  }

  private async emitAuditEvent(
    eventType: string,
    spec: CapabilitySpec,
    context: CapabilityExecutionContext,
    data: Record<string, unknown>
  ): Promise<void> {
    try {
      await this.auditService.logEvent({
        eventType,
        severity: spec.audit.severity,
        operation: `capability:${spec.id}`,
        result: 'success',
        details: {
          capabilityId: spec.id,
          capabilityVersion: spec.version,
          executionId: context.executionId,
          ...data,
        },
        securityContext: {
          correlationId: context.correlationId,
          userId: context.userId,
          businessId: context.businessId,
          operation: `capability_execution:${spec.id}`,
        },
      });
    } catch (error: any) {
      this.logger.error('Failed to emit audit event', error, {
        eventType,
        capabilityId: spec.id,
        correlationId: context.correlationId,
      });
    }
  }

  private redactSensitiveParameters(
    spec: CapabilitySpec,
    parameters: Record<string, unknown>
  ): Record<string, unknown> {
    const redacted = { ...parameters };

    for (const param of spec.parameters) {
      if (param.sensitive && redacted[param.name] !== undefined) {
        redacted[param.name] = '[REDACTED]';
      }
    }

    return redacted;
  }

  private redactSensitiveResult(spec: CapabilitySpec, result: unknown): unknown {
    if (!spec.audit.sensitiveDataHandling.redactResults) {
      return result;
    }

    // Simple redaction - in production, use more sophisticated methods
    if (typeof result === 'object' && result !== null) {
      const redacted = { ...result as Record<string, unknown> };
      const sensitiveFields = ['password', 'token', 'secret', 'key', 'ssn', 'creditCard'];

      for (const field of sensitiveFields) {
        if (field in redacted) {
          redacted[field] = '[REDACTED]';
        }
      }

      return redacted;
    }

    return result;
  }

  private getErrorCode(error: unknown): string {
    if (error instanceof CapabilityValidationError) return error.code;
    if (error instanceof CapabilityPermissionError) return 'PERMISSION_DENIED';
    if (error instanceof CapabilityCostLimitError) return 'COST_LIMIT_EXCEEDED';
    if (error instanceof SecurityError) return 'SECURITY_ERROR';
    return 'UNKNOWN_ERROR';
  }

  private isRetryableError(error: unknown): boolean {
    if (error instanceof CapabilityValidationError) return false;
    if (error instanceof CapabilityPermissionError) return false;
    if (error instanceof CapabilityCostLimitError) return false;
    if (error instanceof SecurityError) return false;
    return true; // Network errors, timeouts, etc. are retryable
  }

  private async estimateSQLCost(sqlOp: any, parameters: Record<string, unknown>): Promise<number> {
    // Estimate based on operation type and potential result size
    const baseCost = {
      select: 2,
      insert: 3,
      update: 4,
      delete: 5,
      procedure: 10,
    }[sqlOp.type] || 2;

    // Add cost based on potential row count
    const maxRows = sqlOp.maxRows || 1000;
    return baseCost + Math.ceil(maxRows / 100);
  }

  private async estimateAPICost(apiOp: any, parameters: Record<string, unknown>): Promise<number> {
    // Base cost for API operations
    return 5 + (apiOp.retries || 0) * 2;
  }

  private async estimateFileCost(fileOp: any, parameters: Record<string, unknown>): Promise<number> {
    // Estimate based on file operation type
    const baseCost = {
      read: 2,
      write: 3,
      delete: 1,
      upload: 5,
      download: 3,
    }[fileOp.operation] || 2;

    // Add cost based on file size if available
    const fileSize = parameters.fileSize as number || 1024; // Default 1KB
    return baseCost + Math.ceil(fileSize / 1024); // 1 unit per KB
  }

  private estimateAITokens(spec: CapabilitySpec, parameters: Record<string, unknown>): number {
    // Simple token estimation based on parameter content
    let totalTokens = 100; // Base prompt tokens

    for (const param of spec.parameters) {
      if (param.aiUsage?.includeInPrompt) {
        const value = parameters[param.name];
        if (typeof value === 'string') {
          totalTokens += Math.ceil(value.length / 4); // Rough token estimation
        } else if (value) {
          totalTokens += Math.ceil(JSON.stringify(value).length / 4);
        }
      }
    }

    return Math.min(totalTokens, param.aiUsage?.maxTokens || 4000);
  }

  private calculateCustomCostFactor(
    factor: string,
    parameters: Record<string, unknown>,
    multiplier: number
  ): number {
    // Custom cost calculation based on factor name
    switch (factor) {
      case 'recordCount':
        return (parameters.recordCount as number || 1) * multiplier;
      case 'fileSize':
        return Math.ceil((parameters.fileSize as number || 0) / 1024) * multiplier;
      case 'complexity':
        return (parameters.complexity as number || 1) * multiplier;
      default:
        return multiplier;
    }
  }

  private initializeBuiltInHandlers(): void {
    // Register default SQL handler
    this.registerSQLHandler('default', {
      async execute(sqlOp: any, parameters: Record<string, unknown>, context: CapabilityExecutionContext) {
        // Placeholder for actual SQL execution
        // In production, this would connect to D1 database
        return { message: 'SQL operation simulated', operation: sqlOp.type, parameters };
      }
    });

    // Register default API handler
    this.registerAPIHandler('default', {
      async execute(apiOp: any, parameters: Record<string, unknown>, context: CapabilityExecutionContext) {
        // Placeholder for actual API calls
        // In production, this would make HTTP requests
        return { message: 'API operation simulated', method: apiOp.method, endpoint: apiOp.endpoint };
      }
    });

    // Register default file handler
    this.registerFileHandler('default', {
      async execute(fileOp: any, parameters: Record<string, unknown>, context: CapabilityExecutionContext) {
        // Placeholder for actual file operations
        // In production, this would interact with R2 storage
        return { message: 'File operation simulated', operation: fileOp.operation };
      }
    });
  }
}