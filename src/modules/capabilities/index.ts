/**
 * Capability Contract System Module
 * Central entry point for safe AI tool use with validation and audit
 */

// Core capability system
export { CapabilityValidator } from './validator';
export { CapabilityExecutor } from './executor';

// Type definitions
export type {
  CapabilitySpec,
  ParameterSpec,
  ParameterValidation,
  SqlOperationSpec,
  ApiOperationSpec,
  FileOperationSpec,
  CostSpec,
  PermissionSpec,
  AuditSpec,
  CapabilityExecutionContext,
  CapabilityExecutionResult,
  ParameterType,
  CostEstimate
} from './types';

// Error types
export {
  CapabilityValidationError,
  CapabilityPermissionError,
  CapabilityCostLimitError
} from './types';

// Validation schemas and constants
export {
  ParameterValidationSchema,
  ParameterSpecSchema,
  SqlOperationSpecSchema,
  ApiOperationSpecSchema,
  FileOperationSpecSchema,
  CostSpecSchema,
  PermissionSpecSchema,
  AuditSpecSchema,
  CapabilitySpecSchema,
  BuiltInValidators,
  DEFAULT_COST_MULTIPLIERS,
  EXECUTION_LIMITS
} from './types';

// Example capabilities and validators
export {
  InvoiceCreationCapability,
  LedgerPostingCapability,
  PaymentProcessingCapability,
  ExampleCapabilities,
  ExampleValidators
} from './examples';

import { CapabilityValidator } from './validator';
import { CapabilityExecutor, type CapabilityExecutorConfig } from './executor';
import { ABACPermissionEngine } from '../abac/permission-engine';
import { AuditService } from '../audit/audit-service';
import { Logger } from '../../shared/logger';
import {
  CapabilitySpec,
  CapabilityExecutionContext,
  CapabilityExecutionResult,
  CapabilityValidationError
} from './types';
import { ExampleValidators } from './examples';

/**
 * Capability Manager
 * High-level interface for managing and executing capabilities
 */
export class CapabilityManager {
  private logger: Logger;
  private validator: CapabilityValidator;
  private executor: CapabilityExecutor;
  private capabilities = new Map<string, CapabilitySpec>();

  constructor(
    permissionEngine: ABACPermissionEngine,
    auditService: AuditService,
    config: Partial<CapabilityExecutorConfig> = {}
  ) {
    this.logger = new Logger();
    this.validator = new CapabilityValidator();
    this.executor = new CapabilityExecutor(permissionEngine, auditService, config);

    this.registerBuiltInValidators();
  }

  /**
   * Register a capability
   */
  registerCapability(capability: CapabilitySpec): void {
    try {
      // Validate the capability specification
      this.validator.validateCapabilitySpec(capability);

      // Store the capability
      this.capabilities.set(capability.id, capability);

      this.logger.info('Capability registered', {
        capabilityId: capability.id,
        version: capability.version,
        category: capability.category,
      });

    } catch (error) {
      this.logger.error('Failed to register capability', error, {
        capabilityId: capability.id,
      });
      throw error;
    }
  }

  /**
   * Get registered capability
   */
  getCapability(capabilityId: string): CapabilitySpec | undefined {
    return this.capabilities.get(capabilityId);
  }

  /**
   * List all registered capabilities
   */
  listCapabilities(category?: string): CapabilitySpec[] {
    const capabilities = Array.from(this.capabilities.values());

    if (category) {
      return capabilities.filter(cap => cap.category === category);
    }

    return capabilities;
  }

  /**
   * Execute a capability
   */
  async executeCapability(
    capabilityId: string,
    parameters: Record<string, unknown>,
    context: Partial<CapabilityExecutionContext>
  ): Promise<CapabilityExecutionResult> {
    const capability = this.capabilities.get(capabilityId);
    if (!capability) {
      throw new CapabilityValidationError(
        `Capability '${capabilityId}' not found`,
        'capability',
        'CAPABILITY_NOT_FOUND'
      );
    }

    return this.executor.executeCapability(capability, parameters, context);
  }

  /**
   * Estimate capability execution cost
   */
  async estimateCost(
    capabilityId: string,
    parameters: Record<string, unknown>,
    context: Partial<CapabilityExecutionContext>
  ) {
    const capability = this.capabilities.get(capabilityId);
    if (!capability) {
      throw new CapabilityValidationError(
        `Capability '${capabilityId}' not found`,
        'capability',
        'CAPABILITY_NOT_FOUND'
      );
    }

    const fullContext = {
      ...context,
      capabilityId,
      executionId: 'estimate',
      startTime: Date.now(),
      timeout: 30000,
    } as CapabilityExecutionContext;

    return this.executor.estimateExecutionCost(capability, parameters, fullContext);
  }

  /**
   * Validate capability parameters without execution
   */
  async validateParameters(
    capabilityId: string,
    parameters: Record<string, unknown>,
    context: Partial<CapabilityExecutionContext>
  ): Promise<Record<string, unknown>> {
    const capability = this.capabilities.get(capabilityId);
    if (!capability) {
      throw new CapabilityValidationError(
        `Capability '${capabilityId}' not found`,
        'capability',
        'CAPABILITY_NOT_FOUND'
      );
    }

    const fullContext = {
      ...context,
      capabilityId,
      executionId: 'validation',
      startTime: Date.now(),
      timeout: 30000,
    } as CapabilityExecutionContext;

    return this.validator.validateExecutionParameters(capability, parameters, fullContext);
  }

  /**
   * Register custom validator
   */
  registerValidator(name: string, validator: (value: unknown) => boolean): void {
    this.validator.registerValidator(name, validator);
  }

  /**
   * Register operation handlers
   */
  registerSQLHandler(name: string, handler: any): void {
    this.executor.registerSQLHandler(name, handler);
  }

  registerAPIHandler(name: string, handler: any): void {
    this.executor.registerAPIHandler(name, handler);
  }

  registerFileHandler(name: string, handler: any): void {
    this.executor.registerFileHandler(name, handler);
  }

  registerCustomHandler(name: string, handler: any): void {
    this.executor.registerCustomHandler(name, handler);
  }

  /**
   * Get capability documentation
   */
  getCapabilityDocumentation(capabilityId: string): any {
    const capability = this.capabilities.get(capabilityId);
    if (!capability) {
      return null;
    }

    return {
      id: capability.id,
      name: capability.name,
      description: capability.description,
      version: capability.version,
      category: capability.category,
      parameters: capability.parameters.map(param => ({
        name: param.name,
        type: param.type,
        description: param.description,
        required: param.validation.required,
        examples: param.examples,
      })),
      returnType: capability.returnType,
      tags: capability.tags,
      permissions: capability.permissions.requiredCapabilities,
      estimatedCost: {
        baseUnits: capability.costEstimation.baseComputeUnits,
        maxCostUSD: capability.costEstimation.maxCostUSD,
      },
      auditSeverity: capability.audit.severity,
      deprecated: capability.deprecated,
      replacedBy: capability.replacedBy,
    };
  }

  /**
   * Search capabilities by criteria
   */
  searchCapabilities(criteria: {
    category?: string;
    tags?: string[];
    permissions?: string[];
    maxCost?: number;
    includeDeprecated?: boolean;
  }): CapabilitySpec[] {
    return Array.from(this.capabilities.values()).filter(capability => {
      // Filter by category
      if (criteria.category && capability.category !== criteria.category) {
        return false;
      }

      // Filter by tags
      if (criteria.tags && criteria.tags.length > 0) {
        const capabilityTags = capability.tags || [];
        if (!criteria.tags.some(tag => capabilityTags.includes(tag))) {
          return false;
        }
      }

      // Filter by required permissions
      if (criteria.permissions && criteria.permissions.length > 0) {
        if (!criteria.permissions.some(perm =>
          capability.permissions.requiredCapabilities.includes(perm)
        )) {
          return false;
        }
      }

      // Filter by max cost
      if (criteria.maxCost !== undefined) {
        const maxCost = capability.costEstimation.maxCostUSD;
        if (maxCost && maxCost > criteria.maxCost) {
          return false;
        }
      }

      // Filter deprecated capabilities
      if (!criteria.includeDeprecated && capability.deprecated) {
        return false;
      }

      return true;
    });
  }

  /**
   * Get capability usage statistics
   */
  getCapabilityStats(capabilityId: string): any {
    // In a real implementation, this would fetch usage statistics from storage
    return {
      capabilityId,
      totalExecutions: 0,
      successfulExecutions: 0,
      failedExecutions: 0,
      averageExecutionTime: 0,
      averageCost: 0,
      lastExecuted: null,
    };
  }

  /**
   * Private methods
   */

  private registerBuiltInValidators(): void {
    // Register example validators
    for (const [name, validator] of Object.entries(ExampleValidators)) {
      this.validator.registerValidator(name, validator);
    }

    // Register additional business logic validators
    this.validator.registerValidator('validateCustomerExists', (customerId: unknown) => {
      // In production, this would check the customer database
      return typeof customerId === 'string' && customerId.length > 0;
    });

    this.validator.registerValidator('validateInvoiceNumberUnique', (invoiceNumber: unknown) => {
      // In production, this would check for duplicate invoice numbers
      return typeof invoiceNumber === 'string' && /^INV-[0-9]{4}-[0-9]+$/.test(invoiceNumber);
    });

    this.validator.registerValidator('validateDateOrder', (params: any) => {
      if (params.issueDate && params.dueDate) {
        return new Date(params.dueDate) > new Date(params.issueDate);
      }
      return true;
    });

    this.validator.registerValidator('validateAccountCodes', (entries: any) => {
      if (Array.isArray(entries)) {
        return entries.every((entry: any) =>
          entry.accountCode && /^[0-9]{4}$/.test(entry.accountCode)
        );
      }
      return true;
    });

    this.validator.registerValidator('validateFiscalPeriodOpen', (fiscalPeriod: unknown) => {
      // In production, this would check if the fiscal period is open for posting
      return typeof fiscalPeriod === 'string' && /^[0-9]{4}-[0-9]{2}$/.test(fiscalPeriod);
    });
  }
}

/**
 * Factory function to create capability manager with default configuration
 */
export async function createCapabilityManager(
  permissionEngine: ABACPermissionEngine,
  auditService: AuditService,
  config: Partial<CapabilityExecutorConfig> = {}
): Promise<CapabilityManager> {
  const manager = new CapabilityManager(permissionEngine, auditService, config);

  // Register example capabilities
  const { ExampleCapabilities } = await import('./examples');
  for (const capability of Object.values(ExampleCapabilities)) {
    manager.registerCapability(capability);
  }

  return manager;
}

/**
 * Utility functions for capability management
 */
export const CapabilityUtils = {
  /**
   * Create a simple capability specification
   */
  createSimpleCapability(config: {
    id: string;
    name: string;
    description: string;
    parameters: Array<{
      name: string;
      type: any;
      description: string;
      required?: boolean;
    }>;
    operation: 'sql' | 'api' | 'file' | 'custom';
    operationConfig: any;
    permissions: string[];
    owner: string;
  }): CapabilitySpec {
    return {
      id: config.id,
      name: config.name,
      description: config.description,
      version: '1.0.0',
      category: config.operation === 'sql' ? 'database' :
                config.operation === 'api' ? 'api' :
                config.operation === 'file' ? 'file' : 'computation',

      parameters: config.parameters.map(param => ({
        ...param,
        validation: {
          required: param.required ?? false,
        },
        aiUsage: {
          includeInPrompt: true,
          sanitize: true,
        },
      })),

      ...(config.operation === 'sql' && { sqlOperation: config.operationConfig }),
      ...(config.operation === 'api' && { apiOperation: config.operationConfig }),
      ...(config.operation === 'file' && { fileOperation: config.operationConfig }),
      ...(config.operation === 'custom' && { customHandler: config.operationConfig }),

      returnType: {
        type: 'object',
      },

      validation: {
        preExecution: [],
        postExecution: [],
      },

      costEstimation: {
        baseComputeUnits: 5,
        maxCostUSD: 0.10,
      },

      permissions: {
        requiredCapabilities: config.permissions,
        businessContextRequired: true,
        userContextRequired: true,
      },

      audit: {
        severity: 'medium',
        eventType: `${config.id}_execution`,
        sensitiveDataHandling: {
          redactParameters: [],
          redactResults: false,
          retentionDays: 365,
        },
      },

      owner: config.owner,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
  },

  /**
   * Validate capability ID format
   */
  validateCapabilityId(id: string): boolean {
    return /^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$/.test(id);
  },

  /**
   * Generate capability documentation in markdown
   */
  generateDocumentation(capability: CapabilitySpec): string {
    const sections = [
      `# ${capability.name}`,
      '',
      `**ID:** \`${capability.id}\``,
      `**Version:** ${capability.version}`,
      `**Category:** ${capability.category}`,
      '',
      `## Description`,
      capability.description,
      '',
      `## Parameters`,
      '',
      '| Name | Type | Required | Description |',
      '|------|------|----------|-------------|',
      ...capability.parameters.map(param =>
        `| ${param.name} | ${param.type} | ${param.validation.required ? 'Yes' : 'No'} | ${param.description} |`
      ),
      '',
      `## Permissions Required`,
      '',
      ...capability.permissions.requiredCapabilities.map(perm => `- ${perm}`),
      '',
      `## Cost Estimation`,
      '',
      `- Base cost: ${capability.costEstimation.baseComputeUnits} compute units`,
      `- Maximum cost: $${capability.costEstimation.maxCostUSD || 'unlimited'}`,
      '',
      `## Audit`,
      '',
      `- Severity: ${capability.audit.severity}`,
      `- Event type: ${capability.audit.eventType}`,
      `- Retention: ${capability.audit.sensitiveDataHandling.retentionDays} days`,
    ];

    return sections.join('\n');
  },
};