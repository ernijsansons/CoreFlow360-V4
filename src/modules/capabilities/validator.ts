/**
 * Capability Validation System
 * Validates capability parameters, prevents SQL injection, and ensures safety
 */

import {
  CapabilitySpec,
  ParameterSpec,
  ParameterValidation,
  CapabilityValidationError,
  BuiltInValidators,
  EXECUTION_LIMITS,
  CapabilityExecutionContext
} from './types';
import { Logger } from '../../shared/logger';
import { SecurityError, InputValidator, PIIRedactor } from '../../shared/security-utils';

export class CapabilityValidator {
  private logger: Logger;
  private customValidators: Map<string, (value: unknown) => boolean> = new Map();

  constructor() {
    this.logger = new Logger();
    this.registerBuiltInValidators();
  }

  /**
   * Validate capability specification
   */
  validateCapabilitySpec(spec: CapabilitySpec): void {
    try {
      // Validate basic structure using Zod schema
      const { CapabilitySpecSchema } = require('./types');
      CapabilitySpecSchema.parse(spec);

      // Additional custom validations
      this.validateOperationSpecs(spec);
      this.validateParameterConsistency(spec);
      this.validateSecurityConstraints(spec);

      this.logger.info('Capability specification validated', {
        capabilityId: spec.id,
        version: spec.version,
        category: spec.category,
      });

    } catch (error) {
      this.logger.error('Capability specification validation failed', error, {
        capabilityId: spec.id,
      });
      throw new CapabilityValidationError(
        `Invalid capability specification: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'specification',
        'INVALID_SPEC',
        spec
      );
    }
  }

  /**
   * Validate execution parameters before capability execution
   */
  async validateExecutionParameters(
    spec: CapabilitySpec,
    parameters: Record<string, unknown>,
    context: CapabilityExecutionContext
  ): Promise<Record<string, unknown>> {
    const startTime = Date.now();

    try {
      // Check execution limits
      this.validateExecutionLimits(parameters);

      // Validate each parameter
      const validatedParameters: Record<string, unknown> = {};

      for (const paramSpec of spec.parameters) {
        const value = parameters[paramSpec.name];
        const validatedValue = await this.validateParameter(paramSpec, value, context);
        validatedParameters[paramSpec.name] = validatedValue;
      }

      // Cross-parameter validation
      if (spec.validation.crossParameterValidation) {
        await this.runCrossParameterValidation(
          spec.validation.crossParameterValidation,
          validatedParameters,
          context
        );
      }

      // Pre-execution validations
      for (const validatorName of spec.validation.preExecution) {
        await this.runCustomValidation(validatorName, validatedParameters, context);
      }

      // SQL injection prevention for SQL operations
      if (spec.sqlOperation) {
        this.validateSQLParameters(spec, validatedParameters);
      }

      const duration = Date.now() - startTime;
      this.logger.info('Parameter validation completed', {
        capabilityId: spec.id,
        parameterCount: Object.keys(validatedParameters).length,
        validationTime: duration,
        correlationId: context.correlationId,
      });

      return validatedParameters;

    } catch (error) {
      const duration = Date.now() - startTime;
      this.logger.error('Parameter validation failed', error, {
        capabilityId: spec.id,
        validationTime: duration,
        correlationId: context.correlationId,
      });
      throw error;
    }
  }

  /**
   * Validate post-execution results
   */
  async validateExecutionResult(
    spec: CapabilitySpec,
    result: unknown,
    context: CapabilityExecutionContext
  ): Promise<unknown> {
    try {
      // Validate result type
      const validatedResult = this.validateResultType(spec.returnType, result);

      // Check result size limits
      this.validateResultSize(validatedResult);

      // Post-execution validations
      for (const validatorName of spec.validation.postExecution) {
        await this.runCustomValidation(validatorName, { result: validatedResult }, context);
      }

      // Redact sensitive data if needed
      const redactedResult = this.redactSensitiveData(spec, validatedResult);

      this.logger.info('Result validation completed', {
        capabilityId: spec.id,
        correlationId: context.correlationId,
      });

      return redactedResult;

    } catch (error) {
      this.logger.error('Result validation failed', error, {
        capabilityId: spec.id,
        correlationId: context.correlationId,
      });
      throw error;
    }
  }

  /**
   * Register custom validator function
   */
  registerValidator(name: string, validator: (value: unknown) => boolean): void {
    this.customValidators.set(name, validator);
    this.logger.info('Custom validator registered', { name });
  }

  /**
   * Private validation methods
   */

  private registerBuiltInValidators(): void {
    for (const [name, validator] of Object.entries(BuiltInValidators)) {
      this.customValidators.set(name, validator);
    }
  }

  private validateOperationSpecs(spec: CapabilitySpec): void {
    const operationCount = [
      spec.sqlOperation,
      spec.apiOperation,
      spec.fileOperation,
      spec.customHandler,
    ].filter(Boolean).length;

    if (operationCount !== 1) {
      throw new CapabilityValidationError(
        'Capability must specify exactly one operation type',
        'operation',
        'MULTIPLE_OPERATIONS'
      );
    }

    // Validate SQL operation safety
    if (spec.sqlOperation) {
      this.validateSQLOperationSpec(spec.sqlOperation);
    }
  }

  private validateParameterConsistency(spec: CapabilitySpec): void {
    const parameterNames = new Set<string>();

    for (const param of spec.parameters) {
      if (parameterNames.has(param.name)) {
        throw new CapabilityValidationError(
          `Duplicate parameter name: ${param.name}`,
          param.name,
          'DUPLICATE_PARAMETER'
        );
      }
      parameterNames.add(param.name);

      // Validate parameter name (no SQL injection risk)
      if (!BuiltInValidators.validateSQLIdentifier(param.name)) {
        throw new CapabilityValidationError(
          `Invalid parameter name: ${param.name}`,
          param.name,
          'INVALID_PARAMETER_NAME'
        );
      }
    }
  }

  private validateSecurityConstraints(spec: CapabilitySpec): void {
    // Ensure sensitive parameters are properly configured
    for (const param of spec.parameters) {
      if (param.sensitive && param.aiUsage?.includeInPrompt) {
        throw new CapabilityValidationError(
          `Sensitive parameter ${param.name} cannot be included in AI prompts`,
          param.name,
          'SENSITIVE_PARAMETER_IN_PROMPT'
        );
      }
    }

    // Validate audit configuration for sensitive operations
    if (spec.category === 'database' && spec.audit.severity === 'low') {
      this.logger.warn('Database operations should have higher audit severity', {
        capabilityId: spec.id,
      });
    }
  }

  private validateSQLOperationSpec(sqlOp: any): void {
    // Prevent dangerous SQL operations
    if (sqlOp.type === 'delete' && !sqlOp.whereClause) {
      throw new CapabilityValidationError(
        'DELETE operations must specify WHERE clause constraints',
        'sqlOperation',
        'UNSAFE_DELETE'
      );
    }

    if (sqlOp.type === 'update' && !sqlOp.whereClause) {
      throw new CapabilityValidationError(
        'UPDATE operations must specify WHERE clause constraints',
        'sqlOperation',
        'UNSAFE_UPDATE'
      );
    }

    // Validate allowed columns
    if (sqlOp.allowedColumns) {
      for (const column of sqlOp.allowedColumns) {
        if (!BuiltInValidators.validateSQLIdentifier(column)) {
          throw new CapabilityValidationError(
            `Invalid column name: ${column}`,
            'allowedColumns',
            'INVALID_COLUMN_NAME'
          );
        }
      }
    }

    // Validate table name
    if (sqlOp.table && !BuiltInValidators.validateSQLIdentifier(sqlOp.table)) {
      throw new CapabilityValidationError(
        `Invalid table name: ${sqlOp.table}`,
        'table',
        'INVALID_TABLE_NAME'
      );
    }
  }

  private validateExecutionLimits(parameters: Record<string, unknown>): void {
    const parameterCount = Object.keys(parameters).length;
    if (parameterCount > EXECUTION_LIMITS.MAX_PARAMETERS) {
      throw new CapabilityValidationError(
        `Too many parameters: ${parameterCount} (max: ${EXECUTION_LIMITS.MAX_PARAMETERS})`,
        'parameters',
        'TOO_MANY_PARAMETERS'
      );
    }

    // Check parameter size
    const parametersSize = JSON.stringify(parameters).length;
    if (parametersSize > EXECUTION_LIMITS.MAX_PARAMETER_SIZE_BYTES) {
      throw new CapabilityValidationError(
        `Parameters too large: ${parametersSize} bytes (max: ${EXECUTION_LIMITS.MAX_PARAMETER_SIZE_BYTES})`,
        'parameters',
        'PARAMETERS_TOO_LARGE'
      );
    }
  }

  private async validateParameter(
    paramSpec: ParameterSpec,
    value: unknown,
    context: CapabilityExecutionContext
  ): Promise<unknown> {
    // Check required parameters
    if (paramSpec.validation.required && (value === undefined || value === null)) {
      throw new CapabilityValidationError(
        `Required parameter '${paramSpec.name}' is missing`,
        paramSpec.name,
        'MISSING_REQUIRED_PARAMETER'
      );
    }

    // Skip validation for optional parameters that are not provided
    if (!paramSpec.validation.required && (value === undefined || value === null)) {
      return value;
    }

    // Type validation and conversion
    const typedValue = this.validateAndConvertType(paramSpec, value);

    // Validation rules
    await this.validateParameterRules(paramSpec, typedValue);

    // Custom validation
    if (paramSpec.validation.customValidator) {
      const validator = this.customValidators.get(paramSpec.validation.customValidator);
      if (!validator) {
        throw new CapabilityValidationError(
          `Custom validator '${paramSpec.validation.customValidator}' not found`,
          paramSpec.name,
          'VALIDATOR_NOT_FOUND'
        );
      }

      if (!validator(typedValue)) {
        throw new CapabilityValidationError(
          `Custom validation failed for parameter '${paramSpec.name}'`,
          paramSpec.name,
          'CUSTOM_VALIDATION_FAILED',
          typedValue
        );
      }
    }

    // Security validation for sensitive parameters
    if (paramSpec.sensitive) {
      await this.validateSensitiveParameter(paramSpec, typedValue, context);
    }

    return typedValue;
  }

  private validateAndConvertType(paramSpec: ParameterSpec, value: unknown): unknown {
    switch (paramSpec.type) {
      case 'string':
        if (typeof value !== 'string') {
          throw new CapabilityValidationError(
            `Parameter '${paramSpec.name}' must be a string`,
            paramSpec.name,
            'INVALID_TYPE',
            value
          );
        }
        return value;

      case 'number':
        const num = Number(value);
        if (!Number.isFinite(num)) {
          throw new CapabilityValidationError(
            `Parameter '${paramSpec.name}' must be a valid number`,
            paramSpec.name,
            'INVALID_NUMBER',
            value
          );
        }
        return num;

      case 'boolean':
        if (typeof value === 'boolean') return value;
        if (typeof value === 'string') {
          const lower = value.toLowerCase();
          if (lower === 'true') return true;
          if (lower === 'false') return false;
        }
        throw new CapabilityValidationError(
          `Parameter '${paramSpec.name}' must be a boolean`,
          paramSpec.name,
          'INVALID_BOOLEAN',
          value
        );

      case 'date':
        const date = new Date(value as string);
        if (isNaN(date.getTime())) {
          throw new CapabilityValidationError(
            `Parameter '${paramSpec.name}' must be a valid date`,
            paramSpec.name,
            'INVALID_DATE',
            value
          );
        }
        return date.toISOString();

      case 'email':
        if (typeof value !== 'string' || !BuiltInValidators.validateEmail(value)) {
          throw new CapabilityValidationError(
            `Parameter '${paramSpec.name}' must be a valid email address`,
            paramSpec.name,
            'INVALID_EMAIL',
            value
          );
        }
        return value.toLowerCase();

      case 'currency':
        const currency = Number(value);
        if (!BuiltInValidators.validateCurrency(currency)) {
          throw new CapabilityValidationError(
            `Parameter '${paramSpec.name}' must be a valid currency amount`,
            paramSpec.name,
            'INVALID_CURRENCY',
            value
          );
        }
        return Math.round(currency * 100) / 100; // Round to 2 decimal places

      case 'percentage':
        const percentage = Number(value);
        if (!BuiltInValidators.validatePercentage(percentage)) {
          throw new CapabilityValidationError(
            `Parameter '${paramSpec.name}' must be a valid percentage (0-100)`,
            paramSpec.name,
            'INVALID_PERCENTAGE',
            value
          );
        }
        return percentage;

      case 'enum':
        if (!paramSpec.validation.enum?.includes(String(value))) {
          throw new CapabilityValidationError(
            `Parameter '${paramSpec.name}' must be one of: ${paramSpec.validation.enum?.join(', ')}`,
            paramSpec.name,
            'INVALID_ENUM_VALUE',
            value
          );
        }
        return String(value);

      case 'array':
        if (!Array.isArray(value)) {
          throw new CapabilityValidationError(
            `Parameter '${paramSpec.name}' must be an array`,
            paramSpec.name,
            'INVALID_ARRAY',
            value
          );
        }
        return value;

      case 'object':
        if (typeof value !== 'object' || value === null || Array.isArray(value)) {
          throw new CapabilityValidationError(
            `Parameter '${paramSpec.name}' must be an object`,
            paramSpec.name,
            'INVALID_OBJECT',
            value
          );
        }
        return value;

      case 'json':
        try {
          return typeof value === 'string' ? JSON.parse(value) : value;
        } catch {
          throw new CapabilityValidationError(
            `Parameter '${paramSpec.name}' must be valid JSON`,
            paramSpec.name,
            'INVALID_JSON',
            value
          );
        }

      default:
        return value;
    }
  }

  private async validateParameterRules(paramSpec: ParameterSpec, value: unknown): Promise<void> {
    const validation = paramSpec.validation;

    // String length validation
    if (typeof value === 'string') {
      if (validation.minLength !== undefined && value.length < validation.minLength) {
        throw new CapabilityValidationError(
          `Parameter '${paramSpec.name}' must be at least ${validation.minLength} characters`,
          paramSpec.name,
          'MIN_LENGTH_VIOLATION',
          value
        );
      }

      if (validation.maxLength !== undefined && value.length > validation.maxLength) {
        throw new CapabilityValidationError(
          `Parameter '${paramSpec.name}' must be at most ${validation.maxLength} characters`,
          paramSpec.name,
          'MAX_LENGTH_VIOLATION',
          value
        );
      }

      // Pattern validation
      if (validation.pattern) {
        const regex = new RegExp(validation.pattern);
        if (!regex.test(value)) {
          throw new CapabilityValidationError(
            `Parameter '${paramSpec.name}' does not match required pattern`,
            paramSpec.name,
            'PATTERN_MISMATCH',
            value
          );
        }
      }

      // SQL injection prevention
      if (!BuiltInValidators.validateNoSQLInjection(value)) {
        throw new CapabilityValidationError(
          `Parameter '${paramSpec.name}' contains potentially dangerous SQL patterns`,
          paramSpec.name,
          'SQL_INJECTION_DETECTED',
          value
        );
      }
    }

    // Numeric range validation
    if (typeof value === 'number') {
      if (validation.min !== undefined && value < validation.min) {
        throw new CapabilityValidationError(
          `Parameter '${paramSpec.name}' must be at least ${validation.min}`,
          paramSpec.name,
          'MIN_VALUE_VIOLATION',
          value
        );
      }

      if (validation.max !== undefined && value > validation.max) {
        throw new CapabilityValidationError(
          `Parameter '${paramSpec.name}' must be at most ${validation.max}`,
          paramSpec.name,
          'MAX_VALUE_VIOLATION',
          value
        );
      }
    }

    // Format validation
    if (validation.format && typeof value === 'string') {
      switch (validation.format) {
        case 'email':
          if (!BuiltInValidators.validateEmail(value)) {
            throw new CapabilityValidationError(
              `Parameter '${paramSpec.name}' must be a valid email address`,
              paramSpec.name,
              'INVALID_EMAIL_FORMAT',
              value
            );
          }
          break;

        case 'url':
          if (!BuiltInValidators.validateURL(value)) {
            throw new CapabilityValidationError(
              `Parameter '${paramSpec.name}' must be a valid URL`,
              paramSpec.name,
              'INVALID_URL_FORMAT',
              value
            );
          }
          break;

        case 'uuid':
          if (!BuiltInValidators.validateUUID(value)) {
            throw new CapabilityValidationError(
              `Parameter '${paramSpec.name}' must be a valid UUID`,
              paramSpec.name,
              'INVALID_UUID_FORMAT',
              value
            );
          }
          break;

        case 'iso8601':
          if (!BuiltInValidators.validateISO8601(value)) {
            throw new CapabilityValidationError(
              `Parameter '${paramSpec.name}' must be a valid ISO 8601 date`,
              paramSpec.name,
              'INVALID_DATE_FORMAT',
              value
            );
          }
          break;
      }
    }
  }

  private async validateSensitiveParameter(
    paramSpec: ParameterSpec,
    value: unknown,
    context: CapabilityExecutionContext
  ): Promise<void> {
    // Additional security checks for sensitive data
    if (typeof value === 'string') {
      // Check for common PII patterns
      const piiPatterns = [
        /\b\d{3}-\d{2}-\d{4}\b/, // SSN pattern
        /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/, // Credit card pattern
      ];

      for (const pattern of piiPatterns) {
        if (pattern.test(value)) {
          this.logger.warn('Potential PII detected in sensitive parameter', {
            parameterName: paramSpec.name,
            correlationId: context.correlationId,
          });
          break;
        }
      }
    }
  }

  private validateSQLParameters(
    spec: CapabilitySpec,
    parameters: Record<string, unknown>
  ): void {
    const sqlOp = spec.sqlOperation!;

    // Validate table name parameter if dynamic
    if (parameters.tableName) {
      const tableName = String(parameters.tableName);
      if (!BuiltInValidators.validateSQLIdentifier(tableName)) {
        throw new CapabilityValidationError(
          'Invalid table name',
          'tableName',
          'INVALID_SQL_IDENTIFIER',
          tableName
        );
      }
    }

    // Validate column parameters
    for (const [key, value] of Object.entries(parameters)) {
      if (key.endsWith('Column') || key.endsWith('Field')) {
        const columnName = String(value);
        if (!BuiltInValidators.validateSQLIdentifier(columnName)) {
          throw new CapabilityValidationError(
            `Invalid column name in parameter '${key}'`,
            key,
            'INVALID_SQL_IDENTIFIER',
            columnName
          );
        }

        // Check against allowed columns
        if (sqlOp.allowedColumns && !sqlOp.allowedColumns.includes(columnName)) {
          throw new CapabilityValidationError(
            `Column '${columnName}' is not in allowed columns list`,
            key,
            'COLUMN_NOT_ALLOWED',
            columnName
          );
        }
      }
    }

    // Validate WHERE clause parameters
    if (sqlOp.whereClause) {
      for (const [key, value] of Object.entries(parameters)) {
        if (key.startsWith('where') && typeof value === 'string') {
          if (!BuiltInValidators.validateNoSQLInjection(value)) {
            throw new CapabilityValidationError(
              `WHERE clause parameter contains dangerous SQL patterns`,
              key,
              'SQL_INJECTION_IN_WHERE',
              value
            );
          }
        }
      }
    }
  }

  private validateResultType(returnTypeSpec: any, result: unknown): unknown {
    // Basic type validation for return values
    switch (returnTypeSpec.type) {
      case 'array':
        if (!Array.isArray(result)) {
          throw new CapabilityValidationError(
            'Result must be an array',
            'result',
            'INVALID_RESULT_TYPE',
            result
          );
        }
        break;

      case 'object':
        if (typeof result !== 'object' || result === null || Array.isArray(result)) {
          throw new CapabilityValidationError(
            'Result must be an object',
            'result',
            'INVALID_RESULT_TYPE',
            result
          );
        }
        break;

      case 'string':
        if (typeof result !== 'string') {
          throw new CapabilityValidationError(
            'Result must be a string',
            'result',
            'INVALID_RESULT_TYPE',
            result
          );
        }
        break;

      case 'number':
        if (typeof result !== 'number' || !Number.isFinite(result)) {
          throw new CapabilityValidationError(
            'Result must be a valid number',
            'result',
            'INVALID_RESULT_TYPE',
            result
          );
        }
        break;

      case 'boolean':
        if (typeof result !== 'boolean') {
          throw new CapabilityValidationError(
            'Result must be a boolean',
            'result',
            'INVALID_RESULT_TYPE',
            result
          );
        }
        break;
    }

    return result;
  }

  private validateResultSize(result: unknown): void {
    const resultSize = JSON.stringify(result).length;
    if (resultSize > EXECUTION_LIMITS.MAX_RESULT_SIZE_BYTES) {
      throw new CapabilityValidationError(
        `Result too large: ${resultSize} bytes (max: ${EXECUTION_LIMITS.MAX_RESULT_SIZE_BYTES})`,
        'result',
        'RESULT_TOO_LARGE',
        resultSize
      );
    }
  }

  private redactSensitiveData(spec: CapabilitySpec, result: unknown): unknown {
    if (!spec.audit.sensitiveDataHandling.redactResults) {
      return result;
    }

    // Simple redaction for demonstration
    // In production, use more sophisticated redaction based on data patterns
    return PIIRedactor.redactSensitiveData(result);
  }

  private async runCrossParameterValidation(
    validatorName: string,
    parameters: Record<string, unknown>,
    context: CapabilityExecutionContext
  ): Promise<void> {
    const validator = this.customValidators.get(validatorName);
    if (!validator) {
      throw new CapabilityValidationError(
        `Cross-parameter validator '${validatorName}' not found`,
        'cross_validation',
        'VALIDATOR_NOT_FOUND'
      );
    }

    if (!validator(parameters)) {
      throw new CapabilityValidationError(
        'Cross-parameter validation failed',
        'cross_validation',
        'CROSS_VALIDATION_FAILED',
        parameters
      );
    }
  }

  private async runCustomValidation(
    validatorName: string,
    data: Record<string, unknown>,
    context: CapabilityExecutionContext
  ): Promise<void> {
    const validator = this.customValidators.get(validatorName);
    if (!validator) {
      this.logger.warn('Custom validator not found', {
        validatorName,
        correlationId: context.correlationId,
      });
      return;
    }

    if (!validator(data)) {
      throw new CapabilityValidationError(
        `Custom validation '${validatorName}' failed`,
        'custom_validation',
        'CUSTOM_VALIDATION_FAILED',
        data
      );
    }
  }
}