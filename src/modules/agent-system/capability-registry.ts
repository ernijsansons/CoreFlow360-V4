/**
 * Capability Contract System
 * Manages capability definitions and agent compatibility
 */

import {
  CapabilityContract,
  CapabilityExample,
  JSONSchema,
  AgentTask,
  ValidationResult,
  CapabilityContractSchema,
  DEPARTMENT_CAPABILITIES
} from './types';
import { Logger } from '../../shared/logger';

export class CapabilityRegistry {
  private logger: Logger;
  private contracts = new Map<string, CapabilityContract>();
  private agentCapabilities = new Map<string, Set<string>>(); // agentId -> capabilities

  constructor() {
    this.logger = new Logger();
    this.initializeBuiltInCapabilities();
  }

  /**
   * Register a capability contract
   */
  register(contract: CapabilityContract): void {
    try {
      // Validate the contract
      CapabilityContractSchema.parse(contract);

      // Validate schema objects
      this.validateJSONSchema(contract.inputSchema);
      this.validateJSONSchema(contract.outputSchema);

      // Check for conflicts with existing contracts
      const existing = this.contracts.get(contract.name);
      if (existing && existing.version !== contract.version) {
        this.logger.warn('Capability contract version conflict', {
          capability: contract.name,
          existingVersion: existing.version,
          newVersion: contract.version,
        });
      }

      // Store the contract
      this.contracts.set(contract.name, contract);

      // Update agent capability mappings
      for (const agentId of contract.supportedAgents) {
        if (!this.agentCapabilities.has(agentId)) {
          this.agentCapabilities.set(agentId, new Set());
        }
        this.agentCapabilities.get(agentId)!.add(contract.name);
      }

      this.logger.info('Capability contract registered', {
        capability: contract.name,
        version: contract.version,
        category: contract.category,
        supportedAgents: contract.supportedAgents.length,
      });

    } catch (error) {
      this.logger.error('Failed to register capability contract', error, {
        capability: contract.name,
      });
      throw error;
    }
  }

  /**
   * Get capability contract by name
   */
  getContract(capability: string): CapabilityContract | undefined {
    return this.contracts.get(capability);
  }

  /**
   * Get all capability contracts
   */
  getAllContracts(): CapabilityContract[] {
    return Array.from(this.contracts.values());
  }

  /**
   * Get capabilities by category
   */
  getCapabilitiesByCategory(category: string): CapabilityContract[] {
    return Array.from(this.contracts.values())
      .filter(contract => contract.category === category);
  }

  /**
   * Get agents that support a capability
   */
  getAgentsForCapability(capability: string): string[] {
    const contract = this.contracts.get(capability);
    return contract?.supportedAgents || ['claude-native']; // Fallback to Claude
  }

  /**
   * Get capabilities supported by an agent
   */
  getCapabilitiesForAgent(agentId: string): string[] {
    const capabilities = this.agentCapabilities.get(agentId);
    return capabilities ? Array.from(capabilities) : [];
  }

  /**
   * Validate task input against capability contract
   */
  validateTaskInput(task: AgentTask): ValidationResult {
    const contract = this.contracts.get(task.capability);
    if (!contract) {
      // If no contract exists, allow the task to proceed
      return {
        valid: true,
        warnings: [`No capability contract found for '${task.capability}'`],
      };
    }

    try {
      const validation = this.validateAgainstSchema(task.input, contract.inputSchema);

      if (!validation.valid) {
        return {
          valid: false,
          errors: validation.errors,
          warnings: validation.warnings,
        };
      }

      // Additional business logic validation
      const businessValidation = this.validateBusinessLogic(task, contract);

      return {
        valid: businessValidation.valid,
        errors: businessValidation.errors,
        warnings: [...(validation.warnings || []), ...(businessValidation.warnings || [])],
        sanitizedInput: validation.sanitizedInput,
      };

    } catch (error) {
      return {
        valid: false,
        errors: [`Validation error: ${error instanceof Error ? error.message : 'Unknown error'}`],
      };
    }
  }

  /**
   * Validate task output against capability contract
   */
  validateTaskOutput(result: unknown, capability: string): ValidationResult {
    const contract = this.contracts.get(capability);
    if (!contract) {
      return { valid: true, warnings: [`No capability contract found for '${capability}'`] };
    }

    return this.validateAgainstSchema(result, contract.outputSchema);
  }

  /**
   * Get capability documentation
   */
  getCapabilityDocumentation(capability: string): string | null {
    const contract = this.contracts.get(capability);
    if (!contract) return null;

    return this.generateDocumentation(contract);
  }

  /**
   * Search capabilities by name, description, or tags
   */
  searchCapabilities(query: string): CapabilityContract[] {
    const queryLower = query.toLowerCase();

    return Array.from(this.contracts.values()).filter(contract => {
      return contract.name.toLowerCase().includes(queryLower) ||
             contract.description.toLowerCase().includes(queryLower) ||
             contract.category.toLowerCase().includes(queryLower);
    });
  }

  /**
   * Get capability suggestions based on input
   */
  suggestCapabilities(input: unknown, limit: number = 5): Array<{
    capability: string;
    confidence: number;
    reason: string;
  }> {
    const suggestions: Array<{ capability: string; confidence: number; reason: string }> = [];

    const inputText = typeof input === 'string' ? input : JSON.stringify(input);
    const inputLower = inputText.toLowerCase();

    for (const contract of this.contracts.values()) {
      let confidence = 0;
      const reasons: string[] = [];

      // Check name match
      if (inputLower.includes(contract.name.toLowerCase())) {
        confidence += 0.4;
        reasons.push('name match');
      }

      // Check description keywords
      const descWords = contract.description.toLowerCase().split(/\s+/);
      const matchingWords = descWords.filter(word =>
        word.length > 3 && inputLower.includes(word)
      );
      if (matchingWords.length > 0) {
        confidence += (matchingWords.length / descWords.length) * 0.3;
        reasons.push(`description keywords: ${matchingWords.slice(0, 3).join(', ')}`);
      }

      // Check category match
      if (inputLower.includes(contract.category.toLowerCase())) {
        confidence += 0.2;
        reasons.push('category match');
      }

      // Check examples
      for (const example of contract.examples) {
        const exampleInput = typeof example.input === 'string'
          ? example.input
          : JSON.stringify(example.input);

        if (this.calculateSimilarity(inputText, exampleInput) > 0.7) {
          confidence += 0.3;
          reasons.push(`similar to example: ${example.name}`);
          break;
        }
      }

      if (confidence > 0.1) {
        suggestions.push({
          capability: contract.name,
          confidence: Math.min(confidence, 1.0),
          reason: reasons.join(', '),
        });
      }
    }

    return suggestions
      .sort((a, b) => b.confidence - a.confidence)
      .slice(0, limit);
  }

  /**
   * Get capability metrics
   */
  getCapabilityMetrics(capability: string): {
    totalAgents: number;
    averageCost: number;
    averageLatency: number;
    examples: number;
    deprecated: boolean;
  } | null {
    const contract = this.contracts.get(capability);
    if (!contract) return null;

    return {
      totalAgents: contract.supportedAgents.length,
      averageCost: contract.estimatedCost,
      averageLatency: contract.estimatedLatency,
      examples: contract.examples.length,
      deprecated: contract.deprecated || false,
    };
  }

  /**
   * Remove a capability contract
   */
  removeContract(capability: string): boolean {
    const contract = this.contracts.get(capability);
    if (!contract) return false;

    // Remove from agent mappings
    for (const agentId of contract.supportedAgents) {
      const agentCaps = this.agentCapabilities.get(agentId);
      if (agentCaps) {
        agentCaps.delete(capability);
        if (agentCaps.size === 0) {
          this.agentCapabilities.delete(agentId);
        }
      }
    }

    // Remove the contract
    this.contracts.delete(capability);

    this.logger.info('Capability contract removed', { capability });
    return true;
  }

  /**
   * Update agent capabilities
   */
  updateAgentCapabilities(agentId: string, capabilities: string[]): void {
    // Remove agent from all existing mappings
    for (const [capName, agentSet] of this.agentCapabilities.entries()) {
      agentSet.delete(agentId);
      if (agentSet.size === 0) {
        this.agentCapabilities.delete(capName);
      }
    }

    // Update contract mappings
    for (const contract of this.contracts.values()) {
      const index = contract.supportedAgents.indexOf(agentId);
      if (capabilities.includes(contract.name)) {
        // Add agent to contract if not already there
        if (index === -1) {
          contract.supportedAgents.push(agentId);
        }
      } else {
        // Remove agent from contract if present
        if (index > -1) {
          contract.supportedAgents.splice(index, 1);
        }
      }
    }

    // Set new capabilities for agent
    this.agentCapabilities.set(agentId, new Set(capabilities));

    this.logger.debug('Agent capabilities updated', {
      agentId,
      capabilities: capabilities.length,
    });
  }

  /**
   * Private helper methods
   */

  private validateJSONSchema(schema: JSONSchema): void {
    if (!schema.type) {
      throw new Error('JSON Schema must have a type');
    }

    // Basic schema validation
    const validTypes = ['string', 'number', 'integer', 'boolean', 'array', 'object', 'null'];
    if (!validTypes.includes(schema.type)) {
      throw new Error(`Invalid schema type: ${schema.type}`);
    }

    // Validate properties for object type
    if (schema.type === 'object' && schema.properties) {
      for (const [key, propSchema] of Object.entries(schema.properties)) {
        if (typeof propSchema === 'object') {
          this.validateJSONSchema(propSchema);
        }
      }
    }

    // Validate items for array type
    if (schema.type === 'array' && schema.items) {
      this.validateJSONSchema(schema.items);
    }
  }

  private validateAgainstSchema(data: unknown, schema: JSONSchema): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      const validated = this.validateValue(data, schema, '');

      if (validated.errors.length > 0) {
        return {
          valid: false,
          errors: validated.errors,
          warnings: validated.warnings,
        };
      }

      return {
        valid: true,
        warnings: validated.warnings.length > 0 ? validated.warnings : undefined,
        sanitizedInput: validated.value,
      };

    } catch (error) {
      return {
        valid: false,
        errors: [`Schema validation error: ${error instanceof Error ? error.message : 'Unknown error'}`],
      };
    }
  }

  private validateValue(value: unknown, schema: JSONSchema, path: string): {
    value: unknown;
    errors: string[];
    warnings: string[];
  } {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Type validation
    if (!this.isCorrectType(value, schema.type)) {
      errors.push(`${path || 'root'}: Expected ${schema.type}, got ${typeof value}`);
      return { value, errors, warnings };
    }

    // Additional validations based on type
    switch (schema.type) {
      case 'string':
        if (typeof value === 'string') {
          if (schema.pattern && !new RegExp(schema.pattern).test(value)) {
            errors.push(`${path || 'root'}: String does not match pattern ${schema.pattern}`);
          }
          if (schema.minimum && value.length < schema.minimum) {
            errors.push(`${path || 'root'}: String length ${value.length} is below minimum ${schema.minimum}`);
          }
          if (schema.maximum && value.length > schema.maximum) {
            warnings.push(`${path || 'root'}: String length ${value.length} exceeds maximum ${schema.maximum}`);
          }
        }
        break;

      case 'number':
      case 'integer':
        if (typeof value === 'number') {
          if (schema.minimum !== undefined && value < schema.minimum) {
            errors.push(`${path || 'root'}: Value ${value} is below minimum ${schema.minimum}`);
          }
          if (schema.maximum !== undefined && value > schema.maximum) {
            errors.push(`${path || 'root'}: Value ${value} exceeds maximum ${schema.maximum}`);
          }
          if (schema.type === 'integer' && !Number.isInteger(value)) {
            errors.push(`${path || 'root'}: Expected integer, got ${value}`);
          }
        }
        break;

      case 'array':
        if (Array.isArray(value) && schema.items) {
          const validatedItems = value.map((item, index) => {
            const itemResult = this.validateValue(item, schema.items!, `${path}[${index}]`);
            errors.push(...itemResult.errors);
            warnings.push(...itemResult.warnings);
            return itemResult.value;
          });
          value = validatedItems;
        }
        break;

      case 'object':
        if (typeof value === 'object' && value !== null && schema.properties) {
          const obj = value as Record<string, unknown>;
          const validatedObj: Record<string, unknown> = {};

          // Check required properties
          if (schema.required) {
            for (const requiredProp of schema.required) {
              if (!(requiredProp in obj)) {
                errors.push(`${path || 'root'}: Missing required property '${requiredProp}'`);
              }
            }
          }

          // Validate existing properties
          for (const [key, propValue] of Object.entries(obj)) {
            const propSchema = schema.properties[key];
            if (propSchema) {
              const propResult = this.validateValue(propValue, propSchema, `${path}.${key}`);
              errors.push(...propResult.errors);
              warnings.push(...propResult.warnings);
              validatedObj[key] = propResult.value;
            } else {
              warnings.push(`${path || 'root'}: Unknown property '${key}'`);
              validatedObj[key] = propValue;
            }
          }

          value = validatedObj;
        }
        break;
    }

    return { value, errors, warnings };
  }

  private isCorrectType(value: unknown, expectedType: string): boolean {
    switch (expectedType) {
      case 'string':
        return typeof value === 'string';
      case 'number':
        return typeof value === 'number';
      case 'integer':
        return typeof value === 'number' && Number.isInteger(value);
      case 'boolean':
        return typeof value === 'boolean';
      case 'array':
        return Array.isArray(value);
      case 'object':
        return typeof value === 'object' && value !== null && !Array.isArray(value);
      case 'null':
        return value === null;
      default:
        return false;
    }
  }

  private validateBusinessLogic(task: AgentTask, contract: CapabilityContract): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Check permissions
    if (contract.requiredPermissions.length > 0) {
      const userPermissions = task.context.permissions || [];
      const missingPermissions = contract.requiredPermissions.filter(
        perm => !userPermissions.includes(perm)
      );

      if (missingPermissions.length > 0) {
        errors.push(`Missing required permissions: ${missingPermissions.join(', ')}`);
      }
    }

    // Check cost constraints
    if (task.constraints?.maxCost !== undefined && contract.estimatedCost > task.constraints.maxCost) {
      errors.push(`Estimated cost (${contract.estimatedCost}) exceeds maximum allowed (${task.constraints.maxCost})`);
    }

    // Check latency constraints
    if (task.constraints?.maxLatency !== undefined && contract.estimatedLatency > task.constraints.maxLatency) {
      warnings.push(`Estimated
  latency (${contract.estimatedLatency}ms) may exceed maximum allowed (${task.constraints.maxLatency}ms)`);
    }

    // Check if capability is deprecated
    if (contract.deprecated) {
      warnings.push(`Capability '${contract.name}' is deprecated`);
      if (contract.replacedBy) {
        warnings.push(`Consider using '${contract.replacedBy}' instead`);
      }
    }

    return {
      valid: errors.length === 0,
      errors: errors.length > 0 ? errors : undefined,
      warnings: warnings.length > 0 ? warnings : undefined,
    };
  }

  private calculateSimilarity(text1: string, text2: string): number {
    // Simple Jaccard similarity
    const words1 = new Set(text1.toLowerCase().split(/\s+/));
    const words2 = new Set(text2.toLowerCase().split(/\s+/));

    const intersection = new Set([...words1].filter(word => words2.has(word)));
    const union = new Set([...words1, ...words2]);

    return union.size > 0 ? intersection.size / union.size : 0;
  }

  private generateDocumentation(contract: CapabilityContract): string {
    const sections = [
      `# ${contract.name}`,
      '',
      `**Version:** ${contract.version}`,
      `**Category:** ${contract.category}`,
      '',
      '## Description',
      contract.description,
      '',
      '## Input Schema',
      '```json',
      JSON.stringify(contract.inputSchema, null, 2),
      '```',
      '',
      '## Output Schema',
      '```json',
      JSON.stringify(contract.outputSchema, null, 2),
      '```',
      '',
      '## Required Permissions',
      ...contract.requiredPermissions.map(perm => `- ${perm}`),
      '',
      '## Supported Agents',
      ...contract.supportedAgents.map(agent => `- ${agent}`),
      '',
      '## Cost & Performance',
      `- Estimated latency: ${contract.estimatedLatency}ms`,
      `- Estimated cost: $${contract.estimatedCost}`,
      '',
      '## Examples',
      ...contract.examples.map(example => [
        `### ${example.name}`,
        example.description,
        '**Input:**',
        '```json',
        JSON.stringify(example.input, null, 2),
        '```',
        '**Expected Output:**',
        '```json',
        JSON.stringify(example.expectedOutput, null, 2),
        '```',
        ''
      ]).flat(),
    ];

    if (contract.deprecated) {
      sections.unshift('> **⚠️ DEPRECATED:** This capability is deprecated.');
      if (contract.replacedBy) {
        sections.unshift(`> Please use \`${contract.replacedBy}\` instead.`);
      }
      sections.unshift('');
    }

    return sections.join('\n');
  }

  private initializeBuiltInCapabilities(): void {
    // Initialize capabilities for each department
    for (const [department, capabilities] of Object.entries(DEPARTMENT_CAPABILITIES)) {
      for (const capability of capabilities) {
        const contract = this.createDefaultContract(capability, department);
        this.contracts.set(capability, contract);
      }
    }

    // Add wildcard capability for general-purpose agents
    const wildcardContract: CapabilityContract = {
      name: '*',
      description: 'Universal capability that can handle any task',
      version: '1.0.0',
      category: 'general',
      inputSchema: {
        type: 'object',
        properties: {
          prompt: { type: 'string' },
          content: { type: 'string' },
          message: { type: 'string' },
        },
      },
      outputSchema: {
        type: 'object',
        properties: {
          response: { type: 'string' },
          data: { type: 'object' },
        },
      },
      requiredPermissions: [],
      supportedAgents: ['claude-native'],
      estimatedLatency: 2000,
      estimatedCost: 0.002,
      examples: [{
        name: 'General Query',
        description: 'Handle any general query or task',
        input: { prompt: 'Help me with this task' },
        expectedOutput: { response: 'I can help you with that task.' },
      }],
      documentation: 'Universal capability for handling any type of task',
    };

    this.contracts.set('*', wildcardContract);
  }

  private createDefaultContract(capability: string, department: string): CapabilityContract {
    return {
      name: capability,
      description: `${capability.replace(/[._]/g, ' ')} capability for ${department} department`,
      version: '1.0.0',
      category: department,
      inputSchema: {
        type: 'object',
        properties: {
          prompt: { type: 'string' },
          data: { type: 'object' },
        },
        required: ['prompt'],
      },
      outputSchema: {
        type: 'object',
        properties: {
          result: { type: 'object' },
          summary: { type: 'string' },
          recommendations: { type: 'array', items: { type: 'string' } },
        },
      },
      requiredPermissions: [`${department}:${capability}`],
      supportedAgents: ['claude-native'],
      estimatedLatency: 3000,
      estimatedCost: 0.005,
      examples: [{
        name: `${capability} Example`,
        description: `Example usage of ${capability}`,
        input: { prompt: `Perform ${capability}` },
        expectedOutput: { result: {}, summary: 'Task completed successfully' },
      }],
      documentation: `Perform ${capability} operations for the ${department} department`,
    };
  }
}