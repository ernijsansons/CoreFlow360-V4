/**
 * AI-Powered Workflow Generator
 * Natural language to workflow conversion with intelligent templates
 */
import type { Env } from '../types/env';
import { getAIClient } from './secure-ai-client';
import { validateInput } from '../utils/validation-schemas';
import { z } from 'zod';

// =====================================================
// TYPES AND INTERFACES
// =====================================================

export interface WorkflowGenerationRequest {
  description: string;
  businessContext: BusinessContext;
  constraints?: WorkflowConstraints;
  templatePreferences?: TemplatePreferences;
  advancedOptions?: AdvancedOptions;
}

export interface BusinessContext {
  industry: string;
  companySize: 'startup' | 'small' | 'medium' | 'large' | 'enterprise';
  department: string;
  useCase: string;
  existingTools: string[];
  businessRules: string[];
  complianceRequirements: string[];
  budgetConstraints?: {
    maxCostPerExecution: number;
    maxMonthlyBudget: number;
  };
}

export interface WorkflowConstraints {
  maxNodes: number;
  maxExecutionTime: number;
  maxCostPerExecution: number;
  requiredIntegrations: string[];
  forbiddenIntegrations: string[];
  securityLevel: 'standard' | 'high' | 'critical';
  complianceStandards: string[];
}

export interface TemplatePreferences {
  preferredNodeTypes: string[];
  aiModelPreferences: string[];
  integrationPriorities: string[];
  approvalRequirements: boolean;
  errorHandlingLevel: 'basic' | 'standard' | 'comprehensive';
}

export interface AdvancedOptions {
  customTemplates?: string[];
  experimentalFeatures?: string[];
  optimizationLevel: 'basic' | 'standard' | 'advanced';
  testingMode: boolean;
  debugOutput: boolean;
}

export interface WorkflowNode {
  id: string;
  type: 'trigger' | 'action' | 'condition' | 'loop' | 'ai' | 'integration' | 'approval' | 'notification' | 'data' | 'custom';
  name: string;
  description: string;
  position: { x: number; y: number };
  configuration: Record<string, any>;
  inputs: NodeInput[];
  outputs: NodeOutput[];
  dependencies: string[];
  errorHandling: ErrorHandlingConfig;
  performance: PerformanceConfig;
  security: SecurityConfig;
}

export interface NodeInput {
  id: string;
  name: string;
  type: 'string' | 'number' | 'boolean' | 'object' | 'array' | 'file' | 'json';
  required: boolean;
  description: string;
  validation: ValidationConfig;
  defaultValue?: any;
}

export interface NodeOutput {
  id: string;
  name: string;
  type: 'string' | 'number' | 'boolean' | 'object' | 'array' | 'file' | 'json';
  description: string;
  schema?: any;
}

export interface ErrorHandlingConfig {
  strategy: 'retry' | 'skip' | 'fail' | 'custom';
  maxRetries: number;
  retryDelay: number;
  fallbackAction?: string;
  customHandler?: string;
}

export interface PerformanceConfig {
  timeout: number;
  maxConcurrency: number;
  caching: boolean;
  optimization: 'none' | 'basic' | 'advanced';
}

export interface SecurityConfig {
  authentication: boolean;
  authorization: string[];
  encryption: boolean;
  auditLogging: boolean;
  dataPrivacy: 'standard' | 'high' | 'critical';
}

export interface ValidationConfig {
  required: boolean;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  min?: number;
  max?: number;
  custom?: string;
}

export interface WorkflowEdge {
  id: string;
  source: string;
  target: string;
  condition?: string;
  label?: string;
  type: 'success' | 'error' | 'conditional' | 'loop';
}

export interface GeneratedWorkflow {
  id: string;
  name: string;
  description: string;
  version: string;
  nodes: WorkflowNode[];
  edges: WorkflowEdge[];
  metadata: WorkflowMetadata;
  validation: WorkflowValidation;
  testing: WorkflowTesting;
  deployment: WorkflowDeployment;
}

export interface WorkflowMetadata {
  createdAt: Date;
  updatedAt: Date;
  createdBy: string;
  businessId: string;
  tags: string[];
  category: string;
  complexity: 'low' | 'medium' | 'high';
  estimatedCost: number;
  estimatedExecutionTime: number;
  successRate: number;
  maintenanceLevel: 'low' | 'medium' | 'high';
}

export interface WorkflowValidation {
  isValid: boolean;
  errors: ValidationError[];
  warnings: ValidationWarning[];
  suggestions: ValidationSuggestion[];
}

export interface ValidationError {
  type: 'syntax' | 'logic' | 'security' | 'performance' | 'compliance';
  message: string;
  nodeId?: string;
  edgeId?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface ValidationWarning {
  type: 'performance' | 'security' | 'maintainability' | 'usability';
  message: string;
  nodeId?: string;
  edgeId?: string;
  suggestion: string;
}

export interface ValidationSuggestion {
  type: 'optimization' | 'security' | 'maintainability' | 'usability';
  message: string;
  nodeId?: string;
  edgeId?: string;
  impact: 'low' | 'medium' | 'high';
  effort: 'low' | 'medium' | 'high';
}

export interface WorkflowTesting {
  testCases: TestCase[];
  coverage: number;
  performance: PerformanceTest;
  security: SecurityTest;
  integration: IntegrationTest;
}

export interface TestCase {
  id: string;
  name: string;
  description: string;
  input: Record<string, any>;
  expectedOutput: Record<string, any>;
  type: 'unit' | 'integration' | 'end-to-end' | 'performance' | 'security';
  priority: 'low' | 'medium' | 'high' | 'critical';
}

export interface PerformanceTest {
  maxExecutionTime: number;
  maxMemoryUsage: number;
  maxCpuUsage: number;
  throughput: number;
  latency: number;
}

export interface SecurityTest {
  vulnerabilityScan: boolean;
  penetrationTest: boolean;
  complianceCheck: boolean;
  dataPrivacyTest: boolean;
}

export interface IntegrationTest {
  externalServices: string[];
  mockServices: string[];
  testData: Record<string, any>;
  environment: 'development' | 'staging' | 'production';
}

export interface WorkflowDeployment {
  environment: 'development' | 'staging' | 'production';
  region: string;
  scaling: ScalingConfig;
  monitoring: MonitoringConfig;
  backup: BackupConfig;
  rollback: RollbackConfig;
}

export interface ScalingConfig {
  minInstances: number;
  maxInstances: number;
  scaleUpThreshold: number;
  scaleDownThreshold: number;
  cooldownPeriod: number;
}

export interface MonitoringConfig {
  enabled: boolean;
  metrics: string[];
  alerts: AlertConfig[];
  dashboards: string[];
  logs: LogConfig;
}

export interface AlertConfig {
  name: string;
  condition: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  action: string;
  cooldown: number;
}

export interface LogConfig {
  level: 'debug' | 'info' | 'warn' | 'error';
  retention: number;
  format: 'json' | 'text';
  destination: string[];
}

export interface BackupConfig {
  enabled: boolean;
  frequency: 'hourly' | 'daily' | 'weekly' | 'monthly';
  retention: number;
  encryption: boolean;
  compression: boolean;
}

export interface RollbackConfig {
  enabled: boolean;
  maxVersions: number;
  automatic: boolean;
  approvalRequired: boolean;
  notificationChannels: string[];
}

// =====================================================
// VALIDATION SCHEMAS
// =====================================================

const WorkflowGenerationRequestSchema = z.object({
  description: z.string().min(10).max(1000),
  businessContext: z.object({
    industry: z.string().min(1),
    companySize: z.enum(['startup', 'small', 'medium', 'large', 'enterprise']),
    department: z.string().min(1),
    useCase: z.string().min(1),
    existingTools: z.array(z.string()),
    businessRules: z.array(z.string()),
    complianceRequirements: z.array(z.string()),
    budgetConstraints: z.object({
      maxCostPerExecution: z.number().min(0),
      maxMonthlyBudget: z.number().min(0),
    }).optional(),
  }),
  constraints: z.object({
    maxNodes: z.number().min(1).max(100),
    maxExecutionTime: z.number().min(1),
    maxCostPerExecution: z.number().min(0),
    requiredIntegrations: z.array(z.string()),
    forbiddenIntegrations: z.array(z.string()),
    securityLevel: z.enum(['standard', 'high', 'critical']),
    complianceStandards: z.array(z.string()),
  }).optional(),
  templatePreferences: z.object({
    preferredNodeTypes: z.array(z.string()),
    aiModelPreferences: z.array(z.string()),
    integrationPriorities: z.array(z.string()),
    approvalRequirements: z.boolean(),
    errorHandlingLevel: z.enum(['basic', 'standard', 'comprehensive']),
  }).optional(),
  advancedOptions: z.object({
    customTemplates: z.array(z.string()).optional(),
    experimentalFeatures: z.array(z.string()).optional(),
    optimizationLevel: z.enum(['basic', 'standard', 'advanced']),
    testingMode: z.boolean(),
    debugOutput: z.boolean(),
  }).optional(),
});

// =====================================================
// AI WORKFLOW GENERATOR CLASS
// =====================================================

export class AIWorkflowGenerator {
  private aiClient: any;
  private env: Env;

  constructor(env: Env) {
    this.env = env;
    this.aiClient = getAIClient(env);
  }

  /**
   * Generate a workflow from natural language description
   */
  async generateWorkflow(request: WorkflowGenerationRequest): Promise<GeneratedWorkflow> {
    try {
      // Validate input
      const validatedRequest = WorkflowGenerationRequestSchema.parse(request);

      // Generate workflow using AI
      const workflow = await this.generateWorkflowWithAI(validatedRequest);

      // Validate generated workflow
      const validation = await this.validateWorkflow(workflow);

      // Generate test cases
      const testing = await this.generateTestCases(workflow);

      // Generate deployment configuration
      const deployment = await this.generateDeploymentConfig(workflow, validatedRequest);

      return {
        ...workflow,
        validation,
        testing,
        deployment,
      };

    } catch (error: any) {
      throw new Error(`Workflow generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Generate workflow using AI
   */
  private async generateWorkflowWithAI(request: WorkflowGenerationRequest): Promise<GeneratedWorkflow> {
    const prompt = this.buildWorkflowPrompt(request);
    
    const response = await this.aiClient.generateStructuredResponse<GeneratedWorkflow>(
      prompt,
      {
        type: 'object',
        properties: {
          id: { type: 'string' },
          name: { type: 'string' },
          description: { type: 'string' },
          version: { type: 'string' },
          nodes: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                id: { type: 'string' },
                type: { type: 'string' },
                name: { type: 'string' },
                description: { type: 'string' },
                position: {
                  type: 'object',
                  properties: {
                    x: { type: 'number' },
                    y: { type: 'number' },
                  },
                },
                configuration: { type: 'object' },
                inputs: { type: 'array' },
                outputs: { type: 'array' },
                dependencies: { type: 'array' },
                errorHandling: { type: 'object' },
                performance: { type: 'object' },
                security: { type: 'object' },
              },
            },
          },
          edges: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                id: { type: 'string' },
                source: { type: 'string' },
                target: { type: 'string' },
                condition: { type: 'string' },
                label: { type: 'string' },
                type: { type: 'string' },
              },
            },
          },
          metadata: { type: 'object' },
        },
      },
      {
        maxTokens: 4000,
        temperature: 0.3,
      }
    );

    return response;
  }

  /**
   * Build workflow generation prompt
   */
  private buildWorkflowPrompt(request: WorkflowGenerationRequest): string {
    return `
Generate a comprehensive workflow based on the following requirements:

DESCRIPTION:
${request.description}

BUSINESS CONTEXT:
- Industry: ${request.businessContext.industry}
- Company Size: ${request.businessContext.companySize}
- Department: ${request.businessContext.department}
- Use Case: ${request.businessContext.useCase}
- Existing Tools: ${request.businessContext.existingTools.join(', ')}
- Business Rules: ${request.businessContext.businessRules.join(', ')}
- Compliance Requirements: ${request.businessContext.complianceRequirements.join(', ')}

CONSTRAINTS:
${request.constraints ? `
- Max Nodes: ${request.constraints.maxNodes}
- Max Execution Time: ${request.constraints.maxExecutionTime} seconds
- Max Cost Per Execution: $${request.constraints.maxCostPerExecution}
- Required Integrations: ${request.constraints.requiredIntegrations.join(', ')}
- Forbidden Integrations: ${request.constraints.forbiddenIntegrations.join(', ')}
- Security Level: ${request.constraints.securityLevel}
- Compliance Standards: ${request.constraints.complianceStandards.join(', ')}
` : ''}

TEMPLATE PREFERENCES:
${request.templatePreferences ? `
- Preferred Node Types: ${request.templatePreferences.preferredNodeTypes.join(', ')}
- AI Model Preferences: ${request.templatePreferences.aiModelPreferences.join(', ')}
- Integration Priorities: ${request.templatePreferences.integrationPriorities.join(', ')}
- Approval Requirements: ${request.templatePreferences.approvalRequirements}
- Error Handling Level: ${request.templatePreferences.errorHandlingLevel}
` : ''}

ADVANCED OPTIONS:
${request.advancedOptions ? `
- Custom Templates: ${request.advancedOptions.customTemplates?.join(', ') || 'None'}
- Experimental Features: ${request.advancedOptions.experimentalFeatures?.join(', ') || 'None'}
- Optimization Level: ${request.advancedOptions.optimizationLevel}
- Testing Mode: ${request.advancedOptions.testingMode}
- Debug Output: ${request.advancedOptions.debugOutput}
` : ''}

Generate a workflow that:
1. Addresses the business requirements effectively
2. Follows best practices for workflow design
3. Includes proper error handling and validation
4. Implements appropriate security measures
5. Optimizes for performance and cost
6. Includes comprehensive testing and monitoring
7. Supports the specified integrations and constraints

Return a complete workflow definition with all necessary nodes, edges, and configurations.
`;
  }

  /**
   * Validate generated workflow
   */
  private async validateWorkflow(workflow: GeneratedWorkflow): Promise<WorkflowValidation> {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];
    const suggestions: ValidationSuggestion[] = [];

    // Validate nodes
    for (const node of workflow.nodes) {
      // Check for required fields
      if (!node.id || !node.name || !node.type) {
        errors.push({
          type: 'syntax',
          message: 'Node missing required fields',
          nodeId: node.id,
          severity: 'high',
        });
      }

      // Check for circular dependencies
      if (this.hasCircularDependency(node.id, workflow.nodes, workflow.edges)) {
        errors.push({
          type: 'logic',
          message: 'Circular dependency detected',
          nodeId: node.id,
          severity: 'critical',
        });
      }

      // Check for performance issues
      if (node.performance.timeout > 300000) { // 5 minutes
        warnings.push({
          type: 'performance',
          message: 'Node timeout is very high',
          nodeId: node.id,
          suggestion: 'Consider breaking down into smaller nodes',
        });
      }

      // Check for security issues
      if (node.security.dataPrivacy === 'critical' && !node.security.encryption) {
        warnings.push({
          type: 'security',
          message: 'Critical data privacy without encryption',
          nodeId: node.id,
          suggestion: 'Enable encryption for critical data',
        });
      }
    }

    // Validate edges
    for (const edge of workflow.edges) {
      const sourceNode = workflow.nodes.find(n => n.id === edge.source);
      const targetNode = workflow.nodes.find(n => n.id === edge.target);

      if (!sourceNode || !targetNode) {
        errors.push({
          type: 'syntax',
          message: 'Edge references non-existent node',
          edgeId: edge.id,
          severity: 'high',
        });
      }
    }

    // Check for orphaned nodes
    const connectedNodes = new Set<string>();
    for (const edge of workflow.edges) {
      connectedNodes.add(edge.source);
      connectedNodes.add(edge.target);
    }

    for (const node of workflow.nodes) {
      if (node.type !== 'trigger' && !connectedNodes.has(node.id)) {
        warnings.push({
          type: 'logic',
          message: 'Node is not connected to the workflow',
          nodeId: node.id,
          suggestion: 'Connect the node or remove if not needed',
        });
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
      suggestions,
    };
  }

  /**
   * Check for circular dependencies
   */
  private hasCircularDependency(nodeId: string, nodes: WorkflowNode[], edges: WorkflowEdge[]): boolean {
    const visited = new Set<string>();
    const recursionStack = new Set<string>();

    const dfs = (currentNodeId: string): boolean => {
      if (recursionStack.has(currentNodeId)) {
        return true; // Circular dependency found
      }

      if (visited.has(currentNodeId)) {
        return false;
      }

      visited.add(currentNodeId);
      recursionStack.add(currentNodeId);

      const outgoingEdges = edges.filter((e: any) => e.source === currentNodeId);
      for (const edge of outgoingEdges) {
        if (dfs(edge.target)) {
          return true;
        }
      }

      recursionStack.delete(currentNodeId);
      return false;
    };

    return dfs(nodeId);
  }

  /**
   * Generate test cases for the workflow
   */
  private async generateTestCases(workflow: GeneratedWorkflow): Promise<WorkflowTesting> {
    const testCases: TestCase[] = [];
    const prompt = `
Generate comprehensive test cases for the following workflow:

WORKFLOW:
${JSON.stringify(workflow, null, 2)}

Generate test cases that cover:
1. Happy path scenarios
2. Error conditions
3. Edge cases
4. Performance testing
5. Security testing
6. Integration testing

Return a JSON array of test cases with input data, expected outputs, and test types.
`;

    try {
      const response = await this.aiClient.generateStructuredResponse<TestCase[]>(
        prompt,
        {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              id: { type: 'string' },
              name: { type: 'string' },
              description: { type: 'string' },
              input: { type: 'object' },
              expectedOutput: { type: 'object' },
              type: { type: 'string' },
              priority: { type: 'string' },
            },
          },
        },
        {
          maxTokens: 2000,
          temperature: 0.2,
        }
      );

      testCases.push(...response);
    } catch (error: any) {
      // Fallback to basic test cases
      testCases.push({
        id: 'basic-1',
        name: 'Basic Execution Test',
        description: 'Test basic workflow execution',
        input: {},
        expectedOutput: {},
        type: 'unit',
        priority: 'high',
      });
    }

    return {
      testCases,
      coverage: 0.8, // Mock coverage
      performance: {
        maxExecutionTime: 300000,
        maxMemoryUsage: 512,
        maxCpuUsage: 80,
        throughput: 100,
        latency: 1000,
      },
      security: {
        vulnerabilityScan: true,
        penetrationTest: true,
        complianceCheck: true,
        dataPrivacyTest: true,
      },
      integration: {
        externalServices: [],
        mockServices: [],
        testData: {},
        environment: 'development',
      },
    };
  }

  /**
   * Generate deployment configuration
   */
  private async generateDeploymentConfig(
    workflow: GeneratedWorkflow,
    request: WorkflowGenerationRequest
  ): Promise<WorkflowDeployment> {
    return {
      environment: 'development',
      region: 'us-east-1',
      scaling: {
        minInstances: 1,
        maxInstances: 10,
        scaleUpThreshold: 80,
        scaleDownThreshold: 20,
        cooldownPeriod: 300,
      },
      monitoring: {
        enabled: true,
        metrics: ['execution_time', 'success_rate', 'error_rate', 'cost'],
        alerts: [
          {
            name: 'High Error Rate',
            condition: 'error_rate > 0.1',
            severity: 'high',
            action: 'notify',
            cooldown: 300,
          },
        ],
        dashboards: ['workflow-overview', 'performance-metrics'],
        logs: {
          level: 'info',
          retention: 30,
          format: 'json',
          destination: ['console', 'file'],
        },
      },
      backup: {
        enabled: true,
        frequency: 'daily',
        retention: 30,
        encryption: true,
        compression: true,
      },
      rollback: {
        enabled: true,
        maxVersions: 5,
        automatic: false,
        approvalRequired: true,
        notificationChannels: ['email', 'slack'],
      },
    };
  }

  /**
   * Get available workflow templates
   */
  async getAvailableTemplates(): Promise<Array<{
    id: string;
    name: string;
    description: string;
    category: string;
    complexity: 'low' | 'medium' | 'high';
    tags: string[];
  }>> {
    // Mock implementation
    return [
      {
        id: 'invoice-processing',
        name: 'Invoice Processing Workflow',
        description: 'Automated invoice processing with validation and approval',
        category: 'finance',
        complexity: 'medium',
        tags: ['invoice', 'automation', 'finance'],
      },
      {
        id: 'customer-onboarding',
        name: 'Customer Onboarding Workflow',
        description: 'Complete customer onboarding process with verification',
        category: 'sales',
        complexity: 'high',
        tags: ['customer', 'onboarding', 'sales'],
      },
      {
        id: 'data-migration',
        name: 'Data Migration Workflow',
        description: 'Safe data migration between systems',
        category: 'data',
        complexity: 'high',
        tags: ['data', 'migration', 'etl'],
      },
    ];
  }

  /**
   * Get workflow generation statistics
   */
  async getGenerationStats(): Promise<{
    totalGenerated: number;
    successRate: number;
    averageComplexity: number;
    popularTemplates: string[];
    commonIssues: string[];
  }> {
    // Mock implementation
    return {
      totalGenerated: 0,
      successRate: 0.95,
      averageComplexity: 0.7,
      popularTemplates: ['invoice-processing', 'customer-onboarding'],
      commonIssues: ['circular-dependencies', 'missing-error-handling'],
    };
  }
}

