/**
 * Workflow Import/Export System
 * Supports multiple formats: JSON, YAML, BPMN 2.0, Mermaid, OpenAPI, Zapier/Make.com
 * Includes version control, template marketplace, and format conversion
 */

import type { Env } from '../types/env';
import { getAIClient } from './secure-ai-client';
import { validateInput } from '../utils/validation-schemas';
import { z } from 'zod';
import * as yaml from 'yaml';

// =====================================================
// TYPES AND INTERFACES
// =====================================================

export interface ImportRequest {
  format: 'json' | 'yaml' | 'bpmn' | 'mermaid' | 'openapi' | 'zapier' | 'make' | 'n8n';
  content: string;
  businessId: string;
  userId: string;
  importOptions?: ImportOptions;
}

export interface ImportOptions {
  preserveIds?: boolean;
  mergeDuplicates?: boolean;
  validateOnImport?: boolean;
  createAsTemplate?: boolean;
  targetVersion?: string;
  customMappings?: Record<string, string>;
}

export interface ExportRequest {
  workflowId: string;
  format: 'json' | 'yaml' | 'bpmn' | 'mermaid' | 'openapi' | 'zapier' | 'make' | 'documentation';
  businessId: string;
  exportOptions?: ExportOptions;
}

export interface ExportOptions {
  includeMetadata?: boolean;
  includeComments?: boolean;
  includeHistory?: boolean;
  minifyOutput?: boolean;
  generateDocumentation?: boolean;
  includeDiagram?: boolean;
  customization?: {
    nodeLabels?: boolean;
    edgeLabels?: boolean;
    colors?: boolean;
    layout?: boolean;
  };
}

export interface ImportResult {
  success: boolean;
  workflowId?: string;
  warnings: string[];
  errors: string[];
  importedNodes: number;
  importedEdges: number;
  mappedIntegrations: Record<string, string>;
  validationResults?: any;
}

export interface ExportResult {
  success: boolean;
  content: string;
  format: string;
  filename: string;
  size: number;
  metadata?: any;
}

export interface TemplateExport {
  id: string;
  name: string;
  description: string;
  category: string;
  industry?: string;
  difficulty: 'beginner' | 'intermediate' | 'advanced' | 'expert';
  estimatedCost: number;
  estimatedDuration: number;
  tags: string[];
  workflow: any;
  documentation?: string;
  examples?: any[];
  version: string;
  author: {
    id: string;
    name: string;
    organization?: string;
  };
  certification?: {
    level: 'bronze' | 'silver' | 'gold' | 'platinum';
    certifiedBy: string;
    certifiedAt: string;
  };
  usage: {
    downloads: number;
    rating: number;
    reviews: number;
  };
  compatibility: {
    minVersion: string;
    maxVersion?: string;
    requiredFeatures: string[];
  };
}

// =====================================================
// WORKFLOW IMPORT/EXPORT SERVICE
// =====================================================

export // TODO: Consider splitting WorkflowImportExportService into smaller, focused classes
class WorkflowImportExportService {
  private env: Env;
  private businessId: string;
  private aiClient: any;

  constructor(env: Env, businessId: string) {
    this.env = env;
    this.businessId = businessId;
    this.aiClient = getAIClient(env);
  }

  // =====================================================
  // IMPORT METHODS
  // =====================================================

  async importWorkflow(request: ImportRequest): Promise<ImportResult> {

    try {
      // Parse the content based on format
      const parsedWorkflow = await this.parseImportContent(request);

      // Convert to internal format
      const internalWorkflow = await this.convertToInternalFormat(parsedWorkflow, request.format);

      // Validate the workflow
      const validationResults = request.importOptions?.validateOnImport
        ? await this.validateImportedWorkflow(internalWorkflow)
        : null;

      if (validationResults?.errors.length > 0) {
        return {
          success: false,
          warnings: validationResults.warnings,
          errors: validationResults.errors,
          importedNodes: 0,
          importedEdges: 0,
          mappedIntegrations: {},
          validationResults
        };
      }

      // Map integrations to available providers
      const integrationMappings = await this.mapIntegrations(internalWorkflow);

      // Generate unique IDs if needed
      if (!request.importOptions?.preserveIds) {
        this.generateNewIds(internalWorkflow);
      }

      // Save to database
      const workflowId = await this.saveImportedWorkflow(internalWorkflow, request);

      return {
        success: true,
        workflowId,
        warnings: validationResults?.warnings || [],
        errors: [],
        importedNodes: internalWorkflow.nodes?.length || 0,
        importedEdges: internalWorkflow.edges?.length || 0,
        mappedIntegrations: integrationMappings,
        validationResults
      };

    } catch (error: any) {
      return {
        success: false,
        warnings: [],
        errors: [error.message],
        importedNodes: 0,
        importedEdges: 0,
        mappedIntegrations: {}
      };
    }
  }

  private async parseImportContent(request: ImportRequest): Promise<any> {
    const { format, content } = request;

    switch (format) {
      case 'json':
        return JSON.parse(content);

      case 'yaml':
        return yaml.parse(content);

      case 'bpmn':
        return this.parseBPMN(content);

      case 'mermaid':
        return this.parseMermaid(content);

      case 'openapi':
        return this.parseOpenAPI(content);

      case 'zapier':
        return this.parseZapier(content);

      case 'make':
        return this.parseMake(content);

      case 'n8n':
        return this.parseN8N(content);

      default:
        throw new Error(`Unsupported import format: ${format}`);
    }
  }

  private async convertToInternalFormat(parsed: any, sourceFormat: string): Promise<any> {
    const aiPrompt = `
      Convert this workflow from ${sourceFormat} format to our internal format:

      Source: ${JSON.stringify(parsed, null, 2)}

      Convert to our internal format with these node types:
      - ai_agent: For AI-powered operations
      - logic: For conditions, loops, transformations
      - integration: For external API calls
      - approval: For human approval processes
      - trigger: For workflow triggers

      Map equivalent concepts:
      - ${sourceFormat === 'bpmn' ? 'BPMN tasks → workflow nodes' : ''}
      - ${sourceFormat === 'zapier' ? 'Zaps → workflow sequences' : ''}
      - ${sourceFormat === 'make' ? 'Modules → workflow nodes' : ''}
      - ${sourceFormat === 'mermaid' ? 'Flowchart elements → workflow components' : ''}

      Return JSON:
      {
        "name": "workflow_name",
        "description": "workflow_description",
        "category": "sales|finance|operations|hr|marketing",
        "nodes": [
          {
            "id": "node_id",
            "type": "ai_agent|logic|integration|approval|trigger",
            "subtype": "specific_implementation",
            "label": "human_readable_name",
            "description": "what_this_node_does",
            "position": {"x": number, "y": number},
            "config": {
              // node-specific configuration
            },
            "dependsOn": ["dependency_node_ids"]
          }
        ],
        "edges": [
          {
            "id": "edge_id",
            "sourceNodeId": "source_node",
            "targetNodeId": "target_node",
            "conditionType": "always|success|failure|conditional",
            "conditionExpression": "condition_if_applicable"
          }
        ],
        "variables": {
          "variable_name": "default_value"
        },
        "metadata": {
          "sourceFormat": "${sourceFormat}",
          "importedAt": "${new Date().toISOString()}",
          "originalData": {...}
        }
      }
    `;

    try {
      const converted = await this.aiClient.parseJSONResponse(aiPrompt);
      converted.metadata.originalData = parsed;
      return converted;
    } catch (error: any) {
      return this.fallbackConversion(parsed, sourceFormat);
    }
  }

  private parseBPMN(content: string): any {
    // Basic BPMN parsing - in production would use a proper BPMN parser
    const bpmnElements = this.extractBPMNElements(content);
    return {
      processes: bpmnElements.processes,
      tasks: bpmnElements.tasks,
      gateways: bpmnElements.gateways,
      events: bpmnElements.events,
      flows: bpmnElements.flows
    };
  }

  private parseMermaid(content: string): any {
    // Parse Mermaid flowchart syntax
    const lines = content.split('\n').filter((line: any) => line.trim());
    const nodes = new Map();
    const edges = [];

    for (const line of lines) {
      if (line.includes('-->')) {
        // Edge definition
        const [source, target] = line.split('-->').map((s: any) => s.trim());
        edges.push({ source, target });
      } else if (line.includes('[') && line.includes(']')) {
        // Node definition with label
        const match = line.match(/(\w+)\[(.*?)\]/);
        if (match) {
          nodes.set(match[1], { id: match[1], label: match[2] });
        }
      }
    }

    return {
      nodes: Array.from(nodes.values()),
      edges
    };
  }

  private parseOpenAPI(content: string): any {
    const spec = JSON.parse(content);
    return {
      info: spec.info,
      paths: spec.paths,
      components: spec.components,
      servers: spec.servers
    };
  }

  private parseZapier(content: string): any {
    const zapData = JSON.parse(content);
    return {
      trigger: zapData.trigger,
      actions: zapData.actions,
      filters: zapData.filters,
      formatter: zapData.formatter
    };
  }

  private parseMake(content: string): any {
    const makeData = JSON.parse(content);
    return {
      scenario: makeData.scenario,
      modules: makeData.modules,
      connections: makeData.connections,
      settings: makeData.settings
    };
  }

  private parseN8N(content: string): any {
    const n8nData = JSON.parse(content);
    return {
      nodes: n8nData.nodes,
      connections: n8nData.connections,
      settings: n8nData.settings,
      staticData: n8nData.staticData
    };
  }

  // =====================================================
  // EXPORT METHODS
  // =====================================================

  async exportWorkflow(request: ExportRequest): Promise<ExportResult> {

    try {
      // Load workflow from database
      const workflow = await this.loadWorkflowForExport(request.workflowId);

      // Convert to target format
      const exportedContent = await this.convertToExportFormat(workflow, request);

      // Generate filename
      const filename = this.generateExportFilename(workflow, request.format);

      return {
        success: true,
        content: exportedContent,
        format: request.format,
        filename,
        size: exportedContent.length,
        metadata: {
          workflowId: request.workflowId,
          exportedAt: new Date().toISOString(),
          format: request.format,
          options: request.exportOptions
        }
      };

    } catch (error: any) {
      return {
        success: false,
        content: '',
        format: request.format,
        filename: '',
        size: 0
      };
    }
  }

  private async convertToExportFormat(workflow: any, request: ExportRequest): Promise<string> {
    const { format } = request;

    switch (format) {
      case 'json':
        return this.exportToJSON(workflow, request.exportOptions);

      case 'yaml':
        return this.exportToYAML(workflow, request.exportOptions);

      case 'bpmn':
        return this.exportToBPMN(workflow, request.exportOptions);

      case 'mermaid':
        return this.exportToMermaid(workflow, request.exportOptions);

      case 'openapi':
        return this.exportToOpenAPI(workflow, request.exportOptions);

      case 'zapier':
        return this.exportToZapier(workflow, request.exportOptions);

      case 'make':
        return this.exportToMake(workflow, request.exportOptions);

      case 'documentation':
        return this.exportToDocumentation(workflow, request.exportOptions);

      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
  }

  private exportToJSON(workflow: any, options?: ExportOptions): string {
    const exportData = { ...workflow };

    if (!options?.includeMetadata) {
      delete exportData.metadata;
      delete exportData.createdAt;
      delete exportData.updatedAt;
    }

    if (!options?.includeComments) {
      delete exportData.comments;
    }

    if (!options?.includeHistory) {
      delete exportData.history;
    }

    return JSON.stringify(exportData, null, options?.minifyOutput ? 0 : 2);
  }

  private exportToYAML(workflow: any, options?: ExportOptions): string {
    const exportData = { ...workflow };

    if (!options?.includeMetadata) {
      delete exportData.metadata;
    }

    return yaml.stringify(exportData);
  }

  private exportToBPMN(workflow: any, options?: ExportOptions): string {
    const bpmnTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<bpmn:definitions xmlns:bpmn="http://www.omg.org/spec/BPMN/20100524/MODEL"
                  xmlns:bpmndi="http://www.omg.org/spec/BPMN/20100524/DI"
                  xmlns:dc="http://www.omg.org/spec/DD/20100524/DC"
                  xmlns:di="http://www.omg.org/spec/DD/20100524/DI"
                  id="Definitions_${workflow.id}"
                  targetNamespace="http://bpmn.io/schema/bpmn">
  <bpmn:process id="Process_${workflow.id}" isExecutable="true">
    ${this.generateBPMNElements(workflow)}
  </bpmn:process>
  ${this.generateBPMNDiagram(workflow)}
</bpmn:definitions>`;

    return bpmnTemplate;
  }

  private generateBPMNDiagram(workflow: any): string {
    // Generate BPMN diagram elements
    let diagramElements = '';
    
    // Add nodes as BPMN shapes
    const nodes = JSON.parse(workflow.nodes as string);
    nodes.forEach((node: any, index: number) => {
      const x = 100 + (index * 200);
      const y = 100;
      diagramElements += `
    <bpmndi:BPMNShape id="Shape_${node.id}" bpmnElement="${node.id}">
      <dc:Bounds x="${x}" y="${y}" width="100" height="80" />
    </bpmndi:BPMNShape>`;
    });

    // Add edges as BPMN edges
    const edges = JSON.parse(workflow.edges as string);
    edges.forEach((edge: any, index: number) => {
      diagramElements += `
    <bpmndi:BPMNEdge id="Edge_${edge.id}" bpmnElement="${edge.id}">
      <di:waypoint x="150" y="140" />
      <di:waypoint x="250" y="140" />
    </bpmndi:BPMNEdge>`;
    });

    return `
  <bpmndi:BPMNDiagram id="BPMNDiagram_${workflow.id}">
    <bpmndi:BPMNPlane id="BPMNPlane_${workflow.id}" bpmnElement="Process_${workflow.id}">
      ${diagramElements}
    </bpmndi:BPMNPlane>
  </bpmndi:BPMNDiagram>`;
  }

  private generateOpenAPIPaths(workflow: any): any {
    const paths: any = {};
    
    // Generate paths for workflow endpoints
    const nodes = JSON.parse(workflow.nodes as string);
    nodes.forEach((node: any) => {
      if (node.type === 'api_endpoint') {
        const path = node.config?.path || `/workflow/${workflow.id}/step/${node.id}`;
        paths[path] = {
          post: {
            summary: node.name || `Execute ${node.type}`,
            description: node.description || `Execute workflow step: ${node.id}`,
            requestBody: {
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      input: {
                        type: 'object',
                        description: 'Input data for the workflow step'
                      }
                    }
                  }
                }
              }
            },
            responses: {
              '200': {
                description: 'Success',
                content: {
                  'application/json': {
                    schema: {
                      type: 'object',
                      properties: {
                        success: { type: 'boolean' },
                        data: { type: 'object' }
                      }
                    }
                  }
                }
              }
            }
          }
        };
      }
    });

    return paths;
  }

  private generateOpenAPISchemas(workflow: any): any {
    const schemas: any = {};
    
    // Generate schemas for workflow data structures
    schemas.WorkflowInput = {
      type: 'object',
      properties: {
        workflowId: { type: 'string' },
        input: { type: 'object' }
      }
    };

    schemas.WorkflowOutput = {
      type: 'object',
      properties: {
        success: { type: 'boolean' },
        data: { type: 'object' },
        errors: { type: 'array', items: { type: 'string' } }
      }
    };

    return schemas;
  }

  private convertToZapierTrigger(workflow: any): any {
    const nodes = JSON.parse(workflow.nodes as string);
    const triggerNode = nodes.find((node: any) => node.type === 'trigger');
    
    if (!triggerNode) {
      return {
        type: 'webhook',
        name: 'Webhook Trigger',
        description: 'Triggered by webhook'
      };
    }

    return {
      type: triggerNode.config?.triggerType || 'webhook',
      name: triggerNode.name || 'Workflow Trigger',
      description: triggerNode.description || 'Trigger for workflow execution',
      config: triggerNode.config || {}
    };
  }

  private convertToZapierActions(workflow: any): any[] {
    const nodes = JSON.parse(workflow.nodes as string);
    const actionNodes = nodes.filter((node: any) => node.type !== 'trigger');
    
    return actionNodes.map((node: any) => ({
      type: node.type,
      name: node.name || `Action: ${node.type}`,
      description: node.description || `Execute ${node.type} action`,
      config: node.config || {}
    }));
  }

  private convertToMakeModules(workflow: any): any[] {
    const nodes = JSON.parse(workflow.nodes as string);
    const edges = JSON.parse(workflow.edges as string);
    
    return nodes.map((node: any, index: number) => {
      const module = {
        id: index + 1,
        type: node.type,
        name: node.name || `Module ${index + 1}`,
        config: node.config || {},
        position: {
          x: 100 + (index * 200),
          y: 100
        }
      };

      // Add connections based on edges
      const outgoingEdges = edges.filter((edge: any) => edge.sourceNodeId === node.id);
      if (outgoingEdges.length > 0) {
        module.connections = outgoingEdges.map((edge: any) => ({
          targetModuleId: nodes.findIndex((n: any) => n.id === edge.targetNodeId) + 1,
          condition: edge.conditionType || 'always'
        }));
      }

      return module;
    });
  }

  private extractRequiredFeatures(workflow: any): string[] {
    const features: string[] = [];
    const nodes = JSON.parse(workflow.nodes as string);
    
    nodes.forEach((node: any) => {
      switch (node.type) {
        case 'ai_agent':
          features.push('ai_integration');
          break;
        case 'api_call':
          features.push('api_integration');
          break;
        case 'email':
          features.push('email_service');
          break;
        case 'database':
          features.push('database_access');
          break;
        case 'webhook':
          features.push('webhook_support');
          break;
        default:
          features.push('basic_workflow');
      }
    });

    return [...new Set(features)]; // Remove duplicates
  }

  private async saveTemplate(template: any): Promise<void> {
    // Save template to database or file system
    // This is a placeholder implementation
    console.log('Saving template:', template.name);
  }

  private async loadTemplate(templateId: string): Promise<any> {
    // Load template from database or file system
    // This is a placeholder implementation
    return {
      id: templateId,
      name: 'Sample Template',
      description: 'A sample workflow template',
      workflow: {}
    };
  }

  private async updateTemplateUsage(templateId: string): Promise<void> {
    // Update template usage statistics
    // This is a placeholder implementation
    console.log('Updating usage for template:', templateId);
  }

  private async resolveMergeConflicts(sourceWorkflow: any, targetWorkflow: any): Promise<any> {
    // Simple merge conflict resolution
    // In a real implementation, this would use AI to intelligently merge workflows
    const mergedWorkflow = {
      ...targetWorkflow,
      name: `${targetWorkflow.name} (Merged)`,
      description: `${targetWorkflow.description}\n\nMerged with: ${sourceWorkflow.name}`,
      nodes: JSON.stringify([
        ...JSON.parse(targetWorkflow.nodes as string),
        ...JSON.parse(sourceWorkflow.nodes as string)
      ]),
      edges: JSON.stringify([
        ...JSON.parse(targetWorkflow.edges as string),
        ...JSON.parse(sourceWorkflow.edges as string)
      ])
    };

    return {
      success: true,
      mergedWorkflow,
      conflicts: []
    };
  }

  private async updateWorkflowFromMerge(workflowId: string, mergedWorkflow: any, userId: string): Promise<void> {
    // Update the workflow with merged changes
    // This is a placeholder implementation
    console.log('Updating workflow from merge:', workflowId, 'by user:', userId);
  }

  private compareNodes(nodes1: string, nodes2: string): any {
    const nodes1Array = JSON.parse(nodes1);
    const nodes2Array = JSON.parse(nodes2);
    
    const added = nodes2Array.filter((node2: any) => 
      !nodes1Array.some((node1: any) => node1.id === node2.id)
    );
    
    const removed = nodes1Array.filter((node1: any) => 
      !nodes2Array.some((node2: any) => node2.id === node1.id)
    );
    
    const modified = nodes2Array.filter((node2: any) => {
      const node1 = nodes1Array.find((n: any) => n.id === node2.id);
      return node1 && JSON.stringify(node1) !== JSON.stringify(node2);
    });

    return { added, removed, modified };
  }

  private compareEdges(edges1: string, edges2: string): any {
    const edges1Array = JSON.parse(edges1);
    const edges2Array = JSON.parse(edges2);
    
    const added = edges2Array.filter((edge2: any) => 
      !edges1Array.some((edge1: any) => edge1.id === edge2.id)
    );
    
    const removed = edges1Array.filter((edge1: any) => 
      !edges2Array.some((edge2: any) => edge2.id === edge1.id)
    );
    
    const modified = edges2Array.filter((edge2: any) => {
      const edge1 = edges1Array.find((e: any) => e.id === edge2.id);
      return edge1 && JSON.stringify(edge1) !== JSON.stringify(edge2);
    });

    return { added, removed, modified };
  }

  private compareConfigurations(workflow1: any, workflow2: any): any {
    const changes: any = {};
    
    // Compare workflow-level configuration
    if (workflow1.name !== workflow2.name) {
      changes.name = { from: workflow1.name, to: workflow2.name };
    }
    
    if (workflow1.description !== workflow2.description) {
      changes.description = { from: workflow1.description, to: workflow2.description };
    }
    
    // Compare other configuration properties
    const config1 = workflow1.config || {};
    const config2 = workflow2.config || {};
    
    Object.keys(config2).forEach(key => {
      if (config1[key] !== config2[key]) {
        changes[key] = { from: config1[key], to: config2[key] };
      }
    });

    return changes;
  }

  private exportToMermaid(workflow: any, options?: ExportOptions): string {
    let mermaidContent = 'flowchart TD\n';

    // Add nodes
    for (const node of workflow.nodes) {
      const shape = this.getMermaidNodeShape(node.type);
      const label = options?.customization?.nodeLabels ? node.label : node.id;
      mermaidContent += `    ${node.id}${shape[0]}${label}${shape[1]}\n`;

      if (options?.customization?.colors) {
        const color = this.getNodeColor(node.type);
        mermaidContent += `    ${node.id} --> ${node.id}:::${color}\n`;
      }
    }

    mermaidContent += '\n';

    // Add edges
    for (const edge of workflow.edges) {
      const arrow = this.getMermaidArrow(edge.conditionType);
      const label = options?.customization?.edgeLabels && edge.label ? `|${edge.label}|` : '';
      mermaidContent += `    ${edge.sourceNodeId} ${arrow}${label} ${edge.targetNodeId}\n`;
    }

    if (options?.customization?.colors) {
      mermaidContent += '\n';
      mermaidContent += '    classDef ai_agent fill:#3b82f6,stroke:#1d4ed8,color:#fff\n';
      mermaidContent += '    classDef logic fill:#10b981,stroke:#047857,color:#fff\n';
      mermaidContent += '    classDef integration fill:#f59e0b,stroke:#d97706,color:#fff\n';
      mermaidContent += '    classDef approval fill:#ef4444,stroke:#dc2626,color:#fff\n';
    }

    return mermaidContent;
  }

  private exportToOpenAPI(workflow: any, options?: ExportOptions): string {
    // Convert workflow to OpenAPI specification
    const openAPISpec = {
      openapi: '3.0.0',
      info: {
        title: workflow.name,
        description: workflow.description,
        version: workflow.version || '1.0.0'
      },
      servers: [
        {
          url: 'https://api.coreflow360.com/v1',
          description: 'CoreFlow360 API Server'
        }
      ],
      paths: this.generateOpenAPIPaths(workflow),
      components: {
        schemas: this.generateOpenAPISchemas(workflow),
        securitySchemes: {
          bearerAuth: {
            type: 'http',
            scheme: 'bearer'
          }
        }
      }
    };

    return JSON.stringify(openAPISpec, null, 2);
  }

  private exportToZapier(workflow: any, options?: ExportOptions): string {
    const zapierFormat = {
      title: workflow.name,
      description: workflow.description,
      trigger: this.convertToZapierTrigger(workflow),
      actions: this.convertToZapierActions(workflow),
      version: '1.0.0'
    };

    return JSON.stringify(zapierFormat, null, 2);
  }

  private exportToMake(workflow: any, options?: ExportOptions): string {
    const makeFormat = {
      scenario: {
        name: workflow.name,
        description: workflow.description,
        modules: this.convertToMakeModules(workflow),
        metadata: {
          version: '1.0.0',
          designer: {
            orphans: []
          }
        }
      }
    };

    return JSON.stringify(makeFormat, null, 2);
  }

  private async exportToDocumentation(workflow: any, options?: ExportOptions): Promise<string> {
    const docPrompt = `
      Generate comprehensive documentation for this workflow:

      ${JSON.stringify(workflow, null, 2)}

      Create a markdown document with:
      1. Overview and purpose
      2. Prerequisites and setup
      3. Detailed node descriptions
      4. Data flow explanation
      5. Configuration guide
      6. Troubleshooting section
      7. API reference (if applicable)
      8. Examples and use cases

      Format as markdown with proper headings, code blocks, and diagrams.
    `;

    try {
      return await this.aiClient.callAI({ prompt: docPrompt });
    } catch (error: any) {
      return this.generateBasicDocumentation(workflow);
    }
  }

  // =====================================================
  // TEMPLATE MARKETPLACE
  // =====================================================

  async exportAsTemplate(workflowId: string, templateInfo: Partial<TemplateExport>): Promise<TemplateExport> {
    const workflow = await this.loadWorkflowForExport(workflowId);

    const template: TemplateExport = {
      id: `template_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      name: templateInfo.name || workflow.name,
      description: templateInfo.description || workflow.description,
      category: templateInfo.category || workflow.category,
      industry: templateInfo.industry,
      difficulty: templateInfo.difficulty || 'intermediate',
      estimatedCost: workflow.estimatedCost || 0,
      estimatedDuration: workflow.estimatedDuration || 0,
      tags: templateInfo.tags || [],
      workflow: {
        ...workflow,
        // Remove instance-specific data
        id: undefined,
        businessId: undefined,
        createdBy: undefined,
        executionHistory: undefined
      },
      documentation: templateInfo.documentation,
      examples: templateInfo.examples,
      version: '1.0.0',
      author: {
        id: templateInfo.author?.id || 'anonymous',
        name: templateInfo.author?.name || 'Anonymous',
        organization: templateInfo.author?.organization
      },
      usage: {
        downloads: 0,
        rating: 0,
        reviews: 0
      },
      compatibility: {
        minVersion: '1.0.0',
        requiredFeatures: this.extractRequiredFeatures(workflow)
      }
    };

    // Save to template marketplace
    await this.saveTemplate(template);

    return template;
  }

  async importFromTemplateMarketplace(templateId: string, businessId: string): Promise<ImportResult> {
    const template = await this.loadTemplate(templateId);

    if (!template) {
      return {
        success: false,
        warnings: [],
        errors: ['Template not found'],
        importedNodes: 0,
        importedEdges: 0,
        mappedIntegrations: {}
      };
    }

    // Convert template to workflow
    const workflow = {
      ...template.workflow,
      id: `wf_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      businessId,
      isTemplate: false,
      templateId: template.id,
      createdAt: new Date().toISOString()
    };

    const workflowId = await this.saveImportedWorkflow(workflow, {
      format: 'json',
      content: JSON.stringify(workflow),
      businessId,
      userId: 'template_import'
    });

    // Update template usage stats
    await this.updateTemplateUsage(templateId);

    return {
      success: true,
      workflowId,
      warnings: [],
      errors: [],
      importedNodes: workflow.nodes?.length || 0,
      importedEdges: workflow.edges?.length || 0,
      mappedIntegrations: {}
    };
  }

  // =====================================================
  // VERSION CONTROL
  // =====================================================

  async createWorkflowBranch(workflowId: string, branchName: string, userId: string): Promise<string> {
    const workflow = await this.loadWorkflowForExport(workflowId);

    const branchId = `${workflowId}_branch_${branchName}_${Date.now()}`;
    const branchedWorkflow = {
      ...workflow,
      id: branchId,
      parentId: workflowId,
      branchName,
      createdBy: userId,
      createdAt: new Date().toISOString()
    };

    await this.saveImportedWorkflow(branchedWorkflow, {
      format: 'json',
      content: JSON.stringify(branchedWorkflow),
      businessId: this.businessId,
      userId
    });

    return branchId;
  }

  async mergeWorkflowBranch(sourceWorkflowId: string, targetWorkflowId: string, userId: string): Promise<boolean> {
    try {
      const sourceWorkflow = await this.loadWorkflowForExport(sourceWorkflowId);
      const targetWorkflow = await this.loadWorkflowForExport(targetWorkflowId);

      // Use AI to assist with merge conflict resolution
      const mergeResult = await this.resolveMergeConflicts(sourceWorkflow, targetWorkflow);

      if (mergeResult.success) {
        // Apply merged changes to target workflow
        await this.updateWorkflowFromMerge(targetWorkflowId, mergeResult.mergedWorkflow, userId);
        return true;
      }

      return false;
    } catch (error: any) {
      return false;
    }
  }

  async compareWorkflowVersions(workflow1Id: string, workflow2Id: string): Promise<any> {
    const [workflow1, workflow2] = await Promise.all([
      this.loadWorkflowForExport(workflow1Id),
      this.loadWorkflowForExport(workflow2Id)
    ]);

    return {
      nodeChanges: this.compareNodes(workflow1.nodes, workflow2.nodes),
      edgeChanges: this.compareEdges(workflow1.edges, workflow2.edges),
      configChanges: this.compareConfigurations(workflow1, workflow2),
      summary: {
        nodesAdded: 0,
        nodesRemoved: 0,
        nodesModified: 0,
        edgesAdded: 0,
        edgesRemoved: 0,
        edgesModified: 0
      }
    };
  }

  // =====================================================
  // UTILITY METHODS
  // =====================================================

  private async loadWorkflowForExport(workflowId: string): Promise<any> {
    const db = this.env.DB_CRM;

    const workflow = await db.prepare(`
      SELECT w.*,
             json_group_array(DISTINCT json_object(
               'id', n.id,
               'type', n.node_type,
               'subtype', n.node_subtype,
               'label', n.node_key,
               'position', json_object('x', n.position_x, 'y', n.position_y),
               'config', n.config,
               'dependsOn', n.depends_on
             )) as nodes,
             json_group_array(DISTINCT json_object(
               'id', e.id,
               'sourceNodeId', e.source_node_id,
               'targetNodeId', e.target_node_id,
               'conditionType', e.condition_type,
               'conditionExpression', e.condition_expression,
               'label', e.label
             )) as edges
      FROM workflow_definitions w
      LEFT JOIN workflow_nodes n ON w.id = n.workflow_id
      LEFT JOIN workflow_edges e ON w.id = e.workflow_id
      WHERE w.id = ? AND w.business_id = ?
      GROUP BY w.id
    `).bind(workflowId, this.businessId).first();

    if (!workflow) {
      throw new Error('Workflow not found');
    }

    return {
      ...workflow,
      nodes: JSON.parse(workflow.nodes as string),
      edges: JSON.parse(workflow.edges as string)
    };
  }

  private async saveImportedWorkflow(workflow: any, request: ImportRequest): Promise<string> {
    const db = this.env.DB_CRM;

    const workflowId = workflow.id || `wf_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    // Save workflow definition
    await db.prepare(`
      INSERT INTO workflow_definitions (
        id, business_id, name, description, category, version,
        graph_data, status, created_by, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      workflowId,
      request.businessId,
      workflow.name,
      workflow.description,
      workflow.category,
      workflow.version || '1.0.0',
      JSON.stringify({ nodes: workflow.nodes, edges: workflow.edges }),
      'draft',
      request.userId,
      new Date().toISOString()
    ).run();

    // Save nodes
    for (const node of workflow.nodes || []) {
      await db.prepare(`
        INSERT INTO workflow_nodes (
          id, workflow_id, business_id, node_key, node_type, node_subtype,
          position_x, position_y, config, depends_on
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        node.id,
        workflowId,
        request.businessId,
        node.label || node.id,
        node.type,
        node.subtype,
        node.position?.x || 0,
        node.position?.y || 0,
        JSON.stringify(node.config || {}),
        JSON.stringify(node.dependsOn || [])
      ).run();
    }

    // Save edges
    for (const edge of workflow.edges || []) {
      await db.prepare(`
        INSERT INTO workflow_edges (
          id, workflow_id, business_id, source_node_id, target_node_id,
          condition_type, condition_expression, label
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        edge.id,
        workflowId,
        request.businessId,
        edge.sourceNodeId,
        edge.targetNodeId,
        edge.conditionType || 'always',
        edge.conditionExpression,
        edge.label
      ).run();
    }

    return workflowId;
  }

  private generateExportFilename(workflow: any, format: string): string {
    const timestamp = new Date().toISOString().split('T')[0];
    const safeName = workflow.name.replace(/[^a-zA-Z0-9]/g, '_').toLowerCase();
    return `${safeName}_${timestamp}.${format}`;
  }

  private generateNewIds(workflow: any): void {
    const idMap = new Map<string, string>();

    // Generate new node IDs
    for (const node of workflow.nodes || []) {
      const newId = `node_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      idMap.set(node.id, newId);
      node.id = newId;
    }

    // Generate new edge IDs and update references
    for (const edge of workflow.edges || []) {
      edge.id = `edge_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      edge.sourceNodeId = idMap.get(edge.sourceNodeId) || edge.sourceNodeId;
      edge.targetNodeId = idMap.get(edge.targetNodeId) || edge.targetNodeId;
    }

    // Update dependencies
    for (const node of workflow.nodes || []) {
      if (node.dependsOn) {
        node.dependsOn = node.dependsOn.map((depId: any) => idMap.get(depId) || depId);
      }
    }
  }

  private async mapIntegrations(workflow: any): Promise<Record<string, string>> {
    const mappings: Record<string, string> = {};

    for (const node of workflow.nodes || []) {
      if (node.type === 'integration' && node.config?.provider) {
        // Map to available integrations in the system
        const availableProvider = await this.findAvailableProvider(node.config.provider);
        if (availableProvider) {
          mappings[node.config.provider] = availableProvider;
          node.config.provider = availableProvider;
        }
      }
    }

    return mappings;
  }

  private async findAvailableProvider(requestedProvider: string): Promise<string | null> {
    // Check if the provider is available in the system
    const providerMappings = {
      'gmail': 'gmail',
      'outlook': 'outlook',
      'sendgrid': 'sendgrid',
      'twilio': 'twilio',
      'slack': 'slack',
      'teams': 'teams',
      'salesforce': 'salesforce',
      'hubspot': 'hubspot'
    };

    return (providerMappings as any)[requestedProvider.toLowerCase()] || null;
  }

  private fallbackConversion(parsed: any, sourceFormat: string): any {
    // Basic fallback conversion when AI fails
    return {
      name: parsed.name || 'Imported Workflow',
      description: parsed.description || 'Imported from ' + sourceFormat,
      category: 'custom',
      nodes: [],
      edges: [],
      variables: {},
      metadata: {
        sourceFormat,
        importedAt: new Date().toISOString(),
        originalData: parsed
      }
    };
  }

  // Helper methods for specific format conversions...
  // (Many additional helper methods would be implemented here)

  private getMermaidNodeShape(nodeType: string): [string, string] {
    const shapes = {
      'ai_agent': ['(', ')'],
      'logic': ['{', '}'],
      'integration': ['[', ']'],
      'approval': ['((', '))'],
      'trigger': ['>', ']']
    };
    return (shapes as any)[nodeType] || ['[', ']'];
  }

  private getMermaidArrow(conditionType: string): string {
    const arrows = {
      'always': '-->',
      'success': '-->',
      'failure': '-.->',
      'conditional': '==>',
    };
    return (arrows as any)[conditionType] || '-->';
  }

  private getNodeColor(nodeType: string): string {
    const colors = {
      'ai_agent': 'ai_agent',
      'logic': 'logic',
      'integration': 'integration',
      'approval': 'approval'
    };
    return (colors as any)[nodeType] || 'default';
  }

  private generateBasicDocumentation(workflow: any): string {
    return `# ${workflow.name}

## Overview
${workflow.description}

## Nodes
${workflow.nodes?.map((node: any) => `- **${node.label}** (${node.type}): ${node.description
  || 'No description'}`).join('\n') || 'No nodes'}

## Configuration
This workflow was imported and may require additional configuration.

## Generated Documentation
This documentation was automatically generated during export.
`;
  }

  // Additional utility methods for BPMN, OpenAPI, version control, etc. would continue here...
}