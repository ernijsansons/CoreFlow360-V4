import type { Capability, CapabilityDefinition, OrgRole, DepartmentType } from './types';

/**
 * Capability Registry - Central registry of all system capabilities
 */
export class CapabilityRegistry {
  private capabilities: Map<Capability, CapabilityDefinition> = new Map();
  private moduleIndex: Map<string, Set<Capability>> = new Map();
  private resourceIndex: Map<string, Set<Capability>> = new Map();
  private actionIndex: Map<string, Set<Capability>> = new Map();

  constructor() {
    this.registerDefaultCapabilities();
  }

  /**
   * Register a capability
   */
  register(definition: CapabilityDefinition): void {
    const { capability, module, resource, action } = definition;

    // Store capability
    this.capabilities.set(capability, definition);

    // Update indexes
    if (!this.moduleIndex.has(module)) {
      this.moduleIndex.set(module, new Set());
    }
    this.moduleIndex.get(module)!.add(capability);

    if (!this.resourceIndex.has(resource)) {
      this.resourceIndex.set(resource, new Set());
    }
    this.resourceIndex.get(resource)!.add(capability);

    if (!this.actionIndex.has(action)) {
      this.actionIndex.set(action, new Set());
    }
    this.actionIndex.get(action)!.add(capability);
  }

  /**
   * Get capability definition
   */
  get(capability: Capability): CapabilityDefinition | undefined {
    return this.capabilities.get(capability);
  }

  /**
   * Check if capability exists
   */
  has(capability: Capability): boolean {
    return this.capabilities.has(capability);
  }

  /**
   * Get capabilities by module
   */
  getByModule(module: string): CapabilityDefinition[] {
    const caps = this.moduleIndex.get(module);
    if (!caps) return [];

    return Array.from(caps)
      .map((cap: any) => this.capabilities.get(cap))
      .filter(Boolean) as CapabilityDefinition[];
  }

  /**
   * Get capabilities by resource
   */
  getByResource(resource: string): CapabilityDefinition[] {
    const caps = this.resourceIndex.get(resource);
    if (!caps) return [];

    return Array.from(caps)
      .map((cap: any) => this.capabilities.get(cap))
      .filter(Boolean) as CapabilityDefinition[];
  }

  /**
   * Get capabilities by action
   */
  getByAction(action: string): CapabilityDefinition[] {
    const caps = this.actionIndex.get(action);
    if (!caps) return [];

    return Array.from(caps)
      .map((cap: any) => this.capabilities.get(cap))
      .filter(Boolean) as CapabilityDefinition[];
  }

  /**
   * Get all capabilities for a role
   */
  getCapabilitiesForRole(role: OrgRole): Capability[] {
    const capabilities: Set<Capability> = new Set();

    this.capabilities.forEach((def, cap) => {
      if (def.defaultRoles?.includes(role)) {
        capabilities.add(cap);
      }
    });

    return Array.from(capabilities);
  }

  /**
   * Get capabilities for department type
   */
  getCapabilitiesForDepartment(deptType: DepartmentType): Capability[] {
    const capabilities: Set<Capability> = new Set();

    this.capabilities.forEach((def, cap) => {
      if (def.departmentTypes?.includes(deptType)) {
        capabilities.add(cap);
      }
    });

    return Array.from(capabilities);
  }

  /**
   * Match capability pattern (supports wildcards)
   */
  matchPattern(pattern: string): Capability[] {
    const regex = new RegExp(
      '^' + pattern.replace(/\*/g, '.*').replace(/\./g, '\\.') + '$'
    );

    return Array.from(this.capabilities.keys()).filter((cap: any) =>
      regex.test(cap)
    );
  }

  /**
   * Parse capability string
   */
  parseCapability(capability: Capability): {
    module: string;
    resource: string;
    action: string;
  } | null {
    const parts = capability.split('.');
    if (parts.length !== 3) return null;

    return {
      module: parts[0]!,
      resource: parts[1]!,
      action: parts[2]!,
    };
  }

  /**
   * Parse capability string (static version)
   */
  static parseCapability(capability: Capability): {
    module: string;
    resource: string;
    action: string;
  } | null {
    const parts = capability.split('.');
    if (parts.length !== 3) return null;

    return {
      module: parts[0]!,
      resource: parts[1]!,
      action: parts[2]!,
    };
  }

  /**
   * Validate capability format
   */
  static isValidCapability(capability: string): boolean {
    const pattern = /^[a-z]+\.[a-z_]+\.(create|read|update|delete|approve|reject|export|share|archive|restore|\*)$/;
    return pattern.test(capability);
  }

  /**
   * Register default system capabilities
   */
  private registerDefaultCapabilities(): void {
    // Finance module
    this.register({
      capability: 'finance.invoice.create',
      module: 'finance',
      resource: 'invoice',
      action: 'create',
      description: 'Create new invoices',
      riskLevel: 'medium',
      defaultRoles: ['owner', 'director', 'manager', 'employee'],
      departmentTypes: ['finance', 'sales'],
    });

    this.register({
      capability: 'finance.invoice.read',
      module: 'finance',
      resource: 'invoice',
      action: 'read',
      description: 'View invoices',
      riskLevel: 'low',
      defaultRoles: ['owner', 'director', 'manager', 'employee', 'viewer'],
    });

    this.register({
      capability: 'finance.invoice.update',
      module: 'finance',
      resource: 'invoice',
      action: 'update',
      description: 'Edit existing invoices',
      riskLevel: 'medium',
      defaultRoles: ['owner', 'director', 'manager'],
      departmentTypes: ['finance'],
    });

    this.register({
      capability: 'finance.invoice.delete',
      module: 'finance',
      resource: 'invoice',
      action: 'delete',
      description: 'Delete invoices',
      riskLevel: 'high',
      requiresMFA: true,
      defaultRoles: ['owner', 'director'],
      departmentTypes: ['finance'],
    });

    this.register({
      capability: 'finance.invoice.approve',
      module: 'finance',
      resource: 'invoice',
      action: 'approve',
      description: 'Approve invoices for payment',
      riskLevel: 'high',
      requiresMFA: true,
      defaultRoles: ['owner', 'director', 'manager'],
      departmentTypes: ['finance', 'executive'],
    });

    // HR module
    this.register({
      capability: 'hr.employee.create',
      module: 'hr',
      resource: 'employee',
      action: 'create',
      description: 'Add new employees',
      riskLevel: 'high',
      requiresMFA: true,
      defaultRoles: ['owner', 'director'],
      departmentTypes: ['hr', 'executive'],
    });

    this.register({
      capability: 'hr.employee.read',
      module: 'hr',
      resource: 'employee',
      action: 'read',
      description: 'View employee information',
      riskLevel: 'medium',
      defaultRoles: ['owner', 'director', 'manager'],
      departmentTypes: ['hr'],
    });

    this.register({
      capability: 'hr.employee.update',
      module: 'hr',
      resource: 'employee',
      action: 'update',
      description: 'Update employee information',
      riskLevel: 'high',
      requiresMFA: true,
      defaultRoles: ['owner', 'director'],
      departmentTypes: ['hr'],
    });

    this.register({
      capability: 'hr.payroll.approve',
      module: 'hr',
      resource: 'payroll',
      action: 'approve',
      description: 'Approve payroll processing',
      riskLevel: 'critical',
      requiresMFA: true,
      requiresApproval: true,
      defaultRoles: ['owner', 'director'],
      departmentTypes: ['hr', 'finance', 'executive'],
    });

    // Operations module
    this.register({
      capability: 'operations.inventory.create',
      module: 'operations',
      resource: 'inventory',
      action: 'create',
      description: 'Add inventory items',
      riskLevel: 'medium',
      defaultRoles: ['owner', 'director', 'manager', 'employee'],
      departmentTypes: ['operations', 'warehouse' as any],
    });

    this.register({
      capability: 'operations.inventory.update',
      module: 'operations',
      resource: 'inventory',
      action: 'update',
      description: 'Update inventory levels',
      riskLevel: 'medium',
      defaultRoles: ['owner', 'director', 'manager'],
      departmentTypes: ['operations', 'warehouse' as any],
    });

    // Sales module
    this.register({
      capability: 'sales.quote.create',
      module: 'sales',
      resource: 'quote',
      action: 'create',
      description: 'Create sales quotes',
      riskLevel: 'low',
      defaultRoles: ['owner', 'director', 'manager', 'employee'],
      departmentTypes: ['sales'],
    });

    this.register({
      capability: 'sales.quote.approve',
      module: 'sales',
      resource: 'quote',
      action: 'approve',
      description: 'Approve sales quotes',
      riskLevel: 'medium',
      defaultRoles: ['owner', 'director', 'manager'],
      departmentTypes: ['sales'],
    });

    // System module
    this.register({
      capability: 'system.settings.update',
      module: 'system',
      resource: 'settings',
      action: 'update',
      description: 'Modify system settings',
      riskLevel: 'critical',
      requiresMFA: true,
      defaultRoles: ['owner'],
      departmentTypes: ['it', 'executive'],
    });

    this.register({
      capability: 'system.users.delete',
      module: 'system',
      resource: 'users',
      action: 'delete',
      description: 'Delete user accounts',
      riskLevel: 'critical',
      requiresMFA: true,
      requiresApproval: true,
      defaultRoles: ['owner'],
      departmentTypes: ['it', 'hr'],
    });

    // Reports module
    this.register({
      capability: 'reports.financial.export',
      module: 'reports',
      resource: 'financial',
      action: 'export',
      description: 'Export financial reports',
      riskLevel: 'high',
      requiresMFA: true,
      defaultRoles: ['owner', 'director'],
      departmentTypes: ['finance', 'executive'],
    });

    this.register({
      capability: 'reports.analytics.read',
      module: 'reports',
      resource: 'analytics',
      action: 'read',
      description: 'View analytics reports',
      riskLevel: 'low',
      defaultRoles: ['owner', 'director', 'manager', 'employee'],
    });

    // Workflow module
    this.register({
      capability: 'workflow.approval.create',
      module: 'workflow',
      resource: 'approval',
      action: 'create',
      description: 'Create approval workflows',
      riskLevel: 'medium',
      defaultRoles: ['owner', 'director', 'manager'],
    });

    this.register({
      capability: 'workflow.task.approve',
      module: 'workflow',
      resource: 'task',
      action: 'approve',
      description: 'Approve workflow tasks',
      riskLevel: 'medium',
      defaultRoles: ['owner', 'director', 'manager'],
    });
  }

  /**
   * Export all capabilities (for documentation)
   */
  exportAll(): CapabilityDefinition[] {
    return Array.from(this.capabilities.values());
  }

  /**
   * Get capability statistics
   */
  getStatistics(): {
    totalCapabilities: number;
    byModule: Record<string, number>;
    byRiskLevel: Record<string, number>;
    requiresMFA: number;
    requiresApproval: number;
  } {
    const stats = {
      totalCapabilities: this.capabilities.size,
      byModule: {} as Record<string, number>,
      byRiskLevel: {
        low: 0,
        medium: 0,
        high: 0,
        critical: 0,
      },
      requiresMFA: 0,
      requiresApproval: 0,
    };

    this.capabilities.forEach((def) => {
      // By module
      if (!stats.byModule[def.module]) {
        stats.byModule[def.module] = 0;
      }
      stats.byModule[def.module]++;

      // By risk level
      stats.byRiskLevel[def.riskLevel]++;

      // MFA/Approval requirements
      if (def.requiresMFA) stats.requiresMFA++;
      if (def.requiresApproval) stats.requiresApproval++;
    });

    return stats;
  }
}

// Singleton instance
export const capabilityRegistry = new CapabilityRegistry();