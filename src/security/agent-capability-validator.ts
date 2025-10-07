/**
 * AI Agent Capability Validator - OWASP 2025 Compliant
 * Prevents AI Agent Privilege Escalation (CVSS 7.2)
 *
 * Security Features:
 * - Capability-based access control for AI agents
 * - Business-specific permission boundaries
 * - Agent action audit trail
 * - Resource access limitations
 * - Cross-business isolation enforcement
 */

import { SecurityError } from '../shared/errors/app-error';
import { createLogger } from '../utils/logger';
import type { D1Database } from '@cloudflare/workers-types';

const logger = createLogger('agent-capability-validator');

export interface AgentCapability {
  id: string;
  name: string;
  description: string;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  requiresApproval: boolean;
  resourceAccess: string[];
  dataScopes: string[];
}

export interface AgentPermission {
  agentId: string;
  businessId: string;
  capabilities: string[];
  restrictions: string[];
  maxResourceUsage: {
    apiCalls: number;
    dataRecords: number;
    computeTime: number; // ms
  };
  expiresAt?: number;
}

export interface AgentAction {
  id: string;
  agentId: string;
  businessId: string;
  action: string;
  capability: string;
  resources: string[];
  status: 'pending' | 'approved' | 'denied' | 'executed' | 'failed';
  executedAt?: number;
  executedBy?: string;
  result?: any;
  error?: string;
}

export class AgentCapabilityValidator {
  private static readonly CAPABILITIES: Map<string, AgentCapability> = new Map([
    ['read_leads', {
      id: 'read_leads',
      name: 'Read Leads',
      description: 'Read access to lead data',
      riskLevel: 'low',
      requiresApproval: false,
      resourceAccess: ['leads', 'contacts'],
      dataScopes: ['basic', 'contact_info']
    }],
    ['write_leads', {
      id: 'write_leads',
      name: 'Write Leads',
      description: 'Create and update lead data',
      riskLevel: 'medium',
      requiresApproval: false,
      resourceAccess: ['leads', 'contacts', 'activities'],
      dataScopes: ['basic', 'contact_info', 'activities']
    }],
    ['delete_leads', {
      id: 'delete_leads',
      name: 'Delete Leads',
      description: 'Delete lead records',
      riskLevel: 'high',
      requiresApproval: true,
      resourceAccess: ['leads'],
      dataScopes: ['deletion']
    }],
    ['execute_workflows', {
      id: 'execute_workflows',
      name: 'Execute Workflows',
      description: 'Run automated workflows',
      riskLevel: 'high',
      requiresApproval: true,
      resourceAccess: ['workflows', 'automations'],
      dataScopes: ['execution']
    }],
    ['access_financial', {
      id: 'access_financial',
      name: 'Access Financial Data',
      description: 'Read financial and payment information',
      riskLevel: 'critical',
      requiresApproval: true,
      resourceAccess: ['invoices', 'payments', 'transactions'],
      dataScopes: ['financial', 'sensitive']
    }],
    ['modify_financial', {
      id: 'modify_financial',
      name: 'Modify Financial Data',
      description: 'Create or update financial records',
      riskLevel: 'critical',
      requiresApproval: true,
      resourceAccess: ['invoices', 'payments', 'transactions'],
      dataScopes: ['financial', 'sensitive', 'modification']
    }],
    ['cross_business_read', {
      id: 'cross_business_read',
      name: 'Cross-Business Read',
      description: 'Read data across multiple businesses',
      riskLevel: 'critical',
      requiresApproval: true,
      resourceAccess: ['*'],
      dataScopes: ['cross_business']
    }],
    ['system_configuration', {
      id: 'system_configuration',
      name: 'System Configuration',
      description: 'Modify system settings',
      riskLevel: 'critical',
      requiresApproval: true,
      resourceAccess: ['settings', 'configuration'],
      dataScopes: ['system']
    }]
  ]);

  private permissions = new Map<string, AgentPermission>();
  private actionLog: AgentAction[] = [];

  constructor(
    private db: D1Database,
    private kvCache?: KVNamespace
  ) {}

  /**
   * Initialize agent permissions from database
   */
  async initialize(): Promise<void> {
    try {
      const result = await this.db.prepare(`
        SELECT * FROM agent_permissions
        WHERE expires_at IS NULL OR expires_at > ?
      `).bind(Date.now()).all();

      for (const row of result.results || []) {
        const permission = row as unknown as AgentPermission;
        const key = `${permission.agentId}:${permission.businessId}`;
        this.permissions.set(key, permission);
      }

      logger.info('Agent permissions loaded', {
        count: this.permissions.size
      });
    } catch (error) {
      logger.error('Failed to load agent permissions', { error });
    }
  }

  /**
   * Validate if an agent has a specific capability
   */
  async validateCapability(
    agentId: string,
    businessId: string,
    capability: string,
    context?: {
      resources?: string[];
      dataScope?: string;
      userId?: string;
    }
  ): Promise<{ allowed: boolean; reason?: string }> {
    // Check if capability exists
    const capabilityDef = AgentCapabilityValidator.CAPABILITIES.get(capability);
    if (!capabilityDef) {
      return {
        allowed: false,
        reason: `Unknown capability: ${capability}`
      };
    }

    // Get agent permissions
    const key = `${agentId}:${businessId}`;
    let permission = this.permissions.get(key);

    // Try to load from cache if not in memory
    if (!permission && this.kvCache) {
      const cached = await this.kvCache.get(`agent:permission:${key}`, 'json') as AgentPermission | null;
      if (cached) {
        permission = cached;
        this.permissions.set(key, cached);
      }
    }

    // Load from database if not cached
    if (!permission) {
      const result = await this.db.prepare(`
        SELECT * FROM agent_permissions
        WHERE agent_id = ? AND business_id = ?
        AND (expires_at IS NULL OR expires_at > ?)
      `).bind(agentId, businessId, Date.now()).first();

      if (result) {
        permission = result as unknown as AgentPermission;
        this.permissions.set(key, permission);

        // Cache for future use
        if (this.kvCache) {
          await this.kvCache.put(
            `agent:permission:${key}`,
            JSON.stringify(permission),
            { expirationTtl: 3600 } // 1 hour cache
          );
        }
      }
    }

    if (!permission) {
      return {
        allowed: false,
        reason: 'Agent has no permissions for this business'
      };
    }

    // Check if agent has the capability
    if (!permission.capabilities.includes(capability)) {
      return {
        allowed: false,
        reason: `Agent lacks capability: ${capability}`
      };
    }

    // Check restrictions
    if (permission.restrictions.includes(capability)) {
      return {
        allowed: false,
        reason: `Capability restricted: ${capability}`
      };
    }

    // Check resource access
    if (context?.resources) {
      const allowedResources = capabilityDef.resourceAccess;
      const unauthorizedResources = context.resources.filter(
        r => !allowedResources.includes(r) && !allowedResources.includes('*')
      );

      if (unauthorizedResources.length > 0) {
        return {
          allowed: false,
          reason: `Unauthorized resource access: ${unauthorizedResources.join(', ')}`
        };
      }
    }

    // Check if approval is required
    if (capabilityDef.requiresApproval) {
      const approvalStatus = await this.checkApproval(
        agentId,
        businessId,
        capability,
        context?.userId
      );

      if (!approvalStatus.approved) {
        return {
          allowed: false,
          reason: approvalStatus.reason || 'Approval required for this capability'
        };
      }
    }

    // Log the capability usage
    await this.logAgentAction({
      id: crypto.randomUUID(),
      agentId,
      businessId,
      action: 'capability_validated',
      capability,
      resources: context?.resources || [],
      status: 'approved',
      executedAt: Date.now(),
      executedBy: context?.userId
    });

    return { allowed: true };
  }

  /**
   * Check if an action requires approval
   */
  private async checkApproval(
    agentId: string,
    businessId: string,
    capability: string,
    userId?: string
  ): Promise<{ approved: boolean; reason?: string }> {
    // Check for pre-approved actions
    const result = await this.db.prepare(`
      SELECT * FROM agent_approvals
      WHERE agent_id = ? AND business_id = ? AND capability = ?
      AND status = 'approved'
      AND (expires_at IS NULL OR expires_at > ?)
      ORDER BY created_at DESC
      LIMIT 1
    `).bind(agentId, businessId, capability, Date.now()).first();

    if (result) {
      return { approved: true };
    }

    // Check if user has approval authority
    if (userId) {
      const userAuth = await this.db.prepare(`
        SELECT role FROM users
        WHERE id = ? AND business_id = ?
      `).bind(userId, businessId).first();

      if (userAuth && ['admin', 'owner'].includes((userAuth as any).role)) {
        // Auto-approve for admins
        await this.createApproval(agentId, businessId, capability, userId);
        return { approved: true };
      }
    }

    return {
      approved: false,
      reason: 'Pending approval from administrator'
    };
  }

  /**
   * Create an approval record
   */
  private async createApproval(
    agentId: string,
    businessId: string,
    capability: string,
    approvedBy: string
  ): Promise<void> {
    await this.db.prepare(`
      INSERT INTO agent_approvals (
        id, agent_id, business_id, capability, status,
        approved_by, created_at, expires_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      crypto.randomUUID(),
      agentId,
      businessId,
      capability,
      'approved',
      approvedBy,
      Date.now(),
      Date.now() + 86400000 // 24 hours
    ).run();
  }

  /**
   * Grant capability to an agent
   */
  async grantCapability(
    agentId: string,
    businessId: string,
    capability: string,
    grantedBy: string
  ): Promise<void> {
    const key = `${agentId}:${businessId}`;
    let permission = this.permissions.get(key);

    if (!permission) {
      // Create new permission
      permission = {
        agentId,
        businessId,
        capabilities: [capability],
        restrictions: [],
        maxResourceUsage: {
          apiCalls: 1000,
          dataRecords: 10000,
          computeTime: 60000
        }
      };
    } else if (!permission.capabilities.includes(capability)) {
      permission.capabilities.push(capability);
    }

    // Save to database
    await this.db.prepare(`
      INSERT OR REPLACE INTO agent_permissions (
        agent_id, business_id, capabilities, restrictions,
        max_api_calls, max_data_records, max_compute_time,
        granted_by, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      agentId,
      businessId,
      JSON.stringify(permission.capabilities),
      JSON.stringify(permission.restrictions),
      permission.maxResourceUsage.apiCalls,
      permission.maxResourceUsage.dataRecords,
      permission.maxResourceUsage.computeTime,
      grantedBy,
      Date.now()
    ).run();

    // Update cache
    this.permissions.set(key, permission);
    if (this.kvCache) {
      await this.kvCache.put(
        `agent:permission:${key}`,
        JSON.stringify(permission),
        { expirationTtl: 3600 }
      );
    }

    // Log the grant
    await this.logAgentAction({
      id: crypto.randomUUID(),
      agentId,
      businessId,
      action: 'capability_granted',
      capability,
      resources: [],
      status: 'executed',
      executedAt: Date.now(),
      executedBy: grantedBy
    });
  }

  /**
   * Revoke capability from an agent
   */
  async revokeCapability(
    agentId: string,
    businessId: string,
    capability: string,
    revokedBy: string
  ): Promise<void> {
    const key = `${agentId}:${businessId}`;
    const permission = this.permissions.get(key);

    if (!permission) {
      return;
    }

    // Remove capability
    permission.capabilities = permission.capabilities.filter(c => c !== capability);

    // Add to restrictions
    if (!permission.restrictions.includes(capability)) {
      permission.restrictions.push(capability);
    }

    // Save to database
    await this.db.prepare(`
      UPDATE agent_permissions
      SET capabilities = ?, restrictions = ?, updated_at = ?
      WHERE agent_id = ? AND business_id = ?
    `).bind(
      JSON.stringify(permission.capabilities),
      JSON.stringify(permission.restrictions),
      Date.now(),
      agentId,
      businessId
    ).run();

    // Update cache
    this.permissions.set(key, permission);
    if (this.kvCache) {
      await this.kvCache.put(
        `agent:permission:${key}`,
        JSON.stringify(permission),
        { expirationTtl: 3600 }
      );
    }

    // Log the revocation
    await this.logAgentAction({
      id: crypto.randomUUID(),
      agentId,
      businessId,
      action: 'capability_revoked',
      capability,
      resources: [],
      status: 'executed',
      executedAt: Date.now(),
      executedBy: revokedBy
    });
  }

  /**
   * Log agent actions for audit trail
   */
  async logAgentAction(action: AgentAction): Promise<void> {
    try {
      // Save to database
      await this.db.prepare(`
        INSERT INTO agent_audit_log (
          id, agent_id, business_id, action, capability,
          resources, status, executed_at, executed_by,
          result, error
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        action.id,
        action.agentId,
        action.businessId,
        action.action,
        action.capability,
        JSON.stringify(action.resources),
        action.status,
        action.executedAt || Date.now(),
        action.executedBy || 'system',
        action.result ? JSON.stringify(action.result) : null,
        action.error || null
      ).run();

      // Keep recent actions in memory for quick access
      this.actionLog.push(action);
      if (this.actionLog.length > 1000) {
        this.actionLog = this.actionLog.slice(-500); // Keep last 500
      }

      logger.info('Agent action logged', {
        agentId: action.agentId,
        action: action.action,
        capability: action.capability,
        status: action.status
      });
    } catch (error) {
      logger.error('Failed to log agent action', { error, action });
    }
  }

  /**
   * Get agent audit trail
   */
  async getAuditTrail(
    agentId: string,
    businessId: string,
    limit = 100
  ): Promise<AgentAction[]> {
    const result = await this.db.prepare(`
      SELECT * FROM agent_audit_log
      WHERE agent_id = ? AND business_id = ?
      ORDER BY executed_at DESC
      LIMIT ?
    `).bind(agentId, businessId, limit).all();

    return (result.results || []).map(row => ({
      ...row,
      resources: JSON.parse((row as any).resources || '[]'),
      result: (row as any).result ? JSON.parse((row as any).result) : undefined
    })) as AgentAction[];
  }

  /**
   * Check resource usage limits
   */
  async checkResourceLimits(
    agentId: string,
    businessId: string,
    resourceType: 'apiCalls' | 'dataRecords' | 'computeTime',
    amount: number
  ): Promise<{ allowed: boolean; remaining?: number; reason?: string }> {
    const key = `${agentId}:${businessId}`;
    const permission = this.permissions.get(key);

    if (!permission) {
      return {
        allowed: false,
        reason: 'No permission found'
      };
    }

    // Get current usage from database
    const timeWindow = Date.now() - 3600000; // Last hour
    const usage = await this.db.prepare(`
      SELECT
        COUNT(*) as api_calls,
        SUM(data_records) as data_records,
        SUM(compute_time) as compute_time
      FROM agent_resource_usage
      WHERE agent_id = ? AND business_id = ? AND timestamp > ?
    `).bind(agentId, businessId, timeWindow).first();

    const currentUsage = (usage as any)?.[resourceType] || 0;
    const limit = permission.maxResourceUsage[resourceType];
    const newUsage = currentUsage + amount;

    if (newUsage > limit) {
      return {
        allowed: false,
        remaining: Math.max(0, limit - currentUsage),
        reason: `Resource limit exceeded: ${resourceType}`
      };
    }

    // Record usage
    await this.db.prepare(`
      INSERT INTO agent_resource_usage (
        id, agent_id, business_id, api_calls, data_records,
        compute_time, timestamp
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      crypto.randomUUID(),
      agentId,
      businessId,
      resourceType === 'apiCalls' ? amount : 0,
      resourceType === 'dataRecords' ? amount : 0,
      resourceType === 'computeTime' ? amount : 0,
      Date.now()
    ).run();

    return {
      allowed: true,
      remaining: limit - newUsage
    };
  }
}

/**
 * Create capability validator instance
 */
export function createAgentCapabilityValidator(
  db: D1Database,
  kvCache?: KVNamespace
): AgentCapabilityValidator {
  return new AgentCapabilityValidator(db, kvCache);
}