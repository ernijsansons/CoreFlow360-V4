/**
 * Attribute-Based Access Control (ABAC) Middleware
 * Advanced authorization system for CoreFlow360 V4
 */
import { Logger } from '../shared/logger';
import type { Context } from 'hono';
import type { Env } from '../types/env';

interface Subject {
  id: string;
  type: 'user' | 'service' | 'system';
  attributes: Map<string, any>;
  roles: string[];
  permissions: string[];
}

interface Resource {
  id: string;
  type: string;
  attributes: Map<string, any>;
  businessId: string;
  ownerId?: string;
}

interface Action {
  name: string;
  type: 'read' | 'write' | 'delete' | 'execute' | 'admin';
  resource: string;
  conditions?: Map<string, any>;
}

interface Environment {
  time: Date;
  location?: string;
  ipAddress?: string;
  userAgent?: string;
  businessId: string;
  context: Map<string, any>;
}

interface Policy {
  id: string;
  name: string;
  description: string;
  effect: 'allow' | 'deny';
  priority: number;
  subjects: SubjectRule[];
  resources: ResourceRule[];
  actions: ActionRule[];
  conditions: ConditionRule[];
  obligations: Obligation[];
}

interface SubjectRule {
  type: 'user' | 'role' | 'group' | 'service';
  value: string;
  attributes?: Map<string, any>;
}

interface ResourceRule {
  type: string;
  pattern: string;
  attributes?: Map<string, any>;
}

interface ActionRule {
  name: string;
  type: string;
  conditions?: Map<string, any>;
}

interface ConditionRule {
  attribute: string;
  operator: 'equals' | 'not_equals' | 'contains' | 'starts_with' | 'ends_with' | 'in' | 'not_in' | 'greater_than' | 'less_than' | 'between';
  value: any;
  required: boolean;
}

interface Obligation {
  type: 'log' | 'notify' | 'audit' | 'transform';
  action: string;
  parameters: Map<string, any>;
}

interface Decision {
  effect: 'allow' | 'deny' | 'indeterminate' | 'not_applicable';
  reason: string;
  policies: string[];
  obligations: Obligation[];
  confidence: number;
  timestamp: Date;
}

export class ABACMiddleware {
  private logger: Logger;
  private policies: Map<string, Policy> = new Map();
  private cache: Map<string, Decision> = new Map();
  private cacheTimeout: number = 5 * 60 * 1000; // 5 minutes

  constructor(private readonly context: Context) {
    this.logger = new Logger({ component: 'abac-middleware' });
    this.initializeDefaultPolicies();
  }

  async authorize(
    subject: Subject,
    action: Action,
    resource: Resource,
    environment: Environment
  ): Promise<Decision> {
    const cacheKey = this.generateCacheKey(subject, action, resource, environment);
    
    // Check cache first
    const cachedDecision = this.cache.get(cacheKey);
    if (cachedDecision && this.isCacheValid(cachedDecision)) {
      this.logger.debug('Using cached authorization decision', { cacheKey });
      return cachedDecision;
    }

    this.logger.info('Evaluating authorization request', {
      subject: subject.id,
      action: action.name,
      resource: resource.id,
      businessId: environment.businessId
    });

    const decision = await this.evaluatePolicies(subject, action, resource, environment);
    
    // Cache the decision
    this.cache.set(cacheKey, decision);
    
    // Log the decision
    await this.logDecision(decision, subject, action, resource, environment);

    return decision;
  }

  private async evaluatePolicies(
    subject: Subject,
    action: Action,
    resource: Resource,
    environment: Environment
  ): Promise<Decision> {
    const applicablePolicies = this.findApplicablePolicies(subject, action, resource, environment);
    
    if (applicablePolicies.length === 0) {
      return {
        effect: 'not_applicable',
        reason: 'No applicable policies found',
        policies: [],
        obligations: [],
        confidence: 1.0,
        timestamp: new Date()
      };
    }

    // Sort policies by priority (higher priority first)
    applicablePolicies.sort((a, b) => b.priority - a.priority);

    let allowCount = 0;
    let denyCount = 0;
    const matchedPolicies: string[] = [];
    const obligations: Obligation[] = [];

    for (const policy of applicablePolicies) {
      const matches = await this.evaluatePolicy(policy, subject, action, resource, environment);
      
      if (matches) {
        matchedPolicies.push(policy.id);
        
        if (policy.effect === 'allow') {
          allowCount++;
        } else {
          denyCount++;
        }
        
        obligations.push(...policy.obligations);
      }
    }

    // Determine final decision
    let effect: 'allow' | 'deny' | 'indeterminate';
    let reason: string;

    if (denyCount > 0) {
      effect = 'deny';
      reason = `Denied by ${denyCount} policy(ies)`;
    } else if (allowCount > 0) {
      effect = 'allow';
      reason = `Allowed by ${allowCount} policy(ies)`;
    } else {
      effect = 'indeterminate';
      reason = 'No policies matched';
    }

    return {
      effect,
      reason,
      policies: matchedPolicies,
      obligations,
      confidence: this.calculateConfidence(allowCount, denyCount, applicablePolicies.length),
      timestamp: new Date()
    };
  }

  private findApplicablePolicies(
    subject: Subject,
    action: Action,
    resource: Resource,
    environment: Environment
  ): Policy[] {
    const applicable: Policy[] = [];

    for (const policy of this.policies.values()) {
      if (this.isPolicyApplicable(policy, subject, action, resource, environment)) {
        applicable.push(policy);
      }
    }

    return applicable;
  }

  private isPolicyApplicable(
    policy: Policy,
    subject: Subject,
    action: Action,
    resource: Resource,
    environment: Environment
  ): boolean {
    // Check subject rules
    if (!this.matchesSubjectRules(policy.subjects, subject)) {
      return false;
    }

    // Check resource rules
    if (!this.matchesResourceRules(policy.resources, resource)) {
      return false;
    }

    // Check action rules
    if (!this.matchesActionRules(policy.actions, action)) {
      return false;
    }

    return true;
  }

  private matchesSubjectRules(rules: SubjectRule[], subject: Subject): boolean {
    if (rules.length === 0) return true;

    for (const rule of rules) {
      if (this.matchesSubjectRule(rule, subject)) {
        return true;
      }
    }

    return false;
  }

  private matchesSubjectRule(rule: SubjectRule, subject: Subject): boolean {
    switch (rule.type) {
      case 'user':
        return subject.id === rule.value;
      case 'role':
        return subject.roles.includes(rule.value);
      case 'group':
        return subject.attributes.get('group') === rule.value;
      case 'service':
        return subject.type === 'service' && subject.id === rule.value;
      default:
        return false;
    }
  }

  private matchesResourceRules(rules: ResourceRule[], resource: Resource): boolean {
    if (rules.length === 0) return true;

    for (const rule of rules) {
      if (this.matchesResourceRule(rule, resource)) {
        return true;
      }
    }

    return false;
  }

  private matchesResourceRule(rule: ResourceRule, resource: Resource): boolean {
    if (resource.type !== rule.type) return false;
    
    if (rule.pattern !== '*' && !this.matchesPattern(resource.id, rule.pattern)) {
      return false;
    }

    if (rule.attributes) {
      for (const [key, value] of rule.attributes) {
        if (resource.attributes.get(key) !== value) {
          return false;
        }
      }
    }

    return true;
  }

  private matchesActionRules(rules: ActionRule[], action: Action): boolean {
    if (rules.length === 0) return true;

    for (const rule of rules) {
      if (this.matchesActionRule(rule, action)) {
        return true;
      }
    }

    return false;
  }

  private matchesActionRule(rule: ActionRule, action: Action): boolean {
    if (action.name !== rule.name && rule.name !== '*') return false;
    if (action.type !== rule.type && rule.type !== '*') return false;

    if (rule.conditions) {
      for (const [key, value] of rule.conditions) {
        if (action.conditions?.get(key) !== value) {
          return false;
        }
      }
    }

    return true;
  }

  private async evaluatePolicy(
    policy: Policy,
    subject: Subject,
    action: Action,
    resource: Resource,
    environment: Environment
  ): Promise<boolean> {
    // Check conditions
    for (const condition of policy.conditions) {
      if (!this.evaluateCondition(condition, subject, action, resource, environment)) {
        if (condition.required) {
          return false;
        }
      }
    }

    return true;
  }

  private evaluateCondition(
    condition: ConditionRule,
    subject: Subject,
    action: Action,
    resource: Resource,
    environment: Environment
  ): boolean {
    let attributeValue: any;

    // Get attribute value based on source
    if (condition.attribute.startsWith('subject.')) {
      const attr = condition.attribute.substring(8);
      attributeValue = subject.attributes.get(attr);
    } else if (condition.attribute.startsWith('resource.')) {
      const attr = condition.attribute.substring(9);
      attributeValue = resource.attributes.get(attr);
    } else if (condition.attribute.startsWith('environment.')) {
      const attr = condition.attribute.substring(12);
      attributeValue = environment.context.get(attr);
    } else {
      // Default to subject attributes
      attributeValue = subject.attributes.get(condition.attribute);
    }

    return this.compareValues(attributeValue, condition.operator, condition.value);
  }

  private compareValues(actual: any, operator: string, expected: any): boolean {
    switch (operator) {
      case 'equals':
        return actual === expected;
      case 'not_equals':
        return actual !== expected;
      case 'contains':
        return String(actual).includes(String(expected));
      case 'starts_with':
        return String(actual).startsWith(String(expected));
      case 'ends_with':
        return String(actual).endsWith(String(expected));
      case 'in':
        return Array.isArray(expected) && expected.includes(actual);
      case 'not_in':
        return Array.isArray(expected) && !expected.includes(actual);
      case 'greater_than':
        return Number(actual) > Number(expected);
      case 'less_than':
        return Number(actual) < Number(expected);
      case 'between':
        return Array.isArray(expected) && expected.length === 2 &&
               Number(actual) >= Number(expected[0]) && Number(actual) <= Number(expected[1]);
      default:
        return false;
    }
  }

  private matchesPattern(value: string, pattern: string): boolean {
    // Simple pattern matching - in production, use proper regex or glob patterns
    if (pattern === '*') return true;
    if (pattern.includes('*')) {
      const regex = new RegExp(pattern.replace(/\*/g, '.*'));
      return regex.test(value);
    }
    return value === pattern;
  }

  private calculateConfidence(allowCount: number, denyCount: number, totalPolicies: number): number {
    if (totalPolicies === 0) return 0;
    
    const totalMatches = allowCount + denyCount;
    if (totalMatches === 0) return 0;
    
    return Math.min(1, totalMatches / totalPolicies);
  }

  private generateCacheKey(
    subject: Subject,
    action: Action,
    resource: Resource,
    environment: Environment
  ): string {
    return `${subject.id}:${action.name}:${resource.id}:${environment.businessId}`;
  }

  private isCacheValid(decision: Decision): boolean {
    const age = Date.now() - decision.timestamp.getTime();
    return age < this.cacheTimeout;
  }

  private async logDecision(
    decision: Decision,
    subject: Subject,
    action: Action,
    resource: Resource,
    environment: Environment
  ): Promise<void> {
    this.logger.info('Authorization decision', {
      effect: decision.effect,
      reason: decision.reason,
      subject: subject.id,
      action: action.name,
      resource: resource.id,
      businessId: environment.businessId,
      policies: decision.policies,
      confidence: decision.confidence
    });
  }

  private initializeDefaultPolicies(): void {
    // Admin access policy
    this.addPolicy({
      id: 'admin_full_access',
      name: 'Admin Full Access',
      description: 'Full access for admin users',
      effect: 'allow',
      priority: 100,
      subjects: [{ type: 'role', value: 'admin' }],
      resources: [{ type: '*', pattern: '*' }],
      actions: [{ name: '*', type: '*' }],
      conditions: [],
      obligations: []
    });

    // Business isolation policy
    this.addPolicy({
      id: 'business_isolation',
      name: 'Business Data Isolation',
      description: 'Users can only access data from their business',
      effect: 'allow',
      priority: 90,
      subjects: [{ type: 'user', value: '*' }],
      resources: [{ type: '*', pattern: '*' }],
      actions: [{ name: '*', type: '*' }],
      conditions: [
        {
          attribute: 'subject.businessId',
          operator: 'equals',
          value: 'resource.businessId',
          required: true
        }
      ],
      obligations: []
    });

    // Read-only access for employees
    this.addPolicy({
      id: 'employee_read_only',
      name: 'Employee Read-Only Access',
      description: 'Employees have read-only access to most resources',
      effect: 'allow',
      priority: 50,
      subjects: [{ type: 'role', value: 'employee' }],
      resources: [{ type: '*', pattern: '*' }],
      actions: [{ name: 'read', type: 'read' }],
      conditions: [],
      obligations: []
    });

    // Manager write access
    this.addPolicy({
      id: 'manager_write_access',
      name: 'Manager Write Access',
      description: 'Managers can write to most resources',
      effect: 'allow',
      priority: 60,
      subjects: [{ type: 'role', value: 'manager' }],
      resources: [{ type: '*', pattern: '*' }],
      actions: [{ name: '*', type: 'write' }],
      conditions: [],
      obligations: []
    });

    // Deny access to sensitive resources for non-admin users
    this.addPolicy({
      id: 'deny_sensitive_resources',
      name: 'Deny Sensitive Resources',
      description: 'Deny access to sensitive resources for non-admin users',
      effect: 'deny',
      priority: 80,
      subjects: [{ type: 'role', value: 'employee' }],
      resources: [{ type: 'audit_logs', pattern: '*' }],
      actions: [{ name: '*', type: '*' }],
      conditions: [],
      obligations: []
    });
  }

  addPolicy(policy: Policy): void {
    this.policies.set(policy.id, policy);
    this.logger.info('Policy added', { policyId: policy.id, policyName: policy.name });
  }

  removePolicy(policyId: string): boolean {
    const removed = this.policies.delete(policyId);
    if (removed) {
      this.logger.info('Policy removed', { policyId });
    }
    return removed;
  }

  updatePolicy(policyId: string, updates: Partial<Policy>): boolean {
    const policy = this.policies.get(policyId);
    if (!policy) return false;

    const updatedPolicy = { ...policy, ...updates };
    this.policies.set(policyId, updatedPolicy);
    this.logger.info('Policy updated', { policyId });
    return true;
  }

  getPolicy(policyId: string): Policy | undefined {
    return this.policies.get(policyId);
  }

  getAllPolicies(): Policy[] {
    return Array.from(this.policies.values());
  }

  clearCache(): void {
    this.cache.clear();
    this.logger.info('Authorization cache cleared');
  }

  getCacheStats(): { size: number; hitRate: number } {
    return {
      size: this.cache.size,
      hitRate: 0.85 // Mock hit rate
    };
  }
}

