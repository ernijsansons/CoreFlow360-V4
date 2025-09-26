import type {
  Subject,
  Resource,
  Capability,
  PolicyRule,
  EvaluationResult,
  SubjectCondition,
  ResourceCondition,
  ContextCondition,
} from './types';

/**
 * Policy-based evaluation engine for complex ABAC rules
 * Used when fast-path evaluation doesn't apply
 */
export class PolicyEvaluator {
  private policies: Map<string, PolicyRule> = new Map();
  private policyIndex: {
    byCapability: Map<Capability, Set<string>>;
    bySubjectRole: Map<string, Set<string>>;
    byResourceType: Map<string, Set<string>>;
  } = {
    byCapability: new Map(),
    bySubjectRole: new Map(),
    byResourceType: new Map(),
  };

  constructor(policies: PolicyRule[] = []) {
    this.loadPolicies(policies);
  }

  /**
   * Evaluate capability against all applicable policies
   */
  async evaluate(
    subject: Subject,
    capability: Capability,
    resource?: Resource
  ): Promise<EvaluationResult> {
    const startTime = performance.now();
    const applicablePolicies = this.getApplicablePolicies(capability, subject, resource);

    // Sort by priority (lower number = higher priority)
    const sortedPolicies = Array.from(applicablePolicies)
      .map(id => this.policies.get(id)!)
      .sort((a, b) => a.priority - b.priority);

    const matched: PolicyRule[] = [];
    const denied: PolicyRule[] = [];
    let finalResult = false;
    let constraints: any = {};

    // Evaluate each policy in priority order
    for (const policy of sortedPolicies) {
      const result = await this.evaluatePolicy(policy, subject, capability, resource);

      if (result.matches) {
        if (policy.effect === 'allow') {
          matched.push(policy);
          finalResult = true;

          // Merge constraints
          if (policy.constraints) {
            constraints = this.mergeConstraints(constraints, policy.constraints);
          }
        } else if (policy.effect === 'deny') {
          denied.push(policy);
          finalResult = false;
          // Deny policies override allow policies regardless of priority
          break;
        }
      }
    }

    // Apply final constraint checks
    if (finalResult && resource) {
      finalResult = this.checkFinalConstraints(constraints, subject, resource);
    }

    const evaluationTime = performance.now() - startTime;

    return {
      allowed: finalResult,
      matched,
      denied,
      evaluationTimeMs: evaluationTime,
      cacheHit: false,
      fastPath: 'policy',
      reason: this.generateReason(finalResult, matched, denied),
      constraints: Object.keys(constraints).length > 0 ? constraints : undefined,
    };
  }

  /**
   * Load and index policies
   */
  loadPolicies(policies: PolicyRule[]): void {
    this.policies.clear();
    this.clearIndexes();

    policies.forEach(policy => {
      this.policies.set(policy.id, policy);
      this.indexPolicy(policy);
    });

  }

  /**
   * Add a single policy
   */
  addPolicy(policy: PolicyRule): void {
    this.policies.set(policy.id, policy);
    this.indexPolicy(policy);
  }

  /**
   * Remove a policy
   */
  removePolicy(policyId: string): boolean {
    const policy = this.policies.get(policyId);
    if (!policy) return false;

    this.policies.delete(policyId);
    this.removeFromIndexes(policy);
    return true;
  }

  /**
   * Get applicable policies for evaluation
   */
  private getApplicablePolicies(
    capability: Capability,
    subject: Subject,
    resource?: Resource
  ): Set<string> {
    const applicable = new Set<string>();

    // Get policies by capability
    const capabilityPolicies = this.policyIndex.byCapability.get(capability) || new Set();
    capabilityPolicies.forEach(id => applicable.add(id));

    // Get wildcard capability policies
    const wildcardPolicies = this.policyIndex.byCapability.get('*.*.*') || new Set();
    wildcardPolicies.forEach(id => applicable.add(id));

    // Get policies by subject role
    const rolePolicies = this.policyIndex.bySubjectRole.get(subject.orgRole) || new Set();
    rolePolicies.forEach(id => applicable.add(id));

    // Get policies by resource type
    if (resource) {
      const resourcePolicies = this.policyIndex.byResourceType.get(resource.type) || new Set();
      resourcePolicies.forEach(id => applicable.add(id));
    }

    // If no specific matches, get all policies (fallback)
    if (applicable.size === 0) {
      this.policies.forEach((_, id) => applicable.add(id));
    }

    return applicable;
  }

  /**
   * Evaluate a single policy against subject/resource/context
   */
  private async evaluatePolicy(
    policy: PolicyRule,
    subject: Subject,
    capability: Capability,
    resource?: Resource
  ): Promise<{ matches: boolean; reason?: string }> {
    // Check if capability is covered by this policy
    if (!this.capabilityMatches(capability, policy.capabilities)) {
      return { matches: false, reason: 'Capability not covered' };
    }

    // Evaluate subject conditions
    if (policy.conditions.subject) {
      const subjectMatch = this.evaluateSubjectCondition(
        policy.conditions.subject,
        subject
      );
      if (!subjectMatch.matches) {
        return { matches: false, reason: `Subject: ${subjectMatch.reason}` };
      }
    }

    // Evaluate resource conditions
    if (policy.conditions.resource && resource) {
      const resourceMatch = this.evaluateResourceCondition(
        policy.conditions.resource,
        resource
      );
      if (!resourceMatch.matches) {
        return { matches: false, reason: `Resource: ${resourceMatch.reason}` };
      }
    }

    // Evaluate context conditions
    if (policy.conditions.context) {
      const contextMatch = this.evaluateContextCondition(
        policy.conditions.context,
        subject.context
      );
      if (!contextMatch.matches) {
        return { matches: false, reason: `Context: ${contextMatch.reason}` };
      }
    }

    return { matches: true };
  }

  /**
   * Check if capability matches policy capabilities
   */
  private capabilityMatches(capability: Capability, policyCapabilities: Capability[]): boolean {
    return policyCapabilities.some(policyCap => {
      if (policyCap === '*.*.*') return true;
      if (policyCap === capability) return true;

      // Pattern matching
      const capParts = capability.split('.');
      const policyParts = policyCap.split('.');

      if (capParts.length !== 3 || policyParts.length !== 3) return false;

      return capParts.every((part, index) => {
        return policyParts[index] === '*' || policyParts[index] === part;
      });
    });
  }

  /**
   * Evaluate subject condition
   */
  private evaluateSubjectCondition(
    condition: SubjectCondition,
    subject: Subject
  ): { matches: boolean; reason?: string } {
    // Check organization role
    if (condition.orgRole) {
      const roles = Array.isArray(condition.orgRole) ? condition.orgRole : [condition.orgRole];
      if (!roles.includes(subject.orgRole)) {
        return { matches: false, reason: `Role ${subject.orgRole} not in ${roles.join(', ')}` };
      }
    }

    // Check department role
    if (condition.deptRole) {
      const requiredRoles = Array.isArray(condition.deptRole) ? condition.deptRole : [condition.deptRole];
      const hasRequiredRole = subject.deptRoles.some(deptRole =>
        requiredRoles.includes(deptRole.role)
      );
      if (!hasRequiredRole) {
        return { matches: false, reason: `No required department role: ${requiredRoles.join(', ')}` };
      }
    }

    // Check custom attributes
    if (condition.attributes) {
      for (const [key, value] of Object.entries(condition.attributes)) {
        if (!this.attributeMatches((subject.attributes as any)[key], value)) {
          return { matches: false, reason: `Attribute ${key} does not match` };
        }
      }
    }

    return { matches: true };
  }

  /**
   * Evaluate resource condition
   */
  private evaluateResourceCondition(
    condition: ResourceCondition,
    resource: Resource
  ): { matches: boolean; reason?: string } {
    // Check resource type
    if (condition.type) {
      const types = Array.isArray(condition.type) ? condition.type : [condition.type];
      if (!types.includes(resource.type)) {
        return { matches: false, reason: `Type ${resource.type} not in ${types.join(', ')}` };
      }
    }

    // Check resource attributes
    if (condition.attributes) {
      for (const [key, value] of Object.entries(condition.attributes)) {
        if (!this.attributeMatches(resource.attributes[key], value)) {
          return { matches: false, reason: `Resource attribute ${key} does not match` };
        }
      }
    }

    return { matches: true };
  }

  /**
   * Evaluate context condition
   */
  private evaluateContextCondition(
    condition: ContextCondition,
    context: Subject['context']
  ): { matches: boolean; reason?: string } {
    // Check IP range
    if (condition.ipRange && condition.ipRange.length > 0) {
      const clientIp = context.ipAddress;
      const inRange = condition.ipRange.some(range =>
        this.ipInRange(clientIp, range)
      );
      if (!inRange) {
        return { matches: false, reason: `IP ${clientIp} not in allowed ranges` };
      }
    }

    // Check time range
    if (condition.timeRange) {
      const now = new Date();
      const currentTime = now.getHours() * 60 + now.getMinutes();

      const [startHour, startMin] = condition.timeRange.start.split(':').map(Number);
      const [endHour, endMin] = condition.timeRange.end.split(':').map(Number);
      const startTime = startHour * 60 + startMin;
      const endTime = endHour * 60 + endMin;

      if (currentTime < startTime || currentTime > endTime) {
        return { matches: false, reason: `Current time outside allowed window` };
      }
    }

    // Check location
    if (condition.location && condition.location.length > 0) {
      const userLocation = context.location;
      if (!userLocation || !condition.location.includes(userLocation)) {
        return { matches: false, reason: `Location ${userLocation} not allowed` };
      }
    }

    return { matches: true };
  }

  /**
   * Check if attribute value matches condition
   */
  private attributeMatches(actualValue: any, conditionValue: any): boolean {
    if (actualValue === conditionValue) return true;

    // Array inclusion check
    if (Array.isArray(conditionValue)) {
      return conditionValue.includes(actualValue);
    }

    // Object comparison for complex attributes
    if (typeof conditionValue === 'object' && conditionValue !== null) {
      if (conditionValue.operator) {
        return this.evaluateOperatorCondition(actualValue, conditionValue);
      }
    }

    return false;
  }

  /**
   * Evaluate operator-based conditions (gt, lt, eq, etc.)
   */
  private evaluateOperatorCondition(actualValue: any, condition: any): boolean {
    switch (condition.operator) {
      case 'eq':
        return actualValue === condition.value;
      case 'ne':
        return actualValue !== condition.value;
      case 'gt':
        return actualValue > condition.value;
      case 'gte':
        return actualValue >= condition.value;
      case 'lt':
        return actualValue < condition.value;
      case 'lte':
        return actualValue <= condition.value;
      case 'in':
        return Array.isArray(condition.value) && condition.value.includes(actualValue);
      case 'contains':
        return String(actualValue).includes(condition.value);
      case 'startsWith':
        return String(actualValue).startsWith(condition.value);
      case 'endsWith':
        return String(actualValue).endsWith(condition.value);
      default:
        return false;
    }
  }

  /**
   * Check if IP is in range (simple CIDR check)
   */
  private ipInRange(ip: string, range: string): boolean {
    if (range === '*' || range === '0.0.0.0/0') return true;
    if (ip === range) return true;

    // Basic CIDR matching - in production, use a proper IP library
    if (range.includes('/')) {
      const [rangeIp, prefixLength] = range.split('/');
      // Simplified check - implement proper CIDR matching in production
      return ip.startsWith(rangeIp.split('.').slice(0, Math.floor(parseInt(prefixLength) / 8)).join('.'));
    }

    return false;
  }

  /**
   * Merge constraints from multiple policies
   */
  private mergeConstraints(existing: any, newConstraints: any): any {
    const merged = { ...existing };

    // Take the most restrictive constraints
    if (newConstraints.maxAmount !== undefined) {
      merged.maxAmount = Math.min(
        merged.maxAmount ?? Infinity,
        newConstraints.maxAmount
      );
    }

    if (newConstraints.timeWindow) {
      merged.timeWindow = newConstraints.timeWindow;
    }

    if (newConstraints.requireMFA) {
      merged.requireMFA = true;
    }

    if (newConstraints.requireApproval) {
      merged.requireApproval = true;
    }

    return merged;
  }

  /**
   * Check final constraints against subject and resource
   */
  private checkFinalConstraints(
    constraints: any,
    subject: Subject,
    resource: Resource
  ): boolean {
    // MFA requirement
    if (constraints.requireMFA && !subject.attributes.mfaEnabled) {
      return false;
    }

    // Amount constraints
    if (constraints.maxAmount && resource.attributes.amount) {
      if (resource.attributes.amount > constraints.maxAmount) {
        return false;
      }
    }

    // Additional constraint checks can be added here

    return true;
  }

  /**
   * Generate human-readable reason for the decision
   */
  private generateReason(
    allowed: boolean,
    matched: PolicyRule[],
    denied: PolicyRule[]
  ): string {
    if (denied.length > 0) {
      return `Denied by policy: ${denied[0].name}`;
    }

    if (matched.length > 0) {
      return `Allowed by policy: ${matched.map(p => p.name).join(', ')}`;
    }

    return allowed ? 'Allowed by default' : 'No matching policy found';
  }

  /**
   * Index policy for faster lookups
   */
  private indexPolicy(policy: PolicyRule): void {
    // Index by capabilities
    policy.capabilities.forEach(capability => {
      if (!this.policyIndex.byCapability.has(capability)) {
        this.policyIndex.byCapability.set(capability, new Set());
      }
      this.policyIndex.byCapability.get(capability)!.add(policy.id);
    });

    // Index by subject role conditions
    if (policy.conditions.subject?.orgRole) {
      const roles = Array.isArray(policy.conditions.subject.orgRole)
        ? policy.conditions.subject.orgRole
        : [policy.conditions.subject.orgRole];

      roles.forEach(role => {
        if (!this.policyIndex.bySubjectRole.has(role)) {
          this.policyIndex.bySubjectRole.set(role, new Set());
        }
        this.policyIndex.bySubjectRole.get(role)!.add(policy.id);
      });
    }

    // Index by resource type conditions
    if (policy.conditions.resource?.type) {
      const types = Array.isArray(policy.conditions.resource.type)
        ? policy.conditions.resource.type
        : [policy.conditions.resource.type];

      types.forEach(type => {
        if (!this.policyIndex.byResourceType.has(type)) {
          this.policyIndex.byResourceType.set(type, new Set());
        }
        this.policyIndex.byResourceType.get(type)!.add(policy.id);
      });
    }
  }

  /**
   * Remove policy from indexes
   */
  private removeFromIndexes(policy: PolicyRule): void {
    // Remove from capability index
    policy.capabilities.forEach(capability => {
      this.policyIndex.byCapability.get(capability)?.delete(policy.id);
    });

    // Remove from subject role index
    if (policy.conditions.subject?.orgRole) {
      const roles = Array.isArray(policy.conditions.subject.orgRole)
        ? policy.conditions.subject.orgRole
        : [policy.conditions.subject.orgRole];

      roles.forEach(role => {
        this.policyIndex.bySubjectRole.get(role)?.delete(policy.id);
      });
    }

    // Remove from resource type index
    if (policy.conditions.resource?.type) {
      const types = Array.isArray(policy.conditions.resource.type)
        ? policy.conditions.resource.type
        : [policy.conditions.resource.type];

      types.forEach(type => {
        this.policyIndex.byResourceType.get(type)?.delete(policy.id);
      });
    }
  }

  /**
   * Clear all indexes
   */
  private clearIndexes(): void {
    this.policyIndex.byCapability.clear();
    this.policyIndex.bySubjectRole.clear();
    this.policyIndex.byResourceType.clear();
  }

  /**
   * Get policy statistics
   */
  getStatistics(): {
    totalPolicies: number;
    allowPolicies: number;
    denyPolicies: number;
    capabilityIndex: number;
    subjectRoleIndex: number;
    resourceTypeIndex: number;
  } {
    let allowCount = 0;
    let denyCount = 0;

    this.policies.forEach(policy => {
      if (policy.effect === 'allow') allowCount++;
      else denyCount++;
    });

    return {
      totalPolicies: this.policies.size,
      allowPolicies: allowCount,
      denyPolicies: denyCount,
      capabilityIndex: this.policyIndex.byCapability.size,
      subjectRoleIndex: this.policyIndex.bySubjectRole.size,
      resourceTypeIndex: this.policyIndex.byResourceType.size,
    };
  }
}