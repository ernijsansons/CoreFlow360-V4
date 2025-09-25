import { Alert, SelfHealingAction } from '../../types/telemetry';
import { TelemetryCollector } from './collector';
import { MetricsCollector } from './metrics';

interface HealingRule {
  id: string;
  name: string;
  condition: string;
  action: SelfHealingAction;
  enabled: boolean;
  priority: number;
  cooldownMinutes: number;
  maxExecutions: number;
  requiresApproval: boolean;
}

interface ExecutionLog {
  id: string;
  ruleId: string;
  actionId: string;
  timestamp: number;
  status: 'pending' | 'running' | 'success' | 'failed' | 'cancelled';
  result?: any;
  error?: string;
  approvedBy?: string;
  duration?: number;
}

interface ServiceHealth {
  service: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  lastCheck: number;
  metrics: {
    cpu: number;
    memory: number;
    latency: number;
    errorRate: number;
    throughput: number;
  };
}

export class SelfHealingEngine {
  private collector: TelemetryCollector;
  private metrics: MetricsCollector;
  private env: any;
  private healingRules: Map<string, HealingRule> = new Map();
  private executionHistory: Map<string, ExecutionLog> = new Map();
  private lastExecution: Map<string, number> = new Map();
  private executionCounts: Map<string, number> = new Map();
  private serviceHealth: Map<string, ServiceHealth> = new Map();
  private pendingApprovals: Map<string, ExecutionLog> = new Map();

  constructor(collector: TelemetryCollector, metrics: MetricsCollector, env: any) {
    this.collector = collector;
    this.metrics = metrics;
    this.env = env;
    this.initializeDefaultRules();
    this.startHealthMonitoring();
  }

  async handleAlert(alert: Alert): Promise<void> {
    const applicableRules = this.findApplicableRules(alert);

    for (const rule of applicableRules) {
      if (await this.shouldExecuteRule(rule, alert)) {
        await this.executeRule(rule, alert);
      }
    }
  }

  private findApplicableRules(alert: Alert): HealingRule[] {
    return Array.from(this.healingRules.values())
      .filter(rule => rule.enabled && this.evaluateCondition(rule.condition, alert))
      .sort((a, b) => b.priority - a.priority);
  }

  private evaluateCondition(condition: string, alert: Alert): boolean {
    try {
      const context = {
        severity: alert.severity,
        source: alert.source,
        message: alert.message,
        metadata: alert.metadata,
        escalationLevel: alert.escalationLevel
      };

      const func = new Function('context', `with(context) { return ${condition}; }`);
      return func(context);
    } catch (error) {
      return false;
    }
  }

  private async shouldExecuteRule(rule: HealingRule, alert: Alert): Promise<boolean> {
    // Check cooldown
    const lastExec = this.lastExecution.get(rule.id);
    if (lastExec && Date.now() - lastExec < rule.cooldownMinutes * 60 * 1000) {
      return false;
    }

    // Check execution count limit
    const execCount = this.executionCounts.get(rule.id) || 0;
    if (execCount >= rule.maxExecutions) {
      return false;
    }

    // Check if action is enabled
    if (!rule.action.enabled) {
      return false;
    }

    return true;
  }

  private async executeRule(rule: HealingRule, alert: Alert): Promise<void> {
    const executionId = crypto.randomUUID();
    const executionLog: ExecutionLog = {
      id: executionId,
      ruleId: rule.id,
      actionId: rule.action.id,
      timestamp: Date.now(),
      status: 'pending'
    };

    this.executionHistory.set(executionId, executionLog);

    try {
      if (rule.requiresApproval && !rule.action.autoApprove) {
        await this.requestApproval(executionLog, rule, alert);
        return;
      }

      await this.executeAction(executionLog, rule.action, alert);
    } catch (error) {
      executionLog.status = 'failed';
      executionLog.error = (error as Error).message;
    }
  }

  private async requestApproval(log: ExecutionLog, rule: HealingRule, alert: Alert): Promise<void> {
    this.pendingApprovals.set(log.id, log);

    // Send approval request notification
    const approvalAlert: Alert = {
      id: crypto.randomUUID(),
      name: `Approval Required: ${rule.name}`,
      severity: 'medium',
      status: 'firing',
      message: `Self-healing action requires approval: ${rule.action.type} for ${alert.name}`,
      timestamp: Date.now(),
      source: 'self-healing-engine',
      metadata: {
        executionId: log.id,
        originalAlert: alert.id,
        action: rule.action
      },
      channels: ['email', 'slack'],
      escalationLevel: 0,
      correlatedAlerts: [alert.id]
    };

    // Send notification through alert system
    if (this.env.APPROVAL_WEBHOOK) {
      await fetch(this.env.APPROVAL_WEBHOOK, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'approval_request',
          execution: log,
          rule,
          alert
        })
      });
    }
  }

  async approveAction(executionId: string, approvedBy: string): Promise<void> {
    const log = this.pendingApprovals.get(executionId);
    if (!log) {
      throw new Error(`Execution ${executionId} not found or not pending approval`);
    }

    log.approvedBy = approvedBy;
    this.pendingApprovals.delete(executionId);

    const rule = this.healingRules.get(log.ruleId);
    if (rule) {
      await this.executeAction(log, rule.action, null);
    }
  }

  async rejectAction(executionId: string, rejectedBy: string): Promise<void> {
    const log = this.pendingApprovals.get(executionId);
    if (log) {
      log.status = 'cancelled';
      log.approvedBy = rejectedBy;
      this.pendingApprovals.delete(executionId);
    }
  }

  private async executeAction(log: ExecutionLog, action: SelfHealingAction, alert: Alert | null): Promise<void> {
    log.status = 'running';
    const startTime = Date.now();

    try {
      let result: any;

      switch (action.type) {
        case 'scale_up':
          result = await this.scaleService(action.target, action.parameters);
          break;
        case 'scale_down':
          result = await this.scaleService(action.target, action.parameters);
          break;
        case 'restart':
          result = await this.restartService(action.target);
          break;
        case 'rollback':
          result = await this.rollbackDeployment(action.target, action.parameters);
          break;
        case 'throttle':
          result = await this.enableRateLimiting(action.target, action.parameters);
          break;
        case 'circuit_breaker':
          result = await this.enableCircuitBreaker(action.target, action.parameters);
          break;
        default:
          throw new Error(`Unknown action type: ${action.type}`);
      }

      log.status = 'success';
      log.result = result;
      log.duration = Date.now() - startTime;

      // Update execution tracking
      this.lastExecution.set(log.ruleId, Date.now());
      const currentCount = this.executionCounts.get(log.ruleId) || 0;
      this.executionCounts.set(log.ruleId, currentCount + 1);

      // Record metrics
      this.metrics.counter('self_healing_actions_total', 1, {
        action_type: action.type,
        target: action.target,
        status: 'success'
      });

      this.metrics.timing('self_healing_action_duration', log.duration, {
        action_type: action.type,
        target: action.target
      });

    } catch (error) {
      log.status = 'failed';
      log.error = (error as Error).message;
      log.duration = Date.now() - startTime;

      this.metrics.counter('self_healing_actions_total', 1, {
        action_type: action.type,
        target: action.target,
        status: 'failed'
      });

      throw error;
    }
  }

  private async scaleService(serviceName: string, parameters: any): Promise<any> {
    const { instances, cpu, memory } = parameters;

    if (this.env.CLOUDFLARE_API_TOKEN) {
      // Cloudflare Workers scaling (if applicable)
     
  const response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${this.env.CLOUDFLARE_ACCOUNT_ID}/workers/scripts/${serviceName}/settings`, {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${this.env.CLOUDFLARE_API_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          settings: {
            cpu_ms: cpu,
            memory_mb: memory
          }
        })
      });

      return response.json();
    }

    if (this.env.KUBERNETES_CONFIG) {
      // Kubernetes scaling
      return this.scaleKubernetesDeployment(serviceName, instances);
    }

    return { message: 'No scaling platform configured' };
  }

  private async scaleKubernetesDeployment(deploymentName: string, replicas: number): Promise<any> {
    // Simplified Kubernetes scaling - in production, use proper K8s client
    const kubeApiUrl = this.env.KUBERNETES_API_URL;
    const namespace = this.env.KUBERNETES_NAMESPACE || 'default';

    const response = await fetch(`${kubeApiUrl}/apis/apps/v1/namespaces/${namespace}/deployments/${deploymentName}/scale`, {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${this.env.KUBERNETES_TOKEN}`,
        'Content-Type': 'application/merge-patch+json'
      },
      body: JSON.stringify({
        spec: { replicas }
      })
    });

    return response.json();
  }

  private async restartService(serviceName: string): Promise<any> {
    if (this.env.KUBERNETES_CONFIG) {
      // Rolling restart by updating annotation
      const kubeApiUrl = this.env.KUBERNETES_API_URL;
      const namespace = this.env.KUBERNETES_NAMESPACE || 'default';

      const response = await fetch(`${kubeApiUrl}/apis/apps/v1/namespaces/${namespace}/deployments/${serviceName}`, {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${this.env.KUBERNETES_TOKEN}`,
          'Content-Type': 'application/merge-patch+json'
        },
        body: JSON.stringify({
          spec: {
            template: {
              metadata: {
                annotations: {
                  'kubectl.kubernetes.io/restartedAt': new Date().toISOString()
                }
              }
            }
          }
        })
      });

      return response.json();
    }

    return { message: 'Service restart initiated' };
  }

  private async rollbackDeployment(serviceName: string, parameters: any): Promise<any> {
    const { version } = parameters;

    if (this.env.KUBERNETES_CONFIG) {
      const kubeApiUrl = this.env.KUBERNETES_API_URL;
      const namespace = this.env.KUBERNETES_NAMESPACE || 'default';

      const response = await fetch(`${kubeApiUrl}/apis/apps/v1/namespaces/${namespace}/deployments/${serviceName}`, {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${this.env.KUBERNETES_TOKEN}`,
          'Content-Type': 'application/merge-patch+json'
        },
        body: JSON.stringify({
          spec: {
            template: {
              spec: {
                containers: [{
                  name: serviceName,
                  image: `${serviceName}:${version}`
                }]
              }
            }
          }
        })
      });

      return response.json();
    }

    return { message: 'Rollback initiated', version };
  }

  private async enableRateLimiting(endpoint: string, parameters: any): Promise<any> {
    const { limit, window } = parameters;

    // This would integrate with your API gateway or load balancer
    if (this.env.CLOUDFLARE_ZONE_ID) {
     
  const response = await fetch(`https://api.cloudflare.com/client/v4/zones/${this.env.CLOUDFLARE_ZONE_ID}/rate_limits`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.env.CLOUDFLARE_API_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          match: {
            request: {
              url: endpoint
            }
          },
          threshold: limit,
          period: window,
          action: {
            mode: 'challenge'
          }
        })
      });

      return response.json();
    }

    return { message: 'Rate limiting enabled', endpoint, limit, window };
  }

  private async enableCircuitBreaker(serviceName: string, parameters: any): Promise<any> {
    const { errorThreshold, timeoutMs } = parameters;

    // This would integrate with your service mesh or circuit breaker library
    return {
      message: 'Circuit breaker enabled',
      service: serviceName,
      errorThreshold,
      timeoutMs
    };
  }

  private startHealthMonitoring(): void {
    setInterval(async () => {
      await this.updateServiceHealth();
      await this.checkForAutomaticHealing();
    }, 30000); // Check every 30 seconds
  }

  private async updateServiceHealth(): Promise<void> {
    // Get health metrics for monitored services
    const services = ['api', 'ai-service', 'database', 'cache'];

    for (const service of services) {
      try {
        const health = await this.checkServiceHealth(service);
        this.serviceHealth.set(service, health);

        this.metrics.gauge('service_health_score', this.getHealthScore(health), {
          service,
          status: health.status
        });
      } catch (error) {
      }
    }
  }

  private async checkServiceHealth(service: string): Promise<ServiceHealth> {
    const timeRange = {
      start: new Date(Date.now() - 5 * 60 * 1000).toISOString(), // 5 minutes
      end: new Date().toISOString()
    };

    const metrics = await this.collector.getMetrics('default', timeRange);

    const serviceMetrics = metrics.filter(m =>
      m.dimensions.service === service ||
      m.dimensions.component === service
    );

    if (serviceMetrics.length === 0) {
      return {
        service,
        status: 'unhealthy',
        lastCheck: Date.now(),
        metrics: {
          cpu: 0,
          memory: 0,
          latency: 0,
          errorRate: 1,
          throughput: 0
        }
      };
    }

    const avgLatency = serviceMetrics.reduce((sum, m) => sum + m.metrics.golden.latency.p95, 0) / serviceMetrics.length;
    const avgErrorRate = serviceMetrics.reduce((sum,
  m) => sum + m.metrics.golden.errors.errorRate, 0) / serviceMetrics.length;
    const avgThroughput = serviceMetrics.reduce((sum,
  m) => sum + m.metrics.golden.traffic.requestsPerSecond, 0) / serviceMetrics.length;

    const status = this.determineHealthStatus(avgLatency, avgErrorRate, avgThroughput);

    return {
      service,
      status,
      lastCheck: Date.now(),
      metrics: {
        cpu: 0, // Would need specific CPU metrics
        memory: 0, // Would need specific memory metrics
        latency: avgLatency,
        errorRate: avgErrorRate,
        throughput: avgThroughput
      }
    };
  }

  private determineHealthStatus(latency: number, errorRate: number,
  throughput: number): 'healthy' | 'degraded' | 'unhealthy' {
    if (errorRate > 0.1 || latency > 5000) { // 10% error rate or 5s latency
      return 'unhealthy';
    } else if (errorRate > 0.05 || latency > 2000) { // 5% error rate or 2s latency
      return 'degraded';
    }
    return 'healthy';
  }

  private getHealthScore(health: ServiceHealth): number {
    switch (health.status) {
      case 'healthy': return 1;
      case 'degraded': return 0.5;
      case 'unhealthy': return 0;
      default: return 0;
    }
  }

  private async checkForAutomaticHealing(): Promise<void> {
    for (const [service, health] of this.serviceHealth) {
      if (health.status === 'unhealthy') {
        await this.triggerAutomaticHealing(service, health);
      }
    }
  }

  private async triggerAutomaticHealing(service: string, health: ServiceHealth): Promise<void> {
    // Create synthetic alert for automatic healing
    const alert: Alert = {
      id: crypto.randomUUID(),
      name: `Service Unhealthy: ${service}`,
      severity: 'high',
      status: 'firing',
      message: `Service
  ${service} is unhealthy: error rate ${health.metrics.errorRate}, latency ${health.metrics.latency}ms`,
      timestamp: Date.now(),
      source: 'health-monitor',
      metadata: { service, health },
      channels: [],
      escalationLevel: 0,
      correlatedAlerts: []
    };

    await this.handleAlert(alert);
  }

  private initializeDefaultRules(): void {
    const defaultRules: HealingRule[] = [
      {
        id: 'high-latency-scale',
        name: 'Scale Up on High Latency',
        condition: 'severity === "high" && message.includes("latency")',
        action: {
          id: 'scale-up-1',
          type: 'scale_up',
          target: 'api',
          parameters: { instances: 2 },
          condition: 'metadata.latency > 2000',
          cooldown: 300000, // 5 minutes
          enabled: true,
          autoApprove: true
        },
        enabled: true,
        priority: 10,
        cooldownMinutes: 10,
        maxExecutions: 3,
        requiresApproval: false
      },
      {
        id: 'high-error-rate-restart',
        name: 'Restart Service on High Error Rate',
        condition: 'severity === "critical" && message.includes("error")',
        action: {
          id: 'restart-1',
          type: 'restart',
          target: 'api',
          parameters: {},
          condition: 'metadata.errorRate > 0.1',
          cooldown: 600000, // 10 minutes
          enabled: true,
          autoApprove: false
        },
        enabled: true,
        priority: 20,
        cooldownMinutes: 15,
        maxExecutions: 2,
        requiresApproval: true
      }
    ];

    defaultRules.forEach(rule => {
      this.healingRules.set(rule.id, rule);
    });
  }

  addHealingRule(rule: HealingRule): void {
    this.healingRules.set(rule.id, rule);
  }

  removeHealingRule(ruleId: string): void {
    this.healingRules.delete(ruleId);
  }

  getExecutionHistory(limit: number = 100): ExecutionLog[] {
    return Array.from(this.executionHistory.values())
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, limit);
  }

  getPendingApprovals(): ExecutionLog[] {
    return Array.from(this.pendingApprovals.values());
  }

  getServiceHealth(): ServiceHealth[] {
    return Array.from(this.serviceHealth.values());
  }

  getHealingRules(): HealingRule[] {
    return Array.from(this.healingRules.values());
  }
}