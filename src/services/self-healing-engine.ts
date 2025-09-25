// CoreFlow360 V4 - Self-Healing Automation Engine
import { Alert, SelfHealingAction } from '../types/observability';
import { getAIClient } from './ai-client';

export class SelfHealingEngine {
  private env: any;
  private db: D1Database;
  private aiClient: any;

  constructor(env: any) {
    this.env = env;
    this.db = env.DB;
    this.aiClient = getAIClient(env);
  }

  async handleAlert(alert: Alert): Promise<void> {
    try {
      // Determine if self-healing should be attempted
      const shouldHeal = await this.shouldAttemptSelfHealing(alert);
      if (!shouldHeal) {
        return;
      }

      // Determine the appropriate action
      const action = await this.determineAction(alert);
      if (!action) {
        return;
      }

      // Log the action attempt
      await this.logHealingAttempt(alert.id, action, 'attempting');

      // Execute the action
      const result = await this.executeAction(action, alert);

      // Log the result
      await this.logHealingAttempt(alert.id, action, result.success ? 'success' : 'failed', result.message);

      // Monitor the effect
      if (result.success) {
        await this.scheduleEffectMonitoring(alert.id, action);
      }

    } catch (error) {
      await this.logHealingAttempt(alert.id, null, 'error', error instanceof Error ? error.message : 'Unknown error');
    }
  }

  private async shouldAttemptSelfHealing(alert: Alert): Promise<boolean> {
    // Check if self-healing is enabled for this business
    const settings = await this.db.prepare(`
      SELECT self_healing_enabled FROM business_settings WHERE business_id = ?
    `).bind(alert.businessId).first();

    if (!settings?.self_healing_enabled) {
      return false;
    }

    // Check alert severity (only heal medium+ severity alerts)
    if (['low'].includes(alert.severity)) {
      return false;
    }

    // Check if we've recently attempted healing for similar issues
    const recentAttempts = await this.db.prepare(`
      SELECT COUNT(*) as count FROM self_healing_log
      WHERE business_id = ? AND fingerprint = ? AND timestamp >= ?
    `).bind(
      alert.businessId,
      alert.fingerprint,
      new Date(Date.now() - 30 * 60 * 1000).toISOString() // Last 30 minutes
    ).first();

    if ((recentAttempts?.count || 0) >= 3) {
      return false; // Too many recent attempts
    }

    // Check if this is a known pattern we can heal
    const knownPatterns = await this.getKnownHealingPatterns(alert);
    return knownPatterns.length > 0;
  }

  async determineAction(alert: Alert): Promise<SelfHealingAction | null> {
    // Get context about the alert and system state
    const context = await this.gatherContext(alert);

    // Use AI to determine the best action
    const aiAction = await this.getAIRecommendedAction(alert, context);
    if (aiAction) {
      return aiAction;
    }

    // Fallback to rule-based actions
    return await this.getRuleBasedAction(alert, context);
  }

  private async gatherContext(alert: Alert): Promise<any> {
    const timeWindow = 15 * 60 * 1000; // 15 minutes
    const since = new Date(Date.now() - timeWindow);

    const [metrics, logs, traces, serviceHealth] = await Promise.all([
      this.getRecentMetrics(alert.businessId, since),
      this.getRecentLogs(alert.businessId, since),
      this.getRecentTraces(alert.businessId, since),
      this.getServiceHealth(alert.businessId)
    ]);

    return {
      alert,
      metrics,
      logs,
      traces,
      serviceHealth,
      timestamp: new Date()
    };
  }

  private async getAIRecommendedAction(alert: Alert, context: any): Promise<SelfHealingAction | null> {
    const prompt = `
    Analyze the following alert and system context to recommend a self-healing action:

    Alert: ${JSON.stringify(alert)}

    System Context: ${JSON.stringify(context)}

    Based on this information, recommend the most appropriate self-healing action from:
    - SCALE_UP: Increase service instances
    - SCALE_DOWN: Decrease service instances
    - RESTART: Restart a service
    - ROLLBACK: Rollback to previous version
    - THROTTLE: Enable rate limiting
    - CIRCUIT_BREAK: Enable circuit breaker
    - CLEAR_CACHE: Clear caches
    - ADJUST_LIMITS: Adjust resource limits

    Return JSON with:
    - type: action type
    - service: target service name
    - parameters: action-specific parameters
    - confidence: confidence level (0-1)
    - reasoning: explanation of why this action was chosen
    - riskLevel: low/medium/high
    - expectedOutcome: what should happen after the action

    Only recommend actions with confidence > 0.7 and risk level low or medium.
    `;

    try {
      const response = await this.aiClient.generateText(prompt);
      const recommendation = JSON.parse(response);

      if (recommendation.confidence > 0.7 && ['low', 'medium'].includes(recommendation.riskLevel)) {
        return {
          type: recommendation.type,
          service: recommendation.service,
          ...recommendation.parameters,
          metadata: {
            confidence: recommendation.confidence,
            reasoning: recommendation.reasoning,
            riskLevel: recommendation.riskLevel,
            expectedOutcome: recommendation.expectedOutcome,
            source: 'ai'
          }
        };
      }

      return null;

    } catch (error) {
      return null;
    }
  }

  private async getRuleBasedAction(alert: Alert, context: any): Promise<SelfHealingAction | null> {
    // Rule-based fallback logic
    const labels = alert.labels;

    // High latency -> scale up or restart
    if (labels.type === 'latency' && alert.metricValue && alert.metricValue > 5000) {
      // Check if service is already under high load
      const serviceMetrics = context.serviceHealth.find((s: any) => s.service_name === labels.service);

      if (serviceMetrics && serviceMetrics.avg_cpu_percent > 80) {
        return {
          type: 'SCALE_UP',
          service: labels.service,
          instances: 2,
          metadata: { source: 'rule-based', reason: 'high_latency_high_cpu' }
        };
      } else {
        return {
          type: 'RESTART',
          service: labels.service,
          metadata: { source: 'rule-based', reason: 'high_latency_low_cpu' }
        };
      }
    }

    // High error rate -> rollback or circuit break
    if (labels.type === 'error_rate' && alert.metricValue && alert.metricValue > 5) {
      // Check if this started recently (might be a bad deployment)
      const recentDeployments = await this.getRecentDeployments(alert.businessId, labels.service);

      if (recentDeployments.length > 0) {
        return {
          type: 'ROLLBACK',
          service: labels.service,
          version: recentDeployments[0].previous_version,
          metadata: { source: 'rule-based', reason: 'high_error_rate_recent_deploy' }
        };
      } else {
        return {
          type: 'CIRCUIT_BREAK',
          service: labels.service,
          endpoint: labels.endpoint,
          metadata: { source: 'rule-based', reason: 'high_error_rate' }
        };
      }
    }

    // High memory usage -> restart or scale up
    if (labels.type === 'memory' && alert.metricValue && alert.metricValue > 90) {
      return {
        type: 'RESTART',
        service: labels.service,
        metadata: { source: 'rule-based', reason: 'high_memory_usage' }
      };
    }

    // High cost -> throttle
    if (labels.type === 'cost' && alert.metricValue && alert.metricValue > 100) {
      return {
        type: 'THROTTLE',
        service: labels.service,
        endpoint: labels.endpoint,
        metadata: { source: 'rule-based', reason: 'high_cost' }
      };
    }

    return null;
  }

  private async executeAction(action: SelfHealingAction, alert: Alert): Promise<{ success: boolean; message: string }> {
    try {
      switch (action.type) {
        case 'SCALE_UP':
          return await this.scaleService(action.service!, action.instances || 1, 'up');

        case 'SCALE_DOWN':
          return await this.scaleService(action.service!, action.instances || 1, 'down');

        case 'RESTART':
          return await this.restartService(action.service!);

        case 'ROLLBACK':
          return await this.rollbackDeployment(action.service!, action.version!);

        case 'THROTTLE':
          return await this.enableRateLimiting(action.service!, action.endpoint);

        case 'CIRCUIT_BREAK':
          return await this.enableCircuitBreaker(action.service!, action.endpoint);

        case 'CLEAR_CACHE':
          return await this.clearCache(action.service!);

        case 'ADJUST_LIMITS':
          return await this.adjustResourceLimits(action.service!, action.metadata);

        default:
          return { success: false, message: `Unsupported action type: ${action.type}` };
      }

    } catch (error) {
      return {
        success: false,
        message: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  private async scaleService(serviceName: string, instances: number, direction:
  'up' | 'down'): Promise<{ success: boolean; message: string }> {
    // This would integrate with your orchestration platform (Kubernetes, Docker Swarm, etc.)
    // For Cloudflare Workers, this might involve updating Durable Object counts or routing

    const newInstanceCount = direction === 'up' ? instances : -instances;

    // Simulate scaling action
    const response = await fetch(`${this.env.ORCHESTRATOR_API}/services/${serviceName}/scale`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.env.ORCHESTRATOR_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        instances: newInstanceCount,
        direction
      })
    });

    if (response.ok) {
      return {
        success: true,
        message: `Successfully ${direction
  === 'up' ? 'scaled up' : 'scaled down'} ${serviceName} by ${instances} instances`
      };
    } else {
      return {
        success: false,
        message: `Failed to scale ${serviceName}: ${response.statusText}`
      };
    }
  }

  private async restartService(serviceName: string): Promise<{ success: boolean; message: string }> {
    const response = await fetch(`${this.env.ORCHESTRATOR_API}/services/${serviceName}/restart`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.env.ORCHESTRATOR_TOKEN}`,
        'Content-Type': 'application/json'
      }
    });

    if (response.ok) {
      return { success: true, message: `Successfully restarted ${serviceName}` };
    } else {
      return { success: false, message: `Failed to restart ${serviceName}: ${response.statusText}` };
    }
  }

  private async rollbackDeployment(serviceName: string, version:
  string): Promise<{ success: boolean; message: string }> {
    const response = await fetch(`${this.env.ORCHESTRATOR_API}/services/${serviceName}/rollback`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.env.ORCHESTRATOR_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ version })
    });

    if (response.ok) {
      return { success: true, message: `Successfully rolled back ${serviceName} to version ${version}` };
    } else {
      return { success: false, message: `Failed to rollback ${serviceName}: ${response.statusText}` };
    }
  }

  private async enableRateLimiting(serviceName: string, endpoint?:
  string): Promise<{ success: boolean; message: string }> {
    // Enable rate limiting via your API gateway or load balancer
    const response = await fetch(`${this.env.GATEWAY_API}/rate-limits`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.env.GATEWAY_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        service: serviceName,
        endpoint: endpoint || '*',
        limit: 100, // requests per minute
        window: 60000 // 1 minute
      })
    });

    if (response.ok) {
      return { success: true, message:
  `Enabled rate limiting for ${serviceName}${endpoint ? ` endpoint ${endpoint}` : ''}` };
    } else {
      return { success: false, message: `Failed to enable rate limiting: ${response.statusText}` };
    }
  }

  private async enableCircuitBreaker(serviceName: string, endpoint?:
  string): Promise<{ success: boolean; message: string }> {
    const response = await fetch(`${this.env.GATEWAY_API}/circuit-breakers`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.env.GATEWAY_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        service: serviceName,
        endpoint: endpoint || '*',
        failureThreshold: 5,
        timeout: 30000 // 30 seconds
      })
    });

    if (response.ok) {
      return { success: true, message:
  `Enabled circuit breaker for ${serviceName}${endpoint ? ` endpoint ${endpoint}` : ''}` };
    } else {
      return { success: false, message: `Failed to enable circuit breaker: ${response.statusText}` };
    }
  }

  private async clearCache(serviceName: string): Promise<{ success: boolean; message: string }> {
    // Clear application caches
    const response = await fetch(`${this.env.CACHE_API}/clear`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.env.CACHE_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        service: serviceName,
        pattern: '*'
      })
    });

    if (response.ok) {
      return { success: true, message: `Successfully cleared cache for ${serviceName}` };
    } else {
      return { success: false, message: `Failed to clear cache: ${response.statusText}` };
    }
  }

  private async adjustResourceLimits(serviceName: string, limits: any): Promise<{ success: boolean; message: string }> {
    const response = await fetch(`${this.env.ORCHESTRATOR_API}/services/${serviceName}/limits`, {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${this.env.ORCHESTRATOR_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(limits)
    });

    if (response.ok) {
      return { success: true, message: `Successfully adjusted resource limits for ${serviceName}` };
    } else {
      return { success: false, message: `Failed to adjust resource limits: ${response.statusText}` };
    }
  }

  private async scheduleEffectMonitoring(alertId: string, action: SelfHealingAction): Promise<void> {
    // Schedule monitoring to see if the action was effective
    const monitoringWindow = 10 * 60 * 1000; // 10 minutes
    const checkAt = new Date(Date.now() + monitoringWindow);

    await this.db.prepare(`
      INSERT INTO self_healing_monitoring (
        id, alert_id, action_type, service, check_at, status, business_id
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      crypto.randomUUID(),
      alertId,
      action.type,
      action.service || 'unknown',
      checkAt.toISOString(),
      'scheduled',
      '' // Would get from alert context
    ).run();
  }

  async checkHealingEffectiveness(): Promise<void> {
    // Check scheduled monitoring tasks
    const now = new Date().toISOString();
    const tasks = await this.db.prepare(`
      SELECT * FROM self_healing_monitoring
      WHERE check_at <= ? AND status = 'scheduled'
    `).bind(now).all();

    for (const task of tasks.results) {
      await this.evaluateHealingEffectiveness(task);
    }
  }

  private async evaluateHealingEffectiveness(task: any): Promise<void> {
    try {
      // Get the original alert with business isolation
      const alert = await this.db.prepare(`
        SELECT * FROM alerts WHERE id = ? AND business_id = ?
      `).bind(task.alert_id, task.business_id).first();

      if (!alert) {
        return;
      }

      // Check if similar alerts have occurred since the healing action
      const since = new Date(task.check_at);
      const similarAlerts = await this.db.prepare(`
        SELECT COUNT(*) as count FROM alerts
        WHERE fingerprint = ? AND triggered_at >= ? AND id != ? AND business_id = ?
      `).bind(alert.fingerprint, since.toISOString(), alert.id, alert.business_id).first();

      const isEffective = (similarAlerts?.count || 0) === 0;

      // Update monitoring status
      await this.db.prepare(`
        UPDATE self_healing_monitoring
        SET status = ?, effectiveness_score = ?, checked_at = ?
        WHERE id = ?
      `).bind(
        'completed',
        isEffective ? 1.0 : 0.0,
        new Date().toISOString(),
        task.id
      ).run();

      // Learn from the result
      await this.updateHealingPatterns(task, isEffective);

    } catch (error) {
    }
  }

  private async updateHealingPatterns(task: any, wasEffective: boolean): Promise<void> {
    // Update learning patterns for future decisions
    const pattern = `${task.action_type}:${task.service}`;

    if (wasEffective) {
      // Increase confidence in this pattern
      await this.db.prepare(`
        INSERT INTO healing_patterns (pattern, success_count, total_count, confidence)
        VALUES (?, 1, 1, 1.0)
        ON CONFLICT(pattern) DO UPDATE SET
          success_count = success_count + 1,
          total_count = total_count + 1,
          confidence = (success_count + 1.0) / (total_count + 1.0)
      `).bind(pattern).run();
    } else {
      // Decrease confidence
      await this.db.prepare(`
        INSERT INTO healing_patterns (pattern, success_count, total_count, confidence)
        VALUES (?, 0, 1, 0.0)
        ON CONFLICT(pattern) DO UPDATE SET
          total_count = total_count + 1,
          confidence = success_count / (total_count + 1.0)
      `).bind(pattern).run();
    }
  }

  private async logHealingAttempt(
    alertId: string,
    action: SelfHealingAction | null,
    status: 'attempting' | 'success' | 'failed' | 'error',
    message?: string
  ): Promise<void> {
    await this.db.prepare(`
      INSERT INTO self_healing_log (
        id, alert_id, action_type, service, status, message,
        timestamp, business_id, fingerprint
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      crypto.randomUUID(),
      alertId,
      action?.type || null,
      action?.service || null,
      status,
      message || null,
      new Date().toISOString(),
      '', // Would get from alert context
      '' // Would get from alert context
    ).run();
  }

  private async getKnownHealingPatterns(alert: Alert): Promise<any[]> {
    // Get patterns we've learned work for this type of alert
    const patterns = await this.db.prepare(`
      SELECT * FROM healing_patterns
      WHERE pattern LIKE ?
        AND confidence > 0.5
      ORDER BY confidence DESC
    `).bind(`%${alert.labels.type || 'unknown'}%`).all();

    return patterns.results;
  }

  private async getRecentMetrics(businessId: string, since: Date): Promise<any[]> {
    const result = await this.db.prepare(`
      SELECT * FROM metrics
      WHERE business_id = ? AND timestamp >= ?
      ORDER BY timestamp DESC
      LIMIT 100
    `).bind(businessId, since.toISOString()).all();

    return result.results;
  }

  private async getRecentLogs(businessId: string, since: Date): Promise<any[]> {
    const result = await this.db.prepare(`
      SELECT * FROM log_entries
      WHERE business_id = ? AND timestamp >= ?
        AND level IN ('ERROR', 'CRITICAL')
      ORDER BY timestamp DESC
      LIMIT 50
    `).bind(businessId, since.toISOString()).all();

    return result.results;
  }

  private async getRecentTraces(businessId: string, since: Date): Promise<any[]> {
    const result = await this.db.prepare(`
      SELECT * FROM traces
      WHERE business_id = ? AND start_time >= ?
        AND status = 'error'
      ORDER BY start_time DESC
      LIMIT 20
    `).bind(businessId, since.toISOString()).all();

    return result.results;
  }

  private async getServiceHealth(businessId: string): Promise<any[]> {
    const since = new Date(Date.now() - 60 * 60 * 1000); // Last hour

    const result = await this.db.prepare(`
      SELECT
        service_name,
        AVG(avg_latency_ms) as avg_latency,
        SUM(request_count) as total_requests,
        SUM(error_count) as total_errors,
        AVG(avg_cpu_percent) as avg_cpu_percent,
        AVG(avg_memory_mb) as avg_memory_mb
      FROM service_performance
      WHERE business_id = ? AND timestamp >= ?
      GROUP BY service_name
    `).bind(businessId, since.toISOString()).all();

    return result.results;
  }

  private async getRecentDeployments(businessId: string, serviceName: string): Promise<any[]> {
    // This would query your deployment tracking system
    // For now, return empty array
    return [];
  }
}