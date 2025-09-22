/**
 * Security Monitoring and Alerting Framework
 * Real-time security event detection, analysis, and alerting
 */

import { Logger } from '../shared/logger';
import { SecurityError } from '../shared/security-utils';

export interface SecurityEvent {
  id: string;
  type: SecurityEventType;
  severity: SecuritySeverity;
  title: string;
  description: string;
  source: string;
  timestamp: number;
  businessId?: string;
  userId?: string;
  ipAddress?: string;
  userAgent?: string;
  metadata: Record<string, any>;
  indicators: SecurityIndicator[];
  mitigationSteps?: string[];
}

export type SecurityEventType =
  | 'authentication_failure'
  | 'authorization_violation'
  | 'sql_injection_attempt'
  | 'prompt_injection_attempt'
  | 'rate_limit_violation'
  | 'tenant_isolation_breach'
  | 'suspicious_behavior'
  | 'data_exfiltration_attempt'
  | 'privilege_escalation'
  | 'account_takeover'
  | 'anomalous_access_pattern'
  | 'malicious_file_upload'
  | 'api_abuse'
  | 'brute_force_attack'
  | 'session_hijacking';

export type SecuritySeverity = 'low' | 'medium' | 'high' | 'critical';

export interface SecurityIndicator {
  type: 'ioc' | 'behavior' | 'pattern' | 'anomaly';
  value: string;
  confidence: number;
  description: string;
}

export interface SecurityAlert {
  id: string;
  eventId: string;
  severity: SecuritySeverity;
  title: string;
  description: string;
  businessId?: string;
  channels: AlertChannel[];
  status: 'open' | 'investigating' | 'resolved' | 'false_positive';
  createdAt: number;
  updatedAt: number;
  resolvedAt?: number;
  assignedTo?: string;
  notes?: string[];
}

export type AlertChannel = 'email' | 'slack' | 'webhook' | 'sms' | 'dashboard';

export interface AlertRule {
  id: string;
  name: string;
  description: string;
  eventTypes: SecurityEventType[];
  severityThreshold: SecuritySeverity;
  conditions: AlertCondition[];
  channels: AlertChannel[];
  throttle: number; // Minutes to wait before sending another alert
  businessIds?: string[]; // Specific businesses, empty for all
  isActive: boolean;
}

export interface AlertCondition {
  field: string;
  operator: 'equals' | 'contains' | 'greater_than' | 'less_than' | 'in' | 'regex';
  value: any;
}

export interface ThreatIntelligence {
  ipAddress?: string;
  domain?: string;
  userAgent?: string;
  riskScore: number;
  categories: string[];
  lastSeen: number;
  source: string;
}

export interface SecurityMetrics {
  eventsLast24h: number;
  criticalEventsLast24h: number;
  topEventTypes: Array<{ type: SecurityEventType; count: number }>;
  topSourceIPs: Array<{ ip: string; count: number; riskScore: number }>;
  alertsOpen: number;
  meanTimeToDetection: number; // milliseconds
  meanTimeToResponse: number; // milliseconds
}

export interface AnomalyDetectionModel {
  type: 'login_pattern' | 'api_usage' | 'data_access' | 'geographic_location';
  baseline: Record<string, number>;
  threshold: number;
  windowSize: number; // minutes
}

export class SecurityMonitor {
  private logger: Logger;
  private events: Map<string, SecurityEvent> = new Map();
  private alerts: Map<string, SecurityAlert> = new Map();
  private alertRules: Map<string, AlertRule> = new Map();
  private threatIntel: Map<string, ThreatIntelligence> = new Map();
  private anomalyModels: Map<string, AnomalyDetectionModel> = new Map();
  private recentThrottles: Map<string, number> = new Map();

  constructor(private env: any) {
    this.logger = new Logger({ component: 'security-monitor' });
    this.initializeDefaultRules();
    this.initializeAnomalyModels();
  }

  /**
   * Record a security event
   */
  async recordEvent(event: Omit<SecurityEvent, 'id' | 'timestamp'>): Promise<SecurityEvent> {
    const fullEvent: SecurityEvent = {
      ...event,
      id: this.generateEventId(),
      timestamp: Date.now()
    };

    // Enrich event with threat intelligence
    await this.enrichWithThreatIntel(fullEvent);

    // Store event
    this.events.set(fullEvent.id, fullEvent);

    // Log the security event
    this.logger.warn('Security event recorded', {
      eventId: fullEvent.id,
      type: fullEvent.type,
      severity: fullEvent.severity,
      source: fullEvent.source,
      businessId: fullEvent.businessId,
      ipAddress: fullEvent.ipAddress
    });

    // Check for anomalies
    await this.checkForAnomalies(fullEvent);

    // Evaluate alert rules
    await this.evaluateAlertRules(fullEvent);

    // Store in persistent storage if available
    if (this.env.DB_SECURITY) {
      await this.persistEvent(fullEvent);
    }

    return fullEvent;
  }

  /**
   * Create an alert based on security event
   */
  async createAlert(
    event: SecurityEvent,
    rule: AlertRule,
    customDescription?: string
  ): Promise<SecurityAlert> {
    const alert: SecurityAlert = {
      id: this.generateAlertId(),
      eventId: event.id,
      severity: event.severity,
      title: `Security Alert: ${event.title}`,
      description: customDescription || this.generateAlertDescription(event, rule),
      businessId: event.businessId,
      channels: rule.channels,
      status: 'open',
      createdAt: Date.now(),
      updatedAt: Date.now()
    };

    this.alerts.set(alert.id, alert);

    this.logger.error('Security alert created', {
      alertId: alert.id,
      eventId: event.id,
      severity: alert.severity,
      businessId: alert.businessId,
      channels: alert.channels
    });

    // Send alert notifications
    await this.sendAlertNotifications(alert, event);

    // Store in persistent storage
    if (this.env.DB_SECURITY) {
      await this.persistAlert(alert);
    }

    return alert;
  }

  /**
   * Check for behavioral anomalies
   */
  private async checkForAnomalies(event: SecurityEvent): Promise<void> {
    if (!event.userId) return;

    const userKey = `${event.businessId}:${event.userId}`;

    // Check login pattern anomalies
    if (event.type === 'authentication_failure' || event.metadata.action === 'login') {
      await this.checkLoginPatternAnomaly(userKey, event);
    }

    // Check API usage anomalies
    if (event.source === 'api') {
      await this.checkApiUsageAnomaly(userKey, event);
    }

    // Check geographic location anomalies
    if (event.ipAddress) {
      await this.checkGeographicAnomaly(userKey, event);
    }
  }

  /**
   * Check for login pattern anomalies
   */
  private async checkLoginPatternAnomaly(userKey: string, event: SecurityEvent): Promise<void> {
    const model = this.anomalyModels.get(`login_pattern:${userKey}`);
    if (!model) return;

    const hour = new Date(event.timestamp).getHours();
    const dayOfWeek = new Date(event.timestamp).getDay();
    const pattern = `${dayOfWeek}:${hour}`;

    const baselineFreq = model.baseline[pattern] || 0;
    const currentTime = Date.now();
    const windowStart = currentTime - (model.windowSize * 60 * 1000);

    // Count recent login attempts for this pattern
    const recentEvents = Array.from(this.events.values())
      .filter(e =>
        e.userId === event.userId &&
        e.timestamp >= windowStart &&
        e.metadata.loginPattern === pattern
      ).length;

    const anomalyScore = baselineFreq > 0 ? recentEvents / baselineFreq : recentEvents;

    if (anomalyScore > model.threshold) {
      await this.recordEvent({
        type: 'anomalous_access_pattern',
        severity: 'medium',
        title: 'Unusual Login Pattern Detected',
        description: `User ${event.userId} showed unusual login pattern: ${pattern}`,
        source: 'anomaly_detection',
        businessId: event.businessId,
        userId: event.userId,
        ipAddress: event.ipAddress,
        userAgent: event.userAgent,
        metadata: {
          anomalyType: 'login_pattern',
          pattern,
          anomalyScore,
          threshold: model.threshold
        },
        indicators: [
          {
            type: 'behavior',
            value: `login_pattern_${pattern}`,
            confidence: Math.min(anomalyScore / model.threshold, 1.0),
            description: 'Unusual login time pattern'
          }
        ]
      });
    }
  }

  /**
   * Evaluate alert rules against event
   */
  private async evaluateAlertRules(event: SecurityEvent): Promise<void> {
    for (const rule of this.alertRules.values()) {
      if (!rule.isActive) continue;

      // Check if rule applies to this business
      if (rule.businessIds && rule.businessIds.length > 0) {
        if (!event.businessId || !rule.businessIds.includes(event.businessId)) {
          continue;
        }
      }

      // Check event type match
      if (!rule.eventTypes.includes(event.type)) continue;

      // Check severity threshold
      if (!this.meetsServerityThreshold(event.severity, rule.severityThreshold)) continue;

      // Check conditions
      if (!this.evaluateConditions(event, rule.conditions)) continue;

      // Check throttling
      const throttleKey = `${rule.id}:${event.businessId || 'global'}`;
      const lastAlert = this.recentThrottles.get(throttleKey);
      if (lastAlert && Date.now() - lastAlert < rule.throttle * 60 * 1000) {
        continue;
      }

      // Create alert
      await this.createAlert(event, rule);
      this.recentThrottles.set(throttleKey, Date.now());
    }
  }

  /**
   * Send alert notifications
   */
  private async sendAlertNotifications(alert: SecurityAlert, event: SecurityEvent): Promise<void> {
    for (const channel of alert.channels) {
      try {
        switch (channel) {
          case 'email':
            await this.sendEmailAlert(alert, event);
            break;
          case 'slack':
            await this.sendSlackAlert(alert, event);
            break;
          case 'webhook':
            await this.sendWebhookAlert(alert, event);
            break;
          case 'sms':
            await this.sendSMSAlert(alert, event);
            break;
          default:
            this.logger.warn('Unknown alert channel', { channel });
        }
      } catch (error) {
        this.logger.error('Failed to send alert notification', error, {
          alertId: alert.id,
          channel
        });
      }
    }
  }

  /**
   * Send email alert
   */
  private async sendEmailAlert(alert: SecurityAlert, event: SecurityEvent): Promise<void> {
    if (!this.env.EMAIL_API_KEY || !this.env.SECURITY_EMAIL) return;

    const subject = `🚨 ${alert.title}`;
    const body = this.formatEmailAlert(alert, event);

    const response = await fetch(`${this.env.API_BASE_URL}/email/send`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.env.EMAIL_API_KEY}`
      },
      body: JSON.stringify({
        to: this.env.SECURITY_EMAIL,
        subject,
        html: body,
        priority: alert.severity === 'critical' ? 'high' : 'normal'
      })
    });

    if (!response.ok) {
      throw new Error(`Email alert failed: ${response.statusText}`);
    }
  }

  /**
   * Send Slack alert
   */
  private async sendSlackAlert(alert: SecurityAlert, event: SecurityEvent): Promise<void> {
    if (!this.env.SLACK_WEBHOOK_URL) return;

    const color = this.getSeverityColor(alert.severity);
    const payload = {
      text: alert.title,
      attachments: [
        {
          color,
          title: alert.title,
          text: alert.description,
          fields: [
            { title: 'Severity', value: alert.severity.toUpperCase(), short: true },
            { title: 'Event Type', value: event.type, short: true },
            { title: 'Source', value: event.source, short: true },
            { title: 'Time', value: new Date(event.timestamp).toISOString(), short: true }
          ],
          footer: 'CoreFlow360 Security Monitor',
          ts: Math.floor(event.timestamp / 1000)
        }
      ]
    };

    const response = await fetch(this.env.SLACK_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`Slack alert failed: ${response.statusText}`);
    }
  }

  /**
   * Get security metrics
   */
  async getSecurityMetrics(businessId?: string): Promise<SecurityMetrics> {
    const now = Date.now();
    const last24h = now - (24 * 60 * 60 * 1000);

    const events = Array.from(this.events.values()).filter(e => {
      if (businessId && e.businessId !== businessId) return false;
      return e.timestamp >= last24h;
    });

    const eventTypes = new Map<SecurityEventType, number>();
    const sourceIPs = new Map<string, { count: number; riskScore: number }>();

    let criticalEvents = 0;

    for (const event of events) {
      if (event.severity === 'critical') criticalEvents++;

      // Count event types
      eventTypes.set(event.type, (eventTypes.get(event.type) || 0) + 1);

      // Count source IPs
      if (event.ipAddress) {
        const existing = sourceIPs.get(event.ipAddress) || { count: 0, riskScore: 0 };
        const intel = this.threatIntel.get(event.ipAddress);
        sourceIPs.set(event.ipAddress, {
          count: existing.count + 1,
          riskScore: intel?.riskScore || 0
        });
      }
    }

    const openAlerts = Array.from(this.alerts.values())
      .filter(a => a.status === 'open').length;

    return {
      eventsLast24h: events.length,
      criticalEventsLast24h: criticalEvents,
      topEventTypes: Array.from(eventTypes.entries())
        .map(([type, count]) => ({ type, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10),
      topSourceIPs: Array.from(sourceIPs.entries())
        .map(([ip, data]) => ({ ip, ...data }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10),
      alertsOpen: openAlerts,
      meanTimeToDetection: 0, // Would be calculated from actual data
      meanTimeToResponse: 0 // Would be calculated from actual data
    };
  }

  /**
   * Initialize default alert rules
   */
  private initializeDefaultRules(): void {
    const defaultRules: AlertRule[] = [
      {
        id: 'critical-auth-failures',
        name: 'Critical Authentication Failures',
        description: 'Multiple failed authentication attempts',
        eventTypes: ['authentication_failure'],
        severityThreshold: 'high',
        conditions: [],
        channels: ['email', 'slack'],
        throttle: 15,
        isActive: true
      },
      {
        id: 'sql-injection-attempts',
        name: 'SQL Injection Attempts',
        description: 'Potential SQL injection attacks detected',
        eventTypes: ['sql_injection_attempt'],
        severityThreshold: 'medium',
        conditions: [],
        channels: ['email', 'slack', 'webhook'],
        throttle: 5,
        isActive: true
      },
      {
        id: 'tenant-isolation-breach',
        name: 'Tenant Isolation Breach',
        description: 'Attempt to access data from different tenant',
        eventTypes: ['tenant_isolation_breach'],
        severityThreshold: 'high',
        conditions: [],
        channels: ['email', 'slack'],
        throttle: 0, // Immediate alert
        isActive: true
      },
      {
        id: 'prompt-injection',
        name: 'AI Prompt Injection',
        description: 'Potential prompt injection attack on AI systems',
        eventTypes: ['prompt_injection_attempt'],
        severityThreshold: 'medium',
        conditions: [],
        channels: ['email', 'slack'],
        throttle: 10,
        isActive: true
      }
    ];

    for (const rule of defaultRules) {
      this.alertRules.set(rule.id, rule);
    }
  }

  /**
   * Initialize anomaly detection models
   */
  private initializeAnomalyModels(): void {
    // Default models would be populated from historical data
    // This is a simplified initialization
  }

  /**
   * Helper methods
   */
  private generateEventId(): string {
    return `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateAlertId(): string {
    return `alt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private async enrichWithThreatIntel(event: SecurityEvent): Promise<void> {
    if (event.ipAddress) {
      const intel = await this.getThreatIntelligence(event.ipAddress);
      if (intel) {
        event.indicators.push({
          type: 'ioc',
          value: event.ipAddress,
          confidence: intel.riskScore,
          description: `Known threat IP: ${intel.categories.join(', ')}`
        });
      }
    }
  }

  private async getThreatIntelligence(ipAddress: string): Promise<ThreatIntelligence | null> {
    // In production, this would query threat intelligence feeds
    return this.threatIntel.get(ipAddress) || null;
  }

  private meetsServerityThreshold(eventSeverity: SecuritySeverity, threshold: SecuritySeverity): boolean {
    const severityOrder = { low: 1, medium: 2, high: 3, critical: 4 };
    return severityOrder[eventSeverity] >= severityOrder[threshold];
  }

  private evaluateConditions(event: SecurityEvent, conditions: AlertCondition[]): boolean {
    return conditions.every(condition => this.evaluateCondition(event, condition));
  }

  private evaluateCondition(event: SecurityEvent, condition: AlertCondition): boolean {
    const value = this.getEventFieldValue(event, condition.field);

    switch (condition.operator) {
      case 'equals':
        return value === condition.value;
      case 'contains':
        return String(value).includes(String(condition.value));
      case 'greater_than':
        return Number(value) > Number(condition.value);
      case 'less_than':
        return Number(value) < Number(condition.value);
      case 'in':
        return Array.isArray(condition.value) && condition.value.includes(value);
      case 'regex':
        return new RegExp(condition.value).test(String(value));
      default:
        return false;
    }
  }

  private getEventFieldValue(event: SecurityEvent, field: string): any {
    const parts = field.split('.');
    let value: any = event;
    for (const part of parts) {
      value = value?.[part];
    }
    return value;
  }

  private generateAlertDescription(event: SecurityEvent, rule: AlertRule): string {
    return `${rule.description}\n\nEvent Details:\n- Type:
  ${event.type}\n- Severity: ${event.severity}\n- Source: ${event.source}\n- Time: ${new Date(event.timestamp).toISOString()}\n\nDescription: ${event.description}`;
  }

  private formatEmailAlert(alert: SecurityAlert, event: SecurityEvent): string {
    return `
      <h2>🚨 Security Alert</h2>
      <h3>${alert.title}</h3>

      <p><strong>Severity:</strong> ${alert.severity.toUpperCase()}</p>
      <p><strong>Event Type:</strong> ${event.type}</p>
      <p><strong>Source:</strong> ${event.source}</p>
      <p><strong>Time:</strong> ${new Date(event.timestamp).toISOString()}</p>

      <h4>Description</h4>
      <p>${alert.description}</p>

      <h4>Event Details</h4>
      <pre>${JSON.stringify(event.metadata, null, 2)}</pre>

      <h4>Indicators</h4>
      <ul>
      
   ${event.indicators.map(i => `<li>${i.description} (${(i.confidence * 100).toFixed(1)}% confidence)</li>`).join('')}
      </ul>

      <p><em>This alert was generated by CoreFlow360 Security Monitor</em></p>
    `;
  }

  private getSeverityColor(severity: SecuritySeverity): string {
    const colors = {
      low: '#36a64f',
      medium: '#ff9900',
      high: '#ff6600',
      critical: '#cc0000'
    };
    return colors[severity];
  }

  private async persistEvent(event: SecurityEvent): Promise<void> {
    // Store in security database
    try {
      await this.env.DB_SECURITY.prepare(`
        INSERT INTO security_events (
          id, type, severity, title, description, source, timestamp,
          business_id, user_id, ip_address, user_agent, metadata, indicators
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        event.id, event.type, event.severity, event.title, event.description,
        event.source, event.timestamp, event.businessId, event.userId,
        event.ipAddress, event.userAgent, JSON.stringify(event.metadata),
        JSON.stringify(event.indicators)
      ).run();
    } catch (error) {
      this.logger.error('Failed to persist security event', error);
    }
  }

  private async persistAlert(alert: SecurityAlert): Promise<void> {
    // Store in security database
    try {
      await this.env.DB_SECURITY.prepare(`
        INSERT INTO security_alerts (
          id, event_id, severity, title, description, business_id,
          channels, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        alert.id, alert.eventId, alert.severity, alert.title, alert.description,
        alert.businessId, JSON.stringify(alert.channels), alert.status,
        alert.createdAt, alert.updatedAt
      ).run();
    } catch (error) {
      this.logger.error('Failed to persist security alert', error);
    }
  }

  private async sendWebhookAlert(alert: SecurityAlert, event: SecurityEvent): Promise<void> {
    if (!this.env.SECURITY_WEBHOOK_URL) return;

    const payload = {
      alert,
      event,
      timestamp: Date.now()
    };

    const response = await fetch(this.env.SECURITY_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`Webhook alert failed: ${response.statusText}`);
    }
  }

  private async sendSMSAlert(alert: SecurityAlert, event: SecurityEvent): Promise<void> {
    // SMS implementation would depend on provider (Twilio, etc.)
    this.logger.info('SMS alert would be sent here', { alertId: alert.id });
  }

  private async checkApiUsageAnomaly(userKey: string, event: SecurityEvent): Promise<void> {
    // Implementation for API usage anomaly detection
  }

  private async checkGeographicAnomaly(userKey: string, event: SecurityEvent): Promise<void> {
    // Implementation for geographic location anomaly detection
  }
}

// Export singleton instance
export const securityMonitor = new SecurityMonitor({});