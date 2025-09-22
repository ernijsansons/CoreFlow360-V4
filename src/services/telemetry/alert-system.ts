import { Alert, AlertRule } from '../../types/telemetry';

interface NotificationChannel {
  id: string;
  type: 'email' | 'sms' | 'slack' | 'discord' | 'teams' | 'webhook' | 'pagerduty';
  config: Record<string, any>;
  enabled: boolean;
}

interface EscalationRule {
  id: string;
  alertRuleId: string;
  level: number;
  delayMinutes: number;
  channels: string[];
  conditions: string[];
}

interface OnCallSchedule {
  id: string;
  name: string;
  timezone: string;
  rotations: Array<{
    users: string[];
    startTime: string;
    durationHours: number;
    recurrence: 'daily' | 'weekly' | 'monthly';
  }>;
}

interface NotificationTemplate {
  id: string;
  type: string;
  subject: string;
  body: string;
  variables: string[];
}

export class AlertSystem {
  private channels: Map<string, NotificationChannel> = new Map();
  private escalationRules: Map<string, EscalationRule[]> = new Map();
  private onCallSchedules: Map<string, OnCallSchedule> = new Map();
  private templates: Map<string, NotificationTemplate> = new Map();
  private alertHistory: Map<string, Alert> = new Map();
  private silenceWindows: Map<string, { start: number; end: number; reason: string }> = new Map();
  private env: any;

  constructor(env: any) {
    this.env = env;
    this.initializeDefaultTemplates();
  }

  async sendAlert(alert: Alert): Promise<void> {
    // Check if alert is silenced
    if (this.isAlertSilenced(alert)) {
      return;
    }

    // Check for duplicate alerts
    const existing = this.findDuplicateAlert(alert);
    if (existing) {
      await this.handleDuplicateAlert(existing, alert);
      return;
    }

    // Store alert
    this.alertHistory.set(alert.id, alert);

    // Send to configured channels
    await this.deliverAlert(alert, alert.channels);

    // Set up escalation if configured
    const escalationRules = this.escalationRules.get(alert.id);
    if (escalationRules && escalationRules.length > 0) {
      this.scheduleEscalation(alert, escalationRules);
    }
  }

  private async deliverAlert(alert: Alert, channelIds: string[]): Promise<void> {
    const deliveryPromises = channelIds.map(async (channelId) => {
      const channel = this.channels.get(channelId);
      if (!channel || !channel.enabled) {
        return;
      }

      try {
        await this.sendToChannel(alert, channel);
      } catch (error) {
      }
    });

    await Promise.all(deliveryPromises);
  }

  private async sendToChannel(alert: Alert, channel: NotificationChannel): Promise<void> {
    const template = this.getTemplate(alert.severity, channel.type);
    const message = this.renderTemplate(template, alert);

    switch (channel.type) {
      case 'email':
        await this.sendEmail(alert, message, channel.config);
        break;
      case 'sms':
        await this.sendSMS(alert, message, channel.config);
        break;
      case 'slack':
        await this.sendSlack(alert, message, channel.config);
        break;
      case 'discord':
        await this.sendDiscord(alert, message, channel.config);
        break;
      case 'teams':
        await this.sendTeams(alert, message, channel.config);
        break;
      case 'webhook':
        await this.sendWebhook(alert, message, channel.config);
        break;
      case 'pagerduty':
        await this.sendPagerDuty(alert, message, channel.config);
        break;
    }
  }

  private async sendEmail(alert: Alert, message: any, config: any): Promise<void> {
    const emailData = {
      from: config.from || this.env.DEFAULT_FROM_EMAIL,
      to: config.to,
      subject: message.subject,
      html: this.generateEmailHTML(alert, message),
      text: message.body
    };

    if (this.env.RESEND_API_KEY) {
      await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.env.RESEND_API_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(emailData)
      });
    } else if (this.env.SENDGRID_API_KEY) {
      await fetch('https://api.sendgrid.com/v3/mail/send', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.env.SENDGRID_API_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          personalizations: [{ to: [{ email: config.to }] }],
          from: { email: emailData.from },
          subject: emailData.subject,
          content: [
            { type: 'text/html', value: emailData.html },
            { type: 'text/plain', value: emailData.text }
          ]
        })
      });
    }
  }

  private async sendSMS(alert: Alert, message: any, config: any): Promise<void> {
    if (!this.env.TWILIO_ACCOUNT_SID || !this.env.TWILIO_AUTH_TOKEN) {
      throw new Error('Twilio credentials not configured');
    }

    const authHeader = btoa(`${this.env.TWILIO_ACCOUNT_SID}:${this.env.TWILIO_AUTH_TOKEN}`);

    await fetch(`https://api.twilio.com/2010-04-01/Accounts/${this.env.TWILIO_ACCOUNT_SID}/Messages.json`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${authHeader}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        From: config.from || this.env.TWILIO_FROM_NUMBER,
        To: config.to,
        Body: `[${alert.severity.toUpperCase()}] ${alert.name}: ${alert.message}`
      })
    });
  }

  private async sendSlack(alert: Alert, message: any, config: any): Promise<void> {
    const slackMessage = {
      channel: config.channel,
      username: 'CoreFlow360 Alerts',
      icon_emoji: this.getAlertEmoji(alert.severity),
      attachments: [{
        color: this.getAlertColor(alert.severity),
        title: alert.name,
        text: alert.message,
        fields: [
          { title: 'Severity', value: alert.severity, short: true },
          { title: 'Source', value: alert.source, short: true },
          { title: 'Time', value: new Date(alert.timestamp).toISOString(), short: true }
        ],
        footer: 'CoreFlow360 Observability',
        ts: Math.floor(alert.timestamp / 1000)
      }]
    };

    await fetch(config.webhook_url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(slackMessage)
    });
  }

  private async sendDiscord(alert: Alert, message: any, config: any): Promise<void> {
    const discordMessage = {
      username: 'CoreFlow360 Alerts',
      avatar_url: 'https://example.com/avatar.png',
      embeds: [{
        title: alert.name,
        description: alert.message,
        color: parseInt(this.getAlertColor(alert.severity).replace('#', ''), 16),
        fields: [
          { name: 'Severity', value: alert.severity, inline: true },
          { name: 'Source', value: alert.source, inline: true },
          { name: 'Time', value: new Date(alert.timestamp).toISOString(), inline: true }
        ],
        footer: { text: 'CoreFlow360 Observability' },
        timestamp: new Date(alert.timestamp).toISOString()
      }]
    };

    await fetch(config.webhook_url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(discordMessage)
    });
  }

  private async sendTeams(alert: Alert, message: any, config: any): Promise<void> {
    const teamsMessage = {
      '@type': 'MessageCard',
      '@context': 'https://schema.org/extensions',
      summary: alert.name,
      themeColor: this.getAlertColor(alert.severity),
      sections: [{
        activityTitle: alert.name,
        activitySubtitle: alert.message,
        facts: [
          { name: 'Severity', value: alert.severity },
          { name: 'Source', value: alert.source },
          { name: 'Time', value: new Date(alert.timestamp).toISOString() }
        ]
      }]
    };

    await fetch(config.webhook_url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(teamsMessage)
    });
  }

  private async sendWebhook(alert: Alert, message: any, config: any): Promise<void> {
    const payload = {
      alert,
      message,
      timestamp: Date.now()
    };

    const headers: Record<string, string> = {
      'Content-Type': 'application/json'
    };

    if (config.auth_header) {
      headers['Authorization'] = config.auth_header;
    }

    await fetch(config.url, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
  }

  private async sendPagerDuty(alert: Alert, message: any, config: any): Promise<void> {
    const pagerDutyEvent = {
      routing_key: config.integration_key,
      event_action: 'trigger',
      dedup_key: alert.id,
      payload: {
        summary: alert.name,
        severity: this.mapSeverityToPagerDuty(alert.severity),
        source: alert.source,
        component: 'CoreFlow360',
        group: 'observability',
        class: 'alert',
        custom_details: {
          message: alert.message,
          metadata: alert.metadata
        }
      }
    };

    await fetch('https://events.pagerduty.com/v2/enqueue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(pagerDutyEvent)
    });
  }

  private getAlertEmoji(severity: string): string {
    switch (severity) {
      case 'critical': return ':rotating_light:';
      case 'high': return ':warning:';
      case 'medium': return ':yellow_circle:';
      case 'low': return ':information_source:';
      default: return ':grey_question:';
    }
  }

  private getAlertColor(severity: string): string {
    switch (severity) {
      case 'critical': return '#FF0000';
      case 'high': return '#FF6600';
      case 'medium': return '#FFCC00';
      case 'low': return '#0099CC';
      default: return '#808080';
    }
  }

  private mapSeverityToPagerDuty(severity: string): string {
    switch (severity) {
      case 'critical': return 'critical';
      case 'high': return 'error';
      case 'medium': return 'warning';
      case 'low': return 'info';
      default: return 'info';
    }
  }

  private generateEmailHTML(alert: Alert, message: any): string {
    const color = this.getAlertColor(alert.severity);

    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>${alert.name}</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
          .container { max-width: 600px;
  margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
          .header { background-color: ${color}; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; }
          .severity { display: inline-block; padding:
  4px 12px; border-radius: 4px; background-color: ${color}; color: white; font-size: 12px; font-weight: bold; text-transform: uppercase; }
          .details { margin-top: 20px; }
          .detail-row { margin-bottom: 10px; }
          .label { font-weight: bold; color: #666; }
          .footer { background-color: #f8f9fa; padding: 15px; text-align: center; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>${alert.name}</h1>
            <div class="severity">${alert.severity}</div>
          </div>
          <div class="content">
            <p><strong>Message:</strong> ${alert.message}</p>
            <div class="details">
        
       <div class="detail-row"><span class="label">Time:</span> ${new Date(alert.timestamp).toLocaleString()}</div>
              <div class="detail-row"><span class="label">Source:</span> ${alert.source}</div>
              <div class="detail-row"><span class="label">Alert ID:</span> ${alert.id}</div>
            </div>
          </div>
          <div class="footer">
            CoreFlow360 Observability Platform
          </div>
        </div>
      </body>
      </html>
    `;
  }

  private isAlertSilenced(alert: Alert): boolean {
    const now = Date.now();
    for (const [, silence] of this.silenceWindows) {
      if (now >= silence.start && now <= silence.end) {
        return true;
      }
    }
    return false;
  }

  private findDuplicateAlert(alert: Alert): Alert | undefined {
    for (const [, existing] of this.alertHistory) {
      if (
        existing.name === alert.name &&
        existing.source === alert.source &&
        existing.status === 'firing' &&
        Date.now() - existing.timestamp < 300000 // 5 minutes
      ) {
        return existing;
      }
    }
    return undefined;
  }

  private async handleDuplicateAlert(existing: Alert, newAlert: Alert): Promise<void> {
    // Correlate alerts
    if (!existing.correlatedAlerts.includes(newAlert.id)) {
      existing.correlatedAlerts.push(newAlert.id);
    }

    // Update escalation level if needed
    const timeSinceFirst = Date.now() - existing.timestamp;
    if (timeSinceFirst > 600000 && existing.escalationLevel < 2) { // 10 minutes
      existing.escalationLevel++;
      await this.escalateAlert(existing);
    }
  }

  private scheduleEscalation(alert: Alert, rules: EscalationRule[]): void {
    rules.forEach(rule => {
      setTimeout(async () => {
        if (this.shouldEscalate(alert, rule)) {
          await this.escalateAlert(alert, rule);
        }
      }, rule.delayMinutes * 60 * 1000);
    });
  }

  private shouldEscalate(alert: Alert, rule: EscalationRule): boolean {
    const current = this.alertHistory.get(alert.id);
    if (!current || current.status !== 'firing') {
      return false;
    }

    // Check escalation conditions
    return rule.conditions.every(condition => {
      switch (condition) {
        case 'not_acknowledged':
          return !current.acknowledgedAt;
        case 'not_resolved':
          return !current.resolvedAt;
        default:
          return true;
      }
    });
  }

  private async escalateAlert(alert: Alert, rule?: EscalationRule): Promise<void> {
    if (rule) {
      alert.escalationLevel = rule.level;
      await this.deliverAlert(alert, rule.channels);
    } else {
      // Default escalation
      const escalatedChannels = ['email', 'sms'];
      await this.deliverAlert(alert, escalatedChannels);
    }
  }

  async acknowledgeAlert(alertId: string, userId: string): Promise<void> {
    const alert = this.alertHistory.get(alertId);
    if (alert) {
      alert.status = 'acknowledged';
      alert.acknowledgedAt = Date.now();
      alert.acknowledgedBy = userId;
    }
  }

  async resolveAlert(alertId: string): Promise<void> {
    const alert = this.alertHistory.get(alertId);
    if (alert) {
      alert.status = 'resolved';
      alert.resolvedAt = Date.now();

      // Send resolution notification
      if (this.env.SEND_RESOLUTION_NOTIFICATIONS) {
        await this.sendResolutionNotification(alert);
      }
    }
  }

  private async sendResolutionNotification(alert: Alert): Promise<void> {
    const resolutionAlert: Alert = {
      ...alert,
      id: crypto.randomUUID(),
      name: `RESOLVED: ${alert.name}`,
      message: `Alert has been resolved. Original message: ${alert.message}`,
      severity: 'low',
      timestamp: Date.now()
    };

    await this.deliverAlert(resolutionAlert, alert.channels);
  }

  addChannel(channel: NotificationChannel): void {
    this.channels.set(channel.id, channel);
  }

  removeChannel(channelId: string): void {
    this.channels.delete(channelId);
  }

  addEscalationRule(rule: EscalationRule): void {
    const rules = this.escalationRules.get(rule.alertRuleId) || [];
    rules.push(rule);
    this.escalationRules.set(rule.alertRuleId, rules);
  }

  addSilenceWindow(id: string, start: number, end: number, reason: string): void {
    this.silenceWindows.set(id, { start, end, reason });
  }

  removeSilenceWindow(id: string): void {
    this.silenceWindows.delete(id);
  }

  private getTemplate(severity: string, channelType: string): NotificationTemplate {
    const templateKey = `${severity}_${channelType}`;
    return this.templates.get(templateKey) || this.templates.get(`default_${channelType}`)!;
  }

  private renderTemplate(template: NotificationTemplate, alert: Alert): any {
    let subject = template.subject;
    let body = template.body;

    const variables = {
      alert_name: alert.name,
      alert_message: alert.message,
      alert_severity: alert.severity,
      alert_source: alert.source,
      alert_timestamp: new Date(alert.timestamp).toISOString(),
      alert_id: alert.id
    };

    for (const [key, value] of Object.entries(variables)) {
      const regex = new RegExp(`\\{\\{${key}\\}\\}`, 'g');
      subject = subject.replace(regex, value);
      body = body.replace(regex, value);
    }

    return { subject, body };
  }

  private initializeDefaultTemplates(): void {
    const emailTemplates = [
      {
        id: 'critical_email',
        type: 'email',
        subject: '[CRITICAL] {{alert_name}}',
       
  body: 'A critical alert has been triggered:\n\n{{alert_message}}\n\nTime: {{alert_timestamp}}\nSource: {{alert_source}}',
        variables: ['alert_name', 'alert_message', 'alert_timestamp', 'alert_source']
      },
      {
        id: 'default_email',
        type: 'email',
        subject: '[{{alert_severity}}] {{alert_name}}',
        body: 'Alert: {{alert_message}}\n\nTime: {{alert_timestamp}}\nSource: {{alert_source}}',
        variables: ['alert_severity', 'alert_name', 'alert_message', 'alert_timestamp', 'alert_source']
      }
    ];

    emailTemplates.forEach(template => {
      this.templates.set(template.id, template);
    });
  }

  getActiveAlerts(): Alert[] {
    return Array.from(this.alertHistory.values()).filter(alert => alert.status === 'firing');
  }

  getAlertHistory(limit: number = 100): Alert[] {
    return Array.from(this.alertHistory.values())
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, limit);
  }

  getChannels(): NotificationChannel[] {
    return Array.from(this.channels.values());
  }

  testChannel(channelId: string): Promise<void> {
    const channel = this.channels.get(channelId);
    if (!channel) {
      throw new Error(`Channel ${channelId} not found`);
    }

    const testAlert: Alert = {
      id: crypto.randomUUID(),
      name: 'Test Alert',
      severity: 'low',
      status: 'firing',
      message: 'This is a test alert to verify channel configuration',
      timestamp: Date.now(),
      source: 'alert-system-test',
      metadata: { test: true },
      channels: [channelId],
      escalationLevel: 0,
      correlatedAlerts: []
    };

    return this.sendToChannel(testAlert, channel);
  }
}