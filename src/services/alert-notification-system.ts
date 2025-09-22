// CoreFlow360 V4 - Multi-Channel Alert Notification System
import { Alert, NotificationChannel, AlertNotification, NotificationChannelConfig } from '../types/observability';

export class AlertNotificationSystem {
  private env: any;
  private db: D1Database;

  constructor(env: any) {
    this.env = env;
    this.db = env.DB;
  }

  async sendAlert(alert: Alert): Promise<void> {
    // Get notification channels for the alert
    const channels = await this.getNotificationChannels(alert.businessId);

    // Filter channels based on alert severity and rules
    const applicableChannels = this.filterChannelsBySeverity(channels, alert.severity);

    // Send notifications through all applicable channels
    for (const channel of applicableChannels) {
      await this.sendNotificationThroughChannel(alert, channel);
    }
  }

  private async getNotificationChannels(businessId: string): Promise<NotificationChannel[]> {
    const result = await this.db.prepare(`
      SELECT * FROM notification_channels
      WHERE business_id = ? AND enabled = true
      ORDER BY type
    `).bind(businessId).all();

    return result.results.map(row => ({
      id: row.id,
      businessId: row.business_id,
      name: row.name,
      type: row.type,
      enabled: row.enabled,
      config: JSON.parse(row.config),
      rateLimitEnabled: row.rate_limit_enabled,
      rateLimitCount: row.rate_limit_count,
      rateLimitWindow: row.rate_limit_window,
      lastTestAt: row.last_test_at ? new Date(row.last_test_at) : undefined,
      lastTestStatus: row.last_test_status,
      lastTestError: row.last_test_error,
      createdBy: row.created_by,
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at)
    }));
  }

  private filterChannelsBySeverity(channels: NotificationChannel[], severity: string): NotificationChannel[] {
    // Basic filtering - in production this would be more sophisticated
    switch (severity) {
      case 'critical':
        return channels; // Send to all channels for critical alerts
      case 'high':
        return channels.filter(c => ['email', 'sms', 'pagerduty', 'slack'].includes(c.type));
      case 'medium':
        return channels.filter(c => ['email', 'slack', 'teams'].includes(c.type));
      case 'low':
        return channels.filter(c => ['email', 'slack'].includes(c.type));
      default:
        return channels.filter(c => c.type === 'email');
    }
  }

  private async sendNotificationThroughChannel(alert: Alert, channel: NotificationChannel): Promise<void> {
    // Check rate limiting
    if (channel.rateLimitEnabled) {
      const isRateLimited = await this.checkRateLimit(channel);
      if (isRateLimited) {
        return;
      }
    }

    try {
      switch (channel.type) {
        case 'email':
          await this.sendEmailNotification(alert, channel);
          break;
        case 'sms':
          await this.sendSMSNotification(alert, channel);
          break;
        case 'slack':
          await this.sendSlackNotification(alert, channel);
          break;
        case 'webhook':
          await this.sendWebhookNotification(alert, channel);
          break;
        case 'pagerduty':
          await this.sendPagerDutyNotification(alert, channel);
          break;
        case 'teams':
          await this.sendTeamsNotification(alert, channel);
          break;
        case 'discord':
          await this.sendDiscordNotification(alert, channel);
          break;
        default:
          throw new Error(`Unsupported notification type: ${channel.type}`);
      }

      // Log successful notification
      await this.logNotification(alert.id, channel, 'sent');

    } catch (error) {
      await this.logNotification(alert.id, channel, 'failed', error instanceof Error ? error.message : 'Unknown error');

      // Schedule retry for failed notifications
      await this.scheduleRetry(alert.id, channel.id);
    }
  }

  private async sendEmailNotification(alert: Alert, channel: NotificationChannel): Promise<void> {
    const config = channel.config as NotificationChannelConfig;

    const emailContent = this.generateEmailContent(alert);

    // Use Cloudflare Email Workers or external SMTP
    if (this.env.EMAIL_PROVIDER === 'smtp') {
      await this.sendSMTPEmail(config, emailContent, alert);
    } else {
      await this.sendCloudflareEmail(config, emailContent, alert);
    }
  }

  private async sendSMTPEmail(config: NotificationChannelConfig, content: any, alert: Alert): Promise<void> {
    const nodemailer = await import('nodemailer');

    const transporter = nodemailer.createTransporter({
      host: config.smtpHost,
      port: config.smtpPort,
      secure: config.smtpPort === 465,
      auth: {
        user: config.smtpUser,
        pass: config.smtpPassword,
      },
    });

    const mailOptions = {
      from: config.fromEmail,
      to: config.toEmails?.join(','),
      subject: content.subject,
      html: content.html,
      text: content.text
    };

    await transporter.sendMail(mailOptions);
  }

  private async sendCloudflareEmail(config: NotificationChannelConfig, content: any, alert: Alert): Promise<void> {
    // Use Cloudflare Email Workers API
    const response = await fetch(`${this.env.EMAIL_API_ENDPOINT}/send`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.env.EMAIL_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: config.fromEmail,
        to: config.toEmails,
        subject: content.subject,
        html: content.html
      })
    });

    if (!response.ok) {
      throw new Error(`Email API error: ${response.statusText}`);
    }
  }

  private generateEmailContent(alert: Alert): { subject: string; html: string; text: string } {
    const subject = `🚨 ${alert.severity.toUpperCase()}: ${alert.title}`;

    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          .alert-card {
            background: #f8f9fa;
            border-left: 4px solid ${this.getSeverityColor(alert.severity)};
            padding: 20px;
            margin: 20px 0;
            font-family: Arial, sans-serif;
          }
          .severity {
            background: ${this.getSeverityColor(alert.severity)};
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            display: inline-block;
            text-transform: uppercase;
          }
          .metadata { background: #f0f0f0; padding: 10px; margin: 10px 0; }
          .actions { margin-top: 20px; }
          .btn {
            background: #007bff;
            color: white;
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 4px;
            display: inline-block;
          }
        </style>
      </head>
      <body>
        <div class="alert-card">
          <h2>${alert.title}</h2>
          <span class="severity">${alert.severity}</span>

          <p><strong>Description:</strong> ${alert.description || 'No description provided'}</p>

          <div class="metadata">
            <p><strong>Triggered:</strong> ${new Date(alert.triggeredAt).toLocaleString()}</p>
            <p><strong>Alert ID:</strong> ${alert.id}</p>
            ${alert.metricValue ? `<p><strong>Metric Value:</strong> ${alert.metricValue}</p>` : ''}
            ${alert.thresholdValue ? `<p><strong>Threshold:</strong> ${alert.thresholdValue}</p>` : ''}
          </div>

          ${Object.keys(alert.labels).length > 0 ? `
          <div class="metadata">
            <h4>Labels:</h4>
            ${Object.entries(alert.labels).map(([key, value]) => `<p><strong>${key}:</strong> ${value}</p>`).join('')}
          </div>
          ` : ''}

          <div class="actions">
            <a href="${this.env.DASHBOARD_URL}/observability/alerts/${alert.id}" class="btn">
              View in Dashboard
            </a>
          </div>
        </div>
      </body>
      </html>
    `;

    const text = `
      ALERT: ${alert.title}
      Severity: ${alert.severity.toUpperCase()}
      Description: ${alert.description || 'No description provided'}
      Triggered: ${new Date(alert.triggeredAt).toLocaleString()}
      Alert ID: ${alert.id}
      ${alert.metricValue ? `Metric Value: ${alert.metricValue}\n` : ''}
      ${alert.thresholdValue ? `Threshold: ${alert.thresholdValue}\n` : ''}

      View in Dashboard: ${this.env.DASHBOARD_URL}/observability/alerts/${alert.id}
    `;

    return { subject, html, text };
  }

  private async sendSMSNotification(alert: Alert, channel: NotificationChannel): Promise<void> {
    const config = channel.config as NotificationChannelConfig;

    const message
  = `🚨 ${alert.severity.toUpperCase()}: ${alert.title}\n\nTriggered: ${new Date(alert.triggeredAt).toLocaleTimeString()}\n\nView: ${this.env.DASHBOARD_URL}/alerts/${alert.id}`;

    // Use Twilio API
    const response = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${config.twilioAccountSid}/Messages.json`, {
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + btoa(`${config.twilioAccountSid}:${config.twilioAuthToken}`),
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        To: config.toPhones?.join(',') || '',
        From: config.fromPhone || '',
        Body: message
      })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Twilio API error: ${error}`);
    }
  }

  private async sendSlackNotification(alert: Alert, channel: NotificationChannel): Promise<void> {
    const config = channel.config as NotificationChannelConfig;

    const payload = {
      text: `🚨 Alert: ${alert.title}`,
      attachments: [{
        color: this.getSeverityColor(alert.severity),
        fields: [
          { title: 'Severity', value: alert.severity.toUpperCase(), short: true },
          { title: 'Triggered', value: new Date(alert.triggeredAt).toLocaleString(), short: true },
          { title: 'Description', value: alert.description || 'No description', short: false }
        ],
        actions: [{
          type: 'button',
          text: 'View in Dashboard',
          url: `${this.env.DASHBOARD_URL}/observability/alerts/${alert.id}`,
          style: 'primary'
        }]
      }],
      channel: config.slackChannel
    };

    const response = await fetch(config.slackWebhookUrl!, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`Slack API error: ${response.statusText}`);
    }
  }

  private async sendWebhookNotification(alert: Alert, channel: NotificationChannel): Promise<void> {
    const config = channel.config as NotificationChannelConfig;

    const payload = {
      alert,
      timestamp: new Date().toISOString(),
      source: 'CoreFlow360',
      version: '4.0'
    };

    const response = await fetch(config.webhookUrl!, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...config.webhookHeaders
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(config.webhookTimeout || 30000)
    });

    if (!response.ok) {
      throw new Error(`Webhook error: ${response.statusText}`);
    }
  }

  private async sendPagerDutyNotification(alert: Alert, channel: NotificationChannel): Promise<void> {
    const config = channel.config as NotificationChannelConfig;

    const payload = {
      routing_key: config.pagerdutyIntegrationKey,
      event_action: 'trigger',
      dedup_key: alert.fingerprint,
      payload: {
        summary: alert.title,
        severity: alert.severity,
        source: 'CoreFlow360',
        component: alert.labels.module || 'unknown',
        group: alert.labels.capability || 'unknown',
        class: 'alert',
        custom_details: {
          description: alert.description,
          triggered_at: alert.triggeredAt,
          metric_value: alert.metricValue,
          threshold_value: alert.thresholdValue,
          labels: alert.labels,
          annotations: alert.annotations
        }
      },
      links: [{
        href: `${this.env.DASHBOARD_URL}/observability/alerts/${alert.id}`,
        text: 'View in CoreFlow360 Dashboard'
      }]
    };

    const response = await fetch('https://events.pagerduty.com/v2/enqueue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`PagerDuty API error: ${response.statusText}`);
    }
  }

  private async sendTeamsNotification(alert: Alert, channel: NotificationChannel): Promise<void> {
    const config = channel.config as NotificationChannelConfig;

    const payload = {
      '@type': 'MessageCard',
      '@context': 'http://schema.org/extensions',
      themeColor: this.getSeverityColor(alert.severity),
      summary: alert.title,
      sections: [{
        activityTitle: `🚨 ${alert.title}`,
        activitySubtitle: `Severity: ${alert.severity.toUpperCase()}`,
        facts: [
          { name: 'Triggered', value: new Date(alert.triggeredAt).toLocaleString() },
          { name: 'Description', value: alert.description || 'No description' },
          ...(alert.metricValue ? [{ name: 'Metric Value', value: alert.metricValue.toString() }] : []),
          ...(alert.thresholdValue ? [{ name: 'Threshold', value: alert.thresholdValue.toString() }] : [])
        ]
      }],
      potentialAction: [{
        '@type': 'OpenUri',
        name: 'View in Dashboard',
        targets: [{
          os: 'default',
          uri: `${this.env.DASHBOARD_URL}/observability/alerts/${alert.id}`
        }]
      }]
    };

    const response = await fetch(config.teamsWebhookUrl!, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`Teams API error: ${response.statusText}`);
    }
  }

  private async sendDiscordNotification(alert: Alert, channel: NotificationChannel): Promise<void> {
    const config = channel.config as NotificationChannelConfig;

    const payload = {
      content: `🚨 **${alert.severity.toUpperCase()} Alert**`,
      embeds: [{
        title: alert.title,
        description: alert.description || 'No description provided',
        color: parseInt(this.getSeverityColor(alert.severity).replace('#', ''), 16),
        fields: [
          { name: 'Severity', value: alert.severity.toUpperCase(), inline: true },
          { name: 'Triggered', value: new Date(alert.triggeredAt).toLocaleString(), inline: true },
          ...(alert.metricValue ? [{ name: 'Metric Value', value: alert.metricValue.toString(), inline: true }] : []),
          ...(alert.thresholdValue ? [{ name: 'Threshold', value: alert.thresholdValue.toString(), inline: true }] : [])
        ],
        timestamp: new Date().toISOString(),
        footer: { text: 'CoreFlow360 V4' }
      }],
      components: [{
        type: 1,
        components: [{
          type: 2,
          style: 5,
          label: 'View in Dashboard',
          url: `${this.env.DASHBOARD_URL}/observability/alerts/${alert.id}`
        }]
      }]
    };

    const response = await fetch(config.discordWebhookUrl!, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`Discord API error: ${response.statusText}`);
    }
  }

  private async checkRateLimit(channel: NotificationChannel): Promise<boolean> {
    if (!channel.rateLimitEnabled) return false;

    const windowStart = new Date(Date.now() - channel.rateLimitWindow * 1000);

    const result = await this.db.prepare(`
      SELECT COUNT(*) as count
      FROM alert_notifications
      WHERE channel_type = ? AND channel_config LIKE ? AND sent_at >= ?
    `).bind(
      channel.type,
      `%${channel.id}%`,
      windowStart.toISOString()
    ).first();

    return (result?.count || 0) >= channel.rateLimitCount;
  }

  private async logNotification(
    alertId: string,
    channel: NotificationChannel,
    status: 'pending' | 'sent' | 'failed' | 'delivered',
    errorMessage?: string
  ): Promise<void> {
    const recipient = this.getChannelRecipient(channel);

    await this.db.prepare(`
      INSERT INTO alert_notifications (
        id, alert_id, channel_type, channel_config, recipient,
        status, sent_at, error_message, retry_count, created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      crypto.randomUUID(),
      alertId,
      channel.type,
      JSON.stringify({ channelId: channel.id }),
      recipient,
      status,
      status === 'sent' ? new Date().toISOString() : null,
      errorMessage,
      0,
      new Date().toISOString()
    ).run();
  }

  private async scheduleRetry(alertId: string, channelId: string): Promise<void> {
    // Implement exponential backoff retry logic
    const retryDelay = 5 * 60 * 1000; // 5 minutes initial delay
    const nextRetryAt = new Date(Date.now() + retryDelay);

    await this.db.prepare(`
      UPDATE alert_notifications
      SET next_retry_at = ?, retry_count = retry_count + 1
      WHERE alert_id = ? AND channel_config LIKE ?
    `).bind(
      nextRetryAt.toISOString(),
      alertId,
      `%${channelId}%`
    ).run();
  }

  async processRetries(): Promise<void> {
    // Get notifications that need retry
    const now = new Date().toISOString();
    const retries = await this.db.prepare(`
      SELECT an.*, a.* FROM alert_notifications an
      JOIN alerts a ON an.alert_id = a.id
      WHERE an.status = 'failed'
        AND an.next_retry_at <= ?
        AND an.retry_count < 3
    `).bind(now).all();

    for (const retry of retries.results) {
      try {
        // Get the channel configuration
        const channel = await this.db.prepare(`
          SELECT * FROM notification_channels WHERE id = ?
        `).bind(JSON.parse(retry.channel_config).channelId).first();

        if (channel) {
          const alert: Alert = {
            id: retry.alert_id,
            ruleId: retry.rule_id,
            businessId: retry.business_id,
            title: retry.title,
            description: retry.description,
            severity: retry.severity,
            status: retry.status,
            triggeredAt: new Date(retry.triggered_at),
            resolvedAt: retry.resolved_at ? new Date(retry.resolved_at) : undefined,
            metricValue: retry.metric_value,
            thresholdValue: retry.threshold_value,
            labels: JSON.parse(retry.labels || '{}'),
            annotations: JSON.parse(retry.annotations || '{}'),
            resolvedBy: retry.resolved_by,
            resolutionNote: retry.resolution_note,
            fingerprint: retry.fingerprint,
            createdAt: new Date(retry.created_at),
            updatedAt: new Date(retry.updated_at)
          };

          const notifChannel: NotificationChannel = {
            id: channel.id,
            businessId: channel.business_id,
            name: channel.name,
            type: channel.type,
            enabled: channel.enabled,
            config: JSON.parse(channel.config),
            rateLimitEnabled: channel.rate_limit_enabled,
            rateLimitCount: channel.rate_limit_count,
            rateLimitWindow: channel.rate_limit_window,
            createdBy: channel.created_by,
            createdAt: new Date(channel.created_at),
            updatedAt: new Date(channel.updated_at)
          };

          await this.sendNotificationThroughChannel(alert, notifChannel);
        }

      } catch (error) {

        // Update retry count and schedule next retry
        const nextRetryDelay = Math.min(retry.retry_count * 10 * 60 * 1000, 60 * 60 * 1000); // Max 1 hour
        const nextRetryAt = new Date(Date.now() + nextRetryDelay);

        await this.db.prepare(`
          UPDATE alert_notifications
          SET retry_count = retry_count + 1, next_retry_at = ?, error_message = ?
          WHERE id = ?
        `).bind(
          nextRetryAt.toISOString(),
          error instanceof Error ? error.message : 'Retry failed',
          retry.id
        ).run();
      }
    }
  }

  async testNotificationChannel(channelId: string): Promise<{ success: boolean; error?: string }> {
    try {
      const channel = await this.db.prepare(`
        SELECT * FROM notification_channels WHERE id = ?
      `).bind(channelId).first();

      if (!channel) {
        return { success: false, error: 'Channel not found' };
      }

      // Create a test alert
      const testAlert: Alert = {
        id: 'test-' + Date.now(),
        ruleId: 'test',
        businessId: channel.business_id,
        title: 'Test Alert - CoreFlow360 V4',
        description: 'This is a test alert to verify notification channel configuration.',
        severity: 'low',
        status: 'firing',
        triggeredAt: new Date(),
        labels: { test: 'true' },
        annotations: { test: 'notification' },
        fingerprint: 'test-fingerprint',
        createdAt: new Date(),
        updatedAt: new Date()
      };

      const notifChannel: NotificationChannel = {
        id: channel.id,
        businessId: channel.business_id,
        name: channel.name,
        type: channel.type,
        enabled: true, // Override for testing
        config: JSON.parse(channel.config),
        rateLimitEnabled: false, // Disable rate limiting for tests
        rateLimitCount: 0,
        rateLimitWindow: 0,
        createdBy: channel.created_by,
        createdAt: new Date(channel.created_at),
        updatedAt: new Date(channel.updated_at)
      };

      await this.sendNotificationThroughChannel(testAlert, notifChannel);

      // Update test status
      await this.db.prepare(`
        UPDATE notification_channels
        SET last_test_at = ?, last_test_status = 'success', last_test_error = NULL
        WHERE id = ?
      `).bind(new Date().toISOString(), channelId).run();

      return { success: true };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';

      // Update test status
      await this.db.prepare(`
        UPDATE notification_channels
        SET last_test_at = ?, last_test_status = 'failed', last_test_error = ?
        WHERE id = ?
      `).bind(new Date().toISOString(), errorMessage, channelId).run();

      return { success: false, error: errorMessage };
    }
  }

  private getSeverityColor(severity: string): string {
    switch (severity) {
      case 'critical': return '#dc2626';
      case 'high': return '#ea580c';
      case 'medium': return '#d97706';
      case 'low': return '#2563eb';
      default: return '#6b7280';
    }
  }

  private getChannelRecipient(channel: NotificationChannel): string {
    const config = channel.config;
    switch (channel.type) {
      case 'email': return config.toEmails?.join(', ') || '';
      case 'sms': return config.toPhones?.join(', ') || '';
      case 'slack': return config.slackChannel || '';
      case 'webhook': return config.webhookUrl || '';
      case 'teams': return 'Microsoft Teams';
      case 'discord': return 'Discord';
      case 'pagerduty': return 'PagerDuty';
      default: return channel.name;
    }
  }
}