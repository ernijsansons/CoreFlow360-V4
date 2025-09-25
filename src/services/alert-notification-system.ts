// CoreFlow360 V4 - Multi-Channel Alert Notification System
import { Alert, NotificationChannel, AlertNotification, NotificationChannelConfig } from '../types/observability';
import type { D1Database } from '@cloudflare/workers-types';

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
      id: row.id as string,
      businessId: row.business_id as string,
      name: row.name as string,
      type: row.type as 'email' | 'sms' | 'slack' | 'webhook' | 'pagerduty' | 'teams' | 'discord',
      enabled: row.enabled as boolean,
      config: JSON.parse(row.config as string),
      rateLimitEnabled: row.rate_limit_enabled as boolean,
      rateLimitCount: row.rate_limit_count as number,
      rateLimitWindow: row.rate_limit_window as number,
      lastTestAt: row.last_test_at ? new Date(row.last_test_at as string) : undefined,
      lastTestStatus: row.last_test_status as 'success' | 'failed' | undefined,
      lastTestError: row.last_test_error as string | undefined,
      createdBy: row.created_by as string,
      createdAt: new Date(row.created_at as string),
      updatedAt: new Date(row.updated_at as string)
    }));
  }

  private filterChannelsBySeverity(channels: NotificationChannel[], severity: string): NotificationChannel[] {
    return channels.filter(channel => {
      // For now, allow all channels - severity filtering would be configured per channel
      return true;
    });
  }

  private async sendNotificationThroughChannel(alert: Alert, channel: NotificationChannel): Promise<void> {
    try {
      // Check rate limiting
      if (channel.rateLimitEnabled) {
        const isRateLimited = await this.checkRateLimit(channel);
        if (isRateLimited) {
          console.log(`Rate limit exceeded for channel ${channel.id}`);
          return;
        }
      }

      // Send notification based on channel type
      switch (channel.type) {
        case 'email':
          await this.sendEmailNotification(alert, channel);
          break;
        case 'slack':
          await this.sendSlackNotification(alert, channel);
          break;
        case 'webhook':
          await this.sendWebhookNotification(alert, channel);
          break;
        case 'sms':
          await this.sendSMSNotification(alert, channel);
          break;
        default:
          console.log(`Unsupported channel type: ${channel.type}`);
      }

      // Record successful notification
      await this.recordNotification(alert, channel, 'sent');

    } catch (error) {
      console.error(`Failed to send notification through channel ${channel.id}:`, error);
      await this.recordNotification(alert, channel, 'failed', error.message);
    }
  }

  private async sendEmailNotification(alert: Alert, channel: NotificationChannel): Promise<void> {
    const config = channel.config as any;
    const emailData = {
      to: config.recipients,
      subject: `Alert: ${alert.title}`,
      body: this.formatAlertForEmail(alert),
      from: config.fromEmail || 'alerts@coreflow360.com'
    };

    // Mock email sending - would use real email service in production
    console.log('Sending email notification:', emailData);
  }

  private async sendSlackNotification(alert: Alert, channel: NotificationChannel): Promise<void> {
    const config = channel.config as any;
    const slackData = {
      channel: config.channel,
      text: this.formatAlertForSlack(alert),
      username: 'CoreFlow360 Alerts',
      icon_emoji: this.getSeverityEmoji(alert.severity)
    };

    // Mock Slack sending - would use real Slack API in production
    console.log('Sending Slack notification:', slackData);
  }

  private async sendWebhookNotification(alert: Alert, channel: NotificationChannel): Promise<void> {
    const config = channel.config as any;
    const webhookData = {
      url: config.url,
      method: config.method || 'POST',
      headers: config.headers || {},
      body: JSON.stringify({
        alert: alert,
        timestamp: new Date().toISOString(),
        source: 'CoreFlow360'
      })
    };

    // Mock webhook sending - would use real HTTP client in production
    console.log('Sending webhook notification:', webhookData);
  }

  private async sendSMSNotification(alert: Alert, channel: NotificationChannel): Promise<void> {
    const config = channel.config as any;
    const smsData = {
      to: config.phoneNumbers,
      message: this.formatAlertForSMS(alert)
    };

    // Mock SMS sending - would use real SMS service in production
    console.log('Sending SMS notification:', smsData);
  }

  private formatAlertForEmail(alert: Alert): string {
    return `
      <h2>Alert: ${alert.title}</h2>
      <p><strong>Severity:</strong> ${alert.severity}</p>
      <p><strong>Description:</strong> ${alert.description}</p>
      <p><strong>Timestamp:</strong> ${alert.triggeredAt}</p>
      <p><strong>Status:</strong> ${alert.status}</p>
      ${Object.keys(alert.labels).length > 0 ? `<p><strong>Labels:</strong> ${JSON.stringify(alert.labels, null, 2)}</p>` : ''}
    `;
  }

  private formatAlertForSlack(alert: Alert): string {
    return `*Alert: ${alert.title}*\nSeverity: ${alert.severity}\nDescription: ${alert.description}\nTimestamp: ${alert.triggeredAt}`;
  }

  private formatAlertForSMS(alert: Alert): string {
    return `Alert: ${alert.title} (${alert.severity}) - ${alert.description}`;
  }

  private getSeverityEmoji(severity: string): string {
    switch (severity.toLowerCase()) {
      case 'critical': return ':red_circle:';
      case 'high': return ':orange_circle:';
      case 'medium': return ':yellow_circle:';
      case 'low': return ':green_circle:';
      default: return ':white_circle:';
    }
  }

  private async checkRateLimit(channel: NotificationChannel): Promise<boolean> {
    const now = new Date();
    const windowStart = new Date(now.getTime() - channel.rateLimitWindow * 1000);

    const result = await this.db.prepare(`
      SELECT COUNT(*) as count
      FROM alert_notifications
      WHERE channel_id = ? AND status = 'sent' AND created_at >= ?
    `).bind(channel.id, windowStart.toISOString()).first();

    return (result.count as number) >= channel.rateLimitCount;
  }

  private async recordNotification(
    alert: Alert,
    channel: NotificationChannel,
    status: 'sent' | 'failed',
    error?: string
  ): Promise<void> {
    const notification: AlertNotification = {
      id: `notif_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      alertId: alert.id,
      channelType: channel.type,
      channelConfig: channel.config,
      recipient: 'default', // Would be determined by channel config
      status: status === 'sent' ? 'sent' : 'failed',
      sentAt: new Date(),
      errorMessage: error,
      retryCount: 0,
      createdAt: new Date()
    };

    await this.db.prepare(`
      INSERT INTO alert_notifications (
        id, alert_id, channel_type, channel_config, recipient, status, sent_at, error_message, retry_count, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      notification.id,
      notification.alertId,
      notification.channelType,
      JSON.stringify(notification.channelConfig),
      notification.recipient,
      notification.status,
      notification.sentAt?.toISOString(),
      notification.errorMessage,
      notification.retryCount,
      notification.createdAt.toISOString()
    ).run();
  }

  async createNotificationChannel(
    businessId: string,
    channelData: Omit<NotificationChannel, 'id' | 'createdAt' | 'updatedAt'>
  ): Promise<NotificationChannel> {
    const channel: NotificationChannel = {
      ...channelData,
      id: `channel_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    await this.db.prepare(`
      INSERT INTO notification_channels (
        id, business_id, name, type, enabled, config, rate_limit_enabled,
        rate_limit_count, rate_limit_window, created_by, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      channel.id,
      channel.businessId,
      channel.name,
      channel.type,
      channel.enabled,
      JSON.stringify(channel.config),
      channel.rateLimitEnabled,
      channel.rateLimitCount,
      channel.rateLimitWindow,
      channel.createdBy,
      channel.createdAt.toISOString(),
      channel.updatedAt.toISOString()
    ).run();

    return channel;
  }

  async updateNotificationChannel(
    channelId: string,
    updates: Partial<NotificationChannel>
  ): Promise<NotificationChannel | null> {
    const existing = await this.getNotificationChannel(channelId);
    if (!existing) return null;

    const updated: NotificationChannel = {
      ...existing,
      ...updates,
      updatedAt: new Date()
    };

    await this.db.prepare(`
      UPDATE notification_channels SET
        name = ?, type = ?, enabled = ?, config = ?, rate_limit_enabled = ?,
        rate_limit_count = ?, rate_limit_window = ?, updated_at = ?
      WHERE id = ?
    `).bind(
      updated.name,
      updated.type,
      updated.enabled,
      JSON.stringify(updated.config),
      updated.rateLimitEnabled,
      updated.rateLimitCount,
      updated.rateLimitWindow,
      updated.updatedAt.toISOString(),
      channelId
    ).run();

    return updated;
  }

  async deleteNotificationChannel(channelId: string): Promise<boolean> {
    const result = await this.db.prepare(`
      DELETE FROM notification_channels WHERE id = ?
    `).bind(channelId).run();

    return (result.meta?.changes as number) > 0;
  }

  async getNotificationChannel(channelId: string): Promise<NotificationChannel | null> {
    const result = await this.db.prepare(`
      SELECT * FROM notification_channels WHERE id = ?
    `).bind(channelId).first();

    if (!result) return null;

    return {
      id: result.id as string,
      businessId: result.business_id as string,
      name: result.name as string,
      type: result.type as 'email' | 'sms' | 'slack' | 'webhook' | 'pagerduty' | 'teams' | 'discord',
      enabled: result.enabled as boolean,
      config: JSON.parse(result.config as string),
      rateLimitEnabled: result.rate_limit_enabled as boolean,
      rateLimitCount: result.rate_limit_count as number,
      rateLimitWindow: result.rate_limit_window as number,
      lastTestAt: result.last_test_at ? new Date(result.last_test_at as string) : undefined,
      lastTestStatus: result.last_test_status as 'success' | 'failed' | undefined,
      lastTestError: result.last_test_error as string | undefined,
      createdBy: result.created_by as string,
      createdAt: new Date(result.created_at as string),
      updatedAt: new Date(result.updated_at as string)
    };
  }

  async testNotificationChannel(channelId: string): Promise<{ success: boolean; error?: string }> {
    const channel = await this.getNotificationChannel(channelId);
    if (!channel) {
      return { success: false, error: 'Channel not found' };
    }

    try {
      // Create test alert
      const testAlert: Alert = {
        id: `test_${Date.now()}`,
        ruleId: 'test_rule',
        businessId: channel.businessId,
        title: 'Test Alert',
        description: 'This is a test alert to verify notification channel configuration',
        severity: 'low',
        status: 'firing',
        triggeredAt: new Date(),
        labels: { test: 'true' },
        annotations: { test: 'true' },
        fingerprint: 'test_fingerprint',
        createdAt: new Date(),
        updatedAt: new Date()
      };

      // Send test notification
      await this.sendNotificationThroughChannel(testAlert, channel);

      // Update channel with test results
      await this.db.prepare(`
        UPDATE notification_channels SET
          last_test_at = ?, last_test_status = 'success', last_test_error = NULL
        WHERE id = ?
      `).bind(new Date().toISOString(), channelId).run();

      return { success: true };

    } catch (error) {
      // Update channel with test failure
      await this.db.prepare(`
        UPDATE notification_channels SET
          last_test_at = ?, last_test_status = 'failed', last_test_error = ?
        WHERE id = ?
      `).bind(new Date().toISOString(), error.message, channelId).run();

      return { success: false, error: error.message };
    }
  }

  async getNotificationHistory(
    alertId?: string,
    channelId?: string,
    limit: number = 100
  ): Promise<AlertNotification[]> {
    let query = 'SELECT * FROM alert_notifications WHERE 1=1';
    const params: any[] = [];

    if (alertId) {
      query += ' AND alert_id = ?';
      params.push(alertId);
    }

    if (channelId) {
      query += ' AND channel_id = ?';
      params.push(channelId);
    }

    query += ' ORDER BY sent_at DESC LIMIT ?';
    params.push(limit);

    const result = await this.db.prepare(query).bind(...params).all();

    return result.results.map(row => ({
      id: row.id as string,
      alertId: row.alert_id as string,
      channelType: row.channel_type as string,
      channelConfig: JSON.parse((row.channel_config as string) || '{}'),
      recipient: row.recipient as string,
      status: row.status as 'pending' | 'sent' | 'failed' | 'delivered',
      sentAt: row.sent_at ? new Date(row.sent_at as string) : undefined,
      deliveredAt: row.delivered_at ? new Date(row.delivered_at as string) : undefined,
      responseCode: row.response_code as number | undefined,
      responseMessage: row.response_message as string | undefined,
      errorMessage: row.error_message as string | undefined,
      retryCount: row.retry_count as number,
      nextRetryAt: row.next_retry_at ? new Date(row.next_retry_at as string) : undefined,
      createdAt: new Date(row.created_at as string)
    }));
  }

  async getNotificationStats(businessId: string): Promise<{
    totalChannels: number;
    activeChannels: number;
    totalNotifications: number;
    successfulNotifications: number;
    failedNotifications: number;
    averageResponseTime: number;
  }> {
    const channelsResult = await this.db.prepare(`
      SELECT COUNT(*) as total, SUM(CASE WHEN enabled = true THEN 1 ELSE 0 END) as active
      FROM notification_channels WHERE business_id = ?
    `).bind(businessId).first();

    const notificationsResult = await this.db.prepare(`
      SELECT COUNT(*) as total, SUM(CASE WHEN status = 'sent' THEN 1 ELSE 0 END) as successful
      FROM alert_notifications an
      JOIN notification_channels nc ON an.channel_id = nc.id
      WHERE nc.business_id = ?
    `).bind(businessId).first();

    return {
      totalChannels: channelsResult.total as number,
      activeChannels: channelsResult.active as number,
      totalNotifications: notificationsResult.total as number,
      successfulNotifications: notificationsResult.successful as number,
      failedNotifications: (notificationsResult.total as number) - (notificationsResult.successful as number),
      averageResponseTime: 0 // Would calculate from actual response times
    };
  }

  async healthCheck(): Promise<{ status: string; timestamp: string }> {
    try {
      return {
        status: 'healthy',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        timestamp: new Date().toISOString()
      };
    }
  }
}
