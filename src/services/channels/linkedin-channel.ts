import { BaseChannel } from './base-channel';
import type {
  ChannelContent,
  ChannelMessage,
  MessageStatus,
  Lead,
  Contact,
  LinkedInChannel as LinkedInConfig
} from '../../types/crm';

export class LinkedInChannel extends BaseChannel {
  type: 'linkedin' = 'linkedin' as const;
  private config: LinkedInConfig;

  constructor(env: any, config?: LinkedInConfig) {
    super(env);
    this.config = config || {
      connection_status: 'not_connected',
      automation_enabled: false,
      daily_connection_limit: 50,
      daily_message_limit: 100,
      use_sales_navigator: false,
      profile_views_enabled: true
    };
  }

  async send(recipient: Lead | Contact, content: ChannelContent): Promise<ChannelMessage> {
    // Validate content
    if (!this.validateContent(content)) {
      throw new Error('Invalid LinkedIn content');
    }

    // Check if recipient has LinkedIn URL - Contact always has it, Lead might have as joined field
    const linkedinUrl = 'linkedin_url' in recipient ? recipient.linkedin_url : undefined;
    if (!linkedinUrl) {
      throw new Error('Recipient does not have a LinkedIn profile');
    }

    // Check connection status with recipient
    const isConnected = await this.checkConnection(linkedinUrl);
    if (!isConnected && content.metadata?.requireConnection !== false) {
      throw new Error('Not connected with recipient on LinkedIn');
    }

    // Check rate limit
    const canSend = await this.checkRateLimit('daily');
    if (!canSend) {
      throw new Error('LinkedIn daily message limit exceeded');
    }

    // Personalize content
    const personalizedContent = await this.personalizeContent(content, recipient);
    const formattedBody = await this.formatContent(personalizedContent, recipient);

    // Create message record
    const message: ChannelMessage = {
      id: this.generateMessageId(),
      business_id: recipient.business_id,
      lead_id: 'id' in recipient ? recipient.id : '',
      contact_id: 'email' in recipient && !('status' in recipient) ? recipient.id : undefined,
      channel: 'linkedin',
      direction: 'outbound',
      status: 'pending',
      content: {
        body: formattedBody,
        metadata: {
          profile_url: linkedinUrl,
          is_inmail: !isConnected,
          used_sales_navigator: this.config.use_sales_navigator
        }
      },
      ai_generated: personalizedContent.ai_generated,
      personalization_score: this.calculatePersonalizationScore(personalizedContent),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    // Track message
    await this.trackMessage(message);

    try {
      // Send via LinkedIn API or automation tool
      await this.sendViaLinkedIn(recipient, formattedBody, isConnected);

      // Update status
      message.status = 'sent';
      message.sent_at = new Date().toISOString();
      await this.updateMessageStatus(message.id, 'sent', { sent_at: message.sent_at });

      // Track profile view if enabled
      if (this.config.profile_views_enabled) {
        await this.trackProfileView(linkedinUrl);
      }

    } catch (error: any) {
      message.status = 'failed';
      message.error_message = error instanceof Error ? error.message : 'Unknown error';
      await this.updateMessageStatus(message.id, 'failed', {
        error_message: message.error_message
      });
      throw error;
    }

    return message;
  }

  async getStatus(messageId: string): Promise<MessageStatus> {
    const db = this.env.DB_CRM;
    if (!db) return 'failed';

    const result = await db.prepare(
      'SELECT status FROM channel_messages WHERE id = ?'
    ).bind(messageId).first<{ status: MessageStatus }>();

    return result?.status || 'failed';
  }

  validateContent(content: ChannelContent): boolean {
    if (!content.body) return false;

    // LinkedIn message limits
    if (content.body.length > 8000) return false; // LinkedIn message character limit

    // LinkedIn doesn't support attachments in messages
    if (content.attachments && content.attachments.length > 0) {
      return false;
    }

    return true;
  }

  async getQuotaStatus(): Promise<{ used: number; limit: number; remaining: number }> {
    const dayKey = `quota:linkedin:day:${new Date().toISOString().split('T')[0]}`;
    const kv = this.env.KV_CACHE || this.env.KV_RATE_LIMIT_METRICS;
    const used = (kv ? await kv.get(dayKey) : null) || '0';
    const dailyUsed = parseInt(used);

    return {
      used: dailyUsed,
      limit: this.config.daily_message_limit,
      remaining: Math.max(0, this.config.daily_message_limit - dailyUsed)
    };
  }

  async formatContent(content: ChannelContent, recipient: Lead | Contact): Promise<string> {
    let message = content.body;

    // Add professional greeting if not present
    if (!message.toLowerCase().startsWith('hi') && !message.toLowerCase().startsWith('hello')) {
      const name = recipient.first_name || 'there';
      message = `Hi ${name},\n\n${message}`;
    }

    // Add CTA if present
    if (content.cta) {
      if (content.cta.type === 'calendar') {
        message += `\n\nWould you be available for a quick call? Here's my calendar: ${content.cta.url}`;
      } else if (content.cta.url) {
        message += `\n\n${content.cta.text}: ${content.cta.url}`;
      }
    }

    // Add professional closing if not present
    if (!message.includes('regards') && !message.includes('best') && !message.includes('sincerely')) {
      message += '\n\nBest regards';
    }

    return message;
  }

  protected async getRateLimit(): Promise<number> {
    return this.config.daily_message_limit;
  }

  private async checkConnection(linkedinUrl: string): Promise<boolean> {
    // Check if we have a connection record
    const db = this.env.DB_CRM;
    if (!db) return false;

    const result = await db.prepare(`
      SELECT connected FROM linkedin_connections
      WHERE profile_url = ?
    `).bind(linkedinUrl).first<{ connected: number }>();

    return result?.connected === 1;
  }

  private async sendViaLinkedIn(
    recipient: Lead | Contact,
    message: string,
    isConnected: boolean
  ): Promise<void> {
    if (!this.config.automation_enabled) {
      // Queue for manual sending
      await this.queueForManualSending(recipient, message);
      return;
    }

    // In production, this would integrate with LinkedIn API or automation tools
    // For now, simulate sending

    // Update quota
    const kv = this.env.KV_CACHE || this.env.KV_RATE_LIMIT_METRICS;
    if (kv) {
      const dayKey = `quota:linkedin:day:${new Date().toISOString().split('T')[0]}`;
      const current = await kv.get(dayKey) || '0';
      await kv.put(dayKey, String(parseInt(current) + 1), {
        expirationTtl: 86400 // 24 hours
      });
    }

    // Simulate API call delay
    await new Promise(resolve => setTimeout(resolve, 1000));
  }

  private async queueForManualSending(recipient: Lead | Contact, message: string): Promise<void> {
    const db = this.env.DB_CRM;
    if (!db) return;

    const linkedinUrl = 'linkedin_url' in recipient ? recipient.linkedin_url : undefined;
    await db.prepare(`
      INSERT INTO linkedin_message_queue (
        recipient_id, recipient_name, linkedin_url, message, status, created_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
      recipient.id,
      `${recipient.first_name || ''} ${recipient.last_name || ''}`.trim(),
      linkedinUrl || '',
      message,
      'queued',
      new Date().toISOString()
    ).run();
  }

  private async trackProfileView(linkedinUrl: string): Promise<void> {
    const db = this.env.DB_CRM;
    if (!db) return;

    await db.prepare(`
      INSERT INTO linkedin_profile_views (
        profile_url, viewed_at
      ) VALUES (?, ?)
    `).bind(linkedinUrl, new Date().toISOString()).run();
  }

  private calculatePersonalizationScore(content: ChannelContent): number {
    let score = 0;

    // Check for personalization tokens
    const tokens = content.personalization_tokens || [];
    if (tokens.length > 0) score += 30;

    // LinkedIn specific personalization
    if (content.body.includes('mutual connection')) score += 15;
    if (content.body.includes('saw your post')) score += 15;
    if (content.body.includes('your experience')) score += 10;
    if (content.body.includes('your company')) score += 10;

    // AI generation bonus
    if (content.ai_generated) score += 20;

    return Math.min(score, 100);
  }

  async sendConnectionRequest(
    recipient: Lead | Contact,
    note?: string
  ): Promise<void> {
    const kv = this.env.KV_CACHE || this.env.KV_RATE_LIMIT_METRICS;
    if (!kv) throw new Error('KV storage not available');

    // Check daily connection limit
    const dayKey = `quota:linkedin:connections:${new Date().toISOString().split('T')[0]}`;
    const current = await kv.get(dayKey) || '0';
    const dailyUsed = parseInt(current);

    if (dailyUsed >= this.config.daily_connection_limit) {
      throw new Error('Daily LinkedIn connection limit exceeded');
    }

    const linkedinUrl = 'linkedin_url' in recipient ? recipient.linkedin_url : undefined;
    if (!linkedinUrl) {
      throw new Error('Recipient does not have a LinkedIn profile');
    }

    // Queue connection request
    const db = this.env.DB_CRM;
    if (db) {
      await db.prepare(`
        INSERT INTO linkedin_connection_requests (
          recipient_id, linkedin_url, note, status, created_at
        ) VALUES (?, ?, ?, ?, ?)
      `).bind(
        recipient.id,
        linkedinUrl,
        note || '',
        'pending',
        new Date().toISOString()
      ).run();
    }

    // Update quota
    await kv.put(dayKey, String(dailyUsed + 1), {
      expirationTtl: 86400
    });
  }
}