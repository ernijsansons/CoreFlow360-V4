import { BaseChannel } from './base-channel';
import type {
  ChannelContent,
  ChannelMessage,
  MessageStatus,
  Lead,
  Contact,
  SMSChannel as SMSConfig
} from '../../types/crm';

export class SMSChannel extends BaseChannel {
  type: 'sms' = 'sms' as const;
  private config: SMSConfig;

  constructor(env: any, config?: SMSConfig) {
    super(env);
    this.config = config || {
      provider: 'twilio',
      from_number: '+1234567890',
      country_code: 'US',
      character_limit: 160,
      supports_mms: false
    };
  }

  async send(recipient: Lead | Contact, content: ChannelContent): Promise<ChannelMessage> {
    // Validate content
    if (!this.validateContent(content)) {
      throw new Error('Invalid SMS content');
    }

    // Check if recipient has valid phone
    if (!recipient.phone) {
      throw new Error('Recipient does not have a phone number');
    }

    // Check rate limit
    const canSend = await this.checkRateLimit(recipient.id);
    if (!canSend) {
      throw new Error('Rate limit exceeded for recipient');
    }

    // Personalize and format content
    const personalizedContent = await this.personalizeContent(content, recipient);
    const formattedBody = await this.formatContent(personalizedContent, recipient);

    // Create message record
    const message: ChannelMessage = {
      id: this.generateMessageId(),
      business_id: recipient.business_id,
      lead_id: 'id' in recipient ? recipient.id : '',
      contact_id: 'email' in recipient && !('status' in recipient) ? recipient.id : undefined,
      channel: 'sms',
      direction: 'outbound',
      status: 'pending',
      content: {
        body: formattedBody,
        metadata: {
          from: this.config.from_number,
          to: recipient.phone,
          segments: this.calculateSegments(formattedBody)
        }
      },
      ai_generated: personalizedContent.ai_generated,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    // Track message
    await this.trackMessage(message);

    try {
      // Send via provider
      await this.sendViaProvider(recipient.phone, formattedBody);

      // Update status
      message.status = 'sent';
      message.sent_at = new Date().toISOString();
      await this.updateMessageStatus(message.id, 'sent', { sent_at: message.sent_at });

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
    const result = await db.prepare(
      'SELECT status FROM channel_messages WHERE id = ?'
    ).bind(messageId).first();

    return result?.status || 'failed';
  }

  validateContent(content: ChannelContent): boolean {
    if (!content.body) return false;

    // Check message length
    const maxLength = this.config.character_limit * 5; // Allow up to 5 segments
    if (content.body.length > maxLength) return false;

    // SMS doesn't support attachments unless MMS is enabled
    if (content.attachments && content.attachments.length > 0) {
      if (!this.config.supports_mms) return false;
    }

    return true;
  }

  async getQuotaStatus(): Promise<{ used: number; limit: number; remaining: number }> {
    const dayKey = `quota:sms:day:${new Date().toISOString().split('T')[0]}`;
    const used = await this.env.KV.get(dayKey) || '0';
    const dailyUsed = parseInt(used);
    const limit = 500; // Daily SMS limit

    return {
      used: dailyUsed,
      limit,
      remaining: Math.max(0, limit - dailyUsed)
    };
  }

  async formatContent(content: ChannelContent, recipient: Lead | Contact): Promise<string> {
    let message = content.body;

    // Remove HTML if present
    message = message.replace(/<[^>]*>/g, '');

    // Add CTA if present
    if (content.cta && content.cta.url) {
      // Shorten URL if needed
      const shortUrl = await this.shortenUrl(content.cta.url);
      message += `\n\n${content.cta.text}: ${shortUrl}`;
    }

    // Add opt-out message
    if (!message.includes('STOP')) {
      message += '\n\nReply STOP to unsubscribe';
    }

    // Truncate if too long
    const maxLength = this.config.character_limit * 3; // Max 3 segments for marketing
    if (message.length > maxLength) {
      message = message.substring(0, maxLength - 3) + '...';
    }

    return message;
  }

  protected async getRateLimit(): Promise<number> {
    return 10; // 10 SMS per hour per recipient
  }

  private calculateSegments(message: string): number {
    const length = message.length;
    const limit = this.config.character_limit;

    if (length <= limit) return 1;

    // For multi-segment messages, each segment is reduced by 7 chars for headers
    const segmentLimit = limit - 7;
    return Math.ceil(length / segmentLimit);
  }

  private async shortenUrl(url: string): Promise<string> {
    // In production, use a URL shortening service
    // For now, return a mock shortened URL
    if (url.length > 30) {
      return `https://short.link/${Math.random().toString(36).substring(7)}`;
    }
    return url;
  }

  private async sendViaProvider(phoneNumber: string, message: string): Promise<void> {
    switch (this.config.provider) {
      case 'twilio':
        await this.sendViaTwilio(phoneNumber, message);
        break;
      case 'messagebird':
        await this.sendViaMessageBird(phoneNumber, message);
        break;
      default:
        throw new Error(`Unsupported SMS provider: ${this.config.provider}`);
    }

    // Update quota
    const dayKey = `quota:sms:day:${new Date().toISOString().split('T')[0]}`;
    const current = await this.env.KV.get(dayKey) || '0';
    await this.env.KV.put(dayKey, String(parseInt(current) + 1), {
      expirationTtl: 86400 // 24 hours
    });
  }

  private async sendViaTwilio(phoneNumber: string, message: string): Promise<void> {
    const accountSid = this.env.TWILIO_ACCOUNT_SID;
    const authToken = this.env.TWILIO_AUTH_TOKEN;

    const response = await fetch(
      `https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Messages.json`,
      {
        method: 'POST',
        headers: {
          'Authorization': 'Basic ' + btoa(`${accountSid}:${authToken}`),
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          From: this.config.from_number,
          To: phoneNumber,
          Body: message,
          MessagingServiceSid: this.config.messaging_service_id || ''
        }).toString()
      }
    );

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Twilio error: ${error}`);
    }
  }

  private async sendViaMessageBird(phoneNumber: string, message: string): Promise<void> {
    const response = await fetch('https://rest.messagebird.com/messages', {
      method: 'POST',
      headers: {
        'Authorization': `AccessKey ${this.env.MESSAGEBIRD_ACCESS_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        originator: this.config.from_number,
        recipients: [phoneNumber],
        body: message
      })
    });

    if (!response.ok) {
      throw new Error(`MessageBird error: ${response.statusText}`);
    }
  }
}