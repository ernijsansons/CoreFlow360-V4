import type {
  ChannelType,
  ChannelContent,
  ChannelMessage,
  MessageStatus,
  Lead,
  Contact
} from '../../types/crm';
import type { Env } from '../../types/env';

export interface IChannel {
  type: ChannelType;
  send(recipient: Lead | Contact, content: ChannelContent): Promise<ChannelMessage>;
  getStatus(messageId: string): Promise<MessageStatus>;
  validateContent(content: ChannelContent): boolean;
  getQuotaStatus(): Promise<{ used: number; limit: number; remaining: number }>;
  formatContent(content: ChannelContent, recipient: Lead | Contact): Promise<string>;
}

export abstract class BaseChannel implements IChannel {
  protected env: Env;
  abstract type: ChannelType;

  constructor(env: Env) {
    this.env = env;
  }

  abstract send(recipient: Lead | Contact, content: ChannelContent): Promise<ChannelMessage>;

  abstract getStatus(messageId: string): Promise<MessageStatus>;

  abstract validateContent(content: ChannelContent): boolean;

  abstract getQuotaStatus(): Promise<{ used: number; limit: number; remaining: number }>;

  abstract formatContent(content: ChannelContent, recipient: Lead | Contact): Promise<string>;

  protected generateMessageId(): string {
    return `msg_${this.type}_${Date.now()}_${Math.random().toString(36).substring(7)}`;
  }

  protected async trackMessage(message: ChannelMessage): Promise<void> {
    // Store message in database
    const db = this.env.DB_CRM;
    await db.prepare(`
      INSERT INTO channel_messages (
        id, campaign_id, business_id, lead_id, contact_id,
        channel, direction, status, content, sent_at,
        ai_generated, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      message.id,
      message.campaign_id || null,
      message.business_id,
      message.lead_id,
      message.contact_id || null,
      message.channel,
      message.direction,
      message.status,
      JSON.stringify(message.content),
      message.sent_at || null,
      message.ai_generated ? 1 : 0,
      message.created_at,
      message.updated_at
    ).run();
  }

  protected async updateMessageStatus(
    messageId: string,
    status: MessageStatus,
    additionalData?: Partial<ChannelMessage>
  ): Promise<void> {
    const db = this.env.DB_CRM;
    const updates = [`status = ?`, `updated_at = ?`];
    const values = [status, new Date().toISOString()];

    if (additionalData?.delivered_at) {
      updates.push('delivered_at = ?');
      values.push(additionalData.delivered_at);
    }
    if (additionalData?.opened_at) {
      updates.push('opened_at = ?');
      values.push(additionalData.opened_at);
    }
    if (additionalData?.clicked_at) {
      updates.push('clicked_at = ?');
      values.push(additionalData.clicked_at);
    }
    if (additionalData?.replied_at) {
      updates.push('replied_at = ?');
      values.push(additionalData.replied_at);
    }
    if (additionalData?.bounce_reason) {
      updates.push('bounce_reason = ?');
      values.push(additionalData.bounce_reason);
    }
    if (additionalData?.error_message) {
      updates.push('error_message = ?');
      values.push(additionalData.error_message);
    }

    values.push(messageId);

    await db.prepare(`
      UPDATE channel_messages
      SET ${updates.join(', ')}
      WHERE id = ?
    `).bind(...values).run();
  }

  protected async personalizeContent(
    content: ChannelContent,
    recipient: Lead | Contact
  ): Promise<ChannelContent> {
    const personalizedContent = { ...content };

    // Replace personalization tokens
    if (content.personalization_tokens && content.personalization_tokens.length > 0) {
      let body = content.body;
      let subject = content.subject || '';

      for (const token of content.personalization_tokens) {
        const value = this.getTokenValue(token, recipient);
        body = body.replace(new RegExp(`{{${token}}}`, 'g'), value);
        subject = subject.replace(new RegExp(`{{${token}}}`, 'g'), value);
      }

      personalizedContent.body = body;
      if (subject) {
        personalizedContent.subject = subject;
      }
    }

    return personalizedContent;
  }

  private getTokenValue(token: string, recipient: Lead | Contact): string {
    const recipientData: any = recipient;

    // Handle nested properties
    const keys = token.split('.');
    let value = recipientData;

    for (const key of keys) {
      value = value?.[key];
      if (value === undefined) {
        break;
      }
    }

    // Return value or fallback
    if (value !== undefined && value !== null) {
      return String(value);
    }

    // Default fallbacks
    const fallbacks: Record<string, string> = {
      'first_name': 'there',
      'company_name': 'your company',
      'title': 'your role'
    };

    return fallbacks[token] || '';
  }

  protected async checkRateLimit(identifier: string): Promise<boolean> {
    const key = `rate_limit:${this.type}:${identifier}`;
    const limit = await this.getRateLimit();

    // Use KV store for rate limiting
    const current = await this.env.KV.get(key);
    const count = current ? parseInt(current) : 0;

    if (count >= limit) {
      return false;
    }

    // Increment counter with TTL of 1 hour
    await this.env.KV.put(key, String(count + 1), { expirationTtl: 3600 });
    return true;
  }

  protected abstract getRateLimit(): Promise<number>;

  protected async logChannelError(error: Error, context: any): Promise<void> {

    // Store error in database for monitoring
    const db = this.env.DB_CRM;
    await db.prepare(`
      INSERT INTO channel_errors (
        channel, error_message, error_context, created_at
      ) VALUES (?, ?, ?, ?)
    `).bind(
      this.type,
      error.message,
      JSON.stringify(context),
      new Date().toISOString()
    ).run();
  }
}