import { BaseChannel } from './base-channel';
import type {
  ChannelContent,
  ChannelMessage,
  MessageStatus,
  Lead,
  Contact,
  EmailChannel as EmailConfig
} from '../../types/crm';

export class EmailChannel extends BaseChannel {
  type: 'email' = 'email' as const;
  private config: EmailConfig;

  constructor(env: any, config?: EmailConfig) {
    super(env);
    this.config = config || {
      provider: 'sendgrid',
      from_address: 'noreply@example.com',
      from_name: 'CoreFlow360',
      daily_limit: 1000,
      hourly_limit: 100
    };
  }

  async send(recipient: Lead | Contact, content: ChannelContent): Promise<ChannelMessage> {
    // Validate content
    if (!this.validateContent(content)) {
      throw new Error('Invalid email content');
    }

    // Check rate limit
    const canSend = await this.checkRateLimit(recipient.id);
    if (!canSend) {
      throw new Error('Rate limit exceeded for recipient');
    }

    // Personalize content
    const personalizedContent = await this.personalizeContent(content, recipient);

    // Format email
    const formattedBody = await this.formatContent(personalizedContent, recipient);

    // Create message record
    const message: ChannelMessage = {
      id: this.generateMessageId(),
      business_id: recipient.business_id,
      lead_id: 'id' in recipient ? recipient.id : '',
      contact_id: 'email' in recipient && !('status' in recipient) ? recipient.id : undefined,
      channel: 'email',
      direction: 'outbound',
      status: 'pending',
      content: {
        subject: personalizedContent.subject || 'No Subject',
        body: formattedBody,
        attachments: personalizedContent.attachments,
        metadata: {
          from: this.config.from_address,
          from_name: this.config.from_name,
          reply_to: this.config.reply_to
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
      // Send via provider
      await this.sendViaProvider(recipient, personalizedContent, formattedBody);

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
    // Email must have subject and body
    if (!content.body) return false;

    // Check body length (typical email limits)
    if (content.body.length > 102400) return false; // 100KB limit

    // Validate attachments if present
    if (content.attachments) {
      const totalSize = content.attachments.reduce((sum, att) => sum + att.size, 0);
      if (totalSize > 25 * 1024 * 1024) return false; // 25MB limit
    }

    return true;
  }

  async getQuotaStatus(): Promise<{ used: number; limit: number; remaining: number }> {
    const hourKey = `quota:email:hour:${new Date().getHours()}`;
    const dayKey = `quota:email:day:${new Date().toISOString().split('T')[0]}`;

    const hourUsed = await this.env.KV.get(hourKey) || '0';
    const dayUsed = await this.env.KV.get(dayKey) || '0';

    const hourlyUsed = parseInt(hourUsed);
    const dailyUsed = parseInt(dayUsed);

    return {
      used: dailyUsed,
      limit: this.config.daily_limit || 1000,
      remaining: Math.max(0, Math.min(
        (this.config.daily_limit || 1000) - dailyUsed,
        (this.config.hourly_limit || 100) - hourlyUsed
      ))
    };
  }

  async formatContent(content: ChannelContent, recipient: Lead | Contact): Promise<string> {
    let html = content.body;

    // Convert markdown to HTML if needed
    if (!html.includes('<') || !html.includes('>')) {
      html = this.markdownToHtml(html);
    }

    // Add tracking pixel
    const trackingPixel = `<img src="${this.getTrackingUrl(content, recipient)}" width="1" height="1" />`;

    // Add unsubscribe link
    const unsubscribeLink = this.config.unsubscribe_url ||
      `https://example.com/unsubscribe?email=${encodeURIComponent(recipient.email)}`;

    // Build complete HTML email
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body
  { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { border-bottom: 2px solid #e5e7eb; margin-bottom: 20px; padding-bottom: 20px; }
          .content { line-height: 1.6; color: #374151; }
          .footer {
  margin-top: 40px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #6b7280; }
          .button { display:
  inline-block; padding: 10px 20px; background: #3b82f6; color: white; text-decoration: none; border-radius: 5px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="content">
            ${html}
          </div>
          ${content.cta ? this.formatCTA(content.cta) : ''}
          <div class="footer">
            <p>This email was sent to ${recipient.email}</p>
            <p><a href="${unsubscribeLink}">Unsubscribe</a> from these emails</p>
          </div>
        </div>
        ${trackingPixel}
      </body>
      </html>
    `;
  }

  private formatCTA(cta: any): string {
    if (cta.type === 'button') {
      return `<div style="text-align: center; margin: 30px 0;">
        <a href="${cta.url}" class="button">${cta.text}</a>
      </div>`;
    }
    return `<p><a href="${cta.url}">${cta.text}</a></p>`;
  }

  private markdownToHtml(markdown: string): string {
    // Simple markdown to HTML conversion
    return markdown
      .replace(/^### (.*$)/gim, '<h3>$1</h3>')
      .replace(/^## (.*$)/gim, '<h2>$1</h2>')
      .replace(/^# (.*$)/gim, '<h1>$1</h1>')
      .replace(/\*\*(.*)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*)\*/g, '<em>$1</em>')
      .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>')
      .replace(/\n\n/g, '</p><p>')
      .replace(/^/, '<p>')
      .replace(/$/, '</p>');
  }

  private getTrackingUrl(content: ChannelContent, recipient: Lead | Contact): string {
    const trackingDomain = this.config.tracking_domain || 'https://track.example.com';
    const messageId = content.metadata?.message_id || this.generateMessageId();
    return `${trackingDomain}/o/${messageId}/${recipient.id}`;
  }

  protected async getRateLimit(): Promise<number> {
    return this.config.hourly_limit || 100;
  }

  private async sendViaProvider(
    recipient: Lead | Contact,
    content: ChannelContent,
    formattedBody: string
  ): Promise<void> {
    switch (this.config.provider) {
      case 'sendgrid':
        await this.sendViaSendGrid(recipient, content, formattedBody);
        break;
      case 'aws_ses':
        await this.sendViaAWSSES(recipient, content, formattedBody);
        break;
      case 'resend':
        await this.sendViaResend(recipient, content, formattedBody);
        break;
      default:
        throw new Error(`Unsupported email provider: ${this.config.provider}`);
    }
  }

  private async sendViaSendGrid(
    recipient: Lead | Contact,
    content: ChannelContent,
    formattedBody: string
  ): Promise<void> {
    const response = await fetch('https://api.sendgrid.com/v3/mail/send', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.env.SENDGRID_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        personalizations: [{
          to: [{ email: recipient.email, name: recipient.first_name || '' }]
        }],
        from: {
          email: this.config.from_address,
          name: this.config.from_name
        },
        reply_to: this.config.reply_to ? {
          email: this.config.reply_to
        } : undefined,
        subject: content.subject || 'No Subject',
        content: [{
          type: 'text/html',
          value: formattedBody
        }],
        tracking_settings: {
          click_tracking: { enable: true },
          open_tracking: { enable: true }
        }
      })
    });

    if (!response.ok) {
      throw new Error(`SendGrid error: ${response.statusText}`);
    }
  }

  private async sendViaAWSSES(
    recipient: Lead | Contact,
    content: ChannelContent,
    formattedBody: string
  ): Promise<void> {
    // AWS SES implementation would go here
  }

  private async sendViaResend(
    recipient: Lead | Contact,
    content: ChannelContent,
    formattedBody: string
  ): Promise<void> {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.env.RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: `${this.config.from_name} <${this.config.from_address}>`,
        to: recipient.email,
        subject: content.subject || 'No Subject',
        html: formattedBody,
        reply_to: this.config.reply_to
      })
    });

    if (!response.ok) {
      throw new Error(`Resend error: ${response.statusText}`);
    }
  }

  private calculatePersonalizationScore(content: ChannelContent): number {
    let score = 0;
    const tokens = content.personalization_tokens || [];

    // Base score for having personalization
    if (tokens.length > 0) score += 30;

    // Score based on number of tokens
    score += Math.min(tokens.length * 10, 40);

    // Score for AI generation
    if (content.ai_generated) score += 20;

    // Score for specific high-value tokens
    const highValueTokens = ['first_name', 'company_name', 'pain_point', 'recent_activity'];
    for (const token of highValueTokens) {
      if (tokens.includes(token)) score += 5;
    }

    return Math.min(score, 100);
  }
}