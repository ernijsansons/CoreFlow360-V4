import { BaseChannel } from './base-channel';
import type {
  ChannelContent,
  ChannelMessage,
  MessageStatus,
  Lead,
  Contact,
  WhatsAppChannel as WhatsAppConfig
} from '../../types/crm';

export class WhatsAppChannel extends BaseChannel {
  type: 'whatsapp' = 'whatsapp' as const;
  private config: WhatsAppConfig;

  constructor(env: any, config?: WhatsAppConfig) {
    super(env);
    this.config = config || {
      provider: 'twilio',
      business_phone: '+1234567890',
      business_id: '',
      verified: false,
      quality_rating: 'green'
    };
  }

  async send(recipient: Lead | Contact, content: ChannelContent): Promise<ChannelMessage> {
    if (!this.validateContent(content)) {
      throw new Error('Invalid WhatsApp content');
    }

    if (!recipient.phone) {
      throw new Error('Recipient does not have a phone number');
    }

    // Check if business is verified
    if (!this.config.verified) {
      throw new Error('WhatsApp Business account not verified');
    }

    // Check quality rating
    if (this.config.quality_rating === 'red') {
      throw new Error('WhatsApp Business account quality rating too low');
    }

    const canSend = await this.checkRateLimit(recipient.id);
    if (!canSend) {
      throw new Error('Rate limit exceeded for recipient');
    }

    const personalizedContent = await this.personalizeContent(content, recipient);
    const formattedBody = await this.formatContent(personalizedContent, recipient);

    const message: ChannelMessage = {
      id: this.generateMessageId(),
      business_id: recipient.business_id,
      lead_id: 'id' in recipient ? recipient.id : '',
      contact_id: 'email' in recipient && !('status' in recipient) ? recipient.id : undefined,
      channel: 'whatsapp',
      direction: 'outbound',
      status: 'pending',
      content: {
        body: formattedBody,
        attachments: personalizedContent.attachments,
        metadata: {
          from: this.config.business_phone,
          to: recipient.phone,
          template_used: content.metadata?.template_id,
          is_template: content.metadata?.is_template || false
        }
      },
      ai_generated: personalizedContent.ai_generated,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    await this.trackMessage(message);

    try {
      await this.sendViaProvider(recipient.phone, formattedBody, personalizedContent);

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

    // WhatsApp message length limit
    if (content.body.length > 4096) return false;

    // Check if using template (required for first message)
    if (content.metadata?.is_first_message && !content.metadata?.template_id) {
      return false;
    }

    return true;
  }

  async getQuotaStatus(): Promise<{ used: number; limit: number; remaining: number }> {
    const dayKey = `quota:whatsapp:day:${new Date().toISOString().split('T')[0]}`;
    const used = await this.env.KV.get(dayKey) || '0';
    const dailyUsed = parseInt(used);
    const limit = 1000; // Daily WhatsApp limit

    return {
      used: dailyUsed,
      limit,
      remaining: Math.max(0, limit - dailyUsed)
    };
  }

  async formatContent(content: ChannelContent, recipient: Lead | Contact): Promise<string> {
    let message = content.body;

    // Format for WhatsApp markdown
    message = this.convertToWhatsAppMarkdown(message);

    // Add media if present
    if (content.attachments && content.attachments.length > 0) {
      const attachment = content.attachments[0]; // WhatsApp supports one media per message
      message = `[${attachment.type.toUpperCase()}: ${attachment.name}]\n\n${message}`;
    }

    // Add CTA buttons if present
    if (content.cta) {
      if (content.cta.type === 'button') {
        message += `\n\n*${content.cta.text}*`;
        if (content.cta.url) {
          message += `\n${content.cta.url}`;
        }
      }
    }

    return message;
  }

  protected async getRateLimit(): Promise<number> {
    return 20; // 20 WhatsApp messages per hour per recipient
  }

  private convertToWhatsAppMarkdown(text: string): string {
    // WhatsApp supports limited markdown
    return text
      .replace(/\*\*(.*?)\*\*/g, '*$1*') // Bold
      .replace(/__(.*?)__/g, '_$1_') // Italic
      .replace(/~~(.*?)~~/g, '~$1~') // Strikethrough
      .replace(/```(.*?)```/gs, '```$1```'); // Code blocks
  }

  private async sendViaProvider(
    phoneNumber: string,
    message: string,
    content: ChannelContent
  ): Promise<void> {
    switch (this.config.provider) {
      case 'twilio':
        await this.sendViaTwilio(phoneNumber, message, content);
        break;
      case 'meta_api':
        await this.sendViaMetaAPI(phoneNumber, message, content);
        break;
      default:
        throw new Error(`Unsupported WhatsApp provider: ${this.config.provider}`);
    }

    // Update quota
    const dayKey = `quota:whatsapp:day:${new Date().toISOString().split('T')[0]}`;
    const current = await this.env.KV.get(dayKey) || '0';
    await this.env.KV.put(dayKey, String(parseInt(current) + 1), {
      expirationTtl: 86400
    });
  }

  private async sendViaTwilio(
    phoneNumber: string,
    message: string,
    content: ChannelContent
  ): Promise<void> {
    const accountSid = this.env.TWILIO_ACCOUNT_SID;
    const authToken = this.env.TWILIO_AUTH_TOKEN;

    const formData = new URLSearchParams({
      From: `whatsapp:${this.config.business_phone}`,
      To: `whatsapp:${phoneNumber}`,
      Body: message
    });

    // Add media if present
    if (content.attachments && content.attachments.length > 0) {
      formData.append('MediaUrl', content.attachments[0].url);
    }

    const response = await fetch(
      `https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Messages.json`,
      {
        method: 'POST',
        headers: {
          'Authorization': 'Basic ' + btoa(`${accountSid}:${authToken}`),
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: formData.toString()
      }
    );

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Twilio WhatsApp error: ${error}`);
    }
  }

  private async sendViaMetaAPI(
    phoneNumber: string,
    message: string,
    content: ChannelContent
  ): Promise<void> {
    const response = await fetch(
      `https://graph.facebook.com/v17.0/${this.config.business_id}/messages`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.env.META_WHATSAPP_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          messaging_product: 'whatsapp',
          to: phoneNumber,
          type: content.metadata?.template_id ? 'template' : 'text',
          text: content.metadata?.template_id ? undefined : { body: message },
          template: content.metadata?.template_id ? {
            name: content.metadata.template_id,
            language: { code: 'en_US' },
            components: content.metadata.template_params || []
          } : undefined
        })
      }
    );

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Meta WhatsApp API error: ${error}`);
    }
  }

  async sendTemplate(
    recipient: Lead | Contact,
    templateId: string,
    params: any[]
  ): Promise<ChannelMessage> {
    const content: ChannelContent = {
      channel: 'whatsapp',
      body: `Template: ${templateId}`,
      metadata: {
        template_id: templateId,
        template_params: params,
        is_template: true
      },
      ai_generated: false,
      tone: 'formal'
    };

    return this.send(recipient, content);
  }
}