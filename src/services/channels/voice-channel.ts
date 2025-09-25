import { BaseChannel } from './base-channel';
import type {
  ChannelContent,
  ChannelMessage,
  MessageStatus,
  Lead,
  Contact
} from '../../types/crm';

export class VoiceChannel extends BaseChannel {
  type: 'call' = 'call' as const;

  async send(recipient: Lead | Contact, content: ChannelContent): Promise<ChannelMessage> {
    // Voice channel uses the existing VoicemailHandler for messages
    // This is primarily for tracking outbound calls

    if (!recipient.phone) {
      throw new Error('Recipient does not have a phone number');
    }

    const message: ChannelMessage = {
      id: this.generateMessageId(),
      business_id: recipient.business_id,
      lead_id: 'id' in recipient ? recipient.id : '',
      contact_id: 'email' in recipient && !('status' in recipient) ? recipient.id : undefined,
      channel: 'call',
      direction: 'outbound',
      status: 'pending',
      content: {
        body: content.body,
        metadata: {
          phone: recipient.phone,
          call_type: content.metadata?.call_type || 'voicemail',
          duration: content.metadata?.duration
        }
      },
      ai_generated: content.ai_generated,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    await this.trackMessage(message);

    // If this is a voicemail, delegate to VoicemailHandler
    if (content.metadata?.call_type === 'voicemail') {
      const { VoicemailHandler } = await import('../voicemail-handler');
      const voicemailHandler = new VoicemailHandler(this.env);

      await voicemailHandler.leaveVoicemail(
        recipient as Lead,
        content.metadata?.attempt_number || 1,
        content.metadata?.scenario || 'follow_up',
        content.body
      );

      message.status = 'sent';
      message.sent_at = new Date().toISOString();
      await this.updateMessageStatus(message.id, 'sent', { sent_at: message.sent_at });
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
    return content.body !== undefined && content.body.length > 0;
  }

  async getQuotaStatus(): Promise<{ used: number; limit: number; remaining: number }> {
    const dayKey = `quota:call:day:${new Date().toISOString().split('T')[0]}`;
    const used = await this.env.KV.get(dayKey) || '0';
    const dailyUsed = parseInt(used);
    const limit = 200; // Daily call limit

    return {
      used: dailyUsed,
      limit,
      remaining: Math.max(0, limit - dailyUsed)
    };
  }

  async formatContent(content: ChannelContent, recipient: Lead | Contact): Promise<string> {
    // For voice channel, content is typically a script or voicemail text
    return content.body;
  }

  protected async getRateLimit(): Promise<number> {
    return 50; // 50 calls per hour
  }
}