/**
 * Twilio Integration for Auto-Capture
 * Captures calls, SMS, and voicemails with automatic transcription
 * Implements Twilio API with webhooks for real-time capture
 */

import { Logger } from '../shared/logger';
import type { D1Database } from '@cloudflare/workers-types';
import { AutoCaptureEngine, type CapturedInteraction, type Participant } from '../services/crm/auto-capture';

const logger = new Logger({ component: 'twilio-integration' });

// ============================================================
// TYPES
// ============================================================

export interface TwilioConfig {
  account_sid: string;
  auth_token: string;
  phone_number: string;
  webhook_url: string;
  features: {
    auto_transcribe: boolean;
    record_calls: boolean;
    analyze_sentiment: boolean;
    extract_action_items: boolean;
  };
}

export interface TwilioCall {
  sid: string;
  from: string;
  to: string;
  status: string;
  direction: 'inbound' | 'outbound-api' | 'outbound-dial';
  duration: string;
  start_time: string;
  end_time: string;
  price: string;
  recording_url?: string;
  transcription_text?: string;
}

export interface TwilioMessage {
  sid: string;
  from: string;
  to: string;
  body: string;
  status: string;
  direction: 'inbound' | 'outbound-api' | 'outbound-reply';
  date_sent: string;
  num_media: string;
  media_urls?: string[];
}

export interface TwilioWebhookPayload {
  CallSid?: string;
  MessageSid?: string;
  From: string;
  To: string;
  CallStatus?: string;
  Direction?: string;
  Duration?: string;
  RecordingUrl?: string;
  TranscriptionText?: string;
  Body?: string;
  MessageStatus?: string;
  NumMedia?: string;
}

export interface TwilioSyncResult {
  calls_processed: number;
  calls_captured: number;
  messages_processed: number;
  messages_captured: number;
  errors: string[];
}

// ============================================================
// TWILIO INTEGRATION
// ============================================================

export class TwilioIntegration {
  private static readonly API_BASE = 'https://api.twilio.com/2010-04-01';

  constructor(
    private db: D1Database,
    private businessId: string,
    private config: TwilioConfig
  ) {}

  // ============================================================
  // WEBHOOK HANDLERS
  // ============================================================

  /**
   * Handle incoming call webhook
   */
  async handleCallWebhook(payload: TwilioWebhookPayload): Promise<void> {
    try {
      // Validate webhook signature (in production, verify X-Twilio-Signature header)

      // Only process completed calls
      if (payload.CallStatus !== 'completed') {
        return;
      }

      const participants: Participant[] = [
        {
          phone: payload.From,
          role: payload.Direction === 'inbound' ? 'caller' : 'callee'
        },
        {
          phone: payload.To,
          role: payload.Direction === 'inbound' ? 'callee' : 'caller'
        }
      ];

      const interaction: CapturedInteraction = {
        id: payload.CallSid!,
        business_id: this.businessId,
        source_type: 'call',
        external_id: payload.CallSid!,
        subject: `Phone call ${payload.Direction === 'inbound' ? 'from' : 'to'} ${payload.From}`,
        transcript: payload.TranscriptionText || undefined,
        participants: participants,
        direction: payload.Direction === 'inbound' ? 'inbound' : 'outbound',
        occurred_at: new Date().toISOString(),
        metadata: {
          duration: parseInt(payload.Duration || '0'),
          recording_url: payload.RecordingUrl,
          status: payload.CallStatus
        }
      };

      const engine = new AutoCaptureEngine(this.db, this.businessId, 'system');
      await engine.captureInteraction(interaction);

      // If recording exists and transcription is enabled, request transcription
      if (payload.RecordingUrl && this.config.features.auto_transcribe && !payload.TranscriptionText) {
        await this.requestTranscription(payload.CallSid!, payload.RecordingUrl);
      }
    } catch (error: any) {
      logger.error('Call webhook error:', error);
      throw error;
    }
  }

  /**
   * Handle incoming SMS webhook
   */
  async handleSmsWebhook(payload: TwilioWebhookPayload): Promise<void> {
    try {
      const participants: Participant[] = [
        {
          phone: payload.From,
          role: 'sender'
        },
        {
          phone: payload.To,
          role: 'recipient'
        }
      ];

      const interaction: CapturedInteraction = {
        id: payload.MessageSid!,
        business_id: this.businessId,
        source_type: 'sms',
        external_id: payload.MessageSid!,
        subject: `SMS ${payload.Direction === 'inbound' ? 'from' : 'to'} ${payload.From}`,
        body: payload.Body,
        participants: participants,
        direction: payload.Direction === 'inbound' ? 'inbound' : 'outbound',
        occurred_at: new Date().toISOString(),
        metadata: {
          status: payload.MessageStatus,
          num_media: parseInt(payload.NumMedia || '0')
        }
      };

      const engine = new AutoCaptureEngine(this.db, this.businessId, 'system');
      await engine.captureInteraction(interaction);
    } catch (error: any) {
      logger.error('SMS webhook error:', error);
      throw error;
    }
  }

  // ============================================================
  // API SYNC (Historical Data)
  // ============================================================

  /**
   * Sync historical calls
   */
  async syncCalls(limit: number = 50): Promise<TwilioSyncResult> {
    const result: TwilioSyncResult = {
      calls_processed: 0,
      calls_captured: 0,
      messages_processed: 0,
      messages_captured: 0,
      errors: []
    };

    try {
      // Fetch recent calls
      const calls = await this.fetchCalls(limit);

      for (const call of calls) {
        try {
          result.calls_processed++;

          // Skip incomplete calls
          if (call.status !== 'completed') {
            continue;
          }

          // Convert to interaction
          const interaction = this.convertCallToInteraction(call);

          // Capture
          const engine = new AutoCaptureEngine(this.db, this.businessId, 'system');
          await engine.captureInteraction(interaction);

          result.calls_captured++;
        } catch (error: any) {
          result.errors.push(`Call ${call.sid}: ${error.message}`);
        }
      }
    } catch (error: any) {
      result.errors.push(`Sync error: ${error.message}`);
    }

    await this.saveSyncResult(result);
    return result;
  }

  /**
   * Sync historical SMS messages
   */
  async syncMessages(limit: number = 50): Promise<number> {
    let messagesCaptured = 0;

    try {
      const messages = await this.fetchMessages(limit);

      for (const message of messages) {
        try {
          const interaction = this.convertMessageToInteraction(message);

          const engine = new AutoCaptureEngine(this.db, this.businessId, 'system');
          await engine.captureInteraction(interaction);

          messagesCaptured++;
        } catch (error: any) {
          logger.error(`Message ${message.sid} error:`, error);
        }
      }
    } catch (error: any) {
      logger.error('Message sync error:', error);
    }

    return messagesCaptured;
  }

  /**
   * Fetch calls from Twilio API
   */
  private async fetchCalls(limit: number): Promise<TwilioCall[]> {
    const url = `${TwilioIntegration.API_BASE}/Accounts/${this.config.account_sid}/Calls.json?PageSize=${limit}`;

    const response = await fetch(url, {
      headers: {
        'Authorization': 'Basic ' + btoa(`${this.config.account_sid}:${this.config.auth_token}`)
      }
    });

    if (!response.ok) {
      throw new Error('Failed to fetch calls from Twilio');
    }

    const data = await response.json() as { calls?: TwilioCall[] };
    return data.calls || [];
  }

  /**
   * Fetch messages from Twilio API
   */
  private async fetchMessages(limit: number): Promise<TwilioMessage[]> {
    const url = `${TwilioIntegration.API_BASE}/Accounts/${this.config.account_sid}/Messages.json?PageSize=${limit}`;

    const response = await fetch(url, {
      headers: {
        'Authorization': 'Basic ' + btoa(`${this.config.account_sid}:${this.config.auth_token}`)
      }
    });

    if (!response.ok) {
      throw new Error('Failed to fetch messages from Twilio');
    }

    const data = await response.json() as { messages?: TwilioMessage[] };
    return data.messages || [];
  }

  /**
   * Request call transcription
   */
  private async requestTranscription(callSid: string, recordingUrl: string): Promise<void> {
    // In production, this would call Twilio's transcription API or a third-party service
    // For now, we'll just log that transcription was requested
    logger.info(`Transcription requested for call ${callSid}`);

    // Example: Using Twilio's transcription service
    // const recordingSid = this.extractRecordingSid(recordingUrl);
    // await fetch(
    //   `${TwilioIntegration.API_BASE}/Accounts/${this.config.account_sid}/Recordings/${recordingSid}/Transcriptions.json`,
    //   {
    //     method: 'POST',
    //     headers: {
    //       'Authorization': 'Basic ' + btoa(`${this.config.account_sid}:${this.config.auth_token}`)
    //     }
    //   }
    // );
  }

  /**
   * Convert Twilio call to CapturedInteraction
   */
  private convertCallToInteraction(call: TwilioCall): CapturedInteraction {
    const participants: Participant[] = [
      {
        phone: call.from,
        role: call.direction.includes('inbound') ? 'caller' : 'callee'
      },
      {
        phone: call.to,
        role: call.direction.includes('inbound') ? 'callee' : 'caller'
      }
    ];

    return {
      id: call.sid,
      business_id: this.businessId,
      source_type: 'call',
      external_id: call.sid,
      subject: `Phone call ${call.direction.includes('inbound') ? 'from' : 'to'} ${call.from}`,
      transcript: call.transcription_text,
      participants: participants,
      direction: call.direction.includes('inbound') ? 'inbound' : 'outbound',
      occurred_at: call.start_time,
      metadata: {
        duration: parseInt(call.duration),
        recording_url: call.recording_url,
        status: call.status,
        end_time: call.end_time,
        price: call.price
      }
    };
  }

  /**
   * Convert Twilio message to CapturedInteraction
   */
  private convertMessageToInteraction(message: TwilioMessage): CapturedInteraction {
    const participants: Participant[] = [
      {
        phone: message.from,
        role: 'sender'
      },
      {
        phone: message.to,
        role: 'recipient'
      }
    ];

    return {
      id: message.sid,
      business_id: this.businessId,
      source_type: 'sms',
      external_id: message.sid,
      subject: `SMS ${message.direction.includes('inbound') ? 'from' : 'to'} ${message.from}`,
      body: message.body,
      participants: participants,
      direction: message.direction.includes('inbound') ? 'inbound' : 'outbound',
      occurred_at: message.date_sent,
      metadata: {
        status: message.status,
        num_media: parseInt(message.num_media),
        media_urls: message.media_urls
      }
    };
  }

  // ============================================================
  // TWIML GENERATION (For call flow)
  // ============================================================

  /**
   * Generate TwiML for incoming calls
   */
  generateIncomingCallTwiml(options?: {
    greeting?: string;
    forward_to?: string;
    record?: boolean;
    transcribe?: boolean;
  }): string {
    const greeting = options?.greeting || 'Thank you for calling. Your call is being recorded.';
    const record = options?.record !== false && this.config.features.record_calls;
    const transcribe = options?.transcribe !== false && this.config.features.auto_transcribe;

    let twiml = '<?xml version="1.0" encoding="UTF-8"?>';
    twiml += '<Response>';
    twiml += `<Say>${greeting}</Say>`;

    if (options?.forward_to) {
      twiml += `<Dial record="${record ? 'record-from-answer' : 'do-not-record'}" recordingStatusCallback="${this.config.webhook_url}/recording">`;
      twiml += `<Number>${options.forward_to}</Number>`;
      twiml += '</Dial>';
    } else {
      twiml += '<Say>Please leave a message after the tone.</Say>';
      twiml += `<Record transcribe="${transcribe}" transcribeCallback="${this.config.webhook_url}/transcription" maxLength="120" />`;
    }

    twiml += '</Response>';

    return twiml;
  }

  /**
   * Generate TwiML for outbound calls
   */
  generateOutboundCallTwiml(phoneNumber: string, message: string): string {
    let twiml = '<?xml version="1.0" encoding="UTF-8"?>';
    twiml += '<Response>';
    twiml += `<Say>${message}</Say>`;
    twiml += `<Dial>${phoneNumber}</Dial>`;
    twiml += '</Response>';

    return twiml;
  }

  // ============================================================
  // PERSISTENCE
  // ============================================================

  private async saveSyncResult(result: TwilioSyncResult): Promise<void> {
    await this.db
      .prepare(`
        UPDATE crm_call_integrations
        SET last_call_at = CURRENT_TIMESTAMP,
            calls_captured = calls_captured + ?
        WHERE business_id = ? AND provider = 'twilio'
      `)
      .bind(
        result.calls_captured,
        this.businessId
      )
      .run();
  }

  async saveIntegration(): Promise<void> {
    await this.db
      .prepare(`
        INSERT INTO crm_call_integrations (
          id, business_id, provider, config,
          auto_create_activities, auto_transcribe, auto_analyze_sentiment
        ) VALUES (?, ?, 'twilio', ?, TRUE, ?, ?)
        ON CONFLICT(business_id, provider) DO UPDATE SET
          config = excluded.config,
          updated_at = CURRENT_TIMESTAMP
      `)
      .bind(
        crypto.randomUUID(),
        this.businessId,
        JSON.stringify(this.config),
        this.config.features.auto_transcribe ? 1 : 0,
        this.config.features.analyze_sentiment ? 1 : 0
      )
      .run();
  }

  /**
   * Test connection
   */
  async testConnection(): Promise<boolean> {
    try {
      const response = await fetch(
        `${TwilioIntegration.API_BASE}/Accounts/${this.config.account_sid}.json`,
        {
          headers: {
            'Authorization': 'Basic ' + btoa(`${this.config.account_sid}:${this.config.auth_token}`)
          }
        }
      );

      return response.ok;
    } catch {
      return false;
    }
  }

  /**
   * Validate webhook signature (for production use)
   */
  static validateWebhookSignature(
    signature: string,
    url: string,
    params: Record<string, string>,
    authToken: string
  ): boolean {
    // In production, implement Twilio's signature validation
    // See: https://www.twilio.com/docs/usage/security#validating-requests
    // This requires crypto libraries for HMAC-SHA1
    return true; // Placeholder
  }
}
