import type {
  VoiceAgentConfig,
  TwilioCallConfig,
  CallResult,
  CallStatus,
  VoiceAgentResponse
} from '../types/voice-agent';
import type { Lead } from '../types/crm';

export interface TwilioResponse {
  success: boolean;
  call_sid?: string;
  status?: string;
  error?: string;
  cost?: number;
}

export interface TwilioWebhookData {
  CallSid: string;
  AccountSid: string;
  From: string;
  To: string;
  CallStatus: string;
  ApiVersion: string;
  Direction: string;
  ForwardedFrom?: string;
  CallerName?: string;
  ParentCallSid?: string;
  CallDuration?: string;
  SipResponseCode?: string;
  RecordingUrl?: string;
  RecordingSid?: string;
  RecordingStatus?: string;
  Digits?: string;
  FinishedOnKey?: string;
  SpeechResult?: string;
  Confidence?: string;
  AnsweredBy?: string;
  MachineDetectionDuration?: string;
  CallbackSource?: string;
  SequenceNumber?: string;
}

export interface TwilioCall {
  sid: string;
  account_sid: string;
  to: string;
  from: string;
  phone_number_sid: string;
  status: string;
  start_time: string;
  end_time?: string;
  duration?: string;
  price?: string;
  price_unit: string;
  direction: string;
  answered_by?: string;
  parent_call_sid?: string;
  caller_name?: string;
  uri: string;
  subresource_uris: {
    notifications: string;
    recordings: string;
    feedback: string;
    events: string;
    siprec: string;
    streams: string;
    payments: string;
  };
}

export // TODO: Consider splitting TwilioService into smaller, focused classes
class TwilioService {
  private accountSid: string;
  private authToken: string;
  private phoneNumber: string;
  private webhookUrl: string;
  private baseUrl: string;

  constructor(config: VoiceAgentConfig['twilio']) {
    this.accountSid = config.account_sid;
    this.authToken = config.auth_token;
    this.phoneNumber = config.phone_number;
    this.webhookUrl = config.webhook_url;
    this.baseUrl = `https://api.twilio.com/2010-04-01/Accounts/${this.accountSid}`;
  }

  async initiateCall(lead: Lead, callConfig: Partial<TwilioCallConfig> = {}): Promise<TwilioResponse> {
    try {
      if (!lead.phone) {
        return {
          success: false,
          error: 'Lead phone number is required'
        };
      }

      const config: TwilioCallConfig = {
        to: this.formatPhoneNumber(lead.phone),
        from: this.phoneNumber,
        url: `${this.webhookUrl}/voice/handle/${lead.id}`,
        method: 'POST',
        status_callback: `${this.webhookUrl}/voice/status/${lead.id}`,
        status_callback_event: ['initiated', 'ringing', 'answered', 'completed'],
        status_callback_method: 'POST',
        timeout: 20,
        record: true,
        recording_channels: 'dual',
        recording_status_callback: `${this.webhookUrl}/voice/recording/${lead.id}`,
        machine_detection: 'DetectMessageEnd',
        machine_detection_timeout: 30,
        machine_detection_speech_threshold: 2000,
        machine_detection_speech_end_threshold: 1200,
        machine_detection_silence_timeout: 5000,
        ...callConfig
      };

      const response = await this.makeApiCall('POST', '/Calls.json', config);

      if (response.error_code) {
        return {
          success: false,
          error: `Twilio error ${response.error_code}: ${response.error_message}`
        };
      }

      return {
        success: true,
        call_sid: response.sid,
        status: response.status,
        cost: this.estimateCallCost(response.direction, 0) // Initial estimate
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  async getCallDetails(callSid: string): Promise<TwilioCall | null> {
    try {
      const response = await this.makeApiCall('GET', `/Calls/${callSid}.json`);
      return response as TwilioCall;
    } catch (error) {
      return null;
    }
  }

  async getCallRecordings(callSid: string): Promise<any[]> {
    try {
      const response = await this.makeApiCall('GET', `/Calls/${callSid}/Recordings.json`);
      return response.recordings || [];
    } catch (error) {
      return [];
    }
  }

  async deleteRecording(recordingSid: string): Promise<boolean> {
    try {
      await this.makeApiCall('DELETE', `/Recordings/${recordingSid}.json`);
      return true;
    } catch (error) {
      return false;
    }
  }

  async updateCall(callSid: string, updates: {
    status?: 'canceled' | 'completed';
    url?: string;
    method?: 'GET' | 'POST';
    status_callback?: string;
    status_callback_method?: 'GET' | 'POST';
    twiml?: string;
  }): Promise<boolean> {
    try {
      await this.makeApiCall('POST', `/Calls/${callSid}.json`, updates);
      return true;
    } catch (error) {
      return false;
    }
  }

  generateTwiMLResponse(text: string, options: {
    voice?: 'man' | 'woman' | 'alice';
    language?: string;
    gather?: {
      input?: 'speech' | 'dtmf' | 'speech dtmf';
      timeout?: number;
      speechTimeout?: number;
      maxSpeechTime?: number;
      action?: string;
      method?: 'GET' | 'POST';
      hints?: string;
    };
    hangup?: boolean;
    redirect?: string;
    pause?: number;
  } = {}): string {
    let twiml = '<?xml version="1.0" encoding="UTF-8"?>';
    twiml += '<Response>';

    if (options.gather) {
      twiml += `<Gather input="${options.gather.input || 'speech'}"`;
      if (options.gather.timeout) twiml += ` timeout="${options.gather.timeout}"`;
      if (options.gather.speechTimeout) twiml += ` speechTimeout="${options.gather.speechTimeout}"`;
      if (options.gather.maxSpeechTime) twiml += ` maxSpeechTime="${options.gather.maxSpeechTime}"`;
      if (options.gather.action) twiml += ` action="${options.gather.action}"`;
      if (options.gather.method) twiml += ` method="${options.gather.method}"`;
      if (options.gather.hints) twiml += ` hints="${options.gather.hints}"`;
      twiml += '>';
    }

    if (options.pause) {
      twiml += `<Pause length="${options.pause}"/>`;
    }

    twiml +=
  `<Say voice="${options.voice || 'alice'}" language="${options.language || 'en-US'}">${this.escapeXml(text)}</Say>`;

    if (options.gather) {
      twiml += '</Gather>';
    }

    if (options.redirect) {
      twiml += `<Redirect method="POST">${options.redirect}</Redirect>`;
    } else if (options.hangup) {
      twiml += '<Hangup/>';
    }

    twiml += '</Response>';
    return twiml;
  }

  generateStreamTwiML(streamUrl: string, track: 'inbound' | 'outbound' | 'both' = 'both'): string {
    return `<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Start>
    <Stream url="${streamUrl}" track="${track}">
      <Parameter name="custom_parameter" value="custom_value"/>
    </Stream>
  </Start>
  <Say>Starting real-time conversation...</Say>
</Response>`;
  }

  parseWebhookData(body: any): TwilioWebhookData {
    // Parse URL-encoded webhook data from Twilio
    if (typeof body === 'string') {
      const params = new URLSearchParams(body);
      const data: any = {};
      for (const [key, value] of params.entries()) {
        data[key] = value;
      }
      return data as TwilioWebhookData;
    }
    return body as TwilioWebhookData;
  }

  validateWebhook(signature: string, url: string, params: any): boolean {
    try {
      // Twilio webhook validation
      const crypto = require('crypto');
      const qs = require('querystring');

      const data = Object.keys(params)
        .sort()
        .reduce((acc: any, key) => {
          acc[key] = params[key];
          return acc;
        }, {});

      const postBody = qs.stringify(data);
      const bodyHash = crypto
        .createHmac('sha1', this.authToken)
        .update(url + postBody)
        .digest('base64');

      return crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(bodyHash)
      );
    } catch (error) {
      return false;
    }
  }

  mapTwilioStatusToCallStatus(twilioStatus: string, answeredBy?: string): CallStatus {
    switch (twilioStatus) {
      case 'queued':
      case 'ringing':
        return 'ringing';
      case 'in-progress':
        if (answeredBy === 'machine_start'
  || answeredBy === 'machine_end_beep' || answeredBy === 'machine_end_silence' || answeredBy === 'machine_end_other') {
          return 'voicemail';
        }
        return 'answered';
      case 'completed':
        return 'completed';
      case 'busy':
        return 'busy';
      case 'no-answer':
        return 'no_answer';
      case 'failed':
      case 'canceled':
        return 'failed';
      default:
        return 'failed';
    }
  }

  estimateCallCost(direction: string, durationSeconds: number): number {
    // Twilio pricing estimates (USD)
    const outboundPerMinute = 0.0075; // $0.0075 per minute for US calls
    const inboundPerMinute = 0.0075;
    const minutes = Math.ceil(durationSeconds / 60);

    if (direction === 'outbound-api') {
      return minutes * outboundPerMinute;
    } else {
      return minutes * inboundPerMinute;
    }
  }

  private async makeApiCall(method: string, endpoint: string, data?: any): Promise<any> {
    const url = `${this.baseUrl}${endpoint}`;
    const credentials = btoa(`${this.accountSid}:${this.authToken}`);

    const headers: Record<string, string> = {
      'Authorization': `Basic ${credentials}`,
      'Content-Type': 'application/x-www-form-urlencoded'
    };

    const options: RequestInit = {
      method,
      headers
    };

    if (data && (method === 'POST' || method === 'PUT')) {
      const formData = new URLSearchParams();
      Object.entries(data).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          if (Array.isArray(value)) {
            value.forEach(item => formData.append(key, String(item)));
          } else {
            formData.append(key, String(value));
          }
        }
      });
      options.body = formData.toString();
    }

    const response = await fetch(url, options);

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Twilio API error: ${response.status} ${errorText}`);
    }

    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      return response.json();
    } else {
      return response.text();
    }
  }

  private formatPhoneNumber(phone: string): string {
    // Remove all non-digit characters
    const digits = phone.replace(/\D/g, '');

    // Add +1 prefix for US numbers if not present
    if (digits.length === 10) {
      return `+1${digits}`;
    } else if (digits.length === 11 && digits.startsWith('1')) {
      return `+${digits}`;
    } else if (digits.startsWith('1') && digits.length > 11) {
      return `+${digits}`;
    }

    // Return as-is if it already has country code
    return `+${digits}`;
  }

  private escapeXml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // Queue management for high-volume calling
  async checkTwilioLimits(): Promise<{
    concurrent_calls: number;
    max_concurrent_calls: number;
    rate_limit_remaining: number;
    can_make_call: boolean;
  }> {
    try {
      // Get account usage
      const usage = await this.makeApiCall('GET', '/Usage/Records.json?Category=calls&Granularity=daily&Limit=1');

      // Get concurrent calls (this would need to be tracked separately)
      const concurrentCalls = 0; // Placeholder - would track active calls

      return {
        concurrent_calls: concurrentCalls,
        max_concurrent_calls: 100, // Default Twilio limit
        rate_limit_remaining: 1000, // Placeholder
        can_make_call: concurrentCalls < 100
      };
    } catch (error) {
      return {
        concurrent_calls: 0,
        max_concurrent_calls: 100,
        rate_limit_remaining: 0,
        can_make_call: false
      };
    }
  }

  async getAccountBalance(): Promise<{ balance: number; currency: string } | null> {
    try {
      const account = await this.makeApiCall('GET', '.json');
      return {
        balance: parseFloat(account.balance),
        currency: account.account_balance_currency || 'USD'
      };
    } catch (error) {
      return null;
    }
  }

  // Call queue management
  async addToCallQueue(leadId: string, priority: 'low' | 'medium' | 'high' | 'urgent' = 'medium'): Promise<boolean> {
    try {
      // This would integrate with a queue system (Redis, Cloudflare Queues, etc.)
      // For now, just return success
      return true;
    } catch (error) {
      return false;
    }
  }

  async getQueueStatus(): Promise<{
    total_queued: number;
    urgent: number;
    high: number;
    medium: number;
    low: number;
    estimated_wait_time: number;
  }> {
    // This would query the actual queue
    return {
      total_queued: 0,
      urgent: 0,
      high: 0,
      medium: 0,
      low: 0,
      estimated_wait_time: 0
    };
  }

  // Conference and multi-party calling
  async createConference(friendlyName: string): Promise<string | null> {
    try {
      const response = await this.makeApiCall('POST', '/Conferences.json', {
        FriendlyName: friendlyName,
        StatusCallback: `${this.webhookUrl}/voice/conference/status`,
        StatusCallbackEvent: 'start end join leave mute hold',
        StatusCallbackMethod: 'POST'
      });

      return response.sid;
    } catch (error) {
      return null;
    }
  }

  async addParticipantToConference(conferenceSid: string, phoneNumber: string): Promise<boolean> {
    try {
      await this.makeApiCall('POST', `/Conferences/${conferenceSid}/Participants.json`, {
        From: this.phoneNumber,
        To: phoneNumber,
        EarlyMedia: true,
        StatusCallback: `${this.webhookUrl}/voice/conference/participant`,
        StatusCallbackEvent: 'join leave hold unhold mute unmute',
        StatusCallbackMethod: 'POST'
      });

      return true;
    } catch (error) {
      return false;
    }
  }
}