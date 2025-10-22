/**
 * Outlook/Office 365 Integration for Auto-Capture
 * Microsoft Graph API integration for automatic email and calendar capture
 * Implements Microsoft Graph v1.0 with proper authentication
 */

import { Logger } from '../shared/logger';
import type { D1Database } from '@cloudflare/workers-types';
import { AutoCaptureEngine, type CapturedInteraction, type Participant } from '../services/crm/auto-capture';

const logger = new Logger({ component: 'outlook-integration' });
import {
  OutlookTokenResponseSchema,
  OutlookMessagesResponseSchema,
  OutlookEventsResponseSchema,
  validateAPIResponse,
  type OutlookTokenResponse,
  type OutlookMessagesResponse,
} from './types/api-responses';

// ============================================================
// TYPES
// ============================================================

export interface OutlookConfig {
  client_id: string;
  client_secret: string;
  redirect_uri: string;
  tenant_id?: string; // 'common' for multi-tenant, or specific tenant ID
  access_token?: string;
  refresh_token?: string;
  token_expires_at?: number;
}

export interface GraphMessage {
  id: string;
  subject: string;
  bodyPreview: string;
  body: {
    contentType: 'text' | 'html';
    content: string;
  };
  from: { emailAddress: { name: string; address: string } };
  toRecipients: Array<{ emailAddress: { name: string; address: string } }>;
  ccRecipients?: Array<{ emailAddress: { name: string; address: string } }>;
  bccRecipients?: Array<{ emailAddress: { name: string; address: string } }>;
  sentDateTime: string;
  receivedDateTime: string;
  conversationId: string;
  isRead: boolean;
  importance: 'low' | 'normal' | 'high';
}

export interface OutlookSyncResult {
  emails_processed: number;
  emails_captured: number;
  meetings_captured: number;
  errors: string[];
  next_link?: string;
}

// ============================================================
// OUTLOOK INTEGRATION
// ============================================================

export class OutlookIntegration {
  private static readonly SCOPES = [
    'https://graph.microsoft.com/Mail.Read',
    'https://graph.microsoft.com/Calendars.Read',
    'https://graph.microsoft.com/User.Read',
    'offline_access'
  ];

  private static readonly GRAPH_API_BASE = 'https://graph.microsoft.com/v1.0';

  constructor(
    private db: D1Database,
    private businessId: string,
    private userId: string,
    private config: OutlookConfig
  ) {
    // Default to common tenant if not specified
    if (!this.config.tenant_id) {
      this.config.tenant_id = 'common';
    }
  }

  // ============================================================
  // OAUTH FLOW
  // ============================================================

  /**
   * Generate OAuth URL for user authorization
   */
  static generateAuthUrl(config: OutlookConfig): string {
    const tenantId = config.tenant_id || 'common';
    const params = new URLSearchParams({
      client_id: config.client_id,
      redirect_uri: config.redirect_uri,
      response_type: 'code',
      scope: this.SCOPES.join(' '),
      response_mode: 'query',
      prompt: 'consent'
    });

    return `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize?${params}`;
  }

  /**
   * Exchange authorization code for tokens
   */
  static async exchangeCode(config: OutlookConfig, code: string): Promise<{
    access_token: string;
    refresh_token: string;
    expires_in: number;
  }> {
    const tenantId = config.tenant_id || 'common';

    const response = await fetch(
      `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: config.client_id,
          client_secret: config.client_secret,
          code,
          grant_type: 'authorization_code',
          redirect_uri: config.redirect_uri,
          scope: this.SCOPES.join(' ')
        })
      }
    );

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to exchange code: ${error}`);
    }

    return await response.json();
  }

  /**
   * Refresh access token
   */
  private async refreshAccessToken(): Promise<string> {
    if (!this.config.refresh_token) {
      throw new Error('No refresh token available');
    }

    const tenantId = this.config.tenant_id || 'common';

    const response = await fetch(
      `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: this.config.client_id,
          client_secret: this.config.client_secret,
          refresh_token: this.config.refresh_token,
          grant_type: 'refresh_token',
          scope: OutlookIntegration.SCOPES.join(' ')
        })
      }
    );

    if (!response.ok) {
      throw new Error('Failed to refresh access token');
    }

    const rawData = await response.json();
    const data: OutlookTokenResponse = validateAPIResponse(
      OutlookTokenResponseSchema,
      rawData,
      'Invalid Outlook token response'
    );

    this.config.access_token = data.access_token;
    this.config.token_expires_at = Date.now() + (data.expires_in * 1000);

    // Update refresh token if provided (some flows return a new one)
    if (data.refresh_token) {
      this.config.refresh_token = data.refresh_token;
    }

    await this.saveConfig();

    return data.access_token;
  }

  /**
   * Get valid access token
   */
  private async getAccessToken(): Promise<string> {
    if (!this.config.access_token) {
      return await this.refreshAccessToken();
    }

    if (this.config.token_expires_at && this.config.token_expires_at < Date.now() + 300000) {
      return await this.refreshAccessToken();
    }

    return this.config.access_token;
  }

  // ============================================================
  // EMAIL SYNC
  // ============================================================

  /**
   * Sync emails from Outlook
   */
  async syncEmails(maxResults: number = 50): Promise<OutlookSyncResult> {
    const accessToken = await this.getAccessToken();
    const result: OutlookSyncResult = {
      emails_processed: 0,
      emails_captured: 0,
      meetings_captured: 0,
      errors: []
    };

    try {
      // Fetch messages (last 7 days or unread)
      const response = await fetch(
        `${OutlookIntegration.GRAPH_API_BASE}/me/messages?$top=${maxResults}&$filter=receivedDateTime ge ${this.getSevenDaysAgo()}`,
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      if (!response.ok) {
        throw new Error('Failed to fetch messages');
      }

      const rawData = await response.json();
      const data: OutlookMessagesResponse = validateAPIResponse(
        OutlookMessagesResponseSchema,
        rawData,
        'Invalid Outlook messages response'
      );
      const messages = data.value || [];

      if (data['@odata.nextLink']) {
        result.next_link = data['@odata.nextLink'];
      }

      // Process each message
      for (const message of messages) {
        try {
          result.emails_processed++;

          // Convert to CapturedInteraction (cast to GraphMessage as API may return partial data)
          const interaction = this.convertToInteraction(message as any as GraphMessage);

          // Capture via AutoCaptureEngine
          const engine = new AutoCaptureEngine(this.db, this.businessId, this.userId);
          await engine.captureInteraction(interaction);

          result.emails_captured++;
        } catch (error: any) {
          result.errors.push(`Message ${message.id}: ${error.message}`);
        }
      }
    } catch (error: any) {
      result.errors.push(`Sync error: ${error.message}`);
    }

    await this.saveSyncResult(result);

    return result;
  }

  /**
   * Sync calendar meetings
   */
  async syncMeetings(maxResults: number = 50): Promise<number> {
    const accessToken = await this.getAccessToken();
    let meetingsCaptured = 0;

    try {
      // Fetch calendar events (last 7 days and future)
      const response = await fetch(
        `${OutlookIntegration.GRAPH_API_BASE}/me/events?$top=${maxResults}&$filter=start/dateTime ge '${this.getSevenDaysAgo()}'`,
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      if (!response.ok) {
        throw new Error('Failed to fetch meetings');
      }

      const rawData = await response.json();
      const data = validateAPIResponse(
        OutlookEventsResponseSchema,
        rawData,
        'Invalid Outlook events response'
      );
      const events = data.value || [];

      // Process meetings (filter for those with external attendees)
      for (const event of events) {
        if (event.attendees && event.attendees.length > 0) {
          // Create meeting activity in CRM
          await this.captureMeeting(event);
          meetingsCaptured++;
        }
      }
    } catch (error: any) {
      logger.error('Meeting sync error:', error);
    }

    return meetingsCaptured;
  }

  /**
   * Convert Graph message to CapturedInteraction
   */
  private convertToInteraction(message: GraphMessage): CapturedInteraction {
    const participants: Participant[] = [];

    // From
    participants.push({
      email: message.from.emailAddress.address,
      name: message.from.emailAddress.name,
      role: 'sender'
    });

    // To
    for (const recipient of message.toRecipients) {
      participants.push({
        email: recipient.emailAddress.address,
        name: recipient.emailAddress.name,
        role: 'recipient'
      });
    }

    // CC
    if (message.ccRecipients) {
      for (const recipient of message.ccRecipients) {
        participants.push({
          email: recipient.emailAddress.address,
          name: recipient.emailAddress.name,
          role: 'cc'
        });
      }
    }

    // BCC
    if (message.bccRecipients) {
      for (const recipient of message.bccRecipients) {
        participants.push({
          email: recipient.emailAddress.address,
          name: recipient.emailAddress.name,
          role: 'bcc'
        });
      }
    }

    // Extract body text
    let body = message.body.content;
    if (message.body.contentType === 'html') {
      body = this.stripHtml(body);
    }

    // Determine direction
    const myEmail = participants.find(p => p.role !== 'sender')?.email || '';
    void myEmail;
    const direction = message.from.emailAddress.address.toLowerCase().includes('coreflow360') ? 'outbound' : 'inbound';

    return {
      id: message.id,
      business_id: this.businessId,
      source_type: 'email',
      external_id: message.id,
      subject: message.subject,
      body: body,
      participants: participants,
      direction: direction,
      occurred_at: message.sentDateTime,
      metadata: {
        conversation_id: message.conversationId,
        importance: message.importance,
        is_read: message.isRead
      }
    };
  }

  /**
   * Capture meeting as interaction
   */
  private async captureMeeting(event: any): Promise<void> {
    const participants: Participant[] = [];

    // Organizer
    if (event.organizer) {
      participants.push({
        email: event.organizer.emailAddress.address,
        name: event.organizer.emailAddress.name,
        role: 'sender'
      });
    }

    // Attendees
    for (const attendee of event.attendees || []) {
      participants.push({
        email: attendee.emailAddress.address,
        name: attendee.emailAddress.name,
        role: 'recipient'
      });
    }

    const interaction: CapturedInteraction = {
      id: event.id,
      business_id: this.businessId,
      source_type: 'email', // Could be 'meeting' if you add that type
      external_id: event.id,
      subject: event.subject,
      body: this.stripHtml(event.body?.content || event.bodyPreview || ''),
      participants: participants,
      direction: 'outbound',
      occurred_at: event.start.dateTime,
      metadata: {
        meeting: true,
        location: event.location?.displayName,
        start: event.start.dateTime,
        end: event.end.dateTime,
        online_meeting_url: event.onlineMeetingUrl
      }
    };

    const engine = new AutoCaptureEngine(this.db, this.businessId, this.userId);
    await engine.captureInteraction(interaction);
  }

  /**
   * Strip HTML tags
   */
  private stripHtml(html: string): string {
    return html
      .replace(/<style[^>]*>.*?<\/style>/gis, '')
      .replace(/<script[^>]*>.*?<\/script>/gis, '')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
  }

  /**
   * Get ISO date string for 7 days ago
   */
  private getSevenDaysAgo(): string {
    const date = new Date();
    date.setDate(date.getDate() - 7);
    return date.toISOString();
  }

  // ============================================================
  // PERSISTENCE
  // ============================================================

  private async saveConfig(): Promise<void> {
    await this.db
      .prepare(`
        UPDATE crm_email_integrations
        SET config = ?, updated_at = CURRENT_TIMESTAMP
        WHERE business_id = ? AND user_id = ? AND provider = 'outlook'
      `)
      .bind(
        JSON.stringify(this.config),
        this.businessId,
        this.userId
      )
      .run();
  }

  private async saveSyncResult(result: OutlookSyncResult): Promise<void> {
    await this.db
      .prepare(`
        UPDATE crm_email_integrations
        SET last_sync_at = CURRENT_TIMESTAMP,
            last_sync_status = ?,
            sync_error = ?,
            emails_synced = emails_synced + ?
        WHERE business_id = ? AND user_id = ? AND provider = 'outlook'
      `)
      .bind(
        result.errors.length > 0 ? 'partial' : 'success',
        result.errors.length > 0 ? JSON.stringify(result.errors) : null,
        result.emails_captured,
        this.businessId,
        this.userId
      )
      .run();
  }

  async saveIntegration(): Promise<void> {
    await this.db
      .prepare(`
        INSERT INTO crm_email_integrations (
          id, business_id, user_id, provider, email_address, config,
          sync_enabled, auto_create_activities, auto_link_contacts
        ) VALUES (?, ?, ?, 'outlook', ?, ?, TRUE, TRUE, TRUE)
        ON CONFLICT(business_id, user_id, provider) DO UPDATE SET
          config = excluded.config,
          updated_at = CURRENT_TIMESTAMP
      `)
      .bind(
        crypto.randomUUID(),
        this.businessId,
        this.userId,
        this.config.access_token ? 'connected' : 'pending',
        JSON.stringify(this.config)
      )
      .run();
  }

  /**
   * Test connection
   */
  async testConnection(): Promise<boolean> {
    try {
      const accessToken = await this.getAccessToken();

      const response = await fetch(
        `${OutlookIntegration.GRAPH_API_BASE}/me`,
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      return response.ok;
    } catch {
      return false;
    }
  }
}
