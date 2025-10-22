/**
 * Microsoft Teams Integration for Auto-Capture
 * Captures messages, meetings, and calls with automatic CRM linking
 * Implements Microsoft Graph API for Teams data access
 */

import { Logger } from '../shared/logger';
import type { D1Database } from '@cloudflare/workers-types';
import { AutoCaptureEngine, type CapturedInteraction, type Participant } from '../services/crm/auto-capture';

const logger = new Logger({ component: 'teams-integration' });

// ============================================================
// TYPES
// ============================================================

export interface TeamsConfig {
  client_id: string;
  client_secret: string;
  tenant_id: string;
  redirect_uri: string;
  access_token?: string;
  refresh_token?: string;
  token_expires_at?: number;
  monitored_channels: string[]; // Channel IDs to monitor
  features: {
    capture_messages: boolean;
    capture_meetings: boolean;
    capture_calls: boolean;
    auto_link_customers: boolean;
  };
}

export interface GraphMessage {
  id: string;
  createdDateTime: string;
  lastModifiedDateTime: string;
  deletedDateTime?: string;
  subject?: string;
  body: {
    contentType: 'html' | 'text';
    content: string;
  };
  from: {
    user: {
      id: string;
      displayName: string;
      userPrincipalName: string;
    };
  };
  mentions?: Array<{
    id: string;
    mentionText: string;
    mentioned: {
      user: {
        id: string;
        displayName: string;
        userPrincipalName: string;
      };
    };
  }>;
  attachments?: Array<{
    id: string;
    contentType: string;
    contentUrl?: string;
    name?: string;
  }>;
}

export interface GraphMeeting {
  id: string;
  subject: string;
  startDateTime: string;
  endDateTime: string;
  organizer: {
    emailAddress: {
      name: string;
      address: string;
    };
  };
  attendees: Array<{
    type: 'required' | 'optional';
    emailAddress: {
      name: string;
      address: string;
    };
  }>;
  onlineMeeting?: {
    joinUrl: string;
  };
}

export interface TeamsWebhookPayload {
  subscriptionId: string;
  changeType: 'created' | 'updated' | 'deleted';
  resource: string;
  resourceData: {
    id: string;
    '@odata.type': string;
  };
}

export interface TeamsSyncResult {
  messages_processed: number;
  messages_captured: number;
  meetings_processed: number;
  meetings_captured: number;
  errors: string[];
}

// ============================================================
// TEAMS INTEGRATION
// ============================================================

export class TeamsIntegration {
  private static readonly GRAPH_API_BASE = 'https://graph.microsoft.com/v1.0';
  private static readonly SCOPES = [
    'ChannelMessage.Read.All',
    'Chat.Read',
    'OnlineMeetings.Read',
    'User.Read.All'
  ];

  constructor(
    private db: D1Database,
    private businessId: string,
    private userId: string,
    private config: TeamsConfig
  ) {}

  // ============================================================
  // OAUTH FLOW
  // ============================================================

  /**
   * Generate OAuth URL for user authorization
   */
  static generateAuthUrl(config: TeamsConfig): string {
    const params = new URLSearchParams({
      client_id: config.client_id,
      response_type: 'code',
      redirect_uri: config.redirect_uri,
      scope: this.SCOPES.join(' '),
      response_mode: 'query'
    });

    return `https://login.microsoftonline.com/${config.tenant_id}/oauth2/v2.0/authorize?${params}`;
  }

  /**
   * Exchange authorization code for tokens
   */
  static async exchangeCode(config: TeamsConfig, code: string): Promise<{
    access_token: string;
    refresh_token: string;
    expires_in: number;
  }> {
    const response = await fetch(
      `https://login.microsoftonline.com/${config.tenant_id}/oauth2/v2.0/token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: config.client_id,
          client_secret: config.client_secret,
          code,
          grant_type: 'authorization_code',
          redirect_uri: config.redirect_uri
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

    const response = await fetch(
      `https://login.microsoftonline.com/${this.config.tenant_id}/oauth2/v2.0/token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: this.config.client_id,
          client_secret: this.config.client_secret,
          refresh_token: this.config.refresh_token,
          grant_type: 'refresh_token'
        })
      }
    );

    if (!response.ok) {
      throw new Error('Failed to refresh access token');
    }

    const data = await response.json() as { access_token: string; expires_in: number };
    this.config.access_token = data.access_token;
    this.config.token_expires_at = Date.now() + (data.expires_in * 1000);

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
  // MESSAGE SYNC
  // ============================================================

  /**
   * Sync messages from Teams channels
   */
  async syncMessages(teamId: string, channelId: string, maxResults: number = 50): Promise<TeamsSyncResult> {
    const accessToken = await this.getAccessToken();
    const result: TeamsSyncResult = {
      messages_processed: 0,
      messages_captured: 0,
      meetings_processed: 0,
      meetings_captured: 0,
      errors: []
    };

    try {
      const response = await fetch(
        `${TeamsIntegration.GRAPH_API_BASE}/teams/${teamId}/channels/${channelId}/messages?$top=${maxResults}`,
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

      const data = await response.json() as { value?: any[] };
      const messages = data.value || [];

      for (const message of messages) {
        try {
          result.messages_processed++;

          const interaction = this.convertMessageToInteraction(message, teamId, channelId);

          const engine = new AutoCaptureEngine(this.db, this.businessId, this.userId);
          await engine.captureInteraction(interaction);

          result.messages_captured++;
        } catch (error: any) {
          result.errors.push(`Message ${message.id}: ${error.message}`);
        }
      }
    } catch (error: any) {
      result.errors.push(`Message sync error: ${error.message}`);
    }

    return result;
  }

  /**
   * Convert Teams message to CapturedInteraction
   */
  private convertMessageToInteraction(message: GraphMessage, teamId: string, channelId: string): CapturedInteraction {
    const participants: Participant[] = [{
      email: message.from.user.userPrincipalName,
      name: message.from.user.displayName,
      role: 'sender'
    }];

    // Add mentioned users
    if (message.mentions) {
      for (const mention of message.mentions) {
        participants.push({
          email: mention.mentioned.user.userPrincipalName,
          name: mention.mentioned.user.displayName,
          role: 'recipient' // Changed from 'mentioned' to valid role type
        });
      }
    }

    // Strip HTML if content is HTML
    const body = message.body.contentType === 'html'
      ? this.stripHtml(message.body.content)
      : message.body.content;

    return {
      id: message.id,
      business_id: this.businessId,
      source_type: 'chat',
      external_id: message.id,
      subject: message.subject || 'Teams Message',
      body: body,
      participants: participants,
      direction: 'inbound',
      occurred_at: message.createdDateTime,
      metadata: {
        team_id: teamId,
        channel_id: channelId,
        message_type: 'teams_channel_message',
        has_attachments: (message.attachments?.length || 0) > 0
      }
    };
  }

  // ============================================================
  // MEETING SYNC
  // ============================================================

  /**
   * Sync online meetings
   */
  async syncMeetings(maxResults: number = 50): Promise<number> {
    const accessToken = await this.getAccessToken();
    let meetingsCaptured = 0;

    try {
      const response = await fetch(
        `${TeamsIntegration.GRAPH_API_BASE}/me/onlineMeetings?$top=${maxResults}`,
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

      const data = await response.json() as { value?: any[] };
      const meetings = data.value || [];

      for (const meeting of meetings) {
        try {
          const interaction = this.convertMeetingToInteraction(meeting);

          const engine = new AutoCaptureEngine(this.db, this.businessId, this.userId);
          await engine.captureInteraction(interaction);

          meetingsCaptured++;
        } catch (error: any) {
          logger.error(`Meeting ${meeting.id} error:`, error);
        }
      }
    } catch (error: any) {
      logger.error('Meeting sync error:', error);
    }

    return meetingsCaptured;
  }

  /**
   * Convert Teams meeting to CapturedInteraction
   */
  private convertMeetingToInteraction(meeting: GraphMeeting): CapturedInteraction {
    const participants: Participant[] = [
      {
        email: meeting.organizer.emailAddress.address,
        name: meeting.organizer.emailAddress.name,
        role: 'sender' // Changed from 'organizer' to valid role type
      }
    ];

    for (const attendee of meeting.attendees) {
      participants.push({
        email: attendee.emailAddress.address,
        name: attendee.emailAddress.name,
        role: 'recipient' // Changed from 'required'/'optional' to valid role type
      });
    }

    return {
      id: meeting.id,
      business_id: this.businessId,
      source_type: 'teams', // Changed from 'meeting' to valid source_type
      external_id: meeting.id,
      subject: meeting.subject,
      participants: participants,
      direction: 'inbound',
      occurred_at: meeting.startDateTime,
      metadata: {
        meeting_type: 'teams_online_meeting',
        start_time: meeting.startDateTime,
        end_time: meeting.endDateTime,
        join_url: meeting.onlineMeeting?.joinUrl
      }
    };
  }

  // ============================================================
  // WEBHOOK HANDLING
  // ============================================================

  /**
   * Handle Teams webhook notification
   */
  async handleWebhook(payload: TeamsWebhookPayload): Promise<void> {
    try {
      if (payload.changeType === 'created' && payload.resourceData['@odata.type'] === '#microsoft.graph.chatMessage') {
        // Fetch the full message
        const accessToken = await this.getAccessToken();
        const messageUrl = `${TeamsIntegration.GRAPH_API_BASE}/${payload.resource}`;

        const response = await fetch(messageUrl, {
          headers: {
            'Authorization': `Bearer ${accessToken}`
          }
        });

        if (response.ok) {
          const message = await response.json() as any;
          // Extract team and channel IDs from resource path
          const [, , teamId, , channelId] = payload.resource.split('/');
          const interaction = this.convertMessageToInteraction(message, teamId, channelId);

          const engine = new AutoCaptureEngine(this.db, this.businessId, this.userId);
          await engine.captureInteraction(interaction);
        }
      }
    } catch (error: any) {
      logger.error('Teams webhook error:', error);
      throw error;
    }
  }

  // ============================================================
  // UTILITY METHODS
  // ============================================================

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

  // ============================================================
  // PERSISTENCE
  // ============================================================

  private async saveConfig(): Promise<void> {
    await this.db
      .prepare(`
        UPDATE crm_chat_integrations
        SET config = ?, updated_at = CURRENT_TIMESTAMP
        WHERE business_id = ? AND provider = 'teams'
      `)
      .bind(
        JSON.stringify(this.config),
        this.businessId
      )
      .run();
  }

  async saveIntegration(): Promise<void> {
    await this.db
      .prepare(`
        INSERT INTO crm_chat_integrations (
          id, business_id, provider, config,
          auto_capture_enabled, monitored_channels
        ) VALUES (?, ?, 'teams', ?, TRUE, ?)
        ON CONFLICT(business_id, provider) DO UPDATE SET
          config = excluded.config,
          monitored_channels = excluded.monitored_channels,
          updated_at = CURRENT_TIMESTAMP
      `)
      .bind(
        crypto.randomUUID(),
        this.businessId,
        JSON.stringify(this.config),
        JSON.stringify(this.config.monitored_channels)
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
        `${TeamsIntegration.GRAPH_API_BASE}/me`,
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`
          }
        }
      );

      return response.ok;
    } catch {
      return false;
    }
  }
}
