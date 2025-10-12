/**
 * Gmail Integration for Auto-Capture
 * OAuth 2.0 integration with Gmail API for automatic email capture
 * Implements Gmail API v1 with proper scopes and security
 */

import type { D1Database } from '@cloudflare/workers-types';
import { AutoCaptureEngine, type CapturedInteraction, type Participant } from '../services/crm/auto-capture';
import {
  GmailTokenResponseSchema,
  GmailMessagesListResponseSchema,
  validateAPIResponse,
  type GmailTokenResponse,
  type GmailMessagesListResponse,
} from './types/api-responses';

// ============================================================
// TYPES
// ============================================================

export interface GmailConfig {
  client_id: string;
  client_secret: string;
  redirect_uri: string;
  access_token?: string;
  refresh_token?: string;
  token_expires_at?: number;
}

export interface GmailMessage {
  id: string;
  threadId: string;
  labelIds: string[];
  snippet: string;
  payload: {
    headers: Array<{ name: string; value: string }>;
    parts?: Array<{
      mimeType: string;
      body: { data?: string; size: number };
    }>;
    body?: { data?: string; size: number };
  };
  internalDate: string;
}

export interface GmailSyncResult {
  emails_processed: number;
  emails_captured: number;
  errors: string[];
  last_history_id?: string;
}

// ============================================================
// GMAIL INTEGRATION
// ============================================================

export class GmailIntegration {
  private static readonly SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.metadata'
  ];

  private static readonly API_BASE = 'https://gmail.googleapis.com/gmail/v1';

  constructor(
    private db: D1Database,
    private businessId: string,
    private userId: string,
    private config: GmailConfig
  ) {}

  // ============================================================
  // OAUTH FLOW
  // ============================================================

  /**
   * Generate OAuth URL for user authorization
   */
  static generateAuthUrl(config: GmailConfig): string {
    const params = new URLSearchParams({
      client_id: config.client_id,
      redirect_uri: config.redirect_uri,
      response_type: 'code',
      scope: this.SCOPES.join(' '),
      access_type: 'offline',
      prompt: 'consent'
    });

    return `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
  }

  /**
   * Exchange authorization code for tokens
   */
  static async exchangeCode(config: GmailConfig, code: string): Promise<{
    access_token: string;
    refresh_token: string;
    expires_in: number;
  }> {
    const response = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: config.client_id,
        client_secret: config.client_secret,
        code,
        grant_type: 'authorization_code',
        redirect_uri: config.redirect_uri
      })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to exchange code: ${error}`);
    }

    return await response.json();
  }

  /**
   * Refresh access token using refresh token
   */
  private async refreshAccessToken(): Promise<string> {
    if (!this.config.refresh_token) {
      throw new Error('No refresh token available');
    }

    const response = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: this.config.client_id,
        client_secret: this.config.client_secret,
        refresh_token: this.config.refresh_token,
        grant_type: 'refresh_token'
      })
    });

    if (!response.ok) {
      throw new Error('Failed to refresh access token');
    }

    const rawData = await response.json();
    const data: GmailTokenResponse = validateAPIResponse(
      GmailTokenResponseSchema,
      rawData,
      'Invalid Gmail token response'
    );

    this.config.access_token = data.access_token;
    this.config.token_expires_at = Date.now() + (data.expires_in * 1000);

    // Update in database
    await this.saveConfig();

    return data.access_token;
  }

  /**
   * Get valid access token (refresh if needed)
   */
  private async getAccessToken(): Promise<string> {
    if (!this.config.access_token) {
      return await this.refreshAccessToken();
    }

    // Check if token is expired or about to expire (5 min buffer)
    if (this.config.token_expires_at && this.config.token_expires_at < Date.now() + 300000) {
      return await this.refreshAccessToken();
    }

    return this.config.access_token;
  }

  // ============================================================
  // EMAIL SYNC
  // ============================================================

  /**
   * Sync emails from Gmail
   */
  async syncEmails(maxResults: number = 50): Promise<GmailSyncResult> {
    const accessToken = await this.getAccessToken();
    const result: GmailSyncResult = {
      emails_processed: 0,
      emails_captured: 0,
      errors: []
    };

    try {
      // Get list of messages
      const messagesResponse = await fetch(
        `${GmailIntegration.API_BASE}/users/me/messages?maxResults=${maxResults}&q=is:unread OR newer_than:7d`,
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      if (!messagesResponse.ok) {
        throw new Error('Failed to fetch messages');
      }

      const rawMessagesData = await messagesResponse.json();
      const messagesData: GmailMessagesListResponse = validateAPIResponse(
        GmailMessagesListResponseSchema,
        rawMessagesData,
        'Invalid Gmail messages list response'
      );
      const messages = messagesData.messages || [];

      // Process each message
      for (const messageRef of messages) {
        try {
          result.emails_processed++;

          // Fetch full message details
          const message = await this.fetchMessage(messageRef.id, accessToken);

          // Convert to CapturedInteraction
          const interaction = this.convertToInteraction(message);

          // Capture via AutoCaptureEngine
          const engine = new AutoCaptureEngine(this.db, this.businessId, this.userId);
          await engine.captureInteraction(interaction);

          result.emails_captured++;
        } catch (error: any) {
          result.errors.push(`Message ${messageRef.id}: ${error.message}`);
        }
      }

      if (messagesData.historyId) {
        result.last_history_id = messagesData.historyId;
      }
    } catch (error: any) {
      result.errors.push(`Sync error: ${error.message}`);
    }

    // Save sync result
    await this.saveSyncResult(result);

    return result;
  }

  /**
   * Fetch full message details
   */
  private async fetchMessage(messageId: string, accessToken: string): Promise<GmailMessage> {
    const response = await fetch(
      `${GmailIntegration.API_BASE}/users/me/messages/${messageId}?format=full`,
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to fetch message ${messageId}`);
    }

    return await response.json();
  }

  /**
   * Convert Gmail message to CapturedInteraction
   */
  private convertToInteraction(message: GmailMessage): CapturedInteraction {
    const headers = message.payload.headers;

    // Extract email addresses
    const from = this.findHeader(headers, 'From');
    const to = this.findHeader(headers, 'To');
    const cc = this.findHeader(headers, 'Cc');
    const subject = this.findHeader(headers, 'Subject');
    const date = this.findHeader(headers, 'Date');

    // Parse participants
    const participants: Participant[] = [];

    if (from) {
      participants.push({
        email: this.extractEmail(from),
        name: this.extractName(from),
        role: 'sender'
      });
    }

    if (to) {
      const recipients = to.split(',').map(r => r.trim());
      for (const recipient of recipients) {
        participants.push({
          email: this.extractEmail(recipient),
          name: this.extractName(recipient),
          role: 'recipient'
        });
      }
    }

    if (cc) {
      const ccRecipients = cc.split(',').map(r => r.trim());
      for (const recipient of ccRecipients) {
        participants.push({
          email: this.extractEmail(recipient),
          name: this.extractName(recipient),
          role: 'cc'
        });
      }
    }

    // Extract body
    const body = this.extractBody(message);

    // Determine direction (outbound if from us, inbound otherwise)
    const myEmail = this.findHeader(headers, 'X-Original-To') || to;
    const direction = from?.toLowerCase().includes('coreflow360') ? 'outbound' : 'inbound';

    return {
      id: message.id,
      business_id: this.businessId,
      source_type: 'email',
      external_id: message.id,
      subject: subject || '(no subject)',
      body: body,
      participants: participants,
      direction: direction,
      occurred_at: date ? new Date(date).toISOString() : new Date(parseInt(message.internalDate)).toISOString(),
      metadata: {
        thread_id: message.threadId,
        labels: message.labelIds,
        snippet: message.snippet
      }
    };
  }

  /**
   * Extract email body from message
   */
  private extractBody(message: GmailMessage): string {
    // Try to get plain text body
    if (message.payload.parts) {
      for (const part of message.payload.parts) {
        if (part.mimeType === 'text/plain' && part.body.data) {
          return this.decodeBase64(part.body.data);
        }
      }

      // Fallback to HTML
      for (const part of message.payload.parts) {
        if (part.mimeType === 'text/html' && part.body.data) {
          return this.stripHtml(this.decodeBase64(part.body.data));
        }
      }
    }

    // Single part message
    if (message.payload.body?.data) {
      const decoded = this.decodeBase64(message.payload.body.data);
      if (message.payload.parts?.[0]?.mimeType === 'text/html') {
        return this.stripHtml(decoded);
      }
      return decoded;
    }

    return message.snippet || '';
  }

  /**
   * Find header value by name
   */
  private findHeader(headers: Array<{ name: string; value: string }>, name: string): string | undefined {
    return headers.find(h => h.name.toLowerCase() === name.toLowerCase())?.value;
  }

  /**
   * Extract email address from "Name <email@example.com>" format
   */
  private extractEmail(raw: string): string {
    const match = raw.match(/<(.+?)>/);
    if (match) return match[1];

    // If no brackets, assume it's just the email
    return raw.trim();
  }

  /**
   * Extract name from "Name <email@example.com>" format
   */
  private extractName(raw: string): string | undefined {
    const match = raw.match(/^([^<]+)</);
    if (match) {
      return match[1].trim().replace(/^["']|["']$/g, '');
    }
    return undefined;
  }

  /**
   * Decode base64url encoded data
   */
  private decodeBase64(data: string): string {
    try {
      // Convert base64url to base64
      const base64 = data.replace(/-/g, '+').replace(/_/g, '/');
      // Decode
      return atob(base64);
    } catch {
      return data;
    }
  }

  /**
   * Strip HTML tags from text
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

  /**
   * Save integration config to database
   */
  private async saveConfig(): Promise<void> {
    await this.db
      .prepare(`
        UPDATE crm_email_integrations
        SET config = ?, updated_at = CURRENT_TIMESTAMP
        WHERE business_id = ? AND user_id = ? AND provider = 'gmail'
      `)
      .bind(
        JSON.stringify(this.config),
        this.businessId,
        this.userId
      )
      .run();
  }

  /**
   * Save sync result to database
   */
  private async saveSyncResult(result: GmailSyncResult): Promise<void> {
    await this.db
      .prepare(`
        UPDATE crm_email_integrations
        SET last_sync_at = CURRENT_TIMESTAMP,
            last_sync_status = ?,
            sync_error = ?,
            emails_synced = emails_synced + ?
        WHERE business_id = ? AND user_id = ? AND provider = 'gmail'
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

  // ============================================================
  // SETUP & MANAGEMENT
  // ============================================================

  /**
   * Save integration to database
   */
  async saveIntegration(): Promise<void> {
    await this.db
      .prepare(`
        INSERT INTO crm_email_integrations (
          id, business_id, user_id, provider, email_address, config,
          sync_enabled, auto_create_activities, auto_link_contacts
        ) VALUES (?, ?, ?, 'gmail', ?, ?, TRUE, TRUE, TRUE)
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
        `${GmailIntegration.API_BASE}/users/me/profile`,
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
