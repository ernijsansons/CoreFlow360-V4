/**
 * Slack Integration for Auto-Capture
 * Captures messages, threads, and mentions with automatic customer linking
 * Implements Slack Web API with Events API for real-time capture
 */

import type { D1Database } from '@cloudflare/workers-types';
import { AutoCaptureEngine, type CapturedInteraction, type Participant } from '../services/crm/auto-capture';
import {
  SlackUserInfoResponseSchema,
  SlackChannelInfoResponseSchema,
  SlackConversationHistoryResponseSchema,
  SlackMessageEventSchema,
  validateAPIResponse,
  type SlackUserInfoResponse,
  type SlackChannelInfoResponse,
  type SlackConversationHistoryResponse,
  type SlackMessageEvent,
} from './types/api-responses';

// ============================================================
// TYPES
// ============================================================

export interface SlackConfig {
  bot_token: string;
  user_token?: string;
  app_id: string;
  team_id: string;
  webhook_url: string;
  monitored_channels: string[]; // Channel IDs to monitor
  features: {
    capture_threads: boolean;
    capture_mentions: boolean;
    capture_direct_messages: boolean;
    auto_link_customers: boolean;
  };
}

export interface SlackMessage {
  type: string;
  subtype?: string;
  user: string;
  text: string;
  ts: string;
  channel: string;
  thread_ts?: string;
  attachments?: Array<{
    fallback?: string;
    text?: string;
    title?: string;
  }>;
  files?: Array<{
    id: string;
    name: string;
    url_private: string;
  }>;
}

export interface SlackUser {
  id: string;
  name: string;
  real_name?: string; // Made optional to match API response
  profile?: {
    email?: string;
    phone?: string;
    title?: string;
    display_name?: string; // Added display_name
  };
}

export interface SlackChannel {
  id: string;
  name: string;
  is_channel: boolean;
  is_group: boolean;
  is_im: boolean;
  is_private: boolean;
}

export interface SlackEventPayload {
  type: string;
  event: {
    type: string;
    user?: string;
    text?: string;
    ts?: string;
    channel?: string;
    thread_ts?: string;
    subtype?: string; // Added missing subtype property
    message?: SlackMessage;
  };
  team_id: string;
}

export interface SlackSyncResult {
  messages_processed: number;
  messages_captured: number;
  errors: string[];
}

// ============================================================
// SLACK INTEGRATION
// ============================================================

export class SlackIntegration {
  private static readonly API_BASE = 'https://slack.com/api';

  constructor(
    private db: D1Database,
    private businessId: string,
    private config: SlackConfig
  ) {}

  // ============================================================
  // EVENT HANDLERS
  // ============================================================

  /**
   * Handle incoming Slack event
   */
  async handleEvent(payload: SlackEventPayload): Promise<void> {
    try {
      const event = payload.event;

      // Handle message events
      if (event.type === 'message' && !event.subtype) {
        await this.captureMessage({
          type: 'message',
          user: event.user!,
          text: event.text!,
          ts: event.ts!,
          channel: event.channel!,
          thread_ts: event.thread_ts
        });
      }

      // Handle message edits
      if (event.type === 'message' && event.subtype === 'message_changed') {
        // Update existing captured message
        if (event.message) {
          await this.updateCapturedMessage(event.message);
        }
      }
    } catch (error: any) {
      console.error('Slack event handler error:', error);
      throw error;
    }
  }

  /**
   * Capture Slack message
   */
  private async captureMessage(message: SlackMessage): Promise<void> {
    try {
      // Check if channel is monitored
      if (!this.config.monitored_channels.includes(message.channel)) {
        return;
      }

      // Skip thread messages if not configured
      if (message.thread_ts && !this.config.features.capture_threads) {
        return;
      }

      // Get user info
      const user = await this.getUserInfo(message.user);

      // Get channel info
      const channel = await this.getChannelInfo(message.channel);

      const participants: Participant[] = [{
        email: user.profile?.email,
        name: user.real_name,
        role: 'sender'
      }];

      // If it's a thread, get thread participants
      if (message.thread_ts) {
        const threadParticipants = await this.getThreadParticipants(message.channel, message.thread_ts);
        participants.push(...threadParticipants);
      }

      const interaction: CapturedInteraction = {
        id: `slack_${message.ts.replace('.', '_')}`,
        business_id: this.businessId,
        source_type: 'chat',
        external_id: message.ts,
        subject: channel.is_im ? 'Direct Message' : `Message in #${channel.name}`,
        body: message.text,
        participants: participants,
        direction: 'inbound',
        occurred_at: new Date(parseFloat(message.ts) * 1000).toISOString(),
        metadata: {
          channel_id: message.channel,
          channel_name: channel.name,
          thread_ts: message.thread_ts,
          is_thread: !!message.thread_ts,
          user_id: message.user,
          user_name: user.name
        }
      };

      const engine = new AutoCaptureEngine(this.db, this.businessId, 'system');
      await engine.captureInteraction(interaction);
    } catch (error: any) {
      console.error('Message capture error:', error);
      throw error;
    }
  }

  /**
   * Update captured message (for edits)
   */
  private async updateCapturedMessage(message: SlackMessage): Promise<void> {
    const externalId = message.ts;

    await this.db
      .prepare(`
        UPDATE crm_conversation_logs
        SET body = ?, updated_at = CURRENT_TIMESTAMP
        WHERE business_id = ? AND external_id = ?
      `)
      .bind(message.text, this.businessId, externalId)
      .run();
  }

  // ============================================================
  // SLACK API METHODS
  // ============================================================

  /**
   * Get user information
   */
  private async getUserInfo(userId: string): Promise<SlackUser> {
    const response = await fetch(`${SlackIntegration.API_BASE}/users.info?user=${userId}`, {
      headers: {
        'Authorization': `Bearer ${this.config.bot_token}`
      }
    });

    if (!response.ok) {
      throw new Error('Failed to fetch user info');
    }

    const rawData = await response.json();
    const data: SlackUserInfoResponse = validateAPIResponse(
      SlackUserInfoResponseSchema,
      rawData,
      'Invalid Slack user info response'
    );

    if (!data.ok) {
      throw new Error(data.error || 'User info request failed');
    }

    if (!data.user) {
      throw new Error('User data not found in response');
    }

    return data.user;
  }

  /**
   * Get channel information
   */
  private async getChannelInfo(channelId: string): Promise<SlackChannel> {
    const response = await fetch(`${SlackIntegration.API_BASE}/conversations.info?channel=${channelId}`, {
      headers: {
        'Authorization': `Bearer ${this.config.bot_token}`
      }
    });

    if (!response.ok) {
      throw new Error('Failed to fetch channel info');
    }

    const rawData = await response.json();
    const data: SlackChannelInfoResponse = validateAPIResponse(
      SlackChannelInfoResponseSchema,
      rawData,
      'Invalid Slack channel info response'
    );

    if (!data.ok) {
      throw new Error(data.error || 'Channel info request failed');
    }

    if (!data.channel) {
      throw new Error('Channel data not found in response');
    }

    return data.channel as SlackChannel;
  }

  /**
   * Get thread participants
   */
  private async getThreadParticipants(channelId: string, threadTs: string): Promise<Participant[]> {
    const response = await fetch(
      `${SlackIntegration.API_BASE}/conversations.replies?channel=${channelId}&ts=${threadTs}`,
      {
        headers: {
          'Authorization': `Bearer ${this.config.bot_token}`
        }
      }
    );

    if (!response.ok) {
      return [];
    }

    const rawData = await response.json();
    const data: SlackConversationHistoryResponse = validateAPIResponse(
      SlackConversationHistoryResponseSchema,
      rawData,
      'Invalid Slack conversation history response'
    );

    if (!data.ok || !data.messages) {
      return [];
    }

    const uniqueUsers = new Set<string>();
    for (const msg of data.messages) {
      if (msg.user) {
        uniqueUsers.add(msg.user);
      }
    }

    const participants: Participant[] = [];
    for (const userId of uniqueUsers) {
      try {
        const user = await this.getUserInfo(userId);
        participants.push({
          email: user.profile?.email,
          name: user.real_name,
          role: 'sender' // Changed from 'participant' to valid role
        });
      } catch {
        // Skip users we can't fetch
      }
    }

    return participants;
  }

  /**
   * Sync historical messages
   */
  async syncMessages(channelId: string, limit: number = 100): Promise<SlackSyncResult> {
    const result: SlackSyncResult = {
      messages_processed: 0,
      messages_captured: 0,
      errors: []
    };

    try {
      const response = await fetch(
        `${SlackIntegration.API_BASE}/conversations.history?channel=${channelId}&limit=${limit}`,
        {
          headers: {
            'Authorization': `Bearer ${this.config.bot_token}`
          }
        }
      );

      if (!response.ok) {
        throw new Error('Failed to fetch messages');
      }

      const rawData = await response.json();
      const data: SlackConversationHistoryResponse = validateAPIResponse(
        SlackConversationHistoryResponseSchema,
        rawData,
        'Invalid Slack conversation history response'
      );

      if (!data.ok) {
        throw new Error(data.error || 'Message fetch failed');
      }

      const messages = data.messages || [];

      for (const message of messages) {
        try {
          result.messages_processed++;

          // Skip bot messages and system messages
          if (message.subtype || message.bot_id) {
            continue;
          }

          await this.captureMessage(message);
          result.messages_captured++;
        } catch (error: any) {
          result.errors.push(`Message ${message.ts}: ${error.message}`);
        }
      }
    } catch (error: any) {
      result.errors.push(`Sync error: ${error.message}`);
    }

    return result;
  }

  // ============================================================
  // PERSISTENCE
  // ============================================================

  async saveIntegration(): Promise<void> {
    await this.db
      .prepare(`
        INSERT INTO crm_chat_integrations (
          id, business_id, provider, config,
          auto_capture_enabled, monitored_channels
        ) VALUES (?, ?, 'slack', ?, TRUE, ?)
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
      const response = await fetch(`${SlackIntegration.API_BASE}/auth.test`, {
        headers: {
          'Authorization': `Bearer ${this.config.bot_token}`
        }
      });

      if (!response.ok) {
        return false;
      }

      const data = await response.json() as { ok?: boolean };
      return data.ok === true;
    } catch {
      return false;
    }
  }

  /**
   * Validate webhook signature (for production use)
   */
  static validateWebhookSignature(
    signature: string,
    timestamp: string,
    body: string,
    signingSecret: string
  ): boolean {
    // In production, implement Slack's signature validation
    // See: https://api.slack.com/authentication/verifying-requests-from-slack
    // This requires crypto libraries for HMAC-SHA256
    return true; // Placeholder
  }
}
