/**
 * CRM Auto-Capture System
 * Automatically captures and processes interactions from multiple channels
 * Inspired by Salesforce Einstein Activity Capture and HubSpot Email Tracking
 */

import type { D1Database } from '@cloudflare/workers-types';

// ============================================================
// TYPES
// ============================================================

export interface CapturedInteraction {
  id: string;
  business_id: string;
  source_type: 'email' | 'call' | 'chat' | 'sms' | 'whatsapp' | 'linkedin' | 'slack' | 'teams';
  external_id?: string;
  subject?: string;
  body?: string;
  transcript?: string;
  participants: Participant[];
  direction: 'inbound' | 'outbound';
  occurred_at: string;
  metadata?: Record<string, any>;
}

export interface Participant {
  email?: string;
  phone?: string;
  name?: string;
  role: 'sender' | 'recipient' | 'cc' | 'bcc' | 'caller' | 'callee';
}

export interface ProcessedInteraction {
  conversation_log_id: string;
  linked_entities: {
    company_id?: string;
    contact_id?: string;
    lead_id?: string;
    deal_id?: string;
  };
  ai_extracted_data: {
    sentiment?: 'positive' | 'neutral' | 'negative';
    intent?: string;
    entities?: ExtractedEntity[];
    action_items?: ActionItem[];
    topics?: string[];
    buying_signals?: string[];
    objections?: string[];
  };
  auto_linked: boolean;
  activity_created: boolean;
  activity_id?: string;
}

export interface ExtractedEntity {
  type: 'person' | 'company' | 'product' | 'date' | 'money' | 'location';
  value: string;
  confidence: number;
}

export interface ActionItem {
  description: string;
  assignee?: string;
  due_date?: string;
  priority: 'low' | 'medium' | 'high';
}

export interface EmailIntegrationConfig {
  provider: 'gmail' | 'outlook' | 'exchange' | 'imap';
  credentials: {
    access_token?: string;
    refresh_token?: string;
    client_id?: string;
    client_secret?: string;
    // IMAP specific
    host?: string;
    port?: number;
    username?: string;
    password?: string;
  };
  sync_settings: {
    sync_frequency_minutes: number;
    sync_sent: boolean;
    sync_received: boolean;
    folders_to_sync?: string[];
    exclude_folders?: string[];
  };
  filters?: {
    min_importance?: 'low' | 'normal' | 'high';
    only_external?: boolean;
    exclude_patterns?: string[];
  };
}

export interface CallIntegrationConfig {
  provider: 'twilio' | 'aircall' | 'dialpad' | 'ringcentral';
  credentials: {
    account_sid?: string;
    auth_token?: string;
    api_key?: string;
  };
  features: {
    auto_transcribe: boolean;
    record_calls: boolean;
    analyze_sentiment: boolean;
    extract_action_items: boolean;
  };
}

// ============================================================
// AUTO-CAPTURE ENGINE
// ============================================================

export class AutoCaptureEngine {
  constructor(
    private db: D1Database,
    private businessId: string,
    private userId: string
  ) {}

  // ============================================================
  // CAPTURE INTERACTION
  // ============================================================

  async captureInteraction(interaction: CapturedInteraction): Promise<string> {
    const id = crypto.randomUUID();

    await this.db
      .prepare(`
        INSERT INTO crm_conversation_logs (
          id, business_id, source_type, external_id,
          subject, body, transcript, participants, direction,
          occurred_at, processing_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
      `)
      .bind(
        id,
        this.businessId,
        interaction.source_type,
        interaction.external_id || null,
        interaction.subject || null,
        interaction.body || null,
        interaction.transcript || null,
        JSON.stringify(interaction.participants),
        interaction.direction,
        interaction.occurred_at
      )
      .run();

    // Trigger async processing
    // In production, this would be sent to a queue (Cloudflare Queues)
    // For now, we'll process immediately in background
    this.processInteractionAsync(id).catch(error => {
      console.error(`Failed to process interaction ${id}:`, error);
    });

    return id;
  }

  // ============================================================
  // PROCESS INTERACTION
  // ============================================================

  async processInteractionAsync(conversationLogId: string): Promise<ProcessedInteraction> {
    // Update status
    await this.db
      .prepare(`
        UPDATE crm_conversation_logs
        SET processing_status = 'processing'
        WHERE id = ?
      `)
      .bind(conversationLogId)
      .run();

    try {
      // Fetch conversation log
      const log = await this.db
        .prepare('SELECT * FROM crm_conversation_logs WHERE id = ?')
        .bind(conversationLogId)
        .first<any>();

      if (!log) {
        throw new Error('Conversation log not found');
      }

      const participants = JSON.parse(log.participants) as Participant[];

      // Step 1: Link to existing entities
      const linkedEntities = await this.linkToEntities(participants, log);

      // Step 2: Extract AI insights
      const aiExtractedData = await this.extractAIInsights(log);

      // Step 3: Create activity if entities found
      let activityId: string | undefined;
      if (linkedEntities.contact_id || linkedEntities.company_id) {
        activityId = await this.createActivity(log, linkedEntities, aiExtractedData);
      }

      // Step 4: Update conversation log with results
      await this.db
        .prepare(`
          UPDATE crm_conversation_logs
          SET processing_status = 'completed',
              ai_extracted_data = ?,
              ai_sentiment = ?,
              ai_intent = ?,
              linked_company_id = ?,
              linked_contact_id = ?,
              linked_lead_id = ?,
              linked_deal_id = ?,
              linked_activity_id = ?,
              auto_linked = ?,
              processed_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `)
        .bind(
          JSON.stringify(aiExtractedData),
          aiExtractedData.sentiment || null,
          aiExtractedData.intent || null,
          linkedEntities.company_id || null,
          linkedEntities.contact_id || null,
          linkedEntities.lead_id || null,
          linkedEntities.deal_id || null,
          activityId || null,
          linkedEntities.contact_id || linkedEntities.company_id ? 1 : 0,
          conversationLogId
        )
        .run();

      return {
        conversation_log_id: conversationLogId,
        linked_entities: linkedEntities,
        ai_extracted_data: aiExtractedData,
        auto_linked: !!(linkedEntities.contact_id || linkedEntities.company_id),
        activity_created: !!activityId,
        activity_id: activityId
      };
    } catch (error: any) {
      // Mark as failed
      await this.db
        .prepare(`
          UPDATE crm_conversation_logs
          SET processing_status = 'failed',
              processed_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `)
        .bind(conversationLogId)
        .run();

      throw error;
    }
  }

  // ============================================================
  // ENTITY LINKING
  // ============================================================

  private async linkToEntities(
    participants: Participant[],
    log: any
  ): Promise<{
    company_id?: string;
    contact_id?: string;
    lead_id?: string;
    deal_id?: string;
  }> {
    const linkedEntities: any = {};

    // Extract emails and phones from participants
    const emails = participants
      .map(p => p.email)
      .filter(Boolean)
      .map(e => e!.toLowerCase());

    const phones = participants
      .map(p => p.phone)
      .filter(Boolean)
      .map(p => this.normalizePhone(p!));

    // Try to find contact by email
    if (emails.length > 0) {
      const contact = await this.db
        .prepare(`
          SELECT id, company_id FROM crm_contacts
          WHERE business_id = ? AND email IN (${emails.map(() => '?').join(',')})
            AND deleted_at IS NULL
          LIMIT 1
        `)
        .bind(this.businessId, ...emails)
        .first<{ id: string; company_id?: string }>();

      if (contact) {
        linkedEntities.contact_id = contact.id;
        if (contact.company_id) {
          linkedEntities.company_id = contact.company_id;
        }
      }
    }

    // Try to find contact by phone if not found by email
    if (!linkedEntities.contact_id && phones.length > 0) {
      const contact = await this.db
        .prepare(`
          SELECT id, company_id FROM crm_contacts
          WHERE business_id = ? AND phone IS NOT NULL
            AND deleted_at IS NULL
        `)
        .bind(this.businessId)
        .all<{ id: string; company_id?: string; phone: string }>();

      for (const c of (contact.results || [])) {
        if (c.phone && phones.includes(this.normalizePhone(c.phone))) {
          linkedEntities.contact_id = c.id;
          if (c.company_id) {
            linkedEntities.company_id = c.company_id;
          }
          break;
        }
      }
    }

    // Try to extract company from email domain
    if (!linkedEntities.company_id && emails.length > 0) {
      for (const email of emails) {
        const domain = this.extractDomain(email);
        if (domain) {
          const company = await this.db
            .prepare(`
              SELECT id FROM crm_companies
              WHERE business_id = ? AND domain = ? AND deleted_at IS NULL
              LIMIT 1
            `)
            .bind(this.businessId, domain)
            .first<{ id: string }>();

          if (company) {
            linkedEntities.company_id = company.id;
            break;
          }
        }
      }
    }

    // Try to find related lead or deal if contact/company found
    if (linkedEntities.contact_id || linkedEntities.company_id) {
      // Find most recent open lead
      const lead = await this.db
        .prepare(`
          SELECT id FROM crm_leads
          WHERE business_id = ?
            AND (contact_id = ? OR company_id = ?)
            AND qualification_status NOT IN ('converted', 'dead')
            AND deleted_at IS NULL
          ORDER BY updated_at DESC
          LIMIT 1
        `)
        .bind(
          this.businessId,
          linkedEntities.contact_id || null,
          linkedEntities.company_id || null
        )
        .first<{ id: string }>();

      if (lead) {
        linkedEntities.lead_id = lead.id;
      }

      // Find most recent open deal
      const deal = await this.db
        .prepare(`
          SELECT id FROM crm_deals
          WHERE business_id = ?
            AND (primary_contact_id = ? OR company_id = ?)
            AND status = 'open'
            AND deleted_at IS NULL
          ORDER BY updated_at DESC
          LIMIT 1
        `)
        .bind(
          this.businessId,
          linkedEntities.contact_id || null,
          linkedEntities.company_id || null
        )
        .first<{ id: string }>();

      if (deal) {
        linkedEntities.deal_id = deal.id;
      }
    }

    return linkedEntities;
  }

  // ============================================================
  // AI INSIGHTS EXTRACTION
  // ============================================================

  private async extractAIInsights(log: any): Promise<any> {
    const content = log.body || log.transcript || '';
    const subject = log.subject || '';

    // In production, this would call Claude API or Workers AI
    // For now, we'll implement basic rule-based extraction

    const insights: any = {
      sentiment: this.analyzeSentiment(content),
      intent: this.extractIntent(subject, content),
      entities: this.extractEntities(content),
      action_items: this.extractActionItems(content),
      topics: this.extractTopics(content),
      buying_signals: this.detectBuyingSignals(content),
      objections: this.detectObjections(content)
    };

    return insights;
  }

  private analyzeSentiment(text: string): 'positive' | 'neutral' | 'negative' {
    const positiveWords = ['great', 'excellent', 'perfect', 'love', 'thanks', 'appreciate', 'wonderful', 'amazing', 'interested', 'yes'];
    const negativeWords = ['no', 'not', 'cancel', 'issue', 'problem', 'difficult', 'concern', 'worried', 'disappointed'];

    const lowerText = text.toLowerCase();
    let positiveCount = 0;
    let negativeCount = 0;

    for (const word of positiveWords) {
      if (lowerText.includes(word)) positiveCount++;
    }

    for (const word of negativeWords) {
      if (lowerText.includes(word)) negativeCount++;
    }

    if (positiveCount > negativeCount + 1) return 'positive';
    if (negativeCount > positiveCount + 1) return 'negative';
    return 'neutral';
  }

  private extractIntent(subject: string, content: string): string {
    const combined = `${subject} ${content}`.toLowerCase();

    if (combined.includes('demo') || combined.includes('presentation')) return 'request_demo';
    if (combined.includes('pricing') || combined.includes('quote') || combined.includes('cost')) return 'pricing_inquiry';
    if (combined.includes('meeting') || combined.includes('call') || combined.includes('schedule')) return 'schedule_meeting';
    if (combined.includes('question') || combined.includes('help') || combined.includes('support')) return 'support_request';
    if (combined.includes('contract') || combined.includes('agreement') || combined.includes('sign')) return 'close_deal';
    if (combined.includes('follow up') || combined.includes('checking in')) return 'follow_up';

    return 'general_inquiry';
  }

  private extractEntities(text: string): ExtractedEntity[] {
    const entities: ExtractedEntity[] = [];

    // Extract dates (simple regex)
    const datePatterns = [
      /\b(january|february|march|april|may|june|july|august|september|october|november|december)\s+\d{1,2}(st|nd|rd|th)?\b/gi,
      /\b\d{1,2}\/\d{1,2}\/\d{2,4}\b/g,
      /\bnext (week|month|quarter)\b/gi
    ];

    for (const pattern of datePatterns) {
      const matches = text.match(pattern);
      if (matches) {
        for (const match of matches) {
          entities.push({
            type: 'date',
            value: match,
            confidence: 0.8
          });
        }
      }
    }

    // Extract money amounts
    const moneyPattern = /\$[\d,]+(?:\.\d{2})?/g;
    const moneyMatches = text.match(moneyPattern);
    if (moneyMatches) {
      for (const match of moneyMatches) {
        entities.push({
          type: 'money',
          value: match,
          confidence: 0.9
        });
      }
    }

    return entities;
  }

  private extractActionItems(text: string): ActionItem[] {
    const actionItems: ActionItem[] = [];

    // Look for action phrases
    const actionPhrases = [
      /\b(i will|i'll|we will|we'll)\s+([^\n.]+)/gi,
      /\b(please|could you)\s+([^\n.]+)/gi,
      /\b(need to|must|should)\s+([^\n.]+)/gi,
      /\b(action item|todo|task):\s*([^\n.]+)/gi
    ];

    for (const pattern of actionPhrases) {
      const matches = [...text.matchAll(pattern)];
      for (const match of matches) {
        const description = match[2] || match[1];
        if (description && description.length > 5) {
          actionItems.push({
            description: description.trim().substring(0, 200),
            priority: 'medium'
          });
        }
      }
    }

    return actionItems.slice(0, 5); // Limit to 5 action items
  }

  private extractTopics(text: string): string[] {
    const topics: string[] = [];

    const topicKeywords: Record<string, string[]> = {
      'pricing': ['price', 'pricing', 'cost', 'budget', 'quote'],
      'features': ['feature', 'functionality', 'capability', 'can it', 'does it'],
      'integration': ['integrate', 'integration', 'api', 'connect', 'sync'],
      'security': ['security', 'secure', 'encryption', 'compliance', 'gdpr'],
      'onboarding': ['onboard', 'setup', 'getting started', 'implementation'],
      'support': ['support', 'help', 'issue', 'problem', 'bug']
    };

    const lowerText = text.toLowerCase();

    for (const [topic, keywords] of Object.entries(topicKeywords)) {
      for (const keyword of keywords) {
        if (lowerText.includes(keyword)) {
          topics.push(topic);
          break;
        }
      }
    }

    return [...new Set(topics)];
  }

  private detectBuyingSignals(text: string): string[] {
    const signals: string[] = [];
    const lowerText = text.toLowerCase();

    const buyingSignalPatterns = [
      { pattern: /\b(ready to|want to|looking to)\s+(buy|purchase|start|proceed)\b/i, signal: 'ready_to_buy' },
      { pattern: /\b(what.*next steps?|how do we proceed)\b/i, signal: 'asking_next_steps' },
      { pattern: /\b(contract|agreement|sign)\b/i, signal: 'contract_discussion' },
      { pattern: /\b(when can we (start|begin|launch))\b/i, signal: 'timeline_inquiry' },
      { pattern: /\b(approved|budget approved|got approval)\b/i, signal: 'budget_approved' },
      { pattern: /\b(decision maker|boss|manager|executive).*agreed\b/i, signal: 'stakeholder_buy_in' }
    ];

    for (const { pattern, signal } of buyingSignalPatterns) {
      if (pattern.test(lowerText)) {
        signals.push(signal);
      }
    }

    return signals;
  }

  private detectObjections(text: string): string[] {
    const objections: string[] = [];
    const lowerText = text.toLowerCase();

    const objectionPatterns = [
      { pattern: /\b(too expensive|too costly|over budget)\b/i, objection: 'price_concern' },
      { pattern: /\b(not sure|uncertain|hesitant)\b/i, objection: 'uncertainty' },
      { pattern: /\b(need to think|need time|not ready)\b/i, objection: 'timing' },
      { pattern: /\b(already (have|using)|current (solution|provider))\b/i, objection: 'existing_solution' },
      { pattern: /\b(missing|doesn''t have|lack of).*feature\b/i, objection: 'feature_gap' },
      { pattern: /\b(complicated|complex|difficult)\b/i, objection: 'complexity_concern' }
    ];

    for (const { pattern, objection } of objectionPatterns) {
      if (pattern.test(lowerText)) {
        objections.push(objection);
      }
    }

    return objections;
  }

  // ============================================================
  // ACTIVITY CREATION
  // ============================================================

  private async createActivity(
    log: any,
    linkedEntities: any,
    aiExtractedData: any
  ): Promise<string> {
    const activityType = this.mapSourceToActivityType(log.source_type);
    const id = crypto.randomUUID();

    await this.db
      .prepare(`
        INSERT INTO crm_activities (
          id, business_id, type, subject, description,
          company_id, contact_id, lead_id, deal_id,
          scheduled_at, completed_at, status, outcome, outcome_notes,
          owner_id, sentiment_score, key_topics, action_items
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        id,
        this.businessId,
        activityType,
        log.subject || `${log.source_type} interaction`,
        log.body || log.transcript || '',
        linkedEntities.company_id || null,
        linkedEntities.contact_id || null,
        linkedEntities.lead_id || null,
        linkedEntities.deal_id || null,
        log.occurred_at,
        log.occurred_at,
        'completed',
        this.mapSentimentToOutcome(aiExtractedData.sentiment),
        JSON.stringify({
          buying_signals: aiExtractedData.buying_signals,
          objections: aiExtractedData.objections
        }),
        this.userId,
        this.sentimentToScore(aiExtractedData.sentiment),
        JSON.stringify(aiExtractedData.topics || []),
        JSON.stringify(aiExtractedData.action_items || [])
      )
      .run();

    return id;
  }

  private mapSourceToActivityType(sourceType: string): string {
    const mapping: Record<string, string> = {
      email: 'email',
      call: 'call',
      chat: 'note',
      sms: 'note',
      whatsapp: 'note',
      linkedin: 'linkedin_message',
      slack: 'note',
      teams: 'note'
    };
    return mapping[sourceType] || 'other';
  }

  private mapSentimentToOutcome(sentiment?: string): string | null {
    if (!sentiment) return null;
    const mapping: Record<string, string> = {
      positive: 'positive',
      neutral: 'neutral',
      negative: 'negative'
    };
    return mapping[sentiment] || null;
  }

  private sentimentToScore(sentiment?: string): number {
    if (!sentiment) return 0;
    const scores: Record<string, number> = {
      positive: 75,
      neutral: 0,
      negative: -75
    };
    return scores[sentiment] || 0;
  }

  // ============================================================
  // UTILITY METHODS
  // ============================================================

  private normalizePhone(phone: string): string {
    return phone.replace(/[^0-9]/g, '');
  }

  private extractDomain(email: string): string | null {
    const match = email.match(/@(.+)$/);
    return match ? match[1].toLowerCase() : null;
  }
}
