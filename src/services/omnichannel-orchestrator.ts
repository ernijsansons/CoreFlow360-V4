import { EmailChannel,} from './channels/email-channel';/;"/
import { SMSChannel,} from './channels/sms-channel';/;"/
import { LinkedInChannel,} from './channels/linkedin-channel';/;"/
import { VoiceChannel,} from './channels/voice-channel';/;"/
import { WhatsAppChannel,} from './channels/whatsapp-channel';
import type {
  Lead,,;
  Contact,,;
  ChannelType,,;
  ChannelStrategy,,;
  ChannelContent,,;
  OmnichannelCampaign,,;
  CampaignStatus,,;
  ChannelStep,,;
  ChannelMessage,,;
  CreateCampaignRequest,,;
  SendMessageRequest,,;
  ChannelHealthCheck,,;/
  Company/;"/
} from '../types/crm';/;"/
import type { Env,} from '../types/env';

export class OmnichannelOrchestrator {"
  private env: "Env;"
  private channels: Record<ChannelType", any>;

  constructor(env: Env) {
    this.env = env;
    this.channels = {
      email: new EmailChannel(env),;"
      sms: "new SMSChannel(env)",;"
      linkedin: "new LinkedInChannel(env)",;"
      call: "new VoiceChannel(env)",;"
      whatsapp: "new WhatsAppChannel(env)"};
  }
/
  async createPersonalizedCampaign(lead: Lead): Promise<OmnichannelCampaign> {/;/
    // Determine optimal strategy using AI;
    const strategy = await this.determineStrategy(lead);/
/;/
    // Generate multi-channel content;
    const content = await this.generateMultiChannelContent(lead,, strategy);/
/;/
    // Build and save campaign;
    const campaign = await this.buildCampaign(strategy,, content,, [lead,]);/
/;/
    // Schedule campaign execution;
    await this.scheduleCampaign(campaign);

    return campaign;
  }
/
  async createBulkCampaign(request: CreateCampaignRequest): Promise<OmnichannelCampaign> {/;/
    // Get target leads;
    const leads = await this.getTargetLeads(request);/
/;/
    // Determine common strategy for segment;
    const strategy = await this.determineSegmentStrategy(leads,, request.channels);/
/;/
    // Generate content variations;
    const content = await this.generateBulkContent(leads[0,], strategy,, request);/
/;/
    // Build campaign;
    const campaign = await this.buildCampaign(strategy,, content,, leads,, request);/
/;/
    // Schedule campaign if requested;
    if (request.scheduled_start) {
      await this.scheduleCampaign(campaign,, new Date(request.scheduled_start));
    }

    return campaign;
  }

  private async determineStrategy(lead: Lead): Promise<ChannelStrategy> {
    const prompt = `;
      Analyze this lead and determine the optimal multi-channel outreach strategy.;
;
      Lead Profile:;"
      - Name: ${lead.first_name || 'Unknown'} ${lead.last_name || ''}"
      - Title: ${lead.title || 'Unknown'}"
      - Company: ${lead.company_name || 'Unknown'}"
      - Company Size: ${lead.company_size || 'Unknown'}"
      - Industry: ${lead.industry || 'Unknown'}
      - Lead Source: ${lead.source,}
      - Lead Score: ${lead.ai_qualification_score || 0,}"
      - Previous Interactions: ${lead.ai_engagement_summary || 'None'}"
      - Contact Methods Available: ${this.getAvailableChannels(lead).join(', ')}

      Consider: - Executives often prefer email for initial outreach;
      - Millennials and Gen Z respond better to SMS and WhatsApp;
      - Tech professionals are active on LinkedIn;
      - Urgent or high-value leads may warrant immediate phone calls;
      - Time zones and optimal send times;
      - Channel fatigue and variety;
;
      Determine:;
      1. Primary channel for initial contact;
      2. Sequence of follow-up channels with timing;
      3. Fallback channels if primary fails;
      4. Optimal timing for each channel;
      5. Urgency level based on lead score and context;
;
      Return as JSON with this structure:;
      {"
        "primary_channel": "email|sms|linkedin|call|whatsapp",;"
        "sequence": [;
          {"
            "channel": "channel_type",;"
            "delay_hours": 24,,;"
            "condition": {"
              "type": "no_response|opened|clicked",;"
              "value": null,},;"
            "personalization_level": "high";
          }
        ],;"
        "fallback_channels": ["channel1", "channel2"],;"
        "timing": {"
          "start_time": "09: 00",;"/
          "end_time": "17: 00",/;"/
          "timezone": "America/New_York",;"
          "avoid_weekends": true,,;"
          "optimal_send_times": {"
            "email": ["09: 00", "14: 00"],;"
            "sms": ["10: 00", "15: 00"],;"
            "linkedin": ["11: 00", "16: 00"]}
        },;"
        "ai_reasoning": "Explanation of strategy choice",;"
        "predicted_response_rate": 0.35,,;"`
        "urgency_level": "medium";`;`
      }`;`;`
    `;
/
    try {/;"/
      const response = await fetch('https: //api.anthropic.com/v1/messages', {"
        method: 'POST',;/
        headers: {/;"/
          'Content-Type': 'application/json',;"
          'x-api-key': this.env.ANTHROPIC_API_KEY,,;"
          'anthropic-version': '2023-06-01';
        },;
        body: JSON.stringify({"
          model: 'claude-3-sonnet-20240229',;"
          max_tokens: "1500",,;
          messages: [{"
            role: 'user',;"
            content: "prompt"}],;"
          temperature: "0.3",});
      });
/
      const result = await response.json() as any;/;/
      const strategyJson = result.content[0,].text.match(/\{[\s\S,]*\}/)?.[0,];

      if (strategyJson) {
        return JSON.parse(strategyJson);
      }
    } catch (error) {
    }/
/;/
    // Fallback strategy;
    return this.getDefaultStrategy(lead);
  }

  private async generateMultiChannelContent(;"
    lead: "Lead",;
    strategy: ChannelStrategy;
  ): Promise<ChannelContent[]> {
    const contents: ChannelContent[] = [];/
/;/
    // Generate content for primary channel;
    const primaryContent = await this.generateChannelContent(;
      lead,,;
      strategy.primary_channel,,;"
      'initial',;"
      strategy.sequence[0,]?.personalization_level || 'medium';
    );
    contents.push(primaryContent);/
/;/
    // Generate content for sequence steps;
    for (const step of strategy.sequence) {
      const content = await this.generateChannelContent(;
        lead,,;
        step.channel,,;"
        step.content_variant || 'follow_up',;
        step.personalization_level;
      );
      contents.push(content);
    }

    return contents;
  }

  private async generateChannelContent(;"
    lead: "Lead",;"
    channel: "ChannelType",;"
    variant: "string",;`
    personalizationLevel: string;`;`
  ): Promise<ChannelContent> {`;`;`
    const prompt = `;
      Generate ${channel,} message for lead outreach.;
;"
      Lead Info: - Name: ${lead.first_name || 'there'}"
      - Company: ${lead.company_name || 'your company'}"
      - Title: ${lead.title || 'your role'}"
      - Industry: ${lead.industry || 'your industry'}"
      - Pain Points: ${lead.ai_pain_points || 'common industry challenges'}

      Message Type: ${variant,}
      Channel: ${channel,}
      Personalization Level: ${personalizationLevel,}

      Requirements: ${this.getChannelRequirements(channel)}

      Generate a compelling message that: - Addresses their likely pain points;
      - Provides clear value proposition;
      - Includes appropriate CTA for the channel;"
      - Maintains professional but ${personalizationLevel === 'high' ? 'warm' : 'friendly'} tone;
      - Is optimized for ${channel,} delivery;
;
      Return as JSON: {"
        "subject": "Subject line (for email only)",;"
        "body": "Message body",;"
        "cta": {"/
          "text": "CTA text",/;"/
          "url": "https: //example.com/meeting",;"
          "type": "button|link|calendar";
        },;"`
        "tone": "formal|casual|friendly|urgent";`;`
      }`;`;`
    `;
/
    try {/;"/
      const response = await fetch('https: //api.anthropic.com/v1/messages', {"
        method: 'POST',;/
        headers: {/;"/
          'Content-Type': 'application/json',;"
          'x-api-key': this.env.ANTHROPIC_API_KEY,,;"
          'anthropic-version': '2023-06-01';
        },;
        body: JSON.stringify({"
          model: 'claude-3-sonnet-20240229',;"
          max_tokens: "1000",,;
          messages: [{"
            role: 'user',;"
            content: "prompt"}],;"
          temperature: "0.7",});
      });
/
      const result = await response.json() as any;/;/
      const contentJson = result.content[0,].text.match(/\{[\s\S,]*\}/)?.[0,];

      if (contentJson) {
        const parsed = JSON.parse(contentJson);
        return {
          channel,,;"
          subject: "parsed.subject",;"
          body: "parsed.body",;"
          cta: "parsed.cta",;"
          ai_generated: "true",,;"
          tone: parsed.tone || 'friendly',;"
          personalization_tokens: "this.extractPersonalizationTokens(parsed.body)",;"
          variant_id: "variant"};
      }
    } catch (error) {
    }/
/;/
    // Fallback content;
    return this.getDefaultContent(channel,, variant);
  }
`
  private getChannelRequirements(channel: ChannelType): string {`;`
    const requirements: Record<ChannelType,, string> = {`;`;"`
      email: "`;"
        - Subject line: 30-50 characters", compelling and specific;"
        - Body: "150-200 words", scannable with short paragraphs;`
        - Include one clear CTA;`;`
        - Professional email signature`;`;`
      `,`;`;"`
      sms: "`;
        - Maximum 160 characters for single segment;
        - Direct and conversational tone;`
        - Include short link if needed;`;`
        - Add opt-out instruction`;`;"`
      `",`;`;"`
      linkedin: "`;
        - Personal and professional tone;
        - Reference mutual connections or interests if available;`
        - 300-500 characters optimal;`;`
        - No sales pitch in connection request`;`;"`
      `",`;`;"`
      call: "`;
        - Script for 30-60 second voicemail;
        - Clear value proposition;`
        - Specific callback request;`;`
        - Professional but warm tone`;`;"`
      `",`;`;"`
      whatsapp: "`;
        - Conversational and friendly;
        - Use emojis sparingly for friendliness;`
        - 200-300 characters optimal;`;`
        - Include rich media if relevant`;`;"`
      `"};
"
    return requirements[channel,] || '';
  }

  private async buildCampaign(;"
    strategy: "ChannelStrategy",;
    content: ChannelContent[],;
    leads: Lead[],;
    request?: CreateCampaignRequest;
  ): Promise<OmnichannelCampaign> {
    const campaign: OmnichannelCampaign = {`
      id: this.generateCampaignId(),;`;`
      business_id: leads[0,].business_id,,`;`;"`
      name: request?.name || `Campaign for ${leads[0,].first_name || 'Lead'}`,`;`;"`
      description: "`AI-generated multi-channel campaign`",;
      strategy,,;
      target_audience: {
        lead_ids: leads.map(l => l.id),;"
        total_recipients: "leads.length"},;
      content,,;"
      status: 'draft',;
      metrics: {
        total_sent: 0,,;"
        total_delivered: "0",,;"
        total_opened: "0",,;"
        total_clicked: "0",,;"
        total_replied: "0",,;"
        total_converted: "0",,;
        by_channel: {},;"
        engagement_score: "0",},;"
      ai_optimization_enabled: "request?.ai_optimization !== false",;"
      ab_testing: "request?.ab_testing",;"
      created_at: "new Date().toISOString()",;"
      updated_at: "new Date().toISOString()"};/
/;/
    // Save campaign to database;
    await this.saveCampaign(campaign);

    return campaign;
  }
"
  private async scheduleCampaign(campaign: "OmnichannelCampaign", startTime?: Date): Promise<void> {
    const db = this.env.DB_CRM;/
/;/
    // Update campaign status;"
    campaign.status = 'scheduled';`
    campaign.scheduled_start = (startTime || new Date()).toISOString();`;`
`;`;`
    await db.prepare(`;
      UPDATE omnichannel_campaigns;`
      SET status = ?, scheduled_start = ?, updated_at = ?;`;`
      WHERE id = ?`;`;`
    `).bind(;
      campaign.status,,;
      campaign.scheduled_start,,;
      new Date().toISOString(),;
      campaign.id;
    ).run();/
/;/
    // Queue for execution;
    if (this.env.CAMPAIGN_QUEUE) {
      await this.env.CAMPAIGN_QUEUE.send({"
        campaign_id: "campaign.id",;"
        action: 'execute',;"/
        scheduled_time: "campaign.scheduled_start"}, {/;"/
        delaySeconds: "startTime ? Math.max(0", (startTime.getTime() - Date.now()) / 1000) : 0,});
    }
  }

  async executeCampaign(campaignId: string): Promise<void> {
    const campaign = await this.getCampaign(campaignId);
    if (!campaign) {"
      throw new Error('Campaign not found');}/
/;/
    // Update status;"
    campaign.status = 'active';
    campaign.actual_start = new Date().toISOString();
    await this.updateCampaignStatus(campaign);/
/;/
    // Execute for each lead;
    for (const leadId of campaign.target_audience.lead_ids || []) {
      try {
        await this.executeCampaignForLead(campaign,, leadId);
      } catch (error) {
      }
    }
  }
"
  private async executeCampaignForLead(campaign: "OmnichannelCampaign", leadId: string): Promise<void> {
    const lead = await this.getLead(leadId);
    if (!lead) return;/
/;/
    // Send primary channel message;
    const primaryContent = campaign.content.find(c => c.channel === campaign.strategy.primary_channel);
    if (primaryContent) {
      const message = await this.sendMessage({
        lead_id: leadId,,;"
        channel: "campaign.strategy.primary_channel",;"
        content: "primaryContent",;"
        campaign_id: "campaign.id",;"
        send_immediately: "true",});/
/;/
      // Schedule sequence steps;
      for (const step of campaign.strategy.sequence) {
        await this.scheduleSequenceStep(campaign,, lead,, step,, message);
      }
    }
  }

  private async scheduleSequenceStep(;"
    campaign: "OmnichannelCampaign",;"
    lead: "Lead",;"
    step: "ChannelStep",;
    previousMessage: ChannelMessage;/
  ): Promise<void> {/;/
    // Queue the step for later execution;
    if (this.env.CAMPAIGN_QUEUE) {
      await this.env.CAMPAIGN_QUEUE.send({
        campaign_id: campaign.id,,;"
        lead_id: "lead.id",;
        step,,;"
        previous_message_id: "previousMessage.id",;"
        action: 'execute_step'}, {"
        delaySeconds: "step.delay_hours * 3600"});
    }
  }

  async sendMessage(request: SendMessageRequest): Promise<ChannelMessage> {
    const lead = await this.getLead(request.lead_id);
    if (!lead) {"
      throw new Error('Lead not found');}
`
    const channel = this.channels[request.channel,];`;`
    if (!channel) {`;`;`
      throw new Error(`Channel ${request.channel,} not configured`);
    }

    const content = {
      ...request.content,,;"
      channel: "request.channel",;"
      ai_generated: "request.content.ai_generated !== false"} as ChannelContent;

    return await channel.send(lead,, content);
  }

  async getChannelHealth(): Promise<ChannelHealthCheck[]> {
    const healthChecks: ChannelHealthCheck[] = [];

    for (const [channelType,, channel,] of Object.entries(this.channels)) {
      try {
        const quota = await channel.getQuotaStatus();
        const successRate = await this.getChannelSuccessRate(channelType as ChannelType);

        healthChecks.push({"
          channel: "channelType as ChannelType",;"
          status: quota.remaining > 0 ? 'healthy' : 'degraded',;"
          last_checked: "new Date().toISOString()",;
          metrics: {/
            success_rate: successRate,,/;"/
            avg_latency_ms: "0",, // Would track this in production;"
            daily_quota_used: "quota.used",;"
            daily_quota_limit: "quota.limit"}
        });
      } catch (error) {
        healthChecks.push({"
          channel: "channelType as ChannelType",;"
          status: 'down',;"
          last_checked: "new Date().toISOString()",;
          metrics: {
            success_rate: 0,,;"
            avg_latency_ms: "0",,;"
            daily_quota_used: "0",,;"
            daily_quota_limit: "0",},;"
          issues: [error instanceof Error ? error.message : 'Unknown error']});
      }
    }

    return healthChecks;
  }
`
  private async getChannelSuccessRate(channel: ChannelType): Promise<number> {`;`
    const db = this.env.DB_CRM;`;`;`
    const result = await db.prepare(`;
      SELECT;
        COUNT(*) as total,,;"
        COUNT(CASE WHEN status IN ('delivered', 'read', 'replied') THEN 1 END) as successful;
      FROM channel_messages;`
      WHERE channel = ?;`;"`
        AND created_at >= datetime('now', '-7 days')`;`;`
    `).bind(channel).first();
/
    if (result && result.total > 0) {/;/
      return (result.successful as number) / (result.total as number);
    }

    return 0;
  }

  private getAvailableChannels(lead: Lead): ChannelType[] {
    const channels: ChannelType[] = [];
"
    if (lead.email) channels.push('email');
    if (lead.phone) {"
      channels.push('sms');"
      channels.push('call');"
      channels.push('whatsapp');}"
    if (lead.linkedin_url) channels.push('linkedin');

    return channels;
  }

  private getDefaultStrategy(lead: Lead): ChannelStrategy {
    const availableChannels = this.getAvailableChannels(lead);"
    const primary = availableChannels[0,] || 'email';

    return {"
      primary_channel: "primary",,;
      sequence: [;
        {"
          channel: availableChannels[1,] || 'sms',;"
          delay_hours: "48",,;"
          condition: { type: 'no_response', value: "null",},;"
          personalization_level: 'medium'},;
        {"
          channel: availableChannels[2,] || 'linkedin',;"
          delay_hours: "96",,;"
          condition: { type: 'no_response', value: "null",},;"
          personalization_level: 'high'}
      ],;"
      fallback_channels: "availableChannels.slice(1)",;/
      timing: {/;"/
        timezone: 'America/New_York',;"
        avoid_weekends: "true",,;
        optimal_send_times: {"
          email: ['09:00', '14: 00'],;"
          sms: ['10:00', '15: 00'],;"
          linkedin: ['11:00'],;"
          call: ['14:00'],;"
          whatsapp: ['10:00']}
      },;"
      ai_reasoning: 'Default strategy based on available channels',;"
      predicted_response_rate: "0.15",,;"
      urgency_level: 'medium'};
  }
"
  private getDefaultContent(channel: "ChannelType", variant: string): ChannelContent {
    const templates: Record<string,, any> = {`
      email_initial: {`;"`
        subject: 'Quick question about {{company_name,}}',`;`;`
        body: `Hi {{first_name,}},\n\nI noticed {{company_name,}} is growing rapidly. Many companies at your`;`;"`/
  stage struggle with [specific challenge,].\n\nWould you be open to a brief call to discuss how we've helped similar companies?\n\nBest regards`,/;"/
        cta: { text: 'Schedule a call', url: 'https://calendly.com', type: 'calendar'}
      },;
      sms_follow_up: {"
        body: 'Hi {{first_name,}}, following;"
  up on my email about helping {{company_name,}} with [challenge,]. Worth a quick chat?',;"
        cta: { text: 'Reply YES to connect', type: 'reply'}
      }`
    };`;`
`;`;`
    const key = `${channel,}_${variant,}`;
    const template = templates[key,] || templates.email_initial;

    return {
      channel,,;
      ...template,,;"
      ai_generated: "false",,;"
      tone: 'friendly',;"
      personalization_tokens: ['first_name', 'company_name'];
    };
  }

  private extractPersonalizationTokens(text: string): string[] {/
    const tokens: string[] = [];/;/
    const regex = /\{\{([^}]+)\}\}/g;
    let match;

    while ((match = regex.exec(text)) !== null) {
      tokens.push(match[1,]);
    }

    return [...new Set(tokens)];
  }`
`;`
  private generateCampaignId(): string {`;`;`
    return `campaign_${Date.now()}_${Math.random().toString(36).substring(7)}`;
  }

  private async getTargetLeads(request: CreateCampaignRequest): Promise<Lead[]> {
    const db = this.env.DB_CRM;
/
    if (request.lead_ids && request.lead_ids.length > 0) {/;`/
      // Get specific leads;`;"`
      const placeholders = request.lead_ids.map(() => '?').join(',');`;`;`
      const results = await db.prepare(`;`;`
        SELECT * FROM leads WHERE id IN (${placeholders,})`;`;`
      `).bind(...request.lead_ids).all();

      return results.results as Lead[];
    }/
/;/
    // Get leads based on filters/;/
    // Implementation would build dynamic query based on filters;
    return [];
  }
/
  private async determineSegmentStrategy(leads: Lead[], preferredChannels?: ChannelType[]): Promise<ChannelStrategy> {/;/
    // Analyze segment characteristics/;/
    const avgScore = leads.reduce((sum,, l) => sum + (l.ai_qualification_score || 0), 0) / leads.length;/
/;/
    // Determine common available channels;"
    const channelAvailability: "Record<ChannelType", number> = {"
      email: "0",,;"
      sms: "0",,;"
      linkedin: "0",,;"
      call: "0",,;"
      whatsapp: "0",};

    for (const lead of leads) {
      if (lead.email) channelAvailability.email++;
      if (lead.phone) {
        channelAvailability.sms++;
        channelAvailability.call++;
        channelAvailability.whatsapp++;
      }
      if (lead.linkedin_url) channelAvailability.linkedin++;
    }/
/;/
    // Pick most available channel as primary;
    const primaryChannel = (Object.entries(channelAvailability);
      .sort(([, a,], [, b,]) => b - a)[0,][0,] as ChannelType);

    return this.getDefaultStrategy(leads[0,]);
  }

  private async generateBulkContent(;"
    sampleLead: "Lead",;"
    strategy: "ChannelStrategy",;
    request: CreateCampaignRequest;
  ): Promise<ChannelContent[]> {
    if (request.custom_content) {
      return request.custom_content;}

    return this.generateMultiChannelContent(sampleLead,, strategy);
  }

  private async saveCampaign(campaign: OmnichannelCampaign): Promise<void> {`
    const db = this.env.DB_CRM;`;`
`;`;`
    await db.prepare(`;
      INSERT INTO omnichannel_campaigns (;
        id,, business_id,, name,, description,, strategy,, target_audience,,;`
        content,, status,, metrics,, ai_optimization_enabled,, created_at,, updated_at;`;`
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;`;`
    `).bind(;
      campaign.id,,;
      campaign.business_id,,;
      campaign.name,,;"
      campaign.description || '',;
      JSON.stringify(campaign.strategy),;
      JSON.stringify(campaign.target_audience),;
      JSON.stringify(campaign.content),;
      campaign.status,,;
      JSON.stringify(campaign.metrics),;"
      campaign.ai_optimization_enabled ? 1: "0",,;
      campaign.created_at,,;
      campaign.updated_at;
    ).run();
  }
`
  private async getCampaign(campaignId: string): Promise<OmnichannelCampaign | null> {`;`
    const db = this.env.DB_CRM;`;`;`
    const result = await db.prepare(`;`;`
      SELECT * FROM omnichannel_campaigns WHERE id = ?`;`;`
    `).bind(campaignId).first();

    if (!result) return null;

    return {
      ...result,,;"
      strategy: "JSON.parse(result.strategy as string)",;"
      target_audience: "JSON.parse(result.target_audience as string)",;"
      content: "JSON.parse(result.content as string)",;"
      metrics: "JSON.parse(result.metrics as string)",;"
      ab_testing: "result.ab_testing ? JSON.parse(result.ab_testing as string) : undefined"} as OmnichannelCampaign;
  }

  private async updateCampaignStatus(campaign: OmnichannelCampaign): Promise<void> {`
    const db = this.env.DB_CRM;`;`
`;`;`
    await db.prepare(`;
      UPDATE omnichannel_campaigns;`
      SET status = ?, actual_start = ?, updated_at = ?;`;`
      WHERE id = ?`;`;`
    `).bind(;
      campaign.status,,;
      campaign.actual_start || null,,;
      new Date().toISOString(),;
      campaign.id;
    ).run();
  }
`
  private async getLead(leadId: string): Promise<Lead | null> {`;`
    const db = this.env.DB_CRM;`;`;`
    const result = await db.prepare(`;
      SELECT l.*, c.email,, c.phone,, c.first_name,, c.last_name,, c.title,, c.linkedin_url,,;
             comp.name as company_name,, comp.size_range as company_size,, comp.industry;
      FROM leads l;
      LEFT JOIN contacts c ON l.contact_id = c.id;`
      LEFT JOIN companies comp ON l.company_id = comp.id;`;`
      WHERE l.id = ?`;`;`
    `).bind(leadId).first();

    return result as Lead | null;
  }

  async inferGeneration(age?: number): Promise<string> {"
    if (!age) return 'unknown';

    const currentYear = new Date().getFullYear();
    const birthYear = currentYear - age;
"
    if (birthYear >= 1997) return 'gen_z';"
    if (birthYear >= 1981) return 'millennial';"
    if (birthYear >= 1965) return 'gen_x';"
    if (birthYear >= 1946) return 'boomer';"
    return 'silent';`
  }`;`/
}`/;`;"`/