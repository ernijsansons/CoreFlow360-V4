import { EmailChannel } from './channels/email-channel';
import { SMSChannel } from './channels/sms-channel';
import { LinkedInChannel } from './channels/linkedin-channel';
import { VoiceChannel } from './channels/voice-channel';
import { WhatsAppChannel } from './channels/whatsapp-channel';
import type { Lead,
  ChannelType,
  ChannelStrategy,
  ChannelContent,
  OmnichannelCampaign,
  CampaignStatus,
  CreateCampaignRequest,
  ChannelHealthCheck } from '../types/crm';
import type { Env } from '../types/env';import { Logger } from "../shared/logger";
const logger = new Logger({ component: "services-omnichannel-orchestrator" });



export class OmnichannelOrchestrator {
  private env: Env;
  private channels: Record<ChannelType, any>;

  constructor(env: Env) {
    this.env = env;
    this.channels = {
      email: new EmailChannel(env),
      sms: new SMSChannel(env),
      linkedin: new LinkedInChannel(env),
      call: new VoiceChannel(env),
      whatsapp: new WhatsAppChannel(env)
    };
  }

  async createPersonalizedCampaign(lead: Lead): Promise<OmnichannelCampaign> {
    // Determine optimal strategy using AI
    const strategy = await this.determineStrategy(lead);

    // Generate multi-channel content
    const content = await this.generateMultiChannelContent(lead, strategy);

    // Build and save campaign
    const campaign = await this.buildCampaign(strategy, content, [lead]);

    // Schedule campaign execution
    await this.scheduleCampaign(campaign);

    return campaign;
  }

  private async determineStrategy(lead: Lead): Promise<ChannelStrategy> {
    // Mock AI strategy determination - would use real AI in production
    const strategies: ChannelStrategy[] = [
      {
        primary_channel: 'email',
        sequence: [
          {
            channel: 'email',
            delay_hours: 0,
            personalization_level: 'high'
          },
          {
            channel: 'sms',
            delay_hours: 24,
            personalization_level: 'medium'
          },
          {
            channel: 'call',
            delay_hours: 72,
            personalization_level: 'high'
          }
        ],
        fallback_channels: ['sms', 'call'],
        timing: {
          timezone: 'America/New_York',
          avoid_weekends: true,
          optimal_send_times: {
            email: ['09:00', '14:00'],
            sms: ['10:00', '15:00'],
            call: ['10:00', '14:00'],
            linkedin: ['09:00', '17:00'],
            whatsapp: ['10:00', '16:00']
          }
        },
        ai_reasoning: 'Professional email-first approach for business leads',
        predicted_response_rate: 0.25,
        urgency_level: 'medium'
      },
      {
        primary_channel: 'linkedin',
        sequence: [
          {
            channel: 'linkedin',
            delay_hours: 0,
            personalization_level: 'hyper_personalized'
          },
          {
            channel: 'email',
            delay_hours: 48,
            personalization_level: 'high'
          },
          {
            channel: 'whatsapp',
            delay_hours: 120,
            personalization_level: 'medium'
          }
        ],
        fallback_channels: ['email', 'whatsapp'],
        timing: {
          timezone: 'America/New_York',
          avoid_weekends: false,
          optimal_send_times: {
            email: ['09:00', '14:00'],
            sms: ['10:00', '15:00'],
            call: ['10:00', '14:00'],
            linkedin: ['09:00', '17:00'],
            whatsapp: ['10:00', '16:00']
          }
        },
        ai_reasoning: 'Social-first approach for tech companies',
        predicted_response_rate: 0.35,
        urgency_level: 'medium'
      }
    ];

    // Select strategy based on lead characteristics
    const companyName = lead.company_name || '';
    if (companyName.toLowerCase().includes('tech')) {
      return strategies[1]; // Social first for tech companies
    }

    return strategies[0]; // Email first for others
  }

  private async generateMultiChannelContent(lead: Lead, strategy: ChannelStrategy): Promise<ChannelContent[]> {
    const leadName = lead.first_name || 'there';
    const companyName = lead.company_name || 'your company';

    const contentMap: Record<string, ChannelContent> = {
      email: {
        channel: 'email',
        subject: `Hi ${leadName}, let's discuss ${companyName}'s growth`,
        body: `Hi ${leadName},\n\nI noticed ${companyName} is growing rapidly. I'd love to discuss how we can help accelerate that growth.\n\nBest regards,\nSales Team`,
        ai_generated: true,
        tone: 'formal'
      },
      sms: {
        channel: 'sms',
        body: `Hi ${leadName}! Quick question about ${companyName}'s growth plans. Got 2 minutes for a quick call?`,
        ai_generated: true,
        tone: 'friendly'
      },
      linkedin: {
        channel: 'linkedin',
        body: `Hi ${leadName}, I see ${companyName} is expanding. Would love to connect and discuss potential opportunities.`,
        ai_generated: true,
        tone: 'formal'
      },
      call: {
        channel: 'call',
        body: `Hi ${leadName}, this is [Name] from [Company]. I'm reaching out because I noticed ${companyName} is growing and I thought we might be able to help. Do you have a few minutes to chat?`,
        ai_generated: true,
        tone: 'friendly'
      },
      whatsapp: {
        channel: 'whatsapp',
        body: `Hi ${leadName}! 👋 I saw ${companyName} is doing great things. Would love to chat about how we might help!`,
        ai_generated: true,
        tone: 'casual'
      }
    };

    // Return content for channels in strategy
    return strategy.sequence.map(step => contentMap[step.channel]).filter(Boolean);
  }

  private async buildCampaign(
    strategy: ChannelStrategy,
    content: ChannelContent[],
    leads: Lead[]
  ): Promise<OmnichannelCampaign> {
    const campaign: OmnichannelCampaign = {
      id: `campaign_${Date.now()}`,
      business_id: leads[0]?.business_id || 'default',
      name: `Personalized Campaign for ${leads.length} leads`,
      strategy,
      target_audience: {
        lead_ids: leads.map(l => l.id),
        total_recipients: leads.length
      },
      content,
      status: 'draft',
      scheduled_start: new Date().toISOString(),
      metrics: {
        total_sent: 0,
        total_delivered: 0,
        total_opened: 0,
        total_clicked: 0,
        total_replied: 0,
        total_converted: 0,
        by_channel: {
          email: { sent: 0, delivered: 0, replied: 0, bounced: 0 },
          sms: { sent: 0, delivered: 0, replied: 0, bounced: 0 },
          linkedin: { sent: 0, delivered: 0, replied: 0, bounced: 0 },
          call: { sent: 0, delivered: 0, replied: 0, bounced: 0 },
          whatsapp: { sent: 0, delivered: 0, replied: 0, bounced: 0 }
        },
        engagement_score: 0
      },
      ai_optimization_enabled: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    return campaign;
  }

  private async scheduleCampaign(campaign: OmnichannelCampaign): Promise<void> {
    // Mock campaign scheduling - would integrate with job queue in production
    logger.info(`Scheduling campaign ${campaign.id} with ${campaign.content.length} content items`);

    for (const contentItem of campaign.content) {
      // Schedule each content item
      setTimeout(() => {
        this.executeContentDelivery(contentItem, campaign.target_audience.lead_ids || []);
      }, 1000); // Immediate for demo
    }
  }

  private async executeContentDelivery(content: ChannelContent, leadIds: string[]): Promise<void> {
    try {
      const channel = this.channels[content.channel];
      if (!channel) {
        logger.error(`Channel ${content.channel} not available`);
        return;
      }

      // Execute delivery for all leads
      for (const leadId of leadIds) {
        await this.sendMessage(content.channel, leadId, content);
      }
    } catch (error: unknown) {
      logger.error(`Failed to execute content delivery for channel ${content.channel}:`, error);
    }
  }

  async sendMessage(channel: ChannelType, leadId: string, content: any): Promise<boolean> {
    try {
      const channelService = this.channels[channel];
      if (!channelService) {
        throw new Error(`Channel ${channel} not available`);
      }

      // Mock message sending - would use real channel services in production
      logger.info(`Sending ${channel} message to lead ${leadId}:`, content);
      
      // Simulate sending delay
      await new Promise(resolve => setTimeout(resolve, 100));
      
      return true;
    } catch (error: unknown) {
      logger.error(`Failed to send ${channel} message to lead ${leadId}:`, error);
      return false;
    }
  }

  async createCampaign(request: CreateCampaignRequest): Promise<OmnichannelCampaign> {
    // Build default strategy if not provided
    const defaultStrategy: ChannelStrategy = {
      primary_channel: 'email',
      sequence: request.channels?.map((ch, idx) => ({
        channel: ch,
        delay_hours: idx * 24,
        personalization_level: 'medium' as const
      })) || [],
      fallback_channels: [],
      timing: {
        timezone: 'America/New_York',
        avoid_weekends: true,
        optimal_send_times: {
          email: ['09:00'],
          sms: ['10:00'],
          linkedin: ['09:00'],
          call: ['10:00'],
          whatsapp: ['10:00']
        }
      },
      ai_reasoning: 'User-created campaign',
      predicted_response_rate: 0.2,
      urgency_level: 'medium'
    };

    const campaign: OmnichannelCampaign = {
      id: `campaign_${Date.now()}`,
      business_id: 'default',
      name: request.name,
      strategy: defaultStrategy,
      target_audience: {
        lead_ids: request.lead_ids,
        segment_id: request.segment_id,
        filters: request.filters,
        total_recipients: request.lead_ids?.length || 0
      },
      content: request.custom_content || [],
      status: 'draft',
      scheduled_start: request.scheduled_start || new Date().toISOString(),
      metrics: {
        total_sent: 0,
        total_delivered: 0,
        total_opened: 0,
        total_clicked: 0,
        total_replied: 0,
        total_converted: 0,
        by_channel: {
          email: { sent: 0, delivered: 0, replied: 0, bounced: 0 },
          sms: { sent: 0, delivered: 0, replied: 0, bounced: 0 },
          linkedin: { sent: 0, delivered: 0, replied: 0, bounced: 0 },
          call: { sent: 0, delivered: 0, replied: 0, bounced: 0 },
          whatsapp: { sent: 0, delivered: 0, replied: 0, bounced: 0 }
        },
        engagement_score: 0
      },
      ai_optimization_enabled: request.ai_optimization || false,
      ab_testing: request.ab_testing,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    return campaign;
  }

  async updateCampaign(campaignId: string, updates: Partial<OmnichannelCampaign>): Promise<OmnichannelCampaign> {
    // Mock campaign update - would update in database in production
    const defaultStrategy: ChannelStrategy = {
      primary_channel: 'email',
      sequence: [],
      fallback_channels: [],
      timing: {
        timezone: 'America/New_York',
        avoid_weekends: true,
        optimal_send_times: {
          email: ['09:00'],
          sms: ['10:00'],
          linkedin: ['09:00'],
          call: ['10:00'],
          whatsapp: ['10:00']
        }
      },
      ai_reasoning: 'Default strategy',
      predicted_response_rate: 0.2,
      urgency_level: 'medium'
    };

    const campaign: OmnichannelCampaign = {
      id: campaignId,
      business_id: updates.business_id || 'default',
      name: updates.name || 'Updated Campaign',
      strategy: updates.strategy || defaultStrategy,
      target_audience: updates.target_audience || { total_recipients: 0 },
      content: updates.content || [],
      status: updates.status || 'draft',
      scheduled_start: updates.scheduled_start,
      metrics: updates.metrics || {
        total_sent: 0,
        total_delivered: 0,
        total_opened: 0,
        total_clicked: 0,
        total_replied: 0,
        total_converted: 0,
        by_channel: {
          email: { sent: 0, delivered: 0, replied: 0, bounced: 0 },
          sms: { sent: 0, delivered: 0, replied: 0, bounced: 0 },
          linkedin: { sent: 0, delivered: 0, replied: 0, bounced: 0 },
          call: { sent: 0, delivered: 0, replied: 0, bounced: 0 },
          whatsapp: { sent: 0, delivered: 0, replied: 0, bounced: 0 }
        },
        engagement_score: 0
      },
      ai_optimization_enabled: updates.ai_optimization_enabled || false,
      created_at: updates.created_at || new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    return campaign;
  }

  async getCampaign(_campaignId: string): Promise<OmnichannelCampaign | null> {
    // Mock campaign retrieval - would fetch from database in production
    return null;
  }

  async getCampaigns(_status?: CampaignStatus): Promise<OmnichannelCampaign[]> {
    // Mock campaigns retrieval - would fetch from database in production
    return [];
  }

  async startCampaign(campaignId: string): Promise<boolean> {
    try {
      // Mock campaign start - would update status and schedule in production
      logger.info(`Starting campaign ${campaignId}`);
      return true;
    } catch (error: unknown) {
      logger.error(`Failed to start campaign ${campaignId}:`, error);
      return false;
    }
  }

  async pauseCampaign(campaignId: string): Promise<boolean> {
    try {
      // Mock campaign pause - would update status in production
      logger.info(`Pausing campaign ${campaignId}`);
      return true;
    } catch (error: unknown) {
      logger.error(`Failed to pause campaign ${campaignId}:`, error);
      return false;
    }
  }

  async stopCampaign(campaignId: string): Promise<boolean> {
    try {
      // Mock campaign stop - would update status and cancel scheduled tasks in production
      logger.info(`Stopping campaign ${campaignId}`);
      return true;
    } catch (error: unknown) {
      logger.error(`Failed to stop campaign ${campaignId}:`, error);
      return false;
    }
  }

  async getCampaignMetrics(campaignId: string): Promise<any> {
    // Mock campaign metrics - would calculate from actual data in production
    return {
      campaignId,
      totalLeads: 100,
      messagesSent: 85,
      messagesDelivered: 80,
      messagesOpened: 60,
      messagesClicked: 15,
      responses: 8,
      conversions: 3,
      deliveryRate: 0.94,
      openRate: 0.75,
      clickRate: 0.25,
      responseRate: 0.13,
      conversionRate: 0.05
    };
  }

  async getChannelHealth(): Promise<ChannelHealthCheck[]> {
    const healthChecks: ChannelHealthCheck[] = [];

    for (const [channelType, channelService] of Object.entries(this.channels)) {
    void channelService;
      try {
        // Mock health check - would test actual channel connectivity in production
        const isHealthy = Math.random() > 0.1; // 90% chance of being healthy


        healthChecks.push({
          channel: channelType as ChannelType,
          status: isHealthy ? 'healthy' : 'down',
          last_checked: new Date().toISOString(),
          metrics: {
            success_rate: isHealthy ? 0.95 : 0,
            avg_latency_ms: Math.floor(Math.random() * 1000),
            daily_quota_used: 100,
            daily_quota_limit: 1000
          },
          issues: isHealthy ? undefined : ['Connection timeout']
        });
      } catch (error: unknown) {
        healthChecks.push({
          channel: channelType as ChannelType,
          status: 'down',
          last_checked: new Date().toISOString(),
          metrics: {
            success_rate: 0,
            avg_latency_ms: -1,
            daily_quota_used: 0,
            daily_quota_limit: 0
          },
          issues: [error instanceof Error ? error.message : 'Unknown error']
        });
      }
    }

    return healthChecks;
  }

  async optimizeCampaign(campaignId: string): Promise<OmnichannelCampaign> {
    // Mock campaign optimization - would use AI to optimize in production
    const campaign = await this.getCampaign(campaignId);
    if (!campaign) {
      throw new Error('Campaign not found');
    }

    // Optimize based on performance data
    const optimizedCampaign = { ...campaign };

    // Adjust timing based on performance (modify strategy sequence)
    optimizedCampaign.strategy.sequence = optimizedCampaign.strategy.sequence.map(step => {
      if (step.channel === 'email' && step.delay_hours < 24) {
        return { ...step, delay_hours: 24 }; // Move email to next day if sent too early
      }
      return step;
    });

    optimizedCampaign.updated_at = new Date().toISOString();
    return optimizedCampaign;
  }

  async getPersonalizationSuggestions(lead: Lead): Promise<string[]> {
    // Mock personalization suggestions - would use AI in production
    const companyName = lead.company_name || 'their company';
    const industry = lead.industry || 'their industry';

    const suggestions = [
      `Mention ${companyName}'s recent growth`,
      `Reference ${industry} trends`,
      `Highlight relevant case studies`,
      `Adjust tone for ${companyName}`
    ];

    return suggestions;
  }

  async testChannel(channel: ChannelType, testData: any): Promise<boolean> {
    try {
      const channelService = this.channels[channel];
      if (!channelService) {
        throw new Error(`Channel ${channel} not available`);
      }

      // Mock channel test - would send actual test message in production
      logger.info(`Testing ${channel} channel with data:`, testData);

      // Simulate test delay
      await new Promise(resolve => setTimeout(resolve, 500));

      return true;
    } catch (error: unknown) {
      logger.error(`Channel test failed for ${channel}:`, error);
      return false;
    }
  }

  async getChannelCapabilities(): Promise<Record<ChannelType, string[]>> {
    return {
      email: ['text', 'html', 'attachments', 'tracking'],
      sms: ['text', 'media', 'tracking'],
      linkedin: ['text', 'media', 'connection_request'],
      call: ['voice', 'recording', 'transcription'],
      whatsapp: ['text', 'media', 'templates', 'tracking']
    };
  }

  async validateCampaign(campaign: OmnichannelCampaign): Promise<{ valid: boolean; errors: string[] }> {
    const errors: string[] = [];

    // Validate strategy
    if (!campaign.strategy || !campaign.strategy.sequence.length) {
      errors.push('Campaign must have at least one channel in sequence');
    }

    // Validate content
    if (!campaign.content || campaign.content.length === 0) {
      errors.push('Campaign must have content');
    }

    // Validate target audience
    if (!campaign.target_audience || campaign.target_audience.total_recipients === 0) {
      errors.push('Campaign must have at least one recipient');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  async cleanup(): Promise<void> {
    try {
      // Mock cleanup - would close connections and clean up resources in production
      logger.info('Omnichannel Orchestrator cleanup completed');
    } catch (error: unknown) {
      logger.error('Omnichannel Orchestrator cleanup failed:', error);
    }
  }
}

