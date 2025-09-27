import { EmailChannel } from './channels/email-channel';
import { SMSChannel } from './channels/sms-channel';
import { LinkedInChannel } from './channels/linkedin-channel';
import { VoiceChannel } from './channels/voice-channel';
import { WhatsAppChannel } from './channels/whatsapp-channel';
import type {
  Lead,
  Contact,
  ChannelType,
  ChannelStrategy,
  ChannelContent,
  OmnichannelCampaign,
  CampaignStatus,
  ChannelStep,
  ChannelMessage,
  CreateCampaignRequest,
  SendMessageRequest,
  ChannelHealthCheck,
  Company
} from '../types/crm';
import type { Env } from '../types/env';

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
        id: 'email_first',
        name: 'Email First Strategy',
        channels: ['email', 'sms', 'call'],
        sequence: [
          { channel: 'email', delay: 0, priority: 1 },
          { channel: 'sms', delay: 24, priority: 2 },
          { channel: 'call', delay: 72, priority: 3 }
        ],
        personalization: {
          tone: 'professional',
          frequency: 'moderate',
          timing: 'business_hours'
        }
      },
      {
        id: 'social_first',
        name: 'Social First Strategy',
        channels: ['linkedin', 'email', 'whatsapp'],
        sequence: [
          { channel: 'linkedin', delay: 0, priority: 1 },
          { channel: 'email', delay: 48, priority: 2 },
          { channel: 'whatsapp', delay: 120, priority: 3 }
        ],
        personalization: {
          tone: 'casual',
          frequency: 'high',
          timing: 'anytime'
        }
      }
    ];

    // Select strategy based on lead characteristics
    if (lead.company && lead.company.includes('tech')) {
      return strategies[1]; // Social first for tech companies
    }
    
    return strategies[0]; // Email first for others
  }

  private async generateMultiChannelContent(lead: Lead, strategy: ChannelStrategy): Promise<ChannelContent> {
    const content: ChannelContent = {
      email: {
        subject: `Hi ${lead.name}, let's discuss ${lead.company}'s growth`,
        body: `Hi ${lead.name},\n\nI noticed ${lead.company} is growing rapidly. I'd love to discuss how we can help accelerate that growth.\n\nBest regards,\nSales Team`,
        htmlBody: `<p>Hi ${lead.name},</p><p>I noticed ${lead.company} is growing rapidly. I'd love to discuss how we can help accelerate that growth.</p><p>Best regards,<br>Sales Team</p>`
      },
      sms: {
        body: `Hi ${lead.name}! Quick question about ${lead.company}'s growth plans. Got 2 minutes for a quick call?`
      },
      linkedin: {
        message: `Hi ${lead.name}, I see ${lead.company} is expanding. Would love to connect and discuss potential opportunities.`
      },
      call: {
        script: `Hi ${lead.name}, this is [Name] from [Company]. I'm reaching out because I noticed ${lead.company} is growing and I thought we might be able to help. Do you have a few minutes to chat?`
      },
      whatsapp: {
        message: `Hi ${lead.name}! 👋 I saw ${lead.company} is doing great things. Would love to chat about how we might help!`
      }
    };

    return content;
  }

  private async buildCampaign(
    strategy: ChannelStrategy, 
    content: ChannelContent, 
    leads: Lead[]
  ): Promise<OmnichannelCampaign> {
    const campaign: OmnichannelCampaign = {
      id: `campaign_${Date.now()}`,
      name: `Personalized Campaign for ${leads.length} leads`,
      strategy,
      content,
      leads: leads.map((lead: any) => ({ leadId: lead.id, status: 'pending' })),
      status: 'draft',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      scheduledAt: new Date().toISOString(),
      steps: this.buildCampaignSteps(strategy, content)
    };

    return campaign;
  }

  private buildCampaignSteps(strategy: ChannelStrategy, content: ChannelContent): ChannelStep[] {
    const steps: ChannelStep[] = [];

    for (const sequenceItem of strategy.sequence) {
      const channelContent = content[sequenceItem.channel as keyof ChannelContent];
      if (channelContent) {
        steps.push({
          id: `step_${sequenceItem.channel}_${sequenceItem.priority}`,
          channel: sequenceItem.channel as ChannelType,
          delay: sequenceItem.delay,
          priority: sequenceItem.priority,
          content: channelContent,
          status: 'pending',
          scheduledAt: new Date(Date.now() + sequenceItem.delay * 60 * 60 * 1000).toISOString()
        });
      }
    }

    return steps;
  }

  private async scheduleCampaign(campaign: OmnichannelCampaign): Promise<void> {
    // Mock campaign scheduling - would integrate with job queue in production
    console.log(`Scheduling campaign ${campaign.id} with ${campaign.steps.length} steps`);
    
    for (const step of campaign.steps) {
      // Schedule each step
      setTimeout(() => {
        this.executeStep(step, campaign.leads);
      }, step.delay * 60 * 60 * 1000);
    }
  }

  private async executeStep(step: ChannelStep, leads: Array<{ leadId: string; status: string }>): Promise<void> {
    try {
      const channel = this.channels[step.channel];
      if (!channel) {
        console.error(`Channel ${step.channel} not available`);
        return;
      }

      // Execute step for all leads
      for (const leadRef of leads) {
        if (leadRef.status === 'pending') {
          await this.sendMessage(step.channel, leadRef.leadId, step.content);
          leadRef.status = 'sent';
        }
      }

      step.status = 'completed';
    } catch (error: any) {
      console.error(`Failed to execute step ${step.id}:`, error);
      step.status = 'failed';
    }
  }

  async sendMessage(channel: ChannelType, leadId: string, content: any): Promise<boolean> {
    try {
      const channelService = this.channels[channel];
      if (!channelService) {
        throw new Error(`Channel ${channel} not available`);
      }

      // Mock message sending - would use real channel services in production
      console.log(`Sending ${channel} message to lead ${leadId}:`, content);
      
      // Simulate sending delay
      await new Promise(resolve => setTimeout(resolve, 100));
      
      return true;
    } catch (error: any) {
      console.error(`Failed to send ${channel} message to lead ${leadId}:`, error);
      return false;
    }
  }

  async createCampaign(request: CreateCampaignRequest): Promise<OmnichannelCampaign> {
    const campaign: OmnichannelCampaign = {
      id: `campaign_${Date.now()}`,
      name: request.name,
      strategy: request.strategy,
      content: request.content,
      leads: request.leadIds.map((leadId: any) => ({ leadId, status: 'pending' })),
      status: 'draft',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      scheduledAt: request.scheduledAt || new Date().toISOString(),
      steps: this.buildCampaignSteps(request.strategy, request.content)
    };

    return campaign;
  }

  async updateCampaign(campaignId: string, updates: Partial<OmnichannelCampaign>): Promise<OmnichannelCampaign> {
    // Mock campaign update - would update in database in production
    const campaign: OmnichannelCampaign = {
      id: campaignId,
      name: updates.name || 'Updated Campaign',
      strategy: updates.strategy || { id: 'default', name: 'Default Strategy', channels: [], sequence: [], personalization: { tone: 'professional', frequency: 'moderate', timing: 'business_hours' } },
      content: updates.content || {},
      leads: updates.leads || [],
      status: updates.status || 'draft',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      scheduledAt: updates.scheduledAt || new Date().toISOString(),
      steps: updates.steps || []
    };

    return campaign;
  }

  async getCampaign(campaignId: string): Promise<OmnichannelCampaign | null> {
    // Mock campaign retrieval - would fetch from database in production
    return null;
  }

  async getCampaigns(status?: CampaignStatus): Promise<OmnichannelCampaign[]> {
    // Mock campaigns retrieval - would fetch from database in production
    return [];
  }

  async startCampaign(campaignId: string): Promise<boolean> {
    try {
      // Mock campaign start - would update status and schedule in production
      console.log(`Starting campaign ${campaignId}`);
      return true;
    } catch (error: any) {
      console.error(`Failed to start campaign ${campaignId}:`, error);
      return false;
    }
  }

  async pauseCampaign(campaignId: string): Promise<boolean> {
    try {
      // Mock campaign pause - would update status in production
      console.log(`Pausing campaign ${campaignId}`);
      return true;
    } catch (error: any) {
      console.error(`Failed to pause campaign ${campaignId}:`, error);
      return false;
    }
  }

  async stopCampaign(campaignId: string): Promise<boolean> {
    try {
      // Mock campaign stop - would update status and cancel scheduled tasks in production
      console.log(`Stopping campaign ${campaignId}`);
      return true;
    } catch (error: any) {
      console.error(`Failed to stop campaign ${campaignId}:`, error);
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
      try {
        // Mock health check - would test actual channel connectivity in production
        const isHealthy = Math.random() > 0.1; // 90% chance of being healthy
        
        healthChecks.push({
          channel: channelType as ChannelType,
          status: isHealthy ? 'healthy' : 'unhealthy',
          lastChecked: new Date().toISOString(),
          responseTime: Math.floor(Math.random() * 1000),
          error: isHealthy ? null : 'Connection timeout'
        });
      } catch (error: any) {
        healthChecks.push({
          channel: channelType as ChannelType,
          status: 'unhealthy',
          lastChecked: new Date().toISOString(),
          responseTime: -1,
          error: error instanceof Error ? error.message : 'Unknown error'
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
    
    // Adjust timing based on performance
    for (const step of optimizedCampaign.steps) {
      if (step.channel === 'email' && step.delay < 24) {
        step.delay = 24; // Move email to next day if sent too early
      }
    }

    optimizedCampaign.updatedAt = new Date().toISOString();
    return optimizedCampaign;
  }

  async getPersonalizationSuggestions(lead: Lead): Promise<string[]> {
    // Mock personalization suggestions - would use AI in production
    const suggestions = [
      `Mention ${lead.company}'s recent growth`,
      `Reference ${lead.industry || 'their industry'} trends`,
      `Highlight relevant case studies`,
      `Use ${lead.preferredLanguage || 'English'} language`,
      `Adjust tone for ${lead.companySize || 'medium'} company`
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
      console.log(`Testing ${channel} channel with data:`, testData);
      
      // Simulate test delay
      await new Promise(resolve => setTimeout(resolve, 500));
      
      return true;
    } catch (error: any) {
      console.error(`Channel test failed for ${channel}:`, error);
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
    if (!campaign.strategy || !campaign.strategy.channels.length) {
      errors.push('Campaign must have at least one channel');
    }

    // Validate content
    for (const channel of campaign.strategy.channels) {
      if (!campaign.content[channel as keyof ChannelContent]) {
        errors.push(`Content missing for channel: ${channel}`);
      }
    }

    // Validate leads
    if (!campaign.leads || campaign.leads.length === 0) {
      errors.push('Campaign must have at least one lead');
    }

    // Validate steps
    if (!campaign.steps || campaign.steps.length === 0) {
      errors.push('Campaign must have at least one step');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  async cleanup(): Promise<void> {
    try {
      // Mock cleanup - would close connections and clean up resources in production
      console.log('Omnichannel Orchestrator cleanup completed');
    } catch (error: any) {
      console.error('Omnichannel Orchestrator cleanup failed:', error);
    }
  }
}

