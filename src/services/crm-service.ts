import { CRMDatabase } from '../database/crm-database';
import type { Env } from '../types/env';
import type {
  Company,
  Contact,
  Lead,
  AITask,
  Conversation,
  LeadActivity,
  LeadFilters,
  ContactFilters,
  ConversationFilters,
  PaginationOptions,
  PaginatedResponse,
  CRMResponse,
  LeadMetrics,
  ContactMetrics,
  AITaskMetrics,
  CRMEvent,
  CreateCompany,
  CreateContact,
  CreateLead,
  CreateAITask,
  ResearchCompanyPayload,
  QualifyLeadPayload,
  SendFollowupPayload,
  AnalyzeConversationPayload,
  QualificationResult,
  ConversationContext,
  QualifyLeadTaskPayload,
  QualificationStatus,
  Meeting,
  MeetingBookingRequest,
  CalendarSlot,
  MeetingType,
  MeetingTemplate,
  Voicemail,
  VoicemailTemplate,
  VoicemailCampaign,
  VoicemailRequest,
  VoicemailCampaignRequest,
  VoicemailStats
} from '../types/crm';

export class CRMService {
  private db: CRMDatabase;
  private env: Env;
  private cache: Map<string, { data: any; timestamp: number }> = new Map();
  private readonly CACHE_TTL = 5 * 60 * 1000; // 5 minutes
  private readonly BATCH_SIZE = 100;

  constructor(env: Env) {
    this.env = env;
    this.db = new CRMDatabase(env);
  }

  private getCacheKey(method: string, params: any): string {
    return `${method}:${JSON.stringify(params)}`;
  }

  private getFromCache<T>(key: string): T | null {
    const cached = this.cache.get(key);
    if (cached && Date.now() - cached.timestamp < this.CACHE_TTL) {
      return cached.data as T;
    }
    this.cache.delete(key);
    return null;
  }

  private setCache(key: string, data: any): void {
    this.cache.set(key, { data, timestamp: Date.now() });
    
    // Clean up old cache entries
    if (this.cache.size > 1000) {
      const now = Date.now();
      for (const [k, v] of this.cache.entries()) {
        if (now - v.timestamp > this.CACHE_TTL) {
          this.cache.delete(k);
        }
      }
    }
  }

  // Company Management
  async createCompany(data: CreateCompany): Promise<CRMResponse<Company>> {
    try {
      const company = await this.db.companies.create(data);
      return { success: true, data: company };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async getCompany(id: string): Promise<CRMResponse<Company>> {
    try {
      const cacheKey = this.getCacheKey('getCompany', { id });
      const cached = this.getFromCache<Company>(cacheKey);
      
      if (cached) {
        return { success: true, data: cached };
      }
      
      const company = await this.db.companies.getById(id);
      if (!company) {
        return { success: false, error: 'Company not found' };
      }
      
      this.setCache(cacheKey, company);
      return { success: true, data: company };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async updateCompany(id: string, data: Partial<Company>): Promise<CRMResponse<Company>> {
    try {
      const company = await this.db.companies.update(id, data);
      return { success: true, data: company };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async deleteCompany(id: string): Promise<CRMResponse<boolean>> {
    try {
      await this.db.companies.delete(id);
      return { success: true, data: true };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  // Contact Management
  async createContact(data: CreateContact): Promise<CRMResponse<Contact>> {
    try {
      const contact = await this.db.contacts.create(data);
      return { success: true, data: contact };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async getContact(id: string): Promise<CRMResponse<Contact>> {
    try {
      const contact = await this.db.contacts.getById(id);
      if (!contact) {
        return { success: false, error: 'Contact not found' };
      }
      return { success: true, data: contact };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async updateContact(id: string, data: Partial<Contact>): Promise<CRMResponse<Contact>> {
    try {
      const contact = await this.db.contacts.update(id, data);
      return { success: true, data: contact };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async deleteContact(id: string): Promise<CRMResponse<boolean>> {
    try {
      await this.db.contacts.delete(id);
      return { success: true, data: true };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async searchContacts(filters: ContactFilters, pagination?: PaginationOptions): Promise<PaginatedResponse<Contact>> {
    try {
      const cacheKey = this.getCacheKey('searchContacts', { filters, pagination });
      const cached = this.getFromCache<PaginatedResponse<Contact>>(cacheKey);
      
      if (cached) {
        return cached;
      }
      
      // Optimize pagination with reasonable limits
      const optimizedPagination = {
        page: pagination?.page || 1,
        limit: Math.min(pagination?.limit || 20, this.BATCH_SIZE)
      };
      
      const result = await this.db.contacts.search(filters, optimizedPagination);
      
      // Cache successful results for 2 minutes
      if (result.data.length > 0) {
        this.setCache(cacheKey, result);
      }
      
      return result;
    } catch (error) {
      return {
        data: [],
        pagination: { page: 1, limit: 10, total: 0, totalPages: 0 },
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  // Lead Management
  async createLead(data: CreateLead): Promise<CRMResponse<Lead>> {
    try {
      const lead = await this.db.leads.create(data);
      return { success: true, data: lead };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async getLead(id: string): Promise<CRMResponse<Lead>> {
    try {
      const lead = await this.db.leads.getById(id);
      if (!lead) {
        return { success: false, error: 'Lead not found' };
      }
      return { success: true, data: lead };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async updateLead(id: string, data: Partial<Lead>): Promise<CRMResponse<Lead>> {
    try {
      const lead = await this.db.leads.update(id, data);
      return { success: true, data: lead };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async deleteLead(id: string): Promise<CRMResponse<boolean>> {
    try {
      await this.db.leads.delete(id);
      return { success: true, data: true };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async searchLeads(filters: LeadFilters, pagination?: PaginationOptions): Promise<PaginatedResponse<Lead>> {
    try {
      const result = await this.db.leads.search(filters, pagination);
      return result;
    } catch (error) {
      return {
        data: [],
        pagination: { page: 1, limit: 10, total: 0, totalPages: 0 },
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  // AI Task Management
  async createAITask(data: CreateAITask): Promise<CRMResponse<AITask>> {
    try {
      const task = await this.db.aiTasks.create(data);
      return { success: true, data: task };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async getAITask(id: string): Promise<CRMResponse<AITask>> {
    try {
      const task = await this.db.aiTasks.getById(id);
      if (!task) {
        return { success: false, error: 'AI Task not found' };
      }
      return { success: true, data: task };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async updateAITask(id: string, data: Partial<AITask>): Promise<CRMResponse<AITask>> {
    try {
      const task = await this.db.aiTasks.update(id, data);
      return { success: true, data: task };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async deleteAITask(id: string): Promise<CRMResponse<boolean>> {
    try {
      await this.db.aiTasks.delete(id);
      return { success: true, data: true };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  // Conversation Management
  async createConversation(data: Partial<Conversation>): Promise<CRMResponse<Conversation>> {
    try {
      const conversation = await this.db.conversations.create(data);
      return { success: true, data: conversation };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async getConversation(id: string): Promise<CRMResponse<Conversation>> {
    try {
      const conversation = await this.db.conversations.getById(id);
      if (!conversation) {
        return { success: false, error: 'Conversation not found' };
      }
      return { success: true, data: conversation };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async updateConversation(id: string, data: Partial<Conversation>): Promise<CRMResponse<Conversation>> {
    try {
      const conversation = await this.db.conversations.update(id, data);
      return { success: true, data: conversation };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async searchConversations(filters: ConversationFilters, pagination?: PaginationOptions): Promise<PaginatedResponse<Conversation>> {
    try {
      const result = await this.db.conversations.search(filters, pagination);
      return result;
    } catch (error) {
      return {
        data: [],
        pagination: { page: 1, limit: 10, total: 0, totalPages: 0 },
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  // Lead Activity Management
  async addLeadActivity(leadId: string, activity: Omit<LeadActivity, 'id' | 'timestamp'>): Promise<CRMResponse<LeadActivity>> {
    try {
      const newActivity: LeadActivity = {
        ...activity,
        id: `activity_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date().toISOString()
      };

      await this.db.leadActivities.create(leadId, newActivity);
      return { success: true, data: newActivity };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async getLeadActivities(leadId: string, pagination?: PaginationOptions): Promise<PaginatedResponse<LeadActivity>> {
    try {
      const result = await this.db.leadActivities.getByLeadId(leadId, pagination);
      return result;
    } catch (error) {
      return {
        data: [],
        pagination: { page: 1, limit: 10, total: 0, totalPages: 0 },
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  // AI Operations
  async researchCompany(payload: ResearchCompanyPayload): Promise<CRMResponse<Company>> {
    try {
      // Mock company research - would use AI in production
      const company: Company = {
        id: `company_${Date.now()}`,
        name: payload.companyName,
        domain: payload.domain || '',
        industry: 'Technology',
        size: 'Medium',
        location: 'United States',
        description: `Research data for ${payload.companyName}`,
        website: payload.domain ? `https://${payload.domain}` : '',
        linkedinUrl: '',
        twitterUrl: '',
        foundedYear: 2020,
        employeeCount: 100,
        revenue: 1000000,
        technologies: ['React', 'Node.js', 'TypeScript'],
        tags: ['tech', 'startup'],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };

      await this.db.companies.create(company);
      return { success: true, data: company };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async qualifyLead(payload: QualifyLeadPayload): Promise<CRMResponse<QualificationResult>> {
    try {
      // Mock lead qualification - would use AI in production
      const result: QualificationResult = {
        leadId: payload.leadId,
        score: Math.floor(Math.random() * 100),
        status: 'qualified' as QualificationStatus,
        reasons: ['High engagement', 'Budget confirmed', 'Decision maker identified'],
        nextSteps: ['Schedule demo', 'Send proposal'],
        confidence: 0.85,
        timestamp: new Date().toISOString()
      };

      return { success: true, data: result };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async sendFollowup(payload: SendFollowupPayload): Promise<CRMResponse<boolean>> {
    try {
      // Mock followup sending - would integrate with email/SMS in production
      console.log(`Sending followup to lead ${payload.leadId}: ${payload.message}`);
      return { success: true, data: true };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async analyzeConversation(payload: AnalyzeConversationPayload): Promise<CRMResponse<ConversationContext>> {
    try {
      // Mock conversation analysis - would use AI in production
      const context: ConversationContext = {
        sentiment: 'positive',
        intent: 'schedule_meeting',
        keyTopics: ['pricing', 'features', 'timeline'],
        nextActions: ['Send proposal', 'Schedule demo'],
        confidence: 0.8,
        timestamp: new Date().toISOString()
      };

      return { success: true, data: context };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  // Meeting Management
  async bookMeeting(request: MeetingBookingRequest): Promise<CRMResponse<Meeting>> {
    try {
      const meeting: Meeting = {
        id: `meeting_${Date.now()}`,
        leadId: request.leadId,
        title: request.title,
        description: request.description,
        startTime: request.startTime,
        endTime: request.endTime,
        duration: request.duration,
        type: request.type,
        status: 'scheduled',
        location: request.location,
        meetingUrl: request.meetingUrl,
        attendees: request.attendees,
        notes: request.notes,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };

      await this.db.meetings.create(meeting);
      return { success: true, data: meeting };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async getMeeting(id: string): Promise<CRMResponse<Meeting>> {
    try {
      const meeting = await this.db.meetings.getById(id);
      if (!meeting) {
        return { success: false, error: 'Meeting not found' };
      }
      return { success: true, data: meeting };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async updateMeeting(id: string, data: Partial<Meeting>): Promise<CRMResponse<Meeting>> {
    try {
      const meeting = await this.db.meetings.update(id, data);
      return { success: true, data: meeting };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async cancelMeeting(id: string): Promise<CRMResponse<boolean>> {
    try {
      await this.db.meetings.update(id, { status: 'cancelled' });
      return { success: true, data: true };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async getAvailableSlots(leadId: string, date: string, duration: number): Promise<CRMResponse<CalendarSlot[]>> {
    try {
      // Mock available slots - would integrate with calendar in production
      const slots: CalendarSlot[] = [
        {
          startTime: new Date(`${date}T09:00:00Z`).toISOString(),
          endTime: new Date(`${date}T10:00:00Z`).toISOString(),
          available: true
        },
        {
          startTime: new Date(`${date}T14:00:00Z`).toISOString(),
          endTime: new Date(`${date}T15:00:00Z`).toISOString(),
          available: true
        }
      ];

      return { success: true, data: slots };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  // Voicemail Management
  async createVoicemail(request: VoicemailRequest): Promise<CRMResponse<Voicemail>> {
    try {
      const voicemail: Voicemail = {
        id: `voicemail_${Date.now()}`,
        leadId: request.leadId,
        content: request.content,
        duration: request.duration,
        status: 'pending',
        scheduledAt: request.scheduledAt,
        sentAt: null,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };

      await this.db.voicemails.create(voicemail);
      return { success: true, data: voicemail };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async getVoicemail(id: string): Promise<CRMResponse<Voicemail>> {
    try {
      const voicemail = await this.db.voicemails.getById(id);
      if (!voicemail) {
        return { success: false, error: 'Voicemail not found' };
      }
      return { success: true, data: voicemail };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async createVoicemailCampaign(request: VoicemailCampaignRequest): Promise<CRMResponse<VoicemailCampaign>> {
    try {
      const campaign: VoicemailCampaign = {
        id: `campaign_${Date.now()}`,
        name: request.name,
        templateId: request.templateId,
        leadIds: request.leadIds,
        status: 'draft',
        scheduledAt: request.scheduledAt,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };

      await this.db.voicemailCampaigns.create(campaign);
      return { success: true, data: campaign };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async getVoicemailStats(campaignId: string): Promise<CRMResponse<VoicemailStats>> {
    try {
      // Mock voicemail stats - would calculate from actual data in production
      const stats: VoicemailStats = {
        campaignId,
        totalSent: 100,
        totalDelivered: 95,
        totalOpened: 80,
        totalClicked: 20,
        deliveryRate: 0.95,
        openRate: 0.84,
        clickRate: 0.25,
        createdAt: new Date().toISOString()
      };

      return { success: true, data: stats };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  // Metrics and Analytics
  async getLeadMetrics(filters?: LeadFilters): Promise<CRMResponse<LeadMetrics>> {
    try {
      // Mock lead metrics - would calculate from actual data in production
      const metrics: LeadMetrics = {
        totalLeads: 1000,
        newLeads: 50,
        qualifiedLeads: 200,
        convertedLeads: 100,
        conversionRate: 0.1,
        averageDealSize: 50000,
        totalValue: 5000000,
        createdAt: new Date().toISOString()
      };

      return { success: true, data: metrics };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async getContactMetrics(filters?: ContactFilters): Promise<CRMResponse<ContactMetrics>> {
    try {
      // Mock contact metrics - would calculate from actual data in production
      const metrics: ContactMetrics = {
        totalContacts: 500,
        newContacts: 25,
        activeContacts: 400,
        engagedContacts: 300,
        engagementRate: 0.75,
        createdAt: new Date().toISOString()
      };

      return { success: true, data: metrics };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async getAITaskMetrics(): Promise<CRMResponse<AITaskMetrics>> {
    try {
      // Mock AI task metrics - would calculate from actual data in production
      const metrics: AITaskMetrics = {
        totalTasks: 200,
        completedTasks: 150,
        pendingTasks: 30,
        failedTasks: 20,
        completionRate: 0.75,
        averageProcessingTime: 300,
        createdAt: new Date().toISOString()
      };

      return { success: true, data: metrics };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  // Event Management
  async emitEvent(event: CRMEvent): Promise<void> {
    try {
      // Mock event emission - would integrate with event system in production
      console.log('CRM Event:', event);
    } catch (error) {
      console.error('Failed to emit CRM event:', error);
    }
  }

  async onEvent(eventType: string, callback: (event: CRMEvent) => void): Promise<void> {
    try {
      // Mock event subscription - would integrate with event system in production
      console.log(`Subscribed to CRM event: ${eventType}`);
    } catch (error) {
      console.error('Failed to subscribe to CRM event:', error);
    }
  }

  // Utility Methods
  async healthCheck(): Promise<CRMResponse<{ status: string; timestamp: string }>> {
    try {
      // Mock health check - would check database connectivity in production
      return {
        success: true,
        data: {
          status: 'healthy',
          timestamp: new Date().toISOString()
        }
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  async cleanup(): Promise<void> {
    try {
      // Mock cleanup - would close database connections in production
      console.log('CRM Service cleanup completed');
    } catch (error) {
      console.error('CRM Service cleanup failed:', error);
    }
  }
}

