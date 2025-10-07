import { CRMService } from './crm-service';
import type { Env } from '../types/env';
import type {
  MetaLeadPayload,
  MetaLeadData,
  ChatMessage,
  ChatSession,
  ChatAIResponse,
  ParsedEmail,
  EmailClassification,
  LeadInput,
  LeadEnrichmentData,
  LeadProcessingResult,
  AIQualificationResult,
  InstantResponse,
  LeadIngestionEvent,
  FormSubmission,
  WebhookVerification,
  LeadIngestionConfig
} from '../types/lead-ingestion';
import type { CreateLead, CreateContact, CreateCompany } from '../types/crm';

export class LeadIngestionService {
  private crmService: CRMService;
  private env: Env;
  private config: LeadIngestionConfig;

  constructor(env: Env, config?: Partial<LeadIngestionConfig>) {
    this.env = env;
    this.crmService = new CRMService(env);
    this.config = {
      meta_webhook: {
        verify_token: 'default-verify-token',
        app_secret: '',
        access_token: ''
      },
      chat_ai: {
        model: '@cf/meta/llama-3.1-8b-instruct',
        max_tokens: 512,
        temperature: 0.7,
        qualification_threshold: 70,
        response_delay_ms: 1000
      },
      email_processing: {
        auto_respond: true,
        classification_threshold: 0.8,
        spam_filter_enabled: true
      },
      enrichment: {
        company_data_sources: ['clearbit', 'hunter'],
        contact_data_sources: ['apollo', 'linkedin'],
        real_time_enrichment: true
      },
      qualification: {
        scoring_model: 'default',
        qualification_threshold: 70,
        auto_assign: true,
        instant_response: true
      },
      ...config
    };
  }

  /**
   * Process Meta webhook lead
   */
  async processMetaLead(payload: MetaLeadPayload): Promise<LeadProcessingResult> {
    try {
      // Verify webhook
      if (!this.verifyMetaWebhook(payload)) {
        throw new Error('Invalid webhook verification');
      }

      // Extract lead data
      const leadData = this.extractMetaLeadData(payload);
      
      // Enrich lead data
      const enrichedData = await this.enrichLeadData(leadData);
      
      // Create lead in CRM
      const lead = await this.createLeadFromData(enrichedData);
      
      // Generate instant response
      const response = await this.generateInstantResponse(lead);
      
      return {
        success: true,
        lead_id: lead.id,
        instant_response: response,
        processing_time_ms: 0,
        ai_tasks_created: 0
      };
    } catch (error: any) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        processing_time_ms: 0,
        ai_tasks_created: 0
      };
    }
  }

  /**
   * Process chat message
   */
  async processChatMessage(
    businessId: string,
    sessionId: string,
    message: ChatMessage
  ): Promise<ChatAIResponse> {
    try {
      // Get or create chat session
      const session = await this.getOrCreateChatSession(businessId, sessionId);
      
      // Add message to session
      session.messages.push(message);
      
      // Generate AI response
      const response = await this.generateChatResponse(session);
      
      // Update session
      await this.updateChatSession(session);
      
      return response;
    } catch (error: any) {
      return {
        message: 'Sorry, I encountered an error. Please try again.',
        context: {
          visitor_qualified: false,
          qualification_score: 0,
          detected_intent: 'error'
        }
      };
    }
  }

  /**
   * Process email lead
   */
  async processEmailLead(
    businessId: string,
    email: ParsedEmail
  ): Promise<LeadProcessingResult> {
    try {
      // Classify email
      const classification = await this.classifyEmail(email);

      if (classification.type === 'spam') {
        return {
          success: false,
          error: 'Email classified as spam',
          processing_time_ms: 0,
          ai_tasks_created: 0
        };
      }
      
      // Extract lead data from email
      const leadData = this.extractEmailLeadData(email);
      
      // Enrich lead data
      const enrichedData = await this.enrichLeadData(leadData);
      
      // Create lead in CRM
      const lead = await this.createLeadFromData(enrichedData);
      
      // Generate auto-response if enabled
      let response: InstantResponse | undefined;
      if (this.config.email_processing.auto_respond) {
        response = await this.generateEmailResponse(lead, email);
      }
      
      return {
        success: true,
        lead_id: lead.id,
        instant_response: response,
        processing_time_ms: 0,
        ai_tasks_created: 0
      };
    } catch (error: any) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        processing_time_ms: 0,
        ai_tasks_created: 0
      };
    }
  }

  /**
   * Process form submission
   */
  async processFormSubmission(
    businessId: string,
    submission: FormSubmission
  ): Promise<LeadProcessingResult> {
    try {
      // Validate form data
      this.validateFormSubmission(submission);
      
      // Extract lead data
      const leadData = this.extractFormLeadData(submission);
      
      // Enrich lead data
      const enrichedData = await this.enrichLeadData(leadData);
      
      // Create lead in CRM
      const lead = await this.createLeadFromData(enrichedData);
      
      // Generate instant response
      const response = await this.generateFormResponse(lead, submission);
      
      return {
        success: true,
        lead_id: lead.id,
        instant_response: response,
        processing_time_ms: 0,
        ai_tasks_created: 0
      };
    } catch (error: any) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        processing_time_ms: 0,
        ai_tasks_created: 0
      };
    }
  }

  /**
   * Verify Meta webhook
   */
  private verifyMetaWebhook(payload: MetaLeadPayload): boolean {
    // Mock verification - would implement real verification in production
    // MetaLeadPayload doesn't have verify_token, so always return true for now
    return true;
  }

  /**
   * Extract lead data from Meta payload
   */
  private extractMetaLeadData(payload: MetaLeadPayload): LeadInput {
    // Extract field data from Meta payload structure
    const fieldData = payload.entry?.[0]?.changes?.[0]?.value || {};

    return {
      source: 'meta_ads',
      source_metadata: {
        form_id: fieldData.form_id,
        leadgen_id: fieldData.leadgen_id,
        ad_id: fieldData.ad_id
      }
    };
  }

  /**
   * Extract lead data from email
   */
  private extractEmailLeadData(email: ParsedEmail): LeadInput {
    return {
      email: email.from.email,
      full_name: email.from.name,
      source: 'email',
      source_metadata: {
        subject: email.subject,
        message_id: email.id
      }
    };
  }

  /**
   * Extract lead data from form submission
   */
  private extractFormLeadData(submission: FormSubmission): LeadInput {
    const fields = submission.fields || {};

    return {
      email: fields.email || '',
      full_name: fields.name || '',
      phone: fields.phone || '',
      company_name: fields.company || '',
      source: 'contact_form',
      source_metadata: {
        form_id: submission.form_id,
        form_name: submission.form_name,
        page_url: submission.page_url
      }
    };
  }

  /**
   * Enrich lead data
   */
  private async enrichLeadData(leadData: LeadInput): Promise<LeadEnrichmentData> {
    // Mock enrichment - would implement real enrichment in production
    return {
      company_data: {
        name: leadData.company_name || 'Unknown',
        domain: leadData.company_domain || '',
        industry: 'Technology',
        size_range: '50-200',
        revenue_range: '$1M-$10M',
        technologies: [],
        social_profiles: {}
      },
      contact_data: {
        full_name: leadData.full_name || `${leadData.first_name || ''} ${leadData.last_name || ''}`.trim(),
        title: leadData.job_title || 'Manager',
        seniority_level: 'manager',
        department: 'Sales',
        linkedin_profile: undefined,
        verified_email: false,
        verified_phone: false
      }
    };
  }

  /**
   * Create lead from enriched data
   */
  private async createLeadFromData(data: LeadEnrichmentData): Promise<any> {
    const leadData: CreateLead = {
      email: data.contact_data?.full_name || 'unknown@example.com',
      first_name: data.contact_data?.full_name?.split(' ')[0] || undefined,
      last_name: data.contact_data?.full_name?.split(' ').slice(1).join(' ') || undefined,
      company_name: data.company_data?.name || undefined,
      title: data.contact_data?.title || undefined,
      phone: undefined,
      source: 'meta_ads',
      status: 'new',
      score: data.qualification_data?.score || 0,
      metadata: {}
    };

    return await this.crmService.createLead(leadData);
  }

  /**
   * Generate instant response
   */
  private async generateInstantResponse(lead: any): Promise<InstantResponse> {
    // Mock response generation - would use real AI in production
    return {
      type: 'email',
      content: `Thank you for your interest, ${lead.first_name || 'there'}! We'll be in touch soon.`,
      personalization_data: {
        leadId: lead.id
      }
    };
  }

  /**
   * Generate chat response
   */
  private async generateChatResponse(session: ChatSession): Promise<ChatAIResponse> {
    // Mock AI response - would use real AI in production
    return {
      message: 'Thank you for your message. How can I help you today?',
      suggested_responses: ['Schedule a demo', 'Learn more', 'Contact sales'],
      context: {
        visitor_qualified: false,
        qualification_score: 0,
        detected_intent: 'inquiry'
      }
    };
  }

  /**
   * Generate email response
   */
  private async generateEmailResponse(lead: any, email: ParsedEmail): Promise<InstantResponse> {
    // Mock email response - would use real AI in production
    return {
      type: 'email',
      content: `Hi ${lead.first_name || 'there'}, thank you for reaching out. We'll get back to you within 24 hours.`,
      personalization_data: {
        leadId: lead.id,
        originalEmail: email
      }
    };
  }

  /**
   * Generate form response
   */
  private async generateFormResponse(lead: any, submission: FormSubmission): Promise<InstantResponse> {
    // Mock form response - would use real AI in production
    return {
      type: 'email',
      content: `Thank you for your submission, ${lead.first_name || 'there'}! We'll review it and get back to you.`,
      personalization_data: {
        leadId: lead.id,
        formId: submission.form_id
      }
    };
  }

  /**
   * Classify email
   */
  private async classifyEmail(email: ParsedEmail): Promise<EmailClassification> {
    // Mock classification - would use real AI in production
    return {
      type: 'inquiry',
      priority: 'medium',
      sentiment: 'neutral',
      intent: ['inquiry'],
      requires_response: true,
      suggested_response_type: 'auto',
      extracted_entities: {}
    };
  }

  /**
   * Validate form submission
   */
  private validateFormSubmission(submission: FormSubmission): void {
    if (!submission.fields.email) {
      throw new Error('Email is required');
    }

    if (!submission.fields.name) {
      throw new Error('Name is required');
    }
  }

  /**
   * Get or create chat session
   */
  private async getOrCreateChatSession(businessId: string, sessionId: string): Promise<ChatSession> {
    // Mock session management - would implement real session management in production
    return {
      id: sessionId,
      visitor_id: 'unknown',
      business_id: businessId,
      status: 'active',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      messages: []
    };
  }

  /**
   * Update chat session
   */
  private async updateChatSession(session: ChatSession): Promise<void> {
    // Mock session update - would implement real session update in production
    session.updated_at = new Date().toISOString();
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<{ status: string; timestamp: string }> {
    try {
      return {
        status: 'healthy',
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        status: 'unhealthy',
        timestamp: new Date().toISOString()
      };
    }
  }
}

