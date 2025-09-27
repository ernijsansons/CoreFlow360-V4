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
        verify_token: env.META_VERIFY_TOKEN || 'default-verify-token',
        app_secret: env.META_APP_SECRET || '',
        access_token: env.META_ACCESS_TOKEN || ''
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
        leadId: lead.id,
        response,
        metadata: {
          source: 'meta_webhook',
          originalPayload: payload
        }
      };
    } catch (error: any) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        metadata: {
          source: 'meta_webhook',
          originalPayload: payload
        }
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
        confidence: 0,
        suggestions: [],
        metadata: {
          error: error instanceof Error ? error.message : 'Unknown error'
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
      
      if (classification.isSpam) {
        return {
          success: false,
          error: 'Email classified as spam',
          metadata: { classification }
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
        leadId: lead.id,
        response,
        metadata: {
          source: 'email',
          classification,
          originalEmail: email
        }
      };
    } catch (error: any) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        metadata: {
          source: 'email',
          originalEmail: email
        }
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
        leadId: lead.id,
        response,
        metadata: {
          source: 'form',
          formId: submission.formId,
          originalSubmission: submission
        }
      };
    } catch (error: any) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        metadata: {
          source: 'form',
          formId: submission.formId,
          originalSubmission: submission
        }
      };
    }
  }

  /**
   * Verify Meta webhook
   */
  private verifyMetaWebhook(payload: MetaLeadPayload): boolean {
    // Mock verification - would implement real verification in production
    return payload.verify_token === this.config.meta_webhook.verify_token;
  }

  /**
   * Extract lead data from Meta payload
   */
  private extractMetaLeadData(payload: MetaLeadPayload): LeadInput {
    return {
      name: payload.lead_data.name || '',
      email: payload.lead_data.email || '',
      phone: payload.lead_data.phone || '',
      company: payload.lead_data.company || '',
      source: 'meta_webhook',
      metadata: {
        originalPayload: payload
      }
    };
  }

  /**
   * Extract lead data from email
   */
  private extractEmailLeadData(email: ParsedEmail): LeadInput {
    return {
      name: email.from.name || '',
      email: email.from.email || '',
      phone: '',
      company: '',
      source: 'email',
      metadata: {
        originalEmail: email
      }
    };
  }

  /**
   * Extract lead data from form submission
   */
  private extractFormLeadData(submission: FormSubmission): LeadInput {
    return {
      name: submission.data.name || '',
      email: submission.data.email || '',
      phone: submission.data.phone || '',
      company: submission.data.company || '',
      source: 'form',
      metadata: {
        formId: submission.formId,
        originalSubmission: submission
      }
    };
  }

  /**
   * Enrich lead data
   */
  private async enrichLeadData(leadData: LeadInput): Promise<LeadEnrichmentData> {
    // Mock enrichment - would implement real enrichment in production
    return {
      ...leadData,
      enriched: true,
      companyData: {
        industry: 'Technology',
        size: '50-200',
        revenue: '$1M-$10M'
      },
      contactData: {
        title: 'Manager',
        department: 'Sales',
        socialProfiles: []
      }
    };
  }

  /**
   * Create lead from enriched data
   */
  private async createLeadFromData(data: LeadEnrichmentData): Promise<any> {
    const leadData: CreateLead = {
      name: data.name,
      email: data.email,
      phone: data.phone,
      company: data.company,
      source: data.source,
      status: 'new',
      score: 0,
      metadata: data.metadata
    };

    return await this.crmService.createLead(leadData);
  }

  /**
   * Generate instant response
   */
  private async generateInstantResponse(lead: any): Promise<InstantResponse> {
    // Mock response generation - would use real AI in production
    return {
      message: `Thank you for your interest, ${lead.name}! We'll be in touch soon.`,
      channel: 'email',
      priority: 'normal',
      metadata: {
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
      confidence: 0.8,
      suggestions: ['Schedule a demo', 'Learn more', 'Contact sales'],
      metadata: {
        sessionId: session.id
      }
    };
  }

  /**
   * Generate email response
   */
  private async generateEmailResponse(lead: any, email: ParsedEmail): Promise<InstantResponse> {
    // Mock email response - would use real AI in production
    return {
      message: `Hi ${lead.name}, thank you for reaching out. We'll get back to you within 24 hours.`,
      channel: 'email',
      priority: 'normal',
      metadata: {
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
      message: `Thank you for your submission, ${lead.name}! We'll review it and get back to you.`,
      channel: 'email',
      priority: 'normal',
      metadata: {
        leadId: lead.id,
        formId: submission.formId
      }
    };
  }

  /**
   * Classify email
   */
  private async classifyEmail(email: ParsedEmail): Promise<EmailClassification> {
    // Mock classification - would use real AI in production
    return {
      isSpam: false,
      category: 'inquiry',
      confidence: 0.9,
      metadata: {
        originalEmail: email
      }
    };
  }

  /**
   * Validate form submission
   */
  private validateFormSubmission(submission: FormSubmission): void {
    if (!submission.data.email) {
      throw new Error('Email is required');
    }
    
    if (!submission.data.name) {
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
      businessId,
      messages: [],
      createdAt: new Date(),
      updatedAt: new Date()
    };
  }

  /**
   * Update chat session
   */
  private async updateChatSession(session: ChatSession): Promise<void> {
    // Mock session update - would implement real session update in production
    session.updatedAt = new Date();
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

