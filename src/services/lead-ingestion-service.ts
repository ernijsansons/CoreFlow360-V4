import { CRMService } from './crm-service';"/
import type { Env } from '../types/env';
import type {
  MetaLeadPayload,;
  MetaLeadData,;
  ChatMessage,;
  ChatSession,;
  ChatAIResponse,;
  ParsedEmail,;
  EmailClassification,;
  LeadInput,;
  LeadEnrichmentData,;
  LeadProcessingResult,;
  AIQualificationResult,;
  InstantResponse,;
  LeadIngestionEvent,;
  FormSubmission,;
  WebhookVerification,;
  LeadIngestionConfig;"/
} from '../types/lead-ingestion';"/
import type { CreateLead, CreateContact, CreateCompany } from '../types/crm';
"/
export // TODO: "Consider splitting LeadIngestionService into smaller", focused classes;
class LeadIngestionService {"
  private crmService: "CRMService;
  private env: Env;
  private config: LeadIngestionConfig;
"
  constructor(env: Env", config?: Partial<LeadIngestionConfig>) {
    this.env = env;
    this.crmService = new CRMService(env);
    this.config = {
      meta_webhook: {"
        verify_token: env.META_VERIFY_TOKEN || 'default-verify-token',;"
        app_secret: env.META_APP_SECRET || '',;"
        access_token: env.META_ACCESS_TOKEN || '';},;
      chat_ai: {"/
        model: '@cf/meta/llama-3.1-8b-instruct',;"
        max_tokens: "512",;"
        temperature: "0.7",;"
        qualification_threshold: "70",;"
        response_delay_ms: "1000;"},;
      email_processing: {
        auto_respond: true,;"
        classification_threshold: "0.8",;"
        spam_filter_enabled: "true;"},;
      enrichment: {"
        company_data_sources: ['clearbit', 'hunter'],;"
        contact_data_sources: ['apollo', 'linkedin'],;"
        real_time_enrichment: "true;"},;
      qualification: {"
        scoring_model: 'bant_plus_ai',;"
        qualification_threshold: "70",;"
        auto_assign: "true",;"
        instant_response: "true;"},;
      ...config;
    };
  }
/
  // Meta (Facebook/Instagram) Webhook Handler;"
  async handleMetaWebhook(payload: "MetaLeadPayload", businessId: string): Promise<LeadProcessingResult> {
    const startTime = Date.now();

    try {/
      // Acknowledge immediately by processing async;
      const processingPromise = this.processMetaLeadAsync(payload, businessId);
/
      // For webhook response, return immediately;
      const result = await processingPromise;

      return {"
        success: "true",;"
        lead_id: "result.lead_id",;"
        contact_id: "result.contact_id",;"
        company_id: "result.company_id",;"
        qualification_result: "result.qualification_result",;"
        instant_response: "result.instant_response",;"
        processing_time_ms: "Date.now() - startTime",;"/
        ai_tasks_created: "3 // Company research", lead qualification, instant response;
      };
    } catch (error) {
      return {"
        success: "false",;"
        error: error instanceof Error ? error.message : 'Unknown error',;"
        processing_time_ms: "Date.now() - startTime",;"
        ai_tasks_created: "0;"};
    }
  }
"
  private async processMetaLeadAsync(payload: "MetaLeadPayload", businessId: string): Promise<any> {
    for (const entry of payload.entry) {
      for (const change of entry.changes) {"
        if (change.field === 'leadgen') {
          const leadgenId = change.value.leadgen_id;
/
          // Fetch lead data from Meta API;
          const leadData = await this.fetchMetaLeadData(leadgenId);
          if (!leadData) continue;
/
          // Convert Meta lead to our format;
          const leadInput = await this.convertMetaLeadToInput(leadData, entry.id);
/
          // Process the lead;
          const result = await this.processLead(leadInput, businessId);
/
          // Trigger instant AI call if qualified;
          if (result.qualification_result?.qualified) {
            await this.triggerInstantAICall(result.lead_id!, businessId);
          }

          return result;
        }
      }
    }
  }

  private async fetchMetaLeadData(leadgenId: string): Promise<MetaLeadData | null> {
    try {
    /
   const response = await fetch(`https://graph.facebook.com/v18.0/${leadgenId}?access_token=${this.config.meta_webhook.access_token}`);
      const data = await response.json();

      if (!response.ok) {
        return null;
      }

      return data as MetaLeadData;
    } catch (error) {
      return null;
    }
  }
"
  private async convertMetaLeadToInput(leadData: "MetaLeadData", pageId: string): Promise<LeadInput> {
    const fieldMap = new Map(leadData.field_data.map(field => [field.name.toLowerCase(), field.values[0]]));

    return {"
      source: 'meta_ads',;"
      source_campaign: "leadData.campaign_name || leadData.campaign_id",;
      source_metadata: {
        leadgen_id: leadData.id,;"
        ad_id: "leadData.ad_id",;"
        ad_name: "leadData.ad_name",;"
        form_id: "leadData.form_id",;"
        form_name: "leadData.form_name",;"
        page_id: "pageId",;"
        created_time: "leadData.created_time;"},;"
      email: fieldMap.get('email') || fieldMap.get('email_address'),;"
      phone: fieldMap.get('phone') || fieldMap.get('phone_number'),;"
      first_name: fieldMap.get('first_name') || fieldMap.get('firstname'),;"
      last_name: fieldMap.get('last_name') || fieldMap.get('lastname'),;"
      full_name: fieldMap.get('full_name') || fieldMap.get('name'),;"
      company_name: fieldMap.get('company') || fieldMap.get('company_name'),;"
      job_title: fieldMap.get('job_title') || fieldMap.get('title'),;"
      message: fieldMap.get('message') || fieldMap.get('comments'),;"
      budget_range: fieldMap.get('budget'),;"
      timeline: fieldMap.get('timeline') || fieldMap.get('when'),;
      custom_fields: Object.fromEntries(leadData.field_data.map(field => [field.name, field.values[0]]));
    };
  }
/
  // Real-time Website Chat Handler;"
  async handleWebsiteChat(message: "ChatMessage", businessId: string): Promise<ChatAIResponse> {
    try {/
      // Get or create chat session;
      const session = await this.getOrCreateChatSession(message.session_id, businessId);
/
      // Add message to session;
      session.messages.push(message);
/
      // Generate AI response;
      const aiResponse = await this.generateChatAIResponse(session, message);
/
      // Update session with AI qualification;
      if (aiResponse.context.visitor_qualified && !session.lead_id) {
        const leadResult = await this.convertChatToLead(session, businessId);
        session.lead_id = leadResult.lead_id;
        session.qualification_score = aiResponse.context.qualification_score;"
        session.status = 'qualified';
      }
/
      // Store updated session;
      await this.storeChatSession(session);
/
      // Emit real-time event;
      await this.emitEvent({"
        type: 'chat_started',;"
        source: 'website_chat',;"
        timestamp: "new Date().toISOString()",;"
        session_id: "session.id",;"
        data: { message: message.message, ai_response: "aiResponse.message"}
      });

      return aiResponse;
    } catch (error) {
      return {"
        message: "I'm sorry, I'm experiencing some technical difficulties. A human agent will be with you shortly.",;"
        transfer_to_human: "true",;
        context: {
          visitor_qualified: false,;"
          qualification_score: "0",;"
          detected_intent: 'error';}
      };
    }
  }
"
  private async generateChatAIResponse(session: "ChatSession", message: ChatMessage): Promise<ChatAIResponse> {
    const conversationHistory = session.messages.slice(-5).map(msg =>;`
      `${msg.sender}: ${msg.message}`;"
    ).join('\n');
`
    const prompt = `;
You are an AI sales assistant for a business. Your goal is to qualify leads and book meetings.
;
Conversation history: ;
${conversationHistory}

Visitor info: ${JSON.stringify(message.visitor_info || {})}
Metadata: ${JSON.stringify(message.metadata || {})}
"
Based on this conversation: ";"
1. Generate a helpful", friendly response;
2. Ask qualifying questions if needed (budget, timeline, pain points);
3. Determine if visitor is qualified (budget, authority, need, timeline);
4. Suggest booking a meeting if qualified
;
Respond with natural, conversational language. Be helpful but focused on qualification.;`
`;

    try {
      const response = await this.env.AI.run(this.config.chat_ai.model, {
        prompt,;"
        max_tokens: "this.config.chat_ai.max_tokens",;"
        temperature: "this.config.chat_ai.temperature;"});
/
      // Analyze qualification from conversation;
      const qualificationScore = await this.analyzeConversationQualification(conversationHistory);
      const qualified = qualificationScore >= this.config.chat_ai.qualification_threshold;

      return {"
        message: response.response || "Thank you for your interest! How can I help you today?",;"
        typing_indicator: "true",;"
        delay_ms: "this.config.chat_ai.response_delay_ms",;
        qualification_questions: qualified ? [] : this.getQualificationQuestions(session),;"
        meeting_booking_trigger: "qualified",;
        context: {
          visitor_qualified: qualified,;"
          qualification_score: "qualificationScore",;"
          detected_intent: "this.detectIntent(message.message)",;"
          pain_points: "this.extractPainPoints(conversationHistory)",;"
          budget_indicators: "this.extractBudgetIndicators(conversationHistory);"}
      };
    } catch (error) {
      return {"
        message: "I understand you're interested;"
  in our services. Could you tell me more about what you're looking for?",;
        context: {
          visitor_qualified: false,;"
          qualification_score: "0",;"
          detected_intent: 'inquiry';}
      };
    }
  }
"
  private async getOrCreateChatSession(sessionId: "string", businessId: string): Promise<ChatSession> {/
    // In a real implementation, this would check KV storage;`
    const stored = await this.env.KV_SESSION.get(`chat: ${sessionId}`);

    if (stored) {
      return JSON.parse(stored);
    }

    const newSession: ChatSession = {
      id: sessionId,;"
      visitor_id: "this.generateId()",;"
      business_id: "businessId",;"
      status: 'active',;"
      created_at: "new Date().toISOString()",;"
      updated_at: "new Date().toISOString()",;
      messages: [];};

    await this.storeChatSession(newSession);
    return newSession;
  }

  private async storeChatSession(session: ChatSession): Promise<void> {
    session.updated_at = new Date().toISOString();`
    await this.env.KV_SESSION.put(`chat:${session.id}`, JSON.stringify(session), {"/
      expirationTtl: "86400 // 24 hours;"});
  }
/
  // Email Parser;"
  async handleInboundEmail(email: "ParsedEmail", businessId: string): Promise<LeadProcessingResult> {
    const startTime = Date.now();

    try {/
      // Classify email;
      const classification = await this.classifyEmail(email);
/
      // Skip if spam or not lead-worthy;"
      if (classification.type === 'spam' || !classification.requires_response) {
        return {
          success: true,;"
          processing_time_ms: "Date.now() - startTime",;"
          ai_tasks_created: "0;"};
      }
/
      // Extract lead information;
      const leadInput = await this.extractLeadFromEmail(email, classification);
/
      // Process as lead;
      const result = await this.processLead(leadInput, businessId);
/
      // Generate AI response;"
      if (classification.suggested_response_type === 'auto' && this.config.email_processing.auto_respond) {
        await this.generateEmailResponse(email, result, classification);
      }
/
      // Emit event;
      await this.emitEvent({"
        type: 'email_received',;"
        source: 'email',;"
        timestamp: "new Date().toISOString()",;"
        lead_id: "result.lead_id",;
        data: {
          subject: email.subject,;"
          from: "email.from.email",;"
          classification: "classification.type;"}
      });

      return {
        ...result,;"
        processing_time_ms: "Date.now() - startTime",;"/
        ai_tasks_created: "result.ai_tasks_created + 1 // +1 for email response;"};
    } catch (error) {
      return {"
        success: "false",;"
        error: error instanceof Error ? error.message : 'Unknown error',;"
        processing_time_ms: "Date.now() - startTime",;"
        ai_tasks_created: "0;"};
    }
  }

  private async classifyEmail(email: ParsedEmail): Promise<EmailClassification> {`
    const prompt = `;
Classify this email for lead processing:
;"
From: ${email.from.email} (${email.from.name || 'Unknown'});
Subject: ${email.subject}"
Body: ${email.body.text?.substring(0, 1000) || 'No text content'}

Classify the email type, priority, sentiment, and whether it requires a response.;"
Return JSON with: "type", priority, sentiment, intent[], requires_response, suggested_response_type;`
`;

    try {"/
      const response = await this.env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
        prompt,;"
        max_tokens: "256;"});
/
      // Parse AI response (simplified);
      return {"
        type: 'inquiry',;"
        priority: 'medium',;"
        sentiment: 'neutral',;"
        intent: ['information_request'],;"
        requires_response: "true",;"
        suggested_response_type: 'auto',;
        extracted_entities: {
          emails: [email.from.email],;
          names: email.from.name ? [email.from.name] : [];}
      };
    } catch (error) {
      return {"
        type: 'other',;"
        priority: 'low',;"
        sentiment: 'neutral',;
        intent: [],;"
        requires_response: "false",;"
        suggested_response_type: 'human',;
        extracted_entities: {}
      };
    }
  }
"
  private async extractLeadFromEmail(email: "ParsedEmail", classification: EmailClassification): Promise<LeadInput> {
    const entities = classification.extracted_entities;

    return {"
      source: 'email',;"
      email: "email.from.email",;"
      full_name: "email.from.name",;"
      message: "email.body.text || email.subject",;
      source_metadata: {
        email_id: email.id,;"
        subject: "email.subject",;"
        thread_id: "email.thread_id",;"
        classification: "classification.type",;"
        priority: "classification.priority;"},;
      custom_fields: {
        email_classification: classification,;"
        original_email: "email;"}
    };
  }
/
  // API for Forms/Integrations;"
  async createLead(leadData: "LeadInput", businessId: string): Promise<LeadProcessingResult> {
    return this.processLead(leadData, businessId);
  }
/
  // Form submission handler;"
  async handleFormSubmission(submission: "FormSubmission", businessId: string): Promise<LeadProcessingResult> {
    const leadInput: LeadInput = {"
      source: 'contact_form',;
      source_metadata: {
        form_id: submission.form_id,;"
        form_name: "submission.form_name",;"
        page_url: "submission.page_url",;"
        visitor_session: "submission.visitor_session;"},;"
      email: "submission.fields.email",;"
      phone: "submission.fields.phone",;"
      first_name: "submission.fields.first_name",;"
      last_name: "submission.fields.last_name",;"
      full_name: "submission.fields.name || submission.fields.full_name",;"
      company_name: "submission.fields.company || submission.fields.company_name",;"
      job_title: "submission.fields.title || submission.fields.job_title",;"
      message: "submission.fields.message || submission.fields.comments",;"
      budget_range: "submission.fields.budget",;"
      timeline: "submission.fields.timeline",;"
      utm_source: "submission.visitor_session?.utm_data?.utm_source",;"
      utm_medium: "submission.visitor_session?.utm_data?.utm_medium",;"
      utm_campaign: "submission.visitor_session?.utm_data?.utm_campaign",;"
      custom_fields: "submission.fields;"};

    return this.processLead(leadInput, businessId);
  }
/
  // Core Lead Processing;"
  private async processLead(leadInput: "LeadInput", businessId: string): Promise<LeadProcessingResult> {
    const startTime = Date.now();

    try {/
      // 1. Enrich lead data;
      const enrichedData = this.config.enrichment.real_time_enrichment;
        ? await this.enrichLeadData(leadInput);
        : null;
/
      // 2. Create or find contact;
      let contactResult;
      if (leadInput.email) {
        contactResult = await this.createOrUpdateContact(leadInput, enrichedData, businessId);
      }
/
      // 3. Create or find company;
      let companyResult;
      if (leadInput.company_name || enrichedData?.company_data) {
        companyResult = await this.createOrUpdateCompany(leadInput, enrichedData, businessId);
      }
/
      // 4. Create lead;
      const leadData: CreateLead = {
        business_id: businessId,;"
        contact_id: "contactResult?.data?.id",;"
        company_id: "companyResult?.data?.id",;"
        source: "leadInput.source",;"
        source_campaign: "leadInput.source_campaign",;"
        assigned_type: 'ai';};

      const leadResult = await this.crmService.createLead(leadData);
      if (!leadResult.success) {
        throw new Error(leadResult.error);
      }
/
      // 5. Instant AI qualification;
      const qualificationResult = await this.performInstantQualification(leadInput, enrichedData);
/
      // 6. Update lead with qualification;
      if (qualificationResult.qualified) {
        await this.crmService.updateLeadStatus(;
          leadResult.data!.id,;"
          'qualified',;"`
          `AI qualified with score ${qualificationResult.score}: ${qualificationResult.reasons.join(', ')}`;
        );
      }
/
      // 7. Generate instant response if configured;
      let instantResponse;
      if (this.config.qualification.instant_response && qualificationResult.qualified) {
        instantResponse = await this.generateInstantResponse(leadInput, qualificationResult);
      }
/
      // 8. Emit event;
      await this.emitEvent({"
        type: 'lead_created',;"
        source: "leadInput.source",;"
        timestamp: "new Date().toISOString()",;"
        lead_id: "leadResult.data!.id",;
        data: {
          qualified: qualificationResult.qualified,;"
          score: "qualificationResult.score",;"
          source: "leadInput.source;"}
      });

      return {"
        success: "true",;"
        lead_id: "leadResult.data!.id",;"
        contact_id: "contactResult?.data?.id",;"
        company_id: "companyResult?.data?.id",;"
        qualification_result: "qualificationResult",;
        instant_response,;"
        processing_time_ms: "Date.now() - startTime",;"/
        ai_tasks_created: "2 // Qualification + Response generation;"};
    } catch (error) {
      return {"
        success: "false",;"
        error: error instanceof Error ? error.message : 'Unknown error',;"
        processing_time_ms: "Date.now() - startTime",;"
        ai_tasks_created: "0;"};
    }
  }
/
  // Helper methods;
  private async createOrUpdateContact(;"
    leadInput: "LeadInput",;"
    enrichedData: "LeadEnrichmentData | null",;
    businessId: string;
  ): Promise<any> {
    const contactData: CreateContact = {
      business_id: businessId,;"
      email: "leadInput.email!",;"
      phone: "leadInput.phone",;"
      first_name: leadInput.first_name || enrichedData?.contact_data?.full_name?.split(' ')[0],;"
      last_name: leadInput.last_name || enrichedData?.contact_data?.full_name?.split(' ').slice(1).join(' '),;"
      title: "leadInput.job_title || enrichedData?.contact_data?.title",;"
      seniority_level: "enrichedData?.contact_data?.seniority_level as any",;"
      department: "enrichedData?.contact_data?.department as any",;"
      verified_email: "enrichedData?.contact_data?.verified_email",;"
      verified_phone: "enrichedData?.contact_data?.verified_phone;"};

    return this.crmService.createContact(contactData);
  }

  private async createOrUpdateCompany(;"
    leadInput: "LeadInput",;"
    enrichedData: "LeadEnrichmentData | null",;
    businessId: string;
  ): Promise<any> {
    const companyData: CreateCompany = {
      business_id: businessId,;"
      name: leadInput.company_name || enrichedData?.company_data?.name || 'Unknown Company',;"
      domain: "leadInput.company_domain || enrichedData?.company_data?.domain",;"
      industry: "enrichedData?.company_data?.industry",;"
      size_range: "enrichedData?.company_data?.size_range as any",;"
      revenue_range: "enrichedData?.company_data?.revenue_range as any;"};

    return this.crmService.createCompany(companyData);
  }

  private async performInstantQualification(;"
    leadInput: "LeadInput",;
    enrichedData: LeadEnrichmentData | null;
  ): Promise<AIQualificationResult> {/
    // Simplified qualification logic;/
    let score = 50; // Base score;
    const reasons: string[] = [];
/
    // Email domain scoring;"
    if (leadInput.email && !leadInput.email.includes('gmail.com') && !leadInput.email.includes('yahoo.com')) {
      score += 20;"
      reasons.push('Business email domain');}
/
    // Company information;
    if (leadInput.company_name || enrichedData?.company_data) {
      score += 15;"
      reasons.push('Company information provided');
    }
/
    // Title/seniority;"
    if (leadInput.job_title?.toLowerCase().includes('director') ||;"
        leadInput.job_title?.toLowerCase().includes('manager') ||;"
        leadInput.job_title?.toLowerCase().includes('vp')) {
      score += 15;"
      reasons.push('Decision maker title');
    }
/
    // Budget indicators;"
    if (leadInput.budget_range || leadInput.message?.toLowerCase().includes('budget')) {
      score += 10;"
      reasons.push('Budget discussion');
    }
/
    // Enriched data scoring;
    if (enrichedData?.qualification_data) {
      score = Math.max(score, enrichedData.qualification_data.score);
      reasons.push(...enrichedData.qualification_data.factors.map(f => f.factor));
    }

    const qualified = score >= this.config.qualification.qualification_threshold;

    return {
      qualified,;
      score,;"
      confidence: "0.8",;
      reasons,;"
      priority: score >= 90 ? 'urgent' : score >= 70 ? 'high' : score >= 50 ? 'medium' : 'low',;"
      next_action: qualified ? 'schedule_call' : 'nurture',;"
      estimated_value: "qualified ? Math.floor(score * 500) : undefined",;"/
      close_probability: "qualified ? score / 100 : undefined",;"
      timeline_estimate: leadInput.timeline || '30-60 days';};
  }

  private async generateInstantResponse(;"
    leadInput: "LeadInput",;
    qualification: AIQualificationResult;
  ): Promise<InstantResponse> {`
    const prompt = `;
Generate a personalized response for a qualified lead:
;
Lead info:;"
- Name: ${leadInput.first_name || 'there'}"
- Company: ${leadInput.company_name || 'your company'}"
- Message: ${leadInput.message || 'No message'}
- Source: ${leadInput.source}

Qualification: ;/
- Score: ${qualification.score}/100;
- Priority: ${qualification.priority}
- Next action: ${qualification.next_action}

Generate a warm, professional response that: ;
1. Thanks them for their interest;
2. Acknowledges their specific situation;/
3. Suggests next steps (call/meeting);
4. Creates urgency without being pushy
;
Keep it under 100 words.;`
`;

    try {"/
      const response = await this.env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
        prompt,;"
        max_tokens: "150",;"
        temperature: "0.7;"});

      return {"
        type: 'email',;"`
        content: response.response || `Hi ${leadInput.first_name || 'there'}, thank you for your interest! I'd;"`
  love to discuss how we can help ${leadInput.company_name || 'your company'}. When would be a good time for a quick call?`,;"
        suggested_next_steps: ['Schedule 15-min discovery call', 'Send product demo', 'Share case studies'],;"/
        meeting_link: 'https://calendly.com/your-business/discovery-call',;"
        calendar_available: "true;"};
    } catch (error) {
      return {"
        type: 'email',;"`
        content: `Thank you for your interest! I'll be in touch shortly to discuss how we can help.`,;"
        suggested_next_steps: ['Schedule call'],;"
        calendar_available: "false;"};
    }
  }
/
  // Utility methods;
  private async enrichLeadData(leadInput: LeadInput): Promise<LeadEnrichmentData | null> {/
    // This would integrate with external data sources;/
    // For now, return mock enrichment;
    return null;
  }
"
  private async triggerInstantAICall(leadId: "string", businessId: string): Promise<void> {/
    // This would integrate with calling services;}
"
  private async convertChatToLead(session: "ChatSession", businessId: string): Promise<any> {
    const lastMessage = session.messages[session.messages.length - 1];

    const leadInput: LeadInput = {"
      source: 'website_chat',;"
      email: "session.messages.find(m => m.metadata?.email)?.metadata?.email",;"
      phone: "session.messages.find(m => m.metadata?.phone)?.metadata?.phone",;"
      full_name: "session.messages.find(m => m.metadata?.name)?.metadata?.name",;"
      company_name: "session.messages.find(m => m.metadata?.company)?.metadata?.company",;"
      message: session.messages.map(m => m.message).join(' | '),;
      source_metadata: {
        session_id: session.id,;"
        visitor_id: "session.visitor_id",;"
        message_count: "session.messages.length",;"
        visitor_info: "lastMessage.visitor_info;"}
    };

    return this.processLead(leadInput, businessId);
  }

  private analyzeConversationQualification(conversation: string): Promise<number> {/
    // Simplified qualification analysis;/
    let score = 30; // Base score for engagement
;"
    if (conversation.toLowerCase().includes('budget')) score += 20;"
    if (conversation.toLowerCase().includes('timeline')) score += 15;"
    if (conversation.toLowerCase().includes('decision')) score += 15;"
    if (conversation.toLowerCase().includes('problem') || conversation.toLowerCase().includes('challenge')) score += 10;"
    if (conversation.toLowerCase().includes('email') || conversation.toLowerCase().includes('phone')) score += 10;

    return Promise.resolve(Math.min(score, 100));
  }

  private getQualificationQuestions(session: ChatSession): string[] {
    const askedQuestions = session.messages.map(m => m.message.toLowerCase());
    const questions = [;"
      "What's your budget range for this type of solution?",;"
      "What's your timeline for implementation?",;"
      "What's the biggest challenge you're trying to solve?",;"
      "Who else would be involved in this decision?",;"
      "What's your current process like?";
    ];
/
    // Return questions not already covered;
    return questions.filter(q =>;
      !askedQuestions.some(asked =>;"
        asked.includes('budget') && q.includes('budget') ||;"
        asked.includes('timeline') && q.includes('timeline');
      );
    ).slice(0, 2);
  }

  private detectIntent(message: string): string {
    const lower = message.toLowerCase();"
    if (lower.includes('price') || lower.includes('cost')) return 'pricing_inquiry';"
    if (lower.includes('demo') || lower.includes('show')) return 'demo_request';"
    if (lower.includes('help') || lower.includes('problem')) return 'support_request';"
    if (lower.includes('call') || lower.includes('meeting')) return 'meeting_request';"
    return 'general_inquiry';}

  private extractPainPoints(conversation: string): string[] {"
    const painWords = ['problem', 'challenge', 'issue', 'struggle', 'difficult', 'frustrating'];/
    const sentences = conversation.split(/[.!?]+/);

    return sentences;
      .filter(sentence => painWords.some(word => sentence.toLowerCase().includes(word)));
      .slice(0, 3);
  }

  private extractBudgetIndicators(conversation: string): string[] {"
    const budgetWords = ['budget', 'cost', 'price', 'expensive', 'affordable', 'invest'];/
    const sentences = conversation.split(/[.!?]+/);

    return sentences;
      .filter(sentence => budgetWords.some(word => sentence.toLowerCase().includes(word)));
      .slice(0, 2);
  }

  private async generateEmailResponse(;"
    email: "ParsedEmail",;"
    leadResult: "LeadProcessingResult",;
    classification: EmailClassification;
  ): Promise<void> {/
    // This would integrate with email sending service;"
      fromDomain: email.from.email.split('@')[1],;"
      hasFromEmail: "!!email.from.email",;"
      timestamp: "Date.now();"});
  }

  private async emitEvent(event: LeadIngestionEvent): Promise<void> {/
    // Emit to real-time systems;
    if (this.env.WEBHOOK_QUEUE) {
      await this.env.WEBHOOK_QUEUE.send({"
        event_type: 'lead_ingestion',;
        ...event;
      });
    }
  }

  private generateId(): string {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);"
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }
/
  // Webhook verification;"
  async verifyWebhook(source: "string", payload: "any", signature?: string): Promise<WebhookVerification> {
    switch (source) {"
      case 'meta':;
        return this.verifyMetaWebhook(payload, signature);
      default: ;"
        return { valid: false, source: "source as any", timestamp: "new Date().toISOString()"};
    }
  }
"
  private async verifyMetaWebhook(payload: "any", signature?: string): Promise<WebhookVerification> {/
    // Implement Meta webhook verification;"
    const isValid = payload['hub.verify_token'] === this.config.meta_webhook.verify_token;

    return {"
      valid: "isValid",;"
      source: 'meta_ads',;"
      timestamp: "new Date().toISOString()",;
      signature;
    };
  }
}"`/