// Lead Ingestion Types for CoreFlow360 AI-Native CRM
// Real-time lead processing from multiple sources

export interface MetaLeadPayload {
  object: 'page';
  entry: Array<{
    id: string;
    time: number;
    changes: Array<{
      value: {
        ad_id?: string;
        form_id: string;
        leadgen_id: string;
        created_time: number;
        page_id: string;
        adgroup_id?: string;
        campaign_id?: string;
      };
      field: 'leadgen';
    }>;
  }>;
}

export interface MetaLeadData {
  id: string;
  created_time: string;
  ad_id?: string;
  ad_name?: string;
  adset_id?: string;
  adset_name?: string;
  campaign_id?: string;
  campaign_name?: string;
  form_id: string;
  form_name?: string;
  is_organic: boolean;
  field_data: Array<{
    name: string;
    values: string[];
  }>;
}

export interface ChatMessage {
  id: string;
  session_id: string;
  message: string;
  timestamp: string;
  sender: 'visitor' | 'ai' | 'human';
  visitor_info?: {
    ip: string;
    user_agent: string;
    referrer?: string;
    utm_source?: string;
    utm_medium?: string;
    utm_campaign?: string;
    page_url: string;
  };
  metadata?: {
    email?: string;
    phone?: string;
    name?: string;
    company?: string;
  };
}

export interface ChatSession {
  id: string;
  visitor_id: string;
  business_id: string;
  status: 'active' | 'qualified' | 'transferred' | 'ended';
  created_at: string;
  updated_at: string;
  messages: ChatMessage[];
  qualification_score?: number;
  lead_id?: string;
  contact_id?: string;
  ai_summary?: string;
  meeting_scheduled?: boolean;
}

export interface ParsedEmail {
  id: string;
  from: {
    email: string;
    name?: string;
  };
  to: Array<{
    email: string;
    name?: string;
  }>;
  subject: string;
  body: {
    text?: string;
    html?: string;
  };
  headers: Record<string, string>;
  attachments?: Array<{
    filename: string;
    content_type: string;
    size: number;
    url?: string;
  }>;
  timestamp: string;
  thread_id?: string;
  in_reply_to?: string;
  references?: string[];
}

export interface LeadInput {
  source: LeadSource;
  source_campaign?: string;
  source_metadata?: Record<string, any>;

  // Contact information
  email?: string;
  phone?: string;
  first_name?: string;
  last_name?: string;
  full_name?: string;

  // Company information
  company_name?: string;
  company_domain?: string;
  job_title?: string;

  // Additional data
  message?: string;
  interests?: string[];
  budget_range?: string;
  timeline?: string;

  // Tracking data
  utm_source?: string;
  utm_medium?: string;
  utm_campaign?: string;
  referrer?: string;
  landing_page?: string;

  // Custom fields
  custom_fields?: Record<string, any>;
}

export type LeadSource =
  | 'meta_ads'
  | 'google_ads'
  | 'website_chat'
  | 'contact_form'
  | 'email'
  | 'phone'
  | 'linkedin'
  | 'organic'
  | 'referral'
  | 'integration'
  | 'manual';

export interface LeadEnrichmentData {
  company_data?: {
    name: string;
    domain: string;
    industry: string;
    size_range: string;
    revenue_range: string;
    technologies: string[];
    social_profiles: Record<string, string>;
  };
  contact_data?: {
    full_name: string;
    title: string;
    seniority_level: string;
    department: string;
    linkedin_profile?: string;
    verified_email: boolean;
    verified_phone: boolean;
  };
  qualification_data?: {
    score: number;
    factors: Array<{
      factor: string;
      weight: number;
      value: any;
      contribution: number;
    }>;
    fit_analysis: string;
    next_action: string;
  };
}

export interface InstantResponse {
  type: 'chat' | 'email' | 'sms' | 'call';
  content: string;
  personalization_data?: Record<string, any>;
  suggested_next_steps?: string[];
  meeting_link?: string;
  calendar_available?: boolean;
}

export interface AIQualificationResult {
  qualified: boolean;
  score: number; // 0-100
  confidence: number; // 0-1
  reasons: string[];
  priority: 'low' | 'medium' | 'high' | 'urgent';
  next_action: 'nurture' | 'qualify_more' | 'schedule_call' | 'send_proposal' | 'disqualify';
  estimated_value?: number;
  close_probability?: number;
  timeline_estimate?: string;
}

export interface LeadProcessingResult {
  success: boolean;
  lead_id?: string;
  contact_id?: string;
  company_id?: string;
  qualification_result?: AIQualificationResult;
  instant_response?: InstantResponse;
  error?: string;
  processing_time_ms: number;
  ai_tasks_created: number;
}

export interface WebhookVerification {
  valid: boolean;
  source: LeadSource;
  timestamp: string;
  signature?: string;
}

export interface ChatAIResponse {
  message: string;
  typing_indicator?: boolean;
  delay_ms?: number;
  suggested_responses?: string[];
  qualification_questions?: string[];
  meeting_booking_trigger?: boolean;
  transfer_to_human?: boolean;
  context: {
    visitor_qualified: boolean;
    qualification_score: number;
    detected_intent: string;
    pain_points?: string[];
    budget_indicators?: string[];
  };
}

export interface EmailClassification {
  type: 'inquiry' | 'support' | 'sales' | 'complaint' | 'spam' | 'other';
  priority: 'low' | 'medium' | 'high' | 'urgent';
  sentiment: 'positive' | 'neutral' | 'negative';
  intent: string[];
  requires_response: boolean;
  suggested_response_type: 'auto' | 'human' | 'template';
  extracted_entities: {
    names?: string[];
    companies?: string[];
    emails?: string[];
    phones?: string[];
    dates?: string[];
    money_amounts?: string[];
  };
}

export interface FormSubmission {
  form_id: string;
  form_name?: string;
  page_url: string;
  submission_time: string;
  fields: Record<string, any>;
  visitor_session?: {
    session_id: string;
    pages_visited: string[];
    time_on_site: number;
    referrer: string;
    utm_data: Record<string, string>;
  };
}

// Configuration types
export interface LeadIngestionConfig {
  meta_webhook: {
    verify_token: string;
    app_secret: string;
    access_token: string;
  };
  chat_ai: {
    model: string;
    max_tokens: number;
    temperature: number;
    qualification_threshold: number;
    response_delay_ms: number;
  };
  email_processing: {
    auto_respond: boolean;
    classification_threshold: number;
    spam_filter_enabled: boolean;
  };
  enrichment: {
    company_data_sources: string[];
    contact_data_sources: string[];
    real_time_enrichment: boolean;
  };
  qualification: {
    scoring_model: string;
    qualification_threshold: number;
    auto_assign: boolean;
    instant_response: boolean;
  };
}

// Event types for real-time updates
export interface LeadIngestionEvent {
  type: 'lead_created' | 'lead_qualified' | 'chat_started' | 'email_received' | 'meeting_scheduled';
  source: LeadSource;
  timestamp: string;
  lead_id?: string;
  session_id?: string;
  data: Record<string, any>;
}

// Integration webhooks
export interface IntegrationWebhook {
  id: string;
  name: string;
  source: LeadSource;
  url: string;
  secret: string;
  headers?: Record<string, string>;
  field_mapping: Record<string, string>;
  active: boolean;
  created_at: string;
}

export interface CalendarIntegration {
  provider: 'calendly' | 'google' | 'outlook' | 'custom';
  booking_url: string;
  availability_check: boolean;
  auto_schedule: boolean;
  meeting_types: Array<{
    name: string;
    duration: number;
    buffer_time: number;
    questions?: string[];
  }>;
}