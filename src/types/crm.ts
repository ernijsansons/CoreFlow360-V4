// CoreFlow360 CRM TypeScript Types
// AI-Native CRM data models for Cloudflare D1

// Multi-Channel Orchestration Types
export type ChannelType = 'email' | 'sms' | 'linkedin' | 'call' | 'whatsapp';
export type MessageStatus = 'pending' | 'sent' | 'delivered' | 'read' | 'replied' | 'bounced' | 'failed';
export type CampaignStatus = 'draft' | 'scheduled' | 'active' | 'paused' | 'completed' | 'failed';

export interface ChannelStrategy {
  primary_channel: ChannelType;
  sequence: ChannelStep[];
  fallback_channels: ChannelType[];
  timing: {
    start_time?: string;
    end_time?: string;
    timezone: string;
    avoid_weekends: boolean;
    optimal_send_times: Record<ChannelType, string[]>;
  };
  ai_reasoning: string;
  predicted_response_rate: number;
  urgency_level: 'low' | 'medium' | 'high' | 'critical';
}

export interface ChannelStep {
  channel: ChannelType;
  delay_hours: number;
  condition?: {
    type: 'no_response' | 'opened' | 'clicked' | 'replied' | 'custom';
    value?: any;
  };
  content_variant?: string;
  personalization_level: 'generic' | 'basic' | 'medium' | 'high' | 'hyper_personalized';
}

export interface ChannelContent {
  channel: ChannelType;
  subject?: string; // For email
  preview_text?: string; // For email
  body: string;
  cta?: CallToAction;
  attachments?: Attachment[];
  metadata?: Record<string, any>;
  personalization_tokens?: string[];
  ai_generated: boolean;
  variant_id?: string;
  tone: 'formal' | 'casual' | 'friendly' | 'urgent' | 'educational';
}

export interface CallToAction {
  text: string;
  url?: string;
  type: 'link' | 'button' | 'calendar' | 'reply' | 'call';
  tracking_enabled: boolean;
}

export interface Attachment {
  name: string;
  url: string;
  type: string;
  size: number;
}

export interface OmnichannelCampaign {
  id: string;
  business_id: string;
  name: string;
  description?: string;
  strategy: ChannelStrategy;
  target_audience: {
    lead_ids?: string[];
    segment_id?: string;
    filters?: LeadFilters;
    total_recipients: number;
  };
  content: ChannelContent[];
  status: CampaignStatus;
  scheduled_start?: string;
  actual_start?: string;
  completed_at?: string;
  metrics: CampaignMetrics;
  ai_optimization_enabled: boolean;
  ab_testing?: ABTestConfig;
  budget?: {
    total: number;
    per_channel: Record<ChannelType, number>;
    spent: number;
  };
  created_at: string;
  updated_at: string;
}

export interface CampaignMetrics {
  total_sent: number;
  total_delivered: number;
  total_opened: number;
  total_clicked: number;
  total_replied: number;
  total_converted: number;
  by_channel: Record<ChannelType, ChannelMetrics>;
  engagement_score: number;
  roi?: number;
}

export interface ChannelMetrics {
  sent: number;
  delivered: number;
  opened?: number;
  clicked?: number;
  replied: number;
  bounced: number;
  unsubscribed?: number;
  cost?: number;
  avg_response_time?: number;
}

export interface ABTestConfig {
  variants: ABTestVariant[];
  split_percentage: number[];
  winning_criteria: 'open_rate' | 'click_rate' | 'reply_rate' | 'conversion_rate';
  test_duration_hours: number;
  auto_select_winner: boolean;
}

export interface ABTestVariant {
  id: string;
  name: string;
  channel_content: ChannelContent[];
  metrics?: CampaignMetrics;
}

export interface ChannelMessage {
  id: string;
  campaign_id?: string;
  business_id: string;
  lead_id: string;
  contact_id?: string;
  channel: ChannelType;
  direction: 'outbound' | 'inbound';
  status: MessageStatus;
  content: {
    subject?: string;
    body: string;
    attachments?: Attachment[];
    metadata?: Record<string, any>;
  };
  sent_at?: string;
  delivered_at?: string;
  opened_at?: string;
  clicked_at?: string;
  replied_at?: string;
  bounce_reason?: string;
  error_message?: string;
  thread_id?: string;
  parent_message_id?: string;
  ai_generated: boolean;
  personalization_score?: number;
  engagement_score?: number;
  created_at: string;
  updated_at: string;
}

export interface EmailChannel {
  provider: 'sendgrid' | 'aws_ses' | 'mailgun' | 'resend' | 'custom';
  from_address: string;
  from_name: string;
  reply_to?: string;
  tracking_domain?: string;
  unsubscribe_url?: string;
  custom_headers?: Record<string, string>;
  daily_limit?: number;
  hourly_limit?: number;
}

export interface SMSChannel {
  provider: 'twilio' | 'messagebird' | 'vonage' | 'aws_sns' | 'custom';
  from_number: string;
  country_code: string;
  messaging_service_id?: string;
  opt_out_keywords?: string[];
  character_limit: number;
  supports_mms: boolean;
}

export interface LinkedInChannel {
  connection_status: 'not_connected' | 'pending' | 'connected';
  automation_enabled: boolean;
  daily_connection_limit: number;
  daily_message_limit: number;
  use_sales_navigator: boolean;
  profile_views_enabled: boolean;
}

export interface WhatsAppChannel {
  provider: 'twilio' | 'meta_api' | 'messagebird' | 'custom';
  business_phone: string;
  business_id: string;
  template_namespace?: string;
  verified: boolean;
  quality_rating?: 'green' | 'yellow' | 'red';
}

export interface ChannelPreferences {
  lead_id: string;
  preferred_channels: ChannelType[];
  blacklisted_channels: ChannelType[];
  best_time_to_contact?: string;
  timezone?: string;
  language_preference?: string;
  communication_frequency?: 'high' | 'medium' | 'low' | 'minimal';
  opted_out: boolean;
  opt_out_reason?: string;
  last_updated: string;
}

export interface OmnichannelTemplate {
  id: string;
  business_id: string;
  name: string;
  description?: string;
  category: 'cold_outreach' | 'follow_up' | 'nurture' | 'win_back' | 'onboarding' | 'announcement' | 'custom';
  channels: ChannelType[];
  content_templates: Record<ChannelType, ChannelContentTemplate>;
  variables: TemplateVariable[];
  performance_stats?: {
    usage_count: number;
    avg_open_rate: number;
    avg_reply_rate: number;
    avg_conversion_rate: number;
  };
  active: boolean;
  created_at: string;
  updated_at: string;
}

export interface ChannelContentTemplate {
  subject_template?: string;
  body_template: string;
  cta_template?: CallToAction;
  tone: 'formal' | 'casual' | 'friendly' | 'urgent' | 'educational';
  max_length?: number;
  required_variables: string[];
}

export interface TemplateVariable {
  name: string;
  type: 'text' | 'number' | 'date' | 'boolean' | 'list';
  description?: string;
  default_value?: any;
  required: boolean;
  source?: 'lead' | 'company' | 'custom' | 'ai_generated';
}

// Request/Response types for Omnichannel operations
export interface CreateCampaignRequest {
  name: string;
  lead_ids?: string[];
  segment_id?: string;
  filters?: LeadFilters;
  channels?: ChannelType[];
  template_id?: string;
  custom_content?: ChannelContent[];
  scheduled_start?: string;
  ai_optimization?: boolean;
  ab_testing?: ABTestConfig;
}

export interface SendMessageRequest {
  lead_id: string;
  channel: ChannelType;
  content: Partial<ChannelContent>;
  send_immediately?: boolean;
  campaign_id?: string;
}

export interface ChannelHealthCheck {
  channel: ChannelType;
  status: 'healthy' | 'degraded' | 'down';
  last_checked: string;
  metrics: {
    success_rate: number;
    avg_latency_ms: number;
    daily_quota_used: number;
    daily_quota_limit: number;
  };
  issues?: string[];
}

export interface Company {
  id: string;
  business_id: string;
  name: string;
  domain?: string;
  industry?: string;
  size_range?: CompanySize;
  revenue_range?: RevenueRange;
  ai_summary?: string;
  ai_pain_points?: string;
  ai_icp_score?: number; // 0-100
  technologies?: string; // JSON string
  funding?: string; // JSON string
  news?: string; // JSON string
  social_profiles?: string; // JSON string
  created_at: string;
  updated_at: string;
}

export interface Contact {
  id: string;
  business_id: string;
  company_id?: string;
  email: string;
  phone?: string;
  first_name?: string;
  last_name?: string;
  title?: string;
  seniority_level?: SeniorityLevel;
  department?: Department;
  linkedin_url?: string;
  ai_personality?: string;
  ai_communication_style?: string;
  ai_interests?: string; // JSON string
  verified_phone: boolean;
  verified_email: boolean;
  timezone?: string;
  preferred_contact_method?: ContactMethod;
  created_at: string;
  updated_at: string;

  // Joined fields from company
  company_name?: string;
  company_domain?: string;
}

export interface Lead {
  id: string;
  business_id: string;
  contact_id?: string;
  company_id?: string;
  source: string;
  source_campaign?: string;
  status: LeadStatus;
  ai_qualification_score?: number; // 0-100
  ai_qualification_summary?: string;
  ai_next_best_action?: string;
  ai_predicted_value?: number;
  ai_close_probability?: number; // 0-1
  ai_estimated_close_date?: string;
  assigned_to?: string;
  assigned_type: AssignedType;
  created_at: string;
  updated_at: string;

  // Joined fields
  first_name?: string;
  last_name?: string;
  email?: string;
  contact_title?: string;
  company_name?: string;
  company_domain?: string;
}

export interface Conversation {
  id: string;
  business_id: string;
  lead_id?: string;
  contact_id?: string;
  type: ConversationType;
  direction: ConversationDirection;
  participant_type: ParticipantType;
  subject?: string;
  transcript?: string;
  ai_summary?: string;
  ai_sentiment?: Sentiment;
  ai_objections?: string; // JSON string
  ai_commitments?: string; // JSON string
  ai_next_steps?: string; // JSON string
  duration_seconds?: number;
  recording_url?: string;
  external_id?: string;
  metadata?: string; // JSON string
  created_at: string;
}

export interface AITask {
  id: string;
  business_id: string;
  type: string;
  priority: number; // 1-10
  payload: string; // JSON string
  status: AITaskStatus;
  assigned_agent?: string;
  attempts: number;
  max_attempts: number;
  last_error?: string;
  scheduled_at?: string;
  started_at?: string;
  completed_at?: string;
  expires_at?: string;
  created_at: string;
  updated_at: string;
}

export interface LeadActivity {
  id: string;
  business_id: string;
  lead_id: string;
  contact_id?: string;
  type: ActivityType;
  description: string;
  outcome?: Outcome;
  ai_generated: boolean;
  metadata?: string; // JSON string
  created_by?: string;
  created_at: string;
}

export interface EmailSequence {
  id: string;
  business_id: string;
  name: string;
  description?: string;
  trigger_type: TriggerType;
  trigger_conditions?: string; // JSON string
  is_active: boolean;
  ai_optimization: boolean;
  created_at: string;
  updated_at: string;
}

export interface EmailSequenceStep {
  id: string;
  sequence_id: string;
  step_order: number;
  delay_hours: number;
  subject_template: string;
  body_template: string;
  ai_personalization: boolean;
  is_active: boolean;
  created_at: string;
}

export interface LeadScoringRule {
  id: string;
  business_id: string;
  name: string;
  category: ScoringCategory;
  condition_field: string;
  condition_operator: ConditionOperator;
  condition_value: string;
  score_points: number;
  is_active: boolean;
  created_at: string;
}

// Enums and Union Types
export type CompanySize = '1-10' | '11-50' | '51-200' | '201-500' | '501-1000' | '1000+';

export type RevenueRange = '0-1M' | '1M-5M' | '5M-10M' | '10M-50M' | '50M-100M' | '100M+';

export type SeniorityLevel =
  | 'individual_contributor'
  | 'team_lead'
  | 'manager'
  | 'director'
  | 'vp'
  | 'c_level'
  | 'founder';

export type Department =
  | 'engineering'
  | 'sales'
  | 'marketing'
  | 'hr'
  | 'finance'
  | 'operations'
  | 'legal'
  | 'executive'
  | 'other';

export type ContactMethod = 'email' | 'phone' | 'linkedin' | 'sms';

export type LeadStatus =
  | 'new'
  | 'qualifying'
  | 'qualified'
  | 'meeting_scheduled'
  | 'opportunity'
  | 'unqualified'
  | 'closed_won'
  | 'closed_lost';

export type AssignedType = 'ai' | 'human';

export type ConversationType = 'call' | 'email' | 'chat' | 'sms' | 'meeting' | 'demo';

export type ConversationDirection = 'inbound' | 'outbound';

export type ParticipantType = 'ai' | 'human' | 'mixed';

export type Sentiment = 'positive' | 'neutral' | 'negative';

export type AITaskStatus = 'pending' | 'processing' | 'completed' | 'failed' | 'cancelled';

export type ActivityType =
  | 'call'
  | 'email'
  | 'meeting'
  | 'note'
  | 'demo'
  | 'proposal'
  | 'contract'
  | 'ai_action';

export type Outcome = 'positive' | 'neutral' | 'negative';

export type TriggerType = 'lead_created' | 'status_change' | 'time_based' | 'behavior_based';

export type ScoringCategory = 'demographic' | 'firmographic' | 'behavioral' | 'engagement';

export type ConditionOperator = 'equals' | 'contains' | 'greater_than' | 'less_than' | 'in' | 'not_in';

// Structured JSON types for complex fields
export interface CompanyTechnologies {
  languages?: string[];
  frameworks?: string[];
  databases?: string[];
  cloud_providers?: string[];
  tools?: string[];
  detected_at?: string;
  confidence_score?: number;
}

export interface CompanyFunding {
  rounds?: Array<{
    round_type: string;
    amount: number;
    currency: string;
    date: string;
    investors?: string[];
  }>;
  total_funding?: number;
  currency?: string;
  last_round_date?: string;
  valuation?: number;
}

export interface CompanyNews {
  articles?: Array<{
    title: string;
    url: string;
    published_at: string;
    source: string;
    sentiment?: Sentiment;
    summary?: string;
  }>;
  last_updated?: string;
}

export interface SocialProfiles {
  linkedin?: string;
  twitter?: string;
  facebook?: string;
  instagram?: string;
  youtube?: string;
  github?: string;
  website?: string;
}

export interface ContactInterests {
  topics?: string[];
  industry_interests?: string[];
  technology_interests?: string[];
  pain_points?: string[];
  detected_from?: string[];
  last_updated?: string;
}

export interface ConversationObjections {
  objections?: Array<{
    type: string;
    description: string;
    severity: 'low' | 'medium' | 'high';
    response_provided?: boolean;
    resolved?: boolean;
  }>;
}

export interface ConversationCommitments {
  commitments?: Array<{
    type: string;
    description: string;
    deadline?: string;
    assignee?: string;
    status: 'pending' | 'in_progress' | 'completed' | 'overdue';
  }>;
}

export interface ConversationNextSteps {
  steps?: Array<{
    action: string;
    owner: string;
    deadline?: string;
    priority: 'low' | 'medium' | 'high';
    status: 'pending' | 'in_progress' | 'completed';
  }>;
}

// AI Task Payload Types
export interface ResearchCompanyPayload {
  company_id: string;
  depth: 'basic' | 'detailed' | 'comprehensive';
  focus_areas?: string[];
  update_existing?: boolean;
}

export interface QualifyLeadPayload {
  lead_id: string;
  criteria?: string[];
  include_company_research?: boolean;
  auto_assign?: boolean;
}

export interface SendFollowupPayload {
  lead_id: string;
  template_type: string;
  personalization_level: 'basic' | 'medium' | 'high';
  delay_hours?: number;
  ai_optimize?: boolean;
}

export interface AnalyzeConversationPayload {
  conversation_id: string;
  include_sentiment?: boolean;
  identify_objections?: boolean;
  extract_commitments?: boolean;
  suggest_next_steps?: boolean;
}

// Filter and Query Types
export interface LeadFilters {
  status?: LeadStatus[];
  assigned_to?: string[];
  source?: string[];
  ai_qualification_score_min?: number;
  ai_qualification_score_max?: number;
  created_after?: string;
  created_before?: string;
  company_id?: string;
  contact_id?: string;
  assigned_type?: AssignedType;
}

export interface ContactFilters {
  company_id?: string;
  department?: Department[];
  seniority_level?: SeniorityLevel[];
  verified_email?: boolean;
  verified_phone?: boolean;
  has_linkedin?: boolean;
}

export interface ConversationFilters {
  lead_id?: string;
  contact_id?: string;
  type?: ConversationType[];
  participant_type?: ParticipantType[];
  sentiment?: Sentiment[];
  date_after?: string;
  date_before?: string;
}

export interface PaginationOptions {
  page?: number;
  limit?: number;
  sortBy?: string;
  sortOrder?: 'ASC' | 'DESC';
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

// API Response Types
export interface CRMResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  timestamp?: string;
}

export interface LeadMetrics {
  total_leads: number;
  new_leads: number;
  qualified_leads: number;
  won_leads: number;
  avg_qualification_score: number;
  total_predicted_value: number;
  conversion_rate?: number;
  avg_deal_size?: number;
}

export interface ContactMetrics {
  total_contacts: number;
  verified_contacts: number;
  contacts_with_linkedin: number;
  top_companies: Array<{
    company_name: string;
    contact_count: number;
  }>;
  department_breakdown: Record<Department, number>;
}

export interface AITaskMetrics {
  pending_tasks: number;
  processing_tasks: number;
  completed_tasks_today: number;
  failed_tasks_today: number;
  avg_processing_time: number;
  success_rate: number;
}

// Event Types for Real-time Updates
export interface CRMEvent {
  type: 'lead_created' | 'lead_updated' | 'contact_created' | 'conversation_started' | 'ai_task_completed';
  timestamp: string;
  business_id: string;
  data: any;
  source: 'ai' | 'human' | 'system';
}

// Webhook Types
export interface WebhookPayload {
  event: CRMEvent;
  webhook_id: string;
  delivery_attempt: number;
  signature: string;
}

// Qualification Types for BANT methodology
export interface QualificationCriteria {
  question: string;
  required: boolean;
  extractor: (text: string) => QualificationAnswer;
  weight?: number; // For scoring, defaults to 1
}

export interface QualificationAnswer {
  value: string | number | boolean;
  confidence: number; // 0-1 scale
  source: 'transcript' | 'direct_question' | 'inferred';
  extractedAt: string;
  rawText?: string;
}

export interface BANTQualification {
  budget: QualificationAnswer | null;
  authority: QualificationAnswer | null;
  need: QualificationAnswer | null;
  timeline: QualificationAnswer | null;
}

export interface QualificationResult {
  leadId: string;
  overall_score: number; // 0-100
  bant_data: BANTQualification;
  qualification_status: QualificationStatus;
  next_questions: string[];
  confidence_level: number; // 0-1
  qualified_at?: string;
  qualification_summary: string;
  ai_insights: {
    buying_signals: string[];
    objections: string[];
    pain_points: string[];
    decision_timeline: string;
    budget_indicators: string[];
    authority_level: AuthorityLevel;
  };
}

export interface ConversationContext {
  leadId: string;
  contactId?: string;
  transcript: string;
  messages: Array<{
    role: 'ai' | 'human';
    content: string;
    timestamp: string;
  }>;
  metadata?: {
    callDuration?: number;
    sentiment?: Sentiment;
    topics?: string[];
  };
}

export type QualificationStatus =
  | 'not_started'
  | 'in_progress'
  | 'qualified'
  | 'unqualified'
  | 'needs_review';

export type AuthorityLevel =
  | 'no_authority'
  | 'influencer'
  | 'decision_maker'
  | 'economic_buyer'
  | 'champion';

export type BudgetRange =
  | 'under_10k'
  | '10k_25k'
  | '25k_50k'
  | '50k_100k'
  | '100k_250k'
  | '250k_500k'
  | '500k_plus'
  | 'undefined';

export type TimelineUrgency =
  | 'immediate'
  | 'this_quarter'
  | 'next_quarter'
  | 'this_year'
  | 'next_year'
  | 'no_timeline';

// AI Task Payload for Qualification
export interface QualifyLeadTaskPayload {
  lead_id: string;
  conversation_ids?: string[];
  qualification_criteria?: Partial<QualificationCriteria>[];
  force_requalification?: boolean;
  conversation_context?: ConversationContext;
}

// Meeting Management Types
export interface Meeting {
  id: string;
  business_id: string;
  lead_id: string;
  contact_id?: string;
  title: string;
  description?: string;
  meeting_type: MeetingType;
  status: MeetingStatus;
  scheduled_start: string; // ISO timestamp
  scheduled_end: string; // ISO timestamp
  timezone: string;
  location?: string;
  meeting_url?: string; // For virtual meetings
  calendar_event_id?: string; // External calendar ID
  attendees: MeetingAttendee[];
  agenda?: string;
  ai_generated_agenda?: boolean;
  booking_source: BookingSource;
  booking_method: BookingMethod;
  confirmation_sent: boolean;
  reminder_sent: boolean;
  no_show: boolean;
  cancelled_at?: string;
  cancellation_reason?: string;
  rescheduled_from?: string; // Previous meeting ID
  notes?: string;
  outcome?: MeetingOutcome;
  follow_up_actions?: string; // JSON string
  recording_url?: string;
  created_at: string;
  updated_at: string;
}

export interface MeetingAttendee {
  email: string;
  name?: string;
  role: AttendeeRole;
  status: AttendeeStatus;
  optional: boolean;
}

export interface CalendarSlot {
  start: string; // ISO timestamp
  end: string; // ISO timestamp
  timezone: string;
  available: boolean;
  busy_reason?: string;
  calendar_owner?: string;
}

export interface ScheduleNegotiation {
  id: string;
  lead_id: string;
  conversation_id: string;
  proposed_slots: CalendarSlot[];
  lead_preferences?: {
    preferred_times?: string[]; // e.g., ["morning", "afternoon"]
    preferred_days?: string[]; // e.g., ["monday", "tuesday"]
    duration_preference?: number; // minutes
    meeting_type_preference?: MeetingType;
    timezone?: string;
  };
  negotiation_rounds: NegotiationRound[];
  final_agreed_slot?: CalendarSlot;
  status: NegotiationStatus;
  expires_at: string;
  created_at: string;
  updated_at: string;
}

export interface NegotiationRound {
  round_number: number;
  ai_proposal: {
    slots: CalendarSlot[];
    reasoning: string;
    persuasion_strategy?: string;
  };
  lead_response?: {
    response_type: 'accept' | 'counter' | 'reject' | 'request_different';
    feedback: string;
    counter_proposal?: CalendarSlot[];
  };
  timestamp: string;
}

export interface MeetingBookingRequest {
  lead_id: string;
  conversation_id?: string;
  meeting_type: MeetingType;
  duration_minutes?: number;
  preferred_slots?: CalendarSlot[];
  timezone?: string;
  ai_negotiation_enabled?: boolean;
  auto_confirm?: boolean;
  send_calendar_invite?: boolean;
}

export interface MeetingTemplate {
  id: string;
  business_id: string;
  name: string;
  meeting_type: MeetingType;
  duration_minutes: number;
  description_template: string;
  agenda_template?: string;
  location_type: 'virtual' | 'in_person' | 'phone';
  default_location?: string;
  auto_generate_meeting_url: boolean;
  buffer_time_before?: number; // minutes
  buffer_time_after?: number; // minutes
  advance_notice_hours: number;
  max_days_in_advance: number;
  working_hours: {
    start: string; // HH:MM format
    end: string; // HH:MM format
    days: WeekDay[];
  };
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

// Meeting-related Enums
export type MeetingType =
  | 'discovery_call'
  | 'demo'
  | 'consultation'
  | 'follow_up'
  | 'closing_call'
  | 'technical_review'
  | 'onboarding'
  | 'check_in'
  | 'custom';

export type MeetingStatus =
  | 'scheduled'
  | 'confirmed'
  | 'in_progress'
  | 'completed'
  | 'cancelled'
  | 'no_show'
  | 'rescheduled';

export type AttendeeRole =
  | 'host'
  | 'lead'
  | 'sales_rep'
  | 'technical_contact'
  | 'decision_maker'
  | 'observer';

export type AttendeeStatus =
  | 'pending'
  | 'accepted'
  | 'declined'
  | 'tentative'
  | 'no_response';

export type BookingSource =
  | 'ai_conversation'
  | 'manual_booking'
  | 'calendar_link'
  | 'email_reply'
  | 'website_form'
  | 'phone_call';

export type BookingMethod =
  | 'ai_negotiated'
  | 'instant_booking'
  | 'manual_confirmation'
  | 'calendar_integration';

export type NegotiationStatus =
  | 'in_progress'
  | 'agreed'
  | 'failed'
  | 'expired'
  | 'cancelled';

export type MeetingOutcome =
  | 'qualified'
  | 'needs_follow_up'
  | 'closed_won'
  | 'closed_lost'
  | 'rescheduled'
  | 'no_show'
  | 'cancelled';

export type WeekDay =
  | 'monday'
  | 'tuesday'
  | 'wednesday'
  | 'thursday'
  | 'friday'
  | 'saturday'
  | 'sunday';

// Calendar Integration Types
export interface CalendarProvider {
  type: 'google' | 'outlook' | 'caldav' | 'exchange';
  user_id: string;
  access_token?: string;
  refresh_token?: string;
  calendar_id?: string;
  webhook_url?: string;
  sync_enabled: boolean;
  last_sync: string;
}

export interface CalendarEvent {
  external_id: string;
  title: string;
  description?: string;
  start: string;
  end: string;
  timezone: string;
  location?: string;
  attendees: string[];
  busy: boolean;
  recurring: boolean;
  provider: string;
}

// AI Task Payload for Meeting Booking
export interface BookMeetingTaskPayload {
  booking_request: MeetingBookingRequest;
  available_slots: CalendarSlot[];
  lead_context?: {
    qualification_data?: any;
    previous_interactions?: string[];
    preferred_communication_style?: string;
  };
}

// Voicemail Management Types
export interface Voicemail {
  id: string;
  business_id: string;
  lead_id: string;
  contact_id?: string;
  call_id?: string; // Reference to the call that triggered voicemail
  attempt_number: number;
  voicemail_type: VoicemailType;
  message_text: string;
  message_duration_seconds: number;
  audio_url?: string;
  transcription?: string;
  ai_generated: boolean;
  personalization_level: PersonalizationLevel;
  voice_settings: VoiceSettings;
  delivery_status: VoicemailDeliveryStatus;
  delivered_at?: string;
  listened: boolean;
  listened_at?: string;
  response_received: boolean;
  response_type?: VoicemailResponseType;
  response_timestamp?: string;
  follow_up_scheduled: boolean;
  follow_up_time?: string;
  sentiment_score?: number; // 0-1 scale for message sentiment
  effectiveness_score?: number; // AI-calculated effectiveness score
  created_at: string;
  updated_at: string;
}

export interface VoicemailTemplate {
  id: string;
  business_id: string;
  name: string;
  voicemail_type: VoicemailType;
  attempt_range: {
    min: number;
    max: number;
  };
  message_template: string;
  personalization_fields: string[]; // Fields that can be personalized
  voice_settings: VoiceSettings;
  call_to_action: string;
  urgency_level: UrgencyLevel;
  max_duration_seconds: number;
  follow_up_delay_hours: number;
  is_active: boolean;
  success_rate?: number; // Historical success rate
  created_at: string;
  updated_at: string;
}

export interface VoicemailCampaign {
  id: string;
  business_id: string;
  name: string;
  description?: string;
  target_segment?: string; // Lead segment to target
  campaign_type: VoicemailCampaignType;
  status: CampaignStatus;
  templates: string[]; // Array of template IDs
  schedule: {
    start_date: string;
    end_date?: string;
    time_windows: TimeWindow[];
    timezone: string;
    max_attempts_per_lead: number;
    retry_delay_hours: number;
  };
  ai_optimization: boolean;
  performance_metrics?: {
    total_sent: number;
    total_delivered: number;
    total_listened: number;
    response_rate: number;
    conversion_rate: number;
  };
  created_at: string;
  updated_at: string;
}

export interface VoiceSettings {
  voice: VoiceType;
  pace: VoicePace;
  emotion: VoiceEmotion;
  pitch?: number; // -1 to 1 scale
  volume?: number; // 0 to 1 scale
  language: string;
  accent?: string;
}

export interface TimeWindow {
  day_of_week: WeekDay;
  start_time: string; // HH:MM format
  end_time: string; // HH:MM format
}

export interface VoicemailAnalytics {
  voicemail_id: string;
  lead_id: string;
  call_duration_before_voicemail?: number;
  ring_duration?: number;
  voicemail_prompt_detected: boolean;
  beep_detected: boolean;
  message_clarity_score: number; // 0-1 scale
  background_noise_level: number; // 0-1 scale
  delivery_confidence: number; // 0-1 scale
  ai_insights?: {
    optimal_call_time?: string;
    recommended_approach?: string;
    lead_availability_pattern?: string[];
  };
  created_at: string;
}

export interface VoicemailFollowUp {
  id: string;
  voicemail_id: string;
  lead_id: string;
  follow_up_type: FollowUpType;
  scheduled_time: string;
  actual_time?: string;
  status: FollowUpStatus;
  method: ContactMethod;
  message?: string;
  outcome?: FollowUpOutcome;
  next_action?: string;
  created_at: string;
  updated_at: string;
}

// Voicemail-related Enums
export type VoicemailType =
  | 'initial_outreach'
  | 'follow_up'
  | 'appointment_reminder'
  | 'missed_meeting'
  | 'proposal_follow_up'
  | 'nurture'
  | 'win_back'
  | 'thank_you'
  | 'urgent'
  | 'custom';

export type VoicemailDeliveryStatus =
  | 'pending'
  | 'delivered'
  | 'failed'
  | 'partial' // Started but cut off
  | 'voicemail_full'
  | 'no_voicemail_detected';

export type VoicemailResponseType =
  | 'callback'
  | 'email_reply'
  | 'text_reply'
  | 'meeting_booked'
  | 'unsubscribe'
  | 'not_interested';

export type PersonalizationLevel =
  | 'generic'
  | 'basic'
  | 'moderate'
  | 'high'
  | 'hyper_personalized';

export type VoiceType =
  | 'professional_male'
  | 'professional_female'
  | 'friendly_male'
  | 'friendly_female'
  | 'authoritative'
  | 'conversational'
  | 'youthful'
  | 'mature'
  | 'custom';

export type VoicePace =
  | 'slow'
  | 'moderate'
  | 'normal'
  | 'quick'
  | 'dynamic'; // Varies based on content

export type VoiceEmotion =
  | 'neutral'
  | 'friendly'
  | 'enthusiastic'
  | 'professional'
  | 'empathetic'
  | 'urgent'
  | 'warm';

export type UrgencyLevel =
  | 'low'
  | 'medium'
  | 'high'
  | 'critical';

export type VoicemailCampaignType =
  | 'cold_outreach'
  | 'lead_nurture'
  | 're_engagement'
  | 'event_promotion'
  | 'product_launch'
  | 'follow_up_sequence';

export type FollowUpType =
  | 'callback'
  | 'email'
  | 'text'
  | 'linkedin'
  | 'meeting_booking'
  | 'proposal_send'
  | 'demo_schedule';

export type FollowUpStatus =
  | 'scheduled'
  | 'completed'
  | 'cancelled'
  | 'overdue'
  | 'rescheduled';

export type FollowUpOutcome =
  | 'successful'
  | 'no_response'
  | 'not_interested'
  | 'callback_requested'
  | 'meeting_scheduled'
  | 'unsubscribe';

// Create/Update interfaces for CRM entities
export interface CreateCompany {
  name: string;
  domain?: string;
  industry?: string;
  size?: string;
  revenue?: number;
  description?: string;
  website?: string;
  phone?: string;
  email?: string;
  address?: string;
  city?: string;
  state?: string;
  country?: string;
  postal_code?: string;
  technologies?: CompanyTechnologies;
  social_profiles?: SocialProfiles;
  metadata?: Record<string, any>;
}

export interface CreateContact {
  email: string;
  first_name?: string;
  last_name?: string;
  title?: string;
  company_id?: string;
  phone?: string;
  linkedin?: string;
  interests?: ContactInterests;
  social_profiles?: SocialProfiles;
  metadata?: Record<string, any>;
}

export interface CreateLead {
  email: string;
  first_name?: string;
  last_name?: string;
  company_name?: string;
  title?: string;
  phone?: string;
  source?: string;
  status?: LeadStatus;
  score?: number;
  assigned_to?: string;
  tags?: string[];
  metadata?: Record<string, any>;
}

export interface CreateAITask {
  lead_id?: string;
  contact_id?: string;
  company_id?: string;
  type: string;
  description: string;
  priority?: 'low' | 'medium' | 'high' | 'critical';
  due_date?: string;
  assigned_to?: string;
  metadata?: Record<string, any>;
}

export interface VoicemailRequest {
  lead_id: string;
  campaign_id?: string;
  script_template?: string;
  voice_settings?: {
    voice_id?: string;
    emotion?: VoiceEmotion;
    pace?: VoicePace;
  };
  scheduling?: {
    send_at?: string;
    timezone?: string;
  };
  personalization?: Record<string, any>;
}

export interface VoicemailStats {
  total_sent: number;
  total_delivered: number;
  total_listened: number;
  avg_listen_duration: number;
  callbacks_received: number;
  conversion_rate: number;
  by_campaign?: Record<string, {
    sent: number;
    delivered: number;
    listened: number;
    callbacks: number;
  }>;
}

export interface VoicemailCampaignRequest {
  name: string;
  description?: string;
  lead_ids: string[];
  script_template: string;
  voice_settings?: {
    voice_id?: string;
    emotion?: VoiceEmotion;
    pace?: VoicePace;
  };
  scheduling?: {
    start_date?: string;
    end_date?: string;
    send_times?: string[];
    timezone?: string;
  };
  follow_up?: {
    enabled: boolean;
    delay_hours?: number;
    type?: FollowUpType;
  };
}

// Database interface for CRM operations
export interface CRMDatabase {
  companies: {
    create: (company: CreateCompany) => Promise<Company>;
    update: (id: string, company: Partial<Company>) => Promise<Company>;
    delete: (id: string) => Promise<void>;
    get: (id: string) => Promise<Company | null>;
    list: (filters?: any) => Promise<Company[]>;
  };
  contacts: {
    create: (contact: CreateContact) => Promise<Contact>;
    update: (id: string, contact: Partial<Contact>) => Promise<Contact>;
    delete: (id: string) => Promise<void>;
    get: (id: string) => Promise<Contact | null>;
    list: (filters?: any) => Promise<Contact[]>;
    search: (query: string) => Promise<Contact[]>;
  };
  leads: {
    create: (lead: CreateLead) => Promise<Lead>;
    update: (id: string, lead: Partial<Lead>) => Promise<Lead>;
    delete: (id: string) => Promise<void>;
    get: (id: string) => Promise<Lead | null>;
    list: (filters?: any) => Promise<Lead[]>;
    convert: (id: string, data: any) => Promise<Contact>;
  };
  conversations: {
    create: (conversation: any) => Promise<Conversation>;
    update: (id: string, conversation: Partial<Conversation>) => Promise<Conversation>;
    get: (id: string) => Promise<Conversation | null>;
    list: (filters?: any) => Promise<Conversation[]>;
  };
  voicemails: {
    create: (voicemail: any) => Promise<Voicemail>;
    update: (id: string, voicemail: Partial<Voicemail>) => Promise<Voicemail>;
    get: (id: string) => Promise<Voicemail | null>;
    list: (filters?: any) => Promise<Voicemail[]>;
  };
  activities: {
    create: (activity: any) => Promise<LeadActivity>;
    list: (filters?: any) => Promise<LeadActivity[]>;
  };
}

// Missing types that are being imported by other services
export interface Playbook {
  id: string;
  business_id: string;
  name: string;
  description?: string;
  sections: PlaybookSection[];
  performance: {
    winRate: number;
    adoptionRate: number;
    avgDealSize: number;
    conversionRate: number;
    averageDealSize?: number;
    salesCycle?: number;
    userFeedback?: number;
  };
  segment?: string;
  version?: number;
  active?: boolean;
  createdAt?: string;
  updatedAt?: string;
  created_at: string;
  updated_at: string;
}

export interface PlaybookSection {
  id: string;
  playbook_id: string;
  title: string;
  content: string;
  order: number;
  category: string;
  is_active: boolean;
  created_at: string;
  type?: string;
  lastUpdated?: string;
}

export interface CustomerSegment {
  id: string;
  business_id: string;
  name: string;
  description?: string;
  criteria: Record<string, any>;
  lead_count: number;
  performance_metrics: {
    conversion_rate: number;
    avg_deal_size: number;
    sales_cycle_days: number;
  };
  created_at: string;
  updated_at: string;
}

export interface Pattern {
  id: string;
  business_id: string;
  name: string;
  description?: string;
  pattern_type: string;
  type?: string;
  data: Record<string, any>;
  confidence_score: number;
  frequency: number;
  last_seen: string;
  created_at: string;
}

export interface Feedback {
  id: string;
  business_id: string;
  source: string;
  type: 'positive' | 'negative' | 'neutral' | 'usability';
  content: string;
  context?: Record<string, any>;
  rating?: number;
  created_at: string;
  playbookId?: string;
  comment?: string;
  category?: string;
  userId?: string;
  timestamp?: string;
}

export interface Strategy {
  id: string;
  business_id: string;
  name: string;
  description?: string;
  strategy_type: string;
  parameters: Record<string, any>;
  effectiveness_score: number;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

// Real-time sales coaching types
export interface CallStream {
  id: string;
  call_id: string;
  stream_type: 'audio' | 'transcript' | 'metadata';
  data: any;
  timestamp: string;
  coachingChannel?: string;
  on?: (event: string, callback: (data: any) => void) => void;
}

export interface TranscriptChunk {
  id: string;
  call_id: string;
  speaker: 'agent' | 'customer';
  text: string;
  timestamp: string;
  confidence: number;
  sentiment?: Sentiment;
}

export interface Situation {
  id: string;
  call_id: string;
  situation_type: string;
  description: string;
  severity: 'low' | 'medium' | 'high';
  detected_at: string;
  resolved: boolean;
  type?: string;
  objection?: string;
  competitor?: string;
  context?: string;
  buyingSignal?: string;
  painPoint?: string;
}

export interface Guidance {
  id: string;
  situation_id: string;
  guidance_type: string;
  content: string;
  priority: 'low' | 'medium' | 'high';
  provided_at: string;
}

export interface Battlecard {
  id: string;
  business_id: string;
  title: string;
  content: string;
  category: string;
  tags: string[];
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface PricingGuidance {
  id: string;
  business_id: string;
  product_id?: string;
  pricing_tier: string;
  guidance: string;
  conditions: Record<string, any>;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface CoachingTip {
  id: string;
  call_id: string;
  tip_type: string;
  content: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  provided_at: string;
  acknowledged: boolean;
  type?: string;
}

export interface LiveCoachingMessage {
  id: string;
  call_id: string;
  message_type: 'tip' | 'warning' | 'suggestion' | 'battlecard';
  content: string | CoachingTip | Guidance | Battlecard | PricingGuidance;
  priority: 'low' | 'medium' | 'high' | 'critical';
  timestamp: string | number;
  delivered: boolean;
}

export interface Participant {
  id: string;
  call_id: string;
  name: string;
  role: 'agent' | 'customer' | 'observer';
  email?: string;
  phone?: string;
  joined_at: string;
  left_at?: string;
}

// Add missing properties to Lead interface
export interface LeadExtended extends Lead {
  company_size?: string;
  industry?: string;
  title?: string;
  ai_intent_summary?: string;
  ai_engagement_score?: number;
}

