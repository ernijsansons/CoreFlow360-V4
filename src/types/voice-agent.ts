// AI Voice Agent Types for CoreFlow360
// Real-time phone conversations with instant lead calling

import type { Lead, Contact, Company } from './crm';

export interface VoiceAgentConfig {
  twilio: {
    account_sid: string;
    auth_token: string;
    phone_number: string;
    webhook_url: string;
    recording_enabled: boolean;
    machine_detection: boolean;
  };
  voice_synthesis: {
    provider: 'elevenlabs' | 'aws_polly' | 'google_tts';
    voice_id: string;
    stability: number;
    similarity_boost: number;
    api_key?: string;
  };
  ai_config: {
    model: string;
    temperature: number;
    max_tokens: number;
    system_prompt: string;
    conversation_timeout: number;
  };
  call_settings: {
    max_call_duration: number;
    answer_timeout: number;
    machine_detection_timeout: number;
    retry_attempts: number;
    retry_delay: number;
  };
}

export interface CallInitiationRequest {
  lead_id: string;
  priority: CallPriority;
  call_type: CallType;
  scheduled_at?: string;
  custom_script?: string;
  context?: CallContext;
}

export type CallPriority = 'low' | 'medium' | 'high' | 'urgent';
export type CallType = 'cold_outreach' | 'follow_up' | 'qualification' | 'demo_booking' | 'support';
export type CallStatus = 'initiated' | 'ringing' | 'answered'
  | 'busy' | 'no_answer' | 'failed' | 'completed' | 'voicemail';
export type ConversationState = 'greeting' | 'qualification'
  | 'objection_handling' | 'demo_scheduling' | 'closing' | 'completed';

export interface CallContext {
  previous_interactions: PreviousInteraction[];
  enrichment_data?: any;
  campaign_context?: string;
  referral_source?: string;
  urgency_reason?: string;
}

export interface PreviousInteraction {
  type: 'email' | 'call' | 'chat' | 'meeting';
  date: string;
  summary: string;
  outcome: string;
  next_steps?: string[];
}

export interface CallResult {
  call_id: string;
  lead_id: string;
  status: CallStatus;
  duration_seconds: number;
  answered: boolean;
  voicemail_detected: boolean;
  machine_detected: boolean;
  conversation_summary?: ConversationSummary;
  next_actions: NextAction[];
  recording_url?: string;
  transcript?: ConversationTranscript;
  cost: number;
  created_at: string;
  completed_at?: string;
}

export interface ConversationSummary {
  outcome: ConversationOutcome;
  key_points: string[];
  objections_raised: Objection[];
  interest_level: 'low' | 'medium' | 'high';
  qualification_status: QualificationStatus;
  next_meeting_scheduled?: MeetingDetails;
  follow_up_required: boolean;
  follow_up_timing?: string;
  sentiment: 'positive' | 'neutral' | 'negative';
  lead_quality_score: number; // 0-100
}

export type ConversationOutcome =
  | 'meeting_scheduled'
  | 'interested_follow_up'
  | 'not_interested'
  | 'wrong_person'
  | 'callback_requested'
  | 'voicemail_left'
  | 'hung_up'
  | 'qualified'
  | 'disqualified';

export interface Objection {
  type: ObjectionType;
  objection: string;
  response_given: string;
  resolved: boolean;
  follow_up_needed: boolean;
}

export type ObjectionType =
  | 'price'
  | 'timing'
  | 'authority'
  | 'need'
  | 'competitor'
  | 'budget'
  | 'trust'
  | 'feature'
  | 'other';

export interface QualificationStatus {
  budget: QualificationLevel;
  authority: QualificationLevel;
  need: QualificationLevel;
  timeline: QualificationLevel;
  overall_score: number; // 0-100
  qualified: boolean;
}

export type QualificationLevel = 'unknown' | 'low' | 'medium' | 'high';

export interface MeetingDetails {
  type: 'demo' | 'discovery' | 'proposal' | 'follow_up';
  proposed_times: string[];
  duration_minutes: number;
  attendees: string[];
  agenda_items: string[];
  calendar_link?: string;
}

export interface NextAction {
  action: string;
  priority: 'low' | 'medium' | 'high';
  due_date?: string;
  assigned_to?: string;
  description: string;
  automated: boolean;
}

export interface ConversationTranscript {
  turns: ConversationTurn[];
  start_time: string;
  end_time: string;
  total_duration: number;
  speaker_time: {
    human: number;
    ai: number;
  };
  words_per_minute: {
    human: number;
    ai: number;
  };
}

export interface ConversationTurn {
  id: string;
  timestamp: string;
  speaker: 'human' | 'ai';
  text: string;
  confidence: number;
  duration_ms: number;
  audio_url?: string;
  intent?: string;
  entities?: ExtractedEntity[];
  sentiment?: 'positive' | 'neutral' | 'negative';
}

export interface ExtractedEntity {
  type: EntityType;
  value: string;
  confidence: number;
  start_pos: number;
  end_pos: number;
}

export type EntityType =
  | 'person_name'
  | 'company_name'
  | 'date'
  | 'time'
  | 'money'
  | 'phone'
  | 'email'
  | 'product'
  | 'location'
  | 'competitor';

export interface CallScript {
  id: string;
  name: string;
  call_type: CallType;
  opening: ScriptSection;
  qualification: ScriptSection;
  objection_handling: Record<ObjectionType, ScriptResponse[]>;
  closing: ScriptSection;
  voicemail: ScriptSection;
  personalization_variables: string[];
  success_metrics: SuccessMetric[];
}

export interface ScriptSection {
  intro: string;
  key_points: string[];
  questions: string[];
  transitions: string[];
  fallbacks: string[];
}

export interface ScriptResponse {
  trigger: string;
  response: string;
  follow_up?: string;
  escalation?: boolean;
}

export interface SuccessMetric {
  name: string;
  target_value: number;
  measurement: string;
}

export interface VoiceSettings {
  voice_id: string;
  stability: number; // 0-1
  similarity_boost: number; // 0-1
  speed: number; // 0.5-2.0
  pitch: number; // -20 to 20
  style: number; // 0-100
  use_speaker_boost: boolean;
}

export interface TwilioCallConfig {
  to: string;
  from: string;
  url: string;
  method: 'GET' | 'POST';
  status_callback?: string;
  status_callback_event?: string[];
  status_callback_method?: 'GET' | 'POST';
  send_digits?: string;
  timeout?: number;
  record?: boolean;
  recording_channels?: 'mono' | 'dual';
  recording_status_callback?: string;
  machine_detection?: 'Enable' | 'DetectMessageEnd';
  machine_detection_timeout?: number;
  machine_detection_speech_threshold?: number;
  machine_detection_speech_end_threshold?: number;
  machine_detection_silence_timeout?: number;
  answering_machine_detection_config?: AnsweringMachineConfig;
}

export interface AnsweringMachineConfig {
  beep_detection: boolean;
  speech_threshold: number;
  speech_end_threshold: number;
  silence_timeout: number;
  machine_detection_speech_threshold: number;
  machine_detection_speech_end_threshold: number;
  machine_detection_silence_timeout: number;
}

export interface CallAnalytics {
  call_id: string;
  lead_id: string;

  // Call metrics
  dial_time: number;
  ring_time: number;
  talk_time: number;
  total_duration: number;

  // Conversation metrics
  ai_talk_ratio: number; // percentage of time AI was talking
  interruptions: number;
  silence_periods: number;
  average_response_time: number;

  // Quality metrics
  audio_quality_score: number;
  transcription_confidence: number;
  conversation_flow_score: number;

  // Outcome metrics
  qualification_score: number;
  interest_score: number;
  objection_count: number;
  objections_resolved: number;

  // Business metrics
  call_cost: number;
  conversion_value: number;
  roi_estimate: number;
}

export interface VoiceAgentPerformance {
  time_period: string;
  total_calls: number;
  successful_calls: number;
  answer_rate: number;
  qualification_rate: number;
  meeting_booking_rate: number;
  average_call_duration: number;
  average_cost_per_call: number;
  average_qualification_score: number;
  top_objections: ObjectionStats[];
  conversion_funnel: ConversionFunnelStats;
}

export interface ObjectionStats {
  type: ObjectionType;
  frequency: number;
  resolution_rate: number;
  average_response_time: number;
}

export interface ConversionFunnelStats {
  calls_initiated: number;
  calls_answered: number;
  conversations_completed: number;
  qualified_leads: number;
  meetings_scheduled: number;
  deals_closed: number;
}

export interface RealTimeCallState {
  call_id: string;
  lead_id: string;
  status: CallStatus;
  state: ConversationState;
  current_intent: string;
  transcript_buffer: string;
  conversation_history: ConversationTurn[];
  detected_entities: ExtractedEntity[];
  qualification_progress: Partial<QualificationStatus>;
  objections_encountered: Objection[];
  next_questions: string[];
  call_start_time: string;
  last_activity_time: string;
}

export interface CallQueueItem {
  id: string;
  lead_id: string;
  priority: CallPriority;
  call_type: CallType;
  scheduled_at: string;
  retry_count: number;
  max_retries: number;
  context: CallContext;
  estimated_duration: number;
  created_at: string;
}

export interface VoiceAgentEvent {
  type: VoiceAgentEventType;
  call_id: string;
  lead_id: string;
  timestamp: string;
  data: any;
}

export type VoiceAgentEventType =
  | 'call_initiated'
  | 'call_ringing'
  | 'call_answered'
  | 'call_completed'
  | 'voicemail_detected'
  | 'machine_detected'
  | 'speech_detected'
  | 'objection_raised'
  | 'meeting_scheduled'
  | 'call_transferred'
  | 'call_failed';

export interface CallRecording {
  call_id: string;
  recording_url: string;
  duration: number;
  file_size: number;
  format: string;
  channels: 'mono' | 'dual';
  transcript_url?: string;
  analysis_url?: string;
  retention_expires_at: string;
}

export interface VoiceAgentMetrics {
  daily_stats: DailyCallStats;
  weekly_trends: WeeklyTrends;
  agent_performance: AgentPerformanceMetrics;
  cost_analysis: CostAnalysis;
}

export interface DailyCallStats {
  date: string;
  calls_initiated: number;
  calls_answered: number;
  calls_completed: number;
  average_duration: number;
  qualification_rate: number;
  meeting_booking_rate: number;
  total_cost: number;
}

export interface WeeklyTrends {
  week_start: string;
  call_volume_trend: number; // percentage change
  answer_rate_trend: number;
  qualification_trend: number;
  cost_efficiency_trend: number;
}

export interface AgentPerformanceMetrics {
  script_adherence_score: number;
  objection_handling_score: number;
  conversation_flow_score: number;
  personalization_score: number;
  overall_performance_score: number;
}

export interface CostAnalysis {
  cost_per_call: number;
  cost_per_qualified_lead: number;
  cost_per_meeting_booked: number;
  monthly_budget_utilization: number;
  roi_estimate: number;
}

// WebRTC and real-time communication types
export interface WebRTCConnection {
  id: string;
  call_id: string;
  peer_connection: any; // RTCPeerConnection in browser context
  audio_stream: any; // MediaStream
  data_channel: any; // RTCDataChannel
  connection_state: 'connecting' | 'connected' | 'disconnected' | 'failed';
}

export interface AudioProcessingConfig {
  sample_rate: number;
  bit_depth: number;
  channels: number;
  noise_suppression: boolean;
  echo_cancellation: boolean;
  automatic_gain_control: boolean;
  voice_activity_detection: boolean;
}

export interface SpeechToTextConfig {
  provider: 'google' | 'aws' | 'azure' | 'assemblyai';
  language: string;
  model: string;
  real_time: boolean;
  punctuation: boolean;
  profanity_filter: boolean;
  speaker_diarization: boolean;
  custom_vocabulary?: string[];
}

export interface TextToSpeechConfig {
  provider: 'elevenlabs' | 'aws_polly' | 'google_tts' | 'azure_tts';
  voice_id: string;
  language: string;
  speaking_rate: number;
  pitch: number;
  volume_gain_db: number;
  audio_encoding: 'mp3' | 'wav' | 'ogg' | 'pcm';
}

export interface ConversationFlowConfig {
  max_silence_duration: number;
  interruption_detection: boolean;
  sentiment_analysis: boolean;
  intent_recognition: boolean;
  entity_extraction: boolean;
  response_timeout: number;
  conversation_timeout: number;
  auto_hangup_conditions: string[];
}

export interface VoiceAgentResponse {
  success: boolean;
  call_id?: string;
  message: string;
  estimated_call_time?: number;
  cost_estimate?: number;
  queue_position?: number;
  error?: string;
}