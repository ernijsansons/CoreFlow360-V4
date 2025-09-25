// Enrichment Pipeline Types for CoreFlow360 AI-Native CRM
// Multi-source data enrichment with AI analysis

import type { Lead } from './crm';

export interface EnrichmentRequest {
  lead_id?: string;
  contact_id?: string;
  company_id?: string;
  email?: string;
  domain?: string;
  company_name?: string;
  linkedin_url?: string;
  phone?: string;
  priority: EnrichmentPriority;
  sources: EnrichmentSource[];
  force_refresh?: boolean;
}

export type EnrichmentPriority = 'low' | 'medium' | 'high' | 'urgent';
export type EnrichmentSource = 'clearbit' | 'apollo' | 'linkedin' |
  'hunter' | 'zoominfo' | 'news' | 'social' | 'github' | 'crunchbase';

export interface EnrichedLead extends Lead {
  enrichment_data: {
    company: CompanyEnrichment;
    contact: ContactEnrichment;
    social: SocialEnrichment;
    news: NewsEnrichment;
    ai_insights: AIInsights;
    enrichment_metadata: EnrichmentMetadata;
  };
}

export interface CompanyEnrichment {
  // Basic info
  legal_name?: string;
  domain?: string;
  website?: string;
  description?: string;
  founded_year?: number;
  industry?: string;
  sub_industry?: string;
  sector?: string;

  // Size and financials
  employee_count?: number;
  employee_range?: string;
  annual_revenue?: number;
  revenue_range?: string;
  funding_total?: number;
  funding_rounds?: FundingRound[];
  valuation?: number;

  // Location
  headquarters?: {
    address: string;
    city: string;
    state: string;
    country: string;
    postal_code: string;
    coordinates?: {
      lat: number;
      lng: number;
    };
  };
  locations?: CompanyLocation[];

  // Technology
  tech_stack?: TechStack;
  job_openings?: JobOpening[];

  // Social and web presence
  logo_url?: string;
  social_profiles?: SocialProfiles;
  seo_metrics?: SEOMetrics;

  // Contact info
  phone?: string;
  email_patterns?: string[];
  key_contacts?: KeyContact[];

  // Market data
  competitors?: string[];
  market_cap?: number;
  public_company?: boolean;
  ticker?: string;
  parent_company?: string;
  subsidiaries?: string[];
}

export interface ContactEnrichment {
  // Basic info
  full_name?: string;
  first_name?: string;
  last_name?: string;
  email?: string;
  personal_email?: string;
  phone?: string;
  mobile_phone?: string;

  // Professional info
  title?: string;
  seniority_level?: string;
  department?: string;
  employment_history?: Employment[];
  skills?: string[];
  education?: Education[];

  // Social profiles
  linkedin_url?: string;
  twitter_handle?: string;
  github_username?: string;
  personal_website?: string;

  // Location
  location?: {
    city: string;
    state: string;
    country: string;
    timezone: string;
  };

  // Engagement data
  email_deliverability?: EmailDeliverability;
  social_activity?: SocialActivity;
  professional_interests?: string[];

  // AI-generated insights
  personality_traits?: PersonalityTraits;
  communication_style?: CommunicationStyle;
  decision_making_style?: DecisionMakingStyle;
  influence_score?: number;
}

export interface SocialEnrichment {
  linkedin?: LinkedInData;
  twitter?: TwitterData;
  facebook?: FacebookData;
  instagram?: InstagramData;
  github?: GitHubData;
  personal_blog?: BlogData;
  professional_network?: NetworkData;
}

export interface NewsEnrichment {
  recent_news?: NewsArticle[];
  press_releases?: PressRelease[];
  funding_announcements?: FundingNews[];
  product_launches?: ProductNews[];
  executive_changes?: ExecutiveNews[];
  awards_recognition?: AwardNews[];
  partnership_news?: PartnershipNews[];
  sentiment_analysis?: NewsSentiment;
}

export interface AIInsights {
  // Lead scoring insights
  icp_fit_score: number; // 0-100
  buying_intent_score: number; // 0-100
  engagement_propensity: number; // 0-100
  conversion_probability: number; // 0-1

  // Qualification insights
  budget_indicators: BudgetIndicator[];
  authority_indicators: AuthorityIndicator[];
  need_indicators: NeedIndicator[];
  timeline_indicators: TimelineIndicator[];

  // Personalization insights
  pain_points: string[];
  value_propositions: string[];
  communication_preferences: CommunicationPreference[];
  meeting_best_times: MeetingTime[];

  // Competitive insights
  current_solutions: CurrentSolution[];
  competitor_relationships: CompetitorRelationship[];
  switching_probability: number; // 0-1

  // Recommendation engine
  recommended_approach: ApproachRecommendation;
  next_best_actions: NextBestAction[];
  personalized_messaging: PersonalizedMessage[];

  // Risk factors
  risk_factors: RiskFactor[];
  churn_indicators: ChurnIndicator[];

  // Opportunity insights
  upsell_opportunities: UpsellOpportunity[];
  cross_sell_opportunities: CrossSellOpportunity[];
  expansion_potential: ExpansionPotential;
}

export interface EnrichmentMetadata {
  enriched_at: string;
  sources_used: EnrichmentSource[];
  data_freshness: Record<EnrichmentSource, string>;
  confidence_scores: Record<string, number>;
  processing_time_ms: number;
  cost: {
    total_cost: number;
    cost_by_source: Record<EnrichmentSource, number>;
  };
  rate_limits: Record<EnrichmentSource, RateLimit>;
  errors: EnrichmentError[];
  next_refresh_at?: string;
}

// Supporting interfaces
export interface FundingRound {
  round_type: string;
  amount: number;
  currency: string;
  date: string;
  investors: string[];
  lead_investor?: string;
  valuation?: number;
  series?: string;
}

export interface CompanyLocation {
  type: 'headquarters' | 'office' | 'remote';
  address: string;
  city: string;
  state: string;
  country: string;
  employee_count?: number;
}

export interface TechStack {
  languages: string[];
  frameworks: string[];
  databases: string[];
  cloud_providers: string[];
  tools: string[];
  confidence_score: number;
  detected_at: string;
}

export interface JobOpening {
  title: string;
  department: string;
  location: string;
  posted_date: string;
  job_board: string;
  url: string;
  seniority_level: string;
}

export interface SocialProfiles {
  linkedin?: string;
  twitter?: string;
  facebook?: string;
  instagram?: string;
  youtube?: string;
  github?: string;
  angellist?: string;
  crunchbase?: string;
}

export interface SEOMetrics {
  domain_authority: number;
  page_authority: number;
  organic_traffic: number;
  organic_keywords: number;
  backlinks: number;
  referring_domains: number;
}

export interface KeyContact {
  name: string;
  title: string;
  email?: string;
  linkedin?: string;
  phone?: string;
  department: string;
  seniority_level: string;
}

export interface Employment {
  company: string;
  title: string;
  start_date: string;
  end_date?: string;
  duration_months: number;
  description?: string;
  location?: string;
  is_current: boolean;
}

export interface Education {
  institution: string;
  degree: string;
  field_of_study: string;
  start_date: string;
  end_date: string;
  gpa?: number;
  activities?: string[];
}

export interface EmailDeliverability {
  deliverable: boolean;
  confidence: number;
  risk_level: 'low' | 'medium' | 'high';
  email_type: 'personal' | 'work' | 'disposable' | 'role';
  mx_record_valid: boolean;
  smtp_valid: boolean;
  catch_all: boolean;
}

export interface SocialActivity {
  platform: string;
  follower_count: number;
  following_count: number;
  post_frequency: string;
  engagement_rate: number;
  last_activity: string;
  verified: boolean;
}

export interface PersonalityTraits {
  openness: number; // 0-1
  conscientiousness: number; // 0-1
  extraversion: number; // 0-1
  agreeableness: number; // 0-1
  neuroticism: number; // 0-1
  confidence_score: number;
}

export interface CommunicationStyle {
  preferred_channels: string[];
  formality_level: 'casual' | 'semi-formal' | 'formal';
  response_time_preference: string;
  meeting_preference: 'phone' | 'video' | 'in-person' | 'email';
  decision_speed: 'fast' | 'moderate' | 'slow';
}

export interface DecisionMakingStyle {
  style: 'analytical' | 'driver' | 'expressive' | 'amiable';
  influences: string[];
  decision_factors: string[];
  risk_tolerance: 'low' | 'medium' | 'high';
}

// AI Insights supporting types
export interface BudgetIndicator {
  type: 'explicit' | 'implicit' | 'inferred';
  indicator: string;
  confidence: number;
  estimated_budget?: number;
  budget_range?: string;
}

export interface AuthorityIndicator {
  type: 'title' | 'decision_history' | 'org_chart' | 'influence';
  indicator: string;
  confidence: number;
  authority_level: 'low' | 'medium' | 'high';
}

export interface NeedIndicator {
  category: string;
  pain_point: string;
  urgency: 'low' | 'medium' | 'high';
  evidence: string[];
  confidence: number;
}

export interface TimelineIndicator {
  type: 'explicit' | 'project_based' | 'budget_cycle' | 'inferred';
  timeline: string;
  urgency_score: number;
  evidence: string[];
}

export interface CommunicationPreference {
  channel: 'email' | 'phone' | 'linkedin' | 'text' | 'video';
  preference_score: number;
  best_times: string[];
  avoid_times: string[];
}

export interface MeetingTime {
  day_of_week: string;
  time_range: string;
  timezone: string;
  confidence: number;
}

export interface CurrentSolution {
  vendor: string;
  product: string;
  satisfaction_level: number; // 0-10
  contract_end_date?: string;
  pain_points: string[];
  switching_cost: 'low' | 'medium' | 'high';
}

export interface CompetitorRelationship {
  competitor: string;
  relationship_type: 'current_customer' | 'past_customer' | 'evaluating' | 'rejected';
  confidence: number;
  details: string;
}

export interface ApproachRecommendation {
  strategy: string;
  messaging_angle: string;
  value_props: string[];
  objection_handling: string[];
  next_steps: string[];
  success_probability: number;
}

export interface NextBestAction {
  action: string;
  priority: 'low' | 'medium' | 'high' | 'urgent';
  timing: string;
  context: string;
  expected_outcome: string;
  success_probability: number;
}

export interface PersonalizedMessage {
  channel: 'email' | 'linkedin' | 'phone' | 'text';
  message_type: 'cold_outreach' | 'follow_up' | 'nurture' | 'proposal';
  subject_line?: string;
  message: string;
  personalization_score: number;
  expected_response_rate: number;
}

export interface RiskFactor {
  type: 'budget' | 'authority' | 'competition' | 'timing' | 'fit';
  risk: string;
  severity: 'low' | 'medium' | 'high';
  mitigation_strategy: string;
  probability: number;
}

export interface ChurnIndicator {
  indicator: string;
  risk_level: 'low' | 'medium' | 'high';
  confidence: number;
  recommended_action: string;
}

export interface UpsellOpportunity {
  product: string;
  fit_score: number;
  revenue_potential: number;
  implementation_complexity: 'low' | 'medium' | 'high';
  timing: string;
}

export interface CrossSellOpportunity {
  product: string;
  department: string;
  champion_required: boolean;
  revenue_potential: number;
  success_probability: number;
}

export interface ExpansionPotential {
  additional_seats: number;
  new_departments: string[];
  geographic_expansion: string[];
  total_revenue_potential: number;
  timeline: string;
}

// Data source specific types
export interface LinkedInData {
  profile_url: string;
  headline: string;
  summary: string;
  experience: Employment[];
  education: Education[];
  skills: string[];
  connections: number;
  recommendations: number;
  activity_level: 'low' | 'medium' | 'high';
  premium_account: boolean;
}

export interface TwitterData {
  handle: string;
  follower_count: number;
  following_count: number;
  tweet_count: number;
  bio: string;
  verified: boolean;
  account_created: string;
  recent_tweets: Tweet[];
  engagement_metrics: TwitterEngagement;
}

export interface FacebookData {
  page_url?: string;
  page_name?: string;
  page_category?: string;
  likes: number;
  followers: number;
  check_ins: number;
  verified: boolean;
  business_info?: FacebookBusiness;
}

export interface InstagramData {
  handle: string;
  follower_count: number;
  following_count: number;
  post_count: number;
  bio: string;
  verified: boolean;
  business_account: boolean;
  recent_posts: InstagramPost[];
}

export interface GitHubData {
  username: string;
  name: string;
  bio: string;
  public_repos: number;
  followers: number;
  following: number;
  contributions_last_year: number;
  top_languages: string[];
  popular_repos: GitHubRepo[];
}

export interface BlogData {
  url: string;
  title: string;
  description: string;
  last_post_date: string;
  post_frequency: string;
  topics: string[];
  writing_style: string;
}

export interface NetworkData {
  mutual_connections: number;
  shared_companies: string[];
  shared_experiences: string[];
  network_strength: 'weak' | 'medium' | 'strong';
  introduction_paths: IntroductionPath[];
}

export interface NewsArticle {
  title: string;
  url: string;
  source: string;
  published_date: string;
  summary: string;
  sentiment: 'positive' | 'neutral' | 'negative';
  relevance_score: number;
  topics: string[];
}

export interface PressRelease {
  title: string;
  date: string;
  summary: string;
  url: string;
  topics: string[];
  impact_score: number;
}

export interface FundingNews {
  amount: number;
  round_type: string;
  date: string;
  investors: string[];
  source: string;
  url: string;
}

export interface ProductNews {
  product_name: string;
  launch_date: string;
  description: string;
  market_impact: 'low' | 'medium' | 'high';
  url: string;
}

export interface ExecutiveNews {
  executive_name: string;
  change_type: 'hired' | 'promoted' | 'departed';
  new_title: string;
  date: string;
  source: string;
}

export interface AwardNews {
  award_name: string;
  category: string;
  date: string;
  source: string;
  significance: 'low' | 'medium' | 'high';
}

export interface PartnershipNews {
  partner_company: string;
  partnership_type: string;
  date: string;
  description: string;
  strategic_value: 'low' | 'medium' | 'high';
}

export interface NewsSentiment {
  overall_sentiment: 'positive' | 'neutral' | 'negative';
  sentiment_score: number; // -1 to 1
  trending: 'up' | 'stable' | 'down';
  key_themes: string[];
}

// Supporting data types
export interface Tweet {
  text: string;
  date: string;
  retweets: number;
  likes: number;
  replies: number;
  sentiment: 'positive' | 'neutral' | 'negative';
}

export interface TwitterEngagement {
  avg_retweets: number;
  avg_likes: number;
  avg_replies: number;
  engagement_rate: number;
  posting_frequency: string;
}

export interface FacebookBusiness {
  address: string;
  phone: string;
  website: string;
  hours: Record<string, string>;
  categories: string[];
}

export interface InstagramPost {
  caption: string;
  date: string;
  likes: number;
  comments: number;
  media_type: 'photo' | 'video' | 'carousel';
}

export interface GitHubRepo {
  name: string;
  description: string;
  language: string;
  stars: number;
  forks: number;
  last_updated: string;
}

export interface IntroductionPath {
  connector_name: string;
  connector_title: string;
  connection_strength: number;
  mutual_company?: string;
  introduction_probability: number;
}

export interface RateLimit {
  requests_remaining: number;
  reset_time: string;
  cost_per_request: number;
}

export interface EnrichmentError {
  source: EnrichmentSource;
  error_type: 'rate_limit' | 'auth_error' | 'not_found' | 'service_error' | 'timeout';
  message: string;
  timestamp: string;
  retry_after?: string;
}

// Configuration types
export interface EnrichmentConfig {
  sources: {
    clearbit: {
      api_key: string;
      endpoints: {
        person: string;
        company: string;
        prospector: string;
      };
      rate_limits: {
        requests_per_minute: number;
        cost_per_request: number;
      };
    };
    apollo: {
      api_key: string;
      endpoints: {
        person_search: string;
        company_search: string;
        email_finder: string;
      };
      rate_limits: {
        requests_per_minute: number;
        cost_per_request: number;
      };
    };
    linkedin: {
      username: string;
      password: string;
      proxy_endpoints: string[];
      rate_limits: {
        requests_per_hour: number;
      };
    };
    hunter: {
      api_key: string;
      endpoints: {
        email_finder: string;
        email_verifier: string;
        domain_search: string;
      };
    };
    news: {
      google_news_api_key: string;
      newsapi_key: string;
      serpapi_key: string;
    };
  };
  ai_analysis: {
    model: string;
    temperature: number;
    max_tokens: number;
    analysis_prompts: Record<string, string>;
  };
  caching: {
    redis_url?: string;
    cache_ttl: Record<EnrichmentSource, number>;
    cache_prefix: string;
  };
  processing: {
    max_concurrent_requests: number;
    timeout_ms: number;
    retry_attempts: number;
    batch_size: number;
  };
}

// Response types
export interface EnrichmentResult {
  success: boolean;
  enriched_lead?: EnrichedLead;
  enrichment_metadata: EnrichmentMetadata;
  error?: string;
}

export interface BulkEnrichmentResult {
  total_processed: number;
  successful: number;
  failed: number;
  results: EnrichmentResult[];
  total_cost: number;
  processing_time_ms: number;
}

export interface EnrichmentStatus {
  request_id: string;
  status: 'queued' | 'processing' | 'completed' | 'failed';
  progress: number; // 0-100
  sources_completed: EnrichmentSource[];
  estimated_completion: string;
  cost_so_far: number;
}