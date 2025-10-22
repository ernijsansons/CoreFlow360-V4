/**
 * Developer Platform Types
 * Shared types for developer accounts, custom integrations, and marketplace
 */

export type DeveloperTier = 'free' | 'pro' | 'enterprise';

export type DeveloperStatus = 'active' | 'suspended' | 'banned';

export type VerificationStatus = 'unverified' | 'email_verified' | 'identity_verified';

export type MarketplaceStatus = 'draft' | 'review' | 'approved' | 'rejected' | 'published' | 'deprecated';

export type IntegrationVisibility = 'private' | 'organization' | 'public';

export type PricingModel = 'free' | 'one_time' | 'subscription' | 'usage_based';

export type InstallStatus = 'active' | 'inactive' | 'expired' | 'error' | 'rate_limited' | 'suspended';

export type AnalyticsType = 'daily' | 'weekly' | 'monthly';

/**
 * Developer Account
 */
export interface Developer {
  id: string;
  user_id: string;

  // Profile
  developer_name?: string;
  developer_email?: string;
  company_name?: string;
  website_url?: string;
  github_username?: string;

  // Tier & Status
  developer_tier: DeveloperTier;
  status: DeveloperStatus;
  verification_status: VerificationStatus;

  // API Credentials
  api_key: string;
  api_secret: string;
  webhook_secret: string;

  // Quotas
  max_custom_integrations: number;
  max_installs: number;
  max_api_calls_per_day: number;

  // Statistics
  total_integrations: number;
  total_installs: number;
  total_api_calls: number;
  total_revenue_usd: number;

  // Timestamps
  created_at: string;
  updated_at: string;
  last_activity_at?: string;
}

/**
 * Custom Integration
 */
export interface CustomIntegration {
  id: string;
  developer_id: string;

  // Identity
  integration_key: string;
  integration_name: string;
  integration_description?: string;
  integration_version: string;

  // Provider Details
  provider_logo_url?: string;
  provider_website?: string;
  provider_category?: string;
  category_tags?: string[];

  // Code & Configuration
  code_bundle: string;
  manifest: string;
  source_code_url?: string;

  // Authentication
  auth_type: 'api_key' | 'oauth2' | 'basic_auth' | 'bearer_token' | 'custom';
  auth_config?: AuthConfig;

  // Capabilities
  supported_actions?: string[];
  supported_triggers?: string[];
  supported_entities?: string[];

  // Visibility
  visibility: IntegrationVisibility;
  marketplace_status: MarketplaceStatus;

  // Pricing
  pricing_model?: PricingModel;
  price_usd: number;

  // Quality
  install_count: number;
  active_install_count: number;
  rating?: number;
  total_reviews: number;

  // Compliance
  security_reviewed: boolean;
  security_review_date?: string;
  security_reviewer_id?: string;
  data_privacy_compliant: boolean;

  // Documentation
  documentation_url?: string;
  changelog_url?: string;
  support_email?: string;
  support_url?: string;

  // Webhooks
  webhook_support: boolean;
  webhook_events?: string[];

  // Timestamps
  created_at: string;
  updated_at: string;
  published_at?: string;
  last_deployed_at?: string;
}

/**
 * Integration Manifest (stored in manifest field)
 */
export interface IntegrationManifest {
  version: string;
  actions: Record<string, ActionDefinition>;
  triggers?: Record<string, TriggerDefinition>;
  auth: AuthConfig;
  schemas?: Record<string, any>;
}

/**
 * Action Definition
 */
export interface ActionDefinition {
  key: string;
  name: string;
  description: string;
  handler: string;
  inputSchema: any; // Zod schema serialized
  outputSchema?: any;
}

/**
 * Trigger Definition
 */
export interface TriggerDefinition {
  key: string;
  name: string;
  description: string;
  handler: string;
  type: 'webhook' | 'polling';
  outputSchema?: any;
}

/**
 * Auth Configuration
 */
export interface AuthConfig {
  type: 'api_key' | 'oauth2' | 'basic_auth' | 'bearer_token' | 'custom';
  // OAuth2
  authorization_url?: string;
  token_url?: string;
  scopes?: string[];
  oauth_config?: {
    client_id: string;
    client_secret: string;
    authorization_url: string;
    token_url: string;
    revoke_url?: string;
    scopes: string[];
  };
  // API Key
  key_name?: string;
  key_location?: 'header' | 'query';
  // Custom
  fields?: Record<string, AuthField>;
}

export interface AuthField {
  label: string;
  type: 'text' | 'password' | 'url';
  required: boolean;
  description?: string;
}

/**
 * Custom Integration Install
 */
export interface CustomIntegrationInstall {
  id: string;
  business_id: string;
  custom_integration_id: string;

  // Installation
  integration_version: string;
  credentials_encrypted?: string;

  // OAuth
  oauth_access_token?: string;
  oauth_refresh_token?: string;
  oauth_token_expires_at?: string;
  oauth_scopes?: string[];

  // Configuration
  settings?: string;
  enabled_features?: string;

  // Webhooks
  webhook_url?: string;
  webhook_secret?: string;
  webhook_events?: string[];

  // Usage
  total_requests: number;
  requests_this_month: number;
  last_request_at?: string;

  // Status
  install_status: InstallStatus;
  error_count: number;
  last_error_message?: string;
  last_error_at?: string;

  // Audit
  installed_by: string;
  installed_at: string;
  uninstalled_at?: string;

  created_at: string;
  updated_at: string;
}

/**
 * Integration Review
 */
export interface CustomIntegrationReview {
  id: string;
  custom_integration_id: string;
  business_id: string;
  user_id: string;

  // Review
  rating: number; // 1-5
  review_title?: string;
  review_text?: string;

  // Developer Response
  developer_response?: string;
  developer_response_at?: string;

  // Moderation
  is_verified_install: boolean;
  is_flagged: boolean;
  flagged_reason?: string;

  created_at: string;
  updated_at: string;
}

/**
 * Integration Usage Log
 */
export interface CustomIntegrationUsageLog {
  id: string;
  custom_integration_install_id: string;
  business_id: string;
  custom_integration_id: string;

  // Request
  action_key?: string;
  trigger_key?: string;
  request_type: 'action' | 'trigger';
  request_payload_hash?: string;

  // Response
  response_status_code?: number;
  response_time_ms?: number;
  response_success: boolean;
  response_error?: string;

  // Entity
  entity_id?: string;
  entity_type?: string;

  // Billing
  credits_used: number;
  cost_usd: number;

  // Context
  triggered_by: 'user' | 'automation' | 'webhook' | 'cron' | 'api';
  user_id?: string;
  correlation_id?: string;

  requested_at: string;
  created_at: string;
}

/**
 * Developer API Key
 */
export interface DeveloperApiKey {
  id: string;
  developer_id: string;

  // Key
  key_name: string;
  api_key: string;
  api_key_prefix: string;
  api_key_hash: string;

  // Permissions
  scopes?: string[];

  // Usage
  total_requests: number;
  last_used_at?: string;

  // Security
  ip_whitelist?: string[];
  rate_limit_per_hour: number;

  // Status
  status: 'active' | 'revoked' | 'expired';
  expires_at?: string;

  created_at: string;
  revoked_at?: string;
  revoked_by?: string;
}

/**
 * OAuth Connection
 */
export interface CustomIntegrationOAuthConnection {
  id: string;
  custom_integration_install_id: string;
  custom_integration_id: string;
  business_id: string;

  // OAuth Flow
  authorization_code?: string;
  state?: string;
  code_verifier?: string;
  code_challenge?: string;

  // Tokens
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_at?: string;
  scopes?: string[];

  // Provider
  provider_user_id?: string;
  provider_account_info?: Record<string, any>;

  // Status
  connection_status: 'active' | 'expired' | 'revoked' | 'error';

  // Refresh
  last_refreshed_at?: string;
  refresh_count: number;

  // Error
  last_error?: string;
  last_error_at?: string;
  retry_count: number;

  created_at: string;
  updated_at: string;
}

/**
 * Integration Analytics
 */
export interface CustomIntegrationAnalytics {
  id: string;
  custom_integration_id: string;

  // Period
  analytics_date: string;
  analytics_type: AnalyticsType;

  // Installation
  new_installs: number;
  uninstalls: number;
  active_installs: number;

  // Usage
  total_requests: number;
  successful_requests: number;
  failed_requests: number;
  avg_response_time_ms?: number;

  // Revenue
  revenue_usd: number;
  refunds_usd: number;

  // Engagement
  unique_users: number;
  unique_businesses: number;

  // Quality
  new_reviews: number;
  avg_rating?: number;
  error_rate?: number;

  created_at: string;
}

/**
 * Request/Response DTOs
 */

// Developer Registration
export interface RegisterDeveloperRequest {
  developer_name?: string;
  developer_email?: string;
  company_name?: string;
  website_url?: string;
  github_username?: string;
  developer_tier?: DeveloperTier;
}

export interface RegisterDeveloperResponse {
  success: boolean;
  developer?: Developer;
  api_key?: string;
  api_secret?: string;
  webhook_secret?: string;
  error?: string;
}

// Create Custom Integration
export interface CreateCustomIntegrationRequest {
  integration_key: string;
  integration_name: string;
  integration_description?: string;
  integration_version?: string;
  code_bundle: string;
  manifest: string;
  auth_type: 'api_key' | 'oauth2' | 'basic_auth' | 'bearer_token' | 'custom';
  auth_config?: AuthConfig;
  provider_category?: string;
  category_tags?: string[];
  visibility?: IntegrationVisibility;
  pricing_model?: PricingModel;
  price_usd?: number;
}

export interface CreateCustomIntegrationResponse {
  success: boolean;
  integration?: CustomIntegration;
  error?: string;
}

// Install Custom Integration
export interface InstallCustomIntegrationRequest {
  credentials?: Record<string, string>;
  settings?: string;
  enabled_features?: string;
  webhook_events?: string[];
}

export interface InstallCustomIntegrationResponse {
  success: boolean;
  install?: CustomIntegrationInstall;
  oauth_authorization_url?: string; // If OAuth2
  error?: string;
}

// Submit Review
export interface SubmitReviewRequest {
  rating: number; // 1-5
  review_title?: string;
  review_text?: string;
}

export interface SubmitReviewResponse {
  success: boolean;
  review?: CustomIntegrationReview;
  error?: string;
}

// Analytics Request
export interface GetAnalyticsRequest {
  start_date?: string;
  end_date?: string;
  analytics_type?: AnalyticsType;
  integration_id?: string;
}

export interface GetAnalyticsResponse {
  success: boolean;
  analytics?: CustomIntegrationAnalytics[];
  summary?: {
    total_installs: number;
    total_requests: number;
    total_revenue: number;
    avg_rating: number;
  };
  error?: string;
}

// ============================================================
// OAUTH TYPES
// ============================================================

export interface OAuthConnection {
  id: string;
  custom_integration_install_id: string;
  custom_integration_id: string;
  business_id: string;
  authorization_code: string;
  state: string;
  code_verifier: string;
  code_challenge: string;
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_at?: string;
  scopes?: string;
  provider_user_id?: string;
  provider_account_info?: string;
  connection_status: 'active' | 'expired' | 'revoked' | 'error';
  last_refreshed_at?: string;
  refresh_count: number;
  last_error?: string;
  last_error_at?: string;
  retry_count: number;
  created_at: string;
  updated_at: string;
}

export interface OAuthAuthorizationRequest {
  integration_key: string;
  business_id: string;
  redirect_uri: string;
  install_id?: string;
  additional_params?: Record<string, string>;
}

export interface OAuthAuthorizationResponse {
  success: boolean;
  authorization_url?: string;
  state?: string;
  error?: string;
}

export interface OAuthTokenExchangeRequest {
  code: string;
  state: string;
  redirect_uri: string;
}

export interface OAuthTokenExchangeResponse {
  success: boolean;
  connection_id?: string;
  access_token?: string;
  refresh_token?: string;
  expires_at?: string | null;
  token_type?: string;
  scopes?: string[];
  error?: string;
}

export interface OAuthRefreshTokenRequest {
  connection_id: string;
}

export interface OAuthRefreshTokenResponse {
  success: boolean;
  access_token?: string;
  refresh_token?: string;
  expires_at?: string | null;
  token_type?: string;
  error?: string;
}

export interface OAuthRevokeTokenRequest {
  connection_id: string;
  token_type: 'access' | 'refresh';
}

// ============================================================
// ANALYTICS TYPES
// ============================================================

export type AnalyticsTimeframe = '7d' | '30d' | '90d';

export interface DeveloperDashboard {
  developer_tier: DeveloperTier;
  total_integrations: number;
  integrations_by_status: any[];
  total_installs: number;
  active_installs: number;
  total_requests_30d: number;
  successful_requests_30d: number;
  failed_requests_30d: number;
  avg_response_time_30d: number;
  total_revenue_30d: number;
  top_integrations: any[];
  quota_usage: {
    integrations: { used: number; limit: number; percentage: number };
    installs: { used: number; limit: number; percentage: number };
    api_calls_today: { used: number; limit: number; percentage: number };
  };
}

export interface IntegrationAnalytics {
  integration_id: string;
  integration_key: string;
  integration_name: string;
  timeframe: AnalyticsTimeframe;
  total_requests: number;
  successful_requests: number;
  failed_requests: number;
  success_rate: number;
  avg_response_time: number;
  min_response_time: number;
  max_response_time: number;
  unique_businesses: number;
  unique_users: number;
  total_revenue: number;
  current_installs: number;
  active_installs: number;
  rating?: number;
  total_reviews: number;
  requests_by_day: any[];
  requests_by_action: any[];
  error_breakdown: any[];
  install_trends: any[];
  uninstall_trends: any[];
}

export interface DeveloperAnalytics {
  developer_id: string;
  timeframe: AnalyticsTimeframe;
  total_integrations: number;
  published_integrations: number;
  total_installs: number;
  total_requests: number;
  total_revenue: number;
  avg_rating: number;
}

export interface IntegrationUsageStats {
  integration_id: string;
  date: string;
  total_requests: number;
  successful_requests: number;
  failed_requests: number;
  avg_response_time: number;
  unique_users: number;
  unique_businesses: number;
}

export interface IntegrationPerformanceMetrics {
  integration_id: string;
  avg_response_time: number;
  p50_response_time: number;
  p95_response_time: number;
  p99_response_time: number;
  error_rate: number;
  uptime_percentage: number;
}

export interface MarketplaceInsights {
  timeframe: AnalyticsTimeframe;
  total_published_integrations: number;
  total_installs: number;
  active_installs: number;
  total_requests: number;
  successful_requests: number;
  success_rate: number;
  new_integrations: number;
  total_developers: number;
  free_tier_developers: number;
  pro_tier_developers: number;
  enterprise_tier_developers: number;
  top_integrations_by_installs: any[];
  top_integrations_by_usage: any[];
  top_integrations_by_rating: any[];
  category_distribution: any[];
}

// ============================================================
// EXECUTION TYPES
// ============================================================

export interface ExecuteActionRequest {
  install_id: string;
  action_key: string;
  payload: Record<string, any>;
  entity_id?: string;
  entity_type?: string;
  triggered_by?: string;
  user_id?: string;
  correlation_id?: string;
}

export interface ExecuteActionResponse {
  success: boolean;
  data?: any;
  error?: string;
  response_time_ms?: number;
  credits_used?: number;
  cost_usd?: number;
}

export interface ProcessTriggerRequest {
  business_id: string;
  integration_key: string;
  trigger_key: string;
  payload: Record<string, any>;
  webhook_signature?: string;
  correlation_id?: string;
}

export interface ProcessTriggerResponse {
  success: boolean;
  data?: any;
  error?: string;
  response_time_ms?: number;
}

export interface IntegrationExecutionLog {
  custom_integration_install_id?: string;
  business_id?: string;
  custom_integration_id?: string;
  action_key?: string;
  trigger_key?: string;
  request_type?: 'action' | 'trigger';
  response_status_code?: number;
  response_time_ms?: number;
  response_success?: boolean;
  response_error?: string;
  entity_id?: string;
  entity_type?: string;
  triggered_by?: string;
  user_id?: string;
  correlation_id?: string;
  cost_usd?: number;
}

export interface SandboxContext {
  business_id: string;
  integration_id: string;
  integration_key: string;
  action_key: string;
  credentials: Record<string, any>;
  settings: Record<string, any>;
  input: Record<string, any>;
  env: {
    KV_CACHE: any;
  };
}

export interface SandboxResult {
  success: boolean;
  data?: any;
  error?: string;
}
