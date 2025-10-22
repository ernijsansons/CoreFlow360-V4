/**
 * Global Integration Types
 * Shared types for ALL ERP integration operations
 * Used by: Finance, CRM, Inventory, HR, Payroll, E-commerce, Support, Analytics
 */

export type IntegrationType =
  | 'data_enrichment'
  | 'email_verification'
  | 'intent_data'
  | 'sales_intelligence'
  | 'marketing_automation'
  | 'payment_processing'
  | 'accounting'
  | 'communication'
  | 'analytics'
  | 'ai_ml'
  | 'crm'
  | 'ecommerce'
  | 'document_management'
  | 'customer_support'
  | 'automation'
  | 'hr_payroll'
  | 'productivity'
  | 'other';

export type AuthType = 'oauth2' | 'api_key' | 'basic_auth' | 'bearer_token' | 'custom';

export type PricingModel = 'free' | 'freemium' | 'per_request' | 'subscription' | 'credit_based' | 'enterprise';

export type ConnectionStatus = 'active' | 'inactive' | 'expired' | 'error' | 'rate_limited' | 'suspended';

export type ERPModule = 'finance' | 'crm' | 'inventory' | 'hr' | 'payroll' | 'ecommerce' | 'support' | 'analytics';

/**
 * Integration Provider (from database)
 */
export interface IntegrationProvider {
  id: string;
  provider_key: string;
  provider_name: string;
  provider_logo_url?: string;
  provider_website?: string;
  provider_type: IntegrationType;
  category_tags: string[];
  capabilities: string[];
  supported_entities?: string[];
  data_fields_provided?: string[];
  auth_type: AuthType;
  auth_config?: Record<string, any>;
  pricing_model: PricingModel;
  base_cost_per_request?: number;
  monthly_free_quota?: number;
  rate_limit_per_minute?: number;
  rate_limit_per_day?: number;
  avg_response_time_ms?: number;
  success_rate?: number;
  data_accuracy_score?: number;
  user_rating?: number;
  total_reviews?: number;
  status: 'active' | 'beta' | 'deprecated' | 'maintenance' | 'inactive';
  is_verified: boolean;
  is_recommended: boolean;
  available_regions?: string[];
  documentation_url?: string;
  api_docs_url?: string;
  support_email?: string;
  webhook_support: boolean;
  created_at: string;
  updated_at: string;
}

/**
 * Business Integration Connection
 */
export interface BusinessIntegration {
  id: string;
  business_id: string;
  provider_id: string;
  connection_name?: string;
  connection_status: ConnectionStatus;
  credentials_encrypted: string;
  credentials_expires_at?: string;
  oauth_access_token?: string;
  oauth_refresh_token?: string;
  oauth_token_expires_at?: string;
  oauth_scopes?: string[];
  settings?: Record<string, any>;
  enabled_features?: string[];
  webhook_url?: string;
  webhook_secret?: string;
  total_requests: number;
  requests_this_month: number;
  last_request_at?: string;
  monthly_quota_used: number;
  monthly_quota_limit?: number;
  total_cost_usd: number;
  cost_this_month: number;
  success_count: number;
  error_count: number;
  avg_response_time_ms?: number;
  last_error_message?: string;
  last_error_at?: string;
  last_sync_at?: string;
  next_sync_at?: string;
  sync_frequency?: 'hourly' | 'daily' | 'weekly' | 'manual';
  auto_sync_enabled: boolean;
  connected_by: string;
  connected_at: string;
  created_at: string;
  updated_at: string;
}

/**
 * Integration Request (any module can use this)
 */
export interface IntegrationRequest {
  business_id: string;
  provider_key: string; // 'quickbooks', 'salesforce', 'stripe', etc.
  module: ERPModule; // Which module is making the request
  operation: string; // 'create_invoice', 'sync_customer', 'process_payment', etc.
  payload: Record<string, any>; // Operation-specific data
  user_id?: string;
  idempotency_key?: string;
}

/**
 * Integration Response
 */
export interface IntegrationResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  provider_response_code?: number;
  response_time_ms?: number;
  credits_used?: number;
  cost_usd?: number;
  metadata?: Record<string, any>;
}

/**
 * Integration Usage Log
 */
export interface IntegrationUsageLog {
  id: string;
  business_integration_id: string;
  business_id: string;
  request_type: string;
  request_endpoint?: string;
  request_method?: string;
  request_payload_hash?: string;
  response_status_code?: number;
  response_time_ms?: number;
  response_success: boolean;
  response_error?: string;
  entity_id?: string;
  entity_type?: string;
  fields_updated?: string[];
  data_quality_score?: number;
  credits_used: number;
  cost_usd: number;
  triggered_by?: 'user' | 'automation' | 'webhook' | 'cron';
  user_id?: string;
  correlation_id?: string;
  requested_at: string;
  created_at: string;
}

/**
 * Encrypted Credentials Structure
 */
export interface IntegrationCredentials {
  api_key?: string;
  client_id?: string;
  client_secret?: string;
  access_token?: string;
  refresh_token?: string;
  username?: string;
  password?: string;
  custom_fields?: Record<string, string>;
}

/**
 * OAuth Configuration
 */
export interface OAuthConfig {
  authorization_url: string;
  token_url: string;
  scopes: string[];
  redirect_uri?: string;
  client_id: string;
  client_secret: string;
}

/**
 * Integration Error Types
 */
export enum IntegrationErrorType {
  AUTH_FAILED = 'auth_failed',
  RATE_LIMITED = 'rate_limited',
  QUOTA_EXCEEDED = 'quota_exceeded',
  INVALID_REQUEST = 'invalid_request',
  PROVIDER_ERROR = 'provider_error',
  NETWORK_ERROR = 'network_error',
  NOT_FOUND = 'not_found',
  EXPIRED_TOKEN = 'expired_token',
  INSUFFICIENT_PERMISSIONS = 'insufficient_permissions',
}

/**
 * Integration Error
 */
export class IntegrationError extends Error {
  constructor(
    public type: IntegrationErrorType,
    message: string,
    public provider_key?: string,
    public statusCode?: number,
    public retryable: boolean = false
  ) {
    super(message);
    this.name = 'IntegrationError';
  }
}
