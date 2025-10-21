-- Migration: 061_integrations_marketplace
-- Description: Global Integrations Infrastructure for All ERP Modules
-- Features: 46 providers, centralized integration management, OAuth support
-- Created: 2025-10-20
-- Part of: Global ERP Infrastructure
-- Scope: Finance, CRM, Inventory, HR, Payroll, E-commerce, Support, Analytics

-- ============================================================
-- INTEGRATION PROVIDERS CATALOG
-- ============================================================
CREATE TABLE IF NOT EXISTS integration_providers (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),

    -- Provider Details
    provider_key TEXT NOT NULL UNIQUE, -- 'apollo', 'clearbit', 'hunter', etc.
    provider_name TEXT NOT NULL,
    provider_logo_url TEXT,
    provider_website TEXT,

    -- Provider Type & Category
    provider_type TEXT NOT NULL CHECK(provider_type IN (
        'data_enrichment',
        'email_verification',
        'intent_data',
        'sales_intelligence',
        'marketing_automation',
        'payment_processing',
        'accounting',
        'communication',
        'analytics',
        'ai_ml',
        'crm',
        'ecommerce',
        'document_management',
        'customer_support',
        'automation',
        'hr_payroll',
        'productivity',
        'other'
    )),
    category_tags TEXT, -- JSON array: ['b2b', 'contact_data', 'company_data']

    -- Capabilities
    capabilities TEXT NOT NULL, -- JSON array of features
    supported_entities TEXT, -- JSON: ['contact', 'company', 'lead']
    data_fields_provided TEXT, -- JSON: fields this provider can enrich

    -- Authentication Methods
    auth_type TEXT NOT NULL CHECK(auth_type IN (
        'api_key',
        'oauth2',
        'basic_auth',
        'bearer_token',
        'custom'
    )),
    auth_config TEXT, -- JSON: OAuth endpoints, scopes, etc.

    -- Pricing & Limits
    pricing_model TEXT CHECK(pricing_model IN (
        'free',
        'freemium',
        'per_request',
        'subscription',
        'credit_based',
        'enterprise'
    )),
    base_cost_per_request REAL DEFAULT 0.0,
    monthly_free_quota INTEGER DEFAULT 0,
    rate_limit_per_minute INTEGER,
    rate_limit_per_day INTEGER,

    -- Quality Metrics
    avg_response_time_ms INTEGER,
    success_rate REAL, -- 0.0 to 1.0
    data_accuracy_score REAL, -- 0.0 to 1.0
    user_rating REAL, -- 1.0 to 5.0
    total_reviews INTEGER DEFAULT 0,

    -- Status & Availability
    status TEXT DEFAULT 'active' CHECK(status IN ('active', 'beta', 'deprecated', 'maintenance', 'inactive')),
    is_verified BOOLEAN DEFAULT 0,
    is_recommended BOOLEAN DEFAULT 0,
    available_regions TEXT, -- JSON array: ['us', 'eu', 'global']

    -- Documentation
    documentation_url TEXT,
    api_docs_url TEXT,
    support_email TEXT,
    webhook_support BOOLEAN DEFAULT 0,

    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_integration_providers_type ON integration_providers(provider_type);
CREATE INDEX idx_integration_providers_status ON integration_providers(status) WHERE status = 'active';
CREATE INDEX idx_integration_providers_recommended ON integration_providers(is_recommended) WHERE is_recommended = 1;

-- ============================================================
-- BUSINESS INTEGRATION CONNECTIONS
-- ============================================================
CREATE TABLE IF NOT EXISTS business_integrations (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),
    provider_id TEXT NOT NULL REFERENCES integration_providers(id),

    -- Connection Details
    connection_name TEXT, -- User-friendly name
    connection_status TEXT DEFAULT 'active' CHECK(connection_status IN (
        'active',
        'inactive',
        'expired',
        'error',
        'rate_limited',
        'suspended'
    )),

    -- Authentication Credentials (Encrypted)
    credentials_encrypted TEXT NOT NULL, -- Encrypted JSON with API keys, tokens, etc.
    credentials_expires_at TIMESTAMP,

    -- OAuth Specific
    oauth_access_token TEXT, -- Encrypted
    oauth_refresh_token TEXT, -- Encrypted
    oauth_token_expires_at TIMESTAMP,
    oauth_scopes TEXT, -- JSON array

    -- Configuration
    settings TEXT, -- JSON: provider-specific settings
    enabled_features TEXT, -- JSON array: which capabilities are enabled
    webhook_url TEXT,
    webhook_secret TEXT,

    -- Usage Tracking
    total_requests INTEGER DEFAULT 0,
    requests_this_month INTEGER DEFAULT 0,
    last_request_at TIMESTAMP,
    monthly_quota_used INTEGER DEFAULT 0,
    monthly_quota_limit INTEGER,

    -- Cost Tracking
    total_cost_usd REAL DEFAULT 0.0,
    cost_this_month REAL DEFAULT 0.0,
    billing_cycle_start DATE,

    -- Health & Performance
    success_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    avg_response_time_ms INTEGER,
    last_error_message TEXT,
    last_error_at TIMESTAMP,

    -- Sync Status
    last_sync_at TIMESTAMP,
    next_sync_at TIMESTAMP,
    sync_frequency TEXT, -- 'hourly', 'daily', 'weekly', 'manual'
    auto_sync_enabled BOOLEAN DEFAULT 1,

    -- Metadata
    connected_by TEXT REFERENCES users(id),
    connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(business_id, provider_id)
);

CREATE INDEX idx_business_integrations_business ON business_integrations(business_id);
CREATE INDEX idx_business_integrations_provider ON business_integrations(provider_id);
CREATE INDEX idx_business_integrations_status ON business_integrations(connection_status);
CREATE INDEX idx_business_integrations_active ON business_integrations(business_id, connection_status) WHERE connection_status = 'active';

-- ============================================================
-- INTEGRATION USAGE LOGS
-- ============================================================
CREATE TABLE IF NOT EXISTS integration_usage_logs (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_integration_id TEXT NOT NULL REFERENCES business_integrations(id),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- Request Details
    request_type TEXT NOT NULL, -- 'enrich_contact', 'verify_email', 'search_company', etc.
    request_endpoint TEXT,
    request_method TEXT,
    request_payload_hash TEXT, -- For deduplication

    -- Response Details
    response_status_code INTEGER,
    response_time_ms INTEGER,
    response_success BOOLEAN,
    response_error TEXT,

    -- Data Tracking
    entity_id TEXT, -- Contact/Company/Lead ID that was enriched
    entity_type TEXT,
    fields_updated TEXT, -- JSON array
    data_quality_score REAL,

    -- Cost & Credits
    credits_used INTEGER DEFAULT 0,
    cost_usd REAL DEFAULT 0.0,

    -- Metadata
    triggered_by TEXT, -- 'user', 'automation', 'webhook', 'cron'
    user_id TEXT REFERENCES users(id),
    correlation_id TEXT, -- For tracking related requests

    -- Timestamps
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_integration_usage_logs_integration ON integration_usage_logs(business_integration_id);
CREATE INDEX idx_integration_usage_logs_date ON integration_usage_logs(requested_at DESC);
CREATE INDEX idx_integration_usage_logs_entity ON integration_usage_logs(entity_id, entity_type);
CREATE INDEX idx_integration_usage_logs_success ON integration_usage_logs(response_success);

-- ============================================================
-- INTEGRATION WEBHOOKS
-- ============================================================
CREATE TABLE IF NOT EXISTS integration_webhooks (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_integration_id TEXT NOT NULL REFERENCES business_integrations(id),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- Webhook Details
    webhook_event_type TEXT NOT NULL, -- 'job_change', 'company_update', 'intent_spike', etc.
    webhook_payload TEXT NOT NULL, -- Full JSON payload
    webhook_signature TEXT,

    -- Processing Status
    processing_status TEXT DEFAULT 'pending' CHECK(processing_status IN (
        'pending',
        'processing',
        'completed',
        'failed',
        'ignored'
    )),
    processing_started_at TIMESTAMP,
    processing_completed_at TIMESTAMP,
    processing_error TEXT,

    -- Actions Taken
    actions_executed TEXT, -- JSON array of actions performed
    entities_affected TEXT, -- JSON: {contact_ids: [], company_ids: []}

    -- Metadata
    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_integration_webhooks_integration ON integration_webhooks(business_integration_id);
CREATE INDEX idx_integration_webhooks_status ON integration_webhooks(processing_status);
CREATE INDEX idx_integration_webhooks_event ON integration_webhooks(webhook_event_type);
CREATE INDEX idx_integration_webhooks_date ON integration_webhooks(received_at DESC);

-- ============================================================
-- SEED INTEGRATION PROVIDERS
-- ============================================================

-- Apollo.io
INSERT INTO integration_providers (
    provider_key,
    provider_name,
    provider_logo_url,
    provider_website,
    provider_type,
    category_tags,
    capabilities,
    supported_entities,
    data_fields_provided,
    auth_type,
    auth_config,
    pricing_model,
    base_cost_per_request,
    monthly_free_quota,
    rate_limit_per_minute,
    rate_limit_per_day,
    avg_response_time_ms,
    success_rate,
    data_accuracy_score,
    status,
    is_verified,
    is_recommended,
    available_regions,
    documentation_url,
    api_docs_url,
    webhook_support
) VALUES (
    'apollo',
    'Apollo.io',
    'https://www.apollo.io/favicon.ico',
    'https://www.apollo.io',
    'sales_intelligence',
    '["b2b", "contact_data", "company_data", "sales_intelligence", "email_finder"]',
    '["contact_search", "company_search", "email_finder", "phone_finder", "technographics", "job_postings", "org_charts", "intent_data"]',
    '["contact", "company", "lead"]',
    '["email", "phone", "job_title", "seniority", "department", "company_name", "company_size", "industry", "revenue", "technologies", "social_profiles", "employment_history"]',
    'api_key',
    '{"header_name": "x-api-key", "base_url": "https://api.apollo.io/v1"}',
    'credit_based',
    0.10,
    100,
    60,
    10000,
    250,
    0.98,
    0.95,
    'active',
    1,
    1,
    '["global"]',
    'https://apolloio.github.io/apollo-api-docs/',
    'https://apolloio.github.io/apollo-api-docs/',
    1
);

-- Clearbit
INSERT INTO integration_providers (
    provider_key,
    provider_name,
    provider_website,
    provider_type,
    category_tags,
    capabilities,
    supported_entities,
    data_fields_provided,
    auth_type,
    pricing_model,
    base_cost_per_request,
    monthly_free_quota,
    status,
    is_verified,
    is_recommended
) VALUES (
    'clearbit',
    'Clearbit',
    'https://clearbit.com',
    'data_enrichment',
    '["b2b", "company_data", "person_data"]',
    '["company_enrichment", "person_enrichment", "logo_api", "reveal"]',
    '["contact", "company"]',
    '["email", "name", "company", "title", "bio", "location", "employment", "social_profiles"]',
    'api_key',
    'per_request',
    0.15,
    50,
    'active',
    1,
    1
);

-- Hunter.io
INSERT INTO integration_providers (
    provider_key,
    provider_name,
    provider_website,
    provider_type,
    category_tags,
    capabilities,
    supported_entities,
    data_fields_provided,
    auth_type,
    pricing_model,
    base_cost_per_request,
    monthly_free_quota,
    status,
    is_verified,
    is_recommended
) VALUES (
    'hunter',
    'Hunter.io',
    'https://hunter.io',
    'email_verification',
    '["email_finder", "email_verification", "domain_search"]',
    '["domain_search", "email_finder", "email_verifier", "author_finder"]',
    '["contact"]',
    '["email", "email_confidence_score", "sources"]',
    'api_key',
    'credit_based',
    0.05,
    50,
    'active',
    1,
    1
);

-- PeopleDataLabs
INSERT INTO integration_providers (
    provider_key,
    provider_name,
    provider_website,
    provider_type,
    category_tags,
    capabilities,
    supported_entities,
    data_fields_provided,
    auth_type,
    pricing_model,
    base_cost_per_request,
    monthly_free_quota,
    webhook_support,
    status,
    is_verified
) VALUES (
    'peopledatalabs',
    'PeopleDataLabs',
    'https://www.peopledatalabs.com',
    'data_enrichment',
    '["b2b", "person_data", "company_data", "job_changes"]',
    '["person_enrichment", "company_enrichment", "job_change_webhooks", "search"]',
    '["contact", "company"]',
    '["full_name", "email", "phone", "job_title", "company", "location", "skills", "education", "experience"]',
    'api_key',
    'per_request',
    0.08,
    100,
    1,
    'active',
    1
);

-- ZoomInfo
INSERT INTO integration_providers (
    provider_key,
    provider_name,
    provider_website,
    provider_type,
    category_tags,
    capabilities,
    supported_entities,
    data_fields_provided,
    auth_type,
    pricing_model,
    status,
    is_verified
) VALUES (
    'zoominfo',
    'ZoomInfo',
    'https://www.zoominfo.com',
    'sales_intelligence',
    '["b2b", "contact_data", "company_data", "intent_data"]',
    '["contact_search", "company_search", "intent_data", "scoops", "technographics"]',
    '["contact", "company", "lead"]',
    '["email", "phone", "direct_dial", "mobile", "job_title", "company_info", "intent_signals", "technographics"]',
    'oauth2',
    'enterprise',
    'active',
    1
);

-- Bombora
INSERT INTO integration_providers (
    provider_key,
    provider_name,
    provider_website,
    provider_type,
    category_tags,
    capabilities,
    supported_entities,
    data_fields_provided,
    auth_type,
    pricing_model,
    webhook_support,
    status,
    is_verified
) VALUES (
    'bombora',
    'Bombora',
    'https://bombora.com',
    'intent_data',
    '["intent_data", "b2b", "account_based_marketing"]',
    '["company_surge", "topic_taxonomy", "intent_scoring", "webhooks"]',
    '["company"]',
    '["intent_topics", "surge_score", "composite_score", "trending_topics"]',
    'api_key',
    'subscription',
    1,
    'active',
    1
);

-- ============================================================
-- TIER 1: ACCOUNTING & FINANCE
-- ============================================================

-- QuickBooks Online
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'quickbooks',
    'QuickBooks Online',
    'https://quickbooks.intuit.com',
    'accounting',
    '["accounting", "invoicing", "expense_tracking", "payroll"]',
    '["invoices", "payments", "expenses", "customers", "vendors", "reports", "bank_reconciliation"]',
    'oauth2',
    'subscription',
    'active', 1, 1
);

-- Xero
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'xero',
    'Xero',
    'https://www.xero.com',
    'accounting',
    '["accounting", "invoicing", "multi_currency", "global"]',
    '["invoices", "bank_feeds", "expenses", "purchase_orders", "inventory", "projects", "1000plus_integrations"]',
    'oauth2',
    'subscription',
    'active', 1, 1
);

-- NetSuite
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'netsuite',
    'NetSuite ERP',
    'https://www.netsuite.com',
    'accounting',
    '["erp", "accounting", "enterprise", "multi_entity"]',
    '["financial_management", "order_management", "inventory", "crm", "ecommerce", "multi_subsidiary"]',
    'oauth2',
    'enterprise',
    'active', 1
);

-- Sage Intacct
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'sage_intacct',
    'Sage Intacct',
    'https://www.sageintacct.com',
    'accounting',
    '["accounting", "multi_entity", "enterprise", "cloud"]',
    '["general_ledger", "accounts_payable", "accounts_receivable", "cash_management", "multi_entity_accounting"]',
    'api_key',
    'enterprise',
    'active', 1
);

-- FreshBooks
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'freshbooks',
    'FreshBooks',
    'https://www.freshbooks.com',
    'accounting',
    '["accounting", "invoicing", "time_tracking", "small_business"]',
    '["invoices", "expenses", "time_tracking", "proposals", "reports", "multi_business_support"]',
    'oauth2',
    'subscription',
    'active', 1
);

-- ============================================================
-- TIER 1: PAYMENT PROCESSING
-- ============================================================

-- Stripe
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    base_cost_per_request, status, is_verified, is_recommended
) VALUES (
    'stripe',
    'Stripe',
    'https://stripe.com',
    'payment_processing',
    '["payments", "subscriptions", "invoicing", "global"]',
    '["payment_processing", "subscriptions", "invoicing", "payment_links", "radar_fraud", "identity", "46_countries", "135_currencies"]',
    'oauth2',
    'per_request',
    0.029,
    'active', 1, 1
);

-- PayPal
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'paypal',
    'PayPal',
    'https://www.paypal.com',
    'payment_processing',
    '["payments", "global", "trusted", "220m_customers"]',
    '["payment_processing", "invoicing", "subscriptions", "checkout", "payouts", "global_payments"]',
    'oauth2',
    'per_request',
    'active', 1, 1
);

-- Square
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'square',
    'Square',
    'https://squareup.com',
    'payment_processing',
    '["payments", "pos", "invoicing", "ecommerce"]',
    '["payment_processing", "pos", "invoicing", "online_store", "appointments", "payroll"]',
    'oauth2',
    'per_request',
    'active', 1
);

-- Authorize.net
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'authorize_net',
    'Authorize.net',
    'https://www.authorize.net',
    'payment_processing',
    '["payments", "enterprise", "secure", "gateway"]',
    '["payment_gateway", "fraud_detection", "recurring_billing", "customer_profiles"]',
    'api_key',
    'subscription',
    'active', 1
);

-- Plaid
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'plaid',
    'Plaid',
    'https://plaid.com',
    'payment_processing',
    '["banking_api", "ach", "account_verification", "50plus_countries"]',
    '["bank_account_verification", "ach_payments", "transactions", "balance", "identity", "income_verification"]',
    'api_key',
    'per_request',
    'active', 1, 1
);

-- ============================================================
-- TIER 1: E-COMMERCE PLATFORMS
-- ============================================================

-- Shopify
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'shopify',
    'Shopify',
    'https://www.shopify.com',
    'ecommerce',
    '["ecommerce", "online_store", "multi_channel", "payments"]',
    '["products", "orders", "customers", "inventory", "fulfillment", "analytics", "shopify_payments"]',
    'oauth2',
    'subscription',
    'active', 1, 1
);

-- WooCommerce
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'woocommerce',
    'WooCommerce',
    'https://woocommerce.com',
    'ecommerce',
    '["ecommerce", "wordpress", "open_source", "flexible"]',
    '["products", "orders", "customers", "coupons", "reports", "payment_gateways", "shipping"]',
    'api_key',
    'free',
    'active', 1, 1
);

-- Magento
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'magento',
    'Magento (Adobe Commerce)',
    'https://business.adobe.com/products/magento/magento-commerce.html',
    'ecommerce',
    '["ecommerce", "enterprise", "b2b", "b2c"]',
    '["catalog_management", "order_management", "customer_segmentation", "b2b_features", "multi_store"]',
    'oauth2',
    'enterprise',
    'active', 1
);

-- BigCommerce
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'bigcommerce',
    'BigCommerce',
    'https://www.bigcommerce.com',
    'ecommerce',
    '["ecommerce", "saas", "multi_channel", "scalable"]',
    '["products", "orders", "customers", "multi_channel_selling", "headless_commerce", "b2b_edition"]',
    'oauth2',
    'subscription',
    'active', 1
);

-- ============================================================
-- TIER 2: CRM SYSTEMS
-- ============================================================

-- Salesforce
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'salesforce',
    'Salesforce',
    'https://www.salesforce.com',
    'crm',
    '["crm", "enterprise", "sales", "marketing", "service"]',
    '["leads", "contacts", "accounts", "opportunities", "cases", "campaigns", "reports", "einstein_ai"]',
    'oauth2',
    'subscription',
    'active', 1, 1
);

-- HubSpot CRM
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'hubspot',
    'HubSpot CRM',
    'https://www.hubspot.com',
    'crm',
    '["crm", "marketing_automation", "sales", "service"]',
    '["contacts", "companies", "deals", "tickets", "email_marketing", "landing_pages", "workflows", "reporting"]',
    'oauth2',
    'freemium',
    'active', 1, 1
);

-- Pipedrive
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'pipedrive',
    'Pipedrive',
    'https://www.pipedrive.com',
    'crm',
    '["crm", "sales_focused", "pipeline_management"]',
    '["deals", "contacts", "organizations", "activities", "pipelines", "email_integration", "sales_reporting"]',
    'oauth2',
    'subscription',
    'active', 1
);

-- Zoho CRM
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'zoho_crm',
    'Zoho CRM',
    'https://www.zoho.com/crm',
    'crm',
    '["crm", "smb", "affordable", "automation"]',
    '["leads", "contacts", "accounts", "deals", "campaigns", "social_crm", "ai_assistant"]',
    'oauth2',
    'subscription',
    'active', 1
);

-- ============================================================
-- TIER 2: EMAIL MARKETING & AUTOMATION
-- ============================================================

-- Mailchimp
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'mailchimp',
    'Mailchimp',
    'https://mailchimp.com',
    'marketing_automation',
    '["email_marketing", "sms", "automation", "2000plus_integrations"]',
    '["email_campaigns", "sms_campaigns", "automation", "landing_pages", "audience_segmentation", "analytics"]',
    'oauth2',
    'freemium',
    'active', 1, 1
);

-- SendGrid (Twilio)
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'sendgrid',
    'SendGrid (Twilio)',
    'https://sendgrid.com',
    'communication',
    '["email", "sms", "whatsapp", "transactional", "marketing"]',
    '["transactional_email", "marketing_email", "email_api", "sms", "whatsapp", "email_validation"]',
    'api_key',
    'per_request',
    'active', 1, 1
);

-- Klaviyo
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'klaviyo',
    'Klaviyo',
    'https://www.klaviyo.com',
    'marketing_automation',
    '["email_marketing", "sms", "ecommerce", "personalization"]',
    '["email_campaigns", "sms_campaigns", "automation", "segmentation", "ecommerce_integration", "predictive_analytics"]',
    'api_key',
    'subscription',
    'active', 1
);

-- ActiveCampaign
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'activecampaign',
    'ActiveCampaign',
    'https://www.activecampaign.com',
    'marketing_automation',
    '["email_marketing", "automation", "crm", "sales"]',
    '["email_marketing", "marketing_automation", "crm", "sales_automation", "messaging", "machine_learning"]',
    'api_key',
    'subscription',
    'active', 1
);

-- Twilio
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'twilio',
    'Twilio',
    'https://www.twilio.com',
    'communication',
    '["sms", "voice", "whatsapp", "video", "api"]',
    '["sms", "mms", "voice_calls", "whatsapp", "video", "email", "verify", "lookup"]',
    'api_key',
    'per_request',
    'active', 1, 1
);

-- Postmark
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'postmark',
    'Postmark',
    'https://postmarkapp.com',
    'communication',
    '["transactional_email", "reliable", "deliverability"]',
    '["transactional_email", "email_templates", "bounce_handling", "webhooks", "smtp_relay"]',
    'api_key',
    'per_request',
    'active', 1
);

-- ============================================================
-- TIER 3: TEAM COMMUNICATION & COLLABORATION
-- ============================================================

-- Slack
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'slack',
    'Slack',
    'https://slack.com',
    'communication',
    '["team_chat", "collaboration", "2000plus_integrations", "developer_friendly"]',
    '["channels", "direct_messages", "file_sharing", "voice_video", "workflows", "app_integrations"]',
    'oauth2',
    'freemium',
    'active', 1, 1
);

-- Microsoft Teams
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'microsoft_teams',
    'Microsoft Teams',
    'https://www.microsoft.com/microsoft-teams',
    'communication',
    '["team_chat", "video", "microsoft_365", "enterprise"]',
    '["chat", "video_meetings", "file_sharing", "microsoft_365_integration", "channels", "apps"]',
    'oauth2',
    'subscription',
    'active', 1, 1
);

-- Zoom
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'zoom',
    'Zoom',
    'https://zoom.us',
    'communication',
    '["video_conferencing", "webinars", "phone", "chat"]',
    '["video_meetings", "webinars", "phone_system", "chat", "rooms", "events", "recordings"]',
    'oauth2',
    'freemium',
    'active', 1, 1
);

-- Google Workspace
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'google_workspace',
    'Google Workspace',
    'https://workspace.google.com',
    'productivity',
    '["email", "calendar", "drive", "docs", "collaboration"]',
    '["gmail", "google_calendar", "google_drive", "google_docs", "google_sheets", "google_meet"]',
    'oauth2',
    'subscription',
    'active', 1, 1
);

-- DocuSign
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'docusign',
    'DocuSign',
    'https://www.docusign.com',
    'document_management',
    '["esignature", "agreement_cloud", "enterprise"]',
    '["esignature", "contract_lifecycle", "document_generation", "payments", "notary", "identify_verification"]',
    'oauth2',
    'subscription',
    'active', 1, 1
);

-- PandaDoc
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'pandadoc',
    'PandaDoc',
    'https://www.pandadoc.com',
    'document_management',
    '["esignature", "proposals", "quotes", "payments"]',
    '["document_creation", "esignatures", "payments", "crm_integration", "analytics", "templates"]',
    'api_key',
    'subscription',
    'active', 1
);

-- Google Drive
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'google_drive',
    'Google Drive',
    'https://drive.google.com',
    'document_management',
    '["cloud_storage", "collaboration", "sharing"]',
    '["file_storage", "file_sharing", "collaboration", "real_time_editing", "version_control"]',
    'oauth2',
    'freemium',
    'active', 1, 1
);

-- Dropbox
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'dropbox',
    'Dropbox',
    'https://www.dropbox.com',
    'document_management',
    '["cloud_storage", "file_sync", "collaboration"]',
    '["file_storage", "file_sync", "file_sharing", "dropbox_paper", "esignatures", "team_folders"]',
    'oauth2',
    'freemium',
    'active', 1
);

-- ============================================================
-- TIER 3: CUSTOMER SUPPORT
-- ============================================================

-- Zendesk
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'zendesk',
    'Zendesk',
    'https://www.zendesk.com',
    'customer_support',
    '["helpdesk", "ticketing", "1000plus_integrations", "ai"]',
    '["ticketing", "live_chat", "knowledge_base", "analytics", "ai_automation", "omnichannel_support"]',
    'oauth2',
    'subscription',
    'active', 1, 1
);

-- Intercom
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'intercom',
    'Intercom',
    'https://www.intercom.com',
    'customer_support',
    '["live_chat", "messaging", "conversational", "product_tours"]',
    '["live_chat", "help_desk", "product_tours", "customer_engagement", "outbound_messaging", "bots"]',
    'oauth2',
    'subscription',
    'active', 1
);

-- Freshdesk
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'freshdesk',
    'Freshdesk',
    'https://www.freshdesk.com',
    'customer_support',
    '["helpdesk", "ticketing", "150plus_integrations", "affordable"]',
    '["ticketing", "knowledge_base", "community_forums", "automation", "reporting", "multichannel"]',
    'api_key',
    'freemium',
    'active', 1
);

-- ============================================================
-- TIER 4: AI/ML PLATFORMS
-- ============================================================

-- OpenAI
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'openai',
    'OpenAI',
    'https://openai.com',
    'ai_ml',
    '["gpt4", "chatgpt", "dall_e", "whisper", "embeddings"]',
    '["text_generation", "chat_completions", "image_generation", "speech_to_text", "embeddings", "fine_tuning"]',
    'api_key',
    'per_request',
    'active', 1, 1
);

-- Google Gemini
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'google_gemini',
    'Google Gemini',
    'https://ai.google.dev',
    'ai_ml',
    '["multimodal", "google_cloud", "enterprise", "gemini"]',
    '["text_generation", "multimodal_understanding", "code_generation", "embeddings", "function_calling"]',
    'api_key',
    'per_request',
    'active', 1, 1
);

-- Hugging Face
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'huggingface',
    'Hugging Face',
    'https://huggingface.co',
    'ai_ml',
    '["open_source", "transformers", "ml_models", "datasets"]',
    '["model_hosting", "inference_api", "datasets", "spaces", "model_training", "community_models"]',
    'api_key',
    'freemium',
    'active', 1
);

-- Replicate
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'replicate',
    'Replicate',
    'https://replicate.com',
    'ai_ml',
    '["ml_models", "api", "stable_diffusion", "llms"]',
    '["run_ml_models", "image_generation", "language_models", "video_generation", "audio_processing"]',
    'api_key',
    'per_request',
    'active', 1
);

-- ============================================================
-- TIER 4: WORKFLOW AUTOMATION
-- ============================================================

-- Zapier
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'zapier',
    'Zapier',
    'https://zapier.com',
    'automation',
    '["workflow_automation", "7000plus_integrations", "no_code"]',
    '["multi_step_zaps", "filters", "formatters", "webhooks", "ai_integration", "paths"]',
    'api_key',
    'freemium',
    'active', 1, 1
);

-- Make (Integromat)
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'make',
    'Make (Integromat)',
    'https://www.make.com',
    'automation',
    '["workflow_automation", "1500plus_integrations", "visual_workflows"]',
    '["scenarios", "data_transformation", "error_handling", "scheduling", "webhooks", "visual_builder"]',
    'api_key',
    'freemium',
    'active', 1
);

-- n8n
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'n8n',
    'n8n',
    'https://n8n.io',
    'automation',
    '["workflow_automation", "open_source", "ai_native", "self_hosted"]',
    '["workflows", "ai_integration", "custom_code", "1000plus_integrations", "webhooks", "langchain"]',
    'api_key',
    'free',
    'active', 1
);

-- Pipedream
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'pipedream',
    'Pipedream',
    'https://pipedream.com',
    'automation',
    '["workflow_automation", "developer_first", "code", "serverless"]',
    '["workflows", "custom_code", "event_sources", "scheduled_jobs", "http_requests", "data_stores"]',
    'api_key',
    'freemium',
    'active', 1
);

-- ============================================================
-- TIER 5: HR & PAYROLL
-- ============================================================

-- Gusto
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'gusto',
    'Gusto',
    'https://gusto.com',
    'hr_payroll',
    '["payroll", "hr", "benefits", "small_business"]',
    '["full_service_payroll", "benefits_administration", "time_tracking", "hr_tools", "compliance", "onboarding"]',
    'oauth2',
    'subscription',
    'active', 1, 1
);

-- ADP
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'adp',
    'ADP',
    'https://www.adp.com',
    'hr_payroll',
    '["payroll", "hr", "enterprise", "700plus_integrations"]',
    '["payroll_processing", "hr_management", "time_attendance", "benefits", "compliance", "talent_management"]',
    'oauth2',
    'enterprise',
    'active', 1
);

-- BambooHR
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'bamboohr',
    'BambooHR',
    'https://www.bamboohr.com',
    'hr_payroll',
    '["hr", "employee_database", "onboarding", "performance"]',
    '["employee_records", "onboarding", "offboarding", "time_off", "performance_management", "reporting"]',
    'api_key',
    'subscription',
    'active', 1
);

-- Workday
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'workday',
    'Workday',
    'https://www.workday.com',
    'hr_payroll',
    '["hr", "payroll", "finance", "enterprise", "global"]',
    '["hr_management", "payroll", "time_tracking", "benefits", "talent_management", "financial_management"]',
    'oauth2',
    'enterprise',
    'active', 1
);

-- ============================================================
-- TIER 6: BUSINESS INTELLIGENCE & ANALYTICS
-- ============================================================

-- Power BI
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'powerbi',
    'Microsoft Power BI',
    'https://powerbi.microsoft.com',
    'analytics',
    '["bi", "data_visualization", "microsoft", "enterprise"]',
    '["dashboards", "reports", "data_modeling", "ai_insights", "microsoft_fabric", "real_time_analytics"]',
    'oauth2',
    'subscription',
    'active', 1, 1
);

-- Tableau
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'tableau',
    'Tableau',
    'https://www.tableau.com',
    'analytics',
    '["bi", "data_visualization", "interactive", "visual_analytics"]',
    '["interactive_dashboards", "visual_analytics", "data_prep", "collaboration", "mobile", "ai_powered"]',
    'api_key',
    'subscription',
    'active', 1, 1
);

-- Looker
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'looker',
    'Looker (Google Cloud)',
    'https://looker.com',
    'analytics',
    '["bi", "google_cloud", "800plus_connectors", "data_modeling"]',
    '["data_exploration", "dashboards", "lookml", "embedded_analytics", "google_cloud_integration"]',
    'oauth2',
    'subscription',
    'active', 1
);

-- Google Analytics
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'google_analytics',
    'Google Analytics',
    'https://analytics.google.com',
    'analytics',
    '["web_analytics", "marketing", "google", "standard"]',
    '["website_analytics", "ecommerce_tracking", "conversion_tracking", "audience_insights", "event_tracking"]',
    'oauth2',
    'freemium',
    'active', 1, 1
);

-- ============================================================
-- EMAIL PROVIDERS
-- ============================================================

-- Gmail (Google Mail)
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'gmail',
    'Gmail',
    'https://mail.google.com',
    'communication',
    '["email", "google", "personal", "business", "imap_smtp"]',
    '["send_email", "receive_email", "labels", "filters", "search", "attachments", "google_workspace_integration"]',
    'oauth2',
    'freemium',
    'active', 1, 1
);

-- Microsoft Outlook (Microsoft 365)
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified, is_recommended
) VALUES (
    'outlook',
    'Microsoft Outlook',
    'https://outlook.com',
    'communication',
    '["email", "microsoft_365", "calendar", "contacts", "enterprise"]',
    '["send_email", "receive_email", "calendar", "contacts", "tasks", "microsoft_365_integration", "exchange_server"]',
    'oauth2',
    'freemium',
    'active', 1, 1
);

-- Zoho Mail
INSERT INTO integration_providers (
    provider_key, provider_name, provider_website, provider_type,
    category_tags, capabilities, auth_type, pricing_model,
    status, is_verified
) VALUES (
    'zoho_mail',
    'Zoho Mail',
    'https://www.zoho.com/mail',
    'communication',
    '["email", "business", "ad_free", "privacy_focused"]',
    '["send_email", "receive_email", "folders", "filters", "calendar", "notes", "tasks", "zoho_integration"]',
    'oauth2',
    'freemium',
    'active', 1
);
