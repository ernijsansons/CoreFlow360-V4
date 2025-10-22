-- Migration: 062_developer_platform
-- Description: Developer Platform for Custom Integrations
-- Features: Custom integrations, developer accounts, marketplace, OAuth helpers
-- Created: 2025-10-20
-- Part of: Global ERP Infrastructure - Developer Platform Extension
-- Scope: Enables third-party developers to build custom integrations for ALL ERP modules

-- ============================================================
-- DEVELOPERS TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS developers (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,

    -- Developer Profile
    developer_name TEXT,
    developer_email TEXT,
    company_name TEXT,
    website_url TEXT,
    github_username TEXT,

    -- Developer Tier
    developer_tier TEXT DEFAULT 'free' CHECK(developer_tier IN (
        'free',      -- 25 installs, private only
        'pro',       -- 500 installs, public marketplace
        'enterprise' -- Unlimited, white-label, SLA
    )),

    -- API Credentials
    api_key TEXT UNIQUE NOT NULL,
    api_secret TEXT NOT NULL,
    webhook_secret TEXT NOT NULL,

    -- Quotas & Limits
    max_custom_integrations INTEGER DEFAULT 5,
    max_installs INTEGER DEFAULT 25,
    max_api_calls_per_day INTEGER DEFAULT 10000,

    -- Statistics
    total_integrations INTEGER DEFAULT 0,
    total_installs INTEGER DEFAULT 0,
    total_api_calls INTEGER DEFAULT 0,
    total_revenue_usd REAL DEFAULT 0.0,

    -- Status
    status TEXT DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'banned')),
    verification_status TEXT DEFAULT 'unverified' CHECK(verification_status IN ('unverified', 'email_verified', 'identity_verified')),

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity_at TIMESTAMP
);

CREATE INDEX idx_developers_user_id ON developers(user_id);
CREATE INDEX idx_developers_api_key ON developers(api_key) WHERE status = 'active';
CREATE INDEX idx_developers_tier ON developers(developer_tier);
CREATE INDEX idx_developers_status ON developers(status) WHERE status = 'active';

-- ============================================================
-- CUSTOM INTEGRATIONS TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS custom_integrations (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    developer_id TEXT NOT NULL REFERENCES developers(id) ON DELETE CASCADE,

    -- Integration Identity
    integration_key TEXT NOT NULL UNIQUE, -- 'my_custom_crm', 'company_internal_tool'
    integration_name TEXT NOT NULL,
    integration_description TEXT,
    integration_version TEXT NOT NULL DEFAULT '1.0.0', -- Semantic versioning

    -- Provider Details
    provider_logo_url TEXT,
    provider_website TEXT,
    provider_category TEXT, -- Same as integration_providers.provider_type
    category_tags TEXT, -- JSON array

    -- Code & Configuration
    code_bundle TEXT NOT NULL, -- Bundled TypeScript/JavaScript code
    manifest TEXT NOT NULL, -- JSON: { actions, triggers, auth, schemas }
    source_code_url TEXT, -- Optional GitHub repo

    -- Authentication
    auth_type TEXT NOT NULL CHECK(auth_type IN (
        'api_key',
        'oauth2',
        'basic_auth',
        'bearer_token',
        'custom'
    )),
    auth_config TEXT, -- JSON: OAuth URLs, scopes, etc.

    -- Capabilities
    supported_actions TEXT, -- JSON array: ['create_contact', 'update_deal']
    supported_triggers TEXT, -- JSON array: ['new_contact', 'deal_closed']
    supported_entities TEXT, -- JSON array: ['contact', 'deal', 'task']

    -- Visibility & Distribution
    visibility TEXT DEFAULT 'private' CHECK(visibility IN (
        'private',      -- Only developer can see/install
        'organization', -- Visible to developer's organization
        'public'        -- Listed in marketplace
    )),
    marketplace_status TEXT DEFAULT 'draft' CHECK(marketplace_status IN (
        'draft',       -- In development
        'review',      -- Submitted for review
        'approved',    -- Approved for marketplace
        'rejected',    -- Rejected by review
        'published',   -- Live in marketplace
        'deprecated'   -- No longer maintained
    )),

    -- Pricing (Optional)
    pricing_model TEXT CHECK(pricing_model IN (
        'free',
        'one_time',
        'subscription',
        'usage_based'
    )),
    price_usd REAL DEFAULT 0.0,

    -- Quality & Trust
    install_count INTEGER DEFAULT 0,
    active_install_count INTEGER DEFAULT 0,
    rating REAL, -- 1.0 to 5.0
    total_reviews INTEGER DEFAULT 0,

    -- Compliance
    security_reviewed BOOLEAN DEFAULT 0,
    security_review_date TIMESTAMP,
    security_reviewer_id TEXT,
    data_privacy_compliant BOOLEAN DEFAULT 0,

    -- Documentation
    documentation_url TEXT,
    changelog_url TEXT,
    support_email TEXT,
    support_url TEXT,

    -- Webhooks
    webhook_support BOOLEAN DEFAULT 0,
    webhook_events TEXT, -- JSON array: ['contact.created', 'deal.updated']

    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    published_at TIMESTAMP,
    last_deployed_at TIMESTAMP
);

CREATE INDEX idx_custom_integrations_developer ON custom_integrations(developer_id);
CREATE INDEX idx_custom_integrations_key ON custom_integrations(integration_key);
CREATE INDEX idx_custom_integrations_visibility ON custom_integrations(visibility);
CREATE INDEX idx_custom_integrations_status ON custom_integrations(marketplace_status) WHERE marketplace_status = 'published';
CREATE INDEX idx_custom_integrations_category ON custom_integrations(provider_category);
CREATE INDEX idx_custom_integrations_rating ON custom_integrations(rating DESC) WHERE marketplace_status = 'published';

-- ============================================================
-- CUSTOM INTEGRATION INSTALLS (Per Business)
-- ============================================================
CREATE TABLE IF NOT EXISTS custom_integration_installs (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
    custom_integration_id TEXT NOT NULL REFERENCES custom_integrations(id) ON DELETE CASCADE,

    -- Installation Details
    integration_version TEXT NOT NULL, -- Version installed
    credentials_encrypted TEXT, -- Encrypted OAuth/API key credentials

    -- OAuth Tokens (if applicable)
    oauth_access_token TEXT,
    oauth_refresh_token TEXT,
    oauth_token_expires_at TIMESTAMP,
    oauth_scopes TEXT, -- JSON array

    -- Configuration
    settings TEXT, -- JSON: custom settings per business
    enabled_features TEXT, -- JSON array: which actions/triggers enabled

    -- Webhook Configuration
    webhook_url TEXT,
    webhook_secret TEXT,
    webhook_events TEXT, -- JSON array: subscribed events

    -- Usage Tracking
    total_requests INTEGER DEFAULT 0,
    requests_this_month INTEGER DEFAULT 0,
    last_request_at TIMESTAMP,

    -- Status
    install_status TEXT DEFAULT 'active' CHECK(install_status IN (
        'active',
        'inactive',
        'expired',
        'error',
        'rate_limited',
        'suspended'
    )),

    -- Error Handling
    error_count INTEGER DEFAULT 0,
    last_error_message TEXT,
    last_error_at TIMESTAMP,

    -- Audit
    installed_by TEXT NOT NULL REFERENCES users(id),
    installed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    uninstalled_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(business_id, custom_integration_id)
);

CREATE INDEX idx_custom_integration_installs_business ON custom_integration_installs(business_id);
CREATE INDEX idx_custom_integration_installs_integration ON custom_integration_installs(custom_integration_id);
CREATE INDEX idx_custom_integration_installs_status ON custom_integration_installs(install_status) WHERE install_status = 'active';

-- ============================================================
-- CUSTOM INTEGRATION REVIEWS
-- ============================================================
CREATE TABLE IF NOT EXISTS custom_integration_reviews (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    custom_integration_id TEXT NOT NULL REFERENCES custom_integrations(id) ON DELETE CASCADE,
    business_id TEXT NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Review Content
    rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
    review_title TEXT,
    review_text TEXT,

    -- Developer Response
    developer_response TEXT,
    developer_response_at TIMESTAMP,

    -- Moderation
    is_verified_install BOOLEAN DEFAULT 0, -- User actually installed it
    is_flagged BOOLEAN DEFAULT 0,
    flagged_reason TEXT,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(custom_integration_id, business_id, user_id)
);

CREATE INDEX idx_custom_integration_reviews_integration ON custom_integration_reviews(custom_integration_id);
CREATE INDEX idx_custom_integration_reviews_rating ON custom_integration_reviews(rating);
CREATE INDEX idx_custom_integration_reviews_flagged ON custom_integration_reviews(is_flagged) WHERE is_flagged = 1;

-- ============================================================
-- CUSTOM INTEGRATION USAGE LOGS
-- ============================================================
CREATE TABLE IF NOT EXISTS custom_integration_usage_logs (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    custom_integration_install_id TEXT NOT NULL REFERENCES custom_integration_installs(id) ON DELETE CASCADE,
    business_id TEXT NOT NULL REFERENCES businesses(id),
    custom_integration_id TEXT NOT NULL REFERENCES custom_integrations(id),

    -- Request Details
    action_key TEXT, -- 'create_contact', 'update_deal'
    trigger_key TEXT, -- 'new_contact', 'deal_closed'
    request_type TEXT, -- 'action' or 'trigger'
    request_payload_hash TEXT, -- For deduplication

    -- Response Details
    response_status_code INTEGER,
    response_time_ms INTEGER,
    response_success BOOLEAN,
    response_error TEXT,

    -- Entity Tracking
    entity_id TEXT,
    entity_type TEXT,

    -- Billing
    credits_used INTEGER DEFAULT 1,
    cost_usd REAL DEFAULT 0.0,

    -- Context
    triggered_by TEXT CHECK(triggered_by IN ('user', 'automation', 'webhook', 'cron', 'api')),
    user_id TEXT REFERENCES users(id),
    correlation_id TEXT, -- For tracing across systems

    -- Timestamps
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_custom_integration_usage_install ON custom_integration_usage_logs(custom_integration_install_id);
CREATE INDEX idx_custom_integration_usage_business ON custom_integration_usage_logs(business_id);
CREATE INDEX idx_custom_integration_usage_integration ON custom_integration_usage_logs(custom_integration_id);
CREATE INDEX idx_custom_integration_usage_date ON custom_integration_usage_logs(requested_at DESC);
CREATE INDEX idx_custom_integration_usage_success ON custom_integration_usage_logs(response_success);

-- ============================================================
-- DEVELOPER API KEYS
-- ============================================================
CREATE TABLE IF NOT EXISTS developer_api_keys (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    developer_id TEXT NOT NULL REFERENCES developers(id) ON DELETE CASCADE,

    -- Key Details
    key_name TEXT NOT NULL,
    api_key TEXT UNIQUE NOT NULL,
    api_key_prefix TEXT NOT NULL, -- First 8 chars for display
    api_key_hash TEXT NOT NULL, -- SHA-256 hash for validation

    -- Permissions
    scopes TEXT, -- JSON array: ['integrations:read', 'integrations:write', 'analytics:read']

    -- Usage Tracking
    total_requests INTEGER DEFAULT 0,
    last_used_at TIMESTAMP,

    -- Security
    ip_whitelist TEXT, -- JSON array of allowed IPs
    rate_limit_per_hour INTEGER DEFAULT 1000,

    -- Status
    status TEXT DEFAULT 'active' CHECK(status IN ('active', 'revoked', 'expired')),
    expires_at TIMESTAMP,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP,
    revoked_by TEXT REFERENCES users(id)
);

CREATE INDEX idx_developer_api_keys_developer ON developer_api_keys(developer_id);
CREATE INDEX idx_developer_api_keys_key ON developer_api_keys(api_key) WHERE status = 'active';
CREATE INDEX idx_developer_api_keys_status ON developer_api_keys(status);

-- ============================================================
-- OAUTH CONNECTIONS (For Custom Integrations)
-- ============================================================
CREATE TABLE IF NOT EXISTS custom_integration_oauth_connections (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    custom_integration_install_id TEXT NOT NULL REFERENCES custom_integration_installs(id) ON DELETE CASCADE,
    custom_integration_id TEXT NOT NULL REFERENCES custom_integrations(id),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- OAuth Flow
    authorization_code TEXT,
    state TEXT, -- CSRF protection
    code_verifier TEXT, -- PKCE
    code_challenge TEXT, -- PKCE

    -- Tokens
    access_token TEXT NOT NULL,
    refresh_token TEXT,
    token_type TEXT DEFAULT 'Bearer',
    expires_at TIMESTAMP,
    scopes TEXT, -- JSON array

    -- Provider Details
    provider_user_id TEXT, -- External provider's user ID
    provider_account_info TEXT, -- JSON: additional account info

    -- Status
    connection_status TEXT DEFAULT 'active' CHECK(connection_status IN (
        'active',
        'expired',
        'revoked',
        'error'
    )),

    -- Refresh Tracking
    last_refreshed_at TIMESTAMP,
    refresh_count INTEGER DEFAULT 0,

    -- Error Handling
    last_error TEXT,
    last_error_at TIMESTAMP,
    retry_count INTEGER DEFAULT 0,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_custom_oauth_install ON custom_integration_oauth_connections(custom_integration_install_id);
CREATE INDEX idx_custom_oauth_integration ON custom_integration_oauth_connections(custom_integration_id);
CREATE INDEX idx_custom_oauth_business ON custom_integration_oauth_connections(business_id);
CREATE INDEX idx_custom_oauth_status ON custom_integration_oauth_connections(connection_status);
CREATE INDEX idx_custom_oauth_expires ON custom_integration_oauth_connections(expires_at) WHERE connection_status = 'active';

-- ============================================================
-- MARKETPLACE ANALYTICS
-- ============================================================
CREATE TABLE IF NOT EXISTS custom_integration_analytics (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    custom_integration_id TEXT NOT NULL REFERENCES custom_integrations(id) ON DELETE CASCADE,

    -- Time Period
    analytics_date DATE NOT NULL,
    analytics_type TEXT CHECK(analytics_type IN ('daily', 'weekly', 'monthly')),

    -- Installation Metrics
    new_installs INTEGER DEFAULT 0,
    uninstalls INTEGER DEFAULT 0,
    active_installs INTEGER DEFAULT 0,

    -- Usage Metrics
    total_requests INTEGER DEFAULT 0,
    successful_requests INTEGER DEFAULT 0,
    failed_requests INTEGER DEFAULT 0,
    avg_response_time_ms INTEGER,

    -- Revenue Metrics (if paid)
    revenue_usd REAL DEFAULT 0.0,
    refunds_usd REAL DEFAULT 0.0,

    -- User Engagement
    unique_users INTEGER DEFAULT 0,
    unique_businesses INTEGER DEFAULT 0,

    -- Quality Metrics
    new_reviews INTEGER DEFAULT 0,
    avg_rating REAL,
    error_rate REAL,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_custom_analytics_integration ON custom_integration_analytics(custom_integration_id);
CREATE INDEX idx_custom_analytics_date ON custom_integration_analytics(analytics_date DESC);
CREATE UNIQUE INDEX idx_custom_analytics_unique ON custom_integration_analytics(custom_integration_id, analytics_date, analytics_type);
