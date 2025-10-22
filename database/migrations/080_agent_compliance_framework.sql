-- Migration: 080_agent_compliance_framework
-- Description: Comprehensive compliance and governance framework for AI agents
-- Created: 2025-10-20
-- Author: CoreFlow360 V4 Agent System

-- ============================================================================
-- COMPANY GUIDELINES & POLICIES
-- ============================================================================

-- Company-wide guidelines that all agents must follow
CREATE TABLE IF NOT EXISTS company_guidelines (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Guideline Configuration
    name TEXT NOT NULL,
    description TEXT,
    category TEXT NOT NULL CHECK (category IN (
        'tone_and_style',
        'content_restrictions',
        'data_boundaries',
        'privacy_and_security',
        'brand_voice',
        'compliance_rules',
        'escalation_triggers',
        'response_limits'
    )),
    severity TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('low', 'medium', 'high', 'critical')),

    -- Guideline Rules (JSON)
    rules TEXT NOT NULL DEFAULT '{}', -- { "prohibited_topics": [], "required_tone": "", "max_length": 0 }

    -- Enforcement Settings
    enforcement_mode TEXT NOT NULL DEFAULT 'enforce' CHECK (enforcement_mode IN (
        'monitor',  -- Log violations but allow
        'warn',     -- Warn user but allow
        'enforce'   -- Block non-compliant responses
    )),
    auto_remediation INTEGER DEFAULT 0, -- Attempt to fix violations automatically

    -- Applicability
    applies_to_agents TEXT DEFAULT '[]', -- JSON array of agent IDs (empty = all agents)
    applies_to_departments TEXT DEFAULT '[]', -- JSON array of departments

    -- Status & Metadata
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'archived')),
    priority INTEGER DEFAULT 100, -- Higher priority rules checked first
    metadata TEXT DEFAULT '{}',

    -- Timestamps
    created_by TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    effective_from TEXT DEFAULT (datetime('now')),
    effective_until TEXT,

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Agent-specific policies (overrides company guidelines)
CREATE TABLE IF NOT EXISTS agent_policies (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,

    -- Policy Configuration
    policy_name TEXT NOT NULL,
    policy_type TEXT NOT NULL CHECK (policy_type IN (
        'capability_restriction',  -- Disable specific capabilities
        'data_access_control',     -- Limit data agent can access
        'rate_limiting',           -- Custom rate limits
        'response_filtering',      -- Content filtering rules
        'escalation_rules',        -- When to escalate to human
        'quality_requirements',    -- Minimum quality thresholds
        'cost_limits'              -- Budget constraints
    )),

    -- Policy Rules (JSON)
    policy_config TEXT NOT NULL DEFAULT '{}',

    -- Enforcement
    enabled INTEGER DEFAULT 1,
    enforcement_level TEXT DEFAULT 'strict' CHECK (enforcement_level IN ('lenient', 'moderate', 'strict')),

    -- Status & Metadata
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'testing')),
    metadata TEXT DEFAULT '{}',

    -- Timestamps
    created_by TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Compliance violations tracking and audit
CREATE TABLE IF NOT EXISTS compliance_violations (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Violation Details
    agent_id TEXT NOT NULL,
    guideline_id TEXT, -- Which guideline was violated
    policy_id TEXT,    -- Which policy was violated
    violation_type TEXT NOT NULL CHECK (violation_type IN (
        'prohibited_content',
        'tone_violation',
        'data_boundary_breach',
        'unauthorized_capability',
        'rate_limit_exceeded',
        'quality_below_threshold',
        'escalation_required',
        'pii_exposure',
        'cost_limit_exceeded'
    )),

    -- Context
    task_id TEXT,
    capability TEXT,
    user_id TEXT,
    department TEXT,

    -- Violation Content
    original_response TEXT, -- What the agent tried to output
    violation_details TEXT NOT NULL, -- JSON with specific violation info
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),

    -- Action Taken
    action_taken TEXT NOT NULL CHECK (action_taken IN (
        'blocked',              -- Response was blocked
        'modified',             -- Response was auto-corrected
        'warned',               -- Warning shown but allowed
        'escalated_to_admin',   -- Sent to admin review
        'escalated_to_human'    -- Sent to human agent
    )),
    remediated_response TEXT, -- The corrected response if modified

    -- Resolution
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'reviewed', 'resolved', 'dismissed')),
    resolved_by TEXT,
    resolved_at TEXT,
    resolution_notes TEXT,

    -- Timestamps
    occurred_at TEXT DEFAULT (datetime('now')),
    created_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (guideline_id) REFERENCES company_guidelines(id) ON DELETE SET NULL,
    FOREIGN KEY (policy_id) REFERENCES agent_policies(id) ON DELETE SET NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (resolved_by) REFERENCES users(id)
);

-- ============================================================================
-- COMPANY KNOWLEDGE BASE
-- ============================================================================

-- Learned company information (website, products, brand)
CREATE TABLE IF NOT EXISTS company_knowledge_base (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Content Classification
    content_type TEXT NOT NULL CHECK (content_type IN (
        'product',
        'service',
        'pricing',
        'policy',
        'terms_of_service',
        'privacy_policy',
        'faq',
        'blog_post',
        'documentation',
        'about_us',
        'contact_info',
        'brand_guidelines',
        'values_mission',
        'other'
    )),
    category TEXT,
    subcategory TEXT,

    -- Content
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    summary TEXT,
    keywords TEXT DEFAULT '[]', -- JSON array of keywords

    -- Source Information
    source_url TEXT,
    source_id TEXT, -- Reference to knowledge_sources table
    scrape_date TEXT,

    -- Content Metadata
    language TEXT DEFAULT 'en',
    word_count INTEGER,
    reading_level TEXT CHECK (reading_level IN ('basic', 'intermediate', 'advanced', 'expert')),

    -- SEO & Search
    meta_title TEXT,
    meta_description TEXT,
    slug TEXT,

    -- Validation & Quality
    verified INTEGER DEFAULT 0,
    verified_by TEXT,
    verified_at TEXT,
    accuracy_score REAL DEFAULT 0 CHECK (accuracy_score >= 0 AND accuracy_score <= 1),
    freshness_score REAL DEFAULT 1 CHECK (freshness_score >= 0 AND freshness_score <= 1),

    -- Usage Tracking
    times_referenced INTEGER DEFAULT 0,
    last_referenced_at TEXT,
    helpfulness_score REAL DEFAULT 0 CHECK (helpfulness_score >= 0 AND helpfulness_score <= 1),

    -- Status & Metadata
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'outdated', 'archived', 'pending_review')),
    metadata TEXT DEFAULT '{}',

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT, -- When this knowledge becomes stale

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (verified_by) REFERENCES users(id)
);

-- Knowledge sources (where to learn from)
CREATE TABLE IF NOT EXISTS knowledge_sources (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Source Configuration
    source_name TEXT NOT NULL,
    source_type TEXT NOT NULL CHECK (source_type IN (
        'website',
        'api',
        'document',
        'rss_feed',
        'knowledge_base',
        'crm',
        'manual_entry'
    )),
    source_url TEXT,

    -- Scraping Configuration (for websites)
    scraping_config TEXT DEFAULT '{}', -- JSON: { "max_depth": 3, "follow_external": false, "rate_limit": 10 }
    crawl_frequency TEXT DEFAULT 'weekly' CHECK (crawl_frequency IN ('daily', 'weekly', 'monthly', 'manual')),
    last_crawl_at TEXT,
    next_crawl_at TEXT,

    -- Authentication (if needed)
    requires_auth INTEGER DEFAULT 0,
    auth_type TEXT CHECK (auth_type IN ('none', 'basic', 'bearer', 'oauth', 'api_key')),
    credentials_encrypted TEXT, -- Encrypted credentials

    -- Filters & Rules
    include_patterns TEXT DEFAULT '[]', -- JSON array of URL patterns to include
    exclude_patterns TEXT DEFAULT '[]', -- JSON array of URL patterns to exclude
    content_selectors TEXT DEFAULT '{}', -- JSON: CSS/XPath selectors for content extraction

    -- Status & Health
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'error', 'rate_limited')),
    last_error TEXT,
    error_count INTEGER DEFAULT 0,
    success_rate REAL DEFAULT 1,

    -- Statistics
    pages_crawled INTEGER DEFAULT 0,
    content_extracted INTEGER DEFAULT 0,
    last_crawl_duration_ms INTEGER,

    -- Priority
    priority INTEGER DEFAULT 100, -- Higher priority sources crawled first
    auto_refresh INTEGER DEFAULT 1, -- Automatically refresh on schedule

    -- Timestamps
    created_by TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- ============================================================================
-- ONBOARDING CONFIGURATION
-- ============================================================================

-- Business-specific onboarding flows
CREATE TABLE IF NOT EXISTS onboarding_configurations (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Configuration
    flow_name TEXT NOT NULL,
    flow_type TEXT NOT NULL CHECK (flow_type IN (
        'initial_setup',
        'user_onboarding',
        'data_migration',
        'integration_setup',
        'team_onboarding'
    )),

    -- Flow Steps (JSON array)
    steps TEXT NOT NULL DEFAULT '[]', -- [{ "id": "step1", "name": "", "required": true }]

    -- Customization
    industry_template TEXT,
    company_size_template TEXT CHECK (company_size_template IN ('micro', 'small', 'medium', 'large', 'enterprise')),

    -- Requirements
    required_data_fields TEXT DEFAULT '[]', -- JSON array of required fields
    optional_data_fields TEXT DEFAULT '[]',
    validation_rules TEXT DEFAULT '{}',     -- JSON validation rules

    -- AI Assistant Configuration
    enable_ai_guidance INTEGER DEFAULT 1,
    ai_tone TEXT DEFAULT 'professional' CHECK (ai_tone IN ('casual', 'professional', 'technical', 'friendly')),
    help_level TEXT DEFAULT 'detailed' CHECK (help_level IN ('minimal', 'standard', 'detailed', 'verbose')),

    -- Progress Tracking
    enable_progress_tracking INTEGER DEFAULT 1,
    enable_analytics INTEGER DEFAULT 1,
    send_completion_email INTEGER DEFAULT 1,

    -- Status & Metadata
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'draft')),
    version INTEGER DEFAULT 1,
    metadata TEXT DEFAULT '{}',

    -- Timestamps
    created_by TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id),

    -- Unique constraint
    UNIQUE(business_id, flow_name)
);

-- Onboarding progress tracking
CREATE TABLE IF NOT EXISTS onboarding_progress (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    configuration_id TEXT NOT NULL,

    -- Progress
    current_step TEXT NOT NULL,
    completed_steps TEXT DEFAULT '[]', -- JSON array of completed step IDs
    skipped_steps TEXT DEFAULT '[]',
    failed_steps TEXT DEFAULT '[]',

    -- Status
    status TEXT DEFAULT 'in_progress' CHECK (status IN ('not_started', 'in_progress', 'completed', 'abandoned')),
    completion_percentage INTEGER DEFAULT 0 CHECK (completion_percentage >= 0 AND completion_percentage <= 100),

    -- Time Tracking
    started_at TEXT,
    completed_at TEXT,
    estimated_time_remaining_minutes INTEGER,
    actual_time_minutes INTEGER,

    -- Interaction Data
    ai_interactions_count INTEGER DEFAULT 0,
    help_requests_count INTEGER DEFAULT 0,
    errors_encountered INTEGER DEFAULT 0,

    -- Data Collected
    imported_data_summary TEXT DEFAULT '{}', -- JSON summary of imported data

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (configuration_id) REFERENCES onboarding_configurations(id) ON DELETE CASCADE
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Company Guidelines Indexes
CREATE INDEX IF NOT EXISTS idx_guidelines_business_status
    ON company_guidelines(business_id, status);
CREATE INDEX IF NOT EXISTS idx_guidelines_category
    ON company_guidelines(category, severity);
CREATE INDEX IF NOT EXISTS idx_guidelines_effective
    ON company_guidelines(effective_from, effective_until);

-- Agent Policies Indexes
CREATE INDEX IF NOT EXISTS idx_policies_business_agent
    ON agent_policies(business_id, agent_id, status);
CREATE INDEX IF NOT EXISTS idx_policies_type
    ON agent_policies(policy_type, enabled);

-- Compliance Violations Indexes
CREATE INDEX IF NOT EXISTS idx_violations_business_date
    ON compliance_violations(business_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_violations_agent_type
    ON compliance_violations(agent_id, violation_type);
CREATE INDEX IF NOT EXISTS idx_violations_severity_status
    ON compliance_violations(severity, status);
CREATE INDEX IF NOT EXISTS idx_violations_user
    ON compliance_violations(user_id, occurred_at DESC);

-- Knowledge Base Indexes
CREATE INDEX IF NOT EXISTS idx_knowledge_business_type
    ON company_knowledge_base(business_id, content_type, status);
CREATE INDEX IF NOT EXISTS idx_knowledge_source
    ON company_knowledge_base(source_id, scrape_date DESC);
CREATE INDEX IF NOT EXISTS idx_knowledge_verified
    ON company_knowledge_base(business_id, verified, status);
CREATE INDEX IF NOT EXISTS idx_knowledge_freshness
    ON company_knowledge_base(freshness_score DESC, updated_at DESC);

-- Knowledge Sources Indexes
CREATE INDEX IF NOT EXISTS idx_sources_business_status
    ON knowledge_sources(business_id, status);
CREATE INDEX IF NOT EXISTS idx_sources_crawl_schedule
    ON knowledge_sources(next_crawl_at, status);
CREATE INDEX IF NOT EXISTS idx_sources_type
    ON knowledge_sources(source_type, status);

-- Onboarding Configuration Indexes
CREATE INDEX IF NOT EXISTS idx_onboarding_config_business
    ON onboarding_configurations(business_id, status);
CREATE INDEX IF NOT EXISTS idx_onboarding_config_type
    ON onboarding_configurations(flow_type, status);

-- Onboarding Progress Indexes
CREATE INDEX IF NOT EXISTS idx_onboarding_progress_business_user
    ON onboarding_progress(business_id, user_id, status);
CREATE INDEX IF NOT EXISTS idx_onboarding_progress_config
    ON onboarding_progress(configuration_id, status);
CREATE INDEX IF NOT EXISTS idx_onboarding_progress_status
    ON onboarding_progress(status, updated_at DESC);

-- ============================================================================
-- TRIGGERS FOR AUTOMATIC UPDATES
-- ============================================================================

-- Update company_guidelines updated_at
CREATE TRIGGER IF NOT EXISTS update_guidelines_timestamp
    AFTER UPDATE ON company_guidelines
    FOR EACH ROW
BEGIN
    UPDATE company_guidelines
    SET updated_at = datetime('now')
    WHERE id = NEW.id;
END;

-- Update agent_policies updated_at
CREATE TRIGGER IF NOT EXISTS update_policies_timestamp
    AFTER UPDATE ON agent_policies
    FOR EACH ROW
BEGIN
    UPDATE agent_policies
    SET updated_at = datetime('now')
    WHERE id = NEW.id;
END;

-- Update company_knowledge_base updated_at
CREATE TRIGGER IF NOT EXISTS update_knowledge_timestamp
    AFTER UPDATE ON company_knowledge_base
    FOR EACH ROW
BEGIN
    UPDATE company_knowledge_base
    SET updated_at = datetime('now')
    WHERE id = NEW.id;
END;

-- Update knowledge_sources updated_at
CREATE TRIGGER IF NOT EXISTS update_sources_timestamp
    AFTER UPDATE ON knowledge_sources
    FOR EACH ROW
BEGIN
    UPDATE knowledge_sources
    SET updated_at = datetime('now')
    WHERE id = NEW.id;
END;

-- Update onboarding_progress updated_at
CREATE TRIGGER IF NOT EXISTS update_progress_timestamp
    AFTER UPDATE ON onboarding_progress
    FOR EACH ROW
BEGIN
    UPDATE onboarding_progress
    SET updated_at = datetime('now')
    WHERE id = NEW.id;
END;

-- ============================================================================
-- VIEWS FOR ANALYTICS
-- ============================================================================

-- Compliance violations summary by business
CREATE VIEW IF NOT EXISTS v_compliance_violations_summary AS
SELECT
    business_id,
    agent_id,
    violation_type,
    severity,
    COUNT(*) as violation_count,
    COUNT(CASE WHEN status = 'resolved' THEN 1 END) as resolved_count,
    COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_count,
    MAX(occurred_at) as last_violation_at
FROM compliance_violations
GROUP BY business_id, agent_id, violation_type, severity;

-- Knowledge base health by business
CREATE VIEW IF NOT EXISTS v_knowledge_base_health AS
SELECT
    business_id,
    content_type,
    COUNT(*) as total_items,
    COUNT(CASE WHEN verified = 1 THEN 1 END) as verified_items,
    COUNT(CASE WHEN status = 'outdated' THEN 1 END) as outdated_items,
    AVG(accuracy_score) as avg_accuracy,
    AVG(freshness_score) as avg_freshness,
    MAX(updated_at) as last_updated_at
FROM company_knowledge_base
WHERE status IN ('active', 'outdated')
GROUP BY business_id, content_type;

-- Onboarding analytics by configuration
CREATE VIEW IF NOT EXISTS v_onboarding_analytics AS
SELECT
    op.configuration_id,
    oc.flow_name,
    oc.flow_type,
    COUNT(DISTINCT op.user_id) as total_users,
    COUNT(CASE WHEN op.status = 'completed' THEN 1 END) as completed_count,
    COUNT(CASE WHEN op.status = 'in_progress' THEN 1 END) as in_progress_count,
    COUNT(CASE WHEN op.status = 'abandoned' THEN 1 END) as abandoned_count,
    AVG(op.completion_percentage) as avg_completion_pct,
    AVG(op.actual_time_minutes) as avg_time_minutes,
    AVG(op.ai_interactions_count) as avg_ai_interactions
FROM onboarding_progress op
INNER JOIN onboarding_configurations oc ON op.configuration_id = oc.id
GROUP BY op.configuration_id, oc.flow_name, oc.flow_type;
