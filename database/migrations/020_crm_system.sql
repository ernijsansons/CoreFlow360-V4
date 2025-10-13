-- Migration: 020_crm_system
-- Description: Fortune 50-Level CRM System (Salesforce/HubSpot-inspired)
-- Created: 2025-10-11
-- Features: Companies, Contacts, Leads, Deals, Activities, AI Insights

-- ============================================================
-- COMPANIES (Accounts)
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_companies (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- Basic Information
    name TEXT NOT NULL,
    legal_name TEXT,
    website TEXT,
    domain TEXT,
    phone TEXT,
    email TEXT,
    industry TEXT,
    sub_industry TEXT,
    company_size TEXT CHECK(company_size IN ('1-10', '11-50', '51-200', '201-500', '501-1000', '1001-5000', '5001-10000', '10000+')),
    annual_revenue REAL,
    currency TEXT DEFAULT 'USD',

    -- Address
    street_address TEXT,
    city TEXT,
    state TEXT,
    postal_code TEXT,
    country TEXT DEFAULT 'US',
    timezone TEXT,

    -- Social & Web Presence
    linkedin_url TEXT,
    twitter_url TEXT,
    facebook_url TEXT,
    crunchbase_url TEXT,

    -- Engagement & Scoring
    lead_score INTEGER DEFAULT 0 CHECK(lead_score >= 0 AND lead_score <= 100),
    engagement_level TEXT DEFAULT 'cold' CHECK(engagement_level IN ('cold', 'warm', 'hot', 'champion')),
    health_score INTEGER DEFAULT 50 CHECK(health_score >= 0 AND health_score <= 100),

    -- Lifecycle & Status
    lifecycle_stage TEXT DEFAULT 'lead' CHECK(lifecycle_stage IN ('lead', 'mql', 'sql', 'opportunity', 'customer', 'evangelist', 'churned')),
    status TEXT DEFAULT 'active' CHECK(status IN ('active', 'inactive', 'prospect', 'customer', 'archived')),
    customer_since DATE,
    last_interaction_at TIMESTAMP,

    -- AI-Powered Insights
    ai_sentiment TEXT CHECK(ai_sentiment IN ('positive', 'neutral', 'negative')),
    churn_risk_score INTEGER CHECK(churn_risk_score >= 0 AND churn_risk_score <= 100),
    upsell_opportunity_score INTEGER CHECK(upsell_opportunity_score >= 0 AND upsell_opportunity_score <= 100),
    next_best_action TEXT,

    -- Ownership & Assignment
    owner_id TEXT REFERENCES users(id),
    team_id TEXT,

    -- Metadata
    tags TEXT, -- JSON array
    custom_fields TEXT, -- JSON object
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

CREATE INDEX idx_crm_companies_business ON crm_companies(business_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_companies_lifecycle ON crm_companies(lifecycle_stage, status) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_companies_owner ON crm_companies(owner_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_companies_score ON crm_companies(lead_score DESC) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_companies_domain ON crm_companies(domain) WHERE deleted_at IS NULL;

-- ============================================================
-- CONTACTS (People)
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_contacts (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),
    company_id TEXT REFERENCES crm_companies(id),

    -- Basic Information
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    full_name TEXT GENERATED ALWAYS AS (first_name || ' ' || last_name) STORED,
    email TEXT NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    phone TEXT,
    mobile_phone TEXT,
    job_title TEXT,
    department TEXT,
    seniority_level TEXT CHECK(seniority_level IN ('individual', 'manager', 'director', 'vp', 'c-level', 'owner')),

    -- Address
    street_address TEXT,
    city TEXT,
    state TEXT,
    postal_code TEXT,
    country TEXT DEFAULT 'US',
    timezone TEXT,

    -- Social Profiles
    linkedin_url TEXT,
    twitter_handle TEXT,

    -- Engagement & Scoring
    lead_score INTEGER DEFAULT 0 CHECK(lead_score >= 0 AND lead_score <= 100),
    engagement_level TEXT DEFAULT 'cold' CHECK(engagement_level IN ('cold', 'warm', 'hot', 'champion')),

    -- Lifecycle & Status
    lifecycle_stage TEXT DEFAULT 'subscriber' CHECK(lifecycle_stage IN ('subscriber', 'lead', 'mql', 'sql', 'opportunity', 'customer', 'evangelist')),
    status TEXT DEFAULT 'active' CHECK(status IN ('active', 'inactive', 'unsubscribed', 'bounced', 'archived')),

    -- Communication Preferences
    email_opt_in BOOLEAN DEFAULT TRUE,
    sms_opt_in BOOLEAN DEFAULT FALSE,
    do_not_call BOOLEAN DEFAULT FALSE,
    preferred_contact_method TEXT CHECK(preferred_contact_method IN ('email', 'phone', 'sms', 'linkedin')),

    -- AI Insights
    persona_type TEXT, -- AI-determined buyer persona
    buying_intent_score INTEGER CHECK(buying_intent_score >= 0 AND buying_intent_score <= 100),
    last_interaction_at TIMESTAMP,
    next_best_action TEXT,

    -- Ownership
    owner_id TEXT REFERENCES users(id),

    -- Metadata
    tags TEXT, -- JSON array
    custom_fields TEXT, -- JSON object
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

CREATE UNIQUE INDEX idx_crm_contacts_email_business ON crm_contacts(email, business_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_contacts_company ON crm_contacts(company_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_contacts_owner ON crm_contacts(owner_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_contacts_lifecycle ON crm_contacts(lifecycle_stage, status) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_contacts_score ON crm_contacts(lead_score DESC) WHERE deleted_at IS NULL;

-- ============================================================
-- LEADS (Potential Opportunities)
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_leads (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),
    company_id TEXT REFERENCES crm_companies(id),
    contact_id TEXT REFERENCES crm_contacts(id),

    -- Lead Information
    title TEXT NOT NULL,
    description TEXT,
    source TEXT CHECK(source IN ('website', 'referral', 'paid_ad', 'organic_search', 'social_media', 'event', 'cold_outreach', 'partner', 'other')),
    source_details TEXT,
    campaign_id TEXT,

    -- Qualification
    lead_score INTEGER DEFAULT 0 CHECK(lead_score >= 0 AND lead_score <= 100),
    qualification_status TEXT DEFAULT 'new' CHECK(qualification_status IN ('new', 'working', 'qualified', 'unqualified', 'converted', 'dead')),
    qualification_notes TEXT,

    -- Budget & Timeline
    estimated_budget REAL,
    estimated_close_date DATE,
    urgency TEXT CHECK(urgency IN ('low', 'medium', 'high', 'critical')),

    -- AI-Powered Insights
    conversion_probability INTEGER CHECK(conversion_probability >= 0 AND conversion_probability <= 100),
    recommended_next_action TEXT,
    ai_qualification_reason TEXT,

    -- Assignment
    owner_id TEXT REFERENCES users(id),
    assigned_at TIMESTAMP,

    -- Conversion
    converted_to_deal_id TEXT REFERENCES crm_deals(id),
    converted_at TIMESTAMP,
    conversion_reason TEXT,

    -- Metadata
    tags TEXT, -- JSON array
    custom_fields TEXT, -- JSON object
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

CREATE INDEX idx_crm_leads_business ON crm_leads(business_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_leads_company ON crm_leads(company_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_leads_status ON crm_leads(qualification_status) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_leads_owner ON crm_leads(owner_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_leads_score ON crm_leads(lead_score DESC) WHERE deleted_at IS NULL;

-- ============================================================
-- DEALS (Opportunities/Pipeline)
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_deals (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),
    company_id TEXT NOT NULL REFERENCES crm_companies(id),
    primary_contact_id TEXT REFERENCES crm_contacts(id),

    -- Deal Information
    name TEXT NOT NULL,
    description TEXT,
    deal_type TEXT CHECK(deal_type IN ('new_business', 'upsell', 'renewal', 'cross_sell')),

    -- Financial
    amount REAL NOT NULL DEFAULT 0,
    currency TEXT DEFAULT 'USD',
    mrr REAL, -- Monthly Recurring Revenue
    arr REAL, -- Annual Recurring Revenue

    -- Pipeline & Stage
    pipeline_id TEXT, -- Reference to custom pipelines
    stage TEXT NOT NULL DEFAULT 'qualification' CHECK(stage IN ('qualification', 'discovery', 'proposal', 'negotiation', 'closed_won', 'closed_lost')),
    stage_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    probability INTEGER DEFAULT 10 CHECK(probability >= 0 AND probability <= 100),

    -- Timeline
    expected_close_date DATE,
    actual_close_date DATE,
    days_in_stage INTEGER DEFAULT 0,
    sales_cycle_days INTEGER,

    -- Status
    status TEXT DEFAULT 'open' CHECK(status IN ('open', 'won', 'lost', 'abandoned')),
    won_reason TEXT,
    lost_reason TEXT,
    lost_to_competitor TEXT,

    -- AI Insights
    win_probability INTEGER CHECK(win_probability >= 0 AND win_probability <= 100),
    risk_factors TEXT, -- JSON array of identified risks
    recommended_actions TEXT, -- JSON array of AI recommendations
    ai_deal_health_score INTEGER CHECK(ai_deal_health_score >= 0 AND ai_deal_health_score <= 100),

    -- Ownership & Team
    owner_id TEXT NOT NULL REFERENCES users(id),
    team_members TEXT, -- JSON array of user IDs

    -- Metadata
    tags TEXT, -- JSON array
    custom_fields TEXT, -- JSON object
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

CREATE INDEX idx_crm_deals_business ON crm_deals(business_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_deals_company ON crm_deals(company_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_deals_stage ON crm_deals(stage, status) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_deals_owner ON crm_deals(owner_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_deals_close_date ON crm_deals(expected_close_date) WHERE deleted_at IS NULL AND status = 'open';
CREATE INDEX idx_crm_deals_amount ON crm_deals(amount DESC) WHERE deleted_at IS NULL;

-- ============================================================
-- ACTIVITIES (Interactions & Engagement)
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_activities (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- Activity Type
    type TEXT NOT NULL CHECK(type IN ('call', 'email', 'meeting', 'note', 'task', 'linkedin_message', 'demo', 'proposal_sent', 'contract_sent', 'other')),
    subject TEXT NOT NULL,
    description TEXT,

    -- Related Records
    company_id TEXT REFERENCES crm_companies(id),
    contact_id TEXT REFERENCES crm_contacts(id),
    lead_id TEXT REFERENCES crm_leads(id),
    deal_id TEXT REFERENCES crm_deals(id),

    -- Scheduling
    scheduled_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_minutes INTEGER,

    -- Status
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'completed', 'cancelled', 'no_show')),
    outcome TEXT CHECK(outcome IN ('positive', 'neutral', 'negative')),
    outcome_notes TEXT,

    -- Assignment
    owner_id TEXT NOT NULL REFERENCES users(id),
    participants TEXT, -- JSON array of user/contact IDs

    -- AI Analysis
    sentiment_score INTEGER CHECK(sentiment_score >= -100 AND sentiment_score <= 100),
    key_topics TEXT, -- JSON array extracted by AI
    action_items TEXT, -- JSON array of follow-ups identified by AI

    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

CREATE INDEX idx_crm_activities_business ON crm_activities(business_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_activities_type ON crm_activities(type, status) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_activities_owner ON crm_activities(owner_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_activities_company ON crm_activities(company_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_activities_deal ON crm_activities(deal_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_activities_scheduled ON crm_activities(scheduled_at) WHERE deleted_at IS NULL AND status = 'pending';

-- ============================================================
-- DEAL STAGES (Custom Pipeline Configuration)
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_deal_stages (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),
    pipeline_id TEXT NOT NULL,

    -- Stage Details
    name TEXT NOT NULL,
    description TEXT,
    display_order INTEGER NOT NULL,
    probability INTEGER CHECK(probability >= 0 AND probability <= 100),

    -- Configuration
    is_active BOOLEAN DEFAULT TRUE,
    is_closed_stage BOOLEAN DEFAULT FALSE,
    stage_type TEXT CHECK(stage_type IN ('open', 'won', 'lost')),

    -- Automation
    auto_actions TEXT, -- JSON configuration for automatic actions
    required_fields TEXT, -- JSON array of required fields

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX idx_crm_deal_stages_pipeline ON crm_deal_stages(business_id, pipeline_id, name);
CREATE INDEX idx_crm_deal_stages_order ON crm_deal_stages(pipeline_id, display_order);

-- ============================================================
-- AI ENRICHMENT DATA (Company & Contact Intelligence)
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_enrichment_data (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- Target
    entity_type TEXT NOT NULL CHECK(entity_type IN ('company', 'contact')),
    entity_id TEXT NOT NULL,

    -- Enrichment Source
    provider TEXT NOT NULL, -- 'clearbit', 'apollo', 'zoominfo', 'internal_ai'
    enrichment_type TEXT NOT NULL, -- 'firmographic', 'technographic', 'social', 'intent'

    -- Data
    enrichment_data TEXT NOT NULL, -- JSON object with enriched information
    confidence_score INTEGER CHECK(confidence_score >= 0 AND confidence_score <= 100),

    -- Metadata
    enriched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

CREATE INDEX idx_crm_enrichment_entity ON crm_enrichment_data(entity_type, entity_id);
CREATE INDEX idx_crm_enrichment_business ON crm_enrichment_data(business_id);

-- ============================================================
-- EMAIL SEQUENCES (Automated Nurture Campaigns)
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_email_sequences (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- Sequence Details
    name TEXT NOT NULL,
    description TEXT,
    sequence_type TEXT CHECK(sequence_type IN ('onboarding', 'nurture', 'sales', 'retention', 'winback')),

    -- Configuration
    is_active BOOLEAN DEFAULT TRUE,
    total_steps INTEGER NOT NULL,

    -- Performance
    total_enrolled INTEGER DEFAULT 0,
    total_completed INTEGER DEFAULT 0,
    avg_completion_rate REAL,

    -- Metadata
    created_by TEXT REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_crm_sequences_business ON crm_email_sequences(business_id);

-- ============================================================
-- SEQUENCE ENROLLMENTS (Track Who's in What Sequence)
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_sequence_enrollments (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),
    sequence_id TEXT NOT NULL REFERENCES crm_email_sequences(id),
    contact_id TEXT NOT NULL REFERENCES crm_contacts(id),

    -- Progress
    current_step INTEGER DEFAULT 1,
    status TEXT DEFAULT 'active' CHECK(status IN ('active', 'paused', 'completed', 'bounced', 'unsubscribed')),

    -- Performance
    emails_sent INTEGER DEFAULT 0,
    emails_opened INTEGER DEFAULT 0,
    emails_clicked INTEGER DEFAULT 0,
    replies_received INTEGER DEFAULT 0,

    -- Timing
    enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_email_sent_at TIMESTAMP,
    completed_at TIMESTAMP,
    unenrolled_at TIMESTAMP,
    unenroll_reason TEXT
);

CREATE UNIQUE INDEX idx_crm_enrollments_contact_seq ON crm_sequence_enrollments(contact_id, sequence_id);
CREATE INDEX idx_crm_enrollments_business ON crm_sequence_enrollments(business_id);
CREATE INDEX idx_crm_enrollments_status ON crm_sequence_enrollments(sequence_id, status);

-- ============================================================
-- NOTES (Rich Text Notes on Any Entity)
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_notes (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- Note Content
    title TEXT,
    content TEXT NOT NULL,
    content_type TEXT DEFAULT 'markdown' CHECK(content_type IN ('plain', 'markdown', 'html')),

    -- Related Entities
    company_id TEXT REFERENCES crm_companies(id),
    contact_id TEXT REFERENCES crm_contacts(id),
    lead_id TEXT REFERENCES crm_leads(id),
    deal_id TEXT REFERENCES crm_deals(id),

    -- Visibility
    is_pinned BOOLEAN DEFAULT FALSE,
    is_private BOOLEAN DEFAULT FALSE,

    -- Authorship
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

CREATE INDEX idx_crm_notes_business ON crm_notes(business_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_notes_company ON crm_notes(company_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_notes_contact ON crm_notes(contact_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_notes_deal ON crm_notes(deal_id) WHERE deleted_at IS NULL;

-- ============================================================
-- ANALYTICS & REPORTING VIEWS
-- ============================================================

-- Company Metrics Summary
CREATE VIEW IF NOT EXISTS v_crm_company_metrics AS
SELECT
    c.id,
    c.name,
    c.business_id,
    c.lifecycle_stage,
    c.lead_score,
    c.health_score,
    COUNT(DISTINCT co.id) as total_contacts,
    COUNT(DISTINCT d.id) as total_deals,
    COALESCE(SUM(CASE WHEN d.status = 'open' THEN d.amount ELSE 0 END), 0) as pipeline_value,
    COALESCE(SUM(CASE WHEN d.status = 'won' THEN d.amount ELSE 0 END), 0) as won_value,
    COUNT(DISTINCT a.id) as total_activities,
    MAX(a.completed_at) as last_activity_date
FROM crm_companies c
LEFT JOIN crm_contacts co ON co.company_id = c.id
LEFT JOIN crm_deals d ON d.company_id = c.id
LEFT JOIN crm_activities a ON a.company_id = c.id
WHERE c.deleted_at IS NULL
GROUP BY c.id;

-- Deal Pipeline Analytics
CREATE VIEW IF NOT EXISTS v_crm_pipeline_analytics AS
SELECT
    d.business_id,
    d.stage,
    d.status,
    COUNT(*) as deal_count,
    SUM(d.amount) as total_value,
    AVG(d.amount) as avg_deal_size,
    AVG(d.probability) as avg_probability,
    AVG(d.days_in_stage) as avg_days_in_stage
FROM crm_deals d
WHERE d.deleted_at IS NULL
GROUP BY d.business_id, d.stage, d.status;
