-- Migration: 050_crm_relationship_graph
-- Description: Relationship Graph Database for LinkedIn-style network intelligence
-- Features: Warm intro paths, hidden relationship discovery, network strength scoring
-- Created: 2025-10-19
-- Part of: Phase 1 Sprint 1 - Feature #1

-- ============================================================
-- RELATIONSHIP GRAPH CORE
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_relationships (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- Graph Nodes (polymorphic - can link any entity)
    source_id TEXT NOT NULL,
    source_type TEXT NOT NULL CHECK(source_type IN ('contact', 'company', 'user', 'lead')),
    target_id TEXT NOT NULL,
    target_type TEXT NOT NULL CHECK(target_type IN ('contact', 'company', 'user', 'lead')),

    -- Relationship Type & Metadata
    relationship_type TEXT NOT NULL CHECK(relationship_type IN (
        'works_at',           -- Contact → Company
        'reports_to',         -- Contact → Contact (manager)
        'peer_of',           -- Contact → Contact (same level)
        'mentor_of',         -- Contact → Contact (mentorship)
        'partner_with',      -- Company → Company (partnership)
        'vendor_of',         -- Company → Company (vendor relationship)
        'customer_of',       -- Company → Company (customer)
        'invested_in',       -- Contact → Company (investor)
        'founded',           -- Contact → Company (founder)
        'board_member',      -- Contact → Company (board seat)
        'shared_network',    -- Contact → Contact (mutual connections)
        'same_household',    -- Contact → Contact (family)
        'linkedin_connection', -- Contact → Contact (1st degree)
        'twitter_follower',  -- Contact → Contact (social)
        'email_thread',      -- Contact → Contact (email history)
        'meeting_attendee',  -- Contact → Contact (met in person)
        'deal_stakeholder',  -- Contact → Deal (involved in deal)
        'deal_blocker',      -- Contact → Deal (blocking deal)
        'deal_champion'      -- Contact → Deal (championing deal)
    )),

    -- Relationship Strength & Context
    strength_score INTEGER DEFAULT 50 CHECK(strength_score >= 0 AND strength_score <= 100),
    confidence_level TEXT DEFAULT 'medium' CHECK(confidence_level IN ('low', 'medium', 'high', 'verified')),
    interaction_count INTEGER DEFAULT 0,
    last_interaction_at TIMESTAMP,
    first_interaction_at TIMESTAMP,

    -- AI-Detected Signals
    detected_via TEXT, -- 'email_analysis', 'linkedin_scrape', 'manual_entry', 'calendar_invite'
    detection_confidence REAL, -- 0.0 to 1.0

    -- Bidirectional Flag
    is_bidirectional BOOLEAN DEFAULT FALSE, -- TRUE if relationship is mutual (e.g., peers)

    -- Metadata
    notes TEXT,
    metadata TEXT, -- JSON: {linkedin_url, shared_connections: 15, mutual_interests: [...]}
    tags TEXT, -- JSON array: ['warm_intro_available', 'high_value', 'decision_maker']

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP,

    -- Constraints
    UNIQUE(source_id, source_type, target_id, target_type, relationship_type, business_id)
);

-- Indexes for fast graph traversal
CREATE INDEX idx_crm_relationships_source ON crm_relationships(source_id, source_type) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_relationships_target ON crm_relationships(target_id, target_type) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_relationships_type ON crm_relationships(relationship_type) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_relationships_strength ON crm_relationships(strength_score DESC) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_relationships_business ON crm_relationships(business_id) WHERE deleted_at IS NULL;

-- Composite index for bidirectional lookups
CREATE INDEX idx_crm_relationships_graph ON crm_relationships(source_id, target_id, relationship_type) WHERE deleted_at IS NULL;

-- ============================================================
-- NETWORK PATHS (Precomputed for Performance)
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_network_paths (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- Path Endpoints
    start_contact_id TEXT NOT NULL REFERENCES crm_contacts(id),
    end_contact_id TEXT NOT NULL REFERENCES crm_contacts(id),

    -- Path Details
    path_length INTEGER NOT NULL, -- Number of hops (1 = direct connection, 2 = 2nd degree, etc.)
    path_nodes TEXT NOT NULL, -- JSON array of node IDs in order
    path_types TEXT NOT NULL, -- JSON array of relationship types in order

    -- Path Strength
    total_strength_score INTEGER CHECK(total_strength_score >= 0 AND total_strength_score <= 100),
    weakest_link_score INTEGER, -- Score of weakest relationship in path

    -- Warm Intro Info
    best_introducer_id TEXT, -- Contact ID who can make the intro
    intro_success_probability REAL, -- 0.0 to 1.0

    -- Caching
    computed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP, -- Recompute after this time

    -- Metadata
    metadata TEXT, -- JSON: additional context

    UNIQUE(start_contact_id, end_contact_id, business_id)
);

CREATE INDEX idx_crm_network_paths_start ON crm_network_paths(start_contact_id) WHERE expires_at > CURRENT_TIMESTAMP;
CREATE INDEX idx_crm_network_paths_end ON crm_network_paths(end_contact_id) WHERE expires_at > CURRENT_TIMESTAMP;
CREATE INDEX idx_crm_network_paths_length ON crm_network_paths(path_length) WHERE expires_at > CURRENT_TIMESTAMP;
CREATE INDEX idx_crm_network_paths_strength ON crm_network_paths(total_strength_score DESC) WHERE expires_at > CURRENT_TIMESTAMP;

-- ============================================================
-- SOCIAL NETWORK PROFILES (LinkedIn, Twitter, etc.)
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_social_profiles (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),
    contact_id TEXT NOT NULL REFERENCES crm_contacts(id),

    -- Platform
    platform TEXT NOT NULL CHECK(platform IN ('linkedin', 'twitter', 'facebook', 'instagram', 'github', 'crunchbase')),
    profile_url TEXT NOT NULL,
    username TEXT,

    -- Profile Data (Enriched)
    follower_count INTEGER,
    connection_count INTEGER,
    post_frequency TEXT, -- 'daily', 'weekly', 'monthly', 'inactive'
    last_post_at TIMESTAMP,
    verified BOOLEAN DEFAULT FALSE,

    -- Influence Score
    influence_score INTEGER CHECK(influence_score >= 0 AND influence_score <= 100),
    engagement_rate REAL, -- Avg likes/comments per post

    -- Network Overlap
    mutual_connections_count INTEGER DEFAULT 0,
    mutual_connections TEXT, -- JSON array of contact IDs

    -- Enrichment Metadata
    last_scraped_at TIMESTAMP,
    scrape_status TEXT CHECK(scrape_status IN ('pending', 'success', 'failed', 'rate_limited')),

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP,

    UNIQUE(contact_id, platform)
);

CREATE INDEX idx_crm_social_profiles_contact ON crm_social_profiles(contact_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_social_profiles_platform ON crm_social_profiles(platform) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_social_profiles_influence ON crm_social_profiles(influence_score DESC) WHERE deleted_at IS NULL;

-- ============================================================
-- RELATIONSHIP INSIGHTS (AI-Generated)
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_relationship_insights (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- Insight Target
    target_id TEXT NOT NULL, -- Contact, Company, or Deal ID
    target_type TEXT NOT NULL CHECK(target_type IN ('contact', 'company', 'deal')),

    -- Insight Type
    insight_type TEXT NOT NULL CHECK(insight_type IN (
        'warm_intro_available',
        'key_decision_maker',
        'potential_blocker',
        'champion_identified',
        'network_gap',
        'strong_advocate',
        'dormant_relationship',
        'recent_job_change',
        'new_connection_opportunity'
    )),

    -- Insight Details
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    recommended_action TEXT,
    priority TEXT DEFAULT 'medium' CHECK(priority IN ('low', 'medium', 'high', 'urgent')),

    -- Supporting Data
    related_contact_ids TEXT, -- JSON array
    supporting_evidence TEXT, -- JSON: emails, meetings, shared connections
    confidence_score REAL, -- 0.0 to 1.0

    -- Status
    status TEXT DEFAULT 'new' CHECK(status IN ('new', 'viewed', 'acted_on', 'dismissed')),
    acted_on_at TIMESTAMP,
    dismissed_at TIMESTAMP,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP, -- Insights can expire (e.g., "warm intro available" if contact leaves)

    deleted_at TIMESTAMP
);

CREATE INDEX idx_crm_relationship_insights_target ON crm_relationship_insights(target_id, target_type) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_relationship_insights_type ON crm_relationship_insights(insight_type) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_relationship_insights_priority ON crm_relationship_insights(priority) WHERE status = 'new' AND deleted_at IS NULL;
CREATE INDEX idx_crm_relationship_insights_status ON crm_relationship_insights(status) WHERE deleted_at IS NULL;

-- ============================================================
-- RELATIONSHIP ACTIVITY LOG (Track Interactions)
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_relationship_activities (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    relationship_id TEXT NOT NULL REFERENCES crm_relationships(id),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- Activity Type
    activity_type TEXT NOT NULL CHECK(activity_type IN (
        'email_sent',
        'email_received',
        'meeting_scheduled',
        'meeting_completed',
        'call_made',
        'call_received',
        'linkedin_message',
        'linkedin_connection_accepted',
        'deal_progressed',
        'introduction_made',
        'referral_given'
    )),

    -- Activity Details
    subject TEXT,
    description TEXT,
    outcome TEXT, -- 'positive', 'neutral', 'negative', 'no_response'
    sentiment_score REAL, -- -1.0 to 1.0

    -- Impact on Relationship
    strength_impact INTEGER, -- +/- points to relationship strength

    -- Timestamps
    occurred_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_crm_relationship_activities_rel ON crm_relationship_activities(relationship_id);
CREATE INDEX idx_crm_relationship_activities_occurred ON crm_relationship_activities(occurred_at DESC);
CREATE INDEX idx_crm_relationship_activities_type ON crm_relationship_activities(activity_type);

-- ============================================================
-- VIEWS FOR COMMON QUERIES
-- ============================================================

-- View: Contact Network Strength
CREATE VIEW IF NOT EXISTS view_contact_network_strength AS
SELECT
    c.id as contact_id,
    c.full_name,
    c.email,
    c.company_id,
    COUNT(r.id) as total_connections,
    AVG(r.strength_score) as avg_connection_strength,
    MAX(r.strength_score) as strongest_connection_score,
    COUNT(CASE WHEN r.relationship_type = 'linkedin_connection' THEN 1 END) as linkedin_connections,
    COUNT(CASE WHEN r.relationship_type IN ('reports_to', 'mentor_of') THEN 1 END) as professional_relationships,
    COUNT(CASE WHEN r.strength_score >= 75 THEN 1 END) as strong_connections
FROM crm_contacts c
LEFT JOIN crm_relationships r ON (
    (r.source_id = c.id AND r.source_type = 'contact') OR
    (r.target_id = c.id AND r.target_type = 'contact')
) AND r.deleted_at IS NULL
WHERE c.deleted_at IS NULL
GROUP BY c.id, c.full_name, c.email, c.company_id;

-- View: Company Relationship Map
CREATE VIEW IF NOT EXISTS view_company_relationships AS
SELECT
    comp.id as company_id,
    comp.name as company_name,
    COUNT(DISTINCT r.id) as total_relationships,
    COUNT(DISTINCT CASE WHEN r.relationship_type = 'partner_with' THEN r.target_id END) as partners,
    COUNT(DISTINCT CASE WHEN r.relationship_type = 'customer_of' THEN r.target_id END) as customers,
    COUNT(DISTINCT CASE WHEN r.relationship_type = 'vendor_of' THEN r.target_id END) as vendors,
    COUNT(DISTINCT c.id) as total_contacts
FROM crm_companies comp
LEFT JOIN crm_relationships r ON (
    (r.source_id = comp.id AND r.source_type = 'company') OR
    (r.target_id = comp.id AND r.target_type = 'company')
) AND r.deleted_at IS NULL
LEFT JOIN crm_contacts c ON c.company_id = comp.id AND c.deleted_at IS NULL
WHERE comp.deleted_at IS NULL
GROUP BY comp.id, comp.name;

-- ============================================================
-- TRIGGERS FOR AUTO-UPDATING RELATIONSHIP STRENGTH
-- ============================================================

-- Trigger: Update relationship strength when activity is logged
CREATE TRIGGER IF NOT EXISTS trg_update_relationship_strength
AFTER INSERT ON crm_relationship_activities
BEGIN
    UPDATE crm_relationships
    SET
        strength_score = MIN(100, MAX(0, strength_score + NEW.strength_impact)),
        interaction_count = interaction_count + 1,
        last_interaction_at = NEW.occurred_at,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = NEW.relationship_id;
END;

-- Trigger: Set first_interaction_at on first activity
CREATE TRIGGER IF NOT EXISTS trg_set_first_interaction
AFTER INSERT ON crm_relationship_activities
WHEN NEW.relationship_id IN (
    SELECT id FROM crm_relationships WHERE first_interaction_at IS NULL
)
BEGIN
    UPDATE crm_relationships
    SET first_interaction_at = NEW.occurred_at
    WHERE id = NEW.relationship_id AND first_interaction_at IS NULL;
END;

-- ============================================================
-- SAMPLE DATA FOR TESTING
-- ============================================================

-- Insert sample relationships (will be populated by enrichment service)
-- Note: Actual data will be created via API calls and enrichment jobs
