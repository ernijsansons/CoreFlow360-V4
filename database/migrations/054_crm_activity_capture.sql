-- Migration: 054_crm_activity_capture
-- Description: Automated activity capture from Gmail, Nylas, and other communication channels
-- Feature: #6 in Phase 1 Sprint 1 - CRM of Tomorrow
-- Created: 2025-01-19

-- ============================================================================
-- ACTIVITY CAPTURE SYSTEM
-- ============================================================================

-- Communication activities (emails, calls, meetings)
CREATE TABLE IF NOT EXISTS crm_activities (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Activity Type
    activity_type TEXT NOT NULL CHECK(activity_type IN (
        'email_sent', 'email_received', 'email_opened', 'email_clicked',
        'call_inbound', 'call_outbound', 'call_missed',
        'meeting_scheduled', 'meeting_completed', 'meeting_cancelled',
        'linkedin_message', 'linkedin_connection',
        'demo_scheduled', 'demo_completed',
        'task_created', 'task_completed',
        'note_created'
    )),

    -- Participants
    contact_id TEXT,                  -- CRM contact involved
    user_id TEXT,                     -- Sales rep/user who performed activity

    -- Activity Details
    subject TEXT,
    body TEXT,                        -- Email body, call notes, meeting notes
    direction TEXT CHECK(direction IN ('inbound', 'outbound', 'internal')),

    -- Communication Metadata
    external_id TEXT,                 -- Gmail message ID, Nylas event ID, etc.
    source TEXT NOT NULL CHECK(source IN ('gmail', 'nylas', 'outlook', 'manual', 'api', 'linkedin')),
    thread_id TEXT,                   -- Email thread grouping

    -- Engagement Tracking
    is_opened INTEGER DEFAULT 0,
    opened_at TEXT,
    is_clicked INTEGER DEFAULT 0,
    clicked_at TEXT,
    is_replied INTEGER DEFAULT 0,
    replied_at TEXT,

    -- Meeting Specifics
    meeting_start_time TEXT,
    meeting_end_time TEXT,
    meeting_duration_minutes INTEGER,
    meeting_attendees TEXT,           -- JSON array of attendee emails
    meeting_location TEXT,

    -- Call Specifics
    call_duration_seconds INTEGER,
    call_recording_url TEXT,
    call_transcript TEXT,

    -- Auto-Creation Flags
    auto_created INTEGER DEFAULT 0,   -- Was this auto-captured?
    contact_auto_created INTEGER DEFAULT 0, -- Was contact auto-created from this?

    -- Timestamps
    activity_timestamp TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (contact_id) REFERENCES crm_contacts(id) ON DELETE SET NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Email sync configuration
CREATE TABLE IF NOT EXISTS crm_email_sync_config (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    user_id TEXT NOT NULL,

    -- Provider Configuration
    provider TEXT NOT NULL CHECK(provider IN ('gmail', 'outlook', 'nylas')),
    email_address TEXT NOT NULL,

    -- OAuth Credentials (encrypted)
    access_token TEXT,
    refresh_token TEXT,
    token_expires_at TEXT,

    -- Nylas Specific
    nylas_grant_id TEXT,
    nylas_calendar_id TEXT,

    -- Sync Settings
    sync_emails INTEGER DEFAULT 1,
    sync_calendar INTEGER DEFAULT 1,
    sync_contacts INTEGER DEFAULT 0,
    auto_create_contacts INTEGER DEFAULT 1,  -- Create CRM contact from email signature
    auto_log_activities INTEGER DEFAULT 1,

    -- Filters
    only_sync_crm_contacts INTEGER DEFAULT 0, -- Only sync emails with known contacts
    excluded_domains TEXT,            -- JSON array: ["internal.com", "spam.com"]

    -- Sync Status
    last_sync_at TEXT,
    next_sync_at TEXT,
    sync_status TEXT DEFAULT 'active' CHECK(sync_status IN ('active', 'paused', 'error', 'disconnected')),
    sync_error TEXT,

    -- Metadata
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, provider, email_address)
);

-- Email signatures for contact auto-creation
CREATE TABLE IF NOT EXISTS crm_email_signatures (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Extracted Data
    email_address TEXT NOT NULL,
    full_name TEXT,
    first_name TEXT,
    last_name TEXT,
    job_title TEXT,
    company_name TEXT,
    phone_number TEXT,
    linkedin_url TEXT,
    website_url TEXT,

    -- Signature Source
    source_activity_id TEXT,          -- Activity this was extracted from
    extraction_confidence REAL,       -- 0.0-1.0 confidence score

    -- Contact Association
    contact_id TEXT,                  -- If matched/created to CRM contact
    is_processed INTEGER DEFAULT 0,

    -- Timestamps
    extracted_at TEXT DEFAULT (datetime('now')),

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (source_activity_id) REFERENCES crm_activities(id) ON DELETE SET NULL,
    FOREIGN KEY (contact_id) REFERENCES crm_contacts(id) ON DELETE SET NULL
);

-- Activity to deal/opportunity mapping
CREATE TABLE IF NOT EXISTS crm_activity_associations (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    activity_id TEXT NOT NULL,

    -- Association Type
    entity_type TEXT NOT NULL CHECK(entity_type IN ('contact', 'deal', 'company', 'lead')),
    entity_id TEXT NOT NULL,

    -- Association Metadata
    association_strength REAL DEFAULT 1.0, -- How confident is this association?
    is_auto_associated INTEGER DEFAULT 0,

    created_at TEXT DEFAULT (datetime('now')),

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (activity_id) REFERENCES crm_activities(id) ON DELETE CASCADE,
    UNIQUE(activity_id, entity_type, entity_id)
);

-- Sync job queue for background processing
CREATE TABLE IF NOT EXISTS crm_sync_jobs (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    user_id TEXT NOT NULL,

    -- Job Configuration
    job_type TEXT NOT NULL CHECK(job_type IN ('full_sync', 'incremental_sync', 'calendar_sync', 'contact_sync')),
    provider TEXT NOT NULL,

    -- Job Parameters
    sync_from_date TEXT,              -- For incremental sync
    sync_to_date TEXT,

    -- Job Status
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'running', 'completed', 'failed')),
    progress_percentage INTEGER DEFAULT 0,

    -- Results
    activities_synced INTEGER DEFAULT 0,
    contacts_created INTEGER DEFAULT 0,
    errors_encountered INTEGER DEFAULT 0,
    error_details TEXT,               -- JSON array of errors

    -- Timing
    started_at TEXT,
    completed_at TEXT,
    duration_seconds INTEGER,

    -- Metadata
    created_at TEXT DEFAULT (datetime('now')),

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

CREATE INDEX idx_crm_activities_contact ON crm_activities(contact_id, activity_timestamp DESC);
CREATE INDEX idx_crm_activities_user ON crm_activities(user_id, activity_timestamp DESC);
CREATE INDEX idx_crm_activities_type ON crm_activities(business_id, activity_type, activity_timestamp DESC);
CREATE INDEX idx_crm_activities_external ON crm_activities(external_id, source);
CREATE INDEX idx_crm_activities_thread ON crm_activities(thread_id) WHERE thread_id IS NOT NULL;

CREATE INDEX idx_crm_email_sync_config_user ON crm_email_sync_config(user_id, sync_status);
CREATE INDEX idx_crm_email_sync_config_next_sync ON crm_email_sync_config(next_sync_at) WHERE sync_status = 'active';

CREATE INDEX idx_crm_email_signatures_email ON crm_email_signatures(email_address);
CREATE INDEX idx_crm_email_signatures_unprocessed ON crm_email_signatures(is_processed) WHERE is_processed = 0;

CREATE INDEX idx_crm_activity_associations_entity ON crm_activity_associations(entity_type, entity_id);
CREATE INDEX idx_crm_activity_associations_activity ON crm_activity_associations(activity_id);

CREATE INDEX idx_crm_sync_jobs_status ON crm_sync_jobs(status, created_at DESC);
CREATE INDEX idx_crm_sync_jobs_user ON crm_sync_jobs(user_id, created_at DESC);

-- ============================================================================
-- ANALYTICS VIEWS
-- ============================================================================

-- Activity summary by contact
CREATE VIEW IF NOT EXISTS view_contact_activity_summary AS
SELECT
    contact_id,
    business_id,
    COUNT(*) as total_activities,
    COUNT(CASE WHEN activity_type LIKE 'email%' THEN 1 END) as email_count,
    COUNT(CASE WHEN activity_type LIKE 'call%' THEN 1 END) as call_count,
    COUNT(CASE WHEN activity_type LIKE 'meeting%' THEN 1 END) as meeting_count,
    MAX(activity_timestamp) as last_activity_at,
    julianday('now') - julianday(MAX(activity_timestamp)) as days_since_last_activity
FROM crm_activities
WHERE contact_id IS NOT NULL
GROUP BY contact_id, business_id;

-- Email engagement metrics
CREATE VIEW IF NOT EXISTS view_email_engagement_metrics AS
SELECT
    user_id,
    business_id,
    DATE(activity_timestamp) as activity_date,
    COUNT(*) as emails_sent,
    SUM(is_opened) as emails_opened,
    SUM(is_clicked) as emails_clicked,
    SUM(is_replied) as emails_replied,
    CAST(SUM(is_opened) * 100.0 / COUNT(*) AS INTEGER) as open_rate_pct,
    CAST(SUM(is_replied) * 100.0 / COUNT(*) AS INTEGER) as reply_rate_pct
FROM crm_activities
WHERE activity_type = 'email_sent'
GROUP BY user_id, business_id, DATE(activity_timestamp);

-- ============================================================================
-- TRIGGERS FOR AUTO-UPDATES
-- ============================================================================

-- Auto-update activity timestamp on changes
CREATE TRIGGER IF NOT EXISTS trg_crm_activities_updated
AFTER UPDATE ON crm_activities
BEGIN
    UPDATE crm_activities
    SET updated_at = datetime('now')
    WHERE id = NEW.id;
END;

-- Auto-update sync config timestamp
CREATE TRIGGER IF NOT EXISTS trg_crm_email_sync_config_updated
AFTER UPDATE ON crm_email_sync_config
BEGIN
    UPDATE crm_email_sync_config
    SET updated_at = datetime('now')
    WHERE id = NEW.id;
END;

-- Auto-associate activities with contacts on insert
CREATE TRIGGER IF NOT EXISTS trg_crm_activity_auto_associate
AFTER INSERT ON crm_activities
WHEN NEW.contact_id IS NOT NULL
BEGIN
    INSERT INTO crm_activity_associations (
        id, business_id, activity_id, entity_type, entity_id, is_auto_associated
    ) VALUES (
        lower(hex(randomblob(16))),
        NEW.business_id,
        NEW.id,
        'contact',
        NEW.contact_id,
        1
    );

    -- Also check if contact is associated with any active deals
    INSERT INTO crm_activity_associations (
        id, business_id, activity_id, entity_type, entity_id, is_auto_associated
    )
    SELECT
        lower(hex(randomblob(16))),
        NEW.business_id,
        NEW.id,
        'deal',
        d.id,
        1
    FROM crm_deals d
    WHERE d.primary_contact_id = NEW.contact_id
      AND d.stage NOT IN ('won', 'lost')
      AND d.business_id = NEW.business_id;
END;
