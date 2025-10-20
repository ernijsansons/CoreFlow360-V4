-- Migration: 041_admin_analytics
-- Description: Admin Dashboard Analytics and Management Tables
-- Created: 2025-01-17
-- Author: CoreFlow360 V4

-- ============================================================================
-- ADMIN DASHBOARDS
-- ============================================================================

-- Admin dashboard configurations
CREATE TABLE IF NOT EXISTS admin_dashboards (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    admin_user_id TEXT NOT NULL,

    -- Dashboard Configuration
    dashboard_name TEXT NOT NULL,
    description TEXT,
    layout_config TEXT, -- JSON configuration
    is_default INTEGER DEFAULT 0,

    -- Widgets Configuration
    widgets_config TEXT, -- JSON array of widget configurations
    refresh_interval INTEGER DEFAULT 30, -- seconds

    -- Permissions
    is_public INTEGER DEFAULT 0, -- Can be viewed by other admins
    shared_with TEXT, -- JSON array of admin user IDs

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    last_accessed_at TEXT,

    -- Foreign Keys
    FOREIGN KEY (admin_user_id) REFERENCES users(id) ON DELETE CASCADE,

    -- Constraints
    CHECK (refresh_interval >= 10),
    CHECK (refresh_interval <= 300)
);

-- ============================================================================
-- METRICS SNAPSHOTS
-- ============================================================================

-- Periodic snapshots of admin metrics
CREATE TABLE IF NOT EXISTS admin_metrics_snapshots (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT,

    -- Snapshot Period
    snapshot_date TEXT NOT NULL,
    snapshot_hour INTEGER, -- Hour of day (0-23)
    period_type TEXT NOT NULL CHECK (period_type IN ('hourly', 'daily', 'weekly', 'monthly')),

    -- Business Metrics
    total_revenue REAL DEFAULT 0,
    total_transactions INTEGER DEFAULT 0,
    active_users INTEGER DEFAULT 0,
    new_users INTEGER DEFAULT 0,
    active_sessions INTEGER DEFAULT 0,

    -- System Metrics
    total_api_requests INTEGER DEFAULT 0,
    total_errors INTEGER DEFAULT 0,
    avg_response_time REAL DEFAULT 0,
    p95_response_time REAL DEFAULT 0,
    p99_response_time REAL DEFAULT 0,

    -- Database Metrics
    total_queries INTEGER DEFAULT 0,
    avg_query_time REAL DEFAULT 0,
    slow_queries INTEGER DEFAULT 0,

    -- Security Metrics
    failed_logins INTEGER DEFAULT 0,
    successful_logins INTEGER DEFAULT 0,
    tokens_revoked INTEGER DEFAULT 0,
    suspicious_activities INTEGER DEFAULT 0,

    -- Storage Metrics
    total_storage_gb REAL DEFAULT 0,
    total_documents INTEGER DEFAULT 0,
    total_backups INTEGER DEFAULT 0,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,

    -- Indexes for efficient querying
    UNIQUE(business_id, snapshot_date, snapshot_hour, period_type)
);

-- ============================================================================
-- SYSTEM ALERTS
-- ============================================================================

-- System-wide alerts for admins
CREATE TABLE IF NOT EXISTS system_alerts (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),

    -- Alert Information
    alert_type TEXT NOT NULL CHECK (alert_type IN (
        'critical',
        'warning',
        'info',
        'security',
        'performance',
        'database',
        'storage',
        'billing'
    )),
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    details TEXT, -- JSON with additional details

    -- Source Information
    source_system TEXT, -- Which system generated the alert
    source_metric TEXT, -- Which metric triggered it
    threshold_value REAL, -- What threshold was exceeded
    actual_value REAL, -- What the actual value was

    -- Related Entities
    business_id TEXT,
    user_id TEXT,

    -- Alert Status
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'acknowledged', 'resolved', 'dismissed')),
    acknowledged_by_admin_id TEXT,
    acknowledged_at TEXT,
    resolved_by_admin_id TEXT,
    resolved_at TEXT,
    resolution_notes TEXT,

    -- Auto-resolution
    auto_resolved INTEGER DEFAULT 0,
    auto_resolved_at TEXT,

    -- Notification Status
    notification_sent INTEGER DEFAULT 0,
    notification_sent_at TEXT,
    notification_methods TEXT, -- JSON array of methods used (email, slack, etc.)

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (acknowledged_by_admin_id) REFERENCES users(id),
    FOREIGN KEY (resolved_by_admin_id) REFERENCES users(id)
);

-- ============================================================================
-- ADMIN ACTIVITY LOG
-- ============================================================================

-- Specific log for admin actions (separate from general audit_log)
CREATE TABLE IF NOT EXISTS admin_activity_log (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    admin_user_id TEXT NOT NULL,

    -- Action Information
    action_type TEXT NOT NULL CHECK (action_type IN (
        'user_management',
        'business_management',
        'system_configuration',
        'security_action',
        'data_export',
        'report_generation',
        'alert_management',
        'session_management',
        'feature_flag_change',
        'system_maintenance'
    )),
    action_name TEXT NOT NULL,
    action_description TEXT,

    -- Target Information
    target_type TEXT, -- 'user', 'business', 'system', etc.
    target_id TEXT,
    target_name TEXT,

    -- Action Details
    changes_made TEXT, -- JSON object with before/after values
    parameters TEXT, -- JSON object with action parameters

    -- Result
    status TEXT NOT NULL CHECK (status IN ('success', 'failed', 'partial')),
    error_message TEXT,

    -- Context
    ip_address TEXT,
    user_agent TEXT,
    session_id TEXT,

    -- Compliance
    requires_approval INTEGER DEFAULT 0,
    approved_by_admin_id TEXT,
    approved_at TEXT,
    approval_notes TEXT,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (admin_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (approved_by_admin_id) REFERENCES users(id)
);

-- ============================================================================
-- FEATURE FLAGS
-- ============================================================================

-- System-wide feature flags
CREATE TABLE IF NOT EXISTS feature_flags (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),

    -- Flag Information
    flag_key TEXT UNIQUE NOT NULL,
    flag_name TEXT NOT NULL,
    description TEXT,

    -- Flag Status
    is_enabled INTEGER DEFAULT 0,
    rollout_percentage INTEGER DEFAULT 0, -- 0-100
    targeting_rules TEXT, -- JSON targeting rules

    -- Business/User Targeting
    enabled_for_businesses TEXT, -- JSON array of business IDs
    enabled_for_users TEXT, -- JSON array of user IDs
    enabled_for_roles TEXT, -- JSON array of roles

    -- Environment
    environment TEXT DEFAULT 'production' CHECK (environment IN ('development', 'staging', 'production')),

    -- Metadata
    category TEXT, -- 'feature', 'experiment', 'killswitch', etc.
    tags TEXT, -- JSON array of tags

    -- Management
    created_by_admin_id TEXT NOT NULL,
    updated_by_admin_id TEXT,
    requires_restart INTEGER DEFAULT 0,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    enabled_at TEXT,
    disabled_at TEXT,

    -- Foreign Keys
    FOREIGN KEY (created_by_admin_id) REFERENCES users(id),
    FOREIGN KEY (updated_by_admin_id) REFERENCES users(id),

    -- Constraints
    CHECK (rollout_percentage >= 0),
    CHECK (rollout_percentage <= 100)
);

-- ============================================================================
-- SYSTEM CONFIGURATION
-- ============================================================================

-- System-wide configuration settings
CREATE TABLE IF NOT EXISTS system_configuration (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),

    -- Configuration Key
    config_key TEXT UNIQUE NOT NULL,
    config_category TEXT NOT NULL, -- 'security', 'performance', 'billing', etc.
    config_name TEXT NOT NULL,
    description TEXT,

    -- Value
    config_value TEXT NOT NULL, -- Can store JSON
    value_type TEXT NOT NULL CHECK (value_type IN ('string', 'number', 'boolean', 'json', 'array')),
    default_value TEXT,

    -- Validation
    validation_rules TEXT, -- JSON validation rules
    min_value REAL,
    max_value REAL,
    allowed_values TEXT, -- JSON array of allowed values

    -- Access Control
    is_public INTEGER DEFAULT 0, -- Can be read by non-admins
    is_readonly INTEGER DEFAULT 0,
    requires_restart INTEGER DEFAULT 0,

    -- Management
    updated_by_admin_id TEXT,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (updated_by_admin_id) REFERENCES users(id)
);

-- ============================================================================
-- PERFORMANCE METRICS
-- ============================================================================

-- Detailed performance metrics tracking
CREATE TABLE IF NOT EXISTS performance_metrics (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),

    -- Metric Information
    metric_name TEXT NOT NULL,
    metric_category TEXT NOT NULL CHECK (metric_category IN (
        'api',
        'database',
        'cache',
        'worker',
        'storage',
        'external_api'
    )),

    -- Measurement
    value REAL NOT NULL,
    unit TEXT NOT NULL, -- 'ms', 'seconds', 'percentage', 'count', 'bytes', etc.

    -- Context
    endpoint TEXT, -- For API metrics
    query_hash TEXT, -- For database metrics
    operation TEXT, -- Operation type
    business_id TEXT,
    user_id TEXT,

    -- Statistics
    min_value REAL,
    max_value REAL,
    avg_value REAL,
    p50_value REAL,
    p95_value REAL,
    p99_value REAL,
    sample_count INTEGER,

    -- Timestamps
    measured_at TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Admin Dashboards Indexes
CREATE INDEX idx_admin_dashboards_user ON admin_dashboards(admin_user_id);
CREATE INDEX idx_admin_dashboards_default ON admin_dashboards(is_default) WHERE is_default = 1;

-- Metrics Snapshots Indexes
CREATE INDEX idx_metrics_snapshots_date ON admin_metrics_snapshots(snapshot_date);
CREATE INDEX idx_metrics_snapshots_business ON admin_metrics_snapshots(business_id, snapshot_date);
CREATE INDEX idx_metrics_snapshots_period ON admin_metrics_snapshots(period_type, snapshot_date);

-- System Alerts Indexes
CREATE INDEX idx_system_alerts_status ON system_alerts(status, severity);
CREATE INDEX idx_system_alerts_type ON system_alerts(alert_type, created_at);
CREATE INDEX idx_system_alerts_business ON system_alerts(business_id) WHERE business_id IS NOT NULL;
CREATE INDEX idx_system_alerts_active ON system_alerts(status, created_at) WHERE status = 'active';

-- Admin Activity Log Indexes
CREATE INDEX idx_admin_activity_admin ON admin_activity_log(admin_user_id, created_at);
CREATE INDEX idx_admin_activity_type ON admin_activity_log(action_type, created_at);
CREATE INDEX idx_admin_activity_target ON admin_activity_log(target_type, target_id);

-- Feature Flags Indexes
CREATE INDEX idx_feature_flags_enabled ON feature_flags(is_enabled);
CREATE INDEX idx_feature_flags_environment ON feature_flags(environment, is_enabled);

-- System Configuration Indexes
CREATE INDEX idx_system_config_category ON system_configuration(config_category);

-- Performance Metrics Indexes
CREATE INDEX idx_performance_metrics_name ON performance_metrics(metric_name, measured_at);
CREATE INDEX idx_performance_metrics_category ON performance_metrics(metric_category, measured_at);
CREATE INDEX idx_performance_metrics_business ON performance_metrics(business_id, measured_at) WHERE business_id IS NOT NULL;

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Update timestamps trigger for admin_dashboards
CREATE TRIGGER update_admin_dashboards_timestamp
AFTER UPDATE ON admin_dashboards
FOR EACH ROW
BEGIN
    UPDATE admin_dashboards
    SET updated_at = datetime('now')
    WHERE id = NEW.id;
END;

-- Update timestamps trigger for system_alerts
CREATE TRIGGER update_system_alerts_timestamp
AFTER UPDATE ON system_alerts
FOR EACH ROW
BEGIN
    UPDATE system_alerts
    SET updated_at = datetime('now')
    WHERE id = NEW.id;
END;

-- Update timestamps trigger for feature_flags
CREATE TRIGGER update_feature_flags_timestamp
AFTER UPDATE ON feature_flags
FOR EACH ROW
BEGIN
    UPDATE feature_flags
    SET updated_at = datetime('now')
    WHERE id = NEW.id;
END;

-- Update timestamps trigger for system_configuration
CREATE TRIGGER update_system_config_timestamp
AFTER UPDATE ON system_configuration
FOR EACH ROW
BEGIN
    UPDATE system_configuration
    SET updated_at = datetime('now')
    WHERE id = NEW.id;
END;

-- Feature flag enabled_at tracking
CREATE TRIGGER track_feature_flag_enabled
AFTER UPDATE ON feature_flags
FOR EACH ROW
WHEN NEW.is_enabled = 1 AND OLD.is_enabled = 0
BEGIN
    UPDATE feature_flags
    SET enabled_at = datetime('now')
    WHERE id = NEW.id;
END;

-- Feature flag disabled_at tracking
CREATE TRIGGER track_feature_flag_disabled
AFTER UPDATE ON feature_flags
FOR EACH ROW
WHEN NEW.is_enabled = 0 AND OLD.is_enabled = 1
BEGIN
    UPDATE feature_flags
    SET disabled_at = datetime('now')
    WHERE id = NEW.id;
END;
