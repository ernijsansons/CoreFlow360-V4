-- Migration: 004_audit_workflows
-- Description: Audit logs with cost tracking and workflow state management
-- Created: 2024-12-01
-- Author: CoreFlow360 V4

-- Audit Logs table with cost tracking
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Audit Information
    event_type TEXT NOT NULL CHECK (event_type IN (
        'create', 'update', 'delete', 'view', 'export', 'import',
        'approve', 'reject', 'cancel', 'void', 'reverse',
        'login', 'logout', 'password_change', 'permission_change',
        'workflow_start', 'workflow_complete', 'workflow_fail',
        'api_call', 'system_event', 'error'
    )),
    event_name TEXT NOT NULL,
    event_description TEXT,

    -- Resource Information
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    resource_name TEXT,

    -- User and Session
    user_id TEXT,
    session_id TEXT,
    impersonated_by_user_id TEXT,

    -- Request Information
    ip_address TEXT,
    user_agent TEXT,
    request_method TEXT,
    request_path TEXT,
    request_query TEXT, -- JSON
    request_body TEXT, -- JSON (sanitized)
    response_status INTEGER,

    -- Changes Tracking
    old_values TEXT, -- JSON of changed fields before
    new_values TEXT, -- JSON of changed fields after
    changed_fields TEXT, -- JSON array of field names

    -- Cost Tracking
    operation_cost REAL DEFAULT 0, -- Cost of the operation in credits/currency
    compute_time_ms INTEGER DEFAULT 0, -- Computation time in milliseconds
    storage_bytes INTEGER DEFAULT 0, -- Storage used in bytes
    network_bytes INTEGER DEFAULT 0, -- Network transfer in bytes
    api_calls_count INTEGER DEFAULT 0, -- Number of API calls made
    database_reads INTEGER DEFAULT 0, -- Number of database reads
    database_writes INTEGER DEFAULT 0, -- Number of database writes

    -- AI Usage Tracking
    ai_model_used TEXT,
    ai_tokens_used INTEGER DEFAULT 0,
    ai_cost REAL DEFAULT 0,

    -- Status and Error
    status TEXT DEFAULT 'success' CHECK (status IN ('success', 'failure', 'partial', 'warning')),
    error_code TEXT,
    error_message TEXT,

    -- Compliance and Security
    is_sensitive INTEGER DEFAULT 0,
    compliance_flags TEXT, -- JSON array of compliance requirements
    risk_score INTEGER DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    event_timestamp TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (impersonated_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Workflow Definitions table
CREATE TABLE IF NOT EXISTS workflow_definitions (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Workflow Information
    workflow_key TEXT NOT NULL,
    workflow_name TEXT NOT NULL,
    workflow_version INTEGER DEFAULT 1,
    description TEXT,

    -- Workflow Type
    workflow_type TEXT NOT NULL CHECK (workflow_type IN (
        'approval',
        'review',
        'document',
        'onboarding',
        'procurement',
        'expense',
        'leave',
        'invoice',
        'payment',
        'custom'
    )),

    -- Workflow Configuration
    config TEXT NOT NULL, -- JSON configuration of workflow steps
    steps_count INTEGER NOT NULL DEFAULT 0,
    timeout_minutes INTEGER,
    auto_approve_conditions TEXT, -- JSON conditions for auto-approval

    -- Permissions
    can_be_cancelled INTEGER DEFAULT 1,
    can_be_paused INTEGER DEFAULT 1,
    requires_comments INTEGER DEFAULT 0,

    -- Status
    status TEXT DEFAULT 'active' CHECK (status IN ('draft', 'active', 'inactive', 'archived')),
    published_at TEXT,
    published_by_user_id TEXT,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    created_by_user_id TEXT,

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by_user_id) REFERENCES users(id),
    FOREIGN KEY (published_by_user_id) REFERENCES users(id),

    -- Constraints
    UNIQUE(business_id, workflow_key, workflow_version)
);

-- Workflow Instances table
CREATE TABLE IF NOT EXISTS workflow_instances (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    workflow_definition_id TEXT NOT NULL,

    -- Instance Information
    instance_key TEXT NOT NULL,
    instance_name TEXT,

    -- Context
    context_type TEXT, -- 'invoice', 'purchase_order', etc.
    context_id TEXT, -- ID of the related entity

    -- State Management
    current_state TEXT NOT NULL DEFAULT 'initiated',
    current_step_number INTEGER DEFAULT 0,
    total_steps INTEGER NOT NULL,

    -- Status
    status TEXT DEFAULT 'active' CHECK (status IN (
        'draft',
        'active',
        'paused',
        'waiting',
        'completed',
        'cancelled',
        'failed',
        'expired'
    )),

    -- Progress Tracking
    progress_percentage INTEGER DEFAULT 0 CHECK (progress_percentage >= 0 AND progress_percentage <= 100),
    completed_steps INTEGER DEFAULT 0,
    skipped_steps INTEGER DEFAULT 0,

    -- Timing
    started_at TEXT,
    paused_at TEXT,
    resumed_at TEXT,
    completed_at TEXT,
    cancelled_at TEXT,
    expires_at TEXT,

    -- Participants
    initiator_user_id TEXT NOT NULL,
    current_assignee_user_id TEXT,
    current_assignee_group TEXT,

    -- Data
    workflow_data TEXT, -- JSON data passed through workflow
    variables TEXT, -- JSON workflow variables

    -- Error Handling
    error_count INTEGER DEFAULT 0,
    last_error TEXT,
    last_error_at TEXT,

    -- Priority and SLA
    priority TEXT DEFAULT 'normal' CHECK (priority IN ('low', 'normal', 'high', 'urgent', 'critical')),
    sla_deadline TEXT,
    is_overdue INTEGER DEFAULT 0,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (workflow_definition_id) REFERENCES workflow_definitions(id),
    FOREIGN KEY (initiator_user_id) REFERENCES users(id),
    FOREIGN KEY (current_assignee_user_id) REFERENCES users(id) ON DELETE SET NULL,

    -- Constraints
    UNIQUE(business_id, instance_key)
);

-- Workflow Steps table
CREATE TABLE IF NOT EXISTS workflow_steps (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    workflow_instance_id TEXT NOT NULL,

    -- Step Information
    step_number INTEGER NOT NULL,
    step_name TEXT NOT NULL,
    step_type TEXT NOT NULL CHECK (step_type IN (
        'start',
        'task',
        'approval',
        'review',
        'notification',
        'condition',
        'parallel',
        'wait',
        'system',
        'end'
    )),

    -- Assignment
    assigned_to_user_id TEXT,
    assigned_to_group TEXT,
    assigned_to_role TEXT,
    assigned_at TEXT,

    -- Execution
    status TEXT DEFAULT 'pending' CHECK (status IN (
        'pending',
        'active',
        'completed',
        'skipped',
        'failed',
        'cancelled',
        'timeout'
    )),
    started_at TEXT,
    completed_at TEXT,
    completed_by_user_id TEXT,

    -- Decision and Action
    action_taken TEXT, -- 'approve', 'reject', 'return', etc.
    comments TEXT,
    attachments TEXT, -- JSON array of attachment IDs

    -- Conditions and Rules
    pre_conditions TEXT, -- JSON conditions to enter step
    post_conditions TEXT, -- JSON conditions to exit step
    timeout_minutes INTEGER,
    auto_complete INTEGER DEFAULT 0,

    -- Data
    input_data TEXT, -- JSON input data
    output_data TEXT, -- JSON output data

    -- Retry and Error
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    error_message TEXT,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    due_at TEXT,

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (workflow_instance_id) REFERENCES workflow_instances(id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_to_user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (completed_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Workflow Transitions table
CREATE TABLE IF NOT EXISTS workflow_transitions (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    workflow_instance_id TEXT NOT NULL,

    -- Transition Information
    from_step_id TEXT,
    to_step_id TEXT,
    from_state TEXT,
    to_state TEXT,

    -- Trigger
    triggered_by_user_id TEXT,
    trigger_type TEXT CHECK (trigger_type IN (
        'user_action',
        'auto_complete',
        'timeout',
        'condition_met',
        'system_event',
        'api_call'
    )),
    trigger_reason TEXT,

    -- Transition Data
    transition_data TEXT, -- JSON data

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (workflow_instance_id) REFERENCES workflow_instances(id) ON DELETE CASCADE,
    FOREIGN KEY (from_step_id) REFERENCES workflow_steps(id) ON DELETE SET NULL,
    FOREIGN KEY (to_step_id) REFERENCES workflow_steps(id) ON DELETE SET NULL,
    FOREIGN KEY (triggered_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Activity Logs table (detailed user activity)
CREATE TABLE IF NOT EXISTS activity_logs (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    user_id TEXT NOT NULL,

    -- Activity Information
    activity_type TEXT NOT NULL,
    activity_name TEXT NOT NULL,
    activity_description TEXT,

    -- Module and Feature
    module TEXT, -- 'finance', 'hr', 'inventory', etc.
    feature TEXT, -- 'invoice_create', 'employee_onboard', etc.

    -- Context
    context_type TEXT,
    context_id TEXT,
    context_name TEXT,

    -- Metrics
    duration_ms INTEGER,
    click_count INTEGER DEFAULT 0,
    scroll_depth INTEGER DEFAULT 0,

    -- Device and Location
    device_type TEXT,
    browser TEXT,
    os TEXT,
    screen_resolution TEXT,

    -- Session
    session_id TEXT,
    page_views INTEGER DEFAULT 1,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    activity_date TEXT DEFAULT (date('now')),
    activity_time TEXT DEFAULT (time('now')),

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- System Events table
CREATE TABLE IF NOT EXISTS system_events (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT,

    -- Event Information
    event_type TEXT NOT NULL,
    event_category TEXT NOT NULL CHECK (event_category IN (
        'security',
        'performance',
        'error',
        'warning',
        'info',
        'debug'
    )),
    event_name TEXT NOT NULL,
    event_description TEXT,

    -- Severity and Priority
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    priority INTEGER DEFAULT 0,

    -- Source
    source_component TEXT,
    source_service TEXT,
    source_version TEXT,

    -- Error Details (if applicable)
    error_code TEXT,
    error_message TEXT,
    stack_trace TEXT,

    -- Context and Metadata
    context TEXT, -- JSON context data
    metadata TEXT, -- JSON metadata

    -- Resolution
    is_resolved INTEGER DEFAULT 0,
    resolved_at TEXT,
    resolved_by_user_id TEXT,
    resolution_notes TEXT,

    -- Notification
    notification_sent INTEGER DEFAULT 0,
    notification_sent_at TEXT,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    event_timestamp TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (resolved_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Create indexes for audit and workflow tables
CREATE INDEX idx_audit_logs_business ON audit_logs(business_id, event_timestamp DESC);
CREATE INDEX idx_audit_logs_user ON audit_logs(user_id, event_timestamp DESC);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_logs_event ON audit_logs(event_type, status);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(event_timestamp);

CREATE INDEX idx_workflow_definitions_business ON workflow_definitions(business_id, status);
CREATE INDEX idx_workflow_definitions_key ON workflow_definitions(workflow_key, workflow_version);

CREATE INDEX idx_workflow_instances_business ON workflow_instances(business_id, status);
CREATE INDEX idx_workflow_instances_definition ON workflow_instances(workflow_definition_id);
CREATE INDEX idx_workflow_instances_context ON workflow_instances(context_type, context_id);
CREATE INDEX idx_workflow_instances_assignee ON workflow_instances(current_assignee_user_id) WHERE status = 'active';
CREATE INDEX idx_workflow_instances_overdue ON workflow_instances(sla_deadline) WHERE is_overdue = 1;

CREATE INDEX idx_workflow_steps_instance ON workflow_steps(workflow_instance_id, step_number);
CREATE INDEX idx_workflow_steps_assigned ON workflow_steps(assigned_to_user_id, status);
CREATE INDEX idx_workflow_steps_status ON workflow_steps(status) WHERE status IN ('pending', 'active');

CREATE INDEX idx_workflow_transitions_instance ON workflow_transitions(workflow_instance_id, created_at);

CREATE INDEX idx_activity_logs_business_user ON activity_logs(business_id, user_id, created_at DESC);
CREATE INDEX idx_activity_logs_session ON activity_logs(session_id);
CREATE INDEX idx_activity_logs_date ON activity_logs(activity_date);

CREATE INDEX idx_system_events_severity ON system_events(severity, is_resolved);
CREATE INDEX idx_system_events_category ON system_events(event_category, created_at DESC);
CREATE INDEX idx_system_events_unresolved ON system_events(is_resolved, severity) WHERE is_resolved = 0;