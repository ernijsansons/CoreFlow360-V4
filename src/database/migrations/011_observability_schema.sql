-- CoreFlow360 V4 - Observability Platform Schema
-- Comprehensive telemetry, metrics, tracing, and alerting

-- =============================================
-- TELEMETRY & LOGGING TABLES
-- =============================================

-- Main log entries table (partitioned by date)
CREATE TABLE log_entries (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Distributed Tracing
    trace_id TEXT NOT NULL,
    span_id TEXT NOT NULL,
    parent_span_id TEXT,

    -- Business Context
    business_id TEXT NOT NULL,
    user_id TEXT,
    session_id TEXT,

    -- Request Context
    request_id TEXT NOT NULL,
    method TEXT,
    path TEXT,
    status_code INTEGER,
    latency_ms REAL,

    -- AI Context
    ai_model TEXT,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    ai_cost_cents REAL,
    ai_provider TEXT,

    -- Business Context
    module TEXT NOT NULL,
    capability TEXT NOT NULL,
    workflow_id TEXT,
    document_id TEXT,

    -- Performance Metrics
    cpu_ms REAL,
    memory_mb REAL,
    io_ops INTEGER,
    cache_hit BOOLEAN,

    -- Error Context
    error_type TEXT,
    error_message TEXT,
    error_stack TEXT,
    error_user_message TEXT,

    -- Log Level
    level TEXT NOT NULL DEFAULT 'INFO', -- DEBUG, INFO, WARN, ERROR, CRITICAL

    -- Custom Metadata (JSON)
    metadata TEXT, -- JSON string

    -- Indexing
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (business_id) REFERENCES businesses(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Indexes for log entries
CREATE INDEX idx_log_entries_timestamp ON log_entries(timestamp);
CREATE INDEX idx_log_entries_trace_id ON log_entries(trace_id);
CREATE INDEX idx_log_entries_business_id ON log_entries(business_id);
CREATE INDEX idx_log_entries_user_id ON log_entries(user_id);
CREATE INDEX idx_log_entries_module ON log_entries(module);
CREATE INDEX idx_log_entries_level ON log_entries(level);
CREATE INDEX idx_log_entries_error_type ON log_entries(error_type);
CREATE INDEX idx_log_entries_latency ON log_entries(latency_ms);

-- =============================================
-- METRICS TABLES
-- =============================================

-- Time-series metrics table
CREATE TABLE metrics (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    business_id TEXT NOT NULL,

    -- Metric Identification
    metric_name TEXT NOT NULL,
    metric_type TEXT NOT NULL, -- counter, gauge, histogram, summary

    -- Values
    value REAL NOT NULL,
    count INTEGER DEFAULT 1,

    -- Labels (JSON)
    labels TEXT, -- JSON object with key-value pairs

    -- Metadata
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (business_id) REFERENCES businesses(id)
);

-- Indexes for metrics
CREATE INDEX idx_metrics_timestamp ON metrics(timestamp);
CREATE INDEX idx_metrics_business_id ON metrics(business_id);
CREATE INDEX idx_metrics_metric_name ON metrics(metric_name);
CREATE INDEX idx_metrics_metric_type ON metrics(metric_type);

-- Pre-aggregated metrics for performance
CREATE TABLE metric_aggregations (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    timestamp DATETIME NOT NULL,
    business_id TEXT NOT NULL,

    metric_name TEXT NOT NULL,
    aggregation_period TEXT NOT NULL, -- 1m, 5m, 1h, 1d

    -- Aggregated values
    count INTEGER NOT NULL,
    sum REAL NOT NULL,
    min REAL NOT NULL,
    max REAL NOT NULL,
    avg REAL NOT NULL,
    p50 REAL,
    p95 REAL,
    p99 REAL,

    -- Labels hash for grouping
    labels_hash TEXT NOT NULL,
    labels TEXT, -- Original labels JSON

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (business_id) REFERENCES businesses(id)
);

-- Indexes for aggregations
CREATE INDEX idx_metric_agg_timestamp ON metric_aggregations(timestamp);
CREATE INDEX idx_metric_agg_business_id ON metric_aggregations(business_id);
CREATE INDEX idx_metric_agg_metric_name ON metric_aggregations(metric_name);
CREATE INDEX idx_metric_agg_period ON metric_aggregations(aggregation_period);
CREATE INDEX idx_metric_agg_labels_hash ON metric_aggregations(labels_hash);

-- =============================================
-- DISTRIBUTED TRACING TABLES
-- =============================================

-- Trace metadata
CREATE TABLE traces (
    trace_id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL,
    user_id TEXT,

    -- Trace Properties
    service_name TEXT NOT NULL,
    operation_name TEXT NOT NULL,
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    duration_ms REAL,

    -- Status
    status TEXT NOT NULL DEFAULT 'ok', -- ok, error, timeout
    status_message TEXT,

    -- Metadata
    tags TEXT, -- JSON object

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (business_id) REFERENCES businesses(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Spans within traces
CREATE TABLE spans (
    span_id TEXT PRIMARY KEY,
    trace_id TEXT NOT NULL,
    parent_span_id TEXT,

    -- Span Properties
    service_name TEXT NOT NULL,
    operation_name TEXT NOT NULL,
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    duration_ms REAL,

    -- Status
    status TEXT NOT NULL DEFAULT 'ok',
    status_message TEXT,

    -- Context
    span_kind TEXT, -- client, server, internal, producer, consumer
    tags TEXT, -- JSON object
    logs TEXT, -- JSON array of log events

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (trace_id) REFERENCES traces(trace_id)
);

-- Indexes for tracing
CREATE INDEX idx_traces_business_id ON traces(business_id);
CREATE INDEX idx_traces_start_time ON traces(start_time);
CREATE INDEX idx_traces_duration ON traces(duration_ms);
CREATE INDEX idx_traces_status ON traces(status);
CREATE INDEX idx_spans_trace_id ON spans(trace_id);
CREATE INDEX idx_spans_parent_span_id ON spans(parent_span_id);
CREATE INDEX idx_spans_start_time ON spans(start_time);

-- =============================================
-- ALERTING SYSTEM TABLES
-- =============================================

-- Alert rules configuration
CREATE TABLE alert_rules (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Rule Definition
    name TEXT NOT NULL,
    description TEXT,
    query TEXT NOT NULL, -- SQL or PromQL-like query
    condition TEXT NOT NULL, -- JSON condition definition

    -- Thresholds
    threshold_value REAL,
    threshold_operator TEXT, -- gt, lt, eq, ne, gte, lte
    evaluation_window TEXT, -- 5m, 15m, 1h, etc.

    -- Alerting Configuration
    severity TEXT NOT NULL, -- low, medium, high, critical
    enabled BOOLEAN NOT NULL DEFAULT true,

    -- Notification Settings
    notification_channels TEXT, -- JSON array of channel IDs
    escalation_rules TEXT, -- JSON escalation configuration

    -- Machine Learning
    use_ml_anomaly_detection BOOLEAN DEFAULT false,
    ml_sensitivity REAL DEFAULT 0.95,
    ml_model_type TEXT, -- isolation-forest, prophet, arima

    -- Metadata
    created_by TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (business_id) REFERENCES businesses(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Alert instances
CREATE TABLE alerts (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    rule_id TEXT NOT NULL,
    business_id TEXT NOT NULL,

    -- Alert Properties
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'firing', -- firing, resolved, silenced

    -- Trigger Information
    triggered_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME,
    metric_value REAL,
    threshold_value REAL,

    -- Context
    labels TEXT, -- JSON object
    annotations TEXT, -- JSON object

    -- Resolution
    resolved_by TEXT,
    resolution_note TEXT,

    -- Fingerprint for deduplication
    fingerprint TEXT NOT NULL,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (rule_id) REFERENCES alert_rules(id),
    FOREIGN KEY (business_id) REFERENCES businesses(id),
    FOREIGN KEY (resolved_by) REFERENCES users(id)
);

-- Alert notifications log
CREATE TABLE alert_notifications (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    alert_id TEXT NOT NULL,

    -- Notification Details
    channel_type TEXT NOT NULL, -- email, sms, slack, webhook, etc.
    channel_config TEXT, -- JSON configuration
    recipient TEXT NOT NULL,

    -- Status
    status TEXT NOT NULL, -- pending, sent, failed, delivered
    sent_at DATETIME,
    delivered_at DATETIME,

    -- Response
    response_code INTEGER,
    response_message TEXT,
    error_message TEXT,

    -- Retry Logic
    retry_count INTEGER DEFAULT 0,
    next_retry_at DATETIME,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (alert_id) REFERENCES alerts(id)
);

-- =============================================
-- DASHBOARD AND VISUALIZATION TABLES
-- =============================================

-- Custom dashboards
CREATE TABLE dashboards (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Dashboard Properties
    name TEXT NOT NULL,
    description TEXT,
    layout TEXT NOT NULL, -- JSON layout configuration

    -- Access Control
    visibility TEXT NOT NULL DEFAULT 'private', -- private, team, public
    shared_with TEXT, -- JSON array of user/team IDs

    -- Configuration
    refresh_interval INTEGER DEFAULT 30, -- seconds
    time_range TEXT DEFAULT '1h', -- default time range
    variables TEXT, -- JSON template variables

    -- Metadata
    created_by TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (business_id) REFERENCES businesses(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Dashboard panels/widgets
CREATE TABLE dashboard_panels (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    dashboard_id TEXT NOT NULL,

    -- Panel Properties
    title TEXT NOT NULL,
    type TEXT NOT NULL, -- chart, table, stat, logs, etc.
    position TEXT NOT NULL, -- JSON {x, y, w, h}

    -- Query Configuration
    query TEXT NOT NULL,
    data_source TEXT NOT NULL,
    visualization_config TEXT, -- JSON visualization settings

    -- Display Options
    display_options TEXT, -- JSON display configuration

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (dashboard_id) REFERENCES dashboards(id)
);

-- =============================================
-- ANOMALY DETECTION AND ML TABLES
-- =============================================

-- ML models for anomaly detection
CREATE TABLE ml_models (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Model Properties
    name TEXT NOT NULL,
    type TEXT NOT NULL, -- isolation-forest, prophet, lstm, etc.
    target_metric TEXT NOT NULL,

    -- Model Configuration
    hyperparameters TEXT, -- JSON hyperparameters
    training_data_query TEXT,
    training_period TEXT, -- 7d, 30d, etc.

    -- Model State
    status TEXT NOT NULL DEFAULT 'training', -- training, ready, error
    accuracy_score REAL,
    last_trained_at DATETIME,
    model_artifact_url TEXT, -- URL to stored model

    -- Metadata
    created_by TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (business_id) REFERENCES businesses(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Anomaly detection results
CREATE TABLE anomalies (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    model_id TEXT NOT NULL,
    business_id TEXT NOT NULL,

    -- Anomaly Properties
    timestamp DATETIME NOT NULL,
    metric_name TEXT NOT NULL,
    actual_value REAL NOT NULL,
    predicted_value REAL,
    anomaly_score REAL NOT NULL, -- 0-1

    -- Classification
    severity TEXT, -- low, medium, high
    confidence REAL, -- 0-1

    -- Context
    labels TEXT, -- JSON object
    explanation TEXT, -- Human-readable explanation

    -- Status
    reviewed BOOLEAN DEFAULT false,
    reviewed_by TEXT,
    review_note TEXT,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (model_id) REFERENCES ml_models(id),
    FOREIGN KEY (business_id) REFERENCES businesses(id),
    FOREIGN KEY (reviewed_by) REFERENCES users(id)
);

-- =============================================
-- NOTIFICATION CHANNELS
-- =============================================

-- Notification channel configurations
CREATE TABLE notification_channels (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Channel Properties
    name TEXT NOT NULL,
    type TEXT NOT NULL, -- email, sms, slack, webhook, pagerduty, etc.
    enabled BOOLEAN NOT NULL DEFAULT true,

    -- Configuration
    config TEXT NOT NULL, -- JSON configuration (URLs, tokens, etc.)

    -- Rate Limiting
    rate_limit_enabled BOOLEAN DEFAULT true,
    rate_limit_count INTEGER DEFAULT 10,
    rate_limit_window INTEGER DEFAULT 3600, -- seconds

    -- Testing
    last_test_at DATETIME,
    last_test_status TEXT, -- success, failed
    last_test_error TEXT,

    -- Metadata
    created_by TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (business_id) REFERENCES businesses(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- =============================================
-- COST TRACKING AND ATTRIBUTION
-- =============================================

-- Cost tracking for AI operations
CREATE TABLE cost_tracking (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    business_id TEXT NOT NULL,

    -- Cost Attribution
    user_id TEXT,
    workflow_id TEXT,
    document_id TEXT,
    module TEXT,
    capability TEXT,

    -- AI Costs
    ai_provider TEXT,
    ai_model TEXT,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    cost_cents REAL NOT NULL,

    -- Request Context
    request_id TEXT,
    trace_id TEXT,

    -- Metadata
    metadata TEXT, -- JSON additional context

    FOREIGN KEY (business_id) REFERENCES businesses(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Indexes for cost tracking
CREATE INDEX idx_cost_tracking_timestamp ON cost_tracking(timestamp);
CREATE INDEX idx_cost_tracking_business_id ON cost_tracking(business_id);
CREATE INDEX idx_cost_tracking_user_id ON cost_tracking(user_id);
CREATE INDEX idx_cost_tracking_workflow_id ON cost_tracking(workflow_id);
CREATE INDEX idx_cost_tracking_ai_provider ON cost_tracking(ai_provider);

-- =============================================
-- PERFORMANCE MONITORING
-- =============================================

-- Service performance metrics
CREATE TABLE service_performance (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    business_id TEXT NOT NULL,

    -- Service Identification
    service_name TEXT NOT NULL,
    endpoint TEXT,
    method TEXT,

    -- Performance Metrics
    request_count INTEGER NOT NULL,
    error_count INTEGER NOT NULL,
    avg_latency_ms REAL NOT NULL,
    p50_latency_ms REAL,
    p95_latency_ms REAL,
    p99_latency_ms REAL,

    -- Resource Usage
    avg_cpu_percent REAL,
    avg_memory_mb REAL,
    max_memory_mb REAL,

    -- Time Window
    window_start DATETIME NOT NULL,
    window_end DATETIME NOT NULL,

    FOREIGN KEY (business_id) REFERENCES businesses(id)
);

-- Indexes for performance monitoring
CREATE INDEX idx_service_perf_timestamp ON service_performance(timestamp);
CREATE INDEX idx_service_perf_business_id ON service_performance(business_id);
CREATE INDEX idx_service_perf_service_name ON service_performance(service_name);
CREATE INDEX idx_service_perf_window_start ON service_performance(window_start);

-- =============================================
-- AUDIT AND COMPLIANCE
-- =============================================

-- Audit log for compliance
CREATE TABLE audit_log (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    business_id TEXT NOT NULL,

    -- Actor Information
    user_id TEXT,
    service_name TEXT,
    ip_address TEXT,
    user_agent TEXT,

    -- Action Details
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,

    -- Changes
    old_values TEXT, -- JSON
    new_values TEXT, -- JSON

    -- Result
    success BOOLEAN NOT NULL,
    error_message TEXT,

    -- Context
    session_id TEXT,
    request_id TEXT,
    trace_id TEXT,

    FOREIGN KEY (business_id) REFERENCES businesses(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Indexes for audit log
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_log_business_id ON audit_log(business_id);
CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_audit_log_resource_type ON audit_log(resource_type);

-- =============================================
-- VIEWS FOR COMMON QUERIES
-- =============================================

-- Error rate by service view
CREATE VIEW service_error_rates AS
SELECT
    service_name,
    business_id,
    DATE(timestamp) as date,
    COUNT(*) as total_requests,
    COUNT(CASE WHEN status_code >= 400 THEN 1 END) as error_requests,
    ROUND(
        (COUNT(CASE WHEN status_code >= 400 THEN 1 END) * 100.0) / COUNT(*),
        2
    ) as error_rate_percent
FROM log_entries
WHERE timestamp >= datetime('now', '-7 days')
GROUP BY service_name, business_id, DATE(timestamp);

-- AI cost summary view
CREATE VIEW ai_cost_summary AS
SELECT
    business_id,
    DATE(timestamp) as date,
    ai_provider,
    ai_model,
    SUM(cost_cents) / 100.0 as total_cost_dollars,
    SUM(prompt_tokens) as total_prompt_tokens,
    SUM(completion_tokens) as total_completion_tokens,
    COUNT(*) as request_count
FROM cost_tracking
WHERE timestamp >= datetime('now', '-30 days')
GROUP BY business_id, DATE(timestamp), ai_provider, ai_model;

-- Active alerts view
CREATE VIEW active_alerts AS
SELECT
    a.id,
    a.title,
    a.severity,
    a.triggered_at,
    ar.name as rule_name,
    a.business_id,
    a.metric_value,
    a.threshold_value
FROM alerts a
JOIN alert_rules ar ON a.rule_id = ar.id
WHERE a.status = 'firing'
ORDER BY
    CASE a.severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
    END,
    a.triggered_at DESC;