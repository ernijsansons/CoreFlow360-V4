-- D1 Database schema for Design System Analytics
-- Initial migration

-- Component usage tracking
CREATE TABLE IF NOT EXISTS component_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    event TEXT NOT NULL,
    component TEXT,
    value REAL DEFAULT 1,
    user_id TEXT,
    session_id TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    metadata TEXT,
    INDEX idx_component_name (name),
    INDEX idx_timestamp (timestamp)
);

-- Analytics events
CREATE TABLE IF NOT EXISTS analytics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT NOT NULL,
    category TEXT,
    component TEXT,
    value REAL,
    user_id TEXT,
    session_id TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    properties TEXT,
    INDEX idx_event (event),
    INDEX idx_timestamp (timestamp)
);

-- Design token usage
CREATE TABLE IF NOT EXISTS token_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_type TEXT NOT NULL,
    token_name TEXT NOT NULL,
    component TEXT,
    count INTEGER DEFAULT 1,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_token_type (token_type),
    INDEX idx_component (component)
);

-- Error tracking
CREATE TABLE IF NOT EXISTS errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    error_type TEXT NOT NULL,
    message TEXT,
    stack TEXT,
    component TEXT,
    user_id TEXT,
    session_id TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved BOOLEAN DEFAULT FALSE,
    INDEX idx_error_type (error_type),
    INDEX idx_timestamp (timestamp)
);

-- Performance metrics
CREATE TABLE IF NOT EXISTS performance_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    metric_name TEXT NOT NULL,
    value REAL NOT NULL,
    component TEXT,
    page TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_metric_name (metric_name),
    INDEX idx_timestamp (timestamp)
);

-- Figma sync logs
CREATE TABLE IF NOT EXISTS figma_sync_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sync_type TEXT NOT NULL,
    status TEXT NOT NULL,
    tokens_updated INTEGER DEFAULT 0,
    error_message TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_timestamp (timestamp)
);