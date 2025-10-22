-- Migration: Custom Report Builder
-- Description: User-defined reports with scheduling
-- Created: 2025-10-12

-- =======================
-- Report Templates
-- =======================

CREATE TABLE IF NOT EXISTS report_templates (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  report_type TEXT NOT NULL,
  data_source TEXT NOT NULL,
  sql_query TEXT,
  filters TEXT,
  columns TEXT NOT NULL,
  sorting TEXT,
  grouping TEXT,
  aggregations TEXT,
  is_public BOOLEAN NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  UNIQUE(business_id, name)
);

-- =======================
-- Scheduled Reports
-- =======================

CREATE TABLE IF NOT EXISTS scheduled_reports (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  template_id TEXT NOT NULL,
  schedule_name TEXT NOT NULL,
  frequency TEXT NOT NULL,
  schedule_time TEXT NOT NULL,
  recipients TEXT NOT NULL,
  format TEXT NOT NULL DEFAULT 'pdf',
  is_active BOOLEAN NOT NULL DEFAULT 1,
  last_run_at TEXT,
  next_run_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (template_id) REFERENCES report_templates(id) ON DELETE CASCADE
);

-- =======================
-- Report Execution History
-- =======================

CREATE TABLE IF NOT EXISTS report_executions (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  template_id TEXT NOT NULL,
  executed_by TEXT NOT NULL,
  execution_time REAL NOT NULL,
  row_count INTEGER NOT NULL,
  file_path TEXT,
  parameters TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (template_id) REFERENCES report_templates(id) ON DELETE CASCADE
);

-- =======================
-- Indexes
-- =======================

CREATE INDEX idx_report_templates_business ON report_templates(business_id);
CREATE INDEX idx_scheduled_reports_template ON scheduled_reports(template_id);
CREATE INDEX idx_scheduled_reports_next_run ON scheduled_reports(next_run_at, is_active) WHERE is_active = 1;
CREATE INDEX idx_report_executions_template ON report_executions(template_id);
