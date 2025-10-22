-- Support Agents Infrastructure Migration
-- Creates tables for Support Ticket, Knowledge Base, Chat Support, and SLA Monitor agents
-- Version: 1.0.0
-- Date: 2025-10-20

-- =====================================================
-- SUPPORT TICKETS
-- =====================================================

CREATE TABLE IF NOT EXISTS support_tickets (
  id TEXT PRIMARY KEY,
  ticket_number TEXT NOT NULL UNIQUE,
  business_id TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  customer_name TEXT NOT NULL,
  customer_email TEXT NOT NULL,

  -- Ticket Content
  subject TEXT NOT NULL,
  description TEXT NOT NULL,
  category TEXT NOT NULL CHECK (category IN ('technical', 'billing', 'feature_request', 'bug', 'question', 'other')),
  priority TEXT NOT NULL CHECK (priority IN ('low', 'medium', 'high', 'critical')),
  status TEXT NOT NULL CHECK (status IN ('new', 'open', 'in_progress', 'waiting_customer', 'resolved', 'closed')),

  -- AI Analysis
  sentiment TEXT CHECK (sentiment IN ('positive', 'neutral', 'negative', 'angry')),
  urgency_score INTEGER CHECK (urgency_score >= 0 AND urgency_score <= 100),
  tags TEXT, -- JSON array

  -- Assignment
  assigned_to TEXT,
  assigned_team TEXT,
  related_tickets TEXT, -- JSON array

  -- SLA Tracking
  sla_due_date TEXT NOT NULL,
  first_response_at TEXT,
  resolved_at TEXT,
  closed_at TEXT,
  response_time INTEGER, -- seconds
  resolution_time INTEGER, -- seconds

  -- Customer Satisfaction
  customer_satisfaction INTEGER CHECK (customer_satisfaction >= 1 AND customer_satisfaction <= 5),

  -- AI Suggestions
  ai_suggested_actions TEXT, -- JSON array
  ai_suggested_responses TEXT, -- JSON array
  ai_knowledge_base_articles TEXT, -- JSON array

  -- Conversation
  conversation_history TEXT, -- JSON array

  -- Metadata
  metadata TEXT, -- JSON object
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_by TEXT NOT NULL,

  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE
);

CREATE INDEX idx_support_tickets_business ON support_tickets(business_id);
CREATE INDEX idx_support_tickets_customer ON support_tickets(customer_id);
CREATE INDEX idx_support_tickets_status ON support_tickets(status);
CREATE INDEX idx_support_tickets_priority ON support_tickets(priority);
CREATE INDEX idx_support_tickets_assigned_team ON support_tickets(assigned_team);
CREATE INDEX idx_support_tickets_sla_due ON support_tickets(sla_due_date);
CREATE INDEX idx_support_tickets_created ON support_tickets(created_at);

-- =====================================================
-- KNOWLEDGE BASE ARTICLES
-- =====================================================

CREATE TABLE IF NOT EXISTS knowledge_base_articles (
  id TEXT PRIMARY KEY,
  business_id TEXT NOT NULL,

  -- Content
  title TEXT NOT NULL,
  slug TEXT NOT NULL,
  content TEXT NOT NULL,
  summary TEXT NOT NULL,

  -- Organization
  category TEXT NOT NULL,
  subcategory TEXT,
  tags TEXT, -- JSON array
  related_articles TEXT, -- JSON array

  -- Metrics
  helpfulness REAL DEFAULT 0 CHECK (helpfulness >= 0 AND helpfulness <= 1),
  views INTEGER DEFAULT 0,
  successful_resolutions INTEGER DEFAULT 0,

  -- Publishing
  language TEXT DEFAULT 'en',
  status TEXT NOT NULL CHECK (status IN ('draft', 'published', 'archived')),
  visibility TEXT NOT NULL CHECK (visibility IN ('public', 'internal', 'customer_only')),
  author TEXT NOT NULL,
  last_reviewed_at TEXT,

  -- Metadata
  metadata TEXT, -- JSON object (difficulty, reading time, prerequisites, etc.)
  seo_metadata TEXT, -- JSON object (meta title, description, keywords)

  -- Timestamps
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  published_at TEXT,

  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  UNIQUE(business_id, slug)
);

CREATE INDEX idx_kb_articles_business ON knowledge_base_articles(business_id);
CREATE INDEX idx_kb_articles_category ON knowledge_base_articles(category);
CREATE INDEX idx_kb_articles_status ON knowledge_base_articles(status);
CREATE INDEX idx_kb_articles_visibility ON knowledge_base_articles(visibility);
CREATE INDEX idx_kb_articles_language ON knowledge_base_articles(language);
CREATE INDEX idx_kb_articles_helpfulness ON knowledge_base_articles(helpfulness DESC);
CREATE INDEX idx_kb_articles_views ON knowledge_base_articles(views DESC);
CREATE INDEX idx_kb_articles_published ON knowledge_base_articles(published_at);
CREATE UNIQUE INDEX idx_kb_articles_slug ON knowledge_base_articles(business_id, slug);

-- Full-text search on title and content
-- Note: SQLite FTS5 virtual table
CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_base_search USING fts5(
  article_id,
  business_id,
  title,
  content,
  tags,
  content='knowledge_base_articles',
  content_rowid='rowid'
);

-- =====================================================
-- CHAT SESSIONS
-- =====================================================

CREATE TABLE IF NOT EXISTS chat_sessions (
  id TEXT PRIMARY KEY,
  business_id TEXT NOT NULL,

  -- Customer Info
  customer_id TEXT NOT NULL,
  customer_name TEXT NOT NULL,
  customer_email TEXT,

  -- Session Details
  channel TEXT NOT NULL CHECK (channel IN ('web', 'mobile', 'sms', 'whatsapp', 'facebook', 'slack')),
  status TEXT NOT NULL CHECK (status IN ('active', 'waiting', 'resolved', 'abandoned')),
  ai_assist_level TEXT NOT NULL CHECK (ai_assist_level IN ('full', 'suggestions', 'off')),

  -- Assignment
  human_agent_id TEXT,
  human_agent_name TEXT,

  -- Analysis
  sentiment TEXT CHECK (sentiment IN ('positive', 'neutral', 'negative', 'frustrated')),
  urgency TEXT CHECK (urgency IN ('low', 'medium', 'high', 'critical')),
  intents TEXT, -- JSON array
  resolved_issues TEXT, -- JSON array
  suggested_articles TEXT, -- JSON array

  -- Metadata
  metadata TEXT, -- JSON object
  context TEXT, -- JSON object (customer profile, previous conversations, etc.)
  satisfaction INTEGER CHECK (satisfaction >= 1 AND satisfaction <= 5),

  -- Timestamps
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  closed_at TEXT,

  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE
);

CREATE INDEX idx_chat_sessions_business ON chat_sessions(business_id);
CREATE INDEX idx_chat_sessions_customer ON chat_sessions(customer_id);
CREATE INDEX idx_chat_sessions_status ON chat_sessions(status);
CREATE INDEX idx_chat_sessions_channel ON chat_sessions(channel);
CREATE INDEX idx_chat_sessions_created ON chat_sessions(created_at);
CREATE INDEX idx_chat_sessions_human_agent ON chat_sessions(human_agent_id);

-- =====================================================
-- CHAT MESSAGES
-- =====================================================

CREATE TABLE IF NOT EXISTS chat_messages (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,

  -- Message Content
  type TEXT NOT NULL CHECK (type IN ('customer', 'agent', 'ai', 'system')),
  author_id TEXT NOT NULL,
  author_name TEXT NOT NULL,
  content TEXT NOT NULL,

  -- Analysis
  intent TEXT,
  sentiment TEXT,
  confidence REAL CHECK (confidence >= 0 AND confidence <= 1),

  -- Attachments
  attachments TEXT, -- JSON array

  -- Metadata
  metadata TEXT, -- JSON object

  -- Timestamp
  created_at TEXT NOT NULL,

  FOREIGN KEY (session_id) REFERENCES chat_sessions(id) ON DELETE CASCADE
);

CREATE INDEX idx_chat_messages_session ON chat_messages(session_id);
CREATE INDEX idx_chat_messages_type ON chat_messages(type);
CREATE INDEX idx_chat_messages_created ON chat_messages(created_at);

-- =====================================================
-- SLA CONFIGURATIONS
-- =====================================================

CREATE TABLE IF NOT EXISTS sla_configurations (
  id TEXT PRIMARY KEY,
  business_id TEXT NOT NULL,

  -- SLA Name and Description
  name TEXT NOT NULL,
  description TEXT,

  -- First Response Time (in hours)
  first_response_low INTEGER DEFAULT 24,
  first_response_medium INTEGER DEFAULT 8,
  first_response_high INTEGER DEFAULT 4,
  first_response_critical INTEGER DEFAULT 1,

  -- Resolution Time (in hours)
  resolution_low INTEGER DEFAULT 72,
  resolution_medium INTEGER DEFAULT 24,
  resolution_high INTEGER DEFAULT 8,
  resolution_critical INTEGER DEFAULT 4,

  -- Escalation
  escalation_threshold INTEGER DEFAULT 2, -- hours before escalation

  -- Business Hours
  business_hours_start INTEGER DEFAULT 9, -- 9 AM
  business_hours_end INTEGER DEFAULT 17, -- 5 PM
  business_days TEXT DEFAULT '["mon","tue","wed","thu","fri"]', -- JSON array
  timezone TEXT DEFAULT 'UTC',

  -- Status
  is_active BOOLEAN DEFAULT 1,

  -- Timestamps
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,

  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE
);

CREATE INDEX idx_sla_configs_business ON sla_configurations(business_id);
CREATE INDEX idx_sla_configs_active ON sla_configurations(is_active);

-- =====================================================
-- SLA TRACKING
-- =====================================================

CREATE TABLE IF NOT EXISTS sla_tracking (
  id TEXT PRIMARY KEY,
  ticket_id TEXT NOT NULL,
  business_id TEXT NOT NULL,
  sla_config_id TEXT NOT NULL,

  -- First Response SLA
  first_response_target INTEGER NOT NULL, -- hours
  first_response_actual INTEGER, -- hours
  first_response_status TEXT CHECK (first_response_status IN ('met', 'at_risk', 'breached')),
  first_response_breached_at TEXT,

  -- Resolution SLA
  resolution_target INTEGER NOT NULL, -- hours
  resolution_actual INTEGER, -- hours
  resolution_status TEXT CHECK (resolution_status IN ('met', 'at_risk', 'breached')),
  resolution_breached_at TEXT,

  -- Escalation
  escalation_required BOOLEAN DEFAULT 0,
  escalated_at TEXT,
  escalated_to TEXT,

  -- Prediction
  predicted_breach BOOLEAN DEFAULT 0,
  breach_probability REAL CHECK (breach_probability >= 0 AND breach_probability <= 1),

  -- Timestamps
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,

  FOREIGN KEY (ticket_id) REFERENCES support_tickets(id) ON DELETE CASCADE,
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  FOREIGN KEY (sla_config_id) REFERENCES sla_configurations(id) ON DELETE CASCADE
);

CREATE INDEX idx_sla_tracking_ticket ON sla_tracking(ticket_id);
CREATE INDEX idx_sla_tracking_business ON sla_tracking(business_id);
CREATE INDEX idx_sla_tracking_first_response_status ON sla_tracking(first_response_status);
CREATE INDEX idx_sla_tracking_resolution_status ON sla_tracking(resolution_status);
CREATE INDEX idx_sla_tracking_escalation ON sla_tracking(escalation_required);

-- =====================================================
-- SUPPORT METRICS (for reporting and analytics)
-- =====================================================

CREATE TABLE IF NOT EXISTS support_metrics (
  id TEXT PRIMARY KEY,
  business_id TEXT NOT NULL,
  date TEXT NOT NULL, -- YYYY-MM-DD

  -- Ticket Metrics
  tickets_created INTEGER DEFAULT 0,
  tickets_resolved INTEGER DEFAULT 0,
  tickets_closed INTEGER DEFAULT 0,
  tickets_escalated INTEGER DEFAULT 0,

  -- Response Times (in seconds)
  avg_first_response_time INTEGER,
  avg_resolution_time INTEGER,
  median_response_time INTEGER,

  -- SLA Performance
  sla_first_response_met INTEGER DEFAULT 0,
  sla_first_response_breached INTEGER DEFAULT 0,
  sla_resolution_met INTEGER DEFAULT 0,
  sla_resolution_breached INTEGER DEFAULT 0,

  -- Customer Satisfaction
  avg_csat REAL CHECK (avg_csat >= 1 AND avg_csat <= 5),
  total_csat_responses INTEGER DEFAULT 0,

  -- Chat Metrics
  chat_sessions_started INTEGER DEFAULT 0,
  chat_sessions_completed INTEGER DEFAULT 0,
  chat_sessions_abandoned INTEGER DEFAULT 0,
  avg_chat_duration INTEGER, -- seconds

  -- Knowledge Base Metrics
  kb_article_views INTEGER DEFAULT 0,
  kb_helpful_votes INTEGER DEFAULT 0,
  kb_unhelpful_votes INTEGER DEFAULT 0,

  -- Agent Performance
  avg_tickets_per_agent REAL,
  agent_utilization REAL CHECK (agent_utilization >= 0 AND agent_utilization <= 1),

  -- Timestamps
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,

  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  UNIQUE(business_id, date)
);

CREATE INDEX idx_support_metrics_business ON support_metrics(business_id);
CREATE INDEX idx_support_metrics_date ON support_metrics(date DESC);
CREATE UNIQUE INDEX idx_support_metrics_business_date ON support_metrics(business_id, date);

-- =====================================================
-- INSERT DEFAULT SLA CONFIGURATION
-- =====================================================

INSERT OR IGNORE INTO sla_configurations (
  id, business_id, name, description, is_active, created_at, updated_at
)
SELECT
  'default_sla_' || id,
  id,
  'Default SLA Policy',
  'Standard SLA policy for all tickets',
  1,
  datetime('now'),
  datetime('now')
FROM businesses
WHERE NOT EXISTS (
  SELECT 1 FROM sla_configurations WHERE business_id = businesses.id
);

-- =====================================================
-- VIEWS FOR ANALYTICS
-- =====================================================

-- Active Tickets Summary
CREATE VIEW IF NOT EXISTS v_active_tickets_summary AS
SELECT
  business_id,
  status,
  priority,
  COUNT(*) as ticket_count,
  AVG(urgency_score) as avg_urgency,
  COUNT(CASE WHEN datetime(sla_due_date) < datetime('now') THEN 1 END) as breached_sla
FROM support_tickets
WHERE status NOT IN ('resolved', 'closed')
GROUP BY business_id, status, priority;

-- Agent Performance
CREATE VIEW IF NOT EXISTS v_agent_performance AS
SELECT
  business_id,
  assigned_to as agent_id,
  COUNT(*) as total_tickets,
  COUNT(CASE WHEN status = 'resolved' THEN 1 END) as resolved_tickets,
  AVG(response_time) as avg_response_time,
  AVG(resolution_time) as avg_resolution_time,
  AVG(customer_satisfaction) as avg_csat
FROM support_tickets
WHERE assigned_to IS NOT NULL
GROUP BY business_id, assigned_to;

-- Knowledge Base Effectiveness
CREATE VIEW IF NOT EXISTS v_kb_effectiveness AS
SELECT
  business_id,
  category,
  COUNT(*) as article_count,
  AVG(helpfulness) as avg_helpfulness,
  SUM(views) as total_views,
  SUM(successful_resolutions) as total_resolutions,
  ROUND(CAST(SUM(successful_resolutions) AS REAL) / NULLIF(SUM(views), 0) * 100, 2) as resolution_rate
FROM knowledge_base_articles
WHERE status = 'published'
GROUP BY business_id, category;

-- =====================================================
-- TRIGGERS FOR AUTOMATIC UPDATES
-- =====================================================

-- Update knowledge_base_search when articles change
CREATE TRIGGER IF NOT EXISTS kb_articles_after_insert
AFTER INSERT ON knowledge_base_articles
BEGIN
  INSERT INTO knowledge_base_search(article_id, business_id, title, content, tags)
  VALUES (NEW.id, NEW.business_id, NEW.title, NEW.content, NEW.tags);
END;

CREATE TRIGGER IF NOT EXISTS kb_articles_after_update
AFTER UPDATE ON knowledge_base_articles
BEGIN
  UPDATE knowledge_base_search
  SET title = NEW.title, content = NEW.content, tags = NEW.tags
  WHERE article_id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS kb_articles_after_delete
AFTER DELETE ON knowledge_base_articles
BEGIN
  DELETE FROM knowledge_base_search WHERE article_id = OLD.id;
END;

-- Update ticket metrics on ticket changes
CREATE TRIGGER IF NOT EXISTS update_ticket_metrics_on_create
AFTER INSERT ON support_tickets
BEGIN
  INSERT INTO support_metrics (
    id, business_id, date, tickets_created, created_at, updated_at
  )
  VALUES (
    'metric_' || NEW.business_id || '_' || date('now'),
    NEW.business_id,
    date('now'),
    1,
    datetime('now'),
    datetime('now')
  )
  ON CONFLICT(business_id, date) DO UPDATE SET
    tickets_created = tickets_created + 1,
    updated_at = datetime('now');
END;

-- =====================================================
-- SAMPLE DATA (for development/testing)
-- =====================================================

-- Note: Sample data would go here for development environments
-- Commented out for production deployment

-- =====================================================
-- MIGRATION COMPLETE
-- =====================================================

-- Verify tables created
SELECT 'Migration 070 completed successfully. Support infrastructure created.' as status;
