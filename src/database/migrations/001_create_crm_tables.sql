-- Migration: 001_create_crm_tables
-- Description: Create initial CRM tables for AI-native operations
-- Created: 2025-09-20

-- Companies table with AI-gathered intelligence
CREATE TABLE companies (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  name TEXT NOT NULL,
  domain TEXT UNIQUE,
  industry TEXT,
  size_range TEXT CHECK (size_range IN ('1-10', '11-50', '51-200', '201-500', '501-1000', '1000+')),
  revenue_range TEXT CHECK (revenue_range IN ('0-1M', '1M-5M', '5M-10M', '10M-50M', '50M-100M', '100M+')),
  ai_summary TEXT,
  ai_pain_points TEXT,
  ai_icp_score INTEGER CHECK (ai_icp_score >= 0 AND ai_icp_score <= 100),
  technologies TEXT CHECK (json_valid(technologies) OR technologies IS NULL),
  funding TEXT CHECK (json_valid(funding) OR funding IS NULL),
  news TEXT CHECK (json_valid(news) OR news IS NULL),
  social_profiles TEXT CHECK (json_valid(social_profiles) OR social_profiles IS NULL),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Contacts table with AI enrichment
CREATE TABLE contacts (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  company_id TEXT,
  email TEXT NOT NULL,
  phone TEXT,
  first_name TEXT,
  last_name TEXT,
  title TEXT,
  seniority_level TEXT CHECK (seniority_level IN ('individual_contributor', 'team_lead', 'manager', 'director', 'vp', 'c_level', 'founder')),
  department TEXT CHECK (department IN ('engineering', 'sales', 'marketing', 'hr', 'finance', 'operations', 'legal', 'executive', 'other')),
  linkedin_url TEXT,
  ai_personality TEXT,
  ai_communication_style TEXT,
  ai_interests TEXT CHECK (json_valid(ai_interests) OR ai_interests IS NULL),
  verified_phone BOOLEAN DEFAULT FALSE,
  verified_email BOOLEAN DEFAULT FALSE,
  timezone TEXT,
  preferred_contact_method TEXT CHECK (preferred_contact_method IN ('email', 'phone', 'linkedin', 'sms')),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (company_id) REFERENCES companies(id),
  UNIQUE(business_id, email)
);

-- Leads table with AI qualification
CREATE TABLE leads (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  contact_id TEXT,
  company_id TEXT,
  source TEXT NOT NULL,
  source_campaign TEXT,
  status TEXT DEFAULT 'new' CHECK (status IN ('new', 'qualifying', 'qualified', 'meeting_scheduled', 'opportunity', 'unqualified', 'closed_won', 'closed_lost')),
  ai_qualification_score INTEGER CHECK (ai_qualification_score >= 0 AND ai_qualification_score <= 100),
  ai_qualification_summary TEXT,
  ai_next_best_action TEXT,
  ai_predicted_value DECIMAL(12,2),
  ai_close_probability DECIMAL(3,2) CHECK (ai_close_probability >= 0 AND ai_close_probability <= 1),
  ai_estimated_close_date DATE,
  assigned_to TEXT,
  assigned_type TEXT DEFAULT 'ai' CHECK (assigned_type IN ('ai', 'human')),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (contact_id) REFERENCES contacts(id),
  FOREIGN KEY (company_id) REFERENCES companies(id)
);

-- Conversations table for AI and human interactions
CREATE TABLE conversations (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  lead_id TEXT,
  contact_id TEXT,
  type TEXT NOT NULL CHECK (type IN ('call', 'email', 'chat', 'sms', 'meeting', 'demo')),
  direction TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound')),
  participant_type TEXT NOT NULL CHECK (participant_type IN ('ai', 'human', 'mixed')),
  subject TEXT,
  transcript TEXT,
  ai_summary TEXT,
  ai_sentiment TEXT CHECK (ai_sentiment IN ('positive', 'neutral', 'negative')),
  ai_objections TEXT CHECK (json_valid(ai_objections) OR ai_objections IS NULL),
  ai_commitments TEXT CHECK (json_valid(ai_commitments) OR ai_commitments IS NULL),
  ai_next_steps TEXT CHECK (json_valid(ai_next_steps) OR ai_next_steps IS NULL),
  duration_seconds INTEGER,
  recording_url TEXT,
  external_id TEXT,
  metadata TEXT CHECK (json_valid(metadata) OR metadata IS NULL),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (lead_id) REFERENCES leads(id),
  FOREIGN KEY (contact_id) REFERENCES contacts(id)
);

-- AI Tasks Queue for autonomous operations
CREATE TABLE ai_tasks (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  type TEXT NOT NULL,
  priority INTEGER DEFAULT 5 CHECK (priority >= 1 AND priority <= 10),
  payload TEXT NOT NULL CHECK (json_valid(payload)),
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'cancelled')),
  assigned_agent TEXT,
  attempts INTEGER DEFAULT 0,
  max_attempts INTEGER DEFAULT 3,
  last_error TEXT,
  scheduled_at TIMESTAMP,
  started_at TIMESTAMP,
  completed_at TIMESTAMP,
  expires_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Performance indexes
CREATE INDEX idx_companies_business_domain ON companies(business_id, domain);
CREATE INDEX idx_companies_ai_icp_score ON companies(business_id, ai_icp_score DESC);
CREATE INDEX idx_contacts_business_email ON contacts(business_id, email);
CREATE INDEX idx_contacts_company ON contacts(company_id, created_at DESC);
CREATE INDEX idx_leads_business_status ON leads(business_id, status, created_at DESC);
CREATE INDEX idx_leads_assigned ON leads(assigned_to, status, created_at DESC);
CREATE INDEX idx_leads_ai_score ON leads(business_id, ai_qualification_score DESC);
CREATE INDEX idx_conversations_lead ON conversations(lead_id, created_at DESC);
CREATE INDEX idx_conversations_contact ON conversations(contact_id, created_at DESC);
CREATE INDEX idx_ai_tasks_pending ON ai_tasks(status, priority DESC, created_at);
CREATE INDEX idx_ai_tasks_business ON ai_tasks(business_id, status, created_at DESC);
CREATE INDEX idx_ai_tasks_scheduled ON ai_tasks(scheduled_at) WHERE scheduled_at IS NOT NULL;

-- Triggers for updated_at timestamps
CREATE TRIGGER update_companies_updated_at
  AFTER UPDATE ON companies
  BEGIN
    UPDATE companies SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;

CREATE TRIGGER update_contacts_updated_at
  AFTER UPDATE ON contacts
  BEGIN
    UPDATE contacts SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;

CREATE TRIGGER update_leads_updated_at
  AFTER UPDATE ON leads
  BEGIN
    UPDATE leads SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;

CREATE TRIGGER update_ai_tasks_updated_at
  AFTER UPDATE ON ai_tasks
  BEGIN
    UPDATE ai_tasks SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;