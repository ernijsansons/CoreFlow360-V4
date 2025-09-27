import { MigrationRunner, type MigrationFile, type MigrationResult } from '../modules/database/migration-runner';
import type { Env } from '../types/env';

export // TODO: Consider splitting CRMMigrationManager into smaller, focused classes
class CRMMigrationManager {
  private migrationRunner: MigrationRunner;
  private env: Env;

  constructor(env: Env, executedBy: string = 'system') {
    this.env = env;
    this.migrationRunner = new MigrationRunner(env.DB_MAIN, executedBy);
  }

  /**
   * Get all CRM migrations in order
   */
  async getCRMMigrations(): Promise<MigrationFile[]> {
    const migrations: MigrationFile[] = [];

    // Migration 001: Core CRM tables
    const migration001 = await this.createMigrationFile(
      '001',
      'create_crm_tables',
      await this.getMigration001SQL()
    );
    migrations.push(migration001);

    // Migration 002: Extended CRM features
    const migration002 = await this.createMigrationFile(
      '002',
      'add_extended_crm_features',
      await this.getMigration002SQL()
    );
    migrations.push(migration002);

    // Migration 003: BANT Qualification features
    const migration003 = await this.createMigrationFile(
      '003',
      'add_bant_qualification',
      await this.getMigration003SQL()
    );
    migrations.push(migration003);

    // Migration 004: Meeting Management and Booking
    const migration004 = await this.createMigrationFile(
      '004',
      'add_meeting_management',
      await this.getMigration004SQL()
    );
    migrations.push(migration004);

    // Migration 005: Voicemail Management
    const migration005 = await this.createMigrationFile(
      '005',
      'add_voicemail_management',
      await this.getMigration005SQL()
    );
    migrations.push(migration005);

    return migrations;
  }

  /**
   * Execute all CRM migrations
   */
  async executeCRMMigrations(): Promise<MigrationResult[]> {
    const migrations = await this.getCRMMigrations();
    return this.migrationRunner.executeMigrations(migrations);
  }

  /**
   * Check CRM migration status
   */
  async getCRMMigrationStatus(): Promise<any[]> {
    return this.migrationRunner.getMigrationStatus();
  }

  /**
   * Initialize CRM database schema
   */
  async initializeCRM(): Promise<{ success: boolean; results: MigrationResult[]; errors: string[] }> {
    try {
      const results = await this.executeCRMMigrations();
      const errors = results
        .filter((r: any) => r.status === 'failed')
        .map((r: any) => r.error || 'Unknown error');

      const success = errors.length === 0;

      return { success, results, errors };
    } catch (error: any) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        success: false,
        results: [],
        errors: [errorMessage]
      };
    }
  }

  /**
   * Verify CRM schema integrity
   */
  async verifyCRMSchema(): Promise<{ valid: boolean; issues: string[] }> {
    const issues: string[] = [];

    try {
      // Check if core tables exist
      const requiredTables = [
        'companies',
        'contacts',
        'leads',
        'conversations',
        'ai_tasks',
        'lead_activities',
        'email_sequences',
        'email_sequence_steps',
        'lead_scoring_rules',
        'lead_qualification_history',
        'qualification_criteria_templates',
        'meetings',
        'meeting_templates',
        'schedule_negotiations',
        'calendar_providers',
        'voicemails',
        'voicemail_templates',
        'voicemail_campaigns',
        'voicemail_follow_ups',
        'voicemail_analytics'
      ];

      for (const table of requiredTables) {
        try {
          // Validate table name to prevent SQL injection
          if (!/^[a-zA-Z0-9_]+$/.test(table)) {
            issues.push(`Table name '${table}' contains invalid characters`);
            continue;
          }
          // SQLite table names cannot be parameterized, but we've validated the input
          await this.env.DB_MAIN.prepare(`SELECT 1 FROM ${table} LIMIT 1`).first();
        } catch (error: any) {
          issues.push(`Table '${table}' does not exist or is not accessible`);
        }
      }

      // Check if indexes exist (sample check)
      const indexChecks = [
        { table: 'leads', column: 'business_id', name: 'idx_leads_business_status' },
        { table: 'companies', column: 'business_id', name: 'idx_companies_business_domain' },
        { table: 'ai_tasks', column: 'status', name: 'idx_ai_tasks_pending' }
      ];

      for (const check of indexChecks) {
        try {
          const result = await this.env.DB_MAIN
            .prepare(`SELECT name FROM sqlite_master WHERE type='index' AND name = ?`)
            .bind(check.name)
            .first();

          if (!result) {
            issues.push(`Index '${check.name}' is missing`);
          }
        } catch (error: any) {
          issues.push(`Could not verify index '${check.name}': ${error}`);
        }
      }

      return { valid: issues.length === 0, issues };
    } catch (error: any) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return { valid: false, issues: [errorMessage] };
    }
  }

  /**
   * Create sample CRM data for testing
   */
  async createSampleData(businessId: string): Promise<{ success: boolean; error?: string }> {
    try {
      // Sample company
      const companyId = await this.generateId();
      await this.env.DB_MAIN
        .prepare(`
          INSERT INTO companies (id, business_id, name, domain, industry, size_range, ai_icp_score)
          VALUES (?, ?, 'Acme Corporation', 'acme.com', 'Technology', '51-200', 85)
        `)
        .bind(companyId, businessId)
        .run();

      // Sample contact
      const contactId = await this.generateId();
      await this.env.DB_MAIN
        .prepare(`
          INSERT
  INTO contacts (id, business_id, company_id, email, first_name, last_name, title, seniority_level, department)
          VALUES (?, ?, ?, 'john.doe@acme.com', 'John', 'Doe', 'VP of Engineering', 'vp', 'engineering')
        `)
        .bind(contactId, businessId, companyId)
        .run();

      // Sample lead
      const leadId = await this.generateId();
      await this.env.DB_MAIN
        .prepare(`
         
  INSERT INTO leads (id, business_id, contact_id, company_id, source, ai_qualification_score, ai_predicted_value)
          VALUES (?, ?, ?, ?, 'website', 75, 25000.00)
        `)
        .bind(leadId, businessId, contactId, companyId)
        .run();

      // Sample AI task
      const taskId = await this.generateId();
      await this.env.DB_MAIN
        .prepare(`
          INSERT INTO ai_tasks (id, business_id, type, payload, priority)
          VALUES (?, ?, 'research_company', '{"company_id": "' + ? + '", "depth": "basic"}', 3)
        `)
        .bind(taskId, businessId, companyId)
        .run();

      return { success: true };
    } catch (error: any) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return { success: false, error: errorMessage };
    }
  }

  private async createMigrationFile(version: string, name: string, sql: string): Promise<MigrationFile> {
    const checksum = await MigrationRunner.calculateChecksum(sql);
    return {
      version,
      name,
      sql,
      checksum
    };
  }

  private async generateId(): Promise<string> {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  private async getMigration001SQL(): Promise<string> {
    return `
-- Migration: 001_create_crm_tables
-- Description: Create initial CRM tables for AI-native operations

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
  seniority_level TEXT CHECK (seniority_level IN
  ('individual_contributor', 'team_lead', 'manager', 'director', 'vp', 'c_level', 'founder')),
  department TEXT CHECK (department IN ('engineering',
  'sales', 'marketing', 'hr', 'finance', 'operations', 'legal', 'executive', 'other')),
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
  status TEXT DEFAULT 'new' CHECK (status
  IN ('new', 'qualifying', 'qualified', 'meeting_scheduled', 'opportunity', 'unqualified', 'closed_won', 'closed_lost')),
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
    `;
  }

  private async getMigration002SQL(): Promise<string> {
    return `
-- Migration: 002_add_extended_crm_features
-- Description: Add extended CRM features (activities, sequences, scoring)

-- Lead Activities for tracking all interactions
CREATE TABLE lead_activities (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  lead_id TEXT NOT NULL,
  contact_id TEXT,
  type TEXT NOT NULL CHECK (type IN ('call', 'email', 'meeting', 'note', 'demo', 'proposal', 'contract', 'ai_action')),
  description TEXT NOT NULL,
  outcome TEXT CHECK (outcome IN ('positive', 'neutral', 'negative')),
  ai_generated BOOLEAN DEFAULT FALSE,
  metadata TEXT CHECK (json_valid(metadata) OR metadata IS NULL),
  created_by TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (lead_id) REFERENCES leads(id),
  FOREIGN KEY (contact_id) REFERENCES contacts(id)
);

-- Email sequences for AI-driven nurturing
CREATE TABLE email_sequences (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  trigger_type TEXT NOT NULL CHECK (trigger_type IN ('lead_created', 'status_change', 'time_based', 'behavior_based')),
  trigger_conditions TEXT CHECK (json_valid(trigger_conditions) OR trigger_conditions IS NULL),
  is_active BOOLEAN DEFAULT TRUE,
  ai_optimization BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Email sequence steps
CREATE TABLE email_sequence_steps (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  sequence_id TEXT NOT NULL,
  step_order INTEGER NOT NULL,
  delay_hours INTEGER NOT NULL,
  subject_template TEXT NOT NULL,
  body_template TEXT NOT NULL,
  ai_personalization BOOLEAN DEFAULT TRUE,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (sequence_id) REFERENCES email_sequences(id),
  UNIQUE(sequence_id, step_order)
);

-- Lead scoring rules for AI qualification
CREATE TABLE lead_scoring_rules (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  name TEXT NOT NULL,
  category TEXT NOT NULL CHECK (category IN ('demographic', 'firmographic', 'behavioral', 'engagement')),
  condition_field TEXT NOT NULL,
  condition_operator TEXT NOT NULL CHECK
  (condition_operator IN ('equals', 'contains', 'greater_than', 'less_than', 'in', 'not_in')),
  condition_value TEXT NOT NULL,
  score_points INTEGER NOT NULL,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Additional indexes for new tables
CREATE INDEX idx_lead_activities_lead ON lead_activities(lead_id, created_at DESC);
CREATE INDEX idx_lead_activities_type ON lead_activities(business_id, type, created_at DESC);
CREATE INDEX idx_email_sequences_business ON email_sequences(business_id, is_active);
CREATE INDEX idx_email_sequence_steps_sequence ON email_sequence_steps(sequence_id, step_order);
CREATE INDEX idx_lead_scoring_rules_business ON lead_scoring_rules(business_id, is_active);

-- Triggers for updated_at timestamps
CREATE TRIGGER update_email_sequences_updated_at
  AFTER UPDATE ON email_sequences
  BEGIN
    UPDATE email_sequences SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;
    `;
  }

  private async getMigration003SQL(): Promise<string> {
    return `
-- Migration: 003_add_bant_qualification
-- Description: Add BANT qualification fields and tables for advanced lead qualification

-- Add BANT qualification columns to leads table
ALTER TABLE leads ADD COLUMN ai_qualification_data
  TEXT CHECK (json_valid(ai_qualification_data) OR ai_qualification_data IS NULL);
ALTER TABLE leads ADD COLUMN qualification_status TEXT DEFAULT
  'not_started' CHECK (qualification_status IN ('not_started', 'in_progress', 'qualified', 'unqualified', 'needs_review'));
ALTER TABLE leads ADD COLUMN qualification_confidence DECIMAL(3,2)
  CHECK (qualification_confidence >= 0 AND qualification_confidence <= 1);
ALTER TABLE leads ADD COLUMN qualified_at TIMESTAMP;
ALTER TABLE leads ADD COLUMN next_qualification_questions
  TEXT CHECK (json_valid(next_qualification_questions) OR next_qualification_questions IS NULL);

-- Create lead qualification history table
CREATE TABLE lead_qualification_history (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  lead_id TEXT NOT NULL,
  qualification_score INTEGER CHECK (qualification_score >= 0 AND qualification_score <= 100),
  qualification_status TEXT NOT NULL,
  bant_data TEXT CHECK (json_valid(bant_data)),
  ai_insights TEXT CHECK (json_valid(ai_insights) OR ai_insights IS NULL),
  conversation_context TEXT CHECK (json_valid(conversation_context) OR conversation_context IS NULL),
  agent_id TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (lead_id) REFERENCES leads(id)
);

-- Create qualification criteria template table for customizable BANT questions
CREATE TABLE qualification_criteria_templates (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  name TEXT NOT NULL,
  criteria_type TEXT NOT NULL CHECK (criteria_type IN ('budget', 'authority', 'need', 'timeline', 'custom')),
  question_template TEXT NOT NULL,
  is_required BOOLEAN DEFAULT TRUE,
  weight DECIMAL(3,2) DEFAULT 1.0,
  extractor_config TEXT CHECK (json_valid(extractor_config) OR extractor_config IS NULL),
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for new tables and columns
CREATE INDEX idx_leads_qualification_status ON leads(business_id, qualification_status, created_at DESC);
CREATE INDEX idx_leads_qualification_score ON leads(business_id, ai_qualification_score DESC, qualification_status);
CREATE INDEX idx_lead_qualification_history_lead ON lead_qualification_history(lead_id, created_at DESC);
CREATE INDEX idx_lead_qualification_history_business ON lead_qualification_history(business_id, created_at DESC);
CREATE INDEX idx_qualification_criteria_templates_business ON qualification_criteria_templates(business_id, is_active);
CREATE INDEX idx_qualification_criteria_templates_type ON qualification_criteria_templates(business_id, criteria_type, is_active);

-- Insert default BANT qualification criteria templates
INSERT INTO qualification_criteria_templates (business_id, name, criteria_type, question_template, is_required, weight) VALUES
('default', 'Budget Qualification', 'budget', 'To ensure we''re aligned, what budget
  range are you working with for this initiative?', TRUE, 0.3),
('default', 'Authority Assessment', 'authority', 'Are you involved in the
  decision-making process for this type of solution?', TRUE, 0.25),
('default', 'Need Identification', 'need', 'What specific challenges are
  you trying to solve with this solution?', TRUE, 0.25),
('default', 'Timeline Evaluation', 'timeline', 'When are you looking to have a solution in place?', TRUE, 0.2);

-- Triggers for updated_at timestamps
CREATE TRIGGER update_qualification_criteria_templates_updated_at
  AFTER UPDATE ON qualification_criteria_templates
  BEGIN
    UPDATE qualification_criteria_templates SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;

-- Update the existing leads table to include qualification status in status checks
-- Note: This would normally be done with ALTER TABLE but SQLite has limitations
-- The status field already supports the values we need, so no change required
    `;
  }

  private async getMigration004SQL(): Promise<string> {
    return `
-- Migration: 004_add_meeting_management
-- Description: Add comprehensive meeting management and booking capabilities

-- Meetings table for storing all meeting information
CREATE TABLE meetings (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  lead_id TEXT NOT NULL,
  contact_id TEXT,
  title TEXT NOT NULL,
  description TEXT,
  meeting_type TEXT NOT NULL CHECK (meeting_type IN
  ('discovery_call', 'demo', 'consultation', 'follow_up', 'closing_call', 'technical_review', 'onboarding', 'check_in', 'custom')),
  status TEXT DEFAULT 'scheduled' CHECK (status
  IN ('scheduled', 'confirmed', 'in_progress', 'completed', 'cancelled', 'no_show', 'rescheduled')),
  scheduled_start TIMESTAMP NOT NULL,
  scheduled_end TIMESTAMP NOT NULL,
  timezone TEXT NOT NULL,
  location TEXT,
  meeting_url TEXT,
  calendar_event_id TEXT,
  attendees TEXT CHECK (json_valid(attendees)),
  agenda TEXT,
  ai_generated_agenda BOOLEAN DEFAULT FALSE,
  booking_source TEXT NOT NULL CHECK
  (booking_source IN ('ai_conversation', 'manual_booking', 'calendar_link', 'email_reply', 'website_form', 'phone_call')),
  booking_method TEXT NOT NULL
  CHECK (booking_method IN ('ai_negotiated', 'instant_booking', 'manual_confirmation', 'calendar_integration')),
  confirmation_sent BOOLEAN DEFAULT FALSE,
  reminder_sent BOOLEAN DEFAULT FALSE,
  no_show BOOLEAN DEFAULT FALSE,
  cancelled_at TIMESTAMP,
  cancellation_reason TEXT,
  rescheduled_from TEXT, -- Reference to previous meeting ID
  notes TEXT,
  outcome TEXT CHECK (outcome IN
  ('qualified', 'needs_follow_up', 'closed_won', 'closed_lost', 'rescheduled', 'no_show', 'cancelled')),
  follow_up_actions TEXT CHECK (json_valid(follow_up_actions) OR follow_up_actions IS NULL),
  recording_url TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (lead_id) REFERENCES leads(id),
  FOREIGN KEY (contact_id) REFERENCES contacts(id)
);

-- Meeting templates for standardized meeting types
CREATE TABLE meeting_templates (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  name TEXT NOT NULL,
  meeting_type TEXT NOT NULL CHECK (meeting_type IN
  ('discovery_call', 'demo', 'consultation', 'follow_up', 'closing_call', 'technical_review', 'onboarding', 'check_in', 'custom')),
  duration_minutes INTEGER NOT NULL,
  description_template TEXT NOT NULL,
  agenda_template TEXT,
  location_type TEXT NOT NULL CHECK (location_type IN ('virtual', 'in_person', 'phone')),
  default_location TEXT,
  auto_generate_meeting_url BOOLEAN DEFAULT TRUE,
  buffer_time_before INTEGER, -- minutes
  buffer_time_after INTEGER, -- minutes
  advance_notice_hours INTEGER DEFAULT 24,
  max_days_in_advance INTEGER DEFAULT 30,
  working_hours TEXT CHECK (json_valid(working_hours)), -- JSON: {start: "09:00", end: "17:00", days: [1,2,3,4,5]}
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Schedule negotiations for AI-powered meeting booking
CREATE TABLE schedule_negotiations (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  lead_id TEXT NOT NULL,
  conversation_id TEXT,
  proposed_slots TEXT CHECK (json_valid(proposed_slots)), -- JSON array of CalendarSlot objects
  lead_preferences TEXT CHECK (json_valid(lead_preferences) OR lead_preferences IS NULL),
  negotiation_rounds TEXT CHECK (json_valid(negotiation_rounds)), -- JSON array of NegotiationRound objects
  final_agreed_slot TEXT CHECK (json_valid(final_agreed_slot) OR final_agreed_slot IS NULL),
  status TEXT DEFAULT 'in_progress' CHECK (status IN ('in_progress', 'agreed', 'failed', 'expired', 'cancelled')),
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (lead_id) REFERENCES leads(id),
  FOREIGN KEY (conversation_id) REFERENCES conversations(id)
);

-- Calendar providers for external calendar integration
CREATE TABLE calendar_providers (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  user_id TEXT NOT NULL, -- Reference to user/rep who owns this calendar
  provider_type TEXT NOT NULL CHECK (provider_type IN ('google', 'outlook', 'caldav', 'exchange')),
  calendar_id TEXT,
  access_token TEXT, -- Encrypted in real implementation
  refresh_token TEXT, -- Encrypted in real implementation
  webhook_url TEXT,
  sync_enabled BOOLEAN DEFAULT TRUE,
  last_sync TIMESTAMP,
  sync_status TEXT DEFAULT 'active' CHECK (sync_status IN ('active', 'error', 'disabled')),
  sync_error TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(business_id, user_id, provider_type)
);

-- Meeting attendee tracking (separate table for better querying)
CREATE TABLE meeting_attendees (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  meeting_id TEXT NOT NULL,
  email TEXT NOT NULL,
  name TEXT,
  role TEXT NOT NULL CHECK (role IN ('host', 'lead', 'sales_rep', 'technical_contact', 'decision_maker', 'observer')),
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'declined', 'tentative', 'no_response')),
  optional BOOLEAN DEFAULT FALSE,
  response_time TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (meeting_id) REFERENCES meetings(id)
);

-- Meeting reminders tracking
CREATE TABLE meeting_reminders (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  meeting_id TEXT NOT NULL,
  reminder_type TEXT NOT NULL CHECK (reminder_type IN ('confirmation', 'reminder_24h', 'reminder_1h', 'reminder_15m')),
  scheduled_at TIMESTAMP NOT NULL,
  sent_at TIMESTAMP,
  delivery_status TEXT DEFAULT 'pending' CHECK (delivery_status IN ('pending', 'sent', 'delivered', 'failed')),
  delivery_error TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (meeting_id) REFERENCES meetings(id)
);

-- Create indexes for performance
CREATE INDEX idx_meetings_business_lead ON meetings(business_id, lead_id, scheduled_start DESC);
CREATE INDEX idx_meetings_status ON meetings(business_id, status, scheduled_start);
CREATE INDEX idx_meetings_scheduled_start ON meetings(scheduled_start);
CREATE INDEX idx_meetings_booking_source ON meetings(business_id, booking_source, created_at DESC);
CREATE INDEX idx_meetings_calendar_event ON meetings(calendar_event_id);

CREATE INDEX idx_meeting_templates_business ON meeting_templates(business_id, is_active);
CREATE INDEX idx_meeting_templates_type ON meeting_templates(business_id, meeting_type, is_active);

CREATE INDEX idx_schedule_negotiations_lead ON schedule_negotiations(lead_id, status, created_at DESC);
CREATE INDEX idx_schedule_negotiations_status ON schedule_negotiations(business_id, status, expires_at);

CREATE INDEX idx_calendar_providers_user ON calendar_providers(business_id, user_id, sync_enabled);
CREATE INDEX idx_calendar_providers_sync ON calendar_providers(sync_enabled, last_sync);

CREATE INDEX idx_meeting_attendees_meeting ON meeting_attendees(meeting_id, role);
CREATE INDEX idx_meeting_attendees_email ON meeting_attendees(email, status);

CREATE INDEX idx_meeting_reminders_meeting ON meeting_reminders(meeting_id, reminder_type);
CREATE INDEX idx_meeting_reminders_scheduled ON meeting_reminders(scheduled_at, delivery_status);

-- Insert default meeting templates
INSERT INTO meeting_templates (business_id, name, meeting_type,
  duration_minutes, description_template, agenda_template, location_type, working_hours) VALUES
('default', 'Discovery Call', 'discovery_call', 30, 'Initial discovery call with {lead_first_name} {lead_last_name} from {company_name}', '1.
  Introductions\n2. Understanding current challenges\n3. Discussing requirements\n4. Next steps', 'virtual', '{"start": "09:00", "end": "17:00", "days": [1,2,3,4,5]}'),
('default', 'Product Demo', 'demo', 45, 'Product demonstration for {lead_first_name} {lead_last_name}', '1. Brief introduction\n2. Live
  product demonstration\n3. Q&A session\n4. Pricing discussion\n5. Next steps', 'virtual', '{"start": "09:00", "end": "17:00", "days": [1,2,3,4,5]}'),
('default', 'Consultation', 'consultation', 60, 'Business consultation with {lead_first_name} {lead_last_name}', '1. Current state analysis\n2. Requirements gathering\n3.
  Solution recommendations\n4. Implementation roadmap\n5. Pricing and next steps', 'virtual', '{"start": "09:00", "end": "17:00", "days": [1,2,3,4,5]}'),
('default', 'Follow-up Call', 'follow_up', 15, 'Follow-up call with {lead_first_name} {lead_last_name}', '1. Recap previous
  discussion\n2. Address any questions\n3. Confirm next steps', 'virtual', '{"start": "09:00", "end": "17:00", "days": [1,2,3,4,5]}');

-- Triggers for updated_at timestamps
CREATE TRIGGER update_meetings_updated_at
  AFTER UPDATE ON meetings
  BEGIN
    UPDATE meetings SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;

CREATE TRIGGER update_meeting_templates_updated_at
  AFTER UPDATE ON meeting_templates
  BEGIN
    UPDATE meeting_templates SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;

CREATE TRIGGER update_schedule_negotiations_updated_at
  AFTER UPDATE ON schedule_negotiations
  BEGIN
    UPDATE schedule_negotiations SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;

CREATE TRIGGER update_calendar_providers_updated_at
  AFTER UPDATE ON calendar_providers
  BEGIN
    UPDATE calendar_providers SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;
    `;
  }

  private async getMigration005SQL(): Promise<string> {
    return `
-- Migration: 005_add_voicemail_management
-- Description: Add comprehensive voicemail handling and tracking

-- Voicemails table for tracking all voicemail messages
CREATE TABLE voicemails (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  lead_id TEXT NOT NULL,
  contact_id TEXT,
  call_id TEXT,
  attempt_number INTEGER NOT NULL,
  voicemail_type TEXT NOT NULL CHECK (voicemail_type IN
  ('initial_outreach', 'follow_up', 'appointment_reminder', 'missed_meeting', 'proposal_follow_up', 'nurture', 'win_back', 'thank_you', 'urgent', 'custom')),
  message_text TEXT NOT NULL,
  message_duration_seconds INTEGER NOT NULL,
  audio_url TEXT,
  transcription TEXT,
  ai_generated BOOLEAN DEFAULT TRUE,
  personalization_level TEXT CHECK (personalization_level
  IN ('generic', 'basic', 'moderate', 'high', 'hyper_personalized')),
  voice_settings TEXT CHECK (json_valid(voice_settings)),
  delivery_status TEXT DEFAULT 'pending' CHECK
  (delivery_status IN ('pending', 'delivered', 'failed', 'partial', 'voicemail_full', 'no_voicemail_detected')),
  delivered_at TIMESTAMP,
  listened BOOLEAN DEFAULT FALSE,
  listened_at TIMESTAMP,
  response_received BOOLEAN DEFAULT FALSE,
  response_type TEXT CHECK (response_type
  IN ('callback', 'email_reply', 'text_reply', 'meeting_booked', 'unsubscribe', 'not_interested')),
  response_timestamp TIMESTAMP,
  follow_up_scheduled BOOLEAN DEFAULT FALSE,
  follow_up_time TIMESTAMP,
  sentiment_score DECIMAL(3,2) CHECK (sentiment_score >= 0 AND sentiment_score <= 1),
  effectiveness_score DECIMAL(3,2) CHECK (effectiveness_score >= 0 AND effectiveness_score <= 1),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (lead_id) REFERENCES leads(id),
  FOREIGN KEY (contact_id) REFERENCES contacts(id)
);

-- Voicemail templates for standardized messages
CREATE TABLE voicemail_templates (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  name TEXT NOT NULL,
  voicemail_type TEXT NOT NULL CHECK (voicemail_type IN
  ('initial_outreach', 'follow_up', 'appointment_reminder', 'missed_meeting', 'proposal_follow_up', 'nurture', 'win_back', 'thank_you', 'urgent', 'custom')),
  attempt_range_min INTEGER NOT NULL,
  attempt_range_max INTEGER NOT NULL,
  message_template TEXT NOT NULL,
  personalization_fields TEXT CHECK (json_valid(personalization_fields)), -- JSON array
  voice_settings TEXT CHECK (json_valid(voice_settings)),
  call_to_action TEXT,
  urgency_level TEXT CHECK (urgency_level IN ('low', 'medium', 'high', 'critical')),
  max_duration_seconds INTEGER NOT NULL,
  follow_up_delay_hours INTEGER NOT NULL,
  is_active BOOLEAN DEFAULT TRUE,
  success_rate DECIMAL(3,2) CHECK (success_rate >= 0 AND success_rate <= 1),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Voicemail campaigns for bulk operations
CREATE TABLE voicemail_campaigns (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  target_segment TEXT,
  campaign_type TEXT CHECK (campaign_type
  IN ('cold_outreach', 'lead_nurture', 're_engagement', 'event_promotion', 'product_launch', 'follow_up_sequence')),
  status TEXT DEFAULT 'draft' CHECK (status IN ('draft', 'scheduled', 'active', 'paused', 'completed', 'cancelled')),
  templates TEXT CHECK (json_valid(templates)), -- JSON array of template IDs
  schedule TEXT CHECK (json_valid(schedule)), -- JSON object with schedule details
  ai_optimization BOOLEAN DEFAULT TRUE,
  performance_metrics TEXT CHECK (json_valid(performance_metrics) OR performance_metrics IS NULL),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Voicemail follow-ups for tracking next actions
CREATE TABLE voicemail_follow_ups (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  voicemail_id TEXT NOT NULL,
  lead_id TEXT NOT NULL,
  follow_up_type TEXT NOT NULL CHECK
  (follow_up_type IN ('call_attempt', 'email', 'sms', 'voicemail', 'social_media', 'direct_mail')),
  scheduled_time TIMESTAMP NOT NULL,
  actual_time TIMESTAMP,
  status TEXT DEFAULT 'scheduled' CHECK (status IN ('scheduled', 'in_progress', 'completed', 'failed', 'cancelled')),
  method TEXT CHECK (method IN ('email', 'phone', 'linkedin', 'sms')),
  message TEXT,
  outcome TEXT CHECK (outcome IN
  ('connected', 'voicemail_left', 'no_answer', 'email_sent', 'sms_sent', 'meeting_scheduled', 'not_interested', 'wrong_number')),
  next_action TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (voicemail_id) REFERENCES voicemails(id),
  FOREIGN KEY (lead_id) REFERENCES leads(id)
);

-- Voicemail analytics for tracking effectiveness
CREATE TABLE voicemail_analytics (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  voicemail_id TEXT NOT NULL,
  lead_id TEXT NOT NULL,
  call_duration_before_voicemail INTEGER,
  ring_duration INTEGER,
  voicemail_prompt_detected BOOLEAN DEFAULT FALSE,
  beep_detected BOOLEAN DEFAULT FALSE,
  message_clarity_score DECIMAL(3,2) CHECK (message_clarity_score >= 0 AND message_clarity_score <= 1),
  background_noise_level DECIMAL(3,2) CHECK (background_noise_level >= 0 AND background_noise_level <= 1),
  delivery_confidence DECIMAL(3,2) CHECK (delivery_confidence >= 0 AND delivery_confidence <= 1),
  ai_insights TEXT CHECK (json_valid(ai_insights) OR ai_insights IS NULL),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (voicemail_id) REFERENCES voicemails(id),
  FOREIGN KEY (lead_id) REFERENCES leads(id),
  UNIQUE(voicemail_id)
);

-- Create indexes for performance
CREATE INDEX idx_voicemails_lead ON voicemails(lead_id, created_at DESC);
CREATE INDEX idx_voicemails_business ON voicemails(business_id, voicemail_type, created_at DESC);
CREATE INDEX idx_voicemails_delivery ON voicemails(delivery_status, follow_up_scheduled);
CREATE INDEX idx_voicemails_response ON voicemails(response_received, response_type);
CREATE INDEX idx_voicemails_attempt ON voicemails(lead_id, attempt_number);

CREATE INDEX idx_voicemail_templates_business ON voicemail_templates(business_id, is_active);
CREATE INDEX idx_voicemail_templates_type ON voicemail_templates(voicemail_type, attempt_range_min, attempt_range_max);

CREATE INDEX idx_voicemail_campaigns_business ON voicemail_campaigns(business_id, status);
CREATE INDEX idx_voicemail_campaigns_status ON voicemail_campaigns(status, campaign_type);

CREATE INDEX idx_voicemail_follow_ups_voicemail ON voicemail_follow_ups(voicemail_id, status);
CREATE INDEX idx_voicemail_follow_ups_scheduled ON voicemail_follow_ups(scheduled_time, status);
CREATE INDEX idx_voicemail_follow_ups_lead ON voicemail_follow_ups(lead_id, follow_up_type, status);

CREATE INDEX idx_voicemail_analytics_voicemail ON voicemail_analytics(voicemail_id);
CREATE INDEX idx_voicemail_analytics_lead ON voicemail_analytics(lead_id, created_at DESC);

-- Insert default voicemail templates
INSERT INTO voicemail_templates (business_id, name, voicemail_type, attempt_range_min,
  attempt_range_max, message_template, voice_settings, urgency_level, max_duration_seconds, follow_up_delay_hours) VALUES
('default', 'Initial Outreach', 'initial_outreach', 1, 1, 'Hi {lead_name}, this is {rep_name} from {company}. I noticed {trigger_event} and wanted to discuss how we
  can help {company_name} with {value_proposition}. Please call me back at {callback_number}.', '{"voice": "professional_female", "pace": "moderate", "emotion": "friendly", "language": "en-US"}', 'medium', 30, 48),
('default', 'Second Attempt', 'follow_up', 2, 2, 'Hi {lead_name}, {rep_name} again. Following up on my previous message about {topic}. We have helped similar companies
  achieve {benefit}. I would love to share how. Call me at {callback_number}.', '{"voice": "professional_male", "pace": "moderate", "emotion": "professional", "language": "en-US"}', 'medium', 25, 72),
('default', 'Third Attempt', 'follow_up', 3, 3, '{lead_name}, I know you are busy. This is my last attempt for now. If {solution} is not
  a priority, just let me know. Otherwise, I would love to help. {callback_number}', '{"voice": "conversational", "pace": "moderate", "emotion": "empathetic", "language": "en-US"}', 'low', 20, 120),
('default', 'Meeting Reminder', 'appointment_reminder', 1, 99, 'Hi {lead_name}, just a reminder about our {meeting_type} scheduled for {meeting_time}. Looking
  forward to discussing {topic}. See you soon!', '{"voice": "friendly_female", "pace": "normal", "emotion": "warm", "language": "en-US"}', 'medium', 15, 24);

-- Triggers for updated_at timestamps
CREATE TRIGGER update_voicemails_updated_at
  AFTER UPDATE ON voicemails
  BEGIN
    UPDATE voicemails SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;

CREATE TRIGGER update_voicemail_templates_updated_at
  AFTER UPDATE ON voicemail_templates
  BEGIN
    UPDATE voicemail_templates SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;

CREATE TRIGGER update_voicemail_campaigns_updated_at
  AFTER UPDATE ON voicemail_campaigns
  BEGIN
    UPDATE voicemail_campaigns SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;

CREATE TRIGGER update_voicemail_follow_ups_updated_at
  AFTER UPDATE ON voicemail_follow_ups
  BEGIN
    UPDATE voicemail_follow_ups SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;
    `;
  }
}