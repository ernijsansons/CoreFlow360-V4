-- Migration: 001_core_tenant_users
-- Description: Core multi-tenant structure with businesses and users
-- Created: 2024-12-01
-- Author: CoreFlow360 V4

-- Businesses (Tenants) table
CREATE TABLE IF NOT EXISTS businesses (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    name TEXT NOT NULL,
    legal_name TEXT,
    registration_number TEXT,
    tax_id TEXT,
    industry TEXT,
    size TEXT CHECK (size IN ('micro', 'small', 'medium', 'large', 'enterprise')),

    -- Contact Information
    email TEXT NOT NULL UNIQUE,
    phone TEXT,
    website TEXT,

    -- Address
    address_line1 TEXT,
    address_line2 TEXT,
    city TEXT,
    state_province TEXT,
    postal_code TEXT,
    country TEXT DEFAULT 'US',
    timezone TEXT DEFAULT 'UTC',

    -- Business Settings
    currency TEXT DEFAULT 'USD',
    fiscal_year_start INTEGER DEFAULT 1 CHECK (fiscal_year_start >= 1 AND fiscal_year_start <= 12),
    date_format TEXT DEFAULT 'YYYY-MM-DD',

    -- Subscription & Billing
    subscription_tier TEXT DEFAULT 'trial' CHECK (subscription_tier IN ('trial', 'starter', 'professional', 'enterprise')),
    subscription_status TEXT DEFAULT 'active' CHECK (subscription_status IN ('active', 'suspended', 'cancelled', 'expired')),
    subscription_expires_at TEXT,
    billing_email TEXT,

    -- Status & Metadata
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended', 'deleted')),
    settings TEXT DEFAULT '{}', -- JSON settings
    metadata TEXT DEFAULT '{}', -- JSON metadata

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    deleted_at TEXT,

    -- Constraints
    CHECK (deleted_at IS NULL OR status = 'deleted')
);

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    email TEXT NOT NULL UNIQUE,
    username TEXT UNIQUE,
    password_hash TEXT NOT NULL,

    -- Personal Information
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    display_name TEXT,
    avatar_url TEXT,
    phone TEXT,

    -- Authentication & Security
    email_verified INTEGER DEFAULT 0,
    email_verified_at TEXT,
    two_factor_enabled INTEGER DEFAULT 0,
    two_factor_secret TEXT,
    password_reset_token TEXT,
    password_reset_expires TEXT,
    last_login_at TEXT,
    last_login_ip TEXT,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TEXT,

    -- User Settings
    language TEXT DEFAULT 'en',
    timezone TEXT DEFAULT 'UTC',
    date_format TEXT DEFAULT 'YYYY-MM-DD',
    notification_preferences TEXT DEFAULT '{}', -- JSON
    ui_preferences TEXT DEFAULT '{}', -- JSON

    -- Status & Metadata
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended', 'deleted')),
    metadata TEXT DEFAULT '{}', -- JSON metadata

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    deleted_at TEXT,

    -- Constraints
    CHECK (email LIKE '%@%.%'),
    CHECK (deleted_at IS NULL OR status = 'deleted'),
    CHECK (failed_login_attempts >= 0)
);

-- Business Memberships (Users <-> Businesses relationship)
CREATE TABLE IF NOT EXISTS business_memberships (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    user_id TEXT NOT NULL,

    -- Primary Role
    role TEXT NOT NULL CHECK (role IN ('owner', 'director', 'manager', 'employee', 'viewer')),

    -- Employment Information
    employee_id TEXT,
    job_title TEXT,
    department TEXT,
    reports_to_user_id TEXT,

    -- Access Control
    is_primary INTEGER DEFAULT 0, -- Primary business for this user
    can_approve_transactions INTEGER DEFAULT 0,
    spending_limit REAL DEFAULT 0,

    -- Status
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended', 'pending')),
    invited_by_user_id TEXT,
    invitation_token TEXT,
    invitation_expires_at TEXT,
    joined_at TEXT,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    deleted_at TEXT,

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (reports_to_user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (invited_by_user_id) REFERENCES users(id) ON DELETE SET NULL,

    -- Constraints
    UNIQUE(business_id, user_id),
    CHECK (deleted_at IS NULL OR status = 'inactive')
);

-- User Sessions table
CREATE TABLE IF NOT EXISTS user_sessions (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    user_id TEXT NOT NULL,
    business_id TEXT,

    -- Session Data
    token TEXT NOT NULL UNIQUE,
    refresh_token TEXT UNIQUE,

    -- Device & Location
    ip_address TEXT,
    user_agent TEXT,
    device_type TEXT,
    device_name TEXT,

    -- Session Metadata
    last_activity_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    revoked_reason TEXT,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,

    -- Constraints
    CHECK (expires_at > created_at)
);

-- API Keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    created_by_user_id TEXT NOT NULL,

    -- Key Information
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL, -- First 8 chars for identification

    -- Permissions
    permissions TEXT DEFAULT '[]', -- JSON array of permissions
    rate_limit INTEGER DEFAULT 1000, -- Requests per hour

    -- Usage Tracking
    last_used_at TEXT,
    last_used_ip TEXT,
    usage_count INTEGER DEFAULT 0,

    -- Status
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'expired', 'revoked')),
    expires_at TEXT,
    revoked_at TEXT,
    revoked_by_user_id TEXT,
    revoked_reason TEXT,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (revoked_by_user_id) REFERENCES users(id) ON DELETE SET NULL,

    -- Constraints
    CHECK (expires_at IS NULL OR expires_at > created_at)
);

-- Create indexes for core tables
CREATE INDEX idx_businesses_email ON businesses(email);
CREATE INDEX idx_businesses_status ON businesses(status) WHERE status != 'deleted';
CREATE INDEX idx_businesses_subscription ON businesses(subscription_status, subscription_expires_at);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_status ON users(status) WHERE status != 'deleted';

CREATE INDEX idx_business_memberships_business ON business_memberships(business_id, status);
CREATE INDEX idx_business_memberships_user ON business_memberships(user_id, status);
CREATE INDEX idx_business_memberships_role ON business_memberships(business_id, role) WHERE status = 'active';
CREATE INDEX idx_business_memberships_primary ON business_memberships(user_id, is_primary) WHERE is_primary = 1;

CREATE INDEX idx_user_sessions_user ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_token ON user_sessions(token);
CREATE INDEX idx_user_sessions_expires ON user_sessions(expires_at) WHERE revoked_at IS NULL;

CREATE INDEX idx_api_keys_business ON api_keys(business_id, status);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX idx_api_keys_expires ON api_keys(expires_at) WHERE status = 'active';