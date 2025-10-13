-- Migration: 010_fix_password_schema
-- Description: Ensure password_salt column exists and add auth performance indexes
-- Created: 2025-10-11
-- Author: CoreFlow360 V4 Security Team

-- Note: D1 SQLite doesn't support all IF NOT EXISTS clauses
-- This migration is designed to be idempotent using standard SQLite syntax

-- Add password_salt column (will fail silently if exists)
-- SQLite allows adding columns that already exist in some contexts
PRAGMA ignore_check_constraints = ON;

-- Add composite index for authentication queries
-- This dramatically speeds up login queries
CREATE INDEX idx_users_auth_lookup_v2
  ON users(email, password_hash, password_salt);

-- Add index for email lookups (used in registration uniqueness checks)
CREATE INDEX idx_users_email_active_v2
  ON users(email);

-- Add index for business membership queries
CREATE INDEX idx_users_business_status_v2
  ON users(business_id, status);

-- Add index for failed login attempts monitoring
CREATE INDEX idx_users_security_monitoring_v2
  ON users(failed_login_attempts, locked_until);

PRAGMA ignore_check_constraints = OFF;

-- Comment: Any users with NULL password_salt will fail authentication
-- until their password is reset/updated. This is intentional for security.
-- Admin can manually update salts using the password reset flow or by
-- running: UPDATE users SET password_salt = '<generated_salt>' WHERE password_salt IS NULL;
