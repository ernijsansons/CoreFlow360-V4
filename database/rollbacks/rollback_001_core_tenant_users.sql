-- Rollback: 001_core_tenant_users
-- Description: Rollback core multi-tenant structure
-- Created: 2024-12-01
-- Author: CoreFlow360 V4

-- Drop indexes first
DROP INDEX IF EXISTS idx_api_keys_expires;
DROP INDEX IF EXISTS idx_api_keys_prefix;
DROP INDEX IF EXISTS idx_api_keys_business;
DROP INDEX IF EXISTS idx_user_sessions_expires;
DROP INDEX IF EXISTS idx_user_sessions_token;
DROP INDEX IF EXISTS idx_user_sessions_user;
DROP INDEX IF EXISTS idx_business_memberships_primary;
DROP INDEX IF EXISTS idx_business_memberships_role;
DROP INDEX IF EXISTS idx_business_memberships_user;
DROP INDEX IF EXISTS idx_business_memberships_business;
DROP INDEX IF EXISTS idx_users_status;
DROP INDEX IF EXISTS idx_users_username;
DROP INDEX IF EXISTS idx_users_email;
DROP INDEX IF EXISTS idx_businesses_subscription;
DROP INDEX IF EXISTS idx_businesses_status;
DROP INDEX IF EXISTS idx_businesses_email;

-- Drop tables in reverse dependency order
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS business_memberships;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS businesses;

-- Update migration tracking
DELETE FROM schema_migrations WHERE version = '001';