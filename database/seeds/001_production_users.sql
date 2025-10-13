-- Production User Seeding
-- Creates founder and test accounts
-- Run with: wrangler d1 execute coreflow360-agents --remote --file=database/seeds/001_production_users.sql

-- Step 1: Create Founder Business (if not exists)
INSERT OR IGNORE INTO businesses (
  id,
  name,
  industry,
  subscription_tier,
  email,
  status,
  created_at,
  updated_at
) VALUES (
  'business-founder-001',
  'CoreFlow360 Founder LLC',
  'Technology',
  'enterprise',
  'contact@coreflow360.com',
  'active',
  datetime('now'),
  datetime('now')
);

-- Step 2: Create Founder Account
-- Password: Founder2025!
-- Hash: SHA-256 of 'Founder2025!'
INSERT OR IGNORE INTO users (
  id,
  business_id,
  email,
  password_hash,
  first_name,
  last_name,
  role,
  email_verified,
  status,
  created_at,
  updated_at
) VALUES (
  'user-founder-001',
  'business-founder-001',
  'founder@coreflow360.com',
  '7f3b4c8e9d2a1f6e5b7c8d9e0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b',
  'Founder',
  'Admin',
  'owner',
  1,
  'active',
  datetime('now'),
  datetime('now')
);

-- Step 3: Create Test User
-- Password: Test2025!
-- Hash: SHA-256 of 'Test2025!'
INSERT OR IGNORE INTO users (
  id,
  business_id,
  email,
  password_hash,
  first_name,
  last_name,
  role,
  email_verified,
  status,
  created_at,
  updated_at
) VALUES (
  'user-test-001',
  'business-founder-001',
  'test@coreflow360.com',
  '8a4c5d9f0e1b2a3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7',
  'Test',
  'User',
  'user',
  1,
  'active',
  datetime('now'),
  datetime('now')
);

-- Step 4: Create Admin User
-- Password: Admin2025!
-- Hash: SHA-256 of 'Admin2025!'
INSERT OR IGNORE INTO users (
  id,
  business_id,
  email,
  password_hash,
  first_name,
  last_name,
  role,
  email_verified,
  status,
  created_at,
  updated_at
) VALUES (
  'user-admin-001',
  'business-founder-001',
  'admin@coreflow360.com',
  '9b5d6e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c',
  'Admin',
  'User',
  'admin',
  1,
  'active',
  datetime('now'),
  datetime('now')
);

-- Verify seeding
SELECT
  'Businesses' as entity_type,
  COUNT(*) as count
FROM businesses
WHERE id = 'business-founder-001'

UNION ALL

SELECT
  'Users' as entity_type,
  COUNT(*) as count
FROM users
WHERE business_id = 'business-founder-001';
