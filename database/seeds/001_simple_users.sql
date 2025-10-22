-- Simple Production User Seeding
-- Minimal fields approach

-- Create a simple business
INSERT OR IGNORE INTO businesses (id, name, slug)
VALUES ('biz001', 'CoreFlow360 Founder', 'coreflow360-founder');

-- Create founder account
-- Password will need to be hashed properly by the backend
INSERT OR IGNORE INTO users (
  id, business_id, email, password_hash,
  first_name, last_name, role, email_verified
) VALUES (
  'usr001',
  'biz001',
  'founder@coreflow360.com',
  'e0ff9a8c2c9b7e0d6c5f4b3a2d1e0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3',
  'Founder',
  'Admin',
  'owner',
  1
);

-- Verify
SELECT 'Created users:' as message, COUNT(*) as count FROM users WHERE business_id = 'biz001';
