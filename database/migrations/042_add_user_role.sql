-- Migration: 042_add_user_role
-- Description: Add role column to users table for admin access control
-- Created: 2025-01-17

-- Add role column to users table
ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user' CHECK (role IN ('user', 'admin', 'sales_rep', 'sales_manager', 'executive', 'ops', 'customer_success', 'marketing'));

-- Create index for faster role-based queries
CREATE INDEX idx_users_role ON users(role);

-- Update existing users to have default 'user' role
UPDATE users SET role = 'user' WHERE role IS NULL;
