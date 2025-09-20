-- Rollback: 002_rbac_departments
-- Description: Rollback RBAC and department management
-- Created: 2024-12-01
-- Author: CoreFlow360 V4

-- Drop indexes first
DROP INDEX IF EXISTS idx_acl_business_resource;
DROP INDEX IF EXISTS idx_acl_principal;
DROP INDEX IF EXISTS idx_acl_resource;
DROP INDEX IF EXISTS idx_role_hierarchies_child;
DROP INDEX IF EXISTS idx_role_hierarchies_parent;
DROP INDEX IF EXISTS idx_role_hierarchies_business;
DROP INDEX IF EXISTS idx_user_permissions_key;
DROP INDEX IF EXISTS idx_user_permissions_resource;
DROP INDEX IF EXISTS idx_user_permissions_business_user;
DROP INDEX IF EXISTS idx_user_permissions_user;
DROP INDEX IF EXISTS idx_permission_templates_type;
DROP INDEX IF EXISTS idx_permission_templates_business;
DROP INDEX IF EXISTS idx_department_roles_business_user;
DROP INDEX IF EXISTS idx_department_roles_user;
DROP INDEX IF EXISTS idx_department_roles_department;
DROP INDEX IF EXISTS idx_departments_head;
DROP INDEX IF EXISTS idx_departments_parent;
DROP INDEX IF EXISTS idx_departments_type;
DROP INDEX IF EXISTS idx_departments_business;

-- Drop tables in reverse dependency order
DROP TABLE IF EXISTS access_control_lists;
DROP TABLE IF EXISTS role_hierarchies;
DROP TABLE IF EXISTS user_permissions;
DROP TABLE IF EXISTS permission_templates;
DROP TABLE IF EXISTS department_roles;
DROP TABLE IF EXISTS departments;

-- Update migration tracking
DELETE FROM schema_migrations WHERE version = '002';