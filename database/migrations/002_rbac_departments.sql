-- Migration: 002_rbac_departments
-- Description: Role-based access control and department management
-- Created: 2024-12-01
-- Author: CoreFlow360 V4

-- Departments table
CREATE TABLE IF NOT EXISTS departments (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Department Information
    code TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    parent_department_id TEXT,
    department_head_user_id TEXT,

    -- Department Type
    type TEXT NOT NULL CHECK (type IN (
        'executive',
        'finance',
        'accounting',
        'hr',
        'operations',
        'sales',
        'marketing',
        'procurement',
        'it',
        'legal',
        'compliance',
        'customer_service',
        'warehouse',
        'production',
        'quality',
        'research',
        'other'
    )),

    -- Budget & Cost Center
    cost_center_code TEXT,
    annual_budget REAL DEFAULT 0,
    budget_used REAL DEFAULT 0,
    budget_year INTEGER,

    -- Status
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'deleted')),

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    deleted_at TEXT,

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (parent_department_id) REFERENCES departments(id) ON DELETE SET NULL,
    FOREIGN KEY (department_head_user_id) REFERENCES users(id) ON DELETE SET NULL,

    -- Constraints
    UNIQUE(business_id, code),
    CHECK (deleted_at IS NULL OR status = 'deleted')
);

-- Department Roles table
CREATE TABLE IF NOT EXISTS department_roles (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    department_id TEXT NOT NULL,
    user_id TEXT NOT NULL,

    -- Role Information
    role_type TEXT NOT NULL CHECK (role_type IN (
        'head',
        'manager',
        'supervisor',
        'lead',
        'senior',
        'member',
        'junior',
        'intern'
    )),

    -- Specific Department Permissions
    can_approve_budget INTEGER DEFAULT 0,
    can_manage_members INTEGER DEFAULT 0,
    can_view_reports INTEGER DEFAULT 0,
    can_create_requests INTEGER DEFAULT 1,
    approval_limit REAL DEFAULT 0,

    -- Assignment
    assigned_by_user_id TEXT,
    assignment_reason TEXT,

    -- Status
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
    effective_from TEXT DEFAULT (datetime('now')),
    effective_until TEXT,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (department_id) REFERENCES departments(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_by_user_id) REFERENCES users(id) ON DELETE SET NULL,

    -- Constraints
    UNIQUE(department_id, user_id, role_type),
    CHECK (effective_until IS NULL OR effective_until > effective_from)
);

-- Permission Templates table
CREATE TABLE IF NOT EXISTS permission_templates (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Template Information
    name TEXT NOT NULL,
    description TEXT,
    template_type TEXT NOT NULL CHECK (template_type IN ('role', 'department', 'custom')),
    applies_to TEXT, -- 'owner', 'director', 'manager', etc.

    -- Permissions (JSON arrays)
    permissions TEXT NOT NULL DEFAULT '{}', -- JSON object with permission categories

    -- Module-specific permissions
    finance_permissions TEXT DEFAULT '[]',
    hr_permissions TEXT DEFAULT '[]',
    operations_permissions TEXT DEFAULT '[]',
    sales_permissions TEXT DEFAULT '[]',
    procurement_permissions TEXT DEFAULT '[]',
    inventory_permissions TEXT DEFAULT '[]',
    reporting_permissions TEXT DEFAULT '[]',

    -- System
    is_system INTEGER DEFAULT 0, -- System templates cannot be modified
    is_default INTEGER DEFAULT 0,

    -- Status
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'inactive')),

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,

    -- Constraints
    UNIQUE(business_id, name)
);

-- User Permissions table (actual permissions assigned to users)
CREATE TABLE IF NOT EXISTS user_permissions (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    user_id TEXT NOT NULL,

    -- Permission Source
    source_type TEXT NOT NULL CHECK (source_type IN ('role', 'department', 'template', 'custom')),
    source_id TEXT, -- ID of the role, department, or template

    -- Resource-based permissions
    resource_type TEXT, -- 'invoice', 'purchase_order', 'employee', etc.
    resource_id TEXT, -- Specific resource ID if applicable

    -- Permission Details
    permission_key TEXT NOT NULL, -- e.g., 'invoice.create', 'employee.view'
    permission_value TEXT DEFAULT 'allow' CHECK (permission_value IN ('allow', 'deny')),

    -- Conditions
    conditions TEXT, -- JSON conditions for permission

    -- Grant Information
    granted_by_user_id TEXT,
    grant_reason TEXT,

    -- Status
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),
    effective_from TEXT DEFAULT (datetime('now')),
    effective_until TEXT,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    revoked_at TEXT,

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (granted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,

    -- Constraints
    CHECK (revoked_at IS NULL OR status = 'revoked'),
    CHECK (effective_until IS NULL OR effective_until > effective_from)
);

-- Role Hierarchies table
CREATE TABLE IF NOT EXISTS role_hierarchies (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Hierarchy Definition
    parent_role TEXT NOT NULL,
    child_role TEXT NOT NULL,
    hierarchy_level INTEGER NOT NULL DEFAULT 0,

    -- Inheritance
    inherit_permissions INTEGER DEFAULT 1,
    inherit_restrictions INTEGER DEFAULT 1,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,

    -- Constraints
    UNIQUE(business_id, parent_role, child_role),
    CHECK (parent_role != child_role)
);

-- Access Control Lists (ACL) table
CREATE TABLE IF NOT EXISTS access_control_lists (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Resource
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,

    -- Principal (who has access)
    principal_type TEXT NOT NULL CHECK (principal_type IN ('user', 'department', 'role', 'group')),
    principal_id TEXT NOT NULL,

    -- Access Level
    access_level TEXT NOT NULL CHECK (access_level IN ('none', 'read', 'write', 'delete', 'admin')),

    -- Additional Permissions
    can_share INTEGER DEFAULT 0,
    can_export INTEGER DEFAULT 0,

    -- Grant Information
    granted_by_user_id TEXT,

    -- Status
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
    expires_at TEXT,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (granted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,

    -- Constraints
    UNIQUE(business_id, resource_type, resource_id, principal_type, principal_id)
);

-- Create indexes for RBAC tables
CREATE INDEX idx_departments_business ON departments(business_id, status);
CREATE INDEX idx_departments_type ON departments(business_id, type) WHERE status = 'active';
CREATE INDEX idx_departments_parent ON departments(parent_department_id);
CREATE INDEX idx_departments_head ON departments(department_head_user_id);

CREATE INDEX idx_department_roles_department ON department_roles(department_id, status);
CREATE INDEX idx_department_roles_user ON department_roles(user_id, status);
CREATE INDEX idx_department_roles_business_user ON department_roles(business_id, user_id) WHERE status = 'active';

CREATE INDEX idx_permission_templates_business ON permission_templates(business_id, status);
CREATE INDEX idx_permission_templates_type ON permission_templates(template_type, applies_to);

CREATE INDEX idx_user_permissions_user ON user_permissions(user_id, status);
CREATE INDEX idx_user_permissions_business_user ON user_permissions(business_id, user_id, status);
CREATE INDEX idx_user_permissions_resource ON user_permissions(resource_type, resource_id) WHERE status = 'active';
CREATE INDEX idx_user_permissions_key ON user_permissions(permission_key, permission_value);

CREATE INDEX idx_role_hierarchies_business ON role_hierarchies(business_id);
CREATE INDEX idx_role_hierarchies_parent ON role_hierarchies(parent_role);
CREATE INDEX idx_role_hierarchies_child ON role_hierarchies(child_role);

CREATE INDEX idx_acl_resource ON access_control_lists(resource_type, resource_id, status);
CREATE INDEX idx_acl_principal ON access_control_lists(principal_type, principal_id, status);
CREATE INDEX idx_acl_business_resource ON access_control_lists(business_id, resource_type, resource_id);