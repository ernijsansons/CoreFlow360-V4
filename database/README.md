# CoreFlow360 V4 Database Schema

## Overview

CoreFlow360 V4 uses a comprehensive multi-tenant database schema built on Cloudflare D1 (SQLite). The schema is designed to support a full-featured ERP system with strong isolation between tenants, role-based access control, double-entry accounting, and comprehensive audit logging.

## Database Structure

### Core Tables

#### 1. **Multi-Tenancy & Users**
- `businesses` - Tenant organizations with subscription management
- `users` - User accounts with authentication details
- `business_memberships` - Links users to businesses with roles
- `user_sessions` - Active user sessions
- `api_keys` - API key management

#### 2. **RBAC & Departments**
- `departments` - Organizational departments with hierarchy
- `department_roles` - User roles within departments
- `permission_templates` - Reusable permission sets
- `user_permissions` - Actual permissions assigned to users
- `role_hierarchies` - Role inheritance structure
- `access_control_lists` - Resource-level access control

#### 3. **Double-Entry Accounting**
- `accounts` - Chart of accounts with hierarchical structure
- `journal_entries` - Journal entry headers
- `journal_lines` - Journal entry line items
- `general_ledger` - Period-based account balances
- `trial_balance` - Trial balance snapshots
- `trial_balance_lines` - Trial balance details
- `accounting_periods` - Fiscal period management

#### 4. **Workflow Management**
- `workflow_definitions` - Workflow templates
- `workflow_instances` - Active workflow instances
- `workflow_steps` - Individual workflow steps
- `workflow_transitions` - Step transition history

#### 5. **Audit & Monitoring**
- `audit_logs` - Comprehensive audit trail with cost tracking
- `activity_logs` - User activity tracking
- `system_events` - System-level events and errors

## Key Features

### Multi-Tenant Isolation
Every table includes a `business_id` column for tenant isolation. All queries must include proper business_id filtering.

### Soft Deletes
Most tables support soft deletes via `deleted_at` timestamp and `status` fields.

### Role Hierarchy
- **Owner**: Full system access
- **Director**: Strategic management access
- **Manager**: Departmental management
- **Employee**: Operational access
- **Viewer**: Read-only access

### Department Types
- Executive, Finance, Accounting, HR, Operations
- Sales, Marketing, Procurement, IT
- Legal, Compliance, Customer Service
- Warehouse, Production, Quality, Research

### Account Types (Double-Entry)
- **Assets**: Cash, Bank, AR, Inventory, Fixed Assets
- **Liabilities**: AP, Accrued, Notes Payable
- **Equity**: Owner's Equity, Retained Earnings
- **Revenue**: Sales, Service, Interest Income
- **Expenses**: COGS, Salaries, Rent, Utilities

### Audit Cost Tracking
Each audit log entry tracks:
- Operation cost in credits
- Compute time in milliseconds
- Storage usage in bytes
- Network transfer in bytes
- API calls count
- Database read/write operations
- AI model usage and tokens

## Migration Management

### Running Migrations

```bash
# Run all migrations
curl -X POST https://your-worker.workers.dev/admin/migrations/run \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"

# Check migration status
curl https://your-worker.workers.dev/admin/migrations/status \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"

# Rollback specific migration
curl -X POST https://your-worker.workers.dev/admin/migrations/rollback/003 \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"
```

### Migration Files

Located in `/database/migrations/`:
1. `001_core_tenant_users.sql` - Core multi-tenant structure
2. `002_rbac_departments.sql` - RBAC and departments
3. `003_double_entry_ledger.sql` - Accounting system
4. `004_audit_workflows.sql` - Audit and workflows
5. `005_additional_indexes.sql` - Performance indexes

### Rollback Scripts

Located in `/database/rollbacks/`:
- Each migration has a corresponding rollback script
- Rollbacks remove all objects created by the migration
- Run in reverse order when rolling back multiple migrations

## Best Practices

### 1. Always Use Business ID
```sql
-- Good
SELECT * FROM invoices WHERE business_id = ? AND status = 'active';

-- Bad (missing business_id)
SELECT * FROM invoices WHERE status = 'active';
```

### 2. Use Proper Indexes
All foreign keys and commonly queried columns have indexes.

### 3. Maintain Audit Trail
All data modifications should create audit log entries:
```sql
INSERT INTO audit_logs (business_id, event_type, resource_type, ...)
VALUES (?, 'update', 'invoice', ...);
```

### 4. Double-Entry Balance
Journal entries must always balance:
```sql
-- Total debits must equal total credits
CHECK (total_debit = total_credit)
```

### 5. Soft Delete Pattern
```sql
UPDATE users
SET status = 'deleted', deleted_at = datetime('now')
WHERE id = ?;
```

## Performance Considerations

### Indexes Strategy
- Primary keys on all tables
- Foreign key indexes for joins
- Composite indexes for common query patterns
- Partial indexes for filtered queries
- Full-text search indexes for text search

### Query Optimization
- Use covering indexes where possible
- Limit result sets with proper pagination
- Use EXISTS instead of COUNT for existence checks
- Batch operations when possible

### Data Archival
- Old audit logs can be moved to archive tables
- Completed workflows can be compressed
- Historical journal entries can be summarized

## Security

### Data Protection
- Password hashes using SHA-256
- API keys stored as hashes
- Sensitive data marked in audit logs
- Row-level security via business_id

### Access Control
- Role-based permissions
- Department-level access
- Resource-specific ACLs
- Audit trail for all actions

## Maintenance

### Regular Tasks
1. Analyze tables for query optimization
2. Archive old audit logs
3. Close accounting periods
4. Review failed workflows
5. Clean up expired sessions

### Monitoring
- Track table growth rates
- Monitor query performance
- Review audit log costs
- Check workflow completion rates

## Support

For database-related issues:
1. Check migration status
2. Review recent audit logs
3. Verify permissions and access
4. Check system events for errors

## License

Copyright (c) 2024 CoreFlow360 V4. All rights reserved.