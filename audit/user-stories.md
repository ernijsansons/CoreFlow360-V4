# User Stories - Backend↔UI Integration

**Created**: 2025-10-22
**Source**: Backend-to-UI Audit (Terminals X, Y, Z)
**Status**: Ready for PM Review & Ticket Creation

---

## Story Format
Each story includes:
- **User Role**: Who needs this feature
- **Backend APIs**: Existing endpoints to integrate
- **Required UI**: Component hierarchy and location
- **Acceptance Criteria**: Testable requirements
- **Dependencies**: Design assets, feature flags, third-party services
- **Effort Estimate**: T-shirt sizing (S/M/L/XL)

---

# Phase 1A: Critical Features (Sprint 34-35)

## Story 1: Compliance Guidelines Management

**As an** Enterprise Administrator
**I want to** create, edit, and manage compliance guidelines through the UI
**So that** I can define organizational compliance requirements without developer assistance

### Backend APIs Available
- `POST /api/compliance/guidelines` - Create guideline
- `GET /api/compliance/guidelines` - List all guidelines (with pagination)
- `GET /api/compliance/guidelines/:id` - Get single guideline
- `PUT /api/compliance/guidelines/:id` - Update guideline
- `DELETE /api/compliance/guidelines/:id` - Delete guideline

### Database Schema
- Table: `company_guidelines`
- Fields: id, business_id, title, description, category, severity, effective_date, created_at, created_by

### Required UI Components

**Location**: `/admin/compliance/guidelines`

**Component Hierarchy**:
```
ComplianceGuidelinesPage
├── GuidelinesToolbar
│   ├── CreateGuidelineButton
│   ├── SearchBar
│   └── FilterDropdown (category, severity)
├── GuidelinesTable
│   ├── GuidelineRow (repeating)
│   │   ├── TitleCell
│   │   ├── CategoryBadge
│   │   ├── SeverityIndicator
│   │   ├── EffectiveDateCell
│   │   └── ActionsMenu (Edit, Delete)
│   └── Pagination
└── GuidelineModal (Create/Edit)
    └── GuidelineForm
        ├── TitleField (required, max 200 chars)
        ├── DescriptionEditor (rich text, max 5000 chars)
        ├── CategorySelect (dropdown)
        ├── SeveritySelect (LOW/MEDIUM/HIGH/CRITICAL)
        ├── EffectiveDatePicker
        └── FormActions (Save, Cancel)
```

### Acceptance Criteria
1. ✅ Admin can view a paginated list of guidelines (20 per page)
2. ✅ Admin can filter guidelines by category and severity
3. ✅ Admin can search guidelines by title or description
4. ✅ Admin can create a new guideline with all required fields
5. ✅ Form validation shows errors within 200ms
6. ✅ Admin can edit an existing guideline
7. ✅ Admin can delete a guideline with confirmation dialog
8. ✅ Changes persist to backend immediately (no stale data)
9. ✅ Success/error toasts appear within 2 seconds
10. ✅ Table auto-refreshes after CRUD operations

### Non-Functional Requirements
- **Response Time**: List load <500ms, Create/Update <1s
- **Accessibility**: WCAG 2.1 AA compliant
- **Responsive**: Works on desktop (1920px) and tablet (768px)
- **Error Handling**: Network errors show retry button

### Dependencies
- Design: Compliance admin mockups from UX team
- Feature Flag: `enableComplianceAdmin` (default: false)
- Permissions: ABAC check for `compliance:guidelines:manage`

### Test Cases
See `e2e-test-plan.md` - Compliance Guidelines section

### Effort Estimate
**Size**: L (Large - 5-8 days)
- Backend integration: 1 day
- UI components: 3 days
- Form validation: 1 day
- Testing: 1.5 days
- Polish & bug fixes: 1 day

---

## Story 2: Agent Policy Management

**As an** Enterprise Administrator
**I want to** define and enforce AI agent behavior policies
**So that** agents operate within organizational compliance boundaries

### Backend APIs Available
- `POST /api/compliance/policies` - Create agent policy
- `GET /api/compliance/policies` - List all policies
- `GET /api/compliance/policies/:id` - Get single policy
- `PUT /api/compliance/policies/:id` - Update policy
- `DELETE /api/compliance/policies/:id` - Delete policy

### Database Schema
- Table: `agent_policies`
- Fields: id, business_id, name, policy_rules (JSON), agent_types (JSON array), is_active, created_at

### Required UI Components

**Location**: `/admin/compliance/policies`

**Component Hierarchy**:
```
AgentPoliciesPage
├── PoliciesHeader
│   ├── CreatePolicyButton
│   ├── ActivePoliciesCount
│   └── PolicySearchBar
├── PoliciesGrid
│   └── PolicyCard (repeating)
│       ├── PolicyHeader (name, active toggle)
│       ├── PolicyRulesList (abbreviated)
│       ├── AppliedAgentsChips
│       └── PolicyActions (Edit, Duplicate, Delete)
└── PolicyEditorModal
    ├── PolicyForm
    │   ├── NameField
    │   ├── DescriptionField
    │   ├── AgentTypeMultiSelect
    │   └── PolicyRulesBuilder
    │       └── RuleRow (repeating)
    │           ├── ConditionSelect
    │           ├── OperatorSelect
    │           ├── ValueInput
    │           └── RemoveButton
    └── PolicyPreview (JSON display)
```

### Acceptance Criteria
1. ✅ Admin can view all agent policies as cards
2. ✅ Admin can create a new policy with multiple rules
3. ✅ Rule builder supports conditions (e.g., "if user role equals X")
4. ✅ Admin can assign policy to one or more agent types
5. ✅ Admin can toggle policy active/inactive without deletion
6. ✅ Admin can duplicate an existing policy
7. ✅ Policy preview shows resulting JSON structure
8. ✅ Validation prevents conflicting rules
9. ✅ Changes take effect immediately for active agents
10. ✅ Audit log records all policy changes

### Non-Functional Requirements
- **Response Time**: Policy list <300ms, Save <1s
- **Validation**: Client-side rule validation before submission
- **Accessibility**: Keyboard navigation for rule builder

### Dependencies
- Design: Policy builder wireframes
- Feature Flag: `enableAgentPolicies`
- AI Agent System: Policy enforcement hook

### Test Cases
See `e2e-test-plan.md` - Agent Policies section

### Effort Estimate
**Size**: XL (X-Large - 8-10 days)
- Rule builder component: 4 days
- Policy CRUD: 2 days
- Validation logic: 2 days
- Testing & polish: 2 days

---

## Story 3: Compliance Violation Tracker

**As an** Compliance Officer
**I want to** view and manage compliance violations
**So that** I can ensure timely resolution of compliance issues

### Backend APIs Available
- `GET /api/compliance/violations` - List violations with filters
- `GET /api/compliance/violations/:id` - Get violation details
- `PUT /api/compliance/violations/:id` - Update violation status

### Database Schema
- Table: `compliance_violations`
- Fields: id, business_id, guideline_id, agent_id, violation_type, severity, status, detected_at, resolved_at

### Required UI Components

**Location**: `/admin/compliance/violations`

**Component Hierarchy**:
```
ViolationsPage
├── ViolationsDashboard
│   ├── ViolationStats (total, open, resolved)
│   ├── SeverityChart (bar chart by severity)
│   └── TrendChart (violations over time)
├── ViolationsFilters
│   ├── StatusFilter (Open, In Progress, Resolved)
│   ├── SeverityFilter
│   ├── DateRangePicker
│   └── AgentTypeFilter
├── ViolationsTable
│   └── ViolationRow (repeating)
│       ├── SeverityBadge (color-coded)
│       ├── ViolationTypeCell
│       ├── GuidelineLink
│       ├── AgentCell
│       ├── DetectedDateCell
│       ├── StatusBadge
│       └── ActionsButton
└── ViolationDetailModal
    ├── ViolationHeader
    ├── ViolationDescription
    ├── GuidelineReference
    ├── AgentInfo
    ├── Timeline (detected, acknowledged, resolved)
    └── StatusUpdateForm
        ├── StatusSelect
        ├── ResolutionNotes
        └── SaveButton
```

### Acceptance Criteria
1. ✅ Dashboard shows violation statistics (total, by severity, by status)
2. ✅ Table displays all violations with color-coded severity
3. ✅ Violations can be filtered by status, severity, date range, agent
4. ✅ Clicking violation opens detail modal with full context
5. ✅ Compliance officer can update violation status with notes
6. ✅ Timeline shows violation lifecycle
7. ✅ Resolved violations show resolution date and notes
8. ✅ Export violations to CSV
9. ✅ Real-time updates when new violations occur
10. ✅ Email notifications for CRITICAL severity violations

### Non-Functional Requirements
- **Response Time**: Dashboard <1s, Table <500ms
- **Real-time**: WebSocket or polling (30s) for new violations
- **Export**: CSV export completes within 5s for 1000 records

### Dependencies
- Design: Violations dashboard mockups
- Feature Flag: `enableViolationTracking`
- Notifications: Email service integration

### Test Cases
See `e2e-test-plan.md` - Violations section

### Effort Estimate
**Size**: L (Large - 6-8 days)
- Dashboard & charts: 2 days
- Table & filters: 2 days
- Detail modal & status updates: 2 days
- Real-time updates: 1 day
- Testing: 1.5 days

---

## Story 4: Compliance Audit Trail Viewer

**As an** Auditor
**I want to** search and view compliance-related audit logs
**So that** I can verify compliance activities for audits and investigations

### Backend APIs Available
- `GET /api/compliance/audit-trail` - List audit events with filters

### Database Schema
- Table: `audit_log` (shared system-wide audit)
- Fields: id, business_id, user_id, action, resource, metadata (JSON), timestamp

### Required UI Components

**Location**: `/admin/compliance/audit-trail`

**Component Hierarchy**:
```
AuditTrailPage
├── AuditSearchBar
│   ├── FullTextSearch
│   └── AdvancedFiltersToggle
├── AdvancedFilters (collapsible)
│   ├── UserSelect (multi-select)
│   ├── ActionTypeSelect
│   ├── ResourceTypeSelect
│   ├── DateRangePicker
│   └── ApplyFiltersButton
├── AuditTimeline
│   └── AuditEvent (repeating)
│       ├── EventTimestamp
│       ├── UserAvatar & Name
│       ├── ActionBadge (color-coded)
│       ├── ResourceLink
│       ├── EventDescription
│       └── ViewDetailsButton
└── AuditEventModal
    ├── EventHeader
    ├── EventMetadata (formatted JSON)
    ├── IPAddress & UserAgent
    └── RelatedEvents (if applicable)
```

### Acceptance Criteria
1. ✅ Audit trail displays events in reverse chronological order
2. ✅ Full-text search works across all audit fields
3. ✅ Advanced filters include user, action type, resource, date range
4. ✅ Timeline updates as filters change (debounced 300ms)
5. ✅ Each event shows timestamp, user, action, resource
6. ✅ Event detail modal shows complete metadata (formatted JSON)
7. ✅ Export filtered results to CSV
8. ✅ Pagination handles large result sets (100+ per page)
9. ✅ IP address and user agent visible in detail view
10. ✅ Audit events are immutable (read-only)

### Non-Functional Requirements
- **Response Time**: Initial load <1s, Filter <500ms
- **Scalability**: Handle 1M+ audit records
- **Security**: Audit trail access requires elevated permissions

### Dependencies
- Design: Audit trail wireframes
- Permissions: `compliance:audit:view` permission check

### Test Cases
See `e2e-test-plan.md` - Audit Trail section

### Effort Estimate
**Size**: M (Medium - 4-5 days)
- Search & filters: 2 days
- Timeline UI: 1 day
- Detail modal: 1 day
- Testing: 1 day

---

# Phase 1B: High Priority (Sprint 36-37)

## Story 5: Invoice Approval Workflow UI

**As a** Finance Manager
**I want to** review and approve invoices through a visual workflow
**So that** invoices follow multi-level approval processes before posting

### Backend APIs Available
- `GET /api/finance/invoices?status=PENDING_APPROVAL` - Get approval queue
- `POST /api/finance/invoice-approvals` - Create approval record
- `PUT /api/finance/invoice-approvals/:id` - Approve/reject
- `GET /api/finance/invoice-approval-rules` - Get approval rules
- `POST /api/finance/invoice-approval-rules` - Create rule
- `PUT /api/finance/invoice-approval-rules/:id` - Update rule

### Database Schema
- Tables: `invoices`, `invoice_approvals`, `invoice_approval_rules`, `invoice_approval_config`
- Workflow Engine: `workflow_executions`, `workflow_steps`

### Required UI Components

**Location**: `/finance/approvals`

**Component Hierarchy**:
```
ApprovalsPage
├── ApprovalQueue
│   ├── QueueStats (pending count, overdue count)
│   ├── MyApprovalsFilter
│   └── ApprovalCard (repeating)
│       ├── InvoiceNumber
│       ├── CustomerName
│       ├── AmountBadge (large, prominent)
│       ├── CurrentApprovalLevel
│       ├── DaysWaiting
│       ├── ReviewButton
│       └── QuickRejectButton
├── ApprovalModal
│   ├── InvoicePreview (read-only)
│   ├── ApprovalFlow (visual)
│   │   └── ApprovalLevel (repeating)
│   │       ├── LevelNumber
│   │       ├── ApproverAvatar
│   │       ├── StatusIndicator (pending/approved/rejected)
│   │       └── Timestamp
│   ├── ApprovalDecision
│   │   ├── ApproveButton (green, prominent)
│   │   ├── RejectButton (red)
│   │   ├── CommentsTextarea (required for reject)
│   │   └── SubmitButton
│   └── ApprovalHistory
└── ApprovalRulesTab
    ├── RulesTable
    │   └── RuleRow (repeating)
    │       ├── ThresholdAmount
    │       ├── RequiredApprovers
    │       ├── ActiveToggle
    │       └── EditButton
    └── CreateRuleButton
```

### Acceptance Criteria

**Approval Queue**:
1. ✅ Shows all invoices pending current user's approval
2. ✅ Filter by "My Approvals" or "All Pending"
3. ✅ Sort by amount, days waiting, customer
4. ✅ Display count of pending and overdue approvals
5. ✅ Overdue invoices (>3 days) highlighted in red

**Approval Flow**:
6. ✅ Visual flow shows all approval levels (past, current, future)
7. ✅ Current level highlighted, completed levels show checkmark
8. ✅ Each level shows approver name, status, timestamp (if completed)
9. ✅ Invoice preview is read-only, shows all line items

**Approval Decision**:
10. ✅ Approve button moves to next level or marks APPROVED (if final)
11. ✅ Reject button immediately marks invoice REJECTED
12. ✅ Comments required for rejection (validation)
13. ✅ Decision persists to backend within 1s
14. ✅ Success toast confirms decision
15. ✅ Approval card removed from queue after decision

**Approval Rules**:
16. ✅ Rules table shows threshold amounts and required approvers
17. ✅ Create rule wizard: threshold input, approver multi-select
18. ✅ Rules can be activated/deactivated without deletion
19. ✅ Invoice amount automatically determines approval levels needed
20. ✅ Rule changes apply to new invoices only (not retroactive)

### Non-Functional Requirements
- **Response Time**: Queue load <500ms, Approval decision <1s
- **Real-time**: Queue updates when approvals occur (polling 30s)
- **Notifications**: Email sent to next approver when level advances
- **Audit**: All approval decisions logged to audit_log

### Dependencies
- Design: Approval workflow mockups with visual flow
- Feature Flag: `enableInvoiceApprovalWorkflow`
- Email: Notification templates for approval requests
- Workflow Engine: Backend workflow orchestration

### Test Cases
See `e2e-test-plan.md` - Invoice Approval Workflow section

### Effort Estimate
**Size**: XL (X-Large - 10-12 days)
- Approval queue & cards: 2 days
- Visual approval flow: 3 days
- Approval decision logic: 2 days
- Rules management: 2 days
- Email notifications: 1 day
- Testing: 2 days

---

## Story 6: Chart of Accounts Manager

**As an** Accountant
**I want to** manage the chart of accounts through the UI
**So that** I can configure account structure without developer assistance

### Backend APIs Available
- `GET /api/finance/accounts` - List all accounts
- `POST /api/finance/accounts` - Create account
- `GET /api/finance/accounts/:id` - Get account details
- `PUT /api/finance/accounts/:id` - Update account
- `DELETE /api/finance/accounts/:id` - Delete account (if no transactions)

### Database Schema
- Table: `chart_of_accounts`
- Fields: id, code, name, type (ASSET/LIABILITY/EQUITY/REVENUE/EXPENSE), category, parent_id, normal_balance, is_active, business_id

### Required UI Components

**Location**: `/finance/accounts`

**Component Hierarchy**:
```
ChartOfAccountsPage
├── AccountsToolbar
│   ├── CreateAccountButton
│   ├── ImportAccountsButton (CSV)
│   ├── AccountTypeFilter
│   └── SearchBar
├── AccountsTreeView
│   └── AccountNode (recursive)
│       ├── AccountCode
│       ├── AccountName
│       ├── AccountTypeBadge
│       ├── BalanceDisplay (if has transactions)
│       ├── ExpandCollapseIcon
│       ├── ChildAccounts (nested)
│       └── ActionsMenu (Edit, Add Child, Delete)
└── AccountModal (Create/Edit)
    └── AccountForm
        ├── CodeInput (formatted, validated)
        ├── NameInput (required)
        ├── TypeSelect (ASSET/LIABILITY/EQUITY/REVENUE/EXPENSE)
        ├── CategorySelect (based on type)
        ├── ParentAccountSelect (hierarchical dropdown)
        ├── NormalBalanceRadio (Debit/Credit, auto-set by type)
        ├── CurrencySelect
        ├── IsActiveCheckbox
        ├── DescriptionTextarea
        └── FormActions (Save, Cancel)
```

### Acceptance Criteria

**Tree View**:
1. ✅ Accounts displayed in hierarchical tree structure
2. ✅ Grouped by account type (Assets, Liabilities, etc.)
3. ✅ Parent accounts expandable/collapsible
4. ✅ Account code formatted consistently (e.g., 1000, 1100, 1110)
5. ✅ Current balance shown for accounts with transactions
6. ✅ Search filters tree in real-time
7. ✅ Filter by account type
8. ✅ Drag-and-drop to change parent (optional enhancement)

**Account Creation**:
9. ✅ Code input validates format (numeric, 4 digits minimum)
10. ✅ Code uniqueness validated on blur
11. ✅ Type selection auto-suggests normal balance (debit/credit)
12. ✅ Category dropdown filtered by selected type
13. ✅ Parent account selector shows hierarchical structure
14. ✅ Can create root account (no parent)
15. ✅ Can create child account under existing parent
16. ✅ Form validation shows errors immediately

**Account Editing**:
17. ✅ Edit preserves account code (if has transactions)
18. ✅ Edit allows changing parent (if no child accounts)
19. ✅ Changes to parent update hierarchy immediately

**Account Deletion**:
20. ✅ Cannot delete account with transactions (error message)
21. ✅ Cannot delete account with child accounts (error message)
22. ✅ Confirmation dialog before deletion
23. ✅ Deletion marks account inactive (soft delete preferred)

**Bulk Import**:
24. ✅ CSV upload interface with template download
25. ✅ Validation preview before import
26. ✅ Import creates accounts with proper hierarchy

### Non-Functional Requirements
- **Response Time**: Tree load <1s (1000 accounts), Create/Update <500ms
- **Validation**: Client-side code format validation
- **Accessibility**: Keyboard navigation for tree view

### Dependencies
- Design: Tree view component design
- Feature Flag: `enableChartOfAccountsManager`
- Permissions: `finance:accounts:manage`

### Test Cases
See `e2e-test-plan.md` - Chart of Accounts section

### Effort Estimate
**Size**: L (Large - 7-9 days)
- Tree view component: 3 days
- Account CRUD forms: 2 days
- Validation logic: 1 day
- Bulk import: 1.5 days
- Testing: 1.5 days

---

## Story 7: CRM AI Intelligence Panel

**As a** Sales Representative
**I want to** see AI-generated insights and recommendations for leads
**So that** I can prioritize effectively and take the best next actions

### Backend APIs Available
- AI fields already exist in database on `leads`, `companies`, `conversations` tables
- No new APIs needed, enhance existing endpoints to return AI fields

### Database Schema (Already Exists)
- `leads`: ai_qualification_score, ai_qualification_summary, ai_next_best_action, ai_predicted_value, ai_close_probability
- `companies`: ai_summary, ai_pain_points, ai_icp_score
- `conversations`: ai_summary, ai_sentiment, ai_objections, ai_commitments

### Required UI Components

**Location**: Enhance existing lead detail page `/crm/leads/:id`

**Component Hierarchy** (Add to existing page):
```
LeadDetailPage (existing)
└── AIInsightsPanel (NEW - sidebar or top card)
    ├── QualificationScoreCard
    │   ├── ScoreMeter (0-100, color-coded)
    │   ├── ScoreExplanation (ai_qualification_summary)
    │   └── ScoreTrend (if historical data)
    ├── NextBestActionCard (prominent)
    │   ├── ActionIcon
    │   ├── ActionTitle (ai_next_best_action)
    │   ├── QuickActionButton
    │   └── DismissButton
    ├── PredictedValueCard
    │   ├── ValueAmount (ai_predicted_value)
    │   ├── ConfidenceIndicator
    │   └── ValueExplanation
    ├── CloseProbabilityCard
    │   ├── ProbabilityMeter (0-100%)
    │   ├── EstimatedCloseDate
    │   └── ProbabilityFactors
    ├── CompanyICPScoreCard
    │   ├── ICPScoreMeter
    │   ├── ICPMatchReasons
    │   └── PainPointsList
    └── ConversationInsightsCard
        ├── LatestSentiment (positive/neutral/negative)
        ├── KeyObjections (list)
        ├── CommitmentsMade (list)
        └── ConversationSummary
```

### Acceptance Criteria

**Qualification Score**:
1. ✅ Score displayed as radial meter (0-100)
2. ✅ Score color-coded: 0-30 red, 31-70 yellow, 71-100 green
3. ✅ AI explanation shown below score
4. ✅ Score updates when lead data changes

**Next Best Action**:
5. ✅ Action displayed prominently (large card, top of panel)
6. ✅ Action is clickable (e.g., "Schedule call" opens scheduler)
7. ✅ User can dismiss action (marks as completed)
8. ✅ New action generated after dismissal

**Predicted Value**:
9. ✅ Value formatted as currency
10. ✅ Confidence indicator shows how certain AI is
11. ✅ Tooltip explains value calculation factors

**Close Probability**:
12. ✅ Probability displayed as percentage meter
13. ✅ Estimated close date shown (ai_estimated_close_date)
14. ✅ Key factors influencing probability listed

**ICP Score**:
15. ✅ Company ICP score displayed (0-100)
16. ✅ Match reasons shown (why this is a good/bad fit)
17. ✅ Pain points from company analysis listed

**Conversation Insights**:
18. ✅ Latest conversation sentiment badge (color-coded)
19. ✅ Key objections listed from all conversations
20. ✅ Commitments made by prospect highlighted
21. ✅ AI summary of conversation context

**General**:
22. ✅ Panel visible on all lead detail pages
23. ✅ Panel collapsible/expandable
24. ✅ Loading states while AI data fetches
25. ✅ Graceful handling if AI data unavailable

### Non-Functional Requirements
- **Response Time**: AI panel loads with page (<1s total)
- **Caching**: AI scores cached client-side for 5 minutes
- **Responsiveness**: Panel adapts to mobile (stacks vertically)

### Dependencies
- Design: AI insights panel mockups
- Backend: Ensure AI fields returned in lead API
- Feature Flag: `enableAIInsights`

### Test Cases
See `e2e-test-plan.md` - CRM AI Intelligence section

### Effort Estimate
**Size**: M (Medium - 4-5 days)
- Panel layout & components: 2 days
- Data integration: 1 day
- Interactive actions: 1 day
- Testing: 1 day

---

# Phase 2: Core Features (Sprint 38-40)

## Story 8: Journal Entry Editor (Enhanced)

**As an** Accountant
**I want to** create complex journal entries with multiple lines
**So that** I can record any transaction in the double-entry system

### Backend APIs Available
- `POST /api/finance/journal-entries` - Create entry with lines
- `GET /api/finance/journal-entries` - List entries
- `POST /api/finance/journal-entries/:id/post` - Post entry to ledger

### Effort Estimate: **L (6-8 days)**

[Detailed acceptance criteria available on request]

---

## Story 9: Account Reconciliation Interface

**As an** Accountant
**I want to** reconcile bank accounts against statements
**So that** I can ensure accounting records match bank records

### Backend APIs Available
- `POST /api/finance/reconciliation` - Create reconciliation
- `POST /api/finance/reconciliation/:id/match` - Match transactions

### Effort Estimate: **L (6-8 days)**

[Detailed acceptance criteria available on request]

---

## Story 10: CRM Data Quality Dashboard

**As a** CRM Administrator
**I want to** identify and fix data quality issues
**So that** the CRM database remains clean and accurate

### Backend APIs Available
- `POST /api/crm/data-quality/duplicates/find` - Find duplicates
- `POST /api/crm/data-quality/duplicates/merge` - Merge records
- `POST /api/crm/data-quality/validate` - Validate entity
- `POST /api/crm/data-quality/auto-fix` - Auto-fix issues

### Effort Estimate: **L (7-9 days)**

[Detailed acceptance criteria available on request]

---

# Remaining Stories (Phase 3 & 4)

## Story 11-20: Additional Features
- Story 11: CRM Data Enrichment Interface (M - 4 days)
- Story 12: Agent Performance Dashboard (L - 6 days)
- Story 13: Custom Report Builder (XL - 10 days)
- Story 14: Budget Management UI (L - 6 days)
- Story 15: Knowledge Base Interface (L - 8 days)
- Story 16: Workflow Visual Designer (XL - 10 days)
- Story 17: Email Sequence Builder (L - 6 days)
- Story 18: ABAC Admin UI (L - 6 days)
- Story 19: AI Audit Dashboard (M - 4 days)
- Story 20: Custom Integrations Builder (XL - 10 days)

[Full specifications available on request for Phase 3 & 4 stories]

---

## Summary

### Total Stories: 20
### Total Estimated Effort: ~120-150 days (6-8 sprints with 2-week sprints, 2 engineers)

### Sprint Allocation
- **Sprint 34-35** (Phase 1A): Stories 1-4 (Compliance) - 4 stories, ~30 days
- **Sprint 36-37** (Phase 1B): Stories 5-7 (Invoice Approval, Chart of Accounts, AI Panel) - 3 stories, ~25 days
- **Sprint 38-40** (Phase 2): Stories 8-12 (Journal, Reconciliation, Data Quality, Enrichment, Agents) - 5 stories, ~35 days
- **Sprint 41-43** (Phase 3): Stories 13-17 (Reports, Budget, Knowledge, Workflow, Sequences) - 5 stories, ~40 days
- **Backlog** (Phase 4): Stories 18-20 (ABAC, AI Audit, Integrations) - 3 stories, ~20 days

---

**Next Step**: Create E2E test plan (`e2e-test-plan.md`)
