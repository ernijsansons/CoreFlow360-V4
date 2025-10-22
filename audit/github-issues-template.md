# GitHub/Linear Issues - Ready to Import

**Source**: Backend-to-UI Audit (2025-10-22)
**Format**: Each issue below can be directly imported into GitHub Issues or Linear

---

## Issue Template Format

```markdown
**Title**: [FEATURE] {Feature Name}
**Labels**: enhancement, ui-integration, phase-{1a|1b|2|3|4}, priority-{critical|high|medium|low}
**Milestone**: Sprint {number}
**Assignees**: TBD
**Story Points**: {estimate}

**Description**: {User story}

**Backend APIs**:
- {List of existing API endpoints}

**Acceptance Criteria**:
- [ ] Criterion 1
- [ ] Criterion 2
...

**Dependencies**:
- Design: {mockups needed}
- Feature Flag: {flag name}
- Permissions: {ABAC checks}

**Technical Notes**:
{Component hierarchy, special considerations}

**Related Issues**: #TBD
```

---

# Phase 1A Issues (Sprint 34-35)

## Issue #1: [FEATURE] Compliance Guidelines Management

**Labels**: `enhancement`, `ui-integration`, `phase-1a`, `priority-critical`, `compliance`
**Milestone**: Sprint 34
**Story Points**: 8

**Description**:
As an Enterprise Administrator, I want to create, edit, and manage compliance guidelines through the UI, so that I can define organizational compliance requirements without developer assistance.

**Backend APIs Available**:
- `POST /api/compliance/guidelines` - Create guideline
- `GET /api/compliance/guidelines` - List all guidelines (with pagination)
- `GET /api/compliance/guidelines/:id` - Get single guideline
- `PUT /api/compliance/guidelines/:id` - Update guideline
- `DELETE /api/compliance/guidelines/:id` - Delete guideline

**Database Schema**:
- Table: `company_guidelines`
- Fields: id, business_id, title, description, category, severity, effective_date

**Acceptance Criteria**:
- [ ] Admin can view a paginated list of guidelines (20 per page)
- [ ] Admin can filter guidelines by category and severity
- [ ] Admin can search guidelines by title or description
- [ ] Admin can create a new guideline with all required fields
- [ ] Form validation shows errors within 200ms
- [ ] Admin can edit an existing guideline
- [ ] Admin can delete a guideline with confirmation dialog
- [ ] Changes persist to backend immediately (no stale data)
- [ ] Success/error toasts appear within 2 seconds
- [ ] Table auto-refreshes after CRUD operations
- [ ] Response time: List load <500ms, Create/Update <1s
- [ ] WCAG 2.1 AA compliant
- [ ] Works on desktop (1920px) and tablet (768px)

**Component Hierarchy**:
```
ComplianceGuidelinesPage
├── GuidelinesToolbar (CreateButton, SearchBar, FilterDropdown)
├── GuidelinesTable (with pagination)
│   └── GuidelineRow × N
└── GuidelineModal (Create/Edit form)
```

**Dependencies**:
- Design: Compliance admin mockups from UX team
- Feature Flag: `enableComplianceAdmin` (default: false)
- Permissions: ABAC check for `compliance:guidelines:manage`

**Technical Notes**:
- Use React Hook Form + Zod for form validation
- Implement optimistic updates for better UX
- Cache list results in React Query for 5 minutes
- Debounce search input by 300ms

**Test Coverage**:
- E2E tests defined in `audit/e2e-test-plan.md` - Test Suite 1 (Tests 1.1-1.5)

**Effort Estimate**: 5-8 days
- Backend integration: 1 day
- UI components: 3 days
- Form validation: 1 day
- Testing: 1.5 days
- Polish & bug fixes: 1 day

**Related Issues**: #TBD (Agent Policy Management), #TBD (Violation Tracker)

---

## Issue #2: [FEATURE] Agent Policy Management

**Labels**: `enhancement`, `ui-integration`, `phase-1a`, `priority-critical`, `compliance`, `ai-agents`
**Milestone**: Sprint 34
**Story Points**: 13

**Description**:
As an Enterprise Administrator, I want to define and enforce AI agent behavior policies, so that agents operate within organizational compliance boundaries.

**Backend APIs Available**:
- `POST /api/compliance/policies` - Create agent policy
- `GET /api/compliance/policies` - List all policies
- `GET /api/compliance/policies/:id` - Get single policy
- `PUT /api/compliance/policies/:id` - Update policy
- `DELETE /api/compliance/policies/:id` - Delete policy

**Database Schema**:
- Table: `agent_policies`
- Fields: id, business_id, name, policy_rules (JSON), agent_types (JSON array), is_active

**Acceptance Criteria**:
- [ ] Admin can view all agent policies as cards
- [ ] Admin can create a new policy with multiple rules
- [ ] Rule builder supports conditions (e.g., "if user role equals X")
- [ ] Admin can assign policy to one or more agent types
- [ ] Admin can toggle policy active/inactive without deletion
- [ ] Admin can duplicate an existing policy
- [ ] Policy preview shows resulting JSON structure
- [ ] Validation prevents conflicting rules
- [ ] Changes take effect immediately for active agents
- [ ] Audit log records all policy changes
- [ ] Response time: Policy list <300ms, Save <1s
- [ ] Client-side rule validation before submission
- [ ] Keyboard navigation for rule builder

**Component Hierarchy**:
```
AgentPoliciesPage
├── PoliciesHeader (CreateButton, ActiveCount, SearchBar)
├── PoliciesGrid
│   └── PolicyCard × N (with active toggle)
└── PolicyEditorModal
    ├── PolicyForm (name, description, agent types)
    ├── PolicyRulesBuilder (dynamic rule rows)
    └── PolicyPreview (JSON display)
```

**Dependencies**:
- Design: Policy builder wireframes
- Feature Flag: `enableAgentPolicies`
- AI Agent System: Policy enforcement hook (backend already exists)

**Technical Notes**:
- Rule builder is a complex component - consider using a library like `react-querybuilder`
- JSON preview should be syntax-highlighted (use `react-json-view`)
- Validate rules against schema before allowing save
- Store rule templates for common patterns

**Test Coverage**:
- E2E tests defined in `audit/e2e-test-plan.md` - Test Suite 2 (Tests 2.1-2.2)

**Effort Estimate**: 8-10 days
- Rule builder component: 4 days
- Policy CRUD: 2 days
- Validation logic: 2 days
- Testing & polish: 2 days

**Related Issues**: #TBD (Compliance Guidelines), #TBD (Violation Tracker)

---

## Issue #3: [FEATURE] Compliance Violation Tracker

**Labels**: `enhancement`, `ui-integration`, `phase-1a`, `priority-critical`, `compliance`, `monitoring`
**Milestone**: Sprint 35
**Story Points**: 8

**Description**:
As a Compliance Officer, I want to view and manage compliance violations, so that I can ensure timely resolution of compliance issues.

**Backend APIs Available**:
- `GET /api/compliance/violations` - List violations with filters
- `GET /api/compliance/violations/:id` - Get violation details
- `PUT /api/compliance/violations/:id` - Update violation status

**Database Schema**:
- Table: `compliance_violations`
- Fields: id, business_id, guideline_id, agent_id, violation_type, severity, status, detected_at, resolved_at

**Acceptance Criteria**:
- [ ] Dashboard shows violation statistics (total, open, resolved)
- [ ] Table displays all violations with color-coded severity
- [ ] Violations can be filtered by status, severity, date range, agent
- [ ] Clicking violation opens detail modal with full context
- [ ] Compliance officer can update violation status with notes
- [ ] Timeline shows violation lifecycle
- [ ] Resolved violations show resolution date and notes
- [ ] Export violations to CSV
- [ ] Real-time updates when new violations occur (WebSocket or 30s polling)
- [ ] Email notifications for CRITICAL severity violations
- [ ] Response time: Dashboard <1s, Table <500ms

**Component Hierarchy**:
```
ViolationsPage
├── ViolationsDashboard (stats, charts)
├── ViolationsFilters (status, severity, date, agent)
├── ViolationsTable
│   └── ViolationRow × N
└── ViolationDetailModal
    ├── ViolationHeader
    ├── Timeline
    └── StatusUpdateForm
```

**Dependencies**:
- Design: Violations dashboard mockups
- Feature Flag: `enableViolationTracking`
- Notifications: Email service integration

**Technical Notes**:
- Use Chart.js or Recharts for violation charts
- Implement real-time updates with WebSocket or SWR with polling
- CSV export should handle large datasets (stream download)
- Color coding: CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=gray

**Test Coverage**:
- E2E tests defined in `audit/e2e-test-plan.md` - Test Suite 3 (Tests 3.1-3.4)

**Effort Estimate**: 6-8 days
- Dashboard & charts: 2 days
- Table & filters: 2 days
- Detail modal & status updates: 2 days
- Real-time updates: 1 day
- Testing: 1.5 days

**Related Issues**: #TBD (Compliance Guidelines), #TBD (Audit Trail)

---

## Issue #4: [FEATURE] Compliance Audit Trail Viewer

**Labels**: `enhancement`, `ui-integration`, `phase-1a`, `priority-high`, `compliance`, `audit`
**Milestone**: Sprint 35
**Story Points**: 5

**Description**:
As an Auditor, I want to search and view compliance-related audit logs, so that I can verify compliance activities for audits and investigations.

**Backend APIs Available**:
- `GET /api/compliance/audit-trail` - List audit events with filters

**Database Schema**:
- Table: `audit_log` (shared system-wide audit)
- Fields: id, business_id, user_id, action, resource, metadata (JSON), timestamp

**Acceptance Criteria**:
- [ ] Audit trail displays events in reverse chronological order
- [ ] Full-text search works across all audit fields
- [ ] Advanced filters include user, action type, resource, date range
- [ ] Timeline updates as filters change (debounced 300ms)
- [ ] Each event shows timestamp, user, action, resource
- [ ] Event detail modal shows complete metadata (formatted JSON)
- [ ] Export filtered results to CSV
- [ ] Pagination handles large result sets (100+ per page)
- [ ] IP address and user agent visible in detail view
- [ ] Audit events are immutable (read-only)
- [ ] Response time: Initial load <1s, Filter <500ms
- [ ] Handle 1M+ audit records

**Component Hierarchy**:
```
AuditTrailPage
├── AuditSearchBar (full-text + advanced filters)
├── AdvancedFilters (collapsible)
├── AuditTimeline
│   └── AuditEvent × N
└── AuditEventModal (detail view)
```

**Dependencies**:
- Design: Audit trail wireframes
- Permissions: `compliance:audit:view` permission check

**Technical Notes**:
- Use virtual scrolling for large result sets (react-window)
- Debounce search by 300ms
- Use date-fns for timestamp formatting
- Syntax highlight JSON metadata

**Test Coverage**:
- E2E tests defined in `audit/e2e-test-plan.md` - Test Suite 4 (Tests 4.1-4.2)

**Effort Estimate**: 4-5 days
- Search & filters: 2 days
- Timeline UI: 1 day
- Detail modal: 1 day
- Testing: 1 day

**Related Issues**: #TBD (Violation Tracker)

---

# Phase 1B Issues (Sprint 36-37)

## Issue #5: [FEATURE] Invoice Approval Workflow UI

**Labels**: `enhancement`, `ui-integration`, `phase-1b`, `priority-critical`, `finance`, `workflow`
**Milestone**: Sprint 36
**Story Points**: 13

**Description**:
As a Finance Manager, I want to review and approve invoices through a visual workflow, so that invoices follow multi-level approval processes before posting.

**Backend APIs Available**:
- `GET /api/finance/invoices?status=PENDING_APPROVAL` - Get approval queue
- `POST /api/finance/invoice-approvals` - Create approval record
- `PUT /api/finance/invoice-approvals/:id` - Approve/reject
- `GET /api/finance/invoice-approval-rules` - Get approval rules
- `POST /api/finance/invoice-approval-rules` - Create rule
- `PUT /api/finance/invoice-approval-rules/:id` - Update rule

**Database Schema**:
- Tables: `invoices`, `invoice_approvals`, `invoice_approval_rules`, `invoice_approval_config`
- Workflow Engine: `workflow_executions`, `workflow_steps`

**Acceptance Criteria**:

**Approval Queue**:
- [ ] Shows all invoices pending current user's approval
- [ ] Filter by "My Approvals" or "All Pending"
- [ ] Sort by amount, days waiting, customer
- [ ] Display count of pending and overdue approvals
- [ ] Overdue invoices (>3 days) highlighted in red

**Approval Flow**:
- [ ] Visual flow shows all approval levels (past, current, future)
- [ ] Current level highlighted, completed levels show checkmark
- [ ] Each level shows approver name, status, timestamp
- [ ] Invoice preview is read-only, shows all line items

**Approval Decision**:
- [ ] Approve button moves to next level or marks APPROVED
- [ ] Reject button immediately marks invoice REJECTED
- [ ] Comments required for rejection
- [ ] Decision persists within 1s
- [ ] Approval card removed from queue after decision

**Approval Rules**:
- [ ] Rules table shows threshold amounts and required approvers
- [ ] Create rule wizard: threshold input, approver multi-select
- [ ] Rules can be activated/deactivated
- [ ] Invoice amount auto-determines approval levels

**Component Hierarchy**:
```
ApprovalsPage
├── ApprovalQueue (stats, cards)
├── ApprovalModal
│   ├── InvoicePreview
│   ├── ApprovalFlow (visual stepper)
│   ├── ApprovalDecision (approve/reject)
│   └── ApprovalHistory
└── ApprovalRulesTab
    ├── RulesTable
    └── CreateRuleButton
```

**Dependencies**:
- Design: Approval workflow mockups with visual flow
- Feature Flag: `enableInvoiceApprovalWorkflow`
- Email: Notification templates
- Workflow Engine: Backend orchestration (already exists)

**Technical Notes**:
- Use a stepper component for approval flow visualization
- Implement optimistic updates for approval decisions
- Real-time queue updates via polling (30s) or WebSocket
- Email notifications sent via queue system

**Test Coverage**:
- E2E tests defined in `audit/e2e-test-plan.md` - Test Suite 5 (Tests 5.1-5.6)

**Effort Estimate**: 10-12 days
- Approval queue & cards: 2 days
- Visual approval flow: 3 days
- Approval decision logic: 2 days
- Rules management: 2 days
- Email notifications: 1 day
- Testing: 2 days

**Related Issues**: #TBD (Chart of Accounts), #TBD (Invoice Manager)

---

## Issue #6: [FEATURE] Chart of Accounts Manager

**Labels**: `enhancement`, `ui-integration`, `phase-1b`, `priority-high`, `finance`, `accounting`
**Milestone**: Sprint 36-37
**Story Points**: 8

**Description**:
As an Accountant, I want to manage the chart of accounts through the UI, so that I can configure account structure without developer assistance.

**Backend APIs Available**:
- `GET /api/finance/accounts` - List all accounts
- `POST /api/finance/accounts` - Create account
- `GET /api/finance/accounts/:id` - Get account details
- `PUT /api/finance/accounts/:id` - Update account
- `DELETE /api/finance/accounts/:id` - Delete account

**Database Schema**:
- Table: `chart_of_accounts`
- Fields: id, code, name, type, category, parent_id, normal_balance, is_active

**Acceptance Criteria**:

**Tree View**:
- [ ] Accounts displayed in hierarchical tree structure
- [ ] Grouped by account type (Assets, Liabilities, etc.)
- [ ] Parent accounts expandable/collapsible
- [ ] Account code formatted consistently
- [ ] Current balance shown for accounts with transactions
- [ ] Search filters tree in real-time
- [ ] Filter by account type

**Account Creation**:
- [ ] Code input validates format (numeric, 4+ digits)
- [ ] Code uniqueness validated on blur
- [ ] Type selection auto-suggests normal balance
- [ ] Category dropdown filtered by selected type
- [ ] Parent account selector shows hierarchy
- [ ] Can create root or child accounts
- [ ] Form validation shows errors immediately

**Account Editing**:
- [ ] Edit preserves code if has transactions
- [ ] Edit allows changing parent if no children
- [ ] Hierarchy updates immediately

**Account Deletion**:
- [ ] Cannot delete account with transactions
- [ ] Cannot delete account with children
- [ ] Confirmation dialog before deletion
- [ ] Soft delete preferred (mark inactive)

**Bulk Import**:
- [ ] CSV upload with template download
- [ ] Validation preview before import
- [ ] Import creates accounts with hierarchy

**Component Hierarchy**:
```
ChartOfAccountsPage
├── AccountsToolbar (CreateButton, ImportButton, Filters)
├── AccountsTreeView
│   └── AccountNode × N (recursive)
└── AccountModal (Create/Edit form)
```

**Dependencies**:
- Design: Tree view component design
- Feature Flag: `enableChartOfAccountsManager`
- Permissions: `finance:accounts:manage`

**Technical Notes**:
- Use `react-arborist` or similar for tree view
- Implement drag-and-drop for reparenting (optional Phase 2)
- Code formatting: 4-digit minimum, pad with zeros
- Virtual scrolling if 1000+ accounts

**Test Coverage**:
- E2E tests defined in `audit/e2e-test-plan.md` - Test Suite 6 (Tests 6.1-6.7)

**Effort Estimate**: 7-9 days
- Tree view component: 3 days
- Account CRUD forms: 2 days
- Validation logic: 1 day
- Bulk import: 1.5 days
- Testing: 1.5 days

**Related Issues**: #TBD (Journal Entry Editor), #TBD (Invoice Approval)

---

## Issue #7: [FEATURE] CRM AI Intelligence Panel

**Labels**: `enhancement`, `ui-integration`, `phase-1b`, `priority-high`, `crm`, `ai`, `quick-win`
**Milestone**: Sprint 37
**Story Points**: 5

**Description**:
As a Sales Representative, I want to see AI-generated insights and recommendations for leads, so that I can prioritize effectively and take the best next actions.

**Backend APIs Available**:
- AI fields already exist in database
- Enhance existing `GET /api/crm/leads/:id` to return AI fields

**Database Schema (Already Exists)**:
- `leads`: ai_qualification_score, ai_qualification_summary, ai_next_best_action, ai_predicted_value, ai_close_probability
- `companies`: ai_summary, ai_pain_points, ai_icp_score
- `conversations`: ai_summary, ai_sentiment, ai_objections, ai_commitments

**Acceptance Criteria**:

**Qualification Score**:
- [ ] Score displayed as radial meter (0-100)
- [ ] Score color-coded: 0-30 red, 31-70 yellow, 71-100 green
- [ ] AI explanation shown below score
- [ ] Score updates when lead data changes

**Next Best Action**:
- [ ] Action displayed prominently (large card)
- [ ] Action is clickable (opens relevant interface)
- [ ] User can dismiss action
- [ ] New action generated after dismissal

**Predicted Value & Probability**:
- [ ] Value formatted as currency
- [ ] Confidence indicator visible
- [ ] Probability displayed as percentage meter
- [ ] Estimated close date shown
- [ ] Key factors listed

**ICP Score**:
- [ ] Company ICP score displayed
- [ ] Match reasons shown
- [ ] Pain points listed

**Conversation Insights**:
- [ ] Latest sentiment badge (color-coded)
- [ ] Key objections listed
- [ ] Commitments highlighted
- [ ] AI summary of context

**General**:
- [ ] Panel visible on all lead detail pages
- [ ] Panel collapsible/expandable
- [ ] Loading states while AI data fetches
- [ ] Graceful handling if AI data unavailable
- [ ] Panel loads with page (<1s total)

**Component Hierarchy**:
```
LeadDetailPage (existing)
└── AIInsightsPanel (NEW - sidebar)
    ├── QualificationScoreCard
    ├── NextBestActionCard
    ├── PredictedValueCard
    ├── CloseProbabilityCard
    ├── CompanyICPScoreCard
    └── ConversationInsightsCard
```

**Dependencies**:
- Design: AI insights panel mockups
- Backend: Ensure AI fields returned in API
- Feature Flag: `enableAIInsights`

**Technical Notes**:
- This is a **QUICK WIN** - mostly UI work, backend ready
- Use Recharts for score meters
- Cache AI scores for 5 minutes (React Query)
- Panel should be a reusable component for deals/contacts too

**Test Coverage**:
- E2E tests defined in `audit/e2e-test-plan.md` - Test Suite 7 (Tests 7.1-7.6)

**Effort Estimate**: 4-5 days
- Panel layout & components: 2 days
- Data integration: 1 day
- Interactive actions: 1 day
- Testing: 1 day

**Related Issues**: #TBD (Lead Pipeline), #TBD (Data Quality)

---

# Phase 2 Issues (Sprint 38-40)

## Issue #8: [FEATURE] Journal Entry Editor (Enhanced)

**Labels**: `enhancement`, `ui-integration`, `phase-2`, `priority-high`, `finance`, `accounting`
**Milestone**: Sprint 38
**Story Points**: 8

**Description**:
As an Accountant, I want to create complex journal entries with multiple debit and credit lines, so that I can record any transaction accurately in the double-entry accounting system.

**Backend APIs Available**:
- `POST /api/finance/journal-entries` - Create entry with multiple lines
- `GET /api/finance/journal-entries` - List all entries with pagination
- `GET /api/finance/journal-entries/:id` - Get single entry with lines
- `PUT /api/finance/journal-entries/:id` - Update entry (if not posted)
- `POST /api/finance/journal-entries/:id/post` - Post entry to ledger (finalize)
- `DELETE /api/finance/journal-entries/:id` - Delete unposted entry

**Database Schema**:
- Tables: `journal_entries`, `journal_lines`
- Fields:
  - journal_entries: id, entry_number, date, description, reference, status (DRAFT/POSTED), business_id
  - journal_lines: id, entry_id, account_id, description, debit_amount, credit_amount, line_number

**Acceptance Criteria**:

**Entry Creation**:
- [ ] Accountant can create journal entry with entry date and reference number
- [ ] Entry number auto-generated sequentially
- [ ] Description field supports rich text (optional formatting)
- [ ] Can add unlimited journal lines (minimum 2 required)

**Line Management**:
- [ ] Each line has account selector (searchable dropdown from COA)
- [ ] Each line has description field
- [ ] Each line has debit OR credit amount (not both)
- [ ] Can add new line with "Add Line" button
- [ ] Can remove line with "Remove" button (except last 2 lines)
- [ ] Lines can be reordered with drag-and-drop

**Balancing Validation**:
- [ ] Total debits calculated in real-time
- [ ] Total credits calculated in real-time
- [ ] Balance indicator shows difference (debits - credits)
- [ ] Balance indicator color-coded: Green if balanced (0), Red if unbalanced
- [ ] "Post" button disabled if entry unbalanced
- [ ] "Save as Draft" button always enabled (allows saving unbalanced)

**Posting**:
- [ ] "Post" button finalizes entry and writes to ledger
- [ ] Posted entries become read-only
- [ ] Posted entries show "POSTED" badge
- [ ] Confirmation dialog before posting
- [ ] Posting creates corresponding ledger_entries records

**Draft Management**:
- [ ] Can save entry as DRAFT without posting
- [ ] Drafts can be edited later
- [ ] Drafts visible in entry list with "DRAFT" badge
- [ ] Can delete drafts (posted entries cannot be deleted)

**Entry List**:
- [ ] Table shows all entries with pagination (50 per page)
- [ ] Filter by status (All, Draft, Posted)
- [ ] Filter by date range
- [ ] Search by entry number, description, account name
- [ ] Sort by date, entry number, amount

**Component Hierarchy**:
```
JournalEntriesPage
├── EntriesToolbar (CreateButton, Filters, Search)
├── EntriesTable
│   └── EntryRow × N (entry number, date, description, status, amount)
└── JournalEntryModal (Create/Edit)
    ├── EntryHeader (entry number, date, reference)
    ├── EntryDescription
    ├── JournalLinesTable
    │   └── JournalLineRow × N
    │       ├── AccountSelect (searchable)
    │       ├── LineDescription
    │       ├── DebitAmountInput
    │       ├── CreditAmountInput
    │       ├── DragHandle (for reordering)
    │       └── RemoveButton
    ├── AddLineButton
    ├── BalanceSummary (total debits, credits, balance)
    └── FormActions (SaveDraft, Post, Cancel)
```

**Dependencies**:
- Design: Journal entry form mockups
- Feature Flag: `enableJournalEntryEditor`
- Permissions: `finance:journal:create`, `finance:journal:post`
- Chart of Accounts: Must have accounts configured

**Technical Notes**:
- Use react-beautiful-dnd for line reordering
- Debounce balance calculation by 300ms
- Validate account selections against chart_of_accounts
- Auto-format amounts with thousand separators
- Support keyboard shortcuts: Ctrl+Enter to add line, Ctrl+S to save

**Test Coverage**:
- E2E tests defined in `audit/e2e-test-plan.md` - Test Suite 8 (Tests 8.1-8.6)

**Effort Estimate**: 6-8 days
- Entry form layout: 2 days
- Line management (add/remove/reorder): 2 days
- Balance validation: 1 day
- Posting logic: 1 day
- Entry list & filtering: 1 day
- Testing: 1.5 days

**Related Issues**: #TBD (Chart of Accounts), #TBD (Ledger Viewer)

---

## Issue #9: [FEATURE] Account Reconciliation Interface

**Labels**: `enhancement`, `ui-integration`, `phase-2`, `priority-high`, `finance`, `accounting`, `reconciliation`
**Milestone**: Sprint 38-39
**Story Points**: 8

**Description**:
As an Accountant, I want to reconcile bank accounts against bank statements, so that I can ensure our accounting records match actual bank activity and identify discrepancies.

**Backend APIs Available**:
- `POST /api/finance/reconciliation` - Create new reconciliation
- `GET /api/finance/reconciliation` - List reconciliations
- `GET /api/finance/reconciliation/:id` - Get reconciliation with transactions
- `POST /api/finance/reconciliation/:id/match` - Match transactions manually
- `POST /api/finance/reconciliation/:id/unmatch` - Unmatch transaction
- `POST /api/finance/reconciliation/:id/complete` - Mark reconciliation complete

**Database Schema**:
- Tables: `account_reconciliation`, `reconciliation_items`
- Fields:
  - account_reconciliation: id, account_id, statement_date, statement_balance, opening_balance, closing_balance, status
  - reconciliation_items: id, reconciliation_id, transaction_id, matched, match_type (AUTO/MANUAL)

**Acceptance Criteria**:

**Reconciliation Setup**:
- [ ] Start new reconciliation by selecting bank account
- [ ] Enter statement date and ending balance
- [ ] System loads opening balance from previous reconciliation (or account balance)
- [ ] System loads unreconciled transactions automatically

**Transaction Matching**:
- [ ] Two-panel view: "Unmatched Transactions" vs "Statement Transactions"
- [ ] Unmatched transactions from accounting system on left
- [ ] Statement transactions (uploaded CSV or manual entry) on right
- [ ] Auto-match by amount and date (within 3-day window)
- [ ] Manual match by drag-and-drop or click-to-match
- [ ] Matched transactions move to "Matched" section
- [ ] Matched transactions show green checkmark
- [ ] Can unmatch transaction with "Unmatch" button

**Discrepancy Resolution**:
- [ ] Calculate difference: (Opening Balance + Credits - Debits) vs Statement Balance
- [ ] Difference shown prominently (red if non-zero, green if zero)
- [ ] Show list of unmatched transactions with amounts
- [ ] Can create journal entry for missing transactions
- [ ] Can mark transaction as cleared without match (with notes)

**Reconciliation Completion**:
- [ ] "Complete Reconciliation" button enabled only when balanced
- [ ] Confirmation dialog shows final summary before completing
- [ ] Completed reconciliations become read-only
- [ ] Completed reconciliations have "COMPLETED" badge
- [ ] Completion date recorded

**Reconciliation History**:
- [ ] Table shows all past reconciliations
- [ ] Filter by account, date range, status
- [ ] Can view details of completed reconciliations
- [ ] Export reconciliation report to PDF

**Statement Import**:
- [ ] Upload CSV bank statement
- [ ] CSV mapping wizard (map columns to fields)
- [ ] Preview mapped transactions before import
- [ ] Import creates statement transactions

**Component Hierarchy**:
```
ReconciliationPage
├── ReconciliationToolbar (AccountSelect, StartNewButton, HistoryButton)
├── ReconciliationSetup (if new)
│   ├── StatementDatePicker
│   ├── StatementBalanceInput
│   ├── OpeningBalanceDisplay (read-only)
│   └── StartButton
└── ReconciliationWorkspace (if active)
    ├── ReconciliationHeader (account, period, difference)
    ├── DifferenceAlert (if unbalanced)
    ├── MatchingPanel
    │   ├── UnmatchedTransactionsTable (left)
    │   ├── StatementTransactionsTable (right)
    │   └── MatchedTransactionsTable (bottom)
    ├── DiscrepancyTools
    │   ├── CreateJournalEntryButton
    │   ├── MarkClearedButton
    │   └── AddNoteButton
    └── ReconciliationActions (SaveProgress, Complete, Cancel)
```

**Dependencies**:
- Design: Reconciliation interface mockups with dual-panel layout
- Feature Flag: `enableReconciliation`
- Permissions: `finance:reconciliation:manage`
- CSV Parser: Library for statement imports

**Technical Notes**:
- Use react-dnd for drag-and-drop matching
- Auto-match algorithm: exact amount match within ±3 days
- Support CSV formats from major banks (template library)
- Store reconciliation progress (can pause and resume)
- Optimistic UI updates for matching/unmatching

**Test Coverage**:
- E2E tests defined in `audit/e2e-test-plan.md` - Test Suite 9 (Tests 9.1-9.5)

**Effort Estimate**: 8-10 days
- Reconciliation setup flow: 1 day
- Dual-panel matching UI: 3 days
- Auto-match algorithm: 1 day
- CSV import: 2 days
- Discrepancy resolution: 1 day
- Completion workflow: 1 day
- Testing: 2 days

**Related Issues**: #TBD (Journal Entry Editor), #TBD (Chart of Accounts)

---

## Issue #10: [FEATURE] CRM Data Quality Dashboard

**Labels**: `enhancement`, `ui-integration`, `phase-2`, `priority-medium`, `crm`, `data-quality`
**Milestone**: Sprint 39
**Story Points**: 8

**Description**:
As a CRM Administrator, I want to identify and fix data quality issues like duplicates and incomplete records, so that the CRM database remains clean, accurate, and trustworthy.

**Backend APIs Available**:
- `POST /api/crm/data-quality/duplicates/find` - Find duplicate records
- `POST /api/crm/data-quality/duplicates/merge` - Merge duplicate records
- `POST /api/crm/data-quality/validate` - Validate entity data
- `POST /api/crm/data-quality/auto-fix` - Auto-fix common issues
- `GET /api/crm/data-quality/stats` - Get data quality statistics

**Database Schema**:
Backend already implements validation rules and duplicate detection algorithms

**Acceptance Criteria**:

**Dashboard Overview**:
- [ ] Data quality score displayed prominently (0-100)
- [ ] Score color-coded: 0-50 red, 51-80 yellow, 81-100 green
- [ ] Score breakdown by category (duplicates, incomplete, invalid)
- [ ] Trend chart shows quality score over time (last 30 days)
- [ ] Issue count by type (duplicates, missing fields, invalid data)

**Duplicate Detection**:
- [ ] "Find Duplicates" button scans database
- [ ] Shows potential duplicates grouped by similarity
- [ ] Each group shows matched records side-by-side
- [ ] Similarity score displayed (0-100%)
- [ ] Can review duplicates one-by-one or bulk select
- [ ] Preview merge shows which fields will be kept/discarded
- [ ] Can merge duplicates with confirmation

**Incomplete Records**:
- [ ] Table shows records with missing critical fields
- [ ] Filter by record type (leads, contacts, companies)
- [ ] Sort by completeness score
- [ ] Click record opens edit form with missing fields highlighted
- [ ] Bulk complete: Apply data to multiple records at once

**Invalid Data**:
- [ ] Shows records with validation errors (invalid email, phone, etc.)
- [ ] Grouped by error type
- [ ] "Auto-Fix" button attempts automatic correction (format fixes)
- [ ] Shows preview of auto-fix changes before applying
- [ ] Manual correction interface for complex issues

**Bulk Operations**:
- [ ] Select multiple records with checkboxes
- [ ] Bulk merge duplicates
- [ ] Bulk delete invalid records (with confirmation)
- [ ] Bulk update missing fields
- [ ] Progress bar for long-running operations

**History & Audit**:
- [ ] View history of data quality operations
- [ ] See who merged what and when
- [ ] Undo capability for recent merges (within 30 days)

**Component Hierarchy**:
```
DataQualityPage
├── QualityScoreDashboard
│   ├── OverallScoreCard
│   ├── ScoreTrendChart
│   └── IssueBreakdown (duplicates, incomplete, invalid)
├── IssuesTabs
│   ├── DuplicatesTab
│   │   ├── FindDuplicatesButton
│   │   ├── DuplicateGroupsList
│   │   │   └── DuplicateGroup × N
│   │   │       ├── SimilarityScore
│   │   │       ├── RecordComparisonTable (side-by-side)
│   │   │       └── MergeButton
│   │   └── MergePreviewModal
│   ├── IncompleteTab
│   │   ├── IncompleteRecordsTable
│   │   │   └── RecordRow × N (completeness %, missing fields)
│   │   └── BulkCompleteButton
│   └── InvalidDataTab
│       ├── InvalidRecordsTable
│       │   └── RecordRow × N (error type, error message)
│       ├── AutoFixButton
│       └── ManualCorrectionModal
└── HistoryTab
    └── OperationsTimeline
```

**Dependencies**:
- Design: Data quality dashboard mockups
- Feature Flag: `enableDataQuality`
- Permissions: `crm:dataQuality:manage`
- Duplicate Detection: Fuzzy matching algorithm (backend already exists)

**Technical Notes**:
- Use web workers for client-side duplicate scoring (if needed)
- Stream large result sets to avoid UI freeze
- Implement undo stack for merge operations
- Cache data quality stats for 5 minutes
- Show estimated time for long-running scans

**Test Coverage**:
- E2E tests defined in `audit/e2e-test-plan.md` - Test Suite 10 (Tests 10.1-10.6)

**Effort Estimate**: 7-9 days
- Dashboard & scoring: 2 days
- Duplicate detection UI: 3 days
- Incomplete records management: 1.5 days
- Invalid data corrections: 1.5 days
- History & undo: 1 day
- Testing: 2 days

**Related Issues**: #TBD (CRM Data Enrichment), #TBD (Leads Management)

---

## Issue #11: [FEATURE] CRM Data Enrichment Interface

**Labels**: `enhancement`, `ui-integration`, `phase-2`, `priority-medium`, `crm`, `ai`, `enrichment`
**Milestone**: Sprint 39
**Story Points**: 5

**Description**:
As a Sales Representative, I want to enrich lead and company data with external information, so that I have comprehensive context without manual research.

**Backend APIs Available**:
- `POST /api/crm/enrichment/enrich` - Enrich single entity
- `POST /api/crm/enrichment/batch` - Enrich multiple entities
- `GET /api/crm/enrichment/status/:jobId` - Check enrichment job status
- `GET /api/crm/enrichment/suggestions` - Get enrichment suggestions

**Database Schema**:
- CRM tables already support enriched fields
- Enrichment metadata stored in JSON columns

**Acceptance Criteria**:

**Single Enrichment**:
- [ ] "Enrich" button visible on lead/contact/company detail pages
- [ ] Click opens enrichment preview modal
- [ ] Shows available data sources (LinkedIn, Clearbit, etc.)
- [ ] Preview shows data before accepting
- [ ] User can select which fields to merge
- [ ] Enrichment completes within 5 seconds
- [ ] Enriched fields marked with badge/icon

**Batch Enrichment**:
- [ ] Bulk enrich from leads/contacts list page
- [ ] Select multiple records with checkboxes
- [ ] "Enrich Selected" button starts batch job
- [ ] Progress bar shows completion percentage
- [ ] Email notification when batch completes
- [ ] Results summary shows success/failure count

**Enrichment Suggestions**:
- [ ] Dashboard shows "Recommended for Enrichment"
- [ ] Prioritizes incomplete or stale records
- [ ] Shows expected data gain (e.g., "Will add job title, company size")
- [ ] One-click enrich from suggestions list

**Auto-Enrichment**:
- [ ] Admin can enable auto-enrichment rules
- [ ] Rule builder: "When new lead created, auto-enrich if domain detected"
- [ ] Toggle auto-enrich on/off per data source
- [ ] Cost tracking for paid enrichment APIs

**Enrichment History**:
- [ ] View enrichment history per record
- [ ] See when data was enriched and from which source
- [ ] Revert enrichment if data incorrect
- [ ] Re-enrich button to refresh stale data

**Component Hierarchy**:
```
EnrichmentInterface
├── EnrichButton (on detail pages)
├── EnrichmentModal
│   ├── DataSourceSelection
│   ├── EnrichmentPreview (before/after comparison)
│   ├── FieldMergeOptions (checkboxes for each field)
│   └── ConfirmEnrichButton
├── BatchEnrichmentModal
│   ├── RecordSelection (count, filters)
│   ├── DataSourceSelection
│   ├── ProgressBar
│   └── ResultsSummary
└── EnrichmentSuggestions (dashboard widget)
    ├── SuggestionsList
    │   └── SuggestionCard × N (record, expected gain, enrich button)
    └── AutoEnrichmentRules (admin settings)
```

**Dependencies**:
- Design: Enrichment modal mockups
- Feature Flag: `enableDataEnrichment`
- Permissions: `crm:enrichment:use`
- External APIs: Clearbit, LinkedIn Sales Navigator, etc.

**Technical Notes**:
- Handle API rate limits gracefully (queue system)
- Cache enrichment results for 30 days
- Show cost estimate before enriching (if paid API)
- Graceful degradation if enrichment source fails
- Optimistic UI updates

**Test Coverage**:
- E2E tests defined in `audit/e2e-test-plan.md` - Test Suite 11 (Tests 11.1-11.4)

**Effort Estimate**: 4-5 days
- Single enrichment UI: 1 day
- Batch enrichment: 1.5 days
- Enrichment suggestions: 1 day
- History & revert: 0.5 days
- Testing: 1 day

**Related Issues**: #TBD (Data Quality), #TBD (AI Intelligence Panel)

---

## Issue #12: [FEATURE] Agent Performance Dashboard

**Labels**: `enhancement`, `ui-integration`, `phase-2`, `priority-medium`, `agents`, `ai`, `monitoring`
**Milestone**: Sprint 40
**Story Points**: 8

**Description**:
As a System Administrator, I want to monitor AI agent performance and activity, so that I can ensure agents are operating efficiently and identify issues proactively.

**Backend APIs Available**:
- `GET /api/agents/stats` - Get agent statistics
- `GET /api/agents/:id/metrics` - Get metrics for specific agent
- `GET /api/agents/:id/activity` - Get activity log for agent
- `GET /api/agents/:id/errors` - Get error log for agent
- `POST /api/agents/:id/restart` - Restart agent
- `POST /api/agents/:id/pause` - Pause agent
- `POST /api/agents/:id/resume` - Resume agent

**Database Schema**:
- Tables: `agents`, `agent_tasks`, `agent_metrics`, `agent_errors`

**Acceptance Criteria**:

**Agent Overview**:
- [ ] Dashboard shows all active agents with status indicators
- [ ] Agent cards show: name, type, status (Running/Paused/Error), uptime
- [ ] Health score per agent (0-100, based on success rate and response time)
- [ ] Total tasks completed today/this week
- [ ] Active agents count vs total agents count

**Performance Metrics**:
- [ ] Average response time chart (last 24 hours)
- [ ] Task success rate percentage
- [ ] Tasks completed vs failed (bar chart)
- [ ] Resource usage: API calls, tokens consumed
- [ ] Cost tracking (if applicable)

**Agent Activity Log**:
- [ ] Real-time activity stream shows agent actions
- [ ] Filter by agent type, date range, status
- [ ] Each activity shows timestamp, agent, task type, outcome
- [ ] Click activity opens detail view with full context
- [ ] Export activity log to CSV

**Error Monitoring**:
- [ ] Error count badge on agent cards (if errors > 0)
- [ ] Errors table shows recent failures
- [ ] Error details include stack trace, context, timestamp
- [ ] Group errors by type
- [ ] Mark errors as resolved
- [ ] Set up error alerts (email when error rate > threshold)

**Agent Controls**:
- [ ] Restart button restarts agent (with confirmation)
- [ ] Pause button pauses agent activity
- [ ] Resume button resumes paused agent
- [ ] Status changes reflect within 2 seconds
- [ ] Audit log records all control actions

**Capacity Planning**:
- [ ] Show current agent load vs capacity
- [ ] Recommend scaling when load > 80%
- [ ] Task queue depth indicator
- [ ] Average wait time for tasks

**Component Hierarchy**:
```
AgentDashboardPage
├── AgentOverview
│   ├── ActiveAgentsCount
│   ├── HealthScoreCard
│   └── TasksCompletedCard
├── AgentsGrid
│   └── AgentCard × N
│       ├── AgentName & Type
│       ├── StatusBadge (Running/Paused/Error)
│       ├── HealthScore
│       ├── TasksCompleted
│       ├── ErrorCount (if > 0)
│       └── ControlButtons (Restart, Pause, View Details)
├── PerformanceChartsSection
│   ├── ResponseTimeChart (line chart)
│   ├── SuccessRateChart (gauge)
│   └── TasksCompletedChart (bar chart)
├── ActivityLogSection
│   ├── ActivityFilters
│   └── ActivityTimeline
│       └── ActivityItem × N
└── ErrorsSection
    ├── ErrorsTable
    │   └── ErrorRow × N (agent, error type, timestamp, details)
    └── AlertSettings
```

**Dependencies**:
- Design: Agent dashboard mockups with charts
- Feature Flag: `enableAgentDashboard`
- Permissions: `agents:monitor`, `agents:control`
- Charts: Recharts or Chart.js library

**Technical Notes**:
- Use WebSocket for real-time activity updates
- Cache metrics for 30 seconds to reduce backend load
- Implement polling fallback if WebSocket unavailable
- Use virtual scrolling for activity log (react-window)
- Color coding: Green (healthy), Yellow (degraded), Red (error)

**Test Coverage**:
- E2E tests defined in `audit/e2e-test-plan.md` - Test Suite 12 (Tests 12.1-12.5)

**Effort Estimate**: 7-9 days
- Agent overview & grid: 2 days
- Performance charts: 2 days
- Activity log: 1.5 days
- Error monitoring: 1.5 days
- Agent controls: 1 day
- Testing: 2 days

**Related Issues**: #TBD (Agent Policies), #TBD (System Monitoring)

---

# Phase 3 Issues (Sprint 41-43)

## Issue #13: [FEATURE] Custom Report Builder

**Labels**: `enhancement`, `ui-integration`, `phase-3`, `priority-medium`, `finance`, `reporting`
**Milestone**: Sprint 41-42
**Story Points**: 13

**Description**:
As a Finance Manager, I want to build custom financial reports with drag-and-drop interface, so that I can create tailored reports without developer assistance.

**Backend APIs Available**:
- `POST /api/finance/reports` - Create report definition
- `GET /api/finance/reports` - List saved reports
- `GET /api/finance/reports/:id` - Get report definition
- `POST /api/finance/reports/:id/execute` - Execute report and get data
- `POST /api/finance/reports/:id/schedule` - Schedule recurring report
- `DELETE /api/finance/reports/:id` - Delete report

**Database Schema**:
- Tables: `custom_reports`, `report_schedules`, `report_executions`
- Report definition stored as JSON (columns, filters, grouping, formatting)

**Acceptance Criteria**:

**Report Builder Interface**:
- [ ] Drag-and-drop interface for selecting columns
- [ ] Available fields organized by category (General Ledger, Accounts Receivable, etc.)
- [ ] Can add calculated fields (formulas using existing fields)
- [ ] Filter builder with multiple conditions (AND/OR logic)
- [ ] Grouping and subtotals configuration
- [ ] Sort order configuration (multi-column)
- [ ] Date range selector with presets (This Month, Last Quarter, etc.)

**Report Preview**:
- [ ] Live preview updates as report configured
- [ ] Preview limited to 100 rows (full export available)
- [ ] Preview shows sample data with actual formatting
- [ ] Loading indicator while preview generates

**Report Formatting**:
- [ ] Column width adjustment
- [ ] Number formatting (currency, percentage, decimal places)
- [ ] Date formatting options
- [ ] Conditional formatting rules (highlight negative values, etc.)
- [ ] Header/footer customization
- [ ] Company logo option

**Report Saving**:
- [ ] Save report with name and description
- [ ] Organize reports into folders
- [ ] Share report with other users (permission-based)
- [ ] Mark report as favorite for quick access
- [ ] Version history for report changes

**Report Execution**:
- [ ] Run report on-demand
- [ ] Export to PDF, Excel, CSV
- [ ] Email report to recipients
- [ ] Schedule recurring reports (daily, weekly, monthly)
- [ ] Report execution history with download links

**Report Library**:
- [ ] Browse saved reports in library view
- [ ] Search reports by name, folder, creator
- [ ] Template reports provided (P&L, Balance Sheet, Cash Flow, AR Aging)
- [ ] Duplicate existing report as starting point
- [ ] Delete reports (with confirmation)

**Component Hierarchy**:
```
ReportBuilderPage
├── ReportLibrary (left sidebar)
│   ├── FolderTree
│   ├── ReportsList
│   │   └── ReportItem × N (name, creator, last run)
│   └── NewReportButton
└── ReportEditor (main area)
    ├── EditorToolbar (Save, Run, Schedule, Export)
    ├── FieldSelector (drag source)
    │   └── FieldCategory × N
    │       └── Field × N (draggable)
    ├── ReportCanvas (drop zone)
    │   ├── SelectedColumnsTable
    │   │   └── ColumnRow × N (field, alias, format, remove)
    │   ├── FilterBuilder
    │   │   └── FilterRow × N (field, operator, value)
    │   ├── GroupingSection
    │   └── SortingSection
    ├── FormattingPanel
    │   ├── NumberFormatting
    │   ├── ConditionalFormatting
    │   └── HeaderFooterEditor
    └── ReportPreview
        ├── PreviewTable (with sample data)
        └── RefreshButton
```

**Dependencies**:
- Design: Report builder interface mockups
- Feature Flag: `enableCustomReports`
- Permissions: `finance:reports:create`, `finance:reports:execute`
- Scheduler: Cloudflare Cron or similar for recurring reports

**Technical Notes**:
- Use react-dnd for drag-and-drop
- Report generation happens server-side (SQL queries)
- Cache report results for 5 minutes
- Support large reports (10K+ rows) with pagination
- Formula parser for calculated fields
- Export libraries: jsPDF for PDF, xlsx for Excel

**Test Coverage**:
- E2E tests defined in `audit/e2e-test-plan.md` - Test Suite 13 (Tests 13.1-13.7)

**Effort Estimate**: 10-12 days
- Report builder UI: 3 days
- Filter and grouping: 2 days
- Formatting options: 2 days
- Report execution & export: 2 days
- Scheduling: 1 day
- Testing: 2 days

**Related Issues**: #TBD (Dashboard), #TBD (Chart of Accounts)

---

## Issue #14: [FEATURE] Budget Management UI

**Labels**: `enhancement`, `ui-integration`, `phase-3`, `priority-medium`, `finance`, `budgeting`
**Milestone**: Sprint 42
**Story Points**: 8

**Description**:
As a Finance Manager, I want to create and manage budgets, so that I can plan financial targets and track variance against actuals.

**Backend APIs Available**:
- `POST /api/finance/budgets` - Create budget
- `GET /api/finance/budgets` - List budgets
- `GET /api/finance/budgets/:id` - Get budget with line items
- `PUT /api/finance/budgets/:id` - Update budget
- `POST /api/finance/budgets/:id/approve` - Approve budget
- `GET /api/finance/budgets/:id/variance` - Get budget vs actual variance report

**Database Schema**:
- Tables: `budgets`, `budget_lines`
- Fields: budget period, account_id, planned_amount, actual_amount, variance

**Acceptance Criteria**:

**Budget Creation**:
- [ ] Create budget for fiscal period (monthly, quarterly, annual)
- [ ] Select budget template (previous year, zero-based, incremental)
- [ ] Specify start and end date
- [ ] Name and description fields
- [ ] Status indicator (Draft, Approved, Active)

**Budget Line Items**:
- [ ] Add line items by account from chart of accounts
- [ ] Enter planned amounts per period (monthly breakdown for annual budget)
- [ ] Copy amounts from previous period
- [ ] Bulk entry: apply percentage increase across all accounts
- [ ] Filter accounts by type (Revenue, Expenses, etc.)
- [ ] Search accounts by code or name

**Budget Editing**:
- [ ] Edit planned amounts inline
- [ ] Add notes to line items
- [ ] Remove line items
- [ ] Lock/unlock budget for editing
- [ ] Save as draft (can edit later)
- [ ] Submit for approval

**Variance Analysis**:
- [ ] View actual vs budget by account
- [ ] Variance displayed as amount and percentage
- [ ] Color coding: Green (under budget), Red (over budget)
- [ ] Drill down to transaction level for variance explanation
- [ ] Filter by variance threshold (e.g., show only >10% variance)
- [ ] Export variance report to Excel/PDF

**Budget Approval**:
- [ ] Approval workflow (if configured)
- [ ] Approval history visible
- [ ] Approved budgets become read-only
- [ ] Can create new version from approved budget

**Budget Dashboard**:
- [ ] Summary cards: Total Revenue Budget, Total Expense Budget, Current Variance
- [ ] Chart: Budget vs Actual by month
- [ ] Top variances list (biggest over/under budget accounts)
- [ ] Budget utilization percentage (by category)

**Component Hierarchy**:
```
BudgetManagementPage
├── BudgetsToolbar (CreateButton, FilterDropdown)
├── BudgetsList
│   └── BudgetCard × N (name, period, status, variance %)
└── BudgetEditor (when selected)
    ├── BudgetHeader (name, period, status, approval button)
    ├── BudgetToolbar (Add Line, Bulk Update, Lock/Unlock)
    ├── BudgetLinesTable
    │   └── BudgetLine × N
    │       ├── AccountSelect
    │       ├── PlannedAmount (editable)
    │       ├── ActualAmount (read-only)
    │       ├── Variance (calculated)
    │       ├── Notes
    │       └── RemoveButton
    ├── BudgetSummary (total planned, actual, variance)
    └── VarianceAnalysisTab
        ├── VarianceChart
        └── VarianceTable (with drill-down)
```

**Dependencies**:
- Design: Budget editor mockups
- Feature Flag: `enableBudgeting`
- Permissions: `finance:budgets:manage`, `finance:budgets:approve`
- Chart of Accounts: Required for account selection

**Technical Notes**:
- Inline editing with debounce (500ms)
- Calculate variance in real-time
- Support multi-currency budgets
- Excel import/export for bulk editing
- Approval workflow reuses invoice approval system

**Test Coverage**:
- E2E tests defined in `audit/e2e-test-plan.md` - Test Suite 14 (Tests 14.1-14.5)

**Effort Estimate**: 6-8 days
- Budget creation & editing: 2 days
- Line items management: 2 days
- Variance analysis: 1.5 days
- Approval workflow: 1 day
- Dashboard & charts: 1 day
- Testing: 1.5 days

**Related Issues**: #TBD (Chart of Accounts), #TBD (Custom Reports)

---

## Issue #15: [FEATURE] Knowledge Base Interface

**Labels**: `enhancement`, `ui-integration`, `phase-3`, `priority-medium`, `knowledge`, `ai`
**Milestone**: Sprint 42
**Story Points**: 8

**Description**:
As a team member, I want to access and search the knowledge base, so that I can find answers to questions and leverage organizational knowledge.

**Backend APIs Available**:
- `POST /api/knowledge/articles` - Create article
- `GET /api/knowledge/articles` - List articles with search
- `GET /api/knowledge/articles/:id` - Get article content
- `PUT /api/knowledge/articles/:id` - Update article
- `DELETE /api/knowledge/articles/:id` - Delete article
- `POST /api/knowledge/search` - Full-text search with AI ranking
- `POST /api/knowledge/ask` - AI-powered Q&A

**Database Schema**:
- Table: `knowledge_articles`
- Fields: title, content (markdown), category, tags, author_id, view_count, helpful_votes, embedding (vector)

**Acceptance Criteria**:

**Article Browsing**:
- [ ] Browse articles by category
- [ ] Filter by tags
- [ ] Sort by relevance, date, popularity
- [ ] Article cards show title, summary, author, date
- [ ] View count and helpful votes visible

**Article Search**:
- [ ] Search bar with auto-complete
- [ ] Full-text search across title and content
- [ ] AI-powered semantic search (finds related concepts)
- [ ] Search results ranked by relevance
- [ ] Search highlights matching terms in results
- [ ] Filters: category, date range, author

**Article Viewer**:
- [ ] Markdown rendering with syntax highlighting
- [ ] Table of contents for long articles (auto-generated from headers)
- [ ] Related articles section (AI-suggested)
- [ ] Breadcrumb navigation
- [ ] Print and export to PDF options
- [ ] Share article link
- [ ] "Was this helpful?" feedback buttons

**Article Creation**:
- [ ] Rich markdown editor with preview
- [ ] Title and summary fields
- [ ] Category selection
- [ ] Tag input with auto-complete
- [ ] Upload images/attachments
- [ ] Save as draft or publish immediately
- [ ] Preview before publishing

**Article Editing**:
- [ ] Edit existing articles (permission-based)
- [ ] Version history with diff view
- [ ] Revert to previous version
- [ ] Approval workflow for published articles (optional)

**AI-Powered Q&A**:
- [ ] Ask questions in natural language
- [ ] AI generates answer from knowledge base articles
- [ ] Shows source articles with citations
- [ ] "Ask follow-up question" capability
- [ ] Save Q&A as new article (if not exists)

**Knowledge Dashboard**:
- [ ] Most viewed articles
- [ ] Recently updated articles
- [ ] Most helpful articles
- [ ] Articles needing review (outdated or low feedback)
- [ ] My contributions (articles created/edited)

**Component Hierarchy**:
```
KnowledgeBasePage
├── KnowledgeHeader (SearchBar, CreateArticleButton)
├── KnowledgeSidebar
│   ├── CategoryTree
│   ├── TagCloud
│   └── PopularArticles
└── KnowledgeContent
    ├── ArticlesList (browsing mode)
    │   └── ArticleCard × N
    ├── ArticleViewer (view mode)
    │   ├── ArticleHeader (title, author, date, actions)
    │   ├── ArticleContent (markdown rendered)
    │   ├── TableOfContents
    │   ├── RelatedArticles
    │   └── ArticleFeedback (helpful votes, comments)
    └── ArticleEditor (create/edit mode)
        ├── TitleInput
        ├── SummaryInput
        ├── MarkdownEditor (with preview)
        ├── CategorySelect
        ├── TagsInput
        ├── AttachmentsUpload
        └── EditorActions (SaveDraft, Publish, Cancel)
```

**Dependencies**:
- Design: Knowledge base interface mockups
- Feature Flag: `enableKnowledgeBase`
- Permissions: `knowledge:read`, `knowledge:create`, `knowledge:edit`
- AI: Embedding model for semantic search, LLM for Q&A
- Markdown: Markdown parser and renderer (marked.js, react-markdown)

**Technical Notes**:
- Use vector embeddings for semantic search
- Cache popular articles for faster load
- Lazy load article content (load on view)
- Image upload to R2 storage
- Implement rate limiting on AI Q&A (expensive operation)
- Markdown editor: react-markdown-editor-lite or similar

**Test Coverage**:
- E2E tests defined in `audit/e2e-test-plan.md` - Test Suite 15 (Tests 15.1-15.6)

**Effort Estimate**: 7-9 days
- Article browsing & search: 2 days
- Article viewer: 1 day
- Article editor: 2 days
- AI Q&A integration: 2 days
- Dashboard: 1 day
- Testing: 2 days

**Related Issues**: #TBD (AI System), #TBD (Document Management)

---

## Issue #16: [FEATURE] Workflow Visual Designer

**Labels**: `enhancement`, `ui-integration`, `phase-3`, `priority-medium`, `workflow`, `automation`
**Milestone**: Sprint 43
**Story Points**: 13

**Description**:
As a Business Analyst, I want to design workflows visually, so that I can automate business processes without coding.

**Backend APIs Available**:
- `POST /api/workflows` - Create workflow definition
- `GET /api/workflows` - List workflows
- `GET /api/workflows/:id` - Get workflow definition
- `PUT /api/workflows/:id` - Update workflow
- `POST /api/workflows/:id/activate` - Activate workflow
- `POST /api/workflows/:id/deactivate` - Deactivate workflow
- `GET /api/workflows/:id/executions` - Get execution history
- Backend workflow engine already exists (used for invoice approval)

**Database Schema**:
- Tables: `workflows`, `workflow_steps`, `workflow_executions`
- Workflow definition stored as JSON (nodes and edges)

**Acceptance Criteria**:

**Visual Canvas**:
- [ ] Drag-and-drop canvas for building workflows
- [ ] Zoom in/out, pan canvas
- [ ] Grid snapping for alignment
- [ ] Mini-map for large workflows
- [ ] Undo/redo capability

**Workflow Nodes**:
- [ ] Trigger nodes (On Record Created, On Schedule, On Webhook, Manual)
- [ ] Action nodes (Send Email, Create Record, Update Field, Call API, Run Agent)
- [ ] Condition nodes (If/Else, Switch)
- [ ] Loop nodes (For Each, While)
- [ ] Delay nodes (Wait For, Wait Until)
- [ ] End nodes (Success, Error)

**Node Configuration**:
- [ ] Click node opens configuration panel
- [ ] Each node type has specific settings
- [ ] Field mapping with drag-and-drop
- [ ] Expression builder for conditions (variables, operators, functions)
- [ ] Test node execution with sample data
- [ ] Validation shows errors on nodes

**Connections**:
- [ ] Draw connections between nodes
- [ ] Connection validation (ensure correct flow)
- [ ] Label connections (for conditional branches)
- [ ] Delete connections
- [ ] Auto-layout option for organizing nodes

**Workflow Testing**:
- [ ] Test workflow with sample input
- [ ] Step-by-step execution view (debugger)
- [ ] See variable values at each step
- [ ] Identify errors in execution
- [ ] Save test scenarios

**Workflow Activation**:
- [ ] Activate workflow (starts listening for triggers)
- [ ] Deactivate workflow (stops execution)
- [ ] Schedule workflow (cron-like)
- [ ] Status indicator (Active, Inactive, Error)

**Execution History**:
- [ ] View past workflow executions
- [ ] Filter by status (Success, Failed, Running)
- [ ] See execution timeline
- [ ] View input/output data for each step
- [ ] Retry failed executions
- [ ] Export execution log

**Workflow Library**:
- [ ] Browse saved workflows
- [ ] Template workflows (Invoice Approval, Lead Assignment, etc.)
- [ ] Duplicate workflow as starting point
- [ ] Organize workflows into folders
- [ ] Share workflows with team

**Component Hierarchy**:
```
WorkflowDesignerPage
├── WorkflowToolbar (Save, Test, Activate, Settings)
├── NodePalette (left sidebar)
│   ├── TriggerNodes
│   ├── ActionNodes
│   ├── ControlNodes
│   └── SearchNodes
├── WorkflowCanvas (react-flow or similar)
│   ├── CanvasToolbar (Zoom, Pan, Auto-layout)
│   ├── WorkflowNode × N (draggable, connectable)
│   │   ├── NodeIcon
│   │   ├── NodeLabel
│   │   ├── NodeStatus (validation)
│   │   └── NodePorts (input/output)
│   └── Connection × N (edges between nodes)
├── NodeConfigPanel (right sidebar)
│   ├── NodeTypeDisplay
│   ├── NodeSettings (specific to node type)
│   ├── FieldMapper
│   ├── ExpressionBuilder
│   └── TestNodeButton
└── ExecutionHistoryTab
    ├── ExecutionsList
    │   └── ExecutionRow × N (date, status, duration)
    └── ExecutionDetailModal
        ├── ExecutionTimeline
        ├── StepDetails (input/output per step)
        └── RetryButton
```

**Dependencies**:
- Design: Workflow designer mockups
- Feature Flag: `enableWorkflowDesigner`
- Permissions: `workflows:create`, `workflows:execute`
- Workflow Engine: Backend engine already exists
- Visual Library: react-flow or xyflow for canvas

**Technical Notes**:
- Use react-flow for visual workflow canvas
- Store workflow as JSON (nodes, edges, node configurations)
- Validate workflow before activation (no infinite loops, all required fields set)
- Execution happens asynchronously on backend
- Support for long-running workflows (hours/days)
- Expression evaluator for dynamic field mapping

**Test Coverage**:
- E2E tests defined in `audit/e2e-test-plan.md` - Test Suite 16 (Tests 16.1-16.6)

**Effort Estimate**: 10-12 days
- Visual canvas setup: 3 days
- Node types & configuration: 3 days
- Execution engine integration: 2 days
- Testing & debugging: 2 days
- Execution history: 1 day
- Testing: 2 days

**Related Issues**: #TBD (Invoice Approval Workflow), #TBD (Agents System)

---

## Issue #17: [FEATURE] Email Sequence Builder

**Labels**: `enhancement`, `ui-integration`, `phase-3`, `priority-medium`, `crm`, `marketing`, `automation`
**Milestone**: Sprint 43
**Story Points**: 8

**Description**:
As a Sales Manager, I want to create automated email sequences for lead nurturing, so that leads receive timely follow-ups without manual effort.

**Backend APIs Available**:
- `POST /api/crm/sequences` - Create email sequence
- `GET /api/crm/sequences` - List sequences
- `GET /api/crm/sequences/:id` - Get sequence definition
- `PUT /api/crm/sequences/:id` - Update sequence
- `POST /api/crm/sequences/:id/activate` - Activate sequence
- `POST /api/crm/sequences/:id/enroll` - Enroll lead in sequence
- `GET /api/crm/sequences/:id/enrollments` - Get enrollment status

**Database Schema**:
- Tables: `email_sequences`, `sequence_steps`, `sequence_enrollments`

**Acceptance Criteria**:

**Sequence Builder**:
- [ ] Create sequence with name and goal
- [ ] Add email steps to sequence
- [ ] Define delay between steps (days, hours)
- [ ] Drag-and-drop to reorder steps
- [ ] Preview sequence timeline
- [ ] Set sequence expiration (optional)

**Email Step Editor**:
- [ ] Subject line with variable insertion {{firstName}}, {{companyName}}
- [ ] Rich text email body editor
- [ ] Insert variables/merge tags
- [ ] Preview with sample data
- [ ] A/B test variant (optional)
- [ ] Attach files to email
- [ ] Add reply tracking

**Sequence Triggers**:
- [ ] Manual enrollment (add lead to sequence)
- [ ] Auto-enrollment rules (when lead matches criteria)
- [ ] Webhook trigger
- [ ] CRM stage change trigger

**Enrollment Management**:
- [ ] View all enrollments (active, completed, paused)
- [ ] See current step for each enrollment
- [ ] Manually advance/pause enrollment
- [ ] Unenroll lead from sequence
- [ ] Track email opens and clicks per enrollment

**Sequence Analytics**:
- [ ] Overall sequence performance (open rate, click rate, reply rate)
- [ ] Step-by-step breakdown (which emails perform best)
- [ ] Conversion tracking (enrollments that became opportunities)
- [ ] Comparison between sequences
- [ ] Export analytics to CSV

**Template Library**:
- [ ] Pre-built sequence templates (Onboarding, Re-engagement, etc.)
- [ ] Duplicate sequence as starting point
- [ ] Share sequences with team
- [ ] Save email step as reusable template

**Compliance**:
- [ ] Unsubscribe link automatically added
- [ ] Respect do-not-contact list
- [ ] Stop sequence if lead replies (optional)
- [ ] Track consent preferences

**Component Hierarchy**:
```
EmailSequencePage
├── SequencesToolbar (CreateButton, TemplatesButton)
├── SequencesList
│   └── SequenceCard × N (name, active enrollments, performance)
└── SequenceBuilder (when selected)
    ├── SequenceHeader (name, activate toggle, stats)
    ├── SequenceTimeline (visual)
    │   └── SequenceStep × N
    │       ├── StepNumber
    │       ├── DelayBadge (e.g., "3 days after previous")
    │       ├── EmailPreview (subject, snippet)
    │       ├── StepStats (open %, click %)
    │       └── EditButton
    ├── StepEditorModal
    │   ├── SubjectLineInput (with variable picker)
    │   ├── EmailBodyEditor (rich text)
    │   ├── DelayConfig (number input + unit select)
    │   ├── AdvancedSettings (A/B test, tracking)
    │   └── PreviewButton
    ├── EnrollmentTab
    │   ├── EnrollButton (manual)
    │   ├── AutoEnrollRules
    │   └── EnrollmentsList
    │       └── EnrollmentRow × N (lead, current step, status)
    └── AnalyticsTab
        ├── OverallStats (open %, click %, reply %)
        ├── StepPerformanceChart
        └── ConversionFunnel
```

**Dependencies**:
- Design: Sequence builder mockups
- Feature Flag: `enableEmailSequences`
- Permissions: `crm:sequences:create`, `crm:sequences:enroll`
- Email Service: SendGrid or similar (already integrated)
- Scheduler: For delayed emails

**Technical Notes**:
- Email templates use Handlebars for variables
- Respect email sending limits (rate limiting)
- Track opens via pixel, clicks via redirect links
- Store unsubscribes in separate table
- Queue system for email sending (Cloudflare Queues)
- React email editor: react-email-editor or similar

**Test Coverage**:
- E2E tests defined in `audit/e2e-test-plan.md` - Test Suite 17 (Tests 17.1-17.5)

**Effort Estimate**: 6-8 days
- Sequence builder UI: 2 days
- Email step editor: 2 days
- Enrollment management: 1.5 days
- Analytics dashboard: 1.5 days
- Testing: 2 days

**Related Issues**: #TBD (CRM Leads), #TBD (Email Templates)

---

# Phase 4 Issues (Backlog)

## Issue #18: [FEATURE] ABAC Admin UI

**Labels**: `enhancement`, `ui-integration`, `phase-4`, `priority-low`, `security`, `admin`
**Milestone**: Backlog
**Story Points**: 8

**Description**:
As a System Administrator, I want to manage Attribute-Based Access Control (ABAC) policies through a UI, so that I can configure fine-grained permissions without editing code.

**Backend APIs Available**:
- `GET /api/abac/policies` - List all ABAC policies
- `POST /api/abac/policies` - Create new policy
- `GET /api/abac/policies/:id` - Get policy details
- `PUT /api/abac/policies/:id` - Update policy
- `DELETE /api/abac/policies/:id` - Delete policy
- `POST /api/abac/test` - Test policy against user/resource
- Backend ABAC system already operational

**Database Schema**:
- Table: `abac_policies`
- Fields: resource_type, action, conditions (JSON), effect (ALLOW/DENY)

**Acceptance Criteria**:

**Policy Management**:
- [ ] View all ABAC policies in table
- [ ] Filter by resource type, action, effect
- [ ] Search policies by name or description
- [ ] Sort by created date, priority
- [ ] Toggle policy active/inactive

**Policy Creation**:
- [ ] Resource type dropdown (Invoice, Lead, Account, etc.)
- [ ] Action dropdown (create, read, update, delete, approve)
- [ ] Effect radio (Allow, Deny)
- [ ] Priority input (higher priority evaluated first)
- [ ] Conditions builder with visual interface
- [ ] Preview policy JSON before saving

**Conditions Builder**:
- [ ] Add attribute conditions (e.g., user.role equals "admin")
- [ ] Support operators: equals, not equals, in, not in, greater than, less than
- [ ] Combine conditions with AND/OR logic
- [ ] Nested condition groups
- [ ] Attribute selector shows available attributes (user, resource, environment)
- [ ] Validation prevents invalid attribute references

**Policy Testing**:
- [ ] Test interface: select user, resource, action
- [ ] Shows which policies match
- [ ] Shows final decision (Allow/Deny)
- [ ] Explains which policy was applied and why
- [ ] Test history saved for later reference

**Role Management**:
- [ ] View all roles (Admin, Manager, User, etc.)
- [ ] Create custom roles
- [ ] Assign users to roles
- [ ] Role hierarchy visualization
- [ ] Role inheritance settings

**Audit & Monitoring**:
- [ ] View policy usage statistics
- [ ] See which policies are most frequently triggered
- [ ] Identify unused policies
- [ ] Audit log of policy changes
- [ ] Who created/modified policies and when

**Component Hierarchy**:
```
ABACAdminPage
├── ABACToolbar (CreatePolicyButton, TestPolicyButton)
├── PoliciesTable
│   └── PolicyRow × N
│       ├── ResourceType
│       ├── Action
│       ├── Effect (badge)
│       ├── Priority
│       ├── ActiveToggle
│       └── ActionsMenu (Edit, Test, Delete)
└── PolicyEditorModal
    ├── PolicyForm
    │   ├── ResourceTypeSelect
    │   ├── ActionSelect
    │   ├── EffectRadio
    │   ├── PriorityInput
    │   └── ConditionsBuilder
    │       └── ConditionGroup (recursive)
    │           ├── AttributeSelect
    │           ├── OperatorSelect
    │           ├── ValueInput
    │           ├── LogicToggle (AND/OR)
    │           └── RemoveButton
    ├── PolicyPreview (JSON display)
    └── PolicyTester
        ├── UserSelect
        ├── ResourceSelect
        ├── ActionSelect
        ├── TestButton
        └── TestResult (decision, matched policies, explanation)
```

**Dependencies**:
- Design: ABAC admin interface mockups
- Feature Flag: `enableABACAdmin`
- Permissions: `system:abac:manage` (super admin only)
- Backend: ABAC engine already operational

**Technical Notes**:
- Policy engine uses attribute evaluation
- Test policy in sandbox (doesn't affect actual permissions)
- Real-time validation of attribute paths
- Syntax highlighting for JSON preview
- Export/import policies as JSON for backup

**Test Coverage**:
- E2E tests defined in `audit/e2e-test-plan.md` - Test Suite 18 (Tests 18.1-18.4)

**Effort Estimate**: 7-9 days
- Policy table & CRUD: 2 days
- Conditions builder: 3 days
- Policy tester: 1.5 days
- Role management: 1.5 days
- Testing: 2 days

**Related Issues**: #TBD (User Management), #TBD (Audit Log)

---

## Issue #19: [FEATURE] AI Audit Dashboard

**Labels**: `enhancement`, `ui-integration`, `phase-4`, `priority-low`, `ai`, `monitoring`, `audit`
**Milestone**: Backlog
**Story Points**: 5

**Description**:
As a Compliance Officer, I want to monitor AI agent activity and decisions, so that I can ensure AI operates ethically and within guidelines.

**Backend APIs Available**:
- `GET /api/ai/audit/logs` - Get AI activity logs
- `GET /api/ai/audit/decisions` - Get AI decision history
- `GET /api/ai/audit/stats` - Get AI usage statistics
- `POST /api/ai/audit/review` - Mark decision for human review
- AI agents already log all activities

**Database Schema**:
- Tables: `ai_audit_log`, `ai_decisions`
- Fields: agent_id, action, input, output, confidence, timestamp, reviewed

**Acceptance Criteria**:

**AI Activity Dashboard**:
- [ ] Total AI actions today/week/month
- [ ] Actions by agent type (pie chart)
- [ ] Most active agents
- [ ] Average confidence score
- [ ] Flagged decisions count

**Activity Log**:
- [ ] Real-time stream of AI activities
- [ ] Filter by agent type, date range, action type
- [ ] Search by keyword in input/output
- [ ] Each entry shows: timestamp, agent, action, confidence
- [ ] Click entry opens detail view

**AI Decision Review**:
- [ ] Shows AI decisions requiring human review
- [ ] Filter by confidence threshold (e.g., <70%)
- [ ] Decision details include input, reasoning, confidence
- [ ] Approve/reject decision
- [ ] Provide feedback to improve AI
- [ ] Decision history with outcomes

**Confidence Analysis**:
- [ ] Confidence distribution chart (histogram)
- [ ] Identify low-confidence patterns
- [ ] Trend analysis (confidence over time)
- [ ] Compare confidence by agent type
- [ ] Recommend retraining when confidence drops

**Bias Detection**:
- [ ] Analyze AI decisions for potential bias
- [ ] Compare outcomes across demographic groups
- [ ] Flag suspicious patterns
- [ ] Export bias report for review

**Token Usage Tracking**:
- [ ] Total tokens consumed (by agent, by model)
- [ ] Cost estimation
- [ ] Usage trends (daily/weekly)
- [ ] Budget alerts when exceeding threshold
- [ ] Most expensive operations identified

**Component Hierarchy**:
```
AIAuditDashboard
├── AuditOverview
│   ├── TotalActionsCard
│   ├── AvgConfidenceCard
│   ├── FlaggedDecisionsCard
│   └── TokenUsageCard
├── ActivityStreamSection
│   ├── ActivityFilters
│   └── ActivityLog
│       └── ActivityItem × N
│           ├── Timestamp
│           ├── AgentBadge
│           ├── ActionSummary
│           ├── ConfidenceBadge
│           └── ViewDetailsButton
├── DecisionReviewSection
│   ├── ReviewQueue
│   │   └── DecisionCard × N
│   │       ├── DecisionSummary
│   │       ├── Confidence
│   │       ├── Input/Output preview
│   │       └── ReviewButtons (Approve, Reject)
│   └── DecisionDetailModal
│       ├── FullInput
│       ├── AIReasoning
│       ├── Confidence breakdown
│       └── FeedbackForm
├── AnalyticsSection
│   ├── ConfidenceChart
│   ├── BiasDetectionPanel
│   └── TokenUsageChart
└── ExportButton (CSV, PDF report)
```

**Dependencies**:
- Design: AI audit dashboard mockups
- Feature Flag: `enableAIAudit`
- Permissions: `ai:audit:view`, `ai:decisions:review`
- Charts: Recharts or Chart.js

**Technical Notes**:
- Use WebSocket for real-time activity stream
- Cache stats for 1 minute to reduce load
- Implement pagination for large logs (100+ per page)
- Highlight low-confidence decisions (<70%) in red
- Export audit trail for compliance reporting

**Test Coverage**:
- E2E tests defined in `audit/e2e-test-plan.md` - Test Suite 19 (Tests 19.1-19.3)

**Effort Estimate**: 4-5 days
- Dashboard overview: 1 day
- Activity log & filtering: 1.5 days
- Decision review interface: 1 day
- Analytics & charts: 1 day
- Testing: 1 day

**Related Issues**: #TBD (Agent Dashboard), #TBD (Compliance Audit)

---

## Issue #20: [FEATURE] Custom Integrations Builder

**Labels**: `enhancement`, `ui-integration`, `phase-4`, `priority-low`, `integrations`, `workflow`, `advanced`
**Milestone**: Backlog
**Story Points**: 13

**Description**:
As a Technical Administrator, I want to create custom integrations with external systems, so that CoreFlow360 can connect to any third-party service without custom development.

**Backend APIs Available**:
- `POST /api/integrations/custom` - Create custom integration
- `GET /api/integrations/custom` - List integrations
- `GET /api/integrations/custom/:id` - Get integration definition
- `PUT /api/integrations/custom/:id` - Update integration
- `POST /api/integrations/custom/:id/test` - Test integration connection
- `POST /api/integrations/custom/:id/sync` - Trigger manual sync
- Backend supports OAuth, API keys, webhooks

**Database Schema**:
- Tables: `custom_integrations`, `integration_mappings`, `integration_sync_log`

**Acceptance Criteria**:

**Integration Creation**:
- [ ] Name and description fields
- [ ] Choose integration type (REST API, SOAP, GraphQL, Webhook)
- [ ] Configure authentication (API Key, OAuth 2.0, Basic Auth)
- [ ] Base URL configuration
- [ ] Request headers (custom headers, user-agent)
- [ ] Rate limiting settings

**API Endpoint Configuration**:
- [ ] Add multiple endpoints (Create, Read, Update, Delete)
- [ ] HTTP method selection (GET, POST, PUT, DELETE, PATCH)
- [ ] URL path with variable placeholders
- [ ] Request body template (JSON, XML)
- [ ] Response mapping (extract fields from response)
- [ ] Error handling configuration

**Field Mapping**:
- [ ] Map CoreFlow360 fields to external system fields
- [ ] Visual mapping interface (drag-and-drop)
- [ ] Data transformation rules (format conversions)
- [ ] Default values for unmapped fields
- [ ] Conditional mapping (if field X, then map to Y)

**Sync Configuration**:
- [ ] Choose sync direction (One-way, Two-way)
- [ ] Schedule recurring syncs (hourly, daily, etc.)
- [ ] Sync trigger options (On Record Create, On Update, Manual)
- [ ] Conflict resolution strategy (Newest Wins, Manual Review)
- [ ] Batch size configuration

**Testing & Debugging**:
- [ ] Test connection button (validates auth)
- [ ] Test individual endpoint with sample data
- [ ] See request/response in real-time
- [ ] Debug mode shows full HTTP traffic
- [ ] Save test scenarios for later

**Sync Monitoring**:
- [ ] View sync history (success, failure counts)
- [ ] See last sync timestamp
- [ ] Error log with details
- [ ] Retry failed syncs
- [ ] Export sync log to CSV

**OAuth Setup**:
- [ ] OAuth 2.0 authorization flow wizard
- [ ] Client ID and secret configuration
- [ ] Redirect URL auto-generated
- [ ] Token refresh automation
- [ ] Token expiry alerts

**Webhook Configuration**:
- [ ] Generate webhook URL
- [ ] Configure webhook secret for verification
- [ ] Define webhook payload parsing
- [ ] Test webhook with sample payload
- [ ] Webhook activity log

**Integration Library**:
- [ ] Pre-built integration templates (Salesforce, HubSpot, QuickBooks, etc.)
- [ ] Duplicate integration as starting point
- [ ] Share integrations with community (optional)
- [ ] Import/export integration definitions (JSON)

**Component Hierarchy**:
```
IntegrationsBuilderPage
├── IntegrationsToolbar (CreateButton, TemplatesButton)
├── IntegrationsList
│   └── IntegrationCard × N
│       ├── Name & Type
│       ├── Status (Active, Inactive, Error)
│       ├── LastSyncTime
│       └── ActionsMenu (Edit, Test, Sync, Delete)
└── IntegrationEditor
    ├── GeneralSettingsTab
    │   ├── NameInput
    │   ├── TypeSelect
    │   ├── BaseURLInput
    │   └── AuthenticationConfig
    │       ├── AuthTypeSelect
    │       ├── APIKeyInput (if API Key)
    │       └── OAuthWizard (if OAuth)
    ├── EndpointsTab
    │   ├── EndpointsList
    │   │   └── EndpointRow × N
    │   │       ├── Method & Path
    │   │       ├── RequestTemplate
    │   │       ├── ResponseMapping
    │   │       └── TestButton
    │   └── AddEndpointButton
    ├── MappingTab
    │   ├── FieldMappingCanvas (drag-and-drop)
    │   │   ├── SourceFields (CoreFlow360)
    │   │   ├── TargetFields (External)
    │   │   └── MappingLines
    │   └── TransformationRules
    ├── SyncTab
    │   ├── SyncDirectionSelect
    │   ├── SyncSchedule
    │   ├── ConflictResolution
    │   └── SyncHistory
    │       └── SyncLogRow × N
    └── TestingTab
        ├── TestConnectionButton
        ├── TestEndpointPanel
        ├── DebugConsole (request/response viewer)
        └── SavedTestScenarios
```

**Dependencies**:
- Design: Integrations builder mockups
- Feature Flag: `enableCustomIntegrations`
- Permissions: `integrations:create`, `integrations:manage`
- OAuth: OAuth 2.0 client library
- Scheduler: For recurring syncs

**Technical Notes**:
- Store integration definitions as JSON
- Support for custom headers, authentication tokens
- Implement retry logic with exponential backoff
- Rate limiting to respect external API limits
- Queue system for batch syncs (Cloudflare Queues)
- Encrypt sensitive credentials (API keys, tokens)

**Test Coverage**:
- E2E tests defined in `audit/e2e-test-plan.md` - Test Suite 20 (Tests 20.1-20.5)

**Effort Estimate**: 10-12 days
- Integration configuration UI: 3 days
- Field mapping interface: 3 days
- OAuth wizard: 2 days
- Sync engine integration: 2 days
- Testing & debugging tools: 1 day
- Testing: 2 days

**Related Issues**: #TBD (Workflow Designer), #TBD (API Management)

---

## Import Instructions

### GitHub Issues
```bash
# For each issue above:
gh issue create \
  --title "[FEATURE] Compliance Guidelines Management" \
  --body "$(cat issue-body.md)" \
  --label "enhancement,ui-integration,phase-1a,priority-critical,compliance" \
  --milestone "Sprint 34"
```

### Linear
```bash
# For each issue above:
linear issue create \
  --title "[FEATURE] Compliance Guidelines Management" \
  --description "$(cat issue-body.md)" \
  --label "enhancement" \
  --label "ui-integration" \
  --project "Backend-UI Integration" \
  --estimate 8
```

### Jira (via CSV Import)
1. Export to CSV with columns: Summary, Description, Issue Type, Priority, Labels, Story Points
2. Import via Jira's CSV import tool

---

## Labels to Create

**Type Labels**:
- `enhancement` - New feature
- `ui-integration` - Backend-to-UI integration work
- `bug` - Bug fix
- `documentation` - Documentation update

**Phase Labels**:
- `phase-1a` - Sprint 34-35 (Critical)
- `phase-1b` - Sprint 36-37 (High Priority)
- `phase-2` - Sprint 38-40 (Core Features)
- `phase-3` - Sprint 41-43 (Completeness)
- `phase-4` - Backlog (Nice-to-Have)

**Priority Labels**:
- `priority-critical` - P0 - Blocks release
- `priority-high` - P1 - Important for release
- `priority-medium` - P2 - Should have
- `priority-low` - P3 - Nice to have

**Domain Labels**:
- `compliance` - Compliance features
- `finance` - Finance/accounting features
- `crm` - CRM features
- `ai` - AI/ML features
- `workflow` - Workflow features
- `reporting` - Reporting features

---

## Summary

**Total Issues**: 20 (All fully detailed and ready to import)
**Total Story Points**: ~150
**Estimated Timeline**: 6-8 sprints (12-16 weeks)

### Breakdown by Phase:
- **Phase 1A** (Sprint 34-35): Issues #1-4 | 34 SP | Compliance features
- **Phase 1B** (Sprint 36-37): Issues #5-7 | 26 SP | Finance & CRM high-priority
- **Phase 2** (Sprint 38-40): Issues #8-12 | 42 SP | Core features
- **Phase 3** (Sprint 41-43): Issues #13-17 | 50 SP | Advanced features
- **Phase 4** (Backlog): Issues #18-20 | 26 SP | Admin & power user tools

### Ready for Immediate Import:
All 20 issues now include:
- Complete descriptions with user stories
- Full acceptance criteria (10-30+ per issue)
- Detailed component hierarchies
- Backend API mappings
- Database schema references
- Technical implementation notes
- Effort estimates with day-by-day breakdown
- Test coverage references
- Dependencies and related issues

These issues can be imported directly into GitHub Issues, Linear, or Jira using the import instructions above.
