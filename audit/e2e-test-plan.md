# End-to-End Test Plan - Backend↔UI Integration

**Created**: 2025-10-22
**Test Framework**: Playwright + Vitest
**Test Environment**: Staging with seeded test data
**Coverage Target**: 95% of acceptance criteria

---

## Test Data Setup

### Required Test Data (Seed Script)
```sql
-- Test business
INSERT INTO businesses (id, name) VALUES ('test-biz-001', 'Test Enterprise Inc');

-- Test users
INSERT INTO users (id, business_id, email, role) VALUES
  ('admin-001', 'test-biz-001', 'admin@test.com', 'admin'),
  ('approver-001', 'test-biz-001', 'approver1@test.com', 'finance_manager'),
  ('approver-002', 'test-biz-001', 'approver2@test.com', 'director');

-- Test compliance data (guidelines, policies, violations)
-- Test finance data (accounts, invoices, customers)
-- Test CRM data (leads, companies, contacts)
```

---

# Phase 1A: Compliance Module Tests

## Test Suite 1: Compliance Guidelines Management

### Test 1.1: Create New Guideline (Happy Path)
**Story**: Story 1
**Priority**: P0 (Critical)

**Preconditions**:
- User logged in as admin
- Navigate to `/admin/compliance/guidelines`

**Steps**:
1. Click "Create Guideline" button
2. Fill form:
   - Title: "Data Privacy Compliance"
   - Description: "All customer data must be encrypted at rest"
   - Category: "Data Security"
   - Severity: "HIGH"
   - Effective Date: Tomorrow's date
3. Click "Save"

**Expected Results**:
- ✅ Form validates all fields before submission
- ✅ Success toast appears: "Guideline created successfully"
- ✅ Modal closes automatically
- ✅ New guideline appears in table within 2 seconds
- ✅ Guideline has correct title, category, severity badge

**API Assertions**:
- `POST /api/compliance/guidelines` returns 201
- Response contains created guideline with ID
- Database record exists with correct business_id

**Cleanup**: Delete created guideline

---

### Test 1.2: Guideline Validation Errors
**Story**: Story 1
**Priority**: P0

**Steps**:
1. Click "Create Guideline" button
2. Leave title empty
3. Click "Save"

**Expected Results**:
- ✅ Form does NOT submit
- ✅ Error message appears under title field: "Title is required"
- ✅ Error appears within 200ms
- ✅ Modal remains open

**Additional Validation Tests**:
- Title >200 characters shows error
- Description >5000 characters shows error
- Effective date in past shows warning

---

### Test 1.3: Edit Existing Guideline
**Story**: Story 1
**Priority**: P1

**Preconditions**: Guideline exists with ID 'guideline-001'

**Steps**:
1. Find guideline in table
2. Click actions menu → Edit
3. Change title to "Updated Privacy Compliance"
4. Click "Save"

**Expected Results**:
- ✅ Modal pre-fills with existing data
- ✅ Save updates guideline
- ✅ Table reflects changes immediately
- ✅ No duplicate entries created

**API Assertions**:
- `PUT /api/compliance/guidelines/guideline-001` returns 200
- GET request shows updated title

---

### Test 1.4: Delete Guideline with Confirmation
**Story**: Story 1
**Priority**: P1

**Steps**:
1. Find guideline in table
2. Click actions menu → Delete
3. Confirmation dialog appears
4. Click "Confirm Delete"

**Expected Results**:
- ✅ Confirmation dialog shows guideline title
- ✅ Guideline removed from table after confirmation
- ✅ Success toast: "Guideline deleted"

**API Assertions**:
- `DELETE /api/compliance/guidelines/:id` returns 204
- GET request confirms deletion

---

### Test 1.5: Pagination and Filtering
**Story**: Story 1
**Priority**: P2

**Preconditions**: 25 guidelines exist in database

**Steps**:
1. Navigate to guidelines page
2. Verify only 20 guidelines shown (page 1)
3. Click "Next Page"
4. Verify remaining 5 guidelines shown (page 2)
5. Filter by severity: "HIGH"
6. Verify filtered results

**Expected Results**:
- ✅ Pagination controls visible
- ✅ Page transitions smooth (<300ms)
- ✅ Filter reduces result set correctly
- ✅ URL updates with filter params

---

## Test Suite 2: Agent Policy Management

### Test 2.1: Create Policy with Multiple Rules
**Story**: Story 2
**Priority**: P0

**Steps**:
1. Navigate to `/admin/compliance/policies`
2. Click "Create Policy"
3. Enter name: "Customer Data Access Policy"
4. Add Rule 1:
   - Condition: "user_role"
   - Operator: "equals"
   - Value: "sales_rep"
5. Add Rule 2:
   - Condition: "data_sensitivity"
   - Operator: "less_than"
   - Value: "high"
6. Select agent types: ["CRM Agent", "Support Agent"]
7. Click "Save"

**Expected Results**:
- ✅ Rule builder allows adding multiple rules
- ✅ Policy preview shows JSON structure
- ✅ Policy card appears in grid
- ✅ Applied agent chips show correct types

**API Assertions**:
- `POST /api/compliance/policies` returns 201
- policy_rules JSON contains 2 rules
- agent_types array contains 2 agent types

---

### Test 2.2: Toggle Policy Active/Inactive
**Story**: Story 2
**Priority**: P1

**Preconditions**: Policy 'policy-001' exists, is_active=true

**Steps**:
1. Find policy card
2. Click active toggle switch
3. Confirm dialog

**Expected Results**:
- ✅ Toggle switches to "Inactive" state
- ✅ Policy card visual changes (grayed out)
- ✅ Toast: "Policy deactivated"

**API Assertions**:
- `PUT /api/compliance/policies/policy-001` with is_active=false
- Agents immediately stop enforcing policy

---

## Test Suite 3: Compliance Violations Tracker

### Test 3.1: View Violations Dashboard
**Story**: Story 3
**Priority**: P0

**Preconditions**: 15 violations in database (5 open, 8 resolved, 2 critical)

**Steps**:
1. Navigate to `/admin/compliance/violations`

**Expected Results**:
- ✅ Dashboard shows: Total: 15, Open: 5, Resolved: 8
- ✅ Severity chart displays correct distribution
- ✅ Table shows all 15 violations
- ✅ Critical violations highlighted in red
- ✅ Load time <1 second

---

### Test 3.2: Update Violation Status
**Story**: Story 3
**Priority**: P0

**Preconditions**: Open violation 'violation-001' exists

**Steps**:
1. Click violation row to open detail modal
2. Change status from "Open" to "In Progress"
3. Add resolution notes: "Investigating root cause"
4. Click "Save"

**Expected Results**:
- ✅ Status updates in table
- ✅ Timeline shows new status change event
- ✅ Toast: "Violation status updated"

**API Assertions**:
- `PUT /api/compliance/violations/violation-001` returns 200
- Status field updated in database
- Audit log records status change

---

### Test 3.3: Filter Violations by Severity
**Story**: Story 3
**Priority**: P2

**Steps**:
1. Open severity filter dropdown
2. Select "CRITICAL"
3. Apply filter

**Expected Results**:
- ✅ Table shows only CRITICAL violations
- ✅ Dashboard stats update to reflect filter
- ✅ Filter persists after page refresh (URL params)

---

### Test 3.4: Export Violations to CSV
**Story**: Story 3
**Priority**: P2

**Steps**:
1. Apply date range filter: Last 30 days
2. Click "Export CSV" button

**Expected Results**:
- ✅ CSV download initiates within 5 seconds
- ✅ CSV contains filtered violations only
- ✅ CSV headers match table columns

---

## Test Suite 4: Compliance Audit Trail

### Test 4.1: Search Audit Events
**Story**: Story 4
**Priority**: P0

**Preconditions**: 100 audit events in database

**Steps**:
1. Navigate to `/admin/compliance/audit-trail`
2. Enter search term: "guideline"
3. Wait for debounced search (300ms)

**Expected Results**:
- ✅ Timeline updates with matching events
- ✅ Search term highlighted in results
- ✅ Non-matching events filtered out

---

### Test 4.2: View Audit Event Details
**Story**: Story 4
**Priority**: P1

**Steps**:
1. Click "View Details" on any audit event
2. Modal opens

**Expected Results**:
- ✅ Modal shows complete event metadata (formatted JSON)
- ✅ IP address visible
- ✅ User agent visible
- ✅ Timestamp formatted correctly

---

---

# Phase 1B: Finance & CRM Tests

## Test Suite 5: Invoice Approval Workflow

### Test 5.1: View Approval Queue
**Story**: Story 5
**Priority**: P0

**Preconditions**:
- User 'approver-001' logged in
- 3 invoices pending approval at level 1
- 2 invoices pending approval at level 2 (not for this user)

**Steps**:
1. Navigate to `/finance/approvals`

**Expected Results**:
- ✅ Queue shows 3 invoices (only this user's level)
- ✅ "My Approvals" badge shows "3"
- ✅ Each card shows amount, customer, days waiting
- ✅ Load time <500ms

---

### Test 5.2: Approve Invoice (Single Level)
**Story**: Story 5
**Priority**: P0

**Preconditions**: Invoice 'inv-001' pending approval, only 1 level required

**Steps**:
1. Click "Review" on invoice card
2. Review invoice preview
3. Verify approval flow shows 1 level (current user)
4. Add comment: "Approved - all items verified"
5. Click "Approve" button

**Expected Results**:
- ✅ Confirmation dialog appears
- ✅ After confirming, invoice status changes to "APPROVED"
- ✅ Invoice removed from queue
- ✅ Toast: "Invoice approved successfully"

**API Assertions**:
- `POST /api/finance/invoice-approvals` creates approval record
- Invoice status updated to "APPROVED"
- Email sent to invoice creator

---

### Test 5.3: Approve Invoice (Multi-Level, First Level)
**Story**: Story 5
**Priority**: P0

**Preconditions**:
- Invoice 'inv-002' requires 2-level approval
- User is first approver

**Steps**:
1. Click "Review" on invoice card
2. Verify approval flow shows 2 levels
3. Verify level 1 highlighted (current level)
4. Verify level 2 shows "Pending" (next approver's name)
5. Click "Approve"

**Expected Results**:
- ✅ Level 1 shows checkmark and timestamp
- ✅ Level 2 becomes highlighted (active)
- ✅ Invoice status changes to "PENDING_APPROVAL" (still pending level 2)
- ✅ Invoice removed from current user's queue
- ✅ Email sent to level 2 approver

**API Assertions**:
- Approval record created for level 1
- Invoice status still "PENDING_APPROVAL"
- Next approver notified

---

### Test 5.4: Reject Invoice
**Story**: Story 5
**Priority**: P0

**Steps**:
1. Click "Review" on invoice
2. Click "Reject" button
3. Comments field becomes required
4. Enter: "Incorrect line items, needs revision"
5. Click "Submit Rejection"

**Expected Results**:
- ✅ Rejection confirmation dialog
- ✅ Invoice status changes to "REJECTED"
- ✅ Invoice removed from queue
- ✅ Email sent to invoice creator with rejection reason

**API Assertions**:
- `PUT /api/finance/invoice-approvals/:id` with status="REJECTED"
- Invoice status updated to "REJECTED"
- Comments saved in approval record

---

### Test 5.5: Create Approval Rule
**Story**: Story 5
**Priority**: P1

**Steps**:
1. Navigate to "Approval Rules" tab
2. Click "Create Rule"
3. Enter threshold: $5000
4. Select currency: USD
5. Add Level 1: Select "Finance Manager" (approver-001)
6. Add Level 2: Select "Director" (approver-002)
7. Click "Save"

**Expected Results**:
- ✅ Rule appears in rules table
- ✅ Rule shows: "$5,000 USD → 2 levels"
- ✅ Rule is active by default

**API Assertions**:
- `POST /api/finance/invoice-approval-rules` creates rule
- required_approvers JSON contains 2 levels

---

### Test 5.6: Approval Rule Auto-Assignment
**Story**: Story 5
**Priority**: P0

**Preconditions**: Approval rule exists: >$5000 requires 2 levels

**Steps**:
1. Create new invoice with total $6,500 (exceeds threshold)
2. Set invoice to "PENDING_APPROVAL" status
3. Check approval workflow

**Expected Results**:
- ✅ Invoice automatically assigned 2 approval levels
- ✅ Level 1 approver matches rule
- ✅ Level 2 approver matches rule
- ✅ Both approvers receive notification

**API Assertions**:
- Invoice approval levels created automatically
- Correct approvers assigned based on rule

---

## Test Suite 6: Chart of Accounts Manager

### Test 6.1: View Account Hierarchy
**Story**: Story 6
**Priority**: P0

**Preconditions**: 50 accounts exist with 3-level hierarchy

**Steps**:
1. Navigate to `/finance/accounts`

**Expected Results**:
- ✅ Accounts displayed in tree structure
- ✅ Grouped by type (Assets, Liabilities, etc.)
- ✅ Parent accounts have expand icons
- ✅ Child accounts indented visually
- ✅ Account codes formatted consistently
- ✅ Load time <1 second

---

### Test 6.2: Create Root Account
**Story**: Story 6
**Priority**: P0

**Steps**:
1. Click "Create Account" button
2. Fill form:
   - Code: 1000
   - Name: "Cash and Cash Equivalents"
   - Type: "ASSET"
   - Category: "CURRENT_ASSET"
   - Parent: (none)
   - Normal Balance: "Debit" (auto-selected)
3. Click "Save"

**Expected Results**:
- ✅ Account created and appears at top level under "Assets"
- ✅ Normal balance auto-selected based on type
- ✅ Toast: "Account created successfully"

**API Assertions**:
- `POST /api/finance/accounts` returns 201
- Account has no parent_id (null)
- Account code unique within business

---

### Test 6.3: Create Child Account
**Story**: Story 6
**Priority**: P0

**Preconditions**: Parent account exists (code: 1000, name: "Cash")

**Steps**:
1. Click actions menu on parent account → "Add Child Account"
2. Fill form:
   - Code: 1010
   - Name: "Checking Account - Bank of America"
   - Type: "ASSET" (inherited, read-only)
   - Category: "CURRENT_ASSET" (inherited)
   - Parent: "1000 - Cash and Cash Equivalents" (pre-selected)
3. Click "Save"

**Expected Results**:
- ✅ Child account appears nested under parent
- ✅ Hierarchy visually correct (indentation)
- ✅ Type and category inherited from parent

**API Assertions**:
- Account has parent_id = parent account ID
- Account code follows parent code pattern

---

### Test 6.4: Code Validation
**Story**: Story 6
**Priority**: P1

**Steps**:
1. Click "Create Account"
2. Enter code: "ABC" (non-numeric)
3. Tab to next field (blur event)

**Expected Results**:
- ✅ Error message: "Account code must be numeric"
- ✅ Error appears within 200ms
- ✅ Submit button disabled

**Additional Validation Tests**:
- Duplicate code shows: "Account code already exists"
- Code <4 digits shows: "Code must be at least 4 digits"

---

### Test 6.5: Delete Account (With Transactions)
**Story**: Story 6
**Priority**: P1

**Preconditions**: Account has 10 ledger transactions

**Steps**:
1. Click actions menu → Delete
2. Confirmation dialog appears

**Expected Results**:
- ✅ Error message: "Cannot delete account with existing transactions"
- ✅ Suggested action: "Mark as inactive instead?"
- ✅ Delete button disabled

---

### Test 6.6: Search Accounts
**Story**: Story 6
**Priority**: P2

**Steps**:
1. Enter search term: "cash"
2. Search filters tree in real-time

**Expected Results**:
- ✅ Tree filters to show only matching accounts
- ✅ Parent accounts remain visible if child matches
- ✅ No matches shows: "No accounts found"

---

### Test 6.7: Bulk Import Accounts (CSV)
**Story**: Story 6
**Priority**: P2

**Steps**:
1. Click "Import Accounts" button
2. Download CSV template
3. Upload populated CSV (10 accounts)
4. Review validation preview
5. Confirm import

**Expected Results**:
- ✅ Template download contains correct headers
- ✅ Validation shows errors/warnings before import
- ✅ Import creates all valid accounts
- ✅ Invalid rows skipped with error report

---

## Test Suite 7: CRM AI Intelligence Panel

### Test 7.1: View AI Insights on Lead Detail
**Story**: Story 7
**Priority**: P0

**Preconditions**:
- Lead 'lead-001' exists with AI scores populated
- User navigates to `/crm/leads/lead-001`

**Expected Results**:
- ✅ AI Insights Panel visible in sidebar
- ✅ Qualification score meter shows value (e.g., 85)
- ✅ Score color-coded (green for 71-100)
- ✅ AI explanation visible below score
- ✅ Next best action card prominent
- ✅ Predicted value shows currency amount
- ✅ Close probability meter visible
- ✅ ICP score meter visible (company data)
- ✅ Latest conversation sentiment badge visible
- ✅ All data loads within 1 second

---

### Test 7.2: Next Best Action Interaction
**Story**: Story 7
**Priority**: P0

**Steps**:
1. View lead detail with next best action: "Schedule follow-up call"
2. Click "Quick Action" button

**Expected Results**:
- ✅ Clicking action opens relevant interface (e.g., calendar scheduler)
- ✅ Action pre-fills with lead context
- ✅ User can complete action from modal

---

### Test 7.3: Dismiss Next Best Action
**Story**: Story 7
**Priority**: P1

**Steps**:
1. Click "Dismiss" button on next best action card

**Expected Results**:
- ✅ Confirmation dialog: "Mark this action as completed?"
- ✅ After confirming, action removed
- ✅ New action appears (or "No actions available")

**API Assertions**:
- Action marked as completed in database
- New action generated by AI (if applicable)

---

### Test 7.4: AI Insights Panel Collapse/Expand
**Story**: Story 7
**Priority**: P2

**Steps**:
1. Click collapse icon on panel header
2. Panel collapses to minimize space
3. Click expand icon
4. Panel expands again

**Expected Results**:
- ✅ Panel collapse animates smoothly
- ✅ Collapsed state shows icon only
- ✅ User preference persists (localStorage)

---

### Test 7.5: AI Data Loading States
**Story**: Story 7
**Priority**: P1

**Preconditions**: Simulate slow API response (3s delay)

**Steps**:
1. Navigate to lead detail page

**Expected Results**:
- ✅ Panel shows skeleton loaders while loading
- ✅ Individual cards load progressively (not all at once)
- ✅ No empty states or broken UI during load

---

### Test 7.6: Handle Missing AI Data Gracefully
**Story**: Story 7
**Priority**: P1

**Preconditions**: Lead has no AI scores (new lead, AI not yet run)

**Steps**:
1. Navigate to lead detail

**Expected Results**:
- ✅ Panel shows: "AI analysis in progress..."
- ✅ No broken UI or errors
- ✅ Option to "Request AI Analysis Now" (manual trigger)

---

---

# Cross-Cutting Tests

## Test Suite 8: Authentication & Permissions

### Test 8.1: Unauthorized Access Redirect
**Priority**: P0

**Steps**:
1. Logout
2. Navigate to `/admin/compliance/guidelines`

**Expected Results**:
- ✅ Redirect to login page
- ✅ After login, redirect back to intended page

---

### Test 8.2: Insufficient Permissions
**Priority**: P0

**Preconditions**: User logged in as "sales_rep" (not admin)

**Steps**:
1. Navigate to `/admin/compliance/guidelines`

**Expected Results**:
- ✅ 403 Forbidden page or permission denied message
- ✅ No data exposed

**API Assertions**:
- ABAC check fails for user role
- API returns 403

---

## Test Suite 9: Performance Tests

### Test 9.1: Large Dataset Performance
**Priority**: P1

**Preconditions**: 1000 guidelines in database

**Steps**:
1. Navigate to guidelines page

**Expected Results**:
- ✅ Initial load <2 seconds
- ✅ Pagination smooth (<300ms per page)
- ✅ Search/filter <500ms

---

### Test 9.2: Concurrent Approvals
**Priority**: P1

**Scenario**: Two approvers approve different invoices simultaneously

**Steps**:
1. Approver 1 approves invoice A
2. Approver 2 approves invoice B (within same second)

**Expected Results**:
- ✅ Both approvals process successfully
- ✅ No race conditions
- ✅ Both queues update correctly

---

## Test Suite 10: Regression Tests

### Test 10.1: Existing CRM Features Still Work
**Priority**: P0

**Tests**: Run existing CRM test suite after AI panel integration

**Expected Results**:
- ✅ All existing tests pass
- ✅ No performance degradation
- ✅ No visual regressions

---

### Test 10.2: Existing Finance Features Still Work
**Priority**: P0

**Tests**: Run existing finance test suite after new features

**Expected Results**:
- ✅ All existing tests pass
- ✅ Invoice creation still works
- ✅ Transaction recording still works

---

---

# Test Execution Plan

## Pre-Deployment Checklist
- [ ] All P0 tests pass
- [ ] All P1 tests pass (or documented exceptions)
- [ ] P2 tests executed (70%+ pass rate)
- [ ] Performance tests meet SLAs
- [ ] Accessibility tests pass (WCAG 2.1 AA)
- [ ] Cross-browser testing (Chrome, Firefox, Safari, Edge)
- [ ] Mobile responsive tests (iOS Safari, Chrome Android)
- [ ] Security tests (OWASP Top 10 checks)

## Continuous Integration
- Run P0 tests on every PR
- Run full suite nightly on staging
- Block merge if P0 tests fail

## Test Data Management
- Seed script creates consistent test data
- Cleanup script runs after each suite
- Isolated test database per environment

---

# Test Coverage Summary

## Phase 1A (Compliance)
- **Test Suites**: 4
- **Test Cases**: 18
- **Priority P0**: 12 tests
- **Priority P1**: 4 tests
- **Priority P2**: 2 tests

## Phase 1B (Finance & CRM)
- **Test Suites**: 3
- **Test Cases**: 20
- **Priority P0**: 13 tests
- **Priority P1**: 5 tests
- **Priority P2**: 2 tests

## Cross-Cutting
- **Test Suites**: 3
- **Test Cases**: 6
- **Priority P0**: 4 tests
- **Priority P1**: 2 tests

## Total
- **Test Suites**: 10
- **Test Cases**: 44
- **Estimated Execution Time**: ~4 hours (full suite)

---

**Test Plan Ready for Review**
**Next Step**: Set up Playwright test infrastructure and begin test implementation
