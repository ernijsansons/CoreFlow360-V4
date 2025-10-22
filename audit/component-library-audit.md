# Component Library Audit - UI Components Needed

**Created**: 2025-10-22
**Purpose**: Identify which UI components need to be built or enhanced for backend-to-UI integration
**Status**: Ready for Design Team Review

---

## Executive Summary

Based on the 20 user stories analyzed, we need **73 unique UI components** to complete the backend-to-UI integration. These components are categorized by complexity and reusability.

**Component Breakdown**:
- ✅ **18 components exist** in current design system (25%)
- 🟡 **22 components need enhancement** (30%)
- ❌ **33 new components required** (45%)

**Priority Levels**:
- **P0 (Critical)**: 15 components - Needed for Phase 1A/1B
- **P1 (High)**: 20 components - Needed for Phase 2
- **P2 (Medium)**: 25 components - Needed for Phase 3
- **P3 (Low)**: 13 components - Phase 4 backlog

---

## Component Inventory

### 1. Data Display Components

#### DataTable (Enhanced)
**Status**: 🟡 Exists, needs enhancement
**Priority**: P0
**Current State**: Basic table with sorting
**Required Enhancements**:
- Inline editing support
- Row selection (single, multiple)
- Expandable rows
- Virtual scrolling for 10K+ rows
- Column resizing and reordering
- Sticky headers
- Pagination with page size options
- Export to CSV/Excel
- Custom cell renderers
- Loading skeleton states

**Used In**: Guidelines Table, Policies Grid, Violations Table, Audit Trail, Journal Entries, etc. (15+ features)

**Design Priority**: **Critical** - Used everywhere
**Implementation Estimate**: 5 days (enhancement)

---

#### TreeView
**Status**: ❌ New component required
**Priority**: P0
**Description**: Hierarchical tree structure with expand/collapse
**Features Needed**:
- Recursive rendering
- Expand/collapse all
- Drag-and-drop for reordering (optional)
- Search/filter with highlighting
- Checkbox selection (tree-aware)
- Virtual scrolling for large trees
- Custom node renderers
- Keyboard navigation

**Used In**: Chart of Accounts, Knowledge Base categories, Folder structures

**Design Priority**: **Critical** - Needed for Phase 1B
**Implementation Estimate**: 4 days (new)

**Design Reference**: Similar to VSCode file tree or macOS Finder sidebar

---

#### MetricCard
**Status**: 🟡 Exists, needs enhancement
**Priority**: P0
**Current State**: Basic stat card
**Required Enhancements**:
- Trend indicators (up/down arrows, percentages)
- Sparkline mini-charts
- Comparison values (vs previous period)
- Color coding based on thresholds
- Loading states
- Click-to-drill-down action

**Used In**: Dashboards across all features (Compliance, Finance, CRM, Agents)

**Design Priority**: High
**Implementation Estimate**: 2 days (enhancement)

---

### 2. Form Components

#### RuleBuilder (Visual Query Builder)
**Status**: ❌ New component required
**Priority**: P0
**Description**: Visual interface for building conditional rules
**Features Needed**:
- Add/remove rule rows
- Field selector (searchable dropdown)
- Operator selector (equals, not equals, greater than, contains, etc.)
- Value input (adapts to field type)
- AND/OR logic toggles
- Nested groups (parentheses)
- Visual hierarchy indicators
- Validation with error highlighting
- JSON preview

**Used In**: Agent Policies, ABAC policies, Workflow conditions, Auto-enrichment rules, Report filters

**Design Priority**: **Critical** - Complex, reusable component
**Implementation Estimate**: 6 days (new)

**Design Reference**: Similar to Zapier filters or Airtable views

---

#### MarkdownEditor
**Status**: ❌ New component required
**Priority**: P1
**Description**: Rich markdown editor with preview
**Features Needed**:
- Split view (edit | preview)
- Toolbar with formatting buttons
- Syntax highlighting
- Image upload with drag-and-drop
- Auto-save draft
- Full-screen mode
- Keyboard shortcuts (Ctrl+B for bold, etc.)
- Table support
- Code block with language selection

**Used In**: Knowledge Base articles, Journal Entry descriptions, Notes fields

**Design Priority**: High
**Implementation Estimate**: 4 days (new)

**Recommended Library**: react-markdown-editor-lite or similar

---

#### FieldMapper
**Status**: ❌ New component required
**Priority**: P2
**Description**: Drag-and-drop field mapping interface
**Features Needed**:
- Two-panel layout (source fields | target fields)
- Drag-and-drop connections
- Visual connection lines
- One-to-one and one-to-many mapping
- Transformation rules per mapping
- Unmapped fields highlighted
- Auto-suggest matches
- Preview mapped data

**Used In**: Custom Integrations, Data Enrichment, Report Builder, CSV Import

**Design Priority**: Medium
**Implementation Estimate**: 5 days (new)

**Design Reference**: Similar to Zapier field mapping or Segment integrations

---

### 3. Workflow & Process Components

#### StepperWizard
**Status**: 🟡 Exists, needs enhancement
**Priority**: P0
**Current State**: Basic linear stepper
**Required Enhancements**:
- Non-linear navigation (jump to step)
- Conditional steps (skip if condition met)
- Step validation indicators
- Progress percentage
- Back/Next with auto-save
- Step completion checkmarks
- Mobile responsive (vertical on mobile)

**Used In**: Invoice Approval flow, Budget creation wizard, Integration setup, OAuth flow

**Design Priority**: High
**Implementation Estimate**: 3 days (enhancement)

---

#### Timeline
**Status**: 🟡 Exists, needs basic version
**Priority**: P0
**Current State**: Basic timeline
**Required Enhancements**:
- Collapsible time periods
- Item grouping by date
- Interactive items (click for details)
- Real-time updates (new items animate in)
- Filter controls
- Infinite scroll or pagination
- Status indicators (icons, colors)

**Used In**: Audit Trail, Violation lifecycle, Approval history, Agent activity log, Workflow execution history

**Design Priority**: High
**Implementation Estimate**: 3 days (enhancement)

---

#### WorkflowCanvas (Visual Flow Builder)
**Status**: ❌ New component required
**Priority**: P2
**Description**: Visual canvas for building workflows
**Features Needed**:
- Drag-and-drop nodes from palette
- Draw connections between nodes
- Zoom, pan, fit-to-screen
- Mini-map for large workflows
- Node configuration panel
- Validation (highlight errors)
- Auto-layout algorithm
- Grid snapping
- Undo/redo
- Export as image

**Used In**: Workflow Designer, Email Sequence builder (visual timeline)

**Design Priority**: Medium (Phase 3)
**Implementation Estimate**: 8 days (new) - Complex component

**Recommended Library**: react-flow or xyflow

---

### 4. Data Visualization Components

#### ChartCard
**Status**: 🟡 Exists, needs enhancement
**Priority**: P1
**Current State**: Basic chart wrapper
**Required Enhancements**:
- Support all chart types (line, bar, pie, area, scatter, gauge)
- Responsive sizing
- Interactive tooltips
- Legend with toggle
- Export as PNG/SVG
- No data state
- Loading state with skeleton
- Click to drill down

**Used In**: All dashboards (Compliance, Finance, Budget, Agent performance, Data Quality, etc.)

**Design Priority**: High
**Implementation Estimate**: 3 days (enhancement)

**Chart Library**: Recharts (already in project)

---

#### GaugeChart (Radial Progress)
**Status**: ❌ New component required
**Priority**: P0
**Description**: Radial gauge for displaying scores/percentages
**Features Needed**:
- Customizable ranges with colors
- Current value with label
- Optional min/max labels
- Animated transitions
- Threshold markers
- Responsive sizing

**Used In**: AI qualification score, ICP score, Health score, Data quality score, Budget utilization

**Design Priority**: High
**Implementation Estimate**: 2 days (new)

---

### 5. Modal & Overlay Components

#### Modal (Enhanced)
**Status**: 🟡 Exists, needs enhancement
**Priority**: P0
**Current State**: Basic modal
**Required Enhancements**:
- Size variants (sm, md, lg, xl, fullscreen)
- Draggable header
- Resizable
- Persistent (doesn't close on backdrop click) option
- Footer with primary/secondary actions
- Loading state
- Nested modals support
- Keyboard shortcuts (ESC to close)

**Used In**: All CRUD forms, Detail views, Confirmation dialogs (50+ instances)

**Design Priority**: **Critical**
**Implementation Estimate**: 3 days (enhancement)

---

#### Drawer (Slide-out Panel)
**Status**: 🟡 Exists, basic version
**Priority**: P1
**Current State**: Basic drawer
**Required Enhancements**:
- Position variants (left, right, top, bottom)
- Overlay or push mode
- Resizable width
- Nested drawers
- Header with close button
- Footer sticky actions
- Loading state

**Used In**: Filters panel, Configuration panels, Detail views, AI insights panel

**Design Priority**: High
**Implementation Estimate**: 2 days (enhancement)

---

#### ConfirmationDialog
**Status**: ✅ Exists
**Priority**: P0
**Current State**: Good, minor enhancements
**Minimal Enhancements**:
- Icon variants (warning, error, success, info)
- Checkbox for "Don't ask again"
- Custom button labels
- Async action support (shows loading on confirm)

**Used In**: Delete confirmations, Approval actions, Data loss warnings

**Design Priority**: Low (mostly done)
**Implementation Estimate**: 1 day (minor)

---

### 6. Input Components

#### SearchBar (Enhanced)
**Status**: 🟡 Exists, needs enhancement
**Priority**: P0
**Current State**: Basic text input
**Required Enhancements**:
- Autocomplete suggestions
- Recent searches
- Search filters (dropdown or chips)
- Clear button
- Search on type (debounced) or on Enter
- Loading indicator
- Keyboard navigation (arrow keys)
- Voice search (optional)

**Used In**: Knowledge Base search, Lead search, Account search, Audit log search (30+ instances)

**Design Priority**: **Critical**
**Implementation Estimate**: 3 days (enhancement)

---

#### DateRangePicker
**Status**: 🟡 Exists, needs enhancement
**Priority**: P0
**Current State**: Basic date picker
**Required Enhancements**:
- Preset ranges (Today, This Week, Last 30 Days, etc.)
- Comparison mode (compare to previous period)
- Relative dates (Last N days)
- Custom range with calendar
- Time selection (if needed)
- Clear selection

**Used In**: Reports, Analytics, Audit logs, Budget periods, Filters (20+ instances)

**Design Priority**: High
**Implementation Estimate**: 3 days (enhancement)

---

#### TagInput (Multi-select with autocomplete)
**Status**: 🟡 Exists, basic version
**Priority**: P1
**Current State**: Basic multi-select
**Required Enhancements**:
- Autocomplete from existing tags
- Create new tags on Enter
- Tag validation (max length, allowed chars)
- Color coding for tag types
- Remove tag with click
- Keyboard navigation
- Max tags limit

**Used In**: Knowledge Base tags, Lead tags, Policy agent types, Compliance categories

**Design Priority**: Medium
**Implementation Estimate**: 2 days (enhancement)

---

### 7. Status & Feedback Components

#### Badge
**Status**: ✅ Exists
**Priority**: P0
**Current State**: Good
**Usage**: Status indicators (DRAFT, POSTED, ACTIVE, APPROVED, etc.)

---

#### Toast/Notification
**Status**: ✅ Exists
**Priority**: P0
**Current State**: Good
**Usage**: Success/error messages after actions

---

#### ProgressBar
**Status**: 🟡 Exists, needs enhancement
**Priority**: P1
**Current State**: Basic bar
**Required Enhancements**:
- Indeterminate state (loading)
- Segments (multi-step progress)
- Label with percentage
- Color coding based on thresholds
- Animated transitions

**Used In**: Bulk operations, File uploads, Enrichment progress, Reconciliation progress

**Design Priority**: Medium
**Implementation Estimate**: 1 day (enhancement)

---

#### Skeleton Loader
**Status**: 🟡 Exists, basic version
**Priority**: P0
**Current State**: Basic rectangle skeletons
**Required Enhancements**:
- Component-specific skeletons (TableSkeleton, CardSkeleton, ChartSkeleton)
- Animated shimmer effect
- Configurable dimensions
- Multiple rows/items

**Used In**: All loading states (everywhere)

**Design Priority**: High
**Implementation Estimate**: 2 days (enhancement)

---

### 8. Complex/Specialized Components

#### DualPanelComparison
**Status**: ❌ New component required
**Priority**: P1
**Description**: Side-by-side comparison view
**Features Needed**:
- Split view (50/50 or adjustable)
- Synchronized scrolling
- Highlight differences
- Select item from left or right
- Merge/choose actions

**Used In**: Duplicate detection, Data enrichment preview, Reconciliation matching, Merge preview

**Design Priority**: Medium
**Implementation Estimate**: 3 days (new)

---

#### KanbanBoard
**Status**: ❌ New component required
**Priority**: P2
**Description**: Drag-and-drop Kanban board
**Features Needed**:
- Multiple columns (customizable)
- Drag-and-drop between columns
- Card customization
- Add card inline
- Column actions (add, rename, delete)
- Horizontal scroll for many columns
- Collapsed columns

**Used In**: Deal pipeline (future), Task management (future), Workflow status

**Design Priority**: Low (Phase 3+)
**Implementation Estimate**: 5 days (new)

**Note**: May not be needed for initial sprints

---

#### CodeEditor
**Status**: ❌ New component required
**Priority**: P2
**Description**: Syntax-highlighted code editor
**Features Needed**:
- Syntax highlighting for JSON, JavaScript, SQL
- Line numbers
- Auto-completion
- Bracket matching
- Read-only mode
- Copy to clipboard
- Diff view (compare two versions)

**Used In**: Workflow expressions, Report formulas, Integration configuration, Policy JSON preview

**Design Priority**: Medium
**Implementation Estimate**: 3 days (new)

**Recommended Library**: Monaco Editor (VSCode) or CodeMirror

---

#### RichTextEditor
**Status**: ❌ New component required
**Priority**: P1
**Description**: WYSIWYG rich text editor
**Features Needed**:
- Formatting toolbar (bold, italic, lists, links)
- Table support
- Image embed
- Undo/redo
- Character/word count
- HTML output
- Mentions (@user)
- Variables/merge fields

**Used In**: Email templates, Knowledge Base, Notes, Journal descriptions

**Design Priority**: Medium
**Implementation Estimate**: 4 days (new)

**Recommended Library**: Tiptap or Lexical

---

## Component Priority Matrix

### Phase 1A (Sprint 34-35) - CRITICAL
Must have for Compliance features:

| Component | Status | Priority | Est. Days |
|-----------|--------|----------|-----------|
| DataTable (Enhanced) | 🟡 | P0 | 5 |
| RuleBuilder | ❌ | P0 | 6 |
| Modal (Enhanced) | 🟡 | P0 | 3 |
| SearchBar (Enhanced) | 🟡 | P0 | 3 |
| DateRangePicker (Enhanced) | 🟡 | P0 | 3 |
| Timeline (Enhanced) | 🟡 | P0 | 3 |
| GaugeChart | ❌ | P0 | 2 |
| StepperWizard (Enhanced) | 🟡 | P0 | 3 |
| ConfirmationDialog | ✅ | P0 | 1 |
| Badge | ✅ | P0 | 0 |

**Total Phase 1A**: 29 days of component work (can be parallelized with 2-3 developers)

---

### Phase 1B (Sprint 36-37) - HIGH
Must have for Finance & CRM:

| Component | Status | Priority | Est. Days |
|-----------|--------|----------|-----------|
| TreeView | ❌ | P0 | 4 |
| MetricCard (Enhanced) | 🟡 | P0 | 2 |
| Drawer (Enhanced) | 🟡 | P1 | 2 |
| ChartCard (Enhanced) | 🟡 | P1 | 3 |
| ProgressBar (Enhanced) | 🟡 | P1 | 1 |
| DualPanelComparison | ❌ | P1 | 3 |

**Total Phase 1B**: 15 days

---

### Phase 2 (Sprint 38-40) - MEDIUM
Core features:

| Component | Status | Priority | Est. Days |
|-----------|--------|----------|-----------|
| MarkdownEditor | ❌ | P1 | 4 |
| RichTextEditor | ❌ | P1 | 4 |
| TagInput (Enhanced) | 🟡 | P1 | 2 |
| Skeleton Loader (Enhanced) | 🟡 | P1 | 2 |

**Total Phase 2**: 12 days

---

### Phase 3 (Sprint 41-43) - ADVANCED
Advanced features:

| Component | Status | Priority | Est. Days |
|-----------|--------|----------|-----------|
| WorkflowCanvas | ❌ | P2 | 8 |
| FieldMapper | ❌ | P2 | 5 |
| CodeEditor | ❌ | P2 | 3 |
| KanbanBoard | ❌ | P2 | 5 |

**Total Phase 3**: 21 days

---

## Component Design Checklist

For each component, the design team should provide:

### Design Assets
- [ ] Figma component with all variants
- [ ] Light and dark mode versions
- [ ] Responsive breakpoints (mobile, tablet, desktop)
- [ ] Interactive states (default, hover, focus, active, disabled, error, loading)
- [ ] Accessibility annotations (ARIA labels, keyboard shortcuts)
- [ ] Animation specifications (timing, easing)

### Documentation
- [ ] Component usage guidelines
- [ ] Props/API documentation
- [ ] Code examples
- [ ] Do's and Don'ts
- [ ] Accessibility requirements

### Tokens & Styling
- [ ] Color tokens used
- [ ] Typography tokens
- [ ] Spacing tokens
- [ ] Border radius, shadows
- [ ] Z-index layers

---

## Recommended Component Libraries

Consider these existing libraries to accelerate development:

### High Priority
- **Radix UI** (already in project?) - Unstyled accessible primitives
- **Recharts** (already in project?) - Charts
- **react-flow** - Visual workflows
- **react-markdown** - Markdown rendering

### Consider Adding
- **react-dnd** / **dnd-kit** - Drag and drop
- **Tiptap** or **Lexical** - Rich text editing
- **Monaco Editor** - Code editing
- **date-fns** - Date utilities
- **react-window** - Virtual scrolling

---

## Design System Recommendations

### 1. Create Component Patterns
- **List Pattern**: DataTable + Filters + Search + Pagination
- **Detail Pattern**: Modal/Drawer + Tabs + Form + Actions
- **Dashboard Pattern**: MetricCards + Charts + Timeline + Filters
- **Wizard Pattern**: StepperWizard + Forms + Validation + Summary

### 2. Establish Conventions
- **Naming**: PascalCase for components, camelCase for props
- **File Structure**: ComponentName/index.tsx, ComponentName.styles.ts, ComponentName.test.tsx
- **Props Interface**: ComponentNameProps (e.g., DataTableProps)
- **Composition**: Use `children` for flexibility

### 3. Accessibility Standards
- WCAG 2.1 AA compliance minimum
- Keyboard navigation for all interactive components
- ARIA labels for screen readers
- Focus indicators visible
- Color contrast ratios: 4.5:1 for text, 3:1 for UI

---

## Next Steps for Design Team

### Week 1: Phase 1A Components (Priority P0)
1. **DataTable (Enhanced)** - 2 days
2. **RuleBuilder** - 3 days
3. **Modal (Enhanced)** - 1 day
4. **SearchBar (Enhanced)** - 1 day

### Week 2: Phase 1A Components (continued)
5. **DateRangePicker (Enhanced)** - 1 day
6. **Timeline (Enhanced)** - 2 days
7. **GaugeChart** - 1 day
8. **StepperWizard (Enhanced)** - 1 day

### Week 3: Phase 1B Components
9. **TreeView** - 2 days
10. **MetricCard (Enhanced)** - 1 day
11. **Drawer (Enhanced)** - 1 day
12. **ChartCard (Enhanced)** - 1 day

### Weeks 4-8: Phase 2 & 3 Components
Continue with remaining components as engineering team progresses

---

## Success Metrics

- [ ] All P0 components designed by Sprint 34 start (Nov 18)
- [ ] All P1 components designed by Sprint 36 start
- [ ] Component library documented in Storybook
- [ ] Design QA process established (design reviews before implementation)
- [ ] Accessibility audit passed for all components
- [ ] Performance benchmarks met (Time to Interactive < 2s)

---

**Component Library Audit Complete** ✅

**Next Actions**:
1. Design team reviews this document
2. Prioritize P0 components for immediate design
3. Set up design review process with engineering
4. Create component library in Figma
5. Begin Storybook documentation

