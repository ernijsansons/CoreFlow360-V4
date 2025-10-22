# Backend Feature Matrix

## Overview
This matrix catalogues backend capabilities by module and tracks their UI exposure status.
UI coverage will be validated in Terminal Y.

---

## Agent System
**Module**: `src/modules/agent-system/`

### Backend Capabilities
- **Agent Orchestration**: Multi-agent coordination and task distribution
- **Agent Registry**: Agent discovery and capability matching
- **Agent Memory**: Persistent context and learning across conversations
- **Cost Tracking**: Monitor and limit AI model costs
- **Performance Benchmarking**: Agent system performance testing
- **Streaming Responses**: Real-time streaming AI responses
- **Retry Logic**: Intelligent retry with exponential backoff
- **Circuit Breaking**: Fault tolerance and recovery
- **Security Scanning**: Prompt injection, SQL injection, XSS detection
- **Audit Logging**: Comprehensive agent activity tracking
- **Distributed Tracing**: Cross-service request tracking

### API Endpoints
- N/A (internal system, mostly accessed through other modules)

### UI Coverage
- **Status**: TBD (check Terminal Y)
- **Expected UI**: Agent management dashboard, performance metrics, cost monitoring, security alerts

### Dependencies
- D1 Database: `agent_memory`, `agent_tasks`, `agent_capabilities`
- KV Cache: Performance data
- Environment: AI API keys (Anthropic, OpenAI)

---

## Compliance
**Module**: `src/modules/compliance/`

### Backend Capabilities
- **Compliance Guidelines Management**: Create, update, delete guidelines
- **Agent Policy Management**: Define AI agent behavior policies
- **Violation Tracking**: Monitor and log compliance violations
- **Audit Trail**: Comprehensive compliance activity logging
- **Policy Enforcement**: Automated policy checking

### API Endpoints
- POST `/api/compliance/guidelines` - Create guideline
- GET `/api/compliance/guidelines` - List guidelines
- PUT `/api/compliance/guidelines/:id` - Update guideline
- DELETE `/api/compliance/guidelines/:id` - Delete guideline
- POST `/api/compliance/policies` - Create policy
- GET `/api/compliance/policies` - List policies
- PUT `/api/compliance/policies/:id` - Update policy
- GET `/api/compliance/violations` - Get violations
- PUT `/api/compliance/violations/:id` - Update violation
- GET `/api/compliance/audit-trail` - Get audit trail

### UI Coverage
- **Status**: TBD (check Terminal Y)
- **Expected UI**: Compliance dashboard, guideline editor, policy manager, violation alerts, audit log viewer

### Dependencies
- D1 Database: `company_guidelines`, `agent_policies`, `compliance_violations`, `audit_trail`

---

## Finance
**Module**: `src/modules/finance/`

### Backend Capabilities
- **Double-Entry Accounting**: Journal entries, ledger management
- **Account Management**: Chart of accounts, account creation
- **Financial Reporting**: Trial balance, balance sheet, P&L, cash flow
- **Invoice Management**: Creation, PDF generation, approval workflow
- **Aging Reports**: AR/AP aging analysis
- **Custom Reports**: Flexible report builder
- **Tax Calculation**: Multi-jurisdiction tax engine
- **Payment Integration**: Stripe and PayPal gateways
- **Multi-Currency**: Exchange rates and conversion
- **Reconciliation**: Bank reconciliation workflows
- **Audit Logging**: Financial activity tracking
- **Performance Monitoring**: Transaction timing and metrics

### API Endpoints
- GET `/api/finance/accounts` - List accounts
- POST `/api/finance/accounts` - Create account
- GET `/api/finance/accounts/:id` - Account details
- POST `/api/finance/journal-entries` - Create entry
- GET `/api/finance/journal-entries` - List entries
- POST `/api/finance/journal-entries/:id/post` - Post entry
- GET `/api/finance/reports/trial-balance` - Trial balance
- GET `/api/finance/reports/balance-sheet` - Balance sheet
- GET `/api/finance/reports/income-statement` - Income statement
- GET `/api/finance/reports/cash-flow` - Cash flow

### Finance Agent API Endpoints
- POST `/api/finance-agent/record-transaction` - Record transaction
- POST `/api/finance-agent/categorize-transaction` - Categorize
- POST `/api/finance-agent/reconcile-account` - Reconcile
- POST `/api/finance-agent/generate-report` - Generate report
- GET `/api/finance-agent/insights` - Financial insights
- GET `/api/finance-agent/dashboard` - Finance dashboard
- GET `/api/finance-agent/tasks` - Agent tasks
- GET `/api/finance-agent/capabilities` - Agent capabilities

### UI Coverage
- **Status**: TBD (check Terminal Y)
- **Expected UI**: Accounting dashboard, journal entry forms, chart of accounts, financial reports viewer, invoice manager, payment interface, reconciliation UI

### Dependencies
- D1 Database: `accounts`, `ledger_entries`, `invoices`, `payments`, `tax_rates`
- Payment Gateways: Stripe, PayPal
- R2 Storage: Invoice PDFs, documents

---

## CRM & Sales
**Module**: Multiple CRM route files

### Backend Capabilities
- **Contact Management**: Create, update, enrich contacts
- **Deal Pipeline**: Deal stages, health scoring
- **Data Quality**: Duplicate detection, validation, auto-fix
- **Data Enrichment**: Third-party data enrichment (Clearbit, Hunter.io)
- **AI Intelligence**: Sentiment analysis, next action suggestions, forecasting
- **Integrations**: Gmail, Outlook, Twilio, Slack, Teams
- **Communication**: Email, SMS, call tracking via webhooks

### API Endpoints

**Integrations** (`crm-integrations.ts`):
- GET `/api/crm/integrations/gmail/authorize`
- GET `/api/crm/integrations/gmail/callback`
- POST `/api/crm/integrations/gmail/sync`
- GET `/api/crm/integrations/outlook/authorize`
- GET `/api/crm/integrations/outlook/callback`
- POST `/api/crm/integrations/outlook/sync`
- POST `/api/crm/integrations/twilio/webhook/call`
- POST `/api/crm/integrations/twilio/webhook/sms`
- POST `/api/crm/integrations/twilio/sync`
- GET `/api/crm/integrations/list`
- DELETE `/api/crm/integrations/:type/:provider`
- GET `/api/crm/integrations/sync-status`
- POST `/api/crm/integrations/:provider/test`

**Enrichment** (`crm-enrichment.ts`):
- POST `/api/crm/enrichment/contact` - Enrich contact
- POST `/api/crm/enrichment/queue` - Queue enrichment
- GET `/api/crm/enrichment/queue/status` - Queue status
- POST `/api/crm/enrichment/queue/process` - Process queue
- GET `/api/crm/enrichment/history/:entityType/:entityId` - History
- GET `/api/crm/enrichment/analytics/success-rates` - Analytics
- GET `/api/crm/enrichment/analytics/needs-enrichment` - Needs enrichment
- GET `/api/crm/enrichment/completeness/:entityType/:entityId` - Completeness
- POST `/api/crm/enrichment/credentials` - Save credentials
- GET `/api/crm/enrichment/credentials` - Get credentials
- DELETE `/api/crm/enrichment/credentials/:source` - Delete credentials

**Data Quality** (`crm-data-quality.ts`):
- POST `/api/crm/data-quality/duplicates/find` - Find duplicates
- POST `/api/crm/data-quality/duplicates/scan` - Scan duplicates
- GET `/api/crm/data-quality/duplicates/pending` - Pending duplicates
- POST `/api/crm/data-quality/duplicates/merge` - Merge duplicates
- POST `/api/crm/data-quality/duplicates/:matchId/dismiss` - Dismiss
- POST `/api/crm/data-quality/validate` - Validate entity
- GET `/api/crm/data-quality/report` - Quality report
- GET `/api/crm/data-quality/issues` - List issues
- POST `/api/crm/data-quality/auto-fix` - Auto-fix issues
- POST `/api/crm/data-quality/issues/:issueId/resolve` - Resolve issue
- GET `/api/crm/data-quality/dashboard` - Dashboard

**AI Intelligence** (`crm-ai-intelligence.ts`):
- POST `/api/crm/ai/sentiment` - Analyze sentiment
- POST `/api/crm/ai/next-actions` - Generate actions
- GET `/api/crm/ai/next-actions/pending` - Pending actions
- POST `/api/crm/ai/forecast` - Generate forecast
- POST `/api/crm/ai/validate/:entityType/:entityId` - Validate
- POST `/api/crm/ai/duplicates/:entityType/:entityId` - Find duplicates
- GET `/api/crm/ai/duplicates` - Get all duplicates

**Deal Health** (`crm-deal-health.ts`):
- POST `/api/crm/deal-health/:dealId/calculate` - Calculate health
- POST `/api/crm/deal-health/:dealId/events` - Track events
- GET `/api/crm/deal-health/at-risk` - At-risk deals

### UI Coverage
- **Status**: TBD (check Terminal Y)
- **Expected UI**: CRM dashboard, contact list/detail views, pipeline kanban, deal cards, data quality dashboard, enrichment status, integration settings, communication history

### Dependencies
- D1 Database: `contacts`, `deals`, `companies`, `interactions`, `data_quality_matches`, `enrichment_queue`
- Third-party APIs: Gmail, Outlook, Twilio, Clearbit, Hunter.io
- KV Cache: Enrichment results, integration tokens

---

## ABAC (Access Control)
**Module**: `src/modules/abac/`

### Backend Capabilities
- **Permission Checking**: Single and batch permission evaluation
- **Policy Evaluation**: Attribute-based access control
- **Permission Caching**: Multi-tier cache for performance
- **Fast Path Evaluation**: Optimized common permission checks
- **Permission Introspection**: View user permissions and capabilities
- **Audit Logging**: Permission check tracking
- **Debug Mode**: Permission debugging for development

### API Endpoints
- POST `/api/abac/check` - Check permission
- POST `/api/abac/check-batch` - Batch check
- GET `/api/abac/permissions` - Get user permissions
- GET `/api/abac/introspect` - Introspect permissions
- GET `/api/abac/capabilities/:resourceType` - Get capabilities
- POST `/api/abac/debug` - Debug permissions (dev only)
- POST `/api/abac/invalidate` - Invalidate cache
- GET `/api/abac/stats` - Permission stats
- GET `/api/abac/health` - Health check
- GET `/api/abac/metrics` - Permission metrics
- GET `/api/abac/admin/stats` - Admin stats
- POST `/api/abac/admin/clear-cache` - Clear cache

### UI Coverage
- **Status**: TBD (check Terminal Y)
- **Expected UI**: Permission management dashboard, role editor, user permission viewer, audit log, debug console (dev mode)

### Dependencies
- D1 Database: `permissions`, `roles`, `user_roles`, `permission_audit_log`
- KV Cache: Permission evaluations

---

## Knowledge Base
**Module**: `src/modules/agents/knowledge-base-agent.ts`, `src/routes/company-knowledge.ts`

### Backend Capabilities
- **Document Management**: Upload, index, delete documents
- **Knowledge Search**: Semantic search with embeddings
- **Entity Extraction**: Extract key entities from documents
- **Document Summarization**: AI-powered summarization
- **Vector Embeddings**: Document embedding for semantic search
- **Knowledge Query**: Natural language queries

### API Endpoints
- POST `/api/knowledge/documents` - Upload document
- GET `/api/knowledge/documents` - List documents
- POST `/api/knowledge/query` - Query knowledge base
- POST `/api/knowledge/embed` - Embed documents
- POST `/api/knowledge/index` - Index documents
- POST `/api/knowledge/search` - Search knowledge
- POST `/api/knowledge/summarize` - Summarize documents
- POST `/api/knowledge/extract` - Extract entities
- GET `/api/knowledge/stats` - Statistics
- DELETE `/api/knowledge/documents/:id` - Delete document
- GET `/api/knowledge/health` - Health check

### UI Coverage
- **Status**: TBD (check Terminal Y)
- **Expected UI**: Knowledge base library, document uploader, search interface, query results, document viewer

### Dependencies
- D1 Database: `knowledge_documents`, `knowledge_embeddings`
- R2 Storage: Document files
- AI APIs: Embeddings, summarization

---

## Chat & Support
**Module**: `src/modules/chat/`, `src/modules/agents/chat-support-agent.ts`, `src/modules/agents/support-ticket-agent.ts`

### Backend Capabilities
- **Chat Conversations**: Create, list, manage conversations
- **Message Handling**: Send/receive messages
- **File Uploads**: Upload files in chat context
- **AI Chat Support**: Intelligent chat responses
- **Support Tickets**: Ticket creation and management
- **Conversation Logging**: Track all chat interactions
- **Sentiment Analysis**: Analyze conversation sentiment

### API Endpoints
- POST `/api/chat/message` - Send message
- GET `/api/chat/conversations` - List conversations
- POST `/api/chat/conversations` - Create conversation
- GET `/api/chat/conversations/:id/messages` - Get messages
- DELETE `/api/chat/conversations/:id` - Delete conversation
- POST `/api/chat/upload-file` - Upload file

**Conversation Logs**:
- GET `/api/conversation-logs` - List logs
- GET `/api/conversation-logs/:id` - Get conversation details
- GET `/api/conversation-logs/stats/summary` - Statistics

### UI Coverage
- **Status**: TBD (check Terminal Y)
- **Expected UI**: Chat widget, conversation list, message thread view, file attachment, support ticket interface

### Dependencies
- D1 Database: `conversations`, `messages`, `support_tickets`
- R2 Storage: Chat file uploads
- AI APIs: Chat completion, sentiment analysis

---

## Export System
**Module**: `src/routes/export.ts`

### Backend Capabilities
- **Data Export**: Export business data in multiple formats
- **Export Progress Tracking**: Real-time progress updates
- **WebSocket Progress**: Live progress via WebSocket
- **Export History**: Track past exports
- **Batch Exports**: Export multiple datasets
- **Export Templates**: Pre-configured export templates
- **Download Management**: Secure download links

### API Endpoints
- POST `/api/export` - Create export
- GET `/api/export/:id/progress` - Export progress
- GET `/api/export/:id/progress/ws` - WebSocket progress
- GET `/api/export/:id/download` - Download export
- DELETE `/api/export/:id` - Delete export
- GET `/api/export/history` - Export history
- POST `/api/export/batch` - Batch export
- GET `/api/export/templates` - Export templates

### UI Coverage
- **Status**: TBD (check Terminal Y)
- **Expected UI**: Export wizard, progress indicator, export history list, template selector, download manager

### Dependencies
- D1 Database: `export_jobs`, `export_templates`
- R2 Storage: Export files
- Durable Objects: Export progress tracking

---

## Custom Integrations
**Module**: `src/routes/custom-integrations.ts`

### Backend Capabilities
- **Integration Builder**: Create custom integrations
- **OAuth Management**: OAuth authorization flows
- **Integration Marketplace**: Browse and install integrations
- **Usage Analytics**: Integration performance metrics
- **API Submission**: Submit integrations to marketplace
- **Configuration Management**: Update integration settings

### API Endpoints
- POST `/api/integrations` - Create integration
- GET `/api/integrations` - List integrations
- GET `/api/integrations/:id` - Get integration details
- PATCH `/api/integrations/:id` - Update integration
- DELETE `/api/integrations/:id` - Delete integration
- POST `/api/integrations/:id/submit` - Submit to marketplace
- GET `/api/integrations/marketplace` - Browse marketplace
- GET `/api/integrations/:id/analytics` - Usage analytics
- POST `/api/integrations/:key/oauth/authorize` - OAuth authorize
- POST `/api/integrations/:key/oauth/callback` - OAuth callback
- POST `/api/integrations/oauth/:connection_id/refresh` - Refresh token

### UI Coverage
- **Status**: TBD (check Terminal Y)
- **Expected UI**: Integration builder, marketplace browser, integration cards, OAuth flow screens, analytics dashboard

### Dependencies
- D1 Database: `custom_integrations`, `integration_connections`, `oauth_tokens`
- KV Cache: OAuth tokens

---

## Integrations Marketplace
**Module**: `src/routes/integrations-marketplace.ts`

### Backend Capabilities
- **Provider Directory**: List integration providers
- **Connection Management**: Create, update, delete connections
- **Provider Details**: Detailed provider information
- **Usage Tracking**: Connection usage statistics
- **Connection Status**: Monitor connection health

### API Endpoints
- GET `/api/marketplace/providers` - List providers
- GET `/api/marketplace/providers/:id` - Provider details
- GET `/api/marketplace/connections` - List connections
- POST `/api/marketplace/connections` - Create connection
- PATCH `/api/marketplace/connections/:id` - Update connection
- DELETE `/api/marketplace/connections/:id` - Delete connection
- GET `/api/marketplace/connections/:id/usage` - Usage stats

### UI Coverage
- **Status**: TBD (check Terminal Y)
- **Expected UI**: Marketplace grid, provider cards, connection manager, usage dashboard

### Dependencies
- D1 Database: `integration_providers`, `marketplace_connections`

---

## Dashboard & Analytics
**Module**: `src/routes/dashboard.ts`, `src/routes/admin-dashboard.ts`, `src/routes/analytics-dashboard.ts`

### Backend Capabilities
- **Dashboard Stats**: Key performance indicators
- **Activity Feed**: Recent business activity
- **Task Management**: Task list and tracking
- **Chart Data**: Time-series metrics
- **Admin Analytics**: System-level KPIs
- **Real-time Analytics**: Live metrics
- **Business Intelligence**: Cross-business insights
- **Security Analytics**: Security event tracking
- **Event Tracking**: Custom analytics events

### API Endpoints
**Dashboard**:
- GET `/api/dashboard/stats` - Dashboard statistics
- GET `/api/dashboard/activity` - Recent activity
- GET `/api/dashboard/tasks` - Task list
- GET `/api/dashboard/charts/:metric` - Chart data

**Admin Dashboard**:
- GET `/api/admin/analytics/kpis` - Key metrics
- GET `/api/admin/analytics/realtime` - Real-time data
- GET `/api/admin/analytics/business-intelligence` - BI insights
- GET `/api/admin/analytics/system` - System analytics
- GET `/api/admin/analytics/security` - Security analytics

**Analytics**:
- GET `/api/analytics/overview` - Analytics overview
- GET `/api/analytics/performance` - Performance metrics
- GET `/api/analytics/geographic` - Geographic data
- POST `/api/analytics/event` - Track event
- GET `/api/analytics/dashboard-url` - Dashboard URL

### UI Coverage
- **Status**: TBD (check Terminal Y)
- **Expected UI**: Main dashboard, admin dashboard, analytics dashboard, charts/graphs, activity timeline, task widgets

### Dependencies
- D1 Database: `analytics_events`, `dashboard_metrics`, `activities`, `tasks`
- KV Cache: Dashboard metrics
- Durable Objects: Real-time metrics aggregation

---

## AI Audit
**Module**: `src/routes/ai-audit.ts`

### Backend Capabilities
- **Comprehensive Audits**: Full AI system audits
- **Model Performance**: Model performance analysis
- **Workflow Audits**: AI workflow evaluation
- **Safety Guardrails**: Safety and compliance checking
- **Bias Detection**: Detect and measure bias
- **Hallucination Detection**: Identify AI hallucinations
- **Optimization Strategies**: Generate improvement recommendations
- **Strategy Execution**: Apply optimizations
- **Audit History**: Track audit results over time

### API Endpoints
- POST `/api/ai-audit/audit/comprehensive` - Comprehensive audit
- POST `/api/ai-audit/audit/models` - Model audit
- POST `/api/ai-audit/audit/workflows` - Workflow audit
- POST `/api/ai-audit/audit/safety` - Safety audit
- POST `/api/ai-audit/audit/bias` - Bias audit
- POST `/api/ai-audit/audit/hallucination` - Hallucination detection
- POST `/api/ai-audit/optimize/strategies` - Generate strategies
- POST `/api/ai-audit/optimize/execute/:strategyId` - Execute optimization
- GET `/api/ai-audit/audit/history` - Audit history
- GET `/api/ai-audit/health` - Health check

### UI Coverage
- **Status**: TBD (check Terminal Y)
- **Expected UI**: AI audit dashboard, audit report viewer, optimization recommendations, audit history timeline, health indicators

### Dependencies
- D1 Database: `ai_audit_results`, `optimization_strategies`, `audit_history`
- AI APIs: Model testing and evaluation

---

## Workflow Engine
**Module**: `src/modules/workflow/`

### Backend Capabilities
- **Workflow Orchestration**: Multi-step workflow execution
- **Step Handlers**: HTTP, database, email, file, delay steps
- **Approval Workflows**: Human-in-the-loop approvals
- **Error Handling**: Retry logic and error recovery
- **Workflow Persistence**: Durable workflow state
- **Step Registry**: Pluggable step handlers
- **Performance Tracking**: Workflow execution metrics

### API Endpoints
- N/A (accessed through other modules, e.g., invoice approval workflow)

### UI Coverage
- **Status**: TBD (check Terminal Y)
- **Expected UI**: Workflow designer, workflow execution monitor, approval interface, workflow history

### Dependencies
- Durable Objects: Workflow state persistence
- D1 Database: Workflow definitions, execution history

---

## Business Context
**Module**: `src/modules/business-context/`

### Backend Capabilities
- **Context Management**: Business context loading and caching
- **Company Analysis**: Company profiling and insights
- **Department Profiling**: Department-level context
- **Context Enrichment**: Enhance context with AI
- **Context Caching**: High-performance context retrieval
- **Multi-Business**: Handle multiple business contexts

### API Endpoints
- N/A (middleware/internal service)

### UI Coverage
- **Status**: TBD (check Terminal Y)
- **Expected UI**: Business switcher, company profile editor, department manager

### Dependencies
- D1 Database: `businesses`, `departments`, `company_profiles`
- KV Cache: Business context data

---

## Authentication & Sessions
**Module**: `src/modules/auth/`

### Backend Capabilities
- **JWT Authentication**: Token-based auth
- **Secret Rotation**: Automatic JWT secret rotation
- **Token Blacklisting**: Revoke compromised tokens
- **Password Management**: Secure hashing and verification
- **MFA/TOTP**: Multi-factor authentication
- **Session Management**: Secure session handling
- **Password Strength**: Password validation
- **Cryptographic Functions**: Encryption, HMAC, secure tokens

### API Endpoints
- POST `/api/auth/login` - User login
- POST `/api/auth/register` - User registration
- POST `/api/auth/logout` - User logout
- POST `/api/auth/refresh` - Refresh token
- POST `/api/keys/generate` - Generate API keys

### UI Coverage
- **Status**: TBD (check Terminal Y)
- **Expected UI**: Login page, registration form, MFA setup, password reset, session management

### Dependencies
- D1 Database: `users`, `sessions`, `api_keys`, `token_blacklist`
- KV Cache: Session data

---

## Database Management
**Module**: `src/modules/database/`, `src/workers/database-admin.ts`

### Backend Capabilities
- **Migration Runner**: Execute database migrations
- **Rollback Support**: Rollback migrations
- **Migration Status**: View migration history
- **Database Stats**: Database health and statistics
- **Schema Management**: Schema version control

### API Endpoints
- GET `/api/db-admin/migrations/status` - Migration status
- POST `/api/db-admin/migrations/run` - Run migrations
- POST `/api/db-admin/migrations/rollback/:version` - Rollback
- GET `/api/db-admin/database/stats` - Database stats
- GET `/api/db-admin/health` - Health check

### UI Coverage
- **Status**: TBD (check Terminal Y)
- **Expected UI**: Database admin panel, migration manager, schema viewer, database statistics dashboard

### Dependencies
- D1 Database: `migrations`, schema tables

---

## Summary Statistics

### Total Modules Catalogued: 18
- Agent System
- Compliance
- Finance
- CRM & Sales
- ABAC (Access Control)
- Knowledge Base
- Chat & Support
- Export System
- Custom Integrations
- Integrations Marketplace
- Dashboard & Analytics
- AI Audit
- Workflow Engine
- Business Context
- Authentication & Sessions
- Database Management
- SSE/Streaming
- Business Switching

### Total API Endpoint Categories: 150+

### Key Gap Areas to Investigate (Terminal Y):
1. Agent system monitoring and management UI
2. Compliance guideline editor and violation tracker
3. Advanced financial reporting interfaces
4. CRM data quality dashboard
5. Permission management UI
6. Knowledge base search and management
7. AI audit dashboard
8. Workflow designer and monitor
9. Database admin panel
10. Custom integration builder

### Next Steps
Proceed to **Terminal Y** (`docs/ui-backlog-audit/terminalY.md`) to trace actual UI coverage and identify gaps.
