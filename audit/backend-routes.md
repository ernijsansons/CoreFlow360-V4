# Backend API Routes Catalogue

## Summary
This file catalogues all backend API route definitions discovered in the codebase.

## Route Patterns Found

### Main Router Routes (src/index.ts)
- GET /health - Health check endpoint
- GET /api/status - API status
- GET /api/supernova/status - Supernova status
- POST /api/supernova/integrate - Supernova integration
- GET /api/supernova/report - Supernova report

### Export Routes (src/routes/export.ts)
- POST / - Create export
- GET /:id/progress - Export progress
- GET /:id/progress/ws - WebSocket progress updates
- GET /:id/download - Download export
- DELETE /:id - Delete export
- GET /history - Export history
- POST /batch - Batch export
- GET /templates - Export templates

### CRM Integration Routes (src/routes/crm-integrations.ts)
- GET /gmail/authorize - Gmail OAuth authorization
- GET /gmail/callback - Gmail OAuth callback
- POST /gmail/sync - Sync Gmail contacts
- GET /outlook/authorize - Outlook authorization
- GET /outlook/callback - Outlook callback
- POST /outlook/sync - Outlook sync
- POST /twilio/webhook/call - Twilio call webhook
- POST /twilio/webhook/sms - Twilio SMS webhook
- POST /twilio/sync - Twilio sync
- POST /twilio/test - Test Twilio integration
- GET /list - List integrations
- DELETE /:type/:provider - Delete integration
- GET /sync-status - Integration sync status
- POST /:provider/test - Test provider integration
- POST /:provider/test-sync - Test sync
- POST /:provider/test-webhook - Test webhook
- PUT /gmail/config - Update Gmail config
- PUT /outlook/config - Update Outlook config
- PUT /twilio/config - Update Twilio config
- PUT /slack/config - Update Slack config
- PUT /teams/config - Update Teams config

### CRM Enrichment Routes (src/routes/crm-enrichment.ts)
- POST /contact - Enrich contact data
- POST /queue - Queue enrichment task
- GET /queue/status - Queue status
- POST /queue/process - Process enrichment queue
- GET /history/:entityType/:entityId - Enrichment history
- GET /analytics/success-rates - Success rate analytics
- GET /analytics/needs-enrichment - Entities needing enrichment
- GET /completeness/:entityType/:entityId - Data completeness score
- POST /credentials - Save enrichment credentials
- GET /credentials - Get credentials
- DELETE /credentials/:source - Delete credentials

### CRM Deal Health Routes (src/routes/crm-deal-health.ts)
- POST /:dealId/calculate - Calculate deal health score
- POST /:dealId/events - Track deal events
- GET /at-risk - Get at-risk deals

### CRM Data Quality Routes (src/routes/crm-data-quality.ts)
- POST /duplicates/find - Find duplicate records
- POST /duplicates/scan - Scan for duplicates
- GET /duplicates/pending - Get pending duplicates
- POST /duplicates/merge - Merge duplicate entities
- POST /duplicates/:matchId/dismiss - Dismiss duplicate match
- POST /validate - Validate entity data
- GET /report - Data quality report
- GET /issues - Data quality issues
- POST /auto-fix - Auto-fix data issues
- POST /issues/:issueId/resolve - Resolve data issue
- GET /dashboard - Data quality dashboard

### CRM AI Intelligence Routes (src/routes/crm-ai-intelligence.ts)
- POST /sentiment - Analyze sentiment
- POST /next-actions - Generate suggested actions
- GET /next-actions/pending - Get pending actions
- POST /forecast - Generate forecasts
- POST /validate/:entityType/:entityId - AI validation
- POST /duplicates/:entityType/:entityId - Find AI duplicates
- GET /duplicates - Get all duplicates

### Finance Routes (src/routes/finance.ts)
- GET /accounts - List accounts
- POST /accounts - Create account
- GET /accounts/:id - Get account details
- POST /journal-entries - Create journal entry
- GET /journal-entries - List journal entries
- POST /journal-entries/:id/post - Post journal entry
- GET /reports/trial-balance - Trial balance report
- GET /reports/balance-sheet - Balance sheet
- GET /reports/income-statement - Income statement
- GET /reports/cash-flow - Cash flow statement

### Finance Agent Routes (src/routes/finance-agent.ts)
- POST /record-transaction - Record financial transaction
- POST /categorize-transaction - Categorize transaction
- POST /reconcile-account - Reconcile account
- POST /generate-report - Generate financial report
- GET /insights - Financial insights
- GET /dashboard - Finance dashboard
- GET /tasks - Finance agent tasks
- GET /capabilities - Agent capabilities

### Compliance Admin Routes (src/routes/admin/compliance-admin.ts)
- POST /guidelines - Create compliance guideline
- GET /guidelines - List guidelines
- PUT /guidelines/:id - Update guideline
- DELETE /guidelines/:id - Delete guideline
- POST /policies - Create agent policy
- GET /policies - List agent policies
- PUT /policies/:id - Update policy
- GET /violations - Get violations
- PUT /violations/:id - Update violation status
- GET /audit-trail - Compliance audit trail

### ABAC (Access Control) Routes (src/routes/abac.ts)
- POST /check - Check permission
- POST /check-batch - Batch permission check
- GET /permissions - Get user permissions
- GET /introspect - Introspect permissions
- GET /capabilities/:resourceType - Get resource capabilities
- POST /debug - Debug permissions (non-prod)
- POST /invalidate - Invalidate permission cache
- GET /stats - Permission statistics
- GET /health - Health check
- GET /metrics - Permission metrics
- GET /admin/stats - Admin statistics
- POST /admin/clear-cache - Clear permission cache
- GET /healthz - Health check

### AI Audit Routes (src/routes/ai-audit.ts)
- POST /audit/comprehensive - Comprehensive AI audit
- POST /audit/models - Model performance audit
- POST /audit/workflows - Workflow audit
- POST /audit/safety - Safety guardrails audit
- POST /audit/bias - Bias detection audit
- POST /audit/hallucination - Hallucination detection
- POST /optimize/strategies - Generate optimization strategies
- POST /optimize/execute/:strategyId - Execute optimization
- GET /audit/history - Audit history
- GET /health - Health check

### Company Knowledge Routes (src/routes/company-knowledge.ts)
- POST /documents - Upload knowledge document
- GET /documents - List documents
- POST /query - Query knowledge base
- POST /embed - Embed document content
- POST /index - Index documents
- POST /search - Search knowledge base
- POST /summarize - Summarize documents
- POST /extract - Extract entities from documents
- GET /stats - Knowledge base statistics
- DELETE /documents/:id - Delete document
- GET /health - Health check

### Conversation Logs Routes (src/routes/conversation-logs.ts)
- GET / - List conversation logs
- GET /:id - Get conversation details
- GET /stats/summary - Conversation statistics

### Custom Integrations Routes (src/routes/custom-integrations.ts)
- POST / - Create custom integration
- GET / - List integrations
- GET /:id - Get integration details
- PATCH /:id - Update integration
- DELETE /:id - Delete integration
- POST /:id/submit - Submit for marketplace
- GET /marketplace - Browse marketplace
- GET /:id/analytics - Integration analytics
- POST /:key/oauth/authorize - OAuth authorization
- POST /:key/oauth/callback - OAuth callback
- POST /oauth/:connection_id/refresh - Refresh OAuth token

### Dashboard Routes (src/routes/dashboard.ts)
- GET /stats - Dashboard statistics
- GET /activity - Recent activity
- GET /tasks - Task list
- GET /charts/:metric - Chart data for metrics

### Analytics Dashboard Routes (src/routes/analytics-dashboard.ts)
- GET /overview - Analytics overview
- GET /performance - Performance metrics
- GET /geographic - Geographic analytics
- POST /event - Track analytics event
- GET /dashboard-url - Get dashboard URL

### Integrations Marketplace Routes (src/routes/integrations-marketplace.ts)
- GET /providers - List integration providers
- GET /providers/:id - Get provider details
- GET /connections - List active connections
- POST /connections - Create connection
- PATCH /connections/:id - Update connection
- DELETE /connections/:id - Delete connection
- GET /connections/:id/usage - Connection usage stats

### Admin Dashboard Routes (src/routes/admin-dashboard.ts)
- GET /analytics/kpis - Key performance indicators
- GET /analytics/realtime - Real-time analytics
- GET /analytics/business-intelligence - Business intelligence
- GET /analytics/system - System analytics
- GET /analytics/security - Security analytics

### Chat Routes (src/routes/chat.ts)
- POST /message - Send chat message
- GET /conversations - List conversations
- POST /conversations - Create conversation
- GET /conversations/:id/messages - Get conversation messages
- DELETE /conversations/:id - Delete conversation
- POST /upload-file - Upload file to chat

## Additional Routes Found in Development/Test Files

### Dev-Simple Routes (src/index.dev-simple.ts)
- GET /api/finance/invoices
- GET /api/finance/expenses
- GET /api/finance/transactions
- GET /api/finance/ledger
- GET /api/finance/reports
- GET /api/crm/deals
- GET /api/crm/pipeline
- GET /api/agents
- GET /api/agents/status
- GET /api/chat/messages
- POST /api/chat/send
- GET /api/dashboard/metrics
- GET /api/migration/status
- GET /api/ai-monitoring/metrics
- POST /api/auth/logout
- POST /api/auth/refresh
- GET /api/reconciliation
- POST /api/documents/upload
- GET /api/entities
- GET /api/export
- GET /api/data-quality

### Secure Index Routes (src/index.secure.ts)
- GET /health
- GET /metrics
- GET /ready
- POST /api/auth/login
- POST /api/auth/register
- POST /api/auth/logout
- POST /api/keys/generate
- GET /api/business/:id

### Database Admin Routes (src/workers/database-admin.ts)
- GET /migrations/status - Migration status
- POST /migrations/run - Run migrations
- POST /migrations/rollback/:version - Rollback migration
- GET /database/stats - Database statistics
- GET /health - Health check

## Notes
- Many routes require authentication middleware
- Several routes support pagination and filtering via query parameters
- Rate limiting is applied to most API routes
- Business context (business_id) is required for multi-tenant routes
- WebSocket support available for real-time features (exports, chat)
