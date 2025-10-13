// Core Services
export { authService } from './auth.service'
export { crmService } from './crm.service'
export { financeService } from './finance.service'
export { dashboardService } from './dashboard.service'

// CRM Extensions
export { crmDataQualityService } from './crm-data-quality.service'
export { crmIntegrationsService } from './crm-integrations.service'

// Financial Services
export { documentsService } from './documents.service'
export { bankingService } from './banking.service'
export { reconciliationService } from './reconciliation.service'
export { anomaliesService } from './anomalies.service'

// AI & Automation
export { agentsService } from './agents.service'
export { chatService } from './chat.service'
export { aiAuditService } from './ai-audit.service'
export { aiMonitoringService } from './ai-monitoring.service'

// Data Management
export { exportService } from './export.service'
export { enrichmentService } from './enrichment.service'
export { migrationService } from './migration.service'
export { leadIngestionService } from './lead-ingestion.service'

// System Services
export { abacService } from './abac.service'
export { observabilityService } from './observability.service'
export { rateLimitingService } from './rate-limiting.service'
export { learningService } from './learning.service'

// Re-export all types
export * from './auth.service'
export * from './crm.service'
export * from './finance.service'
export * from './dashboard.service'
export * from './crm-data-quality.service'
export * from './crm-integrations.service'
export * from './documents.service'
export * from './banking.service'
export * from './reconciliation.service'
export * from './anomalies.service'
export * from './agents.service'
export * from './chat.service'
export * from './export.service'
export * from './enrichment.service'
export * from './migration.service'
export * from './abac.service'
export * from './ai-audit.service'
export * from './ai-monitoring.service'
export * from './observability.service'
export * from './lead-ingestion.service'
export * from './learning.service'
export * from './rate-limiting.service'