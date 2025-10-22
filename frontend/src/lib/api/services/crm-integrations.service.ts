import apiClient, { ApiResponse } from '../client'

export interface EmailIntegration {
  provider: 'gmail' | 'outlook'
  email_address: string
  sync_enabled: boolean
  last_sync_at?: string
  emails_synced: number
}

export interface CallIntegration {
  provider: 'twilio'
  auto_create_activities: boolean
  auto_transcribe: boolean
  last_call_at?: string
  calls_captured: number
}

export interface IntegrationConfig {
  sync_enabled?: boolean
  auto_create_activities?: boolean
  auto_link_contacts?: boolean
  sync_sent_emails?: boolean
  sync_calendar?: boolean
  max_results_per_sync?: number
  auto_transcribe?: boolean
  capture_threads?: boolean
  capture_mentions?: boolean
  capture_messages?: boolean
  capture_meetings?: boolean
}

export interface SyncStatus {
  integration_id: string
  provider: string
  status: 'idle' | 'syncing' | 'error'
  last_sync_at?: string
  results: {
    items_processed: number
    items_captured: number
    items_skipped: number
    errors: string[]
  }
}

class CRMIntegrationsService {
  // Gmail Integration
  async authorizeGmail(): Promise<ApiResponse<{ authUrl: string }>> {
    return apiClient.get('/api/crm/integrations/gmail/authorize')
  }

  async syncGmail(maxResults = 50): Promise<ApiResponse<Record<string, unknown>>> {
    return apiClient.post('/api/crm/integrations/gmail/sync', { maxResults })
  }

  async updateGmailConfig(config: IntegrationConfig): Promise<ApiResponse<void>> {
    return apiClient.put('/api/crm/integrations/gmail/config', config)
  }

  // Outlook Integration
  async authorizeOutlook(): Promise<ApiResponse<{ authUrl: string }>> {
    return apiClient.get('/api/crm/integrations/outlook/authorize')
  }

  async syncOutlook(maxResults = 50): Promise<ApiResponse<Record<string, unknown>>> {
    return apiClient.post('/api/crm/integrations/outlook/sync', { maxResults })
  }

  async updateOutlookConfig(config: IntegrationConfig): Promise<ApiResponse<void>> {
    return apiClient.put('/api/crm/integrations/outlook/config', config)
  }

  // Twilio Integration
  async syncTwilio(limit = 50): Promise<ApiResponse<Record<string, unknown>>> {
    return apiClient.post('/api/crm/integrations/twilio/sync', { limit })
  }

  async testTwilio(): Promise<ApiResponse<{ connected: boolean }>> {
    return apiClient.post('/api/crm/integrations/twilio/test')
  }

  async updateTwilioConfig(config: IntegrationConfig): Promise<ApiResponse<void>> {
    return apiClient.put('/api/crm/integrations/twilio/config', config)
  }

  // Integration Management
  async listIntegrations(): Promise<ApiResponse<{
    email: EmailIntegration[]
    calls: CallIntegration[]
  }>> {
    return apiClient.get('/api/crm/integrations/list')
  }

  async deleteIntegration(
    type: 'email' | 'call',
    provider: string
  ): Promise<ApiResponse<void>> {
    return apiClient.delete(`/api/crm/integrations/${type}/${provider}`)
  }

  async getSyncStatus(): Promise<ApiResponse<SyncStatus[]>> {
    return apiClient.get('/api/crm/integrations/sync-status')
  }

  // Integration Testing
  async testIntegration(provider: string): Promise<ApiResponse<{
    overall_status: 'passed' | 'partial' | 'failed'
    tests: Array<{
      test_name: string
      status: 'passed' | 'failed'
      message: string
      duration_ms: number
    }>
    total_duration_ms: number
  }>> {
    return apiClient.post(`/api/crm/integrations/${provider}/test`)
  }

  async testSync(provider: string, limit = 5): Promise<ApiResponse<{
    items_processed: number
    items_captured: number
    items_skipped: number
    errors: string[]
    message: string
  }>> {
    return apiClient.post(`/api/crm/integrations/${provider}/test-sync`, { limit })
  }

  async testWebhook(provider: string): Promise<ApiResponse<{
    success: boolean
    message: string
    webhook_url: string
  }>> {
    return apiClient.post(`/api/crm/integrations/${provider}/test-webhook`)
  }

  // Slack Integration
  async updateSlackConfig(config: IntegrationConfig): Promise<ApiResponse<void>> {
    return apiClient.put('/api/crm/integrations/slack/config', config)
  }

  // Teams Integration
  async updateTeamsConfig(config: IntegrationConfig): Promise<ApiResponse<void>> {
    return apiClient.put('/api/crm/integrations/teams/config', config)
  }
}

export const crmIntegrationsService = new CRMIntegrationsService()
export default crmIntegrationsService
