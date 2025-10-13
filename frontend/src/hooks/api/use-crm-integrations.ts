import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { crmIntegrationsService } from '@/lib/api/services/crm-integrations.service'
import { toast } from '@/components/ui/toast'

// Query Keys
export const crmIntegrationsKeys = {
  all: ['crm-integrations'] as const,
  list: () => [...crmIntegrationsKeys.all, 'list'] as const,
  gmail: () => [...crmIntegrationsKeys.all, 'gmail'] as const,
  outlook: () => [...crmIntegrationsKeys.all, 'outlook'] as const,
  twilio: () => [...crmIntegrationsKeys.all, 'twilio'] as const,
}

// Gmail Integration Hooks

export function useAuthorizeGmail() {
  return useMutation({
    mutationFn: () => crmIntegrationsService.authorizeGmail(),
    onSuccess: (data) => {
      // Redirect to Gmail OAuth URL
      if (data.data.authUrl) {
        window.location.href = data.data.authUrl
      }
    },
    onError: () => {
      toast({
        title: 'Authorization failed',
        description: 'Failed to initiate Gmail authorization',
        variant: 'destructive',
      })
    },
  })
}

export function useSyncGmail() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (maxResults?: number) => crmIntegrationsService.syncGmail(maxResults),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: crmIntegrationsKeys.gmail() })
      toast({
        title: 'Gmail synced',
        description: 'Gmail emails have been synced successfully',
      })
    },
  })
}

export function useUpdateGmailConfig() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (config: Record<string, unknown>) =>
      crmIntegrationsService.updateGmailConfig(config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: crmIntegrationsKeys.gmail() })
      toast({
        title: 'Configuration updated',
        description: 'Gmail integration configuration updated',
      })
    },
  })
}

// Outlook Integration Hooks

export function useAuthorizeOutlook() {
  return useMutation({
    mutationFn: () => crmIntegrationsService.authorizeOutlook(),
    onSuccess: (data) => {
      if (data.data.authUrl) {
        window.location.href = data.data.authUrl
      }
    },
    onError: () => {
      toast({
        title: 'Authorization failed',
        description: 'Failed to initiate Outlook authorization',
        variant: 'destructive',
      })
    },
  })
}

export function useSyncOutlook() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (maxResults?: number) => crmIntegrationsService.syncOutlook(maxResults),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: crmIntegrationsKeys.outlook() })
      toast({
        title: 'Outlook synced',
        description: 'Outlook emails have been synced successfully',
      })
    },
  })
}

export function useUpdateOutlookConfig() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (config: Record<string, unknown>) =>
      crmIntegrationsService.updateOutlookConfig(config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: crmIntegrationsKeys.outlook() })
      toast({
        title: 'Configuration updated',
        description: 'Outlook integration configuration updated',
      })
    },
  })
}

// Twilio Integration Hooks

export function useSyncTwilio() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (params?: { hours_back?: number }) => crmIntegrationsService.syncTwilio(params),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: crmIntegrationsKeys.twilio() })
      toast({
        title: 'Twilio synced',
        description: 'Twilio calls and messages have been synced',
      })
    },
  })
}

export function useTestTwilioConnection() {
  return useMutation({
    mutationFn: () => crmIntegrationsService.testTwilioConnection(),
    onSuccess: (data) => {
      if (data.data.success) {
        toast({
          title: 'Connection successful',
          description: 'Twilio connection is working correctly',
        })
      } else {
        toast({
          title: 'Connection failed',
          description: data.data.error || 'Twilio connection test failed',
          variant: 'destructive',
        })
      }
    },
  })
}

export function useUpdateTwilioConfig() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (config: { account_sid: string; auth_token: string; phone_number: string }) =>
      crmIntegrationsService.updateTwilioConfig(config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: crmIntegrationsKeys.twilio() })
      toast({
        title: 'Configuration updated',
        description: 'Twilio integration configuration updated',
      })
    },
  })
}

// Integration Management Hooks

export function useIntegrations() {
  return useQuery({
    queryKey: crmIntegrationsKeys.list(),
    queryFn: () => crmIntegrationsService.listIntegrations(),
    staleTime: 1000 * 60 * 5, // 5 minutes
  })
}

export function useDeleteIntegration() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (integrationId: string) => crmIntegrationsService.deleteIntegration(integrationId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: crmIntegrationsKeys.list() })
      toast({
        title: 'Integration deleted',
        description: 'Integration has been removed successfully',
      })
    },
  })
}
