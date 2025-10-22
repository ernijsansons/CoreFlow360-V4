import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { migrationService } from '@/lib/api/services/migration.service'
import { toast } from '@/components/ui/toast'

// Query Keys
export const migrationKeys = {
  all: ['migration'] as const,
  migrations: () => [...migrationKeys.all, 'migrations'] as const,
  migration: (id: string) => [...migrationKeys.all, 'migration', id] as const,
}

// Hooks

export function useTestConnection() {
  return useMutation({
    mutationFn: (params: {
      platform: 'salesforce' | 'hubspot' | 'pipedrive' | 'zoho' | 'csv'
      credentials: Record<string, unknown>
    }) => migrationService.testConnection(params),
    onSuccess: (data) => {
      if (data.data.success) {
        toast({
          title: 'Connection successful',
          description: 'Successfully connected to the platform',
        })
      } else {
        toast({
          title: 'Connection failed',
          description: data.data.error || 'Failed to connect to platform',
          variant: 'destructive',
        })
      }
    },
  })
}

export function useDiscoverSchema() {
  return useMutation({
    mutationFn: (params: {
      platform: 'salesforce' | 'hubspot' | 'pipedrive' | 'zoho' | 'csv'
      credentials: Record<string, unknown>
    }) => migrationService.discoverSchema(params),
    onSuccess: () => {
      toast({
        title: 'Schema discovered',
        description: 'Platform schema has been analyzed',
      })
    },
  })
}

export function useMapSchema() {
  return useMutation({
    mutationFn: (params: {
      source_schema: Record<string, unknown>
      field_mappings: Array<{
        source_field: string
        target_field: string
        transform?: string
      }>
    }) => migrationService.mapSchema(params),
    onSuccess: () => {
      toast({
        title: 'Schema mapped',
        description: 'Field mappings have been configured',
      })
    },
  })
}

export function useCreateMigration() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (params: {
      platform: 'salesforce' | 'hubspot' | 'pipedrive' | 'zoho' | 'csv'
      credentials: Record<string, unknown>
      mapping: Record<string, unknown>
      options?: {
        batch_size?: number
        skip_duplicates?: boolean
        update_existing?: boolean
      }
    }) => migrationService.createMigration(params),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: migrationKeys.migrations() })
      toast({
        title: 'Migration created',
        description: 'Data migration has been configured',
      })
    },
  })
}

export function useStartMigration() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (migrationId: string) => migrationService.startMigration(migrationId),
    onSuccess: (_, migrationId) => {
      queryClient.invalidateQueries({ queryKey: migrationKeys.migration(migrationId) })
      toast({
        title: 'Migration started',
        description: 'Data migration is now in progress',
      })
    },
  })
}

export function usePauseMigration() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (migrationId: string) => migrationService.pauseMigration(migrationId),
    onSuccess: (_, migrationId) => {
      queryClient.invalidateQueries({ queryKey: migrationKeys.migration(migrationId) })
      toast({
        title: 'Migration paused',
        description: 'Data migration has been paused',
      })
    },
  })
}

export function useResumeMigration() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (migrationId: string) => migrationService.resumeMigration(migrationId),
    onSuccess: (_, migrationId) => {
      queryClient.invalidateQueries({ queryKey: migrationKeys.migration(migrationId) })
      toast({
        title: 'Migration resumed',
        description: 'Data migration has been resumed',
      })
    },
  })
}

export function useCancelMigration() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (migrationId: string) => migrationService.cancelMigration(migrationId),
    onSuccess: (_, migrationId) => {
      queryClient.invalidateQueries({ queryKey: migrationKeys.migration(migrationId) })
      queryClient.invalidateQueries({ queryKey: migrationKeys.migrations() })
      toast({
        title: 'Migration cancelled',
        description: 'Data migration has been cancelled',
      })
    },
  })
}

export function useMigration(id: string, enabled = true) {
  return useQuery({
    queryKey: migrationKeys.migration(id),
    queryFn: () => migrationService.getMigrationStatus(id),
    enabled: enabled && !!id,
    refetchInterval: (data) => {
      // Poll while migration is in progress
      if (data?.data?.status === 'in_progress') {
        return 3000 // Poll every 3 seconds
      }
      return false
    },
    staleTime: 0,
  })
}
