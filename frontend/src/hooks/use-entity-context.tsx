import * as React from 'react'
import { useEntityStore } from '@/stores'
import type { Entity } from '@/types'

interface EntityContextType {
  entity: Entity | null
  isLoading: boolean
  error: string | null
  switchEntity: (entityId: string) => Promise<boolean>
  refreshEntity: () => Promise<void>
}

const EntityContext = React.createContext<EntityContextType | null>(null)

interface EntityProviderProps {
  children: React.ReactNode
}

export function EntityProvider({ children }: EntityProviderProps) {
  const {
    currentEntity,
    isLoading,
    error,
    switchEntity,
    loadEntities,
    setError,
  } = useEntityStore()

  const refreshEntity = React.useCallback(async () => {
    if (!currentEntity) return

    try {
      setError(null)

      const response = await fetch(`/api/entities/${currentEntity.id}`, {
        headers: {
          'Authorization': `Bearer ${useAuthStore.getState().token}`,
        },
      })

      if (!response.ok) {
        throw new Error('Failed to refresh entity')
      }

      const { data: entity } = await response.json()
      useEntityStore.getState().setCurrentEntity(entity)
    } catch (error) {
      console.error('Failed to refresh entity:', error)
      setError(error instanceof Error ? error.message : 'Failed to refresh entity')
    }
  }, [currentEntity, setError])

  // Load entities on mount
  React.useEffect(() => {
    loadEntities()
  }, [loadEntities])

  // Auto-refresh entity data every 5 minutes
  React.useEffect(() => {
    if (!currentEntity) return

    const interval = setInterval(refreshEntity, 5 * 60 * 1000)
    return () => clearInterval(interval)
  }, [currentEntity, refreshEntity])

  const contextValue = React.useMemo(() => ({
    entity: currentEntity,
    isLoading,
    error,
    switchEntity,
    refreshEntity,
  }), [currentEntity, isLoading, error, switchEntity, refreshEntity])

  return (
    <EntityContext.Provider value={contextValue}>
      {children}
    </EntityContext.Provider>
  )
}

export function useEntityContext() {
  const context = React.useContext(EntityContext)

  if (!context) {
    throw new Error('useEntityContext must be used within an EntityProvider')
  }

  return context
}

// Hook for requiring an entity to be selected
export function useRequireEntity() {
  const { entity, isLoading, error } = useEntityContext()

  React.useEffect(() => {
    if (!isLoading && !entity && !error) {
      // Redirect to entity selection or show entity selector
      console.warn('No entity selected')
    }
  }, [entity, isLoading, error])

  return { entity, isLoading, error }
}

// Hook for entity-specific permissions
export function useEntityPermissions() {
  const { entity } = useEntityContext()
  const { user } = useAuthStore()

  const hasPermission = React.useCallback((permission: string): boolean => {
    if (!user || !entity) return false

    // Check if user has the permission for this entity
    return user.permissions.some(p =>
      p.name === permission &&
      (p.scope === 'global' || p.scope === 'entity')
    )
  }, [user, entity])

  const canManageEntity = React.useCallback((): boolean => {
    return hasPermission('entity:manage')
  }, [hasPermission])

  const canViewEntity = React.useCallback((): boolean => {
    return hasPermission('entity:view')
  }, [hasPermission])

  return {
    hasPermission,
    canManageEntity,
    canViewEntity,
  }
}