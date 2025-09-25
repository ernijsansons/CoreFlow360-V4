import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'
import { immer } from 'zustand/middleware/immer'
import type { Entity, EntitySwitcherItem } from '@/types'

interface EntityStore {
  currentEntity: Entity | null
  entities: EntitySwitcherItem[]
  recentEntities: EntitySwitcherItem[]
  isLoading: boolean
  error: string | null

  setCurrentEntity: (entity: Entity) => void
  switchEntity: (entityId: string) => Promise<boolean>
  loadEntities: () => Promise<void>
  addToRecent: (entity: EntitySwitcherItem) => void
  updateEntity: (entityId: string, updates: Partial<Entity>) => void
  setLoading: (loading: boolean) => void
  setError: (error: string | null) => void
  reset: () => void
}

const MAX_RECENT_ENTITIES = 5

export const useEntityStore = create<EntityStore>()(
  persist(
    immer((set, get) => ({
      currentEntity: null,
      entities: [],
      recentEntities: [],
      isLoading: false,
      error: null,

      setCurrentEntity: (entity: Entity) => {
        set((state) => {
          state.currentEntity = entity
          state.error = null
        })

        // Add to recent entities
        const entityItem: EntitySwitcherItem = {
          id: entity.id,
          name: entity.name,
          type: entity.type,
          status: entity.status,
          subscription: entity.subscription,
          role: 'owner', // This would come from the API
        }

        get().addToRecent(entityItem)
      },

      switchEntity: async (entityId: string): Promise<boolean> => {
        const { entities, setLoading, setError } = get()
        const entity = entities.find(e => e.id === entityId)

        if (!entity) {
          setError('Entity not found')
          return false
        }

        try {
          setLoading(true)
          setError(null)

          // Call API to switch entity and get full entity data
          const response = await fetch(`/api/entities/${entityId}/switch`, {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${useAuthStore.getState().token}`,
              'Content-Type': 'application/json',
            },
          })

          if (!response.ok) {
            throw new Error('Failed to switch entity')
          }

          const { data: fullEntity } = await response.json()

          set((state) => {
            state.currentEntity = fullEntity
            state.isLoading = false
          })

          // Add to recent
          get().addToRecent(entity)

          return true
        } catch (error) {
          console.error('Entity switch failed:', error)
          setError(error instanceof Error ? error.message : 'Failed to switch entity')
          setLoading(false)
          return false
        }
      },

      loadEntities: async () => {
        const { setLoading, setError } = get()

        try {
          setLoading(true)
          setError(null)

          const response = await fetch('/api/entities', {
            headers: {
              'Authorization': `Bearer ${useAuthStore.getState().token}`,
            },
          })

          if (!response.ok) {
            throw new Error('Failed to load entities')
          }

          const { data: entities } = await response.json()

          set((state) => {
            state.entities = entities
            state.isLoading = false
          })
        } catch (error) {
          console.error('Failed to load entities:', error)
          setError(error instanceof Error ? error.message : 'Failed to load entities')
          setLoading(false)
        }
      },

      addToRecent: (entity: EntitySwitcherItem) => {
        set((state) => {
          // Remove if already exists
          state.recentEntities = state.recentEntities.filter(e => e.id !== entity.id)

          // Add to beginning
          state.recentEntities.unshift(entity)

          // Keep only the most recent
          if (state.recentEntities.length > MAX_RECENT_ENTITIES) {
            state.recentEntities = state.recentEntities.slice(0, MAX_RECENT_ENTITIES)
          }
        })
      },

      updateEntity: (entityId: string, updates: Partial<Entity>) => {
        set((state) => {
          if (state.currentEntity?.id === entityId) {
            Object.assign(state.currentEntity, updates)
          }

          // Update in entities list
          const entityIndex = state.entities.findIndex(e => e.id === entityId)
          if (entityIndex !== -1) {
            Object.assign(state.entities[entityIndex], updates)
          }

          // Update in recent entities
          const recentIndex = state.recentEntities.findIndex(e => e.id === entityId)
          if (recentIndex !== -1) {
            Object.assign(state.recentEntities[recentIndex], updates)
          }
        })
      },

      setLoading: (loading: boolean) => {
        set((state) => {
          state.isLoading = loading
        })
      },

      setError: (error: string | null) => {
        set((state) => {
          state.error = error
        })
      },

      reset: () => {
        set((state) => {
          state.currentEntity = null
          state.entities = []
          state.recentEntities = []
          state.isLoading = false
          state.error = null
        })
      },
    })),
    {
      name: 'entity-store',
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        currentEntity: state.currentEntity,
        recentEntities: state.recentEntities,
      }),
    }
  )
)