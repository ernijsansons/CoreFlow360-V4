import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'
import { immer } from 'zustand/middleware/immer'
import type { CacheItem } from '@/types'

interface CacheStore {
  cache: Record<string, CacheItem>

  get: <T = any>(key: string) => T | null
  set: <T = any>(key: string, data: T, ttl?: number) => void
  remove: (key: string) => void
  clear: () => void
  cleanup: () => void
  isExpired: (key: string) => boolean
  getSize: () => number
}

const DEFAULT_TTL = 5 * 60 * 1000 // 5 minutes

export const useCacheStore = create<CacheStore>()(
  persist(
    immer((set, get) => ({
      cache: {},

      get: <T = any>(key: string): T | null => {
        const { cache, isExpired, remove } = get()
        const item = cache[key]

        if (!item) return null

        if (isExpired(key)) {
          remove(key)
          return null
        }

        return item.data as T
      },

      set: <T = any>(key: string, data: T, ttl: number = DEFAULT_TTL) => {
        set((state) => {
          state.cache[key] = {
            data,
            timestamp: Date.now(),
            ttl,
          }
        })
      },

      remove: (key: string) => {
        set((state) => {
          delete state.cache[key]
        })
      },

      clear: () => {
        set((state) => {
          state.cache = {}
        })
      },

      cleanup: () => {
        const { cache, isExpired } = get()
        const expiredKeys = Object.keys(cache).filter(key => isExpired(key))

        if (expiredKeys.length > 0) {
          set((state) => {
            expiredKeys.forEach(key => {
              delete state.cache[key]
            })
          })
        }
      },

      isExpired: (key: string): boolean => {
        const { cache } = get()
        const item = cache[key]

        if (!item) return true

        const now = Date.now()
        return (now - item.timestamp) > item.ttl
      },

      getSize: (): number => {
        const { cache } = get()
        return Object.keys(cache).length
      },
    })),
    {
      name: 'cache-store',
      storage: createJSONStorage(() => sessionStorage),
      partialize: (state) => ({
        cache: state.cache,
      }),
    }
  )
)

// Auto cleanup expired items every 5 minutes
setInterval(() => {
  useCacheStore.getState().cleanup()
}, 5 * 60 * 1000)