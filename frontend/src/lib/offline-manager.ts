import { openDB, type DBSchema, type IDBPDatabase } from 'idb'
import { useSyncStore } from '@/stores'

interface OfflineDB extends DBSchema {
  entities: {
    key: string
    value: {
      id: string
      data: any
      timestamp: number
      lastAccessed: number
    }
  }
  apiCache: {
    key: string
    value: {
      url: string
      data: any
      timestamp: number
      ttl: number
    }
  }
  userPreferences: {
    key: string
    value: {
      key: string
      value: any
      timestamp: number
    }
  }
  syncQueue: {
    key: string
    value: {
      id: string
      method: string
      url: string
      data?: any
      headers?: Record<string, string>
      timestamp: number
      retries: number
    }
  }
}

class OfflineManager {
  private db: IDBPDatabase<OfflineDB> | null = null
  private dbName = 'CoreFlow360OfflineDB'
  private dbVersion = 1

  async initialize(): Promise<void> {
    try {
      this.db = await openDB<OfflineDB>(this.dbName, this.dbVersion, {
        upgrade(db) {
          // Entities store
          if (!db.objectStoreNames.contains('entities')) {
            const entitiesStore = db.createObjectStore('entities', {
              keyPath: 'id',
            })
            entitiesStore.createIndex('timestamp', 'timestamp')
            entitiesStore.createIndex('lastAccessed', 'lastAccessed')
          }

          // API cache store
          if (!db.objectStoreNames.contains('apiCache')) {
            const cacheStore = db.createObjectStore('apiCache', {
              keyPath: 'url',
            })
            cacheStore.createIndex('timestamp', 'timestamp')
          }

          // User preferences store
          if (!db.objectStoreNames.contains('userPreferences')) {
            db.createObjectStore('userPreferences', {
              keyPath: 'key',
            })
          }

          // Sync queue store
          if (!db.objectStoreNames.contains('syncQueue')) {
            const syncStore = db.createObjectStore('syncQueue', {
              keyPath: 'id',
            })
            syncStore.createIndex('timestamp', 'timestamp')
          }
        },
      })

      console.log('OfflineManager initialized')
    } catch (error) {
      console.error('Failed to initialize OfflineManager:', error)
    }
  }

  // Entity data management
  async storeEntity(id: string, data: any): Promise<void> {
    if (!this.db) await this.initialize()

    try {
      await this.db!.put('entities', {
        id,
        data,
        timestamp: Date.now(),
        lastAccessed: Date.now(),
      })
    } catch (error) {
      console.error('Failed to store entity:', error)
    }
  }

  async getEntity(id: string): Promise<any | null> {
    if (!this.db) await this.initialize()

    try {
      const entity = await this.db!.get('entities', id)

      if (entity) {
        // Update last accessed time
        entity.lastAccessed = Date.now()
        await this.db!.put('entities', entity)
        return entity.data
      }

      return null
    } catch (error) {
      console.error('Failed to get entity:', error)
      return null
    }
  }

  async removeEntity(id: string): Promise<void> {
    if (!this.db) await this.initialize()

    try {
      await this.db!.delete('entities', id)
    } catch (error) {
      console.error('Failed to remove entity:', error)
    }
  }

  // API cache management
  async cacheAPIResponse(url: string, data: any, ttl = 5 * 60 * 1000): Promise<void> {
    if (!this.db) await this.initialize()

    try {
      await this.db!.put('apiCache', {
        url,
        data,
        timestamp: Date.now(),
        ttl,
      })
    } catch (error) {
      console.error('Failed to cache API response:', error)
    }
  }

  async getCachedAPIResponse(url: string): Promise<any | null> {
    if (!this.db) await this.initialize()

    try {
      const cached = await this.db!.get('apiCache', url)

      if (cached) {
        const isExpired = Date.now() - cached.timestamp > cached.ttl

        if (isExpired) {
          await this.db!.delete('apiCache', url)
          return null
        }

        return cached.data
      }

      return null
    } catch (error) {
      console.error('Failed to get cached API response:', error)
      return null
    }
  }

  // User preferences management
  async setUserPreference(key: string, value: any): Promise<void> {
    if (!this.db) await this.initialize()

    try {
      await this.db!.put('userPreferences', {
        key,
        value,
        timestamp: Date.now(),
      })
    } catch (error) {
      console.error('Failed to set user preference:', error)
    }
  }

  async getUserPreference(key: string): Promise<any | null> {
    if (!this.db) await this.initialize()

    try {
      const pref = await this.db!.get('userPreferences', key)
      return pref ? pref.value : null
    } catch (error) {
      console.error('Failed to get user preference:', error)
      return null
    }
  }

  // Sync queue management
  async addToSyncQueue(request: {
    method: string
    url: string
    data?: any
    headers?: Record<string, string>
  }): Promise<void> {
    if (!this.db) await this.initialize()

    try {
      const id = crypto.randomUUID()

      await this.db!.put('syncQueue', {
        id,
        ...request,
        timestamp: Date.now(),
        retries: 0,
      })

      // Also add to Zustand sync store for immediate processing
      useSyncStore.getState().addToQueue(request)
    } catch (error) {
      console.error('Failed to add to sync queue:', error)
    }
  }

  async getSyncQueue(): Promise<any[]> {
    if (!this.db) await this.initialize()

    try {
      return await this.db!.getAll('syncQueue')
    } catch (error) {
      console.error('Failed to get sync queue:', error)
      return []
    }
  }

  async removeFromSyncQueue(id: string): Promise<void> {
    if (!this.db) await this.initialize()

    try {
      await this.db!.delete('syncQueue', id)
    } catch (error) {
      console.error('Failed to remove from sync queue:', error)
    }
  }

  // Cleanup operations
  async cleanup(): Promise<void> {
    if (!this.db) await this.initialize()

    try {
      const now = Date.now()
      const maxAge = 30 * 24 * 60 * 60 * 1000 // 30 days

      // Clean old entities
      const tx1 = this.db!.transaction('entities', 'readwrite')
      const entities = await tx1.store.index('lastAccessed').getAll()

      for (const entity of entities) {
        if (now - entity.lastAccessed > maxAge) {
          await tx1.store.delete(entity.id)
        }
      }

      await tx1.done

      // Clean expired API cache
      const tx2 = this.db!.transaction('apiCache', 'readwrite')
      const cached = await tx2.store.getAll()

      for (const item of cached) {
        if (now - item.timestamp > item.ttl) {
          await tx2.store.delete(item.url)
        }
      }

      await tx2.done

      console.log('OfflineManager cleanup completed')
    } catch (error) {
      console.error('Failed to cleanup offline data:', error)
    }
  }

  // Storage usage information
  async getStorageInfo(): Promise<{
    entities: number
    apiCache: number
    preferences: number
    syncQueue: number
    total: number
  }> {
    if (!this.db) await this.initialize()

    try {
      const [entities, apiCache, preferences, syncQueue] = await Promise.all([
        this.db!.count('entities'),
        this.db!.count('apiCache'),
        this.db!.count('userPreferences'),
        this.db!.count('syncQueue'),
      ])

      const total = entities + apiCache + preferences + syncQueue

      return {
        entities,
        apiCache,
        preferences,
        syncQueue,
        total,
      }
    } catch (error) {
      console.error('Failed to get storage info:', error)
      return {
        entities: 0,
        apiCache: 0,
        preferences: 0,
        syncQueue: 0,
        total: 0,
      }
    }
  }

  // Clear all offline data
  async clearAll(): Promise<void> {
    if (!this.db) await this.initialize()

    try {
      const tx = this.db!.transaction(['entities', 'apiCache', 'userPreferences', 'syncQueue'], 'readwrite')

      await Promise.all([
        tx.objectStore('entities').clear(),
        tx.objectStore('apiCache').clear(),
        tx.objectStore('userPreferences').clear(),
        tx.objectStore('syncQueue').clear(),
      ])

      await tx.done

      console.log('All offline data cleared')
    } catch (error) {
      console.error('Failed to clear offline data:', error)
    }
  }
}

// Global instance
export const offlineManager = new OfflineManager()

// Initialize on first import
offlineManager.initialize()

// Cleanup every hour
setInterval(() => {
  offlineManager.cleanup()
}, 60 * 60 * 1000)