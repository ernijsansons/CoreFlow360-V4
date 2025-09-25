import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'
import { immer } from 'zustand/middleware/immer'
import type { SyncQueueItem, ConnectivityStatus } from '@/types'

interface SyncStore {
  queue: SyncQueueItem[]
  isProcessing: boolean
  connectivity: ConnectivityStatus

  addToQueue: (item: Omit<SyncQueueItem, 'id' | 'timestamp' | 'retries'>) => void
  removeFromQueue: (id: string) => void
  processQueue: () => Promise<void>
  retryItem: (id: string) => Promise<boolean>
  clearQueue: () => void
  setConnectivity: (connectivity: ConnectivityStatus) => void
  getQueueSize: () => number
  getPendingItems: () => SyncQueueItem[]
}

const MAX_RETRIES = 3

export const useSyncStore = create<SyncStore>()(
  persist(
    immer((set, get) => ({
      queue: [],
      isProcessing: false,
      connectivity: { online: navigator.onLine },

      addToQueue: (item: Omit<SyncQueueItem, 'id' | 'timestamp' | 'retries'>) => {
        const queueItem: SyncQueueItem = {
          ...item,
          id: crypto.randomUUID(),
          timestamp: Date.now(),
          retries: 0,
          maxRetries: MAX_RETRIES,
        }

        set((state) => {
          state.queue.push(queueItem)
        })

        // Auto-process if online
        if (get().connectivity.online && !get().isProcessing) {
          get().processQueue()
        }
      },

      removeFromQueue: (id: string) => {
        set((state) => {
          const index = state.queue.findIndex(item => item.id === id)
          if (index !== -1) {
            state.queue.splice(index, 1)
          }
        })
      },

      processQueue: async () => {
        const { queue, connectivity, isProcessing } = get()

        if (!connectivity.online || isProcessing || queue.length === 0) {
          return
        }

        set((state) => {
          state.isProcessing = true
        })

        const token = useAuthStore.getState().token

        try {
          for (const item of [...queue]) {
            try {
              const response = await fetch(item.url, {
                method: item.method,
                headers: {
                  'Content-Type': 'application/json',
                  'Authorization': token ? `Bearer ${token}` : '',
                  ...item.headers,
                },
                body: item.data ? JSON.stringify(item.data) : undefined,
              })

              if (response.ok) {
                get().removeFromQueue(item.id)
              } else if (response.status >= 400 && response.status < 500) {
                // Client error - don't retry
                get().removeFromQueue(item.id)
              } else {
                // Server error - retry
                await get().retryItem(item.id)
              }
            } catch (error) {
              console.error('Sync item failed:', error)
              await get().retryItem(item.id)
            }
          }
        } finally {
          set((state) => {
            state.isProcessing = false
          })
        }
      },

      retryItem: async (id: string): Promise<boolean> => {
        const { queue } = get()
        const item = queue.find(item => item.id === id)

        if (!item) return false

        if (item.retries >= item.maxRetries) {
          get().removeFromQueue(id)
          return false
        }

        set((state) => {
          const itemIndex = state.queue.findIndex(item => item.id === id)
          if (itemIndex !== -1) {
            state.queue[itemIndex].retries += 1
          }
        })

        return true
      },

      clearQueue: () => {
        set((state) => {
          state.queue = []
          state.isProcessing = false
        })
      },

      setConnectivity: (connectivity: ConnectivityStatus) => {
        const wasOffline = !get().connectivity.online
        const isNowOnline = connectivity.online

        set((state) => {
          state.connectivity = connectivity
        })

        // If we just came back online, process the queue
        if (wasOffline && isNowOnline) {
          get().processQueue()
        }
      },

      getQueueSize: (): number => {
        return get().queue.length
      },

      getPendingItems: (): SyncQueueItem[] => {
        return get().queue.filter(item => item.retries < item.maxRetries)
      },
    })),
    {
      name: 'sync-store',
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        queue: state.queue,
      }),
    }
  )
)

// Listen to connectivity changes
window.addEventListener('online', () => {
  useSyncStore.getState().setConnectivity({ online: true })
})

window.addEventListener('offline', () => {
  useSyncStore.getState().setConnectivity({ online: false })
})

// Enhanced connectivity detection
if ('connection' in navigator) {
  const connection = (navigator as any).connection

  const updateConnectionInfo = () => {
    useSyncStore.getState().setConnectivity({
      online: navigator.onLine,
      connectionType: connection.type,
      effectiveType: connection.effectiveType,
      downlink: connection.downlink,
      rtt: connection.rtt,
    })
  }

  connection.addEventListener('change', updateConnectionInfo)
  updateConnectionInfo()
}