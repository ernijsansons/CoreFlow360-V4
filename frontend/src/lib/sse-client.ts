import { useAuthStore, useUIStore, useEntityStore } from '@/stores'

export interface SSEMessage {
  type: string
  data: any
  timestamp: string
  channel?: string
}

export interface SSEOptions {
  url: string
  channels?: string[]
  reconnectInterval?: number
  maxReconnectAttempts?: number
  heartbeatInterval?: number
}

export class SSEClient {
  private eventSource: EventSource | null = null
  private reconnectAttempts = 0
  private maxReconnectAttempts: number
  private reconnectInterval: number
  private heartbeatInterval: number
  private heartbeatTimer: NodeJS.Timeout | null = null
  private isConnected = false
  private listeners: Map<string, Set<(data: any) => void>> = new Map()
  private options: SSEOptions

  constructor(options: SSEOptions) {
    this.options = options
    this.maxReconnectAttempts = options.maxReconnectAttempts ?? 10
    this.reconnectInterval = options.reconnectInterval ?? 1000
    this.heartbeatInterval = options.heartbeatInterval ?? 30000
  }

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        const token = useAuthStore.getState().token
        if (!token) {
          reject(new Error('No authentication token available'))
          return
        }

        const url = new URL(this.options.url)
        if (this.options.channels?.length) {
          url.searchParams.set('channels', this.options.channels.join(','))
        }

        // Add authentication token to URL
        url.searchParams.set('token', token)

        this.eventSource = new EventSource(url.toString())

        this.eventSource.onopen = () => {
          console.log('SSE connection opened')
          this.isConnected = true
          this.reconnectAttempts = 0
          this.startHeartbeat()

          // Update UI store
          useUIStore.getState().addNotification({
            type: 'success',
            title: 'Connected',
            message: 'Real-time updates are now active',
            read: true,
          })

          resolve()
        }

        this.eventSource.onmessage = (event) => {
          try {
            const message: SSEMessage = JSON.parse(event.data)
            this.handleMessage(message)
          } catch (error) {
            console.error('Failed to parse SSE message:', error)
          }
        }

        this.eventSource.onerror = (error) => {
          console.error('SSE connection error:', error)
          this.isConnected = false
          this.stopHeartbeat()

          if (this.eventSource?.readyState === EventSource.CLOSED) {
            this.handleReconnect()
          }
        }

        // Handle custom message types
        this.eventSource.addEventListener('heartbeat', (event) => {
          console.log('Received heartbeat')
        })

        this.eventSource.addEventListener('notification', (event) => {
          try {
            const data = JSON.parse(event.data)
            useUIStore.getState().addNotification({
              type: data.type || 'info',
              title: data.title,
              message: data.message,
              read: false,
            })
          } catch (error) {
            console.error('Failed to parse notification:', error)
          }
        })

        this.eventSource.addEventListener('entity_update', (event) => {
          try {
            const data = JSON.parse(event.data)
            const entityStore = useEntityStore.getState()
            if (data.entityId === entityStore.currentEntity?.id) {
              entityStore.updateEntity(data.entityId, data.updates)
            }
          } catch (error) {
            console.error('Failed to parse entity update:', error)
          }
        })

      } catch (error) {
        reject(error)
      }
    })
  }

  disconnect(): void {
    if (this.eventSource) {
      this.eventSource.close()
      this.eventSource = null
    }

    this.isConnected = false
    this.stopHeartbeat()
    this.listeners.clear()

    console.log('SSE connection closed')
  }

  subscribe(channel: string, callback: (data: any) => void): () => void {
    if (!this.listeners.has(channel)) {
      this.listeners.set(channel, new Set())
    }

    this.listeners.get(channel)!.add(callback)

    // Return unsubscribe function
    return () => {
      const channelListeners = this.listeners.get(channel)
      if (channelListeners) {
        channelListeners.delete(callback)
        if (channelListeners.size === 0) {
          this.listeners.delete(channel)
        }
      }
    }
  }

  private handleMessage(message: SSEMessage): void {
    console.log('Received SSE message:', message)

    // Emit to channel-specific listeners
    if (message.channel) {
      const channelListeners = this.listeners.get(message.channel)
      if (channelListeners) {
        channelListeners.forEach(callback => {
          try {
            callback(message.data)
          } catch (error) {
            console.error('Error in SSE message handler:', error)
          }
        })
      }
    }

    // Emit to type-specific listeners
    const typeListeners = this.listeners.get(message.type)
    if (typeListeners) {
      typeListeners.forEach(callback => {
        try {
          callback(message.data)
        } catch (error) {
          console.error('Error in SSE message handler:', error)
        }
      })
    }
  }

  private handleReconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('Max reconnection attempts reached')
      useUIStore.getState().addNotification({
        type: 'error',
        title: 'Connection Lost',
        message: 'Unable to reconnect to real-time updates. Please refresh the page.',
        read: false,
      })
      return
    }

    const delay = Math.min(
      this.reconnectInterval * Math.pow(2, this.reconnectAttempts),
      30000 // Max 30 seconds
    )

    this.reconnectAttempts++

    console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts}) in ${delay}ms`)

    setTimeout(() => {
      if (!this.isConnected) {
        this.connect().catch(error => {
          console.error('Reconnection failed:', error)
          this.handleReconnect()
        })
      }
    }, delay)
  }

  private startHeartbeat(): void {
    this.stopHeartbeat()

    this.heartbeatTimer = setInterval(() => {
      if (this.isConnected && this.eventSource?.readyState === EventSource.OPEN) {
        // Send heartbeat to server (if supported)
        console.log('Sending heartbeat')
      }
    }, this.heartbeatInterval)
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer)
      this.heartbeatTimer = null
    }
  }

  getConnectionState(): string {
    if (!this.eventSource) return 'disconnected'

    switch (this.eventSource.readyState) {
      case EventSource.CONNECTING:
        return 'connecting'
      case EventSource.OPEN:
        return 'connected'
      case EventSource.CLOSED:
        return 'disconnected'
      default:
        return 'unknown'
    }
  }

  isConnectionOpen(): boolean {
    return this.isConnected && this.eventSource?.readyState === EventSource.OPEN
  }
}

// Global SSE client instance
let sseClient: SSEClient | null = null

export function createSSEClient(options: SSEOptions): SSEClient {
  if (sseClient) {
    sseClient.disconnect()
  }

  sseClient = new SSEClient(options)
  return sseClient
}

export function getSSEClient(): SSEClient | null {
  return sseClient
}

export function disconnectSSE(): void {
  if (sseClient) {
    sseClient.disconnect()
    sseClient = null
  }
}