import * as React from 'react'
import { createSSEClient, getSSEClient, disconnectSSE, type SSEOptions } from '@/lib/sse-client'
import { useAuthStore, useEntityStore } from '@/stores'

interface SSEContextType {
  isConnected: boolean
  connectionState: string
  subscribe: (channel: string, callback: (data: any) => void) => () => void
  connect: () => Promise<void>
  disconnect: () => void
}

const SSEContext = React.createContext<SSEContextType | null>(null)

interface SSEProviderProps {
  children: React.ReactNode
  baseUrl?: string
}

export function SSEProvider({ children, baseUrl = '/api/sse' }: SSEProviderProps) {
  const [isConnected, setIsConnected] = React.useState(false)
  const [connectionState, setConnectionState] = React.useState('disconnected')

  const { isAuthenticated, token } = useAuthStore()
  const { currentEntity } = useEntityStore()

  const connect = React.useCallback(async () => {
    if (!isAuthenticated || !token || !currentEntity) {
      return
    }

    try {
      const client = createSSEClient({
        url: baseUrl,
        channels: [
          'global',
          `entity:${currentEntity.id}`,
          `user:${useAuthStore.getState().user?.id}`,
        ],
        reconnectInterval: 1000,
        maxReconnectAttempts: 10,
        heartbeatInterval: 30000,
      })

      await client.connect()
      setIsConnected(true)
      setConnectionState('connected')
    } catch (error) {
      console.error('Failed to connect to SSE:', error)
      setIsConnected(false)
      setConnectionState('error')
    }
  }, [isAuthenticated, token, currentEntity, baseUrl])

  const disconnect = React.useCallback(() => {
    disconnectSSE()
    setIsConnected(false)
    setConnectionState('disconnected')
  }, [])

  const subscribe = React.useCallback((channel: string, callback: (data: any) => void) => {
    const client = getSSEClient()
    if (!client) {
      console.warn('SSE client not available for subscription')
      return () => {}
    }

    return client.subscribe(channel, callback)
  }, [])

  // Connect when authenticated and entity is selected
  React.useEffect(() => {
    if (isAuthenticated && currentEntity) {
      connect()
    } else {
      disconnect()
    }

    return () => {
      disconnect()
    }
  }, [isAuthenticated, currentEntity, connect, disconnect])

  // Monitor connection state
  React.useEffect(() => {
    const interval = setInterval(() => {
      const client = getSSEClient()
      if (client) {
        const state = client.getConnectionState()
        setConnectionState(state)
        setIsConnected(client.isConnectionOpen())
      }
    }, 1000)

    return () => clearInterval(interval)
  }, [])

  const contextValue = React.useMemo(() => ({
    isConnected,
    connectionState,
    subscribe,
    connect,
    disconnect,
  }), [isConnected, connectionState, subscribe, connect, disconnect])

  return (
    <SSEContext.Provider value={contextValue}>
      {children}
    </SSEContext.Provider>
  )
}

export function useSSE() {
  const context = React.useContext(SSEContext)

  if (!context) {
    throw new Error('useSSE must be used within an SSEProvider')
  }

  return context
}

// Hook for subscribing to specific channels
export function useSSESubscription(
  channel: string,
  callback: (data: any) => void,
  dependencies: React.DependencyList = []
) {
  const { subscribe } = useSSE()

  React.useEffect(() => {
    const unsubscribe = subscribe(channel, callback)
    return unsubscribe
  }, [subscribe, channel, ...dependencies])
}

// Hook for real-time data updates
export function useRealtimeData<T>(
  channel: string,
  initialData?: T
): [T | undefined, (data: T) => void] {
  const [data, setData] = React.useState<T | undefined>(initialData)

  useSSESubscription(channel, (newData: T) => {
    setData(newData)
  })

  return [data, setData]
}

// Hook for connection status indicator
export function useConnectionStatus() {
  const { isConnected, connectionState } = useSSE()

  return {
    isConnected,
    connectionState,
    statusColor: isConnected ? 'success' : connectionState === 'connecting' ? 'warning' : 'error',
    statusText: isConnected ? 'Connected' : connectionState === 'connecting' ? 'Connecting...' : 'Disconnected',
  }
}