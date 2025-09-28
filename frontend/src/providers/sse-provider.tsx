import React, { createContext, useContext, useEffect, useRef, useState, useCallback } from 'react'
import { useAuthStore } from '@/stores'
import { useToast } from '@/hooks/use-toast'

interface SSEMessage {
  id?: string
  event?: string
  data: any
  timestamp: number
}

interface SSEContextValue {
  isConnected: boolean
  lastMessage: SSEMessage | null
  subscribe: (event: string, handler: (data: any) => void) => () => void
  send: (event: string, data: any) => void
  reconnect: () => void
}

const SSEContext = createContext<SSEContextValue | undefined>(undefined)

export function SSEProvider({ children }: { children: React.ReactNode }) {
  const [isConnected, setIsConnected] = useState(false)
  const [lastMessage, setLastMessage] = useState<SSEMessage | null>(null)
  const { token, isAuthenticated } = useAuthStore()
  const { toast } = useToast()

  const eventSourceRef = useRef<EventSource | null>(null)
  const listenersRef = useRef<Map<string, Set<(data: any) => void>>>(new Map())
  const reconnectTimeoutRef = useRef<NodeJS.Timeout>()
  const reconnectAttemptsRef = useRef(0)

  // Connect to SSE endpoint
  const connect = useCallback(() => {
    if (!isAuthenticated || !token) {
      console.log('SSE: Not authenticated, skipping connection')
      return
    }

    const sseUrl = import.meta.env.VITE_SSE_URL || 'http://localhost:8787/sse'
    const url = `${sseUrl}?token=${encodeURIComponent(token)}`

    try {
      console.log('SSE: Connecting to', sseUrl)
      const eventSource = new EventSource(url)
      eventSourceRef.current = eventSource

      eventSource.onopen = () => {
        console.log('SSE: Connection established')
        setIsConnected(true)
        reconnectAttemptsRef.current = 0

        // Show connection success only if recovering from disconnect
        if (reconnectAttemptsRef.current > 0) {
          toast({
            title: 'Real-time updates restored',
            description: 'Connection to server re-established',
            variant: 'success',
            duration: 3000,
          })
        }
      }

      eventSource.onerror = (error) => {
        console.error('SSE: Connection error', error)
        setIsConnected(false)
        eventSource.close()
        eventSourceRef.current = null

        // Implement exponential backoff for reconnection
        const attempts = reconnectAttemptsRef.current
        if (attempts < 5) {
          const delay = Math.min(1000 * Math.pow(2, attempts), 30000)
          console.log(`SSE: Reconnecting in ${delay}ms (attempt ${attempts + 1})`)

          reconnectTimeoutRef.current = setTimeout(() => {
            reconnectAttemptsRef.current++
            connect()
          }, delay)
        } else {
          toast({
            title: 'Connection lost',
            description: 'Unable to establish real-time connection. Some features may not update automatically.',
            variant: 'destructive',
            duration: 0, // Persistent until dismissed
          })
        }
      }

      // Handle incoming messages
      eventSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          const message: SSEMessage = {
            id: event.lastEventId,
            data,
            timestamp: Date.now(),
          }
          setLastMessage(message)

          // Notify all listeners for 'message' event
          const handlers = listenersRef.current.get('message')
          if (handlers) {
            handlers.forEach(handler => handler(data))
          }
        } catch (error) {
          console.error('SSE: Failed to parse message', error)
        }
      }

      // Handle specific event types
      const eventTypes = [
        'lead-update',
        'deal-moved',
        'invoice-paid',
        'payment-received',
        'task-completed',
        'notification',
        'user-activity',
        'system-alert'
      ]

      eventTypes.forEach(eventType => {
        eventSource.addEventListener(eventType, (event: MessageEvent) => {
          try {
            const data = JSON.parse(event.data)
            const message: SSEMessage = {
              id: event.lastEventId,
              event: eventType,
              data,
              timestamp: Date.now(),
            }
            setLastMessage(message)

            // Notify specific event listeners
            const handlers = listenersRef.current.get(eventType)
            if (handlers) {
              handlers.forEach(handler => handler(data))
            }

            // Show toast for certain events
            handleEventNotification(eventType, data)
          } catch (error) {
            console.error(`SSE: Failed to handle ${eventType} event`, error)
          }
        })
      })

    } catch (error) {
      console.error('SSE: Failed to establish connection', error)
      setIsConnected(false)
    }
  }, [isAuthenticated, token, toast])

  // Disconnect from SSE
  const disconnect = useCallback(() => {
    if (eventSourceRef.current) {
      console.log('SSE: Disconnecting')
      eventSourceRef.current.close()
      eventSourceRef.current = null
      setIsConnected(false)
    }
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
    }
  }, [])

  // Subscribe to events
  const subscribe = useCallback((event: string, handler: (data: any) => void) => {
    if (!listenersRef.current.has(event)) {
      listenersRef.current.set(event, new Set())
    }
    listenersRef.current.get(event)!.add(handler)

    // Return unsubscribe function
    return () => {
      const handlers = listenersRef.current.get(event)
      if (handlers) {
        handlers.delete(handler)
        if (handlers.size === 0) {
          listenersRef.current.delete(event)
        }
      }
    }
  }, [])

  // Send message (for bidirectional communication if needed)
  const send = useCallback((event: string, data: any) => {
    // SSE is typically unidirectional, but we can send via regular API
    // This is a placeholder for future WebSocket upgrade
    console.log('SSE: Send not implemented (SSE is receive-only)', { event, data })
  }, [])

  // Manual reconnect
  const reconnect = useCallback(() => {
    disconnect()
    reconnectAttemptsRef.current = 0
    connect()
  }, [connect, disconnect])

  // Handle specific event notifications
  const handleEventNotification = (eventType: string, data: any) => {
    switch (eventType) {
      case 'payment-received':
        toast({
          title: 'Payment received',
          description: `Payment of ${data.amount} received from ${data.customerName}`,
          variant: 'success',
        })
        break
      case 'invoice-paid':
        toast({
          title: 'Invoice paid',
          description: `Invoice #${data.invoiceNumber} has been paid`,
          variant: 'success',
        })
        break
      case 'lead-update':
        // Silent update - components will react to data changes
        break
      case 'deal-moved':
        // Silent update - pipeline will update automatically
        break
      case 'notification':
        toast({
          title: data.title || 'Notification',
          description: data.message,
          variant: data.type || 'default',
        })
        break
      case 'system-alert':
        toast({
          title: 'System Alert',
          description: data.message,
          variant: 'destructive',
          duration: 0, // Persistent
        })
        break
    }
  }

  // Connect when authenticated
  useEffect(() => {
    if (isAuthenticated) {
      connect()
    } else {
      disconnect()
    }

    return () => {
      disconnect()
    }
  }, [isAuthenticated, connect, disconnect])

  // Handle page visibility changes
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.hidden) {
        // Page is hidden, could disconnect to save resources
        console.log('SSE: Page hidden')
      } else {
        // Page is visible, ensure connection
        if (!isConnected && isAuthenticated) {
          console.log('SSE: Page visible, checking connection')
          reconnect()
        }
      }
    }

    document.addEventListener('visibilitychange', handleVisibilityChange)
    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange)
    }
  }, [isConnected, isAuthenticated, reconnect])

  const value: SSEContextValue = {
    isConnected,
    lastMessage,
    subscribe,
    send,
    reconnect,
  }

  return <SSEContext.Provider value={value}>{children}</SSEContext.Provider>
}

export function useSSE() {
  const context = useContext(SSEContext)
  if (!context) {
    throw new Error('useSSE must be used within SSEProvider')
  }
  return context
}

// Hook for subscribing to specific SSE events
export function useSSESubscription(
  event: string,
  handler: (data: any) => void,
  deps: React.DependencyList = []
) {
  const { subscribe } = useSSE()

  useEffect(() => {
    const unsubscribe = subscribe(event, handler)
    return unsubscribe
  }, [event, ...deps]) // eslint-disable-line react-hooks/exhaustive-deps
}