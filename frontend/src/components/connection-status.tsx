import * as React from 'react'
import { Wifi, WifiOff, Loader2 } from 'lucide-react'
import { useConnectionStatus } from '@/hooks/use-sse'
import { useSyncStore } from '@/stores'
import { cn } from '@/lib/utils'

export function ConnectionStatus() {
  const { isConnected, connectionState, statusColor, statusText } = useConnectionStatus()
  const { connectivity, getQueueSize } = useSyncStore()
  const queueSize = getQueueSize()

  const getIcon = () => {
    if (connectionState === 'connecting') {
      return <Loader2 className="h-3 w-3 animate-spin" />
    }

    if (isConnected && connectivity.online) {
      return <Wifi className="h-3 w-3" />
    }

    return <WifiOff className="h-3 w-3" />
  }

  const getStatusColor = () => {
    switch (statusColor) {
      case 'success':
        return 'text-success-600 bg-success-50 border-success-200'
      case 'warning':
        return 'text-warning-600 bg-warning-50 border-warning-200'
      case 'error':
        return 'text-error-600 bg-error-50 border-error-200'
      default:
        return 'text-muted-foreground bg-muted border-border'
    }
  }

  const getDetailedStatus = () => {
    if (!connectivity.online) {
      return 'Offline - Changes will sync when reconnected'
    }

    if (queueSize > 0) {
      return `${queueSize} pending sync${queueSize > 1 ? 's' : ''}`
    }

    return statusText
  }

  return (
    <div
      className={cn(
        "fixed bottom-4 right-4 z-50 flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium transition-all duration-200",
        getStatusColor()
      )}
    >
      {getIcon()}
      <span className="hidden sm:inline">{getDetailedStatus()}</span>

      {/* Connection quality indicator */}
      {connectivity.online && (
        <div className="flex gap-0.5 ml-1">
          {[1, 2, 3].map(bar => (
            <div
              key={bar}
              className={cn(
                "w-0.5 h-2 rounded-full transition-colors",
                isConnected && bar <= 3
                  ? "bg-current"
                  : "bg-current/30"
              )}
            />
          ))}
        </div>
      )}
    </div>
  )
}