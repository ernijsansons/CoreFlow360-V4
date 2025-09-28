import * as React from 'react'

export interface ToastProps {
  id?: string
  title?: string
  description?: string
  action?: React.ReactNode
  variant?: 'default' | 'destructive' | 'success' | 'warning'
  duration?: number
  onDismiss?: () => void
}

interface ToastContextValue {
  toasts: ToastProps[]
  toast: (props: ToastProps) => void
  dismiss: (id?: string) => void
}

const ToastContext = React.createContext<ToastContextValue | undefined>(undefined)

let toastCount = 0

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = React.useState<ToastProps[]>([])

  const toast = React.useCallback((props: ToastProps) => {
    const id = props.id || `toast-${++toastCount}`
    const duration = props.duration ?? 5000

    setToasts((prev) => [...prev, { ...props, id }])

    if (duration > 0) {
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id))
        props.onDismiss?.()
      }, duration)
    }
  }, [])

  const dismiss = React.useCallback((id?: string) => {
    setToasts((prev) => {
      if (id) {
        return prev.filter((t) => t.id !== id)
      }
      return []
    })
  }, [])

  return (
    <ToastContext.Provider value={{ toasts, toast, dismiss }}>
      {children}
    </ToastContext.Provider>
  )
}

export function useToast() {
  const context = React.useContext(ToastContext)
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider')
  }
  return context
}

export function toast(props: ToastProps) {
  // This is a placeholder for global toast function
  // In a real implementation, this would trigger the toast through a global event emitter
  // or by accessing the context imperatively
  console.warn('Global toast function called. Ensure ToastProvider is set up.')
}