import * as React from 'react'
import { X, AlertCircle, CheckCircle, AlertTriangle, Info } from 'lucide-react'
import { useToast } from '@/hooks/use-toast'
import { cn } from '@/lib/utils'

const toastVariants = {
  default: {
    icon: Info,
    className: 'bg-white border-gray-200 text-gray-900',
  },
  success: {
    icon: CheckCircle,
    className: 'bg-green-50 border-green-200 text-green-900',
  },
  destructive: {
    icon: AlertCircle,
    className: 'bg-red-50 border-red-200 text-red-900',
  },
  warning: {
    icon: AlertTriangle,
    className: 'bg-yellow-50 border-yellow-200 text-yellow-900',
  },
}

export function ToastContainer() {
  const { toasts, dismiss } = useToast()

  return (
    <div className="fixed bottom-0 right-0 z-50 p-4 space-y-2 pointer-events-none">
      {toasts.map((toast) => {
        const variant = toast.variant || 'default'
        const { icon: Icon, className } = toastVariants[variant]

        return (
          <div
            key={toast.id}
            className={cn(
              'pointer-events-auto flex items-start gap-3 rounded-lg border p-4 shadow-lg transition-all',
              'animate-in slide-in-from-bottom-5 duration-300',
              'max-w-md',
              className
            )}
          >
            <Icon className="h-5 w-5 flex-shrink-0 mt-0.5" />
            <div className="flex-1 space-y-1">
              {toast.title && (
                <div className="font-semibold text-sm">{toast.title}</div>
              )}
              {toast.description && (
                <div className="text-sm opacity-90">{toast.description}</div>
              )}
              {toast.action && (
                <div className="mt-2">{toast.action}</div>
              )}
            </div>
            <button
              onClick={() => dismiss(toast.id)}
              className="pointer-events-auto flex-shrink-0 rounded-md p-1 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        )
      })}
    </div>
  )
}