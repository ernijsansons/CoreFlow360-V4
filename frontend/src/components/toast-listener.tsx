import { useEffect } from 'react'
import { toast } from 'sonner'

export function ToastListener() {
  useEffect(() => {
    const handleToast = (event: Event) => {
      const customEvent = event as CustomEvent
      const { message, type } = customEvent.detail

      switch (type) {
        case 'success':
          toast.success(message)
          break
        case 'error':
          toast.error(message)
          break
        case 'info':
          toast.info(message)
          break
        case 'warning':
          toast.warning(message)
          break
        default:
          toast(message)
      }
    }

    window.addEventListener('show-toast', handleToast)

    return () => {
      window.removeEventListener('show-toast', handleToast)
    }
  }, [])

  return null
}
