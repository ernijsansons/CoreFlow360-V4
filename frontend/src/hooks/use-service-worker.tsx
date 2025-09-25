import * as React from 'react'
import { Workbox } from 'workbox-window'
import { useUIStore } from '@/stores'

interface ServiceWorkerContextType {
  isInstalled: boolean
  isWaitingForUpdate: boolean
  updateServiceWorker: () => void
  isOnline: boolean
}

const ServiceWorkerContext = React.createContext<ServiceWorkerContextType | null>(null)

interface ServiceWorkerProviderProps {
  children: React.ReactNode
}

export function ServiceWorkerProvider({ children }: ServiceWorkerProviderProps) {
  const [isInstalled, setIsInstalled] = React.useState(false)
  const [isWaitingForUpdate, setIsWaitingForUpdate] = React.useState(false)
  const [workbox, setWorkbox] = React.useState<Workbox | null>(null)
  const [isOnline, setIsOnline] = React.useState(navigator.onLine)

  const { addNotification, addToast } = useUIStore()

  const updateServiceWorker = React.useCallback(() => {
    if (workbox && isWaitingForUpdate) {
      workbox.messageSkipWaiting()
      setIsWaitingForUpdate(false)

      addToast({
        type: 'success',
        message: 'App updated! Reloading...',
        duration: 2000,
      })

      // Reload after a short delay
      setTimeout(() => {
        window.location.reload()
      }, 1000)
    }
  }, [workbox, isWaitingForUpdate, addToast])

  // Initialize service worker
  React.useEffect(() => {
    if ('serviceWorker' in navigator && import.meta.env.PROD) {
      const wb = new Workbox('/sw.js')

      wb.addEventListener('installed', () => {
        console.log('Service Worker installed')
        setIsInstalled(true)

        addNotification({
          type: 'success',
          title: 'App Ready for Offline Use',
          message: 'CoreFlow360 is now available offline',
          read: false,
        })
      })

      wb.addEventListener('waiting', () => {
        console.log('Service Worker waiting')
        setIsWaitingForUpdate(true)

        addNotification({
          type: 'info',
          title: 'App Update Available',
          message: 'A new version is ready. Click to update.',
          read: false,
          actions: [
            {
              label: 'Update Now',
              action: () => updateServiceWorker(),
            },
          ],
        })
      })

      wb.addEventListener('controlling', () => {
        console.log('Service Worker controlling')
        window.location.reload()
      })

      wb.addEventListener('activated', () => {
        console.log('Service Worker activated')
      })

      // Listen for messages from the service worker
      wb.addEventListener('message', (event) => {
        const { type, data } = event.data

        switch (type) {
          case 'BACKGROUND_SYNC':
            if (data.status === 'processing') {
              addToast({
                type: 'info',
                message: 'Syncing offline changes...',
                duration: 3000,
              })
            }
            break

          case 'CACHE_UPDATED':
            console.log('Cache updated:', data)
            break

          default:
            console.log('Unknown SW message:', event.data)
        }
      })

      wb.register()
        .then(() => {
          console.log('Service Worker registration successful')
        })
        .catch((error) => {
          console.error('Service Worker registration failed:', error)
        })

      setWorkbox(wb)
    }
  }, [addNotification, addToast, updateServiceWorker])

  // Monitor online/offline status
  React.useEffect(() => {
    const handleOnline = () => {
      setIsOnline(true)
      addToast({
        type: 'success',
        message: 'You\'re back online!',
        duration: 3000,
      })
    }

    const handleOffline = () => {
      setIsOnline(false)
      addToast({
        type: 'warning',
        message: 'You\'re offline. Changes will sync when reconnected.',
        duration: 5000,
      })
    }

    window.addEventListener('online', handleOnline)
    window.addEventListener('offline', handleOffline)

    return () => {
      window.removeEventListener('online', handleOnline)
      window.removeEventListener('offline', handleOffline)
    }
  }, [addToast])

  // Register for background sync when offline requests are made
  React.useEffect(() => {
    if ('serviceWorker' in navigator && 'sync' in window.ServiceWorkerRegistration.prototype) {
      navigator.serviceWorker.ready.then((registration) => {
        // Register for background sync
        registration.sync.register('background-sync').catch((error) => {
          console.error('Background sync registration failed:', error)
        })
      })
    }
  }, [])

  const contextValue = React.useMemo(() => ({
    isInstalled,
    isWaitingForUpdate,
    updateServiceWorker,
    isOnline,
  }), [isInstalled, isWaitingForUpdate, updateServiceWorker, isOnline])

  return (
    <ServiceWorkerContext.Provider value={contextValue}>
      {children}
    </ServiceWorkerContext.Provider>
  )
}

export function useServiceWorker() {
  const context = React.useContext(ServiceWorkerContext)

  if (!context) {
    throw new Error('useServiceWorker must be used within a ServiceWorkerProvider')
  }

  return context
}

// Hook for PWA install prompt
export function usePWAInstall() {
  const [deferredPrompt, setDeferredPrompt] = React.useState<any>(null)
  const [canInstall, setCanInstall] = React.useState(false)

  React.useEffect(() => {
    const handleBeforeInstallPrompt = (e: Event) => {
      // Prevent the mini-infobar from appearing on mobile
      e.preventDefault()

      // Save the event so it can be triggered later
      setDeferredPrompt(e)
      setCanInstall(true)
    }

    const handleAppInstalled = () => {
      console.log('PWA was installed')
      setCanInstall(false)
      setDeferredPrompt(null)

      useUIStore.getState().addToast({
        type: 'success',
        message: 'CoreFlow360 installed successfully!',
        duration: 3000,
      })
    }

    window.addEventListener('beforeinstallprompt', handleBeforeInstallPrompt)
    window.addEventListener('appinstalled', handleAppInstalled)

    return () => {
      window.removeEventListener('beforeinstallprompt', handleBeforeInstallPrompt)
      window.removeEventListener('appinstalled', handleAppInstalled)
    }
  }, [])

  const installPWA = React.useCallback(async () => {
    if (!deferredPrompt) return false

    try {
      // Show the install prompt
      const result = await deferredPrompt.prompt()

      // Wait for the user to respond to the prompt
      const choiceResult = await result.userChoice

      if (choiceResult.outcome === 'accepted') {
        console.log('User accepted the install prompt')
        return true
      } else {
        console.log('User dismissed the install prompt')
        return false
      }
    } catch (error) {
      console.error('Error installing PWA:', error)
      return false
    } finally {
      setDeferredPrompt(null)
      setCanInstall(false)
    }
  }, [deferredPrompt])

  return {
    canInstall,
    installPWA,
  }
}

// Hook for checking if app is running as PWA
export function useIsPWA() {
  const [isPWA, setIsPWA] = React.useState(false)

  React.useEffect(() => {
    const checkPWA = () => {
      const isStandalone = window.matchMedia('(display-mode: standalone)').matches ||
        (window.navigator as any).standalone ||
        document.referrer.includes('android-app://')

      setIsPWA(isStandalone)
    }

    checkPWA()

    // Listen for display mode changes
    const mediaQuery = window.matchMedia('(display-mode: standalone)')
    mediaQuery.addEventListener('change', checkPWA)

    return () => {
      mediaQuery.removeEventListener('change', checkPWA)
    }
  }, [])

  return isPWA
}