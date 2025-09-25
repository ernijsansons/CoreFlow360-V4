import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'
import { immer } from 'zustand/middleware/immer'
import type { NotificationItem, ModalState, ToastMessage, LoadingState } from '@/types'

interface UIStore {
  theme: 'light' | 'dark' | 'system'
  sidebarOpen: boolean
  commandPaletteOpen: boolean
  notifications: NotificationItem[]
  unreadNotificationCount: number
  modal: ModalState
  toasts: ToastMessage[]
  loading: LoadingState
  breadcrumbs: Array<{ label: string; href?: string }>

  setTheme: (theme: 'light' | 'dark' | 'system') => void
  toggleSidebar: () => void
  setSidebarOpen: (open: boolean) => void
  toggleCommandPalette: () => void
  setCommandPaletteOpen: (open: boolean) => void

  addNotification: (notification: Omit<NotificationItem, 'id'>) => void
  markNotificationAsRead: (id: string) => void
  markAllNotificationsAsRead: () => void
  removeNotification: (id: string) => void
  clearNotifications: () => void

  openModal: (modal: Omit<ModalState, 'isOpen'>) => void
  closeModal: () => void

  addToast: (toast: Omit<ToastMessage, 'id'>) => void
  removeToast: (id: string) => void
  clearToasts: () => void

  setLoading: (loading: Partial<LoadingState>) => void
  clearLoading: () => void

  setBreadcrumbs: (breadcrumbs: Array<{ label: string; href?: string }>) => void
  addBreadcrumb: (breadcrumb: { label: string; href?: string }) => void
}

export const useUIStore = create<UIStore>()(
  persist(
    immer((set, get) => ({
      theme: 'system',
      sidebarOpen: true,
      commandPaletteOpen: false,
      notifications: [],
      unreadNotificationCount: 0,
      modal: { isOpen: false },
      toasts: [],
      loading: { isLoading: false },
      breadcrumbs: [],

      setTheme: (theme: 'light' | 'dark' | 'system') => {
        set((state) => {
          state.theme = theme
        })

        // Apply theme to document
        const root = window.document.documentElement
        root.classList.remove('light', 'dark')

        if (theme === 'system') {
          const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
          root.classList.add(systemTheme)
        } else {
          root.classList.add(theme)
        }
      },

      toggleSidebar: () => {
        set((state) => {
          state.sidebarOpen = !state.sidebarOpen
        })
      },

      setSidebarOpen: (open: boolean) => {
        set((state) => {
          state.sidebarOpen = open
        })
      },

      toggleCommandPalette: () => {
        set((state) => {
          state.commandPaletteOpen = !state.commandPaletteOpen
        })
      },

      setCommandPaletteOpen: (open: boolean) => {
        set((state) => {
          state.commandPaletteOpen = open
        })
      },

      addNotification: (notification: Omit<NotificationItem, 'id'>) => {
        const id = crypto.randomUUID()

        set((state) => {
          state.notifications.unshift({
            ...notification,
            id,
          })

          if (!notification.read) {
            state.unreadNotificationCount += 1
          }
        })
      },

      markNotificationAsRead: (id: string) => {
        set((state) => {
          const notification = state.notifications.find(n => n.id === id)
          if (notification && !notification.read) {
            notification.read = true
            state.unreadNotificationCount = Math.max(0, state.unreadNotificationCount - 1)
          }
        })
      },

      markAllNotificationsAsRead: () => {
        set((state) => {
          state.notifications.forEach(notification => {
            notification.read = true
          })
          state.unreadNotificationCount = 0
        })
      },

      removeNotification: (id: string) => {
        set((state) => {
          const index = state.notifications.findIndex(n => n.id === id)
          if (index !== -1) {
            const notification = state.notifications[index]
            if (!notification.read) {
              state.unreadNotificationCount = Math.max(0, state.unreadNotificationCount - 1)
            }
            state.notifications.splice(index, 1)
          }
        })
      },

      clearNotifications: () => {
        set((state) => {
          state.notifications = []
          state.unreadNotificationCount = 0
        })
      },

      openModal: (modal: Omit<ModalState, 'isOpen'>) => {
        set((state) => {
          state.modal = {
            ...modal,
            isOpen: true,
          }
        })
      },

      closeModal: () => {
        set((state) => {
          state.modal = { isOpen: false }
        })
      },

      addToast: (toast: Omit<ToastMessage, 'id'>) => {
        const id = crypto.randomUUID()

        set((state) => {
          state.toasts.push({
            ...toast,
            id,
          })
        })

        // Auto remove toast after duration
        const duration = toast.duration ?? 5000
        if (duration > 0) {
          setTimeout(() => {
            get().removeToast(id)
          }, duration)
        }
      },

      removeToast: (id: string) => {
        set((state) => {
          const index = state.toasts.findIndex(t => t.id === id)
          if (index !== -1) {
            state.toasts.splice(index, 1)
          }
        })
      },

      clearToasts: () => {
        set((state) => {
          state.toasts = []
        })
      },

      setLoading: (loading: Partial<LoadingState>) => {
        set((state) => {
          Object.assign(state.loading, loading)
        })
      },

      clearLoading: () => {
        set((state) => {
          state.loading = { isLoading: false }
        })
      },

      setBreadcrumbs: (breadcrumbs: Array<{ label: string; href?: string }>) => {
        set((state) => {
          state.breadcrumbs = breadcrumbs
        })
      },

      addBreadcrumb: (breadcrumb: { label: string; href?: string }) => {
        set((state) => {
          state.breadcrumbs.push(breadcrumb)
        })
      },
    })),
    {
      name: 'ui-store',
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        theme: state.theme,
        sidebarOpen: state.sidebarOpen,
      }),
    }
  )
)