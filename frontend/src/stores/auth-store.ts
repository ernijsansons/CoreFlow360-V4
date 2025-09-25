import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'
import { immer } from 'zustand/middleware/immer'
import type { AuthState, User } from '@/types'
import { isTokenExpired, parseJwt } from '@/lib/utils'
import { authService } from '@/lib/api/services/auth.service'
import { useEntityStore } from './entity-store'
import { useCacheStore } from './cache-store'

interface AuthStore extends AuthState {
  login: (token: string, refreshToken: string, user: User) => void
  logout: () => void
  updateUser: (user: Partial<User>) => void
  refreshAuth: () => Promise<boolean>
  setLoading: (loading: boolean) => void
  checkTokenExpiry: () => boolean
}

export const useAuthStore = create<AuthStore>()(
  persist(
    immer((set, get) => ({
      user: null,
      token: null,
      refreshToken: null,
      isAuthenticated: false,
      isLoading: false,

      login: (token: string, refreshToken: string, user: User) => {
        set((state) => {
          state.token = token
          state.refreshToken = refreshToken
          state.user = user
          state.isAuthenticated = true
          state.isLoading = false
        })
      },

      logout: () => {
        set((state) => {
          state.user = null
          state.token = null
          state.refreshToken = null
          state.isAuthenticated = false
          state.isLoading = false
        })

        // Clear other stores on logout
        useEntityStore.getState().reset()
        useCacheStore.getState().clear()
      },

      updateUser: (userData: Partial<User>) => {
        set((state) => {
          if (state.user) {
            Object.assign(state.user, userData)
          }
        })
      },

      refreshAuth: async (): Promise<boolean> => {
        const { refreshToken } = get()

        if (!refreshToken || isTokenExpired(refreshToken)) {
          get().logout()
          return false
        }

        try {
          set((state) => {
            state.isLoading = true
          })

          const response = await authService.refreshToken(refreshToken)

          if (!response.success || !response.data) {
            throw new Error('Failed to refresh token')
          }

          set((state) => {
            state.token = response.data.token
            state.refreshToken = response.data.refreshToken || refreshToken
            state.user = response.data.user
            state.isAuthenticated = true
            state.isLoading = false
          })

          return true
        } catch (error) {
          console.error('Token refresh failed:', error)
          get().logout()
          return false
        }
      },

      setLoading: (loading: boolean) => {
        set((state) => {
          state.isLoading = loading
        })
      },

      checkTokenExpiry: (): boolean => {
        const { token, refreshAuth } = get()

        if (!token) return false

        if (isTokenExpired(token)) {
          refreshAuth()
          return false
        }

        return true
      },
    })),
    {
      name: 'auth-store',
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        token: state.token,
        refreshToken: state.refreshToken,
        user: state.user,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
)