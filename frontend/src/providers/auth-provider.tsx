import React, { createContext, useContext, useEffect } from 'react'
import { useAuthStore } from '@/stores'
import { useNavigate } from '@tanstack/react-router'

interface AuthContextValue {
  isAuthenticated: boolean
  isLoading: boolean
  user: any | null
  login: (email: string, password: string) => Promise<void>
  logout: () => void
  checkAuth: () => Promise<boolean>
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate()
  const {
    isAuthenticated,
    user,
    token,
    login: storeLogin,
    logout: storeLogout,
    checkTokenExpiry,
    setLoading,
    isLoading
  } = useAuthStore()

  // Check authentication status on mount
  useEffect(() => {
    checkAuth()
  }, [])

  // Check token expiry periodically
  useEffect(() => {
    if (!isAuthenticated) return

    const interval = setInterval(() => {
      const isValid = checkTokenExpiry()
      if (!isValid) {
        handleLogout()
      }
    }, 60000) // Check every minute

    return () => clearInterval(interval)
  }, [isAuthenticated, checkTokenExpiry])

  const checkAuth = async (): Promise<boolean> => {
    setLoading(true)
    try {
      // Check if we have a valid token
      const hasToken = !!token
      const isValid = hasToken && checkTokenExpiry()

      if (!isValid && hasToken) {
        // Token expired, clear auth state
        storeLogout()
        return false
      }

      return isValid
    } catch (error) {
      console.error('Auth check failed:', error)
      return false
    } finally {
      setLoading(false)
    }
  }

  const login = async (email: string, password: string) => {
    setLoading(true)
    try {
      await storeLogin(email, password)

      // Redirect to dashboard after successful login
      navigate({ to: '/dashboard' })
    } catch (error) {
      // Error handling is done in the store
      throw error
    } finally {
      setLoading(false)
    }
  }

  const handleLogout = () => {
    storeLogout()
    navigate({ to: '/login' })
  }

  const value: AuthContextValue = {
    isAuthenticated,
    isLoading,
    user,
    login,
    logout: handleLogout,
    checkAuth,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider')
  }
  return context
}

// HOC for protecting routes
export function withAuth<P extends object>(Component: React.ComponentType<P>) {
  return function AuthenticatedComponent(props: P) {
    const { isAuthenticated, isLoading } = useAuth()
    const navigate = useNavigate()

    useEffect(() => {
      if (!isLoading && !isAuthenticated) {
        navigate({ to: '/login' })
      }
    }, [isAuthenticated, isLoading, navigate])

    if (isLoading) {
      return (
        <div className="min-h-screen flex items-center justify-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
        </div>
      )
    }

    if (!isAuthenticated) {
      return null
    }

    return <Component {...props} />
  }
}