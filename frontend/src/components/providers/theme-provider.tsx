import * as React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  ThemeContext,
  ThemeConfig,
  ThemeContextValue,
  defaultTheme,
  getThemeVariables,
  getThemeClasses,
  getSystemTheme,
  getReducedMotionPreference,
  getHighContrastPreference,
  saveTheme,
  loadTheme
} from '@/lib/theme'
import { cn } from '@/lib/utils'

export interface ThemeProviderProps {
  children: React.ReactNode
  defaultTheme?: ThemeConfig
  storageKey?: string
  enableSystem?: boolean
  disableTransitionOnChange?: boolean
  attribute?: string
  value?: Partial<Record<string, string>>
}

export function ThemeProvider({
  children,
  defaultTheme: defaultThemeProp = defaultTheme,
  storageKey = 'coreflow360-theme',
  enableSystem = true,
  disableTransitionOnChange = false,
  attribute = 'data-theme',
  value,
  ...props
}: ThemeProviderProps) {
  const [theme, setThemeState] = React.useState<ThemeConfig>(defaultThemeProp)
  const [systemTheme, setSystemTheme] = React.useState<'light' | 'dark'>('light')
  const [isInitialized, setIsInitialized] = React.useState(false)

  // Resolve the actual theme mode
  const resolvedTheme = React.useMemo(() => {
    if (theme.mode === 'system') {
      return systemTheme
    }
    return theme.mode as 'light' | 'dark'
  }, [theme.mode, systemTheme])

  // Initialize theme from storage and system preferences
  React.useEffect(() => {
    const initializeTheme = () => {
      const storedTheme = loadTheme()
      const currentSystemTheme = getSystemTheme()
      const prefersReducedMotion = getReducedMotionPreference()
      const prefersHighContrast = getHighContrastPreference()

      setSystemTheme(currentSystemTheme)

      const initialTheme = {
        ...storedTheme,
        reducedMotion: storedTheme.reducedMotion || prefersReducedMotion,
        highContrast: storedTheme.highContrast || prefersHighContrast
      }

      setThemeState(initialTheme)
      setIsInitialized(true)
    }

    initializeTheme()
  }, [])

  // Listen for system theme changes
  React.useEffect(() => {
    if (!enableSystem) return

    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
    const handleChange = (e: MediaQueryListEvent) => {
      setSystemTheme(e.matches ? 'dark' : 'light')
    }

    mediaQuery.addEventListener('change', handleChange)
    return () => mediaQuery.removeEventListener('change', handleChange)
  }, [enableSystem])

  // Listen for reduced motion preference changes
  React.useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)')
    const handleChange = (e: MediaQueryListEvent) => {
      setThemeState(prev => ({
        ...prev,
        reducedMotion: e.matches
      }))
    }

    mediaQuery.addEventListener('change', handleChange)
    return () => mediaQuery.removeEventListener('change', handleChange)
  }, [])

  // Listen for high contrast preference changes
  React.useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-contrast: high)')
    const handleChange = (e: MediaQueryListEvent) => {
      setThemeState(prev => ({
        ...prev,
        highContrast: e.matches
      }))
    }

    mediaQuery.addEventListener('change', handleChange)
    return () => mediaQuery.removeEventListener('change', handleChange)
  }, [])

  // Apply theme to document
  React.useEffect(() => {
    if (!isInitialized) return

    const root = document.documentElement
    const body = document.body

    // Remove existing theme classes
    root.classList.remove('light', 'dark')
    body.classList.remove(...getThemeClasses(theme))

    // Apply new theme
    root.classList.add(resolvedTheme)
    body.classList.add(...getThemeClasses(theme))

    // Apply CSS custom properties
    const variables = getThemeVariables(theme, resolvedTheme)
    Object.entries(variables).forEach(([property, value]) => {
      root.style.setProperty(property, value)
    })

    // Apply attribute
    if (attribute) {
      root.setAttribute(attribute, resolvedTheme)
    }

    // Apply custom values
    if (value) {
      Object.entries(value).forEach(([key, val]) => {
        if (val) {
          root.setAttribute(key, val)
        }
      })
    }

    // Handle transitions
    if (disableTransitionOnChange) {
      const css = document.createElement('style')
      css.appendChild(
        document.createTextNode(
          `*,*::before,*::after{-webkit-transition:none!important;-moz-transition:none!important;-o-transition:none!important;-ms-transition:none!important;transition:none!important}`
        )
      )
      document.head.appendChild(css)

      return () => {
        // Force layout reflow
        (() => window.getComputedStyle(document.body))()

        // Wait for next tick before removing
        setTimeout(() => {
          if (document.head.contains(css)) {
            document.head.removeChild(css)
          }
        }, 1)
      }
    }
  }, [theme, resolvedTheme, isInitialized, disableTransitionOnChange, attribute, value])

  // Context methods
  const setTheme = React.useCallback((newTheme: Partial<ThemeConfig>) => {
    const updatedTheme = { ...theme, ...newTheme }
    setThemeState(updatedTheme)
    saveTheme(updatedTheme)
  }, [theme])

  const toggleTheme = React.useCallback(() => {
    const nextMode = resolvedTheme === 'light' ? 'dark' : 'light'
    setTheme({ mode: nextMode })
  }, [resolvedTheme, setTheme])

  const resetTheme = React.useCallback(() => {
    setThemeState(defaultThemeProp)
    saveTheme(defaultThemeProp)
  }, [defaultThemeProp])

  const contextValue: ThemeContextValue = {
    theme,
    setTheme,
    resolvedTheme,
    toggleTheme,
    resetTheme
  }

  if (!isInitialized) {
    return null
  }

  return (
    <ThemeContext.Provider value={contextValue} {...props}>
      <AnimatePresence mode="wait">
        <motion.div
          key={`${resolvedTheme}-${theme.colorScheme}`}
          initial={disableTransitionOnChange ? false : { opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.2 }}
          className="min-h-screen"
        >
          {children}
        </motion.div>
      </AnimatePresence>
    </ThemeContext.Provider>
  )
}

// Theme toggle button component
export interface ThemeToggleProps {
  className?: string
  size?: 'sm' | 'md' | 'lg'
  variant?: 'icon' | 'text' | 'both'
  showTooltip?: boolean
}

export function ThemeToggle({
  className,
  size = 'md',
  variant = 'icon',
  showTooltip = true
}: ThemeToggleProps) {
  const { theme, toggleTheme, resolvedTheme } = React.useContext(ThemeContext)!

  const sizeClasses = {
    sm: 'h-8 w-8 text-xs',
    md: 'h-10 w-10 text-sm',
    lg: 'h-12 w-12 text-base'
  }

  const handleClick = () => {
    toggleTheme()
  }

  return (
    <motion.button
      className={cn(
        "inline-flex items-center justify-center rounded-[var(--radius-md)]",
        "border border-[var(--color-border-default)] bg-[var(--color-bg-surface)]",
        "text-[var(--color-text-primary)] hover:bg-[var(--color-bg-hover)]",
        "focus:outline-none focus:ring-2 focus:ring-[var(--brand-8)] focus:ring-offset-2",
        "transition-colors duration-200",
        sizeClasses[size],
        className
      )}
      onClick={handleClick}
      whileHover={{ scale: 1.05 }}
      whileTap={{ scale: 0.95 }}
      title={showTooltip ? `Switch to ${resolvedTheme === 'light' ? 'dark' : 'light'} mode` : undefined}
    >
      <AnimatePresence mode="wait">
        <motion.div
          key={resolvedTheme}
          initial={{ rotate: -90, opacity: 0 }}
          animate={{ rotate: 0, opacity: 1 }}
          exit={{ rotate: 90, opacity: 0 }}
          transition={{ duration: 0.2 }}
        >
          {resolvedTheme === 'light' ? (
            <svg
              className="h-4 w-4"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"
              />
            </svg>
          ) : (
            <svg
              className="h-4 w-4"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"
              />
            </svg>
          )}
        </motion.div>
      </AnimatePresence>

      {(variant === 'text' || variant === 'both') && (
        <span className="ml-2 capitalize">
          {resolvedTheme === 'light' ? 'Dark' : 'Light'}
        </span>
      )}
    </motion.button>
  )
}

// Theme customizer component
export interface ThemeCustomizerProps {
  className?: string
  onClose?: () => void
}

export function ThemeCustomizer({ className, onClose }: ThemeCustomizerProps) {
  const { theme, setTheme, resetTheme } = React.useContext(ThemeContext)!

  return (
    <motion.div
      className={cn(
        "bg-[var(--color-bg-surface)] border border-[var(--color-border-default)]",
        "rounded-[var(--radius-lg)] p-6 shadow-[var(--shadow-lg)] space-y-6",
        "max-w-sm w-full",
        className
      )}
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.95 }}
    >
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-[var(--color-text-primary)]">
          Customize Theme
        </h3>
        {onClose && (
          <button
            onClick={onClose}
            className="text-[var(--color-text-tertiary)] hover:text-[var(--color-text-primary)]"
          >
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        )}
      </div>

      {/* Theme Mode */}
      <div className="space-y-2">
        <label className="text-sm font-medium text-[var(--color-text-primary)]">
          Theme Mode
        </label>
        <div className="flex gap-2">
          {(['light', 'dark', 'system'] as const).map((mode) => (
            <button
              key={mode}
              onClick={() => setTheme({ mode })}
              className={cn(
                "px-3 py-2 text-xs rounded-[var(--radius-md)] border transition-colors",
                theme.mode === mode
                  ? "bg-[var(--brand-8)] text-white border-[var(--brand-8)]"
                  : "bg-[var(--color-bg-surface)] text-[var(--color-text-secondary)] border-[var(--color-border-default)] hover:bg-[var(--color-bg-hover)]"
              )}
            >
              {mode.charAt(0).toUpperCase() + mode.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Color Scheme */}
      <div className="space-y-2">
        <label className="text-sm font-medium text-[var(--color-text-primary)]">
          Color Scheme
        </label>
        <div className="grid grid-cols-3 gap-2">
          {(['blue', 'violet', 'green', 'orange', 'red', 'slate'] as const).map((scheme) => (
            <button
              key={scheme}
              onClick={() => setTheme({ colorScheme: scheme })}
              className={cn(
                "px-3 py-2 text-xs rounded-[var(--radius-md)] border transition-colors",
                theme.colorScheme === scheme
                  ? "bg-[var(--brand-8)] text-white border-[var(--brand-8)]"
                  : "bg-[var(--color-bg-surface)] text-[var(--color-text-secondary)] border-[var(--color-border-default)] hover:bg-[var(--color-bg-hover)]"
              )}
            >
              {scheme.charAt(0).toUpperCase() + scheme.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Density */}
      <div className="space-y-2">
        <label className="text-sm font-medium text-[var(--color-text-primary)]">
          Density
        </label>
        <div className="flex gap-2">
          {(['compact', 'comfortable', 'spacious'] as const).map((density) => (
            <button
              key={density}
              onClick={() => setTheme({ density })}
              className={cn(
                "px-3 py-2 text-xs rounded-[var(--radius-md)] border transition-colors",
                theme.density === density
                  ? "bg-[var(--brand-8)] text-white border-[var(--brand-8)]"
                  : "bg-[var(--color-bg-surface)] text-[var(--color-text-secondary)] border-[var(--color-border-default)] hover:bg-[var(--color-bg-hover)]"
              )}
            >
              {density.charAt(0).toUpperCase() + density.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Toggles */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium text-[var(--color-text-primary)]">
            Animations
          </span>
          <button
            onClick={() => setTheme({ animations: !theme.animations })}
            className={cn(
              "relative inline-flex h-6 w-11 items-center rounded-full transition-colors",
              theme.animations ? "bg-[var(--brand-8)]" : "bg-[var(--color-bg-muted)]"
            )}
          >
            <span
              className={cn(
                "inline-block h-4 w-4 transform rounded-full bg-white transition-transform",
                theme.animations ? "translate-x-6" : "translate-x-1"
              )}
            />
          </button>
        </div>

        <div className="flex items-center justify-between">
          <span className="text-sm font-medium text-[var(--color-text-primary)]">
            High Contrast
          </span>
          <button
            onClick={() => setTheme({ highContrast: !theme.highContrast })}
            className={cn(
              "relative inline-flex h-6 w-11 items-center rounded-full transition-colors",
              theme.highContrast ? "bg-[var(--brand-8)]" : "bg-[var(--color-bg-muted)]"
            )}
          >
            <span
              className={cn(
                "inline-block h-4 w-4 transform rounded-full bg-white transition-transform",
                theme.highContrast ? "translate-x-6" : "translate-x-1"
              )}
            />
          </button>
        </div>
      </div>

      {/* Reset Button */}
      <button
        onClick={resetTheme}
        className="w-full px-4 py-2 text-sm font-medium text-[var(--color-text-secondary)] border border-[var(--color-border-default)] rounded-[var(--radius-md)] hover:bg-[var(--color-bg-hover)] transition-colors"
      >
        Reset to Default
      </button>
    </motion.div>
  )
}