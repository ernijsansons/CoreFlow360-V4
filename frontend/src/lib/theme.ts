import { createContext, useContext } from 'react'

export type ThemeMode = 'light' | 'dark' | 'system'
export type ColorScheme = 'blue' | 'violet' | 'green' | 'orange' | 'red' | 'slate'
export type Density = 'compact' | 'comfortable' | 'spacious'
export type BorderRadius = 'none' | 'small' | 'medium' | 'large' | 'full'
export type FontScale = 'small' | 'medium' | 'large' | 'extra-large'

export interface ThemeConfig {
  mode: ThemeMode
  colorScheme: ColorScheme
  density: Density
  borderRadius: BorderRadius
  fontScale: FontScale
  animations: boolean
  reducedMotion: boolean
  highContrast: boolean
  customProperties?: Record<string, string>
}

export const defaultTheme: ThemeConfig = {
  mode: 'system',
  colorScheme: 'blue',
  density: 'comfortable',
  borderRadius: 'medium',
  fontScale: 'medium',
  animations: true,
  reducedMotion: false,
  highContrast: false
}

// Theme context
export interface ThemeContextValue {
  theme: ThemeConfig
  setTheme: (theme: Partial<ThemeConfig>) => void
  resolvedTheme: 'light' | 'dark'
  toggleTheme: () => void
  resetTheme: () => void
}

export const ThemeContext = createContext<ThemeContextValue | undefined>(undefined)

export const useTheme = () => {
  const context = useContext(ThemeContext)
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider')
  }
  return context
}

// Theme utilities
export const getThemeVariables = (theme: ThemeConfig, resolvedMode: 'light' | 'dark'): Record<string, string> => {
  const variables: Record<string, string> = {}

  // Color scheme variables
  const colorSchemes = {
    blue: {
      light: {
        'brand-1': '#f0f9ff',
        'brand-2': '#e0f2fe',
        'brand-3': '#bae6fd',
        'brand-4': '#7dd3fc',
        'brand-5': '#38bdf8',
        'brand-6': '#0ea5e9',
        'brand-7': '#0284c7',
        'brand-8': '#0369a1',
        'brand-9': '#075985',
        'brand-10': '#0c4a6e',
        'brand-11': '#082f49',
        'brand-12': '#0f172a'
      },
      dark: {
        'brand-1': '#0f172a',
        'brand-2': '#082f49',
        'brand-3': '#0c4a6e',
        'brand-4': '#075985',
        'brand-5': '#0369a1',
        'brand-6': '#0284c7',
        'brand-7': '#0ea5e9',
        'brand-8': '#38bdf8',
        'brand-9': '#7dd3fc',
        'brand-10': '#bae6fd',
        'brand-11': '#e0f2fe',
        'brand-12': '#f0f9ff'
      }
    },
    violet: {
      light: {
        'brand-1': '#faf5ff',
        'brand-2': '#f3e8ff',
        'brand-3': '#e9d5ff',
        'brand-4': '#d8b4fe',
        'brand-5': '#c084fc',
        'brand-6': '#a855f7',
        'brand-7': '#9333ea',
        'brand-8': '#7c3aed',
        'brand-9': '#6d28d9',
        'brand-10': '#5b21b6',
        'brand-11': '#4c1d95',
        'brand-12': '#2e1065'
      },
      dark: {
        'brand-1': '#2e1065',
        'brand-2': '#4c1d95',
        'brand-3': '#5b21b6',
        'brand-4': '#6d28d9',
        'brand-5': '#7c3aed',
        'brand-6': '#9333ea',
        'brand-7': '#a855f7',
        'brand-8': '#c084fc',
        'brand-9': '#d8b4fe',
        'brand-10': '#e9d5ff',
        'brand-11': '#f3e8ff',
        'brand-12': '#faf5ff'
      }
    },
    green: {
      light: {
        'brand-1': '#f0fdf4',
        'brand-2': '#dcfce7',
        'brand-3': '#bbf7d0',
        'brand-4': '#86efac',
        'brand-5': '#4ade80',
        'brand-6': '#22c55e',
        'brand-7': '#16a34a',
        'brand-8': '#15803d',
        'brand-9': '#166534',
        'brand-10': '#14532d',
        'brand-11': '#052e16',
        'brand-12': '#064e3b'
      },
      dark: {
        'brand-1': '#064e3b',
        'brand-2': '#052e16',
        'brand-3': '#14532d',
        'brand-4': '#166534',
        'brand-5': '#15803d',
        'brand-6': '#16a34a',
        'brand-7': '#22c55e',
        'brand-8': '#4ade80',
        'brand-9': '#86efac',
        'brand-10': '#bbf7d0',
        'brand-11': '#dcfce7',
        'brand-12': '#f0fdf4'
      }
    },
    orange: {
      light: {
        'brand-1': '#fff7ed',
        'brand-2': '#ffedd5',
        'brand-3': '#fed7aa',
        'brand-4': '#fdba74',
        'brand-5': '#fb923c',
        'brand-6': '#f97316',
        'brand-7': '#ea580c',
        'brand-8': '#dc2626',
        'brand-9': '#c2410c',
        'brand-10': '#9a3412',
        'brand-11': '#7c2d12',
        'brand-12': '#431407'
      },
      dark: {
        'brand-1': '#431407',
        'brand-2': '#7c2d12',
        'brand-3': '#9a3412',
        'brand-4': '#c2410c',
        'brand-5': '#dc2626',
        'brand-6': '#ea580c',
        'brand-7': '#f97316',
        'brand-8': '#fb923c',
        'brand-9': '#fdba74',
        'brand-10': '#fed7aa',
        'brand-11': '#ffedd5',
        'brand-12': '#fff7ed'
      }
    },
    red: {
      light: {
        'brand-1': '#fef2f2',
        'brand-2': '#fecaca',
        'brand-3': '#fca5a5',
        'brand-4': '#f87171',
        'brand-5': '#ef4444',
        'brand-6': '#dc2626',
        'brand-7': '#b91c1c',
        'brand-8': '#991b1b',
        'brand-9': '#7f1d1d',
        'brand-10': '#450a0a',
        'brand-11': '#7f1d1d',
        'brand-12': '#1f2937'
      },
      dark: {
        'brand-1': '#1f2937',
        'brand-2': '#7f1d1d',
        'brand-3': '#450a0a',
        'brand-4': '#7f1d1d',
        'brand-5': '#991b1b',
        'brand-6': '#b91c1c',
        'brand-7': '#dc2626',
        'brand-8': '#ef4444',
        'brand-9': '#f87171',
        'brand-10': '#fca5a5',
        'brand-11': '#fecaca',
        'brand-12': '#fef2f2'
      }
    },
    slate: {
      light: {
        'brand-1': '#f8fafc',
        'brand-2': '#f1f5f9',
        'brand-3': '#e2e8f0',
        'brand-4': '#cbd5e1',
        'brand-5': '#94a3b8',
        'brand-6': '#64748b',
        'brand-7': '#475569',
        'brand-8': '#334155',
        'brand-9': '#1e293b',
        'brand-10': '#0f172a',
        'brand-11': '#020617',
        'brand-12': '#000000'
      },
      dark: {
        'brand-1': '#000000',
        'brand-2': '#020617',
        'brand-3': '#0f172a',
        'brand-4': '#1e293b',
        'brand-5': '#334155',
        'brand-6': '#475569',
        'brand-7': '#64748b',
        'brand-8': '#94a3b8',
        'brand-9': '#cbd5e1',
        'brand-10': '#e2e8f0',
        'brand-11': '#f1f5f9',
        'brand-12': '#f8fafc'
      }
    }
  }

  // Apply color scheme
  const schemeColors = colorSchemes[theme.colorScheme][resolvedMode]
  Object.entries(schemeColors).forEach(([key, value]) => {
    variables[`--${key}`] = value
  })

  // Density variables
  const densityScales = {
    compact: {
      'spacing-xs': '0.25rem',
      'spacing-sm': '0.5rem',
      'spacing-md': '0.75rem',
      'spacing-lg': '1rem',
      'spacing-xl': '1.5rem',
      'spacing-2xl': '2rem',
      'font-size-xs': '0.75rem',
      'font-size-sm': '0.875rem',
      'font-size-base': '1rem',
      'font-size-lg': '1.125rem',
      'font-size-xl': '1.25rem',
      'font-size-2xl': '1.5rem'
    },
    comfortable: {
      'spacing-xs': '0.5rem',
      'spacing-sm': '0.75rem',
      'spacing-md': '1rem',
      'spacing-lg': '1.5rem',
      'spacing-xl': '2rem',
      'spacing-2xl': '3rem',
      'font-size-xs': '0.75rem',
      'font-size-sm': '0.875rem',
      'font-size-base': '1rem',
      'font-size-lg': '1.125rem',
      'font-size-xl': '1.25rem',
      'font-size-2xl': '1.5rem'
    },
    spacious: {
      'spacing-xs': '0.75rem',
      'spacing-sm': '1rem',
      'spacing-md': '1.5rem',
      'spacing-lg': '2rem',
      'spacing-xl': '3rem',
      'spacing-2xl': '4rem',
      'font-size-xs': '0.875rem',
      'font-size-sm': '1rem',
      'font-size-base': '1.125rem',
      'font-size-lg': '1.25rem',
      'font-size-xl': '1.5rem',
      'font-size-2xl': '1.75rem'
    }
  }

  Object.entries(densityScales[theme.density]).forEach(([key, value]) => {
    variables[`--${key}`] = value
  })

  // Border radius
  const radiusValues = {
    none: {
      'radius-sm': '0',
      'radius-md': '0',
      'radius-lg': '0',
      'radius-xl': '0',
      'radius-2xl': '0'
    },
    small: {
      'radius-sm': '0.125rem',
      'radius-md': '0.25rem',
      'radius-lg': '0.375rem',
      'radius-xl': '0.5rem',
      'radius-2xl': '0.75rem'
    },
    medium: {
      'radius-sm': '0.25rem',
      'radius-md': '0.375rem',
      'radius-lg': '0.5rem',
      'radius-xl': '0.75rem',
      'radius-2xl': '1rem'
    },
    large: {
      'radius-sm': '0.5rem',
      'radius-md': '0.75rem',
      'radius-lg': '1rem',
      'radius-xl': '1.25rem',
      'radius-2xl': '1.5rem'
    },
    full: {
      'radius-sm': '9999px',
      'radius-md': '9999px',
      'radius-lg': '9999px',
      'radius-xl': '9999px',
      'radius-2xl': '9999px'
    }
  }

  Object.entries(radiusValues[theme.borderRadius]).forEach(([key, value]) => {
    variables[`--${key}`] = value
  })

  // Font scale
  const fontScales = {
    small: {
      'font-scale': '0.9',
      'line-height-tight': '1.2',
      'line-height-normal': '1.4',
      'line-height-relaxed': '1.6'
    },
    medium: {
      'font-scale': '1',
      'line-height-tight': '1.25',
      'line-height-normal': '1.5',
      'line-height-relaxed': '1.75'
    },
    large: {
      'font-scale': '1.1',
      'line-height-tight': '1.3',
      'line-height-normal': '1.6',
      'line-height-relaxed': '1.8'
    },
    'extra-large': {
      'font-scale': '1.2',
      'line-height-tight': '1.35',
      'line-height-normal': '1.65',
      'line-height-relaxed': '1.85'
    }
  }

  Object.entries(fontScales[theme.fontScale]).forEach(([key, value]) => {
    variables[`--${key}`] = value
  })

  // High contrast adjustments
  if (theme.highContrast) {
    variables['--color-text-primary'] = resolvedMode === 'light' ? '#000000' : '#ffffff'
    variables['--color-border-default'] = resolvedMode === 'light' ? '#000000' : '#ffffff'
  }

  // Custom properties
  if (theme.customProperties) {
    Object.entries(theme.customProperties).forEach(([key, value]) => {
      variables[key] = value
    })
  }

  return variables
}

// CSS class generators
export const getThemeClasses = (theme: ThemeConfig): string[] => {
  const classes = []

  classes.push(`theme-${theme.colorScheme}`)
  classes.push(`density-${theme.density}`)
  classes.push(`radius-${theme.borderRadius}`)
  classes.push(`font-scale-${theme.fontScale}`)

  if (!theme.animations || theme.reducedMotion) {
    classes.push('motion-reduce')
  }

  if (theme.highContrast) {
    classes.push('high-contrast')
  }

  return classes
}

// Theme presets
export const themePresets = {
  'corporate': {
    mode: 'light' as ThemeMode,
    colorScheme: 'slate' as ColorScheme,
    density: 'comfortable' as Density,
    borderRadius: 'small' as BorderRadius,
    fontScale: 'medium' as FontScale,
    animations: true,
    reducedMotion: false,
    highContrast: false
  },
  'modern': {
    mode: 'system' as ThemeMode,
    colorScheme: 'blue' as ColorScheme,
    density: 'comfortable' as Density,
    borderRadius: 'medium' as BorderRadius,
    fontScale: 'medium' as FontScale,
    animations: true,
    reducedMotion: false,
    highContrast: false
  },
  'vibrant': {
    mode: 'dark' as ThemeMode,
    colorScheme: 'violet' as ColorScheme,
    density: 'spacious' as Density,
    borderRadius: 'large' as BorderRadius,
    fontScale: 'large' as FontScale,
    animations: true,
    reducedMotion: false,
    highContrast: false
  },
  'minimal': {
    mode: 'light' as ThemeMode,
    colorScheme: 'slate' as ColorScheme,
    density: 'compact' as Density,
    borderRadius: 'none' as BorderRadius,
    fontScale: 'small' as FontScale,
    animations: false,
    reducedMotion: true,
    highContrast: false
  },
  'accessible': {
    mode: 'light' as ThemeMode,
    colorScheme: 'blue' as ColorScheme,
    density: 'spacious' as Density,
    borderRadius: 'medium' as BorderRadius,
    fontScale: 'extra-large' as FontScale,
    animations: false,
    reducedMotion: true,
    highContrast: true
  }
} as const

// Theme storage
export const THEME_STORAGE_KEY = 'coreflow360-theme'

export const saveTheme = (theme: ThemeConfig) => {
  try {
    localStorage.setItem(THEME_STORAGE_KEY, JSON.stringify(theme))
  } catch (error) {
    console.warn('Failed to save theme to localStorage:', error)
  }
}

export const loadTheme = (): ThemeConfig => {
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY)
    if (stored) {
      return { ...defaultTheme, ...JSON.parse(stored) }
    }
  } catch (error) {
    console.warn('Failed to load theme from localStorage:', error)
  }
  return defaultTheme
}

// System preference detection
export const getSystemTheme = (): 'light' | 'dark' => {
  if (typeof window !== 'undefined' && window.matchMedia) {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  }
  return 'light'
}

export const getReducedMotionPreference = (): boolean => {
  if (typeof window !== 'undefined' && window.matchMedia) {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches
  }
  return false
}

export const getHighContrastPreference = (): boolean => {
  if (typeof window !== 'undefined' && window.matchMedia) {
    return window.matchMedia('(prefers-contrast: high)').matches
  }
  return false
}