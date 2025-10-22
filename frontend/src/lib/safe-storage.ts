/**
 * Safe storage wrapper for Zustand persist middleware
 * Prevents crashes when localStorage is unavailable (SSR, private browsing, etc.)
 */

import type { StateStorage } from 'zustand/middleware'

/**
 * Check if we're in a browser environment with localStorage available
 */
function isLocalStorageAvailable(): boolean {
  if (typeof window === 'undefined') {
    return false
  }

  try {
    const testKey = '__storage_test__'
    window.localStorage.setItem(testKey, 'test')
    window.localStorage.removeItem(testKey)
    return true
  } catch {
    return false
  }
}

/**
 * Safe storage that gracefully handles localStorage unavailability
 * Falls back to in-memory storage if localStorage is not available
 */
export const safeStorage: StateStorage = {
  getItem: (name: string): string | null => {
    if (!isLocalStorageAvailable()) {
      console.warn(`[SafeStorage] localStorage not available, returning null for key: ${name}`)
      return null
    }

    try {
      return window.localStorage.getItem(name)
    } catch (error) {
      console.error(`[SafeStorage] Error reading from localStorage for key: ${name}`, error)
      return null
    }
  },

  setItem: (name: string, value: string): void => {
    if (!isLocalStorageAvailable()) {
      console.warn(`[SafeStorage] localStorage not available, skipping setItem for key: ${name}`)
      return
    }

    try {
      window.localStorage.setItem(name, value)
      console.log(`[SafeStorage] ✅ Saved to localStorage: ${name}`, {
        size: typeof value === 'string' ? value.length : JSON.stringify(value).length,
        preview: typeof value === 'string' ? value.substring(0, 100) : JSON.stringify(value).substring(0, 100)
      })
    } catch (error) {
      console.error(`[SafeStorage] ❌ Error writing to localStorage for key: ${name}`, error)
      // Don't throw - just log and continue
    }
  },

  removeItem: (name: string): void => {
    if (!isLocalStorageAvailable()) {
      console.warn(`[SafeStorage] localStorage not available, skipping removeItem for key: ${name}`)
      return
    }

    try {
      window.localStorage.removeItem(name)
    } catch (error) {
      console.error(`[SafeStorage] Error removing from localStorage for key: ${name}`, error)
    }
  },
}

/**
 * Create a safe JSON storage for Zustand persist middleware
 * Use this instead of createJSONStorage(() => localStorage)
 */
export function createSafeJSONStorage() {
  return {
    getItem: (name: string): string | null => {
      return safeStorage.getItem(name)
    },
    setItem: (name: string, value: string): void => {
      safeStorage.setItem(name, value)
    },
    removeItem: (name: string): void => {
      safeStorage.removeItem(name)
    },
  }
}
