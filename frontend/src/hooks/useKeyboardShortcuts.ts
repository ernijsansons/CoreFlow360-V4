/**
 * Keyboard Shortcuts Hook
 * Handles global keyboard shortcuts for accessibility
 */

import { useEffect, useCallback } from 'react'

interface KeyboardShortcut {
  key: string
  ctrlKey?: boolean
  metaKey?: boolean
  shiftKey?: boolean
  altKey?: boolean
  preventDefault?: boolean
}

type ShortcutMap = Record<string, () => void>

export const useKeyboardShortcuts = (shortcuts: ShortcutMap, enabled: boolean = true) => {
  const handleKeyDown = useCallback((event: KeyboardEvent) => {
    if (!enabled) return

    // Build shortcut string
    const parts: string[] = []

    if (event.ctrlKey) parts.push('ctrl')
    if (event.metaKey) parts.push('cmd')
    if (event.shiftKey) parts.push('shift')
    if (event.altKey) parts.push('alt')

    parts.push(event.key.toLowerCase())

    const shortcutString = parts.join('+')

    // Check for matches
    const handler = shortcuts[shortcutString]
    if (handler) {
      event.preventDefault()
      event.stopPropagation()
      handler()
    }
  }, [shortcuts, enabled])

  useEffect(() => {
    if (!enabled) return

    window.addEventListener('keydown', handleKeyDown)
    return () => {
      window.removeEventListener('keydown', handleKeyDown)
    }
  }, [handleKeyDown, enabled])
}

export default useKeyboardShortcuts