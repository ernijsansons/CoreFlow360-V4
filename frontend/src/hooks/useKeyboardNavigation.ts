/**
 * Keyboard Navigation Hook
 * Handles keyboard navigation for lists and menus
 */

import { useEffect, useCallback } from 'react'

interface KeyboardNavigationOptions {
  isEnabled: boolean
  itemCount: number
  selectedIndex: number
  onSelectionChange: (index: number) => void
  onSelect: () => void
  onEscape?: () => void
  loop?: boolean
}

export const useKeyboardNavigation = ({
  isEnabled,
  itemCount,
  selectedIndex,
  onSelectionChange,
  onSelect,
  onEscape,
  loop = true
}: KeyboardNavigationOptions) => {
  const handleKeyDown = useCallback((event: KeyboardEvent) => {
    if (!isEnabled || itemCount === 0) return

    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault()
        const nextIndex = selectedIndex + 1
        if (nextIndex < itemCount) {
          onSelectionChange(nextIndex)
        } else if (loop) {
          onSelectionChange(0)
        }
        break

      case 'ArrowUp':
        event.preventDefault()
        const prevIndex = selectedIndex - 1
        if (prevIndex >= 0) {
          onSelectionChange(prevIndex)
        } else if (loop) {
          onSelectionChange(itemCount - 1)
        }
        break

      case 'Enter':
        event.preventDefault()
        onSelect()
        break

      case 'Escape':
        event.preventDefault()
        onEscape?.()
        break

      case 'Home':
        event.preventDefault()
        onSelectionChange(0)
        break

      case 'End':
        event.preventDefault()
        onSelectionChange(itemCount - 1)
        break
    }
  }, [isEnabled, itemCount, selectedIndex, onSelectionChange, onSelect, onEscape, loop])

  useEffect(() => {
    if (!isEnabled) return

    window.addEventListener('keydown', handleKeyDown)
    return () => {
      window.removeEventListener('keydown', handleKeyDown)
    }
  }, [handleKeyDown, isEnabled])
}

export default useKeyboardNavigation