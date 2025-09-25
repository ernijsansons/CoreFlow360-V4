/**
 * Chat Input Hook
 * Handles advanced chat input functionality
 */

import { useCallback, useRef } from 'react'

export const useChatInput = (textareaRef: React.RefObject<HTMLTextAreaElement>) => {
  const lastHeightRef = useRef<number>(0)

  const adjustTextareaHeight = useCallback(() => {
    if (!textareaRef.current) return

    const textarea = textareaRef.current

    // Reset height to auto to get the correct scrollHeight
    textarea.style.height = 'auto'

    // Calculate new height
    const newHeight = Math.min(textarea.scrollHeight, 120) // Max height of 120px

    // Only update if height changed to avoid infinite loops
    if (newHeight !== lastHeightRef.current) {
      textarea.style.height = `${newHeight}px`
      lastHeightRef.current = newHeight
    }
  }, [textareaRef])

  const handleKeyDown = useCallback((event: React.KeyboardEvent<HTMLTextAreaElement>) => {
    // Handle special key combinations
    if (event.key === 'Tab') {
      event.preventDefault()

      // Insert 2 spaces for tab
      const textarea = event.currentTarget
      const start = textarea.selectionStart
      const end = textarea.selectionEnd

      const value = textarea.value
      const newValue = value.substring(0, start) + '  ' + value.substring(end)

      textarea.value = newValue
      textarea.setSelectionRange(start + 2, start + 2)

      // Trigger change event
      const changeEvent = new Event('input', { bubbles: true })
      textarea.dispatchEvent(changeEvent)
    }
  }, [])

  const insertText = useCallback((text: string) => {
    if (!textareaRef.current) return

    const textarea = textareaRef.current
    const start = textarea.selectionStart
    const end = textarea.selectionEnd

    const value = textarea.value
    const newValue = value.substring(0, start) + text + value.substring(end)

    textarea.value = newValue
    textarea.setSelectionRange(start + text.length, start + text.length)

    // Trigger change event
    const changeEvent = new Event('input', { bubbles: true })
    textarea.dispatchEvent(changeEvent)

    adjustTextareaHeight()
  }, [textareaRef, adjustTextareaHeight])

  const focusInput = useCallback(() => {
    if (textareaRef.current) {
      textareaRef.current.focus()
    }
  }, [textareaRef])

  const clearInput = useCallback(() => {
    if (textareaRef.current) {
      textareaRef.current.value = ''
      textareaRef.current.style.height = 'auto'
      lastHeightRef.current = 0
    }
  }, [textareaRef])

  return {
    handleKeyDown,
    adjustTextareaHeight,
    insertText,
    focusInput,
    clearInput
  }
}

export default useChatInput