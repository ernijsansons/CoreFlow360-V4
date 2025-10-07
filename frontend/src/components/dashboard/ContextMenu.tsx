/* eslint-disable react-refresh/only-export-components */
/**
 * Context Menu Component
 * Right-click context menu for dashboard widgets with smart positioning
 */

import React, { useState, useEffect, useRef, useCallback } from 'react'
import { createPortal } from 'react-dom'
import { AnimatePresence } from 'framer-motion'
import { cn } from '@/lib/utils'
import { QuickActions } from './QuickActions'
import { actionDispatcher } from '@/services/action-dispatcher'
import type { Widget } from '@/types/dashboard'
import type { QuickAction } from './QuickActions'

export interface ContextMenuProps {
  widget: Widget
  children: React.ReactNode
  disabled?: boolean
  customActions?: QuickAction[]
  onActionExecuted?: (action: QuickAction, result: unknown) => void
  className?: string
}

export interface ContextMenuState {
  isVisible: boolean
  position: { x: number; y: number }
  selectedData?: unknown
}

export const ContextMenu: React.FC<ContextMenuProps> = ({
  widget,
  children,
  disabled = false,
  customActions = [],
  onActionExecuted,
  className
}) => {
  const [state, setState] = useState<ContextMenuState>({
    isVisible: false,
    position: { x: 0, y: 0 }
  })

  const triggerRef = useRef<HTMLDivElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)

  // Handle right-click to show context menu
  const handleContextMenu = useCallback((event: React.MouseEvent) => {
    if (disabled) return

    event.preventDefault()
    event.stopPropagation()

    const viewportWidth = window.innerWidth
    const viewportHeight = window.innerHeight

    // Calculate optimal position to keep menu within viewport
    let x = event.clientX
    let y = event.clientY

    // Estimate menu dimensions (will be adjusted after render)
    const estimatedMenuWidth = 280
    const estimatedMenuHeight = 400

    // Adjust X position if menu would overflow right edge
    if (x + estimatedMenuWidth > viewportWidth) {
      x = viewportWidth - estimatedMenuWidth - 10
    }

    // Adjust Y position if menu would overflow bottom edge
    if (y + estimatedMenuHeight > viewportHeight) {
      y = viewportHeight - estimatedMenuHeight - 10
    }

    // Ensure menu doesn't go off left or top edges
    x = Math.max(10, x)
    y = Math.max(10, y)

    setState({
      isVisible: true,
      position: { x, y },
      selectedData: event.target
    })
  }, [disabled])

  // Handle action execution
  const handleAction = useCallback(async (action: QuickAction, widget: Widget) => {
    try {
      const context = {
        widgetId: widget.id,
        dashboardId: 'current-dashboard', // TODO: Get from context
        userId: 'current-user', // TODO: Get from auth
        userRole: 'admin', // TODO: Get from auth
        selectedData: state.selectedData
      }

      const result = await actionDispatcher.executeAction(action, widget, context)

      if (result.success) {
        onActionExecuted?.(action, result)
      }

      // Handle redirects
      if (result.redirectTo) {
        window.location.href = result.redirectTo
      }

    } catch (error) {
      console.error('Failed to execute action:', error)
    } finally {
      setState(prev => ({ ...prev, isVisible: false }))
    }
  }, [state.selectedData, onActionExecuted])

  // Close menu
  const handleClose = useCallback(() => {
    setState(prev => ({ ...prev, isVisible: false }))
  }, [])

  // Handle keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && state.isVisible) {
        handleClose()
      }

      // Global keyboard shortcuts
      if (!state.isVisible && !disabled) {
        if (event.key === 'F10' || (event.shiftKey && event.key === 'F10')) {
          // Show context menu at widget center
          if (triggerRef.current) {
            const rect = triggerRef.current.getBoundingClientRect()
            setState({
              isVisible: true,
              position: {
                x: rect.left + rect.width / 2,
                y: rect.top + rect.height / 2
              }
            })
          }
        }
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [state.isVisible, disabled, handleClose])

  // Handle click outside to close menu
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (state.isVisible &&
          menuRef.current &&
          !menuRef.current.contains(event.target as Node)) {
        handleClose()
      }
    }

    if (state.isVisible) {
      document.addEventListener('mousedown', handleClickOutside)
      return () => document.removeEventListener('mousedown', handleClickOutside)
    }
  }, [state.isVisible, handleClose])

  // Optimize menu position after render
  useEffect(() => {
    if (state.isVisible && menuRef.current) {
      const menuRect = menuRef.current.getBoundingClientRect()
      const viewportWidth = window.innerWidth
      const viewportHeight = window.innerHeight

      let { x, y } = state.position
      let needsUpdate = false

      // Check if menu overflows viewport and adjust
      if (x + menuRect.width > viewportWidth) {
        x = viewportWidth - menuRect.width - 10
        needsUpdate = true
      }

      if (y + menuRect.height > viewportHeight) {
        y = viewportHeight - menuRect.height - 10
        needsUpdate = true
      }

      if (x < 10) {
        x = 10
        needsUpdate = true
      }

      if (y < 10) {
        y = 10
        needsUpdate = true
      }

      if (needsUpdate) {
        setState(prev => ({
          ...prev,
          position: { x, y }
        }))
      }
    }
  }, [state.isVisible, state.position])

  return (
    <>
      <div
        ref={triggerRef}
        onContextMenu={handleContextMenu}
        className={cn("relative", className)}
      >
        {children}
      </div>

      {typeof document !== 'undefined' && createPortal(
        <AnimatePresence>
          {state.isVisible && (
            <div
              ref={menuRef}
              className="fixed inset-0 z-50 pointer-events-none"
              style={{ zIndex: 9999 }}
            >
              <div
                className="absolute pointer-events-auto"
                style={{
                  left: state.position.x,
                  top: state.position.y
                }}
              >
                <QuickActions
                  widget={widget}
                  position={{ x: 0, y: 0 }}
                  isVisible={true}
                  onClose={handleClose}
                  onAction={handleAction}
                  customActions={customActions}
                />
              </div>
            </div>
          )}
        </AnimatePresence>,
        document.body
      )}
    </>
  )
}

// Export hooks from separate file to maintain Fast Refresh compatibility
export { useContextMenu, withContextMenu } from './context-menu-hooks';

export default ContextMenu