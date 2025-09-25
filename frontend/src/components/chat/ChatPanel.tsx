/**
 * AI Chat Panel Component
 * Sliding panel with magnetic snap points and glass morphism design
 */

import React, { useState, useRef, useEffect, useCallback } from 'react'
import { motion, AnimatePresence, PanInfo, useMotionValue, useTransform } from 'framer-motion'
import { MessageSquare, X, Maximize2, Minimize2, Settings, Mic, MicOff } from 'lucide-react'
import { cn } from '@/lib/utils'
import { ChatMessageList } from './ChatMessageList'
import { ChatInput } from './ChatInput'
import { ChatHeader } from './ChatHeader'
import { CommandPalette } from './CommandPalette'
import { useChatStore } from '@/stores/chatStore'
import { useKeyboardShortcuts } from '@/hooks/useKeyboardShortcuts'
import { useVoiceRecording } from '@/hooks/useVoiceRecording'

export interface ChatPanelProps {
  className?: string
  defaultPosition?: 'right' | 'left' | 'center'
  defaultSize?: 'compact' | 'normal' | 'expanded'
  onToggle?: (isOpen: boolean) => void
}

const SNAP_POINTS = {
  closed: 0,
  peek: 80,
  normal: 400,
  expanded: 600,
  fullscreen: '100vw'
}

const MAGNETIC_THRESHOLD = 50

export const ChatPanel: React.FC<ChatPanelProps> = ({
  className,
  defaultPosition = 'right',
  defaultSize = 'normal',
  onToggle
}) => {
  const [isOpen, setIsOpen] = useState(false)
  const [panelSize, setPanelSize] = useState<keyof typeof SNAP_POINTS>(defaultSize)
  const [position, setPosition] = useState(defaultPosition)
  const [isDragging, setIsDragging] = useState(false)
  const [showCommandPalette, setShowCommandPalette] = useState(false)

  const panelRef = useRef<HTMLDivElement>(null)
  const x = useMotionValue(0)
  const y = useMotionValue(0)

  const {
    messages,
    isLoading,
    currentConversation,
    isConnected,
    togglePanel,
    sendMessage
  } = useChatStore()

  const {
    isRecording,
    startRecording,
    stopRecording,
    transcriptText
  } = useVoiceRecording()

  // Transform values for smooth animations
  const opacity = useTransform(x, [-300, 0, 300], [0.7, 1, 0.7])
  const scale = useTransform(x, [-300, 0, 300], [0.95, 1, 0.95])

  // Keyboard shortcuts
  useKeyboardShortcuts({
    'cmd+k': () => setShowCommandPalette(true),
    'cmd+shift+c': () => handleToggle(),
    'cmd+m': () => setPanelSize(panelSize === 'expanded' ? 'normal' : 'expanded'),
    'escape': () => {
      if (showCommandPalette) setShowCommandPalette(false)
      else if (isOpen) handleToggle()
    }
  })

  const handleToggle = useCallback(() => {
    const newState = !isOpen
    setIsOpen(newState)
    onToggle?.(newState)
    togglePanel()
  }, [isOpen, onToggle, togglePanel])

  const handleDragEnd = useCallback((event: any, info: PanInfo) => {
    setIsDragging(false)

    const { offset, velocity } = info
    const { innerWidth } = window

    // Magnetic snapping logic
    const snapToClosest = (value: number, snapPoints: number[]) => {
      return snapPoints.reduce((prev, curr) => {
        return Math.abs(curr - value) < Math.abs(prev - value) ? curr : prev
      })
    }

    // Calculate new position based on drag
    if (position === 'right') {
      const targetX = offset.x + velocity.x * 0.2
      if (targetX > MAGNETIC_THRESHOLD) {
        setIsOpen(false)
        x.set(0)
      } else {
        x.set(0)
      }
    }

    // Handle panel size changes based on drag distance
    const dragDistance = Math.abs(offset.x)
    if (dragDistance > 100) {
      if (panelSize === 'normal') {
        setPanelSize('expanded')
      } else if (panelSize === 'expanded') {
        setPanelSize('normal')
      }
    }
  }, [position, panelSize, x])

  const getPanelWidth = () => {
    if (typeof SNAP_POINTS[panelSize] === 'string') {
      return SNAP_POINTS[panelSize] as string
    }
    return `${SNAP_POINTS[panelSize]}px`
  }

  const panelVariants = {
    closed: {
      x: position === 'right' ? '100%' : position === 'left' ? '-100%' : '50%',
      opacity: 0,
      scale: 0.95
    },
    open: {
      x: 0,
      opacity: 1,
      scale: 1
    }
  }

  const backdropVariants = {
    closed: { opacity: 0 },
    open: { opacity: 1 }
  }

  return (
    <>
      {/* Chat Toggle Button */}
      <motion.button
        onClick={handleToggle}
        className={cn(
          "fixed bottom-6 right-6 z-40",
          "w-14 h-14 rounded-full",
          "bg-gradient-to-r from-blue-600 to-purple-600",
          "shadow-xl hover:shadow-2xl",
          "flex items-center justify-center",
          "text-white transition-all duration-300",
          "hover:scale-110 active:scale-95",
          isOpen && "scale-0 opacity-0"
        )}
        whileHover={{ scale: 1.1 }}
        whileTap={{ scale: 0.95 }}
        initial={false}
        animate={{
          scale: isOpen ? 0 : 1,
          opacity: isOpen ? 0 : 1
        }}
      >
        <MessageSquare className="w-6 h-6" />
      </motion.button>

      {/* Backdrop */}
      <AnimatePresence>
        {isOpen && panelSize !== 'compact' && (
          <motion.div
            className="fixed inset-0 bg-black/20 backdrop-blur-sm z-30"
            variants={backdropVariants}
            initial="closed"
            animate="open"
            exit="closed"
            onClick={() => panelSize !== 'fullscreen' && handleToggle()}
          />
        )}
      </AnimatePresence>

      {/* Chat Panel */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            ref={panelRef}
            className={cn(
              "fixed top-0 z-50",
              position === 'right' && "right-0",
              position === 'left' && "left-0",
              position === 'center' && "left-1/2 -translate-x-1/2",
              "h-full",
              "bg-white/90 dark:bg-gray-900/90",
              "backdrop-blur-xl border-l border-gray-200/50 dark:border-gray-700/50",
              "shadow-2xl",
              isDragging && "cursor-grabbing",
              className
            )}
            style={{
              width: getPanelWidth(),
              x,
              y,
              opacity,
              scale
            }}
            variants={panelVariants}
            initial="closed"
            animate="open"
            exit="closed"
            transition={{
              type: "spring",
              damping: 25,
              stiffness: 200,
              mass: 0.5
            }}
            drag={panelSize !== 'fullscreen'}
            dragConstraints={{ left: -100, right: 100, top: 0, bottom: 0 }}
            dragElastic={0.1}
            onDragStart={() => setIsDragging(true)}
            onDragEnd={handleDragEnd}
          >
            {/* Panel Header */}
            <ChatHeader
              isConnected={isConnected}
              onClose={handleToggle}
              onMinimize={() => setPanelSize('compact')}
              onMaximize={() => setPanelSize(panelSize === 'expanded' ? 'normal' : 'expanded')}
              onSettings={() => setShowCommandPalette(true)}
              isRecording={isRecording}
              onToggleRecording={isRecording ? stopRecording : startRecording}
              conversationTitle={currentConversation?.title}
            />

            {/* Panel Content */}
            <div className="flex flex-col h-full pt-16">
              {/* Messages Area */}
              <div className="flex-1 overflow-hidden">
                <ChatMessageList
                  messages={messages}
                  isLoading={isLoading}
                  className="h-full"
                />
              </div>

              {/* Input Area */}
              <div className="border-t border-gray-200/50 dark:border-gray-700/50 p-4">
                <ChatInput
                  onSendMessage={sendMessage}
                  isLoading={isLoading}
                  placeholder="Ask CoreFlow360 AI anything..."
                  onShowCommands={() => setShowCommandPalette(true)}
                  transcriptText={transcriptText}
                  isRecording={isRecording}
                />
              </div>
            </div>

            {/* Resize Handle */}
            {panelSize !== 'fullscreen' && (
              <div
                className={cn(
                  "absolute top-0 w-1 h-full cursor-ew-resize",
                  "bg-transparent hover:bg-blue-500/20",
                  "transition-colors duration-200",
                  position === 'right' && "left-0",
                  position === 'left' && "right-0"
                )}
                onMouseDown={(e) => {
                  e.preventDefault()
                  // Handle resize logic here
                }}
              />
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Command Palette */}
      <CommandPalette
        isOpen={showCommandPalette}
        onClose={() => setShowCommandPalette(false)}
        onCommand={(command) => {
          setShowCommandPalette(false)
          // Handle command execution
        }}
      />
    </>
  )
}

export default ChatPanel