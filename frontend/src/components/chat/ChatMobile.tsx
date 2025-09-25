/**
 * Mobile Chat Component
 * Optimized chat interface for mobile devices
 */

import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence, PanInfo } from 'framer-motion'
import {
  MessageSquare,
  X,
  Minimize2,
  ArrowDown,
  Menu,
  Send,
  Mic,
  MicOff,
  Paperclip
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { ChatMessageList } from './ChatMessageList'
import { CommandPalette } from './CommandPalette'
import { SmartSuggestions } from './SmartSuggestions'
import { useChatStore } from '@/stores/chatStore'
import { useVoiceRecording } from '@/hooks/useVoiceRecording'

export interface ChatMobileProps {
  userId: string
  businessId: string
  className?: string
}

type MobileViewMode = 'minimized' | 'suggestions' | 'chat' | 'fullscreen'

export const ChatMobile: React.FC<ChatMobileProps> = ({
  userId,
  businessId,
  className
}) => {
  const [viewMode, setViewMode] = useState<MobileViewMode>('minimized')
  const [showCommands, setShowCommands] = useState(false)
  const [inputValue, setInputValue] = useState('')
  const [keyboardHeight, setKeyboardHeight] = useState(0)

  const {
    messages,
    isLoading,
    isConnected,
    sendMessage
  } = useChatStore()

  const {
    isRecording,
    startRecording,
    stopRecording,
    transcriptText
  } = useVoiceRecording()

  // Handle keyboard appearance on mobile
  useEffect(() => {
    const handleResize = () => {
      if (window.visualViewport) {
        const heightDiff = window.innerHeight - window.visualViewport.height
        setKeyboardHeight(heightDiff)
      }
    }

    if (window.visualViewport) {
      window.visualViewport.addEventListener('resize', handleResize)
      return () => {
        window.visualViewport.removeEventListener('resize', handleResize)
      }
    }
  }, [])

  // Update input with voice transcript
  useEffect(() => {
    if (transcriptText) {
      setInputValue(transcriptText)
    }
  }, [transcriptText])

  const handleSend = () => {
    if (!inputValue.trim()) return
    sendMessage(inputValue.trim())
    setInputValue('')
  }

  const handleDragEnd = (event: any, info: PanInfo) => {
    const { offset, velocity } = info

    if (offset.y > 100 || velocity.y > 500) {
      // Drag down - minimize or close
      if (viewMode === 'fullscreen') {
        setViewMode('chat')
      } else if (viewMode === 'chat') {
        setViewMode('suggestions')
      } else if (viewMode === 'suggestions') {
        setViewMode('minimized')
      }
    } else if (offset.y < -100 || velocity.y < -500) {
      // Drag up - expand
      if (viewMode === 'minimized') {
        setViewMode('suggestions')
      } else if (viewMode === 'suggestions') {
        setViewMode('chat')
      } else if (viewMode === 'chat') {
        setViewMode('fullscreen')
      }
    }
  }

  const getContainerHeight = () => {
    switch (viewMode) {
      case 'minimized':
        return '60px'
      case 'suggestions':
        return '40vh'
      case 'chat':
        return '70vh'
      case 'fullscreen':
        return '100vh'
    }
  }

  const getContainerClass = () => {
    return cn(
      "fixed bottom-0 left-0 right-0 z-50",
      "bg-white dark:bg-gray-900",
      "border-t border-gray-200 dark:border-gray-700",
      "shadow-xl",
      viewMode === 'fullscreen' && "border-t-0"
    )
  }

  return (
    <>
      {/* Backdrop for fullscreen mode */}
      <AnimatePresence>
        {viewMode === 'fullscreen' && (
          <motion.div
            className="fixed inset-0 bg-black/20 z-40"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          />
        )}
      </AnimatePresence>

      {/* Main Container */}
      <motion.div
        className={cn(getContainerClass(), className)}
        style={{
          height: getContainerHeight(),
          paddingBottom: keyboardHeight > 0 ? `${keyboardHeight}px` : '0px'
        }}
        drag="y"
        dragConstraints={{ top: 0, bottom: 0 }}
        dragElastic={0.1}
        onDragEnd={handleDragEnd}
        initial={false}
        animate={{
          height: getContainerHeight()
        }}
        transition={{
          type: "spring",
          damping: 25,
          stiffness: 200
        }}
      >
        {/* Drag Handle */}
        <div className="flex justify-center py-2">
          <div className="w-10 h-1 bg-gray-300 dark:bg-gray-600 rounded-full" />
        </div>

        {/* Header */}
        <div className="flex items-center justify-between px-4 py-2 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-600 to-purple-600 flex items-center justify-center">
              <MessageSquare className="w-5 h-5 text-white" />
            </div>
            <div>
              <h3 className="font-semibold text-gray-900 dark:text-white text-sm">
                CoreFlow360 AI
              </h3>
              <div className="flex items-center space-x-1 text-xs text-gray-500">
                <div className={cn(
                  "w-2 h-2 rounded-full",
                  isConnected ? "bg-green-500" : "bg-red-500"
                )} />
                <span>{isConnected ? 'Online' : 'Offline'}</span>
              </div>
            </div>
          </div>

          <div className="flex items-center space-x-1">
            {viewMode !== 'minimized' && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowCommands(true)}
                className="w-8 h-8 p-0"
              >
                <Menu className="w-4 h-4" />
              </Button>
            )}

            <Button
              variant="ghost"
              size="sm"
              onClick={() => setViewMode('minimized')}
              className="w-8 h-8 p-0"
            >
              {viewMode === 'fullscreen' ? <X className="w-4 h-4" /> : <Minimize2 className="w-4 h-4" />}
            </Button>
          </div>
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-hidden">
          {viewMode === 'minimized' && (
            <div className="p-4 flex items-center justify-between">
              <span className="text-sm text-gray-600 dark:text-gray-400">
                Tap to expand chat
              </span>
              <ArrowDown className="w-4 h-4 text-gray-400" />
            </div>
          )}

          {viewMode === 'suggestions' && (
            <div className="h-full overflow-y-auto">
              <SmartSuggestions
                userId={userId}
                businessId={businessId}
                className="p-4"
                onSuggestionSelect={() => setViewMode('chat')}
              />
            </div>
          )}

          {(viewMode === 'chat' || viewMode === 'fullscreen') && (
            <div className="h-full flex flex-col">
              {/* Messages */}
              <div className="flex-1 overflow-hidden">
                <ChatMessageList
                  messages={messages}
                  isLoading={isLoading}
                  className="h-full"
                />
              </div>

              {/* Input Area */}
              <div className="border-t border-gray-200 dark:border-gray-700 p-3">
                <div className="flex items-center space-x-2">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="w-8 h-8 p-0"
                    onClick={() => {
                      // File upload functionality
                    }}
                  >
                    <Paperclip className="w-4 h-4" />
                  </Button>

                  <div className="flex-1 relative">
                    <Input
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && !e.shiftKey) {
                          e.preventDefault()
                          handleSend()
                        }
                      }}
                      placeholder={isRecording ? "Listening..." : "Type a message..."}
                      disabled={isLoading || isRecording}
                      className={cn(
                        "pr-20",
                        isRecording && "text-blue-600"
                      )}
                    />

                    <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center space-x-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={isRecording ? stopRecording : startRecording}
                        className={cn(
                          "w-6 h-6 p-0",
                          isRecording && "text-red-600"
                        )}
                      >
                        {isRecording ? <MicOff className="w-3 h-3" /> : <Mic className="w-3 h-3" />}
                      </Button>

                      <Button
                        size="sm"
                        onClick={handleSend}
                        disabled={!inputValue.trim() || isLoading}
                        className="w-6 h-6 p-0"
                      >
                        <Send className="w-3 h-3" />
                      </Button>
                    </div>
                  </div>
                </div>

                {/* Quick Actions */}
                <div className="flex items-center space-x-2 mt-2 overflow-x-auto">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => sendMessage('/invoice')}
                    className="h-7 px-3 text-xs whitespace-nowrap"
                  >
                    📄 Invoice
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => sendMessage('/search')}
                    className="h-7 px-3 text-xs whitespace-nowrap"
                  >
                    🔍 Search
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => sendMessage('/reports')}
                    className="h-7 px-3 text-xs whitespace-nowrap"
                  >
                    📊 Reports
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => sendMessage('What can you help me with?')}
                    className="h-7 px-3 text-xs whitespace-nowrap"
                  >
                    ❓ Help
                  </Button>
                </div>
              </div>
            </div>
          )}
        </div>
      </motion.div>

      {/* Command Palette */}
      <CommandPalette
        isOpen={showCommands}
        onClose={() => setShowCommands(false)}
        onCommand={() => {
          setShowCommands(false)
          setViewMode('chat')
        }}
      />
    </>
  )
}

export default ChatMobile