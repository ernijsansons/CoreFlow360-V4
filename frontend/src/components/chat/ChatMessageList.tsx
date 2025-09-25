/**
 * Chat Message List Component
 * Renders messages with markdown, syntax highlighting, and streaming support
 */

import React, { useEffect, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { User, Bot, Copy, ThumbsUp, ThumbsDown, RefreshCw, Download, Eye } from 'lucide-react'
import { cn } from '@/lib/utils'
import { MessageRenderer } from './MessageRenderer'
import { LoadingIndicator } from './LoadingIndicator'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import type { ChatMessage, MessageType } from '@/types/chat'

export interface ChatMessageListProps {
  messages: ChatMessage[]
  isLoading: boolean
  className?: string
  onMessageAction?: (messageId: string, action: 'copy' | 'like' | 'dislike' | 'regenerate' | 'download') => void
  onFilePreview?: (fileId: string) => void
}

const messageVariants = {
  hidden: { opacity: 0, y: 20, scale: 0.95 },
  visible: { opacity: 1, y: 0, scale: 1 },
  exit: { opacity: 0, y: -20, scale: 0.95 }
}

const MessageAvatar: React.FC<{ type: MessageType }> = ({ type }) => {
  return (
    <div className={cn(
      "w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0",
      type === 'user'
        ? "bg-blue-600 text-white"
        : "bg-gradient-to-br from-purple-600 to-blue-600 text-white"
    )}>
      {type === 'user' ? (
        <User className="w-4 h-4" />
      ) : (
        <Bot className="w-4 h-4" />
      )}
    </div>
  )
}

const MessageActions: React.FC<{
  messageId: string
  type: MessageType
  onAction?: (messageId: string, action: string) => void
}> = ({ messageId, type, onAction }) => {
  const [showActions, setShowActions] = useState(false)

  if (type === 'user') return null

  return (
    <div
      className="group relative"
      onMouseEnter={() => setShowActions(true)}
      onMouseLeave={() => setShowActions(false)}
    >
      <AnimatePresence>
        {showActions && (
          <motion.div
            className="absolute -top-2 right-0 flex items-center space-x-1 bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 p-1"
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.9 }}
            transition={{ duration: 0.15 }}
          >
            <Button
              variant="ghost"
              size="sm"
              className="w-7 h-7 p-0"
              onClick={() => onAction?.(messageId, 'copy')}
              title="Copy message"
            >
              <Copy className="w-3 h-3" />
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="w-7 h-7 p-0"
              onClick={() => onAction?.(messageId, 'like')}
              title="Like response"
            >
              <ThumbsUp className="w-3 h-3" />
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="w-7 h-7 p-0"
              onClick={() => onAction?.(messageId, 'dislike')}
              title="Dislike response"
            >
              <ThumbsDown className="w-3 h-3" />
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="w-7 h-7 p-0"
              onClick={() => onAction?.(messageId, 'regenerate')}
              title="Regenerate response"
            >
              <RefreshCw className="w-3 h-3" />
            </Button>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

const MessageItem: React.FC<{
  message: ChatMessage
  isLast: boolean
  onAction?: (messageId: string, action: string) => void
  onFilePreview?: (fileId: string) => void
}> = ({ message, isLast, onAction, onFilePreview }) => {
  return (
    <motion.div
      className={cn(
        "flex space-x-3 p-4",
        message.type === 'user' ? "bg-transparent" : "bg-gray-50/50 dark:bg-gray-800/30"
      )}
      variants={messageVariants}
      initial="hidden"
      animate="visible"
      exit="exit"
      layout
    >
      <MessageAvatar type={message.type} />

      <div className="flex-1 min-w-0 relative">
        {/* Message Header */}
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center space-x-2">
            <span className="text-sm font-medium text-gray-900 dark:text-white">
              {message.type === 'user' ? 'You' : 'CoreFlow360 AI'}
            </span>
            <span className="text-xs text-gray-500 dark:text-gray-400">
              {new Date(message.timestamp).toLocaleTimeString()}
            </span>
            {message.contextUsed && (
              <Badge variant="secondary" className="text-xs">
                Context-aware
              </Badge>
            )}
          </div>
          <MessageActions
            messageId={message.id}
            type={message.type}
            onAction={onAction}
          />
        </div>

        {/* Message Content */}
        <div className="prose prose-sm dark:prose-invert max-w-none">
          <MessageRenderer
            content={message.content}
            isStreaming={message.isStreaming}
            messageType={message.type}
          />
        </div>

        {/* File Attachments */}
        {message.attachments && message.attachments.length > 0 && (
          <div className="mt-3 space-y-2">
            {message.attachments.map((file) => (
              <div
                key={file.id}
                className="flex items-center space-x-2 p-2 bg-gray-100 dark:bg-gray-700 rounded-lg"
              >
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                    {file.name}
                  </p>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    {file.size} • {file.type}
                  </p>
                </div>
                <div className="flex items-center space-x-1">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="w-7 h-7 p-0"
                    onClick={() => onFilePreview?.(file.id)}
                    title="Preview file"
                  >
                    <Eye className="w-3 h-3" />
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="w-7 h-7 p-0"
                    onClick={() => onAction?.(message.id, 'download')}
                    title="Download file"
                  >
                    <Download className="w-3 h-3" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Sources/References */}
        {message.sources && message.sources.length > 0 && (
          <div className="mt-3">
            <details className="group">
              <summary className="text-xs text-gray-500 dark:text-gray-400 cursor-pointer hover:text-gray-700 dark:hover:text-gray-300">
                Sources ({message.sources.length})
              </summary>
              <div className="mt-2 space-y-1">
                {message.sources.map((source, index) => (
                  <div
                    key={index}
                    className="text-xs p-2 bg-blue-50 dark:bg-blue-900/20 rounded border-l-2 border-blue-300 dark:border-blue-600"
                  >
                    <div className="font-medium text-blue-900 dark:text-blue-300">
                      {source.title}
                    </div>
                    <div className="text-gray-600 dark:text-gray-400 mt-1">
                      {source.excerpt}
                    </div>
                  </div>
                ))}
              </div>
            </details>
          </div>
        )}

        {/* Streaming Indicator */}
        {message.isStreaming && (
          <div className="mt-2">
            <LoadingIndicator type="typing" />
          </div>
        )}
      </div>
    </motion.div>
  )
}

export const ChatMessageList: React.FC<ChatMessageListProps> = ({
  messages,
  isLoading,
  className,
  onMessageAction,
  onFilePreview
}) => {
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({
        behavior: 'smooth',
        block: 'end'
      })
    }
  }, [messages])

  return (
    <div
      ref={containerRef}
      className={cn(
        "flex flex-col h-full overflow-y-auto",
        "scrollbar-thin scrollbar-thumb-gray-300 dark:scrollbar-thumb-gray-600",
        "scrollbar-track-transparent",
        className
      )}
    >
      {/* Welcome Message */}
      {messages.length === 0 && !isLoading && (
        <div className="flex-1 flex items-center justify-center p-8">
          <div className="text-center max-w-md">
            <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-gradient-to-br from-blue-600 to-purple-600 flex items-center justify-center">
              <Bot className="w-8 h-8 text-white" />
            </div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
              Welcome to CoreFlow360 AI
            </h3>
            <p className="text-gray-600 dark:text-gray-400 text-sm">
              I'm your intelligent business assistant. I can help you with invoices, inventory, customer data, and much more.
              Try asking me about your business metrics or use slash commands for quick actions.
            </p>
            <div className="mt-4 flex flex-wrap gap-2 justify-center">
              <Badge variant="outline" className="text-xs">
                /invoice - Create invoices
              </Badge>
              <Badge variant="outline" className="text-xs">
                /search - Find data
              </Badge>
              <Badge variant="outline" className="text-xs">
                /reports - Generate reports
              </Badge>
            </div>
          </div>
        </div>
      )}

      {/* Messages */}
      <AnimatePresence mode="popLayout">
        {messages.map((message, index) => (
          <MessageItem
            key={message.id}
            message={message}
            isLast={index === messages.length - 1}
            onAction={onMessageAction}
            onFilePreview={onFilePreview}
          />
        ))}
      </AnimatePresence>

      {/* Loading State */}
      {isLoading && (
        <motion.div
          className="flex space-x-3 p-4 bg-gray-50/50 dark:bg-gray-800/30"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <MessageAvatar type="assistant" />
          <div className="flex-1">
            <div className="text-sm font-medium text-gray-900 dark:text-white mb-2">
              CoreFlow360 AI
            </div>
            <LoadingIndicator type="thinking" />
          </div>
        </motion.div>
      )}

      <div ref={messagesEndRef} />
    </div>
  )
}

export default ChatMessageList