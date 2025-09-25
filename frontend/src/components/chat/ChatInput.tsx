/**
 * Chat Input Component
 * Advanced input with file upload, commands, and voice support
 */

import React, { useState, useRef, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Send,
  Paperclip,
  Smile,
  Command,
  Mic,
  MicOff,
  X,
  Image,
  FileText,
  Plus
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import { FileUploadZone } from './FileUploadZone'
import { EmojiPicker } from './EmojiPicker'
import { useChatInput } from '@/hooks/useChatInput'
import type { FileAttachment } from '@/types/chat'

export interface ChatInputProps {
  onSendMessage: (message: string, attachments?: FileAttachment[]) => void
  onShowCommands: () => void
  isLoading?: boolean
  placeholder?: string
  maxLength?: number
  transcriptText?: string
  isRecording?: boolean
  className?: string
}

export const ChatInput: React.FC<ChatInputProps> = ({
  onSendMessage,
  onShowCommands,
  isLoading = false,
  placeholder = "Type your message...",
  maxLength = 4000,
  transcriptText,
  isRecording = false,
  className
}) => {
  const [message, setMessage] = useState('')
  const [attachments, setAttachments] = useState<FileAttachment[]>([])
  const [showFileUpload, setShowFileUpload] = useState(false)
  const [showEmojiPicker, setShowEmojiPicker] = useState(false)
  const [isDragOver, setIsDragOver] = useState(false)

  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const {
    handleKeyDown,
    adjustTextareaHeight,
    insertText,
    focusInput
  } = useChatInput(textareaRef)

  // Update message from voice transcript
  useEffect(() => {
    if (transcriptText && transcriptText !== message) {
      setMessage(transcriptText)
      adjustTextareaHeight()
    }
  }, [transcriptText, message, adjustTextareaHeight])

  // Auto-focus and resize
  useEffect(() => {
    if (textareaRef.current) {
      adjustTextareaHeight()
    }
  }, [message, adjustTextareaHeight])

  const handleSend = useCallback(() => {
    const trimmedMessage = message.trim()
    if (!trimmedMessage && attachments.length === 0) return
    if (isLoading) return

    onSendMessage(trimmedMessage, attachments)
    setMessage('')
    setAttachments([])
    setShowFileUpload(false)
    setShowEmojiPicker(false)

    // Reset textarea height
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto'
    }
  }, [message, attachments, isLoading, onSendMessage])

  const handleKeyPress = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.ctrlKey && !e.altKey) {
      e.preventDefault()
      handleSend()
    } else if (e.key === '/' && message === '') {
      e.preventDefault()
      onShowCommands()
    }
  }, [message, handleSend, onShowCommands])

  const handleFileUpload = useCallback((files: FileAttachment[]) => {
    setAttachments(prev => [...prev, ...files])
    setShowFileUpload(false)
  }, [])

  const removeAttachment = useCallback((id: string) => {
    setAttachments(prev => prev.filter(file => file.id !== id))
  }, [])

  const handleEmojiSelect = useCallback((emoji: string) => {
    insertText(emoji)
    setShowEmojiPicker(false)
    focusInput()
  }, [insertText, focusInput])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragOver(false)

    const files = Array.from(e.dataTransfer.files)
    // Handle file upload logic here
  }, [])

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragOver(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragOver(false)
  }, [])

  const canSend = message.trim().length > 0 || attachments.length > 0

  return (
    <div className={cn("relative", className)}>
      {/* Drag Overlay */}
      <AnimatePresence>
        {isDragOver && (
          <motion.div
            className="absolute inset-0 bg-blue-500/10 border-2 border-dashed border-blue-500 rounded-lg flex items-center justify-center z-20"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
          >
            <div className="text-center">
              <Paperclip className="w-8 h-8 text-blue-500 mx-auto mb-2" />
              <p className="text-blue-700 font-medium">Drop files to attach</p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* File Attachments */}
      <AnimatePresence>
        {attachments.length > 0 && (
          <motion.div
            className="mb-3 flex flex-wrap gap-2"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
          >
            {attachments.map((file) => (
              <motion.div
                key={file.id}
                className="flex items-center space-x-2 bg-gray-100 dark:bg-gray-800 rounded-lg px-3 py-2"
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.9 }}
              >
                {file.type.startsWith('image/') ? (
                  <Image className="w-4 h-4 text-gray-500" />
                ) : (
                  <FileText className="w-4 h-4 text-gray-500" />
                )}
                <span className="text-sm text-gray-700 dark:text-gray-300 truncate max-w-32">
                  {file.name}
                </span>
                <Button
                  variant="ghost"
                  size="sm"
                  className="w-5 h-5 p-0 hover:bg-red-100 dark:hover:bg-red-900/30"
                  onClick={() => removeAttachment(file.id)}
                >
                  <X className="w-3 h-3" />
                </Button>
              </motion.div>
            ))}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Input Container */}
      <div className={cn(
        "relative rounded-lg border border-gray-200 dark:border-gray-700",
        "bg-white dark:bg-gray-800",
        "focus-within:ring-2 focus-within:ring-blue-500 focus-within:border-transparent",
        "transition-all duration-200",
        isDragOver && "border-blue-500 bg-blue-50 dark:bg-blue-900/20"
      )}>
        {/* Voice Recording Indicator */}
        <AnimatePresence>
          {isRecording && (
            <motion.div
              className="absolute top-3 left-3 z-10"
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.9 }}
            >
              <Badge variant="destructive" className="text-xs animate-pulse">
                <Mic className="w-3 h-3 mr-1" />
                Recording...
              </Badge>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Main Input Area */}
        <div className="flex items-end p-3 space-x-2">
          {/* Action Buttons - Left */}
          <div className="flex items-center space-x-1">
            <Button
              variant="ghost"
              size="sm"
              className="w-8 h-8 p-0"
              onClick={() => setShowFileUpload(!showFileUpload)}
              title="Attach files"
            >
              <Paperclip className="w-4 h-4" />
            </Button>

            <Button
              variant="ghost"
              size="sm"
              className="w-8 h-8 p-0"
              onClick={() => setShowEmojiPicker(!showEmojiPicker)}
              title="Add emoji"
            >
              <Smile className="w-4 h-4" />
            </Button>

            <Button
              variant="ghost"
              size="sm"
              className="w-8 h-8 p-0"
              onClick={onShowCommands}
              title="Commands (⌘K)"
            >
              <Command className="w-4 h-4" />
            </Button>
          </div>

          {/* Text Input */}
          <div className="flex-1 relative">
            <Textarea
              ref={textareaRef}
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              onKeyDown={handleKeyPress}
              placeholder={isRecording ? "Listening..." : placeholder}
              disabled={isLoading || isRecording}
              maxLength={maxLength}
              className={cn(
                "min-h-[40px] max-h-32 resize-none",
                "border-0 bg-transparent p-0",
                "focus:ring-0 focus:border-transparent",
                "placeholder:text-gray-400 dark:placeholder:text-gray-500",
                isRecording && "text-blue-600"
              )}
              onDrop={handleDrop}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
            />

            {/* Character Counter */}
            {message.length > maxLength * 0.8 && (
              <div className="absolute bottom-1 right-2 text-xs text-gray-400">
                {message.length}/{maxLength}
              </div>
            )}
          </div>

          {/* Send Button */}
          <Button
            onClick={handleSend}
            disabled={!canSend || isLoading}
            size="sm"
            className={cn(
              "w-8 h-8 p-0 shrink-0",
              canSend && !isLoading && "bg-blue-600 hover:bg-blue-700"
            )}
          >
            <Send className="w-4 h-4" />
          </Button>
        </div>
      </div>

      {/* File Upload Zone */}
      <AnimatePresence>
        {showFileUpload && (
          <motion.div
            className="mt-2"
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
          >
            <FileUploadZone
              onFileUpload={handleFileUpload}
              onClose={() => setShowFileUpload(false)}
              maxFiles={5}
              maxSize={10 * 1024 * 1024} // 10MB
              acceptedTypes={[
                'image/*',
                'application/pdf',
                'text/*',
                'application/json',
                'application/csv'
              ]}
            />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Emoji Picker */}
      <AnimatePresence>
        {showEmojiPicker && (
          <motion.div
            className="absolute bottom-full left-0 mb-2 z-30"
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.9 }}
          >
            <EmojiPicker
              onEmojiSelect={handleEmojiSelect}
              onClose={() => setShowEmojiPicker(false)}
            />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Hidden File Input */}
      <input
        ref={fileInputRef}
        type="file"
        multiple
        className="hidden"
        accept="image/*,application/pdf,text/*,.json,.csv"
        onChange={(e) => {
          const files = Array.from(e.target.files || [])
          // Handle file upload logic here
        }}
      />
    </div>
  )
}

export default ChatInput