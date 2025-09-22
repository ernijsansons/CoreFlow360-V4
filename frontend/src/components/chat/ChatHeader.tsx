/**
 * Chat Header Component
 * Header with connection status, controls, and conversation info
 */

import React from 'react'
import { motion } from 'framer-motion'
import {
  X,
  Minimize2,
  Maximize2,
  Settings,
  Mic,
  MicOff,
  Wifi,
  WifiOff,
  MessageSquare,
  Brain
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'

export interface ChatHeaderProps {
  isConnected: boolean
  onClose: () => void
  onMinimize: () => void
  onMaximize: () => void
  onSettings: () => void
  isRecording: boolean
  onToggleRecording: () => void
  conversationTitle?: string
  className?: string
}

export const ChatHeader: React.FC<ChatHeaderProps> = ({
  isConnected,
  onClose,
  onMinimize,
  onMaximize,
  onSettings,
  isRecording,
  onToggleRecording,
  conversationTitle,
  className
}) => {
  return (
    <div className={cn(
      "absolute top-0 left-0 right-0 z-10",
      "h-16 px-4 py-3",
      "bg-white/95 dark:bg-gray-900/95",
      "backdrop-blur-md",
      "border-b border-gray-200/50 dark:border-gray-700/50",
      "flex items-center justify-between",
      className
    )}>
      {/* Left Section - Logo & Title */}
      <div className="flex items-center space-x-3">
        <div className="flex items-center space-x-2">
          <div className="relative">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-600 to-purple-600 flex items-center justify-center">
              <Brain className="w-5 h-5 text-white" />
            </div>
            {/* Connection Indicator */}
            <div className={cn(
              "absolute -top-1 -right-1 w-3 h-3 rounded-full",
              isConnected ? "bg-green-500" : "bg-red-500",
              "border-2 border-white dark:border-gray-900"
            )}>
              <motion.div
                className={cn(
                  "w-full h-full rounded-full",
                  isConnected ? "bg-green-400" : "bg-red-400"
                )}
                animate={isConnected ? {
                  scale: [1, 1.2, 1],
                  opacity: [1, 0.7, 1]
                } : {}}
                transition={{
                  duration: 2,
                  repeat: Infinity,
                  ease: "easeInOut"
                }}
              />
            </div>
          </div>

          <div className="flex flex-col">
            <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
              CoreFlow360 AI
            </h3>
            {conversationTitle && (
              <p className="text-xs text-gray-500 dark:text-gray-400 truncate max-w-32">
                {conversationTitle}
              </p>
            )}
          </div>
        </div>

        {/* Status Badge */}
        <Badge
          variant={isConnected ? "default" : "destructive"}
          className="text-xs"
        >
          <div className="flex items-center space-x-1">
            {isConnected ? (
              <Wifi className="w-3 h-3" />
            ) : (
              <WifiOff className="w-3 h-3" />
            )}
            <span>{isConnected ? "Connected" : "Disconnected"}</span>
          </div>
        </Badge>
      </div>

      {/* Right Section - Controls */}
      <div className="flex items-center space-x-1">
        {/* Voice Recording Button */}
        <Button
          variant={isRecording ? "destructive" : "ghost"}
          size="sm"
          onClick={onToggleRecording}
          className={cn(
            "w-8 h-8 p-0",
            isRecording && "animate-pulse"
          )}
          title={isRecording ? "Stop recording" : "Start voice input"}
        >
          {isRecording ? (
            <MicOff className="w-4 h-4" />
          ) : (
            <Mic className="w-4 h-4" />
          )}
        </Button>

        {/* Settings Button */}
        <Button
          variant="ghost"
          size="sm"
          onClick={onSettings}
          className="w-8 h-8 p-0"
          title="Open command palette (⌘K)"
        >
          <Settings className="w-4 h-4" />
        </Button>

        {/* Minimize Button */}
        <Button
          variant="ghost"
          size="sm"
          onClick={onMinimize}
          className="w-8 h-8 p-0"
          title="Minimize"
        >
          <Minimize2 className="w-4 h-4" />
        </Button>

        {/* Maximize Button */}
        <Button
          variant="ghost"
          size="sm"
          onClick={onMaximize}
          className="w-8 h-8 p-0"
          title="Toggle size (⌘M)"
        >
          <Maximize2 className="w-4 h-4" />
        </Button>

        {/* Close Button */}
        <Button
          variant="ghost"
          size="sm"
          onClick={onClose}
          className="w-8 h-8 p-0 hover:bg-red-100 dark:hover:bg-red-900/30"
          title="Close chat (⌘⇧C)"
        >
          <X className="w-4 h-4" />
        </Button>
      </div>
    </div>
  )
}

export default ChatHeader