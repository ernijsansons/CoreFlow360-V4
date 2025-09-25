/**
 * Loading Indicator Component
 * Various loading states for chat interface
 */

import React from 'react'
import { motion } from 'framer-motion'
import { cn } from '@/lib/utils'

export interface LoadingIndicatorProps {
  type: 'thinking' | 'typing' | 'processing' | 'uploading'
  className?: string
  message?: string
}

const DotAnimation: React.FC<{ className?: string }> = ({ className }) => (
  <div className={cn("flex space-x-1", className)}>
    {[0, 1, 2].map((i) => (
      <motion.div
        key={i}
        className="w-2 h-2 bg-blue-600 rounded-full"
        animate={{ opacity: [0.4, 1, 0.4] }}
        transition={{
          duration: 1.2,
          repeat: Infinity,
          delay: i * 0.2
        }}
      />
    ))}
  </div>
)

const PulseAnimation: React.FC<{ className?: string }> = ({ className }) => (
  <motion.div
    className={cn("w-4 h-4 bg-blue-600 rounded-full", className)}
    animate={{ scale: [1, 1.2, 1] }}
    transition={{
      duration: 1,
      repeat: Infinity,
      ease: "easeInOut"
    }}
  />
)

const SpinnerAnimation: React.FC<{ className?: string }> = ({ className }) => (
  <motion.div
    className={cn("w-4 h-4 border-2 border-blue-600 border-t-transparent rounded-full", className)}
    animate={{ rotate: 360 }}
    transition={{
      duration: 1,
      repeat: Infinity,
      ease: "linear"
    }}
  />
)

const ProgressBar: React.FC<{ className?: string }> = ({ className }) => (
  <div className={cn("w-32 h-1 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden", className)}>
    <motion.div
      className="h-full bg-blue-600 rounded-full"
      animate={{ x: ["-100%", "100%"] }}
      transition={{
        duration: 1.5,
        repeat: Infinity,
        ease: "easeInOut"
      }}
      style={{ width: "50%" }}
    />
  </div>
)

const getLoadingContent = (type: LoadingIndicatorProps['type']) => {
  switch (type) {
    case 'thinking':
      return {
        animation: <DotAnimation />,
        text: "Thinking..."
      }
    case 'typing':
      return {
        animation: <DotAnimation />,
        text: "Typing..."
      }
    case 'processing':
      return {
        animation: <SpinnerAnimation />,
        text: "Processing..."
      }
    case 'uploading':
      return {
        animation: <ProgressBar />,
        text: "Uploading..."
      }
    default:
      return {
        animation: <PulseAnimation />,
        text: "Loading..."
      }
  }
}

export const LoadingIndicator: React.FC<LoadingIndicatorProps> = ({
  type,
  className,
  message
}) => {
  const { animation, text } = getLoadingContent(type)

  return (
    <div className={cn(
      "flex items-center space-x-3 text-gray-500 dark:text-gray-400",
      className
    )}>
      {animation}
      <span className="text-sm">
        {message || text}
      </span>
    </div>
  )
}

export default LoadingIndicator