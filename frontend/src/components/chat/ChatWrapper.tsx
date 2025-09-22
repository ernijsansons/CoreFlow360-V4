/**
 * Chat Wrapper Component
 * Responsive wrapper that shows desktop or mobile chat based on screen size
 */

import React, { useState, useEffect } from 'react'
import { ChatPanel } from './ChatPanel'
import { ChatMobile } from './ChatMobile'
import { useMediaQuery } from '@/hooks/useMediaQuery'

export interface ChatWrapperProps {
  userId: string
  businessId: string
  className?: string
}

export const ChatWrapper: React.FC<ChatWrapperProps> = ({
  userId,
  businessId,
  className
}) => {
  const isMobile = useMediaQuery('(max-width: 768px)')
  const [mounted, setMounted] = useState(false)

  // Prevent hydration mismatch
  useEffect(() => {
    setMounted(true)
  }, [])

  if (!mounted) {
    return null // or a loading skeleton
  }

  return (
    <>
      {isMobile ? (
        <ChatMobile
          userId={userId}
          businessId={businessId}
          className={className}
        />
      ) : (
        <ChatPanel
          className={className}
          defaultPosition="right"
          defaultSize="normal"
        />
      )}
    </>
  )
}

export default ChatWrapper