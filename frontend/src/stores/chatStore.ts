/**
 * Chat Store
 * Zustand store for chat state management with performance optimizations
 */

import { create } from 'zustand'
import { immer } from 'zustand/middleware/immer'
import { persist } from 'zustand/middleware'
import type { ChatMessage, Conversation } from '@/types/chat'

interface ChatState {
  // Connection state
  isConnected: boolean
  isLoading: boolean
  error: string | null

  // Chat panel state
  isPanelOpen: boolean
  panelSize: 'compact' | 'normal' | 'expanded'
  panelPosition: 'left' | 'right' | 'center'

  // Current conversation
  currentConversation: Conversation | null
  messages: ChatMessage[]

  // Conversations list
  conversations: Conversation[]
  conversationsLoading: boolean

  // Performance optimizations
  messageCache: Map<string, ChatMessage[]>
  lastActivity: number
}

interface ChatActions {
  // Connection actions
  setConnected: (connected: boolean) => void
  setLoading: (loading: boolean) => void
  setError: (error: string | null) => void

  // Panel actions
  togglePanel: () => void
  setPanelSize: (size: ChatState['panelSize']) => void
  setPanelPosition: (position: ChatState['panelPosition']) => void

  // Message actions
  sendMessage: (content: string, attachments?: any[]) => Promise<void>
  addMessage: (message: ChatMessage) => void
  updateMessage: (messageId: string, updates: Partial<ChatMessage>) => void
  clearMessages: () => void

  // Conversation actions
  setCurrentConversation: (conversation: Conversation | null) => void
  loadConversations: () => Promise<void>
  createConversation: (title?: string) => Promise<void>
  deleteConversation: (conversationId: string) => Promise<void>

  // Performance actions
  optimizeMemory: () => void
  updateActivity: () => void
}

type ChatStore = ChatState & ChatActions

const MEMORY_LIMIT = 1000 // Maximum messages to keep in memory
const CACHE_LIMIT = 50 // Maximum conversations to cache
const ACTIVITY_TIMEOUT = 5 * 60 * 1000 // 5 minutes

export const useChatStore = create<ChatStore>()(
  persist(
    immer((set, get) => ({
      // Initial state
      isConnected: false,
      isLoading: false,
      error: null,
      isPanelOpen: false,
      panelSize: 'normal',
      panelPosition: 'right',
      currentConversation: null,
      messages: [],
      conversations: [],
      conversationsLoading: false,
      messageCache: new Map(),
      lastActivity: Date.now(),

      // Connection actions
      setConnected: (connected) =>
        set((state) => {
          state.isConnected = connected
          if (connected) {
            state.error = null
          }
        }),

      setLoading: (loading) =>
        set((state) => {
          state.isLoading = loading
        }),

      setError: (error) =>
        set((state) => {
          state.error = error
          if (error) {
            state.isLoading = false
          }
        }),

      // Panel actions
      togglePanel: () =>
        set((state) => {
          state.isPanelOpen = !state.isPanelOpen
          state.lastActivity = Date.now()
        }),

      setPanelSize: (size) =>
        set((state) => {
          state.panelSize = size
        }),

      setPanelPosition: (position) =>
        set((state) => {
          state.panelPosition = position
        }),

      // Message actions
      sendMessage: async (content, attachments) => {
        const state = get()

        // Update activity
        state.updateActivity()

        // Set loading state
        set((state) => {
          state.isLoading = true
          state.error = null
        })

        try {
          // Create user message
          const userMessage: ChatMessage = {
            id: crypto.randomUUID(),
            conversationId: state.currentConversation?.id || 'temp',
            type: 'user',
            content,
            attachments,
            timestamp: new Date().toISOString(),
            contextUsed: false,
            isStreaming: false
          }

          // Add user message immediately
          state.addMessage(userMessage)

          // Create conversation if none exists
          if (!state.currentConversation) {
            await state.createConversation()
          }

          // Send to API
          const response = await fetch('/api/v1/chat/message', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              conversationId: state.currentConversation?.id,
              message: content,
              attachments
            })
          })

          if (!response.ok) {
            throw new Error(`API error: ${response.statusText}`)
          }

          // Handle streaming response
          if (response.body) {
            const reader = response.body.getReader()
            const decoder = new TextDecoder()

            let assistantMessage: ChatMessage = {
              id: crypto.randomUUID(),
              conversationId: state.currentConversation?.id || 'temp',
              type: 'assistant',
              content: '',
              timestamp: new Date().toISOString(),
              contextUsed: true,
              isStreaming: true
            }

            state.addMessage(assistantMessage)

            try {
              while (true) {
                const { done, value } = await reader.read()

                if (done) break

                const chunk = decoder.decode(value, { stream: true })
                const lines = chunk.split('\n')

                for (const line of lines) {
                  if (line.startsWith('data: ')) {
                    const data = line.slice(6)

                    if (data === '[DONE]') {
                      state.updateMessage(assistantMessage.id, {
                        isStreaming: false
                      })
                      break
                    }

                    try {
                      const parsed = JSON.parse(data)

                      if (parsed.type === 'content' && parsed.content) {
                        assistantMessage.content += parsed.content
                        state.updateMessage(assistantMessage.id, {
                          content: assistantMessage.content
                        })
                      }

                      if (parsed.type === 'done') {
                        state.updateMessage(assistantMessage.id, {
                          isStreaming: false,
                          content: parsed.content || assistantMessage.content
                        })
                        break
                      }
                    } catch (parseError) {
                      console.warn('Failed to parse streaming chunk:', parseError)
                    }
                  }
                }
              }
            } catch (streamError) {
              console.error('Streaming error:', streamError)
              state.updateMessage(assistantMessage.id, {
                isStreaming: false,
                content: assistantMessage.content || 'Sorry, I encountered an error processing your request.'
              })
            }
          }

        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Unknown error'
          set((state) => {
            state.error = errorMessage
          })

          // Add error message
          const errorMsg: ChatMessage = {
            id: crypto.randomUUID(),
            conversationId: state.currentConversation?.id || 'temp',
            type: 'assistant',
            content: `Sorry, I encountered an error: ${errorMessage}`,
            timestamp: new Date().toISOString(),
            contextUsed: false,
            isStreaming: false
          }

          state.addMessage(errorMsg)
        } finally {
          set((state) => {
            state.isLoading = false
          })
        }
      },

      addMessage: (message) =>
        set((state) => {
          state.messages.push(message)
          state.lastActivity = Date.now()

          // Cache message
          if (message.conversationId && message.conversationId !== 'temp') {
            const cached = state.messageCache.get(message.conversationId) || []
            cached.push(message)
            state.messageCache.set(message.conversationId, cached)
          }

          // Memory optimization
          if (state.messages.length > MEMORY_LIMIT) {
            state.messages = state.messages.slice(-MEMORY_LIMIT / 2)
          }
        }),

      updateMessage: (messageId, updates) =>
        set((state) => {
          const messageIndex = state.messages.findIndex(m => m.id === messageId)
          if (messageIndex !== -1) {
            Object.assign(state.messages[messageIndex], updates)

            // Update cache
            const message = state.messages[messageIndex]
            if (message.conversationId && message.conversationId !== 'temp') {
              const cached = state.messageCache.get(message.conversationId) || []
              const cachedIndex = cached.findIndex(m => m.id === messageId)
              if (cachedIndex !== -1) {
                Object.assign(cached[cachedIndex], updates)
              }
            }
          }
          state.lastActivity = Date.now()
        }),

      clearMessages: () =>
        set((state) => {
          state.messages = []
        }),

      // Conversation actions
      setCurrentConversation: (conversation) =>
        set((state) => {
          state.currentConversation = conversation

          if (conversation) {
            // Load cached messages
            const cached = state.messageCache.get(conversation.id)
            if (cached) {
              state.messages = cached
            } else {
              state.messages = []
              // Load messages from server in background
              loadConversationMessages(conversation.id)
            }
          } else {
            state.messages = []
          }

          state.lastActivity = Date.now()
        }),

      loadConversations: async () => {
        set((state) => {
          state.conversationsLoading = true
        })

        try {
          const response = await fetch('/api/v1/chat/conversations')

          if (!response.ok) {
            throw new Error(`Failed to load conversations: ${response.statusText}`)
          }

          const result = await response.json()

          set((state) => {
            state.conversations = result.conversations || []
            state.conversationsLoading = false
          })

        } catch (error) {
          set((state) => {
            state.error = error instanceof Error ? error.message : 'Failed to load conversations'
            state.conversationsLoading = false
          })
        }
      },

      createConversation: async (title) => {
        try {
          const response = await fetch('/api/v1/chat/conversations', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ title })
          })

          if (!response.ok) {
            throw new Error(`Failed to create conversation: ${response.statusText}`)
          }

          const conversation = await response.json()

          set((state) => {
            state.currentConversation = conversation
            state.conversations.unshift(conversation)
            state.messages = []
          })

        } catch (error) {
          set((state) => {
            state.error = error instanceof Error ? error.message : 'Failed to create conversation'
          })
        }
      },

      deleteConversation: async (conversationId) => {
        try {
          const response = await fetch(`/api/v1/chat/conversations/${conversationId}`, {
            method: 'DELETE'
          })

          if (!response.ok) {
            throw new Error(`Failed to delete conversation: ${response.statusText}`)
          }

          set((state) => {
            state.conversations = state.conversations.filter(c => c.id !== conversationId)
            state.messageCache.delete(conversationId)

            if (state.currentConversation?.id === conversationId) {
              state.currentConversation = null
              state.messages = []
            }
          })

        } catch (error) {
          set((state) => {
            state.error = error instanceof Error ? error.message : 'Failed to delete conversation'
          })
        }
      },

      // Performance actions
      optimizeMemory: () =>
        set((state) => {
          const now = Date.now()

          // Clear old cached messages
          if (now - state.lastActivity > ACTIVITY_TIMEOUT) {
            // Keep only current conversation in cache
            const currentId = state.currentConversation?.id
            if (currentId) {
              const currentMessages = state.messageCache.get(currentId)
              state.messageCache.clear()
              if (currentMessages) {
                state.messageCache.set(currentId, currentMessages)
              }
            } else {
              state.messageCache.clear()
            }
          }

          // Limit cache size
          if (state.messageCache.size > CACHE_LIMIT) {
            const entries = Array.from(state.messageCache.entries())
            const toKeep = entries.slice(-CACHE_LIMIT / 2)
            state.messageCache.clear()
            toKeep.forEach(([key, value]) => {
              state.messageCache.set(key, value)
            })
          }
        }),

      updateActivity: () =>
        set((state) => {
          state.lastActivity = Date.now()
        })
    })),
    {
      name: 'chat-store',
      partialize: (state) => ({
        panelSize: state.panelSize,
        panelPosition: state.panelPosition,
        conversations: state.conversations
      })
    }
  )
)

// Helper function to load conversation messages
async function loadConversationMessages(conversationId: string) {
  try {
    const response = await fetch(`/api/v1/chat/conversations/${conversationId}/messages`)

    if (response.ok) {
      const result = await response.json()
      const messages = result.messages || []

      // Update store with loaded messages
      useChatStore.setState((state) => {
        if (state.currentConversation?.id === conversationId) {
          state.messages = messages
        }
        state.messageCache.set(conversationId, messages)
      })
    }
  } catch (error) {
    console.error('Failed to load conversation messages:', error)
  }
}

// Performance optimization - run memory cleanup periodically
if (typeof window !== 'undefined') {
  setInterval(() => {
    useChatStore.getState().optimizeMemory()
  }, 60000) // Every minute
}

export default useChatStore