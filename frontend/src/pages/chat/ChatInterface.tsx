import { useState, useEffect, useRef } from 'react'
import {
  useConversations,
  useConversationMessages,
  useSendMessage,
  useCreateConversation,
  useArchiveConversation
} from '@/hooks/api'
import { Card } from '@/components/ui/card-refactored'
import { Button } from '@/components/ui/button-refactored'
import { Input } from '@/components/ui/input-refactored'
import { Badge } from '@/components/ui/badge-refactored'
import { Loader2, Send, Plus, Archive, Bot, User } from 'lucide-react'

export function ChatInterface() {
  const [selectedConversation, setSelectedConversation] = useState<string | null>(null)
  const [messageInput, setMessageInput] = useState('')
  const messagesEndRef = useRef<HTMLDivElement>(null)

  const { data: conversations } = useConversations({ status: 'active' })
  const { data: messages, isLoading: messagesLoading } = useConversationMessages(
    selectedConversation || '',
    { limit: 100 }
  )
  const sendMessage = useSendMessage()
  const createConversation = useCreateConversation()
  const archiveConversation = useArchiveConversation()

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  const handleSendMessage = () => {
    if (!messageInput.trim()) return

    sendMessage.mutate(
      {
        conversation_id: selectedConversation || undefined,
        message: messageInput
      },
      {
        onSuccess: (data) => {
          if (!selectedConversation) {
            setSelectedConversation(data.data.conversation_id)
          }
          setMessageInput('')
        }
      }
    )
  }

  const handleNewConversation = () => {
    createConversation.mutate(undefined, {
      onSuccess: (data) => {
        setSelectedConversation(data.data.id)
      }
    })
  }

  return (
    <div className="container mx-auto py-8 h-[calc(100vh-8rem)]">
      <div className="grid grid-cols-12 gap-6 h-full">
        {/* Conversations Sidebar */}
        <Card className="col-span-3 p-4 overflow-hidden flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-bold">Conversations</h2>
            <Button size="sm" onClick={handleNewConversation}>
              <Plus className="h-4 w-4" />
            </Button>
          </div>

          <div className="flex-1 overflow-y-auto space-y-2">
            {conversations?.data?.map((conversation) => (
              <div
                key={conversation.id}
                className={`p-3 rounded-lg cursor-pointer transition-colors ${
                  selectedConversation === conversation.id
                    ? 'bg-brand-primary text-white'
                    : 'hover:bg-gray-100 dark:hover:bg-gray-800'
                }`}
                onClick={() => setSelectedConversation(conversation.id)}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <p className="font-medium text-sm line-clamp-1">
                      {conversation.title || 'New Conversation'}
                    </p>
                    <p className="text-xs opacity-75 mt-1">
                      {new Date(conversation.updated_at).toLocaleDateString()}
                    </p>
                  </div>
                  <Badge variant="secondary" className="text-xs">
                    {conversation.message_count}
                  </Badge>
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* Chat Area */}
        <Card className="col-span-9 flex flex-col overflow-hidden">
          {selectedConversation ? (
            <>
              {/* Chat Header */}
              <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="h-10 w-10 rounded-full bg-brand-primary/10 flex items-center justify-center">
                    <Bot className="h-5 w-5 text-brand-primary" />
                  </div>
                  <div>
                    <h3 className="font-semibold">AI Assistant</h3>
                    <p className="text-sm text-gray-500">Always here to help</p>
                  </div>
                </div>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    archiveConversation.mutate(selectedConversation)
                    setSelectedConversation(null)
                  }}
                >
                  <Archive className="h-4 w-4" />
                </Button>
              </div>

              {/* Messages */}
              <div className="flex-1 overflow-y-auto p-6 space-y-4">
                {messagesLoading ? (
                  <div className="flex items-center justify-center h-full">
                    <Loader2 className="h-8 w-8 animate-spin text-brand-primary" />
                  </div>
                ) : messages?.data && messages.data.length > 0 ? (
                  <>
                    {messages.data.map((message) => (
                      <div
                        key={message.id}
                        className={`flex ${
                          message.role === 'user' ? 'justify-end' : 'justify-start'
                        }`}
                      >
                        <div
                          className={`max-w-[70%] ${
                            message.role === 'user'
                              ? 'bg-brand-primary text-white'
                              : 'bg-gray-100 dark:bg-gray-800'
                          } rounded-lg p-4`}
                        >
                          <div className="flex items-start space-x-2">
                            {message.role === 'assistant' && (
                              <Bot className="h-5 w-5 mt-0.5 flex-shrink-0" />
                            )}
                            <div className="flex-1">
                              <p className="text-sm whitespace-pre-wrap">{message.content}</p>
                              <p
                                className={`text-xs mt-2 ${
                                  message.role === 'user' ? 'opacity-75' : 'text-gray-500'
                                }`}
                              >
                                {new Date(message.created_at).toLocaleTimeString()}
                              </p>
                            </div>
                            {message.role === 'user' && (
                              <User className="h-5 w-5 mt-0.5 flex-shrink-0" />
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                    <div ref={messagesEndRef} />
                  </>
                ) : (
                  <div className="flex items-center justify-center h-full text-gray-500">
                    Start a conversation with the AI assistant
                  </div>
                )}
              </div>

              {/* Input Area */}
              <div className="p-4 border-t border-gray-200 dark:border-gray-700">
                <div className="flex space-x-2">
                  <Input
                    value={messageInput}
                    onChange={(e) => setMessageInput(e.target.value)}
                    onKeyPress={(e) => {
                      if (e.key === 'Enter' && !e.shiftKey) {
                        e.preventDefault()
                        handleSendMessage()
                      }
                    }}
                    placeholder="Type your message..."
                    className="flex-1"
                    disabled={sendMessage.isPending}
                  />
                  <Button
                    onClick={handleSendMessage}
                    disabled={!messageInput.trim() || sendMessage.isPending}
                  >
                    {sendMessage.isPending ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Send className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              </div>
            </>
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-gray-500 space-y-4">
              <Bot className="h-16 w-16" />
              <p className="text-lg">Select a conversation or start a new one</p>
              <Button onClick={handleNewConversation}>
                <Plus className="h-4 w-4 mr-2" />
                New Conversation
              </Button>
            </div>
          )}
        </Card>
      </div>
    </div>
  )
}
