/**
 * Chat/Messaging System
 * Team collaboration with AI assistance
 */

import { createFileRoute } from '@tanstack/react-router';
import { useState, useEffect, useRef } from 'react';
import { MainLayout } from '@/layouts/main-layout';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import {
  MessageSquare,
  Send,
  Plus,
  Search,
  Paperclip,
  Mic,
  MoreVertical,
  Users,
  Hash,
  Trash2,
  Edit,
  Star,
  Archive,
  Bot,
  Sparkles,
  X,
  Image,
  File,
  Check,
  CheckCheck
} from 'lucide-react';

export const Route = createFileRoute('/chat')({
  component: ChatPage,
});

interface Message {
  id: string;
  conversationId: string;
  senderId: string;
  senderName: string;
  senderAvatar?: string;
  content: string;
  timestamp: string;
  attachments?: Array<{
    id: string;
    name: string;
    type: string;
    url: string;
    size: number;
  }>;
  read: boolean;
  reactions?: Array<{
    emoji: string;
    userId: string;
    userName: string;
  }>;
}

interface Conversation {
  id: string;
  title: string;
  type: 'direct' | 'channel' | 'ai';
  participants: Array<{
    id: string;
    name: string;
    avatar?: string;
    status: 'online' | 'away' | 'offline';
  }>;
  lastMessage?: {
    content: string;
    timestamp: string;
    senderId: string;
  };
  unreadCount: number;
  pinned: boolean;
  archived: boolean;
}

interface AISuggestion {
  id: string;
  type: 'response' | 'action' | 'insight';
  title: string;
  content: string;
  action?: {
    label: string;
    type: string;
  };
}

function ChatPage() {
  const [conversations, setConversations] = useState<Conversation[]>([
    {
      id: 'conv-1',
      title: 'Product Launch Team',
      type: 'channel',
      participants: [
        { id: 'u1', name: 'Sarah Chen', status: 'online' },
        { id: 'u2', name: 'Mike Johnson', status: 'online' },
        { id: 'u3', name: 'Emma Davis', status: 'away' },
      ],
      lastMessage: {
        content: 'Great progress on the MVP!',
        timestamp: new Date(Date.now() - 300000).toISOString(),
        senderId: 'u1',
      },
      unreadCount: 2,
      pinned: true,
      archived: false,
    },
    {
      id: 'conv-2',
      title: 'AI Assistant',
      type: 'ai',
      participants: [
        { id: 'ai', name: 'CoreFlow AI', status: 'online' },
      ],
      lastMessage: {
        content: 'I found 3 tasks that need attention',
        timestamp: new Date(Date.now() - 600000).toISOString(),
        senderId: 'ai',
      },
      unreadCount: 1,
      pinned: true,
      archived: false,
    },
    {
      id: 'conv-3',
      title: 'Sarah Chen',
      type: 'direct',
      participants: [
        { id: 'u1', name: 'Sarah Chen', status: 'online' },
      ],
      lastMessage: {
        content: 'Can you review the financials?',
        timestamp: new Date(Date.now() - 3600000).toISOString(),
        senderId: 'u1',
      },
      unreadCount: 0,
      pinned: false,
      archived: false,
    },
  ]);

  const [selectedConversation, setSelectedConversation] = useState<string | null>('conv-1');
  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'm1',
      conversationId: 'conv-1',
      senderId: 'u1',
      senderName: 'Sarah Chen',
      content: 'Hey team! Just finished the design mockups for the new dashboard.',
      timestamp: new Date(Date.now() - 3600000).toISOString(),
      read: true,
    },
    {
      id: 'm2',
      conversationId: 'conv-1',
      senderId: 'u2',
      senderName: 'Mike Johnson',
      content: 'Looks great! Can we add the analytics widgets?',
      timestamp: new Date(Date.now() - 1800000).toISOString(),
      read: true,
    },
    {
      id: 'm3',
      conversationId: 'conv-1',
      senderId: 'u1',
      senderName: 'Sarah Chen',
      content: 'Absolutely! I\'ll include them in the next iteration.',
      timestamp: new Date(Date.now() - 900000).toISOString(),
      read: true,
      attachments: [
        {
          id: 'att1',
          name: 'dashboard-mockup.png',
          type: 'image/png',
          url: '#',
          size: 245000,
        },
      ],
    },
    {
      id: 'm4',
      conversationId: 'conv-1',
      senderId: 'u3',
      senderName: 'Emma Davis',
      content: 'Great progress on the MVP!',
      timestamp: new Date(Date.now() - 300000).toISOString(),
      read: false,
    },
  ]);

  const [messageInput, setMessageInput] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [isRecording, setIsRecording] = useState(false);
  const [showSuggestions, setShowSuggestions] = useState(true);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const [aiSuggestions] = useState<AISuggestion[]>([
    {
      id: 's1',
      type: 'response',
      title: 'Suggested Reply',
      content: 'Thanks for sharing! The mockups look excellent. When can we schedule a review session?',
      action: { label: 'Use', type: 'insert' },
    },
    {
      id: 's2',
      type: 'action',
      title: 'Schedule Meeting',
      content: 'Create a calendar event to review the dashboard mockups',
      action: { label: 'Create', type: 'action' },
    },
    {
      id: 's3',
      type: 'insight',
      title: 'Project Update',
      content: 'This conversation mentions the MVP - would you like to update the project status?',
      action: { label: 'Update', type: 'action' },
    },
  ]);

  const currentConv = conversations.find((c) => c.id === selectedConversation);
  const currentMessages = messages.filter((m) => m.conversationId === selectedConversation);

  const filteredConversations = conversations.filter((conv) =>
    conv.title.toLowerCase().includes(searchTerm.toLowerCase())
  );

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSendMessage = () => {
    if (!messageInput.trim() || !selectedConversation) return;

    const newMessage: Message = {
      id: `m${Date.now()}`,
      conversationId: selectedConversation,
      senderId: 'current-user',
      senderName: 'You',
      content: messageInput,
      timestamp: new Date().toISOString(),
      read: true,
    };

    setMessages([...messages, newMessage]);
    setMessageInput('');

    // Update conversation last message
    setConversations(
      conversations.map((c) =>
        c.id === selectedConversation
          ? {
              ...c,
              lastMessage: {
                content: messageInput,
                timestamp: new Date().toISOString(),
                senderId: 'current-user',
              },
            }
          : c
      )
    );
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const toggleRecording = () => {
    setIsRecording(!isRecording);
    // TODO: Implement actual voice recording
  };

  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
  };

  const getConversationIcon = (conv: Conversation) => {
    if (conv.type === 'channel') return <Hash className="w-4 h-4" />;
    if (conv.type === 'ai') return <Bot className="w-4 h-4 text-purple-500" />;
    return null;
  };

  const getFileIcon = (type: string) => {
    if (type.startsWith('image/')) return <Image className="w-4 h-4" />;
    return <File className="w-4 h-4" />;
  };

  return (
    <MainLayout>
      <div className="h-[calc(100vh-4rem)] flex gap-0 -m-6">
        {/* Conversations Sidebar */}
        <div className="w-80 border-r bg-muted/30 flex flex-col">
          {/* Header */}
          <div className="p-4 border-b bg-background">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-lg font-bold">Messages</h2>
              <Button size="sm" variant="ghost">
                <Plus className="w-4 h-4" />
              </Button>
            </div>
            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                type="text"
                placeholder="Search conversations..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 h-9"
              />
            </div>
          </div>

          {/* Conversations List */}
          <div className="flex-1 overflow-y-auto">
            {filteredConversations.map((conv) => (
              <button
                key={conv.id}
                onClick={() => setSelectedConversation(conv.id)}
                className={`w-full p-4 text-left border-b transition-colors hover:bg-muted/50 ${
                  selectedConversation === conv.id ? 'bg-muted' : ''
                }`}
              >
                <div className="flex items-start gap-3">
                  {/* Avatar/Icon */}
                  <div className="flex-shrink-0 w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
                    {getConversationIcon(conv) || (
                      <span className="text-sm font-semibold text-primary">
                        {conv.title.charAt(0)}
                      </span>
                    )}
                  </div>

                  {/* Content */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-semibold text-sm truncate">
                        {conv.title}
                      </span>
                      {conv.lastMessage && (
                        <span className="text-xs text-muted-foreground ml-2 flex-shrink-0">
                          {formatTime(conv.lastMessage.timestamp)}
                        </span>
                      )}
                    </div>
                    {conv.lastMessage && (
                      <p className="text-sm text-muted-foreground truncate">
                        {conv.lastMessage.content}
                      </p>
                    )}
                    <div className="flex items-center gap-2 mt-1">
                      {conv.type === 'channel' && (
                        <span className="text-xs text-muted-foreground flex items-center gap-1">
                          <Users className="w-3 h-3" />
                          {conv.participants.length}
                        </span>
                      )}
                      {conv.pinned && <Star className="w-3 h-3 text-yellow-500 fill-yellow-500" />}
                      {conv.unreadCount > 0 && (
                        <span className="ml-auto bg-primary text-primary-foreground text-xs rounded-full px-2 py-0.5 font-medium">
                          {conv.unreadCount}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Main Chat Area */}
        {currentConv ? (
          <div className="flex-1 flex flex-col bg-background">
            {/* Chat Header */}
            <div className="p-4 border-b flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
                  {getConversationIcon(currentConv) || (
                    <span className="text-sm font-semibold text-primary">
                      {currentConv.title.charAt(0)}
                    </span>
                  )}
                </div>
                <div>
                  <h3 className="font-semibold">{currentConv.title}</h3>
                  {currentConv.type === 'channel' && (
                    <p className="text-sm text-muted-foreground">
                      {currentConv.participants.length} members
                    </p>
                  )}
                  {currentConv.type === 'direct' && (
                    <p className="text-sm text-green-600">
                      {currentConv.participants[0]?.status === 'online' ? 'Online' : 'Offline'}
                    </p>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-2">
                {currentConv.type === 'ai' && (
                  <Button variant="outline" size="sm">
                    <Sparkles className="w-4 h-4 mr-2 text-purple-500" />
                    AI Insights
                  </Button>
                )}
                <Button variant="ghost" size="sm">
                  <MoreVertical className="w-4 h-4" />
                </Button>
              </div>
            </div>

            {/* Messages Area */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
              {currentMessages.map((message, idx) => {
                const isOwnMessage = message.senderId === 'current-user';
                const showAvatar =
                  idx === 0 || currentMessages[idx - 1].senderId !== message.senderId;

                return (
                  <div
                    key={message.id}
                    className={`flex gap-3 ${isOwnMessage ? 'flex-row-reverse' : ''}`}
                  >
                    {/* Avatar */}
                    {showAvatar && !isOwnMessage && (
                      <div className="flex-shrink-0 w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center">
                        <span className="text-xs font-semibold text-primary">
                          {message.senderName.charAt(0)}
                        </span>
                      </div>
                    )}
                    {!showAvatar && !isOwnMessage && <div className="w-8" />}

                    {/* Message Bubble */}
                    <div className={`flex-1 max-w-2xl ${isOwnMessage ? 'flex justify-end' : ''}`}>
                      {showAvatar && !isOwnMessage && (
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-sm font-semibold">{message.senderName}</span>
                          <span className="text-xs text-muted-foreground">
                            {formatTime(message.timestamp)}
                          </span>
                        </div>
                      )}
                      <div
                        className={`rounded-lg p-3 ${
                          isOwnMessage
                            ? 'bg-primary text-primary-foreground'
                            : 'bg-muted'
                        }`}
                      >
                        <p className="text-sm whitespace-pre-wrap">{message.content}</p>

                        {/* Attachments */}
                        {message.attachments && message.attachments.length > 0 && (
                          <div className="mt-2 space-y-2">
                            {message.attachments.map((att) => (
                              <a
                                key={att.id}
                                href={att.url}
                                className={`flex items-center gap-2 p-2 rounded border ${
                                  isOwnMessage
                                    ? 'border-primary-foreground/20 hover:bg-primary-foreground/10'
                                    : 'border-border hover:bg-background'
                                }`}
                              >
                                {getFileIcon(att.type)}
                                <div className="flex-1 min-w-0">
                                  <p className="text-xs font-medium truncate">{att.name}</p>
                                  <p className={`text-xs ${isOwnMessage ? 'opacity-80' : 'text-muted-foreground'}`}>
                                    {(att.size / 1024).toFixed(0)} KB
                                  </p>
                                </div>
                              </a>
                            ))}
                          </div>
                        )}
                      </div>
                      {isOwnMessage && (
                        <div className="flex items-center justify-end gap-1 mt-1">
                          <span className="text-xs text-muted-foreground">
                            {formatTime(message.timestamp)}
                          </span>
                          {message.read ? (
                            <CheckCheck className="w-3 h-3 text-blue-500" />
                          ) : (
                            <Check className="w-3 h-3 text-muted-foreground" />
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
              <div ref={messagesEndRef} />
            </div>

            {/* AI Suggestions Panel */}
            {showSuggestions && currentConv.type === 'ai' && aiSuggestions.length > 0 && (
              <div className="border-t bg-muted/30 p-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <Sparkles className="w-4 h-4 text-purple-500" />
                    <span className="text-sm font-semibold">AI Suggestions</span>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setShowSuggestions(false)}
                  >
                    <X className="w-4 h-4" />
                  </Button>
                </div>
                <div className="grid grid-cols-1 gap-2">
                  {aiSuggestions.map((suggestion) => (
                    <Card key={suggestion.id} className="p-3 hover:shadow-md transition-shadow">
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-semibold text-purple-600 mb-1">
                            {suggestion.title}
                          </p>
                          <p className="text-sm text-muted-foreground">
                            {suggestion.content}
                          </p>
                        </div>
                        {suggestion.action && (
                          <Button size="sm" variant="outline">
                            {suggestion.action.label}
                          </Button>
                        )}
                      </div>
                    </Card>
                  ))}
                </div>
              </div>
            )}

            {/* Message Input */}
            <div className="p-4 border-t">
              <div className="flex items-end gap-2">
                <Button variant="ghost" size="sm" className="mb-1">
                  <Paperclip className="w-4 h-4" />
                </Button>
                <div className="flex-1 min-h-[40px] max-h-[120px] relative">
                  <textarea
                    value={messageInput}
                    onChange={(e) => setMessageInput(e.target.value)}
                    onKeyDown={handleKeyPress}
                    placeholder="Type a message..."
                    className="w-full min-h-[40px] max-h-[120px] p-2 pr-10 rounded-md border border-input bg-background resize-none focus:outline-none focus:ring-2 focus:ring-primary"
                    rows={1}
                  />
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={toggleRecording}
                  className={`mb-1 ${isRecording ? 'text-red-500' : ''}`}
                >
                  <Mic className="w-4 h-4" />
                </Button>
                <Button
                  onClick={handleSendMessage}
                  disabled={!messageInput.trim()}
                  size="sm"
                  className="mb-1"
                >
                  <Send className="w-4 h-4" />
                </Button>
              </div>
            </div>
          </div>
        ) : (
          /* Empty State */
          <div className="flex-1 flex items-center justify-center bg-background">
            <div className="text-center">
              <MessageSquare className="mx-auto h-12 w-12 text-muted-foreground mb-4" />
              <h3 className="text-lg font-semibold mb-2">Select a conversation</h3>
              <p className="text-sm text-muted-foreground">
                Choose a conversation from the sidebar to start messaging
              </p>
            </div>
          </div>
        )}
      </div>
    </MainLayout>
  );
}
