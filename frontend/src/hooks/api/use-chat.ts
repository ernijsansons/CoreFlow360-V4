import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { chatService } from '@/lib/api/services'
import { toast } from '@/hooks/use-toast'

// Query Keys
export const chatKeys = {
  all: ['chat'] as const,
  conversations: (filters?: unknown) => [...chatKeys.all, 'conversations', filters] as const,
  conversation: (id: string) => [...chatKeys.all, 'conversation', id] as const,
  messages: (conversationId: string, filters?: unknown) =>
    [...chatKeys.all, 'messages', conversationId, filters] as const,
  suggestions: (conversationId: string) => [...chatKeys.all, 'suggestions', conversationId] as const,
}

// Conversation Queries
export function useConversations(params?: {
  status?: 'active' | 'archived'
  limit?: number
  offset?: number
}) {
  return useQuery({
    queryKey: chatKeys.conversations(params),
    queryFn: () => chatService.getConversations(params),
    staleTime: 1000 * 60, // 1 minute
  })
}

export function useConversation(id: string) {
  return useQuery({
    queryKey: chatKeys.conversation(id),
    queryFn: () => chatService.getConversation(id),
    enabled: !!id,
  })
}

export function useConversationMessages(
  conversationId: string,
  params?: { limit?: number; offset?: number }
) {
  return useQuery({
    queryKey: chatKeys.messages(conversationId, params),
    queryFn: () => chatService.getConversationMessages(conversationId, params),
    enabled: !!conversationId,
    refetchInterval: 5000, // Auto-refresh every 5 seconds
  })
}

export function useSmartSuggestions(conversationId: string) {
  return useQuery({
    queryKey: chatKeys.suggestions(conversationId),
    queryFn: () => chatService.getSmartSuggestions(conversationId),
    enabled: !!conversationId,
    staleTime: 1000 * 30, // 30 seconds
  })
}

// Chat Mutations
export function useSendMessage() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: {
      conversation_id?: string
      message: string
      context_type?: string
      context_id?: string
      metadata?: Record<string, unknown>
    }) => chatService.sendMessage(data),
    onSuccess: (data) => {
      if (data.data.conversation_id) {
        queryClient.invalidateQueries({
          queryKey: chatKeys.messages(data.data.conversation_id)
        })
        queryClient.invalidateQueries({
          queryKey: chatKeys.conversation(data.data.conversation_id)
        })
      }
      queryClient.invalidateQueries({ queryKey: chatKeys.conversations() })
    },
    onError: (error: Error) => {
      toast({
        title: 'Failed to send message',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

export function useCreateConversation() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data?: {
      title?: string
      context_type?: string
      context_id?: string
    }) => chatService.createConversation(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: chatKeys.conversations() })
      toast({
        title: 'Conversation started',
        description: 'New conversation has been created.',
      })
    },
  })
}

export function useDeleteConversation() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (conversationId: string) => chatService.deleteConversation(conversationId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: chatKeys.conversations() })
      toast({
        title: 'Conversation deleted',
        description: 'The conversation has been removed.',
      })
    },
  })
}

export function useArchiveConversation() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (conversationId: string) => chatService.archiveConversation(conversationId),
    onSuccess: (_, conversationId) => {
      queryClient.invalidateQueries({ queryKey: chatKeys.conversation(conversationId) })
      queryClient.invalidateQueries({ queryKey: chatKeys.conversations() })
      toast({
        title: 'Conversation archived',
        description: 'The conversation has been archived.',
      })
    },
  })
}

export function useUploadChatFile() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ conversationId, file }: {
      conversationId: string
      file: File
    }) => chatService.uploadFile(conversationId, file),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({
        queryKey: chatKeys.messages(variables.conversationId)
      })
      toast({
        title: 'File uploaded',
        description: 'Your file has been uploaded successfully.',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Upload failed',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

export function useTranscribeAudio() {
  return useMutation({
    mutationFn: (file: File) => chatService.transcribeAudio(file),
    onSuccess: (data) => {
      toast({
        title: 'Transcription complete',
        description: `Transcribed with ${data.data.confidence}% confidence.`,
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Transcription failed',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

export function useSearchConversations() {
  return useMutation({
    mutationFn: ({ query, limit }: { query: string; limit?: number }) =>
      chatService.searchConversations(query, { limit }),
  })
}
