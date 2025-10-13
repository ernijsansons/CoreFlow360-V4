import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { documentsService } from '@/lib/api/services'
import { toast } from '@/hooks/use-toast'

// Query Keys
export const documentsKeys = {
  all: ['documents'] as const,
  list: (filters?: unknown) => [...documentsKeys.all, 'list', filters] as const,
  document: (id: string) => [...documentsKeys.all, 'document', id] as const,
}

// Document Queries
export function useDocuments(params?: {
  type?: 'invoice' | 'receipt' | 'bill' | 'other'
  limit?: number
  offset?: number
}) {
  return useQuery({
    queryKey: documentsKeys.list(params),
    queryFn: () => documentsService.listDocuments(params),
    staleTime: 1000 * 60 * 2, // 2 minutes
  })
}

export function useDocument(id: string) {
  return useQuery({
    queryKey: documentsKeys.document(id),
    queryFn: () => documentsService.getDocument(id),
    enabled: !!id,
  })
}

// Document Mutations
export function useUploadDocument() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ file, type }: {
      file: File
      type?: 'invoice' | 'receipt' | 'bill'
    }) => documentsService.uploadDocument(file, type),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: documentsKeys.list() })
      toast({
        title: 'Document uploaded',
        description: `Document processed with ${data.data.confidence}% confidence.`,
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

export function useCreateInvoiceFromDocument() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ documentId, customerId }: {
      documentId: string
      customerId?: string
    }) => documentsService.createInvoiceFromDocument(documentId, customerId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['invoices'] })
      toast({
        title: 'Invoice created',
        description: 'Invoice has been created from the document.',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Failed to create invoice',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

export function useCreateExpenseFromDocument() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ documentId, accountId }: {
      documentId: string
      accountId?: string
    }) => documentsService.createExpenseFromDocument(documentId, accountId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['expenses'] })
      toast({
        title: 'Expense created',
        description: 'Expense has been created from the document.',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Failed to create expense',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

export function useReprocessDocument() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (documentId: string) => documentsService.reprocessDocument(documentId),
    onSuccess: (_, documentId) => {
      queryClient.invalidateQueries({ queryKey: documentsKeys.document(documentId) })
      toast({
        title: 'Document reprocessed',
        description: 'Document has been reprocessed with OCR.',
      })
    },
  })
}

export function useDeleteDocument() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (documentId: string) => documentsService.deleteDocument(documentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: documentsKeys.list() })
      toast({
        title: 'Document deleted',
        description: 'Document has been removed.',
      })
    },
  })
}
