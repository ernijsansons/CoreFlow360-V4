import { useCallback } from 'react'
// import { useDropzone } from 'react-dropzone' // TODO: Install package
import { useDocuments, useUploadDocument, useCreateInvoiceFromDocument, useCreateExpenseFromDocument } from '@/hooks/api'
import { Card } from '@/components/ui/card-refactored'
import { Button } from '@/components/ui/button-refactored'
import { Badge } from '@/components/ui/badge-refactored'
import { Upload, FileText, CheckCircle2, AlertCircle, Loader2, FileCheck, DollarSign } from 'lucide-react'

export function DocumentUpload() {
  const { data: documents, isLoading } = useDocuments({ limit: 10 })
  const uploadDocument = useUploadDocument()
  const createInvoice = useCreateInvoiceFromDocument()
  const createExpense = useCreateExpenseFromDocument()

  const onDrop = useCallback((acceptedFiles: File[]) => {
    const file = acceptedFiles[0]
    if (file) {
      uploadDocument.mutate({ file })
    }
  }, [uploadDocument])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'image/jpeg': ['.jpg', '.jpeg'],
      'image/png': ['.png'],
      'application/pdf': ['.pdf'],
      'image/webp': ['.webp']
    },
    maxSize: 10 * 1024 * 1024, // 10MB
    multiple: false
  })

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 90) return 'text-green-600'
    if (confidence >= 70) return 'text-yellow-600'
    return 'text-red-600'
  }

  const getDocumentTypeIcon = (type: string) => {
    switch (type) {
      case 'invoice':
        return <FileText className="h-5 w-5 text-blue-500" />
      case 'receipt':
        return <FileCheck className="h-5 w-5 text-green-500" />
      case 'bill':
        return <DollarSign className="h-5 w-5 text-purple-500" />
      default:
        return <FileText className="h-5 w-5 text-gray-500" />
    }
  }

  return (
    <div className="container mx-auto py-8 space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Document Processing</h1>
        <p className="text-gray-600 dark:text-gray-400 mt-2">
          Upload invoices, receipts, and bills for automatic OCR processing
        </p>
      </div>

      {/* Upload Area */}
      <Card className="p-8">
        <div
          {...getRootProps()}
          className={`border-2 border-dashed rounded-lg p-12 text-center cursor-pointer transition-colors ${
            isDragActive
              ? 'border-brand-primary bg-brand-primary/5'
              : 'border-gray-300 dark:border-gray-700 hover:border-brand-primary'
          }`}
        >
          <input {...getInputProps()} />

          {uploadDocument.isPending ? (
            <div className="flex flex-col items-center space-y-4">
              <Loader2 className="h-16 w-16 animate-spin text-brand-primary" />
              <p className="text-lg font-medium">Processing document...</p>
              <p className="text-sm text-gray-500">Extracting data with OCR</p>
            </div>
          ) : (
            <div className="flex flex-col items-center space-y-4">
              <Upload className="h-16 w-16 text-gray-400" />
              <div>
                <p className="text-lg font-medium">
                  {isDragActive ? 'Drop document here' : 'Drag & drop or click to upload'}
                </p>
                <p className="text-sm text-gray-500 mt-1">
                  Supports PDF, JPG, PNG, WebP (max 10MB)
                </p>
              </div>
            </div>
          )}
        </div>

        {uploadDocument.isError && (
          <div className="mt-4 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg flex items-start space-x-3">
            <AlertCircle className="h-5 w-5 text-red-600 mt-0.5" />
            <div>
              <p className="font-medium text-red-900 dark:text-red-300">Upload Failed</p>
              <p className="text-sm text-red-700 dark:text-red-400 mt-1">
                {uploadDocument.error?.message || 'Failed to upload document'}
              </p>
            </div>
          </div>
        )}

        {uploadDocument.isSuccess && uploadDocument.data && (
          <div className="mt-4 p-4 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg">
            <div className="flex items-start space-x-3">
              <CheckCircle2 className="h-5 w-5 text-green-600 mt-0.5" />
              <div className="flex-1">
                <p className="font-medium text-green-900 dark:text-green-300">
                  Document Processed Successfully
                </p>
                <div className="mt-2 space-y-2">
                  <p className="text-sm">
                    Type: <Badge>{uploadDocument.data.data.document_type}</Badge>
                  </p>
                  <p className="text-sm">
                    Confidence:{' '}
                    <span className={`font-medium ${getConfidenceColor(uploadDocument.data.data.confidence)}`}>
                      {uploadDocument.data.data.confidence}%
                    </span>
                  </p>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Processing time: {uploadDocument.data.data.processing_time_ms}ms
                  </p>
                </div>
                <div className="flex space-x-3 mt-4">
                  <Button
                    size="sm"
                    onClick={() => createInvoice.mutate({ documentId: uploadDocument.data.data.document_id })}
                    disabled={createInvoice.isPending}
                  >
                    {createInvoice.isPending ? (
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    ) : (
                      <FileText className="h-4 w-4 mr-2" />
                    )}
                    Create Invoice
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => createExpense.mutate({ documentId: uploadDocument.data.data.document_id })}
                    disabled={createExpense.isPending}
                  >
                    {createExpense.isPending ? (
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    ) : (
                      <DollarSign className="h-4 w-4 mr-2" />
                    )}
                    Create Expense
                  </Button>
                </div>
              </div>
            </div>
          </div>
        )}
      </Card>

      {/* Recent Documents */}
      <Card className="p-6">
        <h2 className="text-2xl font-bold mb-6">Recent Documents</h2>

        {isLoading ? (
          <div className="flex items-center justify-center h-48">
            <Loader2 className="h-8 w-8 animate-spin text-brand-primary" />
          </div>
        ) : (
          <div className="space-y-3">
            {documents?.data && documents.data.length > 0 ? (
              documents.data.map((doc) => (
                <div
                  key={doc.id}
                  className="flex items-center justify-between p-4 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
                >
                  <div className="flex items-center space-x-4">
                    {getDocumentTypeIcon(doc.document_type)}
                    <div>
                      <p className="font-medium">{doc.original_filename}</p>
                      <p className="text-sm text-gray-500">
                        {new Date(doc.created_at).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-3">
                    <Badge variant="outline">{doc.document_type}</Badge>
                    <span className={`text-sm font-medium ${getConfidenceColor(doc.confidence_score)}`}>
                      {doc.confidence_score}%
                    </span>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-12 text-gray-500">
                No documents uploaded yet
              </div>
            )}
          </div>
        )}
      </Card>
    </div>
  )
}
