/**
 * Document Uploader Component
 * Drag-and-drop file upload with OCR processing and data extraction preview
 */

import { useState, useCallback, useRef } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import {
  Upload,
  FileText,
  CheckCircle2,
  AlertCircle,
  Loader2,
  Receipt,
  FileSpreadsheet,
  DollarSign,
  Calendar,
  Building2,
  TrendingUp,
  X
} from 'lucide-react';
import apiClient from '@/lib/api/client';

interface ExtractedData {
  invoice_number?: string;
  vendor_name?: string;
  customer_name?: string;
  date?: string;
  due_date?: string;
  total_amount?: number;
  subtotal?: number;
  tax_amount?: number;
  currency?: string;
  line_items?: Array<{
    description: string;
    quantity: number;
    unit_price: number;
    total: number;
  }>;
}

interface OCRResult {
  document_id: string;
  document_type: 'invoice' | 'receipt' | 'bill' | 'unknown';
  confidence: number;
  extracted_data: ExtractedData;
  raw_text: string;
}

interface DocumentUploaderProps {
  onSuccess?: (result: OCRResult) => void;
  onClose?: () => void;
}

export function DocumentUploader({ onSuccess, onClose }: DocumentUploaderProps) {
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [ocrResult, setOcrResult] = useState<OCRResult | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const uploadMutation = useMutation({
    mutationFn: async (file: File) => {
      const formData = new FormData();
      formData.append('file', file);

      const response = await apiClient.post('/api/documents/upload', {
        body: formData,
      });

      if (!response.ok) {
        throw new Error('Upload failed');
      }

      return response.json();
    },
    onSuccess: (data) => {
      setOcrResult(data.data);
      if (onSuccess) {
        onSuccess(data.data);
      }
    },
  });

  const createInvoiceMutation = useMutation({
    mutationFn: async (documentId: string) => {
      const response = await apiClient.post(`/api/documents/${documentId}/create-invoice`);
      return response.json();
    },
    onSuccess: () => {
      const event = new CustomEvent('show-toast', {
        detail: { message: 'Invoice created successfully', type: 'success' }
      });
      window.dispatchEvent(event);
      if (onClose) onClose();
    },
  });

  const createExpenseMutation = useMutation({
    mutationFn: async (documentId: string) => {
      const response = await apiClient.post(`/api/documents/${documentId}/create-expense`);
      return response.json();
    },
    onSuccess: () => {
      const event = new CustomEvent('show-toast', {
        detail: { message: 'Expense created successfully', type: 'success' }
      });
      window.dispatchEvent(event);
      if (onClose) onClose();
    },
  });

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setUploadedFile(file);
      uploadMutation.mutate(file);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);

    const file = e.dataTransfer.files[0];
    if (file) {
      // Validate file type
      const validTypes = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
      if (!validTypes.includes(file.type)) {
        const event = new CustomEvent('show-toast', {
          detail: { message: 'Invalid file type. Please upload JPG, PNG, WebP, or PDF', type: 'error' }
        });
        window.dispatchEvent(event);
        return;
      }

      // Validate file size (10MB)
      if (file.size > 10 * 1024 * 1024) {
        const event = new CustomEvent('show-toast', {
          detail: { message: 'File too large. Maximum size is 10MB', type: 'error' }
        });
        window.dispatchEvent(event);
        return;
      }

      setUploadedFile(file);
      uploadMutation.mutate(file);
    }
  };

  const handleClick = () => {
    fileInputRef.current?.click();
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 90) return 'text-green-600 dark:text-green-400';
    if (confidence >= 70) return 'text-blue-600 dark:text-blue-400';
    if (confidence >= 50) return 'text-yellow-600 dark:text-yellow-400';
    return 'text-red-600 dark:text-red-400';
  };

  const getDocumentIcon = (type: string) => {
    switch (type) {
      case 'invoice': return <FileSpreadsheet className="w-8 h-8" />;
      case 'receipt': return <Receipt className="w-8 h-8" />;
      case 'bill': return <FileText className="w-8 h-8" />;
      default: return <FileText className="w-8 h-8" />;
    }
  };

  const formatCurrency = (amount?: number) => {
    if (!amount) return 'N/A';
    return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(amount);
  };

  const formatDate = (date?: string) => {
    if (!date) return 'N/A';
    return new Date(date).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  };

  return (
    <div className="space-y-6">
      {/* Upload Area */}
      {!ocrResult && (
        <Card className="p-8">
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={handleClick}
            className={`border-2 border-dashed rounded-lg p-12 text-center cursor-pointer transition-colors ${
              isDragging
                ? 'border-brand-primary bg-brand-primary/5'
                : 'border-gray-300 dark:border-gray-700 hover:border-brand-primary hover:bg-brand-primary/5'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept="image/jpeg,image/png,image/webp,application/pdf"
              onChange={handleFileChange}
              className="hidden"
            />

            {uploadMutation.isPending ? (
              <div className="flex flex-col items-center">
                <Loader2 className="w-12 h-12 text-brand-primary animate-spin mb-4" />
                <p className="text-lg font-semibold mb-2">Processing document...</p>
                <p className="text-sm text-muted-foreground">Extracting data with OCR</p>
              </div>
            ) : (
              <div className="flex flex-col items-center">
                <Upload className="w-12 h-12 text-muted-foreground mb-4" />
                <p className="text-lg font-semibold mb-2">
                  {isDragging ? 'Drop your document here' : 'Upload a document'}
                </p>
                <p className="text-sm text-muted-foreground mb-4">
                  Drag & drop or click to browse
                </p>
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <span>Supported: JPG, PNG, PDF, WebP</span>
                  <span>•</span>
                  <span>Max 10MB</span>
                </div>
              </div>
            )}
          </div>

          {uploadMutation.isError && (
            <div className="mt-4 p-4 bg-destructive/10 border border-destructive rounded-lg flex items-center gap-3">
              <AlertCircle className="w-5 h-5 text-destructive flex-shrink-0" />
              <p className="text-sm text-destructive">
                Upload failed. Please try again or check your file format.
              </p>
            </div>
          )}
        </Card>
      )}

      {/* OCR Result Preview */}
      {ocrResult && (
        <div className="space-y-4">
          {/* Header */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-green-100 dark:bg-green-900/20 rounded-lg">
                <CheckCircle2 className="w-6 h-6 text-green-600 dark:text-green-400" />
              </div>
              <div>
                <h3 className="text-lg font-semibold">Document Processed</h3>
                <p className="text-sm text-muted-foreground">
                  {uploadedFile?.name}
                </p>
              </div>
            </div>
            {onClose && (
              <Button variant="ghost" size="sm" onClick={onClose}>
                <X className="w-4 h-4" />
              </Button>
            )}
          </div>

          {/* Document Type & Confidence */}
          <Card className="p-6">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-3">
                {getDocumentIcon(ocrResult.document_type)}
                <div>
                  <p className="text-sm text-muted-foreground">Document Type</p>
                  <p className="text-lg font-semibold capitalize">{ocrResult.document_type}</p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-sm text-muted-foreground">Confidence</p>
                <p className={`text-2xl font-bold ${getConfidenceColor(ocrResult.confidence)}`}>
                  {ocrResult.confidence}%
                </p>
              </div>
            </div>

            {/* Extracted Data */}
            <div className="space-y-4 pt-4 border-t">
              <h4 className="font-semibold mb-3">Extracted Data</h4>

              <div className="grid grid-cols-2 gap-4">
                {/* Amount */}
                {ocrResult.extracted_data.total_amount && (
                  <div className="flex items-center gap-3">
                    <DollarSign className="w-5 h-5 text-green-600 dark:text-green-400" />
                    <div>
                      <p className="text-xs text-muted-foreground">Total Amount</p>
                      <p className="font-semibold">
                        {formatCurrency(ocrResult.extracted_data.total_amount)}
                      </p>
                    </div>
                  </div>
                )}

                {/* Date */}
                {ocrResult.extracted_data.date && (
                  <div className="flex items-center gap-3">
                    <Calendar className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                    <div>
                      <p className="text-xs text-muted-foreground">Date</p>
                      <p className="font-semibold">{formatDate(ocrResult.extracted_data.date)}</p>
                    </div>
                  </div>
                )}

                {/* Vendor/Customer */}
                {(ocrResult.extracted_data.vendor_name || ocrResult.extracted_data.customer_name) && (
                  <div className="flex items-center gap-3">
                    <Building2 className="w-5 h-5 text-purple-600 dark:text-purple-400" />
                    <div>
                      <p className="text-xs text-muted-foreground">
                        {ocrResult.extracted_data.vendor_name ? 'Vendor' : 'Customer'}
                      </p>
                      <p className="font-semibold">
                        {ocrResult.extracted_data.vendor_name || ocrResult.extracted_data.customer_name}
                      </p>
                    </div>
                  </div>
                )}

                {/* Invoice Number */}
                {ocrResult.extracted_data.invoice_number && (
                  <div className="flex items-center gap-3">
                    <FileText className="w-5 h-5 text-orange-600 dark:text-orange-400" />
                    <div>
                      <p className="text-xs text-muted-foreground">Invoice #</p>
                      <p className="font-semibold">{ocrResult.extracted_data.invoice_number}</p>
                    </div>
                  </div>
                )}
              </div>

              {/* Tax & Subtotal */}
              {(ocrResult.extracted_data.subtotal || ocrResult.extracted_data.tax_amount) && (
                <div className="grid grid-cols-2 gap-4 pt-4 border-t">
                  {ocrResult.extracted_data.subtotal && (
                    <div>
                      <p className="text-xs text-muted-foreground">Subtotal</p>
                      <p className="font-semibold">{formatCurrency(ocrResult.extracted_data.subtotal)}</p>
                    </div>
                  )}
                  {ocrResult.extracted_data.tax_amount && (
                    <div>
                      <p className="text-xs text-muted-foreground">Tax</p>
                      <p className="font-semibold">{formatCurrency(ocrResult.extracted_data.tax_amount)}</p>
                    </div>
                  )}
                </div>
              )}

              {/* Line Items */}
              {ocrResult.extracted_data.line_items && ocrResult.extracted_data.line_items.length > 0 && (
                <div className="pt-4 border-t">
                  <p className="text-sm font-semibold mb-2">Line Items</p>
                  <div className="space-y-2">
                    {ocrResult.extracted_data.line_items.slice(0, 3).map((item, idx) => (
                      <div key={idx} className="flex items-center justify-between text-sm">
                        <span className="text-muted-foreground">{item.description}</span>
                        <span className="font-semibold">{formatCurrency(item.total)}</span>
                      </div>
                    ))}
                    {ocrResult.extracted_data.line_items.length > 3 && (
                      <p className="text-xs text-muted-foreground">
                        +{ocrResult.extracted_data.line_items.length - 3} more items
                      </p>
                    )}
                  </div>
                </div>
              )}
            </div>
          </Card>

          {/* Action Buttons */}
          <div className="flex items-center gap-3">
            <Button
              onClick={() => createInvoiceMutation.mutate(ocrResult.document_id)}
              disabled={createInvoiceMutation.isPending || ocrResult.document_type === 'receipt'}
              className="flex-1"
            >
              {createInvoiceMutation.isPending ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <FileSpreadsheet className="w-4 h-4 mr-2" />
              )}
              Create Invoice
            </Button>
            <Button
              onClick={() => createExpenseMutation.mutate(ocrResult.document_id)}
              disabled={createExpenseMutation.isPending || ocrResult.document_type === 'invoice'}
              variant="outline"
              className="flex-1"
            >
              {createExpenseMutation.isPending ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <Receipt className="w-4 h-4 mr-2" />
              )}
              Create Expense
            </Button>
          </div>

          {/* Confidence Warning */}
          {ocrResult.confidence < 70 && (
            <div className="p-4 bg-yellow-100 dark:bg-yellow-900/20 border border-yellow-600 dark:border-yellow-400 rounded-lg flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-yellow-600 dark:text-yellow-400 flex-shrink-0 mt-0.5" />
              <div className="text-sm">
                <p className="font-semibold text-yellow-600 dark:text-yellow-400 mb-1">
                  Low Confidence Detection
                </p>
                <p className="text-yellow-600 dark:text-yellow-400">
                  Please review the extracted data carefully before creating a record. Some fields may need manual correction.
                </p>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
