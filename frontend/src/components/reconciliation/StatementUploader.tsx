/**
 * Statement Uploader Component
 * Upload CSV/OFX/QFX bank statements with progress tracking
 */

import { useState, useRef } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Upload, FileText, CheckCircle2, AlertCircle, Loader2, X } from 'lucide-react';
import apiClient from '@/lib/api/client';

interface StatementUploaderProps {
  reconciliationId: string;
  onSuccess?: (result: any) => void;
}

export function StatementUploader({ reconciliationId, onSuccess }: StatementUploaderProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const queryClient = useQueryClient();

  const uploadMutation = useMutation({
    mutationFn: async (file: File) => {
      const formData = new FormData();
      formData.append('file', file);

      const response = await apiClient.post(
        `/api/v1/reconciliation/${reconciliationId}/upload-statement`,
        { body: formData }
      );

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Upload failed');
      }

      return response.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['reconciliation', reconciliationId] });
      queryClient.invalidateQueries({ queryKey: ['reconciliation-transactions', reconciliationId] });

      const event = new CustomEvent('show-toast', {
        detail: {
          message: `✓ ${data.data.imported_count} transactions imported successfully`,
          type: 'success'
        }
      });
      window.dispatchEvent(event);

      if (onSuccess) onSuccess(data);
      setSelectedFile(null);
    },
    onError: (error: Error) => {
      const event = new CustomEvent('show-toast', {
        detail: {
          message: `✗ Upload failed: ${error.message}`,
          type: 'error'
        }
      });
      window.dispatchEvent(event);
    },
  });

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setSelectedFile(file);
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
      const validTypes = [
        'text/csv',
        'application/vnd.ms-excel',
        'application/x-ofx',
        'application/vnd.intu.qfx',
      ];

      const isValidType = validTypes.includes(file.type) ||
                         file.name.endsWith('.csv') ||
                         file.name.endsWith('.ofx') ||
                         file.name.endsWith('.qfx');

      if (!isValidType) {
        const event = new CustomEvent('show-toast', {
          detail: {
            message: 'Invalid file type. Please upload CSV, OFX, or QFX file',
            type: 'error'
          }
        });
        window.dispatchEvent(event);
        return;
      }

      // Validate file size (10MB)
      if (file.size > 10 * 1024 * 1024) {
        const event = new CustomEvent('show-toast', {
          detail: {
            message: 'File too large. Maximum size is 10MB',
            type: 'error'
          }
        });
        window.dispatchEvent(event);
        return;
      }

      setSelectedFile(file);
    }
  };

  const handleUpload = () => {
    if (selectedFile) {
      uploadMutation.mutate(selectedFile);
    }
  };

  const handleCancel = () => {
    setSelectedFile(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  };

  return (
    <Card className="p-8">
      {!selectedFile && !uploadMutation.isPending ? (
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`border-2 border-dashed rounded-lg p-12 text-center cursor-pointer transition-colors ${
            isDragging
              ? 'border-brand-primary bg-brand-primary/5'
              : 'border-gray-300 dark:border-gray-700 hover:border-brand-primary hover:bg-brand-primary/5'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".csv,.ofx,.qfx,text/csv,application/vnd.ms-excel,application/x-ofx,application/vnd.intu.qfx"
            onChange={handleFileChange}
            className="hidden"
          />

          <div className="flex flex-col items-center">
            <Upload className="w-12 h-12 text-muted-foreground mb-4" />
            <p className="text-lg font-semibold mb-2">
              {isDragging ? 'Drop your statement here' : 'Upload Bank Statement'}
            </p>
            <p className="text-sm text-muted-foreground mb-4">
              Drag & drop or click to browse
            </p>
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <span>Supported: CSV, OFX, QFX</span>
              <span>•</span>
              <span>Max 10MB</span>
            </div>
          </div>
        </div>
      ) : uploadMutation.isPending ? (
        <div className="flex flex-col items-center py-8">
          <Loader2 className="w-16 h-16 text-brand-primary animate-spin mb-4" />
          <p className="text-lg font-semibold mb-2">Processing statement...</p>
          <p className="text-sm text-muted-foreground">
            Parsing transactions and importing data
          </p>
        </div>
      ) : selectedFile ? (
        <div className="space-y-4">
          <div className="flex items-center justify-between p-4 bg-muted rounded-lg">
            <div className="flex items-center gap-3">
              <FileText className="w-8 h-8 text-brand-primary" />
              <div>
                <p className="font-semibold">{selectedFile.name}</p>
                <p className="text-sm text-muted-foreground">
                  {formatFileSize(selectedFile.size)}
                </p>
              </div>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleCancel}
              disabled={uploadMutation.isPending}
            >
              <X className="w-4 h-4" />
            </Button>
          </div>

          <div className="flex items-center gap-3">
            <Button
              onClick={handleUpload}
              disabled={uploadMutation.isPending}
              className="flex-1"
            >
              <Upload className="w-4 h-4 mr-2" />
              Upload & Import Transactions
            </Button>
            <Button
              variant="outline"
              onClick={handleCancel}
              disabled={uploadMutation.isPending}
            >
              Cancel
            </Button>
          </div>
        </div>
      ) : null}

      {uploadMutation.isError && (
        <div className="mt-4 p-4 bg-destructive/10 border border-destructive rounded-lg flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-destructive flex-shrink-0 mt-0.5" />
          <div className="text-sm">
            <p className="font-semibold text-destructive mb-1">Upload Failed</p>
            <p className="text-destructive">
              {uploadMutation.error instanceof Error
                ? uploadMutation.error.message
                : 'Please check your file format and try again.'}
            </p>
          </div>
        </div>
      )}

      {uploadMutation.isSuccess && (
        <div className="mt-4 p-4 bg-green-100 dark:bg-green-900/20 border border-green-600 dark:border-green-400 rounded-lg flex items-start gap-3">
          <CheckCircle2 className="w-5 h-5 text-green-600 dark:text-green-400 flex-shrink-0 mt-0.5" />
          <div className="text-sm">
            <p className="font-semibold text-green-600 dark:text-green-400 mb-1">
              Statement Uploaded Successfully
            </p>
            <p className="text-green-600 dark:text-green-400">
              {uploadMutation.data?.data?.imported_count || 0} transactions imported and ready for matching.
            </p>
          </div>
        </div>
      )}
    </Card>
  );
}
