/**
 * File Upload Zone Component
 * Drag & drop file upload with progress tracking and R2 storage
 */

import React, { useState, useCallback, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Upload,
  File,
  Image,
  FileText,
  Video,
  Music,
  Archive,
  X,
  Check,
  AlertCircle,
  Loader2
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import { useFileUpload } from '@/hooks/useFileUpload'
import type { FileAttachment, UploadProgress } from '@/types/chat'

export interface FileUploadZoneProps {
  onFileUpload: (files: FileAttachment[]) => void
  onClose: () => void
  maxFiles?: number
  maxSize?: number // in bytes
  acceptedTypes?: string[]
  className?: string
}

interface FileWithProgress extends File {
  id: string
  progress: number
  status: 'pending' | 'uploading' | 'completed' | 'error'
  error?: string
  url?: string
}

const getFileIcon = (type: string) => {
  if (type.startsWith('image/')) return Image
  if (type.startsWith('video/')) return Video
  if (type.startsWith('audio/')) return Music
  if (type.includes('pdf') || type.includes('document')) return FileText
  if (type.includes('zip') || type.includes('tar') || type.includes('rar')) return Archive
  return File
}

const formatFileSize = (bytes: number): string => {
  if (bytes === 0) return '0 Bytes'
  const k = 1024
  const sizes = ['Bytes', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

export const FileUploadZone: React.FC<FileUploadZoneProps> = ({
  onFileUpload,
  onClose,
  maxFiles = 5,
  maxSize = 10 * 1024 * 1024, // 10MB
  acceptedTypes = ['*/*'],
  className
}) => {
  const [files, setFiles] = useState<FileWithProgress[]>([])
  const [isDragOver, setIsDragOver] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const { uploadFile, uploadProgress } = useFileUpload()

  const validateFile = useCallback((file: File): string | null => {
    // Check file size
    if (file.size > maxSize) {
      return `File size exceeds ${formatFileSize(maxSize)}`
    }

    // Check file type
    if (acceptedTypes.length > 0 && !acceptedTypes.includes('*/*')) {
      const isAccepted = acceptedTypes.some(type => {
        if (type.endsWith('/*')) {
          return file.type.startsWith(type.slice(0, -1))
        }
        return file.type === type
      })

      if (!isAccepted) {
        return 'File type not supported'
      }
    }

    return null
  }, [maxSize, acceptedTypes])

  const addFiles = useCallback((newFiles: FileList | File[]) => {
    const filesArray = Array.from(newFiles)

    if (files.length + filesArray.length > maxFiles) {
      // TODO: Show error toast
      return
    }

    const validFiles: FileWithProgress[] = []

    for (const file of filesArray) {
      const error = validateFile(file)

      const fileWithProgress: FileWithProgress = Object.assign(file, {
        id: `${file.name}-${Date.now()}-${Math.random()}`,
        progress: 0,
        status: error ? 'error' as const : 'pending' as const,
        error
      })

      validFiles.push(fileWithProgress)
    }

    setFiles(prev => [...prev, ...validFiles])

    // Start uploading valid files
    validFiles
      .filter(file => file.status === 'pending')
      .forEach(file => uploadFileWithProgress(file))

  }, [files.length, maxFiles, validateFile])

  const uploadFileWithProgress = useCallback(async (file: FileWithProgress) => {
    try {
      // Update status to uploading
      setFiles(prev => prev.map(f =>
        f.id === file.id ? { ...f, status: 'uploading' } : f
      ))

      // Upload file with progress tracking
      const uploadedFile = await uploadFile(file, {
        onProgress: (progress) => {
          setFiles(prev => prev.map(f =>
            f.id === file.id ? { ...f, progress } : f
          ))
        }
      })

      // Update with completed status
      setFiles(prev => prev.map(f =>
        f.id === file.id ? {
          ...f,
          status: 'completed',
          progress: 100,
          url: uploadedFile.url
        } : f
      ))

    } catch (error) {
      // Update with error status
      setFiles(prev => prev.map(f =>
        f.id === file.id ? {
          ...f,
          status: 'error',
          error: error instanceof Error ? error.message : 'Upload failed'
        } : f
      ))
    }
  }, [uploadFile])

  const removeFile = useCallback((fileId: string) => {
    setFiles(prev => prev.filter(f => f.id !== fileId))
  }, [])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragOver(false)

    const droppedFiles = e.dataTransfer.files
    if (droppedFiles.length > 0) {
      addFiles(droppedFiles)
    }
  }, [addFiles])

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragOver(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragOver(false)
  }, [])

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFiles = e.target.files
    if (selectedFiles) {
      addFiles(selectedFiles)
    }
    // Reset input value
    e.target.value = ''
  }, [addFiles])

  const handleConfirm = useCallback(() => {
    const completedFiles = files
      .filter(f => f.status === 'completed')
      .map(f => ({
        id: f.id,
        name: f.name,
        size: formatFileSize(f.size),
        type: f.type,
        url: f.url!
      }))

    onFileUpload(completedFiles)
  }, [files, onFileUpload])

  const canConfirm = files.some(f => f.status === 'completed')
  const isUploading = files.some(f => f.status === 'uploading')

  return (
    <motion.div
      className={cn(
        "bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4",
        className
      )}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
          Upload Files
        </h3>
        <Button
          variant="ghost"
          size="sm"
          onClick={onClose}
          className="w-8 h-8 p-0"
        >
          <X className="w-4 h-4" />
        </Button>
      </div>

      {/* Upload Zone */}
      <div
        className={cn(
          "relative border-2 border-dashed rounded-lg p-8 text-center transition-colors",
          isDragOver
            ? "border-blue-500 bg-blue-50 dark:bg-blue-900/20"
            : "border-gray-300 dark:border-gray-600 hover:border-gray-400 dark:hover:border-gray-500"
        )}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onClick={() => fileInputRef.current?.click()}
      >
        <Upload className={cn(
          "w-10 h-10 mx-auto mb-4",
          isDragOver ? "text-blue-500" : "text-gray-400"
        )} />

        <div className="space-y-2">
          <p className="text-lg font-medium text-gray-900 dark:text-white">
            {isDragOver ? 'Drop files here' : 'Drag & drop files here'}
          </p>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            or <span className="text-blue-600 hover:text-blue-700 cursor-pointer">browse</span> to choose files
          </p>
          <div className="flex flex-wrap gap-2 justify-center mt-3">
            <Badge variant="outline" className="text-xs">
              Max {maxFiles} files
            </Badge>
            <Badge variant="outline" className="text-xs">
              Up to {formatFileSize(maxSize)}
            </Badge>
          </div>
        </div>

        <input
          ref={fileInputRef}
          type="file"
          multiple
          accept={acceptedTypes.join(',')}
          onChange={handleFileSelect}
          className="hidden"
        />
      </div>

      {/* File List */}
      <AnimatePresence>
        {files.length > 0 && (
          <motion.div
            className="mt-4 space-y-3"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
          >
            {files.map((file) => {
              const FileIcon = getFileIcon(file.type)

              return (
                <motion.div
                  key={file.id}
                  className="flex items-center space-x-3 p-3 bg-gray-50 dark:bg-gray-700 rounded-lg"
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 10 }}
                >
                  <FileIcon className="w-5 h-5 text-gray-500 flex-shrink-0" />

                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                      {file.name}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      {formatFileSize(file.size)}
                    </p>

                    {/* Progress Bar */}
                    {file.status === 'uploading' && (
                      <div className="mt-2">
                        <Progress value={file.progress} className="h-1" />
                        <p className="text-xs text-gray-500 mt-1">
                          {file.progress}% uploaded
                        </p>
                      </div>
                    )}

                    {/* Error Message */}
                    {file.status === 'error' && file.error && (
                      <p className="text-xs text-red-600 mt-1">
                        {file.error}
                      </p>
                    )}
                  </div>

                  {/* Status Icon */}
                  <div className="flex-shrink-0">
                    {file.status === 'uploading' && (
                      <Loader2 className="w-4 h-4 text-blue-600 animate-spin" />
                    )}
                    {file.status === 'completed' && (
                      <Check className="w-4 h-4 text-green-600" />
                    )}
                    {file.status === 'error' && (
                      <AlertCircle className="w-4 h-4 text-red-600" />
                    )}
                    {file.status === 'pending' && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => removeFile(file.id)}
                        className="w-6 h-6 p-0 hover:bg-red-100 dark:hover:bg-red-900/30"
                      >
                        <X className="w-3 h-3" />
                      </Button>
                    )}
                  </div>
                </motion.div>
              )
            })}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Actions */}
      {files.length > 0 && (
        <div className="flex items-center justify-between mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
          <div className="text-sm text-gray-600 dark:text-gray-400">
            {files.filter(f => f.status === 'completed').length} of {files.length} files uploaded
          </div>

          <div className="flex items-center space-x-2">
            <Button
              variant="outline"
              size="sm"
              onClick={onClose}
              disabled={isUploading}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={handleConfirm}
              disabled={!canConfirm || isUploading}
            >
              {isUploading ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Uploading...
                </>
              ) : (
                'Attach Files'
              )}
            </Button>
          </div>
        </div>
      )}
    </motion.div>
  )
}

export default FileUploadZone