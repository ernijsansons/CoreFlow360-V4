/**
 * File Upload Hook
 * Handles file uploads to R2 storage with progress tracking
 */

import { useState, useCallback } from 'react'
import type { FileAttachment } from '@/types/chat'

interface UploadOptions {
  onProgress?: (progress: number) => void
  onComplete?: (file: FileAttachment) => void
  onError?: (error: Error) => void
}

interface UploadedFile {
  id: string
  name: string
  type: string
  size: number
  url: string
}

export const useFileUpload = () => {
  const [uploadProgress, setUploadProgress] = useState<Record<string, number>>({})
  const [isUploading, setIsUploading] = useState(false)

  const uploadFile = useCallback(async (
    file: File,
    options: UploadOptions = {}
  ): Promise<UploadedFile> => {
    const fileId = `${file.name}-${Date.now()}-${Math.random()}`

    try {
      setIsUploading(true)
      setUploadProgress(prev => ({ ...prev, [fileId]: 0 }))

      // Convert file to base64
      const base64 = await fileToBase64(file)

      // Create upload request
      const uploadData = {
        name: file.name,
        type: file.type,
        size: file.size,
        content: base64
      }

      // Simulate progress for UX (real progress would come from server)
      const progressInterval = setInterval(() => {
        setUploadProgress(prev => {
          const currentProgress = prev[fileId] || 0
          if (currentProgress < 90) {
            const newProgress = currentProgress + Math.random() * 20
            options.onProgress?.(Math.min(newProgress, 90))
            return { ...prev, [fileId]: Math.min(newProgress, 90) }
          }
          return prev
        })
      }, 200)

      // Upload to server
      const response = await fetch('/api/v1/chat/upload-file', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(uploadData)
      })

      clearInterval(progressInterval)

      if (!response.ok) {
        throw new Error(`Upload failed: ${response.statusText}`)
      }

      const result = await response.json()

      // Complete progress
      setUploadProgress(prev => ({ ...prev, [fileId]: 100 }))
      options.onProgress?.(100)

      const uploadedFile: UploadedFile = {
        id: result.id,
        name: result.name,
        type: result.type,
        size: result.size,
        url: result.url
      }

      options.onComplete?.(uploadedFile as FileAttachment)

      return uploadedFile

    } catch (error) {
      const err = error instanceof Error ? error : new Error('Upload failed')
      options.onError?.(err)
      throw err
    } finally {
      setIsUploading(false)
      // Clean up progress after delay
      setTimeout(() => {
        setUploadProgress(prev => {
          const { [fileId]: _, ...rest } = prev
          return rest
        })
      }, 3000)
    }
  }, [])

  const uploadMultipleFiles = useCallback(async (
    files: File[],
    options: UploadOptions = {}
  ): Promise<UploadedFile[]> => {
    const results: UploadedFile[] = []

    for (const file of files) {
      try {
        const result = await uploadFile(file, options)
        results.push(result)
      } catch (error) {
        console.error(`Failed to upload ${file.name}:`, error)
        options.onError?.(error instanceof Error ? error : new Error('Upload failed'))
      }
    }

    return results
  }, [uploadFile])

  return {
    uploadFile,
    uploadMultipleFiles,
    uploadProgress,
    isUploading
  }
}

// Helper function to convert file to base64
const fileToBase64 = (file: File): Promise<string> => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => {
      const result = reader.result as string
      // Remove data URL prefix
      const base64 = result.split(',')[1]
      resolve(base64)
    }
    reader.onerror = reject
    reader.readAsDataURL(file)
  })
}

export default useFileUpload