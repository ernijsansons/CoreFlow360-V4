/**
 * Chat File Service
 * Handles file uploads to Cloudflare R2 storage for chat attachments
 */

import { z } from 'zod'
import type { Env } from '@/types/env'
import { AppError } from '@/shared/errors/app-error'
import { AuditLogger } from '@/shared/services/audit-logger'

const FileUploadSchema = z.object({
  name: z.string().min(1).max(255),
  type: z.string().min(1),
  size: z.number().min(1).max(50 * 1024 * 1024), // 50MB max
  content: z.string() // base64 encoded
})

const FileMetadataSchema = z.object({
  id: z.string(),
  name: z.string(),
  type: z.string(),
  size: z.number(),
  url: z.string(),
  thumbnailUrl: z.string().optional(),
  uploadedBy: z.string(),
  uploadedAt: z.string(),
  conversationId: z.string(),
  messageId: z.string().optional()
})

export type FileMetadata = z.infer<typeof FileMetadataSchema>

export // TODO: Consider splitting ChatFileService into smaller, focused classes
class ChatFileService {
  constructor(
    private env: Env,
    private auditLogger: AuditLogger
  ) {}

  /**
   * Upload file to R2 storage
   */
  async uploadFile(
    fileData: z.infer<typeof FileUploadSchema>,
    conversationId: string,
    userId: string,
    messageId?: string
  ): Promise<FileMetadata> {
    try {
      // Validate input
      const validatedFile = FileUploadSchema.parse(fileData)

      // Generate unique file ID and path
      const fileId = crypto.randomUUID()
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
      const sanitizedName = this.sanitizeFileName(validatedFile.name)
      const fileKey = `chat-files/${conversationId}/${timestamp}-${fileId}-${sanitizedName}`

      // Decode base64 content
      const fileBuffer = this.base64ToBuffer(validatedFile.content)

      // Validate file content
      await this.validateFileContent(fileBuffer, validatedFile.type)

      // Upload to R2
      const uploadResult = await this.env.CHAT_FILES_BUCKET.put(fileKey, fileBuffer, {
        httpMetadata: {
          contentType: validatedFile.type,
          contentDisposition: `attachment; filename="${sanitizedName}"`
        },
        customMetadata: {
          uploadedBy: userId,
          conversationId,
          messageId: messageId || '',
          originalName: validatedFile.name,
          fileId
        }
      })

      if (!uploadResult) {
        throw new AppError('Failed to upload file to storage', 'UPLOAD_FAILED')
      }

      // Generate URLs
      const fileUrl = `${this.env.CHAT_FILES_BASE_URL}/${fileKey}`
      let thumbnailUrl: string | undefined

      // Generate thumbnail for images
      if (validatedFile.type.startsWith('image/')) {
        thumbnailUrl = await this.generateThumbnail(fileKey, fileBuffer, validatedFile.type)
      }

      // Create file metadata
      const metadata: FileMetadata = {
        id: fileId,
        name: validatedFile.name,
        type: validatedFile.type,
        size: validatedFile.size,
        url: fileUrl,
        thumbnailUrl,
        uploadedBy: userId,
        uploadedAt: new Date().toISOString(),
        conversationId,
        messageId
      }

      // Store metadata in D1
      await this.storeFileMetadata(metadata)

      // Log audit event
      await this.auditLogger.log({
        action: 'chat_file_uploaded',
        userId,
        details: {
          fileId,
          fileName: validatedFile.name,
          fileSize: validatedFile.size,
          fileType: validatedFile.type,
          conversationId,
          messageId
        }
      })

      return metadata

    } catch (error) {
      await this.auditLogger.log({
        action: 'chat_file_upload_failed',
        userId,
        details: {
          fileName: fileData.name,
          conversationId,
          error: error instanceof Error ? error.message : 'Unknown error'
        }
      })

      if (error instanceof AppError) {
        throw error
      }

      throw new AppError(
        'Failed to upload file',
        'UPLOAD_FAILED',
        500,
        error instanceof Error ? error.message : undefined
      )
    }
  }

  /**
   * Get file metadata by ID
   */
  async getFileMetadata(fileId: string): Promise<FileMetadata | null> {
    try {
      const result = await this.env.DB.prepare(`
        SELECT * FROM chat_files WHERE id = ?
      `).bind(fileId).first()

      if (!result) {
        return null
      }

      return FileMetadataSchema.parse(result)

    } catch (error) {
      throw new AppError(
        'Failed to retrieve file metadata',
        'DATABASE_ERROR',
        500,
        error instanceof Error ? error.message : undefined
      )
    }
  }

  /**
   * Get files for conversation
   */
  async getConversationFiles(conversationId: string): Promise<FileMetadata[]> {
    try {
      const results = await this.env.DB.prepare(`
        SELECT * FROM chat_files
        WHERE conversation_id = ?
        ORDER BY uploaded_at DESC
      `).bind(conversationId).all()

      return results.results.map(result => FileMetadataSchema.parse(result))

    } catch (error) {
      throw new AppError(
        'Failed to retrieve conversation files',
        'DATABASE_ERROR',
        500,
        error instanceof Error ? error.message : undefined
      )
    }
  }

  /**
   * Delete file
   */
  async deleteFile(fileId: string, userId: string): Promise<void> {
    try {
      // Get file metadata
      const metadata = await this.getFileMetadata(fileId)
      if (!metadata) {
        throw new AppError('File not found', 'FILE_NOT_FOUND', 404)
      }

      // Check permissions (only uploader can delete)
      if (metadata.uploadedBy !== userId) {
        throw new AppError('Insufficient permissions', 'FORBIDDEN', 403)
      }

      // Generate file key from metadata
      const timestamp = metadata.uploadedAt.replace(/[:.]/g, '-')
      const sanitizedName = this.sanitizeFileName(metadata.name)
      const fileKey = `chat-files/${metadata.conversationId}/${timestamp}-${fileId}-${sanitizedName}`

      // Delete from R2
      await this.env.CHAT_FILES_BUCKET.delete(fileKey)

      // Delete thumbnail if exists
      if (metadata.thumbnailUrl) {
        const thumbnailKey = `thumbnails/${fileId}.webp`
        await this.env.CHAT_FILES_BUCKET.delete(thumbnailKey)
      }

      // Delete from database
      await this.env.DB.prepare(`
        DELETE FROM chat_files WHERE id = ?
      `).bind(fileId).run()

      // Log audit event
      await this.auditLogger.log({
        action: 'chat_file_deleted',
        userId,
        details: {
          fileId,
          fileName: metadata.name,
          conversationId: metadata.conversationId
        }
      })

    } catch (error) {
      if (error instanceof AppError) {
        throw error
      }

      throw new AppError(
        'Failed to delete file',
        'DELETE_FAILED',
        500,
        error instanceof Error ? error.message : undefined
      )
    }
  }

  /**
   * Generate file download URL with expiration
   */
  async generateDownloadUrl(fileId: string, expirationMinutes: number = 60): Promise<string> {
    const metadata = await this.getFileMetadata(fileId)
    if (!metadata) {
      throw new AppError('File not found', 'FILE_NOT_FOUND', 404)
    }

    // Generate signed URL for secure download
    const expirationTime = Date.now() + (expirationMinutes * 60 * 1000)
    const signature = await this.generateUrlSignature(fileId, expirationTime)

    return `${metadata.url}?expires=${expirationTime}&signature=${signature}`
  }

  /**
   * Store file metadata in database
   */
  private async storeFileMetadata(metadata: FileMetadata): Promise<void> {
    await this.env.DB.prepare(`
      INSERT INTO chat_files (
        id, name, type, size, url, thumbnail_url,
        uploaded_by, uploaded_at, conversation_id, message_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      metadata.id,
      metadata.name,
      metadata.type,
      metadata.size,
      metadata.url,
      metadata.thumbnailUrl || null,
      metadata.uploadedBy,
      metadata.uploadedAt,
      metadata.conversationId,
      metadata.messageId || null
    ).run()
  }

  /**
   * Generate thumbnail for images
   */
  private async generateThumbnail(
    originalKey: string,
    imageBuffer: ArrayBuffer,
    mimeType: string
  ): Promise<string> {
    try {
      // Use Cloudflare Images for thumbnail generation
      const thumbnailKey = `thumbnails/${originalKey.split('/').pop()}.webp`

      // Simple thumbnail generation (in production, use proper image processing)
      // This is a placeholder - implement actual thumbnail generation
      const thumbnailBuffer = imageBuffer // Would be processed thumbnail

      await this.env.CHAT_FILES_BUCKET.put(thumbnailKey, thumbnailBuffer, {
        httpMetadata: {
          contentType: 'image/webp'
        }
      })

      return `${this.env.CHAT_FILES_BASE_URL}/${thumbnailKey}`

    } catch (error) {
      return ''
    }
  }

  /**
   * Validate file content
   */
  private async validateFileContent(buffer: ArrayBuffer, expectedType: string): Promise<void> {
    // Basic file validation
    if (buffer.byteLength === 0) {
      throw new AppError('File is empty', 'INVALID_FILE')
    }

    // Check magic numbers for common file types
    const uint8Array = new Uint8Array(buffer)
    const header = uint8Array.slice(0, 8)

    const signatures: Record<string, number[][]> = {
      'image/jpeg': [[0xFF, 0xD8, 0xFF]],
      'image/png': [[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]],
      'image/gif': [[0x47, 0x49, 0x46, 0x38]],
      'image/webp': [[0x52, 0x49, 0x46, 0x46]],
      'application/pdf': [[0x25, 0x50, 0x44, 0x46]],
      'application/zip': [[0x50, 0x4B, 0x03, 0x04], [0x50, 0x4B, 0x05, 0x06], [0x50, 0x4B, 0x07, 0x08]]
    }

    if (signatures[expectedType]) {
      const validSignatures = signatures[expectedType]
      const isValid = validSignatures.some(signature =>
        signature.every((byte, index) => header[index] === byte)
      )

      if (!isValid) {
        throw new AppError('File content does not match declared type', 'INVALID_FILE_TYPE')
      }
    }
  }

  /**
   * Sanitize filename for storage
   */
  private sanitizeFileName(name: string): string {
    return name
      .replace(/[^a-zA-Z0-9.-]/g, '_')
      .replace(/_{2,}/g, '_')
      .replace(/^_|_$/g, '')
      .substring(0, 100)
  }

  /**
   * Convert base64 to buffer
   */
  private base64ToBuffer(base64: string): ArrayBuffer {
    // Remove data URL prefix if present
    const base64Data = base64.replace(/^data:[^;]+;base64,/, '')

    try {
      const binaryString = atob(base64Data)
      const buffer = new ArrayBuffer(binaryString.length)
      const uint8Array = new Uint8Array(buffer)

      for (let i = 0; i < binaryString.length; i++) {
        uint8Array[i] = binaryString.charCodeAt(i)
      }

      return buffer
    } catch (error) {
      throw new AppError('Invalid base64 data', 'INVALID_FILE_DATA')
    }
  }

  /**
   * Generate URL signature for secure downloads
   */
  private async generateUrlSignature(fileId: string, expiration: number): Promise<string> {
    const data = `${fileId}:${expiration}`
    const encoder = new TextEncoder()
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(this.env.FILE_SIGNATURE_SECRET),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    )

    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data))
    return Array.from(new Uint8Array(signature))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
  }
}

export default ChatFileService