/**
 * Audio Transcription Service
 * Handles speech-to-text using Cloudflare Workers AI
 */

import { z } from 'zod'
import type { Env } from '@/types/env'
import { AppError } from '@/shared/errors/app-error'
import { AuditLogger } from '@/shared/services/audit-logger'

const TranscriptionRequestSchema = z.object({
  audio: z.string(), // base64 encoded audio
  format: z.enum(['wav', 'mp3', 'webm', 'ogg', 'm4a']),
  language: z.string().optional().default('en'),
  options: z.object({
    enablePunctuation: z.boolean().default(true),
    enableWordTimestamps: z.boolean().default(false),
    maxSpeakers: z.number().optional(),
    model: z.enum(['whisper-1', 'whisper-large']).default('whisper-1')
  }).optional()
})

const TranscriptionResponseSchema = z.object({
  transcript: z.string(),
  confidence: z.number(),
  language: z.string(),
  duration: z.number(),
  words: z.array(z.object({
    word: z.string(),
    start: z.number(),
    end: z.number(),
    confidence: z.number()
  })).optional(),
  speakers: z.array(z.object({
    speaker: z.string(),
    segments: z.array(z.object({
      text: z.string(),
      start: z.number(),
      end: z.number()
    }))
  })).optional()
})

export type TranscriptionRequest = z.infer<typeof TranscriptionRequestSchema>
export type TranscriptionResponse = z.infer<typeof TranscriptionResponseSchema>

export // TODO: Consider splitting TranscriptionService into smaller, focused classes
class TranscriptionService {
  constructor(
    private env: Env,
    private auditLogger: AuditLogger
  ) {}

  /**
   * Transcribe audio to text
   */
  async transcribeAudio(
    request: TranscriptionRequest,
    userId: string
  ): Promise<TranscriptionResponse> {
    try {
      // Validate request
      const validatedRequest = TranscriptionRequestSchema.parse(request)

      await this.auditLogger.log({
        action: 'transcription_started',
        userId,
        details: {
          format: validatedRequest.format,
          language: validatedRequest.language,
          audioSize: validatedRequest.audio.length
        }
      })

      // Convert base64 to buffer
      const audioBuffer = this.base64ToBuffer(validatedRequest.audio)

      // Validate audio file
      this.validateAudioFile(audioBuffer, validatedRequest.format)

      // Prepare audio for Whisper model
      const processedAudio = await this.preprocessAudio(audioBuffer, validatedRequest.format)

      // Call Cloudflare Workers AI Whisper model
      const transcription = await this.callWhisperAPI(processedAudio, validatedRequest)

      // Post-process transcription
      const result = await this.postprocessTranscription(transcription, validatedRequest)

      await this.auditLogger.log({
        action: 'transcription_completed',
        userId,
        details: {
          transcriptLength: result.transcript.length,
          confidence: result.confidence,
          duration: result.duration
        }
      })

      return result

    } catch (error: any) {
      await this.auditLogger.log({
        action: 'transcription_failed',
        userId,
        details: {
          error: error instanceof Error ? error.message : 'Unknown error'
        }
      })

      if (error instanceof AppError) {
        throw error
      }

      throw new AppError(
        'Transcription failed',
        'TRANSCRIPTION_ERROR',
        500,
        error instanceof Error ? error.message : undefined
      )
    }
  }

  /**
   * Stream transcription for real-time processing
   */
  async streamTranscription(
    audioStream: ReadableStream<Uint8Array>,
    userId: string,
    options: {
      language?: string
      format?: string
      onTranscript?: (partial: string) => void
      onComplete?: (final: TranscriptionResponse) => void
    } = {}
  ): Promise<void> {
    try {
      const chunks: Uint8Array[] = []
      const reader = audioStream.getReader()

      while (true) {
        const { done, value } = await reader.read()

        if (done) break

        chunks.push(value)

        // Process chunks when we have enough data (e.g., 1-2 seconds of audio)
        if (this.shouldProcessChunk(chunks)) {
          const audioBuffer = this.combineChunks(chunks)

          try {
            const transcription = await this.callWhisperAPI(audioBuffer, {
              audio: this.bufferToBase64(audioBuffer),
              format: (options.format as any) || 'webm',
              language: options.language
            })

            const result = await this.postprocessTranscription(transcription, {
              audio: '',
              format: 'webm',
              language: options.language
            })

            options.onTranscript?.(result.transcript)

          } catch (error: any) {
          }

          // Keep some overlap for context
          chunks.splice(0, Math.floor(chunks.length * 0.8))
        }
      }

      // Process final chunk
      if (chunks.length > 0) {
        const finalBuffer = this.combineChunks(chunks)
        const finalTranscription = await this.callWhisperAPI(finalBuffer, {
          audio: this.bufferToBase64(finalBuffer),
          format: (options.format as any) || 'webm',
          language: options.language
        })

        const finalResult = await this.postprocessTranscription(finalTranscription, {
          audio: '',
          format: 'webm',
          language: options.language
        })

        options.onComplete?.(finalResult)
      }

    } catch (error: any) {
      throw new AppError(
        'Stream transcription failed',
        'STREAM_TRANSCRIPTION_ERROR',
        500,
        error instanceof Error ? error.message : undefined
      )
    }
  }

  /**
   * Call Cloudflare Workers AI Whisper model
   */
  private async callWhisperAPI(
    audioBuffer: ArrayBuffer,
    request: TranscriptionRequest
  ): Promise<any> {
    try {
      // Use Cloudflare Workers AI Whisper model
      const result = await this.env.AI.run('@cf/openai/whisper', {
        audio: Array.from(new Uint8Array(audioBuffer))
      })

      return result

    } catch (error: any) {
      throw new AppError(
        'AI transcription service failed',
        'AI_SERVICE_ERROR',
        503,
        error instanceof Error ? error.message : undefined
      )
    }
  }

  /**
   * Preprocess audio for optimal transcription
   */
  private async preprocessAudio(
    audioBuffer: ArrayBuffer,
    format: string
  ): Promise<ArrayBuffer> {
    // Basic audio preprocessing
    // In production, you might want to:
    // - Normalize audio levels
    // - Remove noise
    // - Convert to optimal format/sample rate
    // - Split into chunks for large files

    return audioBuffer
  }

  /**
   * Post-process transcription results
   */
  private async postprocessTranscription(
    rawTranscription: any,
    request: TranscriptionRequest
  ): Promise<TranscriptionResponse> {
    let transcript = rawTranscription.text || rawTranscription.transcript || ''

    // Clean up transcript
    transcript = transcript.trim()

    // Add punctuation if enabled
    if (request.options?.enablePunctuation) {
      transcript = this.addPunctuation(transcript)
    }

    // Calculate confidence (if not provided by AI model)
    const confidence = rawTranscription.confidence || this.estimateConfidence(transcript)

    // Extract word timestamps if available
    const words = rawTranscription.words || []

    return {
      transcript,
      confidence,
      language: request.language || 'en',
      duration: rawTranscription.duration || 0,
      words: words.length > 0 ? words : undefined
    }
  }

  /**
   * Add basic punctuation to transcript
   */
  private addPunctuation(text: string): string {
    let result = text

    // Add periods at sentence ends
    result = result.replace(/\b(yes|no|okay|ok|sure|right|exactly|absolutely)\b$/gi, '$1.')
    result = result.replace(/([.!?])\s+([a-z])/g, '$1 $2'.toUpperCase())

    // Add question marks for obvious questions
    result = result.replace(/\b(what|when|where|who|why|how|is|are|can|could|would|will|do|does|did)\b([^.!?]*?)$/gi, '$1$2?')

    // Capitalize first letter
    result = result.charAt(0).toUpperCase() + result.slice(1)

    // Ensure ending punctuation
    if (!/[.!?]$/.test(result.trim())) {
      result += '.'
    }

    return result
  }

  /**
   * Estimate confidence based on transcript quality
   */
  private estimateConfidence(transcript: string): number {
    if (!transcript.trim()) return 0

    let confidence = 0.8 // Base confidence

    // Adjust based on length
    if (transcript.length < 10) confidence -= 0.2
    else if (transcript.length > 100) confidence += 0.1

    // Adjust based on word quality
    const words = transcript.split(' ')
    const shortWords = words.filter((w: any) => w.length < 3).length
    const longWords = words.filter((w: any) => w.length > 8).length

    confidence -= (shortWords / words.length) * 0.1
    confidence += (longWords / words.length) * 0.05

    // Adjust based on punctuation
    if (/[.!?]/.test(transcript)) confidence += 0.05

    return Math.max(0, Math.min(1, confidence))
  }

  /**
   * Validate audio file
   */
  private validateAudioFile(buffer: ArrayBuffer, format: string): void {
    if (buffer.byteLength === 0) {
      throw new AppError('Audio file is empty', 'INVALID_AUDIO')
    }

    if (buffer.byteLength > 25 * 1024 * 1024) { // 25MB limit
      throw new AppError('Audio file too large', 'AUDIO_TOO_LARGE')
    }

    // Basic format validation based on magic numbers
    const uint8Array = new Uint8Array(buffer)
    const header = uint8Array.slice(0, 8)

    const signatures: Record<string, number[][]> = {
      'wav': [[0x52, 0x49, 0x46, 0x46]], // RIFF
      'mp3': [[0xFF, 0xFB], [0xFF, 0xF3], [0xFF, 0xF2]],
      'webm': [[0x1A, 0x45, 0xDF, 0xA3]], // EBML
      'ogg': [[0x4F, 0x67, 0x67, 0x53]], // OggS
      'm4a': [[0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70]] // ftyp
    }

    if (signatures[format]) {
      const validSignatures = signatures[format]
      const isValid = validSignatures.some(signature =>
        signature.every((byte, index) => header[index] === byte)
      )

      if (!isValid) {
        // Don't throw error - some audio might have different headers
      }
    }
  }

  /**
   * Convert base64 to ArrayBuffer
   */
  private base64ToBuffer(base64: string): ArrayBuffer {
    try {
      const binaryString = atob(base64)
      const buffer = new ArrayBuffer(binaryString.length)
      const uint8Array = new Uint8Array(buffer)

      for (let i = 0; i < binaryString.length; i++) {
        uint8Array[i] = binaryString.charCodeAt(i)
      }

      return buffer
    } catch (error: any) {
      throw new AppError('Invalid base64 audio data', 'INVALID_AUDIO_DATA')
    }
  }

  /**
   * Convert ArrayBuffer to base64
   */
  private bufferToBase64(buffer: ArrayBuffer): string {
    const uint8Array = new Uint8Array(buffer)
    let binary = ''
    for (let i = 0; i < uint8Array.byteLength; i++) {
      binary += String.fromCharCode(uint8Array[i])
    }
    return btoa(binary)
  }

  /**
   * Check if we should process the current audio chunk
   */
  private shouldProcessChunk(chunks: Uint8Array[]): boolean {
    const totalSize = chunks.reduce((sum, chunk) => sum + chunk.length, 0)
    // Process when we have ~1-2 seconds of audio (assuming 44.1kHz, 16-bit)
    const targetSize = 44100 * 2 * 1.5 // 1.5 seconds
    return totalSize >= targetSize
  }

  /**
   * Combine audio chunks into single buffer
   */
  private combineChunks(chunks: Uint8Array[]): ArrayBuffer {
    const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0)
    const combined = new Uint8Array(totalLength)

    let offset = 0
    for (const chunk of chunks) {
      combined.set(chunk, offset)
      offset += chunk.length
    }

    return combined.buffer
  }
}

export default TranscriptionService