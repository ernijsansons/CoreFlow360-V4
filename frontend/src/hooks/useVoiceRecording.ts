/**
 * Voice Recording Hook
 * Handles speech-to-text and text-to-speech functionality
 */

import { useState, useRef, useCallback, useEffect } from 'react'

interface VoiceRecordingOptions {
  continuous?: boolean
  interimResults?: boolean
  language?: string
  maxAlternatives?: number
}

interface VoiceRecordingResult {
  transcript: string
  confidence: number
  isFinal: boolean
}

export const useVoiceRecording = (options: VoiceRecordingOptions = {}) => {
  const [isRecording, setIsRecording] = useState(false)
  const [isSupported, setIsSupported] = useState(false)
  const [transcriptText, setTranscriptText] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [isProcessing, setIsProcessing] = useState(false)

  const recognitionRef = useRef<SpeechRecognition | null>(null)
  const mediaRecorderRef = useRef<MediaRecorder | null>(null)
  const audioChunksRef = useRef<Blob[]>([])

  // Check browser support
  useEffect(() => {
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition
    const isWebSpeechSupported = !!SpeechRecognition
    const isMediaRecorderSupported = !!window.MediaRecorder

    setIsSupported(isWebSpeechSupported || isMediaRecorderSupported)

    if (isWebSpeechSupported) {
      recognitionRef.current = new SpeechRecognition()
      setupSpeechRecognition()
    }
  }, [])

  const setupSpeechRecognition = useCallback(() => {
    if (!recognitionRef.current) return

    const recognition = recognitionRef.current

    recognition.continuous = options.continuous ?? true
    recognition.interimResults = options.interimResults ?? true
    recognition.lang = options.language ?? 'en-US'
    recognition.maxAlternatives = options.maxAlternatives ?? 1

    recognition.onstart = () => {
      setIsRecording(true)
      setError(null)
      setTranscriptText('')
    }

    recognition.onresult = (event: SpeechRecognitionEvent) => {
      let interimTranscript = ''
      let finalTranscript = ''

      for (let i = event.resultIndex; i < event.results.length; i++) {
        const result = event.results[i]
        const transcript = result[0].transcript

        if (result.isFinal) {
          finalTranscript += transcript
        } else {
          interimTranscript += transcript
        }
      }

      const fullTranscript = finalTranscript || interimTranscript
      setTranscriptText(fullTranscript)
    }

    recognition.onend = () => {
      setIsRecording(false)
    }

    recognition.onerror = (event: SpeechRecognitionErrorEvent) => {
      setError(`Speech recognition error: ${event.error}`)
      setIsRecording(false)
    }
  }, [options])

  const startRecording = useCallback(async () => {
    if (!isSupported) {
      setError('Voice recording is not supported in this browser')
      return
    }

    try {
      setError(null)

      // Try Web Speech API first
      if (recognitionRef.current) {
        recognitionRef.current.start()
        return
      }

      // Fallback to MediaRecorder with server-side transcription
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true })
      const mediaRecorder = new MediaRecorder(stream, {
        mimeType: 'audio/webm;codecs=opus'
      })

      audioChunksRef.current = []

      mediaRecorder.ondataavailable = (event) => {
        if (event.data.size > 0) {
          audioChunksRef.current.push(event.data)
        }
      }

      mediaRecorder.onstop = async () => {
        const audioBlob = new Blob(audioChunksRef.current, { type: 'audio/webm' })
        await transcribeAudio(audioBlob)

        // Stop all audio tracks
        stream.getTracks().forEach(track => track.stop())
      }

      mediaRecorder.start(100) // Collect audio data every 100ms
      mediaRecorderRef.current = mediaRecorder
      setIsRecording(true)

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to start recording'
      setError(errorMessage)
      console.error('Error starting recording:', err)
    }
  }, [isSupported])

  const stopRecording = useCallback(() => {
    if (recognitionRef.current && isRecording) {
      recognitionRef.current.stop()
      return
    }

    if (mediaRecorderRef.current && isRecording) {
      mediaRecorderRef.current.stop()
      return
    }

    setIsRecording(false)
  }, [isRecording])

  const transcribeAudio = useCallback(async (audioBlob: Blob) => {
    try {
      setIsProcessing(true)

      // Convert blob to base64
      const base64Audio = await blobToBase64(audioBlob)

      // Send to server for transcription
      const response = await fetch('/api/v1/chat/transcribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          audio: base64Audio,
          format: 'webm'
        })
      })

      if (!response.ok) {
        throw new Error('Transcription failed')
      }

      const result = await response.json()
      setTranscriptText(result.transcript || '')

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Transcription failed'
      setError(errorMessage)
      console.error('Error transcribing audio:', err)
    } finally {
      setIsProcessing(false)
      setIsRecording(false)
    }
  }, [])

  const speakText = useCallback(async (text: string, options: {
    voice?: string
    rate?: number
    pitch?: number
    volume?: number
  } = {}) => {
    if (!window.speechSynthesis) {
      setError('Text-to-speech is not supported in this browser')
      return
    }

    try {
      // Cancel any ongoing speech
      window.speechSynthesis.cancel()

      const utterance = new SpeechSynthesisUtterance(text)

      // Configure voice settings
      utterance.rate = options.rate ?? 1
      utterance.pitch = options.pitch ?? 1
      utterance.volume = options.volume ?? 1

      // Set voice if specified
      if (options.voice) {
        const voices = window.speechSynthesis.getVoices()
        const selectedVoice = voices.find(voice =>
          voice.name === options.voice || voice.lang.includes(options.voice!)
        )
        if (selectedVoice) {
          utterance.voice = selectedVoice
        }
      }

      utterance.onerror = (event) => {
        setError(`Speech synthesis error: ${event.error}`)
      }

      window.speechSynthesis.speak(utterance)

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Text-to-speech failed'
      setError(errorMessage)
      console.error('Error speaking text:', err)
    }
  }, [])

  const getAvailableVoices = useCallback((): SpeechSynthesisVoice[] => {
    if (!window.speechSynthesis) return []
    return window.speechSynthesis.getVoices()
  }, [])

  const clearTranscript = useCallback(() => {
    setTranscriptText('')
    setError(null)
  }, [])

  return {
    isRecording,
    isSupported,
    transcriptText,
    error,
    isProcessing,
    startRecording,
    stopRecording,
    speakText,
    getAvailableVoices,
    clearTranscript
  }
}

// Helper function to convert blob to base64
const blobToBase64 = (blob: Blob): Promise<string> => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => {
      const result = reader.result as string
      // Remove data URL prefix
      const base64 = result.split(',')[1]
      resolve(base64)
    }
    reader.onerror = reject
    reader.readAsDataURL(blob)
  })
}

export default useVoiceRecording