import { useAuthStore } from '@/stores/auth-store'
import { useSyncStore } from '@/stores/sync-store'

export interface ApiConfig {
  baseUrl: string
  timeout?: number
  retryAttempts?: number
  retryDelay?: number
}

export interface ApiRequestOptions extends RequestInit {
  skipAuth?: boolean
  skipErrorHandling?: boolean
  retryOnFailure?: boolean
}

export interface ApiError {
  message: string
  code?: string
  status?: number
  details?: Record<string, unknown>
}

export interface ApiResponse<T = unknown> {
  success: boolean
  data?: T
  error?: ApiError
  metadata?: {
    timestamp: string
    requestId?: string
    pagination?: {
      page: number
      limit: number
      total: number
      hasMore: boolean
    }
  }
}

class ApiClient {
  private config: ApiConfig
  private abortControllers: Map<string, AbortController> = new Map()

  constructor(config: ApiConfig) {
    this.config = {
      timeout: 30000,
      retryAttempts: 3,
      retryDelay: 1000,
      ...config,
    }
  }

  private getCSRFToken(): string | null {
    // Get CSRF token from cookie
    const cookies = document.cookie.split(';')
    for (const cookie of cookies) {
      const [name, value] = cookie.trim().split('=')
      if (name === 'csrf-token' || name === '__Host-csrf-token') {
        return decodeURIComponent(value)
      }
    }
    return null
  }

  private async getAuthHeaders(): Promise<HeadersInit> {
    const { token } = useAuthStore.getState()
    const headers: HeadersInit = {}

    if (token) {
      headers['Authorization'] = `Bearer ${token}`
    }

    // Add CSRF token for state-changing methods
    const csrfToken = this.getCSRFToken()
    if (csrfToken) {
      headers['X-CSRF-Token'] = csrfToken
    }

    return headers
  }

  private prepareBody(data: unknown): BodyInit | undefined {
    if (data === undefined || data === null) {
      return undefined
    }

    if (typeof FormData !== 'undefined' && data instanceof FormData) {
      return data
    }

    if (data instanceof URLSearchParams) {
      return data
    }

    if (data instanceof Blob || data instanceof ArrayBuffer) {
      return data as BodyInit
    }

    if (ArrayBuffer.isView(data as ArrayBufferView)) {
      return data as BodyInit
    }

    if (typeof data === 'string') {
      return data
    }

    return JSON.stringify(data)
  }

  private async handleOfflineRequest(url: string, options: ApiRequestOptions): Promise<void> {
    const syncStore = useSyncStore.getState()

    syncStore.addToQueue({
      id: crypto.randomUUID(),
      url,
      method: options.method || 'GET',
      headers: options.headers as Record<string, string>,
      body: options.body as unknown,
      timestamp: Date.now(),
      retryCount: 0,
    })
  }

  private async retryRequest(
    url: string,
    options: ApiRequestOptions,
    attempt: number = 1
  ): Promise<Response> {
    try {
      const controller = new AbortController()
      const requestId = crypto.randomUUID()
      this.abortControllers.set(requestId, controller)

      const timeoutId = setTimeout(() => {
        controller.abort()
      }, this.config.timeout!)

      try {
        const response = await fetch(url, {
          ...options,
          signal: controller.signal,
        })

        clearTimeout(timeoutId)
        this.abortControllers.delete(requestId)

        return response
      } catch (error) {
        clearTimeout(timeoutId)
        this.abortControllers.delete(requestId)
        throw error
      }
    } catch (error: unknown) {
      if (attempt < this.config.retryAttempts! && options.retryOnFailure !== false) {
        await new Promise(resolve =>
          setTimeout(resolve, this.config.retryDelay! * attempt)
        )
        return this.retryRequest(url, options, attempt + 1)
      }
      throw error
    }
  }

  private handleError(error: unknown, status?: number): ApiError {
    if (error instanceof Error && error.name === 'AbortError') {
      return {
        message: 'Request timeout',
        code: 'TIMEOUT',
        status: 408,
      }
    }

    if (!navigator.onLine) {
      return {
        message: 'No internet connection',
        code: 'OFFLINE',
        status: 0,
      }
    }

    if (error instanceof Error) {
      return {
        message: error.message,
        code: 'NETWORK_ERROR',
        status: status || 500,
      }
    }

    return {
      message: 'An unexpected error occurred',
      code: 'UNKNOWN',
      status: status || 500,
    }
  }

  async request<T = unknown>(
    endpoint: string,
    options: ApiRequestOptions = {}
  ): Promise<ApiResponse<T>> {
    const url = `${this.config.baseUrl}${endpoint}`
    const requestOptions: ApiRequestOptions = { ...options }

    try {
      // Prepare headers
      const authHeaders = requestOptions.skipAuth ? {} : await this.getAuthHeaders()

      const headers = new Headers()
      const applyHeaders = (source?: HeadersInit) => {
        if (!source) return

        if (source instanceof Headers) {
          source.forEach((value, key) => headers.set(key, value))
          return
        }

        if (Array.isArray(source)) {
          source.forEach(([key, value]) => headers.set(key, value))
          return
        }

        Object.entries(source).forEach(([key, value]) => {
          if (value !== undefined && value !== null) {
            headers.set(key, String(value))
          }
        })
      }

      applyHeaders(authHeaders)
      applyHeaders(requestOptions.headers)

      const requestBody = requestOptions.body
      const isFormData = typeof FormData !== 'undefined' && requestBody instanceof FormData
      const isBinary =
        requestBody instanceof Blob ||
        requestBody instanceof ArrayBuffer ||
        (requestBody && typeof requestBody === 'object' && ArrayBuffer.isView(requestBody as ArrayBufferView))

      if (!isFormData && !isBinary && requestBody !== undefined && !headers.has('Content-Type')) {
        headers.set('Content-Type', 'application/json')
      }

      if (isFormData) {
        headers.delete('Content-Type')
      }

      const headersObject: Record<string, string> = {}
      headers.forEach((value, key) => {
        headersObject[key] = value
      })

      requestOptions.headers = headersObject

      // Check if offline and queue request if needed
      if (!navigator.onLine && requestOptions.method !== 'GET') {
        await this.handleOfflineRequest(url, requestOptions)
        return {
          success: false,
          error: {
            message: 'Request queued for offline sync',
            code: 'OFFLINE_QUEUED',
            status: 0,
          },
        }
      }

      // Make request with retry logic
      const response = await this.retryRequest(url, requestOptions)

      // Handle non-JSON responses
      const contentType = response.headers.get('content-type')
      if (!contentType?.includes('application/json')) {
        if (response.ok) {
          const text = await response.text()
          return {
            success: true,
            data: text as T,
          }
        }
        throw new Error(`Unexpected response type: ${contentType}`)
      }

      // Parse JSON response
      const data = await response.json()

      // Handle API errors
      if (!response.ok) {
        const error = this.handleError(
          data.error || data.message || 'Request failed',
          response.status
        )

        if (response.status === 401 && !requestOptions.skipAuth) {
          useAuthStore.getState().logout()
        }

        if (!requestOptions.skipErrorHandling) {
          console.error(`API Error [${endpoint}]:`, error)
        }

        return {
          success: false,
          error,
        }
      }

      return {
        success: true,
        data: data.data || data,
        metadata: data.metadata,
      }
    } catch (error: unknown) {
      const apiError = this.handleError(error)

      if (!requestOptions.skipErrorHandling) {
        console.error(`API Error [${endpoint}]:`, apiError)
      }

      // Queue for offline sync if applicable
      if (apiError.code === 'OFFLINE' && requestOptions.method !== 'GET') {
        await this.handleOfflineRequest(url, requestOptions)
        return {
          success: false,
          error: {
            ...apiError,
            message: 'Request queued for offline sync',
            code: 'OFFLINE_QUEUED',
          },
        }
      }

      return {
        success: false,
        error: apiError,
      }
    }
  }

  async get<T = unknown>(endpoint: string, options?: ApiRequestOptions): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, { ...options, method: 'GET' })
  }

  async post<T = unknown>(
    endpoint: string,
    data?: unknown,
    options?: ApiRequestOptions
  ): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, {
      ...options,
      method: 'POST',
      body: this.prepareBody(data),
    })
  }

  async put<T = unknown>(
    endpoint: string,
    data?: unknown,
    options?: ApiRequestOptions
  ): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, {
      ...options,
      method: 'PUT',
      body: this.prepareBody(data),
    })
  }

  async patch<T = unknown>(
    endpoint: string,
    data?: unknown,
    options?: ApiRequestOptions
  ): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, {
      ...options,
      method: 'PATCH',
      body: this.prepareBody(data),
    })
  }

  async delete<T = unknown>(
    endpoint: string,
    options?: ApiRequestOptions
  ): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, { ...options, method: 'DELETE' })
  }

  cancelRequest(requestId: string): void {
    const controller = this.abortControllers.get(requestId)
    if (controller) {
      controller.abort()
      this.abortControllers.delete(requestId)
    }
  }

  cancelAllRequests(): void {
    this.abortControllers.forEach(controller => controller.abort())
    this.abortControllers.clear()
  }
}

// Create singleton instance
const apiClient = new ApiClient({
  baseUrl: import.meta.env.VITE_API_URL || 'http://localhost:8787',
})

export default apiClient
export { ApiClient, apiClient }
