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
  details?: any
}

export interface ApiResponse<T = any> {
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

  private async getAuthHeaders(): Promise<HeadersInit> {
    const { token } = useAuthStore.getState()

    if (!token) {
      return {}
    }

    return {
      'Authorization': `Bearer ${token}`,
    }
  }

  private async handleOfflineRequest(url: string, options: ApiRequestOptions): Promise<void> {
    const syncStore = useSyncStore.getState()

    syncStore.addToQueue({
      id: crypto.randomUUID(),
      url,
      method: options.method || 'GET',
      headers: options.headers as Record<string, string>,
      body: options.body as any,
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
    } catch (error: any) {
      if (attempt < this.config.retryAttempts! && options.retryOnFailure !== false) {
        await new Promise(resolve =>
          setTimeout(resolve, this.config.retryDelay! * attempt)
        )
        return this.retryRequest(url, options, attempt + 1)
      }
      throw error
    }
  }

  private handleError(error: any, status?: number): ApiError {
    if (error.name === 'AbortError') {
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

  async request<T = any>(
    endpoint: string,
    options: ApiRequestOptions = {}
  ): Promise<ApiResponse<T>> {
    const url = `${this.config.baseUrl}${endpoint}`

    try {
      // Check if offline and queue request if needed
      if (!navigator.onLine && options.method !== 'GET') {
        await this.handleOfflineRequest(url, options)
        return {
          success: false,
          error: {
            message: 'Request queued for offline sync',
            code: 'OFFLINE_QUEUED',
            status: 0,
          },
        }
      }

      // Prepare headers
      const authHeaders = options.skipAuth ? {} : await this.getAuthHeaders()
      const headers = {
        'Content-Type': 'application/json',
        ...authHeaders,
        ...options.headers,
      }

      // Make request with retry logic
      const response = await this.retryRequest(url, {
        ...options,
        headers,
      })

      // Handle non-JSON responses
      const contentType = response.headers.get('content-type')
      if (!contentType?.includes('application/json')) {
        if (response.ok) {
          const text = await response.text()
          return {
            success: true,
            data: text as any,
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

        if (response.status === 401 && !options.skipAuth) {
          useAuthStore.getState().logout()
        }

        if (!options.skipErrorHandling) {
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
    } catch (error: any) {
      const apiError = this.handleError(error)

      if (!options.skipErrorHandling) {
        console.error(`API Error [${endpoint}]:`, apiError)
      }

      // Queue for offline sync if applicable
      if (apiError.code === 'OFFLINE' && options.method !== 'GET') {
        await this.handleOfflineRequest(url, options)
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

  async get<T = any>(endpoint: string, options?: ApiRequestOptions): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, { ...options, method: 'GET' })
  }

  async post<T = any>(
    endpoint: string,
    data?: any,
    options?: ApiRequestOptions
  ): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, {
      ...options,
      method: 'POST',
      body: data ? JSON.stringify(data) : undefined,
    })
  }

  async put<T = any>(
    endpoint: string,
    data?: any,
    options?: ApiRequestOptions
  ): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, {
      ...options,
      method: 'PUT',
      body: data ? JSON.stringify(data) : undefined,
    })
  }

  async patch<T = any>(
    endpoint: string,
    data?: any,
    options?: ApiRequestOptions
  ): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, {
      ...options,
      method: 'PATCH',
      body: data ? JSON.stringify(data) : undefined,
    })
  }

  async delete<T = any>(
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
export { ApiClient }