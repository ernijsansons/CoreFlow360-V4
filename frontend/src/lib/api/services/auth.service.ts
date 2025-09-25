import apiClient, { ApiResponse } from '../client'
import type { User } from '../types'

export interface LoginRequest {
  email: string
  password: string
  rememberMe?: boolean
}

export interface LoginResponse {
  token: string
  refreshToken?: string
  user: User
  expiresIn: number
}

export interface RegisterRequest {
  email: string
  password: string
  name: string
  businessName?: string
  acceptTerms: boolean
}

export interface ResetPasswordRequest {
  email: string
}

export interface ConfirmResetRequest {
  token: string
  password: string
}

export interface VerifyMFARequest {
  userId: string
  code: string
  type: 'totp' | 'sms' | 'email'
}

export interface SetupMFAResponse {
  secret: string
  qrCode: string
  backupCodes: string[]
}

class AuthService {
  async login(data: LoginRequest): Promise<ApiResponse<LoginResponse>> {
    return apiClient.post<LoginResponse>('/api/auth/login', data, {
      skipAuth: true,
    })
  }

  async register(data: RegisterRequest): Promise<ApiResponse<User>> {
    return apiClient.post<User>('/api/auth/register', data, {
      skipAuth: true,
    })
  }

  async logout(): Promise<ApiResponse<void>> {
    return apiClient.post<void>('/api/auth/logout')
  }

  async refreshToken(refreshToken: string): Promise<ApiResponse<LoginResponse>> {
    return apiClient.post<LoginResponse>(
      '/api/auth/refresh',
      { refreshToken },
      { skipAuth: true }
    )
  }

  async getCurrentUser(): Promise<ApiResponse<User>> {
    return apiClient.get<User>('/api/auth/me')
  }

  async updateProfile(data: Partial<User>): Promise<ApiResponse<User>> {
    return apiClient.patch<User>('/api/auth/profile', data)
  }

  async changePassword(
    currentPassword: string,
    newPassword: string
  ): Promise<ApiResponse<void>> {
    return apiClient.post<void>('/api/auth/change-password', {
      currentPassword,
      newPassword,
    })
  }

  async resetPassword(data: ResetPasswordRequest): Promise<ApiResponse<void>> {
    return apiClient.post<void>('/api/auth/reset-password', data, {
      skipAuth: true,
    })
  }

  async confirmReset(data: ConfirmResetRequest): Promise<ApiResponse<void>> {
    return apiClient.post<void>('/api/auth/reset-password/confirm', data, {
      skipAuth: true,
    })
  }

  async verifyEmail(token: string): Promise<ApiResponse<void>> {
    return apiClient.post<void>(
      '/api/auth/verify-email',
      { token },
      { skipAuth: true }
    )
  }

  async resendVerificationEmail(): Promise<ApiResponse<void>> {
    return apiClient.post<void>('/api/auth/resend-verification')
  }

  async setupMFA(type: 'totp' | 'sms' | 'email'): Promise<ApiResponse<SetupMFAResponse>> {
    return apiClient.post<SetupMFAResponse>('/api/auth/mfa/setup', { type })
  }

  async verifyMFA(data: VerifyMFARequest): Promise<ApiResponse<LoginResponse>> {
    return apiClient.post<LoginResponse>('/api/auth/mfa/verify', data, {
      skipAuth: true,
    })
  }

  async disableMFA(code: string): Promise<ApiResponse<void>> {
    return apiClient.post<void>('/api/auth/mfa/disable', { code })
  }

  async generateBackupCodes(): Promise<ApiResponse<string[]>> {
    return apiClient.post<string[]>('/api/auth/mfa/backup-codes')
  }

  async listSessions(): Promise<ApiResponse<any[]>> {
    return apiClient.get<any[]>('/api/auth/sessions')
  }

  async revokeSession(sessionId: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/api/auth/sessions/${sessionId}`)
  }

  async revokeAllSessions(): Promise<ApiResponse<void>> {
    return apiClient.post<void>('/api/auth/sessions/revoke-all')
  }
}

export const authService = new AuthService()
export default authService