/**
 * Client-side helper for business switching
 * This would be used in the frontend application
 */
interface BusinessSwitchClient {
  currentBusinessId: string | null;
  accessToken: string | null;
  refreshToken: string | null;
}

export class BusinessSwitchClientHelper {
  private apiUrl: string;
  private onSwitch?: (context: any) => void;
  private performanceBuffer: Array<{
    timestamp: number;
    operation: string;
    duration: number;
  }> = [];

  constructor(apiUrl: string) {
    this.apiUrl = apiUrl;
  }

  /**
   * Initialize with current business context
   */
  async initialize(accessToken: string): Promise<void> {
    const response = await fetch(`${this.apiUrl}/business/current`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
      },
    });

    if (response.ok) {
      const data = await response.json();
      this.storeContext(data.business);
    }
  }

  /**
   * Switch to a different business
   */
  async switchBusiness(
    targetBusinessId: string,
    currentToken: string
  ): Promise<{
    success: boolean;
    context?: any;
    performanceMs?: number;
    error?: string;
  }> {
    const startTime = performance.now();

    try {
      const response = await fetch(`${this.apiUrl}/business/switch`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${currentToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          targetBusinessId,
        }),
      });

      const duration = performance.now() - startTime;
      this.recordPerformance('switch_business', duration);

      if (response.ok) {
        const data = await response.json();
        this.storeContext(data.business);
        
        if (this.onSwitch) {
          this.onSwitch(data.business);
        }

        return {
          success: true,
          context: data.business,
          performanceMs: duration,
        };
      } else {
        const errorData = await response.json();
        return {
          success: false,
          error: errorData.message || 'Business switch failed',
          performanceMs: duration,
        };
      }
    } catch (error: any) {
      const duration = performance.now() - startTime;
      this.recordPerformance('switch_business_error', duration);

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        performanceMs: duration,
      };
    }
  }

  /**
   * Get available businesses for the current user
   */
  async getAvailableBusinesses(accessToken: string): Promise<{
    success: boolean;
    businesses?: Array<{
      id: string;
      name: string;
      domain: string;
      role: string;
      permissions: string[];
    }>;
    error?: string;
  }> {
    try {
      const response = await fetch(`${this.apiUrl}/business/available`, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        return {
          success: true,
          businesses: data.businesses,
        };
      } else {
        const errorData = await response.json();
        return {
          success: false,
          error: errorData.message || 'Failed to get available businesses',
        };
      }
    } catch (error: any) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Get current business context
   */
  getCurrentContext(): BusinessSwitchClient | null {
    try {
      const stored = localStorage.getItem('business_context');
      if (stored) {
        return JSON.parse(stored);
      }
    } catch (error: any) {
      console.error('Failed to parse stored business context:', error);
    }
    return null;
  }

  /**
   * Store business context
   */
  private storeContext(context: any): void {
    try {
      const businessContext: BusinessSwitchClient = {
        currentBusinessId: context.id,
        accessToken: context.accessToken,
        refreshToken: context.refreshToken,
      };
      localStorage.setItem('business_context', JSON.stringify(businessContext));
    } catch (error: any) {
      console.error('Failed to store business context:', error);
    }
  }

  /**
   * Clear business context
   */
  clearContext(): void {
    try {
      localStorage.removeItem('business_context');
    } catch (error: any) {
      console.error('Failed to clear business context:', error);
    }
  }

  /**
   * Set callback for business switch events
   */
  onBusinessSwitch(callback: (context: any) => void): void {
    this.onSwitch = callback;
  }

  /**
   * Get performance metrics
   */
  getPerformanceMetrics(): {
    averageSwitchTime: number;
    totalSwitches: number;
    errorRate: number;
  } {
    const switches = this.performanceBuffer.filter((p: any) => p.operation === 'switch_business');
    const errors = this.performanceBuffer.filter((p: any) => p.operation === 'switch_business_error');
    
    const averageSwitchTime = switches.length > 0 
      ? switches.reduce((sum, p) => sum + p.duration, 0) / switches.length 
      : 0;

    const totalSwitches = switches.length + errors.length;
    const errorRate = totalSwitches > 0 ? (errors.length / totalSwitches) * 100 : 0;

    return {
      averageSwitchTime,
      totalSwitches,
      errorRate,
    };
  }

  /**
   * Record performance metric
   */
  private recordPerformance(operation: string, duration: number): void {
    this.performanceBuffer.push({
      timestamp: Date.now(),
      operation,
      duration,
    });

    // Keep only last 100 entries
    if (this.performanceBuffer.length > 100) {
      this.performanceBuffer = this.performanceBuffer.slice(-100);
    }
  }

  /**
   * Check if user has access to business
   */
  async hasBusinessAccess(
    businessId: string,
    accessToken: string
  ): Promise<boolean> {
    try {
      const response = await fetch(`${this.apiUrl}/business/${businessId}/access`, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
        },
      });

      return response.ok;
    } catch (error: any) {
      return false;
    }
  }

  /**
   * Get business details
   */
  async getBusinessDetails(
    businessId: string,
    accessToken: string
  ): Promise<{
    success: boolean;
    business?: {
      id: string;
      name: string;
      domain: string;
      plan: string;
      features: string[];
      limits: Record<string, number>;
    };
    error?: string;
  }> {
    try {
      const response = await fetch(`${this.apiUrl}/business/${businessId}`, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        return {
          success: true,
          business: data.business,
        };
      } else {
        const errorData = await response.json();
        return {
          success: false,
          error: errorData.message || 'Failed to get business details',
        };
      }
    } catch (error: any) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Refresh business context
   */
  async refreshContext(accessToken: string): Promise<{
    success: boolean;
    context?: any;
    error?: string;
  }> {
    try {
      const response = await fetch(`${this.apiUrl}/business/refresh`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        this.storeContext(data.business);
        return {
          success: true,
          context: data.business,
        };
      } else {
        const errorData = await response.json();
        return {
          success: false,
          error: errorData.message || 'Failed to refresh context',
        };
      }
    } catch (error: any) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Validate business context
   */
  validateContext(): {
    isValid: boolean;
    errors: string[];
  } {
    const context = this.getCurrentContext();
    const errors: string[] = [];

    if (!context) {
      errors.push('No business context found');
      return { isValid: false, errors };
    }

    if (!context.currentBusinessId) {
      errors.push('No current business ID');
    }

    if (!context.accessToken) {
      errors.push('No access token');
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }

  /**
   * Get business switch history
   */
  getSwitchHistory(): Array<{
    timestamp: number;
    fromBusinessId: string | null;
    toBusinessId: string;
    duration: number;
    success: boolean;
  }> {
    // This would typically be stored in a more persistent way
    const history = localStorage.getItem('business_switch_history');
    if (history) {
      try {
        return JSON.parse(history);
      } catch (error: any) {
        console.error('Failed to parse switch history:', error);
      }
    }
    return [];
  }

  /**
   * Add to switch history
   */
  private addToHistory(entry: {
    fromBusinessId: string | null;
    toBusinessId: string;
    duration: number;
    success: boolean;
  }): void {
    try {
      const history = this.getSwitchHistory();
      history.push({
        timestamp: Date.now(),
        ...entry,
      });

      // Keep only last 50 entries
      if (history.length > 50) {
        history.splice(0, history.length - 50);
      }

      localStorage.setItem('business_switch_history', JSON.stringify(history));
    } catch (error: any) {
      console.error('Failed to add to switch history:', error);
    }
  }

  /**
   * Clear switch history
   */
  clearSwitchHistory(): void {
    try {
      localStorage.removeItem('business_switch_history');
    } catch (error: any) {
      console.error('Failed to clear switch history:', error);
    }
  }
}

