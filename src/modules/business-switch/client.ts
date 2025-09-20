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
      // Clear previous business state
      this.clearPreviousState();

      // Make switch request
      const response = await fetch(`${this.apiUrl}/business/switch`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${currentToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          targetBusinessId,
          prefetchContext: true,
        }),
      });

      const duration = performance.now() - startTime;

      if (!response.ok) {
        throw new Error(`Switch failed: ${response.statusText}`);
      }

      const data = await response.json();

      // Store new tokens
      this.storeTokens(data.accessToken, data.refreshToken);

      // Store new context
      this.storeContext(data.businessContext);

      // Apply client state clearing instructions
      this.applyStateClear(data.clientStateClear);

      // Trigger callback
      if (this.onSwitch) {
        this.onSwitch(data.businessContext);
      }

      // Record performance
      this.recordPerformance('business_switch', duration);

      // Log performance if in development
      if (process.env.NODE_ENV === 'development') {
        console.log('Business switch performance:', {
          totalMs: duration.toFixed(2),
          serverMs: data.metadata?.switchTimeMs?.toFixed(2),
          cacheHit: data.metadata?.cacheHit,
          breakdown: data.metadata?.performanceMetrics,
        });
      }

      return {
        success: true,
        context: data.businessContext,
        performanceMs: duration,
      };
    } catch (error) {
      console.error('Business switch error:', error);

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        performanceMs: performance.now() - startTime,
      };
    }
  }

  /**
   * Get list of available businesses
   */
  async getBusinessList(
    token: string,
    forceRefresh = false
  ): Promise<any[]> {
    const response = await fetch(
      `${this.apiUrl}/business/list?forceRefresh=${forceRefresh}`,
      {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      }
    );

    if (response.ok) {
      const data = await response.json();
      return data.businesses;
    }

    return [];
  }

  /**
   * Prefetch likely businesses
   */
  async prefetchBusinesses(token: string): Promise<void> {
    // Fire and forget
    fetch(`${this.apiUrl}/business/prefetch`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    }).catch(console.error);
  }

  /**
   * Set callback for business switch
   */
  onBusinessSwitch(callback: (context: any) => void): void {
    this.onSwitch = callback;
  }

  /**
   * Clear previous business state
   */
  private clearPreviousState(): void {
    // Clear local storage items
    const keysToRemove = [
      'currentDepartment',
      'currentProject',
      'dashboardLayout',
      'recentSearches',
      'unsavedWork',
    ];

    keysToRemove.forEach(key => {
      localStorage.removeItem(key);
    });

    // Clear session storage
    sessionStorage.clear();

    // Clear IndexedDB if needed
    if ('indexedDB' in window) {
      // Implementation depends on your IndexedDB schema
    }
  }

  /**
   * Apply state clearing instructions from server
   */
  private applyStateClear(instructions: any): void {
    if (!instructions) return;

    // Clear cache patterns
    if (instructions.clearCache && Array.isArray(instructions.clearCache)) {
      instructions.clearCache.forEach((pattern: string) => {
        this.clearCachePattern(pattern);
      });
    }

    // Clear storage items
    if (instructions.clearStorage && Array.isArray(instructions.clearStorage)) {
      instructions.clearStorage.forEach((key: string) => {
        localStorage.removeItem(key);
        sessionStorage.removeItem(key);
      });
    }

    // Reset state items
    if (instructions.resetState && Array.isArray(instructions.resetState)) {
      // This would trigger state resets in your frontend framework
      instructions.resetState.forEach((stateKey: string) => {
        // Dispatch reset action or emit event
        window.dispatchEvent(new CustomEvent('state:reset', {
          detail: { key: stateKey }
        }));
      });
    }
  }

  /**
   * Clear cache entries matching pattern
   */
  private clearCachePattern(pattern: string): void {
    if ('caches' in window) {
      caches.keys().then(names => {
        names.forEach(name => {
          if (name.includes(pattern.replace('*', ''))) {
            caches.delete(name);
          }
        });
      });
    }
  }

  /**
   * Store tokens securely
   */
  private storeTokens(accessToken: string, refreshToken: string): void {
    // In production, use secure storage
    sessionStorage.setItem('access_token', accessToken);
    sessionStorage.setItem('refresh_token', refreshToken);
  }

  /**
   * Store business context
   */
  private storeContext(context: any): void {
    sessionStorage.setItem('business_context', JSON.stringify(context));
    sessionStorage.setItem('business_id', context.businessId);
  }

  /**
   * Record performance metrics
   */
  private recordPerformance(operation: string, duration: number): void {
    this.performanceBuffer.push({
      timestamp: Date.now(),
      operation,
      duration,
    });

    // Keep only last 100 entries
    if (this.performanceBuffer.length > 100) {
      this.performanceBuffer.shift();
    }

    // Send to analytics if available
    if ('gtag' in window) {
      (window as any).gtag('event', 'timing_complete', {
        name: operation,
        value: Math.round(duration),
        event_category: 'business_switch',
      });
    }
  }

  /**
   * Get performance statistics
   */
  getPerformanceStats(): {
    average: number;
    min: number;
    max: number;
    count: number;
    recent: typeof this.performanceBuffer;
  } {
    const durations = this.performanceBuffer.map(p => p.duration);

    if (durations.length === 0) {
      return {
        average: 0,
        min: 0,
        max: 0,
        count: 0,
        recent: [],
      };
    }

    return {
      average: durations.reduce((a, b) => a + b, 0) / durations.length,
      min: Math.min(...durations),
      max: Math.max(...durations),
      count: durations.length,
      recent: this.performanceBuffer.slice(-10),
    };
  }

  /**
   * Preload business resources
   */
  async preloadBusinessResources(businessId: string): Promise<void> {
    // Preload common assets
    const assets = [
      `/api/business/${businessId}/logo`,
      `/api/business/${businessId}/theme`,
      `/api/business/${businessId}/settings`,
    ];

    assets.forEach(url => {
      const link = document.createElement('link');
      link.rel = 'prefetch';
      link.href = url;
      document.head.appendChild(link);
    });
  }
}

// Export singleton instance
export const businessSwitchClient = new BusinessSwitchClientHelper(
  process.env.NEXT_PUBLIC_API_URL || '/api'
);