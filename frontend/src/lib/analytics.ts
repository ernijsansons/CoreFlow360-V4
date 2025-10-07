/**
 * Analytics Tracking Service
 * Provides type-safe event tracking for Google Analytics 4
 */

declare global {
  interface Window {
    gtag?: (...args: unknown[]) => void;
    dataLayer?: unknown[];
  }
}

export interface AnalyticsEvent {
  category: string;
  action: string;
  label?: string;
  value?: number;
  userId?: string;
  businessId?: string;
}

export class Analytics {
  private static isEnabled(): boolean {
    return typeof window !== 'undefined' && typeof window.gtag !== 'undefined';
  }

  /**
   * Track page view
   */
  static trackPageView(path: string, title?: string): void {
    if (!this.isEnabled()) return;

    window.gtag?.('event', 'page_view', {
      page_path: path,
      page_title: title || document.title,
    });
  }

  /**
   * Track custom event
   */
  static trackEvent(event: AnalyticsEvent): void {
    if (!this.isEnabled()) return;

    window.gtag?.('event', event.action, {
      event_category: event.category,
      event_label: event.label,
      value: event.value,
      user_id: event.userId,
      business_id: event.businessId,
    });
  }

  /**
   * Track business events
   */
  static trackBusiness = {
    created: (businessId: string) => {
      Analytics.trackEvent({
        category: 'Business',
        action: 'business_created',
        label: businessId,
      });
    },

    switched: (businessId: string) => {
      Analytics.trackEvent({
        category: 'Business',
        action: 'business_switched',
        label: businessId,
      });
    },
  };

  /**
   * Track AI agent events
   */
  static trackAgent = {
    deployed: (agentType: string, businessId: string) => {
      Analytics.trackEvent({
        category: 'AI Agent',
        action: 'agent_deployed',
        label: agentType,
        businessId,
      });
    },

    taskCompleted: (agentType: string, taskType: string) => {
      Analytics.trackEvent({
        category: 'AI Agent',
        action: 'agent_task_completed',
        label: `${agentType}:${taskType}`,
      });
    },
  };

  /**
   * Track conversion funnel
   */
  static trackFunnel = {
    signupStarted: () => {
      Analytics.trackEvent({
        category: 'Conversion',
        action: 'signup_started',
      });
    },

    signupCompleted: (userId: string) => {
      Analytics.trackEvent({
        category: 'Conversion',
        action: 'signup_completed',
        userId,
      });
    },

    trialStarted: (userId: string, plan: string) => {
      Analytics.trackEvent({
        category: 'Conversion',
        action: 'trial_started',
        label: plan,
        userId,
      });
    },

    upgraded: (userId: string, plan: string, value: number) => {
      Analytics.trackEvent({
        category: 'Conversion',
        action: 'plan_upgraded',
        label: plan,
        value,
        userId,
      });
    },
  };

  /**
   * Track user engagement
   */
  static trackEngagement = {
    featureUsed: (feature: string) => {
      Analytics.trackEvent({
        category: 'Engagement',
        action: 'feature_used',
        label: feature,
      });
    },

    timeOnDashboard: (seconds: number) => {
      Analytics.trackEvent({
        category: 'Engagement',
        action: 'time_on_dashboard',
        value: seconds,
      });
    },
  };

  /**
   * Set user properties
   */
  static setUser(userId: string, properties?: Record<string, unknown>): void {
    if (!this.isEnabled()) return;

    window.gtag?.('set', 'user_properties', {
      user_id: userId,
      ...properties,
    });
  }
}
