# Analytics Tracking Setup Guide

## Overview

This guide configures comprehensive analytics tracking for CoreFlow360 V4 to measure growth metrics, user behavior, and business performance.

---

## 1. Analytics Stack

### Primary Analytics Tools

#### **Cloudflare Analytics** (Built-in)
- **Purpose**: Edge analytics, performance metrics, security events
- **Cost**: Free with Workers
- **Setup**: Already enabled

#### **Google Analytics 4** (Recommended)
- **Purpose**: User behavior, conversion tracking, funnel analysis
- **Cost**: Free (up to 10M events/month)
- **Setup**: 15 minutes

#### **PostHog** (Alternative)
- **Purpose**: Product analytics, feature flags, session replay
- **Cost**: Free tier (1M events/month)
- **Setup**: 20 minutes

---

## 2. Google Analytics 4 Setup

### Step 1: Create GA4 Property (5 min)

```bash
# 1. Go to https://analytics.google.com
# 2. Click "Admin" → "Create Property"
# 3. Property name: "CoreFlow360 V4"
# 4. Time zone: Your timezone
# 5. Currency: USD
# 6. Create property

# 7. Set up data stream:
#    - Platform: Web
#    - Website URL: https://production.coreflow360-frontend.pages.dev
#    - Stream name: "Production Frontend"

# 8. Copy Measurement ID (G-XXXXXXXXXX)
```

### Step 2: Install GA4 in Frontend (5 min)

```bash
# Install gtag library
cd frontend
npm install --save-dev @types/gtag.js
```

**Update `frontend/index.html`:**

```html
<!-- Google Analytics 4 -->
<script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXXXXXXXX"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'G-XXXXXXXXXX', {
    send_page_view: true,
    anonymize_ip: true,
    cookie_flags: 'SameSite=None;Secure'
  });
</script>
```

**Create `frontend/src/lib/analytics.ts`:**

```typescript
/**
 * Analytics Tracking Service
 */

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
    return typeof window !== 'undefined' && typeof gtag !== 'undefined';
  }

  /**
   * Track page view
   */
  static trackPageView(path: string, title?: string): void {
    if (!this.isEnabled()) return;

    gtag('event', 'page_view', {
      page_path: path,
      page_title: title || document.title,
    });
  }

  /**
   * Track custom event
   */
  static trackEvent(event: AnalyticsEvent): void {
    if (!this.isEnabled()) return;

    gtag('event', event.action, {
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
  static setUser(userId: string, properties?: Record<string, any>): void {
    if (!this.isEnabled()) return;

    gtag('set', 'user_properties', {
      user_id: userId,
      ...properties,
    });
  }
}
```

### Step 3: Integrate with Router (3 min)

**Update `frontend/src/routes/__root.tsx`:**

```typescript
import { Analytics } from '@/lib/analytics';
import { useEffect } from 'react';
import { useLocation } from '@tanstack/react-router';

function RootComponent() {
  const location = useLocation();
  const { isAuthenticated, user } = useAuthStore();

  // Track page views
  useEffect(() => {
    Analytics.trackPageView(location.pathname);
  }, [location.pathname]);

  // Set user ID when authenticated
  useEffect(() => {
    if (isAuthenticated && user) {
      Analytics.setUser(user.id, {
        email: user.email,
        created_at: user.createdAt,
      });
    }
  }, [isAuthenticated, user]);

  // ... rest of component
}
```

### Step 4: Deploy Tracking (2 min)

```bash
# Build and deploy frontend
cd frontend
npm run build
npx wrangler pages deploy dist --project-name=coreflow360-frontend --branch=production

# Verify tracking in GA4 real-time reports (5 min delay)
```

---

## 3. Key Metrics to Track

### Growth Metrics

#### **Acquisition Metrics**
```typescript
// Track in signup flow
Analytics.trackFunnel.signupStarted();
Analytics.trackFunnel.signupCompleted(userId);
Analytics.trackFunnel.trialStarted(userId, 'professional');
```

**Key Metrics:**
- Visitor → Signup conversion rate (Target: 8%)
- Trial → Paid conversion rate (Target: 25%)
- Time to first value (Target: <10 min)

#### **Activation Metrics**
```typescript
// Track first-time user actions
Analytics.trackBusiness.created(businessId);
Analytics.trackAgent.deployed('finance', businessId);
Analytics.trackEngagement.featureUsed('invoice_automation');
```

**Key Metrics:**
- % users creating first business (Target: 90%)
- % users deploying first agent (Target: 70%)
- Time to first agent deployment (Target: <15 min)

#### **Retention Metrics**
```typescript
// Track returning user behavior
Analytics.trackEngagement.timeOnDashboard(seconds);
Analytics.trackBusiness.switched(businessId);
```

**Key Metrics:**
- Day 1 retention (Target: 60%)
- Day 7 retention (Target: 40%)
- Day 30 retention (Target: 25%)

#### **Revenue Metrics**
```typescript
// Track upgrade events
Analytics.trackFunnel.upgraded(userId, 'premium', 299);
```

**Key Metrics:**
- MRR (Monthly Recurring Revenue)
- ARR (Annual Recurring Revenue)
- ARPU (Average Revenue Per User)
- LTV (Lifetime Value)

---

## 4. Custom Dashboards

### GA4 Custom Reports

#### **Growth Funnel Report**
```yaml
Report Name: Growth Funnel
Metrics:
  - Total Users
  - New Users
  - Conversions (signup_completed)
  - Conversions (trial_started)
  - Conversions (plan_upgraded)
Dimensions:
  - Date
  - Traffic Source
  - Device Category
Filters:
  - None
Visualization: Funnel
```

#### **Feature Usage Report**
```yaml
Report Name: Feature Usage
Metrics:
  - Event Count
  - Users
  - Events per User
Dimensions:
  - Event Name
  - Feature (event_label)
Filters:
  - Event Category = "Engagement"
Visualization: Table
```

#### **AI Agent Analytics**
```yaml
Report Name: AI Agent Performance
Metrics:
  - Total Deployments (agent_deployed)
  - Total Tasks Completed (agent_task_completed)
  - Users with Agents
Dimensions:
  - Agent Type (event_label)
  - Business ID
Visualization: Bar Chart
```

---

## 5. Backend Analytics Events

### Track Server-Side Events

**Update `src/routes/agents.ts`:**

```typescript
import { trackServerEvent } from '../services/analytics-service';

// Track agent deployment
app.post('/api/v1/agents/deploy', async (c) => {
  // ... deployment logic

  await trackServerEvent({
    event: 'agent_deployed',
    userId: user.id,
    businessId: business.id,
    properties: {
      agentType: agentConfig.type,
      deploymentTime: Date.now() - startTime,
    },
  });

  return c.json({ success: true, agent });
});
```

**Create `src/services/analytics-service.ts`:**

```typescript
/**
 * Server-Side Analytics Service
 */

export interface ServerAnalyticsEvent {
  event: string;
  userId?: string;
  businessId?: string;
  properties?: Record<string, any>;
}

export async function trackServerEvent(event: ServerAnalyticsEvent): Promise<void> {
  try {
    // Send to Google Analytics Measurement Protocol
    const measurementId = 'G-XXXXXXXXXX';
    const apiSecret = 'YOUR_API_SECRET'; // Get from GA4 Admin

    const payload = {
      client_id: event.userId || 'anonymous',
      user_id: event.userId,
      events: [{
        name: event.event,
        params: {
          business_id: event.businessId,
          ...event.properties,
        },
      }],
    };

    await fetch(`https://www.google-analytics.com/mp/collect?measurement_id=${measurementId}&api_secret=${apiSecret}`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  } catch (error) {
    console.error('Analytics tracking error:', error);
    // Don't throw - analytics failures should not break functionality
  }
}
```

---

## 6. Real-Time Analytics Dashboard

### Setup Grafana Dashboard (Optional)

```bash
# 1. Install Grafana Cloud (free tier)
# 2. Connect to Cloudflare Analytics API
# 3. Create custom dashboard with:
#    - Active users (last 30 min)
#    - API requests per second
#    - Error rate
#    - Top features used
```

**Grafana Dashboard JSON:**
```json
{
  "dashboard": {
    "title": "CoreFlow360 Real-Time Analytics",
    "panels": [
      {
        "title": "Active Users (30 min)",
        "targets": [
          {
            "query": "sum(rate(user_activity[30m]))"
          }
        ]
      },
      {
        "title": "API Request Rate",
        "targets": [
          {
            "query": "sum(rate(http_requests_total[1m]))"
          }
        ]
      },
      {
        "title": "Error Rate %",
        "targets": [
          {
            "query": "sum(rate(http_requests_total{status=~\"5..\"}[5m])) / sum(rate(http_requests_total[5m])) * 100"
          }
        ]
      }
    ]
  }
}
```

---

## 7. Privacy & Compliance

### GDPR Compliance

**Add Cookie Consent Banner:**

```typescript
// frontend/src/components/CookieConsent.tsx
export function CookieConsent() {
  const [consent, setConsent] = useState<boolean | null>(null);

  useEffect(() => {
    const savedConsent = localStorage.getItem('analytics_consent');
    setConsent(savedConsent === 'true');
  }, []);

  const handleAccept = () => {
    localStorage.setItem('analytics_consent', 'true');
    setConsent(true);
    // Enable analytics
    gtag('consent', 'update', {
      analytics_storage: 'granted',
    });
  };

  const handleDecline = () => {
    localStorage.setItem('analytics_consent', 'false');
    setConsent(false);
    // Disable analytics
    gtag('consent', 'update', {
      analytics_storage: 'denied',
    });
  };

  if (consent !== null) return null;

  return (
    <div className="fixed bottom-0 left-0 right-0 bg-background border-t p-4 z-50">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          We use analytics to improve your experience. Your data is anonymized and never sold.
        </p>
        <div className="flex gap-2">
          <button onClick={handleDecline} className="btn-secondary">
            Decline
          </button>
          <button onClick={handleAccept} className="btn-primary">
            Accept
          </button>
        </div>
      </div>
    </div>
  );
}
```

### Data Retention Policy

```typescript
// Configure in GA4 Admin
// Settings → Data Settings → Data Retention
// Set to: 14 months (maximum for free tier)
// Reset on new activity: ON
```

---

## 8. Analytics Checklist

### Pre-Launch Checklist

- [ ] GA4 property created and configured
- [ ] Measurement ID added to frontend
- [ ] Analytics library integrated in codebase
- [ ] Page view tracking working
- [ ] Event tracking implemented for key actions
- [ ] Server-side events configured
- [ ] Custom dashboards created in GA4
- [ ] Cookie consent banner implemented
- [ ] Data retention policy configured
- [ ] Team members granted access to GA4

### Post-Launch Monitoring (First Week)

- [ ] Verify events appearing in GA4 real-time
- [ ] Check conversion funnel completion rates
- [ ] Monitor feature usage patterns
- [ ] Review user flow reports
- [ ] Validate server-side event accuracy
- [ ] Check for tracking errors in browser console
- [ ] Review data quality reports in GA4

---

## 9. Weekly Analytics Review

### Metrics to Review Every Monday

**Growth Metrics:**
- New signups (week over week)
- Trial starts (week over week)
- Paid conversions (week over week)
- MRR growth

**Engagement Metrics:**
- DAU/MAU ratio
- Average session duration
- Features used per user
- AI agents deployed per business

**Retention Metrics:**
- Day 1/7/30 retention rates
- Churn rate
- Reactivation rate

**Revenue Metrics:**
- MRR/ARR
- ARPU
- LTV:CAC ratio

---

## 10. Next Steps

1. **Create GA4 property** (15 min)
2. **Install tracking code** in frontend (10 min)
3. **Deploy updated frontend** (5 min)
4. **Test tracking** with real user flow (10 min)
5. **Create custom dashboards** (30 min)
6. **Set up weekly review schedule** (5 min)

**Total Setup Time: ~75 minutes**

---

## Support

**GA4 Documentation:** https://support.google.com/analytics/answer/9304153
**Measurement Protocol:** https://developers.google.com/analytics/devguides/collection/protocol/ga4
**Privacy Best Practices:** https://support.google.com/analytics/answer/9019185

**Questions?** Contact the analytics team or review the CoreFlow360 analytics playbook.
