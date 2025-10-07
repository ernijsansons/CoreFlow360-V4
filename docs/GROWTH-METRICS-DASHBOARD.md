# Growth Metrics Dashboard - CoreFlow360 V4

## Track, Measure, and Accelerate Your Business Growth

This guide helps you set up comprehensive growth tracking to measure what matters and make data-driven decisions for scaling CoreFlow360.

**Dashboard URL:** https://coreflow360-v4-prod.ernijs-ansons.workers.dev/dashboard/metrics
**Analytics API:** https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/analytics

## Essential Growth Metrics

### 1. Revenue Metrics

#### Monthly Recurring Revenue (MRR)

```javascript
// MRR Calculation
const calculateMRR = () => {
  return {
    newMRR: 12500,        // New customers this month
    expansionMRR: 3200,   // Upgrades & add-ons
    contractionMRR: -800, // Downgrades
    churnedMRR: -1200,    // Lost customers
    netNewMRR: 13700,     // Total change
    totalMRR: 67400,      // Current total MRR
    growth: '25.5%'       // Month-over-month growth
  };
};

// MRR Movement Waterfall
Month    Start    New    Expansion  Contraction  Churn    End
Oct      53,700  +12,500  +3,200     -800        -1,200   67,400
Sep      42,100  +10,200  +2,800     -600        -800     53,700
Aug      35,400  +7,800   +2,100     -400        -800     42,100
```

**Key Targets:**
- MRR Growth Rate: >15% monthly
- Net Revenue Retention: >110%
- Gross Revenue Retention: >90%
- MRR per Customer: >$300

#### Annual Recurring Revenue (ARR)

```javascript
const arrDashboard = {
  currentARR: 808800,      // MRR × 12
  projectedARR: 1425600,   // Based on growth rate
  targetARR: 1500000,      // Annual goal
  progressToGoal: '53.9%',
  monthsToTarget: 4.2,
  requiredGrowthRate: '12.3%'
};
```

### 2. Customer Metrics

#### Customer Acquisition

```javascript
const acquisitionMetrics = {
  daily: {
    visitors: 1250,
    signups: 42,
    trials: 38,
    conversions: 12,
    conversionRate: '31.6%'
  },
  weekly: {
    visitors: 8750,
    signups: 294,
    trials: 266,
    conversions: 84,
    conversionRate: '31.6%',
    CAC: 285  // Customer Acquisition Cost
  },
  monthly: {
    visitors: 37500,
    signups: 1260,
    trials: 1140,
    conversions: 360,
    conversionRate: '31.6%',
    CAC: 285,
    LTV: 4230,
    LTVtoCAC: 14.8
  }
};
```

**Conversion Funnel:**
```
Visitor → Signup → Trial → Active → Paid → Retained
 100%     3.4%     3.0%    2.4%    0.96%    0.86%

Optimization Opportunities:
- Visitor → Signup: A/B test hero message
- Signup → Trial: Simplify onboarding
- Trial → Paid: Improve activation
```

#### Customer Retention & Churn

```javascript
const retentionMetrics = {
  monthlyChurn: '2.8%',
  annualChurn: '28.4%',
  averageLifetime: '35.7 months',

  cohortRetention: {
    month1: '95%',
    month3: '88%',
    month6: '79%',
    month12: '71%',
    month24: '62%'
  },

  churnReasons: {
    price: '23%',
    features: '18%',
    support: '12%',
    competitor: '15%',
    noLongerNeeded: '32%'
  }
};
```

### 3. Product Usage Metrics

#### Engagement Metrics

```javascript
const engagementDashboard = {
  dailyActiveUsers: 823,
  weeklyActiveUsers: 1456,
  monthlyActiveUsers: 1872,

  stickiness: '43.9%', // DAU/MAU

  sessionMetrics: {
    averageSessionLength: '24.5 min',
    sessionsPerUser: 3.2,
    pageViewsPerSession: 12,
    bounceRate: '18%'
  },

  featureAdoption: {
    aiAgents: '89%',
    automation: '76%',
    reporting: '65%',
    integrations: '54%',
    api: '23%'
  }
};
```

#### Activation Metrics

```javascript
const activationFunnel = {
  signupToFirstLogin: '94%',
  firstLoginToDataImport: '72%',
  dataImportToFirstAutomation: '61%',
  firstAutomationToWeeklyActive: '85%',

  timeToActivation: {
    p50: '3.2 days',
    p75: '5.8 days',
    p90: '9.1 days'
  },

  activationCriteria: [
    {action: 'Import data', completion: '72%'},
    {action: 'Create automation', completion: '61%'},
    {action: 'Invite team member', completion: '34%'},
    {action: 'Generate report', completion: '45%'},
    {action: 'Configure AI agent', completion: '67%'}
  ]
};
```

### 4. Growth Efficiency Metrics

#### Unit Economics

```javascript
const unitEconomics = {
  CAC: {
    total: 285,
    breakdown: {
      marketing: 120,
      sales: 95,
      onboarding: 70
    }
  },

  LTV: {
    total: 4230,
    breakdown: {
      averageRevenue: 299,
      averageLifetime: 14.1,
      grossMargin: 0.85
    }
  },

  paybackPeriod: '3.2 months',
  LTVtoCAC: 14.8,

  marginalCost: {
    perUser: 12,
    perAgent: 3,
    perGB: 0.15
  }
};
```

#### Sales Efficiency

```javascript
const salesMetrics = {
  pipeline: {
    value: 487000,
    deals: 163,
    averageDealSize: 2987,
    closeRate: '31%',
    averageSalesCycle: '18 days'
  },

  velocity: {
    leadsPerDay: 42,
    demosPerWeek: 28,
    closedWonPerWeek: 8.4,
    weeklyRevenue: 25116
  },

  efficiency: {
    leadToDemo: '28%',
    demoToTrial: '68%',
    trialToPaid: '31%',
    endToEndConversion: '5.9%'
  }
};
```

## Real-Time Dashboard Setup

### Dashboard Configuration

```javascript
// frontend/src/dashboards/growth-metrics.tsx
import { MetricCard, Chart, Table } from '@/components/ui';

export function GrowthDashboard() {
  return (
    <div className="grid grid-cols-4 gap-4">
      {/* Key Metrics Row */}
      <MetricCard
        title="MRR"
        value="$67,400"
        change="+25.5%"
        sparkline={mrrHistory}
        target="$75,000"
      />
      <MetricCard
        title="Customers"
        value="225"
        change="+18"
        sparkline={customerHistory}
        target="250"
      />
      <MetricCard
        title="Churn"
        value="2.8%"
        change="-0.3%"
        sparkline={churnHistory}
        target="<3%"
        inverse={true}
      />
      <MetricCard
        title="LTV:CAC"
        value="14.8"
        change="+1.2"
        sparkline={ltvcacHistory}
        target=">12"
      />

      {/* Charts */}
      <Chart
        type="waterfall"
        title="MRR Movement"
        data={mrrMovement}
        className="col-span-2"
      />
      <Chart
        type="funnel"
        title="Conversion Funnel"
        data={conversionFunnel}
        className="col-span-2"
      />

      {/* Cohort Analysis */}
      <Table
        title="Cohort Retention"
        data={cohortData}
        heatmap={true}
        className="col-span-4"
      />
    </div>
  );
}
```

### API Endpoints for Metrics

```javascript
// Get comprehensive metrics
GET /api/v1/analytics/growth
Authorization: Bearer {token}

Response:
{
  "revenue": {
    "mrr": 67400,
    "arr": 808800,
    "growth": 0.255
  },
  "customers": {
    "total": 225,
    "new": 18,
    "churned": 4,
    "netNew": 14
  },
  "usage": {
    "dau": 823,
    "wau": 1456,
    "mau": 1872,
    "stickiness": 0.439
  }
}

// Get cohort analysis
GET /api/v1/analytics/cohorts?months=12

// Get funnel analysis
GET /api/v1/analytics/funnel?from=visitor&to=paid
```

## Tracking Implementation

### Frontend Tracking

```javascript
// src/lib/analytics.ts
class Analytics {
  track(event: string, properties?: Record<string, any>) {
    // Send to analytics service
    fetch('/api/v1/analytics/events', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        event,
        properties,
        timestamp: Date.now(),
        userId: currentUser.id,
        sessionId: session.id
      })
    });

    // Also send to third-party services
    if (window.gtag) {
      window.gtag('event', event, properties);
    }
    if (window.mixpanel) {
      window.mixpanel.track(event, properties);
    }
  }

  // Track key events
  trackSignup(source: string) {
    this.track('signup_completed', { source });
  }

  trackActivation(step: string) {
    this.track('activation_step', { step });
  }

  trackSubscription(plan: string, mrr: number) {
    this.track('subscription_created', { plan, mrr });
  }

  trackChurn(reason: string) {
    this.track('subscription_cancelled', { reason });
  }
}
```

### Backend Metrics Collection

```javascript
// src/services/metrics-collector.ts
export class MetricsCollector {
  async collectDailyMetrics() {
    const metrics = {
      revenue: await this.calculateRevenue(),
      customers: await this.countCustomers(),
      usage: await this.measureUsage(),
      funnel: await this.analyzeFunnel(),
      cohorts: await this.analyzeCohorts()
    };

    // Store in time-series database
    await db.prepare(`
      INSERT INTO daily_metrics (date, metrics)
      VALUES (?, ?)
    `).bind(new Date().toISOString(), JSON.stringify(metrics)).run();

    // Send to monitoring service
    await this.sendToMonitoring(metrics);

    return metrics;
  }

  async calculateRevenue() {
    const result = await db.prepare(`
      SELECT
        SUM(CASE WHEN created_at > DATE('now', '-30 days') THEN amount ELSE 0 END) as new_mrr,
        SUM(CASE WHEN plan_changed = true THEN amount_diff ELSE 0 END) as expansion_mrr,
        SUM(CASE WHEN status = 'cancelled' THEN -amount ELSE 0 END) as churn_mrr,
        SUM(amount) as total_mrr
      FROM subscriptions
      WHERE status = 'active'
    `).first();

    return {
      newMRR: result.new_mrr,
      expansionMRR: result.expansion_mrr,
      churnMRR: result.churn_mrr,
      totalMRR: result.total_mrr,
      growth: (result.new_mrr + result.expansion_mrr + result.churn_mrr) / result.total_mrr
    };
  }
}
```

## Automated Reporting

### Weekly Growth Report

```javascript
// Generate every Monday at 9 AM
const weeklyGrowthReport = {
  subject: "Weekly Growth Report - W{week_number}",

  highlights: {
    mrr: "+$13,700 (25.5% growth)",
    newCustomers: 42,
    churn: "2.8% (improved from 3.1%)",
    topFeature: "AI Agents (89% adoption)"
  },

  wins: [
    "Highest MRR growth in 6 months",
    "Churn below 3% target",
    "LTV:CAC ratio improved to 14.8"
  ],

  concerns: [
    "Trial conversion down 3%",
    "Support tickets up 15%",
    "API adoption still low (23%)"
  ],

  actions: [
    "A/B test new onboarding flow",
    "Add more support resources",
    "Launch API webinar series"
  ]
};
```

### Monthly Board Report

```javascript
const boardReport = {
  executive_summary: {
    mrr: 67400,
    growth: '25.5%',
    customers: 225,
    runway: '18 months',
    burn: 45000
  },

  key_metrics: {
    revenue: {
      mrr: 67400,
      arr: 808800,
      arpu: 299,
      growth: '25.5%'
    },
    customers: {
      total: 225,
      new: 42,
      churned: 9,
      nps: 52
    },
    efficiency: {
      cac: 285,
      ltv: 4230,
      ratio: 14.8,
      payback: '3.2 months'
    }
  },

  narrative: `
    October showed exceptional growth with MRR increasing 25.5% to $67,400.
    Customer acquisition remains efficient with LTV:CAC of 14.8:1.
    Focus areas for November include improving trial conversion and
    reducing churn below 2.5%.
  `
};
```

## Growth Experiments Framework

### A/B Testing Setup

```javascript
// src/lib/experiments.ts
export class ExperimentManager {
  async runExperiment(config: ExperimentConfig) {
    const experiment = {
      id: generateId(),
      name: config.name,
      hypothesis: config.hypothesis,
      metric: config.metric,
      variants: config.variants,
      traffic: config.traffic || 0.5,
      duration: config.duration || 14,
      startDate: new Date()
    };

    // Assign users to variants
    const variant = this.assignVariant(userId, experiment);

    // Track exposure
    analytics.track('experiment_exposure', {
      experimentId: experiment.id,
      variant: variant.name
    });

    return variant;
  }

  // Current experiments
  experiments = [
    {
      name: 'Simplified Onboarding',
      hypothesis: 'Reducing onboarding steps will increase activation by 15%',
      metric: 'activation_rate',
      variants: [
        {name: 'control', steps: 7},
        {name: 'treatment', steps: 3}
      ]
    },
    {
      name: 'Pricing Page CTA',
      hypothesis: 'Adding urgency will increase conversions by 10%',
      metric: 'trial_starts',
      variants: [
        {name: 'control', cta: 'Start Free Trial'},
        {name: 'treatment', cta: 'Start Free Trial (Limited Time)'}
      ]
    }
  ];
}
```

### Growth Experiments Dashboard

```javascript
const experimentsResults = {
  active: [
    {
      name: 'Simplified Onboarding',
      status: 'running',
      progress: '67%',
      duration: '9/14 days',
      participants: 234,
      results: {
        control: {users: 117, conversion: '31%'},
        treatment: {users: 117, conversion: '38%'},
        lift: '+22.6%',
        significance: '94%'
      }
    }
  ],

  completed: [
    {
      name: 'Homepage Hero Test',
      winner: 'variant_b',
      lift: '+18%',
      impact: '+$8,400 MRR'
    }
  ],

  backlog: [
    'Free trial length (7 vs 14 vs 30 days)',
    'Onboarding email sequence',
    'In-app upgrade prompts'
  ]
};
```

## Alerts and Anomaly Detection

### Metric Alerts Configuration

```yaml
alerts:
  - name: MRR Drop
    condition: mrr_growth < -5%
    window: 1 day
    severity: critical
    notify: [slack, email, sms]

  - name: Churn Spike
    condition: daily_churn > 5%
    window: 1 day
    severity: high
    notify: [slack, email]

  - name: Conversion Drop
    condition: trial_conversion < 25%
    window: 3 days
    severity: medium
    notify: [slack]

  - name: High CAC
    condition: cac > 400
    window: 7 days
    severity: medium
    notify: [email]
```

### Anomaly Detection

```javascript
// src/services/anomaly-detector.ts
export class AnomalyDetector {
  async detectAnomalies(metric: string, value: number) {
    // Get historical data
    const history = await this.getHistory(metric, 30);

    // Calculate statistics
    const mean = average(history);
    const stdDev = standardDeviation(history);

    // Detect anomaly (> 2 standard deviations)
    const zScore = (value - mean) / stdDev;

    if (Math.abs(zScore) > 2) {
      await this.alertAnomaly({
        metric,
        value,
        expected: mean,
        deviation: zScore,
        severity: Math.abs(zScore) > 3 ? 'critical' : 'warning'
      });
    }
  }
}
```

## Growth Playbooks

### Rapid Growth Playbook (0-10k MRR)

```
Week 1-2: Foundation
□ Set up tracking (analytics, attribution)
□ Define activation metrics
□ Create onboarding flow
□ Launch first content pieces

Week 3-4: Acquisition
□ Launch paid ads ($1k budget)
□ Start content marketing
□ Begin SEO optimization
□ Partner outreach

Week 5-8: Optimization
□ A/B test landing pages
□ Optimize onboarding
□ Improve activation rate
□ Reduce time to value

Week 9-12: Scale
□ Increase ad spend (if ROI positive)
□ Launch referral program
□ Add customer testimonials
□ Expand content production
```

### Scale Growth Playbook (10k-100k MRR)

```
Month 1: Systems
□ Hire growth marketer
□ Implement CRM
□ Set up marketing automation
□ Build referral system

Month 2: Channels
□ Test 3 new acquisition channels
□ Scale winning channels
□ Launch affiliate program
□ Start webinar series

Month 3: Retention
□ Implement customer success
□ Launch loyalty program
□ Create expansion playbook
□ Reduce churn below 5%
```

## Custom Dashboards

### Executive Dashboard

```javascript
const executiveDashboard = {
  widgets: [
    {type: 'scorecard', metric: 'mrr', position: 'top-left'},
    {type: 'chart', metric: 'mrr_growth', position: 'top-right'},
    {type: 'funnel', metric: 'conversion', position: 'middle-left'},
    {type: 'table', metric: 'top_customers', position: 'middle-right'},
    {type: 'heatmap', metric: 'cohort_retention', position: 'bottom'}
  ]
};
```

### Sales Dashboard

```javascript
const salesDashboard = {
  widgets: [
    {type: 'pipeline', position: 'top'},
    {type: 'leaderboard', position: 'left'},
    {type: 'activities', position: 'right'},
    {type: 'forecast', position: 'bottom'}
  ]
};
```

### Product Dashboard

```javascript
const productDashboard = {
  widgets: [
    {type: 'feature_adoption', position: 'top'},
    {type: 'user_flows', position: 'middle'},
    {type: 'engagement_metrics', position: 'bottom-left'},
    {type: 'experiments', position: 'bottom-right'}
  ]
};
```

## Quick Reference

### Essential SQL Queries

```sql
-- MRR Calculation
SELECT
  DATE_TRUNC('month', created_at) as month,
  SUM(amount) as mrr,
  COUNT(*) as customers
FROM subscriptions
WHERE status = 'active'
GROUP BY 1
ORDER BY 1 DESC;

-- Cohort Retention
SELECT
  DATE_TRUNC('month', u.created_at) as cohort,
  DATE_TRUNC('month', a.date) as month,
  COUNT(DISTINCT u.id) as users
FROM users u
JOIN activities a ON u.id = a.user_id
GROUP BY 1, 2;

-- Churn Analysis
SELECT
  DATE_TRUNC('month', cancelled_at) as month,
  cancellation_reason,
  COUNT(*) as count
FROM subscriptions
WHERE status = 'cancelled'
GROUP BY 1, 2
ORDER BY 1 DESC, 3 DESC;
```

### Key Formulas

```javascript
// LTV = ARPU × Gross Margin × (1 / Monthly Churn Rate)
const ltv = arpu * grossMargin * (1 / monthlyChurn);

// CAC = (Sales + Marketing Costs) / New Customers
const cac = (salesCost + marketingCost) / newCustomers;

// Quick Ratio = (New MRR + Expansion MRR) / (Contraction MRR + Churned MRR)
const quickRatio = (newMRR + expansionMRR) / (contractionMRR + Math.abs(churnedMRR));

// Rule of 40 = Growth Rate % + Profit Margin %
const ruleOf40 = growthRate + profitMargin;
```

---

**Dashboard Access:** https://coreflow360-v4-prod.ernijs-ansons.workers.dev/dashboard
**API Documentation:** https://api.coreflow360.com/docs
**Support:** analytics@coreflow360.com

Remember: What gets measured gets managed. What gets managed gets improved.