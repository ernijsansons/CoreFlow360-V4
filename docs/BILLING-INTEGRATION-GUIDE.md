# Billing Integration Guide - CoreFlow360 V4

## Complete Stripe Billing Setup for Revenue Generation

This guide walks you through setting up Stripe billing to start accepting payments immediately. Follow each step to enable subscriptions, one-time payments, and automated billing.

**Production Payment URL:** https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/payments

## Quick Start (20 Minutes to Revenue)

### Prerequisites
- Stripe account (verified and activated)
- Bank account connected to Stripe
- Business tax information completed
- SSL certificate active (already configured)

## Step 1: Stripe Product Setup (5 minutes)

### Create Subscription Products

Login to Stripe Dashboard and create these products:

#### Starter Plan
```javascript
{
  name: "CoreFlow360 Starter",
  description: "Perfect for solopreneurs and small teams",
  price: 99.00,
  currency: "USD",
  interval: "month",
  features: [
    "1 Business",
    "3 Users",
    "5 AI Agents",
    "10,000 tasks/month",
    "Email support"
  ],
  stripe_price_id: "price_starter_monthly"
}
```

#### Professional Plan
```javascript
{
  name: "CoreFlow360 Professional",
  description: "For growing businesses",
  price: 299.00,
  currency: "USD",
  interval: "month",
  features: [
    "3 Businesses",
    "10 Users",
    "10 AI Agents",
    "50,000 tasks/month",
    "Priority support",
    "API access"
  ],
  stripe_price_id: "price_professional_monthly"
}
```

#### Enterprise Plan
```javascript
{
  name: "CoreFlow360 Enterprise",
  description: "For large organizations",
  price: 999.00,
  currency: "USD",
  interval: "month",
  features: [
    "Unlimited Businesses",
    "Unlimited Users",
    "Unlimited AI Agents",
    "Unlimited tasks",
    "24/7 phone support",
    "Dedicated success manager",
    "Custom integrations"
  ],
  stripe_price_id: "price_enterprise_monthly"
}
```

### Create in Stripe Dashboard

```bash
1. Navigate to: Products → Add product
2. For each plan:
   - Name: [Plan Name]
   - Price: [Amount]
   - Billing: Recurring
   - Billing period: Monthly
   - Click: Save product
3. Copy each price ID (starts with price_)
```

## Step 2: Configure Webhook Endpoints (3 minutes)

### Create Webhook in Stripe

```bash
1. Navigate to: Developers → Webhooks
2. Click: Add endpoint
3. Endpoint URL: https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/webhooks/stripe
4. Select events:
```

### Required Webhook Events

```javascript
// Subscription events
checkout.session.completed
customer.subscription.created
customer.subscription.updated
customer.subscription.deleted
customer.subscription.trial_will_end

// Payment events
payment_intent.succeeded
payment_intent.payment_failed
invoice.paid
invoice.payment_failed
invoice.upcoming

// Customer events
customer.created
customer.updated
customer.deleted

// Dispute events
charge.dispute.created
```

### Save Webhook Secret

```bash
# Copy the signing secret (whsec_...)
wrangler secret put STRIPE_WEBHOOK_SECRET
# Paste webhook secret
```

## Step 3: Payment Implementation (5 minutes)

### Backend API Endpoints

These endpoints are already implemented:

#### Create Checkout Session
```javascript
// POST /api/v1/payments/create-checkout
{
  "priceId": "price_professional_monthly",
  "customerId": "cust_123", // Optional for existing customers
  "successUrl": "https://app.coreflow360.com/success",
  "cancelUrl": "https://app.coreflow360.com/pricing",
  "metadata": {
    "userId": "usr_456",
    "businessId": "biz_789"
  }
}

// Response
{
  "checkoutUrl": "https://checkout.stripe.com/pay/cs_...",
  "sessionId": "cs_..."
}
```

#### Create Customer Portal
```javascript
// POST /api/v1/payments/create-portal
{
  "customerId": "cus_123",
  "returnUrl": "https://app.coreflow360.com/settings/billing"
}

// Response
{
  "portalUrl": "https://billing.stripe.com/p/session/..."
}
```

#### Get Subscription Status
```javascript
// GET /api/v1/payments/subscription/{customerId}

// Response
{
  "status": "active",
  "plan": "professional",
  "currentPeriodEnd": "2024-11-01",
  "cancelAtPeriodEnd": false,
  "usage": {
    "tasks": 12453,
    "limit": 50000
  }
}
```

### Frontend Integration

#### Pricing Page Component
```jsx
// frontend/src/pages/Pricing.tsx
import { loadStripe } from '@stripe/stripe-js';

const stripePromise = loadStripe(import.meta.env.VITE_STRIPE_PUBLISHABLE_KEY);

function PricingPage() {
  const handleSubscribe = async (priceId: string) => {
    const response = await fetch('/api/v1/payments/create-checkout', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        priceId,
        successUrl: window.location.origin + '/success',
        cancelUrl: window.location.origin + '/pricing'
      })
    });

    const { checkoutUrl } = await response.json();
    window.location.href = checkoutUrl;
  };

  return (
    <div className="pricing-grid">
      <PricingCard
        title="Starter"
        price="$99"
        priceId="price_starter_monthly"
        onSubscribe={handleSubscribe}
      />
      <PricingCard
        title="Professional"
        price="$299"
        priceId="price_professional_monthly"
        featured={true}
        onSubscribe={handleSubscribe}
      />
      <PricingCard
        title="Enterprise"
        price="$999"
        priceId="price_enterprise_monthly"
        onSubscribe={handleSubscribe}
      />
    </div>
  );
}
```

#### Billing Settings Page
```jsx
// frontend/src/pages/settings/Billing.tsx
function BillingSettings() {
  const handleManageBilling = async () => {
    const response = await fetch('/api/v1/payments/create-portal', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        returnUrl: window.location.href
      })
    });

    const { portalUrl } = await response.json();
    window.location.href = portalUrl;
  };

  return (
    <div>
      <h2>Billing & Subscription</h2>
      <SubscriptionStatus />
      <UsageMetrics />
      <button onClick={handleManageBilling}>
        Manage Billing
      </button>
    </div>
  );
}
```

## Step 4: Webhook Handler (3 minutes)

### Implement Webhook Processing

```javascript
// src/routes/webhooks.ts
import Stripe from 'stripe';

export async function handleStripeWebhook(request: Request, env: Env) {
  const stripe = new Stripe(env.STRIPE_SECRET_KEY);
  const sig = request.headers.get('stripe-signature');
  const body = await request.text();

  let event;
  try {
    event = stripe.webhooks.constructEvent(
      body,
      sig,
      env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    return new Response('Webhook signature verification failed', { status: 400 });
  }

  // Handle events
  switch (event.type) {
    case 'checkout.session.completed':
      await handleCheckoutComplete(event.data.object);
      break;

    case 'customer.subscription.created':
    case 'customer.subscription.updated':
      await updateSubscription(event.data.object);
      break;

    case 'customer.subscription.deleted':
      await cancelSubscription(event.data.object);
      break;

    case 'invoice.paid':
      await recordPayment(event.data.object);
      break;

    case 'invoice.payment_failed':
      await handlePaymentFailure(event.data.object);
      break;
  }

  return new Response('Webhook processed', { status: 200 });
}

async function handleCheckoutComplete(session: Stripe.Checkout.Session) {
  // Provision access for new customer
  const { customer, subscription, metadata } = session;

  await db.prepare(`
    UPDATE users
    SET stripe_customer_id = ?,
        subscription_id = ?,
        subscription_status = 'active',
        plan_type = ?
    WHERE id = ?
  `).bind(customer, subscription, metadata.plan, metadata.userId).run();

  // Send welcome email
  await sendWelcomeEmail(metadata.email, metadata.plan);
}
```

## Step 5: Usage-Based Billing (Optional)

### Track Usage Metrics

```javascript
// src/services/usage-tracking.ts
export async function trackUsage(userId: string, metric: string, quantity: number) {
  const timestamp = Date.now();

  // Record in database
  await db.prepare(`
    INSERT INTO usage_events (user_id, metric, quantity, timestamp)
    VALUES (?, ?, ?, ?)
  `).bind(userId, metric, quantity, timestamp).run();

  // Report to Stripe (for metered billing)
  if (env.ENABLE_METERED_BILLING) {
    const stripe = new Stripe(env.STRIPE_SECRET_KEY);
    await stripe.subscriptionItems.createUsageRecord(
      subscriptionItemId,
      {
        quantity,
        timestamp: Math.floor(timestamp / 1000),
        action: 'increment'
      }
    );
  }
}

// Track API calls
export async function trackAPICall(userId: string) {
  await trackUsage(userId, 'api_calls', 1);
}

// Track AI agent tasks
export async function trackAITask(userId: string, agentType: string) {
  await trackUsage(userId, `ai_task_${agentType}`, 1);
}
```

### Enforce Usage Limits

```javascript
// src/middleware/usage-limits.ts
export async function checkUsageLimits(userId: string, plan: string) {
  const limits = {
    starter: { api_calls: 10000, ai_tasks: 5000 },
    professional: { api_calls: 50000, ai_tasks: 25000 },
    enterprise: { api_calls: Infinity, ai_tasks: Infinity }
  };

  const usage = await getMonthlyUsage(userId);
  const planLimits = limits[plan];

  if (usage.api_calls >= planLimits.api_calls) {
    throw new Error('API call limit exceeded. Please upgrade your plan.');
  }

  if (usage.ai_tasks >= planLimits.ai_tasks) {
    throw new Error('AI task limit exceeded. Please upgrade your plan.');
  }
}
```

## Step 6: Invoice Customization

### Custom Invoice Generation

```javascript
// src/services/invoice-service.ts
export async function customizeInvoice(invoice: Stripe.Invoice) {
  const stripe = new Stripe(env.STRIPE_SECRET_KEY);

  // Add custom fields
  await stripe.invoices.update(invoice.id, {
    custom_fields: [
      { name: 'Account ID', value: invoice.metadata.accountId },
      { name: 'Business Name', value: invoice.metadata.businessName }
    ],
    footer: 'Thank you for choosing CoreFlow360!',
    metadata: {
      generated_by: 'CoreFlow360 V4',
      tax_id: invoice.metadata.taxId
    }
  });

  // Add usage summary as line item
  const usageSummary = await generateUsageSummary(invoice.customer);
  await stripe.invoiceItems.create({
    customer: invoice.customer,
    invoice: invoice.id,
    description: usageSummary,
    amount: 0 // Informational only
  });
}
```

### Tax Calculation

```javascript
// src/services/tax-service.ts
export async function calculateTax(amount: number, customer: any) {
  // Use Stripe Tax or custom logic
  const taxRate = await getTaxRate(customer.address);

  return {
    subtotal: amount,
    tax: amount * taxRate,
    total: amount * (1 + taxRate),
    rate: taxRate
  };
}
```

## Step 7: Payment Recovery

### Failed Payment Handling

```javascript
// src/services/payment-recovery.ts
export async function handleFailedPayment(invoice: Stripe.Invoice) {
  const customer = await getCustomer(invoice.customer);

  // Retry schedule
  const retrySchedule = [
    { days: 3, action: 'retry' },
    { days: 5, action: 'email_warning' },
    { days: 7, action: 'retry' },
    { days: 10, action: 'restrict_features' },
    { days: 14, action: 'suspend_account' }
  ];

  for (const step of retrySchedule) {
    await scheduleRetry(invoice.id, step);
  }

  // Send immediate notification
  await sendPaymentFailedEmail(customer.email, {
    amount: invoice.amount_due,
    nextRetry: '3 days',
    updatePaymentUrl: generateUpdatePaymentUrl(customer.id)
  });
}
```

### Dunning Management

```javascript
// Configuration for automated dunning
const dunningConfig = {
  emails: [
    {
      trigger: 'payment_failed',
      delay: 0,
      template: 'payment_failed_immediate'
    },
    {
      trigger: 'payment_failed',
      delay: 3 * 24 * 60 * 60 * 1000, // 3 days
      template: 'payment_failed_reminder'
    },
    {
      trigger: 'payment_failed',
      delay: 7 * 24 * 60 * 60 * 1000, // 7 days
      template: 'payment_failed_final_warning'
    }
  ],
  actions: {
    restrict_features: 10 * 24 * 60 * 60 * 1000, // After 10 days
    suspend_account: 14 * 24 * 60 * 60 * 1000 // After 14 days
  }
};
```

## Step 8: Revenue Recognition

### Track MRR and Revenue Metrics

```javascript
// src/services/revenue-metrics.ts
export async function calculateMRR() {
  const activeSubscriptions = await db.prepare(`
    SELECT
      plan_type,
      COUNT(*) as count,
      SUM(monthly_amount) as total
    FROM subscriptions
    WHERE status = 'active'
    GROUP BY plan_type
  `).all();

  const mrr = activeSubscriptions.results.reduce((total, plan) => {
    return total + plan.total;
  }, 0);

  const churnRate = await calculateChurnRate();
  const ltv = mrr / churnRate; // Simplified LTV calculation

  return {
    mrr,
    arr: mrr * 12,
    averageRevenue: mrr / activeSubscriptions.results.length,
    ltv,
    byPlan: activeSubscriptions.results
  };
}

export async function trackRevenueEvent(type: string, amount: number, metadata: any) {
  await db.prepare(`
    INSERT INTO revenue_events (type, amount, metadata, timestamp)
    VALUES (?, ?, ?, ?)
  `).bind(type, amount, JSON.stringify(metadata), Date.now()).run();
}
```

## Step 9: Testing Payments

### Test Card Numbers

Use these in development/staging:

```javascript
// Successful payment
4242 4242 4242 4242

// Card declined
4000 0000 0000 0002

// Requires authentication
4000 0025 0000 3155

// Insufficient funds
4000 0000 0000 9995
```

### Test Webhook Events

```bash
# Install Stripe CLI
# https://stripe.com/docs/stripe-cli

# Forward webhooks to local
stripe listen --forward-to localhost:8787/api/v1/webhooks/stripe

# Trigger test events
stripe trigger payment_intent.succeeded
stripe trigger customer.subscription.created
stripe trigger invoice.payment_failed
```

## Step 10: Production Checklist

### Before Going Live

```bash
□ Products created in Stripe Dashboard
□ Prices configured correctly
□ Webhook endpoint verified
□ Webhook events selected
□ Webhook secret stored securely
□ Tax settings configured
□ Email templates created
□ Customer portal configured
□ Dunning emails set up
□ Payment retry logic tested
□ Usage tracking implemented
□ Revenue reporting ready
□ Refund policy documented
□ Terms of service updated
□ Privacy policy includes payment info
```

### Security Checklist

```bash
□ PCI compliance verified
□ HTTPS enforced on all pages
□ Stripe.js loaded from Stripe CDN
□ No card details stored locally
□ Webhook signatures validated
□ API keys in environment variables
□ Rate limiting on payment endpoints
□ Fraud detection rules configured
□ SCA/3D Secure enabled
□ Audit logging for all transactions
```

## Monitoring & Analytics

### Key Metrics Dashboard

```javascript
// Real-time metrics to track
const billingMetrics = {
  revenue: {
    mrr: '$45,230',
    arr: '$542,760',
    growth: '+12.3%'
  },
  subscriptions: {
    active: 156,
    trial: 23,
    churned: 4
  },
  conversion: {
    trialToPaid: '68%',
    visitToTrial: '4.2%',
    churn: '2.8%'
  },
  lifetime: {
    averageLTV: '$3,450',
    paybackPeriod: '3.2 months',
    CAC: '$285'
  }
};
```

### Revenue Alerts

Configure these alerts:

1. **New Subscription**: Celebrate every win
2. **Failed Payment**: Immediate action required
3. **Churn Risk**: Customer hasn't logged in 14 days
4. **Upgrade Opportunity**: Customer near usage limit
5. **MRR Milestone**: Every $10k increment

## Support Resources

### Stripe Documentation
- [Stripe Docs](https://stripe.com/docs)
- [Stripe API Reference](https://stripe.com/docs/api)
- [Stripe Discord](https://discord.gg/stripe)

### Common Issues

**Issue: Webhook not received**
- Check endpoint URL is exact
- Verify webhook secret
- Check Stripe webhook logs

**Issue: Payment declined**
- Check card details
- Verify billing address
- Try different payment method

**Issue: Subscription not activated**
- Check webhook processing
- Verify database update
- Review error logs

---

**Implementation Time:** 20 minutes
**Testing Time:** 30 minutes
**Revenue Generation:** Immediate

Remember: Every second without billing is money left on the table. Ship it!