# Feedback Collection System

## Overview

Comprehensive feedback collection system for CoreFlow360 V4 to gather customer insights, identify product improvements, and reduce churn.

---

## 1. Feedback Collection Strategy

### Multi-Channel Approach

#### **In-App Feedback Widget** (Primary)
- Always accessible from dashboard
- Contextual prompts at key moments
- Screenshot capture capability
- Priority: P0

#### **NPS Surveys** (Quarterly)
- Track customer satisfaction
- Identify promoters vs. detractors
- Trigger improvement initiatives
- Priority: P1

#### **Feature Request Portal** (Public)
- Customer voting on features
- Transparency in roadmap
- Community engagement
- Priority: P2

#### **Exit Surveys** (Churn Prevention)
- Understand cancellation reasons
- Offer retention incentives
- Identify product gaps
- Priority: P0

---

## 2. In-App Feedback Widget

### Implementation (30 min)

**Install Feedback Library:**

```bash
cd frontend
npm install @headlessui/react react-hook-form zod
```

**Create `frontend/src/components/FeedbackWidget.tsx`:**

```typescript
import { Fragment, useState } from 'react';
import { Dialog, Transition } from '@headlessui/react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';

const feedbackSchema = z.object({
  type: z.enum(['bug', 'feature', 'improvement', 'question', 'other']),
  category: z.string().optional(),
  message: z.string().min(10, 'Please provide more details (minimum 10 characters)'),
  email: z.string().email().optional(),
  screenshot: z.boolean().optional(),
});

type FeedbackForm = z.infer<typeof feedbackSchema>;

export function FeedbackWidget() {
  const [isOpen, setIsOpen] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);

  const { register, handleSubmit, reset, formState: { errors } } = useForm<FeedbackForm>({
    resolver: zodResolver(feedbackSchema),
  });

  const onSubmit = async (data: FeedbackForm) => {
    setIsSubmitting(true);

    try {
      // Capture screenshot if requested
      let screenshotUrl = '';
      if (data.screenshot) {
        screenshotUrl = await captureScreenshot();
      }

      // Submit feedback to API
      await fetch('/api/v1/feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...data,
          screenshotUrl,
          page: window.location.pathname,
          userAgent: navigator.userAgent,
          timestamp: new Date().toISOString(),
        }),
      });

      setSubmitted(true);
      setTimeout(() => {
        setIsOpen(false);
        setSubmitted(false);
        reset();
      }, 2000);
    } catch (error) {
      console.error('Feedback submission error:', error);
      alert('Failed to submit feedback. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const captureScreenshot = async (): Promise<string> => {
    // Use html2canvas or similar library
    // For now, return placeholder
    return 'screenshot-placeholder.png';
  };

  return (
    <>
      {/* Feedback Button (Fixed Position) */}
      <button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-4 right-4 bg-primary text-primary-foreground px-4 py-2 rounded-full shadow-lg hover:bg-primary/90 transition-all z-50"
      >
        💬 Feedback
      </button>

      {/* Feedback Modal */}
      <Transition appear show={isOpen} as={Fragment}>
        <Dialog as="div" className="relative z-50" onClose={() => setIsOpen(false)}>
          <Transition.Child
            as={Fragment}
            enter="ease-out duration-300"
            enterFrom="opacity-0"
            enterTo="opacity-100"
            leave="ease-in duration-200"
            leaveFrom="opacity-100"
            leaveTo="opacity-0"
          >
            <div className="fixed inset-0 bg-black bg-opacity-25" />
          </Transition.Child>

          <div className="fixed inset-0 overflow-y-auto">
            <div className="flex min-h-full items-center justify-center p-4 text-center">
              <Transition.Child
                as={Fragment}
                enter="ease-out duration-300"
                enterFrom="opacity-0 scale-95"
                enterTo="opacity-100 scale-100"
                leave="ease-in duration-200"
                leaveFrom="opacity-100 scale-100"
                leaveTo="opacity-0 scale-95"
              >
                <Dialog.Panel className="w-full max-w-md transform overflow-hidden rounded-2xl bg-white p-6 text-left align-middle shadow-xl transition-all">
                  {submitted ? (
                    <div className="text-center py-8">
                      <div className="text-6xl mb-4">✅</div>
                      <h3 className="text-lg font-medium">Thank you!</h3>
                      <p className="text-sm text-gray-500 mt-2">
                        Your feedback helps us improve CoreFlow360.
                      </p>
                    </div>
                  ) : (
                    <>
                      <Dialog.Title as="h3" className="text-lg font-medium leading-6 text-gray-900">
                        Share Your Feedback
                      </Dialog.Title>

                      <form onSubmit={handleSubmit(onSubmit)} className="mt-4 space-y-4">
                        {/* Feedback Type */}
                        <div>
                          <label className="block text-sm font-medium text-gray-700">
                            What would you like to share?
                          </label>
                          <select
                            {...register('type')}
                            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-primary focus:ring-primary"
                          >
                            <option value="bug">🐛 Bug Report</option>
                            <option value="feature">💡 Feature Request</option>
                            <option value="improvement">📈 Improvement Idea</option>
                            <option value="question">❓ Question</option>
                            <option value="other">💬 Other Feedback</option>
                          </select>
                        </div>

                        {/* Message */}
                        <div>
                          <label className="block text-sm font-medium text-gray-700">
                            Details
                          </label>
                          <textarea
                            {...register('message')}
                            rows={4}
                            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-primary focus:ring-primary"
                            placeholder="Tell us more..."
                          />
                          {errors.message && (
                            <p className="mt-1 text-sm text-red-600">{errors.message.message}</p>
                          )}
                        </div>

                        {/* Email (Optional) */}
                        <div>
                          <label className="block text-sm font-medium text-gray-700">
                            Email (optional, for follow-up)
                          </label>
                          <input
                            {...register('email')}
                            type="email"
                            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-primary focus:ring-primary"
                            placeholder="your@email.com"
                          />
                        </div>

                        {/* Screenshot */}
                        <div className="flex items-center">
                          <input
                            {...register('screenshot')}
                            type="checkbox"
                            className="h-4 w-4 text-primary focus:ring-primary border-gray-300 rounded"
                          />
                          <label className="ml-2 block text-sm text-gray-700">
                            Include screenshot of current page
                          </label>
                        </div>

                        {/* Actions */}
                        <div className="flex gap-2 mt-6">
                          <button
                            type="button"
                            onClick={() => setIsOpen(false)}
                            className="flex-1 px-4 py-2 bg-gray-200 text-gray-700 rounded-md hover:bg-gray-300"
                          >
                            Cancel
                          </button>
                          <button
                            type="submit"
                            disabled={isSubmitting}
                            className="flex-1 px-4 py-2 bg-primary text-white rounded-md hover:bg-primary/90 disabled:opacity-50"
                          >
                            {isSubmitting ? 'Sending...' : 'Send Feedback'}
                          </button>
                        </div>
                      </form>
                    </>
                  )}
                </Dialog.Panel>
              </Transition.Child>
            </div>
          </div>
        </Dialog>
      </Transition>
    </>
  );
}
```

**Add to Main Layout:**

```typescript
// frontend/src/layouts/main-layout.tsx
import { FeedbackWidget } from '@/components/FeedbackWidget';

export function MainLayout({ children }) {
  return (
    <div>
      {children}
      <FeedbackWidget />
    </div>
  );
}
```

### Backend API Endpoint

**Create `src/routes/feedback.ts`:**

```typescript
import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';

const app = new Hono();

const feedbackSchema = z.object({
  type: z.enum(['bug', 'feature', 'improvement', 'question', 'other']),
  message: z.string().min(10),
  email: z.string().email().optional(),
  screenshotUrl: z.string().optional(),
  page: z.string(),
  userAgent: z.string(),
  timestamp: z.string(),
});

app.post('/api/v1/feedback', zValidator('json', feedbackSchema), async (c) => {
  const feedback = c.req.valid('json');
  const user = c.get('user'); // From auth middleware

  try {
    // Store in database
    await c.env.DB.prepare(`
      INSERT INTO feedback (
        user_id, business_id, type, message, email,
        screenshot_url, page, user_agent, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      user?.id || null,
      user?.currentBusinessId || null,
      feedback.type,
      feedback.message,
      feedback.email,
      feedback.screenshotUrl,
      feedback.page,
      feedback.userAgent,
      feedback.timestamp
    ).run();

    // Send notification to team (Slack, Email)
    await notifyTeam(feedback, user);

    // Track analytics
    await trackFeedbackEvent(feedback.type, user?.id);

    return c.json({ success: true, message: 'Feedback received. Thank you!' });
  } catch (error) {
    console.error('Feedback storage error:', error);
    return c.json({ error: 'Failed to submit feedback' }, 500);
  }
});

async function notifyTeam(feedback: any, user: any): Promise<void> {
  // Send to Slack
  const slackWebhook = process.env.SLACK_FEEDBACK_WEBHOOK;
  if (slackWebhook) {
    await fetch(slackWebhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: `New ${feedback.type} feedback`,
        blocks: [
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `*New ${feedback.type} feedback from ${user?.email || 'Anonymous'}*\n\n${feedback.message}`
            }
          },
          {
            type: 'context',
            elements: [
              { type: 'mrkdwn', text: `Page: ${feedback.page}` },
              { type: 'mrkdwn', text: `Time: ${feedback.timestamp}` }
            ]
          }
        ]
      })
    });
  }
}

export default app;
```

**Add Database Migration:**

```sql
-- database/migrations/0010_feedback_system.sql

CREATE TABLE IF NOT EXISTS feedback (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  business_id TEXT,
  type TEXT NOT NULL CHECK (type IN ('bug', 'feature', 'improvement', 'question', 'other')),
  message TEXT NOT NULL,
  email TEXT,
  screenshot_url TEXT,
  page TEXT NOT NULL,
  user_agent TEXT,
  status TEXT DEFAULT 'new' CHECK (status IN ('new', 'in_review', 'planned', 'completed', 'declined')),
  assigned_to TEXT,
  notes TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_feedback_user ON feedback(user_id);
CREATE INDEX idx_feedback_status ON feedback(status);
CREATE INDEX idx_feedback_type ON feedback(type);
CREATE INDEX idx_feedback_created ON feedback(created_at DESC);
```

---

## 3. NPS Survey System

### Quarterly NPS Survey

**Create `frontend/src/components/NPSSurvey.tsx`:**

```typescript
import { useState, useEffect } from 'react';

export function NPSSurvey() {
  const [score, setScore] = useState<number | null>(null);
  const [feedback, setFeedback] = useState('');
  const [showSurvey, setShowSurvey] = useState(false);

  useEffect(() => {
    // Show survey after 30 days of usage
    const accountAge = getAccountAgeDays();
    const lastSurvey = localStorage.getItem('last_nps_survey');
    const daysSinceLastSurvey = lastSurvey
      ? Math.floor((Date.now() - parseInt(lastSurvey)) / (1000 * 60 * 60 * 24))
      : 999;

    if (accountAge >= 30 && daysSinceLastSurvey >= 90) {
      setTimeout(() => setShowSurvey(true), 5000); // Show after 5 seconds
    }
  }, []);

  const submitNPS = async () => {
    if (score === null) return;

    await fetch('/api/v1/nps', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ score, feedback }),
    });

    localStorage.setItem('last_nps_survey', Date.now().toString());
    setShowSurvey(false);
  };

  if (!showSurvey) return null;

  return (
    <div className="fixed bottom-4 right-4 bg-white rounded-lg shadow-xl p-6 max-w-md z-50">
      <button
        onClick={() => setShowSurvey(false)}
        className="absolute top-2 right-2 text-gray-400 hover:text-gray-600"
      >
        ✕
      </button>

      <h3 className="text-lg font-semibold mb-2">Quick Question</h3>
      <p className="text-sm text-gray-600 mb-4">
        How likely are you to recommend CoreFlow360 to a friend or colleague?
      </p>

      {/* NPS Score Selection (0-10) */}
      <div className="flex gap-1 mb-4">
        {[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map((num) => (
          <button
            key={num}
            onClick={() => setScore(num)}
            className={`w-8 h-8 rounded text-sm font-medium transition-colors ${
              score === num
                ? 'bg-primary text-white'
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}
          >
            {num}
          </button>
        ))}
      </div>

      <div className="flex justify-between text-xs text-gray-500 mb-4">
        <span>Not likely</span>
        <span>Very likely</span>
      </div>

      {/* Feedback Text (Optional) */}
      {score !== null && (
        <div className="mb-4">
          <label className="block text-sm font-medium text-gray-700 mb-1">
            What's the main reason for your score? (optional)
          </label>
          <textarea
            value={feedback}
            onChange={(e) => setFeedback(e.target.value)}
            rows={3}
            className="w-full border rounded p-2 text-sm"
            placeholder="Your feedback helps us improve..."
          />
        </div>
      )}

      {/* Submit Button */}
      <button
        onClick={submitNPS}
        disabled={score === null}
        className="w-full bg-primary text-white py-2 rounded hover:bg-primary/90 disabled:opacity-50"
      >
        Submit
      </button>
    </div>
  );
}

function getAccountAgeDays(): number {
  // Get from user store
  const createdAt = useAuthStore.getState().user?.createdAt;
  if (!createdAt) return 0;
  return Math.floor((Date.now() - new Date(createdAt).getTime()) / (1000 * 60 * 60 * 24));
}
```

### NPS Backend

```typescript
// src/routes/nps.ts
app.post('/api/v1/nps', async (c) => {
  const { score, feedback } = await c.req.json();
  const user = c.get('user');

  await c.env.DB.prepare(`
    INSERT INTO nps_responses (user_id, score, feedback, created_at)
    VALUES (?, ?, ?, ?)
  `).bind(user.id, score, feedback, new Date().toISOString()).run();

  // Calculate NPS category
  const category = score >= 9 ? 'promoter' : score >= 7 ? 'passive' : 'detractor';

  // Track in analytics
  await trackEvent('nps_submitted', { score, category, userId: user.id });

  return c.json({ success: true });
});

// Get NPS dashboard
app.get('/api/v1/admin/nps', async (c) => {
  const responses = await c.env.DB.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN score >= 9 THEN 1 ELSE 0 END) as promoters,
      SUM(CASE WHEN score >= 7 AND score < 9 THEN 1 ELSE 0 END) as passives,
      SUM(CASE WHEN score < 7 THEN 1 ELSE 0 END) as detractors,
      AVG(score) as avg_score
    FROM nps_responses
    WHERE created_at >= date('now', '-90 days')
  `).first();

  const nps = ((responses.promoters - responses.detractors) / responses.total) * 100;

  return c.json({ nps, ...responses });
});
```

---

## 4. Feature Request Portal

### Public Voting Board (Canny.io Alternative)

**Simple Implementation:**

```typescript
// frontend/src/routes/feedback/feature-requests.tsx
export function FeatureRequestsPage() {
  const [requests, setRequests] = useState([]);

  useEffect(() => {
    fetch('/api/v1/feature-requests')
      .then(res => res.json())
      .then(setRequests);
  }, []);

  return (
    <div className="max-w-4xl mx-auto p-6">
      <h1 className="text-3xl font-bold mb-6">Feature Requests</h1>

      {/* Submit New Request */}
      <div className="bg-white rounded-lg shadow p-6 mb-6">
        <h2 className="text-xl font-semibold mb-4">Submit New Request</h2>
        {/* Form here */}
      </div>

      {/* Feature Requests List */}
      <div className="space-y-4">
        {requests.map((request) => (
          <div key={request.id} className="bg-white rounded-lg shadow p-6">
            <div className="flex items-start gap-4">
              {/* Upvote Button */}
              <button className="flex flex-col items-center gap-1 min-w-[60px]">
                <div className="text-2xl">▲</div>
                <div className="font-bold">{request.votes}</div>
              </button>

              {/* Request Details */}
              <div className="flex-1">
                <h3 className="font-semibold text-lg">{request.title}</h3>
                <p className="text-gray-600 mt-1">{request.description}</p>
                <div className="flex gap-2 mt-2">
                  <span className="px-2 py-1 bg-blue-100 text-blue-700 rounded text-sm">
                    {request.category}
                  </span>
                  <span className={`px-2 py-1 rounded text-sm ${
                    request.status === 'planned' ? 'bg-green-100 text-green-700' :
                    request.status === 'in_progress' ? 'bg-yellow-100 text-yellow-700' :
                    'bg-gray-100 text-gray-700'
                  }`}>
                    {request.status}
                  </span>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
```

---

## 5. Exit Survey (Churn Prevention)

### Cancellation Flow with Survey

```typescript
// frontend/src/routes/settings/cancel-subscription.tsx
export function CancelSubscriptionPage() {
  const [reason, setReason] = useState('');
  const [feedback, setFeedback] = useState('');
  const [showRetention, setShowRetention] = useState(false);

  const handleSubmit = async () => {
    // Submit exit survey
    await fetch('/api/v1/exit-survey', {
      method: 'POST',
      body: JSON.stringify({ reason, feedback }),
    });

    // Show retention offer based on reason
    if (reason === 'too_expensive') {
      setShowRetention(true);
    } else {
      // Proceed with cancellation
      await cancelSubscription();
    }
  };

  return (
    <div className="max-w-2xl mx-auto p-6">
      <h1 className="text-2xl font-bold mb-6">We're sorry to see you go</h1>

      {showRetention ? (
        <RetentionOffer reason={reason} />
      ) : (
        <>
          <p className="mb-4">Before you cancel, please help us improve by telling us why:</p>

          {/* Cancellation Reasons */}
          <div className="space-y-2 mb-4">
            {[
              { value: 'too_expensive', label: 'Too expensive' },
              { value: 'not_using', label: 'Not using it enough' },
              { value: 'missing_features', label: 'Missing features I need' },
              { value: 'too_complex', label: 'Too complex to use' },
              { value: 'switching', label: 'Switching to competitor' },
              { value: 'business_closed', label: 'Business closed' },
              { value: 'other', label: 'Other' },
            ].map((option) => (
              <label key={option.value} className="flex items-center gap-2">
                <input
                  type="radio"
                  name="reason"
                  value={option.value}
                  checked={reason === option.value}
                  onChange={(e) => setReason(e.target.value)}
                />
                <span>{option.label}</span>
              </label>
            ))}
          </div>

          {/* Additional Feedback */}
          <textarea
            value={feedback}
            onChange={(e) => setFeedback(e.target.value)}
            rows={4}
            className="w-full border rounded p-2 mb-4"
            placeholder="Any additional feedback? (optional)"
          />

          <button
            onClick={handleSubmit}
            className="w-full bg-red-600 text-white py-2 rounded hover:bg-red-700"
          >
            Cancel Subscription
          </button>
        </>
      )}
    </div>
  );
}

function RetentionOffer({ reason }) {
  if (reason === 'too_expensive') {
    return (
      <div className="bg-green-50 border border-green-200 rounded-lg p-6">
        <h2 className="text-xl font-semibold mb-2">Special Offer: 50% Off for 3 Months</h2>
        <p className="mb-4">
          We'd love to keep you! As a valued customer, we're offering you 50% off your subscription for the next 3 months.
        </p>
        <button className="bg-green-600 text-white px-6 py-2 rounded hover:bg-green-700">
          Accept Offer
        </button>
      </div>
    );
  }
  return null;
}
```

---

## 6. Feedback Dashboard (Admin)

### Internal Feedback Review Dashboard

```typescript
// src/routes/admin/feedback.ts
app.get('/api/v1/admin/feedback/dashboard', async (c) => {
  // Get feedback summary
  const summary = await c.env.DB.prepare(`
    SELECT
      type,
      COUNT(*) as count,
      SUM(CASE WHEN status = 'new' THEN 1 ELSE 0 END) as new_count
    FROM feedback
    WHERE created_at >= date('now', '-30 days')
    GROUP BY type
  `).all();

  // Get recent feedback
  const recent = await c.env.DB.prepare(`
    SELECT * FROM feedback
    ORDER BY created_at DESC
    LIMIT 50
  `).all();

  return c.json({ summary: summary.results, recent: recent.results });
});
```

---

## 7. Implementation Checklist

### Week 1: Core Setup
- [ ] Create feedback database tables
- [ ] Implement in-app feedback widget
- [ ] Deploy feedback API endpoint
- [ ] Test feedback submission flow
- [ ] Configure Slack notifications

### Week 2: Surveys
- [ ] Implement NPS survey component
- [ ] Create NPS backend endpoints
- [ ] Schedule quarterly NPS campaigns
- [ ] Build exit survey into cancellation flow

### Week 3: Analytics & Optimization
- [ ] Create admin feedback dashboard
- [ ] Integrate with analytics tracking
- [ ] Set up weekly feedback review process
- [ ] Build feature request voting portal

---

## 8. Feedback Review Process

### Weekly Feedback Triage (Every Monday 30 min)

**Review Workflow:**
1. **Bugs** → Create tickets in issue tracker (P0-P3)
2. **Feature Requests** → Add to product backlog with vote count
3. **Questions** → Respond directly or update docs
4. **Improvements** → Prioritize based on frequency
5. **Other** → Route to appropriate team

**Metrics to Track:**
- Total feedback submissions (week over week)
- Response rate (% responded to within 48h)
- Implementation rate (% of requests implemented)
- Time to resolution (bugs)

---

## Next Steps

1. **Deploy feedback widget** (30 min)
2. **Create database migrations** (10 min)
3. **Configure Slack webhook** (5 min)
4. **Test feedback flow** (15 min)
5. **Schedule first NPS survey** (90 days from now)

**Total Setup Time: 1 hour**

Your customers are ready to help you build a better product!
